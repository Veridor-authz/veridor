# Veridor as an Argo CD PostSync gate

[`application-example.yaml`](application-example.yaml) is an Application with
two sources: your app, and the [`veridor-gate`](../helm/veridor-gate/README.md)
chart with `hook.mode: argocd`. Every sync of the app runs `veridor run`
once the sync's resources are Healthy, except a selective sync or an Apply
Only sync, which Argo CD runs with no hooks ("Syncs that run no gate"). The
gate probes whatever `target.baseUrl` routes to then: aim it at a Service
that selects only the pods this sync rolled out (see "Sync waves and
ordering"). A PostSync gate reports; it does not block. To block, gate a
canary with Argo Rollouts.

You do not run Helm for this: Argo CD renders the chart itself, and your
app's source can be Kustomize or plain manifests. There is no Kustomize
overlay for Argo CD; Kustomize cannot render the Job the way Argo CD needs
it ([`deploy/kustomize/veridor-gate`](../kustomize/veridor-gate/README.md),
"No Argo CD overlay").

## What happens on a sync

Use the gate as a hook: `hook.mode: argocd`. `hook.mode: none` and the
Kustomize `overlays/plain` carry no hook
annotation, so Argo CD would apply that Job like any other resource: nothing
waits for it, and an unchanged Job is not re-created, so a later sync does not
re-run it (the behaviour `kubectl apply` shows for an unchanged Job, measured
on kind; not measured through Argo CD). Only Argo CD renders `hook.mode:
argocd`: `helm install` and `helm upgrade` refuse it at render, because the
Helm CLI does not run Argo CD hooks (measured: before the refusal, `helm
install --server-side=false` exited 0 with the release `deployed` and a Job
nothing waited for).

`hook.mode: helm` is the other way round: it is for the Helm CLI, and Argo
CD refuses to render it. Argo CD would run its Job as a `PostSync` hook
(it maps `helm.sh/hook: post-install,post-upgrade` to `PostSync` and
`before-hook-creation` to `BeforeHookCreation`) under one fixed name, the
shape "Each sync reads its own Job" below describes. Measured with Argo CD
v3.5.3, on a chart that did not refuse it, in an Application of the gate alone:
14 of 80 helm-mode syncs were reported from the previous sync's Job, 6 of
the 40 vulnerable ones `Succeeded` while their own gate exited 1 (argocd
mode: 0 of 50). The chart refuses helm mode on any render that reaches
no cluster, which is how Argo CD renders, so the Application shows a
`ComparisonError` naming the refusal. That includes the gate as a
dependency of your app's chart: set its `hook.mode` to `argocd`.

1. The **Sync** phase applies your app's resources (and the gate's ConfigMap).
2. Argo CD waits until every Sync-phase resource is Healthy.
3. The **PostSync** phase creates the gate Job (`argocd.argoproj.io/hook:
   PostSync`) under a name of its own. The chart renders
   `metadata.generateName`, and Argo CD names the Job
   `<helm.releaseName>-veridor-gate-<revision>-postsync-<the sync's start,
   Unix seconds>`, where `<revision>` is the first 7 characters of the sync's
   revision, and empty for an Application with several sources like the
   example (measured: `invoices-api-gate-veridor-gate--postsync-1790304814`).
   Each sync's Job and its log stay for `job.ttlSecondsAfterFinished` (3600 s
   by default) after the Job finished; the TTL controller deletes a finished
   hook Job like any other (measured on kind with a 30 s TTL: 10 syncs, and 50
   s after the last no Job or pod was left). `hook-delete-policy:
   BeforeHookCreation`, the default, finds no earlier Job of the same name, so
   it deletes nothing (measured: one Job per sync until the TTL). See "Sync
   waves and ordering" for the other policies.
4. Veridor's exit code decides the Job: 0 completes it; 1 (findings), 2
   (configuration refused), 3 (something went unmeasured) and 70 (internal
   error) fail it. `backoffLimit` is 0. Exit 3 includes `liveness_unproven`:
   a denial-only expectation, in a check or a sequence assert step, by an
   identity that presents a credential, where some identity was served in
   the same check or sequence, that nothing in the run proved live (a 2xx
   on a request where an identity with no credential, or the fabricated
   credential, was refused; or its `marker_probe`; for a session, either one
   only under the same login and session cookie value), because a fabricated
   credential got the same denial, none was sent to compare with (one goes
   only with GET, HEAD and OPTIONS, and only when an identity declares a
   credential header to shape it on; never on a write or inside a
   sequence), its request failed, or its answer was neither a refusal nor a
   success. The example gives
   `other_tenant` a `marker_probe` for that reason; the chart README's
   "Exit 3" says when you need one. A `marker_probe` proves only the first
   login of a session with `"reestablish": "check"`, so use
   `"reestablish": "run"` or show it served in the same sequence, and one
   whose session cookie the target replaced needs a 2xx sent after the
   change.
5. A failed hook Job fails the sync operation, and a passing one lets it
   succeed. Each sync is reported from its own Job (next section). A sync
   that runs no hooks runs no gate and succeeds ("Syncs that run no gate").

Measured by `scripts/e2e_kubernetes.sh` (Argo CD v3.5.3, kind), which runs
the example's own gate values (hook settings, gate flags, `secretEnv` and the
Veridor configuration) with only the image, the chart repository and the
target URL replaced:

| | vulnerable target | fixed target |
|---|---|---|
| `status.operationState.phase` | `Failed` | `Succeeded` |
| `status.operationState.message` | `one or more synchronization tasks completed unsuccessfully` | `successfully synced (no more tasks)` |
| hook entry in `status.operationState.syncResult.resources` | `kind: Job`, `name: invoices-api-gate-veridor-gate--postsync-<start>`, `hookType: PostSync`, `hookPhase: Failed`, `message: Job has reached the specified backoff limit` | `hookPhase: Succeeded`, `message: Reached expected number of succeeded pods` |
| gate container exit code | 1 | 0 |
| `status.sync.status` / `status.health.status` | `Synced` / `Healthy` | `Synced` / `Healthy` |

## Each sync reads its own Job

With one fixed name for the gate Job and `BeforeHookCreation`, Argo CD deletes
the previous sync's Job and creates the new one under that name, and Argo CD
v3.5.3 then reports some syncs from the previous sync's Job. Measured on kind
with this chart, its Job named that way, as an Application's only source,
synced against a vulnerable and a fixed target in turn, three runs of 16 syncs (one with 20 s between syncs): 5 of the 24 syncs whose gate
passed were reported `Failed`. With a stand-in PostSync Job that exited 0 and
1 on alternate syncs, 5 of 13 syncs whose Job failed were reported
`Succeeded` with the message "Reached expected number of succeeded pods", the
operation finishing in the second the new Job was created. The e2e saw both
with the full Application: in 4 of 5 runs of the `argocd` scenario a
vulnerable sync was reported `Succeeded` while its gate exited 1, and the
removed Kustomize overlay's leg reported a passing sync `Failed`. A gate
whose sync can be reported from another run's Job does not gate.

The chart now renders `metadata.generateName`, so every sync's Job has a
name no earlier sync used, and Argo CD reads that Job. The same harness with
this chart: every sync was reported from its own Job, 36 of 36 (16 with 20 s
between syncs, 10 with a 30 s TTL, 10 with `HookSucceeded`), and 16 of 16
with a control copy of the chart that differed only in `generateName`. The
e2e, with the example's values in a two-source Application: in 5 runs of
the `argocd` scenario on 2026-09-25 every sync's phase matched its own
gate Job's exit, 35 of 35 (7 syncs a run), no two syncs of a run shared a
Job, and every row matched.

Two consequences worth planning for:

* **The operation message does not name the hook, and neither says why.** The
  hook is named in `syncResult.resources` with the Job's status message, which
  says only that the Job failed. The verdict and the findings are in the Job
  log.
* **A PostSync gate does not undo the sync.** By the time it runs, the new
  version is deployed; the e2e measures the vulnerable Deployment still running
  after the failed gate, and the Application still reports `Synced` and
  `Healthy`. What fails is the *operation*: alert on
  `status.operationState.phase` being `Failed` (for example with an Argo CD
  Notifications trigger on that field), not on sync or health status. That
  phase is this sync's own Job's (above); with the fixed name it was not
  always. Alert as well on a `Succeeded` operation with no `PostSync` entry:
  that sync ran no gate (next section).

## Syncs that run no gate

Argo CD v3.5.3 runs no hook, the gate included, for a sync that names
resources or uses the apply strategy: `controller/sync.go` passes
`skipHooks` for either. That is:

* a selective sync: `argocd app sync <app> --resource ...`, or syncing some
  of the resources from the UI;
* an apply-strategy sync: `argocd app sync <app> --strategy apply`, the UI's
  *Apply Only*;
* automated self-heal, which names the resources it re-applies (read in
  Argo CD's source, not measured). An automated sync of a new revision names
  none and runs the gate.

Such an operation applies what it was asked to and ends `Succeeded`, message
`successfully synced (all tasks run)`, with no `PostSync` entry in
`status.operationState.syncResult.resources` and no gate Job, whatever version
it applied. Measured by the e2e's `argocd` scenario with the vulnerable version
deployed, straight after its full sync `Failed` on the gate: a selective sync
of the Deployment and an Apply Only sync each ended that way. A `Failed` phase
is therefore not the only thing to watch: treat a `Succeeded` operation with
no `PostSync` entry as ungated, and alert on it too.

## PostSync reports; Rollouts blocks

PostSync waits for health and reports; Argo Rollouts blocks. A PostSync hook
is a report on a version that is already serving: a failed gate leaves the new
version running (measured, row `argocd: after failed gate, running version`:
the vulnerable version). Nothing Argo CD does after the hook fails takes it
out of service. To keep a failing version from taking all the traffic, gate a
canary with [Argo Rollouts](../argo-rollouts/README.md): the analysis runs
while the canary has only its share (one of two pods in the example) and
before it is promoted, and a failed analysis aborts the rollout and keeps the
stable ReplicaSet (measured by the e2e's `rollouts` scenario).

## The gate can start before the new pod is routable

Argo CD starts PostSync once every Sync-phase resource is Healthy. That can be
the same second the new pod turns Ready, before its Service routes to it.
Before the wait existed, the e2e's Argo CD leg for the Kustomize overlay
(since removed) failed once in four runs this way: three probes refused
(`ECONNREFUSED`) against the fixed target, exit 3, a failed sync about a
version the gate never reached; a watcher on a later run saw the PostSync Job
created in the same second the new pod turned Ready. With the wait on, the
same leg's gate logged "accepted a connection after 1s (--wait-for-target 60,
2 attempt(s))" in a full e2e run on 2026-09-24: its first connection was
refused, and it was measured anyway.

So the gate waits: `gate.waitForTargetSeconds` (default `60`, chart) and
`--wait-for-target 60` (Kustomize base) make Veridor try a plain TCP
connection to the target's host and port once a second, for at most that
long, before its first request. One line in the Job log says how long it
waited, or that the target never accepted. It never changes a verdict: a
target that never accepts is measured as before and exits 3. Keep it well
under `job.activeDeadlineSeconds` (600), or set it to `0` to turn it off.

The e2e's `wait` scenario measures the race directly, with plain gate Jobs
(`hook.mode: none`, not through Argo CD) started next to targets whose only
pod turns Ready 15 seconds after it starts (0 ready endpoints when each gate
was created):

| gate | target | gate Job | log |
|---|---|---|---|
| no wait | vulnerable | Failed, exit 3 | all 6 probes `Connection refused`; "not one of 6 probe(s) was answered" |
| `waitForTargetSeconds: 60` | vulnerable | Failed, exit 1 | "accepted a connection after 15s", then the finding |
| `waitForTargetSeconds: 60` | fixed | Complete, exit 0 | "accepted a connection after 15s" |

An accepted connection means the port is open, not that the application is
ready; a readiness probe that means "serving the new version" is still the
first line of defence.

## Reading the result

```sh
# the sync operation
kubectl -n argocd get application invoices-api \
  -o jsonpath='{.status.operationState.phase}{"\n"}{.status.operationState.message}{"\n"}'

# the hook this sync ran, with its result
kubectl -n argocd get application invoices-api -o json \
  | jq '.status.operationState.syncResult.resources[] | select(.hookType=="PostSync")'

# the name of this sync's gate Job (empty until Argo CD has created it, and
# empty after the operation has finished: this sync ran no gate)
job="$(kubectl -n argocd get application invoices-api \
  -o jsonpath='{.status.operationState.syncResult.resources[?(@.hookType=="PostSync")].name}')"

# the gate Job's own outcome, Complete or Failed (empty while it runs)
kubectl -n shop get job "$job" -o jsonpath='{.status.conditions[?(@.status=="True")].type}{"\n"}'

# why: the gate's own output, including the findings and Veridor's scope sentences
kubectl -n shop logs "job/$job"
```

Each sync's Job is `<helm.releaseName>-veridor-gate-<revision>-postsync-<the
sync's start, Unix seconds>`: set `helm.releaseName` on the gate source so
the prefix does not depend on the Application's name. Several gate Jobs are
in the namespace at once, one per sync that ran hooks within
`job.ttlSecondsAfterFinished`; the one a sync ran is the one its `syncResult` names (the e2e reads it that
way, and checks it was created after the sync started). (The e2e runs Argo
CD core, without the API server or UI, so only the fields above are
measured.)

## Sync waves and ordering

* PostSync waits for health: it runs after **all** Sync-phase waves have
  completed and become Healthy. That does not make the gate probe the new
  version. A Deployment is Healthy once its rollout is complete, and the pod
  it replaced can still be terminating and answering. Measured through Argo CD
  by the e2e with a `RollingUpdate` app synced from fixed to vulnerable: a
  Service on a `.Release.Revision` label still listed the replaced pod after
  the sync, and the gate passed the vulnerable version in 5 of 10 runs (the
  chart README, "Under Argo CD and `helm template`", has the runs). That label
  is the chart README's recipe for the Helm CLI, and it does nothing here:
  Argo CD renders the app's chart with `helm template`, where
  `.Release.Revision` is always `1`, so the old and the new pods carry the
  same label. Aim `target.baseUrl` at a Service on a label that changes
  whenever the pod template does, such as a hash of the rendered pod spec (the
  chart README has the snippet and the runs; measured through Argo CD in 10
  runs: the replaced pod was not listed and answered none of the gate requests
  counted, and the gate failed on the vulnerable version in each of the 9 runs
  whose exit code was read), or run the app with `strategy: Recreate`, whose
  old pod is gone before the new one starts (measured through Argo CD, fixed
  to vulnerable: the gate exited 1, 10 of 10). A readiness probe decides when
  the NEW pod is routable; it does not stop the old one answering. Either way
  the gate reports on a version already serving; only an Argo Rollouts canary
  keeps a failing version from taking the traffic (above).
* `hook.argocd.syncWave` sets `argocd.argoproj.io/sync-wave` on the Job, to
  order it among other PostSync hooks.
* `hook.argocd.phase` accepts only `PostSync`. `Sync` is refused at render:
  Argo CD runs a Sync hook together with the apply of the application's
  manifests, not once they are Healthy, so the gate would probe whatever the
  Service still routes to, the version being replaced. `PreSync` is refused
  at render too: a PreSync hook runs before the sync applies anything,
  including the chart's own ConfigMap, so it would probe the version already
  running with the previous configuration, or, on a first sync, find no
  configuration to mount (measured for the equivalent Helm `pre-install` and
  `pre-upgrade` hooks on kind; PreSync itself was not run). Neither Sync nor
  PreSync was run through Argo CD by the e2e.
* `hook.argocd.deletePolicy` is one or more of `BeforeHookCreation` (the
  default), `HookSucceeded` and `HookFailed`. Every sync's Job has a name no
  earlier sync used, so no Job an earlier sync left can stand in for the gate
  and `BeforeHookCreation` deletes nothing. `HookSucceeded` deletes a passing
  Job, and `HookFailed` a failing one with the log that says why, as soon as
  Argo CD has recorded the result (measured with `HookSucceeded` and a 30 s
  TTL: 10 of 10 syncs reported from their own Job, each passing Job gone
  before the next sync, each failing one kept until the TTL). With
  `job.ttlSecondsAfterFinished: null` the chart refuses to render unless
  both are listed: otherwise every sync's Job would stay for good.

## Retries

The example sets no `syncPolicy.retry`. A retried sync re-runs the gate, and a
gate retried until it passes reports its luckiest attempt. Retries also undo
the per-sync Job name: Argo CD builds the hook's name from the operation's
start time, and a retry within one operation keeps that start time, so every
attempt gets the same name and each attempt's Job replaces the last under it.
That is the fixed-name case the generated name exists to avoid (read in Argo
CD v3.5.3's source, not measured). The e2e starts every sync explicitly;
automated sync is not measured.

## Credentials and the chart

The Secret that `secretEnv` names must exist in the destination namespace; the
Application does not create it. The chart refuses to render a literal
credential that its rule recognises in `config`, so such a mistake shows up
as a `ComparisonError` condition on the Application, naming the offending
path and not the value (measured by the e2e), rather than as a credential in
a ConfigMap. The rule goes by header and key names; the chart README lists
exactly which names count, and a secret under any other name is not caught.

## Hosting the chart

Each release tag publishes the chart to `oci://ghcr.io/veridor-authz/charts`
and its default image, `ghcr.io/veridor-authz/veridor`. Pointing Argo CD at
that OCI repository was not measured here. To run an image built from the
repository's `Dockerfile`, push it where the cluster can pull it, and set
`image.repository` and `image.tag` in the example's `valuesObject`. The
example points `sources[1].repoURL` at a placeholder: serve the packaged chart
(`helm package deploy/helm/veridor-gate`) from your own Helm repository, or
use a Git source with `path: deploy/helm/veridor-gate` (not measured here).
The e2e script serves it from an in-cluster static Helm repository
(`python3 -m http.server` over `helm repo index` output), which is the setup
measured above.
