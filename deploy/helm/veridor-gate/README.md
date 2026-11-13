# veridor-gate

A Helm chart that runs `veridor run` as a Kubernetes Job, so a deployment is
gated on the authorization expectations you declared. The Job's exit code is
the gate. There is no wrapper script and no `|| true`: Veridor's exit 0
completes the Job, and any other exit fails it.

```
veridor run --config /config/veridor.json --output-dir /work/.veridor \
            --fail-on new+confirmed --base-url <target.baseUrl> --require-complete \
            --wait-for-target 60
```

It attaches to a deployment in one of three ways (`hook.mode`, required):

| `hook.mode` | What the Job is | What fails when the gate fails |
|---|---|---|
| `argocd` | Argo CD `PostSync` hook with no fixed name: `metadata.generateName`, so Argo CD gives each sync that runs hooks a Job of its own (a selective or Apply Only sync runs none, so no gate: [`deploy/argocd`](../../argocd/README.md), "Syncs that run no gate") | the sync operation (`status.operationState.phase: Failed`), read from that sync's own Job ([`deploy/argocd`](../../argocd/README.md), "Each sync reads its own Job"). Rendered by Argo CD only: `helm install` refuses it |
| `helm` | Helm `post-install,post-upgrade` hook (both required), `before-hook-creation` | `helm install` / `helm upgrade` exits non-zero; with `--rollback-on-failure` the release is rolled back, without it `failed` with the new version serving. Under Helm's default flags the hook probes the version being replaced: see "hook.mode helm: what the gate probes". For the Helm CLI only: a render that reaches no cluster (`helm template`, a client-side dry run, Argo CD) is refused unless `hook.helm.allowRenderWithoutCluster` is `true`; under Argo CD use `argocd` |
| `none` | a plain Job named `<release>-veridor-gate-r<revision>` | nothing by itself: whatever applies it must wait for this run's Job (see "hook.mode none") |

There is no default mode. A Job carrying Argo CD annotations installed with
plain `helm install` runs, fails, and leaves the release green -- a gate that
gates nothing -- so the render refuses until you choose, and refuses
`hook.mode: argocd` itself when it reaches a cluster (`helm install`, `helm
upgrade`, a server-side dry run). Argo CD renders with `helm template`, which
never does. Measured with Helm 4.2.2 before that refusal: the argocd-mode
Job, which has no name, failed a server-side install ("resource name may not
be empty"), but with `--server-side=false`, the way Helm 3 applies, the
install exited 0 with the release `deployed` and a Job the API server named,
which nothing waited for. Now all three are refused at render, with no Job
and no release.

The mirror case is refused too: `hook.mode: helm` rendered by Argo CD, as a
dependency of the app's chart or on its own. Argo CD turns `helm.sh/hook:
post-install,post-upgrade` into a `PostSync` hook and `before-hook-creation`
into `BeforeHookCreation` (gitops-engine v3.5.3), so every sync's gate Job has
one fixed name, the shape argocd mode left because Argo CD reported syncs
from the previous sync's Job. Measured on kind with Argo CD v3.5.3, in an
Application of the gate alone with the target switched between a vulnerable
and a fixed API on every sync: 14 of 80 helm-mode syncs were reported from
the previous sync's Job, 6 of the 40 vulnerable ones `Succeeded` while their
own gate exited 1; argocd mode, 0 of 50. With the app rolling on every sync
the helm-mode syncs were read correctly (24 of 24), so the stale reads were
measured only where the Sync phase ends at once, as it does with the gate
alone (a config-only change should be the same; not measured). A render that
reaches no cluster cannot tell Argo CD from `helm template`, so helm mode
refuses every such render. Under Argo CD use `hook.mode: argocd`. To render
helm mode for the Helm CLI without a cluster (`helm template`,
`--dry-run=client`), set `hook.helm.allowRenderWithoutCluster:
true`, and never under Argo CD.

**What that check costs you.** Helm mode asks Helm to `lookup` ConfigMaps in
the release namespace, so the identity running `helm install` / `helm upgrade`
needs `list` on `configmaps` there. Helm's `lookup` passes back anything that
is not a 404, so an identity without it fails the render with Kubernetes' own
`forbidden ... cannot list resource "configmaps"` and not with this chart's
message. Either grant that `list`, or set
`hook.helm.allowRenderWithoutCluster: true`, which is read first and skips the
lookup entirely — and then nothing distinguishes your render from Argo CD's,
so do not set it on a chart Argo CD deploys. `argocd` mode asks the same
question in reverse and carries the same requirement.

All three modes are exercised against a live kind cluster by
`scripts/e2e_kubernetes.sh` (see "What is tested" below).

Each release tag publishes this chart to `oci://ghcr.io/veridor-authz/charts`
and the `ghcr.io/veridor-authz/veridor` image. To run from the repository
instead, package the chart yourself (`helm package deploy/helm/veridor-gate`)
and build the image from the repository's `Dockerfile`, then set
`image.repository` / `image.tag`. A chart the release workflow publishes pins
`image.digest` to its own image; to run a different tag with it, see "Image
and command".

## Quick start

```yaml
# values.yaml
hook:
  mode: argocd
target:
  baseUrl: http://invoices-api.shop.svc.cluster.local:8080
secretEnv:
  - name: VERIDOR_OWNER_TOKEN
    secretName: invoices-gate-credentials
    key: owner-token
  - name: VERIDOR_OUTSIDER_TOKEN
    secretName: invoices-gate-credentials
    key: outsider-token
config:
  version: 1
  target:
    base_url: http://invoices-api.shop.svc.cluster.local:8080
  identities:
    invoice_owner:
      headers: {Authorization: "Bearer ${VERIDOR_OWNER_TOKEN}"}
      marker: vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1
    other_tenant:
      headers: {Authorization: "Bearer ${VERIDOR_OUTSIDER_TOKEN}"}
      marker: vdr-Bq3Wm8Ke5Tz1Yx7Rn2Hd4Vs6
      marker_probe: {method: GET, path: /api/invoices/inv-200}
    anonymous:
      headers: {}
  checks:
    - id: invoice-tenant-isolation
      request: {method: GET, path: /api/invoices/inv-100}
      expect:
        invoice_owner: {status: [200], contains_marker: invoice_owner}
        other_tenant: {status: [404], excludes_marker: invoice_owner}
        anonymous: {status: [401]}
```

`other_tenant`'s `marker` and `marker_probe` name something that identity
is served (its own invoice, `inv-200`), which proves its credential is live.
Without them, a target that answers an unknown token with the same `404` it
gives the cross-tenant request (the repository's demo API does) leaves that
denial unproven, and with `gate.requireComplete: true` the gate exits 3,
`liveness_unproven`, against a fixed target. Measured with the chart's own
arguments against `scripts/demo_server.py`: without the two lines, fixed exit
3 and vulnerable exit 1; with them, fixed exit 0 and vulnerable exit 1.

For Argo CD see [`deploy/argocd/`](../../argocd/README.md); for a canary gate
with Argo Rollouts see [`deploy/argo-rollouts/`](../../argo-rollouts/README.md).

## Exit codes

| Exit | Meaning | Job |
|---|---|---|
| 0 | the gate passed | Complete |
| 1 | the gate failed on findings | Failed |
| 2 | configuration refused (bad configuration, an unset credential variable, an unknown flag) | Failed |
| 3 | the gate passed on findings but something went unmeasured | Failed |
| 70 | internal error | Failed |

`backoffLimit` is 0 and not configurable: a retried gate reports its luckiest
attempt. In Argo CD (each sync from its own Job) and Helm every non-zero exit
fails the sync or the release alike; read the Job log to tell them apart.

**Exit 3.** `gate.requireComplete: true` (the default, as in the GitHub
Action) passes `--require-complete`, so an unmeasured run fails the Job: a
probe that went unanswered (a rate limit, a 5xx, a timeout) exits 3, and so
does `liveness_unproven`: a denial-only expectation, in a check or a
sequence assert step, by an identity that presents a credential, where some
identity was served in the same check or sequence, that nothing else in the
run proved live (a 2xx it drew on a request where an identity with no
credential, or the fabricated credential, was refused; or its
`marker_probe`; for a session, either one only under the same login and
session cookie value), and that did not establish who was denied, because a
fabricated credential received the same denial, failed, or drew neither a
refusal nor a success, or none was sent to compare with. One is sent only
with GET, HEAD and OPTIONS, and only when an identity declares a credential
header to shape it on; never with a write, which can change state, nor
inside a sequence. A check where every identity is refused is not judged.
Such a denial may be the answer to a dead credential; the Job log names the
identity and says what would prove it. Usually that is "Give the identity a
marker_probe": add a `marker` and a `marker_probe` for it, as the quick
start does for `other_tenant`, or a check where that identity is served and
the fabricated credential or an identity with no credential is refused on
the same request: a 2xx on a route that serves every caller proves nothing.
For one with `"reestablish": "check"` a `marker_probe` proves only the first
login, so use `"reestablish": "run"` or show it served in the same sequence,
and one whose session cookie the target replaced needs a 2xx sent after the
change. Liveness proof is point-in-time: the `marker_probe` runs once,
before the first check, so a credential revoked later in the run without
anything Veridor sees changing (a token the target stops accepting, a
session revoked server-side while its cookie keeps its value) is not
detected, and its denials pass. Set
`gate.requireComplete` to `false` to let a partially measured run pass.
Veridor still exits 3 without the flag when not one probe was answered
(measured against an unresolvable cluster DNS name), and
`gate.requireCleanTeardown: true` adds exit 3 for a sequence teardown that
did not complete. Every reason code, with the flag that makes it exit 3, is in
the gate reason table of
[`docs/report-formats.md`](../../../docs/report-formats.md). The only way to
pass an unmeasured run is through these Veridor flags: the chart never masks
an exit code.

`gate.failOn: none` is Veridor's report-only mode and never fails on findings
(measured: a vulnerable target exits 0). It does not switch off
`--require-complete`: with the default `gate.requireComplete: true`, a run
that answered nothing still exits 3. Only `failOn: none` together with
`requireComplete: false` exits 0 when nothing answered.

A Complete Job means Veridor exited 0: nothing the selected gate
(`gate.failOn`, `gate.requireComplete`, `gate.requireCleanTeardown`) selects
was present. It does not mean every declared expectation held: a finding
`gate.failOn` does not select leaves the Job Complete (under `none`, every
finding: measured above, a vulnerable target exits 0), and so does an
unanswered probe with `gate.requireComplete: false`. The summary line in the
Job log still counts them. Nor is a Complete Job evidence that authorization
is enforced beyond the requests sent.

## hook.mode helm: what the gate probes

The gate probes whatever `target.baseUrl` routes to when Helm starts the
hook. Helm starts `post-install` and `post-upgrade` hooks as soon as it has
applied the manifests unless it waits first: Helm 4's default is
`--wait=hookOnly`, which waits for the hooks only, and Helm 3 waits for
nothing without `--wait`. The previous version's pods are still serving
then. A Deployment's `RollingUpdate`, the default, keeps them Ready and
routed until the new ones are Ready. `strategy: Recreate` does not help
here: it removes the old pod before it starts the new one, but the hook
starts first, while the old pod is terminating and, like any process that
does not stop on SIGTERM, still answering (measured below: every gate
request of 2 upgrades answered by the replaced pod). So under Helm's
defaults an upgrade gates the version it is replacing: `--wait-for-target`
returns at once, because the old pods accept the connection, and the gate
passes or fails the release on them.

Waiting is not enough either. With `--wait` or `--rollback-on-failure` Helm
runs the hook once the rollout is complete, and the pod it replaced can still
be terminating and answering then. In every `RollingUpdate` run below with
a 15 s readiness delay, aimed at the app's own Service, the replaced pod
answered some of the gate's requests (unless the app closed its listener on
SIGTERM). The gate passed a vulnerable version in 1 of 3 runs with `--wait`
(0 s delay) and 2 of 6 with `--rollback-on-failure` (15 s).

Use it this way, the way measured correct:

1. **The gate is a dependency of your app's chart**, so the hook runs in the
   release that rolls out the app, and a failed gate fails that release. A
   gate installed as its own release fails and rolls back only itself.
2. **`target.baseUrl` reaches only the pods this release rolled out.** A
   Service that selects this release revision's pods does that: give the
   pod template a label with the revision, and the Service the same
   selector. Keep the label out of the Deployment's `spec.selector`, which
   cannot change. This recipe is for the Helm CLI only: `.Release.Revision`
   changes with `helm install` and `helm upgrade`, and `helm template`
   renders it as `1` every time. Argo CD renders charts with `helm
   template`, so there every pod carries `"1"` and the Service selects the
   old pods with the new; see "Under Argo CD and `helm template`" below.

   ```yaml
   # your chart, templates/deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: invoices-api
   spec:
     selector:
       matchLabels:
         app: invoices-api
     template:
       metadata:
         labels:
           app: invoices-api
           example.com/release-revision: {{ .Release.Revision | quote }}
       spec:
         containers:
           - name: api
             image: {{ .Values.image | quote }}
             ports:
               - name: http
                 containerPort: 8080
   ---
   # your chart, templates/gate-service.yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: invoices-api-this-revision
   spec:
     selector:
       app: invoices-api
       example.com/release-revision: {{ .Release.Revision | quote }}
     ports:
       - port: 8080
         targetPort: http
   ```

   ```yaml
   # your chart, values.yaml
   veridor-gate:
     hook:
       mode: helm
     target:
       baseUrl: http://invoices-api-this-revision.shop.svc.cluster.local:8080
   ```

   Installed with `helm upgrade`, no pod of an earlier revision carries the
   label, so none can answer the gate however long it takes to stop. The
   label changes the pod template on every upgrade, so every `helm upgrade`
   rolls the pods; a rollback re-applies the earlier revision's label and
   selector together. The other way measured correct together with step 3
   is `strategy: Recreate` on the app's Deployment, aimed at its own
   Service: with `--rollback-on-failure` Helm waits for the rollout, and
   Recreate's old pods are gone before the new one starts, at the cost of a
   gap in service on every upgrade. Without step 3 Recreate passed the
   vulnerable version (above).
3. **Install and upgrade with `--rollback-on-failure`** (Helm 4; Helm 3's
   `--atomic` is the same option and was not measured):

   ```sh
   helm upgrade --install shop ./shop --namespace shop --rollback-on-failure --timeout 10m
   ```

   Helm then waits for the release's resources before it runs the hooks
   (`--wait` defaults to `watcher` with it), and when the gate fails it rolls
   the release back to the previous revision and exits non-zero. Without it a
   failed gate leaves the release `failed` and the new version serving.

Measured on kind with Helm 4.2.2, 2026-09-24: the gate as a dependency of an
app chart whose Deployment (one replica) runs `scripts/demo_server.py` and
logs every request with the pod that answered it, upgraded from a fixed
version to a vulnerable one. "Passed" counts vulnerable upgrades the gate let
through; the delay is how long the new pod took to turn Ready; "rolled back"
is `deployed (Rollback to N)` with an outsider's request, once the rollout
settled, answered by the fixed version.

| Helm flags | app Deployment (new pod Ready after) | gate aimed at | vulnerable upgrades passed | gate requests the replaced pod answered | fixed upgrades `deployed` | after a failed gate |
|---|---|---|---|---|---|---|
| none (the defaults) | `RollingUpdate` (0 s) | the app's Service | **2 of 2** | 10 of 10 | not run | none failed; the vulnerable version took all traffic |
| `--wait` | `RollingUpdate` (0 s) | the app's Service | **1 of 3** | 5 of 15 | 3 of 3 | `failed`, the vulnerable version serving |
| `--wait=legacy` | `RollingUpdate` (0 s) | the app's Service | 0 of 3 | 0 of 15 | 3 of 3 | `failed`, the vulnerable version serving |
| `--rollback-on-failure` | `RollingUpdate` (0 s) | the app's Service | 0 of 5 | 0 of 25 | 5 of 5 | rolled back, the fixed version serving |
| `--rollback-on-failure` | `RollingUpdate` (15 s) | the app's Service | **2 of 6** | 15 of 30 | 3 of 3 | rolled back |
| `--rollback-on-failure` | `RollingUpdate`, `minReadySeconds: 10` (0 s) | the app's Service | 0 of 2 | 0 of 10 | not run | rolled back |
| `--rollback-on-failure` | `RollingUpdate`, `minReadySeconds: 10` (15 s) | the app's Service | 0 of 3 | 0 of 15 | not run | rolled back |
| `--rollback-on-failure` | `RollingUpdate` (15 s); the app closes its listener on SIGTERM | the app's Service | 0 of 3 | 0 of 14 | **0 of 3**: a probe refused, exit 3, rolled back | rolled back |
| `--rollback-on-failure` | `Recreate` (15 s) | the app's Service | 0 of 3 | 0 of 15 | 3 of 3 | rolled back |
| none (the defaults) | `Recreate` (5 s) | the app's Service | **2 of 2** | 10 of 10 | 0 of 1 (its gate failed: the pod being replaced was the vulnerable one) | none failed; the vulnerable version took all traffic |
| none (the defaults) | `RollingUpdate` (15 s) | a Service of this revision's pods | 0 of 2 (the gate waited 15 s for the new pod) | 0 of 10 | not run | `failed`, the vulnerable version serving |
| `--rollback-on-failure` | `RollingUpdate` (15 s) | a Service of this revision's pods | 0 of 4 | 0 of 20 | 4 of 4 | rolled back, the fixed version serving |

A row with none passed and no request to the replaced pod does not show that
the race is closed: `--rollback-on-failure` aimed at the app's Service was
clean with a 0 s delay and raced with 15 s. `minReadySeconds` narrowed the
race in these runs (the replaced pod answered nothing in 3 runs with a 15 s
delay, where without it it answered in every one), but nothing in it takes
the terminating pod out of the Service before the hook starts, and 3 runs are
few. With `--rollback-on-failure`, only a Service of this revision's pods
and `Recreate` keep the replaced pod out of reach by construction. Under
Helm's default flags `Recreate` does not: the hook started before the old
pod was gone, and the old pod answered every request.

With a 15 s delay aimed at the app's Service the replaced pod answered some
of the gate's requests in each of the three fixed upgrades as well. The demo
API, like any process running as PID 1 without a SIGTERM handler, keeps
serving while its pod terminates, until it is killed 30 s later; that is the
window the replaced pod answered in. An app that closes its listener on
SIGTERM turns the race into a refused probe: no vulnerable version passed,
and every fixed one failed with exit 3 and was rolled back. Neither
`--wait-for-target` nor a readiness probe closes the window: the first waits
for any accepted connection, and the old pods accept at once; the second
decides when the NEW pod is routed.

The e2e's `helm` scenario runs the three steps above (upgrade to vulnerable:
exit non-zero, rolled back, the fixed version running; upgrade to fixed:
`deployed`) and, as its control, the same upgrade with Helm's default flags
aimed at the app's own Service, which passes the vulnerable version.

### Under Argo CD and `helm template`

The replaced pod can answer wherever the Job runs after a rollout:
`hook.mode none`, the Kustomize plain overlay and an Argo CD `PostSync` hook
alike. Argo CD creates a `PostSync` hook once the sync's resources are
Healthy, and a `RollingUpdate` Deployment is Healthy while the pod it
replaced is still terminating. The revision label of step 2 does not help
there, because Argo CD renders the app's chart with `helm template`, where
`.Release.Revision` is always `1`.

Set the gate's own `hook.mode` to `argocd` there, including when it is a
dependency of the app's chart. The chart refuses `hook.mode: helm` on a render
that reaches no cluster, which is how Argo CD renders: Argo CD would run it as
a `PostSync` hook with one fixed name, and reported syncs from the previous
sync's Job (see the top of this README).

Measured through Argo CD v3.5.3 on kind by the e2e's `argocd` scenario, with
the app on `RollingUpdate` (new pod Ready after 15 s, the replaced pod
serving for up to 90 s after it is told to stop), synced from fixed to
vulnerable. The first 5 runs, on 2026-09-25, had the gate Job under one
fixed name; the next 5, the same day, had it named per sync
(`generateName`).

| gate aimed at | replaced / new pod's label | the gate's Service lists the replaced pod after the sync | gate requests the replaced pod answered | the gate on the vulnerable version |
|---|---|---|---|---|
| a Service on the step 2 revision label, first 5 runs | `"1"` / `"1"`, 5 of 5 | yes, 5 of 5 | 13 of 25 (5, 5, 3, 0 and 0 per run) | **passed it in 2 of 5** (exit 0) |
| the same, next 5 runs | `"1"` / `"1"`, 5 of 5 | yes, 5 of 5 | 13 of 25 (5, 3, 0, 0 and 5) | **passed it in 3 of 5** (exit 0) |
| a Service on the pod-template label below, first 5 runs | different, 5 of 5 | no, 5 of 5 | 0 of 20 (4 runs; in the fifth the count was read before the gate had finished) | failed in the 4 runs whose exit code was read (exit 1); in the fifth the gate had not finished when it was read |
| the same, next 5 runs | different, 5 of 5 | no, 5 of 5 | 0 of 25 | failed, 5 of 5 (exit 1) |

In the first 5 runs the sync's own phase was not a result: in 4 of them
Argo CD reported a vulnerable sync `Succeeded` while its gate Job exited 1,
from the previous sync's Job. With the Job named per sync
([`deploy/argocd`](../../argocd/README.md), "Each sync reads its own Job")
the phase is a row again, and in the next 5 runs every sync's phase matched
its own gate Job's exit (35 of 35 syncs, 7 a run; the pod-template sync
`Failed` 5 of 5).

1. **Give the pod template a label that changes whenever the pod template
   does**: a hash of the rendered pod spec, kept out of the Deployment's
   `spec.selector`. It needs nothing from Helm's release state, so `helm
   template` renders it the same way the Helm CLI does (not run with the
   Helm CLI here).

   ```yaml
   # your chart, templates/_pod.tpl
   {{- define "invoices-api.pod" -}}
   spec:
     containers:
       - name: api
         image: {{ .Values.image | quote }}
         ports:
           - name: http
             containerPort: 8080
   {{- end }}
   {{- define "invoices-api.version" -}}
   {{- include "invoices-api.pod" . | sha256sum | trunc 16 | quote -}}
   {{- end }}
   ---
   # your chart, templates/deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: invoices-api
   spec:
     selector:
       matchLabels:
         app: invoices-api
     template:
       metadata:
         labels:
           app: invoices-api
           example.com/pod-template: {{ include "invoices-api.version" . }}
       {{- include "invoices-api.pod" . | nindent 4 }}
   ---
   # your chart, templates/gate-service.yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: invoices-api-this-version
   spec:
     selector:
       app: invoices-api
       example.com/pod-template: {{ include "invoices-api.version" . }}
     ports:
       - port: 8080
         targetPort: http
   ```

   The hash covers what is inside `invoices-api.pod`. Anything else that
   rolls the pods, such as a checksum annotation on the pod template, has to
   be hashed too, or a change to it alone rolls the pods under the same
   label and the replaced pod is back in the Service.
2. **Aim the gate at that Service**: `target.baseUrl:
   http://invoices-api-this-version.shop.svc.cluster.local:8080`.

`strategy: Recreate`, aimed at the app's own Service, also kept the replaced
pod out of reach through Argo CD (fixed to vulnerable: the gate exited 1 in
10 of 10 runs): Argo CD waits for the rollout before `PostSync`, and
Recreate's old pod is gone before the new one starts.

Either way a `PostSync` gate reports on a version that is already serving;
it does not stop it. To keep a failing version from taking the traffic,
gate an [Argo Rollouts](../../argo-rollouts/README.md) canary: Argo Rollouts
pins the canary Service's selector to the new ReplicaSet's
`rollouts-pod-template-hash` (measured by the e2e's `rollouts` scenario on
the stable Service), the analysis runs before promotion, and a failed one
aborts the rollout. A blue-green `previewService` selects the new
ReplicaSet the same way (not measured here).

## hook.mode none

Nothing fails when a plain Job fails; whatever applies it must wait for THIS
run's Job and read its outcome. It probes whatever `target.baseUrl` routes to
when it runs, so run it after the app's rollout and aim it at a Service of the
new pods only ("hook.mode helm: what the gate probes" says why and how: the
revision label when the app's chart is installed with `helm upgrade`, the
pod-template label when it is rendered with `helm template`). Each `helm
install` or `helm upgrade` is a new
revision, so a new Job (`-r<revision>`), and Helm removes the previous one;
the NOTES printed after the command give the wait below with the Job's name
filled in.

`helm template` always renders revision 1, so a Job rendered with it and
applied with `kubectl apply` is always `<release>-veridor-gate-r1`. Re-applied
unchanged it prints `unchanged` and runs nothing, and a `kubectl wait` reads
the previous run's result (measured on kind: after the target was redeployed
vulnerable, the re-apply printed `unchanged` and `kubectl wait
--for=condition=Complete` exited 0 at once, from the Job that had passed
before). Delete it first, check that `apply` created a new Job, and wait for
THAT Job's own outcome, `Complete` or `Failed`:

```sh
ns=shop
helm template gate ./veridor-gate --namespace "$ns" -f values.yaml > gate.yaml || exit 1
old="$(kubectl -n "$ns" get job gate-veridor-gate-r1 --ignore-not-found -o jsonpath='{.metadata.uid}')" || exit 1
kubectl -n "$ns" delete job gate-veridor-gate-r1 --ignore-not-found --wait=true || exit 1
kubectl -n "$ns" apply -f gate.yaml || exit 1
uid="$(kubectl -n "$ns" get job gate-veridor-gate-r1 -o jsonpath='{.metadata.uid}')" || exit 1
if [ -z "$uid" ] || [ "$uid" = "$old" ]; then echo "gate-veridor-gate-r1: apply created no new Job" >&2; exit 1; fi
while outcome="$(kubectl -n "$ns" get job gate-veridor-gate-r1 -o jsonpath='{.metadata.uid} {.status.conditions[?(@.status=="True")].type}')"; do
  case "$outcome " in "$uid "*) ;; *) outcome=""; break ;; esac
  case " $outcome " in *" Complete "* | *" Failed "*) break ;; esac
  sleep 5
done
kubectl -n "$ns" logs job/gate-veridor-gate-r1
case " $outcome " in *" Complete "*) true ;; *) false ;; esac
```

The last line's exit status is the gate: 0 only when the Job this run
created completed, 1 as soon as it is `Failed` (not when a timeout runs out),
and 1 when the Job cannot be read. The block checks every step itself and
does not depend on `set -e`: a failed render, read, delete or apply exits 1
on the spot, and so does an `apply` that created no new Job (the uid is
unchanged or missing). The previous version of this block had no step checks,
and under plain `sh` an identity that may not delete Jobs got `Forbidden` from
the delete, `unchanged` from the apply, and exit 0 from the previous run's
Job against a target that had since turned vulnerable (measured on kind). A
`helm template` that refused the values fell through the same way: it left
`gate.yaml` empty, `apply` failed, and the loop read the previous Job. Run
the block as a script or as the last lines of a CI step; its `exit 1` would
also close an interactive shell.

Measured on kind by the e2e's `plain` scenario, which extracts this block
(with `ns` set to its namespace) and runs it under `sh` against one target
switched fixed, then vulnerable: exit 0; as an identity that may create but
not delete Jobs, exit 1 with the previous Job left in place (its control, the
previous block under that identity, exits 0 on that stale Job); as the
cluster admin, a new Job, `Failed`, exit 1. The step checks and the uid
binding are also run against a stub `kubectl` by `tests/test_helm_chart.py`.
The Kustomize overlay has the same flow
([`deploy/kustomize/veridor-gate`](../../kustomize/veridor-gate/README.md)).

## Waiting for the target

`gate.waitForTargetSeconds` (default `60`) passes `--wait-for-target`: before
its first request Veridor tries a plain TCP connection to the target's host
and port once a second, until one is accepted or the time is up, and then runs
as usual. One line in the Job log says which it was. It never changes a
verdict: a target that never accepts is measured by the probes' own transport
errors, which with `gate.requireComplete: true` is exit 3.

It does not make a gate reach the new version. While a previous version's
pods are routed, one of them accepts the connection at once (measured: 0 s,
under a `RollingUpdate` Helm upgrade), and the gate measures that version;
"hook.mode helm: what the gate probes" says how to aim it at the new pods.

It is on by default because of a race in the PostSync path. Argo CD creates
the hook Job once every Sync-phase resource is Healthy, which can be the same
second the new pod turns Ready, before the Service routes to it. Probes sent
in that window are refused and the gate exits 3 about a version it never
reached. `0` turns the wait off (no flag is passed); keep the value well under
`job.activeDeadlineSeconds`. An accepted connection means the port is open,
not that the application behind it is ready, so a readiness probe that means
"serving" is still worth having.

## Credentials

Credentials reach the pod only as environment variables from existing
Secrets:

```yaml
secretEnv:
  - {name: VERIDOR_OWNER_TOKEN, secretName: invoices-gate-credentials, key: owner-token}
```

renders `env: [{name: VERIDOR_OWNER_TOKEN, valueFrom: {secretKeyRef: {name:
invoices-gate-credentials, key: owner-token, optional: true}}}]`, and the
configuration refers to it as `${VERIDOR_OWNER_TOKEN}`. `optional: true` is
deliberate: a missing Secret or key leaves the variable unset and Veridor
refuses the configuration at once (exit 2, naming the variable). Marked
required, the pod would instead wait in `CreateContainerConfigError` until
`job.activeDeadlineSeconds`. Either way the Job fails.

The render **fails** -- nothing is produced -- when the `config` value holds a
literal credential this rule recognises. The rule is the one `veridor capsule`
applies before it publishes anything (`capsule.literal_credentials`), applied
to the whole configuration object:

* every value in any `headers` map (the key in any case: `Headers` too), and
  every session `inject` header value, must be only `${NAME}` references, or
  one auth-scheme word and one reference (`Bearer ${VERIDOR_OWNER_TOKEN}`).
  `${capture.NAME}` counts as a reference.
  A `Cookie` header is read one cookie at a time, so `sid=${VERIDOR_SID}`
  renders and `sid=${VERIDOR_SID}; theme=dark` does not. A header that is not
  a credential (`X-Tenant-Id`, `Accept`) can be listed in
  `allowLiteralHeaders`; a name that looks like a credential (`auth`,
  `cookie`, `token`, `secret`, `key`, `session`, `passw`, `credential`) cannot
  be listed.
* every string or number anywhere beneath a credential-named key, in a list
  (`"password": ["..."]`) or an object (`"password": {"value": "..."}`, Okta's
  `credentials.password.value`) at any depth, must be references only:
  `x-${NAME}` is refused. Directly under such a key, `type`, `temporary`,
  `username`, `user`, `email`, `id` and `name` describe the credential rather
  than hold it and are read by the ordinary rules, so Keycloak's `credentials:
  [{type: password, value: "${NAME}", temporary: false}]` renders; any other
  key there, `value` or `note` alike, is held to the rule. An object with a
  `value` and a `name`, `key`, `field` or `type` holding a credential name
  (`{name: password, value: ...}`, Keycloak's `{type: password, value: ...}`)
  is read the same way: its `value` must be references only. A key is
  credential-named, in any case, when it ends in `password`, `passwd`,
  `passphrase`, `secret`, `token`, `jwt`, `credential(s)`, `api_key`,
  `private_key`, `secret_key`, `access_key`, `passcode`, `pin_code`,
  `otp_code`, `mfa_code`, `verification_code` or `client_assertion` (with
  `_`, `-` or nothing between the two words), with or without a separator
  before that word: `access_token`, `accessToken`, `refreshToken`,
  `clientSecret`, `apiKey`, `aws_secret_access_key`, `mfaCode`. `password` also counts followed by a digit or a
  confirmation word (`password1`, `new_password2`, `password_confirmation`,
  `passwordConfirm`, `password_again`, `password_repeat`), and so do
  `passwort`, `kennwort`, `contrasena` or `contraseña` and `mot_de_passe` (or
  `motdepasse`) at the end of a key. `İ` and `ı` read as `i`, `ſ` as `s` and
  the Kelvin sign `K` as `k` in every name matched here (`apİ_key` counts),
  including their percent-escapes; they never make a key a descriptor or a
  header a `Cookie`. Go and Python related these four to ASCII letters
  differently, and the chart rendered `apİ_key` holding a literal that the
  capsule refused (measured). The short words `pass`, `pwd`, `senha`, `pin`,
  `otp`, `totp` and `hotp` count only as a word of their own: the whole key,
  or after `_`, `.` or `-` (`pass`, `user_pass`, `db-pwd`, `senha`,
  `user_senha`, `card_pin`; not `bypass`, `compass`, `resenha`, `spin` or
  `laptop`), and `pass`, `pwd`, `pin`, `otp` and `totp` also capitalised in
  camelCase (`userPass`, `dbPwd`, `userPin`, `smsOtp`). `userpass`, `userpwd`, `dbpass` and `adminpwd` count
  as whole keys. The last `[segment]` of a form name such as `user[password]`
  counts too. Because the rule is about names, a non-secret under such a name
  is refused as well (`pageToken` holding a literal cursor must be a
  reference), and a secret under any other name is not: `superuserpass`,
  `sessionId` as a JSON key, and passwords in languages other than those
  above. Under a `capture` map a credential-named
  key is a capture name, not a credential, only when its value is an
  extractor: an object whose `from` is `cookie`, `header`, `json_pointer` or
  `html_meta`, or a sequence capture's `$.path` or `header:NAME`. Any other
  value there (`{"capture": {"password": "..."}}` in a request body) is held
  to the rule.
* every string is read for `user:password@` in a URL, for credential-named
  parameters in query strings, `;` path parameters and form bodies
  (`password=...` in a login `body`, `?api_key=...` or `?accessToken=...` in a
  path; plus- and percent-decoded), and for JSON text, which is parsed and
  held to the same rules. Python's parser, the capsule's, also reads `NaN`,
  `Infinity`, `-Infinity` and numbers of any size, which Go's refuses, so JSON
  text Go's parser refuses is parsed again with those and every other number
  outside a string read as 0 (string literals are kept as written); text that
  still does not parse is skipped, as the capsule skips text Python cannot
  parse. As a parameter, and only there, a few more whole names count: `key`
  (Google APIs take an API key as `?key=`), `auth` (Firebase), `code` (Azure
  Functions keys, OAuth codes), `sig` and `signature` (Azure SAS and other
  signed URLs), `sessionid`, `session_id`, `jsessionid` and `sid`. That
  refuses a literal that is not a secret under those names too, such as an
  object key in `?key=reports/q1.pdf` or a country in `?code=US`: the rule
  cannot tell them from a Google API key or a function key, so such a value
  has to be a `${NAME}` reference as well. They are matched as the whole
  parameter name only: `keyword=`, `codec=` and `a[key]=` are not refused, and
  neither is a JSON key named `key` or `code`.
* `target.baseUrl` is passed as `--base-url`, which Veridor applies after it
  expands the configuration, and it lands in the Job's arguments. A literal
  credential-named parameter in it (`;token=...`, `?api_key=...`,
  `;jsessionid=...`, `?key=...`) is refused, and so is any `${NAME}`, which
  would be sent as written.
* `target.baseUrl` and `config.target.base_url` must not carry
  `user:password@` at all, references included: Veridor refuses credentials
  in the target URL at run time, so the chart refuses them at render.
* every `${NAME}` outside `sequences` must be provided by a `secretEnv` entry
  (names inside `sequences` may be capture references, resolved at run time).

The message names the offending path and never prints the value.
`tests/fixtures/credential_parity.json` holds cases that both this chart and
`veridor capsule` decide, and `tests/test_credential_parity.py` checks that
they agree. The two deliberate differences (here a literal in ANY header
needs `allowLiteralHeaders`, and the target URL rule above) are cases in that
file with their reasons; the one difference known to need input no
configuration should contain (a non-ASCII percent-escape) is listed in the
docstring of `tests/test_credential_parity.py`, and in it the chart refuses
what the capsule accepts. Whitespace is read the same way by both: in the
patterns, only tab, line feed, form feed, carriage return and space (Go's
`\s`), and when trimming, what Go's `strings.TrimSpace` trims. Python's wider
`\s` had the capsule refuse `a=1&<U+00A0>key=...`, which the chart rendered,
so a name preceded by U+00A0 or U+000B is now read as part of the name by
both. The `target.baseUrl` rules are
the chart's alone: a capsule has no `--base-url`. A ConfigMap supplied through
`existingConfigMap.name` is not read by the chart at all, so none of this
applies to it.

## Target acknowledgement

`veridor run` has no target acknowledgement, and this chart passes none.
Measured: `veridor run --acknowledge-target ...` is refused by the CLI parser
(exit 2, unrecognized argument), and `veridor run` against a cluster DNS name
(`*.svc.cluster.local`) proceeds without one. The acknowledgement
(`--acknowledge-target 'I am authorized to test HOST:PORT'`) belongs to
`veridor map`, which fans out over an OpenAPI specification. This chart runs
`run` only; `map` drift mode is not implemented in chart 0.1.0.

## Image and command

`image.command` defaults to `["veridor"]` and is always set on the container,
so the chart does not depend on the image's `ENTRYPOINT`: it works with an
image whose entrypoint is `veridor` and with an image that only has Veridor on
`PATH` (both measured: the release `Dockerfile`, and the kind demo image,
which has no entrypoint). The chart's arguments follow the command. The image tag
defaults to the chart's `appVersion`; `image.digest` pins
`repository:tag@digest`.

With a digest the kubelet pulls the digest and ignores the tag beside it
(measured on kind: a nonexistent tag with a real digest ran that digest's
image; the tag alone failed with `ErrImageNeverPull`). The chart the release
workflow publishes sets `image.digest` to its own release's image, the one
tagged `appVersion`, so `--set image.tag=<another tag>` on it alone would name
that tag in the manifest and run the release's image. The render refuses that: a
digest is used only with the tag it belongs to, `image.digestTag`, which
defaults to `appVersion`. To change the tag, either set `image.digest: ""` and
pull the tag by tag, or set `image.digest` to that tag's digest and
`image.digestTag` to the tag. Changing only `image.repository` keeps the
published digest, which is right for a mirror that preserves digests and
fails to pull from one that does not.

## Pod Security

The Job is written for the Pod Security Standards `restricted` profile:
`runAsNonRoot: true`, `runAsUser`/`runAsGroup` 10001 (the release image's
`veridor` user), `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation:
false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`,
`automountServiceAccountToken: false`, `enableServiceLinks: false`. The only
writable paths are `/work` (an `emptyDir`, or `output.existingClaim`) and
`/tmp` (an `emptyDir`). On a platform that assigns the uid itself (OpenShift
`restricted-v2`), set `podSecurityContext.runAsUser`, `runAsGroup` and
`fsGroup` to `null`; `runAsNonRoot` stays `true`.

## NetworkPolicy

`networkPolicy.enabled: true` renders a policy that selects the gate's pod,
allows no ingress, and allows egress only to `networkPolicy.targetPeers` on
`networkPolicy.targetPorts`, plus DNS. Name the target's pods and the port the
pods listen on (a policy sees pod IPs and ports, not the Service's).

The render refuses the values that would make a rule allow more than that. A
rule with no peers allows every destination and a port entry with no `port`
every port of its protocol (measured on kind: with `dns.peers: []` a pod that
is not DNS answered the gate's pod on 53/tcp, and with `targetPorts: [{}]` a
target peer answered on a port no entry named). So every
`targetPorts` and `dns.ports` entry needs a `port`, and with `dns.enabled`
`dns.peers` and `dns.ports` must not be empty (turn DNS off with
`dns.enabled: false` instead). The policy selects the pod by
`app.kubernetes.io/name`, `instance` and `component`, so `job.podLabels` may
not set any of them: an override replaced the pod's label and left the policy
selecting no pod (measured on kind: 0 pods selected, and the gate reached a
target the policy excluded). It is
only as good as your network plugin's enforcement. Measured on kind's default
plugin (kindnet with kube-network-policies): egress rules were not applied to
connections a pod made in its first seconds, and Veridor connects at once, so
there the policy did not constrain an undelayed gate. The e2e script's
NetworkPolicy rows therefore delay Veridor by 8 seconds (through
`image.command`) to test the rules themselves. Check your plugin before
relying on the policy.

## Keeping results

By default `/work` is an `emptyDir`: the run history, run JSON and SARIF
(`gate.sarif: true`) disappear with the pod, and the Job log is the record.
The log carries Veridor's summary, including its scope sentences, and stays
readable until `job.ttlSecondsAfterFinished` after the Job finished (3600 s
by default; the TTL controller deletes a hook Job too, measured), or, for a
Helm hook, until the next upgrade replaces it, whichever comes first. An Argo
CD sync never replaces an earlier sync's Job: each has a name of its own (a
passing one goes at once with `HookSucceeded`, a failing one with
`HookFailed`). Set `output.existingClaim` to a
PersistentVolumeClaim to keep the files (measured on kind's `local-path`
storage: `latest.json`, `runs/<id>.json` and `veridor.sarif` were readable
from a second pod after the Job completed).

When `job.activeDeadlineSeconds` expires, Kubernetes stops the pod and marks
the Job `Failed` with reason `DeadlineExceeded` (measured). What Veridor does
when it is stopped mid-run is in the guide's
[Exit codes](../../../docs/guide.md#exit-codes) section.

## Values

| Value | Default | Description |
|---|---|---|
| `hook.mode` | `""` | Required: `argocd`, `helm` or `none`. |
| `hook.argocd.phase` | `PostSync` | `argocd.argoproj.io/hook`. `PostSync` is the only value accepted. `PreSync` is refused: it runs before this chart's ConfigMap is applied. `Sync` is refused: Argo CD runs a Sync hook together with the apply of the application's manifests, not once they are Healthy, so the gate would probe whatever the Service still routes to, the version being replaced. Any other value (`SyncFail`, `Skip`, a different case) is refused too. |
| `hook.argocd.deletePolicy` | `BeforeHookCreation` | `argocd.argoproj.io/hook-delete-policy`: one or more of `BeforeHookCreation`, `HookSucceeded`, `HookFailed`. Each sync's Job has a name of its own (`generateName`), so `BeforeHookCreation` finds no earlier Job to delete: every Job and its log stay for `job.ttlSecondsAfterFinished` after it finished (measured: one Job per sync until then). `HookSucceeded` deletes a passing Job, and `HookFailed` a failing one with its log, as soon as Argo CD has recorded the result (measured with `HookSucceeded`: every sync reported from its own Job). |
| `hook.argocd.syncWave` | `""` | `argocd.argoproj.io/sync-wave` for the Job; empty = not set. |
| `hook.helm.events` | `post-install,post-upgrade` | `helm.sh/hook`. Must include both `post-install` and `post-upgrade`: Helm creates the Job only on the events listed, so a verb left out runs no gate and still reports the release `deployed` (measured: with `test` alone, `helm install` and `helm upgrade` created no Job and exited 0). `post-rollback` and `test` may be added: `test` also runs the gate under `helm test`, where the command's exit status is the gate and a failed test leaves the release `deployed` (measured). `pre-install`, `pre-upgrade` and `pre-rollback` are refused: they run before this chart's ConfigMap is created or updated (measured: a first install could not mount it and failed; an upgrade exited 0 having run the previous revision's configuration). |
| `hook.helm.deletePolicy` | `before-hook-creation` | `helm.sh/hook-delete-policy`. Must include `before-hook-creation` (`hook-succeeded` or `hook-failed` may be added): the Job keeps one name, so without it the next `helm upgrade` finds the Job an earlier run left and does not run the gate again (measured with `hook-failed`: the upgrade exited 0 on the install's Complete Job, no new run). |
| `hook.helm.allowRenderWithoutCluster` | `false` | Helm mode is for the Helm CLI, whose `helm install` and `helm upgrade` reach the cluster. A helm-mode render that reaches none is refused unless this is `true` (a boolean; the string `"true"` is refused): Argo CD renders that way, and runs the Job as a `PostSync` hook with one fixed name, from which Argo CD v3.5.3 reported syncs by the previous sync's Job (measured, see the top of this README). Set it to render helm mode with `helm template` or `--dry-run=client` for the Helm CLI; never under Argo CD, where `hook.mode` is `argocd`. |
| `hook.helm.weight` | `"0"` | `helm.sh/hook-weight`. |
| `image.repository` | `ghcr.io/veridor-authz/veridor` | Gate image, published by each release; see above. |
| `image.tag` | `""` | Empty = the chart's `appVersion`. With `image.digest` set it must equal `image.digestTag` (see "Image and command"). |
| `image.digest` | `""` | `sha256:...`; referenced as `repository:tag@digest`, and the digest is what is pulled. The release workflow sets it to that release's image digest in the chart it publishes. |
| `image.digestTag` | `""` | The tag `image.digest` is the digest of; empty = the chart's `appVersion`. With a digest set, a different tag is refused. |
| `image.pullPolicy` | `IfNotPresent` | |
| `image.command` | `["veridor"]` | Container command; the chart's arguments follow it. |
| `imagePullSecrets` | `[]` | `[{name: ...}]`. |
| `config` | `{}` | The Veridor configuration object, rendered to JSON in a ConfigMap and mounted at `/config/veridor.json`. Subject to the credential rules above. |
| `existingConfigMap.name` | `""` | Use this ConfigMap instead of `config` (not both). Not inspected by the chart. |
| `existingConfigMap.key` | `veridor.json` | Key in that ConfigMap holding the configuration. |
| `target.baseUrl` | `""` | `--base-url`. Required unless `config.target.base_url` is set; `config.target` must still be an object (`target: {}` is enough). No `${NAME}` and no literal credential parameter (see "Credentials"). |
| `secretEnv` | `[]` | `[{name, secretName, key}]`: environment variables from existing Secrets. The only way a credential reaches the pod. |
| `allowLiteralHeaders` | `[]` | Header names (case-insensitive) that may carry a literal because they are not credentials. |
| `gate.failOn` | `new+confirmed` | `--fail-on`: `new+confirmed`, `new`, `any`, `confirmed`, `none`. No `--baseline` is passed, so every finding counts as new unless `extraArgs` adds one. |
| `gate.requireComplete` | `true` | `--require-complete`; see "Exit 3". |
| `gate.requireCleanTeardown` | `false` | `--require-clean-teardown`: exit 3 when a sequence teardown did not complete. |
| `gate.readOnly` | `false` | `--read-only`: refuse (exit 2) a configuration that can send anything but GET, HEAD or OPTIONS. |
| `gate.proveLiveness` | `true` | `false` passes `--no-prove-liveness`. |
| `gate.sarif` | `false` | `--sarif <output.dir>/veridor.sarif`. |
| `gate.waitForTargetSeconds` | `60` | `--wait-for-target`: seconds to wait, before the first request, for the target's port to accept a TCP connection; `0` = no flag. See "Waiting for the target". |
| `extraArgs` | `[]` | Appended verbatim after the chart's arguments. An element that starts with a prefix of a flag the chart passes from a value (`--config`, `--output-dir`, `--fail-on`, `--base-url`, `--require-complete`, `--require-clean-teardown`, `--read-only`, `--no-prove-liveness`, `--sarif`, `--wait-for-target`), with or without `=value`, is refused, and so are `--help` and every single-dash token with an `h` in it (`-h`, `-hx`): Veridor reads an unambiguous prefix of a flag as the flag and keeps its last value, so `--base-u URL` replaced `target.baseUrl` without its credential check (measured), and `--help`, `-h` and a cluster that starts with it (`-hx`, measured) exit 0 having run nothing. Set the value instead. |
| `output.dir` | `/work/.veridor` | `--output-dir`; must be under `/work`. |
| `output.existingClaim` | `""` | Mount this PersistentVolumeClaim at `/work` instead of an `emptyDir`. |
| `output.sizeLimit` | `128Mi` | `sizeLimit` of the `/work` `emptyDir`. |
| `job.activeDeadlineSeconds` | `600` | Deadline for the whole Job. |
| `job.ttlSecondsAfterFinished` | `3600` | Seconds a finished Job and its log are kept; `null` = never deleted. Keep it longer than your hook needs to read the result. With `hook.mode: argocd`, where every sync adds a Job, `null` is refused unless `hook.argocd.deletePolicy` lists both `HookSucceeded` and `HookFailed`. |
| `job.annotations` | `{}` | Extra Job annotations. May not set any key under `helm.sh/` or `argocd.argoproj.io/`. A hook key (`helm.sh/hook*`, `argocd.argoproj.io/hook*`, `argocd.argoproj.io/sync-wave`) is rendered after the hook annotations the chart checks, and Helm keeps the last of two equal keys (measured: `helm.sh/hook: test` there made install and upgrade run no gate); use `hook.*`. The others decide when the Job is kept or deleted (measured on kind with `hook.mode: none`: with `helm.sh/resource-policy: keep`, `helm uninstall` kept the passing Job, and after the target turned vulnerable `helm install` adopted it, still `Complete`, ran no gate, and the NOTES wait exited 0). |
| `job.labels` | `{}` | Extra Job labels. |
| `job.podAnnotations` | `{}` | Extra pod annotations. |
| `job.podLabels` | `{}` | Extra pod labels. May not set `app.kubernetes.io/name`, `instance` or `component`, the NetworkPolicy's selector. |
| `podSecurityContext.runAsUser` | `10001` | Pod and container uid; `null` omits it. |
| `podSecurityContext.runAsGroup` | `10001` | Pod and container gid; `null` omits it. |
| `podSecurityContext.fsGroup` | `10001` | Pod `fsGroup`, so `output.existingClaim` is writable; `null` omits it. |
| `resources.requests.cpu` | `100m` | |
| `resources.requests.memory` | `128Mi` | |
| `resources.limits.cpu` | `"1"` | |
| `resources.limits.memory` | `512Mi` | |
| `serviceAccount.create` | `false` | Create a dedicated ServiceAccount (`automountServiceAccountToken: false`). |
| `serviceAccount.name` | `""` | With `create`: the name to create (empty = fullname). Without: an existing account (empty = `default`). |
| `serviceAccount.annotations` | `{}` | Annotations for the created ServiceAccount. |
| `networkPolicy.enabled` | `false` | Render the egress-only NetworkPolicy. |
| `networkPolicy.targetPeers` | `[]` | NetworkPolicyPeer objects the gate may reach. Required when enabled. |
| `networkPolicy.targetPorts` | `[]` | NetworkPolicyPort objects (the pods' port). Required when enabled; each needs a `port`. |
| `networkPolicy.dns.enabled` | `true` | Also allow DNS. |
| `networkPolicy.dns.peers` | kube-dns in kube-system | Where DNS is. Must not be empty while `dns.enabled`. |
| `networkPolicy.dns.ports` | 53/UDP, 53/TCP | Must not be empty while `dns.enabled`; each needs a `port`. |
| `nodeSelector` | `{}` | |
| `tolerations` | `[]` | |
| `affinity` | `{}` | |
| `nameOverride` | `""` | |
| `fullnameOverride` | `""` | |

`values.schema.json` rejects unknown keys, so a misspelt value fails the
render instead of being ignored. The hook values are refused by the templates
as well, for a render that skips the schema (`--skip-schema-validation`, or
Argo CD's `spec.source.helm.skipSchemaValidation`). There they are read the
way the tool reads them: Helm lower-cases and trims each comma-separated hook
event and delete policy, so `post-install,PRE-UPGRADE` is refused as a
pre-upgrade hook; Argo CD trims each value and matches it case-sensitively,
so ` PreSync` is refused as PreSync and `postsync` as not `PostSync`. The Job
is rendered with the values in that normalised form.

## What is tested

* `tests/test_helm_chart.py` renders the chart with `helm template` and checks
  the hook annotations per mode, the Pod Security fields, `backoffLimit: 0`,
  the credential refusals (and that they never echo the value), that the
  ConfigMap loads through Veridor's own configuration loader, and that the
  Job's arguments parse with Veridor's own CLI parser. It skips when `helm` is
  missing unless `VERIDOR_REQUIRE_HELM=1`.
* `tests/test_credential_parity.py` renders every case in
  `tests/fixtures/credential_parity.json` and compares the verdict with
  `capsule.literal_credentials`, with a mutation control on each side.
* `helm lint` is not a substitute for rendering: measured with helm 4.2, lint
  runs templates in a mode where `fail` only logs, so it passes a chart whose
  render this chart refuses. Render with `helm template` to check values
  (in helm mode with `--set hook.helm.allowRenderWithoutCluster=true`).
* `scripts/e2e_kubernetes.sh` runs every mode on a kind cluster against a
  vulnerable and a fixed demo target, in namespaces that enforce the
  `restricted` profile, and prints expected against observed. Its `helm`
  scenario also runs the invocation "hook.mode helm: what the gate probes"
  documents, with its control, and its `argocd` scenario the pod-template
  label of "Under Argo CD and `helm template`", with the revision label as
  its control. The `argocd` scenario reads every sync's gate Job by the name
  that sync's `syncResult` records, checks it was created after the sync
  started and that no two syncs shared one, records the sync's phase against
  the Job's own exit, and runs `helm install` of the argocd-mode chart, which
  must be refused with no Job and no release, and an Application of the
  helm-mode chart, which Argo CD must fail to render (`ComparisonError`,
  naming the refusal).
