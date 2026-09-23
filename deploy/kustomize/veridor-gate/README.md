# veridor-gate (Kustomize)

The Veridor gate as Kustomize manifests, for clusters and GitOps setups that do
not use Helm. It is the same Job the [Helm chart](../../helm/veridor-gate/README.md)
renders: `veridor run` in a restricted pod, and the Job's exit code is the gate.
Exit 0 completes the Job; any other exit fails it. There is no wrapper script
and no `|| true`.

```
veridor run --config /config/veridor.json --output-dir /work/.veridor \
            --fail-on new+confirmed --require-complete --wait-for-target 60
```

**Not published as of 2026-11-04.** No `ghcr.io/veridor-authz/veridor` image exists in a public
registry, and there is no release tag to reference this directory by. Build
the image from the repository's `Dockerfile` and set it with `images:`; use a
copy of this directory (or, after the first release, a remote reference pinned
to its tag).

## Layout

| Path | What it is |
|---|---|
| `base/` | The Job, and a `configMapGenerator` for `veridor.json`. Not meant to be applied on its own. |
| `base/veridor.json` | An **example** configuration (the demo API's). Replace it. |
| `overlays/plain/` | A plain Job, for a pipeline that deletes the previous Job, applies, and waits for this run's outcome (see "Running the plain Job"). |
| `components/service-account/` | Optional: a dedicated ServiceAccount (token not mounted) instead of the namespace's `default`. |

There is no Argo CD overlay: with Argo CD, take the gate from the Helm chart
(see "No Argo CD overlay" below).

## Use it

Write your own overlay on top of `overlays/plain`:

```yaml
# kustomization.yaml
resources:
  - ../veridor-gate/overlays/plain
images:
  - name: ghcr.io/veridor-authz/veridor          # the placeholder in the base
    newName: registry.example.com/veridor
    newTag: 0.1.0
configMapGenerator:
  - name: veridor-gate-config
    behavior: replace
    files:
      - veridor.json                       # your configuration
patches:                                   # only to use another Secret name
  - target: {kind: Job, name: veridor-gate}
    patch: |-
      apiVersion: batch/v1
      kind: Job
      metadata:
        name: veridor-gate
      spec:
        template:
          spec:
            containers:
              - name: veridor
                env:
                  - name: VERIDOR_OWNER_TOKEN
                    valueFrom:
                      secretKeyRef: {name: invoices-gate-credentials, key: owner-token, optional: true}
                  - name: VERIDOR_OUTSIDER_TOKEN
                    valueFrom:
                      secretKeyRef: {name: invoices-gate-credentials, key: outsider-token, optional: true}
                  - name: VERIDOR_ADMIN_TOKEN
                    valueFrom:
                      secretKeyRef: {name: invoices-gate-credentials, key: admin-token, optional: true}
```

- **Target.** `target.base_url` in your `veridor.json`; in a cluster, usually a
  Service DNS name. To pass it as `--base-url` instead, append the two
  arguments to the container's `args` with a JSON patch.
- **Credentials.** Only from Secrets, one `env` entry per `${NAME}` your
  configuration references. The base declares `VERIDOR_OWNER_TOKEN`,
  `VERIDOR_OUTSIDER_TOKEN` and `VERIDOR_ADMIN_TOKEN` from the Secret
  `veridor-gate-credentials` because the example configuration uses them.
  Create that Secret with those keys and you need no patch. Entries merge
  by name, so a patch changes only the entries it lists: to read another
  Secret, list every variable, as above. Listing only `VERIDOR_OWNER_TOKEN`
  leaves the other two reading `veridor-gate-credentials`, and with only the
  new Secret created Veridor exits 2 ("environment variable
  'VERIDOR_OUTSIDER_TOKEN' is not set", measured). `tests/test_kustomize.py`
  builds this block.
  They are `optional: true`: a missing Secret or key leaves the variable unset
  and Veridor refuses the configuration (exit 2, naming the variable) instead
  of the pod waiting in `CreateContainerConfigError` until the deadline.
- **Waiting for the target.** `--wait-for-target 60` holds the first request
  until the target's port accepts a TCP connection, for at most 60 seconds, as
  the chart's `gate.waitForTargetSeconds` does by default: a Job started as
  soon as a rollout is complete can start before the Service routes to the pod
  that just turned Ready (measured with an Argo CD PostSync hook, below). It
  never changes a verdict. Patch the value to `"0"` to turn it off.
- **Other flags.** `--fail-on`, `--read-only`, `--baseline` and the rest go in
  the container's `args`; `veridor run --help` lists them.

### What Helm checks that Kustomize cannot

The chart refuses to render when the configuration carries a literal
credential its rule recognises (a header, a credential-named field, a
`password=` in a form body or query string, `user:password@` in a URL; the
chart README lists which names count), or when a `${NAME}` has no Secret
behind it. Kustomize has no render-time refusals, so none of
that is checked before your manifests are applied. Veridor still refuses an
unset or empty variable at run time (exit 2), but a literal credential in your
`veridor.json` would be stored in a ConfigMap. Keep credentials as `${NAME}`
references. To check a configuration in CI,
`veridor.capsule.literal_credentials(json.load(...))` returns the JSON path of
every literal credential it finds (the scan `veridor capsule` refuses on).

### Running the plain Job: delete, apply, wait for this run's outcome

A Job runs once. Re-applying an unchanged overlay prints
`job.batch/veridor-gate unchanged` and runs nothing, and a `kubectl wait`
after it reads the previous run's Job for as long as that Job exists
(`ttlSecondsAfterFinished`, 3600 s). Measured on kind: a gate that passed
against a fixed target was re-applied after the target was redeployed
vulnerable; `apply` printed `unchanged`, and `kubectl wait
--for=condition=Complete job/veridor-gate` exited 0 at once, reading the Job
that had completed before the target changed. The gate never ran against the
vulnerable version. After a change of configuration or image the re-apply is
refused instead (`field is immutable`): the generated ConfigMap's name carries
a hash of its content, so a changed configuration is a changed pod template.

So every run deletes the previous Job first, checks that `apply` created a
new one, and then waits for THAT Job's own outcome, `Complete` or `Failed`,
passing only on `Complete`:

```sh
old="$(kubectl get job veridor-gate --ignore-not-found -o jsonpath='{.metadata.uid}')" || exit 1
kubectl delete job veridor-gate --ignore-not-found --wait=true || exit 1
kubectl apply -k my-overlay/ || exit 1
uid="$(kubectl get job veridor-gate -o jsonpath='{.metadata.uid}')" || exit 1
if [ -z "$uid" ] || [ "$uid" = "$old" ]; then echo "veridor-gate: apply created no new Job" >&2; exit 1; fi
while outcome="$(kubectl get job veridor-gate -o jsonpath='{.metadata.uid} {.status.conditions[?(@.status=="True")].type}')"; do
  case "$outcome " in "$uid "*) ;; *) outcome=""; break ;; esac
  case " $outcome " in *" Complete "* | *" Failed "*) break ;; esac
  sleep 5
done
kubectl logs job/veridor-gate
case " $outcome " in *" Complete "*) true ;; *) false ;; esac
```

Run it once the app's new version is the only one `target.base_url`
reaches: see "The gate can reach the version being replaced" below. Run right
after `kubectl apply` of the app, it can probe the previous version.

The last line is the gate: its exit status is 0 only when the Job this run
created completed. The block checks every step itself and does not depend on
`set -e`: a failed read, delete or apply exits 1 on the spot, and so does an
`apply` that created no new Job (the Job's uid is unchanged or missing). That
matters when the delete is refused: measured on kind with an identity allowed
to create, patch and read Jobs but not delete them, the previous block (no step
checks, run under plain `sh`) printed the delete's `Forbidden`, then `apply`
printed `unchanged`, and the loop read the previous run's `Complete` and
exited 0 against a target that had since turned vulnerable. The wait reads
the Job's uid with its conditions, so a Job replaced under the same name
while it waits ends the loop with the last line failing. A failed gate ends
the wait as soon as Kubernetes marks the Job `Failed`, not when a timeout runs
out. If the Job cannot be read (deleted, or the API unreachable), the loop
ends with `outcome` empty and the last line fails. `activeDeadlineSeconds`
(600) bounds how long the Job, and so the loop, can run. The block is POSIX
`sh`; run it as a script or as the last lines of a CI step (its `exit 1`
would also close an interactive shell it was pasted into).

Measured on kind by the e2e's `kustomize` scenario, which extracts this block
from this README and runs it unchanged under `sh` (no `-e`) against one
overlay whose target changes underneath it: fixed target, exit 0; after the
target was redeployed vulnerable, run as an identity that cannot delete Jobs,
exit 1 with the previous run's Job left in place (its control, the previous
block under the same identity, exits 0 on that stale Job); run as the
cluster admin, a new Job, `Failed`, exit 1; fixed again, exit 0. A second
control runs a plain `apply` then `wait --for=condition=Complete` on the same
change and records the stale exit 0.

### The Job can start before the Service routes to the new pod

Measured on kind with this directory's former Argo CD overlay: Argo CD
created the `PostSync` Job in the same second the target's new pod turned
Ready (sampled once a second). In one of four runs of the e2e's fixed leg,
before the base waited for the target, the gate's first three probes were
refused (`Connection refused`), the next three were answered, and the gate
exited 3. It fails closed and says to re-run. A plain Job applied right
after `kubectl rollout status` meets the same window (not measured
separately); `--wait-for-target` is what covers it.

### The gate can reach the version being replaced

The opposite race fails open. The gate probes whatever `target.base_url`
routes to when it runs, and a pod being replaced can still answer after its
Deployment's rollout is complete: measured with Helm's equivalent wait and a
`RollingUpdate` app, the replaced pod answered gate requests after the wait,
and the gate passed a vulnerable version (the chart README's "hook.mode helm:
what the gate probes" has the runs). That holds for the plain Job run after
`kubectl rollout status` too (the same mechanism; not measured separately).
Point `target.base_url` at a Service
that selects only the new pods (a label that changes with every version, and
a Service with that selector), or run the app with `strategy: Recreate`.

## No Argo CD overlay

There is no `overlays/argocd`. It would be the Job as an Argo CD `PostSync`
hook under one fixed name, re-created on every sync by `BeforeHookCreation`.
With a fixed name Argo CD v3.5.3 reported syncs from the previous sync's Job
(measured with the Helm chart's Job named the same way: passing syncs
reported `Failed`, and in the e2e a vulnerable sync reported `Succeeded`
while its gate exited 1; an e2e leg of this overlay when it was tried reported
a passing sync `Failed`). A gate whose result can come from another run does
not gate, so the overlay is left out rather than documented.

Argo CD's remedy is `metadata.generateName`, which gives each sync's Job a
name of its own; the Helm chart renders it (its README, `hook.mode`).
Kustomize refuses it: `kubectl kustomize` (Kustomize v5.7.1) and the
Kustomize bundled in Argo CD v3.5.3 (v5.8.1) both stop with `missing
metadata.name` on a Job that has only `generateName`, in a base or after a
patch that removes the name (measured; `tests/test_kustomize.py` checks
kubectl's). A name that changes with the configuration would not help: a sync
that changes only the app leaves the gate's configuration, and so the name,
as it was.

With Argo CD, take the gate from the Helm chart. Argo CD renders the chart
itself, so you never run Helm, and your app can stay Kustomize:
[`deploy/argocd/application-example.yaml`](../../argocd/application-example.yaml)
is an Application with the app and the chart as its two sources. To keep a
failing version from taking the traffic, gate an Argo Rollouts canary
([`deploy/argo-rollouts`](../../argo-rollouts/README.md)), whose
AnalysisTemplate is plain YAML.

## The Job

Identical to the chart's with default values (`tests/test_kustomize.py`
renders both and compares every field of the Job spec except the pod
template's labels and the ConfigMap's name):

- `backoffLimit: 0`: never retried, because a retry reports the luckiest
  attempt. `activeDeadlineSeconds: 600`, `ttlSecondsAfterFinished: 3600`.
- Pod Security "restricted": `runAsNonRoot`, uid/gid/fsGroup 10001 (the
  release image's `veridor` user), `seccompProfile: RuntimeDefault`,
  `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
  `capabilities.drop: [ALL]`.
- `automountServiceAccountToken: false` (Veridor never calls the Kubernetes
  API), `enableServiceLinks: false`.
- `emptyDir` volumes at `/work` (run history, `--output-dir`) and `/tmp`; the
  configuration read-only at `/config/veridor.json`.

Not provided here: the chart's optional NetworkPolicy. Write your own, or use
the chart, whose README records a measured gap in kind's default network
plugin.

## What is tested

- `tests/test_kustomize.py`: the files, statically (fast tier); and, with
  `kubectl` and `helm` on PATH (slow tier), the rendered overlay compared with
  the rendered chart, with a mutation control showing the comparison notices a
  root uid, a retry, privilege escalation or a mounted token, and kubectl's
  Kustomize refusing a Job with `generateName` (its control: the same Job
  with a name renders).
- `scripts/e2e_kubernetes.sh`, scenario `kustomize`, on a kind cluster: the
  plain overlay accepted by a server-side dry-run in a namespace enforcing Pod
  Security "restricted"; the plain overlay against a vulnerable target (Job
  Failed, exit 1) and a fixed one (Complete, exit 0); this README's
  delete/apply/wait block run unchanged under `sh` against one overlay while
  its target goes fixed, vulnerable, fixed (exit 0, 1, 0, a new Job each
  time), with a plain apply-then-wait as its control (stale exit 0); the same
  block, target vulnerable, run as a ServiceAccount that may create but not
  delete Jobs (exit 1, the previous Job untouched), with the previous block
  under that identity as its control (stale exit 0).

Rendered by the Kustomize embedded in kubectl only (v1.34.1, Kustomize
v5.7.1). Not tested: standalone `kustomize`, Flux, and remote bases (none
exists before a release). The e2e negative control
(`E2E_CONTROL=gate-passes-wrongly`) runs the vulnerable legs with
`--fail-on none` and ends with those rows mismatched and exit 1.
