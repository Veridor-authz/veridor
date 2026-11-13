# Veridor as an Argo Rollouts canary analysis

An Argo CD PostSync gate reports a bad version after it is live. A canary
analysis stops it before it takes all the traffic: the new ReplicaSet gets a
share, `veridor run` probes it through the canary Service, and a failed run
aborts the rollout.

* [`veridor-analysistemplate.yaml`](veridor-analysistemplate.yaml) -- an
  `AnalysisTemplate` named `veridor-gate` with one metric using the **job**
  provider. The Job is the same restricted-profile pod the
  [`veridor-gate`](../helm/veridor-gate/README.md) chart renders (the tests
  hold the two to the same security context), running `veridor run
  --require-complete`.
* [`rollout-example.yaml`](rollout-example.yaml) -- a canary Rollout with
  `canaryService` / `stableService` and the steps `setWeight: 50`, `analysis`,
  `setWeight: 100`.

## How the result maps

| Veridor exit | Job | Measurement | Rollout |
|---|---|---|---|
| 0 | Complete | Successful | continues to `setWeight: 100`, promoted |
| 1, 2, 3, 70 | Failed | Failed | `failureLimit: 0` -> aborted (`status.abort: true`), `status.phase: Degraded`, stable ReplicaSet kept |

The job provider has no Inconclusive outcome, so exit 3 (something went
unmeasured) aborts the rollout like a finding does. `backoffLimit: 0`: a
retried gate reports its luckiest attempt.

Measured by `scripts/e2e_kubernetes.sh` (Argo Rollouts v1.10.0, kind), using
this template as-is and the example Rollout with its container, volumes and
uid replaced by the demo API and two analysis args added (the gate image and
the e2e Secret); its Services, strategy, steps and `base-url` are used
verbatim:

| step | AnalysisRun | gate exit | Rollout |
|---|---|---|---|
| revision 1, fixed (first rollout; steps are skipped) | none | -- | `Healthy`; `invoices-api-stable` selector pinned to the stable ReplicaSet's pod-template-hash |
| revision 2, vulnerable canary (1 canary + 1 stable pod ready when the analysis started) | `Failed` | 1 | `Degraded`, `status.abort: true`, stable ReplicaSet unchanged |
| revision 3, fixed canary | `Successful` | 0 | `Healthy`, promoted |

Revision 3 differs from revision 1 (the e2e changes a pod annotation), so it
is a new canary that has to pass the analysis. Returning to exactly the stable
spec is treated by Argo Rollouts as going back to stable, without the steps
(its documented behaviour; not measured here), which would not exercise the
gate.

## Using it

1. Put the Veridor configuration in a ConfigMap, with credentials as `${NAME}`
   references:

   ```sh
   kubectl -n shop create configmap veridor-config --from-file=veridor.json
   ```

2. Put the credentials in a Secret whose **keys are the variable names** the
   configuration references; the template imports every key with `envFrom`:

   ```sh
   kubectl -n shop create secret generic veridor-credentials \
     --from-literal=VERIDOR_OWNER_TOKEN=... --from-literal=VERIDOR_OUTSIDER_TOKEN=...
   ```

   The `secretRef` is `optional: true`: if the Secret is missing, the variables
   are unset and Veridor refuses the configuration at once (exit 2, naming the
   variable), which fails the measurement, rather than the pod waiting for
   `activeDeadlineSeconds`.

3. Apply the template in the Rollout's namespace, and add the analysis step:

   ```yaml
   - analysis:
       templates:
         - templateName: veridor-gate
       args:
         - name: base-url
           value: http://invoices-api-canary:8080
   ```

### Arguments

| arg | default | |
|---|---|---|
| `base-url` | none (required) | The **canary** Service. A gate pointed at the stable Service measures the version already live. |
| `config-map` | `veridor-config` | ConfigMap holding `veridor.json`. |
| `secret` | `veridor-credentials` | Secret imported with `envFrom`. |
| `image` | `ghcr.io/veridor-authz/veridor:0.1.0` | Gate image, published by each release. To run one built from the repository's `Dockerfile`, pass it here. |
| `fail-on` | `new+confirmed` | `--fail-on`. |
| `wait-for-target` | `"60"` | `--wait-for-target`: seconds to wait, before the first request, for the canary Service to accept a TCP connection. The analysis can start as the canary pod turns Ready, before the Service routes to it; probes sent then are refused and exit 3 aborts the rollout. Never changes a verdict. `"0"` turns it off. |

The Job's arguments are fixed in the template; edit it to add Veridor flags.

## Without traffic routing

The example has no `trafficRouting`, so Argo Rollouts splits by replica
count: at `setWeight: 50` of `replicas: 2` the e2e measured one ready canary
pod and one ready stable pod when the analysis started. Rollouts adds the
pod-template-hash to the Services' selectors (measured on
`invoices-api-stable`), so the gate reaches the canary through
`invoices-api-canary` while clients of `invoices-api-stable` stay on the
stable ReplicaSet. With a traffic router (Istio, NGINX, ...) the same steps
shift traffic by weight; that setup is not measured here.
