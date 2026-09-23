# Veridor on a local kind cluster

A self-contained demonstration: one pod that **runs all three verbs against a real
target inside the cluster**, then serves the viewer over the artifacts it just
produced. Nothing displayed is canned — the finding in the UI was measured by the
init container seconds before the viewer started.

## Run it

```bash
docker build -f deploy/kind/Dockerfile -t veridor:demo .
```

```bash
kind create cluster --config deploy/kind/cluster.yaml
```

```bash
kind load docker-image veridor:demo --name veridor-demo
```

```bash
kubectl --context kind-veridor-demo apply -f deploy/kind/veridor.yaml
```

```bash
kubectl --context kind-veridor-demo -n veridor rollout status deploy/veridor-viewer
```

Then open <http://127.0.0.1:8787>.

## What it deploys

| | |
|---|---|
| **initContainer `seed`** | Starts the vulnerable demo target, runs `run` → `map` → `mutate` against it, then restarts the target *patched* and runs once more. Produces two runs, a map and a mutation report in a shared `emptyDir`. If a target does not come up, or something else already answers on its port, the seed fails and the viewer does not start. |
| **container `viewer`** | `veridor serve` over that directory, mounted **read-only**. |
| **Service** | `NodePort` 30787, mapped by kind to **`127.0.0.1:8787` on the host only**. |

Two runs rather than one on purpose: the same declaration against a vulnerable
and then a patched target is the regression story the product exists for, and a
single run has no baseline to diff against.

## The security posture, stated plainly

**The viewer has no authentication.** That is correct for a local run browser and
wrong for anything reachable off your machine, so exposure is constrained in two
places rather than assumed:

- the container binds `0.0.0.0` because kube-proxy cannot reach it otherwise;
- the kind port mapping sets `listenAddress: "127.0.0.1"`, so the NodePort is
  **not** published on your LAN.

If you change that `listenAddress`, you are publishing an unauthenticated view of
your authorization findings. Don't.

The pod runs as UID 10001, non-root, with `readOnlyRootFilesystem`, all
capabilities dropped, and no privilege escalation. The viewer never writes: the
artifact volume is mounted read-only in the serving container.

## Teardown

```bash
kind delete cluster --name veridor-demo
```

## Notes

- `imagePullPolicy: Never` — the image is side-loaded with `kind load`, never
  pulled from a registry.
- `Dockerfile.dockerignore` beside the Dockerfile replaces the repository's
  `.dockerignore` for this build (BuildKit, the default builder since Docker 23).
  The root file excludes `scripts/` and `fixtures/`, which the release image does
  not need and this one does; `tests/test_release_files.py` fails if a Dockerfile
  copies anything its context excludes.
- The artifact volume is an `emptyDir`, not a PVC. A PVC would imply the viewer
  is a system of record; it is not, and the CLI owns `.veridor/`.
- Both probes hit `/api/runs` rather than `/`, because that proves the artifact
  directory is readable rather than merely that the process is alive.
- This deployment is a **demonstration**. It is not a recommendation to run
  Veridor as a long-lived service — the product is a CI-first CLI, and the
  viewer is a local reader for artifacts it produces.
