#!/usr/bin/env bash
# End-to-end test of the veridor-gate chart, the Argo CD PostSync gate and the
# Argo Rollouts AnalysisTemplate, on a kind cluster.
#
#   KUBE_CONTEXT=kind-veridor-demo scripts/e2e_kubernetes.sh
#
# Every scenario runs both directions -- a vulnerable target the gate must
# fail, a fixed one it must pass -- and the script ends with a table of
# expected against observed. Exit codes:
#   0  every row matched
#   1  at least one row mismatched (the table says which)
#   2  refused to start (precondition, or a manifest failing its sha256 pin)
#   3  stopped before the table: a setup or scenario step failed, so nothing
#      was concluded (the failing line is printed)
#   130 / 143  interrupted
#
# Scenarios (E2E_SCENARIOS, space separated, default all):
#   plain     hook.mode=none Job: vulnerable -> Job Failed, fixed -> Complete;
#             the chart README's none-mode block (helm template, delete,
#             apply, wait), run under sh (no -e) while its target goes fixed
#             -> vulnerable: exit 0; as a ServiceAccount that may create but
#             not delete Jobs, exit 1 with the previous Job untouched (control:
#             the block without its step checks, same identity, exits 0 on
#             that stale Job); as admin, a new Job, Failed, exit 1
#   helm      hook.mode=helm: vulnerable -> `helm install` fails, fixed -> deployed;
#             then the chart README's documented invocation: the gate as a
#             dependency of an app chart (RollingUpdate), aimed at a Service
#             of this release revision's pods, `helm upgrade --install
#             --rollback-on-failure`: install fixed -> deployed; upgrade to
#             vulnerable -> exit non-zero, rolled back, the fixed version
#             running; upgrade to fixed -> deployed (control: the same upgrade
#             to vulnerable with Helm's default flags, aimed at the app's own
#             Service, passes and the vulnerable version runs)
#   argocd    Application (demo app + veridor-gate PostSync hook) served from an
#             in-cluster Helm repository, with deploy/argocd/application-
#             example.yaml's gate values and configuration unchanged but for
#             image and target: vulnerable -> sync Failed naming this sync's
#             hook Job, fixed -> Succeeded, fixed -> vulnerable (strategy
#             Recreate) -> gate exit 1 and sync Failed; then a selective and
#             an Apply Only sync of that vulnerable version -> Succeeded, no
#             PostSync entry, no gate Job (Argo CD runs no hooks for them).
#             Then the app on
#             RollingUpdate, fixed -> vulnerable, with the gate aimed at a
#             Service of the new pods: with the Helm-CLI recipe's
#             .Release.Revision label (control), the replaced and the new pod
#             both carry "1" and the Service lists both; with a label from a
#             hash of the rendered pod template (the Argo CD recipe), the
#             labels differ, the Service lists only the new pod, the replaced
#             pod answered 0 gate requests, the gate exits 1 and the sync is
#             Failed. Every sync's Job is the one its syncResult names,
#             created after the sync started, and no two syncs share one (the
#             chart renders generateName; with one fixed name Argo CD v3.5.3
#             reported syncs from the previous sync's Job). `helm install` of
#             the argocd-mode chart is refused at render, creating no Job, and
#             an Application of the helm-mode chart fails to render
#             (ComparisonError naming the refusal; control: the same with
#             hook.helm.allowRenderWithoutCluster renders)
#   rollouts  deploy/argo-rollouts example: stable(fixed) -> canary(vulnerable)
#             -> analysis Failed -> aborted/Degraded; canary(fixed) -> Healthy
#   psa       namespace enforcing Pod Security "restricted": a non-compliant pod
#             is refused (control), the gate Job is admitted and completes with
#             its NetworkPolicy on, and a NetworkPolicy that does not allow the
#             target makes the gate fail (control)
#   wait      the race --wait-for-target exists for: three gate Jobs started
#             together with their targets, whose only pod turns Ready
#             WAIT_READY_DELAY (15) seconds later. Without the wait the gate
#             exits 3 on a vulnerable target (its probes are refused); with
#             gate.waitForTargetSeconds 60 it exits 1 on the vulnerable
#             target and 0 on the fixed one
#   kustomize deploy/kustomize/veridor-gate: overlays/plain passes a
#             server-side dry-run; its Job: vulnerable -> Failed, fixed ->
#             Complete, and re-applying it with a new configuration is refused;
#             the README's delete/apply/wait block, run unchanged under sh
#             (no -e) against one overlay while its target goes fixed ->
#             vulnerable -> fixed: exit 0 -> 1 -> 0, a new Job each time
#             (control: apply then `wait --for=condition=Complete` after the
#             target turned vulnerable reads the previous run's Job and exits
#             0); with the target vulnerable, the same block as a
#             ServiceAccount that cannot delete Jobs exits 1 and leaves the
#             previous Job (control: the block without its step checks, same
#             identity, exits 0 on that stale Job). There is no Argo CD
#             overlay: Kustomize refuses generateName (tests/test_kustomize.py)
# Every namespace this script creates enforces "restricted", so every scenario
# is also an admission test.
#
# Environment:
#   KUBE_CONTEXT          required; must start with "kind-". The kind cluster is
#                         the rest of the name. The current context is never
#                         read or changed.
#   E2E_CREATE_CLUSTER=1  create that kind cluster when it does not exist. Its
#                         kubeconfig goes to $E2E_WORKDIR/kubeconfig, so the
#                         user's kubeconfig and current context are untouched.
#   E2E_BUILD_IMAGE=0     skip `docker build` of ./Dockerfile (default 1). The
#                         image is always `kind load`ed.
#   E2E_GATE_IMAGE        default veridor:e2e (must carry an explicit tag)
#   E2E_TARGET_IMAGE      image that runs scripts/demo_server.py with python3;
#                         default the gate image
#   E2E_ARGO_MANIFEST_DIR directory holding the pinned install manifests (file
#                         names below). Missing files are downloaded. Either
#                         way the sha256 is checked before anything is applied.
#   E2E_SCENARIOS         see above
#   E2E_TIMEOUT           seconds per wait (default 300)
#   E2E_KEEP=1            keep the namespaces after the run (debugging)
#   E2E_CONTROL=gate-passes-wrongly
#                         negative control of this script: every gate aimed at
#                         a vulnerable target runs with gate.failOn=none, so it
#                         passes when it must not. Expectations are unchanged,
#                         so the run MUST end in MISMATCH rows and exit 1.
#   E2E_WORKDIR           scratch directory (default: mktemp -d)
#
# Needs: bash, kubectl, helm (3.8+ or 4), kind, docker, python3.
# Argo CD core and Argo Rollouts are installed only when absent, and left
# installed. The script's own namespaces (vg-e2e-*), Applications and
# AppProject are deleted on exit.
set -Eeuo pipefail

readonly ARGOCD_VERSION="v3.5.3"
readonly ARGOCD_FILE="argocd-core-install-${ARGOCD_VERSION}.yaml"
readonly ARGOCD_URL="https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/core-install.yaml"
readonly ARGOCD_SHA256="1a87025d8eb2eae621653fd312fb9ca51df1b4b3b6992a030e3a9ef38e45c448"
readonly ROLLOUTS_VERSION="v1.10.0"
readonly ROLLOUTS_FILE="argo-rollouts-install-${ROLLOUTS_VERSION}.yaml"
readonly ROLLOUTS_URL="https://github.com/argoproj/argo-rollouts/releases/download/${ROLLOUTS_VERSION}/install.yaml"
readonly ROLLOUTS_SHA256="ca8a1785391026023627c8a12db5422e227d7a7a6ec7c01f99f7d5b1726ed53c"

readonly NS_REPO="vg-e2e-helmrepo"
readonly NS_PLAIN="vg-e2e-plain"
readonly NS_HELM="vg-e2e-helm"
readonly NS_ARGOCD="vg-e2e-argocd"
readonly NS_ROLLOUTS="vg-e2e-rollouts"
readonly NS_PSA="vg-e2e-psa"
readonly NS_KUSTOMIZE="vg-e2e-kustomize"
readonly NS_WAIT="vg-e2e-wait"
readonly ALL_NAMESPACES=("$NS_REPO" "$NS_PLAIN" "$NS_HELM" "$NS_ARGOCD" "$NS_ROLLOUTS" "$NS_PSA" "$NS_KUSTOMIZE" "$NS_WAIT")
readonly LOCK_NAMESPACE="vg-e2e-lock"
readonly LOCK_STALE_SECONDS=3600
readonly ARGO_APP="vg-e2e-gate"
readonly ARGO_PROJECT="vg-e2e"
readonly REPO_URL="http://vg-helm-repo.${NS_REPO}.svc.cluster.local:8080"
readonly DEMO_PORT=8765
# Seconds the wait scenario's targets stay not-Ready after their pod starts.
readonly WAIT_READY_DELAY=15

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly CHART_DIR="${ROOT}/deploy/helm/veridor-gate"

log() { printf '==> %s\n' "$*" >&2; }
# REFUSED tells the exit trap that exit 2 was a refusal this script made, not
# a status bash produced on its own (bash 5 exits 2 on a syntax error).
REFUSED=0
refuse() {
  REFUSED=1
  printf 'e2e_kubernetes: %s\n' "$*" >&2
  exit 2
}

# --- preconditions ----------------------------------------------------------

[[ -n "${KUBE_CONTEXT:-}" ]] || refuse "KUBE_CONTEXT is not set. Name a kind cluster context, e.g. KUBE_CONTEXT=kind-veridor-demo. The current context is never used."
[[ "$KUBE_CONTEXT" == kind-* ]] || refuse "KUBE_CONTEXT=${KUBE_CONTEXT} does not start with 'kind-'. This script creates and deletes namespaces and installs Argo CD; it runs only against a kind cluster."
readonly KIND_CLUSTER="${KUBE_CONTEXT#kind-}"
[[ -n "$KIND_CLUSTER" ]] || refuse "KUBE_CONTEXT=${KUBE_CONTEXT} names no cluster after 'kind-'."

for tool in kubectl helm kind docker python3; do
  command -v "$tool" >/dev/null 2>&1 || refuse "${tool} is not on PATH; it is required."
done

E2E_BUILD_IMAGE="${E2E_BUILD_IMAGE:-1}"
E2E_GATE_IMAGE="${E2E_GATE_IMAGE:-veridor:e2e}"
E2E_TARGET_IMAGE="${E2E_TARGET_IMAGE:-$E2E_GATE_IMAGE}"
E2E_TIMEOUT="${E2E_TIMEOUT:-300}"
E2E_SCENARIOS="${E2E_SCENARIOS:-plain helm argocd rollouts psa kustomize wait}"
E2E_CONTROL="${E2E_CONTROL:-}"
E2E_KEEP="${E2E_KEEP:-0}"
E2E_CREATE_CLUSTER="${E2E_CREATE_CLUSTER:-0}"
E2E_BREAK_LOCK="${E2E_BREAK_LOCK:-0}"

[[ "$E2E_GATE_IMAGE" == *:* && "${E2E_GATE_IMAGE##*:}" != */* ]] || refuse "E2E_GATE_IMAGE=${E2E_GATE_IMAGE} has no tag. Give one explicitly, e.g. veridor:e2e."
readonly GATE_REPOSITORY="${E2E_GATE_IMAGE%:*}"
readonly GATE_TAG="${E2E_GATE_IMAGE##*:}"
[[ "$E2E_TIMEOUT" =~ ^[0-9]+$ ]] || refuse "E2E_TIMEOUT=${E2E_TIMEOUT} is not a number of seconds."
case "$E2E_CONTROL" in
  "" | gate-passes-wrongly) ;;
  *) refuse "E2E_CONTROL=${E2E_CONTROL} is not a control this script knows; the one it knows is gate-passes-wrongly." ;;
esac
for scenario in $E2E_SCENARIOS; do
  case "$scenario" in
    plain | helm | argocd | rollouts | psa | kustomize | wait) ;;
    *) refuse "E2E_SCENARIOS names '${scenario}'; choose from: plain helm argocd rollouts psa kustomize wait." ;;
  esac
done

if [[ -n "${E2E_WORKDIR:-}" ]]; then
  mkdir -p "$E2E_WORKDIR"
  WORK="$E2E_WORKDIR"
else
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/veridor-e2e.XXXXXX")"
fi
readonly WORK
RUN_ID="$(date +%s)"
readonly RUN_ID
# A fresh chart version per run: Argo CD caches a chart by name and version, so
# re-serving changed bytes under an old version would test the old chart.
readonly CHART_VERSION="0.1.0-e2e.${RUN_ID}"

KUBECTL=(kubectl --context "$KUBE_CONTEXT")
HELM=(helm --kube-context "$KUBE_CONTEXT")

if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
  if [[ "$E2E_CREATE_CLUSTER" == "1" ]]; then
    log "creating kind cluster ${KIND_CLUSTER} (kubeconfig: ${WORK}/kubeconfig)"
    kind create cluster --name "$KIND_CLUSTER" --kubeconfig "${WORK}/kubeconfig" --wait 180s
  else
    refuse "kind has no cluster named ${KIND_CLUSTER}. Create it, or set E2E_CREATE_CLUSTER=1."
  fi
fi
if [[ -f "${WORK}/kubeconfig" ]]; then
  KUBECTL+=(--kubeconfig "${WORK}/kubeconfig")
  HELM+=(--kubeconfig "${WORK}/kubeconfig")
elif ! kubectl config get-contexts -o name | grep -qx "$KUBE_CONTEXT"; then
  # Not `kind export kubeconfig`: that writes the user's kubeconfig and
  # switches its current context, which this script promises never to change.
  # `kind get kubeconfig` only prints, into the file this script reads first.
  refuse "kind has cluster ${KIND_CLUSTER} but the kubeconfig has no context ${KUBE_CONTEXT}. Write one for this script alone, leaving your kubeconfig and current context as they are: kind get kubeconfig --name $(printf '%q' "$KIND_CLUSTER") > $(printf '%q' "${WORK}/kubeconfig"), then re-run with E2E_WORKDIR=$(printf '%q' "$WORK")"
fi

k() { "${KUBECTL[@]}" "$@"; }
h() { "${HELM[@]}" "$@"; }

k get --raw /readyz >/dev/null || refuse "the API server of ${KUBE_CONTEXT} is not ready."

# --- results ----------------------------------------------------------------

RESULT_NAMES=()
RESULT_EXPECTED=()
RESULT_OBSERVED=()
MISMATCHES=0

# record NAME EXPECTED OBSERVED -- a row matches only on string equality.
record() {
  RESULT_NAMES+=("$1")
  RESULT_EXPECTED+=("$2")
  RESULT_OBSERVED+=("$3")
  if [[ "$2" == "$3" ]]; then
    log "MATCH     $1: $3"
  else
    MISMATCHES=$((MISMATCHES + 1))
    log "MISMATCH  $1: expected [$2], observed [$3]"
  fi
}

print_table() {
  local i verdict w1=8 w2=8 w3=8
  for i in "${!RESULT_NAMES[@]}"; do
    ((${#RESULT_NAMES[$i]} > w1)) && w1=${#RESULT_NAMES[$i]}
    ((${#RESULT_EXPECTED[$i]} > w2)) && w2=${#RESULT_EXPECTED[$i]}
    ((${#RESULT_OBSERVED[$i]} > w3)) && w3=${#RESULT_OBSERVED[$i]}
  done
  printf '\n%-*s | %-*s | %-*s | %s\n' "$w1" "scenario" "$w2" "expected" "$w3" "observed" "result"
  printf '%s\n' "$(printf '%*s' $((w1 + w2 + w3 + 17)) '' | tr ' ' '-')"
  for i in "${!RESULT_NAMES[@]}"; do
    verdict="MATCH"
    [[ "${RESULT_EXPECTED[$i]}" == "${RESULT_OBSERVED[$i]}" ]] || verdict="MISMATCH"
    printf '%-*s | %-*s | %-*s | %s\n' "$w1" "${RESULT_NAMES[$i]}" "$w2" "${RESULT_EXPECTED[$i]}" "$w3" "${RESULT_OBSERVED[$i]}" "$verdict"
  done
  printf '\n%d row(s), %d mismatch(es). gate image %s, chart %s, context %s%s\n' \
    "${#RESULT_NAMES[@]}" "$MISMATCHES" "$E2E_GATE_IMAGE" "$CHART_VERSION" "$KUBE_CONTEXT" \
    "${E2E_CONTROL:+, CONTROL=${E2E_CONTROL}}"
  TABLE_PRINTED=1
}

# --- one run at a time ---------------------------------------------------------

LOCK_HELD=0
LOCK_TOKEN="${RUN_ID}-$$-${RANDOM}"

lock_manifest() {
  python3 - "$LOCK_NAMESPACE" "$LOCK_TOKEN" "$$" "${USER:-unknown}" "$(uname -n)" "$WORK" <<'PY'
import datetime, json, sys
name, token, pid, user, host, work = sys.argv[1:]
started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print(json.dumps({
    "apiVersion": "v1",
    "kind": "Namespace",
    "metadata": {
        "name": name,
        "labels": {"app.kubernetes.io/managed-by": "e2e_kubernetes.sh"},
        "annotations": {
            "vg-e2e/holder": f"{user}@{host}",
            "vg-e2e/host": host,
            "vg-e2e/pid": pid,
            "vg-e2e/started-at": started,
            "vg-e2e/run-id": token,
            "vg-e2e/workdir": work,
        },
    },
}))
PY
}

# describe_lock -> "<age in seconds, -1 if gone> <1 if being deleted> <run-id> <who>"
describe_lock() {
  { k get namespace "$LOCK_NAMESPACE" -o json 2>/dev/null || true; } | python3 -c '
import datetime, json, sys
try:
    meta = json.load(sys.stdin).get("metadata") or {}
except ValueError:
    print("-1 0 - (gone)")
    raise SystemExit(0)
notes = meta.get("annotations") or {}
age = -1
if meta.get("creationTimestamp"):
    created = datetime.datetime.strptime(meta["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    age = int((now - created).total_seconds())
who = ", ".join("%s %s" % (key, notes.get("vg-e2e/" + key) or "?")
                for key in ("holder", "host", "pid", "started-at"))
print(age, 1 if meta.get("deletionTimestamp") else 0, notes.get("vg-e2e/run-id") or "-", who)
'
}

acquire_lock() {
  local output age deleting token who waited=0 broke=0
  while :; do
    if output="$(lock_manifest | k create -f - 2>&1)"; then
      LOCK_HELD=1
      log "lock: holding namespace ${LOCK_NAMESPACE} (run-id ${LOCK_TOKEN})"
      return 0
    fi
    if [[ "$output" != *AlreadyExists* ]]; then
      # A setup failure (exit 3), not a refusal: nothing says another run
      # holds the lock, and nothing of this run exists yet to clean up.
      LAST_FAILURE="creating the lock namespace ${LOCK_NAMESPACE}: ${output//$'\n'/ }"
      exit 3
    fi
    read -r age deleting token who <<<"$(describe_lock)"
    # Released a moment ago by a run that just finished, or still being
    # deleted: wait for it rather than refuse.
    if [[ "$deleting" == 1 || "$age" == -1 ]] && ((waited < 120)); then
      sleep 2
      waited=$((waited + 2))
      continue
    fi
    if [[ "$E2E_BREAK_LOCK" == 1 && "$broke" == 0 ]] && ((age > LOCK_STALE_SECONDS)); then
      log "lock: breaking ${LOCK_NAMESPACE} (run-id ${token}, ${who}): ${age}s old, older than ${LOCK_STALE_SECONDS}s, and E2E_BREAK_LOCK=1"
      k delete namespace "$LOCK_NAMESPACE" --wait=true --timeout=120s >/dev/null
      broke=1
      continue
    fi
    if [[ "$E2E_BREAK_LOCK" == 1 ]]; then
      refuse "another run holds the lock namespace ${LOCK_NAMESPACE} on ${KUBE_CONTEXT} (run-id ${token}, ${who}; ${age}s old). It is not older than ${LOCK_STALE_SECONDS}s, so E2E_BREAK_LOCK=1 does not break it. Nothing was touched. Wait for that run; if you know it is dead, delete the lock yourself: kubectl --context ${KUBE_CONTEXT} delete namespace ${LOCK_NAMESPACE}"
    fi
    refuse "another run holds the lock namespace ${LOCK_NAMESPACE} on ${KUBE_CONTEXT} (run-id ${token}, ${who}; ${age}s old). Two runs share the vg-e2e-* namespaces and would delete each other's objects, so this one exits without touching anything. Wait for that run to finish. If it is dead: once the lock is older than ${LOCK_STALE_SECONDS}s, re-run with E2E_BREAK_LOCK=1, or delete it yourself: kubectl --context ${KUBE_CONTEXT} delete namespace ${LOCK_NAMESPACE}"
  done
}

release_lock() {
  local token
  [[ "$LOCK_HELD" == 1 ]] || return 0
  token="$(k get namespace "$LOCK_NAMESPACE" -o jsonpath='{.metadata.annotations.vg-e2e/run-id}' 2>/dev/null || true)"
  if [[ "$token" == "$LOCK_TOKEN" ]]; then
    if k delete namespace "$LOCK_NAMESPACE" --wait=true --timeout=120s >/dev/null 2>&1; then
      log "lock: released ${LOCK_NAMESPACE}"
    else
      log "lock: could not delete ${LOCK_NAMESPACE}; later runs refuse until it is gone: kubectl --context ${KUBE_CONTEXT} delete namespace ${LOCK_NAMESPACE}"
    fi
  else
    log "lock: ${LOCK_NAMESPACE} is no longer this run's (run-id '${token:-none}'); left alone"
  fi
  LOCK_HELD=0
}

# --- cleanup ----------------------------------------------------------------

delete_own_objects() {
  local ns
  # Applications first, so the controller stops reconciling into namespaces
  # that are about to go. No resources finalizer is ever set on them.
  k -n argocd delete application "$ARGO_APP" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  k -n argocd delete appproject "$ARGO_PROJECT" --ignore-not-found >/dev/null 2>&1 || true
  # Argo CD puts argocd.argoproj.io/hook-finalizer on a hook Job and removes
  # it once it has recorded the result. An Application deleted before that
  # (a run stopped mid-sync) leaves it, and the namespace then never finishes
  # deleting (measured). Nothing else of Argo CD's is in these namespaces.
  for ns in "${ALL_NAMESPACES[@]}"; do
    k -n "$ns" get jobs -o name 2>/dev/null | while read -r job; do
      k -n "$ns" patch "$job" --type json -p '[{"op": "remove", "path": "/metadata/finalizers"}]' >/dev/null 2>&1 || true
    done
  done
  for ns in "${ALL_NAMESPACES[@]}"; do
    k delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
  for ns in "${ALL_NAMESPACES[@]}"; do
    k wait --for=delete "namespace/${ns}" --timeout=180s >/dev/null 2>&1 || true
  done
}

on_exit() {
  local status=$?
  # Only the table is a result. Without it, any status but a refusal or an
  # interrupt is "stopped before the table" -- 0 included: measured, bash 3.2
  # (macOS) reaches this trap with status 0 after a syntax error part-way
  # through the file (a script edited while it ran), and exited 0 with no table.
  if [[ "$TABLE_PRINTED" != "1" && "$REFUSED" != "1" ]] && ((status != 130 && status != 143)); then
    printf 'e2e_kubernetes: stopped before the result table (exit %s at %s). Nothing was concluded; this is not a gate result.\n' \
      "$status" "${LAST_FAILURE:-an unknown step}" >&2
    status=3
  fi
  # Without the lock nothing here is this run's: the namespaces belong to the
  # run that holds it, and deleting them is what the lock exists to stop.
  if [[ "$LOCK_HELD" != "1" ]]; then
    exit "$status"
  fi
  if [[ "$E2E_KEEP" == "1" ]]; then
    log "E2E_KEEP=1: leaving namespaces ${ALL_NAMESPACES[*]}"
  else
    log "cleanup: deleting vg-e2e-* namespaces, Application ${ARGO_APP}, AppProject ${ARGO_PROJECT}"
    delete_own_objects
  fi
  release_lock
  exit "$status"
}
TABLE_PRINTED=0
LAST_FAILURE=""
trap 'LAST_FAILURE="line ${LINENO}: ${BASH_COMMAND}"' ERR
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- helpers ----------------------------------------------------------------

create_namespace() {
  local ns="$1"
  k create namespace "$ns" >/dev/null
  k label namespace "$ns" --overwrite \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted >/dev/null
}

# The demo server's credentials are fixed strings in scripts/demo_server.py; they
# are not secrets, but they travel the way real credentials must: in a Secret.
# create_credentials NS [SECRET_NAME]
create_credentials() {
  local ns="$1" name="${2:-vg-e2e-credentials}"
  k -n "$ns" create secret generic "$name" \
    --from-literal=owner-token=owner-token \
    --from-literal=outsider-token=outsider-token \
    --from-literal=admin-token=admin-token \
    --from-literal=VERIDOR_OWNER_TOKEN=owner-token \
    --from-literal=VERIDOR_OUTSIDER_TOKEN=outsider-token \
    --from-literal=VERIDOR_ADMIN_TOKEN=admin-token >/dev/null
}

# wait_job NS NAME -> prints Complete, Failed, or Timeout (at once for "none",
# sync_job's word for no Job)
wait_job() {
  local ns="$1" name="$2" deadline conditions
  if [[ "$name" == none ]]; then
    echo Timeout
    return 0
  fi
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    conditions="$(k -n "$ns" get job "$name" -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type}{" "}{end}' 2>/dev/null || true)"
    case " $conditions " in
      *" Complete "*) echo Complete; return 0 ;;
      *" Failed "*) echo Failed; return 0 ;;
    esac
    sleep 2
  done
  echo Timeout
}

# job_exit NS NAME -> the gate container's exit code, or "none". Selected by
# the Job's uid: a hook Job is recreated under the same name, and a pod of the
# previous one can still be terminating.
job_exit() {
  local uid code=""
  uid="$(k -n "$1" get job "$2" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  if [[ -n "$uid" ]]; then
    code="$(k -n "$1" get pods -l "controller-uid=${uid}" -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)"
  fi
  echo "${code:-none}"
}

show_job_log() {
  log "log of job/$2 (namespace $1):"
  k -n "$1" logs "job/$2" --tail=40 2>&1 | sed 's/^/    | /' >&2 || true
}

# gate_values OUT MODE BASE_URL VULNERABLE_TARGET [EXTRA_JSON]
# Values for the veridor-gate chart, as JSON (valid YAML). EXTRA_JSON is merged
# over the top level.
gate_values() {
  local out="$1" mode="$2" base_url="$3" vulnerable="$4" extra="${5:-}"
  [[ -n "$extra" ]] || extra='{}'
  python3 - "$out" "$mode" "$base_url" "$vulnerable" "$extra" "$E2E_CONTROL" "$GATE_REPOSITORY" "$GATE_TAG" "${WORK}/gate-config.json" <<'PY'
import json, sys
out, mode, base_url, vulnerable, extra, control, repo, tag, config_path = sys.argv[1:]
values = {
    "hook": {"mode": mode},
    "image": {"repository": repo, "tag": tag, "pullPolicy": "IfNotPresent"},
    "target": {"baseUrl": base_url},
    "secretEnv": [
        {"name": "VERIDOR_OWNER_TOKEN", "secretName": "vg-e2e-credentials", "key": "owner-token"},
        {"name": "VERIDOR_OUTSIDER_TOKEN", "secretName": "vg-e2e-credentials", "key": "outsider-token"},
        {"name": "VERIDOR_ADMIN_TOKEN", "secretName": "vg-e2e-credentials", "key": "admin-token"},
    ],
    "config": json.load(open(config_path)),
    "job": {"activeDeadlineSeconds": 240},
}
values.update(json.loads(extra))
if control == "gate-passes-wrongly" and vulnerable == "yes":
    values.setdefault("gate", {})["failOn"] = "none"
json.dump(values, open(out, "w"), indent=2)
PY
}

# retry ATTEMPTS COMMAND... -- for API calls that a freshly created cluster can
# fail transiently (measured: "etcdserver: request timed out" while applying
# the Argo Rollouts CRDs to a new kind cluster). Only idempotent calls.
retry() {
  local attempts="$1" n=1
  shift
  until "$@"; do
    if ((n >= attempts)); then
      return 1
    fi
    log "attempt ${n} of ${attempts} failed, retrying in $((n * 10))s: $*"
    sleep $((n * 10))
    n=$((n + 1))
  done
}

wait_deployment() {
  k -n "$1" rollout status "deployment/$2" --timeout="${E2E_TIMEOUT}s" >/dev/null
}

# install_target NS RELEASE yes|no -- the demo API, vulnerable or fixed
install_target() {
  local ns="$1" release="$2" vulnerable="$3" flag=false
  [[ "$vulnerable" == "yes" ]] && flag=true
  h upgrade --install "$release" "${WORK}/repo/vg-e2e-demo-target-${CHART_VERSION}.tgz" \
    -n "$ns" --set "image=${E2E_TARGET_IMAGE}" --set "vulnerable=${flag}" >/dev/null
  wait_deployment "$ns" "$release"
}

# --- setup: Argo, images, charts, in-cluster Helm repository ------------------

# fetch_manifest runs in $(...), so its REFUSED=1 stays in the subshell. Its
# exit 2 is always a refusal (a pin mismatch, or no curl): carry it out.
refused_in_subshell() {
  local status=$?
  if [[ "$status" == 2 ]]; then
    REFUSED=1
  else
    LAST_FAILURE="fetching a pinned Argo manifest (exit ${status})"
  fi
  exit "$status"
}

fetch_manifest() {
  local file="$1" url="$2" sha="$3" dest actual
  dest="${WORK}/${file}"
  if [[ -n "${E2E_ARGO_MANIFEST_DIR:-}" && -f "${E2E_ARGO_MANIFEST_DIR}/${file}" ]]; then
    cp "${E2E_ARGO_MANIFEST_DIR}/${file}" "$dest"
  else
    command -v curl >/dev/null 2>&1 || refuse "${file} is not in E2E_ARGO_MANIFEST_DIR and curl is not on PATH to download it."
    log "downloading ${url}"
    curl -fsSL --retry 3 -o "$dest" "$url"
  fi
  actual="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$dest")"
  if [[ "$actual" != "$sha" ]]; then
    REFUSED=1
    printf 'e2e_kubernetes: %s has sha256 %s, pinned %s. Not applying it.\n' "$file" "$actual" "$sha" >&2
    exit 2
  fi
  echo "$dest"
}

install_argo() {
  local manifest
  if k get crd applications.argoproj.io >/dev/null 2>&1 \
    && k -n argocd get statefulset argocd-application-controller >/dev/null 2>&1; then
    log "Argo CD present, not reinstalled: $(k -n argocd get statefulset argocd-application-controller -o jsonpath='{.spec.template.spec.containers[0].image}') (pinned ${ARGOCD_VERSION})"
  else
    manifest="$(fetch_manifest "$ARGOCD_FILE" "$ARGOCD_URL" "$ARGOCD_SHA256")" || refused_in_subshell
    log "installing Argo CD core ${ARGOCD_VERSION} (sha256 ${ARGOCD_SHA256:0:12}... checked)"
    k create namespace argocd --dry-run=client -o yaml | k apply -f - >/dev/null
    retry 3 k apply --server-side --force-conflicts -n argocd -f "$manifest" >/dev/null
  fi
  if k get crd rollouts.argoproj.io >/dev/null 2>&1 \
    && k -n argo-rollouts get deployment argo-rollouts >/dev/null 2>&1; then
    log "Argo Rollouts present, not reinstalled: $(k -n argo-rollouts get deployment argo-rollouts -o jsonpath='{.spec.template.spec.containers[0].image}') (pinned ${ROLLOUTS_VERSION})"
  else
    manifest="$(fetch_manifest "$ROLLOUTS_FILE" "$ROLLOUTS_URL" "$ROLLOUTS_SHA256")" || refused_in_subshell
    log "installing Argo Rollouts ${ROLLOUTS_VERSION} (sha256 ${ROLLOUTS_SHA256:0:12}... checked)"
    k create namespace argo-rollouts --dry-run=client -o yaml | k apply -f - >/dev/null
    retry 3 k apply --server-side --force-conflicts -n argo-rollouts -f "$manifest" >/dev/null
  fi
  k wait --for=condition=Established --timeout="${E2E_TIMEOUT}s" \
    crd/applications.argoproj.io crd/appprojects.argoproj.io \
    crd/rollouts.argoproj.io crd/analysistemplates.argoproj.io crd/analysisruns.argoproj.io >/dev/null
  k -n argocd rollout status statefulset/argocd-application-controller --timeout="${E2E_TIMEOUT}s" >/dev/null
  k -n argocd rollout status deployment/argocd-repo-server --timeout="${E2E_TIMEOUT}s" >/dev/null
  k -n argo-rollouts rollout status deployment/argo-rollouts --timeout="${E2E_TIMEOUT}s" >/dev/null
}

build_images() {
  if [[ "$E2E_BUILD_IMAGE" == "1" ]]; then
    log "building ${E2E_GATE_IMAGE} from ${ROOT}/Dockerfile"
    docker build -q -t "$E2E_GATE_IMAGE" -f "${ROOT}/Dockerfile" "$ROOT" >/dev/null
  fi
  docker image inspect "$E2E_GATE_IMAGE" >/dev/null 2>&1 || refuse "image ${E2E_GATE_IMAGE} does not exist locally; build it, or leave E2E_BUILD_IMAGE unset so this script builds it."
  log "loading ${E2E_GATE_IMAGE} into kind cluster ${KIND_CLUSTER}"
  kind load docker-image "$E2E_GATE_IMAGE" --name "$KIND_CLUSTER" >/dev/null
  if [[ "$E2E_TARGET_IMAGE" != "$E2E_GATE_IMAGE" ]]; then
    docker image inspect "$E2E_TARGET_IMAGE" >/dev/null 2>&1 || refuse "image ${E2E_TARGET_IMAGE} does not exist locally."
    kind load docker-image "$E2E_TARGET_IMAGE" --name "$KIND_CLUSTER" >/dev/null
  fi
}

# The demo API as a chart, so Argo CD can deploy it from the same Helm
# repository as the gate. The server script is shipped in a ConfigMap and run
# with python3 from the target image: no demo files are baked into any image.
# With logRequests the server runs under a wrapper that prints one line per
# request naming the pod that answered and the client address, which is how
# the argocd scenario counts the gate requests a replaced pod answered.
write_demo_chart() {
  local dir="${WORK}/charts/vg-e2e-demo-target"
  mkdir -p "${dir}/templates" "${dir}/files"
  cp "${ROOT}/scripts/demo_server.py" "${dir}/files/demo_server.py"
  cat >"${dir}/files/logged_server.py" <<'EOF'
import os
import sys

sys.path.insert(0, "/demo")
import demo_server  # noqa: E402

_make_handler = demo_server.make_handler


def make_handler(*args, **kwargs):
    base = _make_handler(*args, **kwargs)

    class Logged(base):
        def log_message(self, format, *values):
            print("vg-e2e-request pod=%s client=%s %s" % (os.environ.get("HOSTNAME", "?"), self.client_address[0],
                                                          self.requestline), flush=True)

    return Logged


demo_server.make_handler = make_handler
demo_server.main()
EOF
  cat >"${dir}/Chart.yaml" <<'EOF'
apiVersion: v2
name: vg-e2e-demo-target
description: scripts/demo_server.py as a Deployment and Service, for scripts/e2e_kubernetes.sh only
version: 0.1.0
EOF
  cat >"${dir}/values.yaml" <<'EOF'
image: veridor:e2e
vulnerable: true
revision: "1"
# Seconds before the first readiness probe: the wait scenario's not-Ready window.
readinessDelaySeconds: 0
# Recreate: when a gate runs after the rollout, no pod of the previous
# version is serving. The helm and argocd scenarios set RollingUpdate, the
# Deployment default, to measure what a gate probes then.
strategy: Recreate
# A Service selecting only the pods of this release revision (the helm
# scenario's documented gate target): a label from .Release.Revision.
revisionService: false
# A Service selecting only the pods of this pod template: a label from a hash
# of the rendered pod template (the argocd scenario's documented gate target).
podTemplateService: false
# The demo API ignores SIGTERM (PID 1, no handler), so a replaced pod serves
# until it is killed this many seconds later.
terminationGracePeriodSeconds: 30
logRequests: false
EOF
  cat >"${dir}/templates/all.yaml" <<'EOF'
{{- define "vg-e2e-demo-target.podAnnotations" -}}
vg-e2e/revision: {{ .Values.revision | quote }}
{{- end }}
{{- define "vg-e2e-demo-target.podSpec" -}}
automountServiceAccountToken: false
enableServiceLinks: false
terminationGracePeriodSeconds: {{ .Values.terminationGracePeriodSeconds }}
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: api
    image: {{ .Values.image | quote }}
    imagePullPolicy: IfNotPresent
    command:
      - python3
      - {{ ternary "/demo/logged_server.py" "/demo/demo_server.py" .Values.logRequests }}
      - --host
      - 0.0.0.0
      - --port
      - "8765"
      {{- if .Values.vulnerable }}
      - --vulnerable
      {{- end }}
    ports:
      - name: http
        containerPort: 8765
    readinessProbe:
      tcpSocket:
        port: http
      initialDelaySeconds: {{ .Values.readinessDelaySeconds }}
      periodSeconds: 2
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    volumeMounts:
      - name: server
        mountPath: /demo
        readOnly: true
volumes:
  - name: server
    configMap:
      name: {{ .Release.Name }}-server
{{- end }}
{{- define "vg-e2e-demo-target.podTemplateHash" -}}
{{- print (include "vg-e2e-demo-target.podAnnotations" .) (include "vg-e2e-demo-target.podSpec" .) | sha256sum | trunc 16 | quote -}}
{{- end }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-server
data:
  demo_server.py: |
    {{- .Files.Get "files/demo_server.py" | nindent 4 }}
  logged_server.py: |
    {{- .Files.Get "files/logged_server.py" | nindent 4 }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}
spec:
  selector:
    app.kubernetes.io/instance: {{ .Release.Name }}
  ports:
    - name: http
      port: 8765
      targetPort: http
{{- if .Values.revisionService }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-this-revision
spec:
  selector:
    app.kubernetes.io/instance: {{ .Release.Name }}
    vg-e2e/release-revision: {{ .Release.Revision | quote }}
  ports:
    - name: http
      port: 8765
      targetPort: http
{{- end }}
{{- if .Values.podTemplateService }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-this-pod-template
spec:
  selector:
    app.kubernetes.io/instance: {{ .Release.Name }}
    vg-e2e/pod-template: {{ include "vg-e2e-demo-target.podTemplateHash" . }}
  ports:
    - name: http
      port: 8765
      targetPort: http
{{- end }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  replicas: 1
  strategy:
    type: {{ .Values.strategy }}
  selector:
    matchLabels:
      app.kubernetes.io/instance: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: vg-e2e-demo-target
        app.kubernetes.io/instance: {{ .Release.Name }}
        {{- if .Values.revisionService }}
        vg-e2e/release-revision: {{ .Release.Revision | quote }}
        {{- end }}
        {{- if .Values.podTemplateService }}
        vg-e2e/pod-template: {{ include "vg-e2e-demo-target.podTemplateHash" . }}
        {{- end }}
      annotations:
        {{- include "vg-e2e-demo-target.podAnnotations" . | nindent 8 }}
    spec:
      {{- include "vg-e2e-demo-target.podSpec" . | nindent 6 }}
EOF
}

# The gate configuration: fixtures/veridor.demo.json with every credential a
# ${NAME} reference, which is the only shape the chart renders.
write_gate_config() {
  cat >"${WORK}/gate-config.json" <<'EOF'
{
  "version": 1,
  "target": {"base_url": "http://127.0.0.1:8765", "timeout_seconds": 5},
  "identities": {
    "invoice_owner": {
      "headers": {"Authorization": "Bearer ${VERIDOR_OWNER_TOKEN}"},
      "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
    },
    "other_tenant": {
      "headers": {"Authorization": "Bearer ${VERIDOR_OUTSIDER_TOKEN}"},
      "marker": "vdr-Bq3Wm8Ke5Tz1Yx7Rn2Hd4Vs6",
      "marker_probe": {"method": "GET", "path": "/api/invoices/inv-200"}
    },
    "administrator": {"headers": {"Authorization": "Bearer ${VERIDOR_ADMIN_TOKEN}"}},
    "anonymous": {"headers": {}}
  },
  "checks": [
    {
      "id": "invoice-tenant-isolation",
      "name": "Invoice tenant isolation",
      "request": {"method": "GET", "path": "/api/invoices/inv-100"},
      "expect": {
        "invoice_owner": {"status": [200], "contains_marker": "invoice_owner"},
        "other_tenant": {"status": [404], "excludes_marker": "invoice_owner"},
        "anonymous": {"status": [401]}
      }
    },
    {
      "id": "audit-admin-role",
      "name": "Audit log administrator role",
      "request": {"method": "GET", "path": "/api/admin/audit"},
      "expect": {
        "administrator": {"status": [200]},
        "invoice_owner": {"status": [403]},
        "other_tenant": {"status": [403]}
      }
    }
  ]
}
EOF
}

package_charts() {
  mkdir -p "${WORK}/repo"
  rm -f "${WORK}/repo/"*.tgz "${WORK}/repo/index.yaml"
  h lint "$CHART_DIR" -f "${CHART_DIR}/ci/argocd-values.yaml" >/dev/null
  helm package "$CHART_DIR" --version "$CHART_VERSION" -d "${WORK}/repo" >/dev/null
  helm package "${WORK}/charts/vg-e2e-demo-target" --version "$CHART_VERSION" -d "${WORK}/repo" >/dev/null
  helm repo index "${WORK}/repo" --url "$REPO_URL"
}

serve_helm_repo() {
  create_namespace "$NS_REPO"
  k -n "$NS_REPO" create configmap vg-helm-repo --from-file="${WORK}/repo" >/dev/null
  k -n "$NS_REPO" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: vg-helm-repo
spec:
  selector:
    app.kubernetes.io/name: vg-helm-repo
  ports:
    - name: http
      port: 8080
      targetPort: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vg-helm-repo
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: vg-helm-repo
  template:
    metadata:
      labels:
        app.kubernetes.io/name: vg-helm-repo
    spec:
      automountServiceAccountToken: false
      enableServiceLinks: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: http
          image: ${E2E_TARGET_IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/repo"]
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            tcpSocket:
              port: http
            periodSeconds: 2
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: repo
              mountPath: /repo
              readOnly: true
      volumes:
        - name: repo
          configMap:
            name: vg-helm-repo
EOF
  wait_deployment "$NS_REPO" vg-helm-repo
  log "Helm repository serving ${CHART_VERSION} at ${REPO_URL}"
}

# --- scenario: plain Job (hook.mode=none) -------------------------------------

scenario_plain() {
  local leg release status code
  log "scenario plain: hook.mode=none Job against a vulnerable and a fixed target"
  create_namespace "$NS_PLAIN"
  create_credentials "$NS_PLAIN"
  install_target "$NS_PLAIN" target-vuln yes
  install_target "$NS_PLAIN" target-fixed no
  for leg in vuln fixed; do
    release="gate-${leg}"
    gate_values "${WORK}/plain-${leg}.json" none \
      "http://target-${leg}.${NS_PLAIN}.svc.cluster.local:${DEMO_PORT}" \
      "$([[ $leg == vuln ]] && echo yes || echo no)"
    h upgrade --install "$release" "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" \
      -n "$NS_PLAIN" -f "${WORK}/plain-${leg}.json" >/dev/null
  done
  for leg in vuln fixed; do
    status="$(wait_job "$NS_PLAIN" "gate-${leg}-veridor-gate-r1")"
    code="$(job_exit "$NS_PLAIN" "gate-${leg}-veridor-gate-r1")"
    show_job_log "$NS_PLAIN" "gate-${leg}-veridor-gate-r1"
    if [[ $leg == vuln ]]; then
      record "plain: Job vs vulnerable target" "Failed (exit 1)" "${status} (exit ${code})"
    else
      record "plain: Job vs fixed target" "Complete (exit 0)" "${status} (exit ${code})"
    fi
  done
  scenario_plain_readme_flow
}

# block_namespace FILE NS -- the chart README's block sets ns=shop on its
# first line; the e2e points it at NS and changes nothing else.
block_namespace() {
  python3 - "$1" "$2" <<'PY'
import sys
path, ns = sys.argv[1:]
text = open(path, encoding="utf-8").read()
if not text.startswith("ns=shop\n"):
    sys.exit(f"{path}: the block no longer starts with ns=shop")
open(path, "w", encoding="utf-8").write(f"ns={ns}\n" + text[len("ns=shop\n"):])
PY
}

# The chart README's hook.mode none block (helm template, delete, apply, wait),
# extracted and run under sh (no -e) in a directory holding ./veridor-gate and
# values.yaml, against one target that turns vulnerable underneath it.
scenario_plain_readme_flow() {
  local flow="${WORK}/chart-flow" rc before uid status code as
  rm -rf "$flow"
  mkdir -p "$flow"
  cp -R "$CHART_DIR" "${flow}/veridor-gate"
  readme_block "${CHART_DIR}/README.md" "delete job gate-veridor-gate-r1" "${WORK}/chart-flow.sh"
  block_namespace "${WORK}/chart-flow.sh" "$NS_PLAIN"
  unchecked_block "${WORK}/chart-flow.sh" "${WORK}/chart-flow-unchecked.sh"
  pinned_kubectl "${WORK}/chart-kubectl" "$NS_PLAIN"
  as="$(no_delete_identity "$NS_PLAIN")"
  pinned_kubectl "${WORK}/chart-kubectl-nodelete" "$NS_PLAIN" "$as"
  record "plain: the no-delete identity may create Jobs, not delete them" "create yes, delete no" \
    "create $(can_i "$NS_PLAIN" "$as" create), delete $(can_i "$NS_PLAIN" "$as" delete)"
  install_target "$NS_PLAIN" target-flow no
  # "yes": under E2E_CONTROL these values run --fail-on none, since the target
  # turns vulnerable; they stay the same values throughout.
  gate_values "${flow}/values.yaml" none "http://target-flow.${NS_PLAIN}.svc.cluster.local:${DEMO_PORT}" yes

  rc=0
  run_readme_flow "$flow" "${WORK}/chart-flow.sh" "${WORK}/chart-flow.log" "${WORK}/chart-kubectl" || rc=$?
  sed 's/^/    | /' "${WORK}/chart-flow.log" >&2
  read -r before status code <<<"$(job_state "$NS_PLAIN" gate-veridor-gate-r1)"
  record "plain: chart README none-mode flow, fixed target" "exit 0, Complete (exit 0)" "exit ${rc}, ${status} (exit ${code})"

  install_target "$NS_PLAIN" target-flow yes
  rc=0
  run_readme_flow "$flow" "${WORK}/chart-flow.sh" "${WORK}/chart-flow.log" "${WORK}/chart-kubectl-nodelete" || rc=$?
  sed 's/^/    | /' "${WORK}/chart-flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_PLAIN" gate-veridor-gate-r1)"
  record "plain: chart README flow, no-delete identity, target vulnerable" "exit 1, the previous run's Job" \
    "exit ${rc}, $([[ $uid == "$before" ]] && echo "the previous run's Job" || echo "a new Job")"
  # Control: the block without its step checks, same identity, passes stale.
  rc=0
  run_readme_flow "$flow" "${WORK}/chart-flow-unchecked.sh" "${WORK}/chart-flow.log" "${WORK}/chart-kubectl-nodelete" || rc=$?
  sed 's/^/    | /' "${WORK}/chart-flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_PLAIN" gate-veridor-gate-r1)"
  record "plain: control, the unchecked chart block as the no-delete identity" "exit 0, the previous run's Job" \
    "exit ${rc}, $([[ $uid == "$before" ]] && echo "the previous run's Job" || echo "a new Job")"

  rc=0
  run_readme_flow "$flow" "${WORK}/chart-flow.sh" "${WORK}/chart-flow.log" "${WORK}/chart-kubectl" || rc=$?
  sed 's/^/    | /' "${WORK}/chart-flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_PLAIN" gate-veridor-gate-r1)"
  record "plain: chart README flow, target vulnerable" "exit 1, a new Job, Failed (exit 1)" \
    "exit ${rc}, $([[ $uid != "$before" ]] && echo "a new Job" || echo "the previous run's Job"), ${status} (exit ${code})"
  rm -rf "$flow"
}

# --- scenario: Helm hook (hook.mode=helm) -------------------------------------

scenario_helm() {
  local leg rc release_status code
  log "scenario helm: hook.mode=helm; the release must fail when the gate fails"
  create_namespace "$NS_HELM"
  create_credentials "$NS_HELM"
  install_target "$NS_HELM" target-vuln yes
  install_target "$NS_HELM" target-fixed no
  for leg in vuln fixed; do
    gate_values "${WORK}/helm-${leg}.json" helm \
      "http://target-${leg}.${NS_HELM}.svc.cluster.local:${DEMO_PORT}" \
      "$([[ $leg == vuln ]] && echo yes || echo no)"
    rc=0
    h install "hook-${leg}" "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" \
      -n "$NS_HELM" -f "${WORK}/helm-${leg}.json" --timeout "${E2E_TIMEOUT}s" >"${WORK}/helm-${leg}.out" 2>&1 || rc=$?
    release_status="$(h status "hook-${leg}" -n "$NS_HELM" -o json 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["status"])' 2>/dev/null || echo unknown)"
    code="$(job_exit "$NS_HELM" "hook-${leg}-veridor-gate")"
    show_job_log "$NS_HELM" "hook-${leg}-veridor-gate"
    if [[ $leg == vuln ]]; then
      record "helm: install vs vulnerable target" "helm exit!=0, failed, gate exit 1" \
        "helm exit$([[ $rc -ne 0 ]] && echo '!=0' || echo '=0'), ${release_status}, gate exit ${code}"
    else
      record "helm: install vs fixed target" "helm exit=0, deployed, gate exit 0" \
        "helm exit$([[ $rc -ne 0 ]] && echo '!=0' || echo '=0'), ${release_status}, gate exit ${code}"
    fi
  done
  scenario_helm_same_release
}

# --- scenario helm, part two: the gate in the app's own release ---------------

# write_shop_chart -- an app chart as an adopter writes one for hook.mode helm:
# the demo API (RollingUpdate, the Deployment default) and the veridor-gate
# chart as its dependencies, in ONE release, so the post-upgrade hook gates
# this release's own rollout and a failed gate can roll it back.
write_shop_chart() {
  local dir="${WORK}/charts/vg-e2e-shop"
  rm -rf "$dir"
  mkdir -p "${dir}/charts"
  cp -R "${WORK}/charts/vg-e2e-demo-target" "${dir}/charts/vg-e2e-demo-target"
  cp -R "$CHART_DIR" "${dir}/charts/veridor-gate"
  cat >"${dir}/Chart.yaml" <<'CHART'
apiVersion: v2
name: vg-e2e-shop
description: the demo API with veridor-gate as a dependency, for scripts/e2e_kubernetes.sh only
version: 0.1.0
CHART
}

# shop_values OUT VULNERABLE(yes|no) REVISION SERVICE -- the app chart's
# values: the demo API, and the gate aimed at SERVICE (shop-this-revision, the
# Service of this release revision's pods, or shop, the app's own Service).
shop_values() {
  local out="$1" vulnerable="$2" revision="$3" service="$4"
  gate_values "${WORK}/shop-gate.json" helm "http://${service}.${NS_HELM}.svc.cluster.local:${DEMO_PORT}" "$vulnerable"
  python3 - "$out" "${WORK}/shop-gate.json" "$vulnerable" "$revision" "$E2E_TARGET_IMAGE" <<'PY'
import json, sys
out, gate_path, vulnerable, revision, image = sys.argv[1:]
json.dump({
    "vg-e2e-demo-target": {"image": image, "vulnerable": vulnerable == "yes", "revision": revision,
                           "strategy": "RollingUpdate", "revisionService": True,
                           # The new pod is Ready 5 s after it starts: the window
                           # in which Helm's default flags run the hook.
                           "readinessDelaySeconds": 5},
    "veridor-gate": json.load(open(gate_path)),
}, open(out, "w"), indent=2)
PY
}

# shop_leg NAME VULNERABLE REVISION SERVICE [HELM FLAG...] -- one
# `helm upgrade --install` of the app chart. Writes to SHOP_OBSERVED
# "<upgrade exit!=0|=0>, <status> (<description>), gate exit <n>" and, once the
# rollout (or the rollback's) has settled, to SHOP_RUNNING "<revision
# annotation>, <n> vulnerable pod(s)". Not run in $(...): it sets both.
shop_leg() {
  local name="$1" vulnerable="$2" revision="$3" service="$4" rc=0 status code deadline pods=""
  shift 4
  shop_values "${WORK}/shop-${name}.json" "$vulnerable" "$revision" "$service"
  h upgrade --install shop "${WORK}/charts/vg-e2e-shop" -n "$NS_HELM" -f "${WORK}/shop-${name}.json" \
    --timeout "${E2E_TIMEOUT}s" "$@" >"${WORK}/shop-${name}.out" 2>&1 || rc=$?
  status="$(h status shop -n "$NS_HELM" -o json 2>/dev/null \
    | python3 -c 'import json,sys; i=json.load(sys.stdin)["info"]; print("%s (%s)" % (i["status"], i.get("description", "")))' 2>/dev/null || echo unknown)"
  code="$(job_exit "$NS_HELM" shop-veridor-gate)"
  show_job_log "$NS_HELM" shop-veridor-gate
  log "shop ${name} ($*): exit ${rc}: $(tail -n 1 "${WORK}/shop-${name}.out")"
  SHOP_OBSERVED="upgrade exit$([[ $rc -ne 0 ]] && echo '!=0' || echo '=0'), ${status}, gate exit ${code}"
  # Settle: one pod, none terminating. The demo API ignores SIGTERM (PID 1
  # with no handler), so a replaced pod serves until it is killed. Only the
  # app's pods: the gate's pod, a dependency of the same release, carries
  # app.kubernetes.io/instance=shop too, and its finished pod stays until the
  # next upgrade, so selecting on the instance alone never saw one pod and
  # waited out E2E_TIMEOUT on every leg (measured: the four legs' gates ran
  # 311, 318, 304 and 306 s apart, about 20 of the scenario's 21 minutes).
  wait_deployment "$NS_HELM" shop || true
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    pods="$({ k -n "$NS_HELM" get pods -l app.kubernetes.io/instance=shop,app.kubernetes.io/name=vg-e2e-demo-target -o json 2>/dev/null || true; } | python3 -c '
import json, sys
try:
    pods = json.load(sys.stdin)["items"]
except ValueError:
    print("unreadable")
    raise SystemExit(0)
print(len(pods), sum(1 for p in pods if p["metadata"].get("deletionTimestamp")),
      sum(1 for p in pods if "--vulnerable" in p["spec"]["containers"][0]["command"]))')"
    [[ "$pods" == "1 0 "* ]] && break
    sleep 2
  done
  SHOP_RUNNING="$(k -n "$NS_HELM" get deployment shop -o jsonpath='{.spec.template.metadata.annotations.vg-e2e/revision}' 2>/dev/null || true), ${pods##* } vulnerable pod(s)"
}

# The chart README's documented invocation for hook.mode helm, measured: the
# gate as a dependency of the app's chart, aimed at a Service that selects
# only this release revision's pods, installed and upgraded with
# `helm upgrade --install --rollback-on-failure` (Helm 4; --atomic in Helm 3).
scenario_helm_same_release() {
  local rollback="--rollback-on-failure"
  h upgrade --help 2>/dev/null | grep -q -- "--rollback-on-failure" || rollback="--atomic"
  write_shop_chart
  shop_leg install no fixed-1 shop-this-revision "$rollback"
  record "helm: app chart + gate, ${rollback}, install fixed" \
    "upgrade exit=0, deployed (Install complete), gate exit 0" "$SHOP_OBSERVED"
  shop_leg vuln yes vulnerable-2 shop-this-revision "$rollback"
  record "helm: app chart + gate, ${rollback}, upgrade to vulnerable" \
    "upgrade exit!=0, deployed (Rollback to 1), gate exit 1" "$SHOP_OBSERVED"
  record "helm: after that failed upgrade, running" "fixed-1, 0 vulnerable pod(s)" "$SHOP_RUNNING"
  shop_leg fixed no fixed-4 shop-this-revision "$rollback"
  record "helm: app chart + gate, ${rollback}, upgrade to fixed" \
    "upgrade exit=0, deployed (Upgrade complete), gate exit 0" "$SHOP_OBSERVED"
  # Control: the hazard the invocation exists for. Helm's default flags run
  # the hook as soon as the manifests are applied; aimed at the app's own
  # Service, the gate probes the previous (fixed) pod and passes, and the
  # vulnerable version rolls out.
  shop_leg default-flags yes vulnerable-5 shop
  record "helm: control, Helm's default flags, gate aimed at the app's Service" \
    "upgrade exit=0, deployed (Upgrade complete), gate exit 0" "$SHOP_OBSERVED"
  record "helm: control, after it, running" "vulnerable-5, 1 vulnerable pod(s)" "$SHOP_RUNNING"
}

# --- scenario: Argo CD PostSync -----------------------------------------------

# argocd_application OUT VULNERABLE(yes|no) [SERVICE [DEMO_VALUES_JSON]] --
# the Application, built from deploy/argocd/application-example.yaml. Its gate
# values are kept verbatim -- hook settings, gate flags, secretEnv and the
# Veridor configuration a reader copies -- except the placeholders: the gate
# image, the chart repository, and the target URL, pointed at the in-cluster
# demo's SERVICE (default demo, the app's own Service). DEMO_VALUES_JSON is
# merged into the demo app's values. The e2e used to substitute its own
# configuration here, so the example's was never run; it exited 3
# (liveness_unproven) against a fixed target (measured).
argocd_application() {
  local out="$1" vulnerable="$2" service="${3:-demo}" demo_values="${4:-}"
  [[ -n "$demo_values" ]] || demo_values='{}'
  k create --dry-run=client -o json -f "${ROOT}/deploy/argocd/application-example.yaml" >"${WORK}/application-example.json"
  python3 - "${WORK}/application-example.json" "$out" \
    "$ARGO_APP" "$ARGO_PROJECT" "$NS_ARGOCD" "$REPO_URL" "$CHART_VERSION" "$vulnerable" "$E2E_TARGET_IMAGE" \
    "http://${service}.${NS_ARGOCD}.svc.cluster.local:${DEMO_PORT}" "$GATE_REPOSITORY" "$GATE_TAG" "$E2E_CONTROL" \
    "$demo_values" <<'PY'
import json, sys
(example_path, out, name, project, namespace, repo, version, vulnerable, target_image,
 target_url, gate_repository, gate_tag, control, demo_values) = sys.argv[1:]
app = json.load(open(example_path))
gate = next(s for s in app["spec"]["sources"] if s.get("chart") == "veridor-gate")
values = gate["helm"]["valuesObject"]
assert values["hook"]["mode"] == "argocd", "the example must use hook.mode=argocd"
values["image"] = {"repository": gate_repository, "tag": gate_tag, "pullPolicy": "IfNotPresent"}
values["target"]["baseUrl"] = target_url
values["config"]["target"]["base_url"] = target_url
if control == "gate-passes-wrongly" and vulnerable == "yes":
    values.setdefault("gate", {})["failOn"] = "none"
gate["repoURL"] = repo
gate["targetRevision"] = version
app_source = {
    "repoURL": repo,
    "chart": "vg-e2e-demo-target",
    "targetRevision": version,
    "helm": {
        "releaseName": "demo",
        "valuesObject": {"image": target_image, "vulnerable": vulnerable == "yes",
                          "revision": "vulnerable" if vulnerable == "yes" else "fixed",
                          **json.loads(demo_values)},
    },
}
app["spec"]["sources"] = [app_source, gate]
app["metadata"] = {"name": name, "namespace": "argocd"}
app["spec"]["project"] = project
app["spec"]["destination"]["namespace"] = namespace
json.dump(app, open(out, "w"), indent=2)
PY
}

# example_secret -> the one Secret the example's secretEnv names
example_secret() {
  k create --dry-run=client -o json -f "${ROOT}/deploy/argocd/application-example.yaml" | python3 -c '
import json, sys
app = json.load(sys.stdin)
gate = next(s for s in app["spec"]["sources"] if s.get("chart") == "veridor-gate")
names = {entry["secretName"] for entry in gate["helm"]["valuesObject"]["secretEnv"]}
assert len(names) == 1, names
print(names.pop())
'
}

# sync_application [APP [SYNC_JSON]] -> starts an operation whose sync is
# SYNC_JSON (default {"prune":true}, a full sync), waits for it to finish, and
# prints its phase
sync_application() {
  local app="${1:-$ARGO_APP}" sync="${2:-}" before after phase deadline
  [[ -n "$sync" ]] || sync='{"prune":true}'
  before="$(k -n argocd get application "$app" -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null || true)"
  k -n argocd patch application "$app" --type merge \
    -p "{\"operation\":{\"initiatedBy\":{\"username\":\"vg-e2e\"},\"sync\":${sync}}}" >/dev/null
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    after="$(k -n argocd get application "$app" -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null || true)"
    phase="$(k -n argocd get application "$app" -o jsonpath='{.status.operationState.phase}' 2>/dev/null || true)"
    if [[ -n "$after" && "$after" != "$before" ]]; then
      case "$phase" in
        Succeeded | Failed | Error) echo "$phase"; return 0 ;;
      esac
    fi
    sleep 3
  done
  echo Timeout
}

# hook_result [APP] -> "<kind>/<name> <hookPhase>" for the PostSync hook of the
# last operation; the hook's own message goes to the log.
hook_result() {
  k -n argocd get application "${1:-$ARGO_APP}" -o json | python3 -c '
import json, sys
app = json.load(sys.stdin)
resources = (((app.get("status") or {}).get("operationState") or {}).get("syncResult") or {}).get("resources") or []
hooks = [r for r in resources if r.get("hookType") == "PostSync"]
for r in hooks:
    sys.stderr.write("==> Argo CD hook %s/%s message: %s\n" % (r.get("kind"), r.get("name"), r.get("message")))
print(" ".join("%s/%s %s" % (r.get("kind"), r.get("name"), r.get("hookPhase")) for r in hooks) or "no-PostSync-hook")
'
}

# sync_job NS [APP] -- sets SYNC_JOB to the gate Job the last operation
# created: the one PostSync Job its syncResult names, if a Job of that name
# exists in NS and was created at or after the operation's startedAt; else
# "none". Never a Job looked up by a name fixed in advance: the chart's
# argocd-mode Job has none (generateName), and with one fixed name a Job the
# previous sync left could stand in for this sync's (measured: Argo CD itself
# reported syncs from it). Each result is appended to ARGO_SYNC_JOBS. Not
# called in $(...), whose subshell would lose both.
ARGO_SYNC_JOBS=()
SYNC_JOB=none
sync_job() {
  local ns="$1" app="${2:-$ARGO_APP}" name started created
  read -r name started <<<"$(k -n argocd get application "$app" -o json | python3 -c '
import json, sys
state = (json.load(sys.stdin).get("status") or {}).get("operationState") or {}
hooks = [r for r in (state.get("syncResult") or {}).get("resources") or []
         if r.get("hookType") == "PostSync" and r.get("kind") == "Job"]
print(hooks[0]["name"] if len(hooks) == 1 else "-", state.get("startedAt") or "-")')"
  created="$(k -n "$ns" get job "$name" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null || true)"
  # Both are RFC 3339 UTC to the second, so they order as strings.
  if [[ "$name" != "-" && "$started" != "-" && -n "$created" && ! "$created" < "$started" ]]; then
    SYNC_JOB="$name"
  else
    log "no gate Job for this sync: syncResult names '${name}', operation started ${started}, that Job created '${created:-never}'"
    SYNC_JOB=none
  fi
  ARGO_SYNC_JOBS+=("$SYNC_JOB")
}

# comparison_error [TEXT] -> the ComparisonError condition message, once one
# appears that contains TEXT (any, when TEXT is empty: an Application refused
# before still carries the earlier message until Argo CD compares again);
# else the last message seen, or "no ComparisonError".
comparison_error() {
  local needle="${1:-}" deadline message last="no ComparisonError"
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    message="$(k -n argocd get application "$ARGO_APP" -o jsonpath='{.status.conditions[?(@.type=="ComparisonError")].message}' 2>/dev/null || true)"
    if [[ -n "$message" ]]; then
      last="$message"
      if [[ -z "$needle" || "$message" == *"$needle"* ]]; then
        echo "$message"
        return 0
      fi
    fi
    sleep 3
  done
  echo "$last"
}

# comparison_clears -> "rendered" once the Application has compared with no
# ComparisonError (sync status OutOfSync or Synced); else the ComparisonError
# message still standing, or "not compared".
comparison_clears() {
  local deadline state
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    state="$(k -n argocd get application "$ARGO_APP" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    status = json.load(sys.stdin).get("status") or {}
except ValueError:
    print("unreadable")
    raise SystemExit(0)
errors = [c.get("message", "") for c in status.get("conditions") or [] if c.get("type") == "ComparisonError"]
compared = (status.get("sync") or {}).get("status") in ("OutOfSync", "Synced")
print(errors[0] if errors else ("rendered" if compared else "not compared"))' || true)"
    [[ "$state" == rendered ]] && break
    sleep 3
  done
  echo "${state:-not compared}"
}

scenario_argocd() {
  local phase message hook code job prefix live rc out
  log "scenario argocd: Application with the veridor-gate chart as its PostSync hook"
  create_namespace "$NS_ARGOCD"
  # The Secret the example names, so its secretEnv runs unchanged.
  create_credentials "$NS_ARGOCD" "$(example_secret)"
  k apply -f - >/dev/null <<EOF
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: ${ARGO_PROJECT}
  namespace: argocd
spec:
  description: scripts/e2e_kubernetes.sh only; deleted when the script exits
  sourceRepos:
    - ${REPO_URL}
  destinations:
    - server: https://kubernetes.default.svc
      namespace: ${NS_ARGOCD}
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
EOF
  # The example names its gate release invoices-api-gate; Argo CD names each
  # sync's Job <release>-veridor-gate-<revision>-postsync-<start>, with no
  # revision for an Application of several sources. Read the release rather
  # than assume it.
  prefix="$(k create --dry-run=client -o jsonpath='{.spec.sources[1].helm.releaseName}' -f "${ROOT}/deploy/argocd/application-example.yaml")-veridor-gate-"

  argocd_application "${WORK}/app-vuln.json" yes
  k apply -f "${WORK}/app-vuln.json" >/dev/null
  phase="$(sync_application)"
  message="$(k -n argocd get application "$ARGO_APP" -o jsonpath='{.status.operationState.message}')"
  hook="$(hook_result)"
  sync_job "$NS_ARGOCD"
  job="$SYNC_JOB"
  wait_job "$NS_ARGOCD" "$job" >/dev/null
  code="$(job_exit "$NS_ARGOCD" "$job")"
  log "Argo CD operation message: ${message}"
  show_job_log "$NS_ARGOCD" "$job"
  record "argocd: sync vs vulnerable target" "Failed" "$phase"
  record "argocd: PostSync hook in syncResult (vulnerable)" "this sync's Job, ${prefix}*, Failed" \
    "$(this_sync_hook "$hook" "$job" "$prefix")"
  record "argocd: hook Job exit code (vulnerable)" "1" "$code"
  # A PostSync hook cannot undo the sync: the new version is already live.
  live="$(k -n "$NS_ARGOCD" get deployment demo -o jsonpath='{.spec.template.metadata.annotations.vg-e2e/revision}' 2>/dev/null || echo none)"
  record "argocd: after failed gate, running version" "vulnerable" "$live"
  # What the Application itself shows: the resources were applied and are
  # healthy; only the operation failed. Alert on the operation, not on these.
  record "argocd: after failed gate, app sync/health" "Synced/Healthy" \
    "$(k -n argocd get application "$ARGO_APP" -o jsonpath='{.status.sync.status}/{.status.health.status}')"

  argocd_application "${WORK}/app-fixed.json" no
  k apply -f "${WORK}/app-fixed.json" >/dev/null
  phase="$(sync_application)"
  hook="$(hook_result)"
  sync_job "$NS_ARGOCD"
  job="$SYNC_JOB"
  wait_job "$NS_ARGOCD" "$job" >/dev/null
  code="$(job_exit "$NS_ARGOCD" "$job")"
  show_job_log "$NS_ARGOCD" "$job"
  record "argocd: sync vs fixed target" "Succeeded" "$phase"
  record "argocd: PostSync hook in syncResult (fixed)" "this sync's Job, ${prefix}*, Succeeded" \
    "$(this_sync_hook "$hook" "$job" "$prefix")"
  record "argocd: hook Job exit code (fixed)" "0" "$code"

  # The first sync above deployed the vulnerable version into an empty
  # namespace. Now fixed -> vulnerable, with a version to replace: the demo app
  # runs strategy Recreate, whose old pod is gone before the new one starts,
  # so the PostSync gate can reach only the new version. With one fixed Job
  # name, Argo CD v3.5.3 reported vulnerable syncs Succeeded while their gate
  # Job failed, from the previous sync's Job (4 of 5 runs of this scenario).
  argocd_application "${WORK}/app-vuln-again.json" yes
  k apply -f "${WORK}/app-vuln-again.json" >/dev/null
  phase="$(sync_application)"
  log "argocd Recreate fixed -> vulnerable: hook $(hook_result)"
  sync_job "$NS_ARGOCD"
  job="$SYNC_JOB"
  wait_job "$NS_ARGOCD" "$job" >/dev/null
  code="$(job_exit "$NS_ARGOCD" "$job")"
  show_job_log "$NS_ARGOCD" "$job"
  record "argocd: Recreate app, fixed -> vulnerable: gate exit" "1" "$code"
  record "argocd: Recreate app, fixed -> vulnerable: sync" "Failed" "$phase"

  # Syncs that run no gate. Argo CD v3.5.3 runs no hook for a sync that names
  # resources (`argocd app sync --resource`, some resources from the UI,
  # self-heal) or uses the apply strategy (`--strategy apply`, "Apply Only"):
  # controller/sync.go passes skipHooks for either. The vulnerable version is
  # deployed and its full sync just Failed on the gate; each of these
  # operations is expected to end Succeeded with no PostSync entry in its
  # syncResult and no new gate Job. Not rows for sync_job: no gate ran.
  local ungated jobs_before jobs_after
  for ungated in selective apply-only; do
    jobs_before="$(k -n "$NS_ARGOCD" get jobs -l app.kubernetes.io/name=veridor-gate -o name | sort | tr '\n' ' ')"
    if [[ $ungated == selective ]]; then
      phase="$(sync_application "$ARGO_APP" '{"prune":true,"resources":[{"group":"apps","kind":"Deployment","name":"demo"}]}')"
    else
      phase="$(sync_application "$ARGO_APP" '{"prune":true,"syncStrategy":{"apply":{}}}')"
    fi
    hook="$(hook_result)"
    jobs_after="$(k -n "$NS_ARGOCD" get jobs -l app.kubernetes.io/name=veridor-gate -o name | sort | tr '\n' ' ')"
    log "argocd ${ungated} sync: phase ${phase}, message: $(k -n argocd get application "$ARGO_APP" -o jsonpath='{.status.operationState.message}'), hook: ${hook}, running: $(k -n "$NS_ARGOCD" get deployment demo -o jsonpath='{.spec.template.metadata.annotations.vg-e2e/revision}')"
    # "none" only from a listing that saw the earlier syncs' Jobs: an empty
    # one (a wrong selector, an unreadable namespace) is "cannot see".
    record "argocd: ${ungated} sync, vulnerable version: phase, PostSync entry, new gate Job" "Succeeded, no-PostSync-hook, none" \
      "${phase}, ${hook}, $(if [[ -z "${jobs_before// /}" ]]; then echo "cannot see"; elif [[ "$jobs_after" == "$jobs_before" ]]; then echo none; else echo "${jobs_after}"; fi)"
  done

  # A literal credential in the gate's values: the chart refuses to render,
  # so Argo CD cannot even compare -- and the value is not in the message.
  local literal="e2e-literal-credential-${RUN_ID}" error
  python3 - "${WORK}/app-fixed.json" "${WORK}/app-literal.json" "$literal" <<'PY'
import json, sys
source, out, literal = sys.argv[1:]
app = json.load(open(source))
gate = next(s for s in app["spec"]["sources"] if s.get("chart") == "veridor-gate")
gate["helm"]["valuesObject"]["config"]["identities"]["invoice_owner"]["headers"]["Authorization"] = "Bearer " + literal
json.dump(app, open(out, "w"), indent=2)
PY
  k apply -f "${WORK}/app-literal.json" >/dev/null
  k -n argocd annotate application "$ARGO_APP" argocd.argoproj.io/refresh=hard --overwrite >/dev/null
  error="$(comparison_error)"
  log "Argo CD ComparisonError: ${error}"
  record "argocd: literal credential in values" "ComparisonError, path named" \
    "$([[ "$error" == *"config.identities.invoice_owner.headers.Authorization carries a literal value"* ]] && echo 'ComparisonError, path named' || echo "${error:0:60}")"
  record "argocd: literal value echoed in the error" "no" "$([[ "$error" == *"$literal"* ]] && echo yes || echo no)"

  # The mirror of the Helm CLI refusal below: hook.mode helm rendered by Argo
  # CD. Argo CD maps its post-install,post-upgrade hook to PostSync under one
  # fixed name, and v3.5.3 reported syncs from the previous sync's Job (14 of
  # 80 in an Application of the gate alone, measured before the chart refused
  # it). The chart refuses a helm-mode render that reaches no cluster, so Argo
  # CD cannot even compare. The control is the same Application with the
  # Helm CLI's opt-in: it renders, so the refusal is what the row reads.
  local mode_app
  for mode_app in refused opted-in; do
    python3 - "${WORK}/app-fixed.json" "${WORK}/app-helm-mode-${mode_app}.json" "$mode_app" <<'PY'
import json, sys
source, out, which = sys.argv[1:]
app = json.load(open(source))
gate = next(s for s in app["spec"]["sources"] if s.get("chart") == "veridor-gate")
gate["helm"]["valuesObject"]["hook"] = {"mode": "helm"}
if which == "opted-in":
    gate["helm"]["valuesObject"]["hook"]["helm"] = {"allowRenderWithoutCluster": True}
json.dump(app, open(out, "w"), indent=2)
PY
  done
  k apply -f "${WORK}/app-helm-mode-refused.json" >/dev/null
  k -n argocd annotate application "$ARGO_APP" argocd.argoproj.io/refresh=hard --overwrite >/dev/null
  error="$(comparison_error "hook.mode is helm, and this render reached no cluster")"
  log "Argo CD ComparisonError (helm-mode chart): ${error}"
  record "argocd: helm-mode gate chart" "ComparisonError, refusal named" \
    "$([[ "$error" == *"veridor-gate: hook.mode is helm, and this render reached no cluster"* ]] && echo 'ComparisonError, refusal named' || echo "${error:0:60}")"
  k apply -f "${WORK}/app-helm-mode-opted-in.json" >/dev/null
  k -n argocd annotate application "$ARGO_APP" argocd.argoproj.io/refresh=hard --overwrite >/dev/null
  out="$(comparison_clears)"
  log "Argo CD, helm-mode chart with allowRenderWithoutCluster (control, not synced): ${out}"
  record "argocd: control, helm-mode chart with allowRenderWithoutCluster" "rendered" "${out:0:60}"

  # The Helm CLI does not run Argo CD hooks, and the argocd-mode Job has no
  # name. Before the chart refused this, `helm install --server-side=false`
  # (how Helm 3 applies) exited 0 with the release deployed and a Job the API
  # server named, which nothing waited for (measured with Helm 4.2.2).
  gate_values "${WORK}/cli-argocd.json" argocd "http://demo.${NS_ARGOCD}.svc.cluster.local:${DEMO_PORT}" no
  rc=0
  out="$(h install vg-e2e-cli "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" -n "$NS_ARGOCD" \
    -f "${WORK}/cli-argocd.json" 2>&1)" || rc=$?
  log "Helm CLI install of the argocd-mode chart: exit ${rc}: ${out//$'\n'/ }"
  record "argocd: Helm CLI install of the argocd-mode chart" "refused at render, no Job, no release" \
    "$([[ $rc -ne 0 && "$out" == *"veridor-gate: hook.mode is argocd, and this render reached a cluster"* ]] && echo 'refused at render' || echo "exit ${rc}"), $(
      [[ -n "$(k -n "$NS_ARGOCD" get jobs -l app.kubernetes.io/instance=vg-e2e-cli -o name)" ]] && echo 'a Job' || echo 'no Job'), $(
      h status vg-e2e-cli -n "$NS_ARGOCD" >/dev/null 2>&1 && echo 'a release' || echo 'no release')"

  scenario_argocd_rolling "$prefix"
}

# this_sync_hook HOOK JOB PREFIX -> "this sync's Job, PREFIX*, <hookPhase>" when
# hook_result's "Job/<name> <hookPhase>" names JOB (sync_job's pick) and JOB
# starts with PREFIX; else HOOK as it was.
this_sync_hook() {
  local hook="$1" job="$2" prefix="$3"
  if [[ "$job" != none && "$job" == "$prefix"* && "$hook" == "Job/${job} "* ]]; then
    echo "this sync's Job, ${prefix}*, ${hook##* }"
  else
    echo "$hook"
  fi
}

# --- scenario argocd, part two: a RollingUpdate app ---------------------------

# serving_demo_pod -> the one demo pod that is Ready and not terminating, or
# "" when there is not exactly one.
serving_demo_pod() {
  { k -n "$NS_ARGOCD" get pods -l app.kubernetes.io/instance=demo -o json 2>/dev/null || echo '{}'; } | python3 -c '
import json, sys
pods = [p for p in json.load(sys.stdin).get("items", [])
        if not p["metadata"].get("deletionTimestamp")
        and any(c["type"] == "Ready" and c["status"] == "True" for c in p.get("status", {}).get("conditions", []))]
print(pods[0]["metadata"]["name"] if len(pods) == 1 else "")'
}

# pod_label POD KEY -> the label's value, "(none)", or "(pod gone)"
pod_label() {
  { k -n "$NS_ARGOCD" get pod "$1" -o json 2>/dev/null || echo '{}'; } | python3 -c '
import json, sys
pod = json.load(sys.stdin)
print(((pod.get("metadata") or {}).get("labels") or {}).get(sys.argv[1], "(none)") if pod else "(pod gone)")' "$2"
}

# slice_lists SERVICE POD -> yes if an EndpointSlice of SERVICE lists POD (in
# any condition: a terminating pod is listed with serving/terminating), else no
slice_lists() {
  local names
  names="$(k -n "$NS_ARGOCD" get endpointslices -l "kubernetes.io/service-name=$1" \
    -o jsonpath='{range .items[*].endpoints[*]}{.targetRef.name}{" "}{end}')"
  case " $names " in *" $2 "*) echo yes ;; *) echo no ;; esac
}

# gate_requests POD IP -> how many requests from IP the pod's log shows, or
# "cannot see" when the pod or its log is gone (never 0 for "no log").
gate_requests() {
  local text
  if [[ -z "$2" ]] || ! text="$(k -n "$NS_ARGOCD" logs "$1" 2>/dev/null)"; then
    echo "cannot see"
    return 0
  fi
  grep -c "^vg-e2e-request pod=$1 client=$2 " <<<"$text" || true
}

# argocd_rolling_leg NAME VULNERABLE SERVICE DEMO_VALUES_JSON -- one sync.
# Sets ROLL_PHASE, ROLL_CODE, ROLL_REPLACED (the pod serving before the sync),
# ROLL_NEW (the one serving after it) and ROLL_GATE_IP (the gate pod's IP).
argocd_rolling_leg() {
  local name="$1" vulnerable="$2" service="$3" demo_values="$4" job uid deadline
  ROLL_REPLACED="$(serving_demo_pod)"
  argocd_application "${WORK}/app-${name}.json" "$vulnerable" "$service" "$demo_values"
  k apply -f "${WORK}/app-${name}.json" >/dev/null
  ROLL_PHASE="$(sync_application)"
  log "argocd ${name}: operation message: $(k -n argocd get application "$ARGO_APP" -o jsonpath='{.status.operationState.message}' 2>/dev/null || true); hook: $(hook_result)"
  # This sync's Job, and its own outcome, which can come after the operation's.
  sync_job "$NS_ARGOCD"
  job="$SYNC_JOB"
  wait_job "$NS_ARGOCD" "$job" >/dev/null
  ROLL_CODE="$(job_exit "$NS_ARGOCD" "$job")"
  uid="$(k -n "$NS_ARGOCD" get job "$job" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  ROLL_GATE_IP="$(k -n "$NS_ARGOCD" get pods -l "controller-uid=${uid:-none}" -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)"
  show_job_log "$NS_ARGOCD" "$job"
  deadline=$((SECONDS + E2E_TIMEOUT))
  ROLL_NEW=""
  while ((SECONDS < deadline)); do
    ROLL_NEW="$(serving_demo_pod)"
    [[ -n "$ROLL_NEW" ]] && break
    sleep 2
  done
  log "argocd ${name}: sync ${ROLL_PHASE}, gate exit ${ROLL_CODE}, gate pod ${ROLL_GATE_IP:-?}, replaced pod ${ROLL_REPLACED:-none}, serving pod ${ROLL_NEW:-none}"
}

# A PostSync gate runs once every Sync-phase resource is Healthy, and a
# RollingUpdate Deployment is Healthy while the pod it replaced is still
# terminating -- and, for the demo API, still serving. The chart README's
# Helm-CLI recipe, a label from .Release.Revision and a Service selecting it,
# does not separate the two under Argo CD, which renders with `helm template`:
# the revision is 1 on every sync (the control). A label from a hash of the
# rendered pod template changes with every version (the recipe). The
# replaced pods get a 90 s grace so their logs can still be read after the
# gate; the new pod turns Ready 15 s after it starts.
scenario_argocd_rolling() {
  local prefix="$1" control recipe replaced_count new_count
  control='{"strategy": "RollingUpdate", "revisionService": true, "readinessDelaySeconds": 15, "terminationGracePeriodSeconds": 90, "logRequests": true}'
  recipe='{"strategy": "RollingUpdate", "podTemplateService": true, "readinessDelaySeconds": 15, "terminationGracePeriodSeconds": 90, "logRequests": true}'

  argocd_rolling_leg revision-fixed no demo-this-revision "$control"
  record "argocd: RollingUpdate, .Release.Revision label: fixed sync" "Succeeded" "$ROLL_PHASE"
  argocd_rolling_leg revision-vuln yes demo-this-revision "$control"
  record "argocd: .Release.Revision label on the replaced / the new pod" "1 / 1" \
    "$(pod_label "$ROLL_REPLACED" vg-e2e/release-revision) / $(pod_label "$ROLL_NEW" vg-e2e/release-revision)"
  record "argocd: demo-this-revision lists the replaced pod after the sync" "yes" "$(slice_lists demo-this-revision "$ROLL_REPLACED")"
  # Not a row: whether the gate reached the replaced pod is a race.
  replaced_count="$(gate_requests "$ROLL_REPLACED" "$ROLL_GATE_IP")"
  new_count="$(gate_requests "$ROLL_NEW" "$ROLL_GATE_IP")"
  log "argocd control (.Release.Revision label, not a row): sync ${ROLL_PHASE}, gate exit ${ROLL_CODE}; gate requests answered by the replaced pod: ${replaced_count}, by the new pod: ${new_count}"

  argocd_rolling_leg template-fixed no demo-this-pod-template "$recipe"
  record "argocd: RollingUpdate, pod-template label: fixed sync" "Succeeded" "$ROLL_PHASE"
  argocd_rolling_leg template-vuln yes demo-this-pod-template "$recipe"
  record "argocd: pod-template label: vulnerable sync: gate exit" "1" "$ROLL_CODE"
  record "argocd: pod-template label: vulnerable sync: sync" "Failed" "$ROLL_PHASE"
  record "argocd: pod-template label on the replaced and the new pod" "differ" \
    "$(python3 -c 'import sys; a, b = sys.argv[1:]; print("differ" if a != b and "(" not in a + b else "same: " + a)' \
      "$(pod_label "$ROLL_REPLACED" vg-e2e/pod-template)" "$(pod_label "$ROLL_NEW" vg-e2e/pod-template)")"
  record "argocd: demo-this-pod-template lists the replaced pod after the sync" "no" "$(slice_lists demo-this-pod-template "$ROLL_REPLACED")"
  record "argocd: pod-template label: replaced pod still readable" "yes" \
    "$([[ "$(pod_label "$ROLL_REPLACED" app.kubernetes.io/instance)" == demo ]] && echo yes || echo no)"
  replaced_count="$(gate_requests "$ROLL_REPLACED" "$ROLL_GATE_IP")"
  new_count="$(gate_requests "$ROLL_NEW" "$ROLL_GATE_IP")"
  log "argocd recipe (pod-template label): gate requests answered by the replaced pod: ${replaced_count}, by the new pod: ${new_count}"
  record "argocd: pod-template label: gate requests the replaced pod answered" "0" "$replaced_count"
  record "argocd: pod-template label: gate requests the new pod answered" "some" \
    "$([[ "$new_count" =~ ^[1-9][0-9]*$ ]] && echo some || echo "$new_count")"

  # Seven syncs above, and each read a Job of its own: none shared a name, and
  # every one began with the chart's prefix.
  record "argocd: each sync's gate Job, by name" "7 syncs, 7 Jobs, all ${prefix}*" \
    "$(python3 -c '
import sys
prefix, names = sys.argv[1], sys.argv[2:]
mine = [n for n in names if n != "none" and n.startswith(prefix)]
print("%d syncs, %d Jobs, %s" % (len(names), len(set(mine)),
      "all %s*" % prefix if len(mine) == len(names) else "other: " + " ".join(n for n in names if n not in mine)))' \
      "$prefix" ${ARGO_SYNC_JOBS[@]+"${ARGO_SYNC_JOBS[@]}"})"
}

# --- scenario: Argo Rollouts canary analysis ----------------------------------

# rollout_manifest OUT VULNERABLE(yes|no) REVISION -- deploy/argo-rollouts/
# rollout-example.yaml with the pod's container, volumes and uid/gid replaced by
# the demo API, a revision annotation added, and two analysis args appended (the
# gate image, and this script's Secret). Services, strategy, steps and the
# analysis base-url are the example's, verbatim.
rollout_manifest() {
  local out="$1" vulnerable="$2" revision="$3"
  k create --dry-run=client -o json -f "${ROOT}/deploy/argo-rollouts/rollout-example.yaml" >"${WORK}/rollout-example.json"
  python3 - "${WORK}/rollout-example.json" "$out" "$vulnerable" "$revision" "$E2E_TARGET_IMAGE" "$E2E_GATE_IMAGE" "$E2E_CONTROL" <<'PY'
import json, sys
example_path, out, vulnerable, revision, target_image, gate_image, control = sys.argv[1:]
# `kubectl create --dry-run=client -o json` prints one JSON object per document.
text, items, position = open(example_path).read(), [], 0
decoder = json.JSONDecoder()
while position < len(text):
    if text[position].isspace():
        position += 1
        continue
    obj, position = decoder.raw_decode(text, position)
    items.extend(obj["items"] if obj.get("kind") == "List" else [obj])
doc = {"apiVersion": "v1", "kind": "List", "items": items}
for item in items:
    # The client dry-run fills in the kubeconfig's default namespace.
    item["metadata"].pop("namespace", None)
for item in items:
    if item["kind"] != "Rollout":
        continue
    pod = item["spec"]["template"]["spec"]
    container = pod["containers"][0]
    port = next(p["containerPort"] for p in container["ports"] if p.get("name") == "http")
    command = ["python3", "/demo/demo_server.py", "--host", "0.0.0.0", "--port", str(port)]
    if vulnerable == "yes":
        command.append("--vulnerable")
    container["image"] = target_image
    container["imagePullPolicy"] = "IfNotPresent"
    container["command"] = command
    container["volumeMounts"] = [{"name": "server", "mountPath": "/demo", "readOnly": True}]
    pod["volumes"] = [{"name": "server", "configMap": {"name": "vg-e2e-demo-server"}}]
    pod["securityContext"]["runAsUser"] = 10001
    pod["securityContext"]["runAsGroup"] = 10001
    item["spec"]["template"]["metadata"].setdefault("annotations", {})["vg-e2e/revision"] = revision
    for step in item["spec"]["strategy"]["canary"]["steps"]:
        if "analysis" in step:
            args = step["analysis"].setdefault("args", [])
            args.append({"name": "image", "value": gate_image})
            args.append({"name": "secret", "value": "vg-e2e-credentials"})
            if control == "gate-passes-wrongly" and vulnerable == "yes":
                args.append({"name": "fail-on", "value": "none"})
json.dump(doc, open(out, "w"), indent=2)
PY
}

# wait_rollout WANT [STABLE_BEFORE] -> the phase once it is WANT, the other
# terminal phase if the rollout ends there instead, or Timeout(<last phase>).
# Nothing is read until the controller has observed the current spec: a phase
# from the previous revision would otherwise answer immediately. The generation
# is re-read every time, because the controller bumps it itself right after a
# Rollout is created (measured: 1 -> 2 within a second).
wait_rollout() {
  local want="$1" stable_before="${2:-}" phase="" state generation observed deadline
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    state="$(k -n "$NS_ROLLOUTS" get rollout invoices-api -o jsonpath='{.metadata.generation} {.status.observedGeneration}' 2>/dev/null || true)"
    generation="${state%% *}"
    observed="${state#* }"
    if [[ -n "$generation" && "$observed" == "$generation" ]]; then
      phase="$(k -n "$NS_ROLLOUTS" get rollout invoices-api -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      if [[ "$phase" == "$want" ]]; then
        echo "$phase"
        return 0
      fi
      # The other terminal outcome ends the wait too, so a mismatch does not
      # cost the full timeout: an aborted canary when promotion was expected,
      # or a promoted one (stable moved) when an abort was expected.
      if [[ "$want" == "Healthy" && "$phase" == "Degraded" ]]; then
        echo "$phase"
        return 0
      fi
      if [[ "$want" == "Degraded" && "$phase" == "Healthy" && -n "$stable_before" && "$(rollout_revision)" != "$stable_before" ]]; then
        echo "$phase"
        return 0
      fi
    fi
    sleep 3
  done
  echo "Timeout(${phase:-none})"
}

# split_at_analysis STABLE_HASH -> "canary=<ready> stable=<ready>" read as soon
# as the canary's AnalysisRun exists, i.e. after the setWeight step completed.
split_at_analysis() {
  local stable="$1" canary="" deadline
  deadline=$((SECONDS + E2E_TIMEOUT))
  while ((SECONDS < deadline)); do
    canary="$(k -n "$NS_ROLLOUTS" get rollout invoices-api -o jsonpath='{.status.currentPodHash}' 2>/dev/null || true)"
    if [[ -n "$canary" && "$canary" != "$stable" ]] \
      && [[ -n "$(k -n "$NS_ROLLOUTS" get analysisrun -l "rollouts-pod-template-hash=${canary}" -o name 2>/dev/null)" ]]; then
      printf 'canary=%s stable=%s' \
        "$(k -n "$NS_ROLLOUTS" get rs -l "rollouts-pod-template-hash=${canary}" -o jsonpath='{.items[0].status.readyReplicas}')" \
        "$(k -n "$NS_ROLLOUTS" get rs -l "rollouts-pod-template-hash=${stable}" -o jsonpath='{.items[0].status.readyReplicas}')"
      return 0
    fi
    sleep 1
  done
  echo "no AnalysisRun for the canary"
}

rollout_revision() {
  k -n "$NS_ROLLOUTS" get rollout invoices-api -o jsonpath='{.status.stableRS}' 2>/dev/null || true
}

# The AnalysisRun of the current canary: "<phase> job-exit=<code>"
analysis_result() {
  local run phase uid job code
  run="$(k -n "$NS_ROLLOUTS" get analysisrun -o json | python3 -c '
import json, sys
runs = json.load(sys.stdin)["items"]
runs.sort(key=lambda r: r["metadata"]["creationTimestamp"])
print(runs[-1]["metadata"]["name"] if runs else "")
')"
  [[ -n "$run" ]] || { echo "no-AnalysisRun"; return 0; }
  phase="$(k -n "$NS_ROLLOUTS" get analysisrun "$run" -o jsonpath='{.status.phase}')"
  uid="$(k -n "$NS_ROLLOUTS" get analysisrun "$run" -o jsonpath='{.metadata.uid}')"
  job="$(k -n "$NS_ROLLOUTS" get jobs -l "analysisrun.argoproj.io/uid=${uid}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  code="none"
  if [[ -n "$job" ]]; then
    code="$(job_exit "$NS_ROLLOUTS" "$job")"
    show_job_log "$NS_ROLLOUTS" "$job"
  fi
  echo "${phase} job-exit=${code}"
}

scenario_rollouts() {
  local phase stable_before stable_after analysis aborted
  log "scenario rollouts: canary analysis with deploy/argo-rollouts/veridor-analysistemplate.yaml"
  create_namespace "$NS_ROLLOUTS"
  create_credentials "$NS_ROLLOUTS"
  k -n "$NS_ROLLOUTS" create configmap vg-e2e-demo-server --from-file=demo_server.py="${ROOT}/scripts/demo_server.py" >/dev/null
  k -n "$NS_ROLLOUTS" create configmap veridor-config --from-file=veridor.json="${WORK}/gate-config.json" >/dev/null
  k -n "$NS_ROLLOUTS" apply -f "${ROOT}/deploy/argo-rollouts/veridor-analysistemplate.yaml" >/dev/null

  # Revision 1: the fixed API. A first rollout has no stable version to protect,
  # so Argo Rollouts promotes it without running the steps.
  rollout_manifest "${WORK}/rollout-1.json" no fixed-1
  k -n "$NS_ROLLOUTS" apply -f "${WORK}/rollout-1.json" >/dev/null
  phase="$(wait_rollout Healthy)"
  record "rollouts: initial stable (fixed)" "Healthy" "$phase"
  stable_before="$(rollout_revision)"
  # Without trafficRouting, Rollouts pins each Service to its ReplicaSet by
  # adding the pod-template-hash to the selector.
  record "rollouts: stable Service selects stable ReplicaSet" "${stable_before:-none}" \
    "$(k -n "$NS_ROLLOUTS" get service invoices-api-stable -o jsonpath='{.spec.selector.rollouts-pod-template-hash}' 2>/dev/null || echo none)"

  # Revision 2: the vulnerable API as the canary. The analysis must fail it.
  rollout_manifest "${WORK}/rollout-2.json" yes vulnerable-2
  k -n "$NS_ROLLOUTS" apply -f "${WORK}/rollout-2.json" >/dev/null
  record "rollouts: ready pods when the analysis starts" "canary=1 stable=1" "$(split_at_analysis "$stable_before")"
  phase="$(wait_rollout Degraded "$stable_before")"
  analysis="$(analysis_result)"
  aborted="$(k -n "$NS_ROLLOUTS" get rollout invoices-api -o jsonpath='{.status.abort}')"
  stable_after="$(rollout_revision)"
  record "rollouts: canary(vulnerable) analysis" "Failed job-exit=1" "$analysis"
  record "rollouts: canary(vulnerable) rollout" "Degraded abort=true" "${phase} abort=${aborted:-false}"
  record "rollouts: stable ReplicaSet kept" "unchanged" "$([[ "$stable_after" == "$stable_before" ]] && echo unchanged || echo "changed to ${stable_after}")"

  # Revision 3: a fixed API that differs from revision 1 (the annotation), so it
  # is a new canary that must pass the analysis -- not a rollback to stable,
  # which Argo Rollouts would take without running the steps.
  rollout_manifest "${WORK}/rollout-3.json" no fixed-3
  k -n "$NS_ROLLOUTS" apply -f "${WORK}/rollout-3.json" >/dev/null
  phase="$(wait_rollout Healthy)"
  analysis="$(analysis_result)"
  stable_after="$(rollout_revision)"
  record "rollouts: canary(fixed) analysis" "Successful job-exit=0" "$analysis"
  record "rollouts: canary(fixed) rollout" "Healthy, promoted" \
    "${phase}, $([[ -n "$stable_after" && "$stable_after" != "$stable_before" ]] && echo promoted || echo not-promoted)"
}

# --- scenario: Pod Security restricted + NetworkPolicy ------------------------

scenario_psa() {
  local out rc status code
  log "scenario psa: admission under Pod Security restricted, NetworkPolicy egress"
  create_namespace "$NS_PSA"
  create_credentials "$NS_PSA"

  # Control: the label must actually enforce, or "admitted" proves nothing.
  rc=0
  out="$(k -n "$NS_PSA" apply --dry-run=server -f - 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: psa-control
spec:
  containers:
    - name: c
      image: ${E2E_GATE_IMAGE}
EOF
)" || rc=$?
  record "psa: control, non-compliant pod" "refused by PodSecurity" \
    "$([[ $rc -ne 0 && "$out" == *"violates PodSecurity"* ]] && echo 'refused by PodSecurity' || echo "admitted (rc=${rc})")"

  # The gate's own manifests, server-side, before anything runs.
  #
  # The NetworkPolicy legs start Veridor 8 seconds late, through the chart's
  # own image.command. Measured on kind's kindnet (kube-network-policies): an
  # egress rule is not applied to connections a pod makes in its first seconds,
  # and Veridor connects at once, so an undelayed gate would pass the deny
  # control below without the policy ever being consulted. The delay makes
  # these two rows measure the chart's rules (DNS + target), not that race.
  local np_command='"image":{"repository":"'"${GATE_REPOSITORY}"'","tag":"'"${GATE_TAG}"'","command":["sh","-c","sleep 8; exec veridor \"$@\"","veridor"]}'
  gate_values "${WORK}/psa-np.json" none "http://psa-target.${NS_PSA}.svc.cluster.local:${DEMO_PORT}" no \
    '{'"${np_command}"',"networkPolicy":{"enabled":true,"targetPeers":[{"podSelector":{"matchLabels":{"app.kubernetes.io/instance":"psa-target"}}}],"targetPorts":[{"port":8765,"protocol":"TCP"}]}}'
  rc=0
  out="$(h template gate-np "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" -n "$NS_PSA" -f "${WORK}/psa-np.json" \
    | k -n "$NS_PSA" apply --dry-run=server -f - 2>&1)" || rc=$?
  record "psa: chart manifests, server dry-run" "accepted, no warnings" \
    "$([[ $rc -eq 0 && "$out" != *"Warning"* ]] && echo 'accepted, no warnings' || echo "rc=${rc}: ${out//$'\n'/ }")"

  install_target "$NS_PSA" psa-target no
  h upgrade --install gate-np "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" -n "$NS_PSA" -f "${WORK}/psa-np.json" >/dev/null
  status="$(wait_job "$NS_PSA" gate-np-veridor-gate-r1)"
  code="$(job_exit "$NS_PSA" gate-np-veridor-gate-r1)"
  show_job_log "$NS_PSA" gate-np-veridor-gate-r1
  record "psa: gate admitted, NetworkPolicy allows target" "Complete (exit 0)" "${status} (exit ${code})"

  # Control: a NetworkPolicy whose only allowed peer is not the target. If the
  # cluster enforces it the gate reaches nothing and Veridor exits 3 ("not one
  # probe was answered"); if it does not, this row says so.
  gate_values "${WORK}/psa-np-deny.json" none "http://psa-target.${NS_PSA}.svc.cluster.local:${DEMO_PORT}" no \
    '{'"${np_command}"',"networkPolicy":{"enabled":true,"targetPeers":[{"podSelector":{"matchLabels":{"app.kubernetes.io/instance":"no-such-target"}}}],"targetPorts":[{"port":8765,"protocol":"TCP"}]}}'
  h upgrade --install gate-np-deny "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" -n "$NS_PSA" -f "${WORK}/psa-np-deny.json" >/dev/null
  status="$(wait_job "$NS_PSA" gate-np-deny-veridor-gate-r1)"
  code="$(job_exit "$NS_PSA" gate-np-deny-veridor-gate-r1)"
  show_job_log "$NS_PSA" gate-np-deny-veridor-gate-r1
  record "psa: control, NetworkPolicy excludes target" "Failed (exit 3)" "${status} (exit ${code})"
}

# --- scenario: --wait-for-target against a target that is not Ready yet -------

# ready_endpoints NS SERVICE -> how many ready endpoints the Service has now,
# or "unknown" when they cannot be read (never a 0 that was not measured)
ready_endpoints() {
  local out
  # -o json, not a jsonpath filter: a slice with no endpoints has
  # "endpoints": null, which kubectl's filter refuses to read.
  if ! out="$(k -n "$1" get endpointslices -l "kubernetes.io/service-name=$2" -o json)"; then
    echo unknown
    return 0
  fi
  python3 -c '
import json, sys
slices = json.load(sys.stdin)["items"]
print(sum(1 for s in slices for e in (s.get("endpoints") or []) if (e.get("conditions") or {}).get("ready")))
' <<<"$out"
}

scenario_wait() {
  local leg vulnerable wait status code ready log_text
  log "scenario wait: gate Jobs started while their target's only pod is not Ready for ${WAIT_READY_DELAY}s"
  create_namespace "$NS_WAIT"
  create_credentials "$NS_WAIT"
  # Each leg gets its own target, Ready only WAIT_READY_DELAY seconds after
  # its pod starts, and its gate is installed straight after it, without
  # waiting for anything: every gate starts before its Service can route.
  for leg in nowait wait-vuln wait-fixed; do
    vulnerable="$([[ $leg == wait-fixed ]] && echo no || echo yes)"
    wait="$([[ $leg == nowait ]] && echo 0 || echo 60)"
    h upgrade --install "late-${leg}" "${WORK}/repo/vg-e2e-demo-target-${CHART_VERSION}.tgz" -n "$NS_WAIT" \
      --set "image=${E2E_TARGET_IMAGE}" --set "vulnerable=$([[ $vulnerable == yes ]] && echo true || echo false)" \
      --set "readinessDelaySeconds=${WAIT_READY_DELAY}" >/dev/null
    gate_values "${WORK}/wait-${leg}.json" none "http://late-${leg}.${NS_WAIT}.svc.cluster.local:${DEMO_PORT}" \
      "$vulnerable" '{"gate":{"waitForTargetSeconds":'"${wait}"'}}'
    h upgrade --install "gate-${leg}" "${WORK}/repo/veridor-gate-${CHART_VERSION}.tgz" \
      -n "$NS_WAIT" -f "${WORK}/wait-${leg}.json" >/dev/null
    ready="$(ready_endpoints "$NS_WAIT" "late-${leg}")"
    record "wait: ${leg}, target ready endpoints when its gate was created" "0" "$ready"
  done
  for leg in nowait wait-vuln wait-fixed; do
    status="$(wait_job "$NS_WAIT" "gate-${leg}-veridor-gate-r1")"
    code="$(job_exit "$NS_WAIT" "gate-${leg}-veridor-gate-r1")"
    show_job_log "$NS_WAIT" "gate-${leg}-veridor-gate-r1"
    log_text="$(k -n "$NS_WAIT" logs "job/gate-${leg}-veridor-gate-r1" 2>&1 || true)"
    case "$leg" in
      nowait)
        record "wait: no wait, vulnerable target not Ready yet" "Failed (exit 3)" "${status} (exit ${code})"
        record "wait: no wait, the probes were refused" "Connection refused" \
          "$([[ "$log_text" == *"Connection refused"* ]] && echo 'Connection refused' || echo 'no refusal in the log')"
        ;;
      wait-vuln)
        record "wait: gate.waitForTargetSeconds 60, vulnerable target" "Failed (exit 1)" "${status} (exit ${code})"
        record "wait: the vulnerable leg's gate waited" "accepted a connection" \
          "$([[ "$log_text" == *"accepted a connection after"* ]] && echo 'accepted a connection' || echo 'no wait line')"
        log "wait-vuln: $(grep -o 'accepted a connection after [0-9.]*s[^.]*' <<<"$log_text" || true)"
        ;;
      wait-fixed)
        record "wait: gate.waitForTargetSeconds 60, fixed target" "Complete (exit 0)" "${status} (exit ${code})"
        record "wait: the fixed leg's gate waited" "accepted a connection" \
          "$([[ "$log_text" == *"accepted a connection after"* ]] && echo 'accepted a connection' || echo 'no wait line')"
        log "wait-fixed: $(grep -o 'accepted a connection after [0-9.]*s[^.]*' <<<"$log_text" || true)"
        ;;
    esac
  done
}

# --- scenario: Kustomize (deploy/kustomize/veridor-gate) ----------------------

# kustomize_overlay DIR RESOURCE BASE_URL VULNERABLE(yes|no) [NAME_SUFFIX]
# An overlay of this script's own on top of a shipped one: the gate image, the
# e2e configuration aimed at BASE_URL, and (E2E_CONTROL only) --fail-on none.
kustomize_overlay() {
  local dir="$1" resource="$2" base_url="$3" vulnerable="$4" suffix="${5:-}"
  mkdir -p "$dir"
  python3 - "$dir" "$resource" "$base_url" "$vulnerable" "$suffix" "$E2E_CONTROL" \
    "$GATE_REPOSITORY" "$GATE_TAG" "${WORK}/gate-config.json" <<'PY'
import json, sys
directory, resource, base_url, vulnerable, suffix, control, repo, tag, config_path = sys.argv[1:]
config = json.load(open(config_path))
config["target"]["base_url"] = base_url
with open(f"{directory}/veridor.json", "w") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
lines = [
    "apiVersion: kustomize.config.k8s.io/v1beta1",
    "kind: Kustomization",
    "resources:",
    f"  - {resource}",
    "images:",
    "  - name: ghcr.io/veridor-authz/veridor",
    f"    newName: {repo}",
    f'    newTag: "{tag}"',
    "configMapGenerator:",
    "  - name: veridor-gate-config",
    "    behavior: replace",
    "    files:",
    "      - veridor.json",
]
if suffix:
    lines.append(f"nameSuffix: {suffix}")
if control == "gate-passes-wrongly" and vulnerable == "yes":
    # `test` first: if the base's arguments move, the patch fails loudly
    # instead of replacing some other argument.
    lines += [
        "patches:",
        "  - target: {kind: Job, name: veridor-gate}",
        "    patch: |-",
        "      - op: test",
        "        path: /spec/template/spec/containers/0/args/5",
        "        value: --fail-on",
        "      - op: replace",
        "        path: /spec/template/spec/containers/0/args/6",
        "        value: none",
    ]
open(f"{directory}/kustomization.yaml", "w").write("\n".join(lines) + "\n")
PY
}

# readme_block FILE NEEDLE OUT -- the one fenced block of FILE that contains
# NEEDLE, written to OUT, so the e2e runs a README's own commands.
readme_block() {
  python3 - "$1" "$2" "$3" <<'PY'
import re, sys
path, needle, out = sys.argv[1:]
text = open(path, encoding="utf-8").read()
blocks = [b for b in re.findall(r"^```[a-z]*\n(.*?)^```$", text, re.S | re.M) if needle in b]
if len(blocks) != 1:
    sys.exit(f"{path}: {len(blocks)} fenced blocks contain {needle!r}; expected exactly 1")
open(out, "w", encoding="utf-8").write(blocks[0])
PY
}

# pinned_kubectl DIR NS [ARG...] -- DIR/kubectl: this script's kubectl,
# context (and kubeconfig) pinned, in namespace NS, with ARGs (e.g. --as=...)
# after the pins. First on PATH, it runs a README block that says plain
# `kubectl` against this cluster and nothing else.
pinned_kubectl() {
  local dir="$1" ns="$2" real
  shift 2
  real="$(command -v kubectl)"
  mkdir -p "$dir"
  {
    printf '#!/usr/bin/env bash\nexec %q' "$real"
    printf ' %q' "${KUBECTL[@]:1}" -n "$ns" "$@"
    # shellcheck disable=SC2016 # "$@" is for the generated script, not this one
    printf ' "$@"\n'
  } >"${dir}/kubectl"
  chmod +x "${dir}/kubectl"
}

# no_delete_identity NS -- a ServiceAccount in NS that may read, create and
# patch Jobs and ConfigMaps and read pod logs, but not delete anything: a CI
# identity the delete/apply/wait flow never needed before it deleted first.
# Prints the --as argument that impersonates it.
no_delete_identity() {
  local ns="$1"
  k -n "$ns" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vg-e2e-nodelete
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vg-e2e-nodelete
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["get", "list", "watch", "create", "patch", "update"]
  - apiGroups: [""]
    resources: ["configmaps", "serviceaccounts"]
    verbs: ["get", "list", "watch", "create", "patch", "update"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vg-e2e-nodelete
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vg-e2e-nodelete
subjects:
  - kind: ServiceAccount
    name: vg-e2e-nodelete
    namespace: ${ns}
EOF
  echo "--as=system:serviceaccount:${ns}:vg-e2e-nodelete"
}

# can_i NS AS VERB -> yes or no, as that identity, for jobs in NS
can_i() {
  k -n "$1" auth can-i "$3" jobs.batch "$2" 2>/dev/null || true
}

# run_readme_flow DIR SCRIPT LOG [KUBECTL_DIR] -- SCRIPT under sh (no -e) in
# DIR with the pinned kubectl in KUBECTL_DIR (default the admin one) first on
# PATH; returns its status, or 124 after E2E_TIMEOUT. The block waits until
# the Job is Complete or Failed, which activeDeadlineSeconds bounds on a real
# cluster; this bounds it here too.
run_readme_flow() {
  local dir="$1" script="$2" out="$3" bin="${4:-${WORK}/readme-kubectl}" pid waited=0 status=0
  (cd "$dir" && PATH="${bin}:${PATH}" exec sh "$script") >"$out" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if ((waited >= E2E_TIMEOUT)); then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid" || status=$?
  return "$status"
}

# job_state NS NAME -> "<uid> <Complete|Failed|Timeout> <exit code>"
job_state() {
  local uid
  uid="$(k -n "$1" get job "$2" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  echo "${uid:-none} $(wait_job "$1" "$2") $(job_exit "$1" "$2")"
}

scenario_kustomize() {
  local tree="${WORK}/kustomize" leg rc out status code
  log "scenario kustomize: deploy/kustomize/veridor-gate as a plain Job"
  create_namespace "$NS_KUSTOMIZE"
  create_credentials "$NS_KUSTOMIZE" veridor-gate-credentials
  install_target "$NS_KUSTOMIZE" target-vuln yes
  install_target "$NS_KUSTOMIZE" target-fixed no

  # A copy of the shipped tree, with this script's overlays beside it.
  rm -rf "$tree"
  mkdir -p "${tree}/deploy/kustomize" "${tree}/e2e"
  cp -R "${ROOT}/deploy/kustomize/veridor-gate" "${tree}/deploy/kustomize/"

  # The shipped overlay, unmodified, server-side, in a restricted namespace.
  rc=0
  out="$(k kustomize "${tree}/deploy/kustomize/veridor-gate/overlays/plain" \
    | k -n "$NS_KUSTOMIZE" apply --dry-run=server -f - 2>&1)" || rc=$?
  record "kustomize: overlays/plain, server dry-run" "accepted, no warnings" \
    "$([[ $rc -eq 0 && "$out" != *"Warning"* ]] && echo 'accepted, no warnings' || echo "rc=${rc}: ${out//$'\n'/ }")"

  for leg in vuln fixed; do
    kustomize_overlay "${tree}/e2e/plain-${leg}" ../../deploy/kustomize/veridor-gate/overlays/plain \
      "http://target-${leg}.${NS_KUSTOMIZE}.svc.cluster.local:${DEMO_PORT}" \
      "$([[ $leg == vuln ]] && echo yes || echo no)" "-${leg}"
    k kustomize "${tree}/e2e/plain-${leg}" | k -n "$NS_KUSTOMIZE" apply -f - >/dev/null
  done
  for leg in vuln fixed; do
    status="$(wait_job "$NS_KUSTOMIZE" "veridor-gate-${leg}")"
    code="$(job_exit "$NS_KUSTOMIZE" "veridor-gate-${leg}")"
    show_job_log "$NS_KUSTOMIZE" "veridor-gate-${leg}"
    if [[ $leg == vuln ]]; then
      record "kustomize: plain Job vs vulnerable target" "Failed (exit 1)" "${status} (exit ${code})"
    else
      record "kustomize: plain Job vs fixed target" "Complete (exit 0)" "${status} (exit ${code})"
    fi
  done

  # The README's warning, measured: a new configuration is a new ConfigMap
  # name, so a new pod template, which a Job refuses.
  python3 - "${tree}/e2e/plain-fixed/veridor.json" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
config["target"]["timeout_seconds"] = 6
json.dump(config, open(sys.argv[1], "w"), indent=2)
PY
  rc=0
  out="$(k kustomize "${tree}/e2e/plain-fixed" | k -n "$NS_KUSTOMIZE" apply --dry-run=server -f - 2>&1)" || rc=$?
  record "kustomize: plain Job re-applied with a new configuration" "refused (field is immutable)" \
    "$([[ $rc -ne 0 && "$out" == *"field is immutable"* ]] && echo 'refused (field is immutable)' || echo "rc=${rc}: ${out//$'\n'/ }")"
  rm -rf "${tree}/e2e/plain-vuln" "${tree}/e2e/plain-fixed"

  # The README's plain flow, extracted and run unchanged, against ONE overlay
  # whose target changes underneath it. A Job runs once: `apply` of an
  # unchanged overlay prints "unchanged" and a wait reads the previous run's
  # Job (measured: a stale Complete passed a vulnerable target). The block
  # deletes that Job first and waits for the new one's Complete or Failed.
  scenario_kustomize_readme_flow "$tree"
}

# unchecked_block IN OUT -- a README delete/apply/wait block with its step
# checks and uid binding taken out, which is the block as it read before it
# had them. Under plain sh, as an identity that cannot delete Jobs, that block
# fell through the refused delete to `apply` ("unchanged") and read the
# previous run's Job (measured on kind). The e2e runs it as the control for
# the no-delete rows: it must still pass on that stale Job.
unchecked_block() {
  python3 - "$1" "$2" <<'PY'
import sys
source, out = sys.argv[1:]
kept, removed = [], 0
for line in open(source, encoding="utf-8").read().splitlines():
    if line.startswith(("old=", "uid=", 'if [ -z "$uid" ]')) or 'in "$uid "*)' in line:
        removed += 1
        continue
    kept.append(line)
text = "\n".join(kept) + "\n"
checks = text.count(" || exit 1")
text = text.replace(" || exit 1", "").replace("{.metadata.uid} {.status", "{.status")
if removed != 4 or checks < 2 or "uid" in text:
    sys.exit(f"{source}: not the checked block this control expects ({removed} lines, {checks} checks)")
open(out, "w", encoding="utf-8").write(text)
PY
}

# scenario_kustomize_readme_flow TREE
scenario_kustomize_readme_flow() {
  local flow="${1}/e2e/flow" rc before uid status code as
  readme_block "${ROOT}/deploy/kustomize/veridor-gate/README.md" "apply -k my-overlay/" "${WORK}/readme-plain-flow.sh"
  unchecked_block "${WORK}/readme-plain-flow.sh" "${WORK}/readme-plain-flow-previous.sh"
  pinned_kubectl "${WORK}/readme-kubectl" "$NS_KUSTOMIZE"
  as="$(no_delete_identity "$NS_KUSTOMIZE")"
  pinned_kubectl "${WORK}/readme-kubectl-nodelete" "$NS_KUSTOMIZE" "$as"
  record "kustomize: the no-delete identity may create Jobs, not delete them" "create yes, delete no" \
    "create $(can_i "$NS_KUSTOMIZE" "$as" create), delete $(can_i "$NS_KUSTOMIZE" "$as" delete)"
  install_target "$NS_KUSTOMIZE" target-flow no
  # "yes": under E2E_CONTROL this overlay runs --fail-on none, since its
  # target turns vulnerable; it must stay the same overlay throughout.
  kustomize_overlay "${flow}/my-overlay" ../../../deploy/kustomize/veridor-gate/overlays/plain \
    "http://target-flow.${NS_KUSTOMIZE}.svc.cluster.local:${DEMO_PORT}" yes

  rc=0
  run_readme_flow "$flow" "${WORK}/readme-plain-flow.sh" "${WORK}/flow.log" || rc=$?
  sed 's/^/    | /' "${WORK}/flow.log" >&2
  read -r before status code <<<"$(job_state "$NS_KUSTOMIZE" veridor-gate)"
  record "kustomize: README plain flow, fixed target" "exit 0, Complete (exit 0)" "exit ${rc}, ${status} (exit ${code})"

  install_target "$NS_KUSTOMIZE" target-flow yes
  # Control: the flow this README documented before, apply then wait for
  # Complete, on the same overlay. It must read the previous run's Job.
  rc=0
  k -n "$NS_KUSTOMIZE" apply -k "${flow}/my-overlay" >"${WORK}/flow.log" 2>&1 || rc=$?
  k -n "$NS_KUSTOMIZE" wait --for=condition=Complete job/veridor-gate --timeout=60s >>"${WORK}/flow.log" 2>&1 || rc=$?
  sed 's/^/    | /' "${WORK}/flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_KUSTOMIZE" veridor-gate)"
  record "kustomize: control, apply then wait after the target turned vulnerable" "exit 0, the previous run's Job" \
    "exit ${rc}, $([[ $uid == "$before" ]] && echo "the previous run's Job" || echo "a new Job")"

  # The block, run as an identity that cannot delete Jobs: the delete is
  # refused, and the block must stop there instead of reading the old Job.
  rc=0
  run_readme_flow "$flow" "${WORK}/readme-plain-flow.sh" "${WORK}/flow.log" "${WORK}/readme-kubectl-nodelete" || rc=$?
  sed 's/^/    | /' "${WORK}/flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_KUSTOMIZE" veridor-gate)"
  record "kustomize: README plain flow, no-delete identity, target vulnerable" "exit 1, the previous run's Job" \
    "exit ${rc}, $([[ $uid == "$before" ]] && echo "the previous run's Job" || echo "a new Job")"
  # Control: the block without its step checks, under the same identity,
  # passes on that Job.
  rc=0
  run_readme_flow "$flow" "${WORK}/readme-plain-flow-previous.sh" "${WORK}/flow.log" "${WORK}/readme-kubectl-nodelete" || rc=$?
  sed 's/^/    | /' "${WORK}/flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_KUSTOMIZE" veridor-gate)"
  record "kustomize: control, the unchecked block as the no-delete identity" "exit 0, the previous run's Job" \
    "exit ${rc}, $([[ $uid == "$before" ]] && echo "the previous run's Job" || echo "a new Job")"

  rc=0
  run_readme_flow "$flow" "${WORK}/readme-plain-flow.sh" "${WORK}/flow.log" || rc=$?
  sed 's/^/    | /' "${WORK}/flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_KUSTOMIZE" veridor-gate)"
  record "kustomize: README plain flow, target now vulnerable" "exit 1, a new Job, Failed (exit 1)" \
    "exit ${rc}, $([[ $uid != "$before" ]] && echo "a new Job" || echo "the previous run's Job"), ${status} (exit ${code})"
  before="$uid"

  install_target "$NS_KUSTOMIZE" target-flow no
  rc=0
  run_readme_flow "$flow" "${WORK}/readme-plain-flow.sh" "${WORK}/flow.log" || rc=$?
  sed 's/^/    | /' "${WORK}/flow.log" >&2
  read -r uid status code <<<"$(job_state "$NS_KUSTOMIZE" veridor-gate)"
  record "kustomize: README plain flow, target fixed again" "exit 0, a new Job, Complete (exit 0)" \
    "exit ${rc}, $([[ $uid != "$before" ]] && echo "a new Job" || echo "the previous run's Job"), ${status} (exit ${code})"
  rm -rf "$flow"
}

# --- main -----------------------------------------------------------------------

log "context ${KUBE_CONTEXT}, scenarios: ${E2E_SCENARIOS}, work ${WORK}"
acquire_lock
log "removing leftovers of an earlier run, if any"
delete_own_objects
install_argo
build_images
write_demo_chart
write_gate_config
package_charts
serve_helm_repo

for scenario in $E2E_SCENARIOS; do
  "scenario_${scenario}"
done

print_table
if ((MISMATCHES > 0)); then
  exit 1
fi
