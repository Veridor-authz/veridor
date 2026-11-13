#!/usr/bin/env bash
# End-to-end test of the GitLab CI/CD component (templates/veridor.yml), with
# docker standing in for a GitLab runner's docker executor.
#
#   IMAGE=veridor:e2e SAST_SCHEMA=path/to/sast-report-format.json \
#   PYTHON_WITH_JSONSCHEMA=path/to/python scripts/e2e_gitlab_job.sh
#
# What it runs is the template's own shell: tests/ci_validate.py renders the
# component with this script's inputs and writes the gate job's before_script
# and script, exactly as rendered (never re-typed here). Each row then runs
# that shell in the job's image with --entrypoint "" as the job declares, in a
# docker volume laid out like a runner's /builds (project cloned by root with
# umask 0000, as GitLab's docker executor does by default), with GitLab-like
# CI_* variables and the credentials as environment variables. The targets are
# scripts/demo_server.py started with python3 from IMAGE on a private docker
# network, wrapped so every request they receive is counted.
#
# The job shell is the one GitLab Runner's docker executor picks for the
# image: the first bash at /usr/local/bin, /usr/bin or /bin, else sh (the
# detection script in gitlab-runner's shells/bash.go), and the job script
# starts with the header that file writes for both: pipefail when the shell
# has it, then errexit. The release image and the component's default
# python_image are Alpine and have no bash, so their rows run under busybox
# sh. The dash, bash and proxy-variable-dash rows install the wheel with pip
# in E2E_DEBIAN_PYTHON_IMAGE, a Debian python image with bash, where /bin/sh
# is dash: dash and proxy-variable-dash run sh there, and bash runs what the
# runner picks, bash. Each of the three checks which shell it got. The table's
# last line names the shell each image got, and what its /bin/sh is.
#
# Rows (expected job exit code in brackets):
#   vulnerable [1]    fixed [0]    unreachable [3]    unmeasured-allowed [3,
#   and the rendered job allows exactly exit 3]
#   dash [1, install: pip in E2E_DEBIAN_PYTHON_IMAGE, run by its /bin/sh, dash]
#   bash [1, install: pip in E2E_DEBIAN_PYTHON_IMAGE, run by bash, as the
#   runner picks there]
#   pip [1, install: pip in E2E_PYTHON_IMAGE from a locally built wheel]
#   empty-credential [2, nothing sent]    extra-args-override [2, nothing sent]
#   unset-base-url [2, nothing sent]    root-owned-workspace [2, nothing sent]
#   sigterm [143, the shell survives to print the exit line]
#   wait-for-target [0, veridor logs the TCP wait and records it]
#   nondefault-inputs [0: fail_on new, require_complete false, a baseline of
#   the vulnerable row's run, an OpenAPI document and a nested output_dir,
#   against the vulnerable target; the run JSON records fail_on and
#   require_complete]
#   proxy-variable, proxy-variable-dash [1: http_proxy, HTTP_PROXY,
#   HTTPS_PROXY and ALL_PROXY set as pipeline variables, naming a recording
#   proxy; the job removes them, the proxy receives 0 requests and the target
#   more than 0; busybox sh in IMAGE, and dash in E2E_DEBIAN_PYTHON_IMAGE]
#   proxy-opt-in [1: the same variables with proxy_from_environment true; the
#   proxy, which forwards to the target, receives the requests: the control
#   that shows the proxy-variable rows' 0 can fail]
# For every row that runs the gate, every artifacts:paths and artifacts:reports
# file the rendered job declares must exist, gl-sast-report.json must validate
# against SAST_SCHEMA with 0 errors, the JUnit file must parse, and the Code
# Quality file must be a list with unique fingerprints and known severities.
#
# Exit codes:
#   0  every row matched
#   1  at least one row mismatched (the table says which)
#   2  refused to start (a missing tool, image, schema or variable)
#   3  stopped before the table: a setup step failed (the line is printed)
#   130 / 143  interrupted
#
# Environment:
#   IMAGE                   required. The Veridor image the job runs (must hold
#                           veridor, python3 and a POSIX sh; bash is used when
#                           present). It must already be present locally.
#   SAST_SCHEMA             required. GitLab's sast-report-format.json (15.2.x).
#   PYTHON_WITH_JSONSCHEMA  python 3.9+ that can import jsonschema (default python3).
#   E2E_PYTHON_IMAGE        image for the pip row (default: the component's own
#                           python_image default, digest-pinned; pulled when
#                           absent).
#   E2E_DEBIAN_PYTHON_IMAGE image for the dash, bash and proxy-variable-dash rows
#                           (default: python:3.12-slim by digest; pulled when
#                           absent). It must have bash, and dash as /bin/sh.
#   E2E_WHEEL               wheel for the pip row. Default: built from a copy of
#                           this checkout with pip (fetches setuptools).
#   E2E_CONTROL             report-path-typo: mutate the template's JUnit report
#                           path; the run MUST end in exit 1.
#                           no-term-trap: delete the template's SIGTERM trap; the
#                           sigterm row MUST mismatch and the run end in exit 1.
#                           proxy-kept: make the template keep the proxy
#                           variables whatever proxy_from_environment says; the
#                           proxy-variable rows MUST mismatch and the run end
#                           in exit 1.
#   E2E_KEEP=1              keep the work directory (containers, volumes and the
#                           network are always removed).
#   E2E_WORKDIR             work directory (default: mktemp -d).
#
# Needs: bash, docker, python (above). Everything it creates is labelled
# vg-e2e-gl-run=<id> and removed on exit.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly PROJECT_DIR="/builds/veridor-e2e/project"
readonly DEMO_PORT=8765
readonly PROXY_PORT=8766

log() { printf '==> %s\n' "$*" >&2; }
refuse() { printf 'e2e_gitlab_job: %s\n' "$*" >&2; exit 2; }

# --- preconditions ----------------------------------------------------------

IMAGE="${IMAGE:-}"
SAST_SCHEMA="${SAST_SCHEMA:-}"
PY="${PYTHON_WITH_JSONSCHEMA:-python3}"
E2E_PYTHON_IMAGE="${E2E_PYTHON_IMAGE:-}"
# Debian, so /bin/sh is dash and bash is present: the shells the Alpine
# images cannot run. Bumped by hand (.github/dependabot.yml says so).
E2E_DEBIAN_PYTHON_IMAGE="${E2E_DEBIAN_PYTHON_IMAGE:-python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9}"
E2E_WHEEL="${E2E_WHEEL:-}"
E2E_CONTROL="${E2E_CONTROL:-}"
E2E_KEEP="${E2E_KEEP:-0}"

[[ -n "$IMAGE" ]] || refuse "IMAGE is not set. Name the Veridor image the job should run, e.g. IMAGE=veridor:e2e (build one with: docker build -t veridor:e2e .)."
[[ -n "$SAST_SCHEMA" ]] || refuse "SAST_SCHEMA is not set. Point it at GitLab's sast-report-format.json (security-report-schemas 15.2.x, dist/sast-report-format.json)."
[[ -f "$SAST_SCHEMA" ]] || refuse "SAST_SCHEMA=${SAST_SCHEMA} is not a file."
case "$E2E_CONTROL" in
  "" | report-path-typo | no-term-trap | proxy-kept) ;;
  *) refuse "E2E_CONTROL=${E2E_CONTROL} is not a control this script knows (report-path-typo, no-term-trap, proxy-kept)." ;;
esac
command -v docker >/dev/null 2>&1 || refuse "docker is not on PATH; it is required."
command -v "$PY" >/dev/null 2>&1 || refuse "PYTHON_WITH_JSONSCHEMA=${PY} is not on PATH."
"$PY" -c 'import jsonschema' || refuse "PYTHON_WITH_JSONSCHEMA=${PY} cannot import jsonschema (the traceback is above). Use a python that has it."
docker info >/dev/null || refuse "docker info failed (above); is the daemon running?"
docker image inspect "$IMAGE" >/dev/null || refuse "IMAGE=${IMAGE} is not present locally (docker image inspect failed above). Build or pull it first."
if [[ -z "$E2E_PYTHON_IMAGE" ]]; then
  # The component's own default, so the pip row runs what ships.
  E2E_PYTHON_IMAGE="$("$PY" -c 'import sys; sys.path.insert(0, sys.argv[1]); import ci_validate as cv; print(cv.split_component(cv.COMPONENT.read_text(encoding="utf-8"))[0]["inputs"]["python_image"]["default"])' "$ROOT/tests")" \
    || refuse "could not read python_image's default from templates/veridor.yml (above)."
fi

RUN_ID="$(date +%s)-$$"
readonly RUN_ID
readonly LABEL="vg-e2e-gl-run=${RUN_ID}"
readonly NET="vg-e2e-gl-net-${RUN_ID}"
WORK="${E2E_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/vg-e2e-gl.XXXXXX")}"
readonly WORK
mkdir -p "$WORK/rows"
RESULTS="$WORK/results.tsv"
readonly RESULTS
: > "$RESULTS"

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  local ids
  ids="$(docker ps -aq --filter "label=${LABEL}")"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086 # one id per word
    docker rm -f $ids >/dev/null || log "could not remove containers: $ids"
  fi
  ids="$(docker volume ls -q --filter "label=${LABEL}")"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086 # one name per word
    docker volume rm -f $ids >/dev/null || log "could not remove volumes: $ids"
  fi
  if docker network inspect "$NET" >/dev/null 2>&1; then
    docker network rm "$NET" >/dev/null || log "could not remove network $NET"
  fi
  if [[ "$E2E_KEEP" == "1" ]]; then
    log "kept work directory $WORK"
  else
    rm -rf "$WORK"
  fi
}
# shellcheck disable=SC2329 # invoked by the ERR trap
on_error() {
  local status=$? line=$1 command=$2
  trap - ERR
  printf 'e2e_gitlab_job: stopped before the table: line %s exited %s: %s\n' "$line" "$status" "$command" >&2
  exit 3
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
trap cleanup EXIT
trap 'trap - ERR; log "interrupted by SIGINT"; exit 130' INT
trap 'trap - ERR; log "interrupted by SIGTERM"; exit 143' TERM

# --- the template under test ------------------------------------------------

TEMPLATE="$WORK/veridor.yml"
cp "$ROOT/templates/veridor.yml" "$TEMPLATE"
if [[ "$E2E_CONTROL" == "report-path-typo" ]]; then
  "$PY" - "$TEMPLATE" <<'PYEOF'
import sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text()
old = 'junit: "$[[ inputs.output_dir ]]/veridor-junit.xml"'
if text.count(old) != 1:
    sys.exit("control could not be applied: the JUnit report path is not in the template exactly once")
path.write_text(text.replace(old, 'junit: "$[[ inputs.output_dir ]]/veridor-junit.xm"'))
PYEOF
  log "CONTROL report-path-typo: artifacts:reports:junit now names veridor-junit.xm"
elif [[ "$E2E_CONTROL" == "no-term-trap" ]]; then
  "$PY" - "$TEMPLATE" <<'PYEOF'
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text()
new, count = re.subn(r"^ *trap '.*' TERM\n", "", text, flags=re.M)
if count != 1:
    sys.exit(f"control could not be applied: found {count} TERM traps, expected 1")
path.write_text(new)
PYEOF
  log "CONTROL no-term-trap: the job shell's SIGTERM trap is deleted"
elif [[ "$E2E_CONTROL" == "proxy-kept" ]]; then
  "$PY" - "$TEMPLATE" <<'PYEOF'
import sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text()
old = "if $[[ inputs.proxy_from_environment ]]; then"
if text.count(old) != 1:
    sys.exit("control could not be applied: the proxy_from_environment branch is not in the template exactly once")
# Still references the input: the renderer refuses an input nobody uses.
path.write_text(text.replace(old, "if true || $[[ inputs.proxy_from_environment ]]; then"))
PYEOF
  log "CONTROL proxy-kept: the job keeps every proxy variable whatever proxy_from_environment says"
fi

# --- project, wheel, network, targets ---------------------------------------

mkdir -p "$WORK/project"
cp "$ROOT/ci/veridor.example.json" "$WORK/project/veridor.json"
# The same configuration with target.base_url naming the counted vulnerable
# target, for the unset-base-url row: a job that stopped refusing would fall
# through to this target and be counted. With the example's own base_url
# (127.0.0.1 inside the job container) a fall-through reached no counted
# target, so that row's "0 requests" could not fail.
"$PY" -c 'import json, sys; c = json.load(open(sys.argv[1])); c["target"]["base_url"] = sys.argv[3]; json.dump(c, open(sys.argv[2], "w"), indent=2)' \
  "$ROOT/ci/veridor.example.json" "$WORK/project/veridor-fallthrough.json" "http://vulnerable-target:${DEMO_PORT}"

if [[ -z "$E2E_WHEEL" ]]; then
  log "building a wheel from a copy of this checkout (pip fetches setuptools)"
  mkdir -p "$WORK/wheel-src" "$WORK/dist"
  cp -R "$ROOT/pyproject.toml" "$ROOT/README.pypi.md" "$ROOT/LICENSE" "$ROOT/src" "$WORK/wheel-src/"
  "$PY" -m pip wheel --quiet --no-deps --wheel-dir "$WORK/dist" "$WORK/wheel-src" >&2
  E2E_WHEEL="$(ls "$WORK"/dist/veridor-*.whl)"
fi
[[ -f "$E2E_WHEEL" ]] || refuse "E2E_WHEEL=${E2E_WHEEL} is not a file."
mkdir -p "$WORK/project/dist"
cp "$E2E_WHEEL" "$WORK/project/dist/"
WHEEL_IN_PROJECT="dist/$(basename "$E2E_WHEEL")"
readonly WHEEL_IN_PROJECT

for pip_image in "$E2E_PYTHON_IMAGE" "$E2E_DEBIAN_PYTHON_IMAGE"; do
  if ! docker image inspect "$pip_image" >/dev/null 2>&1; then
    log "pulling ${pip_image} for the pip rows"
    docker pull --quiet "$pip_image" >&2
  fi
done

docker network create --label "$LABEL" "$NET" >/dev/null

# The demo server, wrapped so each request prints one REQ line to its log.
cat > "$WORK/counting_target.py" <<'PYEOF'
import sys
sys.path.insert(0, "/demo")
from http.server import ThreadingHTTPServer
import demo_server

Handler = demo_server.make_handler(sys.argv[1] == "vulnerable", True, True)

class Counting(Handler):
    def log_message(self, format, *args):
        print("REQ", self.command, self.path, flush=True)

server = ThreadingHTTPServer(("0.0.0.0", int(sys.argv[2])), Counting)
print("READY", flush=True)
server.serve_forever()
PYEOF
# A forwarding HTTP proxy that prints one REQ line per request it carries,
# for the proxy rows. It forwards, so a job that goes through it still gets
# the target's answers and the same exit code as a direct run.
cat > "$WORK/recording_proxy.py" <<'PYEOF'
import http.client, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer",
       "transfer-encoding", "upgrade"}

class Proxy(BaseHTTPRequestHandler):
    def forward(self):
        print("REQ", self.command, self.path, "authorization" if self.headers.get("Authorization") else "-",
              flush=True)
        target = urlsplit(self.path)
        if target.scheme != "http" or not target.hostname:
            self.send_error(400, "only absolute http:// requests")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        upstream = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=30)
        upstream.request(self.command, (target.path or "/") + (f"?{target.query}" if target.query else ""),
                         body=body, headers=headers)
        response = upstream.getresponse()
        data = response.read()
        self.send_response(response.status, response.reason)
        for key, value in response.getheaders():
            if key.lower() not in HOP and key.lower() != "content-length":
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        upstream.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = forward

    def log_message(self, format, *args):
        pass

server = ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Proxy)
print("READY", flush=True)
server.serve_forever()
PYEOF
# A target that accepts connections and never answers, for the sigterm row.
cat > "$WORK/silent_target.py" <<'PYEOF'
import socket, sys
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", int(sys.argv[1])))
listener.listen(64)
print("READY", flush=True)
held = []
while True:
    connection, _ = listener.accept()
    held.append(connection)
    print("REQ connection", flush=True)
PYEOF

start_target() {  # name, then the command after python3
  local name=$1
  shift
  docker run -d --name "vg-e2e-gl-${RUN_ID}-${name}" --label "$LABEL" \
    --network "$NET" --network-alias "$name" --entrypoint "" \
    -v "$ROOT/scripts/demo_server.py:/demo/demo_server.py:ro" \
    -v "$WORK/counting_target.py:/demo/counting_target.py:ro" \
    -v "$WORK/silent_target.py:/demo/silent_target.py:ro" \
    -v "$WORK/recording_proxy.py:/demo/recording_proxy.py:ro" \
    "$IMAGE" python3 "$@" >/dev/null
  local waited=0
  until docker logs "vg-e2e-gl-${RUN_ID}-${name}" 2>&1 | grep -q '^READY'; do
    sleep 1
    waited=$((waited + 1))
    if (( waited > 30 )); then
      docker logs "vg-e2e-gl-${RUN_ID}-${name}" >&2 || log "could not read the target log"
      printf 'e2e_gitlab_job: target %s did not start in 30s\n' "$name" >&2
      exit 3
    fi
  done
}
# The number of requests a target has logged, or "unreadable" when its log
# cannot be read (a removed container, a docker error). A count this script
# cannot see is never 0: check.py turns "unreadable" into a MISMATCH. It used
# to read as 0, so every later "0 requests" check reported ok about a target
# nobody was counting. docker logs runs as an `if` condition and awk counts
# (exit 0 on no match), so a count of 0 no longer fires the ERR trap, which
# used to print "stopped before the table" on passing runs under bash 3.2.
requests_seen() {  # target name
  local file="$WORK/requests-$1.log"
  if docker logs "vg-e2e-gl-${RUN_ID}-$1" > "$file" 2>&1; then
    awk '/^REQ/ { n++ } END { printf "%d", n + 0 }' "$file"
  else
    printf 'e2e_gitlab_job: cannot count the requests to %s; docker logs failed: %s\n' "$1" \
      "$(tr '\n' ' ' < "$file")" >&2
    printf 'unreadable'
  fi
}
start_target vulnerable-target /demo/counting_target.py vulnerable "$DEMO_PORT"
start_target fixed-target /demo/counting_target.py fixed "$DEMO_PORT"
start_target silent-target /demo/silent_target.py "$DEMO_PORT"
start_target recording-proxy /demo/recording_proxy.py "$PROXY_PORT"

# --- rendering and running one row ------------------------------------------

render() {  # row dir, then NAME=VALUE inputs
  local dir=$1
  shift
  local args=()
  local pair
  for pair in "$@"; do
    args+=(--input "$pair")
  done
  "$PY" "$ROOT/tests/ci_validate.py" render --template "$TEMPLATE" ${args[@]+"${args[@]}"} \
    --shell "$dir/job.sh" --job-json "$dir/job.json" >/dev/null
}

job_field() {  # row dir, python expression over `job`
  "$PY" -c 'import json, sys; job = json.load(open(sys.argv[1]))["job"]; value = eval(sys.argv[2]); print(json.dumps(value) if not isinstance(value, str) else value)' "$1/job.json" "$2"
}

write_env() {  # row dir, then extra KEY=VALUE lines
  local dir=$1
  shift
  {
    printf '%s\n' CI=true GITLAB_CI=true "CI_PROJECT_DIR=${PROJECT_DIR}" "CI_BUILDS_DIR=/builds" \
      "CI_JOB_ID=${RUN_ID//-/}" "CI_JOB_NAME=veridor" "CI_PIPELINE_ID=1" \
      "CI_PIPELINE_SOURCE=merge_request_event" "CI_DEFAULT_BRANCH=main" \
      "CI_COMMIT_REF_NAME=e2e" "CI_COMMIT_SHA=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 0000000000000000000000000000000000000000)" \
      "CI_SERVER_URL=https://gitlab.example.com" \
      VERIDOR_OWNER_TOKEN=owner-token VERIDOR_OTHER_TENANT_TOKEN=outsider-token VERIDOR_ADMIN_TOKEN=admin-token
    local line
    for line in "$@"; do
      printf '%s\n' "$line"
    done
  } > "$dir/env"
}

# The shell GitLab Runner's docker executor runs a job in, for an image: bash
# when its detection script finds an executable one at /usr/local/bin, /usr/bin
# or /bin, else sh. Probed once per image; $JOB_SHELLS feeds the last line.
JOB_SHELLS="$WORK/job-shells.tsv"
readonly JOB_SHELLS
: > "$JOB_SHELLS"
runner_shell() {  # image
  local found sh_is
  found="$(awk -F '\t' -v image="$1" '$1 == image { print $2 }' "$JOB_SHELLS")"
  if [[ -z "$found" ]]; then
    found="$(docker run --rm --entrypoint "" "$1" sh -c \
      'for b in /usr/local/bin/bash /usr/bin/bash /bin/bash; do if [ -x "$b" ]; then echo bash; exit 0; fi; done; echo sh')"
    sh_is="$(docker run --rm --entrypoint "" "$1" readlink -f /bin/sh)"
    printf '%s\t%s\t%s\n' "$1" "$found" "$sh_is" >> "$JOB_SHELLS"
  fi
  printf '%s' "$found"
}
# What /bin/sh is in an image, from the same probe.
sh_target() {  # image
  runner_shell "$1" > /dev/null
  awk -F '\t' -v image="$1" '$1 == image { print $3 }' "$JOB_SHELLS"
}

# The header GitLab Runner writes at the top of every bash or sh job script
# (BashWriter.Finish in gitlab-runner's shells/bash.go): pipefail when the
# shell has it -- bash, busybox sh and the Debian image's dash all do -- then
# errexit.
# shellcheck disable=SC2016 # written into the job script, expanded there
readonly RUNNER_HEADER='case "$(set -o)" in *"pipefail"*) set -o pipefail;; esac; set -o errexit
set +o noclobber'

# Runs the rendered job. Sets JOB_STATUS. Args: row dir, shell (runner: the
# one GitLab Runner would pick for the job's image | sh), umask for the clone
# (0000 like GitLab's docker executor, 0022 for a root-owned 0755 checkout),
# detach (0|1).
run_job() {
  local dir=$1 shell=$2 clone_umask=$3 detach=$4
  local row
  row="$(basename "$dir")"
  local volume="vg-e2e-gl-${RUN_ID}-${row}"
  local container="vg-e2e-gl-${RUN_ID}-job-${row}"
  local image entrypoint
  image="$(job_field "$dir" 'job["image"]["name"] if isinstance(job["image"], dict) else job["image"]')"
  entrypoint="$(job_field "$dir" 'job["image"].get("entrypoint") if isinstance(job["image"], dict) else None')"
  docker volume create --label "$LABEL" "$volume" >/dev/null
  docker run --rm --label "$LABEL" -u 0 --entrypoint "" -v "$volume:/builds" \
    -v "$WORK/project:/src:ro" "$IMAGE" \
    sh -c "umask ${clone_umask} && mkdir -p ${PROJECT_DIR} && cp -R /src/. ${PROJECT_DIR}/"
  printf '%s\n' "$RUNNER_HEADER" | cat - "$dir/job.sh" > "$dir/runner-job.sh"
  local run_args=(--name "$container" --label "$LABEL" --network "$NET"
    -v "$volume:/builds" -w "$PROJECT_DIR" --env-file "$dir/env"
    -v "$dir/runner-job.sh:/e2e/job.sh:ro")
  if [[ "$entrypoint" == '[""]' ]]; then
    run_args+=(--entrypoint "")
  elif [[ "$entrypoint" != "null" ]]; then
    printf 'e2e_gitlab_job: row %s: unexpected image entrypoint %s\n' "$row" "$entrypoint" >&2
    exit 3
  fi
  if [[ "$shell" == "runner" ]]; then
    shell="$(runner_shell "$image")"
  fi
  local command
  case "$shell" in
    bash) command=(bash --noprofile --norc /e2e/job.sh) ;;
    sh) command=(sh /e2e/job.sh) ;;
    *)
      printf 'e2e_gitlab_job: row %s: no job shell for %s (got "%s")\n' "$row" "$image" "$shell" >&2
      exit 3
      ;;
  esac
  log "row ${row}: ${shell} in ${image}"
  JOB_SHELL="$shell"
  JOB_STATUS=0
  if [[ "$detach" == "1" ]]; then
    docker run -d --init "${run_args[@]}" "$image" "${command[@]}" >/dev/null
  else
    docker run "${run_args[@]}" "$image" "${command[@]}" > "$dir/log" 2>&1 || JOB_STATUS=$?
    collect "$dir" "$container"
  fi
}

collect() {  # row dir, container: copy the output directory out, remove the container
  local dir=$1 container=$2
  local out
  # The output directory itself (input output_dir, which may be nested), not
  # its first path segment: project-out then holds exactly what it holds.
  out="$(job_field "$dir" 'job["artifacts"]["paths"][0].rsplit("/", 1)[0]')"
  # A refused row may have no output directory; docker cp then says so on stderr.
  docker cp "$container:${PROJECT_DIR}/${out}" "$dir/project-out" >/dev/null || mkdir -p "$dir/project-out"
  docker rm -f "$container" >/dev/null
}

check() {  # row dir, expected exit, observed exit, reports (yes|no), expected log line, [requests target, expected new requests: 0|>0, before]
  "$PY" "$WORK/check.py" "$SAST_SCHEMA" "$@" >> "$RESULTS"
}

cat > "$WORK/check.py" <<'PYEOF'
import json, sys
import xml.etree.ElementTree as ET
from pathlib import Path

schema_path, dir_, expected, observed, reports, line = sys.argv[1:7]
target, want_requests, before, after = (sys.argv[7:11] + ["", "", "", ""])[:4]
row = Path(dir_).name
rows = []

def emit(check, want, got, ok):
    rows.append(f"{row}\t{check}\t{want}\t{got}\t{'ok' if ok else 'MISMATCH'}")

emit("exit code", expected, observed, expected == observed)
log = (Path(dir_) / "log").read_text(errors="replace") if (Path(dir_) / "log").exists() else ""
emit("log line", line[:60], "present" if line in log else "absent", line in log)
if target:
    if before.isdigit() and after.isdigit():
        got = int(after) - int(before)
        ok = got == 0 if want_requests == "0" else got > 0
        emit(f"requests to {target}", want_requests, str(got), ok)
    else:
        # A count the script could not read is not 0 requests.
        emit(f"requests to {target}", want_requests, f"cannot see ({before or '-'}, {after or '-'})", False)
if reports == "yes":
    import jsonschema
    job = json.loads((Path(dir_) / "job.json").read_text())["job"]
    out_root = Path(dir_) / "project-out"  # the job's output directory itself
    out_dir = Path(job["artifacts"]["paths"][0]).parent
    declared = list(dict.fromkeys(list(job["artifacts"]["paths"]) + list(job["artifacts"]["reports"].values())))
    for rel in declared:
        if Path(rel).parent != out_dir:
            emit(f"artifact {rel}", f"under {out_dir}", "elsewhere, not collected", False)
            continue
        local = out_root / Path(rel).name
        emit(f"artifact {rel}", "exists", "exists" if local.is_file() else "missing", local.is_file())
    sast_path = out_root / "gl-sast-report.json"
    if sast_path.is_file():
        schema = json.loads(Path(schema_path).read_text())
        errors = list(jsonschema.Draft7Validator(schema).iter_errors(json.loads(sast_path.read_text())))
        emit("gl-sast-report.json schema", "0 errors", f"{len(errors)} errors", not errors)
    junit_path = out_root / "veridor-junit.xml"
    if junit_path.is_file():
        try:
            root = ET.parse(junit_path).getroot()
            cases = len(root.findall(".//testcase"))
            emit("veridor-junit.xml parses", "testcases > 0", f"{cases} testcases", cases > 0)
        except ET.ParseError as exc:
            emit("veridor-junit.xml parses", "testcases > 0", f"parse error {exc}", False)
    cq_path = out_root / "gl-code-quality-report.json"
    if cq_path.is_file():
        issues = json.loads(cq_path.read_text())
        severities = {"info", "minor", "major", "critical", "blocker"}
        ok = (isinstance(issues, list) and all(isinstance(i, dict) for i in issues)
              and len({i.get("fingerprint") for i in issues}) == len(issues)
              and all(i.get("severity") in severities for i in issues)
              and all(i.get("fingerprint") for i in issues))
        emit("gl-code-quality-report.json", "list, unique fingerprints", f"{len(issues) if isinstance(issues, list) else 'not a list'} issue(s)", ok)
print("\n".join(rows))
PYEOF

# One row per extra log line a row must print.
check_log() {  # row dir, expected log line
  local found=absent result=MISMATCH
  if grep -qF -- "$2" "$1/log"; then
    found=present
    result=ok
  fi
  printf '%s\tlog line\t%s\t%s\t%s\n' "$(basename "$1")" "${2:0:60}" "$found" "$result" >> "$RESULTS"
}

# One row for the shell a row ran under. An empty observation (the probe
# failed) is a MISMATCH, never a pass.
check_shell() {  # row dir, label, expected, observed
  local result=MISMATCH
  if [[ -n "$4" && "$4" == "$3" ]]; then
    result=ok
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$(basename "$1")" "$2" "$3" "${4:-cannot see}" "$result" >> "$RESULTS"
}

# One row per counted target, for a row that counts more than one.
check_requests() {  # row dir, target, expected new requests (0 | >0), before, after
  local got result=MISMATCH
  if [[ "$4" =~ ^[0-9]+$ && "$5" =~ ^[0-9]+$ ]]; then
    got=$(( $5 - $4 ))
    if { [[ "$3" == 0 ]] && (( got == 0 )); } || { [[ "$3" == ">0" ]] && (( got > 0 )); }; then
      result=ok
    fi
  else
    got="cannot see ($4, $5)"  # a count this script cannot read is never 0
  fi
  printf '%s\trequests to %s\t%s\t%s\t%s\n' "$(basename "$1")" "$2" "$3" "$got" "$result" >> "$RESULTS"
}

# One row per run-document field: what veridor recorded it was asked to do.
# A missing or unreadable veridor-run.json is a MISMATCH, never a pass.
check_run() {  # row dir, label, python expression over `run`, expected value as JSON
  "$PY" "$WORK/check_run.py" "$@" >> "$RESULTS"
}
cat > "$WORK/check_run.py" <<'PYEOF'
import json, sys
from pathlib import Path

dir_, label, expression, want = sys.argv[1:5]
try:
    run = json.loads((Path(dir_) / "project-out" / "veridor-run.json").read_text())
    got = json.dumps(eval(expression, {"run": run}))
except Exception as exc:  # noqa: BLE001 - any failure to read the field is "cannot see"
    got = f"cannot see ({type(exc).__name__})"
print(f"{Path(dir_).name}\t{label}\t{want}\t{got}\t{'ok' if got == want else 'MISMATCH'}")
PYEOF

row_dir() {
  local dir="$WORK/rows/$1"
  mkdir -p "$dir"
  printf '%s' "$dir"
}

base_inputs=("image=${IMAGE}")

log "row vulnerable"
dir="$(row_dir vulnerable)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
write_env "$dir"
printf 'vulnerable\trendered allow_failure\tfalse\t%s\t%s\n' "$(job_field "$dir" 'job["allow_failure"]')" \
  "$([[ "$(job_field "$dir" 'job["allow_failure"]')" == "false" ]] && echo ok || echo MISMATCH)" >> "$RESULTS"
before="$(requests_seen vulnerable-target)"
run_job "$dir" runner 0000 0
after="$(requests_seen vulnerable-target)"
check "$dir" 1 "$JOB_STATUS" yes "veridor-gate: exit 1: FAIL" vulnerable-target ">0" "$before" "$after"
# The defaults as veridor recorded them: the nondefault-inputs row below must
# differ on exactly these.
check_run "$dir" "run JSON gate.fail_on" 'run["gate"]["fail_on"]' '"new+confirmed"'
check_run "$dir" "run JSON gate.require_complete" 'run["gate"]["require_complete"]' true

log "row fixed"
dir="$(row_dir fixed)"
render "$dir" "${base_inputs[@]}" "base_url=http://fixed-target:${DEMO_PORT}"
write_env "$dir"
run_job "$dir" runner 0000 0
check "$dir" 0 "$JOB_STATUS" yes "veridor-gate: exit 0: PASS"

log "row unreachable"
dir="$(row_dir unreachable)"
render "$dir" "${base_inputs[@]}" "base_url=http://fixed-target:8799"
write_env "$dir"
run_job "$dir" runner 0000 0
check "$dir" 3 "$JOB_STATUS" yes "veridor-gate: exit 3: INCOMPLETE, failing the job"

log "row unmeasured-allowed"
dir="$(row_dir unmeasured-allowed)"
render "$dir" "${base_inputs[@]}" "base_url=http://fixed-target:8799" "allow_unmeasured=true"
write_env "$dir"
allowed="$(job_field "$dir" 'job["allow_failure"]')"
printf 'unmeasured-allowed\trendered allow_failure\t{"exit_codes": [3]}\t%s\t%s\n' "$allowed" \
  "$([[ "$allowed" == '{"exit_codes": [3]}' ]] && echo ok || echo MISMATCH)" >> "$RESULTS"
run_job "$dir" runner 0000 0
check "$dir" 3 "$JOB_STATUS" yes "shown as a warning because allow_unmeasured is true"

# The Debian image: what a job with bash, or with dash as its sh, runs. The
# rows above run busybox sh, the only shell the Alpine images have.
debian_inputs=("install=pip" "python_image=${E2E_DEBIAN_PYTHON_IMAGE}" "pip_package=${WHEEL_IN_PROJECT}")

log "row dash"
dir="$(row_dir dash)"
render "$dir" "${debian_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
write_env "$dir"
run_job "$dir" sh 0000 0
check "$dir" 1 "$JOB_STATUS" yes "veridor-gate: exit 1: FAIL"
check_shell "$dir" "/bin/sh is" /usr/bin/dash "$(sh_target "$E2E_DEBIAN_PYTHON_IMAGE")"

log "row bash"
dir="$(row_dir bash)"
render "$dir" "${debian_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
write_env "$dir"
run_job "$dir" runner 0000 0
check "$dir" 1 "$JOB_STATUS" yes "veridor-gate: exit 1: FAIL"
check_shell "$dir" "the runner's shell" bash "$JOB_SHELL"

log "row pip"
dir="$(row_dir pip)"
render "$dir" "install=pip" "python_image=${E2E_PYTHON_IMAGE}" "pip_package=${WHEEL_IN_PROJECT}" \
  "base_url=http://vulnerable-target:${DEMO_PORT}"
write_env "$dir"
run_job "$dir" runner 0000 0
check "$dir" 1 "$JOB_STATUS" yes "veridor-gate: exit 1: FAIL"

log "row empty-credential"
dir="$(row_dir empty-credential)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
write_env "$dir" "VERIDOR_OWNER_TOKEN="
before="$(requests_seen vulnerable-target)"
run_job "$dir" runner 0000 0
after="$(requests_seen vulnerable-target)"
check "$dir" 2 "$JOB_STATUS" no "environment variable 'VERIDOR_OWNER_TOKEN' is set but empty" vulnerable-target 0 "$before" "$after"

log "row extra-args-override"
dir="$(row_dir extra-args-override)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}" "extra_args=--fail none"
write_env "$dir"
before="$(requests_seen vulnerable-target)"
run_job "$dir" runner 0000 0
after="$(requests_seen vulnerable-target)"
check "$dir" 2 "$JOB_STATUS" no "extra_args contains --fail" vulnerable-target 0 "$before" "$after"

log "row unset-base-url"
dir="$(row_dir unset-base-url)"
# shellcheck disable=SC2016 # the input names a variable, deliberately unexpanded
render "$dir" "${base_inputs[@]}" 'base_url=$VERIDOR_E2E_REVIEW_APP_URL' config=veridor-fallthrough.json
write_env "$dir"
before="$(requests_seen vulnerable-target)"
run_job "$dir" runner 0000 0
after="$(requests_seen vulnerable-target)"
check "$dir" 2 "$JOB_STATUS" no "which expanded to an empty string" vulnerable-target 0 "$before" "$after"

log "row root-owned-workspace"
dir="$(row_dir root-owned-workspace)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
write_env "$dir"
before="$(requests_seen vulnerable-target)"
run_job "$dir" runner 0022 0
after="$(requests_seen vulnerable-target)"
check "$dir" 2 "$JOB_STATUS" no "cannot write veridor-out" vulnerable-target 0 "$before" "$after"

log "row sigterm"
dir="$(row_dir sigterm)"
render "$dir" "${base_inputs[@]}" "base_url=http://silent-target:${DEMO_PORT}"
write_env "$dir"
container="vg-e2e-gl-${RUN_ID}-job-sigterm"
run_job "$dir" runner 0000 1
waited=0
until docker exec "$container" python3 -c '
import os, sys
me = str(os.getpid())
for pid in os.listdir("/proc"):
    if pid.isdigit() and pid != me:
        try:
            argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except OSError:
            continue
        if any(a.endswith(b"veridor") for a in argv[:2]) and b"run" in argv:
            sys.exit(0)
sys.exit(1)'; do
  sleep 1
  waited=$((waited + 1))
  if (( waited > 30 )); then
    docker logs "$container" >&2 || log "could not read the job log"
    printf 'e2e_gitlab_job: veridor never started in the sigterm row\n' >&2
    exit 3
  fi
done
sleep 2
# What a runner does on cancel (GitLab Runner's default, FF_USE_NATIVE_CONTAINER_STOP
# off): signal the job's processes directly. PID 1 is docker's init here, so
# kill -1 reaches the job shell and veridor, not the init. `kill -TERM -1`,
# not `kill -s TERM -- -1`: busybox's kill (Alpine) reads -- as a pid and
# exits 1 ("invalid number '--'", though the signal is sent), which stopped
# this script under set -e. Both forms work in dash.
docker exec "$container" sh -c 'kill -TERM -1'
JOB_STATUS="$(docker wait "$container")"
docker logs "$container" > "$dir/log" 2>&1
collect "$dir" "$container"
check "$dir" 143 "$JOB_STATUS" no "veridor-gate: exit 143: INTERRUPTED by SIGTERM"

# The inputs no row above moves off its default, run in IMAGE, so an image
# that lacks a flag the template emits fails here. An image that rejected
# --wait-for-target still passed every row above (measured).
log "row wait-for-target"
dir="$(row_dir wait-for-target)"
render "$dir" "${base_inputs[@]}" "base_url=http://fixed-target:${DEMO_PORT}" "wait_for_target=5"
write_env "$dir"
run_job "$dir" runner 0000 0
check "$dir" 0 "$JOB_STATUS" yes "veridor: target fixed-target:${DEMO_PORT} accepted a connection after"
check_run "$dir" "run JSON target_wait.requested_seconds" 'run["target_wait"]["requested_seconds"]' 5

log "row nondefault-inputs"
# fail_on new, require_complete false, a baseline, an OpenAPI document and a
# nested output_dir, against the vulnerable target. The baseline is the vulnerable row's own run,
# so its finding is not new: exit 0 is reachable only if both --baseline and
# --fail-on new reached veridor. The vulnerable row, on the same target with
# the defaults, exits 1.
cp "$WORK/rows/vulnerable/project-out/veridor-run.json" "$WORK/project/e2e-baseline.json"
cp "$ROOT/fixtures/openapi.demo.json" "$WORK/project/e2e-openapi.json"
dir="$(row_dir nondefault-inputs)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}" "fail_on=new" \
  "require_complete=false" "baseline=e2e-baseline.json" "openapi=e2e-openapi.json" "output_dir=reports/veridor"
write_env "$dir"
before="$(requests_seen vulnerable-target)"
run_job "$dir" runner 0000 0
after="$(requests_seen vulnerable-target)"
check "$dir" 0 "$JOB_STATUS" yes "veridor-gate: exit 0: PASS" vulnerable-target ">0" "$before" "$after"
check_log "$dir" "Regression diff: 0 new, 0 resolved, 1 unchanged"
check_log "$dir" "Authorization boundary coverage:"
check_run "$dir" "run JSON gate.fail_on" 'run["gate"]["fail_on"]' '"new"'
check_run "$dir" "run JSON gate.require_complete" 'run["gate"]["require_complete"]' false

# Pipeline variables that name a proxy. With a literal base_url they used to
# carry every credential to the proxy (measured: 9 requests, the owner,
# other-tenant and admin tokens). The job now removes every *_proxy variable
# before veridor runs, unless proxy_from_environment is true.
proxy_env=("http_proxy=http://recording-proxy:${PROXY_PORT}" "HTTP_PROXY=http://recording-proxy:${PROXY_PORT}"
  "HTTPS_PROXY=http://recording-proxy:${PROXY_PORT}" "ALL_PROXY=http://recording-proxy:${PROXY_PORT}")

# Runs a rendered proxy row with the proxy variables set, then checks the
# exit code, the requests the recording proxy received and those the target
# received (it gets them either way: the proxy forwards).
run_proxy_row() {  # row dir, shell, expected requests to the proxy (0 | >0)
  local dir=$1 before after target_before target_after
  write_env "$dir" "${proxy_env[@]}"
  before="$(requests_seen recording-proxy)"
  target_before="$(requests_seen vulnerable-target)"
  run_job "$dir" "$2" 0000 0
  after="$(requests_seen recording-proxy)"
  target_after="$(requests_seen vulnerable-target)"
  check "$dir" 1 "$JOB_STATUS" yes "veridor-gate: exit 1: FAIL" recording-proxy "$3" "$before" "$after"
  check_requests "$dir" vulnerable-target ">0" "$target_before" "$target_after"
}

log "row proxy-variable"
dir="$(row_dir proxy-variable)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
run_proxy_row "$dir" runner 0
check_log "$dir" "from veridor's environment (proxy_from_environment is false)"

log "row proxy-variable-dash"
dir="$(row_dir proxy-variable-dash)"
render "$dir" "${debian_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}"
run_proxy_row "$dir" sh 0
check_log "$dir" "from veridor's environment (proxy_from_environment is false)"
check_shell "$dir" "/bin/sh is" /usr/bin/dash "$(sh_target "$E2E_DEBIAN_PYTHON_IMAGE")"

log "row proxy-opt-in"
dir="$(row_dir proxy-opt-in)"
render "$dir" "${base_inputs[@]}" "base_url=http://vulnerable-target:${DEMO_PORT}" "proxy_from_environment=true"
run_proxy_row "$dir" runner ">0"
check_log "$dir" "veridor-gate: proxy_from_environment is true, so veridor keeps"
check_log "$dir" "veridor: requests to vulnerable-target:${DEMO_PORT} go through the proxy recording-proxy:${PROXY_PORT}"

# --- the table ----------------------------------------------------------------

printf '\n%-22s %-44s %-28s %-28s %s\n' ROW CHECK EXPECTED OBSERVED RESULT
while IFS=$'\t' read -r row name expected observed result; do
  printf '%-22s %-44s %-28s %-28s %s\n' "$row" "$name" "$expected" "$observed" "$result"
done < "$RESULTS"
mismatches="$(awk '/MISMATCH$/ { n++ } END { printf "%d", n + 0 }' "$RESULTS")"
total="$(wc -l < "$RESULTS" | tr -d ' ')"
shells="$(awk -F '\t' '{ printf "%s%s in %s (/bin/sh is %s)", (NR > 1 ? "; " : ""), $2, $1, $3 }' "$JOB_SHELLS")"
printf '\n%s checks, %s mismatch(es). Image: %s. Control: %s. Job shell: %s.\n' "$total" "$mismatches" \
  "$IMAGE" "${E2E_CONTROL:-none}" "${shells:-none probed}"
if (( mismatches > 0 )); then
  exit 1
fi
exit 0
