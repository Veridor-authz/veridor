"""The workflows, and the release checks they run, held to what they claim.

A workflow is configuration nobody executes locally, so its promises -- every
action pinned, least privilege, no publish without the version check -- drift
the moment nobody reads it. Most are fast, file-reading tests; the two @slow
classes run .github/scripts/install-helm.sh and release.yml's chart step under
bash. Each check that could pass vacuously has a control that makes it fail on
a known-bad sample.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from action_harness import load_yaml  # noqa: E402
from tiers import slow  # noqa: E402

#: The extensions GitHub reads a workflow from. Both, not only .yml: a
#: `*.yml` glob here once skipped every check in this module for a file named
#: extra.yaml, which GitHub runs the same way.
WORKFLOW_SUFFIXES = (".yml", ".yaml")


def workflow_files(directory: Path) -> list[Path]:
    """Every file in the directory GitHub would run as a workflow."""
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in WORKFLOW_SUFFIXES)


def workflow_directory_problems(directory: Path) -> list[str]:
    """Anything in the workflow directory that workflow_files() does not return.

    Such a file is either not run by GitHub or not read by this module, and
    which of the two is not something a test should have to guess."""
    problems = []
    for entry in sorted(directory.iterdir()):
        if entry.is_dir():
            problems.append(f"{entry.name}: a directory; GitHub runs only top-level .yml and .yaml files")
        elif entry.suffix not in WORKFLOW_SUFFIXES:
            problems.append(f"{entry.name}: not .yml or .yaml, so this module would not read it")
    return problems


WORKFLOWS = workflow_files(ROOT / ".github" / "workflows")
E2E_KUBERNETES = ROOT / "scripts" / "e2e_kubernetes.sh"
PINNED_FILES = WORKFLOWS + [ROOT / "action.yml"]
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
_VERSION_COMMENT = re.compile(r"^\s+#\s+v\d+(?:\.\d+)*\b")


def pin_problems(text: str, source: str = "<text>") -> list[str]:
    """Every `uses:` that is neither local (`./`) nor a full SHA with a # vX comment."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        if "uses:" not in line or line.lstrip().startswith("#"):
            continue
        match = _USES.match(line)
        if not match:
            problems.append(f"{source}:{number}: unparsed uses: line {line.strip()!r}")
            continue
        ref, rest = match.group("ref"), match.group("rest")
        if ref.startswith("./"):
            continue
        if not _PIN.match(ref):
            problems.append(f"{source}:{number}: {ref} is not pinned to a full commit SHA")
        elif not _VERSION_COMMENT.match(rest):
            problems.append(f"{source}:{number}: {ref} has no `# vX.Y.Z` comment")
    return problems


_DIGEST_REF = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
#: A registry reference with a namespace and a tag and no digest after it:
#: ghcr.io/o/i:1, moby/buildkit:x, localhost:5000/o/i:1, matched anywhere in
#: the text. A bare name:tag is _BARE_TAG_REF's; `uses: docker://` is refused
#: by the pin test.
_TAG_ONLY_REF = re.compile(
    r"(?<![\w./:@-])"
    r"((?:(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+|localhost)(?::\d+)?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+)"
    r":([A-Za-z0-9_][\w.-]{0,127})(?![\w.-])(?!@sha256:[0-9a-f]{64})")
#: A bare name:tag, which Docker reads as docker.io/library/name:tag:
#: python:3.12-slim, alpine:3. Matched only where an image is consumed
#: (_IMAGE_USE), because the same shape is also a port map (8080:80, which
#: the letter lookahead skips), a uid:gid or a path:mode. It must end where a
#: shell word ends, so a digest after it (`@sha256:`) or a sed pattern
#: (`python:3\.12`) does not match.
_BARE_TAG_REF = re.compile(
    r"(?<![\w./:@$-])(?=[a-z0-9._-]*[a-z])([a-z0-9]+(?:[._-][a-z0-9]+)*)"
    r":([A-Za-z0-9_][\w.-]{0,127})(?=$|[\s\"'`;|&)])")
#: A logical line that consumes an image: a container run, pull or create, a
#: Dockerfile FROM, --from, an image= or image: value (IMAGE=, image:,
#: with.image), a container: value.
_IMAGE_USE = re.compile(r"\b(?:docker|podman)\s+(?:container\s+)?(?:run|pull|create)\b|\bFROM\s|--from[=\s]"
                        r"|\b(?i:image)\s*[:=]|\bcontainer:")
#: A command that builds an image into the local store, and its tag flags.
_BUILD = re.compile(r"\b(?:docker|podman)\s+(?:buildx\s+|image\s+)?build\b")
_TAG_FLAG = re.compile(r"(?:^|\s)(?:--tag|-t)(?:=|\s+)([^\s\"';|&)]+)")


def _logical_lines(text: str) -> list[str]:
    """Shell lines with backslash continuations joined and comment lines
    dropped, so `docker run --rm \\` then `python:3` is one line."""
    lines, pending = [], ""
    for line in text.splitlines():
        if not pending and line.lstrip().startswith("#"):
            continue
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    return lines + ([pending] if pending else [])


def locally_built_tags(job: dict) -> set[str]:
    """The name:tag references a job's own steps build into the runner's
    image store: `docker build -t/--tag`, and build-push-action with load."""
    tags = set()
    for step in job.get("steps", []):
        for line in _logical_lines(str(step.get("run", ""))):
            if _BUILD.search(line):
                tags |= set(_TAG_FLAG.findall(line))
        given = step.get("with") or {}
        if str(step.get("uses", "")).startswith("docker/build-push-action@") and given.get("load") == "true":
            tags |= {tag.strip() for tag in re.split(r"[,\n]", str(given.get("tags", ""))) if tag.strip()}
    return tags


def bare_image_uses(workflow: dict) -> list[tuple[str, str, str, bool]]:
    """(job, where, name:tag, built by that job) for every bare reference
    consumed in a run script, a `with:` input or an env value.

    A bare tag the same job built is the image it just made; any other one
    is pulled from Docker Hub by a tag that can move. A workflow-level env
    value belongs to no job, so nothing counts as built for it."""
    uses = []

    def scan(job: str, where: str, text: str, built: set[str]) -> None:
        for line in _logical_lines(text):
            if _IMAGE_USE.search(line):
                uses.extend((job, where, match.group(0), match.group(0) in built)
                            for match in _BARE_TAG_REF.finditer(line))

    for key, value in (workflow.get("env") or {}).items():
        scan("(workflow)", f"env.{key}", f"{key}: {value}", set())
    for name, job in (workflow.get("jobs") or {}).items():
        built = locally_built_tags(job)
        for key, value in (job.get("env") or {}).items():
            scan(name, f"env.{key}", f"{key}: {value}", built)
        for index, step in enumerate(job.get("steps", [])):
            scan(name, f"step {index}", str(step.get("run", "")), built)
            for block in ("with", "env"):
                for key, value in (step.get(block) or {}).items():
                    scan(name, f"step {index} {block}.{key}", f"{key}: {value}", built)
    return uses


def image_pin_problems(workflow: dict, text: str, source: str) -> list[str]:
    """Every container image a workflow runs that is not pinned by digest.

    Namespaced references are found anywhere in the text. Bare ones
    (python:3.12, which _TAG_ONLY_REF never matched) are found where a job
    consumes an image it did not build itself (bare_image_uses). The ones
    nobody writes are the actions' own defaults: setup-qemu-action runs
    docker.io/tonistiigi/binfmt:latest with --privileged, setup-buildx-action
    starts moby/buildkit:buildx-stable-1 as a privileged builder, and
    build-push-action's `sbom: true` has BuildKit run
    docker/buildkit-syft-scanner:stable-1 (all three read from the pinned
    action sources and measured with local buildx). In the release image job
    that builder pushes the image the job then signs. An image an action
    chooses by itself is not in the text at all: ACTION_IMAGES accounts for
    those."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for match in _TAG_ONLY_REF.finditer(line):
            problems.append(f"{source}:{number}: {match.group(0)} names a tag and no digest")
    for job, where, ref, built in bare_image_uses(workflow):
        if not built:
            problems.append(f"{source}: job {job} {where}: {ref} names a tag and no digest, "
                            "and no step of this job builds it")
    for name, job in (workflow.get("jobs") or {}).items():
        where = f"{source}: job {name}"
        images = []
        if job.get("container"):
            container = job["container"]
            images.append(("container", container if isinstance(container, str) else container.get("image", "")))
        for service, spec in (job.get("services") or {}).items():
            images.append((f"services.{service}", spec if isinstance(spec, str) else spec.get("image", "")))
        for label, image in images:
            if not _DIGEST_REF.match(str(image)):
                problems.append(f"{where}: {label} image {image!r} is not pinned by digest")
        for step in job.get("steps", []):
            uses, given = str(step.get("uses", "")), step.get("with") or {}
            if uses.startswith("docker/setup-qemu-action@"):
                if not _DIGEST_REF.match(str(given.get("image", ""))):
                    problems.append(f"{where}: setup-qemu-action runs its image privileged; "
                                    "with.image must be a ref@sha256 digest")
                if given.get("cache-image") != "false":
                    problems.append(f"{where}: setup-qemu-action falls back to a cached image when the "
                                    "pull fails; set cache-image: false")
            elif uses.startswith("docker/setup-buildx-action@") and given.get("driver", "docker-container") != "docker":
                opts = [opt.strip()[len("image="):] for opt in str(given.get("driver-opts", "")).splitlines()
                        if opt.strip().startswith("image=")]
                if len(opts) != 1 or not _DIGEST_REF.match(opts[0]):
                    problems.append(f"{where}: setup-buildx-action starts a BuildKit image of its choosing; "
                                    "driver-opts must say image=<ref>@sha256:<digest>")
            elif uses.startswith("docker/build-push-action@") and "sbom" in given:
                generator = re.search(r"(?:^|,)\s*generator=([^,\s]+)", str(given["sbom"]))
                if not generator or not _DIGEST_REF.match(generator.group(1)):
                    problems.append(f"{where}: sbom {given['sbom']!r} lets BuildKit pick the scanner image; "
                                    "write sbom: generator=<ref>@sha256:<digest>")
    return problems


#: How each action the workflows and action.yml use runs (`runs.using` in its
#: action.yml at the pinned SHA, read 2026-09-24). image_pin_problems reads
#: what a workflow writes; it cannot see an image an action picks for itself,
#: so a new action fails ActionImageTest until it is classified here.
ACTION_KINDS = {
    "actions/attest-build-provenance": "composite",  # actions/attest, a node action
    "actions/checkout": "node",
    "actions/download-artifact": "node",
    "actions/setup-python": "node",
    "actions/upload-artifact": "node",
    "docker/build-push-action": "node",
    "docker/login-action": "node",
    "docker/metadata-action": "node",
    "docker/setup-buildx-action": "node",
    "docker/setup-qemu-action": "node",
    "github/codeql-action/analyze": "node",
    "github/codeql-action/init": "node",
    "github/codeql-action/upload-sarif": "node",
    "helm/kind-action": "node",
    "ossf/scorecard-action": "docker",
    "pypa/gh-action-pypi-publish": "composite",  # writes and runs a docker action
    "sigstore/cosign-installer": "composite",  # downloads cosign, runs no container
}
#: The actions that run a container image the workflow does not write, and
#: what holds each image. Every `docker` action must be here.
ACTION_IMAGES = {
    "docker/setup-qemu-action": "binfmt: with.image, pinned by digest (image_pin_problems)",
    "docker/setup-buildx-action": "BuildKit: driver-opts image=, pinned by digest (image_pin_problems)",
    "docker/build-push-action": "the SBOM scanner: sbom generator=, pinned by digest (image_pin_problems)",
    "helm/kind-action": "kindest/node: kind v0.33.0's default, which kind's source pins by digest; "
                        "no registry image (registry: false)",
    "pypa/gh-action-pypi-publish": "ghcr.io/pypa/gh-action-pypi-publish:<SHA>: pulled by digest under that "
                                   "name by the step before it, checked by the step after (publish_pin_problems)",
    "ossf/scorecard-action": "ACCEPTED, see SCORECARD",
}
#: The one image nothing here pins. The runner pulls a docker action's image
#: by its tag while it sets up the job, before any step could pull a digest.
#: The job can write code-scanning results and get a Sigstore certificate
#: for scorecard.yml; PyPI's trusted publisher names release.yml, so its
#: token uploads nothing. Keyed by the pinned ref, so a bump fails
#: ActionImageTest until the tag is read again and dependabot.yml agrees.
SCORECARD = {"ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc": "ghcr.io/ossf/scorecard-action:v2.4.4"}
_ACTION_REF = re.compile(r"^\s*(?:-\s+)?uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})\b", re.M)


def action_problems(texts: dict[str, str]) -> list[str]:
    """Every action used that ACTION_KINDS does not classify, and every
    `docker` action ACTION_IMAGES does not account for."""
    used = {name for text in texts.values() for name, _ in _ACTION_REF.findall(text)}
    problems = [f"{name}: not in ACTION_KINDS; read its action.yml at the pinned SHA and classify it"
                for name in sorted(used - set(ACTION_KINDS))]
    problems += [f"{name}: runs a container image; say in ACTION_IMAGES what pins it"
                 for name in sorted(used) if ACTION_KINDS.get(name) == "docker" and name not in ACTION_IMAGES]
    return problems


#: The container the PyPI publish action runs, and the steps around it.
PUBLISH_ACTION = "pypa/gh-action-pypi-publish"
PUBLISH_IMAGE = "ghcr.io/pypa/gh-action-pypi-publish"
PIN_STEP, VERIFY_STEP = ("bash .github/scripts/pin-action-image.sh pin",
                         "bash .github/scripts/pin-action-image.sh verify")
#: What ghcr's tag for each publish-action SHA was resolved to, keyed by the
#: SHA. Nothing here can ask the registry, and both pin-action-image.sh steps
#: compare local names to each other, so a bump that moves the SHA but carries
#: the old digest ran the old container under the new tag and passed. Keyed by
#: the SHA, that bump fails until someone resolves the new tag and records it.
PUBLISH_DIGEST = {"dc37677b2e1c63e2034f94d8a5b11f265b73ba33":
                  "sha256:a68d05519f6d7e47372aeaddab80b851b69afa89be179ec41775c72c4e3ab2d5"}


def publish_pin_problems(job: dict) -> list[str]:
    """The publish action's step, unless the step before it pins the image the
    action will run and the step after it checks what ran.

    pypa/gh-action-pypi-publish writes a docker action whose image is
    docker://ghcr.io/pypa/gh-action-pypi-publish:<the action's SHA>, a tag,
    and that container mints the PyPI token. The tag named ghcr's build of
    the SHA, sha256:a68d0551..., while :v1.14.2, built from the same commit,
    was sha256:5c2f7030... (read 2026-09-24): whichever build pushed a tag
    last is what it names."""
    steps = job.get("steps", [])
    at = [i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith(PUBLISH_ACTION + "@")]
    if len(at) != 1:
        return [f"expected one {PUBLISH_ACTION} step, found {len(at)}"]
    index = at[0]
    sha = steps[index]["uses"].split("@", 1)[1]
    before = steps[index - 1] if index else {}
    after = steps[index + 1] if index + 1 < len(steps) else {}
    problems = []
    if before.get("run") != PIN_STEP:
        problems.append(f"the step before {PUBLISH_ACTION} must run {PIN_STEP!r}")
    if after.get("run") != VERIFY_STEP:
        problems.append(f"the step after {PUBLISH_ACTION} must run {VERIFY_STEP!r}")
    for label, step in (("pin", before), ("verify", after)):
        env = step.get("env") or {}
        if env.get("ACTION_IMAGE") != PUBLISH_IMAGE or env.get("ACTION_REF") != sha:
            problems.append(f"{label}: ACTION_IMAGE/ACTION_REF must be {PUBLISH_IMAGE} and {sha}, "
                            f"the tag the action runs; found {env.get('ACTION_IMAGE')}:{env.get('ACTION_REF')}")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(env.get("ACTION_DIGEST"))):
            problems.append(f"{label}: ACTION_DIGEST {env.get('ACTION_DIGEST')!r} is not a sha256 digest")
        if "if" in step or "continue-on-error" in step:
            problems.append(f"{label}: must not be skippable")
    if (before.get("env") or {}).get("ACTION_DIGEST") != (after.get("env") or {}).get("ACTION_DIGEST"):
        problems.append("pin and verify name different digests")
    recorded, pinned = PUBLISH_DIGEST.get(sha), (before.get("env") or {}).get("ACTION_DIGEST")
    if recorded is None:
        problems.append(f"no digest recorded for {PUBLISH_IMAGE}:{sha}; resolve it as release.yml says "
                        "and record it in PUBLISH_DIGEST")
    elif pinned != recorded and re.fullmatch(r"sha256:[0-9a-f]{64}", str(pinned)):
        problems.append(f"pin: ACTION_DIGEST must be {recorded}, the digest recorded for {PUBLISH_IMAGE}:{sha}; "
                        f"found {pinned}")
    return problems


#: The command GitHub runs a step's script with, by its effective `shell`
#: (GitHub docs, "supported shells"; None is a step with no shell anywhere).
GITHUB_SHELLS = {None: ["bash", "-e"], "bash": ["bash", "--noprofile", "--norc", "-eo", "pipefail"]}
#: Workflows that cannot carry `defaults`, and why. The per-step rule still
#: holds there: a run step added to one needs its own `shell: bash`.
NO_WORKFLOW_DEFAULTS = {
    "scorecard.yml": "the Scorecard API rejects published results from a workflow with top-level or "
                     "job-level defaults (ossf/scorecard-action README, Workflow Restrictions)",
}


def _default_shell(block: dict) -> object:
    return ((block.get("defaults") or {}).get("run") or {}).get("shell")


def effective_shell(workflow: dict, job: dict, step: dict) -> object:
    """The shell GitHub runs a run step with: the step's, else the job's
    default, else the workflow's, else None (`bash -e`)."""
    return step.get("shell") or _default_shell(job) or _default_shell(workflow)


def shell_problems(workflow: dict, name: str) -> list[str]:
    """Every run step GitHub would not run with pipefail, and a workflow that
    does not make `shell: bash` its default.

    With no shell GitHub runs `bash -e {0}`, where a pipeline exits with its
    last command's status. release.yml's `release_check.py versions --tag ...
    | tee -a "$GITHUB_OUTPUT"` ran that way and exited 0 for a tag the tree
    did not match, with the ::error on stderr and empty outputs (measured)."""
    problems = []
    default = _default_shell(workflow)
    if default != "bash" and name not in NO_WORKFLOW_DEFAULTS:
        problems.append(f"{name}: defaults.run.shell is {default!r}, expected 'bash'")
    for job_name, job in (workflow.get("jobs") or {}).items():
        for index, step in enumerate(job.get("steps", [])):
            shell = effective_shell(workflow, job, step)
            if "run" in step and shell != "bash":
                problems.append(f"{name}: {job_name}[{index}] runs as {shell or 'bash -e'!r}, without pipefail")
    return problems


#: release.yml's jobs that check the tagged commit and publish nothing.
RELEASE_CHECKS = ("verify", "test", "build", "detection-baseline")
#: The one protected environment. PyPI's trusted publisher names it, so PyPI
#: takes an upload only from a job GitHub held there for the reviewer.
RELEASE_ENVIRONMENT = "release"
#: Every job that writes outside the run, in the order they run. Each runs in
#: RELEASE_ENVIRONMENT.
PUBLISH_ORDER = ("provenance", "pypi", "image", "chart", "github-release")
#: What a job in the release environment runs first, after the checkout that
#: fetches it: it fails unless the environment requires a reviewer that
#: administrators cannot bypass (EnvironmentCheckStepTest runs it).
ENVIRONMENT_CHECK = f"bash .github/scripts/check-release-environment.sh {RELEASE_ENVIRONMENT}"


def environment_name(job: dict) -> object:
    environment = job.get("environment")
    return environment.get("name") if isinstance(environment, dict) else environment


def environment_check_problems(name: str, job: dict) -> list[str]:
    """A job in the release environment that does not start by checking it.

    The approval step used to be an inline `gh api ... --jq` whose result was
    compared with `[[ "$reviewers" == 0 ]]`: any other string, an HTTP error
    body included, read as protected once the exit status was lost (an added
    `|| true` did it, measured), and an `exit 0` or a `continue-on-error`
    left every test in this module passing."""
    steps = job.get("steps", [])
    if not (steps and str(steps[0].get("uses", "")).startswith("actions/checkout@")
            and len(steps) > 1 and steps[1].get("run") == ENVIRONMENT_CHECK):
        return [f"{name}: steps 0 and 1 must be actions/checkout and {ENVIRONMENT_CHECK!r}"]
    problems = []
    check = steps[1]
    if "if" in check:
        problems.append(f"{name}[1]: a step-level if: can skip the environment check")
    if (check.get("env") or {}).get("GH_TOKEN") != "${{ github.token }}":
        problems.append(f"{name}[1]: the environment check needs env GH_TOKEN: ${{{{ github.token }}}}")
    if (job.get("permissions") or {}).get("actions") != "read":
        problems.append(f"{name}: needs permissions actions: read to read the environment's settings")
    return problems


def _needs(job: dict) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def upstream(jobs: dict, name: str) -> set[str]:
    """Every job `name` transitively needs."""
    found: set[str] = set()
    for parent in _needs(jobs[name]):
        found |= {parent} | upstream(jobs, parent)
    return found


def jobs_that_start(jobs: dict, failing: str) -> list[str]:
    """Which jobs start when `failing` fails, under GitHub's default `if:
    success()` for a job with needs (a failed or skipped need skips it)."""
    started, succeeded = [], set()
    for name in _topological(jobs):
        if all(parent in succeeded for parent in _needs(jobs[name])):
            started.append(name)
            if name != failing:
                succeeded.add(name)
    return started


def _topological(jobs: dict) -> list[str]:
    order: list[str] = []
    while len(order) < len(jobs):
        ready = [n for n in jobs if n not in order and set(_needs(jobs[n])) <= set(order)]
        if not ready:
            raise AssertionError(f"needs cycle or unknown need among {sorted(set(jobs) - set(order))}")
        order += ready
    return order


def release_gate_problems(workflow: dict) -> list[str]:
    """Anything that lets release.yml publish before every check passed, from
    a job GitHub did not hold for the release environment's reviewer, or
    after an earlier publish failed.

    It used to. First, image needed only [verify, test] and chart only
    [verify, image]: simulated over that graph, a failed build, provenance or
    pypi job still started image and chart, which push and sign (and move
    `latest`). Then an `approval` job was the only one in `release`, and the
    PyPI job ran in a `pypi` environment that CONTRIBUTING said to leave
    without a reviewer. Only this file asked for the approval, and a workflow
    file at another commit, tagged v*, could leave the job out and still
    publish to PyPI, the ghcr image and the chart. A step-level if: on any
    step, the run of every pair included, was not refused either."""
    jobs = workflow["jobs"]
    problems = []
    known = set(RELEASE_CHECKS) | set(PUBLISH_ORDER)
    for name in sorted(set(jobs) - known):
        problems.append(f"{name}: not a known check or publish job; classify it in this test")
    for name in sorted(known - set(jobs)):
        problems.append(f"{name}: missing")
    for name, job in jobs.items():
        if "if" in job:
            problems.append(f"{name}: a job-level if: can start it after a failed need")
        if "continue-on-error" in job:
            problems.append(f"{name}: continue-on-error; a release job must fail when it fails")
        for index, step in enumerate(job.get("steps", [])):
            if "continue-on-error" in step:
                problems.append(f"{name}[{index}]: continue-on-error; a release step must fail its job")
            # A skipped step leaves its job green, so everything after it
            # starts. `if: github.event_name == 'workflow_dispatch'` on the
            # step that runs every pair passed this module and actionlint (only
            # the literal `${{ false }}` is flagged there), and on a tag push
            # it is always false. environment_check_problems names an `if` on
            # the environment check itself.
            if "if" in step and not (index == 1 and environment_name(job) == RELEASE_ENVIRONMENT):
                problems.append(f"{name}[{index}]: a step-level if: can skip the step and leave the job green")
        if environment_name(job) == RELEASE_ENVIRONMENT:
            problems += environment_check_problems(name, job)
    if problems:
        return problems
    for name in RELEASE_CHECKS:
        if jobs[name].get("environment"):
            problems.append(f"{name}: a check must not wait on an environment")
    for name in PUBLISH_ORDER:
        if environment_name(jobs[name]) != RELEASE_ENVIRONMENT:
            problems.append(f"{name}: publishes in environment {environment_name(jobs[name])!r}, not "
                            f"{RELEASE_ENVIRONMENT!r}, so GitHub does not hold it for the reviewer")
        missing = set(RELEASE_CHECKS) - upstream(jobs, name)
        if missing:
            problems.append(f"{name}: publishes without waiting for {sorted(missing)}")
    for earlier, later in zip(PUBLISH_ORDER, PUBLISH_ORDER[1:]):
        if earlier not in upstream(jobs, later):
            problems.append(f"{later}: starts whether or not {earlier} succeeded")
    return problems


def _workflow(name: str) -> dict:
    return load_yaml((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def _harness():
    """scripts/patched_pairs.py as a module, a fresh copy each call."""
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("patched_pairs", ROOT / "scripts" / "patched_pairs.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    return harness


#: The one CI job that runs the published-advisory pairs, what it runs, and the
#: `if:` it carries: every pair, on every event, with no condition. There used
#: to be two, split into light and heavy pairs; the split is gone, and a
#: second job running patched_pairs.py is refused (baseline_job_problems).
BASELINE_JOBS = {
    "detection-baseline": ("python3 scripts/patched_pairs.py --pull", None),
}


#: The only steps a baseline job may run before its patched_pairs.py step. The
#: harness runs whatever fixtures/pairs/ holds when it starts, so any other
#: step -- one that deletes or rewrites a fixture, a checkout of another ref,
#: an artifact unpacked over fixtures/ -- narrows the run with every other
#: check here green. Found on 2026-09-26: a release step that
#: deleted fixture files before the pairs ran passed this module. Each action
#: is held to the inputs it has here (None: any `with`), and the one run step
#: allowed, in release.yml, to its exact text.
BASELINE_SETUP_WITH = {"actions/checkout@": {"persist-credentials": "false"},
                       "actions/setup-python@": None,
                       "actions/download-artifact@": {"name": "dist", "path": "dist/"}}
RELEASE_WHEEL_INSTALL = ('python -m venv "$RUNNER_TEMP/baseline-venv"\n'
                         '"$RUNNER_TEMP/baseline-venv/bin/python" -m pip install --no-index --no-deps '
                         '"dist/veridor-${VERSION}-py3-none-any.whl"')


def baseline_setup_problems(name: str, steps: list[dict], actions: tuple[str, ...],
                            runs: tuple[str, ...] = ()) -> list[str]:
    """Every step before a baseline job's pairs that is not one it may run there."""
    problems = []
    for step in steps:
        uses = str(step.get("uses", ""))
        action = next((prefix for prefix in actions if uses.startswith(prefix)), None)
        if action is not None and set(step) <= {"name", "uses", "with"} and (
                BASELINE_SETUP_WITH[action] is None or step.get("with", {}) == BASELINE_SETUP_WITH[action]):
            continue
        if not uses and set(step) <= {"name", "run"} and str(step.get("run", "")).strip() in runs:
            continue
        problems.append(f"{name}: {step.get('name') or uses or str(step.get('run', ''))[:60]!r} runs before the "
                        "pairs and is not a step this job may run there; the harness runs whatever "
                        "fixtures/pairs/ holds when it starts")
    return problems


def baseline_job_problems(jobs: dict) -> list[str]:
    """Anything that lets CI's detection baseline run less than it says."""
    problems = []
    # Another job that runs the harness is a subset in waiting: a
    # detection-baseline-heavy put back with `if:` or a --pair would pass
    # every check below, which reads only the jobs it names.
    for name, job in jobs.items():
        if name not in BASELINE_JOBS and any("patched_pairs.py" in str(step.get("run", ""))
                                             for step in job.get("steps", [])):
            problems.append(f"{name}: runs scripts/patched_pairs.py; only {sorted(BASELINE_JOBS)} may, and it runs "
                            "every pair")
    for name, (run, condition) in BASELINE_JOBS.items():
        job = jobs.get(name)
        if job is None:
            problems.append(f"{name}: missing")
            continue
        steps = job.get("steps", [])
        runners = [step for step in steps if "patched_pairs.py" in str(step.get("run", ""))]
        if len(runners) != 1 or steps[-1] is not runners[0] or runners[0].get("run") != run:
            problems.append(f"{name}: its one patched_pairs.py step must be the last, and run exactly {run!r}")
        if job.get("if") != condition:
            problems.append(f"{name}: if is {job.get('if')!r}, expected {condition!r}")
        # A job with needs runs under GitHub's implicit success(): a need that
        # was skipped or failed skips it. When there were two baseline jobs,
        # `needs:` on the one that skipped pull requests would have skipped the
        # other on every pull request too, and nothing here or in actionlint
        # said so; a need on any job skips this one whenever that job fails.
        if "needs" in job:
            problems.append(f"{name}: needs {job['needs']!r}, so it is skipped whenever that job is skipped or "
                            "fails; a baseline job waits on nothing")
        if "continue-on-error" in job or any("continue-on-error" in step or "if" in step for step in steps):
            problems.append(f"{name}: a step-level if or a continue-on-error lets it pass without running")
        if job.get("timeout-minutes") != "25":
            problems.append(f"{name}: timeout-minutes is {job.get('timeout-minutes')!r}, expected '25'")
        problems += baseline_setup_problems(name, steps[:-1], ("actions/checkout@", "actions/setup-python@"))
    return problems


#: What veridor.yml's `on:` must be for BASELINE_JOBS to mean what it says:
#: every pair on every pull request and on every push to main.
BASELINE_PUSH = {"branches": ["main"]}


def baseline_trigger_problems(workflow: dict) -> list[str]:
    """Anything in veridor.yml's triggers that stops a baseline job running
    where the README and the CI comments say it runs.

    No test read `on:` before. Without the push trigger, or with a push filter
    such as paths-ignore over fixtures/, the pairs the pull requests did not
    run would have run only on a manual dispatch and at release, and this
    module and actionlint still passed (measured on copies of the file, when
    the pairs were split in two)."""
    on = workflow.get("on")
    if not isinstance(on, dict):
        return [f"on is {on!r}; expected a mapping with pull_request and push"]
    problems = []
    if "pull_request" not in on:
        problems.append("on: no pull_request trigger, so detection-baseline runs on no pull request")
    elif on["pull_request"] is not None:
        problems.append(f"on.pull_request is filtered ({on['pull_request']!r}); every pair runs on every one")
    if on.get("push") != BASELINE_PUSH:
        problems.append(f"on.push is {on.get('push')!r}, expected {BASELINE_PUSH!r}: detection-baseline runs "
                        "on every push to main, and a missing trigger or a filter would leave main without it")
    return problems


def coverage_problems(pairs: list[dict]) -> list[str]:
    """What the pairs every run runs could no longer catch. Each pair
    declares the grade its bug can reach; absent means `confirmed`."""
    grades = {pair.get("expected_evidence", "confirmed") for pair in pairs}
    problems = []
    if "ungraded" not in grades:
        problems.append("no status-only pair (expected_evidence ungraded): a status oracle blind to an "
                        "undeclared 200 would pass every run")
    if "confirmed" not in grades:
        problems.append("no marker pair (expected_evidence confirmed): a matched marker read as absent "
                        "would pass every run")
    return problems


def pairs_run_arguments(ci: dict, release: dict) -> dict[str, list[str] | None]:
    """The arguments each job gives scripts/patched_pairs.py, by job: CI's
    from its step as BASELINE_JOBS pins it, the release's from the run
    release_baseline_problems parses. A job that runs it some other way
    reads as None, which no argument list equals."""
    found: dict[str, list[str] | None] = {}
    for label, workflow in (("veridor.yml", ci), ("release.yml", release)):
        for name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                run = str(step.get("run", "")).strip()
                if "patched_pairs.py" not in run:
                    continue
                if label == "release.yml":
                    match = _RELEASE_PAIRS_RUN.match(run)
                    found[f"{label} {name}"] = match["args"].split() if match else None
                else:
                    head, _, args = run.partition("scripts/patched_pairs.py")
                    found[f"{label} {name}"] = args.split() if head == "python3 " else None
    return found


#: The release's run of every pair: the interpreter is quoted, the checkout
#: supplies the script, and nothing but VERIDOR_TEST_AGAINST is set inline.
_RELEASE_PAIRS_RUN = re.compile(
    r'^VERIDOR_TEST_AGAINST=(?P<mode>\S+) "(?P<python>[^"]+)" scripts/patched_pairs\.py(?P<args>(?: \S+)*)$')
_WHEEL_INSTALL = re.compile(
    r'^\s*"(?P<python>\$RUNNER_TEMP/[\w.-]+/bin/python)" -m pip install --no-index --no-deps "dist/[^"]+\.whl"\s*$',
    re.M)


def release_baseline_problems(workflow: dict) -> list[str]:
    """What stops release.yml's detection baseline from testing the wheel it
    publishes, every pair of it, before PyPI does.

    CI runs the pairs against src/, split across two jobs, and release.yml
    did not run them at all: a wheel that no longer caught one of the CVEs
    would have been attested and uploaded."""
    jobs = workflow["jobs"]
    runners = [(name, step) for name, job in jobs.items() for step in job.get("steps", [])
               if "patched_pairs.py" in str(step.get("run", ""))]
    if len(runners) != 1:
        return [f"expected one release step that runs scripts/patched_pairs.py, found {len(runners)}"]
    name, step = runners[0]
    job, steps = jobs[name], jobs[name].get("steps", [])
    match = _RELEASE_PAIRS_RUN.match(str(step["run"]).strip())
    if not match:
        return [f"{name}: {step['run']!r} is not VERIDOR_TEST_AGAINST=installed \"<venv python>\" "
                "scripts/patched_pairs.py --pull"]
    problems = []
    if match["mode"] != "installed":
        problems.append(f"{name}: VERIDOR_TEST_AGAINST={match['mode']}, so the pairs test the checkout, not the wheel")
    if match["args"].split() != ["--pull"]:
        problems.append(f"{name}: runs patched_pairs.py with {match['args'].split()}; the release runs every pair, "
                        "so --pull and nothing else")
    before = "\n".join(str(s.get("run", "")) for s in steps[:steps.index(step)])
    installed_by = [m["python"] for m in _WHEEL_INSTALL.finditer(before)]
    if installed_by != [match["python"]]:
        problems.append(f"{name}: {match['python']} is not the one interpreter an earlier step installed the dist "
                        f"wheel into with --no-index --no-deps (found {installed_by})")
    elif f'python -m venv "{match["python"].removesuffix("/bin/python")}"' not in before:
        problems.append(f"{name}: {match['python']} is not a virtual environment this job created")
    downloads = [s for s in steps[:steps.index(step)] if str(s.get("uses", "")).startswith("actions/download-artifact@")]
    published = [s for s in jobs.get("pypi", {}).get("steps", [])
                 if str(s.get("uses", "")).startswith("actions/download-artifact@")]
    if len(downloads) != 1 or downloads[0].get("with", {}).get("name") != "dist" or not published \
            or downloads[0].get("uses") != published[0].get("uses"):
        problems.append(f"{name}: must download the dist artifact the way pypi does, with the same pinned action")
    if not {"verify", "build"} <= set(_needs(job)):
        problems.append(f"{name}: needs {_needs(job)}, not verify and build")
    if name not in _needs(jobs.get("pypi", {})):
        problems.append(f"pypi: must need {name} directly, not through another job that could stop needing it")
    problems += baseline_setup_problems(name, steps[:steps.index(step)], tuple(BASELINE_SETUP_WITH),
                                        (RELEASE_WHEEL_INSTALL,))
    return problems


#: The tools the slow tier skips without, each turned into a failure. A job
#: that runs the slow tier without one of them passes by not testing.
REQUIRED_TOOLS = {"VERIDOR_REQUIRE_HELM": "1", "VERIDOR_REQUIRE_KUBECTL": "1",
                  "VERIDOR_REQUIRE_SHELLCHECK": "1"}
#: Each one downloads its tool and compares a pinned sha256 before using it.
_INSTALLS = {"VERIDOR_REQUIRE_HELM": "bash .github/scripts/install-helm.sh",
             "VERIDOR_REQUIRE_KUBECTL": "bash .github/scripts/install-kubectl.sh",
             "VERIDOR_REQUIRE_SHELLCHECK": "bash .github/scripts/install-shellcheck.sh"}
INSTALL_HELM = _INSTALLS["VERIDOR_REQUIRE_HELM"]

#: Installer actions that download a binary and run it unchecked. The pinned
#: azure/setup-helm (9bc31f4e, v5.0.1) fetches get.helm.sh's tarball, extracts
#: it and puts it on PATH with no digest comparison and no input to add one
#: (read from its source at that SHA), and it ran in the job that logs in to
#: ghcr and signs the chart.
#: The pinned anchore/sbom-action (3ad72834, v0.24.2) downloads syft's
#: install.sh from raw.githubusercontent.com at the release tag and runs it; that
#: script checks the binary only against the same release's checksums (read
#: from its source at that SHA). It ran in the release build job after dist/
#: was built and before SHA256SUMS, provenance and the PyPI upload.
INSTALL_SYFT = "bash .github/scripts/install-syft.sh"
UNCHECKED_INSTALLERS = {"azure/setup-helm@": INSTALL_HELM, "anchore/sbom-action@": INSTALL_SYFT}


def unchecked_installer_problems(workflows: dict[str, dict]) -> list[str]:
    """Every step, in any job, that uses an installer action which runs an unchecked download."""
    return [f"{source}: job {name} uses {step['uses'].split('@')[0]}; run {replacement!r} instead"
            for source, workflow in workflows.items()
            for name, job in (workflow.get("jobs") or {}).items()
            for step in job.get("steps", [])
            for prefix, replacement in UNCHECKED_INSTALLERS.items()
            if str(step.get("uses", "")).startswith(prefix)]


def sbom_step_problems(job: dict) -> list[str]:
    """The release build runs syft from the checked install, before SHA256SUMS."""
    steps = job.get("steps", [])
    runs = [str(step.get("run", "")) for step in steps]
    install = next((i for i, run in enumerate(runs) if run.strip() == INSTALL_SYFT), None)
    scan = next((i for i, run in enumerate(runs) if re.search(r"(?m)^\s*syft\s+scan\b", run)), None)
    sums = next((i for i, run in enumerate(runs) if "sha256sum" in run), None)
    problems = []
    if scan is None:
        problems.append("no step runs `syft scan`")
    elif install is None or install > scan:
        problems.append(f"`syft scan` runs before {INSTALL_SYFT!r}, or without it")
    if scan is not None and sums is not None and scan > sums:
        problems.append("the SBOM is written after SHA256SUMS, so the sums do not cover it")
    if scan is not None and "dist/veridor-${VERSION}.cdx.json" not in runs[scan]:
        problems.append("the SBOM is not written to dist/veridor-${VERSION}.cdx.json")
    return problems


def required_tool_problems(job: dict) -> list[str]:
    """A job that requires a tool must install it; one that runs the slow tier must require all."""
    problems = []
    env = job.get("env") or {}
    runs = [step.get("run", "") for step in job.get("steps", [])]
    if any("--tier slow" in run for run in runs) and env != REQUIRED_TOOLS:
        problems.append(f"runs the slow tier with env {env}, expected {REQUIRED_TOOLS}")
    for name, install in _INSTALLS.items():
        if env.get(name) == "1" and install not in runs:
            problems.append(f"{name}=1 but no step runs {install!r}")
    return problems


#: Every CI run of the slow tier is sharded over this many worker processes
#: (scripts/run_tests.py --jobs). GitHub's standard runners have 4 vCPUs
#: (ubuntu-latest, public repository), 2 (ubuntu-latest, private) and 3
#: (macos-latest, M1), per docs.github.com, "GitHub-hosted runners". The tier
#: waits far more than it computes -- sleeps, subprocesses, loopback sockets --
#: so four workers do not need four cores.
SLOW_TIER_JOBS = "4"
_TEST_RUN = re.compile(r"scripts/run_tests\.py(?P<args>[^\n;&|]*)")
#: A run_tests.py call that is the whole command on its line: an optional
#: interpreter (bare or quoted, like "$RUNNER_TEMP/venv/bin/python"), the
#: script and its arguments, and nothing else. Anything before or after it on
#: the line can decide the step's exit status instead: `|| true` and `; true`
#: discard a failure, `&& next` hides one under bash -e unless it is the last
#: line, `!` inverts it, and a pipe hands it to the command after. Measured on
#: 2026-09-27: `|| true` on each of the six tier calls left this module,
#: test_ci_configs and test_release_files green, because _TEST_RUN stops at `|`
#: and nothing asked what came next.
_WHOLE_LINE_TEST_RUN = re.compile(
    r"""^\s*(?:(?:python3?|"[^"\s]*/python3?")\s+)?scripts/run_tests\.py(?:\s+[\w./=-]+)*\s*$""")


#: How many times the workflows run each tier: CI's tests job and its
#: installed-package job, and the release's test job. Deleting the fast-tier
#: step from either workflow left every test green while only slow runs were
#: counted (measured).
TIER_RUNS = {"fast": 3, "slow": 3}


def tier_run_problems(workflows: dict[str, dict]) -> tuple[list[str], dict[str, int]]:
    """Every run_tests.py call in a workflow: the slow tier with --jobs
    SLOW_TIER_JOBS, --jobs with no other tier, and no step that runs a tier
    (or its job) skippable. Returns the problems and how many calls of each
    tier were read."""
    problems, runs = [], {"fast": 0, "slow": 0}
    for source, workflow in workflows.items():
        for name, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps", []):
                calls = list(_TEST_RUN.finditer(str(step.get("run", ""))))
                if calls:
                    problems += unskippable_problems(f"{source}: job {name}", job, [step])
                for call in calls:
                    run = str(step.get("run", ""))
                    line_start = run.rfind("\n", 0, call.start()) + 1
                    line_end = run.find("\n", call.end())
                    line = run[line_start:len(run) if line_end == -1 else line_end]
                    if not _WHOLE_LINE_TEST_RUN.match(line):
                        problems.append(f"{source}: job {name}: {line.strip()!r} is not run_tests.py alone on its "
                                        "line, so something else can decide the step's exit status")
                    args = call["args"].split()
                    tier = args[args.index("--tier") + 1] if "--tier" in args[:-1] else None
                    jobs = args[args.index("--jobs") + 1] if "--jobs" in args[:-1] else None
                    where = f"{source}: job {name}: run_tests.py{call['args'].rstrip()}"
                    if tier in runs:
                        runs[tier] += 1
                    if tier == "slow":
                        if jobs != SLOW_TIER_JOBS:
                            problems.append(f"{where}: the slow tier runs with --jobs {SLOW_TIER_JOBS}")
                    elif "--jobs" in args:
                        problems.append(f"{where}: --jobs is for the slow tier only")
    return sorted(set(problems), key=problems.index), runs


_RUNS_HELM = re.compile(r"(?m)(?:^|[;&|(]\s*|\s)helm\s|e2e_kubernetes\.sh")


def runs_helm(step: dict, job: dict) -> bool:
    """The step calls helm, or runs the slow tier in a job that requires helm.

    required_tool_problems() covers the rest."""
    run = step.get("run", "")
    return bool(_RUNS_HELM.search(run)) or (
        "--tier slow" in run and (job.get("env") or {}).get("VERIDOR_REQUIRE_HELM") == "1")


def helm_install_problems(job: dict) -> list[str]:
    """A job that runs helm gets it from the checked install script, before it runs it."""
    problems = []
    steps = job.get("steps", [])
    for step in steps:
        uses = str(step.get("uses", ""))
        for prefix, replacement in UNCHECKED_INSTALLERS.items():
            if uses.startswith(prefix):
                problems.append(f"uses {uses.split('@')[0]}, which runs an unchecked download; "
                                f"run {replacement!r} instead")
    first = next((i for i, step in enumerate(steps) if runs_helm(step, job)), None)
    if first is not None and not any(step.get("run") == INSTALL_HELM for step in steps[:first]):
        problems.append(f"step {first} runs helm, and no earlier step runs {INSTALL_HELM!r}")
    return problems


def e2e_input_problems(job: dict, script: str) -> list[str]:
    """Every variable scripts/e2e_gitlab_job.sh refuses to start without, set before it runs."""
    required = set(re.findall(r'\[\[ -n "\$(\w+)" \]\] \|\| refuse', script))
    if re.search(r"\"\$PY\" -c 'import jsonschema' \|\| refuse", script):
        required.add("PYTHON_WITH_JSONSCHEMA")  # the default, the runner's python3, has no jsonschema
    if not required:
        return ["found no required variable in the script; the parser no longer matches it"]
    steps = job.get("steps", [])
    provided = set(job.get("env") or {}) | set(steps[-1].get("env") or {})
    for step in steps[:-1]:
        provided |= set(re.findall(r'echo "(\w+)=[^"]*" >> "\$GITHUB_ENV"', step.get("run", "")))
    return [f"{name} is required by the script and never set" for name in sorted(required - provided)]


#: GitHub's advisory ids use this alphabet, in three groups of four.
ADVISORY_ID = re.compile(r"CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")


def _CVE_RECORDS(identifier: str) -> tuple[str, ...]:  # noqa: N802
    return (f"https://www.cve.org/CVERecord?id={identifier}", f"https://nvd.nist.gov/vuln/detail/{identifier}")


#: A GHSA advisory page, ending at the id: a substring test passed any URL that
#: merely mentioned one.
_GHSA_ADVISORY = re.compile(r"/advisories/GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}/?$")


def advisory_problems(advisory: dict) -> list[str]:
    """What is wrong with a pair's `advisory` block, checkable without a network."""
    problems = []
    identifier, url = str(advisory.get("id", "")), str(advisory.get("url", ""))
    if not ADVISORY_ID.fullmatch(identifier):
        problems.append(f"{identifier!r} is neither a CVE id nor a GHSA id")
    if not url.startswith("https://"):
        problems.append(f"{identifier}: {url!r} is not an https URL")
    elif identifier.startswith("GHSA-") and not re.search(rf"/{re.escape(identifier)}/?$", url):
        problems.append(f"{identifier}: {url} does not name that advisory")
    elif identifier.startswith("CVE-") and not (url in _CVE_RECORDS(identifier) or _GHSA_ADVISORY.search(url)):
        # A CVE's url is its own record or the GHSA advisory that carries it.
        # A release post fixing several flaws names none of them by its url.
        problems.append(f"{identifier}: {url} is neither that CVE's record nor a GHSA advisory")
    references = advisory.get("references", [])
    if not isinstance(references, list) or not all(
            isinstance(item, str) and item.startswith("https://") for item in references):
        problems.append(f"{identifier}: references must be a list of https URLs, found {references!r}")
    return problems


class PinningTest(unittest.TestCase):
    def test_every_uses_is_local_or_pinned_to_a_commit(self) -> None:
        count = 0
        problems = []
        for path in PINNED_FILES:
            text = path.read_text(encoding="utf-8")
            count += sum(1 for line in text.splitlines() if _USES.match(line))
            problems += pin_problems(text, path.relative_to(ROOT).as_posix())
        self.assertGreater(count, 20, "the scan found almost no uses: lines")
        self.assertEqual(problems, [])

    def test_control_unpinned_references_are_caught(self) -> None:
        samples = {
            "      - uses: actions/checkout@v4\n": "not pinned",
            "      - uses: actions/checkout@main\n": "not pinned",
            "      - uses: actions/checkout@3d3c42e\n": "not pinned",
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n": "no `# vX.Y.Z`",
            "        uses: docker://alpine:3\n": "not pinned",
            "      - uses: 'actions/checkout@v4'\n": "not pinned",
        }
        for sample, message in samples.items():
            with self.subTest(sample=sample.strip()):
                problems = pin_problems(sample)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(message, problems[0])
        self.assertEqual(pin_problems(
            "      - uses: ./\n"
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"), [])


class ActionImageTest(unittest.TestCase):
    """Images an action picks for itself, which no scan of the text can see.

    pypa/gh-action-pypi-publish ran ghcr.io/pypa/gh-action-pypi-publish by a
    tag in the job that mints the PyPI token, and ossf/scorecard-action runs
    ghcr.io/ossf/scorecard-action:v2.4.4 with id-token: write, while the
    image test passed and dependabot.yml listed neither."""

    TEXTS = {path.name: path.read_text(encoding="utf-8") for path in PINNED_FILES}

    def test_every_action_is_classified(self) -> None:
        self.assertEqual(action_problems(self.TEXTS), [])
        used = {name for text in self.TEXTS.values() for name, _ in _ACTION_REF.findall(text)}
        self.assertEqual(used, set(ACTION_KINDS), "ACTION_KINDS lists an action nothing uses")
        self.assertLessEqual(set(ACTION_IMAGES), used)

    def test_control_an_unclassified_or_unaccounted_action_is_named(self) -> None:
        sha = "a" * 40
        texts = {"w.yml": f"      - uses: someone/new-action@{sha} # v1\n"
                          f"      - uses: ossf/scorecard-action@{sha} # v2\n"}
        self.assertEqual(action_problems(texts), [
            "someone/new-action: not in ACTION_KINDS; read its action.yml at the pinned SHA and classify it"])
        saved = ACTION_IMAGES.pop("ossf/scorecard-action")
        try:
            self.assertEqual(action_problems(texts)[1:],
                             ["ossf/scorecard-action: runs a container image; say in ACTION_IMAGES what pins it"])
        finally:
            ACTION_IMAGES["ossf/scorecard-action"] = saved

    def test_the_one_accepted_image_is_the_pinned_scorecard_and_is_documented(self) -> None:
        (ref, image), = SCORECARD.items()
        self.assertIn(f"uses: {ref} #", self.TEXTS["scorecard.yml"], "scorecard-action moved; re-read its image")
        dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn(image, dependabot)
        self.assertIn(PUBLISH_IMAGE, dependabot)

    def test_the_publish_action_runs_the_image_pinned_by_digest(self) -> None:
        self.assertEqual(publish_pin_problems(_workflow("release.yml")["jobs"]["pypi"]), [])

    def test_control_an_unpinned_or_mismatched_publish_image_is_named(self) -> None:
        job = _workflow("release.yml")["jobs"]["pypi"]
        steps = job["steps"]
        index = next(i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith(PUBLISH_ACTION))
        pin, publish, verify = steps[index - 1], steps[index], steps[index + 1]
        head, tail = steps[:index - 1], steps[index + 2:]

        def problems(*middle: dict) -> list[str]:
            return publish_pin_problems(dict(job, steps=head + list(middle) + tail))

        self.assertEqual(problems(publish), [f"the step before {PUBLISH_ACTION} must run {PIN_STEP!r}",
                                             f"the step after {PUBLISH_ACTION} must run {VERIFY_STEP!r}",
                                             "pin: ACTION_IMAGE/ACTION_REF must be ghcr.io/pypa/gh-action-pypi-"
                                             f"publish and {publish['uses'].split('@')[1]}, the tag the action "
                                             "runs; found None:None",
                                             "pin: ACTION_DIGEST None is not a sha256 digest",
                                             "verify: ACTION_IMAGE/ACTION_REF must be ghcr.io/pypa/gh-action-pypi-"
                                             f"publish and {publish['uses'].split('@')[1]}, the tag the action "
                                             "runs; found None:None",
                                             "verify: ACTION_DIGEST None is not a sha256 digest"])
        bumped = dict(publish, uses=f"{PUBLISH_ACTION}@{'b' * 40}")
        moved = problems(pin, bumped, verify)
        self.assertEqual(len(moved), 3, "a moved SHA must fail both steps and the digest recorded for it")
        self.assertTrue(moved[-1].startswith(f"no digest recorded for {PUBLISH_IMAGE}:{'b' * 40};"), moved)
        tagged = dict(pin, env=dict(pin["env"], ACTION_DIGEST="v1.14.2"))
        self.assertIn("pin: ACTION_DIGEST 'v1.14.2' is not a sha256 digest", problems(tagged, publish, verify))
        other = dict(verify, env=dict(verify["env"], ACTION_DIGEST="sha256:" + "c" * 64))
        self.assertEqual(problems(pin, publish, other), ["pin and verify name different digests"])
        self.assertEqual(problems(pin, publish, dict(verify, **{"continue-on-error": "true"})),
                         ["verify: must not be skippable"])
        self.assertEqual(problems(pin, publish, verify), [])

    def test_control_a_bump_that_keeps_the_old_digest_is_named(self) -> None:
        """dependabot.yml promises this test fails until a bump names the new
        tag AND its digest. Moving the SHA and both ACTION_REFs while leaving
        ACTION_DIGEST alone passed both pin-action-image.sh steps: the old
        container ran under the new SHA's tag."""
        job = _workflow("release.yml")["jobs"]["pypi"]
        steps = job["steps"]
        index = next(i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith(PUBLISH_ACTION))
        pin, publish, verify = steps[index - 1], steps[index], steps[index + 1]
        head, tail = steps[:index - 1], steps[index + 2:]
        new = "b" * 40
        bumped = dict(publish, uses=f"{PUBLISH_ACTION}@{new}")
        moved_pin, moved_verify = (dict(step, env=dict(step["env"], ACTION_REF=new)) for step in (pin, verify))

        def problems() -> list[str]:
            return publish_pin_problems(dict(job, steps=head + [moved_pin, bumped, moved_verify] + tail))

        self.assertEqual(problems(), [f"no digest recorded for {PUBLISH_IMAGE}:{new}; resolve it as "
                                      "release.yml says and record it in PUBLISH_DIGEST"])
        new_digest = "sha256:" + "d" * 64
        PUBLISH_DIGEST[new] = new_digest
        try:
            self.assertEqual(problems(), [f"pin: ACTION_DIGEST must be {new_digest}, the digest recorded "
                                          f"for {PUBLISH_IMAGE}:{new}; found {pin['env']['ACTION_DIGEST']}"])
            moved_pin, moved_verify = (dict(step, env=dict(step["env"], ACTION_DIGEST=new_digest))
                                       for step in (moved_pin, moved_verify))
            self.assertEqual(problems(), [])
        finally:
            del PUBLISH_DIGEST[new]


def dependabot_docker_problems(dependabot: str, read=lambda path: (ROOT / path).read_text(encoding="utf-8")) -> list[str]:
    """Each Dockerfile a docker entry in dependabot.yml covers, unless every
    FROM in it names a digest or the header lists it under "Not pinned at
    all". The header said "the Dockerfiles pin their base image by digest"
    while deploy/kind/Dockerfile built FROM python:3.12-slim, a moving tag,
    and the pin tests read only the root Dockerfile."""
    header = "\n".join(line for line in dependabot.splitlines() if line.startswith("#"))
    unpinned_section = header[header.index("# Not pinned at all:"):] if "# Not pinned at all:" in header else ""
    problems = []
    for entry in load_yaml(dependabot)["updates"]:
        if entry.get("package-ecosystem") != "docker":
            continue
        path = f"{str(entry['directory']).strip('/')}/Dockerfile".lstrip("/")
        froms = re.findall(r"^FROM\s+(?:--\S+\s+)*(\S+)", read(path), re.M)
        unpinned = [image for image in froms if "@sha256:" not in image]
        listed = re.search(rf"(?<![\w/.-]){re.escape(path)}", unpinned_section) is not None
        if not froms:
            problems.append(f"{path}: no FROM line")
        elif unpinned and not listed:
            problems.append(f"{path}: FROM {', '.join(unpinned)} is not pinned by digest and the header does "
                            "not list it under 'Not pinned at all'")
        elif listed and not unpinned:
            problems.append(f"{path}: pinned by digest but listed under 'Not pinned at all'")
    return problems


class DependabotDockerTest(unittest.TestCase):
    TEXT = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")

    def test_the_entries_that_bump_several_things_bump_them_together(self) -> None:
        """One pull request per bump is one failing check per bump, on a tab a
        stranger reads as the state of the project. The docker entries each
        move one base image, so grouping would change nothing there."""
        for entry in load_yaml(self.TEXT)["updates"]:
            if entry["package-ecosystem"] != "docker":
                with self.subTest(ecosystem=entry["package-ecosystem"]):
                    self.assertTrue(entry.get("groups"), entry)

    def test_every_docker_entry_is_pinned_or_listed_as_not_pinned(self) -> None:
        self.assertEqual(dependabot_docker_problems(self.TEXT), [])

    def test_control_an_unlisted_tag_and_a_stale_listing_are_named(self) -> None:
        tag = {"Dockerfile": "FROM python:3.12-slim\n", "deploy/kind/Dockerfile": "FROM python:3.12-slim\n"}
        bare = "\n".join(line for line in self.TEXT.splitlines() if "deploy/kind/Dockerfile" not in line)
        self.assertEqual(dependabot_docker_problems(bare, tag.__getitem__), [
            "Dockerfile: FROM python:3.12-slim is not pinned by digest and the header does not list it "
            "under 'Not pinned at all'",
            "deploy/kind/Dockerfile: FROM python:3.12-slim is not pinned by digest and the header does not list "
            "it under 'Not pinned at all'"])
        digest = {path: f"FROM python:3.12-slim@sha256:{'a' * 64} AS build\n" for path in tag}
        self.assertEqual(dependabot_docker_problems(bare, digest.__getitem__), [])
        self.assertEqual(dependabot_docker_problems(self.TEXT, digest.__getitem__), [
            "deploy/kind/Dockerfile: pinned by digest but listed under 'Not pinned at all'"])


#: scripts/image_bytecode_check.py, as the image job runs it.
BYTECODE_CHECK = "python3 scripts/image_bytecode_check.py"
#: The warm step each control puts in place of the Dockerfile's: nothing, and
#: the step as it was before a run was checked.
BYTECODE_CONTROLS = {"cold": "true", "cli-only": 'env -u PYTHONDONTWRITEBYTECODE python -c "import veridor.cli"'}


def unskippable_problems(where: str, job: dict, steps: list[dict]) -> list[str]:
    """An `if` or a `continue-on-error` on the job or on any of ``steps``: a
    skipped step leaves its job green, and a failing one that may continue
    fails nothing. The detection-baseline job was held to this; the checks
    below were not, and `if: ${{ false }}` or `continue-on-error: true` on the
    bytecode check, its controls, the GitLab controls or any tier step left
    every test green (measured)."""
    problems = [f"{where}: the job has `{key}`, so it can pass without running"
                for key in ("if", "continue-on-error") if key in job]
    for step in steps:
        label = step.get("name") or str(step.get("run", step.get("uses", "")))[:60]
        problems += [f"{where}: step {label!r} has `{key}`, so it can pass without running"
                     for key in ("if", "continue-on-error") if key in step]
    return problems


def image_bytecode_problems(job: dict, dockerfile: str) -> list[str]:
    """The image job runs the bytecode check on the image it built, then on one
    image per BYTECODE_CONTROLS entry, built from the Dockerfile with its warm
    step replaced, where the check must exit 1. The warm step the controls
    replace must be the Dockerfile's, and no step of the job may be skipped."""
    steps = job.get("steps", [])
    runs = [str(step.get("run", "")) for step in steps]
    built = next((i for i, step in enumerate(steps)
                  if str(step.get("uses", "")).startswith("docker/build-push-action@")
                  and (step.get("with") or {}).get("load") == "true"), None)
    checking = [i for i, run in enumerate(runs)
                if re.search(rf"^{re.escape(BYTECODE_CHECK)} veridor:ci$", run, re.M)]
    if not checking:
        return ["no step runs the bytecode check on veridor:ci"]
    problems = unskippable_problems("image", job, steps)
    if built is None or checking[0] < built:
        problems.append("the bytecode check runs before the job builds veridor:ci")
    run = runs[checking[0]]
    warm = re.search(r"^warm='(.+)'$", run, re.M)
    if warm is None:
        problems.append("the controls name no warm step to replace")
    elif dockerfile.count(warm.group(1)) != 1:
        problems.append(f"the controls' warm step {warm.group(1)!r} is not in the Dockerfile exactly once")
    if f"for control in {' '.join(BYTECODE_CONTROLS)}; do" not in run:
        problems.append(f"the step does not build every control: {' '.join(BYTECODE_CONTROLS)}")
    if not re.search(r"^\s*replacement=true$", run, re.M) or \
            f"replacement='{BYTECODE_CONTROLS['cli-only']}'" not in run:
        problems.append("a control does not replace the warm step with what BYTECODE_CONTROLS says")
    if not re.search(r'^\s*docker buildx build .*--tag "veridor:ci-\$control"', run, re.M):
        problems.append("the control images veridor:ci-$control are not built")
    if (f'{BYTECODE_CHECK} "veridor:ci-$control" || rc=$?' not in run
            or not re.search(r'^\s*if \[\[ "\$rc" != 1 \]\]; then\n.*\n\s*exit 1$', run, re.M)):
        problems.append("the check on each control image is not required to exit 1")
    return problems


class ImageBytecodeJobTest(unittest.TestCase):
    """The CI image job checks that starting and running the image compile
    nothing from source. Nothing did: with PYTHONDONTWRITEBYTECODE moved above
    the pip install, 109 modules compiled on every start of the slim image,
    and all 176 tests in this module, test_ci_configs.py and the image tests
    passed (measured). Then the check ran `--version` alone and passed while
    every run compiled two codecs from source."""

    JOB = _workflow("veridor.yml")["jobs"]["image"]
    DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    def index(self) -> int:
        return next(i for i, step in enumerate(self.JOB["steps"]) if BYTECODE_CHECK in str(step.get("run", "")))

    def test_the_image_job_runs_the_check_and_its_controls(self) -> None:
        self.assertEqual(image_bytecode_problems(self.JOB, self.DOCKERFILE), [])

    def test_control_a_missing_check_or_a_control_that_cannot_fail_is_named(self) -> None:
        index = self.index()
        without = dict(self.JOB, steps=[s for i, s in enumerate(self.JOB["steps"]) if i != index])
        self.assertEqual(image_bytecode_problems(without, self.DOCKERFILE),
                         ["no step runs the bytecode check on veridor:ci"])
        early = dict(self.JOB, steps=[self.JOB["steps"][index]] + without["steps"])
        self.assertEqual(image_bytecode_problems(early, self.DOCKERFILE),
                         ["the bytecode check runs before the job builds veridor:ci"])
        moved = self.DOCKERFILE.replace("env -u PYTHONDONTWRITEBYTECODE python", "python", 1)
        self.assertNotEqual(moved, self.DOCKERFILE, "the mutation did not apply")
        self.assertEqual(len(image_bytecode_problems(self.JOB, moved)), 1)
        run = self.JOB["steps"][index]["run"]
        for label, mutated in (("passes", run.replace('[[ "$rc" != 1 ]]', '[[ "$rc" != 0 ]]')),
                               ("not built", run.replace('--tag "veridor:ci-$control"', "--tag veridor:ci")),
                               ("one control", run.replace("for control in cold cli-only; do",
                                                           "for control in cold; do")),
                               ("the old step kept", run.replace(BYTECODE_CONTROLS["cli-only"], "true"))):
            with self.subTest(label):
                self.assertNotEqual(mutated, run, "the mutation did not apply")
                steps = [dict(s, run=mutated) if i == index else s for i, s in enumerate(self.JOB["steps"])]
                self.assertEqual(len(image_bytecode_problems(dict(self.JOB, steps=steps), self.DOCKERFILE)), 1)

    def test_control_a_skippable_check_or_job_is_named(self) -> None:
        """Each of these left every test green before."""
        index = self.index()
        gate = next(i for i, step in enumerate(self.JOB["steps"]) if "demo_server.py" in str(step.get("run", "")))
        for label, key, value in (("if", "if", "${{ false }}"), ("continue-on-error", "continue-on-error", "true")):
            for where in (index, gate):
                with self.subTest(label, step=where):
                    steps = [dict(s, **{key: value}) if i == where else s for i, s in enumerate(self.JOB["steps"])]
                    found = image_bytecode_problems(dict(self.JOB, steps=steps), self.DOCKERFILE)
                    self.assertEqual(len(found), 1, found)
                    self.assertIn(f"has `{key}`, so it can pass without running", found[0])
            with self.subTest(label, job=True):
                found = image_bytecode_problems(dict(self.JOB, **{key: value}), self.DOCKERFILE)
                self.assertEqual(found, [f"image: the job has `{key}`, so it can pass without running"])


class ImagePinningTest(unittest.TestCase):
    def test_every_image_a_workflow_names_is_pinned_by_digest(self) -> None:
        problems, qemu = [], 0
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            problems += image_pin_problems(load_yaml(text), text, path.name)
            qemu += text.count("docker/setup-qemu-action@")
        self.assertEqual(problems, [])
        self.assertEqual(qemu, 1, "the scan no longer sees the release image job")

    def test_the_bare_tags_the_workflows_run_are_the_ones_they_build(self) -> None:
        uses = {(path.name, job, ref, built) for path in WORKFLOWS
                for job, _, ref, built in bare_image_uses(load_yaml(path.read_text(encoding="utf-8")))}
        self.assertEqual(uses, {("veridor.yml", "image", "veridor:ci", True),
                                ("veridor.yml", "gitlab-job-e2e", "veridor:gitlab-e2e", True)})

    def test_control_a_bare_tag_is_named_unless_the_same_job_built_it(self) -> None:
        """_TAG_ONLY_REF needs a namespace, so `docker run --rm python:3.12-slim`,
        the commonest way to run an image by a moving tag, passed this test
        when added to release.yml's image job (measured)."""
        digest = "@sha256:" + "a" * 64

        def problems(*steps: dict) -> list[str]:
            return image_pin_problems({"jobs": {"j": {"steps": list(steps)}}}, "", "w")

        unpinned = {
            "run": [{"run": "docker run --rm python:3.12-slim python -V"}],
            "pull": [{"run": "set -e\ndocker pull alpine:3"}],
            "continued": [{"run": "docker run --rm \\\n  -v a:/b python:3 python -V"}],
            "FROM": [{"run": "echo 'FROM python:3.12' | docker build -"}],
            "with.image": [{"uses": "o/a@x", "with": {"image": "postgres:16"}}],
            "step env": [{"run": 'docker run --rm "$IMAGE"', "env": {"IMAGE": "python:3"}}],
            "not built": [{"run": "docker run --rm veridor:ci --version"}],
            "pushed, not loaded": [{"uses": "docker/build-push-action@x", "with": {"push": "true", "tags": "veridor:ci"}},
                                   {"run": "docker run --rm veridor:ci"}],
        }
        for label, steps in unpinned.items():
            with self.subTest(label):
                found = problems(*steps)
                self.assertEqual(len(found), 1, found)
                self.assertIn("names a tag and no digest, and no step of this job builds it", found[0])
        elsewhere = {"jobs": {"build": {"steps": [{"run": "docker build --tag veridor:ci ."}]},
                              "use": {"steps": [{"run": "docker run --rm veridor:ci"}]}}}
        self.assertEqual(len(image_pin_problems(elsewhere, "", "w")), 1, "built by one job, run by another")
        self.assertEqual(problems(
            {"run": "docker build --tag veridor:ci .\ndocker run --rm veridor:ci --version"},
            {"run": 'docker build \\\n  -t veridor:e2e .\necho "IMAGE=veridor:e2e" >> "$GITHUB_ENV"'},
            {"uses": "docker/build-push-action@x", "with": {"load": "true", "tags": "veridor:loaded"}},
            {"run": "docker run --rm veridor:loaded"},
            {"run": "docker run -p 8080:80 -u 1000:1000 python:3.12-slim" + digest},
            {"run": "base=\"$(sed -n 's/^FROM \\(python:3\\.12-alpine@sha256/p' Dockerfile)\""},
            {"run": "# docker run python:3 in a comment\necho python:3 is only text here"}), [])

    def test_control_each_unpinned_shape_is_named(self) -> None:
        digest = "@sha256:" + "a" * 64
        cases = {
            "qemu default": {"uses": "docker/setup-qemu-action@x", "with": {"cache-image": "false"}},
            "qemu by tag": {"uses": "docker/setup-qemu-action@x",
                            "with": {"image": "docker.io/tonistiigi/binfmt:latest", "cache-image": "false"}},
            "qemu cache": {"uses": "docker/setup-qemu-action@x", "with": {"image": "t/binfmt:q" + digest}},
            "buildx default": {"uses": "docker/setup-buildx-action@x"},
            "buildx by tag": {"uses": "docker/setup-buildx-action@x",
                              "with": {"driver-opts": "image=moby/buildkit:v0.32.2"}},
            "sbom true": {"uses": "docker/build-push-action@x", "with": {"sbom": "true"}},
            "sbom by tag": {"uses": "docker/build-push-action@x",
                            "with": {"sbom": "generator=docker/buildkit-syft-scanner:stable-1"}},
        }
        for label, step in cases.items():
            with self.subTest(label):
                self.assertEqual(len(image_pin_problems({"jobs": {"j": {"steps": [step]}}}, "", "w")), 1)
        container = {"jobs": {"j": {"container": "python:3.12", "services": {"db": {"image": "postgres:16"}}}}}
        self.assertEqual(len(image_pin_problems(container, "", "w")), 2)
        for line in ("        image: ghcr.io/o/i:1\n", "  run: docker pull quay.io/o/i:tag && x\n",
                     "  driver-opts: image=moby/buildkit:buildx-stable-1\n", "  x: localhost:5000/o/i:1\n"):
            with self.subTest(line=line.strip()):
                self.assertEqual(len(image_pin_problems({}, line, "w")), 1, line)
        pinned = {"jobs": {"j": {"container": {"image": "python:3.12" + digest}, "steps": [
            {"uses": "docker/setup-qemu-action@x", "with": {"image": "t/binfmt:q" + digest, "cache-image": "false"}},
            {"uses": "docker/setup-buildx-action@x", "with": {"driver-opts": "image=moby/buildkit:v1" + digest}},
            {"uses": "docker/setup-buildx-action@x", "with": {"driver": "docker"}},
            {"uses": "docker/build-push-action@x", "with": {"sbom": "generator=d/s:1" + digest}}]}}}
        text = ("  image: ghcr.io/o/i:1" + digest + "\n  # moby/buildkit:latest in a comment\n"
                "  run: docker run --rm veridor:ci --version\n  url: http://127.0.0.1:8765/api\n")
        self.assertEqual(image_pin_problems(pinned, text, "w"), [])

    def test_every_image_the_detection_baseline_runs_is_pinned_by_digest(self) -> None:
        """The images the detection-baseline jobs run are named in
        fixtures/pairs/, which this class never read, so they ran by tag:
        whatever gitea/gitea:1.26.4 named the day a runner pulled it. The
        harness now runs image:tag@digest, and Docker resolves that by the
        digest alone (a tag given another tag's digest runs the other build,
        measured), so a tag carries one digest wherever it appears, and no two
        tags share one.

        A built pair has no registry image to pin. It is pinned by what it is
        built from, as exactly: a base image by digest and each side's
        published package file by its sha256, two different files."""
        pinned: dict[str, str] = {}
        built: list[str] = []
        paths = sorted((ROOT / "fixtures" / "pairs").glob("*.json"))
        for path in paths:
            pair = json.loads(path.read_text(encoding="utf-8"))
            if "build" in pair:
                built.append(path.name)
                with self.subTest(fixture=path.name, built=True):
                    self.assertRegex(pair["build"]["base"], r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
                    for field in ("vulnerable_sha256", "patched_sha256"):
                        self.assertRegex(str(pair.get(field)), r"^[0-9a-f]{64}$")
                    self.assertNotEqual(pair["vulnerable_sha256"], pair["patched_sha256"])
                    self.assertFalse({"vulnerable_digest", "patched_digest"} & set(pair))
                    self.assertTrue(pair["image"].startswith("veridor-pair-build/"))
                continue
            for side, field in (("vulnerable", "vulnerable_digest"), ("patched", "patched_digest")):
                with self.subTest(fixture=path.name, field=field):
                    self.assertRegex(str(pair.get(field)), r"^sha256:[0-9a-f]{64}$")
                    self.assertEqual(pinned.setdefault(f"{pair['image']}:{pair[side]}", pair[field]), pair[field],
                                     "one tag pinned to two builds")
        self.assertGreaterEqual(len(paths), 9)
        self.assertGreaterEqual(len(built), 1, "the scan no longer sees the built pair")
        self.assertGreaterEqual(len(pinned), 12, "the scan no longer sees the registry pairs' twelve tags")
        self.assertEqual(len(set(pinned.values())), len(pinned), "two tags pinned to one build")
        self.assertEqual(len(_harness().load_pairs(None)), len(paths))

    def test_control_a_pair_without_a_well_formed_pin_is_refused(self) -> None:
        harness = _harness()
        base = json.loads((ROOT / "fixtures" / "pairs" / "gitea-revoked-starred.json").read_text(encoding="utf-8"))
        pin = base["vulnerable_digest"]
        refused = {
            "missing": {key: value for key, value in base.items() if key != "vulnerable_digest"},
            "a tag": {**base, "vulnerable_digest": "1.26.4"},
            "too short": {**base, "vulnerable_digest": "sha256:8e25c717"},
            "upper-case hex": {**base, "vulnerable_digest": "sha256:" + pin.split(":")[1].upper()},
            "another algorithm": {**base, "vulnerable_digest": "sha512:" + pin.split(":")[1]},
            "with the repository": {**base, "vulnerable_digest": f"gitea/gitea@{pin}"},
            "null": {**base, "patched_digest": None},
            "one build on both sides": {**base, "patched_digest": pin},
        }
        with tempfile.TemporaryDirectory() as directory:
            harness.PAIRS_DIR = Path(directory)
            target = Path(directory, "p.json")
            for label, pair in refused.items():
                with self.subTest(label):
                    target.write_text(json.dumps(pair), encoding="utf-8")
                    with self.assertRaises(harness.PairError) as caught:
                        harness.load_pairs(None)
                    self.assertTrue(str(caught.exception).startswith("p.json: "), caught.exception)
            # Control: the fixture as it is loads.
            target.write_text(json.dumps(base), encoding="utf-8")
            self.assertEqual(len(harness.load_pairs(None)), 1)

    def test_a_pair_marked_heavy_is_refused_whatever_the_value(self) -> None:
        """`"heavy": true` used to keep a pair off every pull request. The
        split is gone; a fixture that still carries the key, with any value,
        is refused at load, before any container starts, saying why."""
        harness = _harness()
        base = json.loads((ROOT / "fixtures" / "pairs" / "gitea-revoked-starred.json").read_text(encoding="utf-8"))
        self.assertNotIn("heavy", base)
        with tempfile.TemporaryDirectory() as directory:
            harness.PAIRS_DIR = Path(directory)
            target = Path(directory, "p.json")
            for value in (True, False, "true", 1, None):
                with self.subTest(heavy=value):
                    target.write_text(json.dumps({**base, "heavy": value}), encoding="utf-8")
                    with self.assertRaises(harness.PairError) as caught:
                        harness.load_pairs(None)
                    self.assertTrue(str(caught.exception).startswith('p.json: "heavy" is not a fixture field'))
                    self.assertIn("Every pair runs everywhere", str(caught.exception))
            # Control: the same fixture without the key loads.
            target.write_text(json.dumps(base), encoding="utf-8")
            self.assertEqual(len(harness.load_pairs(None)), 1)
        # No shipped fixture carries it.
        self.assertEqual([path.name for path in sorted((ROOT / "fixtures" / "pairs").glob("*.json"))
                          if "heavy" in json.loads(path.read_text(encoding="utf-8"))], [])


class WorkflowShapeTest(unittest.TestCase):
    def test_the_scan_covers_every_file_github_would_run(self) -> None:
        """GitHub runs .yaml as well as .yml; a *.yml glob skipped every check
        in this module for extra.yaml (measured: the byte-identical file named
        extra.yml failed six tests, named extra.yaml it passed all of them)."""
        directory = ROOT / ".github" / "workflows"
        self.assertEqual(workflow_directory_problems(directory), [])
        self.assertEqual(WORKFLOWS, workflow_files(directory))
        self.assertIn(directory / "release.yml", WORKFLOWS)

    def test_control_a_yaml_workflow_is_scanned_and_anything_else_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ("a.yml", "b.yaml", "notes.md", "c.yml.bak"):
                (directory / name).write_text("on: push\n", encoding="utf-8")
            (directory / "nested").mkdir()
            self.assertEqual([p.name for p in workflow_files(directory)], ["a.yml", "b.yaml"])
            self.assertEqual(workflow_directory_problems(directory), [
                "c.yml.bak: not .yml or .yaml, so this module would not read it",
                "nested: a directory; GitHub runs only top-level .yml and .yaml files",
                "notes.md: not .yml or .yaml, so this module would not read it",
            ])

    def test_every_workflow_parses_and_is_read_only_at_the_top(self) -> None:
        self.assertGreaterEqual(len(WORKFLOWS), 4)
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                workflow = load_yaml(path.read_text(encoding="utf-8"))
                self.assertEqual(workflow["permissions"], {"contents": "read"})

    def test_every_run_step_runs_with_pipefail(self) -> None:
        runs = 0
        for path in WORKFLOWS:
            workflow = load_yaml(path.read_text(encoding="utf-8"))
            with self.subTest(workflow=path.name):
                self.assertEqual(shell_problems(workflow, path.name), [])
            runs += sum("run" in step for job in workflow["jobs"].values() for step in job.get("steps", []))
        self.assertGreater(runs, 30, "the scan found almost no run steps")
        self.assertLessEqual(set(NO_WORKFLOW_DEFAULTS), {path.name for path in WORKFLOWS})

    def test_control_a_run_step_without_pipefail_is_named(self) -> None:
        bare = {"jobs": {"j": {"steps": [{"run": "a | b"}, {"uses": "o/a@x"}]}}}
        self.assertEqual(shell_problems(bare, "w.yml"), [
            "w.yml: defaults.run.shell is None, expected 'bash'",
            "w.yml: j[0] runs as 'bash -e', without pipefail"])
        # The exemption lifts the workflow-level rule, never the per-step one.
        self.assertEqual(shell_problems(bare, "scorecard.yml"),
                         ["scorecard.yml: j[0] runs as 'bash -e', without pipefail"])
        bare["jobs"]["j"]["steps"][0]["shell"] = "bash"
        self.assertEqual(shell_problems(bare, "scorecard.yml"), [])
        workflow = {"defaults": {"run": {"shell": "bash"}},
                    "jobs": {"j": {"steps": [{"run": "a | b"}, {"run": "c", "shell": "sh"}]},
                             "k": {"defaults": {"run": {"shell": "sh"}}, "steps": [{"run": "d"}]}}}
        self.assertEqual(shell_problems(workflow, "w.yml"), [
            "w.yml: j[1] runs as 'sh', without pipefail", "w.yml: k[0] runs as 'sh', without pipefail"])

    def test_every_job_has_a_timeout(self) -> None:
        for path in WORKFLOWS:
            for name, job in load_yaml(path.read_text(encoding="utf-8"))["jobs"].items():
                with self.subTest(workflow=path.name, job=name):
                    self.assertIn("timeout-minutes", job)

    def test_no_checkout_keeps_a_credential(self) -> None:
        checkouts = 0
        for path in WORKFLOWS:
            for name, job in load_yaml(path.read_text(encoding="utf-8"))["jobs"].items():
                for step in job.get("steps", []):
                    if str(step.get("uses", "")).startswith("actions/checkout@"):
                        checkouts += 1
                        with self.subTest(workflow=path.name, job=name):
                            self.assertEqual((step.get("with") or {}).get("persist-credentials"), "false")
        self.assertGreater(checkouts, 10)

    def test_write_permissions_are_granted_only_where_needed(self) -> None:
        allowed = {
            ("veridor.yml", "action-e2e"): {"security-events"},
            ("codeql.yml", "analyze"): {"security-events"},
            ("scorecard.yml", "analysis"): {"security-events", "id-token"},
            ("release.yml", "provenance"): {"id-token", "attestations"},
            ("release.yml", "pypi"): {"id-token"},
            ("release.yml", "image"): {"packages", "id-token"},
            ("release.yml", "chart"): {"packages", "id-token"},
            ("release.yml", "github-release"): {"contents"},
        }
        seen = {}
        for path in WORKFLOWS:
            for name, job in load_yaml(path.read_text(encoding="utf-8"))["jobs"].items():
                writes = {key for key, value in (job.get("permissions") or {}).items() if value == "write"}
                if writes:
                    seen[(path.name, name)] = writes
        self.assertEqual(seen, allowed)

    def test_ci_has_the_jobs_it_documents(self) -> None:
        workflow = _workflow("veridor.yml")
        self.assertEqual(set(workflow["jobs"]), {"tests", "installed-package", "action-e2e",
                                                 "lint", "kubernetes-e2e", "gitlab-job-e2e",
                                                 "image", "detection-baseline"})
        self.assertIn("concurrency", workflow)
        tests = workflow["jobs"]["tests"]
        self.assertEqual(tests["env"], REQUIRED_TOOLS)
        installed = workflow["jobs"]["installed-package"]
        against = [step.get("env", {}).get("VERIDOR_TEST_AGAINST") for step in installed["steps"]]
        self.assertEqual(against.count("installed"), 2, "both tiers must run against the wheel")

    def test_the_action_is_exercised_through_uses_dot(self) -> None:
        steps = _workflow("veridor.yml")["jobs"]["action-e2e"]["steps"]
        local = [step for step in steps if step.get("uses") == "./"]
        self.assertEqual([step["id"] for step in local], ["vulnerable", "fixed"])
        self.assertEqual(local[0].get("continue-on-error"), "true")
        self.assertNotIn("continue-on-error", local[1])
        assertion = next(step for step in steps if step.get("name") == "Assert what a workflow sees")
        self.assertEqual(assertion["env"]["VULNERABLE_OUTCOME"], "${{ steps.vulnerable.outcome }}")
        self.assertIn('check "vulnerable outcome" "$VULNERABLE_OUTCOME" failure', assertion["run"])
        self.assertIn('check "vulnerable exit-code" "$VULNERABLE_EXIT" 1', assertion["run"])
        self.assertIn('check "fixed exit-code" "$FIXED_EXIT" 0', assertion["run"])
        upload = next(step for step in steps if "upload-sarif" in str(step.get("uses")))
        self.assertEqual(upload["with"]["category"], "veridor")
        # The demo's bug is not this repository's: on a push it stood open in
        # the Security tab as an error. Only a manual run uploads it.
        self.assertIn("github.event_name == 'workflow_dispatch'", upload["if"])
        self.assertNotIn("pull_request", upload["if"])

    def test_the_release_procedure_asks_for_the_manual_sarif_run(self) -> None:
        """Only a manual run asks GitHub to accept the SARIF, so with no step that
        makes someone do it, nothing does. A comment on the workflow step was the
        only instruction. The step's name is quoted, so a rename fails here."""
        procedure = " ".join((ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8").split())
        self.assertIn("gh workflow run veridor.yml --ref BRANCH", procedure)
        upload = next(step for step in _workflow("veridor.yml")["jobs"]["action-e2e"]["steps"]
                      if "upload-sarif" in str(step.get("uses")))
        self.assertIn(upload["name"], procedure)

    def test_the_lint_job_shellchecks_every_shell_script(self) -> None:
        """scripts/pre-push has no .sh suffix, so the glob missed it and it held
        a warning (SC2034) that no job could see (measured). Every tracked file
        with a shell shebang has to fall under the step's list."""
        step = next(s for s in _workflow("veridor.yml")["jobs"]["lint"]["steps"]
                    if s.get("name") == "shellcheck the repository's shell scripts")
        listed = re.search(r"scripts=\(([^)]*)\)", step["run"]).group(1).split()
        shell = [path.relative_to(ROOT) for top in ("scripts", "deploy", ".github/scripts")
                 for path in (ROOT / top).rglob("*") if path.is_file()
                 and path.read_bytes()[:64].split(b"\n")[0] in (b"#!/usr/bin/env bash", b"#!/bin/bash", b"#!/bin/sh", b"#!/usr/bin/env sh")]
        self.assertGreater(len(shell), 8)
        for path in shell:
            with self.subTest(path=path.as_posix()):
                self.assertTrue(any(fnmatch.fnmatch(path.as_posix(), pattern.replace("**/", "*/"))
                                    for pattern in listed), listed)

    def test_the_e2e_scripts_ci_runs_are_the_ones_named(self) -> None:
        jobs = _workflow("veridor.yml")["jobs"]
        self.assertEqual(jobs["kubernetes-e2e"]["steps"][-1]["run"], "bash scripts/e2e_kubernetes.sh")
        self.assertEqual(jobs["kubernetes-e2e"]["steps"][-1]["env"]["KUBE_CONTEXT"], "kind-veridor-e2e")
        kind = next(s for s in jobs["kubernetes-e2e"]["steps"] if "kind-action" in str(s.get("uses")))
        self.assertEqual(kind["with"]["cluster_name"], "veridor-e2e")
        self.assertEqual(jobs["gitlab-job-e2e"]["steps"][-1]["run"], "bash scripts/e2e_gitlab_job.sh")
        self.assertTrue((ROOT / "scripts" / "e2e_kubernetes.sh").is_file())

    def test_an_advisory_has_to_name_a_real_id_form_and_where_it_was_published(self) -> None:
        """This test's first form was startswith(("CVE-", "GHSA-")), which any
        string after the prefix passed. What it can hold offline is spelling and
        a cited URL. Whether the advisory exists takes a person with a browser."""
        good = {"id": "CVE-2026-33313", "url": "https://www.cve.org/CVERecord?id=CVE-2026-33313"}
        self.assertEqual(advisory_problems(good), [])
        self.assertEqual(advisory_problems({**good, "url": "https://example.test/advisories/GHSA-mr3j-p26x-72x4"}), [])
        self.assertEqual(advisory_problems({**good, "references": ["https://example.test/release"]}), [])
        self.assertEqual(advisory_problems({"id": "GHSA-qw92-hqxv-2x9g",
                                            "url": "https://example.test/GHSA-qw92-hqxv-2x9g"}), [])
        for label, advisory in (("no digits", {**good, "id": "CVE-"}),
                                ("short sequence", {**good, "id": "CVE-2026-123"}),
                                ("trailing text", {**good, "id": "CVE-2026-33313 maybe"}),
                                ("not a GHSA alphabet", {**good, "id": "GHSA-aaaa-bbbb-1111"}),
                                ("no url", {"id": "CVE-2026-33313"}),
                                ("plain http", {**good, "url": "http://example.test/a"}),
                                ("a GHSA whose url names another",
                                 {"id": "GHSA-qw92-hqxv-2x9g", "url": "https://example.test/a"}),
                                ("a CVE whose url is a page naming no flaw",
                                 {**good, "url": "https://example.test/release-of-1.0/"}),
                                ("a CVE whose url is another CVE's record",
                                 {**good, "url": "https://www.cve.org/CVERecord?id=CVE-2026-33314"}),
                                ("a CVE whose record id is longer than its own",
                                 {**good, "id": "CVE-2026-3331", "url": good["url"]}),
                                ("a CVE whose url only mentions it",
                                 {**good, "url": "https://blog.example/post?CVE-2026-33313"}),
                                ("a CVE whose url mentions a GHSA path mid-way",
                                 {**good, "url": "https://example.test/advisories/GHSA-mr3j-p26x-72x4/../x"}),
                                ("a GHSA whose url only mentions it",
                                 {"id": "GHSA-qw92-hqxv-2x9g", "url": "https://example.test/?q=GHSA-qw92-hqxv-2x9g"}),
                                ("references not a list", {**good, "references": "https://example.test/r"}),
                                ("a plain-http reference", {**good, "references": ["http://example.test/r"]})):
            with self.subTest(label):
                self.assertNotEqual(advisory_problems(advisory), [])

    def test_the_readme_counts_what_the_fixtures_hold(self) -> None:
        """It said "nine CVEs", and one of the nine has only a GHSA id."""
        import json  # noqa: PLC0415

        loaded = {pair.stem: json.loads(pair.read_text(encoding="utf-8"))["advisory"]["id"]
                  for pair in (ROOT / "fixtures" / "pairs").glob("*.json")}
        words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
                 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}
        cves = sum(value.startswith("CVE-") for value in loaded.values())
        ghsa = [stem for stem, value in loaded.items() if value.startswith("GHSA-")]
        applications = {stem.split("-")[0] for stem in loaded}
        readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn(f"{words[len(loaded)]} published advisories in "
                      f"{words[len(applications)]} applications", readme)
        self.assertIn(f"{words[cves]} carry a CVE id and LubeLogger's carries a GHSA id", readme)
        self.assertEqual(ghsa, ["lubelogger-supply-record-idor"])
        self.assertNotIn("nine CVEs", readme)

    def test_the_detection_baseline_runs_the_published_advisory_pairs(self) -> None:
        """CI's gate that runs Veridor against software this project did not
        write (release.yml runs the same pairs again). It shipped wired to
        nothing: `patched_pairs.py` was referenced only by a schema test that
        parses its configs, so the evidence that a real CVE is still caught was
        produced by someone remembering to run it.

        It runs as one job, every pair on every pull request and every push to
        main (BASELINE_JOBS)."""
        workflow = _workflow("veridor.yml")
        jobs = workflow["jobs"]
        self.assertEqual(baseline_job_problems(jobs), [])
        self.assertEqual(baseline_trigger_problems(workflow), [])
        pairs = sorted((ROOT / "fixtures" / "pairs").glob("*.json"))
        self.assertGreaterEqual(len(pairs), 3, "every pair is a published advisory; do not shrink this")
        import json  # noqa: PLC0415

        for pair in pairs:
            with self.subTest(pair=pair.name):
                loaded = json.loads(pair.read_text(encoding="utf-8"))
                self.assertEqual(advisory_problems(loaded["advisory"]), [])
                self.assertTrue(loaded["vulnerable"] and loaded["patched"])
        # Every fixture names a docker runtime and a provisioner the harness
        # has, checked here rather than halfway through a CI run.
        harness = _harness()
        self.assertEqual(len(harness.load_pairs(None)), len(pairs))
        # The owner control probe authenticates by exactly one of `token`
        # (gitea's scheme) or `headers`; both or neither is refused at load.
        import tempfile  # noqa: PLC0415

        base = json.loads(pairs[0].read_text(encoding="utf-8"))
        for label, control, accepted in (
            ("token", {"path": "/", "token": "T"}, True),
            ("headers", {"path": "/", "headers": {"Authorization": "Bearer ${T}"}}, True),
            ("both", {"path": "/", "token": "T", "headers": {"X": "y"}}, False),
            ("neither", {"path": "/"}, False),
        ):
            with self.subTest(control=label), tempfile.TemporaryDirectory() as directory:
                Path(directory, "p.json").write_text(json.dumps({**base, "control": control}), encoding="utf-8")
                harness.PAIRS_DIR = Path(directory)
                if accepted:
                    self.assertEqual(len(harness.load_pairs(None)), 1)
                else:
                    with self.assertRaises(harness.PairError):
                        harness.load_pairs(None)

    def test_control_a_baseline_job_that_runs_less_is_named(self) -> None:
        jobs = _workflow("veridor.yml")["jobs"]
        job = jobs["detection-baseline"]
        name = "detection-baseline"

        def problems(**changes: object) -> list[str]:
            return baseline_job_problems(dict(jobs, **{name: dict(job, **changes)}))

        def with_run(run: str) -> list[dict]:
            return [*job["steps"][:-1], dict(job["steps"][-1], run=run)]

        self.assertEqual(problems(**{"if": "github.event_name == 'push'"}),
                         ["detection-baseline: if is \"github.event_name == 'push'\", expected None"])
        self.assertEqual(len(problems(**{"if": "github.event_name != 'pull_request'"})), 1)
        self.assertEqual(len(problems(**{"if": "${{ always() }}"})), 1)
        # Anything but the pinned command: no pull, one pair, a flag that is
        # gone (it would exit 2, and a job that errors is not a baseline), or
        # any flag added.
        for run in ("python3 scripts/patched_pairs.py",
                    "python3 scripts/patched_pairs.py --pull --pair gitea-private-org-members",
                    "python3 scripts/patched_pairs.py --light --pull",
                    "python3 scripts/patched_pairs.py --pull --json"):
            with self.subTest(run=run):
                self.assertEqual(problems(steps=with_run(run)), [
                    f"{name}: its one patched_pairs.py step must be the last, and run exactly "
                    f"{BASELINE_JOBS[name][0]!r}"])
        self.assertEqual(len(problems(**{"continue-on-error": "true"})), 1)
        skippable = [*job["steps"][:-1], dict(job["steps"][-1], **{"if": "${{ false }}"})]
        self.assertEqual(problems(steps=skippable),
                         ["detection-baseline: a step-level if or a continue-on-error lets it pass without running"])
        self.assertEqual(baseline_job_problems({k: v for k, v in jobs.items() if k != name}),
                         ["detection-baseline: missing"])
        # A need skips the job whenever the need is skipped or fails. With two
        # baseline jobs, the one on every event waiting on the one that skipped
        # pull requests ran on no pull request, and left this module and
        # actionlint passing (measured on a copy of veridor.yml).
        self.assertEqual(problems(needs="tests"), [
            "detection-baseline: needs 'tests', so it is skipped whenever that job is skipped or "
            "fails; a baseline job waits on nothing"])
        # Anything before the pairs other than the checkout and setup-python
        # can narrow them: a step deleting the one status-only pair, or a
        # checkout of an older ref.
        deleting = [*job["steps"][:-1], {"run": "rm fixtures/pairs/gitea-private-org-members.json"},
                    job["steps"][-1]]
        self.assertEqual(len(problems(steps=deleting)), 1)
        self.assertIn("is not a step this job may run there", problems(steps=deleting)[0])
        older = [dict(job["steps"][0], **{"with": {"persist-credentials": "false", "ref": "v0.0.1"}}),
                 *job["steps"][1:]]
        self.assertIn("is not a step this job may run there", problems(steps=older)[0])
        # A second job running the harness -- the heavy job put back, or a
        # "quick" one with --pair -- is a subset the checks above never read.
        heavy = dict(job, **{"if": "github.event_name != 'pull_request'"},
                     steps=with_run("python3 scripts/patched_pairs.py --heavy --pull"))
        self.assertEqual(baseline_job_problems(dict(jobs, **{"detection-baseline-heavy": heavy})), [
            "detection-baseline-heavy: runs scripts/patched_pairs.py; only ['detection-baseline'] may, and it runs "
            "every pair"])
        quick = {"steps": [{"run": "python3 scripts/patched_pairs.py --pull --pair vikunja-task-comment-idor"}]}
        self.assertEqual(len(baseline_job_problems(dict(jobs, quick=quick))), 1)
        # Control: the file as it is.
        self.assertEqual(baseline_job_problems(jobs), [])

    def test_control_a_trigger_that_runs_a_baseline_job_less_is_named(self) -> None:
        workflow = _workflow("veridor.yml")
        on = workflow["on"]

        def problems(**triggers: object) -> list[str]:
            changed = {key: value for key, value in dict(on, **triggers).items() if value != "absent"}
            return baseline_trigger_problems(dict(workflow, on=changed))

        # The two mutations measured to pass this module and actionlint before
        # this check existed: no push trigger, and a push filter over fixtures/.
        self.assertEqual(len(problems(push="absent")), 1)
        self.assertIn("on.push is None, expected {'branches': ['main']}", problems(push="absent")[0])
        ignored = problems(push={"branches": ["main"], "paths-ignore": ["fixtures/**", "scripts/patched_pairs.py"]})
        self.assertEqual(len(ignored), 1)
        self.assertIn("a missing trigger or a filter would leave main without it", ignored[0])
        self.assertEqual(len(problems(push={"branches": ["release"]})), 1)
        self.assertEqual(problems(pull_request="absent"),
                         ["on: no pull_request trigger, so detection-baseline runs on no pull request"])
        self.assertEqual(len(problems(pull_request={"paths": ["src/**"]})), 1)
        self.assertEqual(len(baseline_trigger_problems(dict(workflow, on=["pull_request", "push"]))), 1)
        # Control: the file as it is.
        self.assertEqual(problems(), [])

    def test_ci_and_the_release_run_every_pair_and_the_set_keeps_both_oracles(self) -> None:
        """There is one set of pairs now, and both jobs that run it run all of it.

        This was the light/heavy partition test: CI split the pairs in two by
        download size, pull requests ran the light half, and this test held the
        halves to a partition and the light half to both oracles. The split is
        gone (a fixture carrying "heavy" is refused), so the same intent is now
        held on the whole set: CI's detection-baseline and the release's run
        scripts/patched_pairs.py with no selection flag, and what those exact
        arguments make the harness evaluate is every fixture.

        Why both oracles. Measured on the current seven pairs on 2026-09-27
        (lubelogger and bugsink included), with one-line edits to
        src/veridor/core.py: with the status oracle blind to an undeclared
        200, only gitea-private-org-membership-confirmable failed; with a
        matched marker read as absent, the six marker pairs failed and the
        status-only pair passed. Each run exited 1. So the set must keep a
        status-only pair (expected_evidence "ungraded") and a marker pair
        ("confirmed")."""
        harness = _harness()
        pairs = harness.load_pairs(None)
        names = sorted(pair["name"] for pair in pairs)
        ci, release = _workflow("veridor.yml"), _workflow("release.yml")
        arguments = pairs_run_arguments(ci, release)
        self.assertEqual(arguments, {"veridor.yml detection-baseline": ["--pull"],
                                     "release.yml detection-baseline": ["--pull"]})
        for job, argv in arguments.items():
            with self.subTest(job=job):
                self.assertEqual(evaluated_by(harness, argv), names)
        self.assertEqual(coverage_problems(pairs), [])
        self.assertGreaterEqual(len(names), 7, "every pair is a published advisory; do not shrink this")

        # Controls. A selection flag in either job changes the arguments this
        # compares, and selects less than every pair.
        one = ["--pull", "--pair", names[0]]
        self.assertEqual(evaluated_by(harness, one), [names[0]])
        narrowed = json.loads(json.dumps(ci))
        narrowed["jobs"]["detection-baseline"]["steps"][-1]["run"] = "python3 scripts/patched_pairs.py " + " ".join(one)
        self.assertEqual(pairs_run_arguments(narrowed, release)["veridor.yml detection-baseline"], one)
        narrowed = json.loads(json.dumps(release))
        step = narrowed["jobs"]["detection-baseline"]["steps"][-1]
        step["run"] = step["run"].strip() + " --pair " + names[0]
        self.assertEqual(pairs_run_arguments(ci, narrowed)["release.yml detection-baseline"], one)
        wrapped = json.loads(json.dumps(ci))
        wrapped["jobs"]["detection-baseline"]["steps"][-1]["run"] = "cd x && python3 scripts/patched_pairs.py --pull"
        self.assertIsNone(pairs_run_arguments(wrapped, release)["veridor.yml detection-baseline"])
        # The set without its status-only pair, or without any marker pair.
        status_only = [pair for pair in pairs if pair.get("expected_evidence") == "ungraded"]
        self.assertTrue(status_only)
        without = coverage_problems([pair for pair in pairs if pair not in status_only])
        self.assertEqual(len(without), 1)
        self.assertTrue(without[0].startswith("no status-only pair"), without)
        only = coverage_problems(status_only)
        self.assertEqual(len(only), 1)
        self.assertTrue(only[0].startswith("no marker pair"), only)
        self.assertEqual(len(coverage_problems([])), 2)


def evaluated_by(harness, argv: list[str]) -> list[str]:
    """The pair names harness.main(argv) evaluates, sorted. Everything that
    would reach docker, start a process or pull an image is stubbed; the
    selection and the fixtures are the harness's own."""
    from unittest import mock  # noqa: PLC0415
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415

    evaluated: list[str] = []

    def evaluate(pair: dict) -> dict:
        evaluated.append(pair["name"])
        return {"name": pair["name"], "passed": True, "error": "stubbed: nothing was run"}

    stubs = {"evaluate": evaluate, "build_side": lambda pair, side: "stubbed",
             "veridor_under_test": lambda: ("/stub/veridor", None),
             "docker_on_path": lambda: True, "check_local_tags": lambda pairs: ({"match": 0, "absent": 0}, []),
             "_pull_one": lambda ref: (True, "stubbed")}
    with contextlib.ExitStack() as stack:
        for name, stub in stubs.items():
            stack.enter_context(mock.patch.object(harness, name, stub))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        code = harness.main(list(argv))
    if code != 0:
        raise AssertionError(f"patched_pairs.py {' '.join(argv)} exited {code} with every pair stubbed to pass")
    return sorted(evaluated)


class CiGlueTest(unittest.TestCase):
    """What each CI job needs, provided by pinned, checked means.

    The gitlab-job-e2e job used to be checkout, setup-python and the script:
    run that way, the script stops at once with exit 2, "IMAGE is not set"
    (measured). The tests job ran the Kustomize parity tests without kubectl,
    where they skip."""

    SCRIPT = (ROOT / "scripts" / "e2e_gitlab_job.sh").read_text(encoding="utf-8")
    REQUIREMENTS = ROOT / ".github" / "requirements" / "schema-check.txt"
    FETCH = (ROOT / ".github" / "scripts" / "fetch-schemas.sh").read_text(encoding="utf-8")

    def test_every_job_that_runs_the_slow_tier_requires_and_installs_its_tools(self) -> None:
        checked = 0
        for path in WORKFLOWS:
            for name, job in load_yaml(path.read_text(encoding="utf-8"))["jobs"].items():
                if (job.get("env") or {}).keys() & REQUIRED_TOOLS.keys() or any(
                        "--tier slow" in step.get("run", "") for step in job.get("steps", [])):
                    checked += 1
                    with self.subTest(workflow=path.name, job=name):
                        self.assertEqual(required_tool_problems(job), [])
        # The installed-package job was exempt, so its chart and shellcheck
        # tests skipped when a tool was absent (97 of 202 skipped, measured)
        # and otherwise ran against whatever the runner image shipped.
        self.assertEqual(checked, 3, "expected CI's tests and installed-package jobs and the release test job")

    def test_every_slow_tier_run_is_sharded_and_no_other_is(self) -> None:
        workflows = {path.name: load_yaml(path.read_text(encoding="utf-8")) for path in WORKFLOWS}
        problems, runs = tier_run_problems(workflows)
        self.assertEqual(problems, [])
        # CI tests and installed-package, and the release's test job.
        self.assertEqual(runs, TIER_RUNS)

    def test_control_a_deleted_or_skippable_tier_step_is_named(self) -> None:
        """Each of these left test_workflows, test_ci_configs and
        test_release_files green before (measured)."""
        def run(mutate) -> tuple[list[str], dict[str, int]]:
            workflows = {path.name: load_yaml(path.read_text(encoding="utf-8")) for path in WORKFLOWS}
            mutate(workflows)
            return tier_run_problems(workflows)

        def steps(workflows, source, job):
            return workflows[source]["jobs"][job]["steps"]

        def delete(source, job, text):
            def apply(workflows):
                kept = [s for s in steps(workflows, source, job) if text not in str(s.get("run", ""))]
                self.assertEqual(len(kept), len(steps(workflows, source, job)) - 1, "the mutation did not apply")
                workflows[source]["jobs"][job]["steps"] = kept
            return apply

        for label, source, job in (("CI fast tier", "veridor.yml", "tests"),
                                   ("release fast tier", "release.yml", "test")):
            with self.subTest(deleted=label):
                problems, runs = run(delete(source, job, "--tier fast"))
                self.assertEqual(problems, [])
                self.assertEqual(runs, dict(TIER_RUNS, fast=TIER_RUNS["fast"] - 1))
        for source, job, name in (("veridor.yml", "tests", "Fast tier"), ("veridor.yml", "tests", "Slow tier"),
                                  ("veridor.yml", "installed-package", "Slow tier against the installed package"),
                                  ("veridor.yml", "installed-package", "Fast tier against the installed package")):
            for key, value in (("if", "${{ false }}"), ("continue-on-error", "true")):
                with self.subTest(step=name, key=key):
                    def mutate(workflows, job=job, name=name, key=key, value=value, source=source):
                        (step,) = [s for s in steps(workflows, source, job) if s.get("name") == name]
                        step[key] = value
                    problems, _ = run(mutate)
                    self.assertEqual(problems, [f"{source}: job {job}: step {name!r} has `{key}`, so it can pass "
                                                "without running"])
        with self.subTest(job_level=True):
            problems, _ = run(lambda w: w["veridor.yml"]["jobs"]["tests"].__setitem__("continue-on-error", "true"))
            self.assertEqual(problems, ["veridor.yml: job tests: the job has `continue-on-error`, so it can pass "
                                        "without running"])

    def test_control_a_tier_call_that_does_not_own_its_line_is_named(self) -> None:
        """Every one of the six real tier calls, with something after or before
        it on its line. `|| true` on each left this module, test_ci_configs and
        test_release_files green until 2026-09-27 (measured): _TEST_RUN stops
        its capture at `|` and nothing asked what followed."""
        def calls(workflows):
            for source, workflow in workflows.items():
                for job_name, job in workflow["jobs"].items():
                    for step in job.get("steps", []):
                        if "scripts/run_tests.py" in str(step.get("run", "")):
                            yield source, job_name, step

        fresh = lambda: {path.name: load_yaml(path.read_text(encoding="utf-8")) for path in WORKFLOWS}
        found = list(calls(fresh()))
        self.assertEqual(len(found), sum(TIER_RUNS.values()), "the mutation must reach every tier call")
        self.assertEqual(tier_run_problems(fresh())[0], [])
        for mask in (" || true", "; true", " && echo ran", " | tee tier.log", " & wait"):
            for index in range(len(found)):
                with self.subTest(mask=mask, call=index):
                    workflows = fresh()
                    source, job_name, step = list(calls(workflows))[index]
                    step["run"] = str(step["run"]).rstrip() + mask
                    problems, _ = tier_run_problems(workflows)
                    self.assertTrue(any("is not run_tests.py alone on its line" in problem for problem in problems),
                                    f"{source} {job_name}: {step['run']!r} was accepted")
        workflows = fresh()
        _, _, step = next(calls(workflows))
        step["run"] = "! " + str(step["run"]).lstrip()
        self.assertTrue(any("is not run_tests.py alone" in p for p in tier_run_problems(workflows)[0]),
                        "a leading `!` inverts the exit status and was accepted")

    def test_control_an_unsharded_slow_tier_or_a_sharded_fast_one_is_named(self) -> None:
        workflows = {"ci.yml": {"jobs": {"tests": {"steps": [
            {"run": "python scripts/run_tests.py --tier fast --jobs 4"},
            {"run": "python scripts/run_tests.py --tier slow"},
            {"run": '"$RUNNER_TEMP/venv/bin/python" scripts/run_tests.py --tier slow --jobs 2'},
            {"run": "python scripts/run_tests.py --tier slow --jobs 4"},
            {"run": "python scripts/run_tests.py --jobs 4"}]}}}}
        problems, runs = tier_run_problems(workflows)
        self.assertEqual(runs["slow"], 3)
        self.assertEqual(problems, [
            "ci.yml: job tests: run_tests.py --tier fast --jobs 4: --jobs is for the slow tier only",
            "ci.yml: job tests: run_tests.py --tier slow: the slow tier runs with --jobs 4",
            "ci.yml: job tests: run_tests.py --tier slow --jobs 2: the slow tier runs with --jobs 4",
            "ci.yml: job tests: run_tests.py --jobs 4: --jobs is for the slow tier only"])
        # The workflows as they were, before --jobs: each slow-tier run is named.
        old = {path.name: load_yaml(path.read_text(encoding="utf-8").replace(" --jobs 4", ""))
               for path in WORKFLOWS}
        problems, runs = tier_run_problems(old)
        self.assertEqual((len(problems), runs["slow"]), (3, 3))

    def test_every_job_that_runs_helm_installs_the_checked_binary_first(self) -> None:
        checked = 0
        for path in WORKFLOWS:
            for name, job in load_yaml(path.read_text(encoding="utf-8"))["jobs"].items():
                steps = job.get("steps", [])
                if any(runs_helm(s, job) or "setup-helm" in str(s.get("uses")) for s in steps):
                    checked += 1
                    with self.subTest(workflow=path.name, job=name):
                        self.assertEqual(helm_install_problems(job), [])
        # CI: tests, installed-package, lint, kubernetes-e2e. Release: test, chart.
        self.assertEqual(checked, 6)

    def test_no_job_uses_an_installer_that_runs_an_unchecked_download(self) -> None:
        workflows = {path.name: load_yaml(path.read_text(encoding="utf-8")) for path in WORKFLOWS}
        self.assertEqual(unchecked_installer_problems(workflows), [])

    def test_the_release_sbom_runs_the_checked_syft(self) -> None:
        self.assertEqual(sbom_step_problems(_workflow("release.yml")["jobs"]["build"]), [])

    def test_control_the_sbom_action_as_it_was_is_named(self) -> None:
        old = {"jobs": {"build": {"steps": [
            {"name": "CycloneDX SBOM of the installed wheel",
             "uses": "anchore/sbom-action@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26",
             "with": {"path": "x", "format": "cyclonedx-json", "output-file": "dist/v.cdx.json"}},
            {"run": "cd dist\nsha256sum -- * > SHA256SUMS"}]}}}
        self.assertEqual(unchecked_installer_problems({"release.yml": old}), [
            "release.yml: job build uses anchore/sbom-action; run 'bash .github/scripts/install-syft.sh' instead"])
        self.assertEqual(sbom_step_problems(old["jobs"]["build"]), ["no step runs `syft scan`"])
        job = _workflow("release.yml")["jobs"]["build"]
        job["steps"] = [s for s in job["steps"] if s.get("run", "").strip() != INSTALL_SYFT]
        self.assertEqual(sbom_step_problems(job),
                         ["`syft scan` runs before 'bash .github/scripts/install-syft.sh', or without it"])

    def test_control_an_unchecked_or_late_helm_install_is_named(self) -> None:
        job = {"steps": [{"uses": "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310"},
                         {"run": "helm lint deploy/helm/veridor-gate"}]}
        self.assertEqual(helm_install_problems(job), [
            "uses azure/setup-helm, which runs an unchecked download; "
            "run 'bash .github/scripts/install-helm.sh' instead",
            "step 1 runs helm, and no earlier step runs 'bash .github/scripts/install-helm.sh'"])
        late = {"steps": [{"run": "set -e\nhelm package x"}, {"run": INSTALL_HELM}]}
        self.assertEqual(helm_install_problems(late),
                         ["step 0 runs helm, and no earlier step runs 'bash .github/scripts/install-helm.sh'"])
        for run in ("bash scripts/e2e_kubernetes.sh", "x=1; helm template a b"):
            with self.subTest(run=run):
                self.assertEqual(len(helm_install_problems({"steps": [{"run": run}]})), 1)
        slow = {"env": {"VERIDOR_REQUIRE_HELM": "1"}, "steps": [{"run": "python scripts/run_tests.py --tier slow"}]}
        self.assertEqual(len(helm_install_problems(slow)), 1)
        slow["env"] = {}
        self.assertEqual(helm_install_problems(slow), [])
        self.assertEqual(helm_install_problems({"steps": [{"run": INSTALL_HELM}, {"run": "helm version"}]}), [])
        self.assertEqual(helm_install_problems({"steps": [{"run": "echo helmet; cosign sign x"}]}), [])

    def test_control_a_missing_install_or_requirement_is_named(self) -> None:
        job = _workflow("veridor.yml")["jobs"]["tests"]
        job["steps"] = [s for s in job["steps"] if s.get("run") != _INSTALLS["VERIDOR_REQUIRE_KUBECTL"]]
        self.assertEqual(required_tool_problems(job),
                         ["VERIDOR_REQUIRE_KUBECTL=1 but no step runs 'bash .github/scripts/install-kubectl.sh'"])
        job["env"].pop("VERIDOR_REQUIRE_KUBECTL")
        self.assertTrue(required_tool_problems(job)[0].startswith("runs the slow tier with env"))

    def test_the_gitlab_e2e_job_provides_everything_the_script_requires(self) -> None:
        job = _workflow("veridor.yml")["jobs"]["gitlab-job-e2e"]
        self.assertEqual(e2e_input_problems(job, self.SCRIPT), [])
        runs = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn('echo "E2E_WHEEL=${wheels[0]}" >> "$GITHUB_ENV"', runs)
        self.assertIn('echo "E2E_PYTHON_IMAGE=$base" >> "$GITHUB_ENV"', runs)
        self.assertIn("docker build --tag veridor:gitlab-e2e .", runs)

    def test_control_the_job_as_it_was_provides_nothing(self) -> None:
        old = {"steps": [{"uses": "actions/checkout@x"}, {"uses": "actions/setup-python@x"},
                         {"name": "scripts/e2e_gitlab_job.sh", "run": "bash scripts/e2e_gitlab_job.sh"}]}
        self.assertEqual(e2e_input_problems(old, self.SCRIPT),
                         ["IMAGE is required by the script and never set",
                          "PYTHON_WITH_JSONSCHEMA is required by the script and never set",
                          "SAST_SCHEMA is required by the script and never set"])
        job = _workflow("veridor.yml")["jobs"]["gitlab-job-e2e"]
        for step in job["steps"]:
            if "run" in step:
                step["run"] = step["run"].replace('echo "SAST_SCHEMA=', 'echo "SAST_SCHEMAX=')
        self.assertEqual(e2e_input_problems(job, self.SCRIPT),
                         ["SAST_SCHEMA is required by the script and never set"])

    def test_the_gitlab_e2e_job_and_its_controls_cannot_be_skipped(self) -> None:
        job = _workflow("veridor.yml")["jobs"]["gitlab-job-e2e"]
        self.assertEqual(unskippable_problems("gitlab-job-e2e", job, job["steps"]), [])
        # Control: each left every test green before.
        controls = next(i for i, s in enumerate(job["steps"]) if "E2E_CONTROL=" in s.get("run", ""))
        for index in (controls, len(job["steps"]) - 1):
            for key in ("if", "continue-on-error"):
                with self.subTest(step=job["steps"][index].get("name"), key=key):
                    steps = [dict(s, **{key: "true"}) if i == index else s for i, s in enumerate(job["steps"])]
                    self.assertEqual(len(unskippable_problems("gitlab-job-e2e", job, steps)), 1)

    def test_every_e2e_control_runs_and_must_fail(self) -> None:
        """Every control the script knows, read from its own list, so a new
        one cannot be added without CI running it."""
        known = re.search(r'case "\$E2E_CONTROL" in\n\s*"" \| ([\w| -]+)\)', self.SCRIPT)
        self.assertIsNotNone(known, "the script's list of controls moved")
        controls = {name.strip() for name in known.group(1).split("|")}
        self.assertEqual(controls, {"report-path-typo", "no-term-trap", "proxy-kept"})
        job = _workflow("veridor.yml")["jobs"]["gitlab-job-e2e"]
        step = next(s for s in job["steps"] if "E2E_CONTROL=" in s.get("run", ""))
        self.assertIn(f"for control in {' '.join(sorted(controls, reverse=True))}; do", step["run"])
        self.assertIn('if [[ "$status" != 1 ]]; then', step["run"])
        self.assertLess(job["steps"].index(step), len(job["steps"]) - 1)

    @staticmethod
    def kubernetes_control_problems(job: dict, controls: set[str]) -> list[str]:
        """What stops the kubernetes-e2e job showing each control fails."""
        problems = []
        for control in sorted(controls):
            steps = [s for s in job["steps"]
                     if (s.get("env") or {}).get("E2E_CONTROL") == control]
            if not steps:
                problems.append(f"{control}: no step runs it")
                continue
            step = steps[0]
            if "bash scripts/e2e_kubernetes.sh" not in step.get("run", ""):
                problems.append(f"{control}: the step does not run the script")
            if '[[ "$status" != 1 ]]' not in step.get("run", ""):
                problems.append(f"{control}: exit 1 is not required")
            if "mismatch" not in step.get("run", ""):
                problems.append(f"{control}: the mismatch rows are not required")
            if "continue-on-error" in step:
                problems.append(f"{control}: continue-on-error")
            if job["steps"].index(step) >= len(job["steps"]) - 1:
                problems.append(f"{control}: not before the positive run")
        return problems

    def test_every_kubernetes_e2e_control_runs_and_must_fail(self) -> None:
        """The same rule for scripts/e2e_kubernetes.sh. Its control,
        gate-passes-wrongly, was documented in CONTRIBUTING.md and the
        Kustomize README as ending in exit 1 and ran in no workflow, so CI
        never showed that its 0-mismatch table can fail."""
        script = E2E_KUBERNETES.read_text(encoding="utf-8")
        known = re.search(r'case "\$E2E_CONTROL" in\n\s*"" \| ([\w| -]+)\)', script)
        self.assertIsNotNone(known, "the script's list of controls moved")
        controls = {name.strip() for name in known.group(1).split("|")}
        self.assertEqual(controls, {"gate-passes-wrongly"})
        job = _workflow("veridor.yml")["jobs"]["kubernetes-e2e"]
        self.assertEqual(self.kubernetes_control_problems(job, controls), [])
        # Control: the job as it was, with no control step, is named.
        without = {**job, "steps": [s for s in job["steps"]
                                    if "E2E_CONTROL" not in (s.get("env") or {})]}
        self.assertEqual(self.kubernetes_control_problems(without, controls),
                         ["gate-passes-wrongly: no step runs it"])

    def test_the_schemas_command_runs_with_both_schemas(self) -> None:
        job = _workflow("veridor.yml")["jobs"]["gitlab-job-e2e"]
        runs = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn('"$PYTHON_WITH_JSONSCHEMA" tests/ci_validate.py schemas', runs)
        self.assertIn('--gitlab-schema "$RUNNER_TEMP/schemas/gitlab-ci.json"', runs)
        self.assertIn('--azure-schema "$RUNNER_TEMP/schemas/azure-pipelines.json"', runs)
        self.assertIn("-m pip install --require-hashes --only-binary=:all:", runs)
        self.assertIn("-r .github/requirements/schema-check.txt", runs)

    @staticmethod
    def requirement_problems(text: str) -> list[str]:
        problems, names = [], []
        for block in re.split(r"(?<!\\)\n(?=\S)", "\n".join(
                line for line in text.splitlines() if line.strip() and not line.startswith("#"))):
            head = block.split()[0]
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*)", head)
            hashes = re.findall(r"--hash=sha256:([0-9a-f]+)", block)
            if not match:
                problems.append(f"{head}: not pinned with ==")
                continue
            names.append(match.group(1).lower())
            if not hashes or any(len(h) != 64 for h in hashes):
                problems.append(f"{head}: needs --hash=sha256:<64 hex>")
        if len(names) != len(set(names)):
            problems.append("a package is listed twice")
        return problems

    def test_the_schema_requirements_are_pinned_by_version_and_hash(self) -> None:
        text = self.REQUIREMENTS.read_text(encoding="utf-8")
        self.assertEqual(self.requirement_problems(text), [])
        pinned = set(re.findall(r"^([a-z0-9-]+)==", text, re.M))
        self.assertTrue({"jsonschema", "pyyaml"} <= pinned, pinned)
        # Controls.
        self.assertEqual(self.requirement_problems("jsonschema>=4\n"), ["jsonschema>=4: not pinned with =="])
        self.assertEqual(self.requirement_problems("attrs==26.1.0\n"),
                         ["attrs==26.1.0: needs --hash=sha256:<64 hex>"])
        self.assertEqual(self.requirement_problems("attrs==26.1.0 \\\n    --hash=sha256:abc\n"),
                         ["attrs==26.1.0: needs --hash=sha256:<64 hex>"])

    def test_every_schema_is_fetched_from_a_commit_and_checked(self) -> None:
        calls = re.findall(r"^fetch (\S+) \\\n\s+(\S+) \\\n\s+(\S+)$", self.FETCH, re.M)
        self.assertEqual([name for name, _, _ in calls],
                         ["sast-report-format.json", "gitlab-ci.json", "azure-pipelines.json"])
        for name, url, digest in calls:
            with self.subTest(schema=name):
                self.assertRegex(url, r"^https://[^ ]+/(?:-/raw/)?[0-9a-f]{40}/", "pin the URL to a commit")
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
        # The schema CI validates against is the version the renderer declares.
        from veridor.reports import gitlab_sast  # noqa: PLC0415

        self.assertEqual(gitlab_sast.SCHEMA_VERSION, "15.2.5")
        self.assertIn("security-report-schemas v15.2.5", self.FETCH)
        self.assertIn("security-report-schemas/-/raw/94999aa479bd7607fb28e28701754021fe3a6723/", self.FETCH)
        self.assertIn('if [[ "$actual" != "$expected" ]]; then', self.FETCH)


@slow("runs .github/scripts/install-helm.sh under bash against a stub curl and uname")
class InstallHelmTest(unittest.TestCase):
    """The digest comparison is what makes the script safer than the action it
    replaced, so the refusal is run, not read. Nothing here touches the network:
    curl is a stub that writes bytes which are not helm."""

    SCRIPT = ROOT / ".github" / "scripts" / "install-helm.sh"
    LINUX_DIGEST = "9adafecab4d406853bba163a70e9f104f47dbbf65ce24b7653bae7e36150bcb6"

    def run_script(self, system: str, machine: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        tmp = Path(tempfile.mkdtemp(prefix=f"veridor-{self.SCRIPT.stem}-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        stubs = tmp / "stubs"
        stubs.mkdir()
        (stubs / "uname").write_text(
            f'#!/usr/bin/env bash\ncase "$1" in -s) echo {system};; -m) echo {machine};; esac\n', encoding="utf-8")
        (stubs / "curl").write_text(
            '#!/usr/bin/env bash\n'
            f'echo "$*" >> "{tmp}/curl.log"\n'
            'while (( $# )); do if [[ $1 == -o ]]; then out=$2; shift; fi; shift; done\n'
            'printf "not helm\\n" > "$out"\n', encoding="utf-8")
        for stub in stubs.iterdir():
            stub.chmod(0o755)
        (tmp / "github_path").write_text("", encoding="utf-8")
        env = dict(os.environ, PATH=f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
                   RUNNER_TEMP=str(tmp / "runner"), GITHUB_PATH=str(tmp / "github_path"))
        result = subprocess.run(["bash", str(self.SCRIPT)], env=env, capture_output=True, text=True,
                                timeout=60, check=False)
        return result, tmp

    def test_a_download_that_is_not_the_pinned_tarball_is_refused_and_removed(self) -> None:
        result, tmp = self.run_script("Linux", "x86_64")
        actual = hashlib.sha256(b"not helm\n").hexdigest()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"helm-v4.2.2-linux-amd64.tar.gz sha256 is {actual}, expected {self.LINUX_DIGEST}",
                      result.stderr)
        self.assertIn("https://get.helm.sh/helm-v4.2.2-linux-amd64.tar.gz",
                      (tmp / "curl.log").read_text(encoding="utf-8"))
        self.assertEqual(list((tmp / "runner" / "helm").iterdir()), [], "the download was left behind")
        self.assertEqual((tmp / "github_path").read_text(encoding="utf-8"), "", "PATH was extended")

    def test_a_platform_without_a_pinned_digest_downloads_nothing(self) -> None:
        result, tmp = self.run_script("FreeBSD", "amd64")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("no pinned helm for FreeBSD/amd64", result.stderr)
        self.assertFalse((tmp / "curl.log").exists())


@slow("runs .github/scripts/install-syft.sh under bash against a stub curl and uname")
class InstallSyftTest(unittest.TestCase):
    """install-syft.sh replaces anchore/sbom-action in the release build, so
    its refusal is run too. curl is a stub that writes bytes which are not
    syft; nothing touches the network."""

    SCRIPT = ROOT / ".github" / "scripts" / "install-syft.sh"
    LINUX_DIGEST = "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"
    run_script = InstallHelmTest.run_script

    def test_a_download_that_is_not_the_pinned_tarball_is_refused_and_removed(self) -> None:
        result, tmp = self.run_script("Linux", "x86_64")
        actual = hashlib.sha256(b"not helm\n").hexdigest()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"syft_1.51.1_linux_amd64.tar.gz sha256 is {actual}, expected {self.LINUX_DIGEST}",
                      result.stderr)
        self.assertIn("https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz",
                      (tmp / "curl.log").read_text(encoding="utf-8"))
        self.assertEqual(list((tmp / "runner" / "syft").iterdir()), [], "the download was left behind")
        self.assertEqual((tmp / "github_path").read_text(encoding="utf-8"), "", "PATH was extended")

    def test_a_platform_without_a_pinned_digest_downloads_nothing(self) -> None:
        result, tmp = self.run_script("Linux", "aarch64")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("no pinned syft for Linux/aarch64", result.stderr)
        self.assertFalse((tmp / "curl.log").exists())


def chart_step(workflow: dict) -> dict:
    """The chart job's step that packages, pushes and signs."""
    return next(s for s in workflow["jobs"]["chart"]["steps"] if "helm package" in s.get("run", ""))


@slow("runs release.yml's chart step under bash with the real helm; push and cosign are stubs")
class ChartStepTest(unittest.TestCase):
    """The chart the release signs must deploy the image the release signed.

    It used to package values.yaml as committed, image.digest "", so the signed
    chart rendered ghcr.io/veridor-authz/veridor:X.Y.Z: whatever that tag points at
    when the kubelet pulls, which anyone with packages:write can move."""

    FAKE_CHART_DIGEST = "sha256:" + "c" * 64

    def setUp(self) -> None:
        self.helm = shutil.which("helm")
        if self.helm is None:
            if os.environ.get("VERIDOR_REQUIRE_HELM") == "1":
                self.fail("helm is not on PATH and VERIDOR_REQUIRE_HELM=1 says this must run")
            self.skipTest("helm is not on PATH (set VERIDOR_REQUIRE_HELM=1 to make this a failure)")
        self.workflow = _workflow("release.yml")
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-chart-step-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_step(self, image_digest: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        work, stubs, runner = self.tmp / "work", self.tmp / "stubs", self.tmp / "runner"
        shutil.copytree(ROOT / "deploy" / "helm" / "veridor-gate", work / "deploy" / "helm" / "veridor-gate")
        stubs.mkdir()
        runner.mkdir()
        log = self.tmp / "calls.log"
        (stubs / "helm").write_text(
            "#!/usr/bin/env bash\n"
            f'case "$1" in\n'
            f'  registry) cat > /dev/null; echo "helm $*" >> "{log}";;\n'
            f'  push) echo "helm $*" >> "{log}"; echo "Pushed: x"; echo "Digest: {self.FAKE_CHART_DIGEST}";;\n'
            f'  *) exec "{self.helm}" "$@";;\n'
            "esac\n", encoding="utf-8")
        (stubs / "cosign").write_text(f'#!/usr/bin/env bash\necho "cosign $*" >> "{log}"\n', encoding="utf-8")
        for stub in stubs.iterdir():
            stub.chmod(0o755)
        semver = re.search(r"^version: (\S+)$", (ROOT / "deploy/helm/veridor-gate/Chart.yaml").read_text(
            encoding="utf-8"), re.M).group(1)
        step = chart_step(self.workflow)
        env = dict(os.environ, PATH=f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
                   RUNNER_TEMP=str(runner), GITHUB_OUTPUT=str(self.tmp / "github_output"),
                   SEMVER=semver, IMAGE_DIGEST=image_digest, GH_ACTOR="someone", GH_TOKEN="not-a-token",
                   **self.workflow["env"])
        result = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=work, env=env,
                                capture_output=True, text=True, timeout=120, check=False)
        self.semver = semver
        return result, runner / "chart" / f"veridor-gate-{semver}.tgz"

    def rendered_image(self, package: Path) -> str:
        values = ROOT / "deploy/helm/veridor-gate/ci/argocd-values.yaml"
        out = subprocess.run([self.helm, "template", "gate", str(package), "-f", str(values)],
                             capture_output=True, text=True, timeout=60, check=True).stdout
        return re.findall(r'^\s+image: "([^"]+)"$', out, re.M)[0]

    def calls(self) -> str:
        log = self.tmp / "calls.log"
        return log.read_text(encoding="utf-8") if log.exists() else ""

    def test_the_packaged_chart_pins_the_image_digest_and_the_step_outputs_its_own(self) -> None:
        image_digest = "sha256:" + "a" * 64
        result, package = self.run_step(image_digest)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.rendered_image(package), f"ghcr.io/veridor-authz/veridor:{self.semver}@{image_digest}")
        self.assertIn(f"cosign sign --yes ghcr.io/veridor-authz/charts/veridor-gate@{self.FAKE_CHART_DIGEST}", self.calls())
        self.assertEqual((self.tmp / "github_output").read_text(encoding="utf-8"),
                         f"digest={self.FAKE_CHART_DIGEST}\n")

    def test_without_an_image_digest_nothing_is_pushed_or_signed(self) -> None:
        result, _ = self.run_step("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("the image job gave no digest", result.stdout + result.stderr)
        self.assertEqual(self.calls(), "")


def _environment(rules: list, **fields: object) -> dict:
    """An environment as `gh api repos/O/R/environments/NAME` returns it,
    in the shape read from pypa/pip's PyPI and pypa/build's release
    environments (2026-09-24), with a made-up reviewer."""
    reviewer = {"type": "User", "reviewer": {"login": "maintainer", "id": 1, "type": "User"}}
    built = {"branch_policy": {"id": 1, "node_id": "x", "type": "branch_policy"},
             "wait_timer": {"id": 2, "node_id": "x", "type": "wait_timer", "wait_timer": 5},
             "one reviewer": {"id": 3, "node_id": "x", "type": "required_reviewers",
                              "prevent_self_review": False, "reviewers": [reviewer]},
             "no reviewers": {"id": 4, "node_id": "x", "type": "required_reviewers",
                              "prevent_self_review": False, "reviewers": []}}
    document = {"id": 9, "node_id": "x", "name": "release", "url": "u", "html_url": "h",
                "created_at": "t", "updated_at": "t", "can_admins_bypass": False,
                "protection_rules": [built[rule] for rule in rules],
                "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
    document.update(fields)
    return document


@slow("runs release.yml's environment check steps under bash against a stub gh")
class EnvironmentCheckStepTest(unittest.TestCase):
    """Every release-environment job's first check, run the way GitHub runs
    it, against the answers gh can give.

    The inline step it replaced compared `[[ "$reviewers" == 0 ]]`, so an
    HTTP error body read as protected once its exit status was lost (with an
    added `|| true`, a 404 exited 0 and printed "requires one of
    {"message":"Not Found",...} reviewer(s)"), and it printed "this job
    started after an approval" for pypa/build's release environment, whose
    administrators can bypass it (measured)."""

    NOT_FOUND = ('{"message":"Not Found","documentation_url":"https://docs.github.com/rest/deployments/'
                 'environments#get-an-environment","status":"404"}')

    def setUp(self) -> None:
        # Every job in the environment runs the same step (release_gate_problems
        # holds it to ENVIRONMENT_CHECK), so each distinct script and shell is
        # run once, not once per job.
        self.release = _workflow("release.yml")
        distinct = {}
        for name, job in self.release["jobs"].items():
            if environment_name(job) == RELEASE_ENVIRONMENT:
                step = job["steps"][1]
                distinct.setdefault((step["run"], effective_shell(self.release, job, step)), (name, job, step))
        self.steps = list(distinct.values())

    def run_check(self, job: dict, step: dict, stdout: str, status: int = 0) -> tuple[int, str, str]:
        tmp = Path(tempfile.mkdtemp(prefix="veridor-environment-check-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "bin").mkdir()
        (tmp / "answer").write_text(stdout, encoding="utf-8")
        (tmp / "bin" / "gh").write_text(
            "#!/usr/bin/env bash\n"
            f'echo "gh $*" >> "{tmp}/calls"\n'
            f'cat "{tmp}/answer"\n'
            f'[[ {status} == 0 ]] || echo "gh: Not Found (HTTP 404)" >&2\n'
            f"exit {status}\n", encoding="utf-8")
        (tmp / "bin" / "gh").chmod(0o755)
        (tmp / "step.sh").write_text(step["run"] + "\n", encoding="utf-8")
        env = dict(os.environ, PATH=f"{tmp / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
                   GITHUB_REPOSITORY="owner/repo", GH_TOKEN="not-a-token")
        shell = GITHUB_SHELLS[effective_shell(self.release, job, step)]
        result = subprocess.run([*shell, str(tmp / "step.sh")], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=60, check=False)
        calls = (tmp / "calls").read_text(encoding="utf-8") if (tmp / "calls").exists() else ""
        self.assertEqual(calls, "gh api repos/owner/repo/environments/release\n", "the stub was not asked")
        return result.returncode, result.stdout, result.stderr

    def test_a_reviewer_administrators_cannot_bypass_passes(self) -> None:
        self.assertTrue(self.steps, "no job runs in the release environment")
        for name, job, step in self.steps:
            with self.subTest(job=name):
                status, out, err = self.run_check(job, step, json.dumps(_environment(["branch_policy", "one reviewer"])))
                self.assertEqual(status, 0, err)
                self.assertIn("requires one of 1 reviewer(s), and administrators cannot bypass it", out)
                self.assertIn("they do not show who approved this job", out)
                self.assertNotIn("started after an approval", out)

    def test_every_other_answer_fails_the_job(self) -> None:
        answers = {
            "no rules": (json.dumps(_environment([])), 0, "has no required reviewer"),
            "wait timer only": (json.dumps(_environment(["wait_timer", "branch_policy"])), 0, "has no required reviewer"),
            "empty reviewer list": (json.dumps(_environment(["no reviewers"])), 0, "has no required reviewer"),
            "reviewers not a list": (json.dumps(_environment(["one reviewer"], protection_rules=[
                {"type": "required_reviewers", "reviewers": 1}])), 0, "has no reviewers list"),
            "administrators can bypass": (json.dumps(_environment(["one reviewer"], can_admins_bypass=True)), 0,
                                          "administrators can bypass"),
            "bypass not reported": (json.dumps({k: v for k, v in _environment(["one reviewer"]).items()
                                                if k != "can_admins_bypass"}), 0, "administrators can bypass"),
            "404, status kept": (self.NOT_FOUND, 1, "gh api could not read"),
            "404, status lost": (self.NOT_FOUND, 0, "has no protection_rules list"),
            "not JSON": ("<html>502 Bad Gateway</html>", 0, "did not come back as JSON"),
            "nothing": ("", 0, "did not come back as JSON"),
            "a number": ("1", 0, "has no protection_rules list"),
        }
        for name, job, step in self.steps:
            for label, (stdout, status, message) in answers.items():
                with self.subTest(job=name, answer=label):
                    code, out, err = self.run_check(job, step, stdout, status)
                    self.assertNotEqual(code, 0, out + err)
                    self.assertIn("::error::", out + err)
                    self.assertIn(message, out + err)


COMMIT_CHECK = "bash .github/scripts/check-release-commit.sh"


@slow("runs release.yml's commit check under bash against a stub gh")
class CommitCheckStepTest(unittest.TestCase):
    """A tag on any commit started a release, whether or not it was on main or
    CI had passed on it. GitHub's replies here are stubs of its documented
    shapes: this has not run against GitHub."""

    SHA = "a" * 40

    def run_check(self, compare: str, runs: str, compare_status: int = 0, runs_status: int = 0) -> tuple[int, str]:
        release = _workflow("release.yml")
        job = release["jobs"]["verify"]
        step = next(s for s in job["steps"] if s.get("run") == COMMIT_CHECK)
        tmp = Path(tempfile.mkdtemp(prefix="veridor-commit-check-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "bin").mkdir()
        (tmp / "compare").write_text(compare, encoding="utf-8")
        (tmp / "runs").write_text(runs, encoding="utf-8")
        (tmp / "bin" / "gh").write_text(
            "#!/usr/bin/env bash\n"
            f'echo "gh $*" >> "{tmp}/calls"\n'
            'case "$2" in\n'
            f'  */compare/*) cat "{tmp}/compare"; exit {compare_status} ;;\n'
            f'  */runs*) cat "{tmp}/runs"; exit {runs_status} ;;\n'
            'esac\nexit 9\n', encoding="utf-8")
        (tmp / "bin" / "gh").chmod(0o755)
        (tmp / "step.sh").write_text(step["run"] + "\n", encoding="utf-8")
        env = dict(os.environ, PATH=f"{tmp / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
                   GITHUB_REPOSITORY="owner/repo", GITHUB_SHA=self.SHA, GH_TOKEN="not-a-token")
        shell = GITHUB_SHELLS[effective_shell(release, job, step)]
        result = subprocess.run([*shell, str(tmp / "step.sh")], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=60, check=False)
        self.calls = (tmp / "calls").read_text(encoding="utf-8") if (tmp / "calls").exists() else ""
        return result.returncode, result.stdout + result.stderr

    def run_of(self, **fields: object) -> dict:
        return {"head_sha": self.SHA, "event": "push", "head_branch": "main", "run_number": 7,
                "status": "completed", "conclusion": "success", **fields}

    def runs(self, *runs: dict) -> str:
        return json.dumps({"total_count": len(runs), "workflow_runs": list(runs)})

    def test_a_commit_on_main_with_a_green_ci_run_passes(self) -> None:
        for status in ("identical", "behind"):
            with self.subTest(status=status):
                code, output = self.run_check(json.dumps({"status": status}), self.runs(self.run_of()))
                self.assertEqual(code, 0, output)
                self.assertIn("concluded success", output)
                self.assertIn(f"gh api repos/owner/repo/compare/main...{self.SHA}", self.calls)
                self.assertIn(f"gh api repos/owner/repo/actions/workflows/veridor.yml/runs?head_sha={self.SHA}", self.calls)

    def test_a_commit_not_on_main_fails(self) -> None:
        for status in ("ahead", "diverged", None):
            with self.subTest(status=status):
                code, output = self.run_check(json.dumps({"status": status}), self.runs(self.run_of()))
                self.assertNotEqual(code, 0, output)
                self.assertIn("is not on main", output)

    def test_every_answer_that_does_not_show_a_green_run_fails(self) -> None:
        on_main = json.dumps({"status": "behind"})
        cases = {
            "failed": (self.runs(self.run_of(conclusion="failure")), "conclusion \"failure\""),
            "cancelled": (self.runs(self.run_of(conclusion="cancelled")), "conclusion \"cancelled\""),
            "still running": (self.runs(self.run_of(status="in_progress", conclusion=None)), "status \"in_progress\""),
            "newest failed after an older success": (
                self.runs(self.run_of(), self.run_of(run_number=8, conclusion="failure")), "conclusion \"failure\""),
            "no run": (self.runs(), "has no push run on main"),
            "another commit's run": (self.runs(self.run_of(head_sha="b" * 40)), "has no push run on main"),
            "a pull request's run": (self.runs(self.run_of(event="pull_request")), "has no push run on main"),
            "a branch's run": (self.runs(self.run_of(head_branch="topic")), "has no push run on main"),
            "no list": (json.dumps({"message": "Not Found"}), "has no workflow_runs list"),
            "a number": ("1", "has no workflow_runs list"),
            "not JSON": ("<html>502</html>", "did not come back as JSON"),
            "nothing": ("", "did not come back as JSON"),
        }
        for label, (runs, message) in cases.items():
            with self.subTest(answer=label):
                code, output = self.run_check(on_main, runs)
                self.assertNotEqual(code, 0, output)
                self.assertIn("::error::", output)
                self.assertIn(message, output)

    def test_gh_failing_fails_the_job_with_either_answer_otherwise_good(self) -> None:
        on_main, green = json.dumps({"status": "behind"}), self.runs(self.run_of())
        code, output = self.run_check(on_main, green, compare_status=1)
        self.assertNotEqual(code, 0, output)
        self.assertIn("could not compare", output)
        code, output = self.run_check(on_main, green, runs_status=1)
        self.assertNotEqual(code, 0, output)
        self.assertIn("could not list", output)
        code, output = self.run_check('{"message":"Not Found"}', green)
        self.assertNotEqual(code, 0, output)
        self.assertIn("is not on main", output)


@slow("runs release.yml's publish-image pin and verify steps under bash against a stub docker")
class PublishImageStepTest(unittest.TestCase):
    """The steps around the PyPI publish action, run as GitHub runs them.

    The stub docker keeps an image store in a file: `pull NAME@DIGEST` adds
    the digest's image, `tag A B` points B at A's image, and `image inspect`
    answers from the store, as docker does."""

    PINNED_ID = "sha256:" + "1" * 64

    def setUp(self) -> None:
        self.release = _workflow("release.yml")
        self.job = self.release["jobs"]["pypi"]
        steps = self.job["steps"]
        index = next(i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith(PUBLISH_ACTION + "@"))
        self.pin, self.verify = steps[index - 1], steps[index + 1]
        self.env = self.pin["env"]
        self.named = f"{self.env['ACTION_IMAGE']}:{self.env['ACTION_REF']}"
        self.pinned = f"{self.env['ACTION_IMAGE']}@{self.env['ACTION_DIGEST']}"
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-publish-image-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "work" / ".github" / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / ".github" / "scripts" / "pin-action-image.sh", self.tmp / "work" / ".github" / "scripts")
        (self.tmp / "bin").mkdir()
        (self.tmp / "store").write_text("", encoding="utf-8")
        (self.tmp / "bin" / "docker").write_text(
            "#!/usr/bin/env bash\n"
            f'store="{self.tmp}/store"\n'
            f'echo "docker $*" >> "{self.tmp}/calls"\n'
            'lookup() { awk -v n="$1" \'$1 == n { id = $2 } END { if (id) print id; else exit 1 }\' "$store"; }\n'
            'case "$1" in\n'
            f'  pull) [[ -f "{self.tmp}/pull-fails" ]] && {{ echo "pull failed" >&2; exit 1; }}\n'
            f'        echo "$2 {self.PINNED_ID}" >> "$store";;\n'
            f'  tag) [[ -f "{self.tmp}/tag-ignored" ]] && exit 0\n'
            '       id="$(lookup "$2")" || exit 1; echo "$3 $id" >> "$store";;\n'
            '  image) name="${*: -1}"; id="$(lookup "$name")" || { echo "Error: No such image: $name" >&2; exit 1; }\n'
            '         echo "$id";;\n'
            '  *) exit 3;;\n'
            "esac\n", encoding="utf-8")
        (self.tmp / "bin" / "docker").chmod(0o755)

    def run_step(self, step: dict, **env: str) -> tuple[int, str]:
        (self.tmp / "step.sh").write_text(step["run"] + "\n", encoding="utf-8")
        full = dict(os.environ, PATH=f"{self.tmp / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}")
        full.update(step["env"], **env)
        shell = GITHUB_SHELLS[effective_shell(self.release, self.job, step)]
        result = subprocess.run([*shell, str(self.tmp / "step.sh")], cwd=self.tmp / "work", env=full,
                                capture_output=True, text=True, timeout=60, check=False)
        return result.returncode, result.stdout + result.stderr

    def calls(self) -> list[str]:
        path = self.tmp / "calls"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def generate(self, image: str) -> None:
        """What create-docker-action.py writes (JSON in action.yml)."""
        path = self.tmp / "work" / ".github/.tmp/.generated-actions/run-pypi-publish-in-docker-container/action.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"name": "x", "runs": {"using": "docker", "image": image}}), encoding="utf-8")

    def test_pin_puts_the_digest_under_the_tag_and_verify_accepts_it(self) -> None:
        code, out = self.run_step(self.pin)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.calls()[:2], [f"docker pull {self.pinned}", f"docker tag {self.pinned} {self.named}"])
        self.generate(f"docker://{self.named}")
        code, out = self.run_step(self.verify)
        self.assertEqual(code, 0, out)
        self.assertIn(f"the publish step ran {self.named}, which is {self.pinned}", out)

    def test_every_other_outcome_fails_its_step(self) -> None:
        (self.tmp / "pull-fails").write_text("", encoding="utf-8")
        code, out = self.run_step(self.pin)
        self.assertNotEqual(code, 0, out)
        self.assertNotIn("docker tag", "\n".join(self.calls()))
        (self.tmp / "pull-fails").unlink()
        # A tag that did not take: the name still resolves to another image.
        (self.tmp / "store").write_text(f"{self.named} sha256:{'2' * 64}\n", encoding="utf-8")
        (self.tmp / "tag-ignored").write_text("", encoding="utf-8")
        code, out = self.run_step(self.pin)
        self.assertNotEqual(code, 0, out)
        self.assertIn(f"::error::{self.named} is image 'sha256:{'2' * 64}'", out)
        (self.tmp / "tag-ignored").unlink()
        self.assertEqual(self.run_step(self.pin)[0], 0)
        code, out = self.run_step(self.verify)
        self.assertNotEqual(code, 0, out)
        self.assertIn("is missing, so what the publish step ran cannot be checked", out)
        for image in (f"docker://{self.env['ACTION_IMAGE']}:v1.14.2", "/home/runner/work/_actions/pypa/x/Dockerfile"):
            with self.subTest(generated=image):
                self.generate(image)
                code, out = self.run_step(self.verify)
                self.assertNotEqual(code, 0, out)
                self.assertIn(f"the publish step ran '{image}', not docker://{self.named}", out)
        self.generate(f"docker://{self.named}")
        with (self.tmp / "store").open("a", encoding="utf-8") as store:
            store.write(f"{self.named} sha256:{'3' * 64}\n")  # the name was pulled again
        code, out = self.run_step(self.verify)
        self.assertNotEqual(code, 0, out)
        self.assertIn("the publish step may have run something else", out)
        code, out = self.run_step(self.pin, ACTION_DIGEST="latest")
        self.assertNotEqual(code, 0, out)
        self.assertIn("is not a sha256 digest", out)


@slow("runs release.yml's version-check step under bash, as GitHub would")
class VerifyStepTest(unittest.TestCase):
    """The release's first gate, run with the command GitHub maps its shell to.

    It had no shell, so GitHub ran it as `bash -e`: for tag v0.2.0 on the 0.1.0
    tree the step exited 0 with empty outputs and an ::error on stderr."""

    def run_step(self, tag: str, shell: object) -> tuple[subprocess.CompletedProcess[str], str]:
        release = _workflow("release.yml")
        job = release["jobs"]["verify"]
        step = next(s for s in job["steps"] if s.get("id") == "check")
        tmp = Path(tempfile.mkdtemp(prefix="veridor-verify-step-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "bin").mkdir()
        (tmp / "bin" / "python").symlink_to(sys.executable)  # setup-python's `python`
        (tmp / "step.sh").write_text(step["run"] + "\n", encoding="utf-8")
        output = tmp / "github_output"
        output.write_text("", encoding="utf-8")
        env = dict(os.environ, PATH=f"{tmp / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
                   GITHUB_REF_NAME=tag, GITHUB_OUTPUT=str(output))
        result = subprocess.run([*GITHUB_SHELLS[shell], str(tmp / "step.sh")], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=60, check=False)
        return result, output.read_text(encoding="utf-8")

    def test_a_tag_the_tree_does_not_match_fails_the_step(self) -> None:
        release = _workflow("release.yml")
        job = release["jobs"]["verify"]
        shell = effective_shell(release, job, next(s for s in job["steps"] if s.get("id") == "check"))
        result, outputs = self.run_step("v99.0.0", shell)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("::error title=release check::tag v99.0.0 names 99.0.0", result.stderr)
        self.assertEqual(outputs, "")
        # Controls: the tree's own tag passes and fills the outputs, and the
        # same mismatch under the shell GitHub uses when none is set passes.
        from scripts import release_check  # noqa: PLC0415

        current = release_check.check_versions(ROOT, None, scan=False)
        result, outputs = self.run_step(f"v{current['semver']}", shell)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"version={current['version']}\n", outputs)
        result, outputs = self.run_step("v99.0.0", None)
        self.assertEqual((result.returncode, outputs), (0, ""), "the unset-shell control no longer masks the failure")


@slow("runs release.yml's owner check under bash")
class OwnerStepTest(unittest.TestCase):
    """The step as the workflow writes it, with the workflow's own IMAGE and
    CHART_REPOSITORY. release_check's OwnerTest covers the comparison; this
    is what shows the step reaches it. Everything is read from the tree."""

    def run_step(self, repository: str) -> subprocess.CompletedProcess[str]:
        release = _workflow("release.yml")
        job = release["jobs"]["verify"]
        step = next(s for s in job["steps"] if "release_check.py owner" in s.get("run", ""))
        tmp = Path(tempfile.mkdtemp(prefix="veridor-owner-step-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "bin").mkdir()
        (tmp / "bin" / "python").symlink_to(sys.executable)
        (tmp / "step.sh").write_text(step["run"] + "\n", encoding="utf-8")
        env = dict(os.environ, PATH=f"{tmp / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
                   GITHUB_REPOSITORY=repository, **release["env"])
        return subprocess.run([*GITHUB_SHELLS[effective_shell(release, job, step)], str(tmp / "step.sh")], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=60, check=False)

    def test_the_repository_the_tree_names_passes_and_another_owner_fails(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        repository = re.search(r'^Repository = "https://github\.com/([^"]+)"$', pyproject, re.M).group(1)
        result = self.run_step(repository)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_step("someone-else/veridor")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("::error title=release check::IMAGE", result.stderr)


class ReleaseWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.release = _workflow("release.yml")
        self.jobs = self.release["jobs"]

    def test_only_a_version_tag_triggers_it(self) -> None:
        """workflow_dispatch skipped the tag check on a branch and still published."""
        self.assertEqual(self.release["on"], {"push": {"tags": ["v*.*.*"]}})

    def test_the_release_is_not_posted_until_a_stranger_can_pull_what_it_names(self) -> None:
        """Whether users can pull is a setting on the package, and every other
        check ran after a login. This has to run with no credential, before the
        release says the image exists, and on both references."""
        job = self.jobs["github-release"]
        names = [step.get("name") for step in job["steps"]]
        step = next(s for s in job["steps"] if "anonymous_pull_check.py" in s.get("run", ""))
        self.assertLess(names.index(step["name"]), names.index("Create the release"))
        self.assertIn('"${IMAGE}@${DIGEST}"', step["run"])
        self.assertIn('"${CHART_REPOSITORY#oci://}/veridor-gate@${CHART_DIGEST}"', step["run"])
        self.assertEqual(step["env"], {"DIGEST": "${{ needs.image.outputs.digest }}",
                                       "CHART_DIGEST": "${{ needs.chart.outputs.digest }}"})
        self.assertFalse([s for s in job["steps"] if "login" in str(s.get("uses", "")) or "login" in s.get("run", "")],
                         "a registry login in this job would make the check see what a stranger cannot")

    def test_nothing_publishes_before_the_version_check_and_the_tests(self) -> None:
        def upstream(job: str) -> set[str]:
            needs = self.jobs[job].get("needs") or []
            needs = [needs] if isinstance(needs, str) else needs
            found = set(needs)
            for parent in needs:
                found |= upstream(parent)
            return found

        for job in ("pypi", "image", "chart", "github-release", "provenance"):
            with self.subTest(job=job):
                self.assertTrue({"verify", "test"} <= upstream(job), upstream(job))
        self.assertEqual(self.jobs["test"]["strategy"]["matrix"]["python-version"],
                         ["3.11", "3.12", "3.13"])

    def test_nothing_publishes_until_every_check_passed_and_the_release_environment_approved(self) -> None:
        self.assertEqual(release_gate_problems(self.release), [])
        for failing in RELEASE_CHECKS + PUBLISH_ORDER:
            with self.subTest(failing=failing):
                started = jobs_that_start(self.jobs, failing)
                self.assertEqual(started[-1], failing, started)
                index = PUBLISH_ORDER.index(failing) if failing in PUBLISH_ORDER else -1
                self.assertEqual([j for j in started if j in PUBLISH_ORDER], list(PUBLISH_ORDER[:index + 1]))

    def test_control_the_graph_as_it_was_is_refused(self) -> None:
        """release.yml before this check: image needs [verify, test], chart
        [verify, image], one environment (pypi). Measured then: with build
        failing, image and chart still started."""
        # detection-baseline did not exist then. It is added as it is now,
        # needed by provenance, because without it the gate stops at
        # "detection-baseline: missing" before reading the rest of the graph.
        old = {"jobs": {
            "verify": {}, "test": {"needs": "verify"}, "build": {"needs": ["verify", "test"]},
            "detection-baseline": {"needs": ["verify", "build"]},
            "provenance": {"needs": ["build", "detection-baseline"]},
            "pypi": {"needs": ["verify", "build", "provenance"], "environment": {"name": "pypi"}},
            "image": {"needs": ["verify", "test"]}, "chart": {"needs": ["verify", "image"]},
            "github-release": {"needs": ["verify", "build", "provenance", "pypi", "image", "chart"]}}}
        self.assertEqual(jobs_that_start(old["jobs"], "build"), ["verify", "test", "build", "image", "chart"])
        self.assertEqual(release_gate_problems(old), [
            "provenance: publishes in environment None, not 'release', so GitHub does not hold it for the reviewer",
            "pypi: publishes in environment 'pypi', not 'release', so GitHub does not hold it for the reviewer",
            "image: publishes in environment None, not 'release', so GitHub does not hold it for the reviewer",
            "image: publishes without waiting for ['build', 'detection-baseline']",
            "chart: publishes in environment None, not 'release', so GitHub does not hold it for the reviewer",
            "chart: publishes without waiting for ['build', 'detection-baseline']",
            "github-release: publishes in environment None, not 'release', so GitHub does not hold it for the "
            "reviewer",
            "image: starts whether or not pypi succeeded",
        ])
        fixed = {"jobs": dict(self.jobs)}
        fixed["jobs"]["chart"] = dict(self.jobs["chart"], **{"if": "${{ always() }}"})
        self.assertEqual(release_gate_problems(fixed), ["chart: a job-level if: can start it after a failed need"])
        fixed["jobs"] = dict(self.jobs, extra={"needs": ["verify"]})
        self.assertEqual(release_gate_problems(fixed),
                         ["extra: not a known check or publish job; classify it in this test"])

    def test_control_the_approval_job_as_it_was_is_refused(self) -> None:
        """The publishing jobs as they were before this: the PyPI job ran in
        `pypi`, left without a reviewer, and the rest in no environment. Only
        an `approval` job (left out here) ran in `release`, so the approval was
        this file's rule, not GitHub's."""
        was = {"jobs": {name: {k: v for k, v in job.items() if k != "environment"}
                        for name, job in self.jobs.items()}}
        was["jobs"]["pypi"]["environment"] = {"name": "pypi", "url": "https://pypi.org/p/veridor"}
        self.assertEqual(release_gate_problems(was), [
            f"{name}: publishes in environment {'pypi' if name == 'pypi' else None!r}, not 'release', "
            "so GitHub does not hold it for the reviewer" for name in PUBLISH_ORDER])
        was["jobs"]["verify"]["environment"] = {"name": "release"}
        self.assertIn("verify: steps 0 and 1 must be actions/checkout and "
                      f"{ENVIRONMENT_CHECK!r}", release_gate_problems(was))

    def test_every_publishing_job_waits_in_the_release_environment(self) -> None:
        """GitHub creates a missing environment with no protection rules and
        lets administrators bypass the rules by default; then nothing waits.
        EnvironmentCheckStepTest runs the check; this holds where it runs."""
        environments = {name: environment_name(job) for name, job in self.jobs.items() if job.get("environment")}
        self.assertEqual(environments, dict.fromkeys(PUBLISH_ORDER, RELEASE_ENVIRONMENT))
        for name in PUBLISH_ORDER:
            with self.subTest(job=name):
                self.assertEqual(environment_check_problems(name, self.jobs[name]), [])

    def test_control_a_skippable_or_missing_environment_check_is_refused(self) -> None:
        """Each of these left the old module green (measured with mutants of
        release.yml): continue-on-error on the step, on the approval job and
        on the test job. The rest are the ways to skip or starve the check."""
        def problems(job: str, **changes: object) -> list[str]:
            jobs = dict(self.jobs)
            jobs[job] = dict(self.jobs[job], **changes)
            return release_gate_problems({"jobs": jobs})

        checkout, check, *rest = self.jobs["pypi"]["steps"]
        self.assertEqual(problems("test", **{"continue-on-error": "true"}),
                         ["test: continue-on-error; a release job must fail when it fails"])
        self.assertEqual(problems("pypi", **{"continue-on-error": "true"}),
                         ["pypi: continue-on-error; a release job must fail when it fails"])
        self.assertEqual(problems("pypi", steps=[checkout, dict(check, **{"continue-on-error": "true"}), *rest]),
                         ["pypi[1]: continue-on-error; a release step must fail its job"])
        self.assertEqual(problems("pypi", steps=[checkout, check, *rest[:-1], dict(rest[-1], **{
            "continue-on-error": "true"})]), [f"pypi[{len(rest) + 1}]: continue-on-error; a release step must fail its job"])
        self.assertEqual(problems("pypi", steps=[checkout, dict(check, **{"if": "${{ false }}"}), *rest]),
                         ["pypi[1]: a step-level if: can skip the environment check"])
        self.assertEqual(problems("pypi", steps=[checkout, dict(check, env={}), *rest]),
                         ["pypi[1]: the environment check needs env GH_TOKEN: ${{ github.token }}"])
        self.assertEqual(problems("pypi", permissions={"contents": "read", "id-token": "write"}),
                         ["pypi: needs permissions actions: read to read the environment's settings"])
        missing = [f"pypi: steps 0 and 1 must be actions/checkout and {ENVIRONMENT_CHECK!r}"]
        self.assertEqual(problems("pypi", steps=[checkout, *rest]), missing)
        self.assertEqual(problems("pypi", steps=[check, *rest]), missing)
        self.assertEqual(problems("pypi", steps=[checkout, rest[0], check, *rest[1:]]), missing)

    def test_control_a_step_level_if_anywhere_in_the_release_is_refused(self) -> None:
        """A skipped step leaves its job green. The dispatch-only form is the
        one to hold: release.yml runs only on a tag push, so it is always false
        there, and actionlint flags only the literal `${{ false }}`."""
        dispatch_only = "github.event_name == 'workflow_dispatch'"

        def problems(job: str, index: int, condition: str = dispatch_only) -> list[str]:
            steps = list(self.jobs[job]["steps"])
            steps[index] = dict(steps[index], **{"if": condition})
            return release_gate_problems({"jobs": dict(self.jobs, **{job: dict(self.jobs[job], steps=steps)})})

        baseline = self.jobs["detection-baseline"]["steps"]
        runner = next(i for i, step in enumerate(baseline) if "patched_pairs.py" in str(step.get("run", "")))
        install = next(i for i, step in enumerate(baseline) if "pip install" in str(step.get("run", "")))
        self.assertEqual(problems("detection-baseline", runner), [
            f"detection-baseline[{runner}]: a step-level if: can skip the step and leave the job green"])
        self.assertEqual(problems("detection-baseline", runner, "${{ false }}"), [
            f"detection-baseline[{runner}]: a step-level if: can skip the step and leave the job green"])
        self.assertEqual(len(problems("detection-baseline", install)), 1)
        for job in ("verify", "test", "build"):
            for index in range(len(self.jobs[job]["steps"])):
                with self.subTest(job=job, step=index):
                    self.assertEqual(problems(job, index), [
                        f"{job}[{index}]: a step-level if: can skip the step and leave the job green"])
        last = len(self.jobs["pypi"]["steps"]) - 1
        self.assertEqual(problems("pypi", last), [f"pypi[{last}]: a step-level if: can skip the step and leave the "
                                                  "job green"])
        # The environment check keeps its own message, once.
        self.assertEqual(problems("pypi", 1), ["pypi[1]: a step-level if: can skip the environment check"])
        # Control: release.yml as it is has no step-level if anywhere.
        self.assertEqual([(name, index) for name, job in self.jobs.items()
                          for index, step in enumerate(job.get("steps", [])) if "if" in step], [])
        self.assertEqual(release_gate_problems(self.release), [])

    def test_the_chart_and_the_notes_carry_the_digests(self) -> None:
        chart = self.jobs["chart"]
        step = chart_step(self.release)
        self.assertEqual(step.get("id"), "chart")
        self.assertEqual(step["env"]["IMAGE_DIGEST"], "${{ needs.image.outputs.digest }}")
        self.assertEqual(chart["outputs"], {"digest": "${{ steps.chart.outputs.digest }}"})
        run = step["run"]
        self.assertLess(run.index('digest: "{digest}"'), run.index("helm package"))
        self.assertLess(run.index("helm template"), run.index("helm push"))
        notes = next(s for s in self.jobs["github-release"]["steps"] if "gh release create" in s.get("run", ""))
        self.assertEqual(notes["env"]["CHART_DIGEST"], "${{ needs.chart.outputs.digest }}")
        self.assertIn("veridor-gate@${CHART_DIGEST}", notes["run"])
        self.assertIn('[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ && "$CHART_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]',
                      notes["run"])

    def test_verify_checks_the_owner_and_the_commit_with_no_write_permission(self) -> None:
        verify = self.jobs["verify"]
        self.assertEqual(verify["permissions"], {"contents": "read", "actions": "read"})
        runs = [step.get("run") for step in verify["steps"]]
        self.assertIn(COMMIT_CHECK, runs)
        self.assertIn('python scripts/release_check.py owner --repository "$GITHUB_REPOSITORY" '
                      '--image "$IMAGE" --chart-repository "$CHART_REPOSITORY"', runs)
        step = next(step for step in verify["steps"] if step.get("run") == COMMIT_CHECK)
        self.assertEqual(step["env"], {"GH_TOKEN": "${{ github.token }}"})
        # Everything publishing needs verify, so these stop the run before PyPI.
        self.assertIn("verify", self.jobs["pypi"]["needs"])

    def test_the_version_check_and_notes_run_the_release_script(self) -> None:
        steps = self.jobs["verify"]["steps"]
        check = next(step for step in steps if step.get("id") == "check")
        self.assertEqual(check["run"],
                         'python scripts/release_check.py versions --tag "$GITHUB_REF_NAME" | tee -a "$GITHUB_OUTPUT"')
        # tee's status would be the step's without pipefail; VerifyStepTest runs it.
        self.assertEqual(effective_shell(self.release, self.jobs["verify"], check), "bash")
        self.assertIn('python scripts/release_check.py notes "$GITHUB_REF_NAME"', [step.get("run") for step in steps])

    def test_no_major_tag_moves(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertNotIn("git tag", text)
        self.assertNotIn("git push", text)
        self.assertIn("NO moving major tag", text)

    def test_pypi_gets_only_the_wheel_and_sdist(self) -> None:
        pypi = self.jobs["pypi"]
        self.assertEqual(pypi["environment"], {"name": RELEASE_ENVIRONMENT, "url": "https://pypi.org/p/veridor"})
        self.assertEqual(pypi["permissions"], {"contents": "read", "actions": "read", "id-token": "write"})
        publish = next(step for step in pypi["steps"] if str(step.get("uses", "")).startswith(PUBLISH_ACTION + "@"))
        # Exactly this, so no skip-existing: a re-run re-uploads identical
        # bytes, which PyPI accepts, and skip-existing would hide a same-named
        # file with different bytes (release.yml says why).
        self.assertEqual(publish["with"], {"packages-dir": "pypi/"})

    def test_the_wheel_runs_every_pair_before_pypi_publishes(self) -> None:
        self.assertEqual(release_baseline_problems(self.release), [])
        job = self.jobs["detection-baseline"]
        self.assertNotIn("environment", job, "a check, not a publish: it must not wait for the reviewer")
        self.assertEqual(job["timeout-minutes"], "30")
        # It gates the attestation as well as the upload.
        self.assertIn("detection-baseline", _needs(self.jobs["provenance"]))

    def test_control_a_release_baseline_that_tests_less_is_named(self) -> None:
        jobs = self.jobs
        job = jobs["detection-baseline"]
        *setup, install, run = job["steps"]

        def problems(steps: list | None = None, **changes: object) -> list[str]:
            changed = dict(jobs, **{"detection-baseline": dict(job, steps=steps or job["steps"])})
            for name, value in changes.items():
                changed[name.replace("_", "-")] = dict(jobs[name.replace("_", "-")], **value)
            return release_baseline_problems({"jobs": changed})

        def running(command: str) -> list[dict]:
            return [*setup, install, dict(run, run=command)]

        python = '"$RUNNER_TEMP/baseline-venv/bin/python"'
        as_it_was = {"jobs": {name: job for name, job in jobs.items() if name != "detection-baseline"}}
        as_it_was["jobs"]["pypi"] = dict(jobs["pypi"], needs=["verify", "build", "provenance"])
        self.assertEqual(release_baseline_problems(as_it_was),
                         ["expected one release step that runs scripts/patched_pairs.py, found 0"])
        for label, command in {
            "one pair": f"VERIDOR_TEST_AGAINST=installed {python} scripts/patched_pairs.py --pull --pair x",
            "one pair, flag first": f"VERIDOR_TEST_AGAINST=installed {python} scripts/patched_pairs.py --pair x --pull",
        }.items():
            with self.subTest(label):
                self.assertEqual(len(problems(running(command))), 1)
                self.assertIn("the release runs every pair", problems(running(command))[0])
        self.assertIn("so the pairs test the checkout, not the wheel",
                      problems(running(f"VERIDOR_TEST_AGAINST=source {python} scripts/patched_pairs.py --pull"))[0])
        for label, command in {"no switch": f"{python} scripts/patched_pairs.py --pull",
                               "unquoted": "VERIDOR_TEST_AGAINST=installed python3 scripts/patched_pairs.py --pull"
                               }.items():
            with self.subTest(label):
                self.assertIn("is not VERIDOR_TEST_AGAINST=installed", problems(running(command))[0])
        self.assertIn("is not the one interpreter an earlier step installed the dist wheel into",
                      problems(running('VERIDOR_TEST_AGAINST=installed "python3" scripts/patched_pairs.py --pull'))[0])
        from_index = dict(install, run=install["run"].replace('--no-index --no-deps "dist/veridor-${VERSION}'
                                                              '-py3-none-any.whl"', "veridor"))
        self.assertNotEqual(from_index["run"], install["run"])
        self.assertIn("is not the one interpreter an earlier step installed the dist wheel into",
                      problems([*setup, from_index, run])[0])
        no_venv = dict(install, run=install["run"].replace("python -m venv", "virtualenv"))
        self.assertIn("is not a virtual environment this job created", problems([*setup, no_venv, run])[0])
        other_download = [dict(step, uses="actions/download-artifact@" + "0" * 40)
                          if str(step.get("uses", "")).startswith("actions/download-artifact@") else step
                          for step in setup]
        self.assertIn("with the same pinned action", problems([*other_download, install, run])[0])
        # A step before the pairs that changes what they read: deleting a
        # fixture passed this module until 2026-09-26, and so would an
        # artifact unpacked over fixtures/ or an install step that also
        # removes one.
        for label, steps in {
            "a step deleting a fixture": [*setup, install, {"run": "rm fixtures/pairs/gitea-private-org-members.json"},
                                          run],
            "an artifact over fixtures/": [*[dict(step, **{"with": {"name": "dist", "path": "fixtures/pairs/"}})
                                            if str(step.get("uses", "")).startswith("actions/download-artifact@")
                                            else step for step in setup], install, run],
            "an install that also deletes": [*setup, dict(install, run=install["run"] + "rm -rf fixtures/pairs/j*\n"),
                                             run],
        }.items():
            with self.subTest(label):
                self.assertIn("is not a step this job may run there", problems(steps)[-1])
        self.assertEqual(problems(pypi={"needs": ["verify", "build", "provenance"]}),
                         ["pypi: must need detection-baseline directly, not through another job that could stop "
                          "needing it"])
        self.assertEqual(len(problems(detection_baseline={"needs": ["build"]})), 1)
        # The gate reads the job as a check that every publish waits for.
        without = {"jobs": dict(as_it_was["jobs"], provenance=dict(jobs["provenance"], needs=["build"]))}
        self.assertEqual(release_gate_problems(without), ["detection-baseline: missing"])
        early = {"jobs": dict(jobs, provenance=dict(jobs["provenance"], needs=["build"]))}
        self.assertEqual(release_gate_problems(early), [
            "provenance: publishes without waiting for ['detection-baseline']"])
        self.assertEqual(problems(), [])

    def test_the_image_is_multi_arch_attested_and_signed_by_digest(self) -> None:
        steps = self.jobs["image"]["steps"]
        push = next(step for step in steps if step.get("id") == "push")
        self.assertEqual(push["with"]["platforms"], "linux/amd64,linux/arm64")
        self.assertEqual(push["with"]["provenance"], "mode=max")
        # The scanner image is pinned; `true` let BuildKit pick stable-1 by tag.
        self.assertRegex(push["with"]["sbom"], r"^generator=docker\.io/docker/buildkit-syft-scanner:[\w.-]+@sha256:[0-9a-f]{64}$")
        meta = next(step for step in steps if step.get("id") == "meta")
        self.assertIn("latest=false", meta["with"]["flavor"])
        self.assertIn("type=raw,value=latest,enable=${{ needs.verify.outputs.prerelease == 'false' }}",
                      meta["with"]["tags"])
        self.assertIn('cosign sign --yes "${IMAGE}@${DIGEST}"', steps[-1]["run"])
        self.assertEqual(self.release["env"]["IMAGE"], "ghcr.io/veridor-authz/veridor")


def release_image_check_problems(job: dict) -> list[str]:
    """The release pushed and signed a linux/amd64+linux/arm64 image
    that nothing in the release started; the arm64 variant ran in no
    workflow. Before the push, every platform the push builds must be built
    into the runner's store with the push's build-args and checked; after the
    push, the pushed digest must be checked on every platform before it is
    signed."""
    steps = job.get("steps", [])
    push = next((i for i, step in enumerate(steps) if step.get("id") == "push"), None)
    sign = next((i for i, step in enumerate(steps) if "cosign sign" in str(step.get("run", ""))), None)
    if push is None or sign is None:
        return ["the image job has no push step (id: push) or no `cosign sign` step"]
    problems = []
    given = steps[push].get("with") or {}
    for platform in str(given.get("platforms", "")).split(","):
        loaded = [(i, (step.get("with") or {})) for i, step in enumerate(steps[:push])
                  if str(step.get("uses", "")).startswith("docker/build-push-action@")
                  and (step.get("with") or {}).get("platforms") == platform
                  and (step.get("with") or {}).get("load") == "true"]
        if len(loaded) != 1:
            problems.append(f"{platform}: not built into the runner's image store before the push")
            continue
        index, built = loaded[0]
        if built.get("build-args") != given.get("build-args") or built.get("push") != "false":
            problems.append(f"{platform}: built with other build-args than the push, or pushed")
        check = f"{BYTECODE_CHECK} --platform {platform} {built.get('tags')}"
        if not any(re.search(rf"^{re.escape(check)}$", str(step.get("run", "")), re.M)
                   for step in steps[index + 1:push]):
            problems.append(f"{platform}: {check!r} does not run between its build and the push")
        after = f'{BYTECODE_CHECK} --platform {platform} "${{IMAGE}}@${{DIGEST}}"'
        if not any(re.search(rf"^{re.escape(after)}$", str(step.get("run", "")), re.M)
                   and (step.get("env") or {}).get("DIGEST") == "${{ steps.push.outputs.digest }}"
                   for step in steps[push + 1:sign]):
            problems.append(f"{platform}: the pushed digest is not checked between the push and the signature")
    return problems


class ReleaseImageCheckTest(unittest.TestCase):
    JOB = _workflow("release.yml")["jobs"]["image"]

    def test_every_platform_is_started_before_the_push_and_again_before_the_signature(self) -> None:
        self.assertEqual(release_image_check_problems(self.JOB), [])

    def test_control_each_gap_is_named(self) -> None:
        steps = self.JOB["steps"]

        def without(predicate) -> dict:
            kept = [step for step in steps if not predicate(step)]
            self.assertLess(len(kept), len(steps), "the mutation did not apply")
            return dict(self.JOB, steps=kept)

        def edited(predicate, change) -> dict:
            return dict(self.JOB, steps=[change(dict(step)) if predicate(step) else step for step in steps])

        arm64_build = lambda step: (step.get("with") or {}).get("tags") == "veridor:release-arm64"  # noqa: E731
        self.assertEqual(release_image_check_problems(without(arm64_build)),
                         ["linux/arm64: not built into the runner's image store before the push"])
        pre = lambda step: "veridor:release-arm64" in str(step.get("run", ""))  # noqa: E731
        self.assertEqual(release_image_check_problems(edited(pre, lambda step: dict(
            step, run=step["run"].replace("--platform linux/arm64 veridor:release-arm64\n", "\n")))), [
            f"linux/arm64: '{BYTECODE_CHECK} --platform linux/arm64 veridor:release-arm64' does not run between "
            "its build and the push"])
        other_args = edited(arm64_build, lambda step: dict(step, **{"with": dict(step["with"], **{
            "build-args": "VERSION=0.0.0\n"})}))
        self.assertEqual(release_image_check_problems(other_args),
                         ["linux/arm64: built with other build-args than the push, or pushed"])
        post = lambda step: f'{BYTECODE_CHECK} --platform' in str(step.get("run", "")) and \
            '"${IMAGE}@${DIGEST}"' in str(step.get("run", ""))  # noqa: E731
        self.assertEqual(release_image_check_problems(without(post)), [
            "linux/amd64: the pushed digest is not checked between the push and the signature",
            "linux/arm64: the pushed digest is not checked between the push and the signature"])
        # After the signature is too late: the digest is already signed.
        (check,) = [step for step in steps if post(step)]
        late = dict(self.JOB, steps=[step for step in steps if not post(step)] + [check])
        self.assertEqual(len(release_image_check_problems(late)), 2)


#: Where a `gh attestation verify` command is shown to a reader.
ATTESTATION_DOCUMENTS = ("SECURITY.md", ".github/workflows/release.yml", "CONTRIBUTING.md", "README.md",
                         "ci/README.md", "ci/Jenkinsfile", "ci/azure-pipelines.yml", "ci/buildspec.yml")

#: The signer a release file's attestation must name: release.yml at a v* tag,
#: written for a reader (vX.Y.Z) or filled in by the workflow (${GITHUB_REF}).
_RELEASE_SIGNER = re.compile(
    r"^https://github\.com/(?:Veridor-authz/veridor|\$\{GITHUB_REPOSITORY\})/\.github/workflows/release\.yml"
    r"@(?:refs/tags/vX\.Y\.Z|\$\{GITHUB_REF\})$")


def attestation_commands(text: str) -> list[str]:
    """Every `gh attestation verify ARGS` in a file, continuation lines joined,
    cut at the end of its code span, line or shell command. A bare mention
    with no arguments ("the `gh attestation verify` command in SECURITY.md")
    is a reference, not a command."""
    joined = re.sub(r"\\\n\s*", " ", text)
    return [match.group(0).rstrip("\\").rstrip()
            for match in re.finditer(r"gh attestation verify [^`\n;&|]+", joined)]


def attestation_problems(command: str) -> list[str]:
    """What a command fails to pin. `--repo` alone accepts an attestation made
    by ANY workflow in the repository at ANY ref (measured with gh 2.95.0 on a
    real attestation: a branch workflow's passed). `--signer-workflow` is a
    prefix match and accepts any ref, so it counts only with `--source-ref`."""
    words = command.replace('"', " ").replace("'", " ").replace("\\`", " ").split()

    def value(flag: str) -> str | None:
        return words[words.index(flag) + 1] if flag in words and words.index(flag) + 1 < len(words) else None

    identity = value("--cert-identity")
    if identity is not None:
        return [] if _RELEASE_SIGNER.match(identity) else [f"--cert-identity {identity} is not release.yml at a v* tag"]
    workflow, ref = value("--signer-workflow"), value("--source-ref")
    if workflow is not None and ref is not None:
        if workflow.rstrip("/").endswith("/.github/workflows/release.yml") and re.match(
                r"^(?:refs/tags/vX\.Y\.Z|\$\{GITHUB_REF\})$", ref):
            return []
        return [f"--signer-workflow {workflow} --source-ref {ref} is not release.yml at a v* tag"]
    return [f"pins neither the signer workflow nor the tag: {command.strip()}"]


ATTEST_ACTION = "actions/attest-build-provenance"
#: The files the provenance job attests, by the word the release notes use for
#: each. Everything else `gh release create ... dist/*` attaches, the SBOM and
#: SHA256SUMS, has no provenance, so `gh attestation verify` refuses it.
ATTESTED_SUBJECTS = {"dist/*.whl": "wheel", "dist/*.tar.gz": "sdist", "dist/*.pyz": "zipapp"}
NO_PROVENANCE_SENTENCE = "The SBOM and SHA256SUMS carry no provenance."
CHECKSUM_COMMAND = "sha256sum --check --ignore-missing SHA256SUMS"


NOTES_FILE = '"$RUNNER_TEMP/notes.md"'
_NOTES_GROUP_END = re.compile(r"\}\s*>>\s*" + re.escape(NOTES_FILE))
_ECHO = re.compile(r"""echo(?:\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)'))?\s*""")


def _double_quoted(body: str) -> str | None:
    """What bash prints for "body", leaving parameters unexpanded, or None
    when it runs a command substitution."""
    out, i = [], 0
    while i < len(body):
        char = body[i]
        if char == "\\" and i + 1 < len(body) and body[i + 1] in '$`"\\':
            out.append(body[i + 1])
            i += 2
            continue
        if char == "`" or body.startswith("$(", i):
            return None
        out.append(char)
        i += 1
    return "".join(out)


def release_notes_text(run: str) -> tuple[str, list[str]]:
    """The text the run block's `{ ... } >> "$RUNNER_TEMP/notes.md"` groups
    write, and the lines in them that are not a plain echo. Nothing else in
    the block reaches the notes: a command it runs, or a line it prints to
    the step's log, is not something a reader of the release sees."""
    lines = [line.strip() for line in run.splitlines()]
    text, unreadable, found = [], [], False
    i = 0
    while i < len(lines):
        if lines[i] != "{":
            i += 1
            continue
        end = next((j for j in range(i + 1, len(lines)) if lines[j].startswith("}")), len(lines))
        if end < len(lines) and _NOTES_GROUP_END.fullmatch(lines[end]):
            found = True
            for line in lines[i + 1:end]:
                if not line or line.startswith("#"):
                    continue
                match = _ECHO.fullmatch(line)
                printed = None
                if match and match.group(2) is not None:
                    printed = match.group(2)
                elif match:
                    printed = _double_quoted(match.group(1) or "")
                if printed is None:
                    unreadable.append(f"the notes group runs `{line}`, which the guard cannot read; "
                                      "write the notes with plain echo lines")
                else:
                    text.append(printed)
        i = end + 1
    if not found:
        unreadable.append(f"no `{{ ... }} >> {NOTES_FILE}` group writes the notes")
    return "\n".join(text), unreadable


_GH_CREATE = re.compile(r"gh\s+release\s+create\b")
#: A line that names the notes file, or the directory it lives in.
_NAMES_NOTES = re.compile(r"notes\.md|RUNNER_TEMP")
_ARRAY_SET = re.compile(r"([A-Za-z_]\w*)=\(([^;&|<>`()]*)\)")
_ASSIGNMENT = re.compile(r"(?:(?:export|declare|local|readonly)\s+(?:-\w+\s+)*)?[A-Za-z_]\w*\+?=")
#: gh release create's notes options. --notes-from-tag and --generate-notes
#: take no value; gh prepends --notes or --notes-file to generated notes, so
#: --generate-notes beside the notes file is a second body.
_NOTES_LONG = ("--notes", "--notes-file", "--notes-from-tag", "--generate-notes")
_NOTES_FLAGS = ("--notes-from-tag", "--generate-notes")
#: gh release create's short options that take a value; -n is --notes and -F
#: is --notes-file. A cluster (`-dF X`) ends at the first of them.
_GH_SHORT_VALUE = {"t": "--title", "n": "--notes", "F": "--notes-file", "R": "--repo"}
#: gh release create's long options that take a value, so the word after one
#: is that value rather than an option of its own.
_GH_LONG_VALUE = ("--title", "--target", "--discussion-category", "--repo", "--notes",
                  "--notes-file", "--notes-start-tag")
#: A path under $RUNNER_TEMP as a line spells it, up to a quote or an operator.
_TEMP_PATH = re.compile(r"\$(?:\{RUNNER_TEMP\}|RUNNER_TEMP\b)(?:/[^\s\"'`;|&<>()]*)?")


def _notes_options(tokens: list[str]) -> list[tuple[str, str | None]]:
    """Each notes option in ``tokens`` as (long name, value), read the way
    gh's flag parser reads them: `--notes=x`, `--notes x`, `-F x`, `-Fx`,
    `-F=x` and a short cluster ending in F or n."""
    found, i = [], 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("--"):
            name, equals, value = token.partition("=")
            if name in _NOTES_FLAGS:
                found.append((name, None))
            elif name in _NOTES_LONG:
                if not equals:
                    i += 1
                    value = tokens[i] if i < len(tokens) else ""
                found.append((name, value))
        elif token.startswith("-") and len(token) > 1:
            for j, letter in enumerate(token[1:], start=1):
                if letter not in _GH_SHORT_VALUE:
                    continue
                value = token[j + 1:]
                value = value[1:] if value.startswith("=") else value
                if not value:
                    i += 1
                    value = tokens[i] if i < len(tokens) else ""
                if letter in "nF":
                    found.append((_GH_SHORT_VALUE[letter], value))
                break
        i += 1
    return found


def _unread_expansions(tokens: list[str]) -> list[str]:
    """Words holding an expansion anywhere but in an option's value: `$EXTRA`
    in `flags+=($EXTRA)`, `--$OPT` or `--notes$SUFFIX` may be `--notes x`
    when the step runs, while `--title "$NAME"` and `--title=$NAME` are a
    title whatever they hold. Only a word that began with `$` was read, so an
    expansion inside an option's name passed."""
    found, i = [], 0
    while i < len(tokens):
        token = tokens[i]
        if token in _GH_LONG_VALUE:
            i += 2
            continue
        if token.startswith("--"):
            if "$" in token.partition("=")[0]:
                found.append(token)
            i += 1
            continue
        if token.startswith("-") and len(token) > 1:
            first = next((j for j, letter in enumerate(token[1:], start=1)
                          if letter in _GH_SHORT_VALUE), None)
            if "$" in token[1:first]:
                found.append(token)
            i += 2 if first == len(token) - 1 else 1
            continue
        if "$" in token:
            found.append(token)
        i += 1
    return found


def _unquoted_expansions(line: str) -> list[str]:
    """Words of ``line`` with a `$` outside double quotes, as the line spells
    them. The shell splits such a word, so `$TAG_AND_FLAGS` where the tag goes
    can carry `--notes x` whatever position it holds."""
    lexer = shlex.shlex(line, posix=False)
    lexer.whitespace_split = True
    words = []
    for word in lexer:
        quoted, unquoted = False, False
        for char in word:
            if char == '"':
                quoted = not quoted
            elif char == "$" and not quoted:
                unquoted = True
        if unquoted:
            words.append(word)
    return words


def _temp_spelling(path: str) -> str:
    """One spelling for a path under $RUNNER_TEMP: `${RUNNER_TEMP}` as
    `$RUNNER_TEMP`, `/./` as `/`, no trailing `/`. The notes file spelled
    `${RUNNER_TEMP}/notes.md` was called a second notes source, and
    `$RUNNER_TEMP/` a file beside the notes file."""
    path = path.replace("${RUNNER_TEMP}", "$RUNNER_TEMP")
    while "/./" in path:
        path = path.replace("/./", "/")
    return path.rstrip("/") if path != "/" else path


def _temp_named(line: str) -> tuple[str, bool]:
    """What a line names under $RUNNER_TEMP, in words a problem can use, and
    whether that reaches the notes file: the file itself, the directory
    holding it (`rm -rf "$RUNNER_TEMP"`), or a glob that may match it
    (`$RUNNER_TEMP/*.md`). Another file beside it does not, as far as the
    guard can tell."""
    paths = sorted({_temp_spelling(path) for path in _TEMP_PATH.findall(line)})
    if "$RUNNER_TEMP/notes.md" in paths or not paths:
        return "the notes file", True
    if "$RUNNER_TEMP" in paths:
        return "$RUNNER_TEMP, the directory the notes file is in,", True
    globs = [path for path in paths if re.search(r"[*?\[]", path)]
    if globs:
        return ", ".join(globs) + ", which may be the notes file,", True
    return ", ".join(paths) + ", beside the notes file,", False


def release_publish_problems(run: str) -> list[str]:
    """Whether what the notes groups append to notes.md is what
    `gh release create` reads. release_notes_text reads the groups; this reads
    the order around them.

    The flag must reach the create line: on that line, or in an array it
    expands (`"${flags[@]}"`) whose last setting before it is a line of its
    own carrying the flag. Between the first notes group and the create
    line, no other line may name the notes file or `$RUNNER_TEMP`: a
    truncation, the changelog generator moved after the group, an `rm` or
    a `cp` there drops the lines the group appended. Anywhere before it, a
    variable holding the path is refused, because a write through it cannot
    be followed. A group after the create line is not read by the release.
    Before this, the flag counted anywhere in the block, an echo included,
    and nothing read the order.

    No other notes source may reach the create line: --notes, -n,
    --notes-file or -F naming anything else, or --notes-from-tag, on the line
    itself or in a later setting of an array it expands (`flags+=(...)`, a
    conditional one included). A setting the guard cannot read is refused:
    an array expansion, a command substitution, or an expansion standing as
    a word of its own, any of which may be a notes option at run time; an
    expansion that is an option's value (`--title "$NAME"`) is read as that
    value. The same holds on the create line: an unquoted `${extra[@]}` or a
    `$EXTRA` word is refused, and so is an element set by index
    (`flags[99]=--notes`), an expansion inside an option's name (`--$OPT`,
    `--notes$SUFFIX`), an unquoted expansion where the tag goes, and a quoted
    array no `name=(` line sets (`mapfile`, `read -a`). `--generate-notes` is
    a second source too: gh prepends the notes file to generated notes. gh
    publishes one body, and which one it keeps
    is not something this guard should depend on; reading only whether the
    flag arrived let a trailing `--notes ''` pass. A line naming
    `$RUNNER_TEMP` is described by what it names, the notes file, its
    directory, a glob that may match it, or another path beside it, rather
    than always as the notes file; `${RUNNER_TEMP}`, `/./` and a trailing `/`
    are read as the same path."""
    lines = [line.strip() for line in _logical_lines(run) if line.strip()]
    creates = [i for i, line in enumerate(lines) if _GH_CREATE.match(line)]
    if len(creates) != 1:
        return [f"the step runs `gh release create` {len(creates)} times; the guard reads exactly one"]
    (create,) = creates
    create_line = lines[create]
    if re.search(r"[;&|<>`]|\$\(", create_line):
        return [f"`{create_line}` is not a plain `gh release create` line the guard can read"]
    groups = []
    for start, line in enumerate(lines):
        if line == "{":
            end = next((j for j in range(start + 1, len(lines)) if lines[j].startswith("}")), None)
            if end is not None and _NOTES_GROUP_END.fullmatch(lines[end]):
                groups.append((start, end))
    if not groups:
        return []  # release_notes_text names it
    problems = []
    flag = f"--notes-file {NOTES_FILE}"
    carried = flag in create_line
    #: The lines that set an array the create line expands to hold the flag.
    #: An assignment writes no file, so naming notes.md there is not a write.
    flag_lines = set()
    for name in re.findall(r'"\$\{([A-Za-z_]\w*)\[@\]\}"', create_line):
        sets = [i for i in range(create) if re.search(rf"(?<![\w+]){name}=\(", lines[i])]
        for i in sets:
            match = _ARRAY_SET.fullmatch(lines[i])
            if match is not None and match.group(1) == name and flag in match.group(2):
                flag_lines.add(i)
        if not sets or carried:
            continue
        match = _ARRAY_SET.fullmatch(lines[sets[-1]])
        if match is None or match.group(1) != name:
            problems.append(f"`{lines[sets[-1]]}` sets {name} in a way the guard cannot follow; "
                            "set it on a line of its own")
        elif flag in match.group(2):
            carried = True
    if not carried:
        problems.insert(0, f"the release is not created with {flag}")
    # Every notes option that reaches the create line: on it, and in each
    # setting of an array it expands from the last plain `name=(` on (an
    # append before that is overwritten). Anything but the notes file itself
    # is a second source.
    expected = ("--notes-file", "$RUNNER_TEMP/notes.md")
    sources = [(create_line, option) for option in _notes_options(shlex.split(create_line))]
    for name in re.findall(r'"\$\{([A-Za-z_]\w*)\[@\]\}"', create_line):
        sets = [i for i in range(create) if re.search(rf"(?<![\w+]){name}=\(", lines[i])]
        # Backticks are excluded as in _ARRAY_SET: a command substitution
        # left unmatched is named below as a setting the guard cannot follow.
        setting = re.compile(rf"(?<![\w+]){name}\+?=\(([^()`]*)\)")
        for i in range(sets[-1] if sets else 0, create):
            # `flags[99]=--notes` sets one element; nothing below reads it.
            if re.search(rf"(?<![\w+]){name}\[[^\]]*\]\+?=", lines[i]):
                problems.append(f"`{lines[i]}` adds to {name} in a way the guard cannot follow; "
                                "write each option on the line itself")
                continue
            if not re.search(rf"(?<![\w+]){name}\+?=\(", lines[i]):
                continue
            rest = setting.sub("", lines[i])
            try:
                tokens = [token for content in setting.findall(lines[i]) for token in shlex.split(content)]
            except ValueError:
                tokens = None
            if tokens is None or re.search(rf"(?<![\w+]){name}\+?=\(", rest) or any(
                    "[@]" in token or "[*]" in token for token in tokens) or _unread_expansions(tokens):
                problems.append(f"`{lines[i]}` adds to {name} in a way the guard cannot follow; "
                                "write each option on the line itself")
                continue
            if not _NAMES_NOTES.search(rest):
                flag_lines.add(i)  # an array setting writes no file
            sources += [(lines[i], option) for option in _notes_options(tokens)]
    # A word on the create line that is an expansion of its own: only the
    # quoted "${name[@]}" form is read above, so an unquoted `${extra[@]}`
    # or a `$EXTRA` holding `--notes x` passed unread. The first word after
    # `create` that is not an option is the tag.
    # An array counts as read only when it is quoted and a `name=(` line the
    # guard reads sets it: one filled by mapfile or `read -a` was counted as
    # read because it was quoted, though nothing here read what it held.
    unquoted = set(re.findall(r'(?<!")\$\{([A-Za-z_]\w*)\[[@*]\]\}', create_line))
    read = {name for name in re.findall(r'"\$\{([A-Za-z_]\w*)\[@\]\}"', create_line)
            if any(re.search(rf"(?<![\w+]){name}=\(", line) for line in lines[:create])}
    read -= unquoted
    words = shlex.split(create_line)[3:]
    if words and not words[0].startswith("-"):
        words = words[1:]
    unread = list(dict.fromkeys(
        [word.strip('"') for word in _unquoted_expansions(create_line)]
        + [word for word in _unread_expansions(words)
           if not (re.fullmatch(r"\$\{([A-Za-z_]\w*)\[@\]\}", word)
                   and word[2:-4] in read)]))
    if unread:
        problems.append(f"`{create_line}` passes {', '.join(unread)}, which the guard cannot read "
                        "and which may be a notes option when the step runs; write the option on "
                        "the line or in the flags array")
    if carried:
        for line, (option, value) in sources:
            if value is not None:
                value = _temp_spelling(value)
            if (option, value) != expected:
                source = option if value is None else f"{option} {shlex.quote(value)}"
                problems.append(
                    f"`{line}` gives `gh release create` a second notes source, {source}; gh "
                    "publishes one body, so the release may not show what the notes groups "
                    f"appended to {NOTES_FILE}")
    inside = {i for start, end in groups for i in range(start, end + 1)}
    first = groups[0][0]
    for i, line in enumerate(lines[:create]):
        if i in inside or i in flag_lines or not _NAMES_NOTES.search(line):
            continue
        named, notes = _temp_named(line)
        if _ASSIGNMENT.match(line):
            problems.append(f"`{line}` names {named} in a variable the guard cannot follow; "
                            + (f"write {NOTES_FILE} where it is used" if named == "the notes file"
                               else "write the path where it is used"))
        elif i > first:
            problems.append(f"`{line}` names {named} between the notes group and `gh release create`; "
                            + ("a write there can drop the lines the group appended" if notes else
                               "the guard cannot tell a write there from one that drops the lines "
                               "the group appended. Write it outside $RUNNER_TEMP, or before the "
                               "notes group"))
    if any(start > create for start, _ in groups):
        problems.append("a notes group follows `gh release create`, so the release never reads it")
    return problems


#: sha256sum's options (GNU coreutils; /sbin/sha256sum on Darwin has the
#: same set). A long option may be any unique prefix: `--ch` and `--i` are
#: --check and --ignore-missing, `--t` is refused as ambiguous.
SHA256SUM_LONG = ("binary", "check", "help", "ignore-missing", "quiet", "status", "strict", "tag", "text",
                  "version", "warn", "zero")
SHA256SUM_SHORT = {"b": "binary", "c": "check", "t": "text", "w": "warn", "z": "zero"}


def sha256sum_arguments(args: list[str]) -> tuple[set[str], list[str]] | None:
    """The options and file operands of `sha256sum ARGS`, as getopt_long reads
    them: options anywhere, until `--`. None when an option is not one
    sha256sum takes, so a spelling nobody anticipated is refused rather than
    skipped."""
    options, operands, ended = set(), [], False
    for arg in args:
        if ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            ended = True
        elif arg.startswith("--"):
            name = arg[2:]
            matches = [option for option in SHA256SUM_LONG if option == name] or [
                option for option in SHA256SUM_LONG if option.startswith(name)]
            if len(matches) != 1:
                return None
            options.add(matches[0])
        elif all(letter in SHA256SUM_SHORT for letter in arg[1:]):
            options.update(SHA256SUM_SHORT[letter] for letter in arg[1:])
        else:
            return None
    return options, operands


def release_notes_problems(workflow: dict) -> list[str]:
    """The release notes' verification lines, unless they say which files the
    attestation command works on, say which attached files it refuses, and
    give a checksum command that works on a partial download. They said
    "Verify a download with" over every attached file, and
    `sha256sum --check SHA256SUMS` exits 1 for each listed file the reader
    did not download. SECURITY.md had both right.

    Every sha256sum in the notes is read as getopt_long would read it
    (sha256sum_arguments). Each check must name a file called SHA256SUMS
    and carry --ignore-missing, and there must be one; a check, or an
    option, the parser cannot read is named, not skipped. Matching a single
    spelling let `-c SHA256SUMS`, `-c ./SHA256SUMS`, `--ch SHA256SUMS`, or
    no checksum line at all, pass.
    Only what the notes groups append to notes.md is read
    (release_notes_text): reading the whole run block let a command the step
    runs, or a line it prints to its log, stand in for a line the notes
    lacked. That those lines are still in notes.md when `gh release create`
    reads it, through --notes-file, is release_publish_problems."""
    subjects = [str(step.get("with", {}).get("subject-path", "")).split()
                for step in workflow["jobs"]["provenance"]["steps"]
                if str(step.get("uses", "")).startswith(ATTEST_ACTION + "@")]
    problems = []
    if subjects != [list(ATTESTED_SUBJECTS)]:
        problems.append(f"the provenance step attests {subjects}; say in ATTESTED_SUBJECTS what the notes call each")
    (create,) = [step for step in workflow["jobs"]["github-release"]["steps"]
                 if step.get("name") == "Create the release"]
    run = str(create.get("run", ""))
    problems += release_publish_problems(run)
    text, unreadable = release_notes_text(run)
    problems += unreadable
    if any(problem.startswith("no `{") for problem in unreadable):
        return problems
    notes = " ".join(text.split())
    *head, last = ATTESTED_SUBJECTS.values()
    sentence = f"Verify a {', '.join(head)} or {last} with"
    if sentence not in notes:
        problems.append(f"the notes must say which files carry provenance: {sentence!r}")
    if NO_PROVENANCE_SENTENCE not in notes:
        problems.append(f"the notes must say what `gh attestation verify` refuses: {NO_PROVENANCE_SENTENCE!r}")
    checks = 0
    for args in (command.split()[1:] for command in re.findall(r"\bsha256sum\b[^`\\\"';|&()<>]*", notes)):
        parsed = sha256sum_arguments(args)
        if parsed is not None and "check" not in parsed[0]:
            continue
        if parsed is None or not any(PurePosixPath(operand).name == "SHA256SUMS" for operand in parsed[1]):
            problems.append(f"`sha256sum {' '.join(args)}` is not a spelling the guard can read; "
                            f"write `{CHECKSUM_COMMAND}`")
            continue
        checks += 1
        if "ignore-missing" not in parsed[0]:
            problems.append(f"`sha256sum {' '.join(args)}` without --ignore-missing fails for a reader "
                            "who downloaded only some of the files")
    if not checks:
        problems.append(f"the notes give no `{CHECKSUM_COMMAND}` for a reader to check a download with")
    return problems


class AttestationCommandTest(unittest.TestCase):
    """SECURITY.md presents the attestation as what stops a substituted file.
    It was `gh attestation verify FILE --repo Veridor-authz/veridor`, which a
    workflow pushed on any branch could satisfy by re-uploading and
    re-attesting a release asset."""

    def test_every_documented_command_pins_release_yml_at_the_tag(self) -> None:
        found = {}
        for name in ATTESTATION_DOCUMENTS:
            commands = attestation_commands((ROOT / name).read_text(encoding="utf-8"))
            found[name] = len(commands)
            for command in commands:
                with self.subTest(file=name, command=command):
                    self.assertEqual(attestation_problems(command), [])
        self.assertGreaterEqual(found["SECURITY.md"], 1, found)
        self.assertGreaterEqual(found[".github/workflows/release.yml"], 1, found)

    def test_control_unpinned_forms_are_named(self) -> None:
        for label, command in {
            "repo only (the old SECURITY.md)": "gh attestation verify veridor-X.Y.Z-py3-none-any.whl --repo Veridor-authz/veridor",
            "repo only (the old notes)": "gh attestation verify FILE --repo ${GITHUB_REPOSITORY}\\`",
            "signer workflow alone, a prefix match": ("gh attestation verify FILE --repo Veridor-authz/veridor "
                                                      "--signer-workflow Veridor-authz/veridor/.github/workflows/release.yml"),
            "a branch ref": ("gh attestation verify FILE --repo Veridor-authz/veridor --cert-identity "
                             "https://github.com/Veridor-authz/veridor/.github/workflows/release.yml@refs/heads/main"),
            "another workflow": ("gh attestation verify FILE --repo Veridor-authz/veridor --cert-identity "
                                 "https://github.com/Veridor-authz/veridor/.github/workflows/ci.yml@refs/tags/vX.Y.Z"),
        }.items():
            with self.subTest(control=label):
                self.assertTrue(attestation_problems(command))
        old = ('echo "Verify a download with \\`gh attestation verify FILE --repo ${GITHUB_REPOSITORY}\\`"\n'
               'echo "and \\`sha256sum --check SHA256SUMS\\`."\n')
        self.assertEqual(len(attestation_commands(old)), 1)
        self.assertTrue(attestation_problems(attestation_commands(old)[0]))

    def test_security_md_says_what_the_check_proves_and_what_it_does_not(self) -> None:
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        section = text[text.index("## Verifying a release"):text.index("## Deliberate capabilities")]
        self.assertNotIn("The attestation above is what ties a file\n  to this repository's workflow", section)
        for phrase in ("any workflow in the repository", "at any ref", "does not prove", "SHA256SUMS"):
            self.assertIn(phrase, " ".join(section.split()))

    def test_the_release_notes_name_only_attested_files_and_a_check_that_works(self) -> None:
        self.assertEqual(release_notes_problems(_workflow("release.yml")), [])

    def test_control_the_old_notes_are_named(self) -> None:
        workflow = _workflow("release.yml")
        job = workflow["jobs"]["github-release"]
        # The step as it shipped: the notes in a group appended to notes.md.
        old = ('{\n'
               '  echo "Verify a download with"\n'
               '  echo "\\`gh attestation verify FILE --repo x\\`."\n'
               '  echo "\\`sha256sum --check SHA256SUMS\\` detects a damaged download, not a substituted one."\n'
               '} >> "$RUNNER_TEMP/notes.md"\n'
               'flags=(--verify-tag --title "$GITHUB_REF_NAME" --notes-file "$RUNNER_TEMP/notes.md")\n'
               'gh release create "$GITHUB_REF_NAME" dist/* "${flags[@]}"\n')
        steps = [dict(step, run=old) if step.get("name") == "Create the release" else step for step in job["steps"]]
        jobs = dict(workflow["jobs"], **{"github-release": dict(job, steps=steps)})
        self.assertEqual(release_notes_problems(dict(workflow, jobs=jobs)), [
            "the notes must say which files carry provenance: 'Verify a wheel, sdist or zipapp with'",
            "the notes must say what `gh attestation verify` refuses: "
            "'The SBOM and SHA256SUMS carry no provenance.'",
            "`sha256sum --check SHA256SUMS` without --ignore-missing fails for a reader who "
            "downloaded only some of the files"])
        provenance = workflow["jobs"]["provenance"]
        attest = [dict(step, **{"with": {"subject-path": "dist/*\n"}})
                  if str(step.get("uses", "")).startswith(ATTEST_ACTION + "@") else step
                  for step in provenance["steps"]]
        jobs = dict(workflow["jobs"], provenance=dict(provenance, steps=attest))
        self.assertEqual(release_notes_problems(dict(workflow, jobs=jobs)), [
            "the provenance step attests [['dist/*']]; say in ATTESTED_SUBJECTS what the notes call each"])

    @staticmethod
    def _notes_edited(edit) -> dict:
        """release.yml with the notes step's run block passed through `edit`,
        which takes and returns its list of lines."""
        workflow = _workflow("release.yml")
        job = workflow["jobs"]["github-release"]
        steps = [dict(step, run="\n".join(edit(str(step["run"]).splitlines())))
                 if step.get("name") == "Create the release" else step for step in job["steps"]]
        return dict(workflow, jobs=dict(workflow["jobs"], **{"github-release": dict(job, steps=steps)}))

    def test_a_short_or_reordered_check_without_ignore_missing_is_named(self) -> None:
        # The guard read only `sha256sum --check[ --flags] SHA256SUMS`, so
        # `-c SHA256SUMS`, the most common spelling, put the defect back with
        # the test still green.
        for spelling in ("-c SHA256SUMS", "SHA256SUMS --check", "-wc SHA256SUMS", "--check --strict SHA256SUMS"):
            with self.subTest(spelling=spelling):
                workflow = self._notes_edited(lambda lines: [
                    line.replace("--check --ignore-missing SHA256SUMS", spelling) for line in lines])
                self.assertEqual(release_notes_problems(workflow), [
                    f"`sha256sum {spelling}` without --ignore-missing fails for a reader who "
                    "downloaded only some of the files"])
        for spelling in ("-c --ignore-missing SHA256SUMS", "SHA256SUMS --ignore-missing -c"):
            with self.subTest(spelling=spelling):
                workflow = self._notes_edited(lambda lines: [
                    line.replace("--check --ignore-missing SHA256SUMS", spelling) for line in lines])
                self.assertEqual(release_notes_problems(workflow), [])

    def test_every_checksum_spelling_beside_a_good_one_is_read(self) -> None:
        # The parser took a check only with the bare token SHA256SUMS and a
        # flag of exactly --check or a cluster holding c, so a second command
        # spelt `-c ./SHA256SUMS`, `--ch SHA256SUMS` or `(... SHA256SUMS)`
        # passed beside the good one. sha256sum takes any unique prefix of a
        # long option (`--ch`, `--c`, `--i`; `--t` is ambiguous), as measured
        # with /sbin/sha256sum on Darwin, which has GNU's option set.
        def beside(text: str) -> dict:
            return self._notes_edited(lambda lines: [
                new for line in lines
                for new in ([line, f'  echo "{text}"'] if "sha256sum --check" in line else [line])])

        for spelling in ("-c ./SHA256SUMS", "--ch SHA256SUMS", "--c dist/SHA256SUMS", "-c SHA256SUMS)",
                         "SHA256SUMS -wc"):
            with self.subTest(spelling=spelling):
                text = f"(sha256sum {spelling}" if spelling.endswith(")") else f"\\`sha256sum {spelling}\\`."
                args = spelling.rstrip(")")
                self.assertEqual(release_notes_problems(beside(text)), [
                    f"`sha256sum {args}` without --ignore-missing fails for a reader who "
                    "downloaded only some of the files"])
        for spelling in ("--ch --ig ./SHA256SUMS", "-c --i SHA256SUMS", "--ignore-missing -c dist/SHA256SUMS"):
            with self.subTest(spelling=spelling):
                self.assertEqual(release_notes_problems(beside(f"\\`sha256sum {spelling}\\`.")), [])
        # Alone, a path-qualified check is named for what it lacks, not as
        # no check at all.
        workflow = self._notes_edited(lambda lines: [
            line.replace("--check --ignore-missing SHA256SUMS", "-c ./SHA256SUMS") for line in lines])
        self.assertEqual(release_notes_problems(workflow), [
            "`sha256sum -c ./SHA256SUMS` without --ignore-missing fails for a reader who "
            "downloaded only some of the files"])

    def test_a_checksum_spelling_the_guard_cannot_read_is_named(self) -> None:
        for spelling in ("--t SHA256SUMS", "-cx SHA256SUMS", "--chek --ignore-missing SHA256SUMS",
                         "-c --ignore-missing SUMS.txt", "--check --ignore-missing"):
            with self.subTest(spelling=spelling):
                workflow = self._notes_edited(lambda lines: [
                    new for line in lines
                    for new in ([line, f'  echo "\\`sha256sum {spelling}\\`."']
                                if "sha256sum --check" in line else [line])])
                self.assertEqual(release_notes_problems(workflow), [
                    f"`sha256sum {spelling}` is not a spelling the guard can read; "
                    "write `sha256sum --check --ignore-missing SHA256SUMS`"])

    def test_dropping_the_checksum_command_is_named(self) -> None:
        missing = ["the notes give no `sha256sum --check --ignore-missing SHA256SUMS` "
                   "for a reader to check a download with"]
        workflow = self._notes_edited(lambda lines: [line for line in lines if "sha256sum" not in line])
        self.assertEqual(release_notes_problems(workflow), missing)
        # Kept only in a comment, it is not in the notes.
        workflow = self._notes_edited(lambda lines: [
            line.replace('echo "', '# echo "', 1) if "sha256sum" in line else line for line in lines])
        self.assertEqual(release_notes_problems(workflow), missing)
        # A spelling the guard does not read as a check is not taken for one.
        workflow = self._notes_edited(lambda lines: [
            line.replace("--check --ignore-missing", "--ignore-missing") for line in lines])
        self.assertEqual(release_notes_problems(workflow), missing)

    def test_dropping_the_no_provenance_sentence_is_named(self) -> None:
        missing = ["the notes must say what `gh attestation verify` refuses: "
                   "'The SBOM and SHA256SUMS carry no provenance.'"]
        workflow = self._notes_edited(lambda lines: [line for line in lines if "carry no provenance" not in line])
        self.assertEqual(release_notes_problems(workflow), missing)
        workflow = self._notes_edited(lambda lines: [
            line.replace('echo "', '# echo "', 1) if "carry no provenance" in line else line for line in lines])
        self.assertEqual(release_notes_problems(workflow), missing)

    def test_text_outside_the_notes_group_is_not_notes(self) -> None:
        # The guard read the whole run block, so a line the step runs or
        # prints to its own log satisfied it while notes.md lacked it.
        checksum = ["the notes give no `sha256sum --check --ignore-missing SHA256SUMS` "
                    "for a reader to check a download with"]
        sentence = ["the notes must say what `gh attestation verify` refuses: "
                    "'The SBOM and SHA256SUMS carry no provenance.'"]
        for label, edit, expected in (
            ("a checksum the step runs", lambda lines: [line for line in lines if "sha256sum" not in line] + [
                "(cd dist && sha256sum --check --ignore-missing SHA256SUMS && cd ..)"], checksum),
            ("the sentence in the step's log", lambda lines: [
                line for line in lines if "carry no provenance" not in line] + [
                'echo "::notice::The SBOM and SHA256SUMS carry no provenance."'], sentence),
            ("the sentence echoed before the group", lambda lines: [
                new for line in lines if "carry no provenance" not in line
                for new in (['echo "The SBOM and SHA256SUMS carry no provenance."', line]
                            if line.strip() == "{" else [line])], sentence),
        ):
            with self.subTest(label):
                self.assertEqual(release_notes_problems(self._notes_edited(edit)), expected)

    def test_a_notes_line_the_guard_cannot_read_is_named(self) -> None:
        # Only plain echo lines are read; anything else in the group writes
        # text the guard would have to guess at, so it is refused.
        for label, line in (
            ("a command", '  sha256sum --check SHA256SUMS'),
            ("printf", '  printf "%s\\n" "The SBOM and SHA256SUMS carry no provenance."'),
            ("a command substitution", '  echo "$(cat extra.md)"'),
            ("a backquoted substitution", '  echo "`cat extra.md`"'),
        ):
            with self.subTest(label):
                workflow = self._notes_edited(lambda lines: [
                    new for old in lines for new in ([old, line] if "carry no provenance" in old else [old])])
                self.assertEqual(release_notes_problems(workflow), [
                    f"the notes group runs `{line.strip()}`, which the guard cannot read; "
                    "write the notes with plain echo lines"])

    def test_notes_the_release_does_not_use_are_named(self) -> None:
        workflow = self._notes_edited(lambda lines: [
            line.replace('--notes-file "$RUNNER_TEMP/notes.md"', '--generate-notes') for line in lines])
        self.assertEqual(release_notes_problems(workflow), [
            'the release is not created with --notes-file "$RUNNER_TEMP/notes.md"'])
        workflow = self._notes_edited(lambda lines: [
            line.replace('} >> "$RUNNER_TEMP/notes.md"', '} >> "$RUNNER_TEMP/other.md"') for line in lines])
        self.assertEqual(release_notes_problems(workflow), [
            'no `{ ... } >> "$RUNNER_TEMP/notes.md"` group writes the notes'])

    _GENERATOR = 'python3 scripts/release_check.py notes "$GITHUB_REF_NAME" > "$RUNNER_TEMP/notes.md"'
    _NOT_CREATED = 'the release is not created with --notes-file "$RUNNER_TEMP/notes.md"'

    @staticmethod
    def _before(marker: str, *new: str):
        """An edit that puts ``new`` lines before the first line holding ``marker``."""
        def edit(lines: list[str]) -> list[str]:
            index = next(i for i, line in enumerate(lines) if marker in line)
            return lines[:index] + ["          " + line for line in new] + lines[index:]
        return edit

    def test_notes_overwritten_before_the_release_reads_them_are_named(self) -> None:
        # The guard read what the groups append to notes.md, never whether it
        # was still there when gh release create read it: the generator moved
        # after the group, or a truncation before gh, published notes without
        # the verification lines and the guard returned [].
        def moved(lines: list[str]) -> list[str]:
            kept = [line for line in lines if line.strip() != self._GENERATOR]
            self.assertEqual(len(kept), len(lines) - 1, "the generator line is in release.yml")
            end = next(i for i, line in enumerate(kept) if line.strip() == '} >> "$RUNNER_TEMP/notes.md"')
            return kept[:end + 1] + ["          " + self._GENERATOR] + kept[end + 1:]

        for label, edit, line in (
            ("the generator after the group", moved, self._GENERATOR),
            ("a truncation", self._before("gh release create", ': > "$RUNNER_TEMP/notes.md"'),
             ': > "$RUNNER_TEMP/notes.md"'),
            ("an overwrite", self._before("flags=(", 'echo "## notes" > "$RUNNER_TEMP/notes.md"'),
             'echo "## notes" > "$RUNNER_TEMP/notes.md"'),
            ("a copy over it", self._before("gh release create", 'cp /dev/null "$RUNNER_TEMP/notes.md"'),
             'cp /dev/null "$RUNNER_TEMP/notes.md"'),
        ):
            with self.subTest(label):
                self.assertEqual(release_notes_problems(self._notes_edited(edit)), [
                    f"`{line}` names the notes file between the notes group and `gh release create`; "
                    "a write there can drop the lines the group appended"])
        # It names the directory, not the file; removing it still drops them.
        line = 'rm -rf "$RUNNER_TEMP"'
        with self.subTest("the directory removed"):
            self.assertEqual(release_notes_problems(self._notes_edited(self._before("gh release create", line))), [
                f"`{line}` names $RUNNER_TEMP, the directory the notes file is in, between the notes "
                "group and `gh release create`; a write there can drop the lines the group appended"])
        # Through a variable the guard cannot follow, it is named where it is set.
        alias = 'NOTES="$RUNNER_TEMP/notes.md"'
        workflow = self._notes_edited(lambda lines: self._before("gh release create", ': > "$NOTES"')(
            self._before("python3 scripts/release_check.py", alias)(lines)))
        self.assertEqual(release_notes_problems(workflow), [
            f"`{alias}` names the notes file in a variable the guard cannot follow; "
            'write "$RUNNER_TEMP/notes.md" where it is used'])
        # A group the release never reads is not the notes.
        def after(lines: list[str]) -> list[str]:
            start = next(i for i, line in enumerate(lines) if line.strip() == "{")
            end = next(i for i, line in enumerate(lines) if line.strip().startswith("} >>"))
            return lines[:start] + lines[end + 1:] + lines[start:end + 1]
        self.assertEqual(release_notes_problems(self._notes_edited(after)), [
            "a notes group follows `gh release create`, so the release never reads it"])

    def test_control_appends_and_flags_between_the_group_and_the_release_pass(self) -> None:
        for label, edit in (
            ("another group", self._before("flags=(", "{", '  echo "Built by release.yml."',
                                           '} >> "$RUNNER_TEMP/notes.md"')),
            ("another flag", self._before("gh release create", "flags+=(--latest)")),
            ("a line that names no file", self._before("gh release create", 'echo "creating $GITHUB_REF_NAME"')),
        ):
            with self.subTest(label):
                self.assertEqual(release_notes_problems(self._notes_edited(edit)), [])

    def test_the_notes_file_flag_must_reach_gh_release_create(self) -> None:
        # A presence check on the whole run block: a line outside the notes
        # group that only mentioned the flag satisfied it while the release
        # was created with --generate-notes.
        mention = """echo 'see --notes-file "$RUNNER_TEMP/notes.md"'"""

        def generated(lines: list[str]) -> list[str]:
            return [line.replace('--notes-file "$RUNNER_TEMP/notes.md"', "--generate-notes") for line in lines]

        workflow = self._notes_edited(lambda lines: generated(lines) + ["          " + mention])
        self.assertEqual(release_notes_problems(workflow), [self._NOT_CREATED])
        workflow = self._notes_edited(lambda lines: self._before("gh release create", mention)(generated(lines)))
        self.assertEqual(release_notes_problems(workflow), [
            self._NOT_CREATED,
            f"`{mention}` names the notes file between the notes group and `gh release create`; "
            "a write there can drop the lines the group appended"])
        # The flags array reassigned, or not expanded, does not carry it.
        reassigned = 'if [[ "$PRERELEASE" == true ]]; then flags=(--generate-notes); fi'
        self.assertEqual(release_notes_problems(self._notes_edited(self._before("gh release create", reassigned))), [
            self._NOT_CREATED,
            f"`{reassigned}` sets flags in a way the guard cannot follow; set it on a line of its own"])
        workflow = self._notes_edited(lambda lines: [
            line.replace(' "${flags[@]}"', "") if "gh release create" in line else line for line in lines])
        flags = next(line.strip() for line in workflow["jobs"]["github-release"]["steps"][-1]["run"].splitlines()
                     if line.strip().startswith("flags=("))
        self.assertEqual(release_notes_problems(workflow), [
            self._NOT_CREATED,
            f"`{flags}` names the notes file in a variable the guard cannot follow; "
            'write "$RUNNER_TEMP/notes.md" where it is used'])
        # One plain gh release create, read whole.
        unreadable = 'gh release create "$GITHUB_REF_NAME" dist/* "${flags[@]}" || true'
        workflow = self._notes_edited(lambda lines: [
            "          " + unreadable if "gh release create" in line else line for line in lines])
        self.assertEqual(release_notes_problems(workflow), [
            f"`{unreadable}` is not a plain `gh release create` line the guard can read"])
        workflow = self._notes_edited(lambda lines: [line for line in lines if "gh release create" not in line])
        self.assertEqual(release_notes_problems(workflow), [
            "the step runs `gh release create` 0 times; the guard reads exactly one"])

    @staticmethod
    def _second_source(line: str, source: str) -> str:
        return (f"`{line}` gives `gh release create` a second notes source, {source}; gh "
                "publishes one body, so the release may not show what the notes groups "
                'appended to "$RUNNER_TEMP/notes.md"')

    def test_a_second_notes_source_after_the_flag_is_named(self) -> None:
        # The flag reaching the create line was the whole check, so a later
        # flags+=(--notes-file X), flags+=(-F X), a conditional appending one,
        # or a trailing --notes-file X, -F X or --notes '' on the create line
        # itself passed beside it, and the release could publish X or nothing.
        for label, line, source in (
            ("flags+= --notes-file", "flags+=(--notes-file other.md)", "--notes-file other.md"),
            ("flags+= -F", "flags+=(-F other.md)", "--notes-file other.md"),
            ("flags+= a file under RUNNER_TEMP", 'flags+=(--notes-file "$RUNNER_TEMP/other.md")',
             "--notes-file '$RUNNER_TEMP/other.md'"),
            ("a conditional --notes-file",
             'if [[ "$PRERELEASE" == true ]]; then flags+=(--notes-file other.md); fi',
             "--notes-file other.md"),
            ("a conditional -F", 'if [[ "$DRAFT" == true ]]; then flags+=(-F other.md); fi',
             "--notes-file other.md"),
            ("flags+= --notes", "flags+=(--notes 'see the changelog')", "--notes 'see the changelog'"),
        ):
            with self.subTest(label):
                workflow = self._notes_edited(self._before("gh release create", line))
                self.assertEqual(release_notes_problems(workflow), [self._second_source(line, source)])
        for label, suffix, source in (
            ("--notes-file", "--notes-file other.md", "--notes-file other.md"),
            ("-F", "-F other.md", "--notes-file other.md"),
            ("--notes ''", "--notes ''", "--notes ''"),
            ("--notes=", "--notes=x", "--notes x"),
            ("-F attached", "-Fother.md", "--notes-file other.md"),
            ("a short cluster", "-dF other.md", "--notes-file other.md"),
            ("--notes-from-tag", "--notes-from-tag", "--notes-from-tag"),
        ):
            with self.subTest(label):
                workflow = self._notes_edited(lambda lines: [
                    f"{line} {suffix}" if "gh release create" in line else line for line in lines])
                create = next(line.strip() for line in
                              workflow["jobs"]["github-release"]["steps"][-1]["run"].splitlines()
                              if "gh release create" in line)
                self.assertEqual(release_notes_problems(workflow), [self._second_source(create, source)])

    def test_control_flags_that_are_not_a_second_source_pass(self) -> None:
        for label, edit in (
            ("the same file again", self._before("gh release create",
                                                  'flags+=(--notes-file "$RUNNER_TEMP/notes.md")')),
            ("a title, not notes", self._before("gh release create", "flags+=(-t name --draft)")),
            # Overwritten by the flags=( line after it, so it never reaches gh.
            ("an append the set overwrites", self._before("flags=(", "flags+=(-F other.md)")),
        ):
            with self.subTest(label):
                self.assertEqual(release_notes_problems(self._notes_edited(edit)), [])

    def test_a_flags_append_the_guard_cannot_read_is_named(self) -> None:
        # A command substitution or a bare expansion can be `--notes x` at run
        # time. The append pattern excluded parentheses but not backticks, and
        # read `$EXTRA` as a word that is no option, so both passed while the
        # array expansion "${extra[@]}" was refused.
        for line in ('flags+=("${extra[@]}")',
                     "flags+=(`cat extra-flags`)",
                     'flags+=("`cat extra-flags`")',
                     "flags+=($EXTRA)",
                     'flags+=("$EXTRA")',
                     'if [[ "$DRAFT" == true ]]; then flags+=($EXTRA); fi'):
            with self.subTest(line=line):
                workflow = self._notes_edited(self._before("gh release create", line))
                self.assertEqual(release_notes_problems(workflow), [
                    f"`{line}` adds to flags in a way the guard cannot follow; "
                    "write each option on the line itself"])

    def test_control_an_expansion_that_is_an_option_s_value_passes(self) -> None:
        for line in ('flags+=(--title "$OTHER")', 'flags+=(-t "$OTHER")',
                     'flags+=(--target "$GITHUB_SHA")', 'flags+=(--title="$OTHER")',
                     'flags+=(-dt "$OTHER")'):
            with self.subTest(line=line):
                workflow = self._notes_edited(self._before("gh release create", line))
                self.assertEqual(release_notes_problems(workflow), [])

    def test_a_create_line_word_the_guard_cannot_read_is_named(self) -> None:
        # Only the quoted "${flags[@]}" form was read, so an unquoted array
        # expansion, a string variable or an indexed element set before the
        # line passed, though each can be `--notes x` when the step runs.
        def create_with(extra: str):
            return lambda lines: [f"{line} {extra}" if "gh release create" in line else line
                                  for line in lines]

        for label, extra, word in (("an unquoted array", "${extra[@]}", "${extra[@]}"),
                                   ("a string variable", "$EXTRA", "$EXTRA"),
                                   ("a quoted string variable", '"$EXTRA"', "$EXTRA")):
            with self.subTest(label):
                workflow = self._notes_edited(create_with(extra))
                create = next(line.strip() for line in
                              workflow["jobs"]["github-release"]["steps"][-1]["run"].splitlines()
                              if "gh release create" in line)
                self.assertEqual(release_notes_problems(workflow), [
                    f"`{create}` passes {word}, which the guard cannot read and which may be a "
                    "notes option when the step runs; write the option on the line or in the "
                    "flags array"])
        line = "flags[99]=--notes"
        workflow = self._notes_edited(self._before("gh release create", line))
        self.assertEqual(release_notes_problems(workflow), [
            f"`{line}` adds to flags in a way the guard cannot follow; "
            "write each option on the line itself"])

    def test_more_words_the_guard_cannot_read_are_named(self) -> None:
        # Each passed before. An array filled by mapfile or
        # read counted as read because it was quoted, though no line the
        # guard reads sets it; an expansion inside an option word, and an
        # unquoted one where the tag goes, can each be `--notes x`.
        def create(transform):
            return lambda lines: [transform(line) if "gh release create" in line else line
                                  for line in lines]

        def created(workflow: dict) -> str:
            return next(line.strip() for line in
                        workflow["jobs"]["github-release"]["steps"][-1]["run"].splitlines()
                        if "gh release create" in line)

        def unread(line: str, word: str) -> str:
            return (f"`{line}` passes {word}, which the guard cannot read and which may be a "
                    "notes option when the step runs; write the option on the line or in the "
                    "flags array")

        for label, before, transform, word in (
            ("mapfile", "mapfile -t extra < extra-flags.txt",
             lambda line: f'{line} "${{extra[@]}}"', "${extra[@]}"),
            ("read -ra", 'read -ra extra <<< "$EXTRA_FLAGS"',
             lambda line: f'{line} "${{extra[@]}}"', "${extra[@]}"),
            ("an option word", None, lambda line: f"{line} --notes$S x", "--notes$S"),
            ("the tag", None,
             lambda line: line.replace('"$GITHUB_REF_NAME"', "$TAG_AND_FLAGS"), "$TAG_AND_FLAGS"),
        ):
            with self.subTest(label):
                edit = create(transform)
                if before:
                    edit = (lambda e, b: lambda lines: e(self._before("gh release create", b)(lines)))(edit, before)
                workflow = self._notes_edited(edit)
                self.assertEqual(release_notes_problems(workflow), [unread(created(workflow), word)])
        for line in ("flags+=(--$OPT x)", "flags+=(--notes$SUFFIX x)", "flags+=(-$N x)"):
            with self.subTest(line=line):
                workflow = self._notes_edited(self._before("gh release create", line))
                self.assertEqual(release_notes_problems(workflow), [
                    f"`{line}` adds to flags in a way the guard cannot follow; "
                    "write each option on the line itself"])
        # gh prepends the notes to generated ones, so the body is no longer
        # only what the notes groups appended.
        line = "flags+=(--generate-notes)"
        workflow = self._notes_edited(self._before("gh release create", line))
        self.assertEqual(release_notes_problems(workflow),
                         [self._second_source(line, "--generate-notes")])

    def test_the_notes_file_spelled_with_braces_is_not_a_second_source(self) -> None:
        line = 'flags+=(--notes-file "${RUNNER_TEMP}/notes.md")'
        workflow = self._notes_edited(self._before("gh release create", line))
        self.assertEqual(release_notes_problems(workflow), [])

    def test_a_path_that_can_reach_the_notes_file_is_not_called_beside_it(self) -> None:
        for line, named in (('rm -f $RUNNER_TEMP/*.md', "$RUNNER_TEMP/*.md, which may be the notes file,"),
                            ('rm -rf $RUNNER_TEMP/', "$RUNNER_TEMP, the directory the notes file is in,"),
                            (': > $RUNNER_TEMP/./notes.md', "the notes file")):
            with self.subTest(line=line):
                workflow = self._notes_edited(self._before("gh release create", line))
                self.assertEqual(release_notes_problems(workflow), [
                    f"`{line}` names {named} between the notes group and `gh release create`; "
                    "a write there can drop the lines the group appended"])

    def test_a_line_naming_another_file_in_runner_temp_says_which(self) -> None:
        # The rule refuses any line between the group and the release that
        # names $RUNNER_TEMP, and said every one of them "names the notes
        # file", including one that writes some other file there.
        line = 'echo hi > "$RUNNER_TEMP/other.txt"'
        workflow = self._notes_edited(self._before("gh release create", line))
        self.assertEqual(release_notes_problems(workflow), [
            f"`{line}` names $RUNNER_TEMP/other.txt, beside the notes file, between the notes group "
            "and `gh release create`; the guard cannot tell a write there from one that drops "
            "the lines the group appended. Write it outside $RUNNER_TEMP, or before the notes group"])
        alias = 'OTHER="$RUNNER_TEMP/other.md"'
        workflow = self._notes_edited(self._before("python3 scripts/release_check.py", alias))
        self.assertEqual(release_notes_problems(workflow), [
            f"`{alias}` names $RUNNER_TEMP/other.md, beside the notes file, in a variable the guard "
            "cannot follow; write the path where it is used"])

    def test_control_the_flag_on_the_create_line_itself_passes(self) -> None:
        for create in ('gh release create "$GITHUB_REF_NAME" dist/* --notes-file "$RUNNER_TEMP/notes.md"',
                       'gh release create "$GITHUB_REF_NAME" dist/* \\\n            --notes-file "$RUNNER_TEMP/notes.md"'):
            with self.subTest(create=create):
                workflow = self._notes_edited(lambda lines: [
                    new for line in lines if not line.strip().startswith(("flags", "if [["))
                    for new in (["          " + create] if "gh release create" in line else [line])])
                self.assertEqual(release_notes_problems(workflow), [])


def release_notes_step(workflow: dict) -> dict:
    return next(s for s in workflow["jobs"]["github-release"]["steps"] if "gh release create" in s.get("run", ""))


@slow("runs release.yml's release-notes step under bash; gh and the release script are stubs")
class ReleaseNotesStepTest(unittest.TestCase):
    """The notes a release publishes, as the step writes them for a real tag."""

    def test_the_notes_pin_release_yml_at_the_tag_being_released(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="veridor-notes-step-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        stubs, runner, work = tmp / "stubs", tmp / "runner", tmp / "work"
        for directory in (stubs, runner, work / "dist"):
            directory.mkdir(parents=True)
        notes_copy = tmp / "notes.md"
        (stubs / "python3").write_text("#!/usr/bin/env bash\necho '## [1.2.3] - 2026-09-24'\n", encoding="utf-8")
        (stubs / "gh").write_text(
            "#!/usr/bin/env bash\n"
            'while [[ $# -gt 0 ]]; do if [[ "$1" == --notes-file ]]; then cp "$2" '
            f'"{notes_copy}"; fi; shift; done\n', encoding="utf-8")
        for stub in stubs.iterdir():
            stub.chmod(0o755)
        workflow = _workflow("release.yml")
        env = dict(os.environ, PATH=f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}", RUNNER_TEMP=str(runner),
                   GITHUB_REPOSITORY="Veridor-authz/veridor", GITHUB_REF="refs/tags/v1.2.3", GITHUB_REF_NAME="v1.2.3",
                   PRERELEASE="false", DIGEST="sha256:" + "a" * 64, CHART_DIGEST="sha256:" + "b" * 64,
                   GH_TOKEN="not-a-token", **workflow["env"])
        result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                 release_notes_step(workflow)["run"]], cwd=work, env=env,
                                capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        notes = notes_copy.read_text(encoding="utf-8")
        commands = attestation_commands(notes)
        self.assertEqual(len(commands), 1, notes)
        self.assertIn("--cert-identity https://github.com/Veridor-authz/veridor/.github/workflows/release.yml"
                      "@refs/tags/v1.2.3", commands[0])
        self.assertIn("--repo Veridor-authz/veridor", commands[0])


if __name__ == "__main__":
    unittest.main()
