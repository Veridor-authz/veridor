#!/usr/bin/env bash
# Usage: check-release-commit.sh
#
# Reads GitHub's answer on the commit a release tag names, and fails unless
# that commit is on main and the CI workflow's newest push run on main for
# that commit concluded success. A v*.*.* tag on any commit otherwise starts a
# release, and lint, the end-to-end jobs, CodeQL and the macOS tests run only
# in CI, so nothing else would have asked whether they passed.
#
# It needs no secret: GITHUB_TOKEN with contents: read and actions: read. It
# does not read CodeQL or any other workflow, it does not show that the CI file
# was unchanged, and it reads the answer when it runs. A tag pushed before CI
# finishes fails here; re-run the release's failed jobs once CI is green.
#
# Each answer is parsed as JSON and checked field by field, so an error body,
# empty output or anything else fails the job, whatever exit status gh gave.
set -euo pipefail

: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
if ! compare="$(gh api "repos/${GITHUB_REPOSITORY}/compare/main...${GITHUB_SHA}?per_page=1")"; then
  echo "::error::gh api could not compare ${GITHUB_SHA} with main (its error is above), so nothing shows this commit is on main."
  exit 1
fi
if ! runs="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/veridor.yml/runs?head_sha=${GITHUB_SHA}&event=push&branch=main&per_page=100")"; then
  echo "::error::gh api could not list CI's runs for ${GITHUB_SHA} (its error is above), so nothing shows CI passed. Check that the job has permissions: actions: read, then re-run it."
  exit 1
fi

COMPARE="$compare" RUNS="$runs" python3 - <<'PY'
import json
import os
import sys

sha = os.environ["GITHUB_SHA"]


def answer(name, what):
    try:
        return json.loads(os.environ[name])
    except ValueError:
        sys.exit(f"::error::the answer on {what} did not come back as JSON "
                 f"({os.environ[name][:200]!r}), so nothing was checked")


compare = answer("COMPARE", "whether the commit is on main")
status = compare.get("status") if isinstance(compare, dict) else None
# compare/main...SHA: "behind" means main contains SHA and more, "identical"
# means SHA is main's head. "ahead" and "diverged" mean main does not contain it.
if status not in ("identical", "behind"):
    sys.exit(f"::error::{sha} is not on main (compare status {json.dumps(status)}). "
             "Merge it, then tag the commit on main.")

listing = answer("RUNS", "CI's runs")
if not isinstance(listing, dict) or not isinstance(listing.get("workflow_runs"), list):
    sys.exit(f"::error::the answer on CI's runs has no workflow_runs list ({os.environ['RUNS'][:200]!r}), "
             "so nothing was checked")
runs = [run for run in listing["workflow_runs"]
        if isinstance(run, dict) and run.get("head_sha") == sha and run.get("event") == "push"
        and run.get("head_branch") == "main" and isinstance(run.get("run_number"), int)]
if not runs:
    sys.exit(f"::error::CI has no push run on main for {sha}, so nothing shows it passed. CI runs on the "
             "newest commit of a push: tag a commit CI ran on.")
newest = max(runs, key=lambda run: run["run_number"])
if newest.get("status") != "completed" or newest.get("conclusion") != "success":
    sys.exit(f"::error::CI run {newest['run_number']} for {sha} is status {json.dumps(newest.get('status'))}, "
             f"conclusion {json.dumps(newest.get('conclusion'))}. Re-run this job once CI has passed on it.")
print(f"{sha} is on main ({status}), and CI run {newest['run_number']} for it concluded success.")
PY
