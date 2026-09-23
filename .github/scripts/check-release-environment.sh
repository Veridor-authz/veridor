#!/usr/bin/env bash
# Usage: check-release-environment.sh ENVIRONMENT
#
# Reads the settings of the GitHub environment a release.yml job runs in, and
# fails unless the environment requires at least one reviewer and does not let
# administrators bypass that. GitHub creates an environment a workflow names
# if it does not exist, with no protection, and lets administrators bypass the
# protection by default, so both are checked rather than assumed.
#
# If this passes, then when it ran the environment required a reviewer that
# administrators could not bypass, and GitHub held the job for an approval
# under those settings, unless they were changed while the job waited.
#
# It does not show who approved the job, or that anyone did: it reads the
# settings as they are now, not the approval. It does not check the tag rule
# on the environment or the repository's tag ruleset. And the workflow file of
# another commit need not run it at all, which is why the environment's
# reviewer is the control and this is only a check that it is set.
# CONTRIBUTING.md, "Releasing", lists what has to be set on GitHub.
#
# The answer is parsed as JSON and checked field by field, so an error body,
# empty output or anything else that is not those settings fails the job,
# whatever exit status gh returned with it.
set -euo pipefail

environment="${1:?usage: check-release-environment.sh ENVIRONMENT}"
if ! body="$(gh api "repos/${GITHUB_REPOSITORY:?}/environments/${environment}")"; then
  echo "::error::gh api could not read the ${environment} environment's settings (its error is above), so nothing shows that this job waited for a reviewer. Check that the job has permissions: actions: read, then re-run it."
  exit 1
fi

BODY="$body" python3 - "$environment" <<'PY'
import json
import os
import sys

environment = sys.argv[1]
where = f"Settings > Environments > {environment}"
try:
    settings = json.loads(os.environ["BODY"])
except ValueError:
    sys.exit(f"::error::the {environment} environment's settings did not come back as JSON "
             f"({os.environ['BODY'][:200]!r}), so nothing was checked")
if not isinstance(settings, dict) or not isinstance(settings.get("protection_rules"), list):
    sys.exit(f"::error::the answer for the {environment} environment has no protection_rules list "
             f"({os.environ['BODY'][:200]!r}), so nothing was checked")
reviewers = 0
for rule in settings["protection_rules"]:
    if isinstance(rule, dict) and rule.get("type") == "required_reviewers":
        if not isinstance(rule.get("reviewers"), list):
            sys.exit(f"::error::the {environment} environment's required_reviewers rule has no reviewers list")
        reviewers += len(rule["reviewers"])
if reviewers < 1:
    sys.exit(f"::error::the {environment} environment has no required reviewer, so nothing waited for an "
             f"approval. Add one ({where}), then re-run this job.")
if settings.get("can_admins_bypass") is not False:
    bypass = json.dumps(settings["can_admins_bypass"]) if "can_admins_bypass" in settings else "missing"
    sys.exit(f"::error::administrators can bypass the {environment} environment's required reviewer "
             f"(can_admins_bypass is {bypass}), so this job may have started "
             f"without an approval. Untick 'Allow administrators to bypass configured protection rules' "
             f"({where}), then re-run this job.")
print(f"the {environment} environment requires one of {reviewers} reviewer(s), and administrators cannot "
      "bypass it. These are its settings now; they do not show who approved this job.")
PY
