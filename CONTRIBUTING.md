# Contributing to Veridor

Thanks for looking. This document is short on ceremony and specific about the
two things that are unusual here: what the tests are for, and what Veridor is
allowed to claim. [GOVERNANCE.md](GOVERNANCE.md) says how decisions are made,
and [SUPPORT.md](SUPPORT.md) where questions go.

## Getting set up

Python 3.11 or newer, no dependencies.

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install -e .
python3.12 scripts/run_tests.py --tier fast
```

Name the interpreter version. On macOS the bare `python3` is 3.9 and
`requires-python = ">=3.11"` rejects it; on Homebrew and Debian-family systems
`pip install` into the system Python is refused by PEP 668.

## The two test tiers

```bash
python3.12 scripts/run_tests.py --tier fast            # every commit
python3.12 scripts/run_tests.py --tier slow --jobs 4   # before you open a PR
python3.12 scripts/run_tests.py                        # both, in one process
```

To run the fast tier on what you push, before it leaves your machine, install
the hook: `ln -sf ../../scripts/pre-push .git/hooks/pre-push`.

The split is enforced, not conventional. The fast tier runs with every route
to the network or to a new process replaced by one that raises: socket binds,
connects and sends, DNS lookups, `subprocess`, `os.system`, `posix_spawn`,
`fork` and `exec`, and multiprocessing, with an audit hook behind them
(`tests/tiers.py` lists them). A test that quietly starts touching the network
fails by name with the marker it is missing, and no fast test may spend more
than two seconds of CPU time and sleep, or 30 on the wall clock. The whole tier
may take 300 seconds. A busy machine does not fail the first limit, and the
messages for the other two say so. Only `time.sleep` counts as sleep, so a test
that waits some other way passes with a note up to the 30 and should be `@slow`
instead. If your test stands up a server, drives a real target, or spawns a
subprocess, mark it:

```python
from tiers import slow

@slow("stands up a loopback HTTP server")
class MyTest(unittest.TestCase):
    ...
```

A test that stands up an HTTP server starts it with `loopback.start(server)`
from `tests/loopback.py`, or `loopback.serve(server)` on a thread it manages.
It never calls `server.serve_forever()` directly. The standard library checks
for shutdown every 0.5 s, so every `shutdown()` waited about half a second.
`tests/test_loopback.py` refuses a `serve_forever` anywhere else under
`tests/`, and in a test process a server started any other way (through
`operator.methodcaller`, say, or `http.server.test`) is refused when it
starts, unless it polls as often as the helper's. A port the test closes and
later binds or connects to comes from `loopback.unallocated_port()`. It lies
outside the kernel's ephemeral range, so the kernel never hands it to another
process's `bind(0)` or `connect()` in between. Nothing reserves it, so
another process's own random pick could match it; under `--jobs` each worker
picks from its own share of those ports, so no two workers of one run pick the
same one, and a `--jobs` run started inside a worker splits only that worker's
share.

`--jobs N` runs the slow tier in N worker processes that take whole test
classes from one queue, and fails unless together they started exactly the
tests a serial run selects, each once. A class whose `setUpClass` or
`setUpModule` skipped in a worker runs again, alone, after the other workers
finish, so a skip caused by another worker's lock or port cannot excuse it.
Classes run in another order than they do serially, so a test must not
depend on another class having run first. Every tier, with `--jobs` or
without, fails when it selects no test, or does not start a test it selected
(a `SystemExit` from a class fixture used to end a serial tier with exit 0).

Some slow tests need a tool and skip without it. Set the matching variable to
turn the skip into a failure, as CI is configured to:

| Tool | Tests | Variable |
| --- | --- | --- |
| `helm` | `tests/test_helm_chart.py`, `tests/test_kustomize.py` | `VERIDOR_REQUIRE_HELM=1` |
| `kubectl` | `tests/test_kustomize.py` (`kubectl kustomize`) | `VERIDOR_REQUIRE_KUBECTL=1` |
| `shellcheck` | `tests/test_action.py` (`test_ci_configs.py` and `test_helm_chart.py` use it too, but skip without it whatever the variable says) | `VERIDOR_REQUIRE_SHELLCHECK=1` |

### Which Veridor the tests import

`tests/source_path.py` decides, once, for the whole suite.
`VERIDOR_TEST_AGAINST=source` (the default) puts `src/` first on `sys.path`;
`VERIDOR_TEST_AGAINST=installed` leaves it alone, so the suite tests the
Veridor installed in that interpreter:

```bash
python3.12 -m venv build/venv && build/venv/bin/python -m pip install dist/veridor-*.whl
VERIDOR_TEST_AGAINST=installed build/venv/bin/python scripts/run_tests.py --tier fast
```

A new test module imports it and never puts `src/` on `sys.path` or
`PYTHONPATH` itself, and neither does a script under `scripts/` that a test
imports or runs: `tests/test_packaging.py` parses all of them and fails on
every spelling it lists in `SRC_PATH_SPELLINGS`. A test spawns Veridor with the
same choice:

```python
sys.path.insert(0, str(ROOT / "tests"))
import source_path

subprocess.run([sys.executable, "-m", "veridor", ...], env=source_path.child_env())
```

### Before a pull request

Run the full suite and `python3.12 scripts/e2e_validation.py`.

If you touched the README or the configuration schema, run
`python3.12 scripts/blind_config_study.py`. It asks whether somebody could still
write a working configuration from the published documentation alone: every
documented example must load, every key a working config needs must appear in
the README, and a plausible first mistake must produce a refusal that names the
right key and says what it wanted. The suite runs it too. It is a mechanical
proxy for a user study, not a substitute for one.

If you changed the number of tests, run `python3.12 scripts/sync_doc_counts.py`:
the counts in `README.md` are asserted by a test.

## End-to-end checks

These drive the integrations the way their platforms would. None runs on the
platform itself; each says in its header what it stands in for.

**The GitHub Action.** `tests/action_harness.py` executes `action.yml`'s steps
in order under the runner's bash flags, with `GITHUB_OUTPUT`, `GITHUB_ENV` and
`GITHUB_STEP_SUMMARY` as real files. `tests/test_action.py` drives it with a
stub package and, in the slow tier, with the real one against the demo API:

```bash
python3.12 -m unittest tests.test_action -v
```

**The GitLab component.** `scripts/e2e_gitlab_job.sh` renders
`templates/veridor.yml` and runs the job's own script in docker against the
demo API. It needs docker, an image built from this repository, GitLab's SAST
report schema 15.2.5, and a Python that can import jsonschema.
`.github/scripts/fetch-schemas.sh` fetches the schema by a pinned URL and
checks its sha256, and `.github/requirements/schema-check.txt` pins jsonschema
and PyYAML by hash:

```bash
docker build -t veridor:e2e .
bash .github/scripts/fetch-schemas.sh build/schemas
python3.12 -m venv build/schema-venv && build/schema-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: -r .github/requirements/schema-check.txt
IMAGE=veridor:e2e SAST_SCHEMA=build/schemas/sast-report-format.json \
  PYTHON_WITH_JSONSCHEMA=build/schema-venv/bin/python bash scripts/e2e_gitlab_job.sh
```

Each control must end in exit `1`: `E2E_CONTROL=report-path-typo`,
`E2E_CONTROL=no-term-trap` and `E2E_CONTROL=proxy-kept`. The same Python
validates the CI templates against the platforms' published schemas:
`build/schema-venv/bin/python tests/ci_validate.py schemas --gitlab-schema build/schemas/gitlab-ci.json --azure-schema build/schemas/azure-pipelines.json`.

**Kubernetes, Argo CD and Argo Rollouts.** `scripts/e2e_kubernetes.sh` runs the
Helm chart, the Kustomize overlays, a PostSync gate and a canary analysis on a
kind cluster, each against a vulnerable and a fixed target. It needs bash,
docker, kind, kubectl, helm, python3 and git:

```bash
E2E_CREATE_CLUSTER=1 KUBE_CONTEXT=kind-veridor-e2e bash scripts/e2e_kubernetes.sh
```

`KUBE_CONTEXT` must name a kind cluster; the current context is never read or
changed. `E2E_CONTROL=gate-passes-wrongly` must end in exit `1`. The script
uses fixed `vg-e2e-*` namespace names and removes leftovers when it starts, so
it first takes a lock in the cluster, the `vg-e2e-lock` namespace. A second run
against the same cluster while one holds it exits `2`, names the holder and
touches nothing; run them one at a time, or on separate kind clusters. A lock
left by a dead run is broken by `E2E_BREAK_LOCK=1` once it is over an hour
old, or by deleting the namespace yourself.

## What a good change looks like

**Write the test that fails first.** Not as ritual: a surprising number of the
bugs found in this codebase were found by writing an assertion and discovering
it passed against broken code. If you cannot make your new test fail by breaking
the thing it covers, it is not testing that thing. Several tests here carry a
comment recording exactly which mutation they were confirmed to catch, and that
is a good habit to copy.

**Explain the why, not the what.** The diff already says what changed. Comments
and commit messages here are for the reasoning that is not recoverable from the
code: the hazard avoided, the alternative rejected, the failure that motivated
a guard. A comment restating the line below it is noise.

**Match the surrounding code.** No third-party runtime dependencies: the runtime
is standard library only, and `tests/test_stdlib_only.py` asserts it by
AST-scanning every import in `src/veridor/**`. Tests may not add dependencies
either.

### Commit messages

The subject says what changed. The body says why it was wrong before, and how
you know: the command you ran and what it printed, or the input that broke it.
If something was not measured, say so rather than implying it was.

```text
Refuse a ${NAME} that is set but empty, like an unset one

Only `name not in os.environ` was refused, so an empty value was
substituted and the run went ahead. Reproduced on the demo target: an
empty owner token reported unexpected_denial and exited 1, a
configuration problem reported as a finding about the target.
```

## Claim discipline

This is the part to read even if you skip the rest. Veridor's value is that it
does not overstate, and every one of these is enforced by a test that will fail
your build:

- **Boundary coverage is ASSERTED, never ENFORCED.** It counts operations for
  which you declared a cross-identity denial. It says nothing about whether the
  target enforces one.
- **A candidate is a hypothesis, never a finding.** `map` produces no SARIF,
  never enters the run history, and nothing it discovers changes an exit code.
- **A mutation score measures your declaration, not your target.** A surviving
  mutant means a check may be vacuous, not that the system is broken.
- **Blast radius counts operations, not objects.** An operation counted as
  reached may expose one record or every record.
- **The marker oracle proves data flow, never policy.** `confirmed` means a
  string that exists only in one identity's data appeared in another's
  response. Whether that is *allowed* is the operator's declaration, not
  Veridor's judgement.
- **Drift reports what moved, and never why.** Reach that opened may be a
  feature you shipped; reach that closed may be a broken deploy.

Words like *vulnerable*, *exploit*, *proven* and *secure* are banned from
several report surfaces by test. If a change makes a claim stronger than the
evidence supports, that is a defect here, the same as a crash.

A useful check on any new message: **could a reader act on this and be wrong?**

## Pull requests

Keep them focused, explain the reasoning in the description, and say what you
ran and what you did not. If you found a real problem with the approach, say
so: a PR that argues with the design is welcome, one that silently works around
it is not.

Security issues go through [SECURITY.md](SECURITY.md), not a pull request.

## Repository settings

For maintainers. These live in GitHub's settings, where no test can read them,
so the tree cannot show whether they are on. A fork or a new copy of the
repository has none of them. What they do on GitHub is from GitHub's
documentation; as of 2026-11-04 nothing here has been run there.

- **Private vulnerability reporting: on.** [SECURITY.md](SECURITY.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) send reports to that form, and it is
  unavailable until this is on. Open the form from a second account to check.
- **Branch protection on `main`.** Block force pushes and deletion, and require
  the `Tests` jobs in `.github/workflows/veridor.yml` to pass, which also stops
  a direct push to `main`. Do not require a review while there is one
  maintainer: GitHub does not let an author approve their own pull request, so
  `.github/CODEOWNERS` asks for a review and requires none. Open that file on
  GitHub to see whether it flags the owner as invalid.
- **Secret scanning and push protection: on.** CI runs no secret scan as a gate
  (`scripts/secrets_audit.py` is deliberately not one).
- **The `claim-discipline` label.** `gh label create claim-discipline`. GitHub
  leaves out a label the repository does not have, so until then an overclaim
  report carries `bug` only.
- **Discussions: off.** Questions go through the "Question" issue form. Turning
  Discussions on means adding it to the code of conduct's scope.
- **About panel.** Use the `description` in `pyproject.toml`, its `Homepage`
  (https://veridor.org/) as the website, and its `keywords` as topics.

Two things that can look like defects and are not. Neither has been seen on
GitHub yet:

- **Red Dependabot pull requests.** A bump of the Dockerfile's digest fails
  `tests/test_ci_configs.py` until the GitLab component names the same digest,
  and a bump of the PyPI publish action fails `tests/test_workflows.py` until
  its digest is recorded. `.github/dependabot.yml` says why. Fix the second
  value on the pull request's branch.
- **A low OpenSSF Scorecard result.** `.github/workflows/scorecard.yml` has
  `publish_results: true` and runs on each push to `main`, so the score is public
  under the repository's name. The pinned
  `fixtures/pairs/recipes/datasette/requirements.txt` is a test target's lock
  file, not something users install, and a vulnerability check may still flag it.

## Releasing

For maintainers. This is the procedure `.github/workflows/release.yml` expects.
It had not been run end to end before the first release was tagged.

Every job in `release.yml` that publishes (provenance, PyPI, the image, the
chart, the GitHub release) runs in one protected environment, `release`, and
GitHub holds each of those jobs until a required reviewer approves it. For
PyPI this does not rest on the workflow file: the trusted publisher below
names `release`, so a workflow at another commit that left the environment
out could not upload. The image, chart and release jobs push with GITHUB_TOKEN,
which no environment gates. For them the environment holds this workflow's
jobs only. What limits any other workflow is who can push `v*` tags and
branches: the ruleset and write access below. Set these once, before the
first release.

On GitHub, under the repository's Settings:

- **Environments, `release`.**
  - Add the maintainers as required reviewers. While there is one
    maintainer, leave "Prevent self-review" off, or nobody can approve that
    maintainer's own tag.
  - Untick "Allow administrators to bypass configured protection rules". Left
    ticked, an administrator can start a held job without any approval.
  - Under deployment branches and tags, choose "Selected branches and tags"
    and add one tag rule, `v*`, so a run on a branch cannot use the
    environment.
- **Rules, Rulesets: a tag ruleset**, active, for tags matching `v*`, with
  "Restrict creations", "Restrict updates" and "Restrict deletions", and only
  the maintainers on its bypass list. A `v*` tag is what starts a release and
  what the environment's tag rule admits, so this decides who can start one,
  and nobody off the bypass list can move or delete a pushed tag.

On PyPI, add a trusted publisher for this repository with workflow
`release.yml` and environment `release`. Before the project exists on PyPI,
add it as a pending publisher. PyPI then accepts an upload only from a job
that ran in `release`, whichever commit's workflow ran it. The provenance,
image and chart jobs can mint the same token, because they run in `release`
too. They wait for the same kind of approval. Do not count on a pending
publisher to hold the name: check PyPI's documentation, and until the first
upload treat the name as open to anyone.

Expect to approve each publishing job in turn, since GitHub holds every job
that uses the environment. As of 2026-11-08 this has not been seen on GitHub,
because the release workflow has not run there. Rejecting a job stops the jobs after it.

What the workflow checks by itself, before anything is built: the `verify` job
fails unless `IMAGE` and `CHART_REPOSITORY` sit under `ghcr.io/<owner>/` for
the repository running it, lowercase, the chart's default image is `IMAGE` and
`pyproject.toml` names that repository. It also fails unless the tagged commit
is on `main` and the CI workflow's newest push run on `main` for that commit
passed (`.github/scripts/check-release-commit.sh`). So push the commit, wait for
CI, then tag it. CI runs on the newest commit of a push, so a commit in the
middle of one cannot be tagged. Neither check had run on GitHub before the
first release.

Each job in `release` also first runs
`.github/scripts/check-release-environment.sh`. The job fails unless
`release` requires at least one reviewer and administrators cannot bypass
it. GitHub creates an environment the first time a workflow names it, with no
protection, so without this check a missing setting would publish with no
approval. The script reads the settings when the job starts. It does not
show who approved the job, or that anyone did. It does not check the tag
rule or the ruleset. A workflow file at another commit need not run it at
all. The settings above are the control, and the check only confirms two of
them.

What none of this covers: anyone who can push a branch can run a workflow of
their own that asks GITHUB_TOKEN for `packages: write` or `contents: write`.
That workflow can push to the ghcr packages or change a release without
using the environment. Keep write access to the repository to the
maintainers.

1. **Bump.** `python3.12 scripts/release_check.py bump X.Y.Z` prints the diff
   for every place the version is written; add `--write` to apply it. It
   refuses if the tree holds a version string it does not know about. Register
   a new one in `REGISTRY` in `scripts/release_check.py` rather than editing it
   by hand. A pre-release is `X.Y.ZrcN`; the tool writes the SemVer spelling
   (`X.Y.Z-rc.N`) where a tag, image or chart needs it.
2. **Changelog.** Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, drop
   its opening paragraph that says nothing has been released, and add an empty
   `## [Unreleased]` above it. The GitHub release's notes come from that
   section: `python3.12 scripts/release_check.py notes vX.Y.Z` prints all of
   its text before its first `###` heading, every paragraph of it, if there is
   any, and a link to the section in `CHANGELOG.md` at the tag, and the
   release stops in its first job if it cannot. It refuses a missing or empty
   section, a section that still says it is not released, and an
   `## [Unreleased]` with anything under it. The notes are not the whole section because GitHub
   refuses a release body over 125,000 characters: the first release's
   section was about 223,000, and its release job failed after everything
   else had published.
   So the first job also runs `release_check.py release-body vX.Y.Z`, which
   runs the release job's "Create the release" step with `gh` stubbed and
   placeholder digests, and fails if what it would post is empty or over the
   limit. To run it locally, add `--repository Veridor-authz/veridor --image
   ghcr.io/veridor-authz/veridor --chart-repository
   oci://ghcr.io/veridor-authz/charts`. Write the text before the first `###`
   for a reader of the release page, upgrade notes included: it is all of the
   section they see there. Nothing is cut to fit; over the limit, `notes`
   fails.
   For the first release:
   `## [0.1.0]` already exists and was never tagged, so a 0.1.0 release folds
   `[Unreleased]` into it and replaces its "Not released" paragraph.
3. **Statements the release makes false.** Rewrite the dated "no release"
   sentences: the README's Install section, CI/CD integrations intro, GitHub
   Action and GitLab sections, both in `SECURITY.md`, `SUPPORT.md`, and the ones
   in `ci/`, `templates/veridor.yml` and `deploy/`, and the warnings that the PyPI
   name is unclaimed. In `ci/azure-pipelines.yml` and `ci/buildspec.yml`, replace
   the wheel path that stops the install step with a pin of the released version.
   These tests hold those sentences, so change them in the same commit:
   `tests/test_action.py`, `tests/test_kustomize.py`,
   `test_each_file_says_what_the_first_release_publishes` in
   `tests/test_ci_configs.py`,
   `test_the_action_examples_pin_a_commit_never_a_tag` in
   `tests/test_release_files.py`,
   `test_the_released_version_is_dated_and_says_so` and
   `test_the_table_claims_nothing_exists_that_does_not` in
   `tests/test_governance_docs.py`, and
   `test_the_changelog_states_the_break_under_changed` in `tests/test_docs.py`.
   `REGISTRY` in `scripts/release_check.py` matches some of those sentences
   (`Not published at`, `At chart version`), so `versions` names any you rewrote
   past it. `README.pypi.md`, the readme `pyproject.toml` names, is the PyPI
   description, and an uploaded version's page cannot be replaced: `notes`
   refuses any shipped file except
   `tests/`, `CHANGELOG.md`, this file and `scripts/release_check.py` that still
   holds one of the phrases in `_PRE_RELEASE_STATEMENT`, and `dist --tag` refuses a
   wheel or sdist whose description does. Those rules read phrases, not meaning, so
   a sentence worded another way passes: read the sections as well, and the first
   paragraphs of this section. PyPI has no base URL for a
   repository-relative link and gives headings no ids, so `README.md` keeps
   its GitHub links and `README.pypi.md` uses only absolute ones: `dist`
   refuses a wheel or sdist whose description has any other link, on every
   build, and `PyPIDescriptionTest` in `tests/test_release_files.py` holds
   each of its links to a file or README heading in the tree and its first
   paragraph to the README's.
4. **Check.** `python3.12 scripts/release_check.py versions --tag vX.Y.Z`, the
   full suite, and the end-to-end checks above.
5. **Tag.** Dispatch `.github/workflows/veridor.yml` on a branch other than `main`
   (`gh workflow run veridor.yml --ref BRANCH`) and check that its "Upload the
   vulnerable run's SARIF to code scanning" step passed: only a manual run asks
   GitHub to accept the SARIF, so nothing else shows the upload still works.
   Push the commit to `main`, wait for CI to pass on it, then push an
   annotated tag `vX.Y.Z` on that commit. The workflow checks that the commit
   is on `main` and CI passed, checks the version against the tag, runs the
   suite on 3.11, 3.12
   and 3.13, builds and checks the dist files, and runs every
   published-advisory pair (`scripts/patched_pairs.py`) against the built wheel,
   which downloads 2.42 GB of images and package files (compressed,
   linux/amd64). Nothing is
   published before those pass. Then the jobs publish in order: provenance,
   PyPI, the image, the chart, the GitHub release. Each waits in the `release`
   environment for your approval, and each needs the one before, so a
   failure or a rejection stops the rest. Finish with "Re-run failed jobs" on
   the tag's run. That includes a PyPI upload that stopped part-way: the
   re-run uploads the same files, and PyPI's upload code accepts a file whose
   name and hashes it already holds (read there, not run). A file of the same
   name with different bytes is refused, which is why the workflow does not
   use `skip-existing`. There is no moving major tag (`v0`, `v1`) while the version
   is `0.x`: users pin a full commit SHA.
6. **Public packages.** A new ghcr package may start private, which would leave
   every default image and chart answering `denied` to users. That comes from
   GitHub's documentation as recalled, and has not been seen. `github-release`
   runs `scripts/anonymous_pull_check.py` with no login before it posts anything,
   and fails until both are served. If it fails, set the `veridor` image and the
   `charts/veridor-gate` package to public in each package's settings on GitHub,
   then re-run that job.

`python3.12 scripts/release_check.py identity` lists every use of the
organisation, registry and domain names (`github.com/Veridor-authz`,
`ghcr.io/veridor-authz` and the rest), in any case, for when those change.
It exits 1 on a name in `IDENTITY_RETIRED`, the namespaces this project does not
hold, in any case and with a regex source's escapes. That is a list of spellings,
so one it does not cover passes. It does not list `scripts/release_check.py` or
`tests/test_release_check.py`, so a rename changes the patterns and release
literals there by hand.

## Signing off your commits (DCO)

Every commit in a pull request carries a sign-off under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO). A
`Signed-off-by` line is your statement that you can make the DCO's
certification for that change, and that you understand the contribution and the
sign-off are public and kept with the project. `git commit -s` adds it:

    Signed-off-by: Your Name <you@example.com>

using the name and email you commit as; the sign-off has to match the commit's
author. Nothing checks it on pull requests yet, so a reviewer does. Commits
merged before this section was written carry no sign-off.

## AI-assisted commits and provenance

A commit written with AI assistance has a human author: the maintainer or
contributor who reviewed it, understands it and answers for it, and who adds the
`Signed-off-by` above. A tool is never recorded as an author or co-author and
cannot sign off, because it cannot make the DCO's certification. No commit in
this repository's history has a tool as its author or co-author.

## Licence

By contributing you agree that your contributions are licensed under the
Apache License 2.0, the same as the rest of the project.
