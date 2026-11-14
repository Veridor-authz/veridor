# Veridor guide

Veridor is a CI-first **authorization regression runner**. You declare what each
identity is allowed to do; Veridor issues the same request as every declared
identity, compares what happened against what you declared, and fails the build
when the answer changes. It is not a scanner and not a pentest: it invents no
policy, discovers no routes, sends no payloads, and cannot tell you whether your
declaration is right — only whether your target still agrees with it. Read
[what a finding does and does not mean](#what-a-veridor-finding-does-and-does-not-mean)
before you read a report. Runtime is the Python standard library only.

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/veridor)](https://artifacthub.io/packages/helm/veridor/veridor-gate)

**Status: early alpha.** Each release is listed in [CHANGELOG.md](../CHANGELOG.md).
The configuration format, commands, flags and report formats may still change
between minor versions. What Veridor does not claim is set out in
[what a finding does and does not mean](#what-a-veridor-finding-does-and-does-not-mean)
and [Non-goals](#non-goals).

Veridor is an independent personal project. It is not affiliated with or endorsed by any employer.

## The three verbs

Everything Veridor does is one of three questions, asked in this order.

| Verb | The question | What you get |
| --- | --- | --- |
| [`map`](#map-what-would-a-compromise-reach) | What don't I cover, and what would a compromise reach? | An access matrix, a blast radius per identity, boundary coverage, ranked anomaly candidates, and a [diff against last week's matrix](#drift-catching-a-regression-with-nothing-declared) |
| [`run`](#run-does-the-boundary-hold-and-did-it-change) | Does the boundary hold, and did it change? | Findings, evidence grades, a baseline diff, SARIF, and the CI exit code |
| [`mutate`](#mutate-would-my-suite-catch-a-regression) | Would my suite actually catch a regression? | A mutation score and every mutant your checks failed to kill |

**Discover, declare, gate, then verify the gate.** `map` proposes; you decide
what to declare; `run` holds you to it; `mutate` tells you whether holding you
to it means anything.

Only `run` gates on what it *discovered*. `map` exits `0` no matter what it
finds — an inconsistency it noticed is a hypothesis, not a finding, and
discovery must never fail somebody's build. The single exception is opt-in and
is not about a finding at all: `--fail-on-drift` fails when this run's matrix
differs from a baseline you recorded earlier, which is a fact about two runs
rather than a judgement about one. `mutate` has its own exit code that is never
a run's; a surviving mutant says your *declaration* is weak, not that your
*target* is broken.

`capsule`, `init`, `coverage`, `new-marker`, `report` and `serve` are utilities
you reach for while using the three verbs, not headline commands. `veridor --help` shows
the same split.

## Install

Python 3.11 or newer. No runtime dependencies. Installing from source with pip
fetches setuptools from PyPI to build the package; the zipapp below needs no
index to build or run.

Each release tag publishes the
`veridor` package to PyPI, the image to `ghcr.io/veridor-authz/veridor`, the
Helm chart and a GitHub release with the zipapp and `SHA256SUMS`. The
repository's Releases page lists every release. You can also install from
source or build the image or the zipapp yourself.

| How | From a release | Built yourself |
| --- | --- | --- |
| pip | `pip install veridor==X.Y.Z` | From source, below |
| Container image | `ghcr.io/veridor-authz/veridor:X.Y.Z` | `docker build -t veridor:local .` |
| Zipapp, one file | `veridor-X.Y.Z.pyz` with `SHA256SUMS` on the release | `python3.12 scripts/build_zipapp.py` writes `dist/veridor-<version>.pyz` |

From source:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install .
veridor --version
```

```
veridor 0.1.0
```

The virtual environment is not ceremony. `python3 -m pip install .` is refused
outright on Homebrew Python and on any Debian or Ubuntu system Python — PEP 668
answers it with `error: externally-managed-environment` — and on macOS the bare
`python3` is 3.9, which `requires-python = ">=3.11"` rejects as well. Both
obvious interpreters fail, so name the version and give it its own environment.
`pipx install .` works too if you want the binary on your PATH without
activating anything.

The zipapp needs Python 3.11 or newer (`python3.12 dist/veridor-<version>.pyz
run ...`); run on 3.11 it gated the demo API correctly, and 3.9 refused it
with exit `2`.
The image runs as uid 10001 with `veridor` as its entrypoint; the comment at
the top of the [Dockerfile](../Dockerfile) shows how to run it on a mounted
directory, which uid 10001 has to be able to write.
It is built on `python:3.12-alpine` (musl): 20.9 MB compressed for linux/amd64
and 21.4 MB for linux/arm64, from OCI exports on 2026-09-27. It has no bash
and no pip, and building it needs BuildKit, because the wheel is installed
from a build mount. Its CA bundle is Alpine's, which lacks some legacy roots
Debian's still carries, DigiCert Global Root CA and GlobalSign Root CA among
them. For a target whose certificate chain ends at one of those, mount a file
that holds it and point `SSL_CERT_FILE` at it:
`docker run -v "$PWD/ca.pem:/certs/ca.pem:ro" -e SSL_CERT_FILE=/certs/ca.pem ...`.
The file adds to the image's roots; it does not replace them. OpenSSL still
reads the 121 roots in `/etc/ssl/certs`, so every public CA the image trusts
can still vouch for the target. To trust only the mounted file, for example a
private CA, also point `SSL_CERT_DIR` at a directory that holds no
certificates: `-e SSL_CERT_FILE=/certs/ca.pem -e SSL_CERT_DIR=/nonexistent`.
Veridor has no TLS setting of its own, and a configuration that names one
(`client_cert`, `ca_file`, `verify_tls` and the like) is refused.

CI is configured to run the full fast tier on every version that floor allows
(3.11, 3.12 and 3.13), plus a wheel build and install, because running from a
checkout proves nothing about installing. Every job passed on GitHub-hosted
runners on 2026-11-08 (CI run 42508338432, at `38025ed`), while the repository
was still private.

Releases are configured to be tagged `vX.Y.Z`. The image gets `X.Y.Z`, plus
`X.Y` and `latest` for a final release. There is no moving major tag (`v0`,
`v1`) while the version is `0.x`, because a minor release may change
behaviour: pin a version. For the Action, pin a full commit SHA. For the
GitLab component, include it from the commit the release tag points to, with
an `integrity` hash, not from the tag URL ([GitLab CI](#gitlab-ci) shows how).

## CI/CD integrations

What each integration is, and exactly what had been executed for it as of
2026-11-08. The Kubernetes rows have run on the system they target, on kind
clusters, locally and in this repository's CI on a GitHub-hosted runner. The
GitHub Action has run through `uses: ./` in that same CI, which was private
then; **every other row ran outside its platform**.
The image, chart and package names in these files are the ones each release
tag publishes.

| Integration | Files | What has been executed | Not yet |
| --- | --- | --- | --- |
| [GitHub Action](#github-action) | [action.yml](../action.yml) | Its steps, run in order by a local harness under the runner's bash flags, against the demo API: vulnerable fails the step with exit 1, fixed passes (`tests/test_action.py`); the `action-e2e` CI job through `uses: ./` on GitHub-hosted `ubuntu-latest` and `macos-latest`, same result (2026-11-08) | A run from another repository; a SARIF upload to code scanning; Windows runners |
| [GitLab CI/CD component](#gitlab-ci) | [templates/veridor.yml](../templates/veridor.yml) | The job's own rendered script in docker against the demo API, last run locally 2026-09-27, on the Alpine image ([counts and controls](../ci/README.md#what-was-tested)), and with its three controls in CI on a GitHub-hosted runner on 2026-11-08, covering exits 0, 1, 2, 3 and 143, every report, every input that changes the script, and proxy variables set as pipeline variables (`scripts/e2e_gitlab_job.sh`); the YAML against GitLab's CI schema | A GitLab runner; the CI/CD Catalog |
| Argo CD PostSync gate, Helm | [deploy/helm/veridor-gate](../deploy/helm/veridor-gate/README.md), [deploy/argocd](../deploy/argocd/README.md) | A kind cluster with Argo CD v3.5.3, locally and on a GitHub-hosted runner (`scripts/e2e_kubernetes.sh`): a vulnerable target fails the sync, a fixed one succeeds, each sync that runs hooks read from a gate Job of its own (`generateName`); a selective or Apply Only sync runs no hook and no gate; also as a Helm hook and a plain Job | Other clusters and Argo CD versions; a run from the published chart |
| Argo CD PostSync gate, Kustomize | [deploy/kustomize/veridor-gate](../deploy/kustomize/veridor-gate/README.md) | Not provided: Kustomize refuses the `generateName` an Argo CD hook Job needs, so with Argo CD use the Helm chart. The plain overlay ran in the same kind run: vulnerable Job `Failed`, fixed `Complete`, and its README's delete/apply/wait block | Standalone kustomize, Flux |
| Argo Rollouts analysis | [deploy/argo-rollouts](../deploy/argo-rollouts/README.md) | The same kind run with Argo Rollouts v1.10.0: a vulnerable canary is aborted, a fixed one promoted | A traffic router |
| Jenkins | [ci/Jenkinsfile](../ci/Jenkinsfile) | The gate shell, run on a host against the demo API (`tests/test_ci_configs.py`); the file accepted by Jenkins' declarative linter | A Jenkins build |
| Azure Pipelines | [ci/azure-pipelines.yml](../ci/azure-pipelines.yml) | The gate shell, run on a host; the YAML against Azure's pipeline schema | An Azure run |
| AWS CodeBuild | [ci/buildspec.yml](../ci/buildspec.yml) | The gate shell, run on a host; the keys against AWS's buildspec reference | A CodeBuild build |
| Any CI, container image | [Dockerfile](../Dockerfile) | Built locally and run as the job image in the GitLab run above; built and run as the gate by the `image` CI job on a GitHub-hosted runner (2026-11-08) | A run from the published image |
| Any CI, zipapp | [scripts/build_zipapp.py](../scripts/build_zipapp.py) | Built, then run on Python 3.11 against the demo API: vulnerable exits 1, fixed 0 | A run of the release asset |

[ci/README.md](../ci/README.md#what-was-tested) has the detail for GitLab,
Jenkins, Azure and CodeBuild, and the READMEs under `deploy/helm`,
`deploy/kustomize`, `deploy/argocd` and `deploy/argo-rollouts` say what the
kind runs measured.

## Quickstart: your first 60 seconds

You do not need an API of your own. The repository ships a deterministic demo
target with a real cross-tenant bug behind a flag.

> **From a `pip install`, skip to [your own API](#against-your-own-api) below.**
> The demo target and the fixtures below live in the git repository, not in the
> distribution — a wheel carries the `veridor` package and nothing else. Running
> the next command against an installed wheel gives you
> `veridor: configuration not found: fixtures/veridor.demo.json`, which reads
> like a broken install and is not one. Clone the repository to follow along.

```bash
python3 scripts/demo_server.py --vulnerable &
veridor run --config fixtures/veridor.demo.json --sarif veridor.sarif
```

If port 8765 is already taken, the demo server prints `cannot listen on
127.0.0.1:8765`, exits `2`, and does **not** start — whatever else owns that
port would answer the probes instead, and a green run against it would say
nothing about this demo. Run it elsewhere and point the command at it:
`python3 scripts/demo_server.py --vulnerable --port 8799 &` then
`veridor run --config fixtures/veridor.demo.json --base-url http://127.0.0.1:8799`.
Every run prints its own `Target:` line, so you can always see what the verdict
above it was a verdict about.

```
Veridor run 20260731T224235Z-ddccef: 5/6 probes matched their declaration, 1 vulnerable, 0 unexpected denial, 0 inconclusive
Target: http://127.0.0.1:8765
Regression diff: no baseline given, so every finding (1) counts as new
Evidence: 1 confirmed, 0 suspected, 0 ungraded
Scope: Veridor evaluates the expectations you declared. A finding means observed behaviour differed from your declaration; it does not establish that the declaration is correct.
Pass: A matched probe means the target agreed with your declaration for that one request. It is not evidence that the boundary is enforced, and an expectation that accepts both access and denial matches trivially.
- [vulnerable (confirmed)] invoice-tenant-isolation / other_tenant: Identity 'other_tenant' received HTTP 200 (declared: one of [404]) and the response carried 'invoice_owner''s marker: 'invoice_owner''s declared marker was observed in 'other_tenant''s response. That is proof the string crossed, and proof of data flow insofar as the marker is unique to 'invoice_owner''s data. You declared that 'other_tenant' must not receive 'invoice_owner''s data, and Veridor measured that it did. Whether that declaration is correct is not something Veridor can check.
```

Exit code `1`, and `veridor.sarif` is ready for code scanning. `confirmed` is
the strongest evidence Veridor produces: the other tenant's response literally
contained a string that exists only in the owner's data. Restart the demo
without `--vulnerable` and the same command exits `0` with `6/6 probes matched`.

Runs are persisted under `.veridor/runs`, and `.veridor/latest.json` points at
the newest. Every run rewrites `latest.json`, so it cannot be the `--baseline`
of a run into the same `--output-dir` (that is refused with exit `2`: the run
would compare a live finding against itself on the re-run); copy it to a file
of its own and pass that. `veridor serve` opens a local viewer on
<http://127.0.0.1:8787> covering **all three verbs** — see
[The local viewer](#the-local-viewer) below.

<a id="against-your-own-api"></a>
### Against your own API

**You do not need an OpenAPI specification to gate a build.** `run`, `mutate`,
`capsule` and `verify` take a hand-written `veridor.json` and nothing else —
that is the entire gate: detection, evidence grades, the regression diff, SARIF,
and a portable proof. Only `map`, `init` and `coverage` require a spec, because
they read a route inventory and Veridor never discovers routes on its own.

If you have no spec, either write the config by hand from
[Configure](#configure), or write a route-list stub — empty operation objects
are enough, and this unlocks `map`, `init` and `coverage` completely:

```json
{"openapi": "3.0.0", "info": {"title": "mine", "version": "1"},
 "paths": {"/api/invoices": {"get": {}}, "/api/invoices/{id}": {"get": {}},
           "/api/admin/audit": {"get": {}}}}
```

With a specification, start from a specification. There are two on-ramps, and
the right one depends on whether you want to write down your policy today.

**If you don't** — start here. Nothing is declared, and the first useful run is
three commands away:

```bash
veridor init --for drift --openapi openapi.json --output veridor.json
```

Output below is the real thing, against the demo specification this repository
ships:

```
Wrote a drift scaffold for 4 paths to veridor.json  (--for drift: no checks, nothing declared)
  target.base_url: http://127.0.0.1:8765  (spec)
  Confirm that URL names a test environment before running.

  1 route(s) need a real object id. Until each one has a specimen it is
  not probed at all, and `map` refuses to send REPLACE-WITH-A-REAL-ID:
    /api/invoices/{id}

Next:
  1. export VERIDOR_OWNER_TOKEN=... VERIDOR_OTHER_TENANT_TOKEN=...
  2. replace every REPLACE-WITH-A-REAL-ID with an id that exists and belongs to 'owner'
  3. veridor map --config veridor.json --openapi openapi.json --matrix veridor/baseline-matrix.json
     # records the baseline. Finds nothing, and says so
  4. git add veridor/baseline-matrix.json && git commit -m 'record the authorization baseline'
     # a gate compares against a committed FILE. A CI runner has no .veridor/ from last
     # week, and a DIRECTORY of matrices resolves to the newest -- which after one
     # failed build is the run that recorded the regression
  5. veridor map --config veridor.json --openapi openapi.json --baseline veridor/baseline-matrix.json --fail-on-drift opened

Step 3 is not a test and cannot fail. Step 5 fails only when an identity that was
refused is now served, or another identity's marker turns up in a response — a fact
about two runs, not a verdict on your API.
Drift is blind to anything that did not change. An endpoint open to everyone since
before step 3 never moves, so it never appears. That is what `veridor init --for run`
and declared checks are for. Coverage reports this scaffold as unreviewed until you delete "_generated_by".
```

Two credentials and one real object id per templated route — that is the whole
setup, and none of it is a policy. The placeholder is a value `map` **refuses to
send**: a fake id would 404, a 404 is recorded as `refused`, and a grid of
refusals reads exactly like a boundary that holds. See
[drift](#drift-catching-a-regression-with-nothing-declared) for what that buys
you and what it stays blind to.

**If you do want to declare expectations**, scaffold the checks instead. This is
the stronger claim and it costs more up front:

```bash
veridor init --openapi openapi.json --output veridor.json
```

```
Wrote 5 checks from 4 paths to veridor.json  (--for run: you declare the policy, `run` gates on it)
  target.base_url: http://127.0.0.1:8765  (spec)
  Confirm that URL names a test environment before running.

  This scaffold contains DELETE, POST checks. Running it writes to the target.
  Delete those checks, or pass --read-only to refuse them before anything is sent.

Next:
  1. read every check: they are the tool's guesses, not your policy
  2. decide about the DELETE, POST checks: delete them, or keep them knowing they write
  3. export VERIDOR_OWNER_TOKEN=... VERIDOR_OTHER_TENANT_TOKEN=...
  4. replace the path placeholders in 2 checks with real resource ids
  5. veridor run --config veridor.json --openapi openapi.json --coverage coverage.json
     add --read-only to that command to refuse the DELETE, POST checks instead of
     issuing them: it exits 2 and names the check, before anything is sent.

Every check is a claim you are making about your API, not a measurement. Edit before you trust.
Expect the first run to be red: this file guesses that 'owner' is allowed everywhere,
including on routes no owner is entitled to. Coverage reports this scaffold as unreviewed until you delete "_generated_by".

If writing that policy is not where you want to start, `veridor init --for drift`
scaffolds the other path: no checks, no expectations. It records what your API does
today and later runs report what moved.
```

`init` refuses to overwrite an existing file unless you pass `--force`, and it
never writes over the specification. **The generated expectations are claims,
not measurements** — read them, delete the checks whose operations have no
authorization boundary, and replace `{id}`-style path placeholders with real
resource identifiers before you trust anything the run says.

Two things follow from that, and both are deliberate. The first run of an
unedited scaffold is red, because the file guesses that `owner` is allowed on
every operation the specification declares — including admin routes no owner is
entitled to. And the same scaffold scores 100% boundary coverage of every
operation the specification does not mark public, because every such generated
check asserts a denial for `other_tenant`; that is a restatement of
the scaffold, not a measurement of anything you decided. So while the file still
carries the `_generated_by` key that `init` wrote, `veridor coverage` prints
`THIS NUMBER IS NOT YOURS YET` and `--badge` renders `unreviewed` rather than a
percentage. Delete the key when you have read the checks, and the number becomes
yours.

An operation the specification marks public (`security: []`, or a requirement
list offering `{}`) gets no denial: its `other_tenant` expectation accepts both
access and denial, so `run` reports it as asserting nothing rather than
scaffolding a refusal the specification itself contradicts.

## Map: what would a compromise reach?

`veridor run` answers questions you already thought to ask. `veridor map`
answers the one you did not: *given the routes this API actually has, what can
each identity reach, and where do the answers contradict each other?*

The output below is against the **vulnerable** demo target — the same
`python3 scripts/demo_server.py --vulnerable &` the quickstart started. If you
restarted it without `--vulnerable`, restart it with the flag before running
this, or `map` correctly reports `0 candidates.` and the example will look like
it contradicts the document.

```bash
veridor map --config fixtures/veridor.map-demo.json \
            --openapi fixtures/openapi.demo.json \
            --promote candidates.json
```

Abridged — the real report also prints the plan banner, per-identity reach, and
the coverage scoreboard:

```
Observed reach (lower bound), identity "other_tenant": at least 1 of 5 probed operations returned a success status.
  reached 1   refused 2   unresolved 0   unmeasured 2   of 5
  no share is rendered: 2 operation(s) were not measured, and a percentage over an incomplete denominator reads as the answer.
    reached  GET /api/invoices/{id} [specimen owner_invoice]  [200]

1 candidate(s), ordered by counted observations only (no score, no confidence number):

[marker_reach] candidate -- other_tenant on GET /api/invoices/{id} [specimen owner_invoice]
    other_tenant reached GET /api/invoices/{id} and the response carried
    invoice_owner's planted marker. Data belonging to another named identity
    was observed in other_tenant's response. This is an inconsistency in the
    observations, not a finding. Declare the expectation to test it.

Wrote access matrix to .veridor/matrix/20260731T224247Z-20e64e.json
Wrote blast radius to .veridor/blast-radius/20260731T224247Z-20e64e.json
Wrote candidates to .veridor/candidates/20260731T224247Z-20e64e.json
Wrote 1 promotion stub(s) to candidates.json
```

One command, one report, in four parts:

1. **Access matrix.** One request per operation, per identity, per specimen.
   Every cell of the grid is accounted for — a status, or an explicit
   `unknown_reason`. Nothing is silently omitted, because a missing cell reads
   as "nothing there".
2. **Blast radius per identity.** Which operations each identity was observed to
   reach. It is a **lower bound on observed reach, not a measure of exposure**,
   and it **counts operations reached, never objects**: an operation counted as
   reached may expose one record or every record. Veridor probes the specimens
   you supplied and never enumerates identifiers.
3. **Boundary coverage.** The same measurement `veridor coverage` makes, against
   the same specification the matrix was built from.
4. **Anomaly candidates.** Inconsistencies between the observations, ranked by
   counted evidence — no score, no confidence percentage, because a fabricated
   `0.86` invites you to read it as "86% likely real" and nothing here supports
   that claim.

### A candidate is not a finding

This is the line the whole command is built around. A candidate is an
inconsistency between observations and a **hypothesis to declare and test**. It
produces no SARIF result, never enters `latest.json` or `.veridor/runs`, and
never changes an exit code. `--promote` writes each one as a deliberately
incomplete check — the name is a `TODO` and you confirm which identity should be
allowed — because *what the boundary is* is your decision, not Veridor's.

If a stub is pasted in unedited, `run` grades it like any other declaration —
it cannot audit a declaration and never claims to — but it says so. The `TODO`
name travels with the finding into the console summary and into SARIF
(`checkName`, plus an `unreviewedPromotionStubs` run property), and `run` prints
an `Unreviewed:` block above the findings naming every check that still carries
it. A machine-generated hypothesis must not arrive looking hand-written.

Six rules run, each stating in the report where it is known to be wrong:
`marker_reach`, `unauthenticated_reach`, `inverted_guard`, `peer_divergence`,
`sibling_asymmetry`, `method_asymmetry`. Where a rule declined to raise a
candidate, the report counts the suppression by reason — a tightened rule that
quietly stops working must not look like a quiet target.

### Drift: catching a regression with nothing declared

Everything above costs you a declaration. Drift costs you nothing: run `map`
once to record what your API does today, and every run after that reports what
moved.

This is the whole configuration — no `checks`, because `map` evaluates none:

```json
{
  "version": 1,
  "target": {"base_url": "https://staging.example.com"},
  "identities": {
    "owner":    {"headers": {"Authorization": "Bearer ${OWNER_TOKEN}"}},
    "outsider": {"headers": {"Authorization": "Bearer ${OUTSIDER_TOKEN}"}}
  },
  "matrix": {
    "specimens": {
      "/api/invoices/{id}": [{"label": "inv", "values": {"id": "inv-100"}}]
    }
  }
}
```

Two credentials, one real object id per templated route, and the OpenAPI file
you already have. Two identities is the one floor that does not move — a single
principal cannot express a boundary at all.

What each part buys you, measured against the demo target by flipping it from
patched to vulnerable and running the same command twice:

| Configuration | Drift caught the regression? |
| --- | --- |
| `version`, `target`, two identities | **No.** Every `{id}` route is unmeasured, so nothing to compare |
| …plus one `specimen` per templated route | **Yes** — `reach_opened`: the outsider went from refused to served |
| …plus a `marker` on the owner | **Yes, with proof** — also `marker_appeared`: the owner's data was in the outsider's response |

The specimen is what makes drift work at all, and it is one line per route you
care about. The marker is what upgrades *"the status code changed"* into
*"another tenant's data crossed the boundary"* — see
[Markers and evidence grades](#markers-and-evidence-grades). Neither is a
policy; both are facts about your test data.

```bash
# Monday. Records the matrix. Finds nothing, says nothing, exits 0.
veridor map --config veridor.json --openapi openapi.json \
            --matrix veridor/baseline-matrix.json

# Every build after. Same command, one flag.
veridor map --config veridor.json --openapi openapi.json \
            --baseline veridor/baseline-matrix.json
```

The drift section of the second run's report, from `fixtures/veridor.map-demo.json`
and `fixtures/openapi.demo.json` against the demo target, patched for the first run
and `--vulnerable` for the second (the plan, reach and candidate sections are left
out):

```
Access-matrix drift — 2 change(s), 2 that mean more access
  baseline 20 cells · current 20 cells · 20 comparable
  drift saw 60% of the grid: 12 of 20 comparable cell(s)
     were measured in BOTH runs. A quiet report below is quiet about the rest
     of it, not evidence about it.
  !! 8 of 20 cell(s) WERE NEVER PROBED, by this plan's own rules
     (skipped_mutating x8)
     Drift is blind there and will stay blind: re-running changes nothing,
     because nothing failed. Widen the plan -- a specimen, an
     --allow-mutating-method, a dropped matrix.ignore -- or read that
     half of the matrix as out of scope for drift.

  MORE ACCESS THAN THE BASELINE
    [reach_opened] GET /api/invoices/{id} other_tenant [specimen owner_invoice]
        refused -> reached
        this identity was refused here and is now served. That is more
        access than the baseline recorded; whether it is intended is not
        something Veridor can tell you
    [marker_appeared] GET /api/invoices/{id} other_tenant [specimen owner_invoice]
        absent -> present
        this response now carries 'invoice_owner''s planted marker and did
        not before. That is a measured fact about data flow, and it is the
        strongest signal in this report

  A change is an observation, not a verdict. Reach that opened may be a feature you shipped;
  reach that closed may be a broken deploy rather than a fix. Veridor reports what moved.

  Accept these as the new baseline by keeping this run's matrix: marker_appeared=1, reach_opened=1
```

Nobody wrote a policy. Veridor recorded reality on Monday and a human reads a
diff on Friday — the bargain snapshot testing makes, and the reason snapshot
tests got adopted at a scale hand-written assertions never reached. The
declaration still exists; it moved from *write it before* to *accept it after*,
and accepting it is keeping this run's matrix file.

`--baseline` takes a matrix file or a directory, and a directory resolves to the
most recent matrix in it. Point it at `.veridor/matrix` and the comparison is
always against your last run — useful while you are exploring, and **refused
under `--fail-on-drift`**. `map` writes into that same directory, so under a
gate the directory form ratchets: the run that catches a regression records it,
and the re-run everybody does next compares the regression against itself and
goes green with the regression still live. A gate compares against a committed
file. `--drift PATH` writes the report as JSON; without `--baseline` there is no
report to write, so it is refused with exit `2` before anything is sent.

**A change is an observation, not a verdict.** Reach that opened may be a
feature you shipped this week. Reach that closed may be a broken deploy rather
than a fix. Veridor reports what moved and does not know which one it is looking
at, so drift produces no SARIF, no findings, and no exit code unless you ask:

```bash
veridor map ... --baseline veridor/baseline-matrix.json --fail-on-drift opened
```

| Policy | Fails the build when |
| --- | --- |
| `none` (default) | never — the report is printed and `map` still exits `0` |
| `opened` | an identity that was refused is now served, or a marker appeared |
| `any` | anything at all moved, including an operation leaving the inventory |

`opened` is the one worth wiring into CI. `any` is noisy by design — a status
code changing from `401` to `403` trips it — and is there for the case where you
want to review every difference before it lands. `opened` does not count a
cell the baseline answered with a redirect and this run serves: Veridor does not
follow redirects, so it never saw whether that `302` was a denial, and counting
it would fail the gate on every trailing-slash fix. An anonymous `302` to
`/login` that became a `200` may still be an authentication bypass, so every
such cell is counted in `redirect_now_served_cells` and in the report's headline
on stdout and in the Markdown report, and on stderr under every policy but
`any`, which fails on it instead. The cells themselves are listed one by one
with the report's changes, each with a note that its baseline was a redirect.
`--fail-on-drift` without
`--baseline` is refused with exit `2` rather than accepted and silently never
gating; a gate that was never comparing anything is worse than no gate. For the
same reason, a comparison in which not one cell was measured in both runs exits
`3` under `opened` or `any`, not `0`. A baseline recorded while the target was
down is the usual cause: every cell in it is `unknown`, so every later
comparison is `unknown → something` and neither policy could fire. Measured
without this rule, such a baseline lets the gate exit `0` against the demo target
serving another tenant's invoice. A redirect does not count as measured either:
Veridor never follows one, so nothing behind it was observed. A baseline
recorded while every request was redirected — a login wall, an SSO proxy, a
maintenance page, `http://` for an https-only host — measured nothing, and
`map` exits `3` when it records one. `--fail-on-drift none` still exits `0`.

### A probe nobody answered is not a finding, and not a pass

A rate limiter or a crashing handler can answer any probe. Graded as a finding,
*"identity `anonymous` received HTTP 429 (declared: one of [401])"* would assert
a boundary failure into somebody's code scanning when anonymous was denied
**harder**. The noise-floor study (`scripts/noise_floor_study.py`, described
below) measured this on `veridor run` with a grading that called those statuses
`vulnerable`, which is not what ships: 70% of its runs failed the build.

A `429` or a `5xx` is not an answer from the authorization layer: the request
was throttled, or the handler fell over. It establishes nothing in either
direction, so it is graded `inconclusive` — the same verdict a timeout gets.
`matrix.classify_reach` reads those statuses as `unknown`; this is the same
knowledge, for the verb that makes claims.

**`--fail-on new|any|confirmed` does not fire on `inconclusive`, deliberately,**
because a gate that fires when nothing was measured is not strict — it is wrong,
and it is the reason gates get switched off. Findings *about the target* —
`vulnerable` and `unexpected_denial` — still gate.

Coverage still cannot fail silently, and this is the half that matters:

- **Not one probe answered → exit `3`, no flag required.** A wrong base URL or
  a target that is down would otherwise exit `0` with *"0 probes matched"* and read
  as verified. That is a stronger overclaim than any false positive, so it does
  not wait to be opted into. *Answered* means the authorization layer answered:
  a `429`, a `5xx`, a transport error and a body too large to scan are **not**
  answers, and a target that returns `500` to everything exits `3` here. That
  is the same predicate the `inconclusive` verdict uses — one definition, so
  the exit code and the grade cannot disagree about what a measurement is.
  Check probes and sequence assert steps are judged together, and a probe
  never sent because its identity's session did not come up counts as
  unanswered: the run exits `3` here when neither a check probe nor an assert
  step was answered. A setup step grades no declaration, so an answered setup
  is not an answer: a sequence whose setup was served and whose assert drew a
  `503` measured nothing. A run that declares no check and no assert step
  grades nothing however the target answers, and the message says so rather
  than blaming the network; so does one whose asserts were all skipped because
  the setup before them was answered with a status it did not declare.
  Unanswered probes beside an answered assert step are `inconclusive` instead,
  and gate under `--require-complete`.
- **`--require-complete`** exits `3` when *any* probe went unanswered, for
  pipelines that want coverage enforced. **The GitHub Action turns this on by
  default**, because selecting the Action is itself the request for a gate. It
  also promotes an *unproven denial* — see below — because that is the same
  question one layer up: was this boundary measured?
- **`--wait-for-target SECONDS`** (`run` and `map`; default `0`, off) holds
  the first request until the target's host and port accept a plain TCP
  connection, trying once a second for at most SECONDS. The check connects
  directly even when a proxy carries the requests, and then its line says so.
  One stderr line says which happened, and the run goes ahead either way: a target that never
  accepted shows up as the probes' own transport errors, graded as above. It
  never changes a verdict, `run` records it in the run document as
  `target_wait`, and `verify <capsule>` refuses it. It is for a gate started
  in the same moment as the deployment it gates, such as an Argo CD PostSync
  Job, where probes sent before the new pod is routable are refused and the
  gate exits `3`. An accepted connection means the port is open, not that the
  service behind it is ready, nor that it is the new version: while the
  previous version's pods are still routed, one of them accepts at once, and
  the gate measures that version (measured under a `RollingUpdate` Helm
  upgrade: 0 s). The Helm chart's README, "hook.mode helm: what the gate
  probes", shows how to aim a gate at the new pods only: for the Helm CLI a
  label from `.Release.Revision`, and for Argo CD, which renders with `helm
  template` where that is always 1, a label hashed from the pod template. A
  PostSync gate still reports on a version that is already serving; to keep
  a failing one from taking traffic, gate an Argo Rollouts canary
  ([`deploy/argo-rollouts`](../deploy/argo-rollouts/README.md)).
- **A denial that proves nothing says so.** An expectation that accepts
  only denial statuses (`401`, `403`, `404`, `405`, `407`) is satisfied by a
  boundary that refused this identity **and** by a credential that expired or
  was mistyped. To tell them apart, `run` issues one probe per such `GET`,
  `HEAD` or `OPTIONS` request carrying a credential it fabricated —
  `veridor-sham-…`, which authenticates to nothing — in every header your
  identities declare except a standard request header that never carries a
  credential (`Accept`, `Content-Type`, `Origin`, `If-*` and the like). A
  credential-named header (`Authorization`, `X-Api-Key`) always gets the
  fabricated value. Another header that two or more identities send with the
  same value (`X-Api-Version`, `Stripe-Version`, `Notion-Version`) is sent
  with that value instead, so a target that refuses an unknown version still
  judges the credential. Any other is left out when every identity declaring
  it also sends a credential-named header or has a session (an `X-Tenant-Id`
  beside `Authorization`): a fabricated tenant gave a target that resolves the
  tenant first a reason to refuse that has nothing to do with the credential,
  and that refusal proved an expired token live. Where it is an identity's
  only credential (the `X-Remote-User` an auth proxy names the caller by) it
  gets the fabricated value. The same list decides whether an identity
  presents a credential at all, so a custom `X-Tenant` does, and an anonymous
  identity that sends only `Accept` does not; its denials are never listed
  unproven. Its answer tells the
  two apart only when it is a refusal (`401`, `403`, `404`, `405`) or a
  2xx/3xx. If the target *serves* the fabricated credential (a 2xx), it
  accepted a credential nobody issued; the run says so on the console and in
  `oracle_disclosures` (`control_source: fabricated_credential`).

  No fabricated credential is sent with `POST`, `PUT`, `PATCH` or `DELETE`,
  inside a sequence, or when no identity declares a credential header to
  shape one on (cookie-session identities alone); those requests and steps
  are named (method and path) on the console and listed in
  `liveness.requests_not_probed`, and `--no-prove-liveness` names every
  denial-only request it leaves unchecked. A denial
  counts as unproven, on the console and in `liveness.unproven`, only when
  all of these hold: the identity presents a credential (for a sequence
  step, a static credential header, or a session cookie that a response
  replaced, or set in a form the cookie jar dropped, after login and before
  the step was sent: the login proved the earlier value only); some identity
  was served in the same
  check, or the same sequence; nothing else in the run proved the identity
  live (a 2xx it drew on a request where an identity with no credential, or
  the fabricated credential, was refused; or its `marker_probe`; for a session
  with `"reestablish": "check"`, only a 2xx in the same sequence counts, since
  each check and sequence is a login of its own; and for any session, only
  evidence sent with the same value of the cookie that established it, so once
  a response gives that cookie a different value (or sets it in a form the
  cookie jar drops), the `marker_probe` and any 2xx sent before stop counting,
  and only a 2xx sent after it proves its denials) — a 2xx on
  a route that serves every caller proves nothing, so a `GET` that serves
  such an identity gets a fabricated credential too, and its 2xx counts only
  if that is refused (on a route an identity with no credential is declared
  served on too: a target that refuses a bad token even there proves the
  credential live, and one that serves the fabricated credential is doing
  what the declaration says, so that is not reported as a served sham);
  and the fabricated credential drew the same denial, was not sent, failed
  (a timeout, a reset), or drew neither a refusal nor a success (a `400`,
  `406`, `407`, `429` or `5xx`). A check where every identity is refused is
  not judged: it says "nobody may have this", and a dead token being refused
  is that declaration coming true. Under `--require-complete` an unproven
  denial exits 3. The fabricated credential is not shaped like your token, so
  a target that refuses a malformed credential but serves a well-formed
  expired one as anonymous can let its refusal prove an expired token live.
  In `liveness.unproven`, an unproven denial of a `"reestablish": "check"`
  identity carries `"proof_scope": "login"`, and one sent after a response
  replaced its session cookie, or whose identity was proven live only under
  another value of it, carries `"proof_scope": "cookie_value"` (a
  `"reestablish": "check"` identity's denial sent after such a replacement
  does too); their advice says what would prove them rather
  than to add a `marker_probe`.

  Liveness evidence is point-in-time. The `marker_probe` runs once, before the
  first check, and a 2xx proves the credential at the moment it was served. A
  credential the target revokes later in the run, without changing anything
  Veridor sees — a bearer token or static header it stops accepting, a session
  revoked server-side while its cookie keeps the same value — is not
  detected: the earlier evidence still counts, and a denial drawn after the
  revocation is graded on it (measured: a token revoked by the marker probe's
  own response, then safe 2, vulnerable 0, `liveness.unproven` empty). Keep a
  run short relative to the credential's lifetime. For a session,
  `"reestablish": "check"` narrows the window to one check or sequence,
  because only evidence under that login counts; nothing narrows it for a
  static credential.

  Other limits of the session cookie rules. A change Veridor sees is a
  response setting the cookie that established the session: to a new value,
  or in a form Python's cookie jar drops. A target that ends the session by
  other means while the cookie stays as it was is the revocation above. A
  cookie the jar keeps but a browser would reject is not noticed. Cookie
  names are folded for the same-name refusal as described under sessions
  (case, `.`, space, `[`), the folds PHP 8.5 was measured to make; a server
  that folds names some other way is not covered.

  This is **stated, never graded**: an identity asserted only to be
  denied and never served anywhere is the ordinary shape of an authorization
  suite, so a finding would fire on most correct configurations. `mutate`'s M6
  reached the same conclusion from the other direction. The remedy is one line
  — give that identity a `marker_probe` naming something it *should* be served,
  and the line disappears because the credential is now provably live — for
  a session, for denials sent under the login and session cookie value the
  `marker_probe` ran with (above).
  The shipped demo config does exactly that for `other_tenant`.

  `--no-prove-liveness` skips the extra requests. The count is printed before
  the first one is sent, and it is **one per request**, not per identity: on the
  shipped fixtures that is +33% rather than +57%.
- Either way the message prints, whichever exit code wins.

| | `429` and `5xx` graded `vulnerable` | Graded `inconclusive`, as shipped |
| --- | --- | --- |
| runs failing the build on transients | 70% | **0 of 10** |
| false `vulnerable` claims into SARIF | 4 per 10 runs | **0 of 10** |
| runs catching a *real* leak | — | **62–100%** per seed, every one graded `confirmed` |

Ten runs per seed. `0 of 10` bounds the rate below roughly 28% with 95%
confidence — a small sample, stated as a count rather than as a rate so it is
not read as a guarantee.

### A mutation score is only as wide as the mutants it could evaluate

The third verb is open to the same class of bug in its quietest form. `mutate`
re-runs the whole suite once per mutant, so it multiplies its exposure to
transients — and a mutant whose baseline probe went unanswered, recorded
`not_applicable`, would be **dropped from the denominator**.

Those two outcomes look identical in a summary and mean opposite things.
`not_applicable` is structural: this operator has nothing to rewrite on this
check, it recurs identically every run, and removing it from the score is
correct. A probe lost to a rate limit is neither structural nor permanent — that
mutant would have been evaluated on a quieter afternoon.

Measured against a target whose boundary never moved, recording it that way
took a run from **15 generated mutants to 11** and still reported a score of
**1.00 and exit 0**. A third of the population gone, and the number describing
it unchanged.

So an unanswered baseline is `errored`, the outcome that means *"the engine
does not know"* — and which makes `mutate` exit `2` rather than `0`. On a
healthy target that changes nothing: 1.00, exit `0`, zero errored. On the noisy
one, exit `2` on four runs in five.

| | Quiet target | Noisy target, unanswered as `not_applicable` | Noisy target, as shipped |
| --- | --- | --- | --- |
| generated per run | 15 | 11 | **15** |
| exit code | `0` | `0` | **`2`** |

### What the gate costs you in false alarms

A gate that cries wolf gets switched off, and then it is worth nothing on the
week it matters. So the noise floor is measured, not asserted:
`scripts/noise_floor_study.py` runs `map` repeatedly against
`scripts/noisy_server.py` — an API whose authorization boundary never changes
and whose everything-else moves like a real one: fresh request ids and
timestamps, moving ETags, a collection sorted by "recently updated" so records
change page, transient `429`s and `503`s, and latency past the client timeout.
Every change reported against it is a false positive by construction.

| | Without the rules below | With them |
| --- | --- | --- |
| runs firing `--fail-on-drift any` | 100% | **0 of 90** |
| runs firing `--fail-on-drift opened` | 20% (up to 75% on a quiet target) | **0 of 90** |

`0 of 90` is not `0%`. Ninety runs that did not fire bound the false-gate rate
below roughly **4%** with 95% confidence (Wilson, `[0.0%, 4.1%]`) — they cannot
establish that it is zero, and no number of clean runs could. All ninety are one
synthetic server at one noise profile; a real API with a different failure shape
is not covered by this measurement.

Measured with `scripts/noise_floor_study.py --verb map --runs 10 --seed N` for
the two false-alarm rows and `--verb map --runs 10 --seed N --detect` for the
detection row — `--detect` is what plants the real boundary opening, so the
command without it cannot produce that number. At the script's default noise — a
`429` on 6% of requests, a `5xx` on 3%, and latency past the client timeout on
5% — over seeds 1–9, ten runs each. Detection
was 90% on seeds 1–3 and 100% on seeds 4–9; the false-alarm rates are 0% on
every seed. Re-run it yourself; the seeds are deterministic.

**Detection, stated separately and on purpose.** It is not a false-alarm rate
and does not belong in the table above: adjacent rows invite the summary
"0% false alarms, 97% detection", which neither number supports. Over the same
seeds, a *planted* boundary opening on *one* fixture was caught on **87 of 90
runs** — 96.7%, 95% CI `[90.7%, 98.9%]`. That is a per-run reliability figure
for one regression on one target, conditional on a baseline that measured the
cell: where the baseline is blind, detection is 0% and no amount of re-running
changes it. It is not a detection rate for authorization bugs in general, and
nothing here measures that.

One behaviour moves detection more than any threshold: the noisy server sends
`Retry-After` with its `429`s, and a matrix that gave up on the first one would be
blind wherever the throttle happened to land. Giving up there, detection was 0–90%
per seed; carrying on, as `map` does by default, it is 90–100%.

Three rules keep those false positives out, and each is worth knowing about
because each corrects a category error rather than a threshold:

- **A cell nobody could measure is not a cell whose access changed.** Reporting a
  `429` as `reach_closed` — *"this identity was served here and is not now"* —
  would say that about a rate limit. Transients are `measurement_lost` /
  `measurement_gained`, and **no policy gates on them**, including `any`.
- **Two different failures are not a difference.** A timeout in one run and a
  `429` in the other are not a `status_changed`.
- **A marker in its own owner's response is not a crossing.** The owner is
  supposed to see their own data, so whether page one still holds the marked
  record is ordering noise — but `marker_appeared` is *significant*, so counting
  it would alone fail builds on up to 75% of runs. Drift skips
  `owner == identity`, as the `marker_reach` candidate rule does.

**The limit that remains, and it is not fixable by tuning.** Detection is not a
constant, and the spread is not variance around a mean — it is one binary fact
about each measurement: detection is high for every cell the baseline measured
and **0% for any cell the baseline itself could not measure** — a baseline
recorded through one bad minute is blind there forever, because every later comparison is `unknown → something`, which is
never "more access". Veridor cannot repair that, so it refuses to hide it:
`map` warns when the matrix it just wrote would make a poor baseline, and any
drift report against a blind baseline says so **above its own counts**, in
those words. A green build you cannot trust is worse than a red one.

**What drift cannot do.** It is blind to anything that did not change. An
endpoint that should be admin-only and has been open to everyone since before
your first run never moves, so it never appears here — and "nothing moved" is
reported as exactly that, never as a clean bill of health. Drift catches the
regression you introduced. Finding what was already wrong is what the access
matrix, the candidates, and a declared `run` are for.

And it is blind to whatever `map` did not probe. On a CRUD specification the
mutating half of the inventory is skipped by default, so those cells are
`unknown` in the baseline *and* in every later run — which means drift can never
report more access there, only `measurement_gained`. On the demo specification
(`fixtures/openapi.demo.json`, 5 operations, 3 of them read-only) that is 8 of
20 cells: drift speaks about 60% of the grid, and says so above its own counts.
This is a scope choice, not noise and not a tuning problem — re-running changes
nothing, because nothing failed. Widen it with `--allow-mutating-method`,
against an environment you can recreate, or read the writes as out of scope for
drift and cover them with a declared `run`.

### Safety posture

The matrix is a scanning-shaped workload and is treated as one.

- **Read-only by default.** Only `GET` and `HEAD` are sent. A mutating verb must
  be named literally with `--allow-mutating-method DELETE` (never a wildcard)
  *and* accompanied by `--acknowledge-mutating` verbatim. Two independent gates,
  so one stray flag opens neither; mutating requests then get their own budget
  of 50 within the total, and every one is listed by name before the first is
  sent. **What you do not opt in to is not probed at all**: those cells are
  recorded `unknown / skipped_mutating`, never `refused`, and the banner prints
  the count before the run starts.
- **The plan is refused before the first request.** `--max-requests` (default
  500) is checked against the built plan, which reports the number it refused
  and how to narrow it. **20,000 is an absolute ceiling** no flag raises.
- **Rate limited and sequential.** `--rate` defaults to 2 req/s and is capped at
  **10 req/s**. There is no flag that disables the limiter.
- **The run has a wall clock.** `--max-run-seconds` defaults to **1,800s (30m)**
  and is capped at 7,200s (2h). It is a *stop*, not a budget: the matrix reports
  a partial grid, and the cells it never reached read `unknown`, never "no
  access". **The three numbers interact, and the wall clock usually binds
  first.** Rate × wall clock is the real request ceiling — at the default 2 req/s
  that is 3,600 requests, far below 20,000, so an ordinary 1,000-operation spec
  across five identities already exceeds it. `--dry-run` prints the estimate
  beside the stop and says so when the plan cannot finish.
- **`--dry-run` sends nothing.** It prints the plan, the posture and the
  estimate. Run it first against anything you did not provision yourself. A
  plan over `--max-requests` is printed and then refused with exit `2`, as the
  run itself refuses it.
- **A public target must be typed out.** A target that is neither loopback nor
  a private, non-globally-routable address needs
  `--acknowledge-target "I am authorized to test HOST"` verbatim. Waived without
  it, on purpose: every address that is not globally routable — RFC 1918
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`),
  IPv6 ULA (`fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`, which
  includes the cloud metadata address `169.254.169.254`) and the documentation
  ranges. A hostname is never resolved, so every hostname except `localhost`
  and `*.localhost` needs it. That is friction, not a security boundary: the
  point is that pointing the matrix at the wrong host is hard to do by accident.
- **No redirects, no retries, no concurrency**, and the run stops on signals
  that mean you are not welcome — repeated rate limiting, repeated server
  errors, repeated transport failures. A `429` carrying `Retry-After` counts
  toward the same rate-limit budget as a bare one (three consecutive, five
  cumulative), so a target that sends the header gets the same tolerance as one
  that does not — never less. `--on-retry-after stop` abandons the grid on the
  first one instead.
- **`--include` and `--ignore` match by path prefix**, not as globs and not as
  regexes. A match selects the route *and everything beneath it*, so
  `--include 'GET /api/invoices/{id}'` also selects `/api/invoices/{id}/lines`;
  `*` is an ordinary character; `{id}` must be spelled the way the
  specification spells it. An `--include` list where every pattern misses is
  refused before a socket opens, because an empty selection produces an empty
  grid rather than a clean one; so is an `--ignore`, `matrix.ignore` or
  `--include`, alone or together, that leaves nothing to probe: no operation
  in the specification, or only writes the read-only posture skips and routes
  with no specimen (exit `2`). A selection that excludes no operation changes
  nothing, so a specification of writes alone, with or without one, plans no
  request, says so in the banner and exits `0`.

- **A session-backed identity is refused, not guessed at.** `map` builds every
  probe from the identity's static `headers`: it has no cookie jar and does not
  log in. An identity that authenticates through a `session` block would
  therefore be probed *anonymously*, and the anonymous reach recorded under its
  name — a blast radius smaller than the truth, which is the one direction this
  tool must never be wrong in. `map` refuses the configuration before it opens a
  socket and tells you to use `run`, which does log in.

Veridor still never crawls or guesses routes. The inventory comes from the
OpenAPI file you point it at, and the concrete object behind each `{id}` comes
from the `matrix.specimens` you wrote.

### The `matrix` section in full

`specimens` is the only key `map` needs. The rest tell the candidate rules what
they cannot observe — **who is a peer of whom, and which way privilege runs** —
and each one switches on rules that stay silent without it. Veridor never infers
these from behaviour: a wrong grouping does not produce fewer candidates, it
produces confidently wrong ones.

```json
"matrix": {
  "specimens": {
    "/api/invoices/{id}": [{"label": "inv", "values": {"id": "inv-100"}}]
  },
  "marker_owner": "invoice_owner",
  "peer_groups": {"tenants": ["invoice_owner", "other_tenant"]},
  "privilege_order": ["anonymous", "other_tenant", "administrator"],
  "unauthenticated": "anonymous",
  "ignore": ["POST /api/webhooks"]
}
```

| Key | What it does | Without it |
| --- | --- | --- |
| `specimens` | A real object id per templated path. One entry per `{placeholder}` in the route. | The operation is **not probed at all** and every cell reads `unmeasured` |
| `marker_owner` | Which identity's planted marker the matrix scans responses for. | No cell is ever graded `marker_scan: present`, so `marker_reach` cannot fire and drift loses its strongest signal |
| `peer_groups` | Identities that should be able to reach the same things — tenants of one another. | `peer_divergence` and `sibling_asymmetry` stay silent |
| `privilege_order` | Least privileged first. | `inverted_guard` stays silent: it has no way to know that admin outranks a tenant |
| `unauthenticated` | The identity that carries no credentials. | `unauthenticated_reach` stays silent |
| `ignore` | Operations never to probe, as `METHOD /path/template`. | Everything the specification declares is in scope |

An identity that is meant to be anonymous declares `"headers": {}` explicitly.
Writing credentials one level too high —
`{"owner": {"Authorization": "..."}}` instead of
`{"owner": {"headers": {"Authorization": "..."}}}` — is refused, because as
written that identity sends nothing and would be probed anonymously under its
own name.

## Run: does the boundary hold, and did it change?

`run` is the gate, and the only command that can fail your build. It issues
every declared expectation as every declared identity, grades the evidence,
diffs against a baseline, and writes SARIF.

```bash
veridor run \
  --config veridor.json \
  --baseline baseline.json \
  --json current.json \
  --sarif veridor.sarif \
  --fail-on new+confirmed
```

`verify` is an alias for `run`.

### Configure

Configuration is JSON. Each check sends one request under at least two named
identities:

```json
{
  "version": 1,
  "target": {
    "base_url": "https://staging.example.com",
    "timeout_seconds": 10
  },
  "identities": {
    "owner": {
      "headers": {"Authorization": "Bearer ${OWNER_TOKEN}"},
      "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
    },
    "other_tenant": {
      "headers": {"Authorization": "Bearer ${OTHER_TENANT_TOKEN}"}
    },
    "anonymous": {"headers": {}}
  },
  "checks": [
    {
      "id": "invoice-tenant-isolation",
      "request": {"method": "GET", "path": "/api/invoices/inv-100"},
      "expect": {
        "owner": {"status": [200], "contains_marker": "owner"},
        "other_tenant": {"status": [403, 404], "excludes_marker": "owner"},
        "anonymous": {"status": [401]}
      }
    }
  ]
}
```

`${NAME}` is read from the environment at load time; a missing variable fails
the run before any request is sent (exit `2`), and so does one that is set but
empty — which is what a pull request from a fork gets for a withheld secret, and
would otherwise be probed as a real identity. Requests are sent as you wrote
them, except that redirects are never followed (a `3xx` is an observed response,
and credentials are never forwarded to a new host), `Accept-Encoding` is forced
to `identity`, and `Cache-Control` and `Pragma` to `no-cache`. A run also sends
requests of its own: each `marker_probe`, and the [controls that carry a
fabricated credential](#a-probe-nobody-answered-is-not-a-finding-and-not-a-pass). A `request` takes `method`, `path`, `headers`, `json` and `body`;
any other key is refused with exit `2` unless it starts with `_`, which marks
an annotation such as `_comment`. A `path` with a `.` or `..` segment is
refused too (plain, percent-encoded any number of times, or as overlong UTF-8
such as `%c0%ae`, and `..;` as well, which a servlet container reads as `..`),
and so is one beside an encoded separator (`..%2f`, `..%5c`, which a gateway
that decodes them reads as `../`), because joined onto `base_url` it would
reach a different path than the one written. A segment still decoding after
eight rounds is refused too. An encoded `/` inside a name, as in
`group%2Fproject`, is kept. Spellings only one server family reads, such as
IIS's `%u002e` or a segment with trailing spaces, are not judged. A `Host` header,
in any header map and any case, is refused with exit `2`: urllib would send it
in place of the URL's host, and a gateway that routes by `Host` would deliver
the request somewhere the target checks never looked. The host belongs in
`base_url`.

A key starting with `_` is an annotation, and Veridor never reads it, in each
of these: the root, `target`, an identity, its `marker_probe`, its `session`,
a login step, a capture, an inject entry, a check, a check's request, an
expectation, a sequence, a step, a teardown entry, their requests, their
`expect` blocks, and `coverage`. Only `establishes`, `matrix` and a specimen
take none. A map keyed by names you choose has no annotations either, because
a `_` key there is one more name: in `identities`, a check's `expect` and a
`capture` map, `"_remark": "a note"` is refused as an identity, an
expectation or a capture, and in `headers` it is sent as a header. A request block, a login step and `marker_probe` refuse every other
key they do not read. Elsewhere, most objects also ignore a key without the
`_` that Veridor does not read, unless it reads as a slip of a real key: a
case variant, a close misspelling, or the same letters in another order. That
is refused with exit `2` even when it was meant as a note, so a root
`checksum` (read as `checks`), `schema` (`$schema`), `versions` or
`x-version` (`version`), or an identity's `remark` (`marker`) stops the run.
Start such a key with `_`
(`_checksum`, `_remark`), as every such refusal says.

Requests go straight to `base_url` unless `http_proxy` or `https_proxy` (in
either case) is set for its scheme and `no_proxy` does not name its host. Then
they go through that proxy, and Veridor says so on stderr before the first
request, naming the proxy's host and port and the variable. Behind a proxy an
`http://` target's requests, credentials included, are readable by the proxy.
An `https://` target's are readable too if the proxy inspects TLS with a
certificate authority the machine trusts, as many corporate egress proxies do;
only a proxy that tunnels sees nothing but the host and port, and Veridor
cannot tell which kind it is. The operating system's proxy settings are never
read, and a loopback target (`127.0.0.0/8`, `::1`, `localhost`) is always
reached directly. An `https://` proxy for an `https://` target is refused with
exit `2` (urllib would open the tunnel in plaintext), as is a proxy value that
is not `host:port` after its `user:password@`; neither value is printed. The
variables follow urllib's rules, which are not curl's: `REQUEST_METHOD` (set
under CGI) makes it ignore an upper-case `HTTP_PROXY`, `all_proxy` is not
read, and `no_proxy` takes names, domain suffixes and `*` but not CIDR ranges
or `*.example.com`. The notice's hint names the `no_proxy` variable urllib
actually reads, and the bracketed form of an IPv6 host.

**Response bodies are never persisted.** Evidence holds status, duration, body
size, a SHA-256 digest of the body, and — when a marker is configured — booleans
derived from an in-memory scan. No response text and no headers are ever
written to disk — including on the failure path, where a malformed response is
described by a constant rather than by the bytes that confused the parser.
Query values are redacted from stored URLs, and a valueless query parameter
(`?<opaque-token>`) is redacted whole, name included. Every value expanded from
a `${NAME}`, in a path or anywhere else, is written and printed as `${NAME}`,
except a value under 8 characters, which the command names on stderr instead;
a token typed literally into a path is written as typed. See
[SECURITY.md](../SECURITY.md#what-veridor-does-with-your-credentials).

A body that was not fully materialized never produces a claim of absence. A
stream cut short of its declared `Content-Length`, a compressed stream that
ended mid-member, and a body past the scan ceiling all report `unknown` with a
reason rather than `absent`.

### Markers and evidence grades

A status code alone cannot tell you whether any data actually moved. `200`
where you declared `404` is a disagreement with your declaration; it is not yet
evidence that the other tenant saw anything.

A **marker** closes that gap — the data-flow gap, and only that one; see
[what a finding does and does not mean](#what-a-veridor-finding-does-and-does-not-mean).
Put a high-entropy string in an identity's own data (an invoice reference, a
profile field — anywhere the API will echo it back), declare it on the identity,
and reference it from the expectations:

```bash
veridor new-marker    # prints a marker that passes validation
```

```
vdr-EuHSKZURhbkafLHayRObGLF5
```

- `"contains_marker": "owner"` — this response *must* carry `owner`'s marker.
  It is the control: it proves the oracle can see the data at all.
- `"excludes_marker": "owner"` — this response *must not* carry it. Absence is
  only meaningful if presence was demonstrable, so Veridor **requires a
  control** behind every exclusion and refuses to load a configuration without
  one.

#### The two controls, and why they are not equivalent

Veridor accepts two, and grades them differently because they prove different
things.

**1. The same-check control (strong).** `owner` is probed at the very path
under test and asserts its own marker there:

```json
"expect": {
  "owner":    { "status": [200], "contains_marker": "owner" },
  "attacker": { "status": [404], "excludes_marker": "owner" }
}
```

This proves the marker is observable *at this path*, so absence in the
attacker's response is falsifiable. Use it whenever it is possible.

**You must declare it.** An `excludes_marker` with no control in the same check
and no identity `marker_probe` is refused at load time, before any request —
the refusal prints the exact JSON to paste. Declaring `owner` at the path with
a plain status expectation is *not* enough; the control is the
`contains_marker` assertion, because that is what makes the marker's absence
falsifiable rather than assumed.

Once declared, it does the work automatically: if the owner's own data comes
back *without* the owner's marker, this path cannot surface markers at all, the
exclusion is unfalsifiable *here*, and the finding is `inconclusive` — an
identity `marker_probe` of some other endpoint cannot override that.

**2. The identity `marker_probe` (weaker).** Some APIs path every resource by
the *caller's own* principal — `/fleet/v1/{caller}/artifacts/...` — so the
marker owner can never be probed at the attacker's path and a same-check
control is impossible. Declare the probe on the identity instead:

```json
"identities": {
  "device_a": {
    "headers": { "Authorization": "Bearer ${DEVICE_A_TOKEN}" },
    "marker": "vdr-OIItAlvvweFpwlDNmT1j5WJ8",
    "marker_probe": { "method": "GET", "path": "/fleet/v1/device-a/artifacts/fw.bin" }
  }
}
```

`marker_probe` takes the same keys as a check `request` (`method`, `path`,
`headers`, `json`, `body`) and runs once per run, before any check, as the
identity that owns the marker. It is a **control, not a check**: it produces no
finding, never enters `probes`, and never changes the check tally. It fails
closed — a request error, an unscannable body, or a missing marker all withhold
the licence. Like a check, it is rejected at load time if its own request would
carry the marker it later matches.

What it proves is narrower: the marker is **live somewhere**, not that the path
under test can surface it. A run that leans on it says so, on the console and in
the dashboard, and in the JUnit, Code Quality, GitLab SAST and Markdown
reports, and records it under `oracle_disclosures` in the run JSON and
`runs[0].properties.oracleDisclosures` in SARIF:

```
Unproven oracle: 1 exclusion(s) were licensed by an identity marker_probe,
which proves the marker is live elsewhere, not that the path under test can
surface it:
  - fleet-device-b-artifact / device_b: ...
```

Prefer the same-check control. Reach for `marker_probe` only when the API's
shape makes the strong control impossible, and read the notice as what it is:
a green run with a weaker oracle behind it.

Markers are matched against the response bytes in ASCII and both UTF-16 byte
orders, case-insensitively, after `gzip`/`deflate` decoding — including every
member of a concatenated gzip stream. Only the needle is transformed, never the
body. **Response headers are scanned too**, not just the body: a
`Content-Disposition: filename="…"`, a `Location` pointing at a foreign
resource, an `ETag` derived from foreign content and `X-Owner`-style debug
headers are all real leak channels, and a marker found in one of them is a
leak. Each finding records `marker_channel` (`body` or `header`) so a reviewer
can see where.

The marker literal itself is not written to a run document, a matrix or any
report. A [capsule](#capsules-sending-a-proof-to-someone-else) is the exception,
by design: it carries the marker of each identity its check names, because
`verify` has to match it.
A configuration that would send a marker in the request it later matches is
rejected outright —
a reflected marker cannot prove a leak. That check covers every byte Veridor
puts on the wire (method, base URL, path, header names and values, body) and
inspects each through the decodings a target may apply before echoing: percent,
plus, HTML entity, `\uXXXX`, base64, and hex. The same rule holds at run time
for a value a *sequence captured*: if a target echoes a planted marker back and
a later step would interpolate that capture into its own request, the step is
not issued and the sequence reports inconclusive.

Veridor sends `Cache-Control: no-cache` and `Pragma: no-cache` on every request
and drops any configured value for either, for the same reason it forces
`Accept-Encoding: identity`. When a response nonetheless announces that it came
from a cache (`Age`, `X-Cache`, `CF-Cache-Status`, …), the marker result
describes the object at some earlier time: it cannot license a pass and it
cannot refute a write, so the step reports `VERIDOR-CACHE-001` / inconclusive.

Every finding therefore carries an `evidence_grade`:

| Grade | Meaning |
| --- | --- |
| `confirmed` | The response carried another identity's declared marker. That is proof the **string** crossed, and proof of **data flow** insofar as the marker is unique to that identity's data — a premise you supply by planting it. If a credential Veridor fabricated gets the same marker back, no `confirmed` is issued: see `suspected` and `n/a`. That credential is sent once for every `GET`, `HEAD` or `OPTIONS` request carrying an `excludes_marker`, whatever statuses it accepts; where none is sent (a write, no credential header to shape it on, `--no-prove-liveness`) or its response could not be scanned, the console and `liveness.marker_uniqueness_not_checked` say the marker's uniqueness was not checked there, and a crossing is graded on your premise alone. Never proof of **policy**: [what a finding does and does not mean](#what-a-veridor-finding-does-and-does-not-mean). |
| `suspected` | The observed status differed from the declared one, and no owner-specific marker was observed: either the marker was not observed, or a credential Veridor fabricated got it back too, so it is not unique to its owner. The status is the evidence; exposure is unproven. Also a marker observed beside a status that matched the declaration when the target **served** a credential Veridor fabricated (a 2xx) and returned the marker to it: the target accepts a credential nobody issued, which says nothing about the marker's uniqueness, so the leak stays `VERIDOR-LEAK-001` `vulnerable`, graded `suspected`. The default gate fails on it; `--fail-on confirmed` does not. |
| `ungraded` | The observed status differed from the declared one and no marker was configured for this check. |
| `n/a` | Inconclusive: the request failed, or the oracle could not be verified. That includes a marker observed beside a status that matched the declaration when a credential Veridor fabricated, and the target refused, got it back too: nothing else in that probe suggests a leak, so it is `VERIDOR-ORACLE-001`, not a finding against the target. |

Grades are finding **properties**. They are not part of the finding fingerprint,
so adding markers to an existing suite never invalidates your baseline.

### Sequences: state across requests

A check is a *fan-out*: one request, many identities. Some authorization bugs
cannot be expressed that way, because proving them needs state that only exists
between requests — an id returned by an earlier call, an object provisioned as
the victim, or a write whose effect only a later read can confirm. A
**sequence** is the ordered form: a list of requests, each issued as exactly one
named identity, each declaring a status expectation, each optionally naming
values to carry forward.

```json
{
  "version": 2,
  "sequences": [
    {
      "id": "invoice-cross-tenant-delete",
      "steps": [
        {"role": "setup", "as": "owner",
         "request": {"method": "POST", "path": "/api/invoices",
                     "json": {"note": "${marker:owner}"}},
         "expect": {"status": [201]},
         "capture": {"invoice_id": "$.id"}},

        {"role": "setup", "as": "owner",
         "request": {"method": "GET", "path": "/api/invoices/${invoice_id}"},
         "expect": {"status": [200], "contains_marker": "owner"}},

        {"role": "assert", "as": "attacker",
         "request": {"method": "DELETE", "path": "/api/invoices/${invoice_id}"},
         "expect": {"status": [403, 404]}},

        {"role": "assert", "as": "owner",
         "request": {"method": "GET", "path": "/api/invoices/${invoice_id}"},
         "expect": {"status": [200], "contains_marker": "owner"}}
      ],
      "teardown": [
        {"as": "owner",
         "request": {"method": "DELETE", "path": "/api/invoices/${invoice_id}"},
         "expect": {"status": [204, 404]}}
      ]
    }
  ]
}
```

`sequences` requires `"version": 2` and is a sibling of `checks`; a config may
declare either or both. Existing configs are untouched, and a config with no
`sequences` key produces the same run document, the same fingerprints, and the
same exit code it produced before. The console prints a line per sequence, per
step and per teardown entry, so a multi-step suite never looks like a
single-request one.

**A sequence is not a program.** There are no conditionals, no loops, no
arithmetic, no expressions, no transforms, no retries, and none of those will be
added. A config nobody can review is not a security tool. The only state a
sequence carries is a flat, single-assignment map of names to strings and
integers, which never touches disk. A sequence that cannot establish its own
preconditions reports `inconclusive` — never safe, never vulnerable.

**Captured values are never persisted.** The step URL recorded in the run
document is the config *template*, `${…}` tokens intact, so the one channel by
which a captured id could reach an artifact is closed at the source rather than
filtered on the way out.

#### Teardown always runs

Every `teardown` entry is attempted on **every** code path: a setup step that
failed, a probe that failed, an unexpected exception, `Ctrl-C`. Only `SIGKILL`
or a runner eviction escapes it. Four rules that will not change:

* **Teardown never changes a verdict.** Its results create no findings, enter no
  probe count, and contribute to no fingerprint. Grading runs on records that
  were complete before cleanup started.
* **Teardown never masks a finding.** A real finding always wins the exit code.
* **Every entry is attempted.** One failure does not stop the ones after it;
  stopping at the first is how half a fixture set gets orphaned.
* **Teardown is loud.** Every failure and skip prints to stderr and emits a
  GitHub Actions `::warning`, including on a cancelled run, where no run
  document is written at all.

An entry whose `${…}` reference never resolved — because setup failed before the
capture existed — is *skipped*, never sent with the literal text. Cleanup gets
its own budget via `target.teardown_timeout_seconds` (default:
`timeout_seconds`), so a hung cleanup endpoint cannot stall CI on every entry.
The per-sequence outcome is recorded as `teardown_state`: `clean`, `incomplete`
(something was skipped), `failed`, `not_required`, or `aborted`. Pass
`--require-clean-teardown` to additionally exit `3` when it is not `clean`;
without that flag a broken cleanup endpoint is reported everywhere but does not
block the security gate.

### Write safety

Sequencing makes Veridor a tool that **writes to the target**. That is a
categorical change and it is treated as one.

> Fixture setup creates and deletes objects in the target.
> **This is for systems you own.**
> Point it only at an ephemeral environment you can recreate: a per-run
> container, a seeded test tenant, a preview deploy.
> Never at production, and never at a shared staging system holding data
> anyone relies on.
> Teardown runs on every code path including cancellation, but a `SIGKILL` or a
> runner eviction can still leave fixtures behind.
> **If losing an object in the target would matter to anyone, use
> `--read-only`.**

`--read-only` is a hard refusal: the load fails with exit `2` if *any* request
the configuration can issue — check, sequence step, teardown, login, or marker
probe — uses a method outside `GET`, `HEAD`, and `OPTIONS`. It fails before a
single request is sent. This is the recommended default for any target you did
not personally provision.

A run that issues a mutating request prints one banner on stderr before its
first request, and the run document records what it did:

```json
"mutation": {"verbs": ["DELETE", "POST"], "requests_issued": 4}
```

Every surface counts: a check request, a marker probe, a sequence step and a
sequence teardown all reach the banner and the block. A `DELETE` declared as an
ordinary check is a write, and `veridor init` scaffolds one by default. The
single exception is a session login, which creates no object in the target and
needs no cleanup — `--read-only` still refuses it, because that flag is about
the wire and this block is about blast radius. The block is absent when nothing
was written, so the artifact answers "did this run change my target?" without
anyone having to reason about the config.

Two limits worth stating plainly. If the attacker's own probe is mutating and
succeeds — that being the vulnerability — the resulting state change is the
attack's, not the fixture's, and Veridor does not attempt to undo it: it cannot
know what happened, and guessing would need conditionals. And sequences are
strictly serial, as everything in Veridor is, so there is no interleaved fixture
state to reason about.

### Session state: cookies, logins, and CSRF

Cookie-authenticated targets cannot be probed with a static header. An identity
may declare a `session`: an ordered login, the proof that it worked, and the
tokens to carry forward.

```json
{
  "identities": {
    "victim": {
      "session": {
        "login": [
          {"method": "GET", "path": "/login", "expect_status": [200],
           "capture": {"login_csrf": {"from": "html_meta", "name": "csrf-token"}}},
          {"method": "POST", "path": "/login",
           "headers": {"X-CSRFToken": "${capture.login_csrf}"},
           "body": "user=victim&password=${VICTIM_PASSWORD}",
           "expect_status": [200, 302]}
        ],
        "establishes": {"cookie": "sessionid"},
        "capture": {"csrf": {"from": "cookie", "name": "csrftoken"}},
        "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
        "reestablish": "run"
      },
      "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
    }
  }
}
```

`login_csrf` is the one-shot token scraped from the login page; `csrf` is the
live cookie every later request injects. Two names because they are two
different values with two different lifetimes — and because one name would not
load.

**Capture names are one flat namespace per identity, and single-assignment.**
Step-level and session-level captures share it, and declaring the same name in
both is a load error (exit `2`, before any request) rather than a silent
override: `identity 'victim' session declares capture 'csrf' more than once`.
The two kinds are not interchangeable:

| Declared on | May read | Read when |
| --- | --- | --- |
| a **login step** | `cookie`, `header`, `json_pointer`, `html_meta` | once, from that step's response, and frozen for the rest of the run — except `cookie`, which is read from the jar at send time like a session-level one |
| the **session** | `cookie` only | **live, at send time** — so a rotating CSRF cookie needs no logic at all |

A session-level capture is restricted to `cookie` for that reason: the jar is
the only source that still holds a value after the login response is gone.
Everything else is a property of one response and belongs on the step that
produced it. A login step's `cookie` capture is checked when its step runs, so
a missing cookie still fails the login, but after that it is read live: a frozen
copy would outlive the cookie, and as the `establishes` proof it would keep an
expired session looking live. A cookie with an empty value (`Set-Cookie:
csrftoken=`) is no value: a `${capture.…}` reference to it is unresolved and
the request is not sent. A cookie read live is held to the same rules as a
value captured from a login response — at most 4096 bytes, printable ASCII, no
spaces or control characters — and one that breaks them is unresolved too,
rather than injected as is (or, for a character outside Latin-1, failing inside
the HTTP client and reported as a failed request rather than one not sent). If a cookie the target
set during the current login has since expired or been cleared, the reason is
`capture_cookie_expired`, with session advice, not `unresolved_reference`, which
is kept for a capture that never had a value: a misspelt name, or a cookie the
target has not set yet.

**Cookies never cross identities.** Each identity gets its own jar, built on
`http.cookiejar` with a policy that accepts and returns cookies for exactly one
host, the one in `target.base_url` (an IPv6 literal such as `http://[::1]:8080`
included). The jar reaches a request as an argument, so isolation is a property of
the call, not of a registry someone could key wrongly — and there is no API
anywhere that copies, unions, or seeds one jar from another. This is the single
most important property in the feature: a leaked jar turns the attacker's probe
into the owner's, and a lost session turns it into an anonymous probe that draws
a `401` matching a declared denial. Both directions manufacture a green run over
a live vulnerability.

An identity that declares both a static `Cookie` header and a `session` is a
load error, because `add_cookie_header` silently does nothing when a `Cookie`
header is already present — the session cookie would vanish with no diagnostic.

**Establishment is proven, not assumed.** `establishes` is required and names
exactly one of `cookie` (present in the jar with a non-empty value and usable
against this origin — a `Secure` cookie over plain `http` fails here rather than
three checks later) or `capture` (non-empty, for bearer flows). If the jar holds
two cookies of the proving name with different values, for example one per
`Path`, the session does not establish: which one the target authenticates is
unknowable. Otherwise the proof is that cookie — its name, domain and path — and
not its name alone, so a later same-named cookie on a narrower path cannot stand
in for it once it expires. `expect_status` is required on every
login step, because the common real login is `POST /login` → `302`, redirects
are never followed, and the cookie is on the `302`.

If a session does not establish, every probe naming that identity reports
`inconclusive` with `VERIDOR-EXEC-001` **and no request is issued**; its
`marker_probe` is skipped and its control degrades to `unverified`; its teardown
entries are skipped and reported. Degraded state is never allowed to look like a
result.

An established session is checked again on every request, on the request
itself: once the jar has attached its cookies, the cookie that proved the
session (named in `establishes`, or read by the capture it names) must be on it
with its current value. If that cookie has expired since login, or its `Path` or
`Domain` does not cover the URL, the request **is not sent** and is graded
`inconclusive`, because without the cookie it would go out anonymous and its
`403` or `404` could match a declared denial. The same holds for every cookie
whose value the request carries through a `${capture.…}` reference, such as a
CSRF token injected as a header: if the jar would leave that cookie off, a
double-submit CSRF check would refuse the request with a `403`, so it is not
sent either.

Being on the request is not enough if a different value rides beside it. A
response after login can set a second cookie under the same name on a
narrower path (`sid=guest; Path=/docs`), and the jar then sends both, longer
path first: `Cookie: sid=guest; sid=attacker`. A server that reads the first
occurrence (Express's cookie-parser, PHP, Go's `r.Cookie`) authenticates the
guest. So a request that would carry the proof cookie, or a cookie a
`${capture.…}` value was read from, beside a different value under the same
name **is not sent** and is graded `inconclusive`
(`session_cookie_ambiguous`) — the rule that stops such a login from
establishing, applied to every request. "The same name" is compared the way
the most lenient server reads it: without case, with `.` and space read as
`_`, and a `[` read both as the end of the name and as `_`. So `SID=guest`
beside `sid=attacker`, `sid[x]=guest` beside `sid=attacker`, and `s.id=guest`
or `s[id=guest` beside `s_id=attacker` are refused, because a server that
folds cookie names (PHP stores `s.id` and an unclosed `s[id` as `s_id`, and
`sid[x]` as an array under `sid`) reads both as one; a server that does not
gets `inconclusive` too. The same value under the same name on
two paths is not ambiguous and goes out. When the login set the proof cookie
more than once with one value (on two paths, or host-only and with `Domain=`),
every copy is the proof, and once a later response gives one copy a different
value, every request of that session is refused the same way, including one
that only the unchanged copy would reach. A target that replaces the proof
cookie itself (same name, domain and path) is treated as rotating it: the new
value is the proof from then on and requests go out with it. Veridor cannot
tell that from a target that swapped the session for an anonymous one, so
liveness evidence taken under the old value — the `marker_probe`, an earlier
2xx — no longer proves a denial drawn under the new one (see "A denial that
proves nothing says so"). A response that sets the proof cookie in a form
Python's cookie jar drops (a `Max-Age` that is not a whole number, such as
`3600.5` or `abc`, which a browser ignores and keeps the cookie) leaves the old
value going out; that counts the same way, so earlier evidence stops proving
denials, and the session's entry in the run document carries a `note` saying
so. A deletion (`Max-Age=0`, or an `Expires` in the past) is not counted.

| Capture `from` | Reads |
| --- | --- |
| `cookie` | that identity's own jar, live at send time — so a rotating CSRF cookie works with no logic at all |
| `header` | the named response header of the login step that declares it |
| `json_pointer` | an RFC 6901 pointer into that step's response, in memory |
| `html_meta` | `<meta name="X" content="Y">`, via the stdlib HTML parser |

A `json_pointer` resolves a string, number or boolean leaf, a number or boolean
as its JSON text (`0`, `false`); an object, an array or `null` does not
resolve. A capture that resolves proves only that the login response held a
non-empty value there, not that the target accepts it as a credential: `{"tok":
false}` establishes a session whose token is the text `false`. Whether the
token works is what the liveness controls measure, and a denial drawn with one
the target ignores is listed in `liveness.unproven` when the fabricated
credential draws the same answer (measured with `false`, `0` and `"null"`).

`inject` applies to every request issued as that identity once the session is
established — check probes, marker probes, sequence steps, and teardown. It sets
a `header`, appends a `form_field` to a form-encoded body (a `body` string with
no `Content-Type` is sent form-encoded), or sets a top-level `json_field` on a
JSON object body. A **graded** request whose body cannot carry the declared
field is not sent and is graded `inconclusive`; a `GET`, `HEAD` or `OPTIONS`
with no body, and any teardown request, goes out without it instead — a safe
method has no body to carry a field, and teardown is cleanup that is never
graded, so refusing it would only orphan the fixture the entry removes. Whenever
a request goes out without a declared field — a check probe, sequence step,
teardown entry or marker probe alike — the run records which field was dropped
on that request's own record and `run` reports it on the console alongside the
other pass disclosures — and lists it under `injection_disclosures` in the run
JSON, on the dashboard, in `runs[0].properties.injectionDisclosures` in
SARIF, and in the JUnit, Code Quality, GitLab SAST and Markdown reports — so a
matched denial is not read as a field-carried pass. It may never
fill `Cookie`, `Authorization`, or
`Proxy-Authorization`: the jar and the identity's own static headers own the
credential slots, and a capture in one of those would let one identity borrow
another's credential and fabricate a `confirmed` finding out of legitimate
access. If a reference cannot be resolved, the request **is not sent** — an
untokened request draws a `403`, and a `403` that matches a declared denial is a
false pass. Set `"reestablish": "check"` to replace the jar and log in again
before each check and each sequence. Liveness proof then belongs to the login
it was measured under: the identity's `marker_probe` runs once, under the login
before the first check, so it no longer proves its denials live, and neither
does a 2xx it drew in another check or sequence. A denial of such an identity
is proven only within its own sequence or by the fabricated credential's
answer, and is otherwise listed in `liveness.unproven`, with advice to use
`"reestablish": "run"` if the target's sessions last the whole run.

**Credentials never reach an artifact.** Cookie values, captured tokens, and
`Set-Cookie` attributes are never placed in any object that is serialised,
printed, or handed to SARIF — not redacted on the way out, but never put there
in the first place. The `sessions` block records cookie *names* (sanitised),
a count, capture *state* and declared *source*, and per-step status, size and
digest. No hash, prefix, suffix, or length of an isolated secret is recorded:
many CSRF-shaped tokens live in a guessable domain, and a hash of one makes
offline confirmation trivial. A cookie the parser rejects is reported by a
constant string, because a cookie parse error can embed the cookie.

`${capture.<name>}` is deliberately dotted: `${NAME}` environment expansion
cannot match it, so the two namespaces can never collide and no new escaping
rule exists. Capture references are legal only inside a session; a `${capture.…}`
in a check request is a load error rather than a literal on the wire.

### Regression gates

Findings are matched across runs by a stable fingerprint over the check id,
identity, finding kind, method, path, request-body digest, and expected
statuses, producing:

- `new` — present now, absent from the baseline;
- `resolved` — present in the baseline, absent now;
- `unchanged` — present in both;
- `escalated` — unchanged, but the grade rose to `confirmed` since the baseline.

`--fail-on` selects the exit-code policy:

| Policy | Exits `1` when |
| --- | --- |
| `new+confirmed` (default) | Either of the two below fires. |
| `new` | A finding is absent from the baseline. |
| `any` | Any finding about the target exists (`vulnerable` or `unexpected_denial`), new or not. An `inconclusive` one does not count. |
| `confirmed` | Any finding is graded `confirmed`, whether it is new, unchanged, or newly escalated. |
| `none` | Never. Report-only — `veridor run` exits `0` under this policy even when `--openapi` is passed and boundary coverage cannot be measured. |

#### Why novelty alone is not a gate

`new` is a set difference over finding ids against `baseline.json` — a file this
guide asks you to **commit to the repository**. Finding ids are deterministic
and stable across runs, which is what makes the diff useful and is also the
whole problem: a pull request that adds twenty characters to that file moves a
live `confirmed` cross-tenant leak from `new` to `unchanged`, and the build goes
green. Measured on the demo target, exit `1` becomes exit `0` — with the console
still printing `1 vulnerable` directly above it.

There is no baseline validation that fixes this, and adding one would be
security theatre. A tampered baseline and a legitimately triaged one are *the
same bytes*: "we accepted this finding last quarter" and "I accepted it in this
diff" are indistinguishable by inspection, because they are the same operation.
Veridor records the baseline's content digest in every run document so two runs
claiming to compare against the same baseline can be shown to have read
different files — but that is forensics after the fact, not a gate.

So the gate moved instead. **`new+confirmed` is the default**: a finding that is
new, *or* a finding whose response actually carried another identity's marker,
regardless of how long it has been in the baseline. Proof of data flow does not
become acceptable by being old, and a gate whose verdict depends on a file
inside the diff it is gating is not a gate.

Every run against a baseline now also names what that baseline is absorbing:

```
Regression diff: 0 new, 0 resolved, 1 unchanged
  Suppressed by the baseline: 1 finding(s) about your target are present in this
  run AND in the baseline, so `--fail-on new` does not see them.
  1 of those carries a marker another identity's response actually contained.
    invoice-tenant-isolation / other_tenant [0ec4c5cbd79deaed6e9f]
```

`--fail-on new` is available and means what it says. It is not the default,
and this guide does not recommend it for CI: use the default,
`new+confirmed`, as the pull-request gate.

`confirmed` is the narrowest gate: it fires only on measured cross-identity
data flow and deliberately ignores novelty, so a pre-existing one keeps failing
the build. It is a complement to `new` — which is why the default is the union
of the two — not a replacement — a genuine
authorization break that happens not to expose a marker is graded `suspected`
and will not trip it, and an over-strict declaration will trip it on behaviour
that is entirely legitimate. Use `confirmed` alone where only measured data
flow may block a release.

Regenerate SARIF, or any other [report format](#report-formats), from a
persisted run without repeating the probes:

```bash
veridor report --from-run current.json --format sarif --output veridor.sarif
```

```
Wrote SARIF report to veridor.sarif
```

`veridor report --input current.json --sarif veridor.sarif` writes the same
file.

### Boundary coverage

A regression suite is only as good as what it covers, and the honest question is
"which operations have a denial asserted at all?" Point Veridor at an OpenAPI 3
or Swagger 2 **JSON** specification to find out — during a run with
`--openapi`, or offline, without issuing a single request:

```bash
veridor coverage --config fixtures/veridor.demo.json --openapi fixtures/openapi.demo.json
```

```
Veridor boundary coverage
  spec:      openapi.demo.json (OpenAPI 3.0.3, 'Veridor Demo API')
  config:    veridor.demo.json
  base path: (none)  (no prefix; 2 of 2 check paths matched)

Authorization boundary coverage: 2/5 operations (40.0%)

  Coverage measures whether a cross-identity denial is ASSERTED for each
  operation. It does not measure whether authorization is ENFORCED.
  Run `veridor run` to test enforcement.

  Every figure here is a fact about your CONFIGURATION, not about any
  run. It is a property of what you wrote down; nothing here observed a
  target.

Corroborated: 2/5 operations

  A positive control is declared in the same check -- one identity asserted
  to be served alongside one asserted to be refused -- so the denial cannot
  pass merely because the route is absent.

3 operations have no cross-identity denial asserted:
  GET    /api/invoices
  DELETE /api/invoices/{id}
  POST   /api/admin/audit/export

Path-level coverage (secondary): 2/4 paths (50.0%)
```

An operation counts as covered when at least one check asserts a denial-only
outcome for at least one identity — which is a fact about your configuration,
not about your target. The badge says `authz denial asserted` / `40.0%
asserted` for exactly that reason: this command opens no socket, so it can
score an API that was never contacted, and a stronger word would claim
enforcement the report explicitly disclaims. Expectations that accept both
success and refusal assert nothing and are reported as diagnostics rather than
counted. An expectation of `401` alone is an authentication assertion and never
counts. The authorization refusals are `403` and `404`; a config can replace
them with a top-level `"coverage": {"denial_statuses": [...]}`, which accepts
only 4xx statuses other than `401` and `407` and is printed with the report
whenever it differs from the default. The block holds `denial_statuses` and
`_` annotations and nothing else. A status outside that rule, a `null`, a
misspelt or unknown key in the block (a near-miss is named), or a `coverage`
that is not an object is refused before the figure is computed: `veridor
coverage` exits `2`, and `run --openapi` reports coverage as not measured.
On that refusal, and on a configuration or specification that does not load,
a `--coverage` file is rewritten with `"status": "not_measured"`, a `null`
figure and the reason, and a `--badge` file as `unknown`, so neither keeps a
previous run's figure.

Coverage still loads and validates the configuration, so the environment
variables the config references must resolve — any placeholder value will do.

When the specification and the configuration share no route, or the
specification declares no in-scope operations, the measurement is **undefined**.
Veridor refuses to render that as `0%`, prints the base-path scoreboard it used,
and exits `2`; the badge is rewritten as `unknown` so a stale green badge cannot
survive. Pass `--allow-no-matches` to accept it, or `--base-path` to state the
specification's prefix explicitly. Coverage never blocks the authorization
result: the probes run and their findings print first, whatever the spec does.

Specifications must be JSON. Veridor has no YAML parser by design, and a
hand-written one could silently drop routes and inflate the number. Convert
once: `npx @redocly/cli bundle openapi.yaml -o openapi.json`.

## Mutate: would my suite catch a regression?

A green run means nothing the gate fails on was found. A finding it does not
gate on (under the default `--fail-on new+confirmed`, one already in the
baseline and not graded `confirmed`) and an unanswered probe without
`--require-complete` exit `0` as well; see [exit codes](#exit-codes). And an
expectation that did hold may not have been able to fail. An expectation of
`[200, 403, 404]` matches whatever the target does; a `404` you read as a
denial may be a route that answers `404` to everybody. Both pass forever, and
neither is a test.

This example has its own target — a second fixture API, on port 8766, separate
from the quickstart's demo server so the frozen mutation numbers below cannot
move when the demo changes. Start it first:

```bash
python3 fixtures/veridor_mutation_fixture.py --port 8766 &
veridor mutate --config fixtures/veridor.mutation-demo.json
```

Without it, `mutate` reports `THE BASELINE DID NOT REACH THE TARGET`, a score of
`n/a`, and exits `2`. That is the correct answer — nothing was measured — but it
is not the one this section is about.

Abridged — the real report also prints per-check and per-operator tables and a
description of every operator:

```
Mutation score: 0.92  (12 killed / 13 generated)
  survived 1  aberrant 0  errored 0  not applicable 2  skipped 3
  0.86 of 14 generated + limited (1 could not be evaluated). A mutation score is only as wide as the mutants it could evaluate.
  skipped, by reason -- no mutant was generated by POLICY, not by measurement:
      1 x the identity was already served 2xx here, so there is no denial
      whose meaning is in question
      1 x the identity declares no credential header, so a fabricated one (M6)
      would leave it already indistinguishable from a caller the target does
      not know
      1 x the request carries no credential to remove, so an unauthenticated
      copy (M4) would be the same request
  requests: 5 baseline, 7 issued by mutation (M4, M5, M6)

SURVIVING MUTANTS (1) -- these checks may be vacuous

  [SURVIVED] M1 invert-denial -- check 'widget-read-permissive', identity outsider
      mutation: declare 'outsider' receives [200] instead of [200, 403, 404]
      (the status 'order_owner' received on this request)
      expected: the mutated expectation must now fail because the target
      REFUSED this identity
      observed: the mutated expectation still passed
      means:    'outsider' was served HTTP 200 on this request and the
      declaration [200, 403, 404] accepted it. The expectation cannot tell
      allowed from denied, so its pass may be vacuous: narrow it to the denial
      statuses you actually require.
```

`mutate` rewrites your expectations one at a time and re-grades them. A mutant
your suite **kills** is a check with the power to fail. A mutant that
**survives** is a check that cannot, and the report says which and diagnoses
why. Six operators run: inverted denials and allows, dropped markers, stripped
credentials, positive controls, and a sham credential the target cannot have
recognised.

The score measures **your declaration, not your target.** Nothing it produces is
a finding, it emits no SARIF, and it never touches `latest.json` — a killed
mutant surfacing in a code-scanning UI would be exactly the false alarm this is
meant to prevent. Its exit code is its own: `0` everything killed, `1` at least
one survivor, `2` nothing was measured or something was unresolved.

### What mutate costs your target

`mutate` re-issues **every request you declared**, `DELETE` included, and then
issues probes of its own on top. It prints the number, the rate and the write
posture before it opens a socket:

```
Veridor mutation -- this will re-issue your 120 declared request(s) to http://api.internal,
  plus up to 500 additional probe(s) of its own.
  rate:      2 req/s (0.5s apart), sequential
  measures:  your declaration. Nothing here is a finding about the target.
!! This configuration issues DELETE. Running it WRITES to the target,
!! once per baseline probe and again for every mutation probe of the
!! same request. Pass --read-only to refuse it before anything is sent.
```

- **`--read-only`** is the same hard refusal `run --read-only` gives you, on the
  same configuration, at either tier: exit `2` before a single request, for any
  verb outside `GET`, `HEAD` and `OPTIONS`.
- **`--min-interval`** defaults to `0.5` — 2 req/s, matching `map` — and covers
  *every* request, the re-issued baseline included, because that is most of the
  traffic. Pass `0` against a fixture you own.
- **`--request-budget`** defaults to `500` and caps the additional probes only.
  The baseline is what `run` issues anyway, and its volume is governed by
  `--max-requests` rather than by this flag.
- **`--max-requests`** defaults to `5,000` and bounds the planned requests,
  baseline included, with the tier-2 exceptions at the end of this point.
  `--min-interval` bounds how fast the target is hit; this bounds how
  much. A plan over the ceiling is refused with exit `2` before the first
  request, and the message names the number it refused so you can raise it
  deliberately. It applies at **both** tiers, and at tier 2 the baseline is
  charged once per hook plus once for the unmutated run, because that is how
  many times it goes on the wire. Each of those tier-2 runs is a full `run`,
  so its liveness controls (one per denial-only `GET`/`HEAD`/`OPTIONS`
  request) are charged too. Session logins and `sequences` steps are not
  counted at tier 2.

`run` is the gate and stays unthrottled. `mutate` is the before-merge analysis
verb, so it takes `map`'s posture rather than `run`'s — including `map`'s
long-standing rule that an oversized plan is *refused*, not merely narrated.

**One deliberate asymmetry.** `map` refuses a public target — neither loopback
nor a private, non-globally-routable address — until you pass
`--acknowledge-target`; `mutate` does not, and that is a decision rather than an
oversight. `map` fans out from a *specification* across every identity, which is
close to scanning, so it asks first. `mutate` re-issues the requests **you**
declared in a configuration **you** wrote naming a `base_url` — exactly what
`veridor run` does — so gating it and not `run` would be incoherent. If you want
one posture everywhere, `--read-only` and `--max-requests` are honoured by
`mutate` at both tiers.

Tier 2 is the exception to the envelope: it runs the suite through `run`'s own
machinery once against the unmutated target and then once per hook, so it
inherits `run`'s posture of no throttle and no probe budget. `--read-only` and
`--max-requests` still apply, and at tier 2 the baseline is charged against the
ceiling once per hook plus once for the unmutated run.

### Tier 2 runs commands you supply

Tier 1 mutates your config. Tier 2 mutates *your target*, using two commands you
write: one that produces a build with a named guard removed, one that puts it
back. Veridor does not parse your source and does not generate the mutation.

```bash
veridor mutate --config veridor.json --tier 2 --hooks hooks.json \
               --i-understand-tier-2-runs-my-commands
```

```json
{
  "hooks": [
    {
      "name": "drop-tenant-filter",
      "removes": "the tenant predicate in InvoiceRepository.find_by_id",
      "apply_command": ["./scripts/mutate.sh", "remove", "tenant-filter"],
      "restore_command": ["./scripts/mutate.sh", "restore", "tenant-filter"],
      "timeout_seconds": 300
    }
  ]
}
```

Say plainly what this does: **`apply_command` and `restore_command` are executed
on your machine, as you, with your environment.** They are run as an argv list
with no shell, so nothing in them is expanded, globbed, or interpreted — but
they are still your commands and they still run. Only the exit status is read;
stdout and stderr are discarded, because a build log is exactly the kind of
artifact that carries a token.

The refusals, all of which happen before anything executes:

- No `--tier 2` without both `--hooks` and
  `--i-understand-tier-2-runs-my-commands`.
- **A hook with no `restore_command` is refused.** There is no default, not even
  a no-op, because "I forgot the restore command" and "this target needs no
  restore" must not be indistinguishable.
- Every argv element must be a non-empty string. A bare string is not a command
  line, and a number from a JSON file is not an argument.
- The whole file is validated together. Hook 3 failing after hooks 1 and 2 have
  already altered your target is a mess, not a diagnostic.

Before any hook is applied, the suite runs once against the target as it is.
A hook is killed only when the suite, with the guard removed, sees an identity
served what its declaration refuses — that is what removing a guard does — and
that means nothing if the suite was red already: when the unmutated run reports
a finding, every hook is reported not applicable and none is applied, and when
it cannot grade everything, every hook is errored. A mutated build that only
refuses is reported aberrant, because a kill needs the suite to see an
identity served what its declaration refuses and it saw only refusals:
whether it refuses an identity the suite expects it to serve — a rebuild that
reset the store, a rotated signing key — or refuses an identity the suite
expects refused with a different status (`401` declared, `302` drawn; `403`
declared, `404` drawn). Veridor cannot tell whether the guard's removal
caused a changed refusal; a guard that hid existence can turn `403` into
`404`. The report names each identity and what it drew, and words the reason
for that case. And an
inconclusive result is never a kill: a mutated run that graded nothing is
errored. Both make `mutate` exit `2`.

`restore_command` runs on every path — apply failing, the suite raising, the
suite passing, the suite going red. If it does not exit `0` the hook is reported
errored, the report says **the target may still be mutated**, and every later
hook is skipped rather than applied on top of a target in an unknown state. A
tier-2 suite run is *full of findings by design* — it runs against a build with
a guard deliberately removed — so its run documents are written to their own
directory and are the measurement, not results about your real target. A worked
example lives in [`fixtures/tier2_guard_toggle.py`](../fixtures/tier2_guard_toggle.py).

## Capsules: sending a proof to someone else

Everything above assumes you own the target. A capsule is for the case where you
don't — you found something in someone else's software and now have to convince
a maintainer it is real.

```bash
veridor capsule --config veridor.json --check invoice-tenant-isolation \
                --from-run .veridor/latest.json --output proof.json
```

One file: the request, the two identities, the declared expectation, the marker,
and the finding you observed. Attach it to the report. The maintainer runs:

```bash
veridor verify proof.json --base-url https://their-own-instance
```

```
Veridor capsule — CONFIRMED

  check:    invoice-tenant-isolation  (Invoice tenant isolation)
  verified: https://their-own-instance
  reported: http://127.0.0.1:8765  (the reporter's target, not this one)
  claim:    finding 0ec4c5cbd79deaed6e9f graded confirmed by the reporter

  The reporter's original statement:
    Identity 'other_tenant' received HTTP 200 (declared: one of [404]) and ...

  CONFIRMED: the declared expectation failed here as well.
```

(The statement is shortened here.) Everything above the verdict line came
from the capsule; the verdict line and the `Scope:` sentence under it are
Veridor's. The verdict line's reason can quote the capsule too: an identity
name, or the grade the reporter claimed, which must be one of the four
Veridor writes. The reporter's statement is shown with each run of spaces
made one and cut at 600 characters (the file keeps all of it), and every other
capsule value is cut at 120, so capsule text takes a few rows at most.

`CONFIRMED` exits `1`, `NOT_REPRODUCED` exits `0`, `INCONCLUSIVE` exits `2`.
`verify` writes the run of the capsule under `--output-dir` (`.veridor/` by
default) with the verdict and that exit code in it, so `report --from-run`
leads with the verdict and `serve` lists the run as `capsule · VERDICT`.
`NOT_REPRODUCED` needs a measurement behind it: every identity the check names
was answered with a status the capsule declares, every marker the check grades
was observed where it had to be, and `liveness.unproven` names no denial on the
check: none that a credential Veridor fabricated drew as well, and none it
could not compare, because no fabricated credential was sent (a write, or no
credential header to shape one on) or its request failed or drew neither a
refusal nor a success. A capsule holds one check, so for a `POST`, `PUT`,
`PATCH` or `DELETE` capsule (`verify` sends no fabricated credential with a
write) a denial-only identity counts as proven live only through its own
`marker_probe`, which `veridor capsule` copies into the file: with one that
draws its marker, a fixed target is `NOT_REPRODUCED`; without one the verdict
is `INCONCLUSIVE` (exit `2`), and the reason says to add it. Give the denied
identity a `marker_probe` before you write a write-method capsule. The control
is on unless you pass `--no-prove-liveness`, and the verdict then says it was
off. Anything short of
that is `INCONCLUSIVE`, never `NOT_REPRODUCED`, and the reason names what was
not measured: an unreachable target, a proxy answering `407`, a `VERIDOR_*`
token the target rejects, or a target that refuses with a different status
than the capsule declares (`404` where it says `403`). A maintainer whose
instance was down, or whose token expired, must not be told the bug isn't real.

`CONFIRMED` does not need that much: an identity got an answer its declaration
rules out. When the evidence here is `suspected` (a status, with no owner-specific
marker observed; the verdict line says so when the reporter's grade was stronger, and
`--json` records each finding's grade), something that answers every request
with `200` produces the same verdict: a proxy, a captive portal, a gateway
serving its own page. Measured: through a proxy answering `200` to everything,
`verify` printed `CONFIRMED`, exit `1`, and the target received none of the
four requests. The run cannot tell that apart from a real vulnerability: it
records the same statuses, marker scans and liveness result as an endpoint
that serves anyone, and a vulnerable instance where nobody planted the
reporter's markers also leaves the owner's marker unobserved. The banner says
when a proxy carries the requests. Before acting on a `suspected`
`CONFIRMED`, look for the requests in the target's own access log.

**`verify` treats the capsule as untrusted input.** It came from someone else,
and it is expanded from *your* environment. Before anything is sent, it refuses
with exit `2`:

- a `${NAME}` that is not `VERIDOR_*`, wherever it appears. `verify` reads no
  other variable, and prints the ones it does read and where it sends them;
- a target that is not this machine's loopback (`127.0.0.0/8`, `::1`,
  `localhost`), unless you pass `--base-url` for your own instance;
- any `POST`, `PUT`, `PATCH` or `DELETE` (a session login included) unless you
  pass `--base-url`, even on loopback, where an untrusted `DELETE` can still
  reach a local admin service. Under `--read-only`, any of them at all;
- a request path that would leave the target: one that becomes an absolute URL
  when joined, or one with a `.` or `..` segment (plain, percent-encoded any
  number of times or as overlong UTF-8, followed by a `;` path parameter as in
  `..;`, which Tomcat and Jetty read as `..`, or beside an encoded `/` or `\`
  as in `..%2f`, which nginx decodes and routes as `../`), which moves it off
  the path written and can take it
  outside the `--base-url` path, to another application behind the same
  gateway. `run` refuses the same paths;
- a `Host` header anywhere in the capsule (a check, an identity, a marker
  probe, a login step or a session `inject`), in any case. urllib sends it in
  place of the `--base-url` host, so behind a gateway that routes by `Host` the
  requests, with your credentials, reach whichever application it names;
- any `run` flag it does not apply. It applies `--base-url`, `--output-dir`,
  `--read-only`, `--json`, `--sarif` and `--no-prove-liveness`;
- a `claim` field (any string in it, a key or a nested value included), the
  `scope` or the check's `name` carrying a terminal control character (an
  escape sequence, a C1 control, a line break, a bidi override such as
  U+202E), which could redraw the verdict on your screen or a report's. Anything else
  `verify` prints from the capsule, a refusal included, is shown escaped
  (`\x1b`), with each run of blanks as one space and at most 120 characters of
  each value, so a long key or value cannot wrap into a screen of its own; the
  `Scope:` line is Veridor's own, not the capsule's copy;
- a `claim.check_id` that differs from the id of the check the capsule
  carries, which would read as `NOT_REPRODUCED` whatever the target did;
- a `claim.evidence_grade` that is not one Veridor writes (`n/a`, `ungraded`,
  `suspected`, `confirmed`). The grade is quoted in the verdict's reason, and
  a long one would wrap into a verdict of its own;
- a check `status` that is not an HTTP status (100-599) or a non-empty list of
  them. A single integer is read as a one-element list, as in a
  configuration.

`veridor capsule` writes only names `verify` accepts: a reference such as
`${MY_TOKEN}` in identity `owner` becomes `${VERIDOR_OWNER_MY_TOKEN}`, and the
command tells you what it renamed. It writes a single-integer `status` as the
list it stands for.

**A capsule carries no credential Veridor can recognise.** It is built from
your configuration *as written*, before `${ENV_VAR}` interpolation, and writing
one is **refused** if a literal value sits where a credential goes: an
`Authorization`, `Cookie` or API-key header, a field, parameter or cookie whose
name reads as a credential (`password`, `accessToken`, `api_key`, ...), or a
`user:password@` URL. Recognition is by name and position, so a secret under a
name the rule does not know (a `customerRef` field, say) is not caught: read
the capsule before you send it. The header case looks like this:

```
veridor: identity 'invoice_owner' carries a literal Authorization value, and a
capsule is meant to be attached to a disclosure and read by someone else. Move
it to an environment variable first, for example "Authorization": "Bearer
${VERIDOR_INVOICE_OWNER_TOKEN}", and re-run. Nothing has been written.
```

There is no override flag. A published bearer token cannot be recalled, the
reporter would not find out until far too late, and the fix is one line. The
capsule instead names the environment variables the reader must supply from
their own instance — which is the right division of labour anyway: a maintainer
should be testing their own deployment, not replaying yours.

It also carries only the identities that one check names, not your whole roster,
and the same scope sentence every other artifact carries: a `CONFIRMED` capsule
says the declared expectation failed there too. It does not say the declaration
was right.

## The local viewer

```bash
veridor serve
```

Opens <http://127.0.0.1:8787> over whatever is in `.veridor/`. It is a **viewer
for artifacts already on your disk** — it never writes, never runs a probe, and
serves nothing outside the output directory.

It has one tab per verb, because each verb makes a different claim and mixing
them is how a hypothesis gets read as a finding:

| Tab | Shows | The claim it is careful about |
| --- | --- | --- |
| **map** | blast radius per identity, matrix counts, anomaly candidates, and the drift diff when there was a baseline | Reach is an **observation**, counted in *operations, not objects*, and every headline is a lower bound. Candidates are **hypotheses**: the panel is titled "HYPOTHESES, NOT FINDINGS" and carries the document's own discipline sentence. Each candidate can expand to show **the rule's declared false-positive modes**, so you can judge it rather than take it on trust. |
| **run** | findings, evidence grades, the baseline diff | The scope block renders above the findings and is never conditional — a passing run states its caveats too. A refusal is counted as "Unexpected denial", never folded into "Vulnerable", and a matched probe is labelled **Matched**, never "Safe". |
| **mutate** | mutation score, surviving mutants and their diagnosis | A survivor means a check **may be vacuous**, never that your target is defective — the same banned-vocabulary list the report uses is enforced on this view by a test. The relationship between coverage and mutation score is rendered in full so the two can't be conflated. |

**Drift renders inside the map view, not in a tab of its own.** A fourth tab
would sell it as a fourth verb, when it is what a map *means* read against an
earlier one — so it sits under the candidate list with its own heading, "A
DIFFERENCE BETWEEN TWO RUNS, NOT A VERDICT". Three states, rendered three
different ways: no baseline given and the panel does not appear at all; a
baseline that matched and it says *nothing moved, which is not a clean bill of
health*; a baseline that did not, and every change is listed with the note
explaining what it does and does not mean. A diff whose two matrices name
different targets is called out above the changes, because that compares
deployments rather than changes.

Two deliberate visual rules. Survivors and candidates are **amber, not red**:
both mean *"you cannot conclude anything here"*, which is a different state from
a measured difference, and colouring them like a finding would overclaim in
exactly the way the report text is written to avoid. And an **incomplete map
says so above its counts** — a rule that never reached quorum produces zero
candidates just like a clean target does, so the two must not look alike.

It follows your system light/dark preference and remembers an explicit choice,
works from the keyboard, respects `prefers-reduced-motion`, and ships no
webfont, CDN or tracker — the Content-Security-Policy is `default-src 'self'`,
so every byte is served from the package. An empty view names the command that
would fill it rather than telling you to select something you do not have.

Localhost and unauthenticated by design. If you want run history shared across a
team, that is a different product than this one, and Veridor does not pretend to
be it.

## Continuous integration

`run` is the verb that belongs in CI, and `mutate` is something you do
deliberately at a desk, because its output is for a human. `map` is too —
except for [drift](#drift-catching-a-regression-with-nothing-declared), which is
built for CI and is the one way to get a gate without declaring anything.

Drift needs last week's matrix, and a CI runner has no `.veridor/` from last
week. Commit the baseline to the repository, the way you would commit a test
snapshot:

```bash
veridor map --config veridor.json --openapi openapi.json \
            --baseline veridor/baseline-matrix.json \
            --fail-on-drift opened
```

Accepting a change is then a reviewable diff in a pull request: re-run without
`--fail-on-drift`, copy the new matrix over `veridor/baseline-matrix.json`, and
commit it with the change that caused it. A reviewer sees *this PR opens
`GET /api/invoices/{id}` to `other_tenant`* next to the code that did it.
Caching the file between runs works too, but a cache miss silently means no
baseline, and the committed file cannot go missing without somebody noticing.

### GitHub Action

Releases are tagged `vX.Y.Z`. There is no Marketplace listing.
`Veridor-authz/veridor@<full-commit-sha>` in the examples below stands for the
full 40-character commit SHA a release tag points to: replace it with that SHA
and keep the version as a comment, the way this repository pins every action
it uses. There is no moving `v0` or `v1` tag while the version is `0.x`: a
minor release may change behaviour, and a floating reference would change what
runs in your pipeline, with your credentials in its environment, without a
commit of yours.

The Action runs Veridor from its own checkout with the runner's Python, which
must be 3.11 or newer (`actions/setup-python` provides one). Nothing is
installed and no package index is contacted; the only network traffic is what
Veridor sends to your target, through a proxy only if the job sets
`http_proxy`/`https_proxy` for it, which the step's log then says. It runs
`python -P -m veridor` with `PYTHONPATH` pointing at the Action's `src/`, so a
`veridor/` directory in your repository cannot stand in for the package, and
it prints the Veridor version and the path it loaded before it starts. A
runner whose `python3` and `python` are both older than 3.11 fails the step
with exit `2`, naming what it found.

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload step only

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      persist-credentials: false
  - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
    with:
      python-version: "3.12"
  - uses: Veridor-authz/veridor@<full-commit-sha> # vX.Y.Z
    id: veridor
    with:
      config: veridor.json
      # Omit on a first run: nothing produces baseline.json, and a missing
      # one is a hard exit 2. Add it once you have a run to compare against,
      # and commit it -- see the note under the drift step below.
      # baseline: baseline.json
      # Not `new`. See "Why novelty alone is not a gate" above.
      fail-on: new+confirmed
      # On by default in the Action; stated here because it is the difference
      # between "verified" and "unverified". A probe the target could not
      # answer -- a 5xx, a rate limit, a timeout, a body too big to scan --
      # exits 3 rather than passing as a boundary that held.
      require-complete: true
      openapi: openapi.json
  - if: ${{ always() && steps.veridor.outputs.sarif != '' }}
    uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    with:
      sarif_file: ${{ steps.veridor.outputs.sarif }}
      category: veridor
```

The step fails with Veridor's own exit code (see [Exit codes](#exit-codes)).
Exit `70` (Veridor crashed: a bug in Veridor, not a finding about your target)
and exit `143` (SIGTERM: a cancelled job or a timeout; teardown ran first and
nothing was concluded) each get their own error annotation. The outputs and the
job summary are written before the step fails, so a later step can read them.
A failure of the Action's own script fails the step too; it never reads as a
pass.

With `summary: true`, the default, the Markdown report is appended to the job
summary: the gate verdict, the counts, the findings and the gate reasons, with
the scope sentences. What earlier steps wrote there is kept. When Veridor exits
before it has written a run document, as it does on a refusal, the summary
says so instead of showing a result.

The SARIF upload is your step, not the Action's, and it needs
`security-events: write` on that job (plus `actions: read` in a private
repository). `always()` is what makes it run after the gate fails, which
is exactly when there is something to upload. The `sarif` output is what
keeps it from uploading the wrong file: it is set only when Veridor wrote the
SARIF during that step, so after a refusal the upload is skipped. Do not test
`hashFiles('veridor.sarif')` instead: it is true for a file an earlier step left
there, and would upload that file as this run's. The SARIF carries
`runs[].automationDetails.id` = `veridor/<run_id>`, and the example passes the
matching `category: veridor`. How code scanning groups and closes the
resulting alerts has not been observed here.

Drift is the same Action with `mode: drift`:

```yaml
  - uses: Veridor-authz/veridor@<full-commit-sha> # vX.Y.Z
    with:
      mode: drift
      config: veridor.json
      openapi: openapi.json
      matrix-baseline: veridor/baseline-matrix.json
      fail-on-drift: opened
      matrix: current-matrix.json
      acknowledge-target: I am authorized to test staging.example.com
```

`matrix` writes this run's matrix so a failing build gives you the file to
review and commit. `acknowledge-target` is required verbatim whenever the
target is neither loopback nor a private address — a job pointed at a service
container on `localhost` does not need it, one pointed at real staging does.

Two things about that step are worth stating plainly. A `matrix-baseline` that
does not exist **fails the step** rather than passing as a gate with nothing to
compare, and so does one that exists but shares no measured cell with this run
(Veridor exits `3`; a baseline recorded while the target was down is the usual
cause). And `fail-on-drift` defaults to `opened` here while the `veridor map`
CLI defaults to `none`: the CLI is a discovery command with many uses, whereas
selecting `mode: drift` in CI is itself the request for a gate.

An input belonging to the other mode is refused with exit `2`, not ignored.
Mode-specific inputs default to empty so the refusal can see them: `sarif`,
`junit`, `json`, `baseline` or `fail-on` on a drift step, and `fail-on-drift`
or any other drift input on a run step, are refused whatever their value. The
one thing the Action cannot tell apart is an input you left out and one you set
to an empty string, so `sarif: ''` on a drift step is accepted silently; it
asks for nothing. The boolean inputs (`read-only`, `require-complete`,
`require-clean-teardown`, `allow-no-matches`, `summary`) accept `true` or
`false` in any letter case and nothing else: `yes`, `1`, `on` and an empty
value are refused, naming the input. Compared as text, `read-only: yes` would be
unequal to `true` and silently turn the refusal of mutating requests off.

One step is one verb. If you want both a declared gate and drift, use two
steps — they exit non-zero for different reasons, and a shared exit code would
hide which one failed.

**Inputs.** `tests/test_action.py` fails if this table and `action.yml`
disagree on a name, a default or a mode.

| Input | Default | Mode | What it does |
| --- | --- | --- | --- |
| `mode` | `run` | both | `run` or `drift`; one verb per step |
| `config` | required | both | Path to the Veridor JSON configuration |
| `baseline` | — | run | A prior run JSON to compare against |
| `output-dir` | `.veridor` | both | Directory for run history |
| `sarif` | — | run | SARIF path; empty means `veridor.sarif` |
| `junit` | — | run | JUnit XML path; empty means a file under `RUNNER_TEMP` |
| `markdown` | — | both | Markdown report path; empty means a file under `RUNNER_TEMP` |
| `summary` | `true` | both | Append the Markdown report to the job summary |
| `fail-on` | — | run | Gate policy; empty means `new+confirmed` |
| `json` | — | run | Run JSON path; empty means a file under `RUNNER_TEMP` |
| `base-url` | — | both | Override `target.base_url` |
| `wait-for-target` | `0` | both | Seconds to wait before the first request for the target's port to accept a TCP connection; `0` does not wait. Never changes a verdict |
| `openapi` | — | both | OpenAPI 3 or Swagger 2 JSON; enables coverage; required for drift |
| `coverage` | — | both | Coverage report JSON path (needs `openapi`) |
| `badge` | — | both | shields.io badge endpoint JSON path (needs `openapi`) |
| `base-path` | — | both | Specification path prefix (needs `openapi`) |
| `allow-no-matches` | `false` | both | Report coverage as not measured instead of failing (needs `openapi`) |
| `matrix-baseline` | — | drift | The committed matrix FILE to diff against; required |
| `fail-on-drift` | — | drift | `opened` (what empty means), `any` or `none` |
| `drift` | — | drift | Drift report JSON path; empty means a file under `RUNNER_TEMP` |
| `matrix` | — | drift | Also write this run's matrix here |
| `acknowledge-target` | — | drift | `I am authorized to test HOST`, for a target that is not private |
| `max-requests` | — | drift | Refuse a matrix plan larger than this |
| `rate` | — | drift | Requests per second |
| `read-only` | `false` | run | Refuse a configuration that can send anything but GET, HEAD or OPTIONS |
| `require-complete` | `true` | both | Exit `3` when any probe went unanswered, or (run mode) a denial is unproven (`liveness.unproven`): a denial-only expectation (in a check, or a sequence assert step) whose identity presents a credential, where some identity was served in the same check or sequence, that nothing else in the run proved live (a 2xx it drew on a request where an identity with no credential, or the fabricated credential, was refused; or its `marker_probe`; for a session, either one only under the same login and session cookie value), and that a fabricated credential could not tell apart from a dead token: it drew the same denial, none was sent (with every POST, PUT, PATCH or DELETE, inside a sequence, or when no identity declares a credential header), its request failed, or its answer was neither a refusal nor a success. Give that identity a `marker_probe`; for one with `"reestablish": "check"` a `marker_probe` proves only the first login, so use `"reestablish": "run"` or show it served in the same sequence, and one whose session cookie the target replaced needs a 2xx sent after the change |
| `require-clean-teardown` | `false` | run | Exit `3` when a sequence teardown was unclean |

**Outputs.** The test also fails if an output is missing here or not declared in `action.yml`.

| Output | Mode | What it holds |
| --- | --- | --- |
| `exit-code` | both | Veridor's exit code; written on every path out of the step |
| `version` | both | The Veridor version the Action ran |
| `run-json` | run | Path of the run document |
| `sarif` | run | Path of the SARIF file |
| `junit` | run | Path of the JUnit XML report |
| `markdown` | both | Path of the Markdown report |
| `drift-json` | drift | Path of the drift report |
| `coverage-json` | both | Path of the coverage document, when `openapi` is set |
| `run-id` | run | The run identifier |
| `gate-exit-code` | run | The exit code the gate decided, from the run document |
| `gate-reasons` | run | The gate's reasons as one line of JSON; `[]` when it passed |
| `findings` | run | Findings of every verdict |
| `findings-new` | run | Findings absent from the baseline |
| `findings-vulnerable` | run | Findings whose verdict is `vulnerable` |
| `findings-inconclusive` | run | Probes that could not be graded |
| `coverage-percent` | both | Boundary coverage, to one decimal place |
| `coverage-status` | both | The coverage document's own status string |
| `drift-changes` | drift | Differences from the baseline |
| `drift-significant` | drift | Differences that mean more access |
| `drift-blind-cells` | drift | Cells the baseline never measured |

A path output (`run-json`, `sarif`, `junit`, `markdown`, `drift-json`,
`coverage-json`) is set only when Veridor wrote that file during this step,
and is empty otherwise, after a refusal for one. Set either way, `sarif` would
name, after a refusal, whatever an earlier step had left at `veridor.sarif`.
Counts, too, are read only from documents Veridor wrote during this step: the
step notes which file sits at each path before Veridor starts and takes a path
only if a different file is there afterwards. Comparing modification times would
let a document written in the same second, or with a clock ahead, pass as this
step's.

```yaml
- uses: Veridor-authz/veridor@<full-commit-sha> # vX.Y.Z
  id: authz
  continue-on-error: true          # you MUST re-fail below, or the gate is off
  with:
    config: veridor.json
    openapi: openapi.json
- name: Comment on the pull request   # needs pull-requests: write
  if: ${{ always() && github.event_name == 'pull_request' && steps.authz.outputs.findings-vulnerable != '' && steps.authz.outputs.findings-vulnerable != '0' }}
  env:
    GH_TOKEN: ${{ github.token }}
    PR: ${{ github.event.pull_request.number }}
    VULNERABLE: ${{ steps.authz.outputs.findings-vulnerable }}
    INCONCLUSIVE: ${{ steps.authz.outputs.findings-inconclusive }}
  run: |
    gh pr comment "$PR" --body "Veridor: $VULNERABLE vulnerable, $INCONCLUSIVE inconclusive. The job summary has the rest."
- name: Re-fail on the gate's exit code
  if: ${{ always() }}                 # without this the build is green on a finding
  env:
    VERIDOR_EXIT_CODE: ${{ steps.authz.outputs.exit-code }}
  run: exit "${VERIDOR_EXIT_CODE:-1}"
```

**`continue-on-error: true` turns the gate off.** It is required to read outputs
after a failing run, and it makes the Action *advisory* until you re-fail on
`exit-code` yourself — which is what the last step above is for. Without it, a
run that finds a live cross-tenant read leaves the build green. The `:-1` is
deliberate: a missing `exit-code` means the step did not get far enough to have
an opinion, and that is not a pass. The `!= ''` guard on the comment matters for
the same reason — on exit `2` no run document exists, so no `findings-*` output
is emitted at all and a bare `!= '0'` compares against an empty string and fires.

Quote `findings-vulnerable` in a summary, not `findings`: the latter counts
inconclusive probes too, and a probe that went unanswered is not a finding about
your target. `findings-inconclusive` and `drift-blind-cells` are there for the
same reason — a gate that passes with either of them high has not established
what its silence suggests.

SARIF results carry `partialFingerprints.veridorFindingId/v1` plus `verdict`,
`evidenceGrade`, and `markerState` properties, so code scanning tracks the same
identity Veridor does. Findings are also emitted as file annotations. Keep
tokens in Actions secrets and reference them through `${NAME}` in the config.

**Runners.** The Action needs bash and Python 3.11 or newer on `PATH`.
`.github/workflows/veridor.yml` runs it through `uses: ./` on `ubuntu-latest`
and `macos-latest` (the `action-e2e` job). Both passed on GitHub-hosted runners
on 2026-11-08 (CI run 42508338432): the vulnerable demo failed the step with exit 1 and
one finding and wrote SARIF and JUnit; the fixed one passed. That job uploads
SARIF to code scanning only on a manual run, so no upload has been seen. The
harness in `tests/action_harness.py` executes `action.yml` step by step
under the runner's bash flags: on macOS with bash 3.2 and on Linux with bash
5.2 in a container. Windows runners have not been tried.

### Report formats

`veridor run --report FORMAT=PATH` (repeatable) writes the run as `sarif`,
`junit`, `gitlab-sast` (GitLab security report, schema 15.2.5), `codequality`
(GitLab Code Quality) or `markdown` (a job summary or merge request note).
`veridor report --from-run run.json --format FORMAT [--output PATH]` renders
the same report later from the run JSON, to stdout when `--output` is `-` or
omitted:

```bash
veridor run --config veridor.json --report junit=veridor-junit.xml --report markdown=summary.md
veridor report --from-run run.json --format gitlab-sast --output gl-sast-report.json
```

Reports are written whatever the gate decides. The run document carries the
decision the process exited with as a `gate` object (`fail_on`, `exit_code`,
and machine-readable `reasons` such as `findings`, `nothing_answered`,
`identity_unauthenticated` or `inconclusive`), and every format except SARIF
renders it: an exit `3` that is not a finding fails the `veridor.gate` JUnit
case, sets the GitLab `scan.status` to `failure`, and never reads as "passed"
in Markdown. SARIF carries findings only and has no gate, so a run that exited
3 for an unproven denial or an unclean teardown renders as zero results, the
same bytes as a run that exited 0. For SARIF, read the job's exit code.
[docs/report-formats.md](report-formats.md) has the reason codes, the
severity mappings, and what each format does not claim.

### Contributing, and reporting a problem

[CONTRIBUTING.md](../CONTRIBUTING.md) covers the test tiers, the end-to-end
checks and the claim discipline a change has to stay inside.
[CHANGELOG.md](../CHANGELOG.md) records what moved between releases,
[GOVERNANCE.md](../GOVERNANCE.md) how decisions are made, and
[SUPPORT.md](../SUPPORT.md) where questions go. Commits are signed off under the
DCO, and [CONTRIBUTING.md](../CONTRIBUTING.md#ai-assisted-commits-and-provenance)
says who is the author of a commit written with AI assistance. Running Veridor
somewhere real? Add yourself to [ADOPTERS.md](../ADOPTERS.md).

Found something that would let an attacker reach a target, escape a safety gate,
or read a credential? Report it privately — [SECURITY.md](../SECURITY.md) has the
route, plus what Veridor does with your credentials and which of its dangerous
capabilities are deliberate. If a report or document overstates what was
measured, that is a defect here too, and there is an issue template for it.

### Working on Veridor itself

Veridor's own suite is split in two, because a tool that asks you to run it on
every commit has to be buildable on every commit.

```bash
python3.12 scripts/run_tests.py --tier fast            # every commit
python3.12 scripts/run_tests.py --tier slow --jobs 4   # before merge
python3.12 scripts/run_tests.py                        # both, in one process
```

The suite runs from a clone or a GitHub source archive. The sdist carries
only what builds the wheel: `MANIFEST.in` leaves `tests/` out, and
`scripts/release_check.py dist` refuses an sdist that carries it or that is
missing any file the wheel installs.

Name the interpreter version, or work inside the virtual environment from
[Install](#install). Both scripts refuse anything older than 3.11 and say so
before running a thing, because on macOS the bare `python3` is 3.9 and a
partial collection under it reads as a broken repository.

Measured on 2026-10-15, Python 3.12, one arm64 laptop, medians of 3
interleaved runs with helm, kubectl and shellcheck required (ranges: fast 13.8
to 14.0s; slow 348.4 to 350.0s, and 90.8 to 91.2s with `--jobs 4`; both 363.9
to 364.8s), on that day's 3,260-test tree. The counts below are kept current
by `scripts/sync_doc_counts.py`; the times are not, so they grow as tests are
added until the next measurement:

| Tier | Tests | Wall time | Contains |
| --- | --- | --- | --- |
| `fast` | 2,657 | **13.9s** | Pure unit tests: config validation, fingerprints, parsing, scoring arithmetic, report rendering, documentation contracts |
| `slow` | 1,014 | 349.7s; 91.2s with `--jobs 4` | Anything that stands up a loopback HTTP server, drives a live target, or spawns a subprocess |
| both | 3,671 | 364.0s | The whole suite, in one process, with no guard |

`--jobs N` runs the slow tier in N worker processes that take whole test
classes from one queue. The run fails unless every worker finished and,
between them, they started exactly the tests a serial run selects, each once.
A class whose `setUpClass` or `setUpModule` skipped in a worker runs again,
alone, once the others finish. With or without `--jobs`, a tier fails when it
selects no test or does not start one it selected. `--report PATH` writes each
test's start and outcome as JSON lines. The fast tier and `all` refuse
`--jobs`, because the fast tier's guard, per-test budget and stdout check
assume one process.

The boundary is enforced, not conventional. The fast tier runs with sockets and
subprocesses monkeypatched to raise, so an unmarked test that reaches the
network fails by name and tells you which marker it is missing, and no fast test
may spend more than two seconds of CPU time and sleep, or 30 on the wall clock.
The whole tier may take 300 seconds.
`tests/tiers.py` holds the mechanism and
`tests/test_tiers.py` asserts the two tiers are a partition of the whole suite.
`python3.12 -m unittest discover -s tests` still runs everything, unchanged.

**Both tiers test Veridor against targets this project wrote.** That is the
weaker half of the claim: a target written to have the bug cannot drift from
the oracle that looks for it. The other half is
[`scripts/patched_pairs.py`](../scripts/patched_pairs.py), which runs one
configuration against a published advisory's own software at the two tags either
side of the fix:

```bash
python3.12 scripts/patched_pairs.py          # every pair; needs docker
python3.12 scripts/patched_pairs.py --pull   # docker pull each image by digest first
python3.12 scripts/pair_sizes.py             # what the pairs download, read from the registry
```

A pair passes only when the verdict **flips** — and four further assertions
stop the flip being hollow: the endpoint has to survive the fix (or a removed
route reads as "fixed"), the owner's control probe has to still reach the
marker (the four status-only pairs, whose control asks for no marker, are
held to its status alone, and the output names that check not evaluated), the
evidence grade has to be the one the pair declares, and every
denial on the patched build has to have reached a credential the run proved
live (served elsewhere in the run, or answered differently from a credential
Veridor fabricated). Without that last one a dead attacker session that the
target refuses like any stranger would certify the fix; given a dead Ghost
contributor session, the pair fails (measured 2026-10-14). Today that is
thirteen published advisories in ten applications (Gitea three times, Ghost
twice, LubeLogger, Bugsink, Audiobookshelf, Vikunja, Datasette, InvoiceShelf,
Eclipse hawkBit, Domoticz; Go, Python, C#, Node, PHP, Java and C++), 87
assertions: twelve carry a CVE id and LubeLogger's carries a GHSA id. Each fixture
cites where its id was published; each Gitea pair links its CVE record, and all
three cite the one release post that fixed them.

Every image runs pinned by the digest in its fixture, as `image:tag@sha256:…`,
and a tag the local Docker already holds that no longer names the pinned build
stops the run before any pair starts.

One pair is built, not pulled. Datasette publishes no image of the 1.0 alphas
CVE-2023-40570 sits between, so its fixture carries a `build` block instead of
digests: a recipe under `fixtures/pairs/recipes/`, a base image by digest and the
package, with each side's published file named by its sha256
(`vulnerable_sha256`, `patched_sha256`). A base by tag, a missing or shared
file hash, digests alongside the build, or an image name outside
`veridor-pair-build/` is refused at load. Both sides are built before any pair
runs: the recipe installs with `pip --require-hashes --only-binary=:all:` from
one lock both sides share, the image is then asked, with no network, which
release it holds, and its tag carries a hash of every input, so a changed
recipe or pin never runs an older image. A failed build fails only its own
pair. The lock carries both architectures' hashes for its two compiled wheels:
resolved on arm64 alone, it was refused on linux/amd64, which is what a GitHub
runner is (measured).

For the twenty images and the built pair's base and files, a linux/amd64
runner downloads 2.42 GB, compressed, each layer and file counted once
(2,424,520,975 bytes, read from the registries and PyPI on 2026-11-09; the
Datasette pair is 49,587,267 of them). `pair_sizes.py` measured all of it but
the two hawkBit images, which hawkBit publishes as single linux/amd64 manifests
rather than an index, and which it refuses; those two were sized from their
manifests after their config blobs confirmed linux/amd64. `pair_sizes.py` reads each pinned index
from Docker Hub or ghcr.io, checks it against its digest, picks the platform's
manifest (`--platform`, default linux/amd64) and sums its layers; for a built
pair it reads the base the same way and each pinned file's size from PyPI, by
its hash. It never asks Docker: the disk usage
`docker image ls` reports counts the unpacked copy as well, so it is not what
a runner downloads.

Every pair is configured to run everywhere:

- `detection-baseline` is configured to run `--pull`, every pair, on every pull request and every push to main.
- The release workflow is configured to run every pair against the wheel it built, installed
  alone in a fresh virtual environment under `VERIDOR_TEST_AGAINST=installed`,
  before the provenance attestation and the PyPI upload, which both wait for it.

There is no lighter subset. A fixture that carries a `"heavy"` key is refused,
and a pair too large to run on every pull request is replaced by a cross-user read
in the same language, not skipped.
`--pair NAME` runs one pair; a `--pair` that names nothing exits `2`, never
`0`, and every pair it leaves out is named, with the reason. Under
`VERIDOR_TEST_AGAINST=installed` the harness prints which `veridor` it imports
and refuses to start unless an installed distribution's RECORD lists the
`veridor.cli` it imports and that file is outside this checkout's `src/`, so
neither a copy of the package nor a `veridor/` directory in the working
directory is tested in the wheel's place.
`tests/test_workflows.py` refuses a CI or release file that drops the job,
gives it an `if:`, makes it wait on another job, adds another job that runs the
harness, drops or filters the pull request or push-to-main trigger, narrows
either run, puts a step-level `if:` on any release step, or runs anything
before the pairs but the checkout, setup-python and, at release, the `dist`
download and the wheel install, each with its exact inputs (the harness runs
whatever `fixtures/pairs/` holds when it starts). Timed on one arm64 laptop
with every image and the Datasette pair's build layers already present
(2026-10-15, three runs, load average about 2.5 from other work): every pair
with `--pull` took 53 seconds median (52 to 64). On a GitHub-hosted `ubuntu-latest`
runner the CI job's `--pull` step took 155 seconds (one
run, 2026-11-08). The release job had not run by then.

`--pairs-dir DIR` (or `VERIDOR_PAIRS_DIR`) also runs the pairs in a directory
outside the repository. It is for findings whose details are not public yet: a
fixture describes the bug, so shipping one here would disclose it. A
`provisioners.py` in that directory is imported and may add runtimes and
provisioners, never rebind one the harness ships, and a pair name may not be
used twice, so a private directory cannot quietly replace a published advisory's
pair. The run names how many pairs came from where.

It fails when detection breaks; that was measured by breaking it, on the nine
pairs the set held then, last on 2026-10-14. With the status oracle made to accept an undeclared
200, the two status-only pairs fail, `gitea-private-org-membership-confirmable`
and `datasette-private-instance-api-explorer` (each vulnerable build exits 0
with no finding), and the seven marker pairs still catch their advisory's bug through the
marker. With a matched marker read as absent, those seven fail, LubeLogger,
Bugsink and Ghost among them, and the two status-only pairs still pass.
Either change exits 1. The four pairs added since, InvoiceShelf and hawkBit
(marker) and Domoticz and Ghost 6 (status only), have not been run with
detection broken. `tests/test_workflows.py` keeps at least one pair of each
kind in the set.

### GitLab CI

[`templates/veridor.yml`](../templates/veridor.yml) is a GitLab CI/CD component:
one gate job that runs `veridor run` and publishes its JUnit, GitLab SAST and
Code Quality reports through `artifacts:reports`. Include it from your own
`.gitlab-ci.yml`:

```yaml
include:
  - remote: "https://raw.githubusercontent.com/Veridor-authz/veridor/COMMIT_SHA_OF_THE_RELEASE_TAG/templates/veridor.yml"
    integrity: "sha256-REPLACE+with+the+base64+SHA256+of+that+file="
    inputs:
      config: veridor.json
      base_url: "https://staging.example.com"
```

Pin the include to a commit, not to the tag URL
`https://raw.githubusercontent.com/Veridor-authz/veridor/v0.1.0/templates/veridor.yml`.
GitLab fetches a remote include again for every pipeline, with no notice when
it changes, and the included job runs with your project's CI/CD variables,
credentials included; a tag can be moved. Put the full commit SHA the release
tag points to in the URL, and set `integrity` to `sha256-` followed by the
base64 SHA-256 of the file at that commit
(`curl -fsSL URL | openssl dgst -sha256 -binary | base64`). `integrity` needs
GitLab 17.9 or later; on an older GitLab, drop it and keep the commit URL.
Left as shown, both placeholders stop the pipeline rather than run anything.

Once the repository is mirrored to GitLab and released there, the CI/CD
Catalog form is `include: component: gitlab.com/Veridor-authz/veridor/veridor@0.1.0`.
The `v0.1.0` tag publishes the `ghcr.io/veridor-authz/veridor:0.1.0` image the
job runs and the PyPI package; it does not publish a Catalog entry. The Catalog
address assumes the `gitlab.com/Veridor-authz` namespace belongs to this project,
and nothing here shows that it does. Whoever holds that namespace could publish a
component at that address, and it would run with your CI/CD variables, so check
the holder before you use it.
[`ci/.gitlab-ci.yml`](../ci/.gitlab-ci.yml) shows both forms.

The job exits with Veridor's own code and prints one line saying what that
code means. Exit `3` fails the job unless `allow_unmeasured` is `true`; then
`allow_failure: exit_codes: [3]` shows exit 3, and only exit 3, as a warning.
Nothing in the component uses `allow_failure: true` or `|| true`. A rule you
pass in `job_rules` can still set `allow_failure`, which GitLab documents as
overriding the job's own; `allow_failure: true` there would show a finding
as a warning. The component cannot check those rules: leave `allow_failure`
out of them. GitLab
writes input text into the job's script before the shell reads it, so every
input that lands there refuses a `$` that does not begin a `$NAME` or `${NAME}`
reference: `$(...)` and `${NAME:...}` fail when the pipeline is created,
instead of running in the job that holds your credentials. Credentials
are masked CI/CD variables named as the configuration's `${VERIDOR_*}`
references. A merge request pipeline from a fork gets none of them, and an
unset or empty one makes Veridor stop with exit 2 before sending anything. In
the Veridor image the job runs as uid 10001, so the project directory must be
writable by it. GitLab Runner's documentation says its docker executor makes
it so by default; when it is not, the job stops with exit 2 and says why.

| Input | Type | Default | What it does |
| --- | --- | --- | --- |
| `stage` | string | `test` | The stage the job runs in. The gate probes whatever `base_url` serves when it starts, so run it after the job that deploys that target, in a later stage or with `needs:` on that job. `test` runs before GitLab's default `deploy` stage |
| `job_name` | string | `veridor` | The job's name; include the component twice under two names to gate two configurations |
| `install` | string | `image` | `image` runs the Veridor container image; `pip` installs `pip_package` into `python_image`, for runners that cannot pull it |
| `image` | string | `ghcr.io/veridor-authz/veridor:0.1.0` | The Veridor image (`install: image`); pin it by digest |
| `python_image` | string | `python:3.12-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111` | The Python 3.11+ image (`install: pip`), pinned by digest: the job runs pip and the gate in it with every credential. The digest is the one the release Dockerfile builds on. It has no bash; the job's script needs none |
| `pip_package` | string | `veridor==0.1.0` | What pip installs (`install: pip`): a pinned requirement or a wheel path |
| `config` | string | `veridor.json` | The Veridor configuration |
| `base_url` | string | (empty) | Overrides `target.base_url`. Every credential is sent here, so prefer a literal URL. For a review app, a variable the deploy job writes to a dotenv report ([`ci/.gitlab-ci.yml`](../ci/.gitlab-ci.yml) shows how), but only where the project's *Minimum role to use pipeline variables* excludes everyone who may not read the credentials: a pipeline variable of the same name outranks the dotenv value. Not `$CI_ENVIRONMENT_URL`, which GitLab sets only in a job with an environment. A variable that is empty when the job runs is refused, not ignored |
| `proxy_from_environment` | boolean | `false` | `false` runs Veridor without any `*_proxy` variable (`http_proxy`, `HTTPS_PROXY`, any case), so its requests go straight to the target, and the log names what was removed. A pipeline variable of that name would otherwise pick where every credential goes, whatever `base_url` says. `true` keeps them, for a target reachable only through a proxy |
| `wait_for_target` | number | `0` | `--wait-for-target`: seconds to wait before the first request for the target's port to accept a TCP connection; `0` does not wait, and anything but a whole number is refused. Never changes a verdict |
| `fail_on` | string | `new+confirmed` | `--fail-on`: `new+confirmed`, `new`, `confirmed`, `any` or `none`. The default fails on every finding not in the baseline, and on a confirmed one even when the baseline holds it. A suspected or ungraded finding stops failing once its id is in the baseline |
| `require_complete` | boolean | `true` | `--require-complete`: an unanswered probe exits 3, and so does an unproven denial (`liveness.unproven`): a denial-only expectation (in a check, or a sequence assert step) whose identity presents a credential, where some identity was served in the same check or sequence, that nothing else in the run proved live (a 2xx it drew on a request where an identity with no credential, or the fabricated credential, was refused; or its `marker_probe`; for a session, either one only under the same login and session cookie value), and that a fabricated credential could not tell apart from a dead token: it drew the same denial, none was sent (with every POST, PUT, PATCH or DELETE, inside a sequence, or when no identity declares a credential header), its request failed, or its answer was neither a refusal nor a success. Give that identity a `marker_probe`; for one with `"reestablish": "check"` a `marker_probe` proves only the first login, so use `"reestablish": "run"` or show it served in the same sequence, and one whose session cookie the target replaced needs a 2xx sent after the change |
| `allow_unmeasured` | boolean | `false` | Show exit 3 as a warning instead of failing the job |
| `baseline` | string | (empty) | `--baseline`: a prior run JSON to diff against. It is part of your merge request's diff, so require Code Owner approval for it (GitLab Premium) |
| `openapi` | string | (empty) | `--openapi`: enables boundary coverage |
| `output_dir` | string | `veridor-out` | Where the run history and every report go |
| `extra_args` | string | (empty) | More `veridor run` flags. One that would override an input above, or `--help`, is refused, abbreviations included |
| `artifacts_expire_in` | string | `30 days` | `artifacts:expire_in` |
| `job_rules` | array | `[{"when": "on_success"}]` | The job's `rules`. The default puts the gate in every pipeline your workflow creates; anything narrower leaves the gate out of the pipelines it skips. A rule's `allow_failure` overrides the job's own, so leave it out |

**Where the job runs.** By default, in every pipeline your workflow creates.
Narrower rules, such as merge request pipelines plus the default branch, leave the
job out of every other pipeline, with no failed or skipped job to show for it when
that pipeline has other jobs: a project using only branch pipelines (GitLab's
Branch-Pipelines workflow) never runs the gate before merge, and tag pipelines
and child or multi-project pipelines off the default branch run without it. The cost: a project with no `workflow:rules` gets two pipelines
for each push to a branch with an open merge request, as GitLab documents for
any job whose rules match both, and the gate runs in both. To run it once, add
`workflow:rules` that pick one pipeline type, such as GitLab's
[switch between branch and merge request pipelines](https://docs.gitlab.com/ci/yaml/workflow/#switch-between-branch-pipelines-and-merge-request-pipelines)
recipe ([`ci/.gitlab-ci.yml`](../ci/.gitlab-ci.yml) shows it). Setting `job_rules`
instead restricts the gate itself, and each pipeline the rules leave out then
runs without it. These rules were evaluated against a model of the variables
GitLab sets in each kind of pipeline, read from GitLab's source and
documentation (`tests/test_ci_configs.py` `JobRulesTest`); no GitLab instance
was used.

Under `output_dir` the job writes `gl-sast-report.json`, `veridor-junit.xml`,
`gl-code-quality-report.json`, `veridor-run.json` and `veridor-summary.md`.
The component has not run on a GitLab runner. `scripts/e2e_gitlab_job.sh` runs
the job's own rendered script in docker against the demo server. It checks
exit codes 0, 1, 2, 3 and 143, each report, every input that changes the
job's script, that every refusal sends nothing to a target it counts, and that
a proxy named by a pipeline variable receives nothing unless
`proxy_from_environment` is `true`. [ci/README.md](../ci/README.md#what-was-tested) lists that run and what
remains untested.

### Other CI platforms

[`ci/README.md`](../ci/README.md) is the guide for everything that is not GitHub
Actions. It covers install options, credentials, exit codes, which platform
reads which report, and what was and was not tested.

| Platform | File | What it publishes |
| --- | --- | --- |
| GitLab CI | `templates/veridor.yml`, used from `ci/.gitlab-ci.yml` | JUnit, SAST and Code Quality via `artifacts:reports` |
| Jenkins | `ci/Jenkinsfile` | JUnit, and SARIF through Warnings NG when it is installed |
| Azure Pipelines | `ci/azure-pipelines.yml` | JUnit via `PublishTestResults@2`, the Markdown summary, SARIF as an artifact |
| AWS CodeBuild | `ci/buildspec.yml` | JUnit report group; SARIF and the run JSON as artifacts |

**Jenkins, Azure and CodeBuild have never run on their own platform**, and each
file says `UNTESTED` in its header. Exit 3 fails the build on all three unless
you opt in: UNSTABLE on Jenkins, SucceededWithIssues on Azure. CodeBuild has
no warning state, so there it always fails. The base URL, which receives every
credential, and the settings that can weaken the gate are fixed in the
Jenkinsfile and the Azure YAML, not build or queue-time parameters. On
CodeBuild, `StartBuild` can override them, so IAM has to deny that
([ci/README.md](../ci/README.md#credentials) says how). A fixed base URL is not
the whole answer: Veridor follows `http_proxy` or `https_proxy` for a target
that is not loopback, so whoever may add such a variable when a build starts
chooses where the credentials go too, and `PIP_INDEX_URL` picks the code a
pip install runs. The GitLab component runs Veridor without any `*_proxy`
variable unless `proxy_from_environment` is `true`. For every platform,
[ci/README.md](../ci/README.md#credentials) names the setting that decides who
may add a variable when a build starts. Each gate shell has been executed
against the demo server outside its platform. Every `veridor` command line in
every file is parsed by the CLI's own parser on every test run.

AWS **CodeDeploy** is a deployment service and has no build phase to put a gate
in; the gate belongs in CodeBuild, which is what `ci/buildspec.yml` targets.

### This repository's own workflow

The repository's own workflow at `.github/workflows/veridor.yml` is configured
to run both tiers on Python 3.11, 3.12 and 3.13 on Linux and 3.12 on macOS,
with helm, kubectl and shellcheck installed and required; the suite again
against the installed wheel (`VERIDOR_TEST_AGAINST=installed`, see
`tests/source_path.py`); the Action through `uses: ./`; actionlint, shellcheck
and the Helm chart lint; the Kubernetes end-to-end script; the GitLab and
Azure templates against those platforms' published schemas, fetched by pinned
URL and sha256; the GitLab end-to-end script, after its three controls have
failed as they must; and the release image as the gate, with a check that
`--version` and a `run` of the demo in it compile no Python module from
source (and two control images the check must fail: one built without the
step that makes that true, and one with that step as it was before `run` was
checked). The release workflow is configured to check each platform's image
the same way before it pushes, and the pushed digest again before it signs.
Every one of those CI jobs passed on GitHub-hosted runners on 2026-11-08 (CI run 42508338432, at
`38025ed`), before the release workflow had run. While the repository was
private, the CodeQL and OpenSSF Scorecard workflows failed on it: CodeQL's upload
needed Advanced Security enabled, and Scorecard's query of the repository was
refused ("Resource not accessible by integration"). The Linux Python 3.12 leg
also runs the end-to-end validation:

```bash
python3.12 scripts/e2e_validation.py
```

It starts a safe fixture API and verifies all six probes, starts a deliberately
vulnerable fixture and detects the cross-tenant BOLA regression against the safe
baseline, asserts the marker oracle graded it `confirmed`, checks that no marker
literal reached any artifact, validates the exit code and SARIF fingerprints,
reads run history and the regression diff back through the UI's HTTP API, and
exercises `map`, promotion stubs, the mutation score and the tier-2 refusals. It
prints `E2E PASS` for each half only when all of that succeeds.

## Exit codes

`veridor map` exits `0` when it produced a map, whatever it found, unless you
asked [`--fail-on-drift`](#drift-catching-a-regression-with-nothing-declared)
for a gate and the matrix moved — then `1` — or the comparison measured nothing,
with no cell measured in both this run and the baseline — then `3`. It also
exits `3` when its own grid probed cells and measured none of them (a
redirect, which Veridor does not follow, does not count as measured), or with
`--require-complete` when any probed cell went unmeasured (a rate limit, a
5xx, a timeout). A plan with nothing to probe and no selection that emptied it
(a specification of writes alone, under the read-only posture) sends nothing
and exits `0`. It exits `2` when it refused (an over-budget plan, a missing
acknowledgement, an off-target path, a `--fail-on-drift` without a
`--baseline`, an `--ignore`, `matrix.ignore` or `--include` that leaves nothing
to probe, counting writes the read-only posture skips and routes with no
specimen as nothing) or could not load its inputs.
Nothing `map` *discovers* can produce a non-zero code: only a diff against a
baseline you recorded, or a grid it could not measure, can. `veridor mutate` exits `0` when
every mutant was killed, `1` when one survived, and `2` when nothing was
measured or a mutant was unresolved.

For `veridor run`:

| Code | Meaning |
| --- | --- |
| `0` | The selected gate passed, and coverage (if requested) was measured. |
| `1` | The gate failed. |
| `2` | Configuration, specification, path-safety, or undefined-coverage error — including a `--read-only` refusal, and an `--output-dir` or report path this process cannot write. Both are decided before any request. |
| `3` | The security gate passed but something else did not: a sequence teardown was unclean (`--require-clean-teardown`), a probe went unanswered or a denial is unproven (`--require-complete`; see "A denial that proves nothing says so"), or **not one probe was answered at all** — that last needs no flag. A real finding always wins, so this code never replaces `1`. |

Every command, `run` included, can also end without finishing:

| Code | Meaning |
| --- | --- |
| `70` | Internal error: an uncaught exception inside Veridor. The traceback is on stderr with a request to report it. It is never a finding about the target, so it is not `1`, which a pipeline reads as "the gate failed". |
| `130` | Interrupted by SIGINT (Ctrl-C). Teardown for the in-flight sequence runs on the way out; a second Ctrl-C can cut it short. A run interrupted before its probes finish writes no run document. |
| `143` | Terminated by SIGTERM — a Kubernetes pod termination or Job deadline, a CI runner cancelling the job. It takes the same path as SIGINT: teardown for the in-flight sequence runs first, and a run stopped before its probes finish writes no run document. A second SIGTERM during that teardown is ignored. SIGKILL cannot be caught, so it ends the process without teardown. |

The run document carries its own `status`, and it is **not** the exit code —
the exit code depends on `--fail-on` and the other flags. `veridor run` records
that decision separately, as the document's
[`gate` object](#report-formats). `status` has three values, matching the
verdicts:

| `status` | Means |
| --- | --- |
| `passed` | No finding at all: nothing `vulnerable`, `unexpected_denial` or `inconclusive`. |
| `failed` | At least one finding is `vulnerable` or `unexpected_denial`. |
| `inconclusive` | No finding is `vulnerable` or `unexpected_denial`, and at least one is `inconclusive` — a probe or sequence step that could not be graded. Other probes in the same run may still have been answered and matched. |

`status` is computed from the findings alone. Conditions that produce no
finding — a non-asserting expectation, unproven liveness, an unclean teardown —
leave it `passed`; the [`gate` object](#report-formats) records them. A run in
which not one probe was answered is `inconclusive` here and carries the gate
reason `nothing_answered`. A run that declares nothing to grade (no check, and
sequences of setup steps only) is `passed` here beside that same reason when
every setup matched, since it has no finding, and the viewer shows it as
`passed · gate exit 3`; a setup the target did not answer, or answered with a
status it did not declare, is an `inconclusive` finding.

It does not come from the finding *count*. If it did, a run whose probes all timed
out would say `failed` while exiting `3`, and the viewer would render a red
**FAILED** badge over a build CI had called green. `inconclusive` renders
amber, because a run with a probe it could not grade is neither.

Output paths are validated before anything runs: `--json`, `--sarif`,
`--coverage`, and `--badge` must be distinct and may never overwrite the
configuration, the baseline, the specification, or the managed run history,
and no input may be a file the command itself rewrites under `--output-dir`
(`latest.json` for `run` and `verify`, the `mutation/` report for `mutate`).
`capsule --output` and `report --output` may not overwrite the configuration
or the run they read. They are compared as files, so on a case-insensitive
filesystem (the macOS default) `VERIDOR.JSON` is refused where `veridor.json`
would be. Then `run`, `verify`, `map` and `mutate` create each output
directory and write and remove a test file in it; if that fails they exit `2`
before the first request, naming the path, the uid:gid they run as, and the
fix. Without the check, a run into an unwritable directory probed the target
and then lost the result. In a container that runs as uid 10001 (the release image), a
root-owned `/work` is the usual cause: run with
`docker run --user "$(id -u):$(id -g)"`, or pass an `--output-dir` that uid can
write.

## What a Veridor finding does and does not mean

This is the tool's defining limit, and the three verbs each stop at a different
one.

**Your configuration is the policy.** Veridor has no independent notion of who
should be allowed to see what. It reads the expectations you declared, issues
the requests, and reports where observed behaviour and declaration disagree.

So a finding means exactly one thing:

> Observed behaviour differed from the expectation you declared.

And it does not mean:

> The declaration was correct.

Veridor cannot tell those apart. **A wrong declaration and a real
vulnerability produce the same finding.** If you declare that an
administrator must receive `404` on a resource that administrator is genuinely
entitled to read, Veridor will report a failure — a true one, against your
declaration, and a false one against reality. Veridor consumes a policy
statement; it cannot audit one.

### The three measurements, and what each does not claim

| Measurement | Claims | Never claims |
| --- | --- | --- |
| Boundary coverage (`map`, `coverage`) | A cross-identity denial is **asserted** for this operation — a fact about your configuration | That the boundary is **enforced**, or that the assertion could ever fail |
| Mutation score (`mutate`) | Perturbing your declaration changes the verdict, so the check **would catch a regression** | That the boundary is **enforced**, or anything about operations your suite does not cover |
| A finding (`run`) | Observed behaviour differed from **your declaration** on this request | That the declaration was right |
| A candidate (`map`) | Two observations are **inconsistent** — a hypothesis to declare and test | That anything is wrong; it is not a finding and produces no SARIF result |
| Blast radius (`map`) | How many **operations** an identity was observed to reach, as a lower bound | How many **objects** those operations expose |

The two scores multiply rather than add. Full coverage made of checks that
cannot fail is worth nothing, and a perfect mutation score over one operation
says nothing about the operations coverage reports as untested.

### `confirmed` proves data flow, never policy

The marker oracle is the strongest evidence Veridor produces, and it is worth
being precise about what it buys you. A marker is a high-entropy string that
exists only in one identity's data. When it turns up in another identity's
response, that is a measurement, not an inference: bytes that belong to A were
served to B. Veridor states this flatly, because it observed it.

What the marker cannot tell you is whether B was allowed to see them. Marker
presence is a fact about **data flow**. Entitlement is a fact about **policy**,
and policy comes from your config file.

Take the quickstart's `confirmed` finding: `other_tenant` received
`invoice_owner`'s marker, and you declared it should not. Now suppose your product
means that identity to read that invoice, as a support role might. The run reports
exactly the same `evidence_grade: confirmed` finding, because the marker really is
in the response. Nothing is wrong with the target. The declaration is wrong, and
the marker oracle cannot rescue it, because there is nothing about the data flow to
rescue. `DeclarationScopeTest` in `tests/test_marker.py` builds this case.

Findings are therefore worded to keep the two apart: what Veridor measured,
what you declared, and no verdict on the declaration itself. Every run prints
the same standing line next to its evidence counts, and every run document
carries it under the `interpretation` key so downstream consumers inherit the
caveat instead of re-deriving it.

The practical consequence: **triage a `confirmed` finding by checking your
declaration first.** It is the cheapest of the two hypotheses to eliminate.

## Non-goals

Stated plainly, because a security tool that overstates itself is worse than no
tool at all. None of these are on a roadmap:

- **No API discovery.** Veridor never crawls, spiders, or guesses routes. The
  routes it sends to are the ones you wrote, and the optional route inventory
  comes from an OpenAPI file you point it at.
- **No policy invention.** Veridor has no idea who should be allowed to do what.
  Your configuration *is* the policy. An unstated boundary is an untested one.
- **No fuzzing and no payloads.** A `run` sends each check once per identity, as
  configured, with `Accept-Encoding`, `Cache-Control` and `Pragma` forced. On top of those
  it sends each `marker_probe` and, unless you pass `--no-prove-liveness`, one
  [control carrying a credential it fabricated](#a-probe-nobody-answered-is-not-a-finding-and-not-a-pass) per `GET`, `HEAD` or
  `OPTIONS` request whose declaration accepts only denials. That credential
  authenticates to nothing, but a target's lockout or WAF rules can still count
  it. No mutation, no injection, no traversal strings.
- **No injection classes.** SQL injection, command injection, SSRF, XSS, path
  traversal and their relatives are somebody else's tool. Veridor tests
  authorization and nothing else.
- **No authentication-strength testing.** Veridor does not crack tokens, analyse
  JWTs, test session fixation, or evaluate password policy. It presents the
  credentials you give it. A `401` for an anonymous caller is an authentication
  result and is never counted as authorization coverage.
- **No proof of security.** A passing run means nothing the gate fails on was
  found on this run; an expectation that held is evidence, not a guarantee.

## Verdicts

Every one of these is a comparison against *your declaration* — read them
alongside [what a Veridor finding does and does not
mean](#what-a-veridor-finding-does-and-does-not-mean).

- `safe` — the response matched the declared expectation. Reported on the
  console as *matched*: it is agreement with your configuration for one
  request, not a finding of security. This is the `summary.safe` key.
- `vulnerable` — a reachable target served a response the declaration did not
  allow: a status outside the declared set, or a response carrying another
  identity's marker. [Never proof of
  policy](#what-a-veridor-finding-does-and-does-not-mean).
- `unexpected_denial` — the target **did not serve** the request: a status
  outside the declared set and outside 2xx (`401`, `403`, `404`, and also
  `400`, `405`, `409`, a `302` and the like), other than the statuses graded
  `inconclusive` below, and no marker was observed. The declaration still failed and the finding still trips the gates,
  but nothing was returned to the identity, so nothing was exposed — a missing
  route, an unshipped feature, or an over-restriction reads as what it is
  instead of as a breach.
- `inconclusive` — execution or the marker oracle could not produce a verdict.
  A `429`, a `5xx` and a proxy's `407` (Proxy Authentication Required) are not
  answers from the authorization layer, so a probe that drew one is
  inconclusive, not a finding about the target.

Verdicts are finding **properties**, outside the fingerprint, so this vocabulary
can be refined without invalidating a baseline.

## Design commitments

These are properties, not preferences. Changing one is a breaking change:

1. **Standard library only at runtime.** A running Veridor imports nothing else,
   so no dependency tree comes with it. Building from source still runs setuptools.
2. **Response bodies are never persisted.** Scanned in memory, discarded.
3. **Finding fingerprints are stable.** New concepts ride as properties, so a
   Veridor upgrade never reports your whole suite as new.
4. **The measurement fails closed.** A weak marker, an unverifiable oracle, an
   unestablished session, or an undefined coverage ratio is reported as such.
   Veridor would rather say "unknown" than say something reassuring and false.
5. **The configuration is not a programming language.** No conditionals, loops,
   arithmetic, or expressions, in checks or in sequences. A security tool nobody
   can review is worthless, and every step toward Turing-completeness makes the
   config less reviewable.
6. **Credentials are never written down.** Cookie values, captured tokens, and
   login secrets exist only in memory for the duration of a run. No cookie jar
   is ever persisted, under any flag.
