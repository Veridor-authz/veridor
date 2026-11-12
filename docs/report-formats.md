# Report formats

`veridor run` exits with a code a pipeline can read. The reports below are how
the same decision reaches a test tab, a security dashboard or a merge request.
Every format is rendered from the run document alone, and every one except SARIF
reads the `gate` object `veridor run` writes into that document, so a job that
exited 3 because nothing was answered never renders as a pass. SARIF carries
findings only and has no gate: a run that exited 3 only for an unproven denial
or an unclean teardown renders as zero results, the same bytes as a run that
exited 0. For SARIF the job's exit code is the gate.

| `--format` | What it is | Where it goes |
| --- | --- | --- |
| `sarif` | SARIF 2.1.0 | GitHub code scanning (`upload-sarif`), Jenkins Warnings NG |
| `junit` | JUnit XML | GitLab `reports: junit`, Jenkins `junit`, Azure `PublishTestResults@2`, CodeBuild `JUNITXML` |
| `gitlab-sast` | GitLab security report, schema 15.2.5 | GitLab `reports: sast` |
| `codequality` | GitLab Code Quality JSON array | GitLab `reports: codequality` |
| `markdown` | Markdown summary | `$GITHUB_STEP_SUMMARY`, a merge request note |

## Writing them

From the run that produced them, as many as you like:

```bash
veridor run --config veridor.json \
  --report junit=veridor-junit.xml \
  --report gitlab-sast=gl-sast-report.json \
  --report markdown=summary.md
```

`--report FORMAT=PATH` is repeatable. Reports are written whatever the gate
decides, because a failing gate is when CI needs them. `PATH` may not be `-`:
`run` prints its own summary on stdout. Report paths get the same checks as
`--json` and `--sarif`: they must be distinct, and may not overwrite the
configuration, the baseline, the specification or the managed run history. A
report that cannot be written is printed on stderr and changes the exit code to
`2`, unless the gate already failed on a finding (`1`), which is kept.

From a run document you already have, without repeating a single request:

```bash
veridor report --from-run run.json --format junit --output veridor-junit.xml
veridor report --from-run run.json --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Every value Veridor expanded from a `${NAME}` appears in a report as
`${NAME}`, never as the value; a value under 8 characters is the exception, and
the command names it on stderr. `report --from-run` renders what the run
document holds. The details are in
[SECURITY.md](../SECURITY.md#what-veridor-does-with-your-credentials).

`--output -`, or no `--output` at all, writes to stdout.
`veridor report --input run.json --sarif veridor.sarif` writes SARIF too. `report`
refuses, with exit 2, a file that is not a Veridor run: a matrix, a drift or
coverage document, an empty object, a `schema_version` this Veridor does not
read, or a run in which a finding, a container, or a field inside one that a
format reads (a probe's `response`, a finding's `evidence.request`, a gate
reason's `finding_ids`, ...) has the wrong type or is missing. The message
names the field.

## Exit codes, and how each format shows them

`veridor run` writes the decision it exits with into the run document:

```json
"gate": {
  "fail_on": "new+confirmed",
  "require_complete": true,
  "require_clean_teardown": false,
  "exit_code": 3,
  "reasons": [{"code": "nothing_answered", "exit_code": 3, "count": 6}],
  "not_enforced": [{"code": "inconclusive", "exit_code": 0, "count": 6,
                    "enforced_by": "--require-complete"}]
}
```

`reasons` lists every condition that moved, or would have moved, the exit code
under these flags, in precedence order; the first one's `exit_code` is the
process exit code, and `reasons` is empty exactly when that code is `0`.
`not_enforced` lists what was present in the run but not gated under these
flags, with the flag that would gate it.

| Reason code | Exit | Gated when |
| --- | --- | --- |
| `findings` | 1 | the `--fail-on` policy selects a `vulnerable` or `unexpected_denial` finding (carries `count`, `by_grade`, `finding_ids`) |
| `coverage_not_measured` | 2 | `--openapi` was given and boundary coverage could not be measured |
| `nothing_answered` | 3 | not one check probe and not one sequence assert step was answered (an answered setup step grades no declaration and is not counted), and nothing about the target was found (any policy but `none`). A run that declares neither a check nor an assert step gets it too, with `count` `0` and `nothing_graded: true`, and every report says it declares nothing to grade |
| `identity_unauthenticated` | 3 | a session identity failed to log in deterministically (any policy but `none`; carries `identities`) |
| `teardown_unclean` | 3 | `--require-clean-teardown` and a sequence teardown failed, was incomplete or aborted (carries `sequences`) |
| `expectations_non_asserting` | 3 | `--require-complete` and an expectation accepts both access and denial |
| `inconclusive` | 3 | `--require-complete` and a probe or step came back `inconclusive` |
| `liveness_unproven` | 3 | `--require-complete` (and a policy other than `none`) and a denial-only expectation, held by an identity that presents a credential in a check where some identity was served (for a sequence assert step: a static credential header, in a sequence where some identity was served), did not establish who was denied: the identity was not proven live elsewhere in the run (a 2xx it drew on a request where an identity with no credential, or the fabricated credential, was refused; or its `marker_probe`), and either a fabricated credential received the same denial, or none was sent to compare with (on a write, which never carries one, on a sequence step, or because no identity declares a credential header to shape one on: only `GET`, `HEAD` and `OPTIONS` requests get one), or its request failed or drew neither a refusal nor a success |

`veridor verify` writes the same object beside a `capsule` one, and its exit
code is the capsule's verdict rather than a `--fail-on` decision, so
`fail_on` is `null`:

```json
"capsule": {"verdict": "INCONCLUSIVE", "exit_code": 2, "reason": "...",
            "check_id": "invoice-tenant-isolation", "path": "proof.json"},
"gate": {"fail_on": null, "exit_code": 2, "not_enforced": [],
         "reasons": [{"code": "capsule_inconclusive", "exit_code": 2, "detail": "..."}]}
```

`CONFIRMED` is `capsule_confirmed` (exit `1`, a reason about the target, with
the reproduced `finding_ids`), `INCONCLUSIVE` is `capsule_inconclusive` (exit
`2`, a non-zero exit that is not a finding), and `NOT_REPRODUCED` is exit `0`
with no reason. `markdown` leads with the verdict and `junit` names it on the
`veridor.gate` case, instead of a policy. `gitlab-sast` and `codequality` show
`capsule_inconclusive` the way the table below shows any non-zero exit that is
not a finding, and a CONFIRMED verdict through its findings; neither names a
NOT_REPRODUCED verdict. `sarif` has no gate, so it carries no verdict. A
document whose verdict, `exit_code` and gate disagree is refused with exit
`2`, never rendered.

A run document written without `veridor run` has no recorded decision. Each format then re-derives one with
the CLI defaults and says so; the job may have used other flags, and its own
exit code decides.

| Format | Findings | A non-zero exit that is not a finding |
| --- | --- | --- |
| `junit` | a `<failure>` on the probe's or the sequence step's test case; `inconclusive` and a step that never ran are `<error>`, never `<skipped>` | a `<failure>` on the `veridor.gate` test case, which fails on every non-zero exit and lists every reason |
| `gitlab-sast` | `vulnerable` is severity `High`, `unexpected_denial` is `Info`; nothing is `Critical`, because every finding is graded against a declaration Veridor cannot audit. `inconclusive` is not a vulnerability | `scan.status: failure`, and a `scan.messages` entry per reason. A run that answered nothing is `failure` under any policy |
| `codequality` | `vulnerable`+`confirmed` is `critical`, other `vulnerable` `major`, `unexpected_denial` `minor`, `inconclusive` `info`; each pass disclosure is an `info` issue | one `veridor.gate` issue, severity `major` |
| `markdown` | a findings table, gating findings first | the verdict line: `Gate incomplete (exit 3)` or `Gate failed (exit 2)`, never `passed` |
| `sarif` | a result per finding; rules carry `tags` (`security`, `authorization`) and, for the rules that are findings about the target, `security-severity` | not represented; SARIF has no gate |

## What each format carries, and what it does not claim

- **SARIF.** `tool.driver.semanticVersion` is the running Veridor's version.
  `runs[].automationDetails.id` is `veridor/<run_id>`, which by GitHub's
  documented rule files every run under one category, `veridor`, unless the
  upload names another. `partialFingerprints.veridorFindingId/v1` is Veridor's
  finding fingerprint. `security-severity` is `7.5` for `VERIDOR-AUTHZ-001`
  and `8.8` for `VERIDOR-LEAK-001` and `VERIDOR-EFFECT-001`; the rules that
  mean nothing was measured carry the `security` tag and no severity. How
  GitHub ranks or files these has not been observed from this repository.
- **GitLab SAST.** Vulnerability ids are UUIDs derived from Veridor's finding
  fingerprint only, so a finding keeps its id across pipelines. The location is
  the configuration line the finding graded, relative to the working directory
  when the configuration is under it. The output was validated with
  `jsonschema` against GitLab's published `sast-report-format.json`
  (`self.version` 15.2.5), with a deliberately broken report as a control that
  the schema rejected; the repository's tests restate those constraints with
  the standard library and do not re-run the schema.
- **JUnit.** One test case per check probe, one per sequence step, and
  `veridor.gate`. Counts are computed from the cases written, and characters
  XML 1.0 cannot carry are replaced with U+FFFD. The declaration and pass scope
  sentences travel as `veridor.scope` and `veridor.pass_scope` properties.
- **Markdown.** The verdict line, the policy, counts, every gate reason and
  every condition present but not gated, the `Scope:` and `Pass:` sentences the
  console prints, and the findings. A report-only run (`--fail-on none`) that
  answered nothing says so instead of "passed". It stays under 1 MiB, GitHub's
  step-summary limit; findings past it are cut at a row with a visible note
  saying how many.

Every format also carries the pass disclosures the console prints: a
non-asserting expectation, an exclusion licensed by a `marker_probe`, a
fabricated credential the target served, and a request that went out without
a declared `form_field` or `json_field` (`injection_disclosures`). None is a
finding and none changes the exit code; each says what a matched probe did not
establish. JUnit puts one on the probe or sequence step case it qualifies, as
`<system-out>`, and one that names no case (a teardown or marker-probe
request, a served fabricated credential) on `veridor.gate`. Code Quality makes
each an `info` issue, GitLab SAST an `info` `scan.messages` entry, and
Markdown lists them under "What the matched probes do not establish". SARIF
carries the lists as run properties (`nonAssertingExpectations`,
`oracleDisclosures`, `injectionDisclosures`).

None of these reports is evidence that a boundary is enforced. A finding means
observed behaviour differed from your declaration; a passing test case means
the target agreed with it for one request.

## Drift

A drift report (`veridor map --baseline ... --drift drift.json`) is an
observation, never a finding, so it renders to Markdown only:

```bash
veridor report --from-drift drift.json --format markdown
```

Any other format is refused with exit 2: SARIF, JUnit, GitLab SAST and Code
Quality would all present a change as a finding. So is a drift document whose
counts (`comparable_cells`, `redirect_now_served_cells`, each side's `cells`,
every `counts` value, ...) are not non-negative integers: the summary prints
them, two in its bold headline, and a string there was printed as Markdown. The drift document does not
record the `--fail-on-drift` policy or the exit code, and the summary says so.
It does record `measured_in_both_cells`, the cells measured in both runs, and
`measured_cells` for each side. A redirect is not counted as measured, because
Veridor does not follow it; `redirect_cells` counts the cells in both runs that
were a redirect in at least one, and `redirect_now_served_cells` the cells the
baseline answered with a redirect that the current run serves. `--fail-on-drift
opened` does not count those, so the summary names them every time and points
at `--fail-on-drift any`, which does. When `measured_in_both_cells` is 0 the summary
says in bold that not one cell was measured in both runs, and that under
`--fail-on-drift` Veridor exits 3 rather than 0.
