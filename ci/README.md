# Veridor in CI systems other than GitHub Actions

This directory holds starting points for GitLab CI, Jenkins, Azure Pipelines
and AWS CodeBuild. **None of them has run on its own platform.** No GitLab
runner, Jenkins controller, Azure agent or CodeBuild project is attached to this
repository. [What was tested](#what-was-tested) below lists exactly what was
executed, what was only checked against a schema or read, and what was not
looked at.

**Not yet published, as of 2026-11-04.** No release tag, container image
(`ghcr.io/veridor-authz/veridor`), PyPI package, zipapp or GitLab CI/CD Catalog entry
exists. Every file here names the first release (0.1.0)
and works only after that release exists.

| File | What it is |
| --- | --- |
| [`../templates/veridor.yml`](../templates/veridor.yml) | The GitLab CI/CD component: the gate job, with typed `spec:inputs` |
| [`.gitlab-ci.yml`](.gitlab-ci.yml) | A consumer example that includes the component |
| [`Jenkinsfile`](Jenkinsfile) | Jenkins declarative pipeline template |
| [`azure-pipelines.yml`](azure-pipelines.yml) | Azure Pipelines template |
| [`buildspec.yml`](buildspec.yml) | AWS CodeBuild buildspec template |
| [`veridor.example.json`](veridor.example.json) | A Veridor configuration whose credentials are `${VERIDOR_*}` references. It targets the repository's demo server (`scripts/demo_server.py`); replace the target, identities, markers and checks with your own |

Veridor writes the GitLab SAST and JUnit reports itself, with `veridor run
--report FORMAT=PATH` or `veridor report --from-run RUN.json --format FORMAT`
([docs/report-formats.md](../docs/report-formats.md)). It has no
`##vso[task.logissue]` report format. The Azure template publishes JUnit, SARIF
and the Markdown summary instead.

## Install

| | Container image | pip | Zipapp |
| --- | --- | --- | --- |
| GitLab | Default (`install: image`). The job clears the image's `veridor` entrypoint | `install: pip`: `pip_package` into `python_image` | Not offered |
| Jenkins | Active: Docker Pipeline agent with `args '--entrypoint='` | In a venv, in a `python:3.12-slim` agent | `python3 veridor-0.1.0.pyz run ...` |
| Azure | Not as a container job (see below); `docker run` from a bash step | Active: `UsePythonVersion`, then pip on a wheel path you fill in | `python veridor-0.1.0.pyz run ...` |
| CodeBuild | Not checked | Active: `runtime-versions`, then pip on a wheel path you fill in | `python3 veridor-0.1.0.pyz run ...` |

A downloaded zipapp runs with every `VERIDOR_*` credential, so check it with
the `gh attestation verify` command in
[SECURITY.md](../SECURITY.md#verifying-a-release-after-the-first-release),
which accepts only provenance signed by `release.yml` at the release's tag.
`SHA256SUMS` comes from the same release page, so it detects a damaged
download, not a substituted one.

The name `veridor` is unclaimed on PyPI, so anyone can publish a version under
it, and a pip line naming it would run that code with the job's credentials. The
Azure and CodeBuild templates therefore do not name it. Their install step holds
`./REPLACE_WITH_THE_PATH_OF_A_VERIDOR_WHEEL.whl`, which stops the job until you
put in the path of a wheel built from this repository. The GitLab `pip_package`
default and the Jenkins pip option do name it, and neither is the default install.
Until the first release, give them a wheel path too.

The container image runs as uid 10001 and its `ENTRYPOINT` is `veridor`. Two
consequences:

* **GitLab.** The job writes its reports into the project directory, so that
  directory must be writable by uid 10001. Measured with docker standing in for
  the runner: uid 10001 cannot write a checkout that root created with umask
  0022 (mode 0755), but can write one created with umask 0000 (mode 0777).
  Veridor checks this itself before its first request. On 2026-09-24, with an
  image built from this tree, a plain `veridor run` pointed at the 0755
  checkout exited 2 with ``cannot write the results of `run` to --output-dir``
  and sent 0 requests to a counting demo target; the same run on the 0777
  checkout sent 9 and exited 1. Its advice, `--output-dir /tmp/veridor` or
  `docker run --user`, is not something a GitLab job can act on. GitLab
  Runner's feature-flag documentation says the docker and kubernetes executors
  run `umask 0000` by default, and that `FF_DISABLE_UMASK_FOR_DOCKER_EXECUTOR`
  / `FF_DISABLE_UMASK_FOR_KUBERNETES_EXECUTOR` replace that with a chown to
  the image user. That is read in the docs, not observed on a runner. So the
  job checks first and stops with exit 2 and a message naming the uid, the
  directory and both options. `install: pip` runs in a Python image as root
  instead.
* **Azure.** Azure's container-job documentation requires an image without an
  `ENTRYPOINT` whose user can run `groupadd`. The Veridor image meets neither,
  so the template installs with pip.

## Credentials

Every credential in a Veridor configuration is a `${NAME}` reference, filled
from the environment; the templates use `VERIDOR_*` names. A variable that is
unset **or empty** makes Veridor refuse with exit 2 before it sends anything,
naming the variable. Sent as an empty credential, the result would read as a
finding about the target.

| Platform | Where the secret lives | What to know |
| --- | --- | --- |
| GitLab | Masked CI/CD variables named as in the configuration | A merge request pipeline from a fork runs in the fork and receives none of the parent project's variables. A protected variable reaches a merge request pipeline only when both source and target branches are protected (GitLab 18.1+ documentation). Both cases end in exit 2, not in a probe without the credential |
| Jenkins | `withCredentials([string(credentialsId: ..., variable: 'VERIDOR_...')])` | A binding to a credential that does not exist fails the build |
| Azure | Secret pipeline variables, mapped one by one in the gate step's `env:` | Secret variables are not exported to scripts unless mapped. A mapped variable that was never defined arrives as its literal macro text `$(NAME)`, so the step refuses any `VERIDOR_*` value that still reads `$(...)` (exit 2). Fork pull request builds do not receive secrets by default |
| CodeBuild | `env: secrets-manager` or `env: parameter-store` | Never under `env: variables`, which is plain text in the buildspec |

Masking hides a value in a log. It does not stop a job that can run code from
reading it. Use test identities whose tokens can do no harm if they leak.

**Whoever may set the base URL decides where every `VERIDOR_*` credential is
sent.** Veridor sends each identity's credential to the template's base-URL
override, or to `target.base_url` in the configuration, and `veridor run`
asks for no acknowledgement. A value someone can set when a build starts is
therefore a way to collect every token without permission to read them.
Measured before the change below: the Jenkins and Azure gate shells, run with
only that value changed, sent the owner, other-tenant and admin tokens to a
capture server. The same goes for the settings that can weaken the gate:
the fail-on policy, the baseline, the exit-3 switch and the configuration.

**So does whoever may add a proxy variable, whatever the base URL says.**
Veridor follows `http_proxy` or `https_proxy`, in either case, for a target
that is not loopback, and a proxy reads every request to an `http://` target,
credentials included. Measured on 2026-09-24, outside both platforms: the
GitLab job and the Azure gate step, each with the literal base URL
`http://staging.invalid:8080`, sent 9 requests carrying the owner,
other-tenant and admin tokens to a capture server named only by `http_proxy`
or `HTTP_PROXY`, and 0 without it. Other variables do as much:
`PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL` and `PIP_FIND_LINKS` pick the code a
pip install then runs with the credentials, and `BASH_ENV` runs a file in any
non-interactive bash. No list of names is complete, so the control is the
platform setting in the table below that decides who may add a variable when
a build starts. The GitLab component also runs Veridor without any `*_proxy`
variable unless its `proxy_from_environment` input is `true`, and says in the
job log which ones it removed (0 requests reached the same capture server
afterwards; `true` let all 9 through). The other templates do not.

| Platform | Where the templates set them | What else to restrict |
| --- | --- | --- |
| GitLab | Component inputs, written in your `.gitlab-ci.yml` | A pipeline variable (set when someone runs a pipeline, or by a trigger or schedule) can have any name, and GitLab ranks it above dotenv, project and `.gitlab-ci.yml` variables of the same name. A `$VARIABLE` in `base_url` is filled from it. A literal `base_url` is not, but the variable still reaches the job: the component removes every `*_proxy` variable, such as `http_proxy`, before Veridor runs unless `proxy_from_environment` is `true`, and with `install: pip` a `PIP_INDEX_URL` picks the code that runs. So wherever someone who may not read the credentials can run a pipeline, set the project's **Minimum role to use pipeline variables** to `maintainer` or `no_one_allowed`, whatever `base_url` says. GitLab's documentation gives `no_one_allowed` as the default for new projects in new namespaces on GitLab.com, and `maintainer` on Self-Managed |
| Jenkins | `environment` entries in the Jenkinsfile. None is a build parameter | An `environment` entry wins over a build parameter of the same name, including one added in the job's configuration (measured, below). Jenkins drops a parameter the job does not declare unless `hudson.model.ParametersAction.keepUndefinedParameters` is `true` (SECURITY-170, read in Jenkins' advisory, not tried here): keep it unset. A variable the Jenkinsfile does not fix still reaches the gate from the agent, the controller's global properties or a parameter added in the job's configuration: `http_proxy` sends every credential to a proxy, and `PIP_INDEX_URL` picks what the pip option installs. Keep those settings to people who may read the credentials |
| Azure | The `variables:` block in `azure-pipelines.yml`. There are no runtime parameters | Azure documents that a YAML variable cannot be overridden at queue time and outranks a queue-time variable of the same name. Do not also define these names in the pipeline settings. A name the YAML does not define is different: Azure's documentation says the UI and the Runs API let a user add one when queueing a run, unless **Limit variables that can be set at queue time** is on for the organization or the project. `HTTP_PROXY` added that way sends every credential to a proxy (measured on the step outside Azure, above), and `PIP_INDEX_URL` picks what the install step runs. Turn that setting on wherever someone who may queue a run must not read the credentials |
| CodeBuild | `env: variables` in the buildspec. `StartBuild` can override every environment variable, and the buildspec itself | Deny `codebuild:StartBuild` requests that carry a buildspec (`Null` on `codebuild:source.buildspec`) or environment overrides (`codebuild:environment.environmentVariables.name`) to anyone who may start a build but not read the credentials. Deny any override, not a list of names: an added `HTTP_PROXY` or `https_proxy` sends every credential to a proxy, `PIP_INDEX_URL` picks what the install phase runs, and `BASH_ENV` runs a file in the build's bash. Read in AWS's documentation, not tried |

## Exit codes

Veridor's codes are the same on every platform. What each template asks its
platform to do with them:

| Code | Meaning | GitLab job | Jenkins build | Azure step | CodeBuild build |
| --- | --- | --- | --- | --- | --- |
| `0` | Nothing the fail-on policy gates on was found. A finding it does not gate on, such as one in the baseline, still gives `0` | passes | SUCCESS | Succeeded | succeeds |
| `1` | The gate failed on a finding | fails | FAILURE | Failed | fails |
| `2` | Refused: configuration, credential, path or coverage | fails | FAILURE | Failed | fails |
| `3` | No gating finding, but something went unmeasured | **fails**; a warning only with `allow_unmeasured: true` | **FAILURE**; UNSTABLE only with `VERIDOR_ALLOW_UNMEASURED = 'true'` in the Jenkinsfile | **Failed**; SucceededWithIssues only with `VERIDOR_ALLOW_UNMEASURED: "true"` in the YAML | **fails**: CodeBuild has no warning state |
| `70` | Veridor crashed; never a finding | fails | FAILURE | Failed | fails |
| `130` / `143` | Interrupted by SIGINT / SIGTERM; sequence teardown ran first | fails | FAILURE | Failed | fails |
| other | Not a Veridor code | fails | FAILURE | Failed | fails |

Each template prints one line naming the code and what it means, and exits with
Veridor's own code. The exit-0 line names the policy and says that a finding
it does not gate on also gives `0`. It does not claim that all declared
expectations were met, which would be false over a run that recorded a vulnerable
finding the baseline or the policy left ungated (measured on the GitLab,
Azure and CodeBuild shells).

Nothing uses `|| true`, `set +e`, `allow_failure: true` or
an `exit 0` after the gate, except the one opt-in exit 3 branch in Azure. These
are what the templates instruct. The GitLab component cannot check the rules an
includer passes in its `job_rules` input, and GitLab documents a rule's
`allow_failure` as overriding the job's own: a rule with `allow_failure: true`
would show a finding as a warning. How GitLab, Jenkins, Azure and CodeBuild then
render each result was not observed.

On cancellation, GitLab Runner's documentation says it signals the job's
processes directly (with `FF_USE_NATIVE_CONTAINER_STOP` off, the default).
Veridor turns SIGTERM into teardown and exit 143. The GitLab, Azure and
CodeBuild shells trap SIGTERM so that they survive until Veridor exits and then
print the exit line. Measured in docker: without the trap the job still ends
143, but the line never reaches the log.

## Reports

| Format (`--report`) | File | GitLab | Jenkins | Azure | CodeBuild |
| --- | --- | --- | --- | --- | --- |
| `junit` | `veridor-junit.xml` | `artifacts:reports:junit` | `junit`, with `skipMarkingBuildUnstable: true` | `PublishTestResults@2`, `failTaskOnFailedTests: false` | report group, `JUNITXML` |
| `gitlab-sast` | `gl-sast-report.json` | `artifacts:reports:sast` | | | |
| `codequality` | `gl-code-quality-report.json` | `artifacts:reports:codequality` | | | |
| `sarif` | `veridor.sarif` | not written: GitLab has no SARIF import | Warnings NG `recordIssues` (optional) | artifact `CodeAnalysisLogs`, for the SARIF SAST Scans Tab extension | artifact |
| `markdown` | `veridor-summary.md` | artifact | artifact | `##vso[task.uploadsummary]` | artifact |
| run JSON (`--json`) | `veridor-run.json` | artifact | artifact | artifact | artifact |

Veridor writes every report whatever the gate decides. It also exits 2 when a
report cannot be written, unless the gate already failed with 1. An exit 0
therefore always comes with its reports, so none of the templates lets a
missing report change the result. A report's own pass/fail never decides it
either: that is the exit code's job. GitLab's SAST documentation lists the
downloadable SAST report on every tier, and merge-request findings and
vulnerability management on Ultimate only.

## What was tested

"Executed" means the thing ran here and its result was observed. Nothing in
this table ran on GitLab, Jenkins, Azure or AWS.

| What | How | Result |
| --- | --- | --- |
| The GitLab job, as the component renders it | **Executed.** `scripts/e2e_gitlab_job.sh` renders `templates/veridor.yml` and runs the job's own `before_script` + `script`, not a copy, in the job's image with `--entrypoint ""`. It uses a docker volume cloned by root with umask 0000, GitLab-like `CI_*` variables, and demo targets that count every request | 2026-09-27, image built from this tree's Dockerfile (`python:3.12-alpine`, linux/arm64): 158 checks, 0 mismatches, in three runs (34 s each). Each job runs in the shell GitLab Runner picks for its image, the first bash at /usr/local/bin, /usr/bin or /bin, else sh, and starts with the header the runner writes (`pipefail` where the shell has it, then `errexit`). The release image and the component's default `python_image` have no bash, so their rows ran under busybox sh. Three rows install the wheel with pip in `python:3.12-slim` (Debian, by digest) instead: `dash` runs the job under its /bin/sh, which is dash, and `bash` under the shell the runner picks there, bash; each exits 1 and checks the shell it got. vulnerable → 1, fixed → 0, unreachable → 3 (allow_failure false), `allow_unmeasured` → 3 with `exit_codes: [3]` rendered, `install: pip` from a locally built wheel in the component's default `python_image` (`python:3.12-alpine` by digest) → 1, `wait_for_target: 5` → 0 with Veridor's TCP-wait line and `target_wait` in the run JSON. `fail_on: new`, `require_complete: false`, a baseline holding the vulnerable row's own run, an OpenAPI document and a nested `output_dir`, against the vulnerable target → 0, with the regression-diff and coverage lines, and `gate.fail_on` / `gate.require_complete` read back from the run JSON (the vulnerable row reads the defaults). Every input that changes the job's script is set by some row; `stage`, `job_name`, `artifacts_expire_in` and `job_rules` do not change it. Refused with exit 2 and **0 requests** to the counted target: an empty credential, `extra_args: --fail none`, a `base_url` naming an unset variable (with a configuration whose own target is the counted one, so a fall-through would be counted), a root-owned 0755 checkout. A count the script cannot read is a mismatch, never 0. SIGTERM mid-run → 143 and the exit line. `http_proxy`, `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` set as pipeline variables, naming a recording proxy that forwards to the vulnerable target: the job removed them and exited 1, with **0 requests** to the proxy and 9 to the target, under busybox sh in the release image and under dash in the Debian image; with `proxy_from_environment: true` the proxy received all 9 and Veridor's proxy line was in the log. Every declared artifact existed, `gl-sast-report.json` validated against security-report-schemas 15.2.5 with 0 errors, JUnit parsed, Code Quality fingerprints were unique |
| Controls for that script | **Executed.** `E2E_CONTROL=report-path-typo` (JUnit report path misspelt in the template), `E2E_CONTROL=no-term-trap` (SIGTERM trap deleted) and `E2E_CONTROL=proxy-kept` (the job keeps the proxy variables whatever `proxy_from_environment` says). By hand, on copies: an older image whose CLI rejects `--wait-for-target` (which passed all 77 checks of the script before these rows existed); the template's `base_url` refusal deleted; its `--baseline` and `--openapi` lines deleted; the counted target removed after the pip row | exit 1 every time. `report-path-typo`: 12 mismatches of 170 checks (the typo'd report is missing in every row that runs the gate). `no-term-trap`: 1 of 158 (the exit-143 line is absent). `proxy-kept`: 4 of 158 (9 requests reached the proxy in each proxy-variable row where 0 were expected, and the removal line is absent). `E2E_DEBIAN_PYTHON_IMAGE` set to the Alpine image, by hand: 3 of 158 (each shell check names busybox sh). These four were run on 2026-09-27. The older image: 8 of 102 (the wait-for-target row exits 2 and writes nothing). Refusal deleted: 3, including 9 requests where 0 were expected. Flags deleted: 4. Target removed: 8, five of them "cannot see" request counts |
| Every template's gate shell | **Executed.** `tests/test_ci_configs.py` `GateShellRunTest` (slow tier) runs the GitLab, Jenkins, Azure and CodeBuild gate shells with `sh -e` on the host, against an in-process demo server, with the real CLI. The fail-on value and the allow-unmeasured switch each shell gets are the ones its own file ships: the Jenkinsfile's `environment` entries, the Azure `variables:` block, the buildspec's `env: variables`. The test does not supply them, so a template that ships `none` is what runs | Each exits 1 / 0 / 3 for vulnerable / fixed / unreachable and writes its reports. Azure exits 0 on 3 only when `VERIDOR_ALLOW_UNMEASURED` is true, and 2 for a value that is neither, and for an undefined `$(VERIDOR_...)` mapping. A fast test reads the same values and requires `new+confirmed` and allow-unmeasured off. Controls: `none` or an opt-in value in any of the three files, or an Azure `env:` entry hard-coded to `none`, each fails it |
| Who can set the gate settings | **Checked** (`tests/test_ci_configs.py` `QueueTimeSettingsTest`, fast tier): the Jenkinsfile declares no build parameter and reads no `params.`, and every setting its shell reads (base URL, configuration, fail-on, baseline) is an `environment` entry. The Azure pipeline has no runtime parameter, and every setting its gate step reads is a literal in `variables:`, not remapped in the step's `env:` | Both clean. Controls named: the old `parameters` block, an entry removed from `environment`, a `params.` read, the old `baseUrl` runtime parameter, an `env:` remap from a parameter, a variable dropped, a variable built from `$(...)` |
| Every `veridor` command line | **Parsed** by Veridor's own argument parser (`tests/test_ci_configs.py`, fast tier): the rendered component with its defaults and with every input changed, the Jenkinsfile, the Azure step, the buildspec | All parse. Controls: a misspelt flag, a bad `--fail-on` value, an unknown report format and a `map`-only flag are each refused |
| The component's inputs | **Rendered** by `tests/ci_validate.py`, a reimplementation of GitLab's `$[[ inputs.NAME ]]` interpolation (types, options, regex, defaults; no functions). Regexes are applied as GitLab applies them, with RE2's `$` (end of text); 495 comparisons against the RE2 library on the template's regexes agreed, while Python's own `re` disagreed 23 times | Renders; declared and used inputs agree both ways. Controls refused: a misspelt reference, an interpolation function, an unused input, a misspelt input key, a default outside its options, wrong types, `fail_on: all`, an absolute `output_dir`. Every string input written into the job's script refuses `$(...)`, `$((...))`, `${NAME:...}` and every other `$` that does not begin a `$NAME` or `${NAME}` reference. During development, looser regexes accepted 76 such values across six inputs, and `$(touch ...)` in `base_url`, `config`, `baseline`, `openapi` or `pip_package` created its file when the rendered script ran. A `$NAME` whose value holds `$(...)` is expanded, not executed (`GateShellRunTest`, with a control that does execute) |
| Where the GitLab job runs | **Modelled**, not observed. `tests/test_ci_configs.py` `JobRulesTest` evaluates the rendered `rules` with GitLab's `rules:if` semantics (read in `lib/gitlab/ci/pipeline/expression`) against the variables GitLab sets in 24 kinds of pipeline (read in its variable builder and docs), and under four `workflow:rules`: none, the Branch-Pipelines and MergeRequest-Pipelines templates, and the switch recipe | The default is in all 24. A narrower default, merge request pipelines and the default branch, was out of 13, including a branch pipeline for a merge request's branch, tags, a child of a merge request pipeline and a multi-project pipeline off the default branch; under Branch-Pipelines it never ran before merge. With no `workflow:rules` the default runs twice per push to an open merge request's branch, once with the switch recipe. Controls: that narrower default is seen leaving pipelines out; an unsupported rule (`=~`, `changes`) is refused, not guessed |
| GitLab YAML | **Schema-validated.** `python3 tests/ci_validate.py schemas` with PyYAML and jsonschema, against GitLab's CI JSON schema (`ci.json`, draft-07; the copy used here is dated 2026-09-24): the spec header, both renders, `ci/.gitlab-ci.yml` and the README's GitLab YAML | 0 errors. Controls rejected: an unknown job key, `artifacts:reports:sast: 5`, `allow_failure: exit_codes: []`, an input `type: enum`, the remote include's `integrity` as a hex digest, and the key misspelt `integrty` |
| Azure YAML | **Schema-validated** against `service-schema.json` from microsoft/azure-pipelines-vscode (main, fetched 2026-09-24). Loaded with every scalar a string, as Azure parses it; boolean and integer fields accept `true`/`false` and digits | 0 errors. Controls rejected: a job key `stepz`, `continueOnError: sometimes`, `failTaskOnFailedTests: maybe`, `testResultsFormat: JUnit5`. The schema types most scalars as strings, so it cannot catch, for example, `cancelTimeoutInMinutes: two` |
| Jenkinsfile | **Linted** by Jenkins' declarative linter (`/pipeline-model-converter/validate`) in `jenkins/jenkins:lts-jdk21` (Jenkins 2.568.3) with pipeline-model-definition, docker-workflow, credentials-binding, junit and warnings-ng installed. Step parameters checked against its `/pipeline-syntax/gdsl` | "successfully validated", again on 2026-09-24 for the Jenkinsfile without build parameters. Controls rejected: an undefined section (also on 2026-09-24, `environmnt`), `boolParam`, an unknown docker agent option, a syntax error, an `environment` entry with no value. **Accepted**: an unknown step name (`junitz`); the linter does not check step names. The gdsl lists `junit`'s `allowEmptyResults`, `skipMarkingBuildUnstable` and `skipPublishingChecks`, `recordIssues`' `enabledForFailure`, `qualityGates` and `tools`, and `sh`'s `returnStatus`. It does not list `archiveArtifacts` or the `sarif` tool, so those two were not checked |
| Jenkins parameter vs `environment` | **Executed** on the same local Jenkins, 2026-09-24: minimal pipelines on the built-in node, each built with `VERIDOR_BASE_URL=http://collector.example`. The parameter was declared in the pipeline's `parameters` block or added in the job's configuration, each with and without `environment { VERIDOR_BASE_URL = '' }`. Also `env.VERIDOR_ALLOW_UNMEASURED == 'true'` with the entry at `'false'` and `'true'` | With the `environment` entry, every parameterised build's `sh` saw an empty value, in both forms. Without it (the controls), `sh` saw the collector. `'false'` took the failing branch, `'true'` gave UNSTABLE. So the Jenkinsfile fixes every gate setting in `environment` and declares no build parameter |
| buildspec | **Structure-checked** against the keys in AWS's buildspec reference (`tests/ci_validate.py` `buildspec_problems`). SchemaStore's catalog has no buildspec schema | No problems. Controls caught: a misspelt phase, `shell: zsh`, an unknown report format, a misspelt `env` key, `runtime-versions` outside `install` |
| Shell hygiene | **shellcheck** 0.11.0, `-s sh`, on every extracted gate shell, and on `scripts/e2e_gitlab_job.sh` | Clean. Control: an array in `sh` is flagged |

**UNTESTED**, because it needs the platform:

* **GitLab.** Resolving `include: remote:` or `include: component:`, and
  what `integrity:` does on a match or a mismatch (GitLab's documentation says
  a mismatch fails the pipeline). GitLab's
  own interpolation, including how it writes a boolean inside a string (read in
  the docs as "interpolated as a string"; `true`/`false` is inferred). Its
  `extends` merge, `allow_failure: exit_codes` rendering, report upload and
  merge-request widgets. The runner's real cancel path. The kubernetes and
  shell executors. Publishing to the CI/CD Catalog.
* **Jenkins.** Any build. The Docker Pipeline plugin with `--entrypoint=`,
  `withCredentials`, what `skipMarkingBuildUnstable` does to the result, and
  Warnings NG's SARIF parsing.
* **Azure.** Any run. `task.complete result=SucceededWithIssues` followed by
  `exit 0`, the export of the `variables:` block to the gate step's shell
  (documented by Azure, not observed; the step accepts `true` or `false` in
  either case and refuses anything else), that a queue-time variable cannot
  override it, `task.uploadsummary`, both publish tasks, secret mapping, fork
  builds.
* **CodeBuild.** Any build. `exit` inside a buildspec 0.2 command, which runs in
  one shared shell. Report and artifact upload after a failed build.
  `runtime-versions` python 3.12 on your build image. `secrets-manager`.
* **The release image.** The GitLab rows ran on an image built locally from
  this tree's Dockerfile, not on a published one (none exists).
* **pip from PyPI.** The package is not published. The pip row installed a
  wheel built from this checkout.

## Reproduce

```bash
# GitLab job end to end (docker; needs a python with jsonschema)
docker build -t veridor:e2e .
IMAGE=veridor:e2e SAST_SCHEMA=path/to/sast-report-format.json \
  PYTHON_WITH_JSONSCHEMA=path/to/python scripts/e2e_gitlab_job.sh
E2E_CONTROL=report-path-typo IMAGE=... scripts/e2e_gitlab_job.sh   # must exit 1
E2E_CONTROL=proxy-kept IMAGE=... scripts/e2e_gitlab_job.sh         # must exit 1

# Schemas (PyYAML and jsonschema; neither is a Veridor dependency)
python3 tests/ci_validate.py schemas --gitlab-schema path/to/ci.json \
  --azure-schema path/to/service-schema.json

# Static checks and the gate-shell runs
python3.12 -m unittest tests.test_ci_configs -v
```

`scripts/e2e_gitlab_job.sh` exits 0 when every row matched, 1 on a mismatch,
2 when it refused to start, and 3 when setup failed before the table. It
removes every container, volume and network it created.
