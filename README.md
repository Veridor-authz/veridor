# Veridor

Veridor is an authorization regression runner for CI. You declare what each
identity is allowed to do; Veridor sends the same request as every declared
identity and fails the build when the answer changes. It is not a scanner and
not a pentest: it invents no policy, discovers no routes, sends no payloads,
and cannot tell you whether your declaration is right, only whether your
target still agrees with it.

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/veridor)](https://artifacthub.io/packages/helm/veridor/veridor-gate)

Status: early alpha. Each release is listed in [CHANGELOG.md](CHANGELOG.md).
The configuration format, commands, flags and report formats may still change
between minor versions, so pin a version.

Veridor is an independent personal project. It is not affiliated with or endorsed by any employer.

## What it does

| Command | The question it answers |
| --- | --- |
| <a id="map-what-would-a-compromise-reach"></a>[`map`](docs/guide.md#map-what-would-a-compromise-reach) | What don't I cover, and what would a compromise reach? |
| <a id="run-does-the-boundary-hold-and-did-it-change"></a>[`run`](docs/guide.md#run-does-the-boundary-hold-and-did-it-change) | Does the boundary hold, and did it change? This is the one meant to gate CI. |
| <a id="mutate-would-my-suite-catch-a-regression"></a>[`mutate`](docs/guide.md#mutate-would-my-suite-catch-a-regression) | Would my suite actually catch a regression? |

## Install

Python 3.11 or newer. No runtime dependencies.

- PyPI: `pip install veridor==X.Y.Z`
- Container image: `ghcr.io/veridor-authz/veridor:X.Y.Z`
- Helm chart: `veridor-gate`, published to `oci://ghcr.io/veridor-authz/charts`

Use a virtual environment or `pipx`; Homebrew and Debian system Pythons refuse
a bare `pip install`.

## Try it

The demo target and its configuration live in this repository, not in the
package, so run this from a clone:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install .
python3 scripts/demo_server.py --vulnerable &
veridor run --config fixtures/veridor.demo.json --sarif veridor.sarif
```

The run finds the demo's cross-tenant bug and exits `1`. Restart the demo
without `--vulnerable` and the same command exits `0`.
To point it at your own API, see
<a id="against-your-own-api"></a>[Against your own API](docs/guide.md#against-your-own-api).

## CI/CD

<a id="cicd-integrations"></a>What has been run for each integration, and where: [CI/CD integrations](docs/guide.md#cicd-integrations).

- GitHub Action: [action.yml](action.yml), set up as in [GitHub Action](docs/guide.md#github-action).
- GitLab CI: a CI/CD component, see [GitLab CI](docs/guide.md#gitlab-ci).
- Argo CD: a PostSync gate from the Helm chart, see [deploy/argocd](deploy/argocd/README.md).
- Argo Rollouts: an analysis step, see [deploy/argo-rollouts](deploy/argo-rollouts/README.md).
- Jenkins, Azure Pipelines, AWS CodeBuild and others: [ci/README.md](ci/README.md).

<a id="exit-codes"></a>What each exit code means is in [Exit codes](docs/guide.md#exit-codes).

## Documentation

- <https://docs.veridor.org/>
- [docs/guide.md](docs/guide.md), the full manual in this repository
- <a id="what-a-veridor-finding-does-and-does-not-mean"></a>[What a finding does and does not mean](docs/guide.md#what-a-veridor-finding-does-and-does-not-mean):
  read this before you read a report.
- <a id="non-goals"></a>[Non-goals](docs/guide.md#non-goals): what Veridor does not try to do.
- <a id="confirmed-proves-data-flow-never-policy"></a>[What a `confirmed` finding proves](docs/guide.md#confirmed-proves-data-flow-never-policy).

## Contributing, security, license

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). New commits are signed
  off under the DCO, and [authorship and provenance](CONTRIBUTING.md#ai-assisted-commits-and-provenance)
  are covered there too.
- Security issues: report them privately as described in [SECURITY.md](SECURITY.md).
- License: Apache-2.0, see [LICENSE](LICENSE).
- Using Veridor somewhere real? Add yourself to [ADOPTERS.md](ADOPTERS.md).
