<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/veridor-mark-dark.svg">
  <img src=".github/assets/veridor-mark.svg" alt="Veridor" height="76">
</picture>

# Veridor

Authorization regression runner for multi-user APIs, built for CI

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/veridor)](https://artifacthub.io/packages/helm/veridor/veridor-gate)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/veridor)](https://pypi.org/project/veridor/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://pypi.org/project/veridor/)
[![Docs](https://img.shields.io/badge/docs-docs.veridor.org-blue.svg)](https://docs.veridor.org/)

[Documentation](https://docs.veridor.org/) · [Website](https://veridor.org/) · [Quick start](https://docs.veridor.org/quickstart/)

</div>

Veridor is an authorization regression runner for CI. You declare what each
identity is allowed to do; Veridor sends the same request as every declared
identity and fails the build when the answer changes. It is not a scanner and
not a pentest: it invents no policy, discovers no routes, sends no payloads,
and cannot tell you whether your declaration is right, only whether your
target still agrees with it.

<a id="what-a-veridor-finding-does-and-does-not-mean"></a>Read [what a finding does and does not mean](docs/guide.md#what-a-veridor-finding-does-and-does-not-mean) before you read a report.

## How it works

| Command | The question | What you get |
| --- | --- | --- |
| <a id="map-what-would-a-compromise-reach"></a>[`map`](docs/guide.md#map-what-would-a-compromise-reach) | What don't I cover, and what would a compromise reach? | An access matrix, a blast radius per identity and ranked anomaly candidates |
| <a id="run-does-the-boundary-hold-and-did-it-change"></a>[`run`](docs/guide.md#run-does-the-boundary-hold-and-did-it-change) | Does the boundary hold, and did it change? This is the one meant to gate CI. | Findings, evidence grades, a baseline diff, SARIF and the CI exit code |
| <a id="mutate-would-my-suite-catch-a-regression"></a>[`mutate`](docs/guide.md#mutate-would-my-suite-catch-a-regression) | Would my suite actually catch a regression? | A mutation score and every mutant your checks failed to kill |

## Install

Python 3.11 or newer. No runtime dependencies. From PyPI:
`pip install veridor==X.Y.Z`, in a virtual environment or with `pipx`, because
Homebrew and Debian system Pythons refuse a bare `pip install`.

Each release tag also publishes the image `ghcr.io/veridor-authz/veridor`, the
[Helm chart](deploy/helm/veridor-gate/README.md) `oci://ghcr.io/veridor-authz/charts/veridor-gate`
and a zipapp with `SHA256SUMS`. [Install](https://docs.veridor.org/install/) covers each.

## Quick start

The repository ships a demo target with a real cross-tenant bug behind a flag.
It lives in the git repository, not in the package, so run this from a clone:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install .
python3 scripts/demo_server.py --vulnerable &
veridor run --config fixtures/veridor.demo.json --sarif veridor.sarif
```

The run reports one `vulnerable (confirmed)` finding and exits `1`. Restart the demo
without `--vulnerable` and the same command exits `0` with `6/6 probes matched`.
<a id="against-your-own-api"></a>Next: [against your own API](docs/guide.md#against-your-own-api).

## CI/CD

- GitHub Action: [docs.veridor.org/ci/github-action](https://docs.veridor.org/ci/github-action/)
- GitLab CI/CD component: [docs.veridor.org/ci/gitlab](https://docs.veridor.org/ci/gitlab/)
- Argo CD PostSync gate (Helm chart): [docs.veridor.org/ci/argo-cd](https://docs.veridor.org/ci/argo-cd/)
- Argo Rollouts analysis: [docs.veridor.org/ci/argo-rollouts](https://docs.veridor.org/ci/argo-rollouts/)
- Jenkins, Azure Pipelines, AWS CodeBuild and any other CI: [docs.veridor.org/ci/other-ci](https://docs.veridor.org/ci/other-ci/)

<a id="cicd-integrations"></a>What has been run for each integration, and where: [CI/CD integrations](docs/guide.md#cicd-integrations).

## Documentation

- [Install](https://docs.veridor.org/install/): pip, container image, Helm chart, zipapp
- [Your first finding](https://docs.veridor.org/quickstart/): the demo target, step by step
- [How Veridor works](https://docs.veridor.org/concepts/): the terms Veridor uses
- [Write your access policy](https://docs.veridor.org/policy/): from who may do what to a `veridor.json`
- [Configuration reference](https://docs.veridor.org/config/reference/)
- [Command-line reference](https://docs.veridor.org/reference/cli/)
- <a id="exit-codes"></a>[Exit codes](docs/guide.md#exit-codes): what each one means to your pipeline
- <a id="confirmed-proves-data-flow-never-policy"></a>[What a `confirmed` finding proves](docs/guide.md#confirmed-proves-data-flow-never-policy)
- <a id="non-goals"></a>[Non-goals](docs/guide.md#non-goals): what Veridor does not try to do
- [Safety posture](https://docs.veridor.org/safety/)
- [Troubleshooting](https://docs.veridor.org/troubleshooting/)

The full manual is also in this repository: [docs/guide.md](docs/guide.md).

## Status

Early alpha. The configuration format, commands, flags and report formats may
still change between minor versions. There is no moving major tag (`v0`, `v1`)
while the version is `0.x`, so pin a version. Each release is listed in
[CHANGELOG.md](CHANGELOG.md).

Veridor is an independent personal project. It is not affiliated with or endorsed by any employer.

## Contributing

```bash
python3.12 scripts/run_tests.py --tier fast            # every commit
python3.12 scripts/run_tests.py --tier slow --jobs 4   # before merge
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers the test tiers, the end-to-end checks
and the claim discipline a change has to stay inside. New commits are signed off
under the DCO, and [AI-assisted commits and provenance](CONTRIBUTING.md#ai-assisted-commits-and-provenance)
are covered there too. See also [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[GOVERNANCE.md](GOVERNANCE.md) and [SUPPORT.md](SUPPORT.md). Using Veridor? Add
yourself to [ADOPTERS.md](ADOPTERS.md).

## Security

Report a vulnerability privately as [SECURITY.md](SECURITY.md) describes, never in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
