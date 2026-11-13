# Veridor

Veridor is an authorization regression runner for CI. You declare what each
identity is allowed to do; Veridor sends the same request as every declared
identity and fails the build when the answer changes. It is not a scanner and
not a pentest: it invents no policy, discovers no routes, sends no payloads,
and cannot tell you whether your declaration is right, only whether your
target still agrees with it.

This page is the package description. The full documentation is the
[guide in the repository](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md) and
<https://docs.veridor.org/>. Read
[what a finding does and does not mean](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#what-a-veridor-finding-does-and-does-not-mean)
before you read a report. Each release is listed in
[CHANGELOG.md](https://github.com/Veridor-authz/veridor/blob/main/CHANGELOG.md).
The project is in early alpha: the configuration format, commands, flags and
report formats may still change between minor versions, so pin a version.

## Install

Python 3.11 or newer, no runtime dependencies. Install into a virtual
environment or with pipx; Homebrew and Debian system Pythons refuse a bare
`pip install` (PEP 668).

```bash
python3.12 -m venv .venv && . .venv/bin/activate
python -m pip install veridor
veridor --version
```

The wheel carries the `veridor` package and nothing else. The demo target and
the fixtures the quickstart uses live in the repository, so with a `pip install`
start from [your own API](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#against-your-own-api).

## The three verbs

| Verb | The question |
| --- | --- |
| [`map`](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#map-what-would-a-compromise-reach) | What don't I cover, and what would a compromise reach? |
| [`run`](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#run-does-the-boundary-hold-and-did-it-change) | Does the boundary hold, and did it change? |
| [`mutate`](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#mutate-would-my-suite-catch-a-regression) | Would my suite actually catch a regression? |

Only `run` gates on what it discovered. `map` exits `0` whatever it finds unless
you opt in to `--fail-on-drift`, and `mutate` has its own exit code. The
[exit codes](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#exit-codes) and the
[CI/CD integrations](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#cicd-integrations)
are in the guide.

## Links

- [Security policy and reporting a vulnerability](https://github.com/Veridor-authz/veridor/blob/main/SECURITY.md)
- [Contributing](https://github.com/Veridor-authz/veridor/blob/main/CONTRIBUTING.md)
- [Non-goals](https://github.com/Veridor-authz/veridor/blob/main/docs/guide.md#non-goals)
- [Licence: Apache-2.0](https://github.com/Veridor-authz/veridor/blob/main/LICENSE)
