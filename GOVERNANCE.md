# Governance

Veridor has one maintainer: [@Santoshkumarpuppala](https://github.com/Santoshkumarpuppala).
There is no foundation, company or steering group behind it. This file says
how decisions are made under that arrangement and how it changes when a
second maintainer joins.

## What the maintainer does

- Reviews and merges pull requests, and owns every path in
  [.github/CODEOWNERS](.github/CODEOWNERS).
- Triages issues and security reports ([SECURITY.md](SECURITY.md)).
- Cuts releases: pushes a version tag, then approves each publishing job in
  [.github/workflows/release.yml](.github/workflows/release.yml) as GitHub
  holds it in the protected `release` environment. That rests on GitHub and
  PyPI settings listed in [CONTRIBUTING.md](CONTRIBUTING.md#releasing): the
  maintainer as the environment's required reviewer with administrator
  bypass turned off, a tag ruleset that lets only the maintainer push `v*`
  tags, and a PyPI trusted publisher that accepts uploads only from that
  environment. The workflow checks the reviewer and the bypass setting
  before it publishes. It cannot check the rest.

One maintainer is a single point of failure. A security report or a release
waits until that person is available. [SECURITY.md](SECURITY.md) says how to
report one, and [SUPPORT.md](SUPPORT.md) says there is no response-time
commitment.

## How decisions are made

A change is proposed as an issue or a pull request, and discussed there in the
open. The maintainer decides. A decision records its reasoning in the pull
request or commit message, so it can be disagreed with later on the merits.

Two things weigh more than convenience, and a change that trades them away
will be declined whoever proposes it:

- **Claims stay inside the evidence.** No output or document may say more than
  was measured ([CONTRIBUTING.md](CONTRIBUTING.md#claim-discipline)).
- **Controls fail closed.** A check that can pass without checking anything is
  treated as a defect, not a feature gap.

A change that breaks a documented behaviour (an exit code, a report format,
an Action input, the configuration schema) is called out under Changed in
[CHANGELOG.md](CHANGELOG.md). During `0.x`, a minor release may do that.

## Becoming a maintainer

Maintainers are added by the existing maintainers. The usual path is a record
of reviewed contributions: changes that came with a test that was shown to
fail first, and reviews of other people's pull requests. A new maintainer is
added in a pull request that updates this file and `.github/CODEOWNERS`.

With two or more maintainers, a change needs the approval of a maintainer
other than its author, and a disagreement between maintainers is settled in the
open issue or pull request before merge. This file will be revised then to say
how ties are broken.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
