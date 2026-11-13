# Getting help

Veridor is maintained by one person ([GOVERNANCE.md](GOVERNANCE.md)). There is
no response-time commitment, for security reports or anything else. What
follows is where each kind of question goes, so it reaches the right place the
first time.

| You have | Go to |
| --- | --- |
| A way to reach a target, escape a safety gate or read a credential | [SECURITY.md](SECURITY.md): report it privately, not in an issue |
| A crash, a wrong exit code, a refusal that should not happen | A bug report issue. Include `veridor --version`, the command, the exit code and a minimal configuration with credentials as `${VERIDOR_*}` references |
| A result or document that claims more than was measured | The "A result or document overclaims" issue template. This is a defect here, not a matter of taste |
| An idea for a new check, format or integration | The feature request issue template |
| A question about what a result means | The "Question" issue template. Read [what a finding does and does not mean](README.md#what-a-veridor-finding-does-and-does-not-mean) first |

## What is supported

- **Releases.** Only the latest release
  gets fixes ([SECURITY.md](SECURITY.md#supported-versions)).
- **Python.** 3.11, 3.12 and 3.13. The CI workflow is configured to run the
  suite on all three on Linux and on 3.12 on macOS; Windows has not been tried.
- **CI/CD platforms.** The [integrations table](README.md#cicd-integrations)
  says, for each one, what has been executed and what has not. A platform
  marked as never run on its own system is a starting point, not a supported
  integration: a report that it fails there is welcome and useful.

## Before you ask

Most refusals name the offending key or flag and say what would fix it. Paste
the whole message when you report one; a message that does not explain itself
is a bug worth fixing.
