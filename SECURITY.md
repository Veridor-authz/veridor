# Security policy

## Reporting a vulnerability in Veridor

Report privately through this repository's private vulnerability reporting form:

**<https://github.com/Veridor-authz/veridor/security/advisories/new>**

If the form is unavailable, write to **security@veridor.org**. If that fails
too, open a public issue with the "Question" issue form asking for a contact,
and leave out every detail of the problem.

Please do not open a public issue for anything that would let an attacker reach
a target, escape a safety gate, or read a credential. A public issue is
reasonable for a crash, a wrong number, or a claim the documentation overstates.

Include the version (`veridor --version`), the command you ran, and a minimal
configuration with **every credential replaced by an `${ENV_VAR}` reference**.
Veridor's own [proof capsules](docs/guide.md#capsules-sending-a-proof-to-someone-else)
refuse to build with a literal credential in them, and the same rule applies to
anything you send us.

One person reads these reports, on a best-effort basis, and there is no
response-time commitment ([SUPPORT.md](SUPPORT.md)). If you have had no reply
and want to check that a report arrived, use the same issue form, again with no
details. This is a small project with no security team and no bounty programme;
that is a statement of capacity, not of how seriously a report will be taken.

## Supported versions

Fixes land on `main`. Only the
latest release is supported. Veridor is `0.x`, and older versions are not
patched.

A confirmed vulnerability is disclosed through a GitHub security advisory on
this repository once a fix is available.

## What Veridor does with your credentials

Veridor is a testing tool that authenticates as several identities against a
running system, so it necessarily handles secrets.

- Credentials come from your configuration, and `${NAME}` expands from the
  process environment. Keep them in CI secrets and reference them; a literal
  token in a committed config is the most likely way to leak one.
- A `${NAME}` that is unset **or empty** stops the run with exit `2` before
  anything is sent, naming the variable. A pull request from a fork receives
  empty secrets; sending an empty credential would read as a finding about the
  target.
- Header values are not written to a run document, a matrix or any report,
  and query values are redacted in every URL Veridor stores. A capsule
  (`veridor capsule`) is the exception: it holds one check and the identities
  that check names, as configured, so it carries their literal header values
  that are not credentials, and their markers. A credential header in it must be a `${NAME}` reference,
  or the capsule is refused. Beyond that, every value Veridor
  expands from a `${NAME}`, wherever you put it (a path segment, a `;param`,
  a base URL, a body), is replaced by its `${NAME}` reference in every file
  Veridor writes and in everything the `veridor` command prints: run
  documents and their history copies, matrices, drift, blast radius,
  coverage, mutation reports and every report format. That covers the value
  as written, percent-encoded and `+`-encoded, lower-cased as a host name is
  stored, and re-encoded as a query parameter name is stored. So a `${NAME}`
  in a request path does not reach the run document or the GitLab SAST report
  as its value. Three limits:
  - a value shorter than 8 characters is left as it is, because it cannot be
    told apart from ordinary text; the command names each such `${NAME}` on
    stderr. Do not use a value that short for a secret;
  - a credential typed literally into a configuration, or into a flag such
    as `--base-url`, is your own text: Veridor cannot recognise it, so
    outside headers and query values it is written wherever that text goes,
    a path segment included. Reference it as `${NAME}` in the configuration
    instead;
  - a finding id is a truncated SHA-256 over the check's request, path and
    body included, so a short or guessable value there can be confirmed from
    the id by guessing. A random token cannot.
- Veridor connects to the target you configured and to nothing else, with
  one exception you control: when `http_proxy` or `https_proxy` (in either
  case) is set for the target's scheme and `no_proxy` does not cover its
  host, requests go through that proxy. Before the first request it then says
  so on stderr, naming the proxy's host and port and the variable. For an
  `http://` target the proxy reads every request in full, credentials
  included. For `https://`, a proxy that only tunnels sees the host and port,
  but one that inspects TLS with a certificate authority the machine trusts,
  as many corporate egress proxies do, reads every request in full too;
  Veridor cannot tell the two apart. The operating system's own proxy
  settings are never read, and a loopback target (`127.0.0.0/8`, `::1`,
  `localhost`) is always reached directly, so a capsule `verify` runs without
  `--base-url` never goes through a proxy. Refused with exit `2`, before
  anything is sent and without printing the value: an `https://` proxy for an
  `https://` target, because urllib opens the tunnel to a proxy in plaintext,
  CONNECT line and `user:password` included; and a proxy value that is not
  `host:port` once its `user:password@` is set aside (a `%40` for the `@`, a
  path after the port), which urllib reads differently from what was meant.
  The variables are read by urllib's rules: with `REQUEST_METHOD` set (as
  under CGI) an upper-case `HTTP_PROXY` is ignored for an `http://` target,
  `all_proxy` is never read, and `no_proxy` matches host names, domain
  suffixes and `*`, not CIDR ranges or `*.example.com`. Where that differs from
  what another tool would do, the stderr notice, or its absence, is what says
  which way the requests went. `--wait-for-target` opens its TCP check to the
  target directly either way, and its line says so when a proxy carries the
  requests.
  There is no telemetry, no update check, and no third-party runtime dependency
  — the runtime is the Python standard library. `tests/test_stdlib_only.py`
  (fast tier) AST-scans every import in `src/veridor/**`, including ones
  inside functions and `try` blocks, and fails on any module that is neither
  in the standard library nor Veridor's own; it also fails if
  `pyproject.toml` declares a runtime dependency.
- `veridor serve` binds `127.0.0.1` by default, serves files from your output
  directory, never writes, and is unauthenticated by design. A `--host` other
  than loopback (`127.0.0.1`, `localhost` or `::1`) is refused with exit `2`
  unless you also pass `--i-understand-this-is-unauthenticated`. With it, your
  run history, including every finding, is readable by anyone who can reach
  the port. Prefer an SSH tunnel.

## Verifying a capsule someone sent you

A [proof capsule](docs/guide.md#capsules-sending-a-proof-to-someone-else) is
written by someone else, and `veridor verify` treats it as untrusted input.
Before it sends anything, it refuses with exit `2`:

- any `${NAME}` in the capsule that is not `VERIDOR_` followed by upper-case
  letters, digits or underscores. The list is read from the capsule's content,
  not from its `requires_environment`, so a capsule cannot ask for
  `${AWS_SECRET_ACCESS_KEY}` or anything else in your environment;
- a target that is not loopback (`127.0.0.0/8`, `::1` or `localhost`), unless
  you pass `--base-url`. The capsule names the reporter's target; `--base-url`
  names the instance you are verifying;
- any request whose method is not GET, HEAD or OPTIONS, a session login
  included, unless you pass `--base-url`, even on loopback;
- with `--read-only`, any such request at all;
- a request path, in the check, a marker probe or a session login, that does
  not stay on the target. `/http://host/x` reads as a path but becomes an
  absolute URL once its leading `/` is dropped to join it onto the target, and
  it would send every identity's credentials to `host` past all of the
  refusals above. A path with a `.` or `..` segment, plain, percent-encoded
  any number of times (a segment still decoding after eight rounds is refused
  too) or as overlong UTF-8 (`%c0%ae`), before a `;` path parameter (`..;`,
  which Tomcat and Jetty read as `..`), or beside an encoded `/` or `\`
  (`..%2f`, `..%5c`, `..%252f`, which a gateway that decodes them reads as
  `../`), is refused too: joined onto a
  `--base-url` of `https://gateway/service-a/`,
  `/../service-b/admin` would go to `/service-b/admin`, another application
  behind the same gateway, with your credentials and, for a `DELETE`, as a
  write. `run` refuses the same paths, sequence steps included, and a step
  path resolved at run time is checked again before it is sent. Spellings
  only one server family reads, such as IIS's `%u002e` or a segment with
  trailing spaces, are not judged;
- a `Host` header, in any case, in any header map the capsule carries (a
  check, an identity, a marker probe, a login step, a session `inject`).
  urllib sends it instead of the host in the URL, and every check above reads
  the URL: `"headers": {"Host": "admin.internal"}` kept the path on the target
  you named and delivered the request, with your credentials, to the admin
  virtual host behind a gateway that routes by `Host`. `run` refuses it too;
- any run option `verify` does not apply. It applies `--base-url`,
  `--output-dir`, `--read-only`, `--json`, `--sarif` and
  `--no-prove-liveness`; anything else is refused by name rather than ignored;
- a `claim` field (any string in it, keys and nested values included), the
  `scope` or the check's `name` carrying a character a terminal acts on
  instead of showing: C0 and C1 controls (an escape sequence), a line break,
  or a Unicode format control such as the bidi override U+202E. The claim is
  printed beside the verdict, and so was the scope: a capsule whose `scope`
  began `ESC[2J ESC[H` cleared the screen and drew a verdict of its own over
  the real one. The check's name goes into every finding of the run, which
  `report` prints. `veridor capsule` never writes one;
- a `claim.check_id` that is not the id of the check the capsule carries. The
  verdict is read from findings under the claimed id, so a mismatch would
  come out `NOT_REPRODUCED`, exit `0`, whatever the target did;
- a `claim.evidence_grade` that is not one Veridor writes (`n/a`, `ungraded`,
  `suspected`, `confirmed`). It is quoted in the reason under the verdict, and
  a 3774-character one of spaces and a copied session would wrap into a
  NOT_REPRODUCED over a real CONFIRMED.

Whatever `verify` prints from a capsule or from its run, and every refusal
that quotes the capsule, shows such characters escaped (`\x1b`, `\u202e`)
rather than sending them to your terminal, and the scope sentence under the
verdict is Veridor's own, not the capsule's copy. It also shows at most 120
characters of each value it quotes, with each run of blanks as one space:
a key of spaces and a copy of a genuine session, padded to the terminal's
width, would wrap into a whole verdict session over the real refusal. A
refusal line longer than 1000 characters keeps its start and its end.

When nothing is refused, it prints the target it will contact, the
`VERIDOR_*` variables it will read, and the proxy the values go through when
one applies (only with `--base-url`: a loopback target is never proxied).
Set only those variables, with credentials for test identities on your own
instance. On the writing side, `veridor capsule` refuses
to write a capsule with a literal value in a credential-looking header, field,
query or form parameter, or URL, wherever in the capsule it sits, and renames
other variable references to `VERIDOR_*` names.

Separately from those refusals, every request Veridor sends is checked just
before it is built: a URL without the target's scheme, host and port is not
sent, and neither is one outside the target URL's path when that URL has one
(with `https://gateway/service-a/`, only `/service-a` and what is under it).
A target URL with no path contains requests to its origin and nothing
narrower: a request to any path on that host is sent. Every sender goes
through that one check, `map` and `mutate` included; `run`, `verify` and
`map` then stop with exit `2`, which is what the tests exercise.

A way to make `verify` read another variable, reach another host or send a
write past these refusals is a vulnerability. `tests/test_capsule.py` and
`tests/test_origin_containment.py` hold each refusal, including runs against a
local listener that must receive nothing.

## Verifying a release

Nothing below had been run against a release when the first one was tagged. It
describes what `.github/workflows/release.yml` is configured to produce for a
tag `vX.Y.Z`.

Every job in that workflow that publishes runs in a protected `release`
environment and waits there for a maintainer's approval. It relies on these
repository and PyPI settings, listed in
[CONTRIBUTING.md](CONTRIBUTING.md#releasing):

- the environment has a required reviewer, administrators cannot bypass it,
  and only `v*` tags may use it;
- a tag ruleset limits who can push `v*` tags;
- PyPI's trusted publisher for `veridor` names that environment, so PyPI takes
  no upload from a job that did not wait.

Before publishing, the workflow checks the reviewer and the bypass setting.
It cannot show who approved a job, and it cannot check the tag rule, the
ruleset or PyPI's side. The image, chart and release pushes use the
workflow's own token, so for them the environment binds this workflow only.

- **Release files** (wheel, sdist, zipapp) carry GitHub build provenance.
  Verify it against the workflow and the tag, not only the repository:

  ```bash
  gh attestation verify veridor-X.Y.Z-py3-none-any.whl --repo Veridor-authz/veridor \
    --cert-identity https://github.com/Veridor-authz/veridor/.github/workflows/release.yml@refs/tags/vX.Y.Z
  ```

  With `--repo` alone, `gh` accepts an attestation made by any workflow in the
  repository at any ref. Anyone who can push a branch can run a workflow of
  their own with write access ([CONTRIBUTING.md](CONTRIBUTING.md#releasing)),
  and such a workflow could replace a release file and attest the
  replacement. That last step is inferred from GitHub's permission model,
  not tried on a release. `--cert-identity` must
  match the signing certificate exactly, so it accepts only a run of
  `release.yml` from the tag `vX.Y.Z`. (`--signer-workflow` alone is not
  enough: it is a prefix match and accepts any ref.) This was measured with
  gh 2.95.0 on another project's real attestation, made by a workflow on
  `refs/heads/main`. `--repo` alone accepted it. `--cert-identity` with the
  exact signer accepted it, and the same identity at another ref, or naming
  another workflow, was refused.

  What a pass proves: GitHub Actions signed provenance for this file's
  sha256 in a run of `.github/workflows/release.yml`, as that file stood at
  the tag `vX.Y.Z`. It does not prove that the tag points at the commit you
  expect (if you know that commit, add `--source-digest <commit sha>`), that
  a reviewer approved the run, or that nothing the run fetched while building
  was tampered with. Anyone allowed to push a `v*` tag can produce this
  identity, which is why the tag ruleset above matters.

- **`SHA256SUMS`** lists the sha256 of every other file attached to the release:

  ```bash
  sha256sum --check --ignore-missing SHA256SUMS
  ```

  It is downloaded from the same place as the files and is not attested
  itself, so it detects a damaged download, not a substituted one. Only the
  pinned attestation check above ties a file to `release.yml` at the tag.

- **The container image and the Helm chart** are signed with cosign's keyless
  signing by the release workflow. Verify by digest:

  ```bash
  cosign verify ghcr.io/veridor-authz/veridor@sha256:<digest> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/Veridor-authz/veridor/\.github/workflows/release\.yml@refs/tags/v'
  ```

  The chart is `ghcr.io/veridor-authz/charts/veridor-gate@sha256:<digest>`, checked
  the same way. The release notes name both digests. The published chart's
  `image.digest` is set to the image digest, so a verified chart deploys the
  signed image by digest rather than by its `X.Y.Z` tag.

## Deliberate capabilities that are not vulnerabilities

Three parts of Veridor do dangerous things on purpose, behind gates. Reports
that these *can* happen are not vulnerabilities; reports that a gate can be
**bypassed** very much are.

- **`mutate --tier 2` executes commands you supply** — `apply` and
  `restore` — as an argv list with no shell, on your machine, as you, with your
  environment. It is behind four independent refusals and an unsuppressible
  disclosure. A way to run a command without those refusals is a vulnerability.
- **`map` sends live requests** to the target, read-only by default. Mutating
  verbs need both a literal method name and an exact acknowledgement string; a
  public target needs the acknowledgement typed verbatim. Public means a
  globally routable address, or any hostname but `localhost` and
  `*.localhost`, because hostnames are never resolved. Every address that is
  not globally routable — RFC 1918, CGNAT, ULA, link-local (including the
  cloud metadata address 169.254.169.254) and the documentation ranges — is
  waived by design, so probing one without the acknowledgement is not a
  vulnerability. A way to send a `DELETE`, or to probe a public host, without
  those is.
- **Sequences write to the target.** They are for systems you own, and
  `--read-only` is a pre-flight refusal that fires before anything is sent. A
  write that escapes `--read-only` is a vulnerability.

Output paths are validated before anything runs: an artifact may never overwrite
your configuration, baseline, specification, or managed run history, and that
includes the file a command writes its own result to under `--output-dir`
(`latest.json` for `run` and `verify`, the `mutation/` report for `mutate`):
an input that is that file is refused with exit `2`. Otherwise
`run --baseline .veridor/latest.json` would replace its own baseline, and the
re-run would compare a live finding against itself and exit `0`. Paths are
compared as files, not as strings: by device and inode when both exist, and
otherwise by the directory the file would go in and the case rule that
directory's filesystem applies, found by looking rather than assumed from the
platform. Otherwise `--json VERIDOR.DEMO.JSON` would replace `veridor.demo.json`
on a case-insensitive macOS volume. A path that escapes that check is a
vulnerability.

## What Veridor claims, and what it does not

Veridor evaluates the expectations **you** declared. A finding means observed
behaviour differed from your declaration; it does not establish that your
declaration is correct, and a passing run is not evidence that a boundary is
enforced. See
[What a Veridor finding does and does not mean](docs/guide.md#what-a-veridor-finding-does-and-does-not-mean).

If you believe a report or document overstates what was measured, please raise
it. Overclaiming is treated as a defect in this project.

## Using Veridor against systems you do not own

Don't. The safety gates exist to make an accident hard, not to make
unauthorised testing safe or lawful. Point it at systems you own or have written
permission to test.
