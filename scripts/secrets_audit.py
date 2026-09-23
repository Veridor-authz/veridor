#!/usr/bin/env python3.12
"""Scan every blob in git history for credentials and personal data.

Audit a history before you publish it, and again before publishing any
history you rewrote: once a repository is public, its history is copied and
indexed, and a later deletion does not reach those copies.

    python3.12 scripts/secrets_audit.py            # human readable
    python3.12 scripts/secrets_audit.py --json     # machine readable

A working-tree scan is not this. `git status` and `git grep` see one commit;
this walks `git rev-list --objects --all`, so it also reads blobs from deleted
files, abandoned branches and amended commits -- which is where a secret that
was "removed" actually still lives.

Exit codes: 0 no rule's hit was counted, 1 findings to review, 2 could not run.

WHAT IT CATCHES is the rules in PATTERNS and nothing else: the token prefixes
listed there, private keys, JSON web tokens, an Authorization header holding a
literal value, and a value assigned to a name that says it is a credential
(password, secret, token, api key, access key, private key, an upper-case
*_KEY). A random value under any other name, or with no name at all, matches
nothing, and neither does a credential split across lines. An unquoted value
needs both a letter and a digit. It reads blobs, so commit messages, tag messages
and binary files go unread. 0 means no rule matched. It does not mean the history
holds no credential.

FALSE POSITIVES ARE ACCEPTED within those rules. They report what is plausible
and tag it with why; a scanner tuned until it is quiet is a scanner that will
miss the one that matters. Fixture-looking values are labelled `likely-fixture`
rather than dropped, so the reviewer decides and the decision is visible. The
label is read from the matched value, never the rest of its line, and a CRITICAL
hit counts toward the verdict even when it carries the label. A value two rules
match is reported once, under the more severe.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from typing import Any

#: The names the assignment rules read as credentials. `(?-i:...)` keeps *_KEY
#: to upper case: an env variable, where `cache_key` and `sort_key` in code say
#: nothing about a credential.
_CREDENTIAL_NAME = (r"secret(?:[_-]?key)?|token|api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|"
                    r"private[_-]?key|(?-i:[A-Z][A-Z0-9_]*_KEY)")

#: (severity, name, pattern). Severity drives review order, not truth.
PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("CRITICAL", "private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("CRITICAL", "aws access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("CRITICAL", "github token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("CRITICAL", "github fine-grained pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("CRITICAL", "slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("CRITICAL", "sk- prefixed api key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("CRITICAL", "google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("CRITICAL", "stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("CRITICAL", "npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("CRITICAL", "gitlab token", re.compile(r"\bgl(?:pat|dt|rt|ptt|oas)-[A-Za-z0-9_-]{20,}")),
    ("CRITICAL", "pypi token", re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}")),
    ("HIGH", "json web token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.")),
    # `["']?` after each key name: a JSON key's closing quote sits between the
    # name and the colon, and without it `"password": "..."` matched nothing.
    # `(?<![A-Za-z0-9])` before it, not `\b`: `\b` does not match between `_`
    # and a letter, so `DB_PASSWORD="..."` and `APP_SECRET="..."` matched
    # nothing either.
    # The AWS value is its own group: `\S{20,}` ran on past it, so on a
    # compact JSON line or a query string the match took in a later field's
    # `localhost` and excused a real key. The group starts after any run of
    # non-alphanumeric characters and an optional Python string prefix: a
    # fixed `\\?["']?` before it let one backslash and one quote through and
    # nothing else, so a YAML flow list (`["KEY"]`), a string prefix
    # (`b'KEY'`, `r"KEY"`) and a doubly escaped quote (`\\\"KEY`) matched no
    # rule, though `\S{20,}` had counted each of them. The value is 20
    # characters or more of anything but a space, a quote, a backslash, `,`,
    # `&`, `;`, a backtick, `[`, `]`, `(` or `)`, so it ends where the field
    # does and nothing after it is searched. It was the AWS alphabet, 40 or
    # more, which dropped a 31-character B2 key and a value with `-`, `_` or
    # `.`, as S3-compatible stores accept. `<` and `$` do not end the run
    # before the value, so `<your-key>` and `${AWS_SECRET_ACCESS_KEY}` stay
    # whole and are tagged by the hints, as main tagged them. A `=` or `:`
    # must come between the key and the value, as main required: without it
    # a list of key names (`"aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"`)
    # read the second name as the first one's value. A space separates too,
    # as in `aws configure set aws_secret_access_key KEY`, when the value
    # after it has a lowercase letter or a digit, so `$AWS_SECRET_ACCESS_KEY`
    # or an environment variable's name is not read as a value. Only the
    # value's own characters are read for that: the whole next word let an
    # escaped `\n` after a variable name supply the lowercase letter. A `\/`
    # inside the value is JSON's escaped slash (PHP writes every `/` so), and
    # does not end it.
    ("HIGH", "aws secret access key", re.compile(r"aws_secret_access_key(?:[^A-Za-z0-9<$=:]*[=:]|[ \t]+(?=(?-i:[^A-Za-z0-9\s]*[^\s\"'\\,&;`\[\]()]*?[a-z0-9])))(?:[^A-Za-z0-9<$]|(?<![A-Za-z0-9])[bruf]{1,2}(?=[\"']))*((?:[^\s\"'\\,&;`\[\]()]|\\/){20,})", re.I)),
    ("HIGH", "password assignment", re.compile(r"(?<![A-Za-z0-9])(?:password|passwd|pwd)[\"']?\s*[=:]\s*[\"']([^\"'\s]{6,})", re.I)),
    ("HIGH", "secret assignment", re.compile(rf"(?<![A-Za-z0-9])(?:{_CREDENTIAL_NAME})[\"']?\s*[=:]\s*[\"']([^\"'\s]{{12,}})", re.I)),
    # The same names with no quote before the value, as an env file or YAML
    # writes it. A value must hold a letter and a digit, and stops at anything
    # that is not a token character, so `password: ${{ x }}`, `token = get()`
    # and `secret: some-word` are not read as credentials.
    ("HIGH", "unquoted credential assignment", re.compile(rf"(?<![A-Za-z0-9])(?:password|passwd|pwd|{_CREDENTIAL_NAME})[\"']?[ \t]*[=:][ \t]*(?=[A-Za-z0-9_\-+/=.~]*[0-9])(?=[A-Za-z0-9_\-+/=.~]*[A-Za-z])([A-Za-z0-9_\-+/=.~]{{12,}})(?![A-Za-z0-9_\-+/=.~(\[])", re.I)),
    # The quote before the value is optional for curl -H "Authorization: Bearer ...".
    ("MEDIUM", "authorization header literal", re.compile(r"Authorization[\"']?\s*[:=]\s*[\"']?(?:Bearer|Basic|token)\s+([^\"'\s]{12,})", re.I)),
    ("MEDIUM", "private ssh key body", re.compile(r"\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/]{100,}")),
    ("LOW", "us social security number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("LOW", "email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

#: Values that are obviously test scaffolding. NOT dropped -- tagged, so the
#: reviewer sees them and can disagree. Searched in the captured value, or the
#: matched text for a rule with no group, and never the rest of the line: on
#: the whole line, `veridor` (this product's own env-var prefix), any `<tag>`,
#: `localhost` or a `# xxx` comment excused a real token next to it.
FIXTURE_HINTS = re.compile(
    r"example\.(?:com|org|invalid)|\.invalid\b|localhost|127\.0\.0\.1|"
    r"veridor|marker|owner-token|admin-token|outsider|attacker|victim|"
    r"hunter2|changeme|password123|passw0rd|s3cret|dummy|placeholder|"
    r"xxx+|yyy+|<[a-z-]+>|\$\{[A-Za-z_]+\}|redacted|noreply|"
    # A whole value that is a `{NAME}` format placeholder is a template, as
    # `${NAME}` is: `password = "{PASSWORD}"` in an f-string is no secret.
    r"^\{[A-Za-z_][A-Za-z0-9_]*\}$",
    re.I,
)

SKIP_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2")


def blobs() -> list[tuple[str, str]]:
    """Every (sha, path) that has ever existed, including in deleted files."""
    out = subprocess.run(
        ["git", "rev-list", "--objects", "--all"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    seen = []
    for line in out:
        sha, _, path = line.partition(" ")
        if path and not path.endswith(SKIP_SUFFIX):
            seen.append((sha, path))
    return seen


def commits_touching(path: str) -> str:
    result = subprocess.run(
        ["git", "log", "--all", "--oneline", "--", path],
        capture_output=True, text=True,
    ).stdout.splitlines()
    return result[0] if result else "?"


def matched_lines(text: str, start: int, end: int) -> str:
    """The line or lines holding text[start:end], every run of whitespace in
    them one space. Lines are found by "\\n" only, as `line` is counted: this
    was `str.splitlines()`, which also splits on a form feed, a lone CR,
    U+2028 and others, so after one of those `context` showed a different
    line from the one that matched. A CR or form feed left inside is a space,
    so it cannot rewrite the terminal line the text listing prints."""
    first = text.rfind("\n", 0, start) + 1
    last = text.find("\n", max(start, end - 1))
    return " ".join(text[first:len(text) if last < 0 else last].split())


def scan() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for sha, path in blobs():
        content = subprocess.run(
            ["git", "cat-file", "-p", sha], capture_output=True
        ).stdout
        if b"\0" in content[:8192]:
            continue
        text = content.decode("utf-8", "replace")
        values: list[tuple[int, int]] = []
        for severity, name, pattern in PATTERNS:
            for match in pattern.finditer(text):
                span = match.span(1) if pattern.groups else match.span()
                if any(start < span[1] and span[0] < end for start, end in values):
                    continue  # a more severe rule already reported this value
                values.append(span)
                snippet = match.group(0)
                line_no = text.count("\n", 0, match.start()) + 1
                # A rule that captures its value is judged on the value alone.
                value = match.group(1) if pattern.groups else snippet
                likely_fixture = bool(FIXTURE_HINTS.search(value))
                findings.append({
                    "severity": severity,
                    "rule": name,
                    "path": path,
                    "blob": sha[:10],
                    "line": line_no,
                    "match": snippet[:80],
                    "context": matched_lines(text, match.start(), match.end())[:140],
                    "likely_fixture": likely_fixture,
                    # A CRITICAL rule is a token shape, not a guess: tagged
                    # for the reviewer, never excused from the count.
                    "counted": severity == "CRITICAL" or not likely_fixture,
                })
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--include-fixtures", action="store_true",
                        help="list every likely-fixture hit individually")
    args = parser.parse_args(argv)

    try:
        findings = scan()
    except subprocess.CalledProcessError as error:
        print(f"could not read git history: {error}", file=sys.stderr)
        return 2

    real = [f for f in findings if f["counted"]]
    fixture = [f for f in findings if not f["counted"]]

    if args.json:
        print(json.dumps({"findings": findings, "needs_review": len(real)}, indent=1))
        return 1 if real else 0

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    print(f"Secrets audit over git history — {len(blobs())} blobs, "
          f"{subprocess.run(['git','rev-list','--all','--count'],capture_output=True,text=True).stdout.strip()} commits\n")

    if not real:
        print("  No rule matched outside obvious test scaffolding. "
              "The rules cover named shapes only: this does not show the history is clean.\n")
    for f in sorted(real, key=lambda f: (order[f["severity"]], f["path"])):
        tagged = "  (looks like a fixture; CRITICAL is counted anyway)" if f["likely_fixture"] else ""
        print(f"  [{f['severity']}] {f['rule']}  —  {f['path']}:{f['line']}  (blob {f['blob']}){tagged}")
        print(f"            {f['context']}")

    grouped: dict[tuple[str, str], int] = defaultdict(int)
    for f in fixture:
        grouped[(f["severity"], f["rule"])] += 1
    if grouped:
        print(f"\n  {len(fixture)} hit(s) tagged likely-fixture and NOT counted:")
        for (severity, rule), n in sorted(grouped.items(), key=lambda kv: order[kv[0][0]]):
            print(f"    {n:>4}  [{severity}] {rule}")
        if args.include_fixtures:
            for f in sorted(fixture, key=lambda f: (order[f["severity"]], f["path"])):
                print(f"      {f['path']}:{f['line']}  {f['context'][:100]}")
        print("\n  Tagged, not dropped. Read them before trusting the verdict.")

    print(f"\n  {len(real)} finding(s) need review.")
    return 1 if real else 0


if __name__ == "__main__":
    raise SystemExit(main())
