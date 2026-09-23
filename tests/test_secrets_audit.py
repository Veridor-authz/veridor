"""scripts/secrets_audit.py: what it counts, through the command a person runs.

The audit is a manual pre-publication tool (CI leaves it out on purpose), so
its headline, its count and its exit code are what a person acts on. Each test
here builds a throwaway git repository, commits one file per case, and reads
the command's own --json answer.

Every credential below is synthetic and assembled at run time, so this file
carries no credential-shaped literal of its own.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from tiers import slow  # noqa: E402

SCRIPT = ROOT / "scripts" / "secrets_audit.py"

#: Shaped like the CRITICAL rules, random-looking, and matching no fixture hint.
GITHUB_TOKEN = "ghp" + "_" + "Q7mZ2kR9vT4nB8cW1pL6" * 2
AWS_KEY = "AK" + "IA" + "Q7MZ2KR9VT4NB8CW"
#: The same token shape with a fixture hint inside the value itself.
GITHUB_TOKEN_XXX = "ghp" + "_" + "x" * 40
#: Below-CRITICAL values: random-looking, and matching no fixture hint.
PASSWORD = "Qz7mK" + "2rP9vT4"
SECRET = "Q7mZ2kR9" + "vT4nB8cW"
AWS_SECRET = "Qz7mK2" + "rP9vT4" + "nB8cW1pL6aZ0" * 3
#: S3-compatible secrets outside the AWS alphabet: a B2-length value, and
#: values with `-`, `_` and `.`, as MinIO accepts.
B2_SECRET = "Qz7mK2" + "rP9vT4" + "nB8cW1pL6aZ0Qz7mK2r"
DASHED_SECRET = "Qz7mK2" + "rP-9vT4" + "nB8cW-1pL6aZ0"
DOTTED_SECRET = "Qz7mK2" + "rP_9vT4" + "nB8cW.1pL6aZ0"
GITLAB_TOKEN = "gl" + "pat-" + "Q7mZ2kR9vT4nB8cW1pL6"
PYPI_TOKEN = "py" + "pi-" + "Q7mZ2kR9vT4nB8cW1pL6" * 3
#: An `sk-` prefixed API key, bare and with the `ant-` infix the rule also takes.
SK_KEY = "s" + "k-" + "Qm7Lp2Xv9Rt4Wb8Nc3Zd6Hf1"
SK_ANT_KEY = "s" + "k-ant-" + "Vr5Tn8Kc2Lw7Pq4Xm9Bz3Jh6"
#: A shell reference to the secret's variable, which is no secret.
ENV_REFERENCE = "$" + "AWS_SECRET_ACCESS_KEY"


@slow("builds git repositories and runs scripts/secrets_audit.py in them")
class SecretsAuditTest(unittest.TestCase):
    def audit(self, files: dict[str, str]) -> tuple[int, dict[str, list[dict]], dict]:
        """Commit each file, run the audit with --json, and return its exit
        code, its findings by path, and the whole document."""
        repo = Path(tempfile.mkdtemp(prefix="veridor-secrets-"))
        self.addCleanup(shutil.rmtree, repo, True)
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, timeout=60)

        git("init", "-q")
        for name, text in files.items():
            (repo / name).write_text(text, encoding="utf-8")
            git("add", name)
            git("commit", "-q", "-m", name)
        done = subprocess.run([sys.executable, "-I", str(SCRIPT), "--json"], cwd=repo, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertIn(done.returncode, (0, 1), done.stderr)
        document = json.loads(done.stdout)
        by_path: dict[str, list[dict]] = {}
        for finding in document["findings"]:
            by_path.setdefault(finding["path"], []).append(finding)
        return done.returncode, by_path, document

    def test_control_a_bare_token_is_counted(self) -> None:
        code, found, document = self.audit({"a.env": f'GH_TOKEN = "{GITHUB_TOKEN}"\n'})
        self.assertEqual(code, 1)
        self.assertEqual(document["needs_review"], 1)
        self.assertEqual([f["rule"] for f in found["a.env"]], ["github token"])

    def test_a_hint_elsewhere_on_the_line_does_not_excuse_a_credential(self) -> None:
        """REGRESSION. The fixture hint was searched across the whole source
        line, and `veridor`, `xxx`, any lowercase tag and `localhost` are
        hints, so this product's own env-var prefix excused a real token: the
        audit printed "0 finding(s) need review" and exited 0 (reproduced)."""
        cases = {
            "prefix.env": f'VERIDOR_GH_TOKEN = "{GITHUB_TOKEN}"\n',
            "cell.html": f"<td>{GITHUB_TOKEN}</td>\n",
            "comment.py": f"aws_key = {AWS_KEY}  # xxx\n",
            "host.env": f"API_HOST=localhost GH_TOKEN={GITHUB_TOKEN}\n",
        }
        code, found, document = self.audit(cases)
        self.assertEqual(code, 1)
        for path in cases:
            with self.subTest(path=path):
                self.assertTrue(found.get(path), f"{path}: no rule matched")
                self.assertTrue(all(f["counted"] for f in found[path]), found[path])
        self.assertEqual(document["needs_review"], len(cases))

    def test_a_hint_elsewhere_on_the_line_does_not_excuse_a_high_or_medium_hit(self) -> None:
        """REGRESSION. The test above uses CRITICAL tokens only, and a CRITICAL
        hit is counted whether or not it is tagged, so reading the hint from
        the whole line again (`FIXTURE_HINTS.search(line or snippet)`) left it
        green while these were excused again (measured on a copy). Below
        CRITICAL, only the matched value may carry the hint."""
        cases = {
            "password.py": (f'password = "{PASSWORD}"  # xxx\n', "password assignment"),
            "secret.yml": (f'secret: "{SECRET}"  # localhost\n', "secret assignment"),
            "header.json": (f'{{"base_url": "http://localhost", "Authorization": "Bearer {SECRET}"}}\n',
                            "authorization header literal"),
        }
        code, found, document = self.audit({path: text for path, (text, _) in cases.items()})
        self.assertEqual(code, 1)
        for path, (_, rule) in cases.items():
            with self.subTest(path=path):
                [hit] = found.get(path) or [None]
                self.assertIsNotNone(hit, f"{path}: no rule matched")
                self.assertEqual(hit["rule"], rule)
                self.assertNotEqual(hit["severity"], "CRITICAL")
                self.assertFalse(hit["likely_fixture"], hit)
                self.assertTrue(hit["counted"], hit)
        self.assertEqual(document["needs_review"], len(cases))

    def test_env_var_names_match_the_assignment_rules(self) -> None:
        """REGRESSION. `\\b` does not match between `_` and a letter, so
        `DB_PASSWORD="..."` and `VERIDOR_SECRET="..."`, the commonest way a
        credential is written to an env file, matched no rule (reproduced)."""
        cases = {
            "db.env": (f'DB_PASSWORD="{PASSWORD}"\n', "password assignment"),
            "app.env": (f'APP_SECRET="{SECRET}"\n', "secret assignment"),
            "client.py": (f'client_secret = "{SECRET}"\n', "secret assignment"),
            "commented.py": (f'db_password = "{PASSWORD}"  # xxx\n', "password assignment"),
        }
        code, found, document = self.audit({path: text for path, (text, _) in cases.items()})
        self.assertEqual(code, 1)
        for path, (_, rule) in cases.items():
            with self.subTest(path=path):
                self.assertEqual([f["rule"] for f in found.get(path, [])], [rule])
                self.assertTrue(found[path][0]["counted"], found[path])
        self.assertEqual(document["needs_review"], len(cases))
        # Control: a name that merely ends in the word is not a key.
        _, found, _ = self.audit({"word.py": f'nopassword = "{PASSWORD}"\nmysecret = "{SECRET}"\n'})
        self.assertEqual(found.get("word.py", []), [])

    def test_the_aws_secret_rule_matches_its_json_and_env_spellings(self) -> None:
        """The rule was widened to cross a JSON key's closing quote; nothing
        exercised it, so reverting that left every test green."""
        cases = {
            "aws.json": f'{{"aws_secret_access_key": "{AWS_SECRET}"}}\n',
            "aws.env": f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n",
            "credentials": f"aws_secret_access_key = {AWS_SECRET}\n",
        }
        code, found, _ = self.audit(cases)
        self.assertEqual(code, 1)
        for path in cases:
            with self.subTest(path=path):
                self.assertEqual([f["rule"] for f in found.get(path, [])], ["aws secret access key"])
                self.assertTrue(found[path][0]["counted"])

    def test_a_hint_after_the_aws_secret_value_does_not_excuse_it(self) -> None:
        """REGRESSION. The AWS-secret rule ended in `\\S{20,}`, which runs past
        the value to the next space, so on a compact JSON line or a query
        string the match took in `localhost` from a later field and the real
        key was tagged a fixture and left out of the count (reproduced). The
        value is now its own group, and only the group is searched for hints."""
        cases = {
            "compact.json": f'{{"aws_secret_access_key":"{AWS_SECRET}","endpoint":"http://localhost:9000"}}\n',
            "query.txt": f"aws_secret_access_key={AWS_SECRET}&endpoint=localhost\n",
        }
        code, found, document = self.audit(cases)
        self.assertEqual(code, 1)
        for path in cases:
            with self.subTest(path=path):
                [hit] = found.get(path) or [None]
                self.assertIsNotNone(hit, f"{path}: no rule matched")
                self.assertEqual(hit["rule"], "aws secret access key")
                self.assertFalse(hit["likely_fixture"], hit)
                self.assertTrue(hit["counted"], hit)
        self.assertEqual(document["needs_review"], len(cases))
        # Control: a placeholder in the value itself is still excused, at the
        # 40+ alphabet length an AWS secret has, so the value group, not the
        # length rule, is what the hint is searched in.
        code, found, _ = self.audit({"placeholder.env":
                                     f"aws_secret_access_key={'placeholder' * 4}\n"})
        self.assertEqual(code, 0)
        [hit] = found["placeholder.env"]
        self.assertTrue(hit["likely_fixture"])
        self.assertFalse(hit["counted"])

    def test_an_aws_secret_behind_an_escaped_quote_is_counted(self) -> None:
        """REGRESSION. Giving the AWS-secret value its own group made the
        optional opening quote unable to step over a backslash, so in
        `echo "aws_secret_access_key=\\"KEY\\"" >> creds` the group took
        the `\\` alone, fell short of 20 characters, and no rule matched a
        line the old rule had counted (reproduced). A backslash before either
        quote is now allowed, and is never part of the value."""
        cases = {
            "escaped.sh": f'echo "aws_secret_access_key=\\"{AWS_SECRET}\\"" >> creds\n',
            "escaped.json": f'"{{\\"aws_secret_access_key\\":\\"{AWS_SECRET}\\"}}"\n',
        }
        code, found, document = self.audit(cases)
        self.assertEqual(code, 1)
        for path in cases:
            with self.subTest(path=path):
                [hit] = found.get(path) or [None]
                self.assertIsNotNone(hit, f"{path}: no rule matched")
                self.assertEqual(hit["rule"], "aws secret access key")
                self.assertFalse(hit["likely_fixture"], hit)
                self.assertTrue(hit["counted"], hit)
                self.assertIn(AWS_SECRET, hit["match"])
                self.assertNotIn(AWS_SECRET + "\\", hit["match"])
        self.assertEqual(document["needs_review"], len(cases))

    def test_an_aws_secret_after_any_punctuation_or_string_prefix_is_counted(self) -> None:
        """REGRESSION. The value group began after an optional `\\` and one
        optional quote, so a value behind anything else matched nothing,
        although the previous `\\S{20,}` had counted each of these (reproduced):
        a YAML flow list (`["KEY"]`), a Python string prefix
        (`b'KEY'`, `r"KEY"`) and a doubly escaped quote (`\\\\\\"KEY`). The
        value now starts after any run of non-alphanumeric characters and an
        optional string prefix."""
        exact = (AWS_SECRET[:19] + "/" + AWS_SECRET[19:38] + "+")  # 40, both symbols
        self.assertEqual(len(exact), 40)
        cases = {
            "flow.yml": (f'aws_secret_access_key: ["{AWS_SECRET}"]\n', AWS_SECRET),
            "bytes.py": (f"aws_secret_access_key = b'{AWS_SECRET}'\n", AWS_SECRET),
            "raw.py": (f'aws_secret_access_key = r"{exact}"\n', exact),
            "double.sh": (f'aws_secret_access_key=\\\\\\"{AWS_SECRET}\\\\\\"\n', AWS_SECRET),
        }
        code, found, document = self.audit({path: text for path, (text, _) in cases.items()})
        self.assertEqual(code, 1)
        for path, (_, value) in cases.items():
            with self.subTest(path=path):
                [hit] = found.get(path) or [None]
                self.assertIsNotNone(hit, f"{path}: no rule matched")
                self.assertEqual(hit["rule"], "aws secret access key")
                self.assertTrue(hit["match"].endswith(value), hit)
                self.assertFalse(hit["likely_fixture"], hit)
                self.assertTrue(hit["counted"], hit)
        self.assertEqual(document["needs_review"], len(cases))
        # Control: the hint is still searched in the value, so a placeholder
        # behind the same prefix is tagged and not counted.
        code, found, _ = self.audit({"placeholder.py":
                                     f"aws_secret_access_key = b'{'placeholder' * 4}'\n"})
        self.assertEqual(code, 0)
        [hit] = found["placeholder.py"]
        self.assertTrue(hit["likely_fixture"])
        self.assertFalse(hit["counted"])

    def test_an_aws_style_secret_outside_the_aws_alphabet_is_counted(self) -> None:
        """REGRESSION. Bounding the value to the AWS alphabet, 40 characters or
        more, dropped what the previous `\\S{20,}` had counted under the same key
        (reproduced): a 31-character value, as a B2 application key
        is, and one with `-`, `_` or `.` in it, as S3-compatible stores such as
        MinIO accept. The value is now 20 characters or more of anything but a
        space, a quote, a backslash or a separator that ends it."""
        cases = {
            "short.env": (f"aws_secret_access_key = {B2_SECRET}\n", B2_SECRET),
            "hyphen.env": (f"aws_secret_access_key={DASHED_SECRET}\n", DASHED_SECRET),
            "dotted.yml": (f'aws_secret_access_key: "{DOTTED_SECRET}"\n', DOTTED_SECRET),
        }
        code, found, document = self.audit({path: text for path, (text, _) in cases.items()})
        self.assertEqual(code, 1)
        for path, (_, value) in cases.items():
            with self.subTest(path=path):
                [hit] = found.get(path) or [None]
                self.assertIsNotNone(hit, f"{path}: no rule matched")
                self.assertEqual(hit["rule"], "aws secret access key")
                self.assertTrue(hit["match"].endswith(value), hit)
                self.assertTrue(hit["counted"], hit)
        self.assertEqual(document["needs_review"], len(cases))
        # Control: a reference and a placeholder are tagged, as main tagged
        # them, rather than counted now that `$`, `{` and `<` can be in a value.
        # A list of key names assigns nothing: main required `=` or `:` after
        # the key, and without it the next name, `AWS_SECRET_ACCESS_KEY`, was
        # read as the value (tests/test_capsule.py's CREDENTIALS tuple, 23
        # counted hits in this repository's history).
        code, found, _ = self.audit({
            "reference.env": "aws_secret_access_key=${AWS_SECRET_ACCESS_KEY}\n",
            "template.yml": 'aws_secret_access_key: "<your-secret-access-key>"\n',
            "names.py": 'NAMES = ("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "access_key")\n',
        })
        self.assertEqual(code, 0)
        for path in ("reference.env", "template.yml"):
            with self.subTest(control=path):
                [hit] = found[path]
                self.assertTrue(hit["likely_fixture"], hit)
                self.assertFalse(hit["counted"], hit)
        self.assertNotIn("names.py", found)

    def test_the_aws_cli_form_is_counted(self) -> None:
        """REGRESSION. Requiring `=` or `:` after the key, to stop a list of
        key names reading the next name as a value, dropped `aws configure
        set aws_secret_access_key KEY`, which an earlier version counted (reproduced
        with a random value). A space now separates too, when the word after
        it has a lowercase letter or a digit, so an environment variable's
        name is still not read as its value."""
        code, found, document = self.audit({
            "deploy.sh": f"aws configure set aws_secret_access_key {AWS_SECRET}\n",
            "quoted.sh": f'aws configure set aws_secret_access_key "{AWS_SECRET}"\n',
        })
        self.assertEqual(code, 1)
        for path in ("deploy.sh", "quoted.sh"):
            with self.subTest(path=path):
                [hit] = found[path]
                self.assertEqual(hit["rule"], "aws secret access key")
                self.assertTrue(hit["match"].endswith(AWS_SECRET), hit)
                self.assertTrue(hit["counted"], hit)
        self.assertEqual(document["needs_review"], 2)
        # Controls: a name, or a reference to one, after the space is no value.
        code, found, _ = self.audit({
            "reference.sh": f"aws configure set aws_secret_access_key {ENV_REFERENCE}\n",
            "table.md": "| aws_secret_access_key | AWS_SECRET_ACCESS_KEY |\n",
            "mapping.txt": f"aws_secret_access_key {ENV_REFERENCE[1:]}\n",
        })
        self.assertEqual(code, 0)
        for path in ("reference.sh", "table.md", "mapping.txt"):
            with self.subTest(control=path):
                self.assertNotIn(path, found)

    def test_a_json_escaped_slash_does_not_end_the_value(self) -> None:
        """REGRESSION, in every earlier form of the rule. PHP's
        json_encode writes `/` as `\\/`, and the value ended at the backslash,
        so a secret with a slash in its first 20 characters matched nothing."""
        slashed = AWS_SECRET[:10] + "/" + AWS_SECRET[10:39]
        escaped = slashed.replace("/", "\\/")
        code, found, _ = self.audit({"php.json": f'{{"aws_secret_access_key":"{escaped}"}}\n'})
        self.assertEqual(code, 1)
        [hit] = found["php.json"]
        self.assertEqual(hit["rule"], "aws secret access key")
        self.assertTrue(hit["match"].endswith(escaped), hit)
        self.assertTrue(hit["counted"], hit)

    def test_a_format_placeholder_is_tagged_not_counted(self) -> None:
        """A value that is a whole `{NAME}` placeholder is a template, as
        `${NAME}` is; this file's own `password = "{PASSWORD}"` f-strings were
        counted as secrets needing review. Control: a value that only contains
        braces is still counted."""
        code, found, _ = self.audit({
            "template.py": 'password = "{DB_PASSWORD}"\n',
            # Assembled so this file's own line is not a hit of the rule.
            "braced.env": "pass" + f'word = "{{{PASSWORD}}}x"\n',
        })
        [template] = found["template.py"]
        self.assertTrue(template["likely_fixture"], template)
        self.assertFalse(template["counted"], template)
        [braced] = found["braced.env"]
        self.assertFalse(braced["likely_fixture"], braced)
        self.assertTrue(braced["counted"], braced)
        self.assertEqual(code, 1)

    def test_the_space_separator_reads_only_the_value(self) -> None:
        """The check after a space looked past the value to the rest of the
        line, so an escaped `\\n` after a variable name supplied the lowercase
        letter and the name was counted. It reads the value's own characters."""
        code, found, _ = self.audit({
            "escaped.json": f'{{"run": "aws configure set aws_secret_access_key {ENV_REFERENCE}\\n"}}\n',
        })
        self.assertEqual(code, 0)
        self.assertNotIn("escaped.json", found)

    def test_context_is_the_line_that_matched(self) -> None:
        """REGRESSION. `line` counts newlines, but `context` came from
        `str.splitlines()`, which also splits on a form feed, a lone CR, U+2028
        and more, so after one of those the context was another line: `b` for
        a password on line 2 here (reproduced). A match whose whitespace spans
        a newline shows every line it spans."""
        _, found, _ = self.audit({
            "drift.py": f'a\x0cb\nother = 1\u2028x\rpassword = "{PASSWORD}"\n',
            "spans.yml": f'top:\n  password:\n    "{PASSWORD}"\nnext: 1\n',
        })
        [drift] = found["drift.py"]
        self.assertEqual(drift["line"], 2)
        self.assertIn(f'password = "{PASSWORD}"', drift["context"])
        [spans] = found["spans.yml"]
        self.assertEqual(spans["line"], 2)
        self.assertEqual(spans["context"], f'password: "{PASSWORD}"')

    def test_a_critical_hit_is_counted_even_when_its_value_looks_like_a_fixture(self) -> None:
        """A CRITICAL rule is a token shape, not a guess. It is still tagged,
        so the reviewer sees why it looked like scaffolding, but it moves the
        count and the exit code."""
        code, found, _ = self.audit({"fixture.json": f'{{"token": "{GITHUB_TOKEN_XXX}"}}\n'})
        self.assertEqual(code, 1)
        [hit] = found["fixture.json"]
        self.assertTrue(hit["likely_fixture"])
        self.assertTrue(hit["counted"])

    def test_json_style_keys_match_the_assignment_rules(self) -> None:
        """REGRESSION. `\\s*[=:]` straight after the key name cannot cross the
        quote that closes a JSON key, so `"password": "..."` and
        `"api_key": "..."` matched no rule at all (reproduced), while the YAML
        and Python spellings did."""
        cases = {
            "password.json": (f'{{"password": "{PASSWORD}"}}\n', "password assignment"),
            "api_key.json": (f'{{"api_key": "{SECRET}"}}\n', "secret assignment"),
            "password.yml": (f'password: "{PASSWORD}"\n', "password assignment"),
            "api_key.py": (f'api_key = "{SECRET}"\n', "secret assignment"),
        }
        code, found, _ = self.audit({path: text for path, (text, _) in cases.items()})
        self.assertEqual(code, 1)
        for path, (_, rule) in cases.items():
            with self.subTest(path=path):
                self.assertEqual([f["rule"] for f in found.get(path, [])], [rule])
                self.assertTrue(found[path][0]["counted"])

    def test_the_ordinary_credential_shapes_are_counted(self) -> None:
        """REGRESSION. The docstring said "Anything plausible is reported" while
        8 of 10 ordinary shapes holding the same random value matched nothing,
        and the text output said no credential-shaped value was found."""
        cases = {
            "settings.py": (f'SECRET_KEY = "{SECRET}"\n', "secret assignment"),
            "db.env": (f"DB_PASSWORD={SECRET}\n", "unquoted credential assignment"),
            "client.yaml": (f"client_secret: {SECRET}\n", "unquoted credential assignment"),
            "token.py": (f'TOKEN = "{SECRET}"\n', "secret assignment"),
            "call.sh": (f'curl -H "Authorization: Bearer {SECRET}" https://h\n', "authorization header literal"),
            "app.yaml": (f"password: {SECRET}\n", "unquoted credential assignment"),
            "key.env": (f"API_KEY={SECRET}\n", "unquoted credential assignment"),
            "sign.env": (f'SIGNING_KEY="{SECRET}"\n', "secret assignment"),
            "gitlab.txt": (f"{GITLAB_TOKEN}\n", "gitlab token"),
            "pypi.txt": (f"{PYPI_TOKEN}\n", "pypi token"),
        }
        code, found, document = self.audit({path: text for path, (text, _) in cases.items()})
        self.assertEqual(code, 1)
        for path, (_, rule) in cases.items():
            with self.subTest(path=path):
                self.assertEqual([f["rule"] for f in found.get(path, [])], [rule])
                self.assertTrue(found[path][0]["counted"], found[path])
        self.assertEqual(document["needs_review"], len(cases))

    def test_an_sk_prefixed_api_key_is_counted_under_its_rule(self) -> None:
        """No test planted a value for this rule, so renaming or breaking it
        changed nothing a test could see."""
        cases = {"bare.txt": f"{SK_KEY}\n", "infix.txt": f"{SK_ANT_KEY}\n"}
        code, found, document = self.audit(cases)
        self.assertEqual(code, 1)
        for path in cases:
            with self.subTest(path=path):
                self.assertEqual([f["rule"] for f in found.get(path, [])], ["sk- prefixed api key"])
                self.assertTrue(found[path][0]["counted"], found[path])
        self.assertEqual(document["needs_review"], len(cases))

    def test_control_what_only_names_a_credential_is_not_counted(self) -> None:
        """The widened rules read a value, not a name in code."""
        cases = {
            "workflow.yml": "password: ${{ github.token }}\n",
            "call.py": "token = get_the_access_token(1)\n",
            "lookup.py": 'token = environ["GH_TOKEN"]\n',
            "word.yml": "secret: some-long-plain-word\n",
            "sorted.py": 'sort_key = "a_long_lowercase_name1"\n',
            "unset.env": "API_KEY=\n",
        }
        code, found, document = self.audit(cases)
        self.assertEqual((code, document["needs_review"]), (0, 0), found)
        self.assertEqual(found, {})

    def test_a_value_two_rules_match_is_one_finding_under_the_more_severe(self) -> None:
        code, found, document = self.audit({"a.env": f"GH_TOKEN={GITHUB_TOKEN}\n"})
        self.assertEqual([f["rule"] for f in found["a.env"]], ["github token"])
        self.assertEqual((code, document["needs_review"]), (1, 1))

    def test_a_zero_says_what_it_covers_and_a_miss_is_still_a_miss(self) -> None:
        """The stated limit, held to what the tool does: a random value under a
        name no rule reads is not caught, and the text output must not call
        that clean."""
        repo = Path(tempfile.mkdtemp(prefix="veridor-secrets-"))
        self.addCleanup(shutil.rmtree, repo, True)
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        (repo / "a.env").write_text(f"WIDGET_VALUE={SECRET}\n", encoding="utf-8")
        for args in (("init", "-q"), ("add", "a.env"), ("commit", "-q", "-m", "a")):
            subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, timeout=60)
        done = subprocess.run([sys.executable, "-I", str(SCRIPT)], cwd=repo, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("this does not show the history is clean", done.stdout)
        self.assertNotIn("No credential-shaped value found", done.stdout)

    def test_the_docstring_states_the_limit_and_not_the_old_claim(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        docstring = ast.get_docstring(ast.parse(text)) or ""
        self.assertNotIn("Anything plausible is reported", docstring)
        self.assertIn("It does not mean the history\nholds no credential.", docstring)

    def test_control_a_fixture_value_below_critical_is_still_excused(self) -> None:
        """The tag still works where it should: a placeholder value is tagged,
        reported, and left out of the count."""
        code, found, document = self.audit({"conf.py": 'password = "hunter2hunter2"\n'})
        self.assertEqual(code, 0)
        self.assertEqual(document["needs_review"], 0)
        [hit] = found["conf.py"]
        self.assertTrue(hit["likely_fixture"])
        self.assertFalse(hit["counted"])


if __name__ == "__main__":
    unittest.main()
