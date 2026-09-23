"""One literal-credential rule, two implementations, one corpus.

``capsule.literal_credentials`` (Python) decides what a capsule may publish;
the veridor-gate chart's ``_helpers.tpl`` (Go templates) decides what it may
render into a ConfigMap. Measured with ``helm template`` before this corpus
existed, they disagreed three ways: the chart rendered a login form body
``password=hunter2`` into its ConfigMap (it did not parse string bodies),
refused ``Cookie: sid=${VAR}`` that the capsule allows, and accepted a
credential field ``x-${VAR}`` that the capsule refuses.

``tests/fixtures/credential_parity.json`` holds the cases. Every case is
evaluated by both; each must reach the case's ``expect``. A deliberate
difference is recorded in the case as ``chart_differs`` with its reason, and
is asserted as the chart's expected verdict, so it cannot widen silently.

One difference is known and deliberately NOT in the corpus, because it
needs input no configuration should contain, and in it the chart refuses what
the capsule accepts, never the other way round: the chart percent-decodes
ASCII and the four letters below only; any other escaped UTF-8 sequence
becomes one U+FFFD, where Python decodes it. Either way the result is
non-empty, so a literal stays a literal; only a value that decodes to Unicode
whitespace alone (``%C2%A0``) is refused by the chart and accepted by the
capsule. (With a U+FFFD per BYTE, as it was, ``contrase%E2%82%ACa`` had three
characters in $credKey's one-or-two slot and the chart rendered what the
capsule refused; those cases are in the corpus now.)

Whitespace is no longer such a difference. This docstring used to list
``\\s`` (ASCII in Go's RE2, Unicode in Python's ``re``) here and say the chart
only ever refused more. It did not: ``a=1&<U+00A0>key=L`` and ``<U+000B>key``
split at ``key`` in Python, which refused them, and kept the space in the
name in Go, which rendered them; JSON text after a U+001C was parsed after
Python's ``strip()`` and skipped after Go's ``trim`` (measured with helm
template). Both sides now spell out ``[\\t\\n\\f\\r ]``, what ``\\s`` means in
RE2, and the capsule trims exactly what Go's ``strings.TrimSpace`` does
(``capsule._TRIM_SPACE``, pinned below and measured against helm). The
``whitespace:`` cases hold it.

Four letters are related to an ASCII letter by one language's case rules and
not the other's (measured over every code point: Python's ``(?i)`` reads
U+0130 and U+0131 as ``i`` and RE2 does not; Python lowers U+0130 to ``i`` and
U+0307, Go to ``i``). The chart rendered ``apİ_key`` and ``credentİals``
holding a literal that the capsule refused (measured). Both now read those
four as their ASCII letter where a match makes the scan stricter, and match
only ASCII keys where a match exempts; the ``Unicode:`` cases hold it, and
the fold is pinned equal below.

JSON text is parsed by Go's encoding/json in the chart and by Python's
``json`` in the capsule. Python also reads ``NaN``, ``Infinity``,
``-Infinity`` and numbers beyond float64, which Go refuses; the chart skipped
such text, so a literal password next to a ``NaN`` was refused by the capsule
and rendered into a ConfigMap by the chart (measured). The chart now parses
again with those, and every other number outside a string, read as 0 (a
pattern for "beyond float64" missed a 251-digit mantissa with ``e60`` and 301
digits glued to an exponent, measured). String literals are kept as they are:
rewriting inside them merged keys and turned ``"${A-1}"`` into a reference.
The corpus holds the cases, and the chart may now parse text Python refuses
(``-NaN``, nesting deeper than Python's recursion limit), where it only
refuses more.

Fast half: the corpus is well formed, the capsule side, and the shared regexes
pinned equal. Slow half: the chart side with ``helm template``, and a mutation
control on each side showing the comparison notices a broken implementation.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor import capsule  # noqa: E402

CORPUS_PATH = ROOT / "tests" / "fixtures" / "credential_parity.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CHART = ROOT / "deploy" / "helm" / "veridor-gate"
HELPERS = CHART / "templates" / "_helpers.tpl"
REQUIRE_HELM_ENV = "VERIDOR_REQUIRE_HELM"

#: What a credential refusal says in the chart. Any other render failure is a
#: broken case, not a verdict.
CHART_REFUSALS = (
    "carries a literal value",
    "is a credential-named field with a literal value",
    "carries user:password@",
    "carries a literal value for the credential-named parameter",
    "carries a literal value for cookie",
)
_ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def build(case: dict[str, Any]) -> dict[str, Any]:
    config = copy.deepcopy(CORPUS["base"])
    for path, value in case["patch"]:
        node: Any = config
        for step in path[:-1]:
            node = node[step] if isinstance(step, int) else node.setdefault(step, {})
        node[path[-1]] = copy.deepcopy(value)
    return config


#: What a refusal case refuses, where that is not ``CORPUS["literal"]``. These
#: cases never contain the corpus literal, so asserting only that it is absent
#: from a refusal could not fail on them: a refusal echoing ``123456`` or the
#: ``dark`` of ``theme=dark`` passed (measured with a value-echo mutation). Each
#: refusal is checked for its own value; ``test_every_refused_value_is_in_its_case``
#: keeps the map honest.
REFUSED_VALUES: dict[str, str] = {
    "Authorization with a literal glued to a reference": "abc",
    "Cookie with a reference and a literal cookie": "dark",
    "login JSON password numeric": "123456",
    "login JSON pin numeric": "4821",
    "login JSON password with a literal prefix on the reference": "x-${VERIDOR_OWNER_PASSWORD}",
    "login JSON password holding a list with an object with a literal": "blue",
    "a URL with a user and no password": "bob",
}

#: Refusal cases that refuse the SHAPE around a reference -- a scheme word on a
#: header that takes the reference alone, a ``${A-1}`` that is not a reference,
#: whitespace either side -- and carry no literal value to leak.
REFERENCE_SHAPED: frozenset[str] = frozenset({
    "X-Auth-Token with a scheme word before the reference",
    "JSON text with a number beyond float64 and a password that only looks like a reference",
    "Unicode: a Cookie header spelled with U+0130 holding a reference",
    "whitespace: Bearer and a reference separated by U+00A0",
    "whitespace: a reference followed by U+001C in the Authorization header",
})


#: The REFUSED_VALUES cases whose value sits in a credential-named field, the
#: slot the mutation controls on both sides make print its value.
ECHOED_FIELD_CASES = (
    "login JSON password numeric",
    "login JSON pin numeric",
    "login JSON password with a literal prefix on the reference",
    "login JSON password holding a list with an object with a literal",
)


#: The REFUSED_VALUES cases whose value sits in a credential header: an
#: Authorization header and one cookie of a Cookie header.
ECHOED_HEADER_CASES = (
    "Authorization with a literal glued to a reference",
    "Cookie with a reference and a literal cookie",
)

#: The REFUSED_VALUES case whose value is URL userinfo inside a string.
ECHOED_URL_CASES = ("a URL with a user and no password",)

#: Every REFUSED_VALUES case with a value-echo control, on both sides.
ECHO_CONTROLLED = ECHOED_FIELD_CASES + ECHOED_HEADER_CASES + ECHOED_URL_CASES


def refused_value(case: dict[str, Any]) -> str:
    return REFUSED_VALUES.get(case["name"], CORPUS["literal"])


def _scalars(value: Any) -> list[str]:
    """Every scalar in ``value`` as text: the forms a refusal could echo."""
    if isinstance(value, dict):
        return [text for item in value.values() for text in _scalars(item)]
    if isinstance(value, list):
        return [text for item in value for text in _scalars(item)]
    return [] if value is None or isinstance(value, bool) else [str(value)]


def capsule_verdict(config: dict[str, Any]) -> str:
    return "refuse" if capsule.literal_credentials(config) else "accept"


def chart_expectation(case: dict[str, Any]) -> str:
    return (case.get("chart_differs") or {}).get("expect", case["expect"])


class CorpusTest(unittest.TestCase):
    def test_the_corpus_is_well_formed_and_covers_both_verdicts(self) -> None:
        names = [case["name"] for case in CORPUS["cases"]]
        self.assertEqual(len(names), len(set(names)), "duplicate case names")
        for case in CORPUS["cases"]:
            with self.subTest(case=case["name"]):
                self.assertIn(case["expect"], ("refuse", "accept"))
                self.assertLessEqual(set(case), {"name", "patch", "expect", "chart_allow_literal_headers",
                                                 "chart_differs"})
                if "chart_differs" in case:
                    differs = case["chart_differs"]
                    self.assertNotEqual(differs["expect"], case["expect"])
                    self.assertGreater(len(differs["reason"]), 40, "a difference needs its reason")
                build(case)
        verdicts = [case["expect"] for case in CORPUS["cases"]]
        self.assertGreater(verdicts.count("refuse"), 15)
        self.assertGreater(verdicts.count("accept"), 15)

    def test_the_three_measured_disagreements_are_cases(self) -> None:
        """The defects that started this: each must stay in the corpus."""
        by_name = {case["name"]: case for case in CORPUS["cases"]}
        self.assertEqual(by_name["login form body with a literal password"]["expect"], "refuse")
        self.assertEqual(by_name["Cookie whose one value is a reference"]["expect"], "accept")
        self.assertEqual(
            by_name["login JSON password with a literal prefix on the reference"]["expect"], "refuse")


class CapsuleSideTest(unittest.TestCase):
    def test_every_case_is_decided_as_expected_by_the_capsule(self) -> None:
        for case in CORPUS["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(capsule_verdict(build(case)), case["expect"])

    def test_a_refusal_never_carries_the_value(self) -> None:
        for case in CORPUS["cases"]:
            found = capsule.literal_credentials(build(case))
            with self.subTest(case=case["name"]):
                self.assertNotIn(CORPUS["literal"], json.dumps(found))
                # Raw text as well as JSON: json.dumps escapes U+00A0 and U+001C,
                # so a value carrying either could not be found in it.
                self.assertNotIn(refused_value(case), "\n".join(part for entry in found for part in entry))

    def test_a_refusal_that_printed_its_value_would_be_caught(self) -> None:
        """Mutation control: a credential-field refusal that echoes the value it
        refused carries each of these cases' own value, which the corpus literal
        alone never showed."""
        original = capsule._scan_credential_value

        def echoing(value, path, key):
            for where, what, stem in original(value, path, key):
                yield where, f"{what} {value}", stem

        with mock.patch.object(capsule, "_scan_credential_value", echoing):
            for name in ECHOED_FIELD_CASES:
                case = next(case for case in CORPUS["cases"] if case["name"] == name)
                found = capsule.literal_credentials(build(case))
                with self.subTest(case=name):
                    self.assertIn(refused_value(case), "\n".join(part for entry in found for part in entry))
                    self.assertNotIn(CORPUS["literal"], json.dumps(found))

    def test_a_header_or_url_refusal_that_printed_its_value_would_be_caught(self) -> None:
        """Mutation control for the header and URL-userinfo refusals: one that
        echoes what it refused carries abc, dark or bob, which the corpus
        literal alone never showed."""
        header, string = capsule._scan_header, capsule._scan_string

        def echoing_header(path, name, value):
            for where, what, stem in header(path, name, value):
                yield where, f"{what} {value}", stem

        def echoing_string(path, text):
            for where, what, stem in string(path, text):
                yield where, f"{what} {text}", stem

        with mock.patch.object(capsule, "_scan_header", echoing_header), \
                mock.patch.object(capsule, "_scan_string", echoing_string):
            for name in ECHOED_HEADER_CASES + ECHOED_URL_CASES:
                case = next(case for case in CORPUS["cases"] if case["name"] == name)
                found = capsule.literal_credentials(build(case))
                with self.subTest(case=name):
                    self.assertIn(refused_value(case), "\n".join(part for entry in found for part in entry))
                    self.assertNotIn(CORPUS["literal"], json.dumps(found))

    def test_every_refused_value_has_an_echo_control(self) -> None:
        """A value check with no control on a case may be unable to fail there.

        The controls first covered only the credential-field cases; abc (an
        Authorization header), dark (a Cookie) and bob (URL userinfo) were
        asserted absent from a refusal with nothing showing the assertion could
        catch a refusal that printed them."""
        self.assertEqual(set(ECHO_CONTROLLED), set(REFUSED_VALUES))

    def test_every_refused_value_is_in_its_case(self) -> None:
        """Otherwise the check above passes on that case whatever is printed."""
        for case in CORPUS["cases"]:
            if case["expect"] != "refuse":
                continue
            scalars = _scalars([value for _, value in case["patch"]])
            with self.subTest(case=case["name"]):
                if case["name"] in REFERENCE_SHAPED:
                    self.assertTrue(any("${" in text for text in scalars))
                    continue
                self.assertTrue(
                    any(refused_value(case) in text for text in scalars),
                    "this case refuses something other than its recorded value; add it to REFUSED_VALUES",
                )
        names = {case["name"] for case in CORPUS["cases"]}
        self.assertLessEqual(set(REFUSED_VALUES) | REFERENCE_SHAPED, names)

    def test_the_capsule_side_can_fail(self) -> None:
        """Mutation control: a capsule that stops reading name=value pairs
        disagrees with the corpus on the form-body and query-string cases."""
        with mock.patch.object(capsule, "_PAIR", re.compile(r"(?!)")):
            wrong = [case["name"] for case in CORPUS["cases"]
                     if capsule_verdict(build(case)) != case["expect"]]
        self.assertIn("login form body with a literal password", wrong)
        self.assertIn("query string with a literal api_key", wrong)

    def test_the_credential_name_cases_need_the_current_pattern(self) -> None:
        """Mutation control for the name cases: the separator-only pattern
        that shipped before disagrees with the corpus on them. With it,
        ``accessToken``, ``userPassword``, ``secret_key`` and ``pass`` were
        published by the capsule and rendered by the chart (measured)."""
        separator_only = re.compile(
            r"(?i)^(.*[_.-])?(password|passwd|passphrase|pwd|secret|token|api[_-]?key"
            r"|apikey|client[_-]?secret|private[_-]?key|credentials?)$")
        with mock.patch.object(capsule, "CREDENTIAL_FIELD", separator_only):
            wrong = {case["name"] for case in CORPUS["cases"]
                     if capsule_verdict(build(case)) != case["expect"]}
        for name in ("login JSON accessToken literal", "login JSON userPassword literal",
                     "login JSON secret_key literal", "login JSON aws_secret_access_key literal",
                     "login JSON pass literal", "login JSON userPass literal",
                     "check JSON accessToken literal", "query string with a literal accessToken"):
            self.assertIn(name, wrong)

    #: The name cases added when the pattern was widened, and the parameter-only
    #: ones among them: with the previous pattern, or without PAIR_CREDENTIAL,
    #: each is published again (measured before the change).
    WIDENED_NAMES = (
        "login JSON new_password1 literal", "login JSON passwordConfirmation literal",
        "login JSON password_confirm literal", "login JSON jwt literal", "login JSON userpass literal",
        "login JSON userpwd literal", "login JSON passwort literal", "login JSON kennwort literal",
        "login JSON contrasena literal", "login JSON contraseña literal", "login JSON mot_de_passe literal",
        "login JSON senha literal", "Django signup form body password1 and password2",
        "Rails form body user[password_confirmation]", "form body contraseña percent-encoded",
        "query string with a literal jwt",
        "percent-encoded: contrase, a three-byte character, a, in a query string",
        "percent-encoded: contrase, a four-byte character, a, in a query string",
    )
    PARAMETER_ONLY = (
        "query string with a literal key (Google API key)", "query string with a literal auth (Firebase)",
        "query string with a literal code (Azure Functions)", "query string with a literal sig (Azure SAS)",
        "query string with a literal session_id", "path parameter with a literal jsessionid",
        "whitespace: an ASCII space before key= in a form body is not part of the name",
        "whitespace: a tab before sid= in a form body is not part of the name",
    )

    #: The one-time codes, PINs and client assertions, added later still: with
    #: the pattern before them each was published by the capsule and rendered
    #: by the chart while the same value under ``password`` was refused.
    SECOND_FACTOR_NAMES = (
        "login JSON passcode literal", "login JSON pin numeric", "login JSON pinCode literal",
        "login JSON userPin literal", "login JSON otp literal", "login JSON smsOtp literal",
        "login JSON totp literal", "login JSON mfa_code literal", "login JSON verification_code literal",
        "login JSON client_assertion literal",
    )

    def test_the_widened_names_need_the_widened_pattern(self) -> None:
        # The older pattern misses the second-factor names too, so they are in
        # the expected set alongside the names that widening added.
        previous = re.compile(
            r"(?i)^(?:.*(?:password|passwd|passphrase|secret|token|credentials?|api[_-]?key"
            r"|private[_-]?key|secret[_-]?key|access[_-]?key)"
            r"|(?:.*[_.-])?(?:pwd|pass)|.*(?-i:[a-z0-9]P)(?:wd|ass))$")
        with mock.patch.object(capsule, "CREDENTIAL_FIELD", previous):
            wrong = {case["name"] for case in CORPUS["cases"] if capsule_verdict(build(case)) != case["expect"]}
        self.assertEqual(wrong, set(self.WIDENED_NAMES) | set(self.SECOND_FACTOR_NAMES))
        with mock.patch.object(capsule, "PAIR_CREDENTIAL", re.compile(r"(?!)")):
            wrong = {case["name"] for case in CORPUS["cases"] if capsule_verdict(build(case)) != case["expect"]}
        self.assertEqual(wrong, set(self.PARAMETER_ONLY))

    def test_the_second_factor_names_need_the_current_pattern(self) -> None:
        before = re.compile(
            r"(?i)^(?:.*(?:password(?:[_-]?(?:confirm(?:ation)?|again|repeat|[0-9]))?|passwd|passphrase|passwort|kennwort"
            r"|contrase(?:n|[^\x00-\x7f]{1,2})a|mot[_-]?de[_-]?passe|secret|token|jwt|credentials?|api[_-]?key"
            r"|private[_-]?key|secret[_-]?key|access[_-]?key)"
            r"|(?:.*[_.-])?(?:pwd|pass|senha)|.*(?-i:[a-z0-9]P)(?:wd|ass)|(?:user|db|admin)(?:pass|pwd))$")
        with mock.patch.object(capsule, "CREDENTIAL_FIELD", before):
            wrong = {case["name"] for case in CORPUS["cases"] if capsule_verdict(build(case)) != case["expect"]}
        self.assertEqual(wrong, set(self.SECOND_FACTOR_NAMES))

    def test_the_nameless_cookie_cases_need_the_nameless_branch(self) -> None:
        """Mutation control: a capsule whose Cookie scan skips a part with no
        ``name=`` (the branch replaced with ``continue``, which survived every
        test before these cases existed) disagrees on exactly those cases."""
        source = Path(capsule.__file__).read_text(encoding="utf-8")
        branch = "                cookie_value, cookie = cookie, name\n"
        self.assertEqual(source.count(branch), 1, "the mutation no longer applies")
        mutant = types.ModuleType("capsule_without_the_nameless_cookie_branch")
        exec(compile(source.replace(branch, "                continue\n"), "<mutant>", "exec"),  # noqa: S102
             mutant.__dict__)
        wrong = sorted(case["name"] for case in CORPUS["cases"]
                       if ("refuse" if mutant.literal_credentials(build(case)) else "accept") != case["expect"])
        self.assertEqual(wrong, ["Cookie that is one bare literal",
                                 "Cookie with a reference and a nameless literal",
                                 "a check's Cookie that is one bare literal"])

    WHITESPACE_FLIPPED = (
        "whitespace: U+00A0 before key= in a form body is part of the name",
        "whitespace: U+000B before key= in a form body is part of the name",
        "whitespace: U+00A0 inside a URL's userinfo",
        "whitespace: Bearer and a reference separated by U+00A0",
        "whitespace: a reference followed by U+001C in the Authorization header",
        "whitespace: U+001C before JSON text is not trimmed, so it is not read as JSON",
    )

    def test_the_whitespace_cases_need_go_s_whitespace(self) -> None:
        """Mutation control: with Python's own ``\\s`` in the three shared
        patterns and ``str.strip()``'s whitespace, as before, the capsule
        disagrees with the chart on exactly these cases."""
        with mock.patch.object(capsule, "_PAIR", re.compile(r"(?:^|[?&;])\s*([^=&;?#\s]+)=([^&;#\s]*)")), \
                mock.patch.object(capsule, "_USERINFO", re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#@\s]*)@")), \
                mock.patch.object(capsule, "REFERENCE_ONLY_HEADER", re.compile(
                    r"^\s*([A-Za-z][A-Za-z0-9._~+/-]*\s+)?\$\{[A-Za-z_][A-Za-z0-9_.]*\}\s*$")), \
                mock.patch.object(capsule, "_TRIM_SPACE", None):
            wrong = {case["name"] for case in CORPUS["cases"] if capsule_verdict(build(case)) != case["expect"]}
        self.assertEqual(wrong, set(self.WHITESPACE_FLIPPED))

    UNICODE_NAMES = (
        "Unicode: api_key spelled with U+0130", "Unicode: api_key spelled with U+0131",
        "Unicode: credentials spelled with U+0130", "Unicode: camelCase Pass after U+0130",
        "Unicode: a headers map spelled with U+017F holding a literal Authorization",
    )

    def test_the_unicode_cases_need_the_fold(self) -> None:
        """Mutation control: without the fold the capsule publishes the
        look-alike names again. The Python-only half of what they test:
        U+0130 and U+0131 in a name were already refused here through
        Python's (?i); the camelCase and headers cases were not."""
        with mock.patch.object(capsule, "_ASCII_FOLD", {}):
            wrong = {case["name"] for case in CORPUS["cases"] if capsule_verdict(build(case)) != case["expect"]}
        self.assertEqual(wrong, {"Unicode: camelCase Pass after U+0130",
                                 "Unicode: a headers map spelled with U+017F holding a literal Authorization"})

    def test_the_nested_labelled_and_capture_cases_need_their_branches(self) -> None:
        """Mutation control for the rules added when Okta's
        credentials.password.value, Keycloak's {type: password, value: L}, a
        name/value list and a literal under a request body's `capture` key
        were all published (measured): each mutant flips exactly its cases."""
        source = Path(capsule.__file__).read_text(encoding="utf-8")
        for mutant_name, (original, replacement, _, _, expected) in NESTED_MUTANTS.items():
            with self.subTest(mutant=mutant_name):
                self.assertEqual(source.count(original), 1, "the mutation no longer applies")
                mutant = types.ModuleType("capsule_mutant")
                exec(compile(source.replace(original, replacement), "<mutant>", "exec"), mutant.__dict__)  # noqa: S102
                wrong = sorted(case["name"] for case in CORPUS["cases"]
                               if ("refuse" if mutant.literal_credentials(build(case)) else "accept") != case["expect"])
                self.assertEqual(wrong, expected)


#: Mutations of the rules that read beneath a credential-named key, a
#: labelled pair's value and a capture map, each with the corpus cases it
#: must flip (on both sides): the evidence those cases test the branch.
NESTED_MUTANTS = {
    "an object under a credential key walked by the ordinary rules": (
        "            if isinstance(inner, str) and inner.isascii() and inner.lower() in CREDENTIAL_DESCRIPTORS.split():\n",
        "            if True:\n",
        r'{{- if and (regexMatch "^[\\x00-\\x7f]*$" $inner) (has (lower $inner) $descriptors) -}}',
        '{{- if true -}}',
        ["Keycloak credentials list with a literal value", "Okta change-password oldPassword.value literal",
         "Okta create-user credentials.password.value literal",
         "Unicode: descriptor spelled with U+0130 under a password holds a literal",
         "a literal two objects beneath a credential-named key", "a password holding an object with a literal value",
         "login JSON password holding a list with an object with a literal"]),
    "no labelled pairs": (
        "        if label is not None and key == \"value\":\n",
        "        if False:\n",
        '{{- if and $label (eq $key "value") -}}',
        '{{- if false -}}',
        ["Keycloak reset-password body with a literal value", "a field/value pair naming a token",
         "a key/value pair naming an api_key", "a name/value pair list naming a password"]),
    "every key under a capture map exempt": (
        "            and not (capture_names and _is_extractor(item))\n",
        "            and not capture_names\n",
        '(not (and $captureNames (eq (include "veridor-gate.isExtractor" $item) "true")))',
        '(not $captureNames)',
        ["a capture map in a request body with a literal password"]),
}

#: The corpus cases of these rules, flipped or not: the chart half renders
#: these under each mutant (every case would be one render per case).
NESTED_CASES = (
    "Okta create-user credentials.password.value literal", "Okta change-password oldPassword.value literal",
    "Keycloak credentials list with a literal value", "Keycloak credentials list with a referenced value",
    "Keycloak reset-password body with a literal value", "a password holding an object with a literal value",
    "a literal two objects beneath a credential-named key", "a credential-named key holding only descriptors",
    "a credential-named key holding only a descriptor (user)",
    "login JSON password holding a list with an object with a literal",
    "a name/value pair list naming a password", "a key/value pair naming an api_key",
    "a field/value pair naming a token", "a name/value pair naming a password with a reference",
    "a name/value pair that names no credential", "a capture map in a request body with a literal password",
    "a login step's capture named token", "a sequence capture named token",
    "Unicode: descriptor spelled with U+0130 under a password holds a literal",
    "Unicode: descriptor id under a password holds a literal (ASCII control)",
)


def _chart_literal(name: str) -> str:
    """The Go string literal assigned to ``$<name>`` in _helpers.tpl, decoded."""
    found = re.findall(r"\$" + name + r' := ("(?:[^"\\]|\\.)*")', HELPERS.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise AssertionError(f"${name} is assigned a string literal {len(found)} times in {HELPERS}")
    return json.loads(found[0])


class SharedPatternTest(unittest.TestCase):
    """The regexes both sides use, pinned equal (credKey, headerOk and the
    allowLiteralHeaders word are pinned by tests/test_capsule.py)."""

    def test_the_patterns_are_the_same_strings(self) -> None:
        self.assertEqual(_chart_literal("anyReference"), capsule._ANY_REFERENCE.pattern)
        self.assertEqual(_chart_literal("pairPattern"), capsule._PAIR.pattern)
        self.assertEqual(_chart_literal("userinfoPattern"), capsule._USERINFO.pattern)
        self.assertEqual(_chart_literal("credentialDescriptors"), capsule.CREDENTIAL_DESCRIPTORS)
        self.assertEqual(_chart_literal("pairLabels"), capsule.PAIR_LABELS)
        self.assertEqual(_chart_literal("captureExtractor"), capsule.CAPTURE_EXTRACTOR.pattern)
        self.assertEqual(_chart_literal("pairOnlyKey"), capsule.PAIR_CREDENTIAL.pattern)

    #: Escapes whose meaning differs between Go's RE2 and Python's ``re`` on
    #: str patterns: RE2 reads them as ASCII classes, Python as Unicode ones.
    ENGINE_DEPENDENT = ("\\s", "\\S", "\\d", "\\D", "\\w", "\\W", "\\b", "\\B")
    SHARED = ("_ANY_REFERENCE", "_PAIR", "_USERINFO", "CAPTURE_EXTRACTOR", "PAIR_CREDENTIAL",
              "REFERENCE_ONLY_HEADER", "CREDENTIAL_FIELD", "CREDENTIAL_HEADER_WORD")

    def engine_dependent(self, pattern: str) -> list[str]:
        return [escape for escape in self.ENGINE_DEPENDENT if escape in pattern]

    def test_no_shared_pattern_uses_a_class_the_two_engines_read_differently(self) -> None:
        """REGRESSION: the pair, userinfo and header patterns were the same
        TEXT on both sides and still disagreed, because ``\\s`` is ASCII in
        RE2 and Unicode in Python: ``a=1&<U+00A0>key=L`` was refused by the
        capsule and rendered by the chart (measured with helm template).
        Pinned text is only pinned meaning without these escapes."""
        for name in self.SHARED:
            with self.subTest(pattern=name):
                self.assertEqual(self.engine_dependent(getattr(capsule, name).pattern), [])
        # Control: the pair pattern as it was is caught.
        self.assertEqual(self.engine_dependent(r"(?:^|[?&;])\s*([^=&;?#\s]+)=([^&;#\s]*)"), ["\\s"])

    def test_the_trim_is_go_s_strings_trim_space(self) -> None:
        """``capsule._TRIM_SPACE`` is what sprig's ``trim`` (Go's
        ``strings.TrimSpace``) strips: Python's ``str.isspace()`` without
        U+001C-U+001F, which Python calls space and Go does not (measured with
        helm over every BMP code point; ChartSideTest measures it again).
        White_Space has no character outside the BMP."""
        python_space = {chr(code) for code in range(0x10000) if chr(code).isspace()}
        self.assertEqual(set(capsule._TRIM_SPACE), python_space - {"\x1c", "\x1d", "\x1e", "\x1f"})
        self.assertEqual(len(capsule._TRIM_SPACE), len(set(capsule._TRIM_SPACE)))
        # Control: what str.strip() removes and trim does not.
        self.assertEqual("\x1c{".strip(), "{")
        self.assertEqual("\x1c{".strip(capsule._TRIM_SPACE), "\x1c{")

    def test_the_fold_is_the_same_four_letters(self) -> None:
        """veridor-gate.fold replaces exactly what capsule._ASCII_FOLD does."""
        found = re.findall(r'replace "\\u([0-9a-f]{4})" "([a-z])"', HELPERS.read_text(encoding="utf-8"))
        chart = {int(code, 16): letter for code, letter in found}
        self.assertEqual(chart, capsule._ASCII_FOLD)
        self.assertEqual(len(chart), 4)

    def test_the_extraction_can_fail(self) -> None:
        with self.assertRaises(AssertionError):
            _chart_literal("noSuchPattern")


class _Helm(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("helm") is None:
            if os.environ.get(REQUIRE_HELM_ENV) == "1":
                self.fail(f"helm is not on PATH and {REQUIRE_HELM_ENV}=1 says these tests must run")
            self.skipTest(f"helm is not on PATH (set {REQUIRE_HELM_ENV}=1 to make this a failure)")
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-parity-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def chart_verdict(self, case: dict[str, Any], chart: Path = CHART) -> tuple[str, str]:
        config = build(case)
        outside_sequences = {k: v for k, v in config.items() if k != "sequences"}
        names = sorted(set(_ENV_REFERENCE.findall(json.dumps(outside_sequences))))
        values = {
            "hook": {"mode": "none"},
            "config": config,
            "secretEnv": [{"name": n, "secretName": "gate-credentials", "key": n} for n in names],
            "allowLiteralHeaders": case.get("chart_allow_literal_headers", []),
        }
        path = self.tmp / "values.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        result = subprocess.run(["helm", "template", "gate", str(chart), "-f", str(path)],
                                capture_output=True, text=True, timeout=60, check=False)
        if result.returncode == 0:
            return "accept", result.stdout
        if "veridor-gate:" in result.stderr and any(m in result.stderr for m in CHART_REFUSALS):
            return "refuse", result.stderr
        raise AssertionError(f"{case['name']}: the render failed for another reason:\n{result.stderr}")


@slow("spawns helm template")
class ChartWhitespaceTest(_Helm):
    def test_helm_s_trim_strips_exactly_the_capsule_s_whitespace(self) -> None:
        """The chart's ``trim`` (sprig, Go's strings.TrimSpace), measured on
        this helm: every BMP character Python calls space, and the C0
        controls, trimmed or not. It must strip exactly ``_TRIM_SPACE``. The
        C0 controls are the control: U+001C-U+001F are space to Python and
        must come back untrimmed, so the probe can report a difference."""
        chart = self.tmp / "trim"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: trim\nversion: 0.1.0\n", encoding="utf-8")
        (chart / "templates" / "t.yaml").write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: t\ndata:\n"
            "  trimmed: {{ range .Values.chars }}{{ len (trim .) }},{{ end }}\n", encoding="utf-8")
        chars = sorted({chr(code) for code in range(0x10000) if chr(code).isspace()} | {chr(code) for code in range(0x20)})
        (chart / "values.json").write_text(json.dumps({"chars": chars}), encoding="utf-8")
        result = subprocess.run(["helm", "template", "t", str(chart), "-f", str(chart / "values.json")],
                                capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        lengths = re.search(r"trimmed: ([0-9,]+)", result.stdout).group(1).rstrip(",").split(",")
        self.assertEqual(len(lengths), len(chars))
        trimmed = {char for char, length in zip(chars, lengths) if length == "0"}
        self.assertEqual(trimmed, set(capsule._TRIM_SPACE))
        self.assertNotIn("\x1c", trimmed)


@slow("spawns helm template once per corpus case")
class ChartSideTest(_Helm):
    def test_every_case_is_decided_as_expected_by_the_chart(self) -> None:
        for case in CORPUS["cases"]:
            with self.subTest(case=case["name"]):
                verdict, output = self.chart_verdict(case)
                self.assertEqual(verdict, chart_expectation(case), output[-600:])
                if verdict == "refuse":
                    self.assertNotIn(CORPUS["literal"], output, "the refusal printed the value")
                    self.assertNotIn(refused_value(case), output, "the refusal printed the value")
                else:
                    # An accepted render carries the configuration verbatim.
                    self.assertIn("veridor.json", output)

    def test_a_chart_refusal_that_printed_its_value_would_be_caught(self) -> None:
        """Mutation control for the value check above: a chart whose
        credential-field refusal prints the value renders each of these cases'
        own value into its error, which the corpus literal alone never showed."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        original = 'is a credential-named field with a literal value (not printed).'
        self.assertEqual(text.count(original), 1, "the mutation no longer applies")
        text = text.replace(original, 'is a credential-named field with a literal value %v.')
        tail = 'map NAME with secretEnv." $path) -}}'
        self.assertEqual(text.count(tail), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(tail, 'map NAME with secretEnv." $path .value) -}}'), encoding="utf-8")
        for name in ECHOED_FIELD_CASES:
            case = next(case for case in CORPUS["cases"] if case["name"] == name)
            with self.subTest(case=name):
                verdict, output = self.chart_verdict(case, broken)
                self.assertEqual(verdict, "refuse")
                self.assertIn(refused_value(case), output)
                self.assertNotIn(CORPUS["literal"], output)

    def test_a_chart_header_or_url_refusal_that_printed_its_value_would_be_caught(self) -> None:
        """Mutation control for the value check on the header, cookie and
        URL-userinfo refusals: a chart that prints what it refused renders abc,
        dark or bob into its error, which the corpus literal alone never showed."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        for original, echoing in (
            # A credential header: print the whole header value.
            ("carries a literal value (not printed). The chart never renders",
             "carries a literal value %v. The chart never renders"),
            ('list it in allowLiteralHeaders." $path $name) -}}',
             'list it in allowLiteralHeaders." $path $text $name) -}}'),
            # One cookie of a Cookie header: print that cookie.
            ("carries a literal value for cookie %q (not printed).",
             "carries a literal value for cookie %q %v."),
            ("$path (ternary (trim $cookie._0) $name $named)) -}}",
             "$path (ternary (trim $cookie._0) $name $named) $part) -}}"),
            # URL userinfo: print the match.
            ("carries user:password@ in a URL (not printed).",
             "carries user:password@ in a URL %v."),
            ('header referencing a Secret (secretEnv)." $path) -}}',
             'header referencing a Secret (secretEnv)." $path $match) -}}'),
        ):
            self.assertEqual(text.count(original), 1, f"the mutation no longer applies: {original}")
            text = text.replace(original, echoing)
        helpers.write_text(text, encoding="utf-8")
        for name in ECHOED_HEADER_CASES + ECHOED_URL_CASES:
            case = next(case for case in CORPUS["cases"] if case["name"] == name)
            with self.subTest(case=name):
                verdict, output = self.chart_verdict(case, broken)
                self.assertEqual(verdict, "refuse")
                self.assertIn(refused_value(case), output)
                self.assertNotIn(CORPUS["literal"], output)

    def test_the_chart_side_can_fail(self) -> None:
        """Mutation control: a chart whose form/query scan never matches
        renders the literal form body again, and the comparison says so."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        literal = '$pairPattern := "' + capsule._PAIR.pattern.replace("\\", "\\\\") + '"'
        self.assertEqual(text.count(literal), 1, "the mutation no longer applies")
        # "x^" can never match: nothing precedes the start of the text.
        helpers.write_text(text.replace(literal, '$pairPattern := "x^"'), encoding="utf-8")
        wrong = []
        for case in CORPUS["cases"]:
            if "form body" in case["name"] or "query string" in case["name"]:
                verdict, _ = self.chart_verdict(case, broken)
                if verdict != chart_expectation(case):
                    wrong.append(case["name"])
        self.assertIn("login form body with a literal password", wrong)
        self.assertIn("query string with a literal api_key", wrong)

    def test_the_chart_s_nameless_cookie_cases_need_its_nameless_branch(self) -> None:
        """Mutation control: a chart that reads a Cookie part with no ``name=``
        as empty renders the bare literal cookie, and the comparison says so.
        The same mutation survived every chart test before these cases."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        branch = "(ternary $cookie._1 $part $named)"
        self.assertEqual(text.count(branch), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(branch, '(ternary $cookie._1 "" $named)'), encoding="utf-8")
        wrong = sorted(case["name"] for case in CORPUS["cases"]
                       if "Cookie" in case["name"] and self.chart_verdict(case, broken)[0] != chart_expectation(case))
        self.assertEqual(wrong, ["Cookie that is one bare literal",
                                 "Cookie with a reference and a nameless literal",
                                 "a check's Cookie that is one bare literal"])

    def test_the_chart_s_nested_labelled_and_capture_cases_need_their_branches(self) -> None:
        """The chart half of CapsuleSideTest's mutation control of the same name."""
        for mutant_name, (_, _, original, replacement, expected) in NESTED_MUTANTS.items():
            with self.subTest(mutant=mutant_name):
                broken = self.tmp / mutant_name.replace(" ", "-") / "veridor-gate"
                shutil.copytree(CHART, broken)
                helpers = broken / "templates" / "_helpers.tpl"
                text = helpers.read_text(encoding="utf-8")
                self.assertEqual(text.count(original), 1, "the mutation no longer applies")
                helpers.write_text(text.replace(original, replacement), encoding="utf-8")
                self.assertLessEqual(set(NESTED_CASES), {case["name"] for case in CORPUS["cases"]})
                wrong = sorted(case["name"] for case in CORPUS["cases"] if case["name"] in NESTED_CASES
                               and self.chart_verdict(case, broken)[0] != chart_expectation(case))
                self.assertEqual(wrong, expected)

    def test_the_chart_s_parameter_only_names_need_their_pattern(self) -> None:
        """Mutation control: a chart whose $pairOnlyKey never matches renders
        the ?key=, ?auth=, ?code=, sig=, session_id= and ;jsessionid= cases."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        literal = '$pairOnlyKey := ' + json.dumps(capsule.PAIR_CREDENTIAL.pattern)
        self.assertEqual(text.count(literal), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(literal, '$pairOnlyKey := "x^"'), encoding="utf-8")
        candidates = CapsuleSideTest.PARAMETER_ONLY + ("query string with a literal jwt", "query string with a referenced key")
        wrong = sorted(name for name in candidates
                       if self.chart_verdict(next(c for c in CORPUS["cases"] if c["name"] == name), broken)[0]
                       != chart_expectation(next(c for c in CORPUS["cases"] if c["name"] == name)))
        self.assertEqual(wrong, sorted(CapsuleSideTest.PARAMETER_ONLY))

    def test_the_chart_s_unicode_cases_need_its_fold(self) -> None:
        """Mutation control: a chart whose fold changes nothing renders the
        look-alike names and escapes again (measured before the fold: every
        one of these rendered), and reads a Cookie spelled with U+0130 as
        before."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        fold = '{{- toString . | replace "\\u0130" "i" | replace "\\u0131" "i" | replace "\\u017f" "s" | replace "\\u212a" "k" -}}'
        self.assertEqual(text.count(fold), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(fold, "{{- toString . -}}"), encoding="utf-8")
        wrong = sorted(case["name"] for case in CORPUS["cases"] if case["name"].startswith("Unicode:")
                       and self.chart_verdict(case, broken)[0] != chart_expectation(case))
        self.assertEqual(wrong, sorted([
            "Unicode: api_key spelled with U+0130", "Unicode: api_key spelled with U+0131",
            "Unicode: credentials spelled with U+0130", "Unicode: camelCase Pass after U+0130",
            "Unicode: api_key spelled with U+0130 in a query string",
            "Unicode: api_key with U+0130 percent-encoded in a query string",
            "Unicode: a headers map spelled with U+017F holding a literal Authorization"]))

    def test_the_chart_s_escaped_unicode_cases_need_its_decoding(self) -> None:
        """Mutation control: without decoding the four letters' UTF-8 escapes
        (each escaped sequence is then one U+FFFD), the escaped U+017F and
        U+212A names render again. RE2's (?i) itself reads those two letters
        as s and k, so only the decoding stands between them and the render."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        lines = [line for line in text.splitlines(keepends=True)
                 if line.startswith('{{- $text = regexReplaceAll "%[') and '"\\u' in line and "ufffd" not in line]
        self.assertEqual(len(lines), 4, "the mutation no longer applies")
        for line in lines:
            text = text.replace(line, "")
        helpers.write_text(text, encoding="utf-8")
        wrong = sorted(case["name"] for case in CORPUS["cases"] if "percent-encoded" in case["name"]
                       and self.chart_verdict(case, broken)[0] != chart_expectation(case))
        self.assertEqual(wrong, ["Unicode: api_key with U+0130 percent-encoded in a query string",
                                 "Unicode: api_key with U+212A percent-encoded in a query string",
                                 "Unicode: password with U+017F percent-encoded in a query string"])

    def test_the_chart_reads_an_escaped_multibyte_character_as_one(self) -> None:
        """Mutation control: with a U+FFFD per byte, as the chart decoded
        before, a three- or four-byte character in contraseña's one-or-two
        slot rendered what the capsule refuses (measured)."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        lines = [line for line in text.splitlines(keepends=True)
                 if line.startswith('{{- $text = regexReplaceAll "%[Ff]') and "ufffd" in line]
        self.assertEqual(len(lines), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(lines[0], ""), encoding="utf-8")
        wrong = sorted(case["name"] for case in CORPUS["cases"] if case["name"].startswith("percent-encoded:")
                       and self.chart_verdict(case, broken)[0] != chart_expectation(case))
        self.assertEqual(wrong, ["percent-encoded: contrase, a four-byte character, a, in a query string",
                                 "percent-encoded: contrase, a three-byte character, a, in a query string"])

    def test_the_chart_s_json_retry_is_what_refuses_nan(self) -> None:
        """Mutation control: without the second parse, the chart renders the
        NaN, Infinity and beyond-float64 cases again."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        retry = "{{- $parsed = fromJsonArray"
        self.assertEqual(text.count(retry), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(retry, "{{- $_ := fromJsonArray"), encoding="utf-8")
        wrong = sorted(case["name"] for case in CORPUS["cases"]
                       if case["name"].startswith("JSON text with")
                       and self.chart_verdict(case, broken)[0] != chart_expectation(case))
        self.assertEqual(wrong, ["JSON text with -Infinity and a literal password",
                                 "JSON text with 301 digits glued to an exponent and a literal password",
                                 "JSON text with Infinity and a literal password",
                                 "JSON text with NaN and a literal password",
                                 "JSON text with a 251-digit mantissa and e60 and a literal password",
                                 "JSON text with a number beyond float64 and a literal password",
                                 "JSON text with a number beyond float64 and a password that only looks like a reference",
                                 "JSON text with numbers inside strings, a number beyond float64 and a literal password",
                                 "JSON text with numeric keys, a number beyond float64 and a literal password"])

    def test_the_chart_s_json_retry_keeps_strings_as_they_are(self) -> None:
        """Mutation control: a retry that rewrites numbers across the whole
        text, strings included, merges the keys "1" and "2" (the literal
        disappears from the parse) and turns "${A-1}" into a reference, so
        the chart renders both literals again."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        retry = '{{- $parsed = fromJsonArray (printf "[%s]" $normalised) -}}'
        self.assertEqual(text.count(retry), 1, "the mutation no longer applies")
        whole = ('{{- $parsed = fromJsonArray (printf "[%s]" (regexReplaceAll '
                 '"-?Infinity|NaN|-?(?:0|[1-9][0-9]*)(?:\\\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?" $stripped "0")) -}}')
        helpers.write_text(text.replace(retry, whole), encoding="utf-8")
        wrong = sorted(case["name"] for case in CORPUS["cases"]
                       if case["name"].startswith("JSON text with")
                       and self.chart_verdict(case, broken)[0] != chart_expectation(case))
        self.assertEqual(wrong, ["JSON text with a number beyond float64 and a password that only looks like a reference",
                                 "JSON text with numeric keys, a number beyond float64 and a literal password"])


if __name__ == "__main__":
    unittest.main()
