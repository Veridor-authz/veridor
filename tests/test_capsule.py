"""The capsule is the one artifact deliberately handed to a stranger.

Everything else Veridor writes stays on the operator's disk or goes into their
own CI. A capsule is attached to a disclosure and read by someone the reporter
has never met, which makes one property non-negotiable: **it must never carry a
credential.** A published bearer token cannot be recalled, and the reporter will
not find out until it is far too late.

So the refusal tests here are not schema tests. They are the feature.
"""

from __future__ import annotations

import contextlib
import copy
import email.message
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import unittest
import urllib.response
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import capsule, core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402


def _config(auth: str = "Bearer ${VERIDOR_OWNER_TOKEN}") -> dict:
    return {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:8765"},
        "identities": {
            "owner": {
                "headers": {"Authorization": auth},
                "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
            },
            "attacker": {"headers": {"Authorization": "Bearer ${VERIDOR_ATTACKER_TOKEN}"}},
            "unrelated": {"headers": {"Authorization": "Bearer ${VERIDOR_UNUSED_TOKEN}"}},
        },
        "checks": [
            {
                "id": "tenant-isolation",
                "name": "Tenant isolation",
                "request": {"method": "GET", "path": "/invoices/1"},
                "expect": {
                    "owner": {"status": [200], "contains_marker": "owner"},
                    "attacker": {"status": [404], "excludes_marker": "owner"},
                },
            }
        ],
    }


class CredentialRefusalTest(unittest.TestCase):
    """The property the whole artifact exists to protect."""

    def test_a_literal_authorization_header_is_refused(self) -> None:
        with self.assertRaises(capsule.CapsuleError) as caught:
            capsule.build(_config("Bearer sk-live-realtoken-9f3a2b1c"), "tenant-isolation")
        message = str(caught.exception)
        self.assertIn("literal Authorization", message)
        # The refusal must say what to do instead and confirm nothing leaked.
        self.assertIn("${VERIDOR_OWNER_TOKEN}", message)
        self.assertIn("Nothing has been written", message)

    def test_a_literal_cookie_is_refused_with_a_usable_hint(self) -> None:
        """"Bearer" in a Cookie is nonsense; a fix-it hint that does not work
        is worse than none."""
        config = _config()
        config["identities"]["owner"]["headers"] = {"Cookie": "sid=REAL-SESSION-abc123"}
        with self.assertRaises(capsule.CapsuleError) as caught:
            capsule.build(config, "tenant-isolation")
        message = str(caught.exception)
        self.assertIn("literal Cookie", message)
        self.assertNotIn("Bearer", message)

    def test_every_credential_header_is_covered(self) -> None:
        for header in ("Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "Token"):
            with self.subTest(header=header):
                config = _config()
                config["identities"]["owner"]["headers"] = {header: "literal-secret-value"}
                with self.assertRaises(capsule.CapsuleError):
                    capsule.build(config, "tenant-isolation")

    def test_a_non_credential_header_may_stay_literal(self) -> None:
        """Refusing every literal would make the artifact unusable."""
        config = _config()
        config["identities"]["owner"]["headers"]["X-Tenant"] = "acme"
        built = capsule.build(config, "tenant-isolation")
        self.assertEqual(built["identities"]["owner"]["headers"]["X-Tenant"], "acme")

    def test_the_emitted_capsule_contains_no_literal_secret(self) -> None:
        """Belt and braces: scan the serialised artifact, not the inputs."""
        built = capsule.build(_config(), "tenant-isolation")
        blob = json.dumps(built)
        for pattern in (r"sk-[A-Za-z0-9-]{10,}", r"Bearer [A-Za-z0-9]{12,}"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, blob))
        self.assertEqual(
            built["requires_environment"],
            ["VERIDOR_ATTACKER_TOKEN", "VERIDOR_OWNER_TOKEN"],
        )


LITERAL = "hunter2-LITERAL"


def _with_login(step: dict) -> dict:
    """The owner logs in through a session instead of a static header."""
    config = _config()
    login = {"method": "POST", "path": "/login", "expect_status": [200]}
    login.update(step)
    config["identities"]["owner"] = {
        "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
        "session": {"login": [login], "establishes": {"cookie": "sid"}},
    }
    return config


def _refusal(config: dict, **kwargs) -> str:
    """Build, expect a refusal, and return its text."""
    with contextlib.suppress(capsule.CapsuleError):
        built = capsule.build(config, "tenant-isolation", **kwargs)
        raise AssertionError(
            "the capsule was written; literal present in it: "
            f"{LITERAL in json.dumps(built)}"
        )
    try:
        capsule.build(config, "tenant-isolation", **kwargs)
    except capsule.CapsuleError as error:
        return str(error)
    raise AssertionError("unreachable")


class LiteralValueRefusalTest(unittest.TestCase):
    """A capsule must not publish a literal credential ANYWHERE in it.

    REGRESSION. The writer refused a literal credential header on an identity
    and nothing else, so `veridor capsule` copied session login steps verbatim:
    a config whose login body said ``"password": "hunter2-LITERAL"`` produced a
    capsule carrying that password (reproduced for a JSON body and for a
    form-encoded body, exit 0, capsule written), while the same value as an
    ``Authorization`` header was refused. Check headers, marker-probe headers,
    login headers, session inject values, query strings and ``user:pass@`` URLs
    were all copied the same way.
    """

    def _assert_refused(self, config: dict, path: str, **kwargs) -> str:
        message = _refusal(config, **kwargs)
        self.assertIn(path, message)
        self.assertNotIn(LITERAL, message)
        self.assertIn("${VERIDOR_", message)
        self.assertIn("Nothing has been written", message)
        return message

    def test_a_literal_password_in_a_json_login_body_is_refused(self) -> None:
        self._assert_refused(
            _with_login({"json": {"username": "alice", "password": LITERAL}}),
            "identities.owner.session.login[0].json.password",
        )

    def test_a_literal_password_in_a_form_login_body_is_refused(self) -> None:
        message = self._assert_refused(
            _with_login({"body": f"username=alice&password={LITERAL}"}),
            "identities.owner.session.login[0].body",
        )
        self.assertIn("password", message)

    def test_a_literal_password_in_a_json_text_body_is_refused(self) -> None:
        self._assert_refused(
            _with_login({"body": json.dumps({"user": {"password": LITERAL}})}),
            "identities.owner.session.login[0].body",
        )

    def test_a_bracketed_form_field_is_still_a_credential_field(self) -> None:
        self._assert_refused(
            _with_login({"body": f"user%5Bname%5D=alice&user[password]={LITERAL}"}),
            "identities.owner.session.login[0].body",
        )

    def test_control_a_referenced_password_is_written(self) -> None:
        """The control: the rule refuses literals, not login bodies."""
        for step in (
            {"json": {"username": "alice", "password": "${VERIDOR_OWNER_PASSWORD}"}},
            {"body": "username=alice&password=${VERIDOR_OWNER_PASSWORD}"},
            {"body": "username=alice&password=%24%7BVERIDOR_OWNER_PASSWORD%7D"},
            {"body": json.dumps({"password": "${VERIDOR_OWNER_PASSWORD}"})},
        ):
            with self.subTest(step=step):
                built = capsule.build(_with_login(step), "tenant-isolation")
                self.assertIn("VERIDOR_OWNER_PASSWORD", json.dumps(built))

    def test_control_a_foreign_reference_is_renamed_then_written(self) -> None:
        built = capsule.build(
            _with_login({"json": {"password": "${OWNER_PASSWORD}"}}), "tenant-isolation"
        )
        login = built["identities"]["owner"]["session"]["login"][0]
        self.assertEqual(login["json"]["password"], "${VERIDOR_OWNER_PASSWORD}")

    def test_credential_headers_are_refused_wherever_they_appear(self) -> None:
        def at(mutate):
            config = _config()
            mutate(config)
            return config

        places = {
            "check.request.headers.Authorization": lambda c: c["checks"][0]["request"].update(
                {"headers": {"Authorization": f"Bearer {LITERAL}"}}
            ),
            "check.request.headers.X-Api-Key": lambda c: c["checks"][0]["request"].update(
                {"headers": {"X-Api-Key": LITERAL}}
            ),
            "identities.owner.marker_probe.headers.Cookie": lambda c: c["identities"][
                "owner"
            ].update({"marker_probe": {"path": "/x", "headers": {"Cookie": f"sid={LITERAL}"}}}),
            "identities.owner.headers.X-Session-Id": lambda c: c["identities"]["owner"][
                "headers"
            ].update({"X-Session-Id": LITERAL}),
            "identities.owner.headers.Authorization": lambda c: c["identities"]["owner"][
                "headers"
            ].update({"Authorization": "Bearer ${VERIDOR_OWNER_TOKEN} " + LITERAL}),
        }
        for path, mutate in places.items():
            with self.subTest(path=path):
                self._assert_refused(at(mutate), path)

    def test_login_headers_and_inject_values_are_refused(self) -> None:
        self._assert_refused(
            _with_login({"headers": {"Authorization": f"Basic {LITERAL}"}}),
            "identities.owner.session.login[0].headers.Authorization",
        )
        config = _with_login({})
        config["identities"]["owner"]["session"]["inject"] = [
            {"header": "X-CSRF-Token", "value": LITERAL}
        ]
        self._assert_refused(config, "identities.owner.session.inject[0]")

    def test_control_references_and_captures_in_headers_are_written(self) -> None:
        config = _with_login({"headers": {"Authorization": "Basic ${VERIDOR_OWNER_BASIC}"}})
        config["identities"]["owner"]["session"]["inject"] = [
            {"header": "X-CSRF-Token", "value": "${capture.csrf}"}
        ]
        config["identities"]["owner"]["session"]["login"][0]["capture"] = {
            "csrf": {"from": "cookie", "name": "XSRF-TOKEN"}
        }
        config["checks"][0]["request"]["headers"] = {
            "Cookie": "sid=${VERIDOR_SID}; theme=${VERIDOR_THEME}",
            "X-Tenant": "acme",
        }
        built = capsule.build(config, "tenant-isolation")
        self.assertEqual(built["check"]["request"]["headers"]["X-Tenant"], "acme")

    def test_control_a_realistic_csrf_session_is_written(self) -> None:
        """False-positive control, in the session shapes tests/test_session.py
        drives live: a capture NAMED token is an extractor, not a secret."""
        config = _config()
        config["identities"]["owner"] = {
            "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
            "session": {
                "login": [
                    {"method": "GET", "path": "/login", "expect_status": [200],
                     "capture": {"csrf": {"from": "html_meta", "name": "csrf-token"}}},
                    {"method": "POST", "path": "/login", "expect_status": [200],
                     "headers": {"X-CSRFToken": "${capture.csrf}"},
                     "body": "username=alice&password=${VERIDOR_OWNER_PASSWORD}"
                             "&csrfmiddlewaretoken=${capture.csrf}",
                     "capture": {"token": {"from": "json_pointer", "pointer": "/data/token"}}},
                ],
                "establishes": {"capture": "token"},
                "inject": [{"header": "X-CSRFToken", "value": "${capture.token}"}],
            },
        }
        built = capsule.build(config, "tenant-isolation")
        self.assertEqual(built["requires_environment"],
                         ["VERIDOR_ATTACKER_TOKEN", "VERIDOR_OWNER_PASSWORD"])

    def test_one_literal_cookie_among_references_is_refused(self) -> None:
        config = _config()
        config["checks"][0]["request"]["headers"] = {
            "Cookie": f"sid=${{VERIDOR_SID}}; remember={LITERAL}"
        }
        message = self._assert_refused(config, "check.request.headers.Cookie")
        self.assertIn("remember", message)

    def test_credential_query_parameters_are_refused(self) -> None:
        for parameter in ("api_key", "access_token", "token", "client_secret"):
            with self.subTest(parameter=parameter):
                config = _config()
                config["checks"][0]["request"]["path"] = (
                    f"/invoices/1?page=2&{parameter}={LITERAL}"
                )
                message = self._assert_refused(config, "check.request.path")
                self.assertIn(parameter, message)

    def test_control_ordinary_and_referenced_query_parameters_are_written(self) -> None:
        config = _config()
        config["checks"][0]["request"]["path"] = (
            "/invoices/1?page=2&sort=asc&api_key=${VERIDOR_API_KEY}"
        )
        built = capsule.build(config, "tenant-isolation")
        self.assertEqual(
            built["check"]["request"]["path"],
            "/invoices/1?page=2&sort=asc&api_key=${VERIDOR_API_KEY}",
        )

    def test_user_and_password_in_a_url_are_refused(self) -> None:
        config = _config()
        config["target"]["base_url"] = f"http://alice:{LITERAL}@127.0.0.1:8765"
        self._assert_refused(config, "target.base_url")
        config = _config()
        config["checks"][0]["request"]["json"] = {
            "callback": f"https://{LITERAL}@hooks.example/notify"
        }
        self._assert_refused(config, "check.request.json.callback")

    def test_the_final_pass_covers_what_no_rule_names(self) -> None:
        """Defence in depth: the finished document is scanned, not only the
        places the writer knows credentials live. A reporter's run document is
        copied into the claim, so a credential there is published too."""
        run = {
            "run_id": "r1",
            "findings": [{
                "check_id": "tenant-isolation",
                "message": f"see https://alice:{LITERAL}@internal.example/debug",
            }],
        }
        self._assert_refused(_config(), "claim.statement", run_document=run)
        config = _config()
        config["target"]["notes"] = {"deploy": {"password": LITERAL}}
        self._assert_refused(config, "target.notes.deploy.password")

    def test_every_offender_is_named_and_no_value_is_printed(self) -> None:
        config = _with_login({"json": {"password": LITERAL}})
        config["checks"][0]["request"]["path"] = f"/x?token={LITERAL}2"
        message = _refusal(config)
        self.assertIn("identities.owner.session.login[0].json.password", message)
        self.assertIn("check.request.path", message)
        self.assertNotIn(LITERAL, message)

    def test_the_scan_names_paths_in_any_document(self) -> None:
        found = capsule.literal_credentials(
            {"a": [{"headers": {"Authorization": f"Bearer {LITERAL}"}}],
             "b": {"secret": 12345}, "c": {"secret": ""}, "d": {"token": None},
             "e": {"capture": {"token": "header:X-Token"}}}
        )
        self.assertEqual([path for path, _ in found], ["a[0].headers.Authorization", "b.secret"])
        self.assertNotIn(LITERAL, json.dumps(found))

    def test_the_heuristic_is_the_helm_chart_s(self) -> None:
        """One rule for "this names a credential", in two languages.

        deploy/helm/veridor-gate/templates/_helpers.tpl refuses literal
        credentials with the same two patterns: credential-named keys, and
        credential-named header names. If one side changes alone, a value one
        refuses the other would publish.
        """
        helpers = (ROOT / "deploy" / "helm" / "veridor-gate" / "templates" / "_helpers.tpl").read_text(
            encoding="utf-8"
        )
        cred_key = re.findall(r'\$credKey := ("(?:[^"\\]|\\.)*")', helpers)
        header_word = re.findall(
            r'range \.Values\.allowLiteralHeaders -}}\s*{{- if regexMatch ("(?:[^"\\]|\\.)*")', helpers
        )
        header_ok = re.findall(r'\$headerOk := ("(?:[^"\\]|\\.)*")', helpers)
        # The extraction is the control: each pattern found exactly once, so a
        # renamed variable fails here instead of comparing nothing.
        self.assertEqual((len(cred_key), len(header_word), len(header_ok)), (1, 1, 1))
        self.assertEqual(json.loads(cred_key[0]), capsule.CREDENTIAL_FIELD.pattern)
        self.assertEqual(json.loads(header_word[0]), capsule.CREDENTIAL_HEADER_WORD.pattern)
        self.assertEqual(json.loads(header_ok[0]), capsule.REFERENCE_ONLY_HEADER.pattern)

    def test_a_nameless_literal_cookie_is_refused(self) -> None:
        """REGRESSION pin for the Cookie branch that reads a part with no
        ``name=`` as a value. Replacing it with ``continue`` survived every
        test (measured), and `veridor capsule` then wrote the literal session
        cookie. On a check request, not an identity: an identity's bare
        Cookie is refused earlier by the identity-header check, which would
        mask the branch."""
        for cookie in (LITERAL, "sid=${VERIDOR_SID}; " + LITERAL):
            with self.subTest(cookie=cookie):
                config = _config()
                config["checks"][0]["request"]["headers"] = {"Cookie": cookie}
                message = self._assert_refused(config, "check.request.headers.Cookie")
                self.assertIn("'Cookie'", message)
        config = _config()
        config["checks"][0]["request"]["headers"] = {"Cookie": "${VERIDOR_SESSION_COOKIE}"}
        capsule.build(config, "tenant-isolation")  # the control: a whole reference is written


class CredentialNameTest(unittest.TestCase):
    """Which keys hold a credential. REGRESSION: the pattern required a
    separator before every word, so ``accessToken``, ``refreshToken``,
    ``userPassword``, ``secret_key``, ``aws_secret_access_key`` and ``pass``
    matched nothing, and ``capsule.build`` wrote a capsule carrying a literal
    ``refreshToken`` while ``refresh_token`` was refused (measured)."""

    CREDENTIALS = (
        "password", "PASSWORD", "user_password", "userPassword", "newPassword", "passwd",
        "passphrase", "pwd", "db-pwd", "dbPwd", "pass", "PASS", "user_pass", "userPass",
        "secret", "client_secret", "clientSecret", "token", "access_token", "ACCESS_TOKEN",
        "access-token", "accessToken", "refreshToken", "apiToken", "loginToken", "csrf.token",
        "api_key", "apiKey", "apikey", "x-api-key", "private_key", "privateKey", "secret_key",
        "secretKey", "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "access_key", "accessKey",
        "credential", "credentials", "userCredentials",
        # Confirmation and numbered forms (Django, Rails), jwt, the lower-case
        # compounds, and the non-English words: each was published (measured).
        "password1", "password2", "new_password1", "new_password2", "password_confirmation",
        "passwordConfirmation", "password_confirm", "password-again", "password_repeat", "jwt", "id_jwt",
        "userpass", "userpwd", "dbpass", "adminpwd", "passwort", "Kennwort", "contrasena", "contraseña",
        "CONTRASEÑA", "contrase\ufffd\ufffda", "mot_de_passe", "motdepasse", "senha", "user_senha",
    )
    NOT_CREDENTIALS = (
        "passage", "bypass", "compass", "surpass", "tokenizer", "tokens", "max_tokens", "keyboard",
        "author", "authorization", "username", "secretary", "passport", "passwords", "key",
        "access_key_id", "session", "cookie", "monkey", "resenha", "password_hint", "passwordless",
        "code", "sid", "sessionid", "superuserpass", "jwts",
    )
    #: Credentials only as a name=value parameter in a string (PAIR_CREDENTIAL).
    PAIR_ONLY = ("key", "KEY", "auth", "sig", "signature", "code", "sessionid", "session_id", "jsessionid",
                 "JSESSIONID", "sid")
    NOT_PAIR = ("keys", "keyword", "codec", "author", "sigma", "sids", "session", "api", "authority")

    def test_the_names_that_are_credentials(self) -> None:
        for name in self.CREDENTIALS:
            with self.subTest(name=name):
                self.assertTrue(capsule.CREDENTIAL_FIELD.fullmatch(name))

    #: One-time codes, PINs and client assertions. REGRESSION: none matched,
    #: so a literal under any of them in a login body was published while the
    #: same value under ``password`` was refused (measured).
    SECOND_FACTORS = (
        "passcode", "pass_code", "userPasscode", "pin", "PIN", "card_pin", "userPin", "pinCode",
        "pin_code", "otp", "user.otp", "smsOtp", "otp_code", "totp", "totp_code", "userTotp",
        "hotp", "mfa_code", "mfaCode", "verification_code", "verificationCode", "client_assertion",
        "clientAssertion",
    )
    NOT_SECOND_FACTORS = (
        "pinned", "spin", "shipping", "opinion", "otp_enabled", "mfa", "mfa_enabled", "laptop",
        "client_assertion_type", "assertion", "zipcode", "postcode", "country_code",
    )

    def test_one_time_codes_pins_and_assertions_are_credentials(self) -> None:
        for name in self.SECOND_FACTORS:
            with self.subTest(name=name):
                self.assertTrue(capsule.CREDENTIAL_FIELD.fullmatch(name))
        for name in self.NOT_SECOND_FACTORS:
            with self.subTest(control=name):
                self.assertIsNone(capsule.CREDENTIAL_FIELD.fullmatch(name))
        for key in ("passcode", "pin", "pinCode", "otp", "totp", "mfa_code",
                    "verification_code", "client_assertion"):
            with self.subTest(json=key):
                message = _refusal(_with_login({"json": {"username": "alice", key: LITERAL}}))
                self.assertIn(f"login[0].json.{key}", message)
                self.assertNotIn(LITERAL, message)
            with self.subTest(form=key):
                message = _refusal(_with_login({"body": f"username=alice&{key}={LITERAL}"}))
                self.assertIn("login[0].body", message)
        # "a numeric PIN is still a PIN" (_is_literal), now under a key named pin.
        self.assertIn("login[0].json.pin", _refusal(_with_login({"json": {"pin": 4821}})))

    def test_the_names_that_are_not(self) -> None:
        """The control: a pattern that matched everything would pass the test above."""
        for name in self.NOT_CREDENTIALS:
            with self.subTest(name=name):
                self.assertIsNone(capsule.CREDENTIAL_FIELD.fullmatch(name))

    def test_the_parameter_only_names(self) -> None:
        for name in self.PAIR_ONLY:
            with self.subTest(name=name):
                self.assertTrue(capsule.PAIR_CREDENTIAL.fullmatch(name))
        for name in self.NOT_PAIR:
            with self.subTest(name=name):
                self.assertIsNone(capsule.PAIR_CREDENTIAL.fullmatch(name))
        found = capsule.literal_credentials({"path": f"/x?key={LITERAL}&code=${{VERIDOR_C}}", "json": {"key": "q1.pdf"},
                                             "body": f"a[key]={LITERAL}"})
        # A parameter, not a JSON key, and the whole name, not a [segment].
        self.assertEqual([path for path, _ in found], ["path"])

    def test_a_camel_case_credential_in_a_check_is_not_published(self) -> None:
        for key in ("refreshToken", "userPassword", "aws_secret_access_key"):
            with self.subTest(key=key):
                config = _config()
                config["checks"][0]["request"]["json"] = {"grant": "refresh", key: LITERAL}
                message = _refusal(config)
                self.assertIn(f"check.request.json.{key}", message)
                self.assertNotIn(LITERAL, message)

    def test_everything_beneath_a_credential_key_is_read(self) -> None:
        """Lists and objects under a credential-named key, at any depth.
        REGRESSION: an object there was walked by the ordinary rules, so
        ``{"password": {"value": LITERAL}}`` (Okta's
        ``credentials.password.value``) and the Keycloak credential
        ``{"type": "password", "value": LITERAL}`` were published (measured).
        ``{"note": "blue"}`` under ``secret`` used to be accepted here; it
        cannot be told apart from ``{"value": ...}`` by name, and the rule
        refuses on names, so it is refused now. Only a key that describes
        the credential (``type``, ``username``, ...) is read as ordinary."""
        found = capsule.literal_credentials({"json": {"password": [LITERAL], "token": [["${VERIDOR_T}", 42]],
                                                      "secret": ["${VERIDOR_S}", {"note": "blue"}],
                                                      "credentials": [{"type": "password", "value": LITERAL,
                                                                       "temporary": False, "username": "alice"}]}})
        self.assertEqual([path for path, _ in found], ["json.password[0]", "json.token[0][1]", "json.secret[1].note",
                                                       "json.credentials[0].value"])
        self.assertNotIn(LITERAL, json.dumps(found))

    def test_a_labelled_value_is_read_as_the_credential_its_label_names(self) -> None:
        found = capsule.literal_credentials(
            {"fields": [{"name": "password", "value": LITERAL}, {"name": "theme", "value": "dark"}],
             "pair": {"key": "api_key", "value": {"v": LITERAL}}, "reset": {"type": "password", "value": LITERAL},
             "ok": {"type": "password", "value": "${VERIDOR_P}"}})
        self.assertEqual([path for path, _ in found], ["fields[0].value", "pair.value.v", "reset.value"])

    def test_a_capture_map_exempts_extractors_only(self) -> None:
        """REGRESSION: every key directly under any ``capture`` map skipped
        the credential-name check, so ``{"capture": {"password": LITERAL}}``
        in a request body was published (measured)."""
        found = capsule.literal_credentials(
            {"json": {"capture": {"password": LITERAL}},
             "step": {"capture": {"token": "$.data.token", "csrf": "header:X-CSRF-Token"}},
             "login": {"capture": {"token": {"from": "json_pointer", "pointer": "/token"},
                                   "secret": {"from": "nowhere", "pointer": LITERAL}}}})
        # Not an extractor (no capture source), so `secret` holds a credential.
        self.assertEqual([path for path, _ in found],
                         ["json.capture.password", "login.capture.secret.from", "login.capture.secret.pointer"])

    def test_the_capture_extractor_is_the_schema_s(self) -> None:
        schema = json.loads((ROOT / "schema" / "veridor-config-v1.schema.json").read_text(encoding="utf-8"))
        pattern = schema["$defs"]["sequence_step"]["properties"]["capture"]["additionalProperties"]["pattern"]
        self.assertEqual(capsule.CAPTURE_EXTRACTOR.pattern, pattern)

    def test_a_capitalised_headers_key_is_read_as_headers(self) -> None:
        """Veridor's loader accepts ``request.Headers`` and ignores it, so it is
        not sent; a capsule still must not publish what it carries."""
        found = capsule.literal_credentials(
            {"request": {"Headers": {"Authorization": f"Bearer {LITERAL}"}},
             "other": {"HEADERS": {"Authorization": "Bearer ${VERIDOR_OWNER_TOKEN}"}}})
        self.assertEqual([path for path, _ in found], ["request.Headers.Authorization"])


@slow("runs the capsule command in a subprocess")
class LiteralValueCliTest(unittest.TestCase):
    """The refusal as the reporter meets it: exit 2, nothing written, nothing echoed."""

    def _capsule(self, config: dict, *extra: str) -> tuple[subprocess.CompletedProcess, Path]:
        directory = Path(tempfile.mkdtemp(prefix="veridor-capsule-"))
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        (directory / "veridor.json").write_text(json.dumps(config), encoding="utf-8")
        env = source_path.child_env()
        completed = subprocess.run(
            [sys.executable, "-m", "veridor", "capsule", "--config", str(directory / "veridor.json"),
             "--check", "tenant-isolation", *extra],
            capture_output=True, text=True, env=env, cwd=directory, timeout=60,
        )
        return completed, directory

    def test_a_literal_login_password_exits_2_and_writes_nothing(self) -> None:
        for body in ({"json": {"password": LITERAL}}, {"body": f"password={LITERAL}"}):
            with self.subTest(body=body):
                completed, directory = self._capsule(
                    _with_login(body), "--output", "proof.json"
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertFalse((directory / "proof.json").exists())
                self.assertNotIn(LITERAL, completed.stdout + completed.stderr)
                self.assertIn("session.login[0]", completed.stderr)

    def test_stdout_mode_prints_no_capsule(self) -> None:
        completed, _ = self._capsule(_with_login({"json": {"password": LITERAL}}))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertNotIn(LITERAL, completed.stderr)

    def test_control_a_referenced_password_exits_0(self) -> None:
        completed, directory = self._capsule(
            _with_login({"json": {"password": "${VERIDOR_OWNER_PASSWORD}"}}),
            "--output", "proof.json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        written = (directory / "proof.json").read_text(encoding="utf-8")
        self.assertIn("${VERIDOR_OWNER_PASSWORD}", written)
        self.assertIn("VERIDOR_OWNER_PASSWORD", json.loads(written)["requires_environment"])


class ScopeTest(unittest.TestCase):
    def test_only_the_identities_this_check_names_are_carried(self) -> None:
        """A proof of one finding is not a copy of the reporter's environment."""
        built = capsule.build(_config(), "tenant-isolation")
        self.assertEqual(sorted(built["identities"]), ["attacker", "owner"])
        self.assertNotIn("unrelated", built["identities"])

    def test_the_marker_owner_is_carried_even_when_not_expected(self) -> None:
        """`excludes_marker: owner` is meaningless without owner's marker."""
        config = _config()
        config["checks"][0]["expect"].pop("owner")
        built = capsule.build(config, "tenant-isolation")
        self.assertIn("owner", built["identities"])

    def test_an_unknown_check_names_the_ones_that_exist(self) -> None:
        with self.assertRaises(capsule.CapsuleError) as caught:
            capsule.build(_config(), "no-such-check")
        self.assertIn("tenant-isolation", str(caught.exception))

    def test_the_declaration_scope_travels_with_the_claim(self) -> None:
        """A reader who reads only the capsule still learns what it does not say."""
        from veridor.core import DECLARATION_SCOPE  # noqa: PLC0415

        self.assertEqual(capsule.build(_config(), "tenant-isolation")["scope"],
                         DECLARATION_SCOPE)


#: How each identity of _config()'s check can come out of a run, as the probe
#: the run records and the finding it grades from it (None: the probe matched
#: its declaration and produced no finding). Owner is declared [200] with
#: contains_marker owner; attacker [404] with excludes_marker owner.
_OUTCOMES = {
    "owner": {
        "expected": (200, "present", None),
        # A refusal from the target itself (a 407 is the proxy's, not a finding).
        "unexpected_denial": (403, "absent", "unexpected_denial"),
        "inconclusive": (None, "unknown", "inconclusive"),
        "marker_not_observed": (200, "absent", None),
    },
    "attacker": {
        "vulnerable": (200, "present", "vulnerable"),
        "expected": (404, "absent", None),
        "unexpected_denial": (401, "absent", "unexpected_denial"),
        "inconclusive": (None, "unknown", "inconclusive"),
        "marker_not_observed": (404, "unknown", None),
    },
}
_DECLARED = {"owner": [200], "attacker": [404]}


def _run_document(owner: str = "expected", attacker: str = "expected", *,
                  liveness: str = "proven", check_id: str = "tenant-isolation") -> dict:
    """A run of _config()'s check shaped as ``execute_run`` writes one.

    ``liveness`` is "proven" (controls ran and showed nothing), "unproven"
    (the attacker's denial matched a fabricated credential's) or "off"
    (--no-prove-liveness).
    """
    probes, findings = [], []
    for identity, outcome in (("owner", owner), ("attacker", attacker)):
        status, scan, verdict = _OUTCOMES[identity][outcome]
        probes.append({
            "check_id": check_id,
            "identity": identity,
            "request": {"method": "GET", "url": "http://127.0.0.1:8765/invoices/1"},
            "response": {"status": status, "marker_scan": scan, "from_cache": False},
            "error": "connection refused" if status is None else None,
        })
        if verdict is not None:
            findings.append({
                "check_id": check_id,
                "identity": identity,
                "verdict": verdict,
                "evidence_grade": "confirmed" if verdict == "vulnerable" else "n/a",
                "message": f"Identity {identity!r} received HTTP {status}.",
                "evidence": {"expected_statuses": _DECLARED[identity],
                             "actual_status": status},
            })
    unproven = []
    if liveness == "unproven":
        unproven.append({"check_id": check_id, "identity": "attacker", "status": 404,
                         "expected_statuses": [404], "statement": "..."})
    return {
        "summary": {"probes": len(probes)},
        "findings": findings,
        "probes": probes,
        "liveness": {"enabled": liveness != "off", "unproven": unproven},
    }


class AdjudicationTest(unittest.TestCase):
    """Three verdicts, and INCONCLUSIVE is a first-class one.

    A maintainer whose target was unreachable must never be told
    NOT_REPRODUCED -- that reads as "your bug is not real". It used to be
    told exactly that whenever every probe was REFUSED with a status the
    capsule did not declare: ``adjudicate`` looked only for ``vulnerable`` and
    ``inconclusive`` findings, and an all-``unexpected_denial`` run fell
    through to "the declared expectation held on this target", exit 0.
    Reproduced end to end: a proxy answering 407 to every request (the
    target received none) and stale VERIDOR_* tokens against a vulnerable
    target both printed NOT_REPRODUCED.
    """

    def setUp(self) -> None:
        self.capsule = capsule.build(_config(), "tenant-isolation", run_document=_RUN_WITH_FINDING)

    def _verdict(self, *args, **kwargs) -> dict:
        return capsule.adjudicate(self.capsule, _run_document(*args, **kwargs))

    def test_a_reproduced_finding_is_confirmed(self) -> None:
        result = self._verdict(attacker="vulnerable")
        self.assertEqual(result["verdict"], capsule.CONFIRMED)

    def test_the_claim_is_the_vulnerable_finding_not_the_first_one(self) -> None:
        """`run` emits a check's findings in expect order, so the owner's
        refused control comes before the attacker's vulnerable finding.
        `--from-run` took findings[0] whatever its verdict, published the
        control as the claim, and `verify` then reported a grade mismatch
        against the finding it actually reproduced."""
        run = _run_document(owner="unexpected_denial", attacker="vulnerable")
        run["findings"][0]["id"], run["findings"][1]["id"] = "aaa", "bbb"
        self.assertEqual(run["findings"][0]["identity"], "owner")
        claim = capsule.build(_config(), "tenant-isolation", run_document=run)["claim"]
        self.assertEqual(
            (claim["finding_id"], claim["identity"], claim["verdict"], claim["evidence_grade"]),
            ("bbb", "attacker", "vulnerable", "confirmed"),
        )
        self.assertIn("'attacker' received HTTP 200", claim["statement"])
        built = capsule.build(_config(), "tenant-isolation", run_document=run)
        result = capsule.adjudicate(built, _run_document(attacker="vulnerable"))
        self.assertEqual(result["verdict"], capsule.CONFIRMED)
        self.assertNotIn("different strength", result["reason"])
        # Control: with no vulnerable finding the run's first finding is still
        # the claim, so a reporter's inconclusive run is carried as written.
        run = _run_document(owner="unexpected_denial", attacker="inconclusive")
        claim = capsule.build(_config(), "tenant-isolation", run_document=run)["claim"]
        self.assertEqual((claim["identity"], claim["verdict"]), ("owner", "unexpected_denial"))

    def test_control_a_measured_fixed_target_is_not_reproduced(self) -> None:
        """Every probe answered as declared, the marker was observed where the
        exclusion needs it, and liveness was proven: the one case that is."""
        result = self._verdict()
        self.assertEqual(result["verdict"], capsule.NOT_REPRODUCED)
        self.assertIn("not proof the boundary is enforced", result["reason"])

    def test_refusals_the_capsule_does_not_declare_are_inconclusive(self) -> None:
        """The 407 proxy: every identity refused, the target never reached."""
        result = self._verdict(owner="unexpected_denial", attacker="unexpected_denial")
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE, result["reason"])
        self.assertIn("'owner' received HTTP 403", result["reason"])
        self.assertIn("'attacker' received HTTP 401", result["reason"])
        self.assertIn("[200]", result["reason"])
        self.assertIn("[404]", result["reason"])
        self.assertIn("proxy", result["reason"])
        self.assertNotIn("held", result["reason"])

    def test_a_refused_claimed_identity_alone_is_inconclusive(self) -> None:
        """The stale attacker token: the owner's control succeeded, the
        claimed identity's credential was not recognised."""
        result = self._verdict(attacker="unexpected_denial")
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE, result["reason"])
        self.assertIn("'attacker' received HTTP 401", result["reason"])

    def test_a_refused_control_alone_is_inconclusive(self) -> None:
        result = self._verdict(owner="unexpected_denial")
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE, result["reason"])
        self.assertIn("'owner' received HTTP 403", result["reason"])

    def test_every_outcome_combination(self) -> None:
        """NOT_REPRODUCED only when the check measured the claim; CONFIRMED
        whenever it reproduced, whatever else happened."""
        for owner in _OUTCOMES["owner"]:
            for attacker in _OUTCOMES["attacker"]:
                for liveness in ("proven", "unproven", "off"):
                    with self.subTest(owner=owner, attacker=attacker, liveness=liveness):
                        result = self._verdict(owner, attacker, liveness=liveness)
                        if attacker == "vulnerable":
                            expected = capsule.CONFIRMED
                        elif (owner, attacker) == ("expected", "expected") and liveness != "unproven":
                            expected = capsule.NOT_REPRODUCED
                        else:
                            expected = capsule.INCONCLUSIVE
                        self.assertEqual(result["verdict"], expected, result["reason"])

    def test_an_unobserved_marker_is_named(self) -> None:
        owner = self._verdict(owner="marker_not_observed")
        self.assertIn("'owner'", owner["reason"])
        self.assertIn("marker", owner["reason"])
        attacker = self._verdict(attacker="marker_not_observed")
        self.assertIn("'attacker'", attacker["reason"])
        self.assertIn("marker", attacker["reason"])

    def test_an_unproven_liveness_is_named(self) -> None:
        result = self._verdict(liveness="unproven")
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)
        self.assertIn("'attacker'", result["reason"])
        self.assertIn("fabricated", result["reason"])

    def test_an_unproven_write_does_not_claim_a_sham_was_sent(self) -> None:
        """No fabricated credential rides a write, so the gap must not say one did."""
        document = _run_document(liveness="unproven")
        document["liveness"]["unproven"][0]["control"] = "withheld_unsafe_method"
        result = capsule.adjudicate(self.capsule, document)
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)
        self.assertIn("'attacker'", result["reason"])
        self.assertIn("no credential Veridor fabricated was sent", result["reason"])
        self.assertNotIn("so did a credential Veridor fabricated", result["reason"])

    def test_a_scoped_unproven_denial_is_not_told_to_add_a_marker_probe(self) -> None:
        """Its marker_probe ran, under a login or cookie value the denial did not use."""
        for scope in ("login", "cookie_value"):
            with self.subTest(scope=scope):
                document = _run_document(liveness="unproven")
                entry = document["liveness"]["unproven"][0]
                entry["control"], entry["proof_scope"] = "withheld_sequence_step", scope
                result = capsule.adjudicate(self.capsule, document)
                self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)
                self.assertIn("a marker_probe proves only the login and session cookie "
                              "value it ran under, and this denial was sent under another",
                              result["reason"])
                self.assertNotIn("would prove it live", result["reason"])

    def test_control_an_unscoped_one_is_told_to_add_a_marker_probe(self) -> None:
        document = _run_document(liveness="unproven")
        document["liveness"]["unproven"][0]["control"] = "withheld_sequence_step"
        result = capsule.adjudicate(self.capsule, document)
        self.assertIn("(a marker_probe on 'attacker', naming something it is served, "
                      "would prove it live)", result["reason"])
        self.assertNotIn("proves only the login", result["reason"])

    def test_liveness_turned_off_says_so_beside_the_verdict(self) -> None:
        result = self._verdict(liveness="off")
        self.assertEqual(result["verdict"], capsule.NOT_REPRODUCED)
        self.assertIn("--no-prove-liveness", result["reason"])
        self.assertNotIn("--no-prove-liveness", self._verdict()["reason"])

    def test_an_inconclusive_probe_is_inconclusive(self) -> None:
        result = self._verdict(attacker="inconclusive")
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)

    def test_no_probe_at_all_is_inconclusive(self) -> None:
        document = _run_document()
        document["probes"], document["summary"]["probes"] = [], 0
        result = capsule.adjudicate(self.capsule, document)
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)

    def test_a_claimed_identity_that_was_never_probed_is_inconclusive(self) -> None:
        document = _run_document()
        document["probes"] = [p for p in document["probes"] if p["identity"] != "attacker"]
        result = capsule.adjudicate(self.capsule, document)
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)
        self.assertIn("'attacker'", result["reason"])

    def test_a_finding_for_another_check_is_ignored(self) -> None:
        document = _run_document()
        document["findings"].append({"check_id": "something-else", "verdict": "vulnerable"})
        result = capsule.adjudicate(self.capsule, document)
        self.assertEqual(result["verdict"], capsule.NOT_REPRODUCED)

    def test_probes_of_another_check_measure_nothing_about_this_one(self) -> None:
        document = _run_document(check_id="something-else")
        result = capsule.adjudicate(self.capsule, document)
        self.assertEqual(result["verdict"], capsule.INCONCLUSIVE)

    def test_a_changed_evidence_grade_is_reported_not_hidden(self) -> None:
        document = _run_document(attacker="vulnerable")
        document["findings"][0]["evidence_grade"] = "ungraded"
        result = capsule.adjudicate(self.capsule, document)
        self.assertEqual(result["verdict"], capsule.CONFIRMED)
        self.assertIn("different strength of evidence", result["reason"])

    def test_a_single_integer_status_is_read_as_the_list_it_stands_for(self) -> None:
        """The config schema's shorthand, ``"status": 404``, read raw.

        ``_unmeasured`` tested ``status not in declared`` on the capsule as
        written, so a scalar raised TypeError -- exit 70, "a bug in Veridor"
        -- on exactly the run where the boundary held. ``load`` now hands it a
        list; this holds ``adjudicate`` to the same answer when it is handed
        the raw form directly.
        """
        scalar = copy.deepcopy(self.capsule)
        for expectation in scalar["check"]["expect"].values():
            expectation["status"] = expectation["status"][0]
        for outcome in ({}, {"attacker": "vulnerable"}, {"attacker": "marker_not_observed"},
                        {"owner": "unexpected_denial"}):
            with self.subTest(**outcome):
                expected = capsule.adjudicate(self.capsule, _run_document(**outcome))
                result = capsule.adjudicate(scalar, _run_document(**outcome))
                self.assertEqual(result["verdict"], expected["verdict"], result["reason"])
        self.assertEqual(capsule.adjudicate(scalar, _run_document())["verdict"],
                         capsule.NOT_REPRODUCED)

    def test_a_status_that_is_not_a_status_measures_nothing(self) -> None:
        """Called directly, past ``load``: a declaration that is no status
        cannot be met, so it is INCONCLUSIVE -- never a crash, never
        NOT_REPRODUCED."""
        for bad in ("404", None, True, {"a": 1}, 404.0):
            with self.subTest(bad=bad):
                document = copy.deepcopy(self.capsule)
                document["check"]["expect"]["attacker"]["status"] = bad
                result = capsule.adjudicate(document, _run_document())
                self.assertEqual(result["verdict"], capsule.INCONCLUSIVE, result["reason"])
                self.assertIn("'attacker' received HTTP 404", result["reason"])

    def test_the_writer_writes_a_single_integer_status_as_a_list(self) -> None:
        """So a capsule `veridor capsule` wrote from the shorthand also
        verifies under a verifier that predates ``load``'s reading of it."""
        config = _config()
        for expectation in config["checks"][0]["expect"].values():
            expectation["status"] = expectation["status"][0]
        built = capsule.build(config, "tenant-isolation")
        self.assertEqual(
            {name: e["status"] for name, e in built["check"]["expect"].items()},
            {"owner": [200], "attacker": [404]},
        )
        # The writer copies; the reporter's config is not rewritten under them.
        self.assertEqual(config["checks"][0]["expect"]["attacker"]["status"], 404)


class RenderTest(unittest.TestCase):
    def test_the_verified_target_is_the_one_probed_not_the_reporter_s(self) -> None:
        """Printing the reporter's URL beside a verdict about the maintainer's
        would be a small lie in the one document whose job is to be believable."""
        built = capsule.build(_config(), "tenant-isolation")
        text = capsule.render(built, {"verdict": capsule.CONFIRMED, "reason": "x"},
                              "https://maintainer.example")
        self.assertIn("verified: https://maintainer.example", text)
        self.assertIn("reported: http://127.0.0.1:8765", text)

    def test_a_matching_target_is_not_reported_twice(self) -> None:
        built = capsule.build(_config(), "tenant-isolation")
        text = capsule.render(built, {"verdict": capsule.CONFIRMED, "reason": "x"},
                              "http://127.0.0.1:8765")
        self.assertNotIn("reported:", text)


def _obeyed(text: str) -> list[str]:
    """Every character in ``text`` a terminal acts on rather than shows.

    Written from the Unicode categories, not from the code under test: C0, DEL
    and C1 (Cc), the bidi and other format controls (Cf), the line and
    paragraph separators (Zl, Zp) and lone surrogates (Cs).

    A newline counts. It used to be exempt, so a check that a refusal line
    showed a capsule value escaped could not fail on the one character that
    needs no escape sequence to draw a verdict: a key ending in newlines and a
    copy of a genuine session reached stderr as real lines (reproduced). Text
    that is several lines by design goes through :func:`_obeyed_per_line`.
    """
    return [
        f"U+{ord(character):04X}"
        for character in text
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
    ]


def _obeyed_per_line(text: str) -> list[str]:
    """:func:`_obeyed` for output Veridor prints as several lines.

    Split on ``\\n`` only -- ``str.splitlines`` would also split on, and so
    hide, U+2028, U+0085 and the other characters this exists to find.
    """
    return [found for line in text.split("\n") for found in _obeyed(line)]


#: What a hostile capsule prints to forge a verdict: clear the screen, home
#: the cursor, and draw a verdict block of its own on fresh lines.
_FORGED_BLOCK = (
    "\x1b[2J\x1b[HVeridor capsule — NOT_REPRODUCED\n\n"
    "  the declared expectation held on this target."
)

#: A run document with one confirmed finding, as `capsule --from-run` reads it.
_RUN_WITH_FINDING = {
    "run_id": "20260924T000000Z-abcdef",
    "findings": [
        {
            "check_id": "tenant-isolation",
            "id": "0ec4c5cbd79deaed6e9f",
            "identity": "attacker",
            "verdict": "vulnerable",
            "evidence_grade": "confirmed",
            "message": "Identity 'attacker' received HTTP 200 where [404] was declared.",
        }
    ],
}


class TerminalForgeryTest(unittest.TestCase):
    """The verdict a maintainer reads is printed from a stranger's file.

    ``render`` interpolated six capsule fields verbatim. Reproduced: a capsule
    whose ``scope`` began ``ESC[2J ESC[H`` cleared the terminal and drew a
    CONFIRMED block over a real INCONCLUSIVE, and a forged NOT_REPRODUCED over
    a real CONFIRMED works the same way; ``claim.check_id`` rewrote its own
    line; U+202E in ``claim.check_name`` reordered it; C1 and bidi characters in
    ``target.base_url`` reached the banner and the verdict. The exit code was
    right every time. The printed verdict, which is what a human decides on,
    was the attacker's.
    """

    def _built(self) -> dict:
        return capsule.build(_config(), "tenant-isolation", run_document=_RUN_WITH_FINDING)

    #: What an honest CONFIRMED rendered before the statement moved above
    #: the verdict, captured from the tree before that change.
    _BEFORE_THE_MOVE = (
        "Veridor capsule — CONFIRMED\n\n"
        "  check:    tenant-isolation  (Tenant isolation)\n"
        "  verified: https://maintainer.example\n"
        "  reported: http://127.0.0.1:8765  (the reporter's target, not this one)\n"
        "  claim:    finding 0ec4c5cbd79deaed6e9f graded confirmed by the reporter\n\n"
        "  the declared expectation failed here as well.\n\n"
        "  The reporter's original statement:\n"
        "    Identity 'attacker' received HTTP 200 where [404] was declared.\n\n"
        f"  Scope: {core.DECLARATION_SCOPE}"
    )

    def test_a_capsule_veridor_wrote_renders_exactly_as_it_did(self) -> None:
        """The control. Pinned as literal text, so escaping and bounding cannot
        quietly change what an honest capsule prints. The one intended change
        from the text captured before (``_BEFORE_THE_MOVE``): the statement is
        printed above Veridor's verdict, and that line names the verdict."""
        text = capsule.render(
            self._built(),
            {"verdict": capsule.CONFIRMED,
             "reason": "the declared expectation failed here as well."},
            "https://maintainer.example",
        )
        self.assertEqual(
            text,
            "Veridor capsule — CONFIRMED\n\n"
            "  check:    tenant-isolation  (Tenant isolation)\n"
            "  verified: https://maintainer.example\n"
            "  reported: http://127.0.0.1:8765  (the reporter's target, not this one)\n"
            "  claim:    finding 0ec4c5cbd79deaed6e9f graded confirmed by the reporter\n\n"
            "  The reporter's original statement:\n"
            "    Identity 'attacker' received HTTP 200 where [404] was declared.\n\n"
            "  CONFIRMED: the declared expectation failed here as well.\n\n"
            f"  Scope: {core.DECLARATION_SCOPE}",
        )
        moved = "  the declared expectation failed here as well."
        before = [line for line in self._BEFORE_THE_MOVE.split("\n") if line != moved]
        after = [line for line in text.split("\n")
                 if line != "  CONFIRMED: the declared expectation failed here as well."]
        self.assertEqual(sorted(before), sorted(after))

    def test_an_escape_sequence_in_any_printed_field_is_shown_not_obeyed(self) -> None:
        sinks = {
            "claim.check_id": lambda d, a, v: d["claim"].update(check_id=v),
            "claim.check_name": lambda d, a, v: d["claim"].update(check_name=v),
            "claim.finding_id": lambda d, a, v: d["claim"].update(finding_id=v),
            "claim.evidence_grade": lambda d, a, v: d["claim"].update(evidence_grade=v),
            "claim.statement": lambda d, a, v: d["claim"].update(statement=v),
            "target.base_url": lambda d, a, v: d["target"].update(base_url=v),
            # INCONCLUSIVE carries the run's own message, which quotes the
            # transport error; it is printed through the same escaping.
            "adjudication.reason": lambda d, a, v: a.update(reason=v),
        }
        for where, plant in sinks.items():
            for probed in ("https://maintainer.example", None):
                with self.subTest(where=where, probed=probed):
                    document = self._built()
                    adjudication = {"verdict": capsule.CONFIRMED, "reason": "x"}
                    plant(document, adjudication, where + _FORGED_BLOCK)
                    text = capsule.render(document, adjudication, probed)
                    self.assertEqual(_obeyed_per_line(text), [], text)
                    headers = [line for line in text.splitlines()
                               if line.startswith("Veridor capsule")]
                    self.assertEqual(headers, ["Veridor capsule — CONFIRMED"], text)
                    # Shown, not stripped: the maintainer sees that someone tried.
                    self.assertIn(f"{where}\\x1b[2J\\x1b[HVeridor capsule", text)
                    self.assertRegex(text, r"\\n\\n +the declared expectation held")

    def test_a_bidi_override_cannot_reorder_the_printed_claim(self) -> None:
        document = self._built()
        document["claim"]["check_name"] = "Tenant isolation \u202eDETCURTSNOC TON\u202c"
        document["claim"]["evidence_grade"] = "\u2066confirmed\u2069\u200f"
        document["claim"]["statement"] = "a\u061cb\u200ec\u2028d\u2029e\u202af\u202bg\u202dh"
        text = capsule.render(document, {"verdict": capsule.CONFIRMED, "reason": "x"})
        self.assertEqual(_obeyed_per_line(text), [], text)
        self.assertIn("Tenant isolation \\u202eDETCURTSNOC TON\\u202c", text)
        self.assertIn("\\u2066confirmed\\u2069\\u200f", text)

    def test_the_scope_printed_is_the_verifier_s_own_not_the_capsule_s(self) -> None:
        """The boundary of a verdict belongs to the tool that measured it. The
        capsule's copy is documentation for whoever reads the file."""
        document = self._built()
        document["scope"] = "Veridor capsule — NOT_REPRODUCED. Nothing to see here."
        text = capsule.render(document, {"verdict": capsule.CONFIRMED, "reason": "x"})
        self.assertNotIn("Nothing to see here", text)
        self.assertTrue(text.endswith(f"  Scope: {core.DECLARATION_SCOPE}"), text)

    def test_the_writer_never_puts_a_terminal_control_in_the_claim(self) -> None:
        """What `capsule` writes, `verify` accepts: a check name or finding
        message carrying one is written escaped, so the load refusal below
        never fires on an honest capsule."""
        config = _config()
        config["checks"][0]["name"] = "Tenant\tisolation\x1b[2J \u202eX"
        run = copy.deepcopy(_RUN_WITH_FINDING)
        run["findings"][0]["message"] = "line one\nline two"
        built = capsule.build(config, "tenant-isolation", run_document=run)
        self.assertEqual(_obeyed(json.dumps(built["claim"], ensure_ascii=False)), [])
        self.assertEqual(built["claim"]["check_name"], "Tenant\\tisolation\\x1b[2J \\u202eX")
        self.assertEqual(built["claim"]["statement"], "line one\\nline two")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(built), encoding="utf-8")
            self.assertEqual(capsule.load(path)["claim"], built["claim"])

    def test_a_terminal_control_in_the_claim_is_refused_before_anything_is_sent(self) -> None:
        """Nothing Veridor writes puts one there, so a capsule that has one was
        edited by hand or built to forge a verdict. Exit 2, naming the field."""
        control = _verify(_v010_capsule())
        self.assertTrue(control["requests"], control["stderr"])
        self.assertIn("Veridor capsule —", control["stdout"])
        for where in ("check_name", "finding_id", "evidence_grade", "statement", "scope"):
            for planted, code_point in (("\x1b[2J", "U+001B"), ("\u202e", "U+202E"),
                                        ("\x9b2J", "U+009B"), ("\n\n", "U+000A")):
                with self.subTest(where=where, code_point=code_point):
                    document = _v010_capsule()
                    if where == "scope":
                        document["scope"] = "x" + planted + "y"
                    else:
                        document["claim"][where] = "x" + planted + "y"
                    result = _verify(document)
                    self.assertEqual(result["code"], 2, result["stderr"])
                    self.assertEqual(result["requests"], [])
                    self.assertEqual(result["stdout"], "")
                    self.assertEqual(_obeyed(result["stderr"].removesuffix("\n")), [],
                                     result["stderr"])
                    self.assertIn(where, result["stderr"])
                    self.assertIn(code_point, result["stderr"])
                    self.assertNotIn("internal error", result["stderr"])

    def test_check_name_and_non_string_claim_values_are_held_to_the_rule(self) -> None:
        """Only string claim values and the scope were checked. A claim value
        that is a list or an object, a claim key, and the check's own ``name``
        -- which reaches the run document's findings and from there `report`,
        whose junit and codequality formats printed U+009B and U+202E raw to
        stdout (measured) -- loaded without a word."""
        cases = {
            "check.name": lambda d: d["check"].update(name="Invoice\x9b2J\u202e"),
            "claim.check_name": lambda d: d["claim"].update(check_name=["x\x1b[2Jy"]),
            "claim.statement": lambda d: d["claim"].update(statement={"a": ["\u2028b"]}),
            "claim key": lambda d: d["claim"].update({"note\n\nVeridor capsule": 1}),
        }
        for where, plant in cases.items():
            with self.subTest(where=where):
                document = _v010_capsule()
                plant(document)
                result = _verify(document)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertEqual(result["requests"], [])
                self.assertEqual(_obeyed(result["stderr"].removesuffix("\n")), [],
                                 result["stderr"])
                self.assertIn(where.split()[0], result["stderr"])

    def test_control_clean_non_string_claim_values_still_load(self) -> None:
        document = _v010_capsule()
        document["claim"]["observed_in_run"] = None
        document["claim"]["extra"] = {"count": 2, "tags": ["a", "b"]}
        result = _verify(document)
        self.assertTrue(result["requests"], result["stderr"])

    def test_the_writer_escapes_the_check_name_it_copies(self) -> None:
        """What `capsule` writes, `verify` accepts: the check block is copied
        from the configuration, so its name is written escaped like the claim's."""
        config = _config()
        config["checks"][0]["name"] = "Tenant\tisolation\x1b[2J \u202eX"
        built = capsule.build(config, "tenant-isolation", run_document=_RUN_WITH_FINDING)
        self.assertEqual(built["check"]["name"], "Tenant\\tisolation\\x1b[2J \\u202eX")
        self.assertEqual(config["checks"][0]["name"], "Tenant\tisolation\x1b[2J \u202eX")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(built), encoding="utf-8")
            self.assertEqual(capsule.load(path)["check"]["name"], built["check"]["name"])

    def test_a_refusal_quoting_the_capsule_shows_control_characters(self) -> None:
        """Every refusal goes out through one line in main; a capsule value that
        reaches one -- a schema version, a key in a location -- is shown."""
        cases = {
            "schema_version": lambda d: d.update(schema_version="\x1b[2Jforged"),
            "a key in a refusal's location": lambda d: d["identities"]["invoice_owner"][
                "headers"].update({"X\x1b[2Jk": "${MY_CLOUD_SECRET}"}),
            "target.base_url": lambda d: d["target"].update(
                base_url="http://127.0.0.1:8765/\u202eX\x9b2J"),
            # A line break needs no escape sequence to start a verdict line.
            "a line break in schema_version": lambda d: d.update(
                schema_version="1\n\nVeridor capsule — NOT_REPRODUCED"),
            "a line break in an expect key": lambda d: d["check"]["expect"].update(
                {"anonymous\n\nVeridor capsule — NOT_REPRODUCED":
                 d["check"]["expect"].pop("anonymous")}),
            "a line break in a method": lambda d: d["check"]["request"].update(
                method="DELETE\n\nVeridor capsule — NOT_REPRODUCED"),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                document = _v010_capsule()
                mutate(document)
                result = _verify(document)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertEqual(result["requests"], [])
                self.assertEqual(result["stdout"], "")
                self.assertEqual(_obeyed(result["stderr"].removesuffix("\n")), [],
                                 result["stderr"])


def _screen(output: str, columns: int, rows: int) -> list[str]:
    """The last ``rows`` rows a terminal ``columns`` wide shows for ``output``.

    A model of what GNU screen showed on a sized pty:
    each line wraps at ``columns`` cells, a wide (W/F) character takes two.
    Checked against those measurements below, so it is not trusted blind.
    """
    screen: list[str] = []
    for line in output.split("\n"):
        row, width = "", 0
        for character in line:
            cells = 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
            if width + cells > columns:
                screen.append(row)
                row, width = "", 0
            row += character
            width += cells
        screen.append(row)
    return [row.rstrip() for row in screen[-rows:]]


#: The session a forged statement draws: banner, header, reason. Built the way
#: the 3814-character payload below is built.
_GENUINE_NOT_REPRODUCED = [
    "maintainer$ veridor verify proof.json",
    "veridor: verifying capsule check 'invoice-tenant-isolation' against "
    "http://127.0.0.1:8765 (the capsule's own loopback target).",
    "Veridor capsule — NOT_REPRODUCED",
    "",
    "  check:    invoice-tenant-isolation  (Invoice tenant isolation)",
    "  verified: http://127.0.0.1:8765",
    "  claim:    finding 0ec4c5cbd79deaed6e9f graded confirmed by the reporter",
    "",
    "  the declared expectation held on this target. That is not proof the "
    "boundary is enforced -- only that this one declaration was met here.",
]


def _wrap_forgery(columns: int, filler: str = " ") -> str:
    """A statement of printable text only that, printed after "    " on a
    terminal ``columns`` wide, scrolls the real verdict away with thirty blank
    rows and then draws a NOT_REPRODUCED session one line per row."""
    def pad(line: str) -> str:
        wanted = max(1, -(-len(line) // columns)) * columns
        return line + filler * (wanted - len(line))

    statement = filler * (columns - 4) + filler * (columns * 30)
    statement += "".join(pad(line) for line in _GENUINE_NOT_REPRODUCED)
    return statement.rstrip(filler)


_VERDICT_WORDS = re.compile(r"\b(CONFIRMED|NOT_REPRODUCED|INCONCLUSIVE)\b")


class WrapForgeryTest(unittest.TestCase):
    """A long statement drew a verdict by line wrapping alone.

    ``render`` printed the reporter's ``claim.statement`` AFTER Veridor's own
    verdict and reason, and nothing bounded its length or its runs of spaces.
    Reproduced with GNU screen on an 80x24 pty: a 3814-character statement of
    spaces and printable text, against a vulnerable target (exit 1, CONFIRMED
    on stdout line 1), left a complete NOT_REPRODUCED session on the visible
    screen, indistinguishable from a genuine one. No control character, no
    newline -- both earlier checks passed on it.
    """

    def _rendered(self, statement: str, verdict: str = capsule.CONFIRMED) -> str:
        document = capsule.build(_config(), "tenant-isolation", run_document=_RUN_WITH_FINDING)
        document["claim"]["statement"] = statement
        reasons = {capsule.CONFIRMED: "the declared expectation failed here as well.",
                   capsule.NOT_REPRODUCED: "the declared expectation held on this target.",
                   capsule.INCONCLUSIVE: "no probe reached the target, so nothing was measured"}
        return capsule.render(document, {"verdict": verdict, "reason": reasons[verdict]},
                              "http://127.0.0.1:8765")

    def test_control_the_screen_model_reproduces_the_forgery_measured_on_a_pty(self) -> None:
        """Without the fix the model shows what GNU screen showed: the last
        verdict word on an 80x24 screen is the forged one. Applied to the
        rendering as it was, so the model is shown able to fail."""
        statement = _wrap_forgery(80)
        old_layout = "\n".join([
            "Veridor capsule — CONFIRMED", "", "  the declared expectation failed here as well.",
            "", "  The reporter's original statement:", "    " + statement, "",
            f"  Scope: {core.DECLARATION_SCOPE}",
        ])
        screen = _screen(old_layout, 80, 24)
        words = [m.group(1) for row in screen for m in _VERDICT_WORDS.finditer(row)]
        self.assertEqual(words[-1], "NOT_REPRODUCED", "\n".join(screen))
        self.assertTrue(any(row.startswith("Veridor capsule — NOT_REPRODUCED")
                            for row in screen), "\n".join(screen))

    def test_the_last_verdict_on_screen_is_veridor_s_at_80_and_120_columns(self) -> None:
        for columns, rows in ((80, 24), (120, 30)):
            for filler in (" ", "\u00a0", "\u2800"):
                for built_for in (80, 120):
                    with self.subTest(columns=columns, filler=hex(ord(filler)), built_for=built_for):
                        text = self._rendered(_wrap_forgery(built_for, filler))
                        screen = _screen(text, columns, rows)
                        words = [m.group(1) for row in screen
                                 for m in _VERDICT_WORDS.finditer(row)]
                        self.assertTrue(words, "\n".join(screen))
                        self.assertEqual(words[-1], "CONFIRMED", "\n".join(screen))
                        self.assertFalse(any(row.startswith("Veridor capsule — NOT_REPRODUCED")
                                             for row in screen), "\n".join(screen))

    def test_nothing_from_the_capsule_follows_the_verdict_line(self) -> None:
        for verdict in (capsule.CONFIRMED, capsule.NOT_REPRODUCED, capsule.INCONCLUSIVE):
            with self.subTest(verdict=verdict):
                lines = self._rendered("STATEMENT-TEXT", verdict).split("\n")
                last_verdict = max(i for i, line in enumerate(lines) if verdict in line)
                self.assertGreater(last_verdict, 0)
                self.assertTrue(lines[last_verdict].startswith(f"  {verdict}: "), lines)
                self.assertEqual(lines[last_verdict + 1:],
                                 ["", f"  Scope: {core.DECLARATION_SCOPE}"])
                if verdict == capsule.CONFIRMED:
                    self.assertLess(lines.index("    STATEMENT-TEXT"), last_verdict)

    def test_a_statement_is_bounded_and_its_blank_runs_collapsed(self) -> None:
        for filler in (" ", "\u00a0", "\u3000", " \u2002 "):
            with self.subTest(filler=hex(ord(filler[0]))):
                text = self._rendered("a" + filler * 3000 + "b")
                self.assertIn("    a b\n", text)
        text = self._rendered("x" * 5000)
        line = next(line for line in text.split("\n") if line.startswith("    x"))
        self.assertLess(len(line), 700)
        self.assertIn("more characters in the capsule", line)

    def test_a_refused_key_cannot_draw_a_session_by_wrapping(self) -> None:
        """An ``expect`` key of 'anonymous',
        then spaces and a genuine session, each line padded to the terminal's
        width -- no newline, no control character. verify refuses it (exit 2,
        nothing sent), and the refusal quoted the whole key, so the screen was
        that session, measured identical to a genuine one with GNU screen at
        80x24, for NOT_REPRODUCED and for CONFIRMED, and at 120x30 with a
        120-column build. The refusal line must be what the screen shows."""
        prefix = ("veridor: check 'invoice-tenant-isolation' references unknown "
                  "identities: anonymous")
        confirmed = [line.replace("NOT_REPRODUCED", "CONFIRMED") for line in
                     _GENUINE_NOT_REPRODUCED[:-1]] + [
            "  CONFIRMED: the declared expectation failed here as well."]
        for columns, rows in ((80, 24), (120, 30)):
            for verdict, session in (("NOT_REPRODUCED", _GENUINE_NOT_REPRODUCED),
                                     ("CONFIRMED", confirmed)):
                with self.subTest(columns=columns, verdict=verdict):
                    def pad(line: str) -> str:
                        return line + " " * (max(1, -(-len(line) // columns)) * columns - len(line))
                    key = ("anonymous" + " " * (columns - len(prefix) % columns)
                           + " " * columns * 30 + "".join(pad(line) for line in session))
                    # Control: printed the way it was, the key draws the session.
                    before = _screen(prefix + key[len("anonymous"):], columns, rows)
                    self.assertIn(f"Veridor capsule — {verdict}", before)
                    self.assertFalse(any(prefix[:40] in row for row in before))

                    document = _v010_capsule()
                    document["check"]["expect"][key] = document["check"]["expect"].pop("anonymous")
                    result = _verify(document)
                    self.assertEqual(result["code"], 2, result["stderr"][:300])
                    self.assertEqual(result["requests"], [])
                    self.assertEqual(result["stdout"], "")
                    screen = _screen(result["stderr"], columns, rows)
                    self.assertTrue(any(row.startswith(prefix[:columns]) for row in screen),
                                    "\n".join(screen))
                    self.assertFalse(any(row.startswith("Veridor capsule") for row in screen),
                                     "\n".join(screen))
                    self.assertLess(len(result["stderr"]), 600)

    def test_every_capsule_field_is_bounded(self) -> None:
        """Through adjudicate, not a hand-built reason: the claimed grade is
        quoted in Veridor's own CONFIRMED reason, after the verdict word, and
        this test used to pass render the reason 'r', so it could not see
        that the grade reached the terminal whole there."""
        document = capsule.build(_config(), "tenant-isolation", run_document=_RUN_WITH_FINDING)
        for key in ("check_name", "finding_id", "evidence_grade"):
            document["claim"][key] = "y" * 3000
        document["target"]["base_url"] = "http://127.0.0.1:8765/" + "z" * 3000
        adjudication = capsule.adjudicate(document, _run_document(attacker="vulnerable"))
        self.assertEqual(adjudication["verdict"], capsule.CONFIRMED)
        self.assertIn("yyy", adjudication["reason"])
        text = capsule.render(document, adjudication, "https://maintainer.example")
        for line in text.split("\n"):
            self.assertLess(len(line), 400, line[:80])

    def test_the_claimed_grade_cannot_draw_a_verdict_after_veridor_s(self) -> None:
        """An evidence_grade of spaces and a
        NOT_REPRODUCED session, padded to 80 columns, against a vulnerable
        target. adjudicate put it whole into Veridor's CONFIRMED reason, after
        the verdict word, and the 80x24 screen was a NOT_REPRODUCED session
        (exit 1). `load` now refuses such a grade; adjudicate, which does not
        rely on that, quotes it bounded."""
        columns = 80

        def pad(line: str) -> str:
            return line + " " * (max(1, -(-len(line) // columns)) * columns - len(line))

        forged = _GENUINE_NOT_REPRODUCED[:-1] + [
            "  NOT_REPRODUCED: the declared expectation held on this target. "
            "The original claim was graded 'confirmed"]
        grade = ("confirmed" + " " * columns * 31 + "".join(pad(line) for line in forged[:-1])
                 + forged[-1][: -len("confirmed")] + "confirmed")
        document = capsule.build(_config(), "tenant-isolation", run_document=_RUN_WITH_FINDING)
        document["claim"]["evidence_grade"] = grade
        adjudication = capsule.adjudicate(document, _run_document(attacker="vulnerable"))
        self.assertEqual(adjudication["verdict"], capsule.CONFIRMED)
        self.assertNotIn("NOT_REPRODUCED", adjudication["reason"])
        self.assertLess(len(adjudication["reason"]), 400)
        screen = _screen(capsule.render(document, adjudication, None), columns, 24)
        words = [m.group(1) for row in screen for m in _VERDICT_WORDS.finditer(row)]
        self.assertEqual(words[-1], "CONFIRMED", "\n".join(screen))
        self.assertFalse(any("NOT_REPRODUCED" in row for row in screen), "\n".join(screen))


class LoadTest(unittest.TestCase):
    def test_a_configuration_is_not_a_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(_config()), encoding="utf-8")
            with self.assertRaises(capsule.CapsuleError):
                capsule.load(path)

    def test_a_future_schema_version_is_refused(self) -> None:
        built = capsule.build(_config(), "tenant-isolation")
        built["schema_version"] = 99
        with self.assertRaises(capsule.CapsuleError) as caught:
            capsule.to_config(built)
        self.assertIn("not supported", str(caught.exception))

    def test_a_wrongly_shaped_capsule_is_refused_not_crashed_on(self) -> None:
        """A capsule is untrusted input: a wrong shape is exit 2, never 70."""
        for key, value in (("check", []), ("identities", "x"), ("target", ["a"]),
                           ("claim", {"no": "check_id"})):
            with self.subTest(key=key):
                document = _v010_capsule()
                document[key] = value
                result = _verify(document)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertEqual(result["requests"], [])
                self.assertNotIn("internal error", result["stderr"])

    def test_load_reads_a_single_integer_status_as_a_list_and_refuses_the_rest(self) -> None:
        """``adjudicate`` reads what ``load`` returns, so ``load`` puts every
        declared status in the one shape it tests, and refuses (exit 2) what
        the config loader would refuse."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            document = _v010_capsule()
            document["check"]["expect"]["other_tenant"]["status"] = 404
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = capsule.load(path)
            self.assertEqual(loaded["check"]["expect"]["other_tenant"]["status"], [404])
            self.assertEqual(loaded["check"]["expect"]["anonymous"]["status"], [401])
            for bad in ("404", True, [], [600], [True], None):
                with self.subTest(bad=bad):
                    document["check"]["expect"]["other_tenant"]["status"] = bad
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(capsule.CapsuleError) as caught:
                        capsule.load(path)
                    self.assertIn("'other_tenant'", str(caught.exception))
                    self.assertIn("Nothing has been sent", str(caught.exception))

    def test_an_evidence_grade_veridor_never_writes_is_refused(self) -> None:
        """claim.evidence_grade is printed beside Veridor's verdict and quoted
        in its reason. `veridor capsule` copies it from a finding, which only
        ever carries one of core.EVIDENCE_GRADES, so anything else was edited
        in. Refused at load, exit 2, before anything is sent."""
        vulnerable = _demo_target(vulnerable=True)
        for grade in ("bogus", "Confirmed", " " * 3000 + "confirmed",
                      "confirmed" + " " * 3000 + "Veridor capsule — NOT_REPRODUCED",
                      3, ["confirmed"], {"a": "confirmed"}, ""):
            with self.subTest(grade=repr(grade)[:30]):
                document = _v010_capsule()
                document["claim"]["evidence_grade"] = grade
                result = _verify(document, opener=_TargetOpener(vulnerable))
                self.assertEqual(result["code"], 2, result["stderr"][-300:])
                self.assertEqual(result["requests"], [])
                self.assertEqual(result["stdout"], "")
                self.assertIn("claim.evidence_grade", result["stderr"])
                self.assertIn("n/a, ungraded, suspected, confirmed", result["stderr"])
                self.assertLess(len(result["stderr"]), 800)

    def test_the_writer_refuses_a_run_whose_grade_verify_would_refuse(self) -> None:
        """What `capsule` writes, `verify` accepts: a hand-edited run document
        is refused by the writer rather than published as a capsule no one
        can verify."""
        for grade in ("bogus", " " * 300 + "confirmed", 3):
            with self.subTest(grade=repr(grade)[:20]):
                run = copy.deepcopy(_RUN_WITH_FINDING)
                run["findings"][0]["evidence_grade"] = grade
                with self.assertRaises(capsule.CapsuleError) as caught:
                    capsule.build(_config(), "tenant-isolation", run_document=run)
                self.assertIn("evidence_grade", str(caught.exception))
                self.assertLess(len(str(caught.exception)), 500)
        for grade in (*core.EVIDENCE_GRADES, None):
            with self.subTest(grade=grade):
                run = copy.deepcopy(_RUN_WITH_FINDING)
                run["findings"][0]["evidence_grade"] = grade
                built = capsule.build(_config(), "tenant-isolation", run_document=run)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "proof.json"
                    path.write_text(json.dumps(built), encoding="utf-8")
                    self.assertEqual(capsule.load(path)["claim"]["evidence_grade"], grade)

    def test_control_every_grade_veridor_writes_still_verifies(self) -> None:
        vulnerable = _demo_target(vulnerable=True)
        for grade in (*core.EVIDENCE_GRADES, None, "absent"):
            with self.subTest(grade=grade):
                document = _v010_capsule()
                if grade == "absent":
                    del document["claim"]["evidence_grade"]
                else:
                    document["claim"]["evidence_grade"] = grade
                result = _verify(document, opener=_TargetOpener(vulnerable))
                self.assertEqual(result["code"], 1, result["stderr"][-300:])
                self.assertIn("Veridor capsule — CONFIRMED", result["stdout"])

    def test_a_claim_about_another_check_is_refused(self) -> None:
        """``adjudicate`` looks for findings under ``claim.check_id`` and the
        run produces them under ``check.id``. When the two differed, no finding
        ever matched, so the verdict was NOT_REPRODUCED, exit 0 -- measured
        with nothing listening at all, where the truth is INCONCLUSIVE."""
        control = _verify(_v010_capsule())
        self.assertTrue(control["requests"], control["stderr"])
        self.assertIn("INCONCLUSIVE", control["stdout"])
        document = _v010_capsule()
        document["claim"]["check_id"] = "some-other-check"
        result = _verify(document)
        self.assertEqual(result["code"], 2, result["stdout"] + result["stderr"])
        self.assertEqual(result["requests"], [])
        self.assertNotIn("NOT_REPRODUCED", result["stdout"])
        self.assertIn("'some-other-check'", result["stderr"])
        self.assertIn("'invoice-tenant-isolation'", result["stderr"])

    def test_the_image_is_documentation_not_configuration(self) -> None:
        built = capsule.build(_config(), "tenant-isolation", image="app@sha256:dead")
        self.assertEqual(built["target"]["image"], "app@sha256:dead")
        self.assertNotIn("image", capsule.to_config(built)["target"])


class CliSurfaceTest(unittest.TestCase):
    """`verify` gained a positional; `run --config` must be untouched."""

    def test_run_still_requires_a_config_or_a_capsule(self) -> None:
        from veridor.core import ConfigError  # noqa: PLC0415

        from veridor.cli import _parser  # noqa: PLC0415

        args = _parser().parse_args(["run"])
        self.assertIsNone(args.config)
        self.assertIsNone(args.capsule)
        # main() turns this into exit 2 with a message naming both forms.
        self.assertEqual(veridor_main(["run"]), 2)

    def test_run_with_a_config_parses_exactly_as_before(self) -> None:
        from veridor.cli import _parser  # noqa: PLC0415

        args = _parser().parse_args(["run", "--config", "veridor.json"])
        self.assertEqual(args.config, Path("veridor.json"))
        self.assertIsNone(args.capsule)

    def test_verify_accepts_a_positional_capsule(self) -> None:
        from veridor.cli import _parser  # noqa: PLC0415

        args = _parser().parse_args(["verify", "proof.json"])
        self.assertEqual(args.capsule, Path("proof.json"))
        self.assertEqual(args.command, "verify")

    def test_capsule_is_visible_in_the_top_level_help(self) -> None:
        from veridor.cli import _OVERVIEW  # noqa: PLC0415

        self.assertIn("capsule", _OVERVIEW)
        self.assertIn("CONFIRMED / NOT_REPRODUCED / INCONCLUSIVE", _OVERVIEW)


# ---------------------------------------------------------------------------
# Verifying a capsule someone else wrote.
#
# The capsule is untrusted input from a stranger, and `verify` used to treat it
# as trusted configuration. Reproduced before these tests existed: a capsule
# whose identity header read "Bearer ${MY_CLOUD_SECRET}" and whose base_url was
# the reporter's own listener made `veridor verify` send the verifier's
# MY_CLOUD_SECRET to that listener (5 requests received, 2 carrying the
# secret); and `verify --read-only` on a DELETE capsule sent 3 DELETEs while
# its own banner said "Pass --read-only to refuse".
# ---------------------------------------------------------------------------

SECRET = "MY-CLOUD-SECRET-SENTINEL-THIS-SHOULD-NEVER-LEAVE-THE-MACHINE"
LOOPBACK = "http://127.0.0.1:8765"
VERIFIER_ENV = {
    "VERIDOR_INVOICE_OWNER_TOKEN": "owner-token",
    "VERIDOR_OTHER_TENANT_TOKEN": "outsider-token",
    "MY_CLOUD_SECRET": SECRET,
    "MY_HOST": "collector.attacker.example",
    # Set, so a refusal of the lower-case name cannot be the "not set" error.
    "veridor_other_tenant_token": "lower-case-secret",
}


def _v010_capsule(base_url: str = LOOPBACK, method: str = "GET") -> dict:
    """A capsule exactly as veridor 0.1.0 wrote it for the demo finding."""
    return {
        "kind": "veridor.capsule",
        "schema_version": 1,
        "created_at": "2026-09-23T18:20:36Z",
        "veridor_version": "0.1.0",
        "claim": {
            "check_id": "invoice-tenant-isolation",
            "check_name": "Invoice tenant isolation",
            "finding_id": "0ec4c5cbd79deaed6e9f",
            "identity": "other_tenant",
            "verdict": "vulnerable",
            "evidence_grade": "confirmed",
            "statement": "Identity 'other_tenant' received HTTP 200.",
            "observed_in_run": "20260923T182030Z-71e80e",
        },
        "scope": "Veridor evaluates the expectations you declared.",
        "target": {"base_url": base_url, "timeout_seconds": 3},
        "identities": {
            "anonymous": {"headers": {}},
            "invoice_owner": {
                "headers": {"Authorization": "Bearer ${VERIDOR_INVOICE_OWNER_TOKEN}"},
                "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
            },
            "other_tenant": {
                "headers": {"Authorization": "Bearer ${VERIDOR_OTHER_TENANT_TOKEN}"},
                "marker": "vdr-Bq3Wm8Ke5Tz1Yx7Rn2Hd4Vs6",
                "marker_probe": {"method": "GET", "path": "/api/invoices/inv-200"},
            },
        },
        "check": {
            "id": "invoice-tenant-isolation",
            "name": "Invoice tenant isolation",
            "request": {"method": method, "path": "/api/invoices/inv-100"},
            "expect": {
                "invoice_owner": {"status": [200], "contains_marker": "invoice_owner"},
                "other_tenant": {"status": [404], "excludes_marker": "invoice_owner"},
                "anonymous": {"status": [401]},
            },
        },
        "requires_environment": [
            "VERIDOR_INVOICE_OWNER_TOKEN",
            "VERIDOR_OTHER_TENANT_TOKEN",
        ],
        "how_to_verify": ["Run: veridor verify <this file> [--base-url https://your-instance]"],
    }


def _evil_capsule() -> dict:
    """The reproduction: a capsule that names a variable of the verifier's
    choosing -- no, of the REPORTER's choosing -- and its own collector."""
    evil = _v010_capsule()
    evil["identities"]["other_tenant"]["headers"]["Authorization"] = "Bearer ${MY_CLOUD_SECRET}"
    evil["requires_environment"] = sorted(evil["requires_environment"] + ["MY_CLOUD_SECRET"])
    return evil


class _RecordingOpener:
    """Stands in for ``core._OPENER``, the one object every request goes through.

    It records what would have gone on the wire and raises the transport error
    an unreachable target raises, so the engine runs to completion unchanged.
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def open(self, request, timeout=None):  # noqa: A003 - mirrors OpenerDirector
        self.requests.append(
            {
                "method": request.get_method(),
                "url": request.full_url,
                "headers": {k.lower(): v for k, v in request.header_items()},
                "body": request.data or b"",
            }
        )
        raise URLError("recorded by the test; nothing was sent")

    def carried(self, value: str) -> list[dict]:
        return [
            entry
            for entry in self.requests
            if value in entry["url"]
            or any(value in header for header in entry["headers"].values())
            or value.encode() in entry["body"]
        ]


def _verify(document: dict, *flags: str, env: dict | None = None, opener=None) -> dict:
    opener = _RecordingOpener() if opener is None else opener
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "proof.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        argv = ["verify", str(path), "--output-dir", str(root / "out")]
        argv += [flag.replace("{root}", str(root)) for flag in flags]
        with patch.dict(os.environ, VERIFIER_ENV if env is None else env):
            with patch.object(core, "_OPENER", opener):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = veridor_main(argv)
        written = {
            str(p.relative_to(root)): p.read_text(encoding="utf-8")
            for p in root.rglob("*")
            if p.is_file() and p.suffix in {".json", ".sarif"} and p != path
            and "out" not in p.relative_to(root).parts
        }
        return {
            "code": code,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "requests": opener.requests,
            "opener": opener,
            "path": str(path),
            "root": str(root),
            "written": written,
        }


class _TargetOpener:
    """Stands in for ``core._OPENER`` and ANSWERS, like the demo target would.

    ``answer(method, path, authorization)`` returns ``(status, body)``. A
    non-2xx status is raised as the ``HTTPError`` the real opener raises, so
    the engine grades exactly what it grades on the wire.
    """

    def __init__(self, answer) -> None:
        self.answer = answer
        self.requests: list[dict] = []

    def open(self, request, timeout=None):  # noqa: A003 - mirrors OpenerDirector
        authorization = request.get_header("Authorization")
        self.requests.append({"url": request.full_url, "authorization": authorization})
        status, payload = self.answer(request.get_method(), urlsplit(request.full_url).path,
                                      authorization)
        body = json.dumps(payload).encode()
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
        if 200 <= status < 300:
            return urllib.response.addinfourl(io.BytesIO(body), headers, request.full_url, status)
        raise HTTPError(request.full_url, status, "refused", headers, io.BytesIO(body))


def _demo_target(*, vulnerable: bool):
    """The demo invoice API for _v010_capsule(): an unknown token draws 401."""
    owner_marker = _v010_capsule()["identities"]["invoice_owner"]["marker"]
    other_marker = _v010_capsule()["identities"]["other_tenant"]["marker"]

    def answer(method, path, authorization):
        if not authorization:
            return 401, {"error": "authentication required"}
        if authorization not in ("Bearer owner-token", "Bearer outsider-token"):
            return 401, {"error": "unknown credential"}
        if path == "/api/invoices/inv-100":
            if authorization == "Bearer owner-token" or vulnerable:
                return 200, {"id": "inv-100", "customer_ref": owner_marker}
            return 404, {"error": "not found"}
        if path == "/api/invoices/inv-200" and authorization == "Bearer outsider-token":
            return 200, {"id": "inv-200", "customer_ref": other_marker}
        return 404, {"error": "not found"}

    return answer


def _proxy_407(method, path, authorization):
    """An authenticating proxy urllib cannot satisfy: 407 to every request."""
    return 407, {"error": "proxy authentication required"}


class VerifyMeasuresTheClaimTest(unittest.TestCase):
    """`verify` end to end, in process, against a target that answers.

    NOT_REPRODUCED used to be printed, exit 0, whenever nothing reproduced --
    including when nothing was measured. Reproduced on the wire before this
    class existed: a vulnerable target behind a proxy answering 407 received
    0 requests and `verify` said "the declared expectation held on this
    target"; with the verifier's VERIDOR_* tokens stale the vulnerable target
    answered 401 to both, and the same sentence was printed.
    """

    def _verify(self, answer, *flags: str, env: dict | None = None,
                document: dict | None = None) -> dict:
        opener = _TargetOpener(answer)
        result = _verify(document or _v010_capsule(), *flags, env=env, opener=opener)
        result["answered"] = opener.requests
        return result

    def _stale(self, **names: str) -> dict:
        env = dict(VERIFIER_ENV)
        env.update(names)
        return env

    def test_control_a_vulnerable_target_is_confirmed(self) -> None:
        result = self._verify(_demo_target(vulnerable=True))
        self.assertEqual(result["code"], 1, result["stdout"] + result["stderr"])
        self.assertIn("Veridor capsule — CONFIRMED", result["stdout"])

    def test_control_a_fixed_target_is_not_reproduced(self) -> None:
        result = self._verify(_demo_target(vulnerable=False))
        self.assertEqual(result["code"], 0, result["stdout"] + result["stderr"])
        self.assertIn("Veridor capsule — NOT_REPRODUCED", result["stdout"])

    def test_a_proxy_answering_407_is_inconclusive(self) -> None:
        result = self._verify(_proxy_407)
        self.assertTrue(result["answered"])
        self.assertEqual(result["code"], 2, result["stdout"])
        self.assertIn("Veridor capsule — INCONCLUSIVE", result["stdout"])
        self.assertNotIn("NOT_REPRODUCED", result["stdout"])
        self.assertIn("HTTP 407", result["stdout"])

    def test_stale_tokens_against_a_vulnerable_target_are_inconclusive(self) -> None:
        stale = self._stale(VERIDOR_INVOICE_OWNER_TOKEN="expired-1",
                            VERIDOR_OTHER_TENANT_TOKEN="expired-2")
        result = self._verify(_demo_target(vulnerable=True), env=stale)
        self.assertEqual(result["code"], 2, result["stdout"])
        self.assertIn("INCONCLUSIVE", result["stdout"])
        self.assertIn("'invoice_owner' received HTTP 401", result["stdout"])

    def test_a_stale_token_for_the_claimed_identity_alone_is_inconclusive(self) -> None:
        stale = self._stale(VERIDOR_OTHER_TENANT_TOKEN="expired-2")
        for vulnerable in (True, False):
            with self.subTest(vulnerable=vulnerable):
                result = self._verify(_demo_target(vulnerable=vulnerable), env=stale)
                self.assertEqual(result["code"], 2, result["stdout"])
                self.assertIn("'other_tenant' received HTTP 401", result["stdout"])

    def test_a_denial_a_fabricated_credential_also_drew_is_inconclusive(self) -> None:
        """Declared [401, 404], so the stale token's 401 matches the
        declaration -- and the sham credential got the same 401, so the denial
        says nothing about whether the target recognised the identity."""
        document = _v010_capsule()
        document["check"]["expect"]["other_tenant"]["status"] = [401, 404]
        stale = self._stale(VERIDOR_OTHER_TENANT_TOKEN="expired-2")
        result = self._verify(_demo_target(vulnerable=True), env=stale, document=document)
        self.assertEqual(result["code"], 2, result["stdout"])
        self.assertIn("'other_tenant'", result["stdout"])
        self.assertIn("fabricated", result["stdout"])
        control = self._verify(_demo_target(vulnerable=False), document=document)
        self.assertEqual(control["code"], 0, control["stdout"])

    def test_a_proxy_answering_200_reads_as_a_suspected_confirmed(self) -> None:
        """Documented, not changed (README, verify): something that answers
        every request with 200 draws CONFIRMED, and nothing in the run tells
        it from an endpoint that serves anyone. What the README tells the
        reader to look at is the grade on the verdict line, so that is held
        here: 'suspected', where a marker-backed CONFIRMED says nothing."""
        def everything_200(method, path, authorization):
            return 200, {"html": "Access denied by corporate proxy policy"}

        def serves_anyone(method, path, authorization):
            return 200, {"id": "inv-100", "customer_ref": "maintainer-own-data"}

        verdicts = []
        for answer in (everything_200, serves_anyone):
            result = self._verify(answer)
            self.assertEqual(result["code"], 1, result["stderr"][-300:])
            verdict = next(line for line in result["stdout"].split("\n")
                           if line.startswith("  CONFIRMED: "))
            self.assertIn("here it is 'suspected'", verdict)
            verdicts.append(verdict)
        self.assertEqual(verdicts[0], verdicts[1])
        control = self._verify(_demo_target(vulnerable=True))
        self.assertEqual(control["code"], 1)
        self.assertIn("  CONFIRMED: the declared expectation failed here as well.\n",
                      control["stdout"])

    def test_with_liveness_off_the_verdict_says_what_it_did_not_check(self) -> None:
        result = self._verify(_demo_target(vulnerable=False), "--no-prove-liveness")
        self.assertEqual(result["code"], 0, result["stdout"])
        self.assertIn("--no-prove-liveness", result["stdout"])

    def test_a_write_capsule_needs_its_denied_identity_proven_live(self) -> None:
        """The rule for a write, as the README states it.

        No fabricated credential is sent with a DELETE, and a capsule holds one
        check, so the denied identity's own marker_probe is the only thing that
        can prove its credential live. With it, a fixed target is
        NOT_REPRODUCED; without it, the denial could be an expired token and
        the verdict is INCONCLUSIVE, naming the marker_probe as the remedy.
        """
        cases = (("with marker_probe", True, 0, "NOT_REPRODUCED"),
                 ("without", False, 2, "INCONCLUSIVE"))
        for label, probe, code, verdict in cases:
            with self.subTest(case=label):
                document = _v010_capsule(method="DELETE")
                if not probe:
                    del document["identities"]["other_tenant"]["marker_probe"]
                result = self._verify(_demo_target(vulnerable=False),
                                      "--base-url", LOOPBACK, document=document)
                self.assertEqual(result["code"], code, result["stdout"])
                self.assertIn(f"Veridor capsule — {verdict}", result["stdout"])
                if not probe:
                    self.assertIn("no credential Veridor fabricated was sent",
                                  result["stdout"])
                    self.assertIn("marker_probe", result["stdout"])

    def _scalar_capsule_from_the_writer(self) -> dict:
        """What `veridor capsule` writes from a config in the schema's
        single-integer status form (``"status": 404``)."""
        source = _v010_capsule()
        config = {
            "version": 1,
            "target": source["target"],
            "identities": source["identities"],
            "checks": [source["check"]],
        }
        for expectation in config["checks"][0]["expect"].values():
            expectation["status"] = expectation["status"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "veridor.json").write_text(json.dumps(config), encoding="utf-8")
            out = root / "proof.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = veridor_main([
                    "capsule", "--config", str(root / "veridor.json"),
                    "--check", "invoice-tenant-isolation", "--output", str(out),
                ])
            self.assertEqual(code, 0)
            return json.loads(out.read_text(encoding="utf-8"))

    def test_a_capsule_written_from_a_single_integer_status_verifies(self) -> None:
        """Reproduced on the wire (two demo servers): `veridor capsule` from a
        config written ``"status": 404`` -- the schema's documented shorthand --
        and `verify` of that untouched file against the fixed target exited
        70, "internal error ... a bug in Veridor", where it must say
        NOT_REPRODUCED. Against the vulnerable target it said CONFIRMED."""
        document = self._scalar_capsule_from_the_writer()
        fixed = self._verify(_demo_target(vulnerable=False), document=document)
        self.assertEqual(fixed["code"], 0, fixed["stdout"] + fixed["stderr"][-600:])
        self.assertIn("Veridor capsule — NOT_REPRODUCED", fixed["stdout"])
        self.assertNotIn("internal error", fixed["stderr"])
        vulnerable = self._verify(_demo_target(vulnerable=True), document=document)
        self.assertEqual(vulnerable["code"], 1, vulnerable["stdout"])
        self.assertIn("Veridor capsule — CONFIRMED", vulnerable["stdout"])

    def test_an_edited_single_integer_status_verifies(self) -> None:
        """The same shorthand edited into a capsule by hand, past the writer:
        ``load`` reads it as the one-element list the schema says it is."""
        document = _v010_capsule()
        for expectation in document["check"]["expect"].values():
            expectation["status"] = expectation["status"][0]
        for vulnerable, code, verdict in ((False, 0, "NOT_REPRODUCED"), (True, 1, "CONFIRMED")):
            with self.subTest(vulnerable=vulnerable):
                result = self._verify(_demo_target(vulnerable=vulnerable), document=document)
                self.assertEqual(result["code"], code, result["stdout"] + result["stderr"][-600:])
                self.assertIn(f"Veridor capsule — {verdict}", result["stdout"])

    def test_control_a_status_that_is_not_a_status_is_refused_before_sending(self) -> None:
        """Reading the shorthand must not widen what loads: a status that is
        not an HTTP status is still exit 2, with nothing sent."""
        for bad in ("404", True, [], [99], [True], ["404"], None, 404.0):
            with self.subTest(bad=bad):
                document = _v010_capsule()
                document["check"]["expect"]["other_tenant"]["status"] = bad
                result = self._verify(_demo_target(vulnerable=False), document=document)
                self.assertEqual(result["code"], 2, result["stdout"] + result["stderr"][-600:])
                self.assertEqual(result["answered"], [])
                self.assertNotIn("internal error", result["stderr"])
                self.assertIn("'other_tenant'", result["stderr"])


class VerifyEnvironmentTest(unittest.TestCase):
    """A capsule may only read VERIDOR_* variables, derived from its content."""

    def test_the_exfiltration_capsule_is_refused_before_anything_is_sent(self) -> None:
        result = _verify(_evil_capsule())
        self.assertEqual(result["requests"], [], "a request left the machine")
        self.assertEqual(result["code"], 2)
        self.assertIn("MY_CLOUD_SECRET", result["stderr"])
        self.assertIn("VERIDOR_", result["stderr"])
        self.assertNotIn(SECRET, result["stderr"] + result["stdout"])

    def test_every_place_a_reference_can_hide_is_checked(self) -> None:
        def at(mutate):
            document = _v010_capsule()
            mutate(document)
            return document

        places = {
            "a non-credential identity header": lambda d: d["identities"]["other_tenant"][
                "headers"
            ].update({"X-Trace": "${MY_CLOUD_SECRET}"}),
            "the check path": lambda d: d["check"]["request"].update(
                {"path": "/api/invoices/${MY_CLOUD_SECRET}"}
            ),
            "the check query": lambda d: d["check"]["request"].update(
                {"path": "/api/invoices/inv-100?k=${MY_CLOUD_SECRET}"}
            ),
            "a check header": lambda d: d["check"]["request"].update(
                {"headers": {"X-Debug": "${MY_CLOUD_SECRET}"}}
            ),
            "a nested JSON body": lambda d: d["check"]["request"].update(
                {"json": {"a": [{"b": "${MY_CLOUD_SECRET}"}]}}
            ),
            "a raw body": lambda d: d["check"]["request"].update(
                {"body": "token=${MY_CLOUD_SECRET}"}
            ),
            "a marker_probe path": lambda d: d["identities"]["other_tenant"][
                "marker_probe"
            ].update({"path": "/api/${MY_CLOUD_SECRET}"}),
            "the target base_url": lambda d: d["target"].update(
                {"base_url": "http://127.0.0.1:8765/${MY_CLOUD_SECRET}"}
            ),
            "a lower-case veridor_ name": lambda d: d["identities"]["other_tenant"][
                "headers"
            ].update({"Authorization": "Bearer ${veridor_other_tenant_token}"}),
        }
        for place, mutate in places.items():
            with self.subTest(place=place):
                result = _verify(at(mutate))
                self.assertEqual(result["requests"], [], place)
                self.assertEqual(result["code"], 2)
                self.assertRegex(result["stderr"], r"MY_CLOUD_SECRET|veridor_other_tenant_token")

    def test_the_capsule_s_own_list_is_not_trusted(self) -> None:
        """requires_environment is re-derived. A capsule that declares nothing
        still has its references found; one that declares a foreign name it
        does not use has nothing to expand and sends nothing secret."""
        silent = _evil_capsule()
        silent["requires_environment"] = []
        self.assertEqual(_verify(silent)["requests"], [])

        declared_only = _v010_capsule()
        declared_only["requires_environment"] = ["MY_CLOUD_SECRET"]
        result = _verify(declared_only)
        self.assertTrue(result["requests"])
        self.assertEqual(result["opener"].carried(SECRET), [])

    def test_the_verifier_is_told_which_variables_are_read(self) -> None:
        document = _v010_capsule()
        document["requires_environment"] = []
        result = _verify(document)
        self.assertIn("VERIDOR_INVOICE_OWNER_TOKEN", result["stderr"])
        self.assertIn("VERIDOR_OTHER_TENANT_TOKEN", result["stderr"])

    def test_a_capsule_written_by_0_1_0_still_verifies(self) -> None:
        """Control: the refusal is about foreign names, not about capsules."""
        result = _verify(_v010_capsule())
        self.assertTrue(result["requests"], result["stderr"])
        self.assertTrue(result["opener"].carried("Bearer owner-token"))
        self.assertTrue(all(r["url"].startswith(LOOPBACK) for r in result["requests"]))
        # Unreachable (the recorder refuses every request): INCONCLUSIVE, exit 2.
        self.assertIn("INCONCLUSIVE", result["stdout"])

    def test_an_empty_verifier_variable_is_refused(self) -> None:
        env = dict(VERIFIER_ENV, VERIDOR_OTHER_TENANT_TOKEN="")
        result = _verify(_v010_capsule(), env=env)
        self.assertEqual(result["requests"], [])
        self.assertEqual(result["code"], 2)
        self.assertIn("'VERIDOR_OTHER_TENANT_TOKEN' is set but empty", result["stderr"])


class VerifyTargetTest(unittest.TestCase):
    """A capsule names the reporter's target. Requests go there only when it is
    this machine's loopback; anywhere else needs the verifier's --base-url."""

    def test_a_non_loopback_capsule_target_needs_an_explicit_base_url(self) -> None:
        for base_url in (
            "https://collector.attacker.example",
            "http://10.0.0.5:8080",
            "http://192.168.1.10",
            "http://0.0.0.0:8765",
            "http://localhost.attacker.example:8765",
            "http://evil.localhost:8765",
            "http://2130706433:8765",
        ):
            with self.subTest(base_url=base_url):
                result = _verify(_v010_capsule(base_url))
                self.assertEqual(result["requests"], [])
                self.assertEqual(result["code"], 2)
                self.assertIn("--base-url", result["stderr"])
                self.assertIn("the instance YOU are verifying", result["stderr"])
                self.assertIn("REPORTER's target", result["stderr"])

    def test_an_explicit_base_url_is_where_the_requests_go(self) -> None:
        result = _verify(
            _v010_capsule("https://collector.attacker.example"), "--base-url", LOOPBACK
        )
        self.assertTrue(result["requests"], result["stderr"])
        self.assertTrue(all(r["url"].startswith(LOOPBACK) for r in result["requests"]))

    def test_a_loopback_capsule_target_needs_no_flag(self) -> None:
        for base_url in ("http://127.0.0.1:8765", "http://localhost:8765", "http://[::1]:8765"):
            with self.subTest(base_url=base_url):
                result = _verify(_v010_capsule(base_url))
                self.assertTrue(result["requests"], result["stderr"])


class VerifyWriteTest(unittest.TestCase):
    def test_read_only_refuses_a_mutating_capsule_before_sending(self) -> None:
        for flags in ((), ("--base-url", LOOPBACK)):
            with self.subTest(flags=flags):
                result = _verify(_v010_capsule(method="DELETE"), "--read-only", *flags)
                self.assertEqual(result["requests"], [])
                self.assertEqual(result["code"], 2)
                self.assertIn("--read-only refuses DELETE", result["stderr"])

    def test_read_only_lets_a_safe_capsule_through(self) -> None:
        """Control: --read-only refuses writes, not capsules."""
        result = _verify(_v010_capsule(), "--read-only")
        self.assertTrue(result["requests"])
        self.assertEqual({r["method"] for r in result["requests"]}, {"GET"})

    def test_a_mutating_capsule_needs_an_explicit_base_url_even_on_loopback(self) -> None:
        """Loopback is not harmless: an untrusted DELETE can reach a local admin
        service. Writes never go to an address the capsule chose."""
        result = _verify(_v010_capsule(method="DELETE"))
        self.assertEqual(result["requests"], [])
        self.assertEqual(result["code"], 2)
        self.assertIn("DELETE", result["stderr"])
        self.assertIn("--base-url", result["stderr"])

    def test_an_explicit_base_url_licenses_the_write(self) -> None:
        result = _verify(_v010_capsule(method="DELETE"), "--base-url", LOOPBACK)
        self.assertIn("DELETE", {r["method"] for r in result["requests"]})

    def test_a_session_login_is_a_write(self) -> None:
        document = _v010_capsule()
        document["identities"]["invoice_owner"] = {
            "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
            "session": {
                "login": [
                    {
                        "method": "POST",
                        "path": "/login",
                        "body": "password=${VERIDOR_INVOICE_OWNER_TOKEN}",
                        "expect_status": [200],
                    }
                ],
                "establishes": {"cookie": "sid"},
            },
        }
        result = _verify(document)
        self.assertEqual(result["requests"], [])
        self.assertEqual(result["code"], 2)
        self.assertIn("POST", result["stderr"])


class VerifyFlagTest(unittest.TestCase):
    """Every run flag verify does not honour is refused, never ignored."""

    def test_run_only_flags_are_refused_not_ignored(self) -> None:
        cases = {
            "--config": ["--config", "veridor.json"],
            "--baseline": ["--baseline", "baseline.json"],
            "--fail-on": ["--fail-on", "any"],
            "--require-complete": ["--require-complete"],
            "--require-clean-teardown": ["--require-clean-teardown"],
            "--openapi": ["--openapi", "openapi.json"],
            "--allow-no-matches": ["--allow-no-matches"],
        }
        for flag, argv in cases.items():
            with self.subTest(flag=flag):
                result = _verify(_v010_capsule(), *argv)
                self.assertEqual(result["requests"], [])
                self.assertEqual(result["code"], 2)
                self.assertIn(flag, result["stderr"])

    def test_every_parser_option_is_honoured_or_refused_never_crashed_on(self) -> None:
        """Derived from the real parser, not a hand list: the hand list above
        was written before ``--report`` existed, and typing ``--report`` next to
        a capsule crashed the flag detector (exit 70) instead of refusing it.
        Any option added to ``run`` later is covered the day it lands."""
        import argparse

        from veridor import cli

        parser = cli._parser()
        subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        run = subparsers.choices["run"]
        refused = [
            action for action in run._actions
            if action.option_strings
            and action.dest not in cli._CAPSULE_OPTIONS
            and action.dest != "help"
        ]
        self.assertTrue(any(action.dest == "reports" for action in refused), [a.dest for a in refused])
        for action in refused:
            flag = action.option_strings[-1]
            argv = [flag]
            if action.nargs != 0:
                if action.choices:
                    argv.append(sorted(action.choices)[0])
                elif action.dest == "reports":
                    argv.append("junit={root}/report.xml")
                elif action.type in (int, float, cli._wait_seconds):
                    # A value the option's own type accepts, so the refusal
                    # measured is the capsule's, not argparse's.
                    argv.append("1")
                else:
                    argv.append("{root}/value")
            with self.subTest(flag=flag):
                result = _verify(_v010_capsule(), *argv)
                self.assertEqual(result["code"], 2, result["stderr"][-400:])
                self.assertEqual(result["requests"], [])
                self.assertIn(flag, result["stderr"])
                self.assertIn(cli._CAPSULE_OPTIONS_TEXT, result["stderr"])

    def test_the_default_value_typed_explicitly_is_still_refused(self) -> None:
        """`--fail-on new+confirmed` is the default; typing it is still asking
        for a policy a capsule run does not apply."""
        result = _verify(_v010_capsule(), "--fail-on", "new+confirmed")
        self.assertEqual(result["requests"], [])
        self.assertEqual(result["code"], 2)
        self.assertIn("--fail-on", result["stderr"])

    def test_json_and_sarif_are_written_and_name_the_capsule(self) -> None:
        result = _verify(
            _v010_capsule(), "--json", "{root}/run.json", "--sarif", "{root}/run.sarif"
        )
        self.assertIn("run.json", result["written"], result["stderr"])
        self.assertIn("run.sarif", result["written"])
        document = json.loads(result["written"]["run.json"])
        self.assertEqual(document["config"], result["path"])
        self.assertTrue(document["findings"])
        for finding in document["findings"]:
            self.assertEqual(finding["location"], result["path"])
        sarif = json.loads(result["written"]["run.sarif"])
        uris = {
            location["physicalLocation"]["artifactLocation"]["uri"]
            for run in sarif["runs"]
            for item in run["results"]
            for location in item["locations"]
        }
        # The capsule, not the deleted temporary config -- and by name, not by
        # absolute path. This asserted the absolute path itself, which is the
        # local filesystem layout SARIF must not carry: the capsule lives in a
        # temporary directory outside the working tree, so its file name is
        # all that may be written.
        self.assertEqual(uris, {Path(result["path"]).name})
        self.assertNotIn(result["root"], result["written"]["run.sarif"])
        self.assertNotIn("capsule-config.json", result["written"]["run.json"])

    def test_no_prove_liveness_is_honoured(self) -> None:
        with_controls = _verify(_v010_capsule())
        without = _verify(_v010_capsule(), "--no-prove-liveness")
        self.assertTrue(with_controls["opener"].carried("veridor-sham-"))
        self.assertEqual(without["opener"].carried("veridor-sham-"), [])

    def test_json_may_not_overwrite_the_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(_v010_capsule()), encoding="utf-8")
            stderr = io.StringIO()
            opener = _RecordingOpener()
            with patch.dict(os.environ, VERIFIER_ENV), patch.object(core, "_OPENER", opener):
                with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    code = veridor_main(["verify", str(path), "--json", str(path),
                                         "--output-dir", str(Path(directory) / "out")])
            self.assertEqual(code, 2)
            self.assertEqual(opener.requests, [])
            self.assertEqual(json.loads(path.read_text()), _v010_capsule())


def _failing_handler(method, path, authorization):
    """The demo target, vulnerable, whose handler fails for the outsider.

    The shape of the verification that rendered "Gate passed (exit 0)": the
    claimed identity's probe draws a 500, which grades inconclusive -- not a
    finding the default ``--fail-on`` policy gates on -- so re-deriving a gate
    from the findings passed what `verify` had exited 2 on.
    """
    if path == "/api/invoices/inv-100" and authorization == "Bearer outsider-token":
        return 500, {"error": "internal"}
    return _demo_target(vulnerable=True)(method, path, authorization)


#: The three verdicts, each with the target that draws it and its exit code.
_VERDICT_TARGETS = (
    ("CONFIRMED", 1, _demo_target(vulnerable=True)),
    ("NOT_REPRODUCED", 0, _demo_target(vulnerable=False)),
    ("INCONCLUSIVE", 2, _failing_handler),
)


class VerifyRecordsItsVerdictTest(unittest.TestCase):
    """What `verify` writes says what `verify` exited with.

    The verdict existed only on stdout. `verify` persisted the run of the
    capsule through execute_run as an ordinary run: no gate, no verdict, and
    `config` naming a temporary file deleted before the command returned. So
    `report --from-run .veridor/latest.json` re-derived a gate with the `run`
    defaults and printed "Gate passed (exit 0)" over an INCONCLUSIVE
    verification that had exited 2, and `serve` listed it as a plain run.
    """

    def _verify(self, answer, *, json_flag: bool = True) -> dict:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        path = root / "proof.json"
        path.write_text(json.dumps(_v010_capsule()), encoding="utf-8")
        out = root / "out"
        stdout, stderr = io.StringIO(), io.StringIO()
        flags = ["--json", str(root / "run.json")] if json_flag else []
        with patch.dict(os.environ, VERIFIER_ENV), \
                patch.object(core, "_OPENER", _TargetOpener(answer)):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(["verify", str(path), "--output-dir", str(out), *flags])
        latest = (out / "latest.json").read_text(encoding="utf-8")
        history = list((out / "runs").glob("*.json"))
        self.assertEqual(len(history), 1)
        return {
            "code": code, "path": str(path), "root": root, "latest_path": out / "latest.json",
            "latest_text": latest, "latest": json.loads(latest),
            "history": json.loads(history[0].read_text(encoding="utf-8")),
            "json": (json.loads((root / "run.json").read_text(encoding="utf-8"))
                     if json_flag else None),
            "output": stdout.getvalue() + stderr.getvalue(),
        }

    def _report(self, path: Path, fmt: str) -> tuple[int, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = veridor_main(["report", "--from-run", str(path), "--format", fmt])
        return code, stdout.getvalue() + stderr.getvalue()

    def test_every_verdict_is_written_with_the_exit_code_verify_returned(self) -> None:
        for verdict, exit_code, answer in _VERDICT_TARGETS:
            with self.subTest(verdict=verdict):
                result = self._verify(answer)
                self.assertEqual(result["code"], exit_code, result["output"])
                self.assertIn(f"Veridor capsule — {verdict}", result["output"])
                for where in ("latest", "history", "json"):
                    document = result[where]
                    self.assertEqual(document["capsule"]["verdict"], verdict, where)
                    self.assertEqual(document["capsule"]["exit_code"], exit_code, where)
                    self.assertEqual(document["capsule"]["check_id"],
                                     "invoice-tenant-isolation")
                    self.assertEqual(document["gate"]["exit_code"], exit_code, where)
                    self.assertIsNone(document["gate"]["fail_on"])
                    # The capsule that ran, not the temporary config execute_run
                    # loaded, which no longer exists.
                    self.assertEqual(document["config"], result["path"], where)
                    self.assertEqual(document["capsule"]["path"], result["path"], where)
                self.assertNotIn("capsule-config.json", result["latest_text"])
                self.assertEqual(result["latest"], result["history"])
                core.validate_run(result["latest"], source="latest.json")

    def test_the_history_names_the_capsule_when_no_json_is_asked_for(self) -> None:
        """The relabel from the temporary config to the capsule used to run only
        under --json or --sarif, and every other test here passes --json. The
        reported case had neither: `verify proof.json` alone left latest.json
        citing a capsule-config.json that no longer existed."""
        result = self._verify(_failing_handler, json_flag=False)
        self.assertEqual(result["code"], 2, result["output"])
        for where in ("latest", "history"):
            self.assertEqual(result[where]["config"], result["path"], where)
            self.assertEqual(result[where]["capsule"]["verdict"], "INCONCLUSIVE", where)
        self.assertNotIn("capsule-config.json", result["latest_text"])

    def test_report_renders_the_verdict_and_never_a_pass_over_inconclusive(self) -> None:
        rendered = {}
        for verdict, exit_code, answer in _VERDICT_TARGETS:
            result = self._verify(answer)
            code, text = self._report(result["latest_path"], "markdown")
            self.assertEqual(code, 0, text)
            rendered[verdict] = (exit_code, text, result)
        inconclusive = rendered["INCONCLUSIVE"][1]
        self.assertIn("**Capsule INCONCLUSIVE (exit 2):**", inconclusive)
        self.assertIn("This is not a pass.", inconclusive)
        self.assertIn("HTTP 500", inconclusive)
        self.assertNotIn("passed", inconclusive)
        # Re-derived from the findings alone this was "Gate passed": the 500
        # graded inconclusive, which the default policy does not gate on.
        self.assertNotIn("re-derived", inconclusive)
        confirmed = rendered["CONFIRMED"][1]
        self.assertIn("**Capsule CONFIRMED (exit 1):** the claim reproduced", confirmed)
        not_reproduced = rendered["NOT_REPRODUCED"][1]
        verdict_line = next(line for line in not_reproduced.splitlines()
                            if line.startswith("**Capsule"))
        self.assertIn("NOT\\_REPRODUCED (exit 0)", verdict_line)
        self.assertIn("not proof the boundary is enforced", verdict_line)
        for word in ("passed", "safe", "secure", "verified"):
            self.assertNotIn(word, verdict_line.lower())
        for verdict, (exit_code, text, _) in rendered.items():
            with self.subTest(verdict=verdict):
                self.assertIn("`veridor verify` exits 1 for CONFIRMED", text)
                self.assertNotIn("--fail-on", text)
                self.assertNotIn("**Gate", text)

        # JUnit: the gate case fails exactly when verify did not exit 0.
        for verdict, (exit_code, _, result) in rendered.items():
            with self.subTest(verdict=verdict, fmt="junit"):
                code, xml = self._report(result["latest_path"], "junit")
                self.assertEqual(code, 0, xml)
                self.assertIn(f'name="veridor.capsule.verdict" value="{verdict}"', xml)
                self.assertEqual(f'type="exit-{exit_code}"' in xml, exit_code != 0, xml)
                self.assertNotIn("--fail-on None", xml)

    def test_a_capsule_document_that_disagrees_with_itself_is_refused(self) -> None:
        """An edited verdict, exit code or gate is refused rather than rendered:
        the one thing a reader must not get is a pass the command never gave."""
        result = self._verify(_failing_handler)
        edits = {
            "verdict softened": lambda d: d["capsule"].update(verdict="NOT_REPRODUCED"),
            "exit code softened": lambda d: d["capsule"].update(exit_code=0),
            "gate removed": lambda d: d.pop("gate"),
            "gate softened": lambda d: d["gate"].update(exit_code=0, reasons=[]),
            "unknown verdict": lambda d: d["capsule"].update(verdict="PROBABLY_FINE"),
        }
        path = result["root"] / "edited.json"
        control = dict(result["latest"])
        path.write_text(json.dumps(control), encoding="utf-8")
        code, text = self._report(path, "markdown")
        self.assertEqual(code, 0, text)
        for name, edit in edits.items():
            with self.subTest(edit=name):
                document = json.loads(result["latest_text"])
                edit(document)
                path.write_text(json.dumps(document), encoding="utf-8")
                code, text = self._report(path, "markdown")
                self.assertEqual(code, 2, text)
                self.assertNotIn("passed", text)

    def test_serve_lists_the_verdict_and_an_ordinary_run_lists_none(self) -> None:
        from veridor import server

        result = self._verify(_failing_handler)
        summary = server._run_summary(result["latest"])
        self.assertEqual(summary["capsule"],
                         {"verdict": "INCONCLUSIVE", "check_id": "invoice-tenant-isolation"})
        self.assertEqual(summary["gate_exit_code"], 2)
        ordinary = dict(result["latest"])
        del ordinary["capsule"]
        self.assertIsNone(server._run_summary(ordinary)["capsule"])


class WriterNamesTest(unittest.TestCase):
    """`veridor capsule` must write what `veridor verify` accepts."""

    def _config(self) -> dict:
        config = _config("Bearer ${MY_TOKEN}")
        config["identities"]["attacker"]["headers"]["Authorization"] = "Bearer ${ATTACKER_KEY}"
        config["checks"][0]["request"]["headers"] = {"X-Tenant": "${TENANT_ID}"}
        return config

    def test_foreign_references_are_renamed_to_verifier_names(self) -> None:
        built = capsule.build(self._config(), "tenant-isolation")
        self.assertEqual(
            built["identities"]["owner"]["headers"]["Authorization"],
            "Bearer ${VERIDOR_OWNER_MY_TOKEN}",
        )
        # The identity prefix is not doubled.
        self.assertEqual(
            built["identities"]["attacker"]["headers"]["Authorization"],
            "Bearer ${VERIDOR_ATTACKER_KEY}",
        )
        self.assertEqual(built["check"]["request"]["headers"]["X-Tenant"], "${VERIDOR_TENANT_ID}")
        self.assertEqual(
            built["requires_environment"],
            ["VERIDOR_ATTACKER_KEY", "VERIDOR_OWNER_MY_TOKEN", "VERIDOR_TENANT_ID"],
        )
        blob = json.dumps(built)
        for name in re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", blob):
            self.assertRegex(name, r"^VERIDOR_[A-Z0-9_]+$")
        self.assertIn(
            "Export: VERIDOR_ATTACKER_KEY, VERIDOR_OWNER_MY_TOKEN, VERIDOR_TENANT_ID",
            built["how_to_verify"],
        )

    def test_the_input_configuration_is_not_modified(self) -> None:
        config = self._config()
        before = copy.deepcopy(config)
        capsule.build(config, "tenant-isolation")
        self.assertEqual(config, before)

    def test_what_the_writer_emits_the_verifier_accepts(self) -> None:
        built = capsule.build(self._config(), "tenant-isolation")
        env = {
            "VERIDOR_OWNER_MY_TOKEN": "owner-token",
            "VERIDOR_ATTACKER_KEY": "attacker-token",
            "VERIDOR_TENANT_ID": "acme",
        }
        result = _verify(built, env=env)
        self.assertTrue(result["requests"], result["stderr"])
        self.assertTrue(result["opener"].carried("Bearer owner-token"))

    def test_existing_verifier_names_are_kept_and_never_collided_with(self) -> None:
        config = _config("Bearer ${MY_TOKEN}")
        config["identities"]["owner"]["headers"]["X-Other"] = "${VERIDOR_OWNER_MY_TOKEN}"
        built = capsule.build(config, "tenant-isolation")
        headers = built["identities"]["owner"]["headers"]
        self.assertEqual(headers["X-Other"], "${VERIDOR_OWNER_MY_TOKEN}")
        self.assertEqual(headers["Authorization"], "Bearer ${VERIDOR_OWNER_MY_TOKEN_2}")

    def test_the_capsule_command_tells_the_reporter_what_was_renamed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "veridor.json").write_text(json.dumps(self._config()), encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(["capsule", "--config", str(root / "veridor.json"),
                                     "--check", "tenant-isolation",
                                     "--output", str(root / "proof.json")])
            self.assertEqual(code, 0, stderr.getvalue())
            text = stdout.getvalue() + stderr.getvalue()
            self.assertIn("MY_TOKEN -> VERIDOR_OWNER_MY_TOKEN", text)


@contextlib.contextmanager
def _listener():
    """A loopback host standing in for the reporter's: records every request."""
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _record(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length) if length else b""
            received.append(
                {"method": self.command, "path": self.path,
                 "headers": dict(self.headers), "body": body}
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = _record  # noqa: N815 - stdlib callback names
        do_POST = _record  # noqa: N815
        do_PUT = _record  # noqa: N815
        do_DELETE = _record  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(httpd)
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", received
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@slow("spawns veridor verify as a subprocess against a loopback listener")
class VerifyEndToEndTest(unittest.TestCase):
    """The exfiltration and write reproductions, run as a subprocess the way a
    maintainer runs `veridor verify`."""

    def _verify(self, document: dict, *flags: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            env = source_path.child_env(**VERIFIER_ENV)
            completed = subprocess.run(
                [sys.executable, "-m", "veridor.cli", "verify", str(path),
                 "--output-dir", str(Path(directory) / "out"), *flags],
                capture_output=True, text=True, env=env, cwd=directory, timeout=120,
            )
        return completed.returncode, completed.stdout + completed.stderr

    def _leaks(self, received: list[dict]) -> list[dict]:
        return [r for r in received if any(SECRET in v for v in r["headers"].values())]

    def test_the_exfiltration_capsule_sends_nothing(self) -> None:
        with _listener() as (url, received):
            evil = _evil_capsule()
            evil["target"]["base_url"] = url
            code, output = self._verify(evil)
        self.assertEqual(received, [], output)
        self.assertEqual(code, 2, output)
        self.assertIn("MY_CLOUD_SECRET", output)

    def test_control_a_veridor_only_capsule_reaches_the_listener(self) -> None:
        """Without this, an empty listener could mean a broken listener."""
        with _listener() as (url, received):
            code, output = self._verify(_v010_capsule(url))
        self.assertTrue(received, output)
        self.assertEqual(self._leaks(received), [])
        self.assertIn("Bearer owner-token", [r["headers"].get("Authorization") for r in received])

    def test_read_only_sends_no_delete(self) -> None:
        with _listener() as (url, received):
            code, output = self._verify(_v010_capsule(url, "DELETE"), "--read-only",
                                        "--base-url", url)
        self.assertEqual(received, [], output)
        self.assertEqual(code, 2, output)
        self.assertIn("--read-only refuses DELETE", output)

    def test_control_the_delete_goes_out_only_with_an_explicit_base_url(self) -> None:
        with _listener() as (url, received):
            refused_code, refused = self._verify(_v010_capsule(url, "DELETE"))
            refused_requests = list(received)
            code, output = self._verify(_v010_capsule(url, "DELETE"), "--base-url", url)
        self.assertEqual(refused_requests, [], refused)
        self.assertEqual(refused_code, 2, refused)
        self.assertIn("DELETE", {r["method"] for r in received}, output)


if __name__ == "__main__":
    unittest.main()
