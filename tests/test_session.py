"""Session state and teardown: isolation, redaction, CSRF, cleanup, blast radius.

The highest-stakes test in this file is ``CookieIsolationTest``. A cookie jar
that leaks across identities turns the attacker's probe into the owner's probe
-- which gets the status the declaration allows for the owner -- or, when a
session is lost, into an anonymous probe, which gets a 401 that matches a
declared denial. Both directions manufacture a SAFE verdict over a live
vulnerability, so isolation is asserted behaviourally against a server-side
request log, and ``test_jar_leak_is_detectable`` proves that assertion can
actually fail.

Everything else defends one of four properties:

* no cookie value, captured secret, or login credential reaches any artifact;
* teardown runs on every code path and can never change a verdict;
* a session that did not establish makes its probes inconclusive, never safe;
* ``--read-only`` refuses before a single byte reaches the target.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import fast, slow  # noqa: E402
from veridor import core, sequence  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402
from veridor.core import ConfigError, execute_run, load_config  # noqa: E402

MARKER_VICTIM = "vdr-Nq4Zt8Wm3Kx7Bv2Ld6Rj9Ph5"
MARKER_ATTACKER = "vdr-Ac7Fg2Hj5Kl8Mn1Qs4Tv6Wy0"

VICTIM_TOKEN = "Bearer victim-token"
ATTACKER_TOKEN = "Bearer attacker-token"

#: Unique, high-entropy, and never legitimately present in a Veridor artifact.
COOKIE_SENTINEL = "K7wQ2fZp9Lm4Rt8XcVb3Nj6Hd0Gs1Ay5"
CSRF_SENTINEL = "T3xR9bN2mQ7wL5kZ8vJ4hC6dF1gP0sYa"
PASSWORD_SENTINEL = "Pw9Zq2Vt6Nb4Xm8Lc3Hj7Rd1Ks5Gf0Ya"  # gitleaks:allow


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class _Log:
    """Every request the target saw, in order, with the headers it carried."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self._lock = threading.Lock()

    def record(self, entry: dict) -> None:
        with self._lock:
            self.entries.append(entry)

    def cookies_for(self, token: str) -> list[str]:
        return [entry["cookie"] for entry in self.entries if entry["auth"] == token]

    def methods(self) -> list[str]:
        return [entry["method"] for entry in self.entries]

    def paths(self, method: str | None = None) -> list[str]:
        return [
            entry["path"]
            for entry in self.entries
            if method is None or entry["method"] == method
        ]


@contextlib.contextmanager
def _server(responder):
    """Run a loopback server and log every request. ``responder(request)``.

    ``request`` is the logged dict; the responder returns
    ``(status, headers, body)`` or ``None`` to drop the connection.
    """
    log = _Log()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            payload = self.rfile.read(length) if length else b""
            entry = {
                "method": self.command,
                "path": self.path,
                "auth": self.headers.get("Authorization", ""),
                "cookie": self.headers.get("Cookie", ""),
                "cookies": self.headers.get_all("Cookie") or [],
                "csrf": self.headers.get("X-CSRFToken", ""),
                "accept": self.headers.get("Accept", ""),
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "body": payload,
            }
            log.record(entry)
            reply = responder(entry)
            if reply is None:
                self.close_connection = True
                return
            status, headers, body = reply
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        do_GET = _dispatch  # noqa: N815 - stdlib callback names
        do_POST = _dispatch  # noqa: N815
        do_PUT = _dispatch  # noqa: N815
        do_DELETE = _dispatch  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(httpd)
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", log
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _who(entry: dict) -> str:
    return "victim" if entry["auth"] == VICTIM_TOKEN else "attacker"


def _session(cookie: str = "sid", **extra) -> dict:
    declaration = {
        "login": [
            {
                "method": "POST",
                "path": "/login",
                "body": f"password={PASSWORD_SENTINEL}",
                "expect_status": [200],
            }
        ],
        "establishes": {"cookie": cookie},
    }
    declaration.update(extra)
    return declaration


def _identities(*, sessions: bool = True, marker: bool = True) -> dict:
    victim: dict = {"headers": {"Authorization": VICTIM_TOKEN}}
    attacker: dict = {"headers": {"Authorization": ATTACKER_TOKEN}}
    if marker:
        victim["marker"] = MARKER_VICTIM
        attacker["marker"] = MARKER_ATTACKER
    if sessions:
        victim["session"] = _session()
        attacker["session"] = _session()
    return {"victim": victim, "attacker": attacker}


def _doc_check() -> dict:
    return {
        "id": "cross-tenant-doc-read",
        "request": {"method": "GET", "path": "/docs/1"},
        "expect": {
            "victim": {"status": [200], "contains_marker": "victim"},
            "attacker": {"status": [403], "excludes_marker": "victim"},
        },
    }


def _config(**overrides) -> dict:
    config = {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
        "identities": _identities(),
        "checks": [_doc_check()],
    }
    config.update(overrides)
    return config


@contextlib.contextmanager
def _written(config: dict, base_url: str | None = None):
    """Write the config to disk so the environment pre-pass really runs."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        if base_url is not None:
            config = json.loads(json.dumps(config))
            config["target"]["base_url"] = base_url
        path = root / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        yield path, root


def _run(config: dict, base_url: str, **kwargs):
    """Execute a run and return ``(result, sessions, output_dir)``."""
    captured: dict[str, sequence.IdentitySession] = {}
    real = sequence.establish_sessions

    def spy(inner):
        established = real(inner)
        captured.update(established)
        return established

    with _written(config, base_url) as (path, root):
        with patch.object(sequence, "establish_sessions", spy):
            result = execute_run(path, output_dir=root / "out", **kwargs)
        yield_root = root / "out"
        # Read every artifact back before the directory disappears.
        artifacts = {
            item: item.read_text(encoding="utf-8")
            for item in yield_root.rglob("*")
            if item.is_file()
        }
    return result, captured, artifacts


def _finding_map(result: dict) -> dict[tuple[str, str], dict]:
    return {
        (finding["check_id"], finding["identity"]): finding
        for finding in result["findings"]
    }


# --------------------------------------------------------------------------
# (a) cookie isolation -- the highest-stakes property in this file
# --------------------------------------------------------------------------


def _isolating_target(entry: dict):
    """Sessions are per-identity; ``/docs/1`` serves the victim's marker only.

    A leaked jar makes the attacker's ``GET /docs/1`` carry ``sid=victim``, and
    the target then hands the attacker the victim's marker -- which grades
    `confirmed` and fails the test loudly, in the right direction.
    """
    if entry["path"] == "/login":
        return 200, [("Set-Cookie", f"sid={_who(entry)}; Path=/")], b"ok"
    if entry["path"] == "/docs/1":
        if entry["cookie"] == "sid=victim":
            return 200, [("Content-Type", "application/json")], json.dumps(
                {"note": MARKER_VICTIM}
            ).encode()
        return 403, [("Content-Type", "application/json")], b'{"error":"denied"}'
    return 404, [], b""


@slow("stands up a loopback HTTP server and runs the engine against it")
class CookieIsolationTest(unittest.TestCase):
    def test_cookie_jar_does_not_leak_between_identities(self) -> None:
        with _server(_isolating_target) as (url, log):
            result, sessions, _ = _run(_config(), url)
        self.assertEqual(result["findings"], [], result["findings"])
        self.assertEqual(result["summary"]["safe"], 2)

        attacker_docs = [
            entry
            for entry in log.entries
            if entry["auth"] == ATTACKER_TOKEN and entry["path"] == "/docs/1"
        ]
        self.assertEqual(len(attacker_docs), 1)
        # Exactly one Cookie header, and it is the attacker's own session.
        self.assertEqual(attacker_docs[0]["cookies"], ["sid=attacker"])
        # No request issued as the attacker ever carried the victim's cookie.
        for value in log.cookies_for(ATTACKER_TOKEN):
            self.assertNotIn("sid=victim", value)
        for value in log.cookies_for(VICTIM_TOKEN):
            self.assertNotIn("sid=attacker", value)
        self.assertEqual(
            {state.state for state in sessions.values()}, {"established"}
        )

    def test_jar_leak_is_detectable(self) -> None:
        """A safety test that cannot fail is decoration. This proves it can."""
        with _server(_isolating_target) as (url, log):
            config = _config()
            config["target"]["base_url"] = url
            established = sequence.establish_sessions(config)
            # Deliberately hand the VICTIM's session to a request issued as the
            # attacker, which is precisely what the engine has no API to do.
            core._perform_request(
                url,
                5,
                {"method": "GET", "path": "/docs/1"},
                config["identities"]["attacker"],
                session=established["victim"],
            )
        leaked = [
            value
            for value in log.cookies_for(ATTACKER_TOKEN)
            if "sid=victim" in value
        ]
        self.assertTrue(leaked, "the leak assertion in the isolation test is inert")

    def test_jars_are_distinct_objects_and_never_merged(self) -> None:
        with _server(_isolating_target) as (url, _):
            _, sessions, _ = _run(_config(), url)
        victim, attacker = sessions["victim"], sessions["attacker"]
        self.assertIsNot(victim.jar, attacker.jar)
        victim_pairs = {(cookie.name, cookie.value) for cookie in victim.jar}
        attacker_pairs = {(cookie.name, cookie.value) for cookie in attacker.jar}
        self.assertTrue(victim_pairs and attacker_pairs)
        self.assertEqual(victim_pairs & attacker_pairs, set())
        for module in (core, sequence):
            for name, value in vars(module).items():
                self.assertNotIsInstance(
                    value,
                    sequence.http.cookiejar.CookieJar,
                    f"{module.__name__}.{name} is a module-level cookie jar",
                )

    def test_identity_without_session_sends_no_cookie_header(self) -> None:
        """An existing config cannot acquire cookie behaviour by accident."""

        def target(entry: dict):
            headers = [
                ("Set-Cookie", "tracker=always; Path=/"),
                ("Content-Type", "application/json"),
            ]
            if entry["path"] == "/docs/1" and entry["auth"] == VICTIM_TOKEN:
                return 200, headers, json.dumps({"note": MARKER_VICTIM}).encode()
            return 403, headers, b'{"error":"denied"}'

        config = _config(identities=_identities(sessions=False))
        with _server(target) as (url, log):
            result, sessions, _ = _run(config, url)
        self.assertEqual(sessions, {})
        self.assertNotIn("sessions", result)
        self.assertEqual(result["findings"], [])
        # Three, not two: the liveness control is a third request. It carries
        # NO cookie, which is the property this test is about -- a fabricated
        # credential must not pick up somebody's jar either.
        self.assertEqual([entry["cookie"] for entry in log.entries], ["", "", ""])

    @fast("asserts on the declaration, not on a live target")
    def test_static_cookie_header_plus_session_is_a_config_error(self) -> None:
        config = _config()
        config["identities"]["victim"]["headers"]["Cookie"] = "sid=stale"
        with _written(config) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("static Cookie header and a session", str(caught.exception))
        # The message names the header, never its value.
        self.assertNotIn("sid=stale", str(caught.exception))

    def test_cookies_are_extracted_from_a_302_login(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return (
                    302,
                    [("Location", "/dashboard"), ("Set-Cookie", "sid=victim; Path=/")],
                    b"",
                )
            if entry["path"] == "/docs/1" and entry["cookie"] == "sid=victim":
                return 200, [], MARKER_VICTIM.encode()
            return 403, [], b"denied"

        config = _config(identities={"victim": {
            "headers": {"Authorization": VICTIM_TOKEN},
            "marker": MARKER_VICTIM,
            "session": {
                "login": [{"method": "POST", "path": "/login", "expect_status": [302]}],
                "establishes": {"cookie": "sid"},
            },
        }, "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}}})
        config["checks"] = [{
            "id": "c",
            "request": {"method": "GET", "path": "/docs/1"},
            "expect": {
                "victim": {"status": [200], "contains_marker": "victim"},
                "attacker": {"status": [403]},
            },
        }]
        with _server(target) as (url, log):
            result, sessions, _ = _run(config, url)
        self.assertEqual(sessions["victim"].state, "established")
        self.assertEqual(result["findings"], [])
        # The redirect target was never fetched: credentials are not forwarded.
        self.assertNotIn("/dashboard", log.paths())

    def test_secure_cookie_over_http_fails_establishment(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", "sid=victim; Path=/; Secure")], b"ok"
            return 200, [], MARKER_VICTIM.encode()

        with _server(target) as (url, _):
            result, sessions, _ = _run(_config(), url)
        self.assertEqual(sessions["victim"].state, "failed")
        self.assertIn("not_established", sessions["victim"].reason)
        verdicts = {finding["verdict"] for finding in result["findings"]}
        self.assertEqual(verdicts, {"inconclusive"})


# --------------------------------------------------------------------------
# (b) cookie values are credentials
# --------------------------------------------------------------------------


class RedactionTest(unittest.TestCase):
    def _sentinel_target(self, entry: dict):
        if entry["path"] == "/login" and entry["method"] == "GET":
            body = (
                f'<html><head><meta name="csrf-token" content="{CSRF_SENTINEL}">'
                "</head><body>hi</body></html>"
            ).encode()
            return 200, [("Content-Type", "text/html")], body
        if entry["path"] == "/login":
            if entry["csrf"] != CSRF_SENTINEL:
                return 403, [], b"no csrf"
            return (
                200,
                [("Set-Cookie", f"sid={COOKIE_SENTINEL}; Path=/")],
                b"ok",
            )
        if entry["cookie"] == f"sid={COOKIE_SENTINEL}":
            return 200, [], MARKER_VICTIM.encode()
        return 403, [], b"denied"

    def _sentinel_config(self) -> dict:
        return _config(
            identities={
                "victim": {
                    "headers": {"Authorization": VICTIM_TOKEN},
                    "marker": MARKER_VICTIM,
                    "session": {
                        "login": [
                            {
                                "method": "GET",
                                "path": "/login",
                                "expect_status": [200],
                                "capture": {
                                    "csrf": {"from": "html_meta", "name": "csrf-token"}
                                },
                            },
                            {
                                "method": "POST",
                                "path": "/login",
                                "headers": {"X-CSRFToken": "${capture.csrf}"},
                                # Read from the environment at load time, as a
                                # real config does: the password exists only in
                                # memory, never in a file this test can scan.
                                "body": "password=${VERIDOR_TEST_PASSWORD}",
                                "expect_status": [200],
                            },
                        ],
                        "establishes": {"cookie": "sid"},
                    },
                },
                "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}},
            },
            checks=[
                {
                    "id": "c",
                    "request": {"method": "GET", "path": "/docs/1"},
                    "expect": {
                        "victim": {"status": [200], "contains_marker": "victim"},
                        "attacker": {"status": [403]},
                    },
                }
            ],
        )

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_no_credential_value_reaches_any_artifact(self) -> None:
        """The boundary. A future field that leaks a credential fails here."""
        stdout, stderr = io.StringIO(), io.StringIO()
        self.enterContext(
            patch.dict(os.environ, {"VERIDOR_TEST_PASSWORD": PASSWORD_SENTINEL})
        )
        with _server(self._sentinel_target) as (url, log):
            with _written(self._sentinel_config(), url) as (path, root):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    code = veridor_main(
                        [
                            "run",
                            "--config",
                            str(path),
                            "--output-dir",
                            str(root / "out"),
                            "--json",
                            str(root / "run.json"),
                            "--sarif",
                            str(root / "run.sarif"),
                            "--fail-on",
                            "none",
                        ]
                    )
                artifacts = {
                    item: item.read_text(encoding="utf-8")
                    for item in root.rglob("*")
                    if item.is_file() and item.suffix in {".json", ".sarif"}
                }
        self.assertEqual(code, 0)
        # The session really did work, or the test would prove nothing.
        self.assertTrue(any(entry["cookie"] for entry in log.entries))
        haystacks = {str(name): text for name, text in artifacts.items()}
        haystacks["stdout"] = stdout.getvalue()
        haystacks["stderr"] = stderr.getvalue()
        self.assertGreater(len(haystacks), 3)
        for secret in (COOKIE_SENTINEL, CSRF_SENTINEL, PASSWORD_SENTINEL):
            for variant in _encodings(secret):
                for where, text in haystacks.items():
                    self.assertNotIn(
                        variant, text, f"{secret[:6]}… leaked into {where}"
                    )

    def test_cookie_jar_is_not_persisted(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "src" / "veridor").rglob("*.py")
        )
        for banned in ("FileCookieJar", "MozillaCookieJar", "LWPCookieJar", "save("):
            self.assertNotIn(banned, source, banned)

    def test_cookie_name_is_sanitised(self) -> None:
        self.assertEqual(sequence._safe_cookie_name("csrftoken"), "csrftoken")
        self.assertEqual(sequence._safe_cookie_name("a.b-c_1"), "a.b-c_1")
        self.assertEqual(
            sequence._safe_cookie_name("smuggled data"), "[REDACTED_NAME]"
        )
        self.assertEqual(sequence._safe_cookie_name("x" * 65), "[REDACTED_NAME]")

    def test_cookie_parse_error_message_is_constant(self) -> None:
        state = _bare_session()

        class Exploding:
            def info(self):  # pragma: no cover - raising is the point
                raise ValueError(f"bad cookie: sid={COOKIE_SENTINEL}")

        state.harvest(Exploding(), None)
        self.assertEqual(state.note, sequence.COOKIE_ERROR)
        self.assertNotIn(COOKIE_SENTINEL, state.note)

    def test_no_hash_of_a_captured_secret_is_recorded(self) -> None:
        state = _bare_session()
        state._values["csrf"] = CSRF_SENTINEL
        state._sources["csrf"] = "html_meta:csrf-token"
        report = json.dumps(state.report())
        self.assertIn("html_meta:csrf-token", report)
        self.assertNotIn(CSRF_SENTINEL, report)
        for digest in _digests(CSRF_SENTINEL):
            self.assertNotIn(digest, report)


def _encodings(secret: str) -> set[str]:
    import base64
    from urllib.parse import quote

    return {
        secret,
        secret.lower(),
        secret.upper(),
        quote(secret),
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
    }


def _digests(secret: str) -> set[str]:
    import hashlib

    return {
        hashlib.sha256(secret.encode()).hexdigest(),
        hashlib.md5(secret.encode(), usedforsecurity=False).hexdigest(),
        hashlib.sha1(secret.encode(), usedforsecurity=False).hexdigest(),
    }


def _bare_session() -> sequence.IdentitySession:
    return sequence.IdentitySession(
        "victim",
        {"headers": {}, "session": {"establishes": {"cookie": "sid"}}},
        "http://127.0.0.1:1",
        5,
        {},
    )


# --------------------------------------------------------------------------
# (c) CSRF capture and injection
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class CsrfTest(unittest.TestCase):
    def _run_with_injection(self, target, session_extra: dict, **kwargs):
        config = _config(
            identities={
                "victim": {
                    "headers": {"Authorization": VICTIM_TOKEN},
                    "marker": MARKER_VICTIM,
                    "session": _session(**session_extra),
                },
                "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}},
            },
            checks=[
                {
                    "id": "c",
                    "request": {"method": "GET", "path": "/docs/1"},
                    "expect": {
                        "victim": {"status": [200], "contains_marker": "victim"},
                        "attacker": {"status": [403]},
                    },
                }
            ],
        )
        config.update(kwargs)
        with _server(target) as (url, log):
            result, sessions, _ = _run(config, url)
        return result, sessions, log

    def test_csrf_from_cookie_is_injected_into_header(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return (
                    200,
                    [
                        ("Set-Cookie", "sid=victim; Path=/"),
                        ("Set-Cookie", f"csrftoken={CSRF_SENTINEL}; Path=/"),
                    ],
                    b"ok",
                )
            if entry["auth"] != VICTIM_TOKEN:
                return 403, [], b"denied"
            if entry["csrf"] != CSRF_SENTINEL:
                return 403, [], b"missing csrf"
            return 200, [], MARKER_VICTIM.encode()

        result, sessions, log = self._run_with_injection(
            target,
            {
                "capture": {"csrf": {"from": "cookie", "name": "csrftoken"}},
                "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
            },
        )
        self.assertEqual(result["findings"], [])
        probe = [
            entry
            for entry in log.entries
            if entry["path"] == "/docs/1" and entry["auth"] == VICTIM_TOKEN
        ]
        self.assertEqual([entry["csrf"] for entry in probe], [CSRF_SENTINEL])
        report = sessions["victim"].report()
        self.assertEqual(
            report["captures"]["csrf"], {"state": "captured", "source": "cookie:csrftoken"}
        )
        self.assertEqual(report["cookies"]["names"], ["csrftoken", "sid"])

    def test_csrf_rotation_uses_the_latest_value(self) -> None:
        """A cookie capture is read live from the jar, so rotation is free."""
        rotated = "R0tatedTokenValue987654321abcdef"

        def target(entry: dict):
            if entry["path"] == "/login" and entry["method"] == "GET":
                return 200, [("Set-Cookie", f"csrftoken={CSRF_SENTINEL}; Path=/")], b"1"
            if entry["path"] == "/login":
                return (
                    200,
                    [
                        ("Set-Cookie", "sid=victim; Path=/"),
                        ("Set-Cookie", f"csrftoken={rotated}; Path=/"),
                    ],
                    b"ok",
                )
            return (
                (200, [], MARKER_VICTIM.encode())
                if entry["csrf"] == rotated
                else (403, [], b"stale csrf")
            )

        result, _, log = self._run_with_injection(
            target,
            {
                "login": [
                    {"method": "GET", "path": "/login", "expect_status": [200]},
                    {"method": "POST", "path": "/login", "expect_status": [200]},
                ],
                "capture": {"csrf": {"from": "cookie", "name": "csrftoken"}},
                "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
            },
        )
        self.assertEqual(result["findings"], [])
        probes = [entry for entry in log.entries if entry["path"] == "/docs/1"]
        self.assertEqual([entry["csrf"] for entry in probes if entry["csrf"]], [rotated])

    def test_csrf_from_html_meta(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login" and entry["method"] == "GET":
                body = (
                    b'<html><head><meta name="other" content="wrong">'
                    b'<meta name="csrf-token" content="' + CSRF_SENTINEL.encode() +
                    b'"></head></html>'
                )
                return 200, [("Content-Type", "text/html")], body
            if entry["path"] == "/login":
                if entry["csrf"] != CSRF_SENTINEL:
                    return 403, [], b"no csrf"
                return 200, [("Set-Cookie", "sid=victim; Path=/")], b"ok"
            if entry["auth"] != VICTIM_TOKEN:
                return 403, [], b"denied"
            return 200, [], MARKER_VICTIM.encode()

        result, sessions, _ = self._run_with_injection(
            target,
            {
                "login": [
                    {
                        "method": "GET",
                        "path": "/login",
                        "expect_status": [200],
                        "capture": {
                            "csrf": {"from": "html_meta", "name": "csrf-token"}
                        },
                    },
                    {
                        "method": "POST",
                        "path": "/login",
                        "headers": {"X-CSRFToken": "${capture.csrf}"},
                        "expect_status": [200],
                    },
                ]
            },
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(sessions["victim"].state, "established")

    def test_csrf_from_json_pointer_establishes_a_bearer_session(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                body = json.dumps({"data": {"token": CSRF_SENTINEL}}).encode()
                return 200, [("Content-Type", "application/json")], body
            return (
                (200, [], MARKER_VICTIM.encode())
                if entry["csrf"] == CSRF_SENTINEL and entry["auth"] == VICTIM_TOKEN
                else (403, [], b"denied")
            )

        result, sessions, _ = self._run_with_injection(
            target,
            {
                "login": [
                    {
                        "method": "POST",
                        "path": "/login",
                        "expect_status": [200],
                        "capture": {
                            "token": {"from": "json_pointer", "pointer": "/data/token"}
                        },
                    }
                ],
                "establishes": {"capture": "token"},
                "inject": [{"header": "X-CSRFToken", "value": "${capture.token}"}],
            },
        )
        self.assertEqual(sessions["victim"].state, "established")
        self.assertEqual(result["findings"], [])

    def test_unresolved_injection_fails_closed(self) -> None:
        """An untokened request draws a 403, and a 403 can match a denial."""

        def target(entry: dict):
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", "sid=victim; Path=/")], b"ok"
            return 403, [], b"denied"

        config = _config(
            identities={
                "victim": {
                    "headers": {"Authorization": VICTIM_TOKEN},
                    "marker": MARKER_VICTIM,
                    "session": _session(
                        capture={"csrf": {"from": "cookie", "name": "never-set"}},
                        inject=[{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
                    ),
                },
                "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}},
            },
            checks=[
                {
                    "id": "c",
                    "request": {"method": "GET", "path": "/docs/1"},
                    # The trap: a denial is declared, so a request that went out
                    # without its token would MATCH and the run would be green.
                    "expect": {
                        "victim": {"status": [403]},
                        "attacker": {"status": [403]},
                    },
                }
            ],
        )
        with _server(target) as (url, log):
            result, _, _ = _run(config, url)
        victim = _finding_map(result)[("c", "victim")]
        self.assertEqual(victim["verdict"], "inconclusive")
        self.assertIn("was not sent", victim["message"])
        # Nothing was put on the wire FOR THAT PROBE. The second /docs/1 is the
        # liveness control, which carries a fabricated credential and no
        # session at all -- so it cannot be the unresolved injection leaking.
        self.assertEqual(log.paths("GET"), ["/docs/1", "/docs/1"])

    def test_a_captured_value_carrying_a_marker_is_blocked(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return (
                    200,
                    [
                        ("Set-Cookie", "sid=victim; Path=/"),
                        ("Set-Cookie", f"csrftoken={MARKER_VICTIM}; Path=/"),
                    ],
                    b"ok",
                )
            return 200, [], MARKER_VICTIM.encode()

        config = _config(
            identities={
                "victim": {
                    "headers": {"Authorization": VICTIM_TOKEN},
                    "marker": MARKER_VICTIM,
                    "session": _session(
                        capture={"csrf": {"from": "cookie", "name": "csrftoken"}},
                        inject=[{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
                    ),
                },
                "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}},
            },
            checks=[
                {
                    "id": "c",
                    "request": {"method": "GET", "path": "/docs/1"},
                    "expect": {
                        "victim": {"status": [200], "contains_marker": "victim"},
                        "attacker": {"status": [403]},
                    },
                }
            ],
        )
        with _server(target) as (url, _):
            result, _, _ = _run(config, url)
        victim = _finding_map(result)[("c", "victim")]
        self.assertEqual(victim["verdict"], "inconclusive")
        self.assertIn("reflected marker", victim["message"])

    @fast("asserts on the declaration, not on a live target")
    def test_a_check_cannot_reference_a_capture(self) -> None:
        config = _config()
        config["checks"][0]["request"]["headers"] = {"X-T": "${capture.csrf}"}
        with _written(config) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("undefined capture", str(caught.exception))

    @fast("asserts on the declaration, not on a live target")
    def test_inject_cannot_fill_a_credential_slot(self) -> None:
        for header in ("Cookie", "Authorization", "Proxy-Authorization"):
            config = _config()
            config["identities"]["victim"]["session"]["inject"] = [
                {"header": header, "value": "x"}
            ]
            with _written(config) as (path, _):
                with self.assertRaises(ConfigError) as caught:
                    load_config(path)
            self.assertIn("cookie jar owns it", str(caught.exception))


_FORM = "application/x-www-form-urlencoded"


@slow("stands up a loopback HTTP server and runs the engine against it")
class BodyInjectionTest(unittest.TestCase):
    """A form_field or json_field the request cannot carry is never skipped.

    ``prepare`` used to append a form_field only when the CONFIG named a form
    Content-Type and set a json_field only on a JSON object body, and otherwise
    sent the request without the token and said nothing. The untokened request
    drew a CSRF 403, the 403 matched the declared denial, and the run passed.
    """

    @staticmethod
    def _target(entry: dict):
        if entry["path"] == "/login":
            return (
                200,
                [
                    ("Set-Cookie", "sid=victim; Path=/"),
                    ("Set-Cookie", f"csrftoken={CSRF_SENTINEL}; Path=/"),
                ],
                b"ok",
            )
        if entry["auth"] != VICTIM_TOKEN:
            return 403, [], b"denied"
        if CSRF_SENTINEL.encode() not in entry["body"]:
            return 403, [], b"missing csrf"
        return 200, [], MARKER_VICTIM.encode()

    @staticmethod
    def _config(slot: dict, request: dict) -> dict:
        return _config(
            identities={
                "victim": {
                    "headers": {"Authorization": VICTIM_TOKEN},
                    "marker": MARKER_VICTIM,
                    "session": _session(
                        capture={"csrf": {"from": "cookie", "name": "csrftoken"}},
                        inject=[{**slot, "value": "${capture.csrf}"}],
                    ),
                },
                "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}},
            },
            checks=[
                {
                    "id": "c",
                    "request": request,
                    # The trap: a denial is declared, so an untokened request
                    # would MATCH and the run would be green.
                    "expect": {
                        "victim": {"status": [403]},
                        "attacker": {"status": [403]},
                    },
                }
            ],
        )

    def _post(self, slot: dict, request: dict):
        config = self._config(slot, request)
        with _server(self._target) as (url, log):
            result, _, _ = _run(config, url)
        sent = [
            entry["body"]
            for entry in log.entries
            if entry["path"] == "/items" and entry["auth"] == VICTIM_TOKEN
        ]
        return _finding_map(result).get(("c", "victim")), sent, result

    def test_a_form_body_with_no_content_type_carries_the_field(self) -> None:
        """urllib form-encodes a ``body`` string that names no Content-Type."""
        finding, sent, _ = self._post(
            {"form_field": "csrfmiddlewaretoken"},
            {"method": "POST", "path": "/items", "body": "title=x"},
        )
        self.assertEqual(sent, [f"title=x&csrfmiddlewaretoken={CSRF_SENTINEL}".encode()])
        self.assertEqual(finding["verdict"], "vulnerable")

    def test_a_request_that_cannot_carry_the_field_is_not_sent(self) -> None:
        cases = {
            "form_field, no body": (
                {"form_field": "csrfmiddlewaretoken"},
                {"method": "POST", "path": "/items"},
            ),
            "form_field, JSON body": (
                {"form_field": "csrfmiddlewaretoken"},
                {"method": "POST", "path": "/items", "json": {"title": "x"}},
            ),
            "json_field, array body": (
                {"json_field": "csrf"},
                {"method": "POST", "path": "/items", "json": [{"title": "x"}]},
            ),
            "json_field, no body": (
                {"json_field": "csrf"},
                {"method": "DELETE", "path": "/items"},
            ),
            "json_field, form body": (
                {"json_field": "csrf"},
                {"method": "POST", "path": "/items", "body": "title=x"},
            ),
        }
        for label, (slot, request) in cases.items():
            with self.subTest(label):
                finding, sent, _ = self._post(slot, request)
                self.assertEqual(sent, [])
                self.assertEqual(finding["verdict"], "inconclusive")
                self.assertIn("was not sent", finding["message"])

    def _assert_configuration_advice(self, finding: dict) -> None:
        self.assertTrue(finding["message"].startswith("Request not sent: "),
                        finding["message"])
        self.assertNotIn("reachable", finding["remediation"])
        self.assertIn("form-encoded", finding["remediation"])
        self.assertIn("JSON object", finding["remediation"])
        self.assertIn("session.inject", finding["remediation"])

    def test_a_withheld_request_gets_configuration_advice_not_network_advice(
        self,
    ) -> None:
        """REGRESSION. Nothing was sent and the target was healthy, but the
        finding read "Request failed: ..." and "Confirm the target is reachable
        from the runner and retry." (reproduced, check and sequence step
        alike), and the SARIF help for EXEC-001 said only that. The fix is in
        the configuration: a body that can carry the field, or no field."""
        finding, sent, result = self._post(
            {"json_field": "csrf"},
            {"method": "POST", "path": "/items", "json": [1, 2]},
        )
        self.assertEqual(sent, [])
        self._assert_configuration_advice(finding)
        rules = {rule["id"]: rule
                 for rule in core.to_sarif(result)["runs"][0]["tool"]["driver"]["rules"]}
        help_text = rules["VERIDOR-EXEC-001"]["help"]["text"]
        self.assertIn("session.inject", help_text)
        self.assertIn("form-encoded", help_text)

        config = _injecting_teardown_config()
        config["sequences"][0]["steps"][0]["request"] = {
            "method": "POST", "path": "/docs", "json": {"title": "x"}}
        with _server(_injecting_teardown_target) as (url, log):
            result, _, _ = _run(config, url)
        self.assertEqual(log.paths("POST"), ["/login"])
        [step_finding] = [f for f in result["findings"]
                          if f["rule_id"] == "VERIDOR-EXEC-001" and f.get("step_index") == 0]
        self._assert_configuration_advice(step_finding)

        # Control: a transport failure keeps its transport advice.
        advice = core._transport_remediation("connection refused", {})
        self.assertIn("Nothing was listening", advice)

    def test_a_run_withheld_entirely_is_not_sent_to_the_network(self) -> None:
        """Every probe withheld for injection_not_applicable, end to end.

        The target was up and answered both logins, nothing else was sent,
        and the run exited 3 telling the operator to check the target URL and
        that the target is up.
        """
        config = self._config({"json_field": "csrf"},
                              {"method": "POST", "path": "/items", "json": [1, 2]})
        config["identities"]["attacker"]["session"] = _session(
            capture={"csrf": {"from": "cookie", "name": "csrftoken"}},
            inject=[{"json_field": "csrf", "value": "${capture.csrf}"}],
        )
        stderr = io.StringIO()
        with _server(self._target) as (url, log):
            with _written(config, url) as (path, root):
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(stderr):
                    code = veridor_main(
                        ["run", "--config", str(path), "--output-dir", str(root / "out")]
                    )
        self.assertEqual(log.paths("POST"), ["/login", "/login"])
        self.assertEqual(code, 3)
        line = next(line for line in stderr.getvalue().splitlines()
                    if "not one of" in line)
        self.assertNotIn("that the target is up", line)
        self.assertIn("injection_not_applicable (2)", line)
        self.assertIn("not a network problem", line)

    def test_the_controls_still_carry_the_field(self) -> None:
        """Explicit form type and a JSON object: the cases that always worked."""
        finding, sent, _ = self._post(
            {"form_field": "csrfmiddlewaretoken"},
            {"method": "POST", "path": "/items", "body": "title=x",
             "headers": {"Content-Type": _FORM}},
        )
        self.assertEqual(sent, [f"title=x&csrfmiddlewaretoken={CSRF_SENTINEL}".encode()])
        self.assertEqual(finding["verdict"], "vulnerable")
        finding, sent, _ = self._post(
            {"json_field": "csrf"},
            {"method": "POST", "path": "/items", "json": {"title": "x"}},
        )
        self.assertEqual(json.loads(sent[0]), {"title": "x", "csrf": CSRF_SENTINEL})
        self.assertEqual(finding["verdict"], "vulnerable")

    def test_a_bodyless_safe_method_is_sent_but_the_dropped_field_is_disclosed(
        self,
    ) -> None:
        """A GET has no body to carry a form or JSON field and no CSRF check to
        satisfy, so it is sent rather than refused -- refusing it would make
        every read check and marker probe of a form_field session inconclusive.
        But the GET matched the declared [403] WITHOUT its declared field, which
        is the silent pass this whole section fixes; the drop must be recorded
        on the probe and disclosed, not swallowed by a clean grade."""
        finding, sent, result = self._post(
            {"form_field": "csrfmiddlewaretoken"}, {"method": "GET", "path": "/items"}
        )
        self.assertEqual(sent, [b""])
        # Still no finding -- the GET matched its denial -- which is exactly why
        # the drop has to be recorded somewhere a reader will see it.
        self.assertIsNone(finding)
        victim_probe = next(
            p for p in result["probes"]
            if p["check_id"] == "c" and p["identity"] == "victim"
        )
        self.assertEqual(
            victim_probe["injection_not_applied"], ["form_field 'csrfmiddlewaretoken'"]
        )
        disclosure = next(
            d for d in result["injection_disclosures"]
            if d["check_id"] == "c" and d["identity"] == "victim"
        )
        self.assertIn("form_field 'csrfmiddlewaretoken'", disclosure["statement"])
        # The captured CSRF value is never written to the document.
        self.assertNotIn(CSRF_SENTINEL, json.dumps(result))

    def test_the_dropped_field_is_printed_on_the_console(self) -> None:
        """A clean run that leaned on a dropped field says so on stdout, next to
        the other pass disclosures; the raw JSON is not where an operator looks."""
        config = self._config(
            {"form_field": "csrfmiddlewaretoken"}, {"method": "GET", "path": "/items"}
        )
        stdout = io.StringIO()
        with _server(self._target) as (url, _):
            with _written(config, url) as (path, root):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    veridor_main(
                        ["run", "--config", str(path), "--output-dir", str(root / "out")]
                    )
        printed = stdout.getvalue()
        self.assertIn("Injection not applied:", printed)
        self.assertIn("c / victim:", printed)
        self.assertNotIn(CSRF_SENTINEL, printed)


class BodyInjectionPrepareTest(unittest.TestCase):
    """The same rule at ``prepare``, with no target."""

    def _prepare(self, slot: dict, headers: dict, body: bytes | None, method: str):
        identity = {"session": {"inject": [{**slot, "value": "tok"}]}}
        session = sequence.IdentitySession("victim", identity, "http://127.0.0.1:1", 5, {})
        session._injecting = True
        return session.prepare(headers, body, method=method)

    def test_each_case(self) -> None:
        form = {"form_field": "f"}
        field = {"json_field": "f"}
        json_type = {"Content-Type": "application/json"}
        blocked = (None, "injection_not_applicable")
        cases = [
            (form, {}, b"a=1", "POST", (b"a=1&f=tok", None)),
            (form, {"Content-Type": _FORM}, b"a=1", "POST", (b"a=1&f=tok", None)),
            (form, {}, b"", "POST", (b"f=tok", None)),
            (form, {}, None, "POST", blocked),
            (form, {}, None, "DELETE", blocked),
            (form, json_type, b"{}", "POST", blocked),
            (form, {}, None, "GET", (None, None)),
            (field, json_type, b'{"a":1}', "PATCH", (b'{"a":1,"f":"tok"}', None)),
            (field, json_type, b"[1]", "POST", blocked),
            (field, json_type, b"not json", "POST", blocked),
            (field, {}, b"a=1", "POST", blocked),
            (field, {}, None, "PUT", blocked),
            (field, {}, None, "HEAD", (None, None)),
        ]
        for slot, headers, body, method, (want_body, want_blocked) in cases:
            with self.subTest(slot=slot, headers=headers, body=body, method=method):
                _, sent, reason, not_applied = self._prepare(
                    slot, headers, body, method
                )
                self.assertEqual(reason, want_blocked)
                if want_blocked is None:
                    self.assertEqual(sent, want_body)
                # The only non-blocked cases that drop a field are the bodyless
                # safe methods; they record the drop rather than swallow it.
                if reason is None and method in core.SAFE_METHODS:
                    self.assertEqual(len(not_applied), 1)
                else:
                    self.assertEqual(not_applied, [])

    def test_the_reason_is_an_unsent_reason(self) -> None:
        self.assertIn("injection_not_applicable", core.UNSENT_REASONS)
        self.assertIn("not sent", core.UNSENT_REASONS["injection_not_applicable"])


# --------------------------------------------------------------------------
# (d) teardown
# --------------------------------------------------------------------------


def _sequence_config(extra_teardown: bool = False) -> dict:
    teardown = [
        {
            "as": "victim",
            "request": {"method": "DELETE", "path": "/docs/${doc_id}"},
            "expect": {"status": [204]},
        }
    ]
    if extra_teardown:
        teardown.insert(
            0,
            {
                "as": "victim",
                "request": {"method": "DELETE", "path": "/other/${doc_id}"},
                "expect": {"status": [204]},
            },
        )
    return {
        "version": 2,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
        "identities": _identities(sessions=False),
        "checks": [],
        "sequences": [
            {
                "id": "seq",
                "steps": [
                    {
                        "role": "setup",
                        "as": "victim",
                        "request": {
                            "method": "POST",
                            "path": "/docs",
                            "json": {"note": "${marker:victim}"},
                        },
                        "expect": {"status": [201]},
                        "capture": {"doc_id": "$.id"},
                    },
                    {
                        # The control: the victim reads back their own marker,
                        # so the attacker's exclusion below is falsifiable.
                        "role": "setup",
                        "as": "victim",
                        "request": {"method": "GET", "path": "/docs/${doc_id}"},
                        "expect": {"status": [200], "contains_marker": "victim"},
                    },
                    {
                        "role": "assert",
                        "as": "attacker",
                        "request": {"method": "GET", "path": "/docs/${doc_id}"},
                        "expect": {"status": [403], "excludes_marker": "victim"},
                    },
                ],
                "teardown": teardown,
            }
        ],
    }


def _fixture_target(
    *,
    assert_status: int = 403,
    teardown_status: int = 204,
    victim_read_status: int = 200,
):
    """Provision, read back as the owner, refuse the attacker, delete."""

    def target(entry: dict):
        if entry["path"] == "/docs" and entry["method"] == "POST":
            return (
                201,
                [("Content-Type", "application/json")],
                json.dumps({"id": 42}).encode(),
            )
        if entry["method"] == "DELETE":
            return teardown_status, [], b""
        if entry["method"] == "GET" and entry["auth"] == VICTIM_TOKEN:
            body = json.dumps({"note": MARKER_VICTIM}).encode()
            return (
                victim_read_status,
                [("Content-Type", "application/json")],
                body if victim_read_status == 200 else b'{"e":1}',
            )
        if entry["method"] == "GET":
            return assert_status, [("Content-Type", "application/json")], b'{"e":1}'
        return 404, [], b""

    return target


def _injecting_teardown_config() -> dict:
    """A session that injects a form_field, and a bodyless DELETE teardown.

    The setup POST carries a form body, so the field applies there and the
    session establishes; the teardown DELETE has no body to carry it. Teardown
    is cleanup, never graded, so that request must still be sent.
    """
    victim = {
        "headers": {"Authorization": VICTIM_TOKEN},
        "session": _session(
            capture={"csrf": {"from": "cookie", "name": "csrftoken"}},
            inject=[{"form_field": "csrfmiddlewaretoken", "value": "${capture.csrf}"}],
        ),
    }
    return {
        "version": 2,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
        "identities": {
            "victim": victim,
            "attacker": {"headers": {"Authorization": ATTACKER_TOKEN}},
        },
        "checks": [],
        "sequences": [
            {
                "id": "seq",
                "steps": [
                    {
                        "role": "setup",
                        "as": "victim",
                        "request": {"method": "POST", "path": "/docs", "body": "title=x"},
                        "expect": {"status": [201]},
                        "capture": {"doc_id": "$.id"},
                    }
                ],
                "teardown": [
                    {
                        "as": "victim",
                        "request": {"method": "DELETE", "path": "/docs/${doc_id}"},
                        "expect": {"status": [204]},
                    }
                ],
            }
        ],
    }


def _injecting_teardown_target(entry: dict):
    if entry["path"] == "/login":
        return (
            200,
            [
                ("Set-Cookie", "sid=victim; Path=/"),
                ("Set-Cookie", f"csrftoken={CSRF_SENTINEL}; Path=/"),
            ],
            b"ok",
        )
    if entry["method"] == "POST" and entry["path"] == "/docs":
        return 201, [("Content-Type", "application/json")], json.dumps({"id": 42}).encode()
    if entry["method"] == "DELETE":
        return 204, [], b""
    return 404, [], b""


@slow("stands up a loopback HTTP server and runs the engine against it")
class SequenceWithheldFirstStepTest(unittest.TestCase):
    """A sequences-only run whose first step the configuration withheld.

    The step after it was skipped and counted as unanswered rather than
    withheld, so the run ended "Check the target URL, the credentials, and
    that the target is up" although only the login was sent and the target
    answered it.
    """

    def test_the_skipped_step_counts_as_withheld(self) -> None:
        config = _injecting_teardown_config()
        sequence_ = config["sequences"][0]
        sequence_["steps"][0]["request"] = {
            "method": "POST", "path": "/docs", "json": {"title": "x"}}
        sequence_["steps"].append({
            "role": "assert", "as": "attacker",
            "request": {"method": "GET", "path": "/docs/${doc_id}"},
            "expect": {"status": [403]},
        })
        sequence_["teardown"] = []
        stderr = io.StringIO()
        with _server(_injecting_teardown_target) as (url, log):
            with _written(config, url) as (path, root):
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(stderr):
                    code = veridor_main(
                        ["run", "--config", str(path), "--output-dir", str(root / "out")]
                    )
        self.assertEqual(log.paths(), ["/login"])
        self.assertEqual(code, 3)
        line = next(line for line in stderr.getvalue().splitlines()
                    if "not one of" in line)
        self.assertNotIn("that the target is up", line)
        self.assertIn("injection_not_applicable (2)", line)
        self.assertIn("not a network problem", line)


@slow("stands up a loopback HTTP server and runs the engine against it")
class TeardownInjectionTest(unittest.TestCase):
    """A teardown entry a declared injection cannot reach is still attempted.

    ``prepare`` refuses a graded probe whose body cannot carry a declared
    form_field or json_field: unsent, graded inconclusive. Teardown is never
    graded, so that refusal does not belong here -- it left the DELETE unsent,
    counted it a teardown failure, and orphaned the fixture the entry existed to
    remove. Teardown now passes ``graded=False``: the request goes out and the
    dropped field is noted in the run document.
    """

    def test_a_bodyless_teardown_is_sent_and_the_dropped_field_is_noted(self) -> None:
        with _server(_injecting_teardown_target) as (url, log):
            result, _, _ = _run(_injecting_teardown_config(), url)
        # The DELETE reached the wire; before the fix it was refused and the
        # fixture was orphaned.
        self.assertEqual(log.paths("DELETE"), ["/docs/42"])
        record = result["sequences"][0]["teardown"][0]
        self.assertEqual(record["state"], "executed")
        self.assertTrue(record["matched"])
        self.assertEqual(result["sequences"][0]["teardown_state"], "clean")
        self.assertEqual(result["summary"]["teardown_failures"], 0)
        # The run document says the field could not be carried -- the name
        # only, never the captured value.
        self.assertEqual(
            record["injection_not_applied"], ["form_field 'csrfmiddlewaretoken'"]
        )
        self.assertNotIn(CSRF_SENTINEL, json.dumps(result))


def _run_on_console(config: dict, target) -> tuple[str, dict]:
    """``veridor run`` end to end: what it printed, and the document it wrote."""
    stdout = io.StringIO()
    with _server(target) as (url, _):
        with _written(config, url) as (path, root):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                io.StringIO()
            ):
                with contextlib.suppress(SystemExit):
                    veridor_main(
                        ["run", "--config", str(path), "--output-dir", str(root / "out")]
                    )
            document = json.loads((root / "out" / "latest.json").read_text("utf-8"))
    return stdout.getvalue(), document


def _console_block(printed: str) -> str:
    """The 'Injection not applied' block alone, or '' when it was not printed."""
    start = printed.find("Injection not applied:")
    if start < 0:
        return ""
    lines = printed[start:].splitlines()
    block = [lines[0]]
    for line in lines[1:]:
        if not line.startswith("  - "):
            break
        block.append(line)
    return "\n".join(block)


@slow("stands up a loopback HTTP server and runs the engine against it")
class InjectionDisclosureEveryRequestTest(unittest.TestCase):
    """Every request that goes out without a declared field is disclosed.

    The first disclosure covered check probes only. A graded sequence step that
    used the GET carve-out went out without the field with nothing recorded on
    its record and nothing said; teardown and marker-probe drops were recorded
    in the run document but never reached the console. README says that
    whenever a request goes out without a declared field the run records it and
    ``run`` reports it on the console, so each kind is checked here end to end:
    on its own record, in ``injection_disclosures``, and in the printed block.
    """

    def _assert_disclosed(
        self, printed: str, document: dict, *, source: str, where: str
    ) -> dict:
        entry = next(
            (
                d for d in document.get("injection_disclosures") or ()
                if d.get("source") == source and d.get("identity") == "victim"
            ),
            None,
        )
        self.assertIsNotNone(
            entry,
            f"no {source} entry in injection_disclosures: "
            f"{document.get('injection_disclosures')}",
        )
        self.assertEqual(entry["where"], where)
        self.assertIn("form_field 'csrfmiddlewaretoken'", entry["statement"])
        self.assertIn(f"  - {where} / victim:", _console_block(printed))
        # The document the renderers read holds the new entry's shape, and a
        # renderer refuses one that lost the label it prints.
        core.validate_run(document)
        broken = json.loads(json.dumps(document))
        next(
            d for d in broken["injection_disclosures"] if d["source"] == source
        ).pop("where")
        with self.assertRaisesRegex(ConfigError, r"injection_disclosures\[\d+\]\.where"):
            core.validate_run(broken)
        # Field names only: the captured CSRF value reaches neither channel.
        self.assertNotIn(CSRF_SENTINEL, printed)
        self.assertNotIn(CSRF_SENTINEL, json.dumps(document))
        return entry

    def test_a_graded_get_step_is_recorded_and_printed(self) -> None:
        config = _injecting_teardown_config()
        config["sequences"][0]["steps"].append(
            {
                "role": "assert",
                "as": "victim",
                "request": {"method": "GET", "path": "/docs/${doc_id}"},
                "expect": {"status": [403, 404]},
            }
        )
        printed, document = _run_on_console(config, _injecting_teardown_target)
        step = document["sequences"][0]["steps"][1]
        # The step went out and matched its denial: no finding, so the record
        # and the console are the only places the drop can be seen.
        self.assertEqual(step["state"], "matched")
        self.assertEqual(
            step["injection_not_applied"], ["form_field 'csrfmiddlewaretoken'"]
        )
        self._assert_disclosed(
            printed, document, source="sequence_step", where="sequence 'seq' step 1"
        )

    def test_a_teardown_request_is_printed(self) -> None:
        printed, document = _run_on_console(
            _injecting_teardown_config(), _injecting_teardown_target
        )
        record = document["sequences"][0]["teardown"][0]
        self.assertEqual(
            record["injection_not_applied"], ["form_field 'csrfmiddlewaretoken'"]
        )
        self._assert_disclosed(
            printed, document, source="teardown", where="sequence 'seq' teardown 0"
        )

    def test_a_marker_probe_is_printed(self) -> None:
        config = _injecting_teardown_config()
        config["identities"]["victim"]["marker"] = MARKER_VICTIM
        config["identities"]["victim"]["marker_probe"] = {"path": "/me/docs"}

        def target(entry: dict):
            if entry["path"] == "/me/docs":
                return 200, [], MARKER_VICTIM.encode()
            return _injecting_teardown_target(entry)

        printed, document = _run_on_console(config, target)
        control = next(
            c for c in document["marker_controls"] if c["identity"] == "victim"
        )
        self.assertEqual(
            control["injection_not_applied"], ["form_field 'csrfmiddlewaretoken'"]
        )
        self._assert_disclosed(
            printed, document, source="marker_probe", where="marker_probe"
        )

    def test_sarif_carries_the_injection_disclosures(self) -> None:
        """A passing check emits no SARIF result, so a caveat on a pass rides on
        the run properties beside its siblings or a code-scanning consumer never
        sees it."""
        config = _injecting_teardown_config()
        with _server(_injecting_teardown_target) as (url, _):
            result, _, _ = _run(config, url)
        properties = core.to_sarif(result)["runs"][0]["properties"]
        self.assertEqual(
            properties.get("injectionDisclosures"), result["injection_disclosures"]
        )
        self.assertEqual(
            [d["source"] for d in properties["injectionDisclosures"]], ["teardown"]
        )
        # And a run with nothing dropped gains no key.
        config["sequences"][0]["teardown"] = []
        with _server(_injecting_teardown_target) as (url, _):
            result, _, _ = _run(config, url)
        self.assertNotIn("injection_disclosures", result)
        self.assertNotIn(
            "injectionDisclosures", core.to_sarif(result)["runs"][0]["properties"]
        )

    def test_a_request_that_carried_the_field_is_not_listed(self) -> None:
        """The control: the setup POST carries the field, so it is not listed,
        and a run with no drop at all prints no block."""
        config = _injecting_teardown_config()
        config["sequences"][0]["teardown"] = []
        printed, document = _run_on_console(config, _injecting_teardown_target)
        self.assertNotIn("injection_not_applied", json.dumps(document))
        self.assertNotIn("injection_disclosures", document)
        self.assertEqual(_console_block(printed), "")


@slow("stands up a loopback HTTP server and runs the engine against it")
class TeardownTest(unittest.TestCase):
    def test_teardown_runs_on_a_clean_pass(self) -> None:
        with _server(_fixture_target()) as (url, log):
            result, _, _ = _run(_sequence_config(), url)
        self.assertEqual(log.paths("DELETE"), ["/docs/42"])
        self.assertEqual(result["sequences"][0]["teardown_state"], "clean")
        self.assertEqual(result["summary"]["teardown_failures"], 0)

    def test_teardown_runs_after_a_middle_step_fails(self) -> None:
        with _server(_fixture_target(victim_read_status=500)) as (url, log):
            result, _, _ = _run(_sequence_config(), url)
        self.assertEqual(log.paths("DELETE"), ["/docs/42"])
        # The sequence aborted at the middle step; cleanup still ran.
        self.assertEqual(result["sequences"][0]["outcome"], "aborted")
        self.assertEqual(result["sequences"][0]["aborted_at_step"], 1)
        self.assertEqual(result["sequences"][0]["teardown_state"], "clean")

    def test_teardown_runs_when_a_step_raises(self) -> None:
        real = core._perform_request

        def exploding(base_url, timeout, request_config, identity, **kwargs):
            if request_config.get("method") == "GET":
                raise RuntimeError("boom")
            return real(base_url, timeout, request_config, identity, **kwargs)

        with _server(_fixture_target()) as (url, log):
            with patch.object(core, "_perform_request", exploding):
                with self.assertRaises(RuntimeError):
                    with _written(_sequence_config(), url) as (path, root):
                        execute_run(path, output_dir=root / "out")
        self.assertEqual(log.paths("DELETE"), ["/docs/42"])

    def test_teardown_runs_on_keyboard_interrupt(self) -> None:
        real = core._perform_request

        def interrupting(base_url, timeout, request_config, identity, **kwargs):
            if request_config.get("method") == "GET":
                raise KeyboardInterrupt
            return real(base_url, timeout, request_config, identity, **kwargs)

        with _server(_fixture_target()) as (url, log):
            with patch.object(core, "_perform_request", interrupting):
                with self.assertRaises(KeyboardInterrupt):
                    with _written(_sequence_config(), url) as (path, root):
                        execute_run(path, output_dir=root / "out")
        self.assertEqual(log.paths("DELETE"), ["/docs/42"])

    def test_all_teardown_entries_are_attempted_after_one_fails(self) -> None:
        def target(entry: dict):
            if entry["method"] == "POST":
                return 201, [("Content-Type", "application/json")], b'{"id":42}'
            if entry["path"] == "/other/42":
                return 500, [], b"cleanup broke"
            if entry["method"] == "DELETE":
                return 204, [], b""
            return 403, [], b"denied"

        with _server(target) as (url, log):
            result, _, _ = _run(_sequence_config(extra_teardown=True), url)
        # Stopping at the first failure is how half a fixture set gets orphaned.
        self.assertEqual(log.paths("DELETE"), ["/other/42", "/docs/42"])
        self.assertEqual(result["sequences"][0]["teardown_state"], "failed")
        self.assertEqual(result["summary"]["teardown_failures"], 1)

    def test_teardown_is_skipped_when_the_capture_never_resolved(self) -> None:
        def target(entry: dict):
            if entry["method"] == "POST":
                return 500, [], b"provisioning broke"
            return 204, [], b""

        with _server(target) as (url, log):
            result, _, _ = _run(_sequence_config(), url)
        # A literal '${doc_id}' must never reach the wire.
        self.assertEqual(log.paths("DELETE"), [])
        entry = result["sequences"][0]["teardown"][0]
        self.assertEqual(entry["state"], "skipped_unresolved")
        self.assertEqual(result["sequences"][0]["teardown_state"], "incomplete")
        self.assertEqual(result["summary"]["teardown_skipped"], 1)

    def test_teardown_failure_changes_neither_verdict_nor_finding_ids(self) -> None:
        with _server(_fixture_target(assert_status=200)) as (url, _):
            clean, _, _ = _run(_sequence_config(), url)
        with _server(
            _fixture_target(assert_status=200, teardown_status=500)
        ) as (url, _):
            dirty, _, _ = _run(_sequence_config(), url)
        self.assertEqual(
            [(f["id"], f["verdict"], f["evidence_grade"]) for f in clean["findings"]],
            [(f["id"], f["verdict"], f["evidence_grade"]) for f in dirty["findings"]],
        )
        self.assertTrue(clean["findings"])
        for key in ("safe", "vulnerable", "inconclusive", "confirmed", "suspected"):
            self.assertEqual(
                clean["summary"][key], dirty["summary"][key], key
            )
        self.assertEqual(clean["status"], dirty["status"])
        self.assertEqual(dirty["sequences"][0]["teardown_state"], "failed")
        # A teardown entry is never a probe and never a finding.
        self.assertEqual(dirty["summary"]["probes"], clean["summary"]["probes"])

    def test_teardown_failure_does_not_mask_a_finding_in_the_exit_code(self) -> None:
        with _server(
            _fixture_target(assert_status=200, teardown_status=500)
        ) as (url, _):
            with _written(_sequence_config(), url) as (path, root):
                argv = [
                    "run",
                    "--config",
                    str(path),
                    "--output-dir",
                    str(root / "out"),
                    "--fail-on",
                    "any",
                    "--require-clean-teardown",
                ]
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    code = veridor_main(argv)
        # The security result wins; the cleanup problem never replaces it.
        self.assertEqual(code, 1)

    def test_require_clean_teardown_exits_3_on_a_clean_security_run(self) -> None:
        with _server(_fixture_target(teardown_status=500)) as (url, _):
            with _written(_sequence_config(), url) as (path, root):
                base = [
                    "run",
                    "--config",
                    str(path),
                    "--output-dir",
                    str(root / "out"),
                    "--fail-on",
                    "any",
                ]
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    without = veridor_main(base)
                    with_flag = veridor_main(base + ["--require-clean-teardown"])
        # Without the flag a broken cleanup endpoint does not block the gate.
        self.assertEqual(without, 0)
        self.assertEqual(with_flag, 3)

    def test_teardown_failure_is_reported_on_stderr(self) -> None:
        stderr = io.StringIO()
        with _server(_fixture_target(teardown_status=500)) as (url, _):
            with contextlib.redirect_stderr(stderr):
                _run(_sequence_config(), url)
        self.assertIn("teardown entry 0 of sequence 'seq'", stderr.getvalue())
        self.assertIn("may hold a fixture", stderr.getvalue())

    def test_teardown_uses_its_own_timeout(self) -> None:
        config = _sequence_config()
        config["target"]["teardown_timeout_seconds"] = 0.75
        seen: list[float] = []
        real = core._perform_request

        def spy(base_url, timeout, request_config, identity, **kwargs):
            seen.append(timeout)
            return real(base_url, timeout, request_config, identity, **kwargs)

        with _server(_fixture_target()) as (url, _):
            with patch.object(core, "_perform_request", spy):
                _run(config, url)
        self.assertEqual(seen[-1], 0.75)
        self.assertEqual(seen[0], 5.0)

    def test_teardown_is_skipped_when_the_session_is_unavailable(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return 500, [], b"login broke"
            if entry["method"] == "POST":
                return 201, [("Content-Type", "application/json")], b'{"id":42}'
            return 403, [], b"denied"

        config = _sequence_config()
        config["identities"] = _identities(sessions=True)
        with _server(target) as (url, log):
            result, _, _ = _run(config, url)
        self.assertEqual(log.paths("DELETE"), [])
        self.assertEqual(
            result["sequences"][0]["teardown"][0]["state"],
            "skipped_session_unavailable",
        )


# --------------------------------------------------------------------------
# (e) auth bootstrap -- fail closed
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class BootstrapTest(unittest.TestCase):
    def test_a_failed_login_makes_probes_inconclusive_not_safe(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login" and entry["auth"] == VICTIM_TOKEN:
                return 500, [], b"login broke"
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", "sid=attacker; Path=/")], b"ok"
            # The trap: an unauthenticated probe is denied, and a denial is
            # exactly what the attacker's expectation declares.
            return 403, [], b"denied"

        with _server(target) as (url, log):
            result, sessions, _ = _run(_config(), url)
        self.assertEqual(sessions["victim"].state, "failed")
        victim = _finding_map(result)[("cross-tenant-doc-read", "victim")]
        self.assertEqual(victim["verdict"], "inconclusive")
        self.assertEqual(victim["evidence_grade"], "n/a")
        self.assertEqual(victim["rule_id"], "VERIDOR-EXEC-001")
        self.assertIn("was not established", victim["message"])
        self.assertIn("this probe was not issued", victim["message"])
        # No request was issued for the victim's probe.
        self.assertEqual(
            [entry["path"] for entry in log.entries if entry["auth"] == VICTIM_TOKEN],
            ["/login"],
        )
        self.assertEqual(result["summary"]["sessions_failed"], 1)
        self.assertLess(result["summary"]["safe"], 2)

    def test_a_failed_login_degrades_the_marker_control(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return 500, [], b"login broke"
            return 200, [], MARKER_VICTIM.encode()

        config = _config()
        config["identities"]["victim"]["marker_probe"] = {"path": "/me/docs"}
        with _server(target) as (url, log):
            result, _, _ = _run(config, url)
        control = {item["identity"]: item for item in result["marker_controls"]}
        self.assertEqual(control["victim"]["state"], "unverified")
        self.assertIn("was not established", control["victim"]["reason"])
        self.assertNotIn("/me/docs", log.paths())

    def test_the_marker_probe_runs_inside_the_session(self) -> None:
        """Before this, a marker control could not work against cookie auth."""

        def target(entry: dict):
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", f"sid={_who(entry)}; Path=/")], b"ok"
            if entry["path"] == "/me/docs":
                if entry["cookie"] != "sid=victim":
                    return 401, [], b"anonymous"
                return 200, [], MARKER_VICTIM.encode()
            return _isolating_target(entry)

        config = _config()
        config["identities"]["victim"]["marker_probe"] = {"path": "/me/docs"}
        with _server(target) as (url, _):
            result, _, _ = _run(config, url)
        control = {item["identity"]: item for item in result["marker_controls"]}
        self.assertEqual(control["victim"]["state"], "verified")

    def test_reestablish_per_check_uses_a_fresh_jar(self) -> None:
        logins: list[str] = []

        def target(entry: dict):
            if entry["path"] == "/login":
                logins.append(_who(entry))
                return 200, [("Set-Cookie", f"sid={_who(entry)}; Path=/")], b"ok"
            return _isolating_target(entry)

        config = _config()
        for name in ("victim", "attacker"):
            config["identities"][name]["session"]["reestablish"] = "check"
        config["checks"] = [_doc_check(), dict(_doc_check(), id="second")]
        with _server(target) as (url, _):
            result, sessions, _ = _run(config, url)
        # One establishment at run start, then one before each of two checks.
        self.assertEqual(logins.count("victim"), 3)
        self.assertEqual(result["findings"], [])
        self.assertEqual(sessions["victim"].state, "established")

    def test_a_sequence_step_is_not_issued_without_a_session(self) -> None:
        def target(entry: dict):
            if entry["path"] == "/login":
                return 500, [], b"login broke"
            return 201, [("Content-Type", "application/json")], b'{"id":42}'

        config = _sequence_config()
        config["identities"] = _identities(sessions=True)
        with _server(target) as (url, log):
            result, _, _ = _run(config, url)
        self.assertEqual(log.paths("POST"), ["/login", "/login"])
        self.assertNotIn("/docs", log.paths())
        verdicts = {finding["verdict"] for finding in result["findings"]}
        self.assertEqual(verdicts, {"inconclusive"})


# --------------------------------------------------------------------------
# (f) blast radius
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class ReadOnlyTest(unittest.TestCase):
    def test_read_only_refuses_before_any_request(self) -> None:
        stderr = io.StringIO()
        with _server(_fixture_target()) as (url, log):
            with _written(_sequence_config(), url) as (path, root):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    stderr
                ):
                    code = veridor_main(
                        [
                            "run",
                            "--config",
                            str(path),
                            "--output-dir",
                            str(root / "out"),
                            "--read-only",
                        ]
                    )
        self.assertEqual(code, 2)
        self.assertIn("--read-only refuses POST", stderr.getvalue())
        # Not one byte reached the target.
        self.assertEqual(log.entries, [])

    @fast("asserts on the declaration, not on a live target")
    def test_read_only_refuses_a_mutating_teardown_and_login(self) -> None:
        for mutate, expected in (
            ("teardown", "--read-only refuses DELETE"),
            ("login", "--read-only refuses POST"),
        ):
            config = _sequence_config()
            if mutate == "teardown":
                config["sequences"][0]["steps"][0]["request"]["method"] = "GET"
                config["sequences"][0]["steps"][0]["request"].pop("json")
                config["sequences"][0]["steps"][0]["expect"] = {"status": [200]}
            else:
                config["sequences"] = []
                config["checks"] = [_doc_check()]
                config["identities"] = _identities(sessions=True)
            with _written(config) as (path, _):
                with self.assertRaises(ConfigError) as caught:
                    load_config(path, read_only=True)
            self.assertIn(expected, str(caught.exception))

    @fast("asserts on the declaration, not on a live target")
    def test_read_only_accepts_a_safe_configuration(self) -> None:
        with _written(_config(identities=_identities(sessions=False))) as (path, _):
            self.assertTrue(load_config(path, read_only=True))

    def test_the_run_document_records_the_mutation_block(self) -> None:
        with _server(_fixture_target()) as (url, _):
            result, _, _ = _run(_sequence_config(), url)
        self.assertEqual(
            result["mutation"], {"verbs": ["DELETE", "POST"], "requests_issued": 2}
        )

    def test_a_read_only_run_has_no_mutation_block(self) -> None:
        """A login is authentication, not a fixture write."""
        with _server(_isolating_target) as (url, _):
            result, _, _ = _run(_config(), url)
        self.assertNotIn("mutation", result)
        self.assertIn("sessions", result)

    @fast("asserts on the declaration, not on a live target")
    def test_a_mutating_check_is_on_the_disclosure_surface(self) -> None:
        # REGRESSION. The surface selected `sequence ` prefixes only, so a
        # DELETE, PUT or PATCH declared as an ordinary CHECK reached neither
        # the stderr banner nor the run document's `mutation` key -- and
        # `veridor init` scaffolds a DELETE check by default. The artifact
        # therefore denied writes that happened, on a user's very first run
        # against their own API. `--read-only` refused the same config, which
        # is the proof the tool knew.
        for method in ("DELETE", "PUT", "PATCH", "POST"):
            with self.subTest(method=method):
                check = _doc_check()
                check["request"]["method"] = method
                config = _config(
                    identities=_identities(sessions=False), checks=[check]
                )
                surface = core._mutating_disclosure_surface(config)
                self.assertEqual([entry[0] for entry in surface], [method])
                self.assertEqual(surface[0][2], "check")
                # one request per identity the check names, not one per check
                self.assertEqual(surface[0][3], len(check["expect"]))

    @fast("asserts on the declaration, not on a live target")
    def test_a_login_is_still_not_a_write(self) -> None:
        # The one deliberate carve-out, kept: a login creates no object in the
        # target and needs no cleanup. `--read-only` still refuses it.
        config = _config(identities=_identities(sessions=True), checks=[_doc_check()])
        self.assertEqual(core._mutating_disclosure_surface(config), [])
        self.assertTrue(core._mutating_requests(config))

    def test_a_run_that_issues_a_delete_check_records_it(self) -> None:
        deleted: list[str] = []

        def target(entry: dict):
            if entry["method"] == "DELETE":
                deleted.append(entry["path"])
                return 204, [], b""
            return 200, [], b"{}"

        check = _doc_check()
        check["request"]["method"] = "DELETE"
        check["expect"] = {"victim": {"status": [204]}, "attacker": {"status": [403]}}
        config = _config(identities=_identities(sessions=False), checks=[check])
        stderr = io.StringIO()
        with _server(target) as (url, _):
            with contextlib.redirect_stderr(stderr):
                result, _, _ = _run(config, url)
        self.assertEqual(len(deleted), 2)
        self.assertEqual(
            result["mutation"], {"verbs": ["DELETE"], "requests_issued": 2}
        )
        self.assertIn("write mode", stderr.getvalue())
        self.assertIn("2 mutating request(s)", stderr.getvalue())
        self.assertIn("--read-only", stderr.getvalue())


# --------------------------------------------------------------------------
# compatibility
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class CompatibilityTest(unittest.TestCase):
    def test_finding_ids_are_unchanged_when_an_identity_gains_a_session(self) -> None:
        """Invariant 3. A session touches no fingerprint input."""

        def target(entry: dict):
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", f"sid={_who(entry)}; Path=/")], b"ok"
            return 500, [], b"broken"

        without = _config(identities=_identities(sessions=False))
        with _server(target) as (url, _):
            plain, _, _ = _run(without, url)
        with _server(target) as (url, _):
            sessioned, _, _ = _run(_config(), url)
        self.assertTrue(plain["findings"])
        self.assertEqual(
            sorted(finding["id"] for finding in plain["findings"]),
            sorted(finding["id"] for finding in sessioned["findings"]),
        )

    def test_a_config_without_a_session_produces_todays_document(self) -> None:
        with _server(_isolating_target) as (url, _):
            result, _, _ = _run(_config(identities=_identities(sessions=False)), url)
        self.assertEqual(result["schema_version"], 2)
        for key in ("sessions", "mutation"):
            self.assertNotIn(key, result)
        for key in ("sessions_failed", "teardown_skipped"):
            self.assertNotIn(key, result["summary"])

    def test_a_session_emits_no_sarif_result(self) -> None:
        with _server(_isolating_target) as (url, _):
            result, _, _ = _run(_config(), url)
        sarif = core.to_sarif(result)
        self.assertIn("sessions", result)
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertNotIn("sessions", json.dumps(sarif["runs"][0]["properties"]))

    def test_the_session_block_holds_no_value_shaped_field(self) -> None:
        with _server(_isolating_target) as (url, _):
            result, _, _ = _run(_config(), url)
        blob = json.dumps(result["sessions"])
        self.assertNotIn("victim; Path", blob)
        for banned in ("value", "Set-Cookie", "headers", "token"):
            self.assertNotIn(banned, blob, banned)
        self.assertEqual(result["sessions"][0]["cookies"]["names"], ["sid"])


class ValidationTest(unittest.TestCase):
    def _rejects(self, mutate, fragment: str) -> None:
        config = _config()
        mutate(config["identities"]["victim"]["session"])
        with _written(config) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn(fragment, str(caught.exception))

    def test_a_session_without_establishes_is_refused(self) -> None:
        self._rejects(lambda s: s.pop("establishes"), "requires 'establishes'")

    def test_establishes_must_name_exactly_one_proof(self) -> None:
        self._rejects(
            lambda s: s.update(establishes={"cookie": "sid", "capture": "t"}),
            "exactly one of 'cookie' or 'capture'",
        )
        self._rejects(lambda s: s.update(establishes={}), "exactly one")

    def test_a_login_step_requires_expect_status(self) -> None:
        self._rejects(
            lambda s: s["login"][0].pop("expect_status"),
            "a 302 login is common; declare it",
        )

    def test_an_undefined_capture_reference_is_refused(self) -> None:
        self._rejects(
            lambda s: s.update(inject=[{"header": "X-T", "value": "${capture.nope}"}]),
            "references undefined capture 'nope'",
        )

    def test_a_session_capture_may_only_read_the_jar(self) -> None:
        self._rejects(
            lambda s: s.update(capture={"t": {"from": "header", "name": "X-T"}}),
            "'from' must be one of cookie",
        )

    def test_a_marker_in_a_login_body_is_refused(self) -> None:
        config = _config()
        config["identities"]["victim"]["session"]["login"][0]["body"] = (
            f"note={MARKER_VICTIM}"
        )
        with _written(config) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("session login step 0", str(caught.exception))
        self.assertIn("reflected marker", str(caught.exception))

    def test_a_marker_in_a_session_inject_value_is_refused(self) -> None:
        """Inject rides every request the identity sends after login.

        The guard read static headers, check requests, login steps and
        marker_probe, never inject. A marker literal there went out on every
        request, and a target echoing it graded LEAK-001 `confirmed` -- while
        the same value in a static header was refused at load.
        """
        encoded = base64.b64encode(MARKER_VICTIM.encode()).decode()
        for slot, value in (("header", MARKER_VICTIM),
                            ("form_field", f"x-{MARKER_VICTIM}"),
                            ("json_field", encoded)):
            name = "X-Echo" if slot == "header" else "note"
            with self.subTest(slot=slot):
                self._rejects(
                    lambda s, slot=slot, name=name, value=value: s.update(
                        inject=[{slot: name, "value": value}]
                    ),
                    "reflected marker",
                )
        # The slot's NAME is sent too: a header name, or a field name in every
        # body after login. These subTests used to put the marker in the value
        # only, so dropping the three name slots from the guard left this test
        # green while such a config loaded (measured on a copy). They assert
        # 'reflected marker' as the value subTests do: 'session inject 0' alone
        # is also the prefix of every structural refusal of the same entry
        # ("... session inject 0 'header' is not a valid header name"), so a
        # structural rule that refused the name first would have kept them
        # green with the marker guard gone.
        for slot, name in (("header", MARKER_VICTIM),
                           ("form_field", f"x-{MARKER_VICTIM}"),
                           ("json_field", MARKER_VICTIM)):
            with self.subTest(slot=slot, marker_in="name"):
                for fragment in ("session inject 0", "reflected marker"):
                    self._rejects(
                        lambda s, slot=slot, name=name: s.update(
                            inject=[{slot: name, "value": "hello"}]
                        ),
                        fragment,
                    )
        # The control: the same slots with a name and value that are not a
        # marker load.
        for slot in ("header", "form_field", "json_field"):
            with self.subTest(slot=slot, control=True):
                config = _config()
                config["identities"]["victim"]["session"]["inject"] = [
                    {slot: "X-Echo" if slot == "header" else "note", "value": "hello"}
                ]
                with _written(config) as (path, _):
                    self.assertTrue(load_config(path))

    def test_a_near_miss_session_key_is_refused(self) -> None:
        self._rejects(lambda s: s.update(establishs={"cookie": "sid"}), "did you mean")

    def test_teardown_timeout_must_be_positive(self) -> None:
        config = _config()
        config["target"]["teardown_timeout_seconds"] = 0
        with _written(config) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("teardown_timeout_seconds", str(caught.exception))


class NonGoalTest(unittest.TestCase):
    def test_the_session_layer_has_no_conditional_or_expression_key(self) -> None:
        source = Path(sequence.__file__).read_text(encoding="utf-8")
        for banned in ('"if"', '"unless"', '"retry"', '"while"', '"assert_expr"'):
            self.assertNotIn(banned, source, banned)

    def test_capture_references_cannot_collide_with_the_environment(self) -> None:
        """The dot is load-bearing: ``_ENV_PATTERN`` cannot match it."""
        self.assertEqual(core._ENV_PATTERN.findall("${capture.csrf}"), [])
        self.assertEqual(core._ENV_PATTERN.findall("${TOKEN}"), ["TOKEN"])
        self.assertEqual(
            core._CAPTURE_REF.findall("a ${capture.csrf} b"), ["csrf"]
        )

    def test_no_login_credential_appears_in_a_validation_message(self) -> None:
        config = _config()
        config["identities"]["victim"]["session"]["login"][0]["headers"] = {
            "X-Secret": PASSWORD_SENTINEL,
            "Cookie": "${capture.csrf}",
        }
        with _written(config) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertNotIn(PASSWORD_SENTINEL, str(caught.exception))

    def test_json_pointer_rejects_a_container_leaf(self) -> None:
        body = json.dumps({"a": {"b": [1, 2]}, "c": "ok", "d": 7}).encode()
        self.assertIsNone(sequence._json_pointer(body, "/a"))
        self.assertIsNone(sequence._json_pointer(body, "/a/b"))
        self.assertIsNone(sequence._json_pointer(body, "/missing"))
        self.assertEqual(sequence._json_pointer(body, "/c"), "ok")
        self.assertEqual(sequence._json_pointer(body, "/d"), "7")
        self.assertEqual(sequence._json_pointer(body, "/a/b/1"), "2")

    def test_a_control_character_in_a_captured_value_is_refused(self) -> None:
        state = _bare_session()
        sink = {"headers": [("X-T", "ok")], "body": b""}
        self.assertEqual(
            state._extract({"from": "header", "name": "X-T"}, sink), "ok"
        )
        sink["headers"] = [("X-T", "a"), ("X-T", "b")]
        self.assertIsNone(state._extract({"from": "header", "name": "X-T"}, sink))


class DocumentationTest(unittest.TestCase):
    """The README is an emitted artifact; a write tool must document its blast radius."""

    README = (ROOT / "README.md").read_text(encoding="utf-8")
    PROSE = re.sub(r"\s+", " ", README.replace("**", "").replace("*", ""))

    def test_the_readme_documents_every_new_config_key(self) -> None:
        for key in (
            '"session"',
            '"establishes"',
            '"reestablish"',
            '"inject"',
            '"capture"',
            '"teardown"',
            "teardown_timeout_seconds",
            "${capture.csrf}",
        ):
            self.assertIn(key, self.README, key)

    def test_the_readme_documents_every_new_flag_and_exit_code(self) -> None:
        for flag in ("--read-only", "--require-clean-teardown"):
            self.assertIn(flag, self.README, flag)
        self.assertIn("| `3` |", self.README)

    def test_the_readme_states_the_write_safety_posture(self) -> None:
        self.assertIn("Never at production", self.PROSE)
        self.assertIn("ephemeral environment you can recreate", self.PROSE)
        self.assertIn("Teardown never changes a verdict", self.PROSE)
        self.assertIn("Cookies never cross identities", self.PROSE)

    def test_the_readme_does_not_promise_what_teardown_cannot_do(self) -> None:
        """Teardown is not a guarantee against SIGKILL and must not read as one."""
        self.assertIn("SIGKILL", self.README)


# --------------------------------------------------------------------------
# (k) a session that is no longer live must never produce a graded probe
# --------------------------------------------------------------------------


def _idor_sequence() -> list[dict]:
    """A real IDOR: any logged-in caller reads the victim's note."""
    return [
        {
            "id": "sess-idor",
            "steps": [
                {
                    "role": "setup",
                    "as": "victim",
                    "request": {
                        "method": "POST",
                        "path": "/notes",
                        "json": {"provenance": "${marker:victim}"},
                    },
                    "expect": {"status": [201]},
                    "capture": {"note": "$.id"},
                },
                {
                    "role": "setup",
                    "as": "victim",
                    "request": {"method": "GET", "path": "/notes/${note}"},
                    "expect": {"status": [200], "contains_marker": "victim"},
                },
                {
                    "role": "assert",
                    "as": "attacker",
                    "request": {"method": "GET", "path": "/notes/${note}"},
                    "expect": {
                        "status": [401, 403, 404],
                        "excludes_marker": "victim",
                    },
                },
            ],
        }
    ]


@slow("stands up a loopback HTTP server and runs the engine against it")
class SessionLivenessTest(unittest.TestCase):
    """`state` is decided once, at the end of `establish`, and never revisited.

    A cookie expires on a clock the TARGET chose. When it does,
    `add_cookie_header` silently omits it and the probe goes out fully
    anonymous: it draws a 401, a 401 is the kind of status a denial declaration
    lists, the marker is absent, and the run is green over a live vulnerability.
    That is the exact failure this module's header says the whole section exists
    to prevent, and the unresolved-capture path already fails closed for it.
    """

    @staticmethod
    def _config(*, attacker_max_age: int | None, victim_delay: float) -> dict:
        identities = _identities(sessions=False)
        identities["victim"]["session"] = _session()
        identities["attacker"]["session"] = _session()
        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 20},
            "identities": identities,
            "checks": [],
            "sequences": _idor_sequence(),
        }
        config["_attacker_max_age"] = attacker_max_age
        config["_victim_delay"] = victim_delay
        return config

    @staticmethod
    def _target(*, attacker_max_age: int | None, victim_delay: float,
                server_side_ttl: float | None = None):
        notes: dict[str, bytes] = {}
        issued: dict[str, float] = {}

        def responder(entry: dict):
            who = _who(entry)
            if entry["path"] == "/login":
                attributes = f"sid={who}; Path=/"
                if who == "attacker" and attacker_max_age is not None:
                    attributes += f"; Max-Age={attacker_max_age}"
                issued[who] = time.time()
                return 200, [("Set-Cookie", attributes)], b"ok"

            cookie = entry["cookie"]
            live = None
            for name in ("victim", "attacker"):
                if f"sid={name}" in cookie:
                    live = name
            if live == "attacker" and server_side_ttl is not None:
                if time.time() - issued.get("attacker", 0) > server_side_ttl:
                    live = None          # idle timeout, cookie still perfect
            if live is None:
                return 401, [("Content-Type", "application/json")], b'{"e":"anon"}'

            if entry["method"] == "POST":
                notes["n1"] = json.dumps({"provenance": MARKER_VICTIM}).encode()
                return (
                    201,
                    [("Content-Type", "application/json")],
                    json.dumps({"id": "n1"}).encode(),
                )
            if live == "victim" and victim_delay:
                time.sleep(victim_delay)
            body = notes.get(entry["path"].rsplit("/", 1)[-1])
            if body is None:
                return 404, [("Content-Type", "application/json")], b'{"e":"gone"}'
            # IDOR: no ownership check at all.
            return 200, [("Content-Type", "application/json")], body

        return responder

    def _execute(self, config: dict, responder):
        with _server(responder) as (url, log):
            result, _sessions, _ = _run(config, url)
        return result, log

    def test_control_the_real_idor_is_still_reported(self) -> None:
        """A safety test that cannot fail is decoration."""
        config = self._config(attacker_max_age=None, victim_delay=0)
        result, log = self._execute(
            config, self._target(attacker_max_age=None, victim_delay=0)
        )
        rules = [finding["rule_id"] for finding in result["findings"]]
        self.assertEqual(rules, ["VERIDOR-AUTHZ-001"])
        self.assertEqual(result["findings"][0]["evidence_grade"], "confirmed")

    def test_an_expired_cookie_never_becomes_an_anonymous_probe(self) -> None:
        config = self._config(attacker_max_age=1, victim_delay=3)
        result, log = self._execute(
            config, self._target(attacker_max_age=1, victim_delay=3)
        )
        # The request is not sent at all, so it cannot be graded as a denial.
        probes = [
            entry
            for entry in log.entries
            if entry["path"].startswith("/notes/")
            and entry["auth"] == ATTACKER_TOKEN
        ]
        self.assertEqual(probes, [])
        self.assertEqual(
            {finding["verdict"] for finding in result["findings"]}, {"inconclusive"}
        )
        self.assertIn("no longer live", json.dumps(result["findings"]))

    def test_a_server_side_invalidation_is_inconclusive_not_a_pass(self) -> None:
        """The cookie is perfect; only the target knows the session is dead."""
        config = self._config(attacker_max_age=None, victim_delay=3)
        result, log = self._execute(
            config,
            self._target(
                attacker_max_age=None, victim_delay=3, server_side_ttl=1
            ),
        )
        probe = [
            entry
            for entry in log.entries
            if entry["path"].startswith("/notes/")
            and entry["auth"] == ATTACKER_TOKEN
        ]
        # The cookie WAS sent -- Veridor cannot see the problem from its jar.
        self.assertEqual(len(probe), 1)
        self.assertIn("sid=attacker", probe[0]["cookie"])
        rules = [finding["rule_id"] for finding in result["findings"]]
        self.assertEqual(rules, ["VERIDOR-SESSION-001"])
        self.assertEqual(result["findings"][0]["verdict"], "inconclusive")
        self.assertEqual(
            result["sequences"][0]["steps"][2]["state"], "mismatched"
        )

    def test_is_live_re_runs_the_proof_establish_finished_with(self) -> None:
        config = self._config(attacker_max_age=None, victim_delay=0)
        with _server(
            self._target(attacker_max_age=None, victim_delay=0)
        ) as (url, _log):
            config["target"]["base_url"] = url
            established = sequence.establish_sessions(config)
        session = established["attacker"]
        self.assertEqual(session.state, "established")
        self.assertTrue(session.is_live())
        for cookie in list(session.jar):
            session.jar.clear(cookie.domain, cookie.path, cookie.name)
        # `state` is unchanged -- that is the defect. `is_live` is not.
        self.assertEqual(session.state, "established")
        self.assertFalse(session.is_live())

    def test_an_identity_without_a_session_is_not_affected_by_the_401_rule(
        self,
    ) -> None:
        """A 401 declared for a token identity is an ordinary declaration."""
        identities = _identities(sessions=False)
        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
            "identities": identities,
            "checks": [],
            "sequences": [
                {
                    "id": "plain",
                    "steps": [
                        {
                            "role": "assert",
                            "as": "attacker",
                            "request": {"method": "GET", "path": "/notes/n1"},
                            "expect": {
                                "status": [401],
                                "excludes_marker": "victim",
                            },
                        }
                    ],
                }
            ],
        }

        def responder(entry: dict):
            return 401, [("Content-Type", "application/json")], b'{"e":"anon"}'

        with _server(responder) as (url, _log):
            result, _sessions, _ = _run(config, url)
        self.assertEqual(result["sequences"][0]["steps"][0]["state"], "matched")


@slow("stands up a loopback HTTP server and runs the engine against it")
class CookieOnlyLivenessTest(unittest.TestCase):
    """No identity declares a header, so there is nothing to shape a sham on.

    `_execute_liveness_controls` returned at once and sent nothing, while the
    banner -- counted from the plan -- announced one fabricated request per
    denial-only request. The session identities the run itself counts as
    credential-bearing never got a control, and no unproven line could appear.
    """

    @staticmethod
    def _config(*, attacker_served_elsewhere: bool,
                anonymous_refused_there: bool = True) -> dict:
        def session(user: str) -> dict:
            return {
                "login": [{"method": "POST", "path": "/login", "body": f"u={user}",
                           "expect_status": [200]}],
                "establishes": {"cookie": "sid"},
            }

        checks = [{
            "id": "doc-read",
            "request": {"method": "GET", "path": "/docs/1"},
            "expect": {"victim": {"status": [200]}, "attacker": {"status": [403]},
                       "anon": {"status": [403]}},
        }]
        if attacker_served_elsewhere:
            checks.append({
                "id": "mine",
                "request": {"method": "GET", "path": "/mine"},
                "expect": {"attacker": {"status": [200]}, "victim": {"status": [200]},
                           # The refusal that makes the attacker's 2xx proof:
                           # see test_a_2xx_where_nobody_is_refused_proves_nothing.
                           **({"anon": {"status": [403]}}
                              if anonymous_refused_there else {})},
            })
        return {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
            "identities": {
                "victim": {"session": session("victim")},
                "attacker": {"session": session("attacker")},
                "anon": {"headers": {}},
            },
            "checks": checks,
        }

    @staticmethod
    def _responder(entry: dict):
        if entry["path"] == "/login":
            user = entry["body"].decode().split("=", 1)[1]
            return 200, [("Set-Cookie", f"sid={user}; Path=/")], b"ok"
        if entry["path"] == "/mine" and entry["cookie"]:
            return 200, [], b"{}"
        if entry["cookie"] == "sid=victim":
            return 200, [], b"{}"
        return 403, [], b"{}"

    def _execute(self, config: dict):
        stderr = io.StringIO()
        with _server(self._responder) as (url, log), contextlib.redirect_stderr(stderr):
            result, _, _ = _run(config, url)
        return result, stderr.getvalue(), log

    def test_the_banner_does_not_announce_a_request_it_never_sends(self) -> None:
        result, stderr, log = self._execute(self._config(attacker_served_elsewhere=False))
        self.assertEqual(result["liveness"]["requests_issued"], 0)
        self.assertEqual(len(log.paths("GET")), 3, "victim, attacker, anon -- no sham")
        self.assertNotIn("extra request(s) carrying a credential", stderr)
        self.assertIn("no identity declares a credential header", stderr)
        # The banner described an earlier name rule ("a name with token, key,
        # auth, secret or session in it"); any non-standard header carries
        # the fabricated value now, so it says that.
        self.assertIn("any header but a standard one such as Accept", stderr)
        self.assertNotIn("a name with token", stderr)
        self.assertEqual(
            result["liveness"]["requests_not_probed"],
            [{"method": "GET", "path": "/docs/1", "reason": "no_credential_header"}],
        )

    def test_a_cookie_identity_denial_is_unproven_without_a_control(self) -> None:
        result, _, _ = self._execute(self._config(attacker_served_elsewhere=False))
        unproven = result["liveness"]["unproven"]
        # The anonymous identity sends nothing, so it has no credential to be
        # dead; the session identity does, and nothing tested it.
        self.assertEqual([entry["identity"] for entry in unproven], ["attacker"])
        self.assertEqual(unproven[0]["control"], "withheld_no_credential_header")

    def test_control_a_cookie_identity_served_elsewhere_is_proven(self) -> None:
        result, _, _ = self._execute(self._config(attacker_served_elsewhere=True))
        self.assertEqual(result["liveness"]["unproven"], [])

    def test_a_2xx_where_nobody_is_refused_proves_nothing(self) -> None:
        """`/mine` serves any cookie; nothing on that request was refused.

        No fabricated credential can be shaped in a cookie-only config, so the
        only thing that could make the attacker's 200 there proof is a caller
        with no credential being refused on the same request. Without one the
        attacker's denial on `/docs/1` stays unproven; the control above
        declares the anonymous identity on `/mine` and it is proven.
        """
        result, _, _ = self._execute(self._config(
            attacker_served_elsewhere=True, anonymous_refused_there=False))
        self.assertEqual(
            [(entry["identity"], entry.get("control"))
             for entry in result["liveness"]["unproven"]],
            [("attacker", "withheld_no_credential_header")],
        )

    def test_a_benign_header_is_not_a_credential_to_shape_a_sham_on(self) -> None:
        """An `Accept` on the anonymous identity used to become the sham.

        `_sham_header_names` took every declared header name, so one benign
        header defeated the no-header withholding: the sham carried only
        `Accept: veridor-sham-...`, no cookie, and the session identities were
        judged against it. A target that answers an unparseable Accept with
        406 then "told the credentials apart", and a dead session cookie
        passed with exit 0 under --require-complete, where the same suite with
        `anon: {headers: {}}` exited 3. Only credential-bearing names shape a
        sham now, so this is the no-header case it always was.
        """
        config = self._config(attacker_served_elsewhere=False)
        config["identities"]["anon"]["headers"] = {"Accept": "application/json"}

        def responder(entry: dict):
            if entry["accept"] and "/" not in entry["accept"]:
                return 406, [], b"bad accept"
            return self._responder(entry)

        stderr = io.StringIO()
        with _server(responder) as (url, log), contextlib.redirect_stderr(stderr):
            result, _, _ = _run(config, url)
        self.assertEqual(
            [entry for entry in log.entries if "veridor-sham-" in entry["accept"]], [],
            "a benign header must not carry a fabricated credential",
        )
        self.assertEqual(result["liveness"]["requests_issued"], 0)
        self.assertEqual(
            result["liveness"]["requests_not_probed"],
            [{"method": "GET", "path": "/docs/1", "reason": "no_credential_header"}],
        )
        controls = {entry["identity"]: entry.get("control")
                    for entry in result["liveness"]["unproven"]}
        self.assertEqual(controls.get("attacker"), "withheld_no_credential_header")
        self.assertIn("no identity declares a credential header", stderr.getvalue())

    def test_an_accept_only_anonymous_identity_is_not_listed_unproven(self) -> None:
        """One classifier decides who presents a credential.

        The sham planner already ignored a benign `Accept`, but the set of
        identities that "present a credential" counted any declared header, so
        the same anonymous identity was listed unproven -- with a marker_probe
        remediation it cannot use -- and the Action's default require-complete
        exited 3 on an ordinary cookie-session suite. With `anon: {headers:
        {}}` the same run lists only the attacker.
        """
        config = self._config(attacker_served_elsewhere=False)
        config["identities"]["anon"]["headers"] = {"Accept": "application/json"}
        result, _, _ = self._execute(config)
        self.assertEqual(
            [entry["identity"] for entry in result["liveness"]["unproven"]],
            ["attacker"],
        )


class CredentialClassifierTest(unittest.TestCase):
    """Who presents a credential, and which headers a sham is shaped on.

    Three places answered it three ways: the check path counted any declared
    header, `plan_sequence_liveness` any static header, and the sham planner
    six names plus a regex. `blastradius` answers the same question with a
    closed list of standard request headers that never carry one. They now
    share that list, so `Accept` is never a credential anywhere and a custom
    `X-Tenant` is one everywhere.
    """

    def test_benign_headers_present_no_credential(self) -> None:
        for headers in ({}, {"Accept": "application/json"},
                        {"Accept-Language": "en", "Origin": "https://a.test",
                         "Sec-Fetch-Mode": "cors", "If-None-Match": "x"}):
            with self.subTest(headers=headers):
                self.assertFalse(core.presents_credential({"headers": headers}))

    def test_any_other_header_or_a_session_presents_one(self) -> None:
        for identity in ({"headers": {"Authorization": "Bearer x"}},
                         {"headers": {"X-Tenant": "acme"}},
                         {"headers": {"PRIVATE-TOKEN": "x"}},
                         {"headers": {"Sec-WebSocket-Protocol": "bearer.x"}},
                         {"headers": {"Accept": "a/b", "X-Api-Key": "k"}},
                         {"headers": {}, "session": {"login": []}}):
            with self.subTest(identity=identity):
                self.assertTrue(core.presents_credential(identity))

    def test_blastradius_and_core_agree(self) -> None:
        from veridor import blastradius  # noqa: PLC0415

        for headers in ({"Accept": "a/b"}, {"X-Tenant": "acme"},
                        {"Sec-WebSocket-Protocol": "x"}, {"Sec-CH-UA": "x"}):
            with self.subTest(headers=headers):
                self.assertEqual(
                    core.presents_credential({"headers": headers}),
                    blastradius._presents_a_credential({"headers": headers}),
                )

    def test_a_sham_is_fabricated_on_every_header_no_two_identities_share(self) -> None:
        """Rewritten twice. It first pinned every non-benign header; a later fix
        narrowed the sham to credential-named headers, which dropped the one
        header an auth proxy names a caller by. A fabricated value now goes
        into every non-benign header except one several identities send with
        the same value (ShamSharedHeaderTest); a benign `Accept` never.
        """
        config = {"identities": {
            "anon": {"headers": {"Accept": "application/json"}},
            "a": {"headers": {"X-Tenant": "acme", "Accept": "a/b"}},
            "b": {"headers": {"Sec-WebSocket-Protocol": "bearer.x"}},
            "c": {"headers": {"PRIVATE-TOKEN": "x"}},
        }}
        self.assertEqual(core._sham_header_names(config),
                         ["PRIVATE-TOKEN", "Sec-WebSocket-Protocol", "X-Tenant"])
        self.assertTrue(core.presents_credential(config["identities"]["a"]))

    def test_an_accept_only_identity_s_assert_step_is_not_planned(self) -> None:
        def step(identity: str) -> dict:
            return {"role": "assert", "as": identity, "expect": {"status": [401]},
                    "request": {"method": "GET", "path": "/x"}}

        config = {
            "identities": {"anon": {"headers": {"Accept": "application/json"}},
                           "tenant": {"headers": {"X-Tenant": "acme"}}},
            "sequences": [{"id": "s", "steps": [step("anon"), step("tenant")]}],
        }
        self.assertEqual(
            [index for _, index, _, _, _ in core.plan_sequence_liveness(config)],
            [1],
        )


class TenantFirstTargetTest(unittest.TestCase):
    """REGRESSION, through `veridor run` with a recording opener.

    The target resolves X-Tenant-Id before it reads a credential: missing is
    400, unknown is 404 ("tenant not found"). /branding is per tenant and
    reads no credential; /invoices/b1 is bob's and hides existence with 404.
    alice's token is never valid. The sham carried a fabricated X-Tenant-Id,
    drew 404 on both requests, and that 404 read as a credential refused: her
    200 on /branding proved her live and the run exited 0 under
    --require-complete, though nothing about her credential was measured
    (reproduced; the previous version exited 3). Control: an X-Api-Version only
    alice sends, against a target that 400s an unknown version, exits 0 --
    the fabricated version drew 400 and made that run exit 3.
    """

    def _run(self, scenario: str) -> tuple[int, dict, list]:
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        wire: list[dict] = []

        class Target:
            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                headers = {k.lower(): v for k, v in request.header_items()}
                path = request.full_url.split("127.0.0.1:9", 1)[1]
                wire.append({"path": path, **headers})
                status = answer(path, headers)
                message = email.message.Message()
                message["Content-Length"] = "2"
                message["Content-Type"] = "application/json"
                return urllib.response.addinfourl(io.BytesIO(b"{}"), message,
                                                  request.full_url, status)

        def answer(path: str, headers: dict) -> int:
            if scenario == "version":
                if headers.get("x-api-version", "2024-01") != "2024-01":
                    return 400
                if headers.get("authorization") not in ("Bearer alice-token",
                                                        "Bearer bob-token"):
                    return 401
                return 200 if path == "/me" or "bob" in headers["authorization"] else 403
            tenant = headers.get("x-tenant-id")
            if tenant is None:
                return 400
            if tenant not in ("a", "b"):
                return 404
            if path == "/branding":
                return 200
            return 200 if tenant == "b" and headers.get("authorization") == "Bearer bob-token" else 404

        if scenario == "version":
            identities = {"alice": {"headers": {"Authorization": "Bearer alice-token",
                                                "X-Api-Version": "2024-01"}},
                          "bob": {"headers": {"Authorization": "Bearer bob-token"}}}
            checks = [{"id": "me", "request": {"method": "GET", "path": "/me"},
                       "expect": {"alice": {"status": [200]}, "bob": {"status": [200]}}},
                      {"id": "admin", "request": {"method": "GET", "path": "/admin"},
                       "expect": {"bob": {"status": [200]}, "alice": {"status": [403]}}}]
        else:
            identities = {"alice": {"headers": {"Authorization": "Bearer alice-token",
                                                "X-Tenant-Id": "a"}},
                          "bob": {"headers": {"Authorization": "Bearer bob-token",
                                              "X-Tenant-Id": "b"}}}
            checks = [{"id": "branding", "request": {"method": "GET", "path": "/branding"},
                       "expect": {"alice": {"status": [200]}, "bob": {"status": [200]}}},
                      {"id": "cross", "request": {"method": "GET", "path": "/invoices/b1"},
                       "expect": {"bob": {"status": [200]}, "alice": {"status": [404]}}}]
        config = {"version": 2,
                  "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
                  "identities": identities, "checks": checks}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with patch.object(core, "_OPENER", Target()), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    code = veridor_main(["run", "--config", str(path), "--output-dir",
                                         str(root / "h"), "--require-complete"])
                except SystemExit as exc:
                    code = exc.code
            document = json.loads((root / "h" / "latest.json").read_text("utf-8"))
        shams = [entry for entry in wire
                 if "veridor-sham" in entry.get("authorization", "")]
        return code, document, shams

    def test_an_expired_token_behind_a_tenant_first_target_is_unproven(self) -> None:
        code, document, shams = self._run("tenant")
        self.assertTrue(shams, "no fabricated credential was sent")
        for sham in shams:
            self.assertNotIn("x-tenant-id", sham)
        self.assertEqual(code, 3)
        self.assertEqual([entry["identity"] for entry in document["liveness"]["unproven"]],
                         ["alice"])

    def test_control_a_version_only_one_identity_sends_is_not_fabricated(self) -> None:
        code, document, shams = self._run("version")
        self.assertTrue(shams)
        for sham in shams:
            self.assertNotIn("veridor-sham", sham.get("x-api-version", ""))
        self.assertEqual(code, 0, document["liveness"].get("unproven"))


class ShamSharedHeaderTest(unittest.TestCase):
    """Which headers carry a fabricated value, which a shared one, which none.

    The sham carried `veridor-sham-...` on every non-benign header, so an
    `X-Api-Version` (or `Stripe-Version`, `X-Tenant-Id`) declared beside
    `Authorization` was overwritten too. A target that refuses an unknown
    version with 400 answered every sham 400, every denial on the run went
    `control_uninformative`, and an ordinary versioned-API suite exited 3
    under --require-complete. Now a non-benign header that two or more
    identities send with one identical value, and whose name does not mark it
    a credential, rides along unchanged. Any other header whose name does not
    mark it a credential is left out when every identity declaring it also
    presents another credential (a credential-named header or a session):
    beside Authorization an X-Tenant-Id is routing, and fabricating it let a
    tenant-first target's "tenant not found" 404 read as a credential refused,
    so an expired token passed (TenantFirstTargetTest). Where it is
    the declarer's only credential it is fabricated: an earlier version left every such
    header out, which dropped the one header an auth-proxy setup identifies
    the caller by (X-Remote-User, X-Forwarded-User), so no sham could be
    shaped and every denial went withheld. Socket-free: the request is
    captured, not sent.
    """

    TOKEN = "veridor-sham-vdr-Qx7Lm2Np9Rt4Vb8Kc3Hj6Wd"  # gitleaks:allow

    def _sham(self, identities: dict) -> dict | None:
        config = {
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
            "identities": identities,
            "checks": [{
                "id": "c",
                "request": {"method": "GET", "path": "/x"},
                "expect": {name: {"status": [403]} for name in identities},
            }],
        }
        sent: list[dict] = []

        def capture(_base, _timeout, _request, identity, **_kwargs):
            sent.append(dict(identity.get("headers") or {}))
            return {"request": {}, "response": {"status": 401}, "error": None}

        with patch.object(core, "_perform_request", capture):
            core._execute_liveness_controls(config, self.TOKEN)
        self.assertLessEqual(len(sent), 1)
        return sent[0] if sent else None

    def test_a_shared_api_version_rides_the_sham_unchanged(self) -> None:
        sham = self._sham({
            "admin": {"headers": {"Authorization": "Bearer a",
                                  "X-Api-Version": "2024-01-01"}},
            "user": {"headers": {"Authorization": "Bearer u",
                                 "X-Api-Version": "2024-01-01"}},
            "anon": {"headers": {}},
        })
        self.assertEqual(sham, {"Authorization": f"Bearer {self.TOKEN}",
                                "X-Api-Version": "2024-01-01"})

    def test_every_common_version_header_is_carried(self) -> None:
        for name in ("X-GitHub-Api-Version", "Stripe-Version", "Notion-Version"):
            with self.subTest(header=name):
                sham = self._sham({
                    "a": {"headers": {"Authorization": "Bearer a", name: "v9"}},
                    "b": {"headers": {"Authorization": "Bearer b", name: "v9"}},
                })
                self.assertEqual(sham, {"Authorization": f"Bearer {self.TOKEN}",
                                        name: "v9"})

    def test_a_tenant_beside_a_credential_is_left_out(self) -> None:
        """Rewritten. It pinned a fabricated X-Tenant-Id, and a
        target that resolves the tenant first answered that sham 404 "tenant
        not found", which proved an expired token live. Beside Authorization
        the tenant is routing, not the credential, so the sham leaves it
        out."""
        sham = self._sham({
            "admin": {"headers": {"Authorization": "Bearer a", "X-Tenant-Id": "t1"}},
            "user": {"headers": {"Authorization": "Bearer u", "X-Tenant-Id": "t2"}},
        })
        self.assertEqual(sham, {"Authorization": f"Bearer {self.TOKEN}"})

    def test_a_header_one_identity_declares_beside_a_credential_is_left_out(self) -> None:
        """Rewritten: it pinned a fabricated X-Partner-Id. Beside
        the declarer's own Authorization it is context the sham does not send;
        alone it may be the credential, and is fabricated."""
        sham = self._sham({
            "admin": {"headers": {"Authorization": "Bearer a"}},
            "partner": {"headers": {"Authorization": "Bearer p", "X-Partner-Id": "p1"}},
        })
        self.assertEqual(sham, {"Authorization": f"Bearer {self.TOKEN}"})
        sham = self._sham({
            "admin": {"headers": {"Authorization": "Bearer a"}},
            "partner": {"headers": {"X-Partner-Id": "p1"}},
        })
        self.assertEqual(sham, {"Authorization": f"Bearer {self.TOKEN}",
                                "X-Partner-Id": self.TOKEN})

    def test_a_tenant_beside_a_session_is_left_out(self) -> None:
        """A session is the credential; a fabricated tenant beside it is the
        whole sham, and a tenant-first target's 404 to it proved the session
        live. With nothing left to fabricate no sham is sent."""
        def session(user: str) -> dict:
            return {"login": [{"method": "POST", "path": "/login", "body": f"u={user}",
                               "expect_status": [200]}],
                    "establishes": {"cookie": "sid"}}

        config = {"identities": {
            "a": {"session": session("a"), "headers": {"X-Tenant-Id": "t1"}},
            "b": {"session": session("b"), "headers": {"X-Tenant-Id": "t2"}},
        }}
        self.assertEqual(core._sham_header_names(config), [])

    def test_an_auth_proxy_user_header_is_fabricated(self) -> None:
        """Behind an auth proxy the caller is
        named by X-Remote-User alone, a name no heuristic marks a credential."""
        for name in ("X-Remote-User", "X-Forwarded-User", "X-User-Id", "Impersonate-User"):
            with self.subTest(header=name):
                sham = self._sham({
                    "alice": {"headers": {name: "alice"}},
                    "bob": {"headers": {name: "bob"}},
                })
                self.assertEqual(sham, {name: self.TOKEN})

    def test_a_custom_session_token_is_fabricated(self) -> None:
        sham = self._sham({
            "a": {"headers": {"X-Session-Token": "s-a", "X-Api-Version": "3"}},
            "b": {"headers": {"X-Session-Token": "s-b", "X-Api-Version": "3"}},
        })
        self.assertEqual(sham, {"X-Session-Token": self.TOKEN, "X-Api-Version": "3"})

    def test_a_shared_value_under_a_credential_name_is_still_fabricated(self) -> None:
        sham = self._sham({
            "a": {"headers": {"Authorization": "Bearer a", "X-Api-Key": "app"}},
            "b": {"headers": {"Authorization": "Bearer b", "X-Api-Key": "app"}},
        })
        self.assertEqual(sham, {"Authorization": f"Bearer {self.TOKEN}",
                                "X-Api-Key": self.TOKEN})

    def test_only_a_shared_header_sends_no_sham(self) -> None:
        """A header every identity sends with one value tells none of them
        apart, so with nothing else there is nothing to fabricate: the
        request is `no_credential_header`, as with no header at all."""
        identities = {
            "a": {"headers": {"X-Api-Version": "3"}},
            "b": {"headers": {"X-Api-Version": "3"}},
        }
        self.assertIsNone(self._sham(identities))
        self.assertEqual(core._sham_header_names({"identities": identities}), [])


@slow("stands up a loopback HTTP server and runs the engine against it")
class ShamApiVersionEndToEndTest(unittest.TestCase):
    """A target that 400s an unknown API version, end to end.

    Reproduced: the sham carried `X-Api-Version:
    veridor-sham-...`, drew 400, and the user's denial was listed
    `control_uninformative`, so the run exited 3 under --require-complete.
    """

    def test_a_versioned_api_s_denial_is_proven_by_the_sham(self) -> None:
        config = {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
            "identities": {
                "admin": {"headers": {"Authorization": "Bearer admin-tok",
                                      "X-Api-Version": "2024-01-01"}},
                "user": {"headers": {"Authorization": "Bearer user-tok",
                                     "X-Api-Version": "2024-01-01"}},
            },
            "checks": [{
                "id": "admin-only",
                "request": {"method": "GET", "path": "/admin"},
                "expect": {"admin": {"status": [200]}, "user": {"status": [403]}},
            }],
        }

        def responder(entry: dict):
            if entry["headers"].get("x-api-version") != "2024-01-01":
                return 400, [], b"unknown version"
            if entry["auth"] == "Bearer admin-tok":
                return 200, [], b"{}"
            if entry["auth"] == "Bearer user-tok":
                return 403, [], b"{}"
            return 401, [], b"{}"

        with _server(responder) as (url, log), contextlib.redirect_stderr(io.StringIO()):
            result, _, _ = _run(config, url)
        shams = [entry for entry in log.entries if "veridor-sham-" in entry["auth"]]
        self.assertEqual(len(shams), 1)
        self.assertEqual(shams[0]["headers"].get("x-api-version"), "2024-01-01")
        self.assertEqual(result["liveness"]["unproven"], [])


class EstablishesUnknownKeyTest(unittest.TestCase):
    """`establishes` was the one session object that accepted anything.

    Found by writing a CSRF probe against a plausible-but-wrong schema: an
    operator who puts `"csrf": {...}` inside `establishes` -- a reasonable
    guess, since CSRF genuinely is a session concern -- used to get silence and
    a session that established nothing of the sort. Silently ignoring
    configuration is how a check becomes vacuous, which is the exact failure
    this product exists to surface, so it must not be the loader's own
    behaviour.
    """

    def _config(self, establishes: dict) -> dict:
        return {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:9"},
            "identities": {
                "a": {
                    "headers": {"X": "1"},
                    "session": {
                        "login": [
                            {
                                "method": "GET",
                                "path": "/login",
                                "expect_status": [200],
                                "capture": {
                                    "csrf": {"from": "html_meta", "name": "csrf-token"}
                                },
                            }
                        ],
                        "inject": [
                            {"header": "X-CSRFToken", "value": "${capture.csrf}"}
                        ],
                        "establishes": establishes,
                    },
                },
                "b": {"headers": {"X": "2"}},
            },
            "checks": [
                {
                    "id": "c",
                    "request": {"method": "GET", "path": "/x"},
                    "expect": {"a": {"status": [200]}, "b": {"status": [403]}},
                }
            ],
        }

    def _load(self, establishes: dict):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(self._config(establishes)), encoding="utf-8")
            return load_config(path, None)

    def test_both_supported_shapes_still_load(self) -> None:
        self._load({"capture": "csrf"})
        self._load({"cookie": "sid"})

    def test_an_unknown_key_is_refused_rather_than_ignored(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self._load({"capture": "csrf", "csrf": {"from": "html_meta"}})
        message = str(caught.exception)
        self.assertIn("unsupported keys: csrf", message)
        # The message has to say where CSRF actually goes, or the operator
        # simply moves the same wrong key somewhere else.
        self.assertIn("inject", message)


# --------------------------------------------------------------------------
# a cookie that expires between prepare() and attach_cookies()
# --------------------------------------------------------------------------

import http.cookiejar  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402
from urllib.request import Request  # noqa: E402


class _Clock:
    """``time`` as http.cookiejar and veridor.sequence see it, plus an offset.

    prepare() asks is_live(), then add_cookie_header() reads the clock again.
    Moving this clock between the two is the race, made certain: measured on
    a real clock the window is about 12 us median and 113 us at worst, which
    no wall-clock test can hit on purpose.
    """

    def __init__(self) -> None:
        self.offset = 0.0

    def __getattr__(self, name: str):
        return getattr(time, name)

    def time(self) -> float:
        return time.time() + self.offset

    def past(self, expires: int) -> None:
        self.offset = expires + 1 - time.time()


@contextlib.contextmanager
def _clock():
    clock = _Clock()
    with patch.object(http.cookiejar, "time", clock), patch.object(sequence, "time", clock):
        yield clock


def _jar_session(
    *, path: str = "/", establishes: dict | None = None, capture: dict | None = None
) -> sequence.IdentitySession:
    declaration: dict = {"establishes": establishes or {"cookie": "sid"}}
    if capture:
        declaration["capture"] = capture
    session = sequence.IdentitySession(
        "attacker", {"headers": {}, "session": declaration}, "http://127.0.0.1:1", 5, {}
    )
    session.jar.set_cookie(http.cookiejar.Cookie(
        0, "sid", "attacker", None, False, "127.0.0.1", False, False, path, True,
        False, int(time.time()) + 100, False, None, None, {}))
    session.state = "established"
    if session._establishing_cookie() == "sid":
        # What establish() records as the proof: this cookie, by its jar identity.
        session._proof = frozenset({("127.0.0.1", path, "sid")})
    return session


def _expires(session: sequence.IdentitySession) -> int:
    return next(cookie.expires for cookie in session.jar if cookie.name == "sid")


class AttachCookiesRaceTest(unittest.TestCase):
    """attach_cookies() looks for the session cookie on the request it built."""

    def _race(self, session: sequence.IdentitySession, clock: _Clock):
        _headers, _body, blocked, _ = session.prepare({}, None, method="GET")
        self.assertIsNone(blocked, "prepare() saw a live session")
        clock.past(_expires(session))
        request = Request("http://127.0.0.1:1/notes/n1", method="GET")
        return session.attach_cookies(request), request

    def test_a_cookie_that_expires_after_prepare_is_refused_at_attach(self) -> None:
        with _clock() as clock:
            reason, request = self._race(_jar_session(), clock)
        # The jar left it off without a word; that is the race.
        self.assertIsNone(request.get_header("Cookie"))
        self.assertEqual(reason, "session_expired")

    def test_control_a_live_cookie_goes_on_and_nothing_is_refused(self) -> None:
        session = _jar_session()
        with _clock():
            request = Request("http://127.0.0.1:1/notes/n1", method="GET")
            self.assertIsNone(session.prepare({}, None, method="GET")[2])
            self.assertIsNone(session.attach_cookies(request))
        self.assertEqual(request.get_header("Cookie"), "sid=attacker")

    def test_a_cookie_scoped_away_from_the_url_is_refused_by_its_own_reason(self) -> None:
        session = _jar_session(path="/app")
        request = Request("http://127.0.0.1:1/notes/n1", method="GET")
        self.assertTrue(session.is_live())
        self.assertEqual(session.attach_cookies(request), "session_cookie_not_sent")
        self.assertIn("session_cookie_not_sent", core.UNSENT_REASONS)
        inside = Request("http://127.0.0.1:1/app/notes/n1", method="GET")
        self.assertIsNone(session.attach_cookies(inside))

    def test_a_login_step_is_never_refused(self) -> None:
        """Login runs before the session exists, with whatever the jar holds."""
        session = _jar_session(path="/app")
        session.state = "pending"
        request = Request("http://127.0.0.1:1/login", method="POST")
        self.assertIsNone(session.attach_cookies(request))

    def test_a_capture_read_from_the_cookie_is_the_same_proof(self) -> None:
        session = _jar_session(
            establishes={"capture": "csrf"},
            capture={"csrf": {"from": "cookie", "name": "sid"}},
        )
        with _clock() as clock:
            reason, _request = self._race(session, clock)
        self.assertEqual(reason, "session_expired")

    def test_a_capture_from_the_response_body_has_no_cookie_to_lose(self) -> None:
        """Its value is in the request already; the jar cannot take it back.

        A login step's capture from a header or body lands in ``_values``;
        a capture from a cookie, on the session or a login step, is read from
        the jar.
        """
        session = _jar_session(establishes={"capture": "token"})
        session._values["token"] = "tok"
        with _clock() as clock:
            reason, request = self._race(session, clock)
        self.assertIsNone(reason)
        self.assertIsNone(request.get_header("Cookie"))

    def test_perform_request_sends_nothing_when_attach_refuses(self) -> None:
        class Opener:
            def open(self, *_args, **_kwargs):
                raise AssertionError("a request reached the opener")

        session = _jar_session()
        real_attach = sequence.IdentitySession.attach_cookies

        def attach(inner, request):
            clock.past(_expires(inner))
            return real_attach(inner, request)

        with _clock() as clock, patch.object(core, "_OPENER", Opener()), \
                patch.object(sequence.IdentitySession, "attach_cookies", attach):
            result = core._perform_request(
                "http://127.0.0.1:1", 5, {"method": "GET", "path": "/docs/1"},
                {"headers": {}}, marker=MARKER_VICTIM, session=session,
            )
        self.assertEqual(result["error"], core.UNSENT_REASONS["session_expired"])
        self.assertIsNone(result["response"]["status"])
        self.assertEqual(result["response"]["marker_scan"], "unknown")


class SessionRemediationTest(unittest.TestCase):
    """A request a session could not carry gets session advice, not network advice."""

    def test_each_session_reason_gets_session_advice(self) -> None:
        for reason in ("session_unavailable", "session_expired", "session_cookie_not_sent"):
            with self.subTest(reason=reason):
                advice = core.unsent_remediation(core.UNSENT_REASONS[reason])
                self.assertIsNotNone(advice)
                self.assertNotIn("reachable", advice)
        self.assertIn("reestablish", core.unsent_remediation(
            core.UNSENT_REASONS["session_expired"]))

    def test_a_step_message_of_its_own_is_matched_by_its_reason(self) -> None:
        advice = core.unsent_remediation(
            "the session for 'a' was not established (x); this step was not issued",
            "session_unavailable",
        )
        self.assertEqual(advice, core.SESSION_NOT_ESTABLISHED_REMEDIATION)

    def test_the_gate_still_does_not_call_a_session_failure_configuration(self) -> None:
        """Exit codes read CONFIGURATION_UNSENT_ERRORS; a session can fail on the target."""
        for reason in ("session_unavailable", "session_expired", "session_cookie_not_sent"):
            self.assertNotIn(reason, core.CONFIGURATION_UNSENT_ERRORS.values())

    def test_control_a_transport_failure_still_gets_no_unsent_advice(self) -> None:
        self.assertIsNone(core.unsent_remediation("connection refused"))


@slow("stands up a loopback HTTP server and runs the engine against it")
class CookieExpiresBetweenPrepareAndAttachTest(unittest.TestCase):
    """The attacker's cookie expires after is_live() said yes and before the jar runs.

    The target answers an anonymous request with 404, a status the denial
    declaration lists and not one the 401 rule catches. Before the fix the
    graded probe went out with an empty Cookie header, drew that 404, and a
    live IDOR was graded safe (check) or matched (sequence).
    """

    PROBE = {"seq": "/notes/n1", "check": "/docs/1"}

    @staticmethod
    def _target(*, cookie_path: str = "/"):
        notes: dict[str, bytes] = {}

        def responder(entry: dict):
            who = _who(entry)
            if entry["path"] == "/login":
                attributes = f"sid={who}; Path={cookie_path}"
                if who == "attacker":
                    attributes += "; Max-Age=100"
                return 200, [("Set-Cookie", attributes)], b"ok"
            if "sid=" not in entry["cookie"]:
                return 404, [("Content-Type", "application/json")], b'{"e":"anon"}'
            if entry["method"] == "POST":
                notes["n1"] = json.dumps({"provenance": MARKER_VICTIM}).encode()
                return 201, [("Content-Type", "application/json")], b'{"id":"n1"}'
            if entry["path"] == "/m":
                owner = MARKER_ATTACKER if who == "attacker" else MARKER_VICTIM
                return 200, [("Content-Type", "application/json")], json.dumps(
                    {"m": owner}).encode()
            # IDOR: any logged-in caller reads the victim's record.
            body = notes.get("n1") or json.dumps({"provenance": MARKER_VICTIM}).encode()
            return 200, [("Content-Type", "application/json")], body

        return responder

    @staticmethod
    def _config(kind: str) -> dict:
        identities = _identities(sessions=True)
        if kind == "seq":
            sequences = _idor_sequence()
            sequences[0]["steps"][2]["expect"]["status"] = [403, 404]
            return {"version": 2,
                    "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                    "identities": identities, "checks": [], "sequences": sequences}
        for identity in identities.values():
            identity["marker_probe"] = {"method": "GET", "path": "/m"}
        check = _doc_check()
        check["expect"]["attacker"]["status"] = [403, 404]
        return {"version": 1,
                "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                "identities": identities, "checks": [check]}

    def _execute(self, kind: str, *, race: bool, cookie_path: str = "/"):
        real_attach = sequence.IdentitySession.attach_cookies
        fired: list[str] = []

        def attach(session, request):
            # The attacker's own graded probe, not the sham liveness control
            # that replaces its Authorization header.
            if (race and not fired and session.name == "attacker"
                    and session.state == "established"
                    and request.get_header("Authorization") == ATTACKER_TOKEN
                    and urlsplit(request.full_url).path == self.PROBE[kind]):
                fired.append(request.full_url)
                clock.past(_expires(session))
            return real_attach(session, request)

        with _clock() as clock, \
                patch.object(sequence.IdentitySession, "attach_cookies", attach), \
                _server(self._target(cookie_path=cookie_path)) as (url, log):
            result, _sessions, _ = _run(self._config(kind), url)
        if race:
            self.assertEqual(len(fired), 1, "the race was never forced")
        probes = [entry for entry in log.entries
                  if entry["auth"] == ATTACKER_TOKEN and entry["path"] == self.PROBE[kind]]
        return result, probes

    def test_control_without_the_race_the_idor_is_confirmed(self) -> None:
        for kind in ("seq", "check"):
            with self.subTest(kind=kind):
                result, probes = self._execute(kind, race=False)
                self.assertEqual(len(probes), 1)
                self.assertIn("sid=attacker", probes[0]["cookie"])
                rules = [(f["rule_id"], f["verdict"], f["evidence_grade"])
                         for f in result["findings"]]
                self.assertEqual(rules, [("VERIDOR-AUTHZ-001", "vulnerable", "confirmed")])

    def test_the_sequence_assert_step_is_never_sent_anonymous(self) -> None:
        result, probes = self._execute("seq", race=True)
        self.assertEqual(probes, [], "an anonymous graded probe reached the target")
        steps = result["sequences"][0]["steps"]
        self.assertNotEqual(steps[2]["state"], "matched")
        self.assertEqual(result["summary"]["sequence_steps_matched"], 2)
        self.assertEqual(result["summary"]["safe"], 0)
        self.assertEqual([(f["rule_id"], f["verdict"]) for f in result["findings"]],
                         [("VERIDOR-EXEC-001", "inconclusive")])
        finding = result["findings"][0]
        self.assertIn("no longer live", finding["message"])
        self.assertIn("reestablish", finding["remediation"])

    def test_the_check_probe_is_never_sent_anonymous(self) -> None:
        result, probes = self._execute("check", race=True)
        self.assertEqual(probes, [], "an anonymous graded probe reached the target")
        attacker = _finding_map(result)[("cross-tenant-doc-read", "attacker")]
        self.assertEqual((attacker["rule_id"], attacker["verdict"]),
                         ("VERIDOR-EXEC-001", "inconclusive"))
        self.assertIn("no longer live", attacker["message"])
        self.assertIn("reestablish", attacker["remediation"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        # The victim's probe is the only one graded safe.
        self.assertEqual(result["summary"]["safe"], 1)

    def test_a_cookie_scoped_away_from_the_probe_is_not_sent_anonymous(self) -> None:
        result, probes = self._execute("check", race=False, cookie_path="/app")
        self.assertEqual(probes, [])
        attacker = _finding_map(result)[("cross-tenant-doc-read", "attacker")]
        self.assertEqual(attacker["verdict"], "inconclusive")
        self.assertIn("Path or Domain", attacker["message"])


@slow("stands up a loopback HTTP server and runs the engine against it")
class SequenceSessionRemediationTest(unittest.TestCase):
    """A sequence step whose session never established was told to check the network.

    The login answered 200; its cookie was the problem. The check path has
    always said so.
    """

    def test_the_sequence_step_gets_the_advice_the_check_probe_gets(self) -> None:
        def responder(entry: dict):
            # Logs in fine, and sets a cookie under a name nobody declared.
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", "other=1; Path=/")], b"ok"
            return 404, [], b""

        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
            "identities": _identities(sessions=True),
            "checks": [_doc_check()],
            "sequences": _idor_sequence(),
        }
        with _server(responder) as (url, log):
            result, _sessions, _ = _run(config, url)
        # Nothing but the logins went out as either identity (the liveness
        # control's fabricated credential is neither).
        self.assertEqual(
            {entry["path"] for entry in log.entries
             if entry["auth"] in (VICTIM_TOKEN, ATTACKER_TOKEN)},
            {"/login"},
        )
        execution = [f for f in result["findings"] if f["rule_id"] == "VERIDOR-EXEC-001"]
        steps = [f for f in execution if f["check_id"] == "sess-idor"]
        checks = [f for f in execution if f["check_id"] == "cross-tenant-doc-read"]
        self.assertEqual((len(steps), len(checks)), (1, 2))
        for finding in steps + checks:
            with self.subTest(finding=finding["id"]):
                self.assertEqual(finding["verdict"], "inconclusive")
                self.assertEqual(finding["remediation"],
                                 core.SESSION_NOT_ESTABLISHED_REMEDIATION)
                self.assertNotIn("reachable", finding["remediation"])
        # Nothing was sent, so it does not say the request failed.
        self.assertTrue(steps[0]["message"].startswith("Request not sent: "))



# --------------------------------------------------------------------------
# What proves a session, and what a request carries from a cookie
# --------------------------------------------------------------------------


def _cookie(name: str, value: str, *, path: str = "/", max_age: int = 100):
    return http.cookiejar.Cookie(
        0, name, value, None, False, "127.0.0.1", False, False, path, True,
        False, int(time.time()) + max_age, False, None, None, {})


def _offline_session(declaration: dict, *cookies) -> sequence.IdentitySession:
    """Run establish() with the login step answered in process, no socket.

    Each login request puts ``cookies`` into the jar and answers 200, which is
    all establish() reads from a login response for a cookie proof.
    """
    session = sequence.IdentitySession(
        "attacker", {"headers": {}, "session": declaration}, "http://127.0.0.1:1", 5, {}
    )

    def perform(base_url, timeout, request_config, identity, *, session=None, **_):
        for cookie in cookies:
            session.jar.set_cookie(cookie)
        return {
            "request": {"method": "POST", "url": f"{base_url}/login"},
            "response": {"status": 200, "duration_ms": 1, "body_bytes": 2,
                         "body_sha256": "0" * 64},
            "error": None,
        }

    with patch.object(core, "_perform_request", perform):
        session.establish()
    return session


def _login(capture: dict | None = None) -> list[dict]:
    step: dict = {"method": "POST", "path": "/login", "expect_status": [200]}
    if capture:
        step["capture"] = capture
    return [step]


def _expiry_of(session: sequence.IdentitySession, name: str) -> int:
    return max(cookie.expires for cookie in session.jar if cookie.name == name)


class LoginStepCookieCaptureIsLiveTest(unittest.TestCase):
    """A login step's capture read from a cookie is read from the jar when used.

    It was frozen in the value map at login. As the establishing proof
    (``establishes: {"capture": NAME}``) it kept the session "live" after the
    cookie expired, attach_cookies() had no cookie to look for, and the graded
    probe went out anonymous: safe 2, vulnerable 0 over a confirmed IDOR.
    """

    DECLARATION = {
        "login": _login({"tok": {"from": "cookie", "name": "sid"}}),
        "establishes": {"capture": "tok"},
    }

    def _session(self) -> sequence.IdentitySession:
        session = _offline_session(self.DECLARATION, _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established", session.reason)
        return session

    def test_control_while_the_cookie_lives_the_session_is_live(self) -> None:
        session = self._session()
        with _clock():
            self.assertTrue(session.is_live())
            self.assertEqual(session.lookup("tok"), "attacker")
            self.assertIsNone(session.prepare({}, None, method="GET")[2])
            request = Request("http://127.0.0.1:1/docs/1", method="GET")
            self.assertIsNone(session.attach_cookies(request))
        self.assertEqual(request.get_header("Cookie"), "sid=attacker")

    def test_the_session_dies_with_the_cookie(self) -> None:
        session = self._session()
        with _clock() as clock:
            clock.past(_expiry_of(session, "sid"))
            self.assertFalse(session.is_live())
            self.assertIsNone(session.lookup("tok"))
            self.assertEqual(session.prepare({}, None, method="GET")[2], "session_expired")

    def test_a_cookie_that_expires_after_prepare_is_refused_at_attach(self) -> None:
        session = self._session()
        with _clock() as clock:
            self.assertIsNone(session.prepare({}, None, method="GET")[2])
            clock.past(_expiry_of(session, "sid"))
            request = Request("http://127.0.0.1:1/docs/1", method="GET")
            self.assertEqual(session.attach_cookies(request), "session_expired")
        self.assertIsNone(request.get_header("Cookie"))

    def test_control_a_login_step_capture_from_a_header_stays_frozen(self) -> None:
        """Only a cookie source has a jar to read again; the rest is one response."""
        session = sequence.IdentitySession(
            "attacker",
            {"headers": {}, "session": {
                "login": _login({"tok": {"from": "header", "name": "X-Token"}}),
                "establishes": {"capture": "tok"}}},
            "http://127.0.0.1:1", 5, {},
        )

        def perform(base_url, timeout, request_config, identity, *, sink=None, **_):
            sink["headers"] = [("X-Token", "frozen-token")]
            return {"request": {"method": "POST", "url": f"{base_url}/login"},
                    "response": {"status": 200, "duration_ms": 1, "body_bytes": 0,
                                 "body_sha256": "0" * 64},
                    "error": None}

        with patch.object(core, "_perform_request", perform):
            session.establish()
        self.assertEqual(session.state, "established")
        with _clock() as clock:
            clock.offset = 10_000
            self.assertTrue(session.is_live())
            self.assertEqual(session.lookup("tok"), "frozen-token")


class EmptyCookieIsNoProofTest(unittest.TestCase):
    """``Set-Cookie: sid=`` clears a cookie; it never proved a session.

    establish() and is_live() tested the cookie for ``is not None``, so an
    empty one established the session and every probe went out as ``sid=``,
    which a target treats as anonymous: safe 2, vulnerable 0 over a confirmed
    IDOR. A capture proof already had to be non-empty.
    """

    COOKIE = {"login": _login(), "establishes": {"cookie": "sid"}}
    CSRF = {
        "login": _login(), "establishes": {"cookie": "sid"},
        "capture": {"csrf": {"from": "cookie", "name": "csrftoken"}},
        "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
    }

    def test_an_empty_establishing_cookie_does_not_establish(self) -> None:
        session = _offline_session(self.COOKIE, _cookie("sid", ""))
        self.assertEqual(session.state, "failed")
        self.assertEqual(session.reason_code, "not_established")
        self.assertFalse(session.is_live())

    def test_control_a_non_empty_one_does(self) -> None:
        session = _offline_session(self.COOKIE, _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established")
        self.assertTrue(session.is_live())

    def test_an_established_session_whose_cookie_is_emptied_is_not_live(self) -> None:
        session = _offline_session(self.COOKIE, _cookie("sid", "attacker"))
        session.jar.set_cookie(_cookie("sid", ""))  # the same cookie, cleared
        self.assertFalse(session.is_live())
        self.assertEqual(session.prepare({}, None, method="GET")[2], "session_expired")

    def test_an_empty_csrf_cookie_is_not_injected(self) -> None:
        """An empty X-CSRFToken draws the target's CSRF 403, a declared denial."""
        session = _offline_session(self.CSRF, _cookie("sid", "attacker"),
                                   _cookie("csrftoken", ""))
        self.assertEqual(session.state, "established")
        _headers, _body, blocked, _ = session.prepare({}, b"{}", method="POST")
        self.assertEqual(blocked, "unresolved_reference")

    def test_control_a_non_empty_csrf_cookie_is_injected(self) -> None:
        session = _offline_session(self.CSRF, _cookie("sid", "attacker"),
                                   _cookie("csrftoken", CSRF_SENTINEL))
        headers, _body, blocked, _ = session.prepare({}, b"{}", method="POST")
        self.assertIsNone(blocked)
        self.assertEqual(headers["X-CSRFToken"], CSRF_SENTINEL)


class ProofCookieIdentityTest(unittest.TestCase):
    """Liveness asks after the cookie that proved the session, not its name.

    A same-named cookie on a narrower path (``sid=guest; Path=/docs``) outlived
    the real one: is_live() took any usable ``sid`` and attach_cookies() found
    ``sid`` on the request by name, so the probe went out as the guest.
    """

    DECLARATION = {"login": _login(), "establishes": {"cookie": "sid"}}

    def test_a_later_same_named_cookie_does_not_keep_the_session_live(self) -> None:
        session = _offline_session(self.DECLARATION, _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established")
        # A later response sets a guest cookie under the same name, on /docs.
        session.jar.set_cookie(_cookie("sid", "guest", path="/docs", max_age=10_000))
        with _clock() as clock:
            clock.past(next(c.expires for c in session.jar if c.value == "attacker"))
            self.assertFalse(session.is_live())
            request = Request("http://127.0.0.1:1/docs/1", method="GET")
            # The jar would have sent the guest; nothing is sent instead.
            self.assertEqual(session.attach_cookies(request), "session_expired")
        self.assertEqual(request.get_header("Cookie"), "sid=guest")

    def test_control_the_real_cookie_alive_beside_the_guest_is_sent(self) -> None:
        """Where the guest's Path does not reach, the proof alone goes out.

        Inside /docs both would go out, which SameNamedCookieOnTheRequestTest
        covers: that request is refused, not sent with the proof beside a guest.
        """
        session = _offline_session(self.DECLARATION, _cookie("sid", "attacker"))
        session.jar.set_cookie(_cookie("sid", "guest", path="/docs", max_age=10_000))
        with _clock():
            self.assertTrue(session.is_live())
            request = Request("http://127.0.0.1:1/m", method="GET")
            self.assertIsNone(session.attach_cookies(request))
        self.assertEqual(request.get_header("Cookie"), "sid=attacker")

    def test_two_values_under_the_proving_name_at_login_do_not_establish(self) -> None:
        """Which of the two the target authenticates is unknowable."""
        session = _offline_session(self.DECLARATION, _cookie("sid", "guest", path="/docs"),
                                   _cookie("sid", "attacker"))
        self.assertEqual(session.state, "failed")
        self.assertEqual(session.reason_code, "not_established")
        self.assertIn("set more than once with different values", session.reason)

    def test_control_one_value_on_two_paths_establishes(self) -> None:
        session = _offline_session(self.DECLARATION, _cookie("sid", "attacker", path="/docs"),
                                   _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established", session.reason)
        self.assertTrue(session.is_live())

    def test_a_rotated_proof_cookie_is_still_the_proof(self) -> None:
        """The target re-setting the same (domain, path, name) is rotation."""
        session = _offline_session(self.DECLARATION, _cookie("sid", "attacker"))
        session.jar.set_cookie(_cookie("sid", "attacker-rotated"))
        request = Request("http://127.0.0.1:1/docs/1", method="GET")
        self.assertIsNone(session.attach_cookies(request))
        self.assertEqual(request.get_header("Cookie"), "sid=attacker-rotated")


class CarriedCookieTest(unittest.TestCase):
    """A request carrying a value read from a cookie must carry the cookie too.

    prepare() injected ``X-CSRFToken`` from the ``csrftoken`` cookie, then the
    jar left the cookie off -- expired in between, or scoped by Path away from
    the URL. A double-submit CSRF check compared the two, answered 403, and the
    403 matched the declared denial: safe 2, vulnerable 0 over a confirmed IDOR.
    """

    @staticmethod
    def _session(csrf_path: str = "/") -> sequence.IdentitySession:
        return _offline_session(
            EmptyCookieIsNoProofTest.CSRF, _cookie("sid", "attacker", max_age=10_000),
            _cookie("csrftoken", CSRF_SENTINEL, path=csrf_path))

    def _send(self, session, path: str = "/docs/1", *, expire_csrf: bool = False):
        with _clock() as clock:
            headers, body, blocked, _ = session.prepare({}, b"{}", method="POST")
            self.assertIsNone(blocked)
            if expire_csrf:
                clock.past(_expiry_of(session, "csrftoken"))
            request = Request(f"http://127.0.0.1:1{path}", data=body, headers=headers,
                              method="POST")
            return session.attach_cookies(request), request

    def test_control_the_cookie_goes_out_with_its_value(self) -> None:
        reason, request = self._send(self._session())
        self.assertIsNone(reason)
        self.assertIn(f"csrftoken={CSRF_SENTINEL}", request.get_header("Cookie"))
        self.assertEqual(request.get_header("X-csrftoken"), CSRF_SENTINEL)

    def test_a_csrf_cookie_that_expires_after_prepare_is_refused(self) -> None:
        reason, request = self._send(self._session(), expire_csrf=True)
        self.assertEqual(request.get_header("Cookie"), "sid=attacker")
        self.assertEqual(reason, "capture_cookie_not_sent")

    def test_a_csrf_cookie_scoped_away_from_the_url_is_refused(self) -> None:
        reason, request = self._send(self._session(csrf_path="/app"))
        self.assertEqual(request.get_header("Cookie"), "sid=attacker")
        self.assertEqual(reason, "capture_cookie_not_sent")

    def test_control_inside_its_path_the_scoped_cookie_is_sent(self) -> None:
        reason, _request = self._send(self._session(csrf_path="/app"), "/app/docs/1")
        self.assertIsNone(reason)

    def test_the_reason_gets_session_advice_and_is_not_configuration(self) -> None:
        error = core.UNSENT_REASONS["capture_cookie_not_sent"]
        advice = core.unsent_remediation(error)
        self.assertIsNotNone(advice)
        self.assertNotIn("reachable", advice)
        self.assertNotIn("capture_cookie_not_sent", core.CONFIGURATION_UNSENT_ERRORS.values())
        self.assertTrue(core.execution_message(error).startswith("Request not sent: "))


@slow("stands up a loopback HTTP server and runs the engine against it")
class SessionProofGapsEndToEndTest(unittest.TestCase):
    """The same gaps, through the engine, against a target with a live IDOR.

    The target answers a request with no real ``sid`` with 404, and a POST
    whose X-CSRFToken does not match its csrftoken cookie with 403; both are
    statuses the attacker's declaration lists. Any logged-in caller reads the
    victim's document. Each non-control case was graded safe before the fix.
    """

    STEP_CAPTURE = {"login": _login({"tok": {"from": "cookie", "name": "sid"}}),
                    "establishes": {"capture": "tok"}}
    COOKIE = {"login": _login(), "establishes": {"cookie": "sid"}}
    CSRF = EmptyCookieIsNoProofTest.CSRF

    @staticmethod
    def _target(attacker_cookies: list[str]):
        def responder(entry: dict):
            who = _who(entry)
            if entry["path"] == "/login":
                cookies = (attacker_cookies if who == "attacker"
                           else ["sid=victim; Path=/", "csrftoken=cv; Path=/"])
                return 200, [("Set-Cookie", item) for item in cookies], b"ok"
            jar = dict(part.strip().partition("=")[::2]
                       for part in entry["cookie"].split(";") if part.strip())
            if jar.get("sid") not in ("attacker", "victim"):
                return 404, [("Content-Type", "application/json")], b'{"e":"anon"}'
            if entry["method"] == "POST" and (
                    not entry["csrf"] or entry["csrf"] != jar.get("csrftoken")):
                return 403, [("Content-Type", "application/json")], b'{"e":"csrf"}'
            if entry["path"] == "/m":
                owner = MARKER_ATTACKER if who == "attacker" else MARKER_VICTIM
                return 200, [("Content-Type", "application/json")], json.dumps(
                    {"m": owner}).encode()
            # IDOR: any logged-in caller reads the victim's document.
            return 200, [("Content-Type", "application/json")], json.dumps(
                {"provenance": MARKER_VICTIM}).encode()

        return responder

    def _execute(self, session: dict, attacker_cookies: list[str], *,
                 method: str = "GET", expire: bool = False):
        identities = _identities(sessions=True)
        for identity in identities.values():
            identity["session"] = json.loads(json.dumps(session))
            identity["marker_probe"] = {"method": "GET", "path": "/m"}
        check = _doc_check()
        check["request"] = {"method": method, "path": "/docs/1"}
        if method == "POST":
            check["request"]["json"] = {"a": 1}
        check["expect"]["attacker"]["status"] = [403, 404]
        config = {"version": 1,
                  "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                  "identities": identities, "checks": [check]}
        real_attach = sequence.IdentitySession.attach_cookies
        fired: list[str] = []

        def attach(inner, request):
            # The attacker's graded probe of /docs/1: its sid expires after
            # prepare() and before the jar runs.
            if (expire and not fired and inner.name == "attacker"
                    and inner.state == "established"
                    and request.get_header("Authorization") == ATTACKER_TOKEN
                    and urlsplit(request.full_url).path == "/docs/1"):
                fired.append(request.full_url)
                clock.past(_expiry_of(inner, "sid"))
            return real_attach(inner, request)

        with _clock() as clock, \
                patch.object(sequence.IdentitySession, "attach_cookies", attach), \
                _server(self._target(attacker_cookies)) as (url, log):
            result, _sessions, _ = _run(config, url)
        if expire:
            self.assertEqual(len(fired), 1, "the expiry was never forced")
        probes = [entry for entry in log.entries
                  if entry["auth"] == ATTACKER_TOKEN and entry["path"] == "/docs/1"]
        # None when the attacker's probe was graded safe: safe findings are not listed.
        return result, probes, _finding_map(result).get(("cross-tenant-doc-read", "attacker"))

    def _assert_confirmed(self, result, probes, verdict) -> None:
        self.assertEqual(len(probes), 1)
        self.assertIsNotNone(verdict, f"graded safe: {result['summary']}")
        self.assertEqual((verdict["rule_id"], verdict["verdict"], verdict["evidence_grade"]),
                         ("VERIDOR-AUTHZ-001", "vulnerable", "confirmed"))

    def _assert_withheld(self, words: str, result, probes, verdict) -> None:
        self.assertEqual([entry["cookie"] for entry in probes], [],
                         "a graded probe reached the target without its cookie")
        self.assertIsNotNone(verdict, f"graded safe: {result['summary']}")
        self.assertEqual((verdict["rule_id"], verdict["verdict"]),
                         ("VERIDOR-EXEC-001", "inconclusive"))
        self.assertIn(words, verdict["message"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(result["summary"]["safe"], 1)  # the victim's alone

    def test_control_a_login_step_cookie_capture_proof_while_it_lives(self) -> None:
        self._assert_confirmed(*self._execute(
            self.STEP_CAPTURE, ["sid=attacker; Path=/; Max-Age=100"]))

    def test_a_login_step_cookie_capture_proof_that_expired_sends_nothing(self) -> None:
        self._assert_withheld("no longer live", *self._execute(
            self.STEP_CAPTURE, ["sid=attacker; Path=/; Max-Age=100"], expire=True))

    def test_control_a_non_empty_establishing_cookie(self) -> None:
        self._assert_confirmed(*self._execute(self.COOKIE, ["sid=attacker; Path=/"]))

    def test_an_empty_establishing_cookie_sends_nothing(self) -> None:
        self._assert_withheld("not established", *self._execute(self.COOKIE, ["sid=; Path=/"]))

    def test_control_a_csrf_cookie_that_covers_the_url(self) -> None:
        self._assert_confirmed(*self._execute(
            self.CSRF, ["sid=attacker; Path=/", "csrftoken=ca; Path=/"], method="POST"))

    def test_a_csrf_cookie_scoped_away_from_the_url_sends_nothing(self) -> None:
        self._assert_withheld("captured from a cookie", *self._execute(
            self.CSRF, ["sid=attacker; Path=/", "csrftoken=ca; Path=/app"], method="POST"))


# --------------------------------------------------------------------------
# A second value under a cookie name the session depends on
# --------------------------------------------------------------------------


class SameNamedCookieOnTheRequestTest(unittest.TestCase):
    """The proof cookie on the request is not enough if another value rides beside it.

    A response after login set ``sid=guest; Path=/docs``. The jar writes longer
    paths first, so a request for /docs/1 went out as ``sid=guest; sid=attacker``
    and passed the attach check, which looked only for the proof's value. A
    server that reads the first occurrence (Express cookie-parser, PHP, Go's
    ``r.Cookie``) authenticated the guest, whose 404 matched the declared
    denial: safe 2, vulnerable 0, ``liveness.unproven`` empty.
    """

    COOKIE = {"login": _login(), "establishes": {"cookie": "sid"}}
    STEP_CAPTURE = LoginStepCookieCaptureIsLiveTest.DECLARATION

    def _attach(self, declaration: dict, later, path: str = "/docs/1"):
        session = _offline_session(declaration, _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established", session.reason)
        session.jar.set_cookie(later)
        request = Request(f"http://127.0.0.1:1{path}", method="GET")
        return session.attach_cookies(request), request.get_header("Cookie")

    def test_a_later_same_named_cookie_beside_the_proof_is_refused(self) -> None:
        reason, cookie = self._attach(self.COOKIE, _cookie("sid", "guest", path="/docs"))
        self.assertEqual(cookie, "sid=guest; sid=attacker")
        self.assertEqual(reason, "session_cookie_ambiguous")

    def test_the_same_for_a_proof_read_by_a_login_step_capture(self) -> None:
        reason, _cookie_header = self._attach(
            self.STEP_CAPTURE, _cookie("sid", "guest", path="/docs"))
        self.assertEqual(reason, "session_cookie_ambiguous")

    def test_control_outside_the_guest_cookies_path_the_request_goes_out(self) -> None:
        reason, cookie = self._attach(
            self.COOKIE, _cookie("sid", "guest", path="/docs"), path="/m")
        self.assertEqual(cookie, "sid=attacker")
        self.assertIsNone(reason)

    def test_control_another_name_on_the_same_path_goes_out(self) -> None:
        reason, cookie = self._attach(self.COOKIE, _cookie("other", "guest", path="/docs"))
        self.assertEqual(cookie, "other=guest; sid=attacker")
        self.assertIsNone(reason)

    def test_control_the_proof_value_on_a_second_path_goes_out(self) -> None:
        reason, cookie = self._attach(self.COOKIE, _cookie("sid", "attacker", path="/docs"))
        self.assertEqual(cookie, "sid=attacker; sid=attacker")
        self.assertIsNone(reason)

    def _csrf(self, *later) -> str | None:
        session = _offline_session(
            EmptyCookieIsNoProofTest.CSRF, _cookie("sid", "attacker"),
            _cookie("csrftoken", CSRF_SENTINEL))
        for cookie in later:
            session.jar.set_cookie(cookie)
        headers, body, blocked, _ = session.prepare({}, b"{}", method="POST")
        self.assertIsNone(blocked)
        self.assertEqual(headers["X-CSRFToken"], CSRF_SENTINEL)
        request = Request("http://127.0.0.1:1/docs/1", data=body, headers=headers,
                          method="POST")
        return session.attach_cookies(request)

    def test_a_carried_csrf_cookie_beside_a_second_value_is_refused(self) -> None:
        """The CSRF check may compare the header with the other one and answer 403."""
        self.assertEqual(self._csrf(_cookie("csrftoken", "other", path="/docs")),
                         "session_cookie_ambiguous")

    def test_control_a_carried_csrf_cookie_alone_goes_out(self) -> None:
        self.assertIsNone(self._csrf())
        self.assertIsNone(self._csrf(_cookie("csrftoken", CSRF_SENTINEL, path="/docs")))

    def test_the_reason_gets_session_advice_and_is_not_configuration(self) -> None:
        error = core.UNSENT_REASONS["session_cookie_ambiguous"]
        advice = core.unsent_remediation(error)
        self.assertIsNotNone(advice)
        self.assertNotIn("reachable", advice)
        self.assertNotIn("session_cookie_ambiguous", core.CONFIGURATION_UNSENT_ERRORS.values())
        self.assertTrue(core.execution_message(error).startswith("Request not sent: "))


@slow("stands up a loopback HTTP server and runs the engine against it")
class SameNamedCookieEndToEndTest(unittest.TestCase):
    """The same, through the engine, against a server that reads the first ``sid``.

    The attacker's marker probe (GET /m) draws a response that also sets a
    second cookie on Path=/docs; /docs/1 is an IDOR any logged-in caller reads,
    and a request whose first ``sid`` is not a real session gets 404, which the
    attacker's declaration lists.
    """

    @staticmethod
    def _execute(late: str):
        def responder(entry: dict):
            who = _who(entry)
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", f"sid={who}; Path=/")], b"ok"
            sids = [part.strip()[4:] for part in entry["cookie"].split(";")
                    if part.strip().startswith("sid=")]
            if not sids or sids[0] not in ("attacker", "victim"):
                return 404, [("Content-Type", "application/json")], b'{"e":"anon"}'
            headers = [("Content-Type", "application/json")]
            if entry["path"] == "/m":
                if who == "attacker":
                    headers.append(("Set-Cookie", late))
                owner = MARKER_ATTACKER if who == "attacker" else MARKER_VICTIM
                return 200, headers, json.dumps({"m": owner}).encode()
            return 200, headers, json.dumps({"provenance": MARKER_VICTIM}).encode()

        identities = _identities(sessions=True)
        for identity in identities.values():
            identity["marker_probe"] = {"method": "GET", "path": "/m"}
        check = _doc_check()
        check["expect"]["attacker"]["status"] = [403, 404]
        config = {"version": 1,
                  "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                  "identities": identities, "checks": [check]}
        with _server(responder) as (url, log):
            result, _sessions, _ = _run(config, url)
        probes = [entry["cookie"] for entry in log.entries
                  if entry["auth"] == ATTACKER_TOKEN and entry["path"] == "/docs/1"]
        return result, probes, _finding_map(result).get(("cross-tenant-doc-read", "attacker"))

    def test_control_a_later_cookie_of_another_name_leaves_the_idor_confirmed(self) -> None:
        result, probes, verdict = self._execute("other=guest; Path=/docs")
        self.assertEqual(probes, ["other=guest; sid=attacker"])
        self.assertIsNotNone(verdict, f"graded safe: {result['summary']}")
        self.assertEqual((verdict["rule_id"], verdict["verdict"], verdict["evidence_grade"]),
                         ("VERIDOR-AUTHZ-001", "vulnerable", "confirmed"))

    def test_a_later_same_named_cookie_sends_nothing(self) -> None:
        result, probes, verdict = self._execute("sid=guest; Path=/docs")
        self.assertEqual(probes, [], "the probe reached the target as the guest")
        self.assertIsNotNone(verdict, f"graded safe: {result['summary']}")
        self.assertEqual((verdict["rule_id"], verdict["verdict"]),
                         ("VERIDOR-EXEC-001", "inconclusive"))
        self.assertIn("second, different value", verdict["message"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(result["summary"]["safe"], 1)  # the victim's alone


# --------------------------------------------------------------------------
# A live cookie value passes the checks a captured one does
# --------------------------------------------------------------------------


class LiveCookieValueChecksTest(unittest.TestCase):
    """A value read from the jar at send time is held to the capture rules.

    lookup() routes a live cookie through the same size, control-character and
    ASCII checks as a value captured from a login response. Without them a
    cookie value with a space went out in a header as is, and a non-ASCII one
    raised UnicodeEncodeError inside http.client instead of a typed refusal.
    """

    @staticmethod
    def _csrf(value: str) -> tuple[dict, str | None]:
        session = _offline_session(
            EmptyCookieIsNoProofTest.CSRF, _cookie("sid", "attacker"),
            _cookie("csrftoken", value))
        headers, _body, blocked, _ = session.prepare({}, b"{}", method="POST")
        return headers, blocked

    def test_control_a_plain_value_is_injected(self) -> None:
        headers, blocked = self._csrf(CSRF_SENTINEL)
        self.assertIsNone(blocked)
        self.assertEqual(headers["X-CSRFToken"], CSRF_SENTINEL)

    def test_a_value_with_a_space_is_not_injected(self) -> None:
        self.assertEqual(self._csrf("tok en"), ({}, "unresolved_reference"))

    def test_a_non_ascii_value_is_not_injected(self) -> None:
        self.assertEqual(self._csrf("töken"), ({}, "unresolved_reference"))

    def test_an_oversize_value_is_not_injected(self) -> None:
        self.assertEqual(self._csrf("x" * (sequence.MAX_CAPTURE_VALUE_BYTES + 1)),
                         ({}, "unresolved_reference"))

    def test_control_a_value_at_the_size_limit_is_injected(self) -> None:
        value = "x" * sequence.MAX_CAPTURE_VALUE_BYTES
        headers, blocked = self._csrf(value)
        self.assertIsNone(blocked)
        self.assertEqual(headers["X-CSRFToken"], value)

    def test_the_proof_cookie_read_by_a_capture_is_checked_too(self) -> None:
        declaration = dict(LoginStepCookieCaptureIsLiveTest.DECLARATION,
                           inject=[{"header": "X-Token", "value": "${capture.tok}"}])
        session = _offline_session(declaration, _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established", session.reason)
        # Control: the value the login step checked goes out.
        self.assertEqual(session.lookup("tok"), "attacker")
        self.assertEqual(session.prepare({}, None, method="GET")[0]["X-Token"], "attacker")
        # The target rotates the proof cookie to a value the login step would
        # have refused; read live, it is refused the same way.
        session.jar.set_cookie(_cookie("sid", "tök"))
        self.assertIsNone(session.lookup("tok"))
        self.assertEqual(session.prepare({}, None, method="GET")[2], "unresolved_reference")


# --------------------------------------------------------------------------
# A capture cookie that expired is the session's state, not the configuration
# --------------------------------------------------------------------------


class _Response:
    """What CookieJar.extract_cookies reads from a response: its headers."""

    def __init__(self, *set_cookies: str) -> None:
        import email.message

        self._headers = email.message.Message()
        for value in set_cookies:
            self._headers["Set-Cookie"] = value

    def info(self):
        return self._headers


class ExpiredCaptureCookieReasonTest(unittest.TestCase):
    """A ``${capture.…}`` whose cookie expired since login says so.

    It said unresolved_reference: "the capture it names is not declared, or the
    login step meant to produce it did not find it", configuration advice, and
    the gate counted it as a configuration error -- for a cookie the target set
    and let expire. Nothing is sent either way; the reason and advice change.
    """

    def _session(self, *cookies) -> sequence.IdentitySession:
        session = _offline_session(
            EmptyCookieIsNoProofTest.CSRF, _cookie("sid", "attacker", max_age=10_000),
            *cookies)
        self.assertEqual(session.state, "established", session.reason)
        return session

    def test_a_csrf_cookie_set_at_login_that_expired_reports_expiry(self) -> None:
        session = self._session(_cookie("csrftoken", CSRF_SENTINEL))
        with _clock() as clock:
            self.assertIsNone(session.prepare({}, b"{}", method="POST")[2])
            clock.past(_expiry_of(session, "csrftoken"))
            self.assertTrue(session.is_live())
            self.assertEqual(session.prepare({}, b"{}", method="POST")[2],
                             "capture_cookie_expired")

    def test_a_csrf_cookie_set_after_login_that_expired_reports_expiry(self) -> None:
        session = self._session()
        session.harvest(_Response(f"csrftoken={CSRF_SENTINEL}; Path=/; Max-Age=100"),
                        Request("http://127.0.0.1:1/m", method="GET"))
        with _clock() as clock:
            headers, _body, blocked, _ = session.prepare({}, b"{}", method="POST")
            self.assertIsNone(blocked)
            self.assertEqual(headers["X-CSRFToken"], CSRF_SENTINEL)
            clock.past(_expiry_of(session, "csrftoken"))
            self.assertEqual(session.prepare({}, b"{}", method="POST")[2],
                             "capture_cookie_expired")

    def test_control_a_cookie_the_target_never_set_is_still_unresolved(self) -> None:
        session = self._session()
        self.assertEqual(session.prepare({}, b"{}", method="POST")[2], "unresolved_reference")

    def test_control_a_new_login_forgets_what_the_last_one_saw(self) -> None:
        session = self._session(_cookie("csrftoken", CSRF_SENTINEL))
        self.assertIn("csrftoken", session._seen)
        session.establish = sequence.IdentitySession.establish.__get__(session)
        with patch.object(core, "_perform_request", lambda *a, **k: {
                "request": {"method": "POST", "url": "http://127.0.0.1:1/login"},
                "response": {"status": 200, "duration_ms": 1, "body_bytes": 0,
                             "body_sha256": "0" * 64},
                "error": None}):
            session.establish()
        # The new login set no cookie at all, so nothing is established and
        # nothing remembered from the previous login.
        self.assertEqual(session.state, "failed")
        self.assertEqual(session._seen, set())

    def test_the_reason_gets_session_advice_and_is_not_configuration(self) -> None:
        error = core.UNSENT_REASONS["capture_cookie_expired"]
        advice = core.unsent_remediation(error)
        self.assertIsNotNone(advice)
        self.assertIn("reestablish", advice)
        self.assertNotIn("capture_cookie_expired", core.CONFIGURATION_UNSENT_ERRORS.values())
        self.assertTrue(core.execution_message(error).startswith("Request not sent: "))


# --------------------------------------------------------------------------
# Liveness proof belongs to the login it was measured under
# --------------------------------------------------------------------------


class ProvenUnderSameLoginTest(unittest.TestCase):
    """For an identity that logs in again per check and sequence, which proof counts."""

    @staticmethod
    def _record(sequence_id: str) -> dict:
        def step(identity: str, status: int) -> dict:
            return {"as": identity, "request": {"method": "GET", "url": "/docs/2"},
                    "response": {"status": status}, "error": None}

        return {"sequence_id": sequence_id,
                "steps": [step("anonymous", 401), step("attacker", 200)]}

    def _proven(self, entry: dict) -> bool:
        return core._proven_under_same_login(
            entry, {"checks": []}, {}, [self._record("s1")], {"attacker"})

    def test_control_a_2xx_in_the_same_sequence_proves_it(self) -> None:
        self.assertTrue(self._proven({"identity": "attacker", "sequence_id": "s1"}))

    def test_a_2xx_in_another_sequence_does_not(self) -> None:
        self.assertFalse(self._proven({"identity": "attacker", "sequence_id": "s2"}))

    def test_nothing_at_run_level_proves_a_check_denial(self) -> None:
        self.assertFalse(self._proven({"identity": "attacker", "check_id": "c"}))


@slow("stands up a loopback HTTP server and runs the engine against it")
class ReloginLivenessProofTest(unittest.TestCase):
    """``"reestablish": "check"``: an earlier login's proof does not cover a later one.

    The marker control runs once, under the login before the first check; each
    check then logs in again. A re-login the target answered with a cookie it
    treats as anonymous drew the 404 the declaration lists, and the denial was
    graded safe with ``liveness.unproven`` empty, on the strength of the first
    login's marker -- or of a 2xx in an earlier check under its own login.
    """

    @staticmethod
    def _execute(sids: list[str], *, own_doc_check: bool = False,
                 marker: bool = True, reestablish: str = "check", idor: bool = True):
        logins: list[str] = []

        def responder(entry: dict):
            who = _who(entry)
            if entry["path"] == "/login":
                if who == "victim":
                    return 200, [("Set-Cookie", "sid=victim; Path=/")], b"ok"
                sid = sids[min(len(logins), len(sids) - 1)]
                logins.append(sid)
                return 200, [("Set-Cookie", f"sid={sid}; Path=/")], b"ok"
            sid = entry["cookie"].partition("sid=")[2].partition(";")[0]
            if sid not in ("attacker", "victim") or (
                    not idor and sid == "attacker" and entry["path"] == "/docs/1"):
                return 404, [("Content-Type", "application/json")], b'{"e":"anon"}'
            body = {"/m": {"m": MARKER_ATTACKER if sid == "attacker" else MARKER_VICTIM},
                    "/docs/2": {"provenance": MARKER_ATTACKER}}.get(
                        entry["path"], {"provenance": MARKER_VICTIM})
            return 200, [("Content-Type", "application/json")], json.dumps(body).encode()

        identities = _identities(sessions=True)
        for identity in identities.values():
            if marker:
                identity["marker_probe"] = {"method": "GET", "path": "/m"}
            identity["session"]["reestablish"] = reestablish
        checks = []
        if own_doc_check:
            checks.append({"id": "own-doc", "request": {"method": "GET", "path": "/docs/2"},
                           "expect": {"attacker": {"status": [200]},
                                      "victim": {"status": [200]}}})
        check = _doc_check()
        check["expect"]["attacker"]["status"] = [403, 404]
        checks.append(check)
        config = {"version": 1,
                  "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                  "identities": identities, "checks": checks}
        with _server(responder) as (url, _log):
            result, _sessions, _ = _run(config, url)
        unproven = [entry for entry in result["liveness"]["unproven"]
                    if entry["identity"] == "attacker"]
        return result, logins, unproven

    def test_control_every_login_real_the_idor_is_confirmed(self) -> None:
        result, logins, _unproven = self._execute(["attacker"])
        self.assertEqual(logins, ["attacker", "attacker"])
        verdict = _finding_map(result)[("cross-tenant-doc-read", "attacker")]
        self.assertEqual((verdict["rule_id"], verdict["verdict"]),
                         ("VERIDOR-AUTHZ-001", "vulnerable"))

    def test_a_guest_relogin_is_not_proven_by_the_first_logins_marker(self) -> None:
        result, logins, unproven = self._execute(["attacker", "guest"])
        self.assertEqual(logins, ["attacker", "guest"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual([entry["check_id"] for entry in unproven], ["cross-tenant-doc-read"])
        self.assertIn('"reestablish": "check"', unproven[0]["remediation"])

    def test_a_guest_relogin_is_not_proven_by_an_earlier_checks_2xx(self) -> None:
        result, logins, unproven = self._execute(
            ["attacker", "attacker", "guest"], own_doc_check=True, marker=False)
        self.assertEqual(logins, ["attacker", "attacker", "guest"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual([entry["check_id"] for entry in unproven], ["cross-tenant-doc-read"])

    def test_control_one_login_for_the_run_is_proven_by_its_marker(self) -> None:
        """Without a re-login the marker proves the login every request used."""
        result, logins, unproven = self._execute(["attacker"], reestablish="run", idor=False)
        self.assertEqual(logins, ["attacker"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(unproven, [])

    def test_a_relogin_denial_is_disclosed_even_when_every_login_is_real(self) -> None:
        """The behaviour change: no proof under the login the probe used is listed.

        Every login here is real and the boundary holds, but nothing measured
        that under the check's own login: the marker ran under the first one,
        and the fabricated credential drew the same 404.
        """
        result, logins, unproven = self._execute(["attacker"], idor=False)
        self.assertEqual(logins, ["attacker", "attacker"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual([entry["check_id"] for entry in unproven], ["cross-tenant-doc-read"])


# --------------------------------------------------------------------------
# A proof made of several cookies stops being one when they disagree
# --------------------------------------------------------------------------


def _harvested_session(base_url: str, *set_cookies: str) -> sequence.IdentitySession:
    """establish() with the login answered in process by these Set-Cookie headers.

    Parsed by the jar from a response, as a real login is, so ``Domain=`` and
    ``Path=`` attributes mean what they mean on the wire.
    """
    session = sequence.IdentitySession(
        "attacker",
        {"headers": {}, "session": {"login": _login(), "establishes": {"cookie": "sid"}}},
        base_url, 5, {},
    )

    def perform(base_url, timeout, request_config, identity, *, session=None, **_):
        session.harvest(_Response(*set_cookies), Request(f"{base_url}/login", method="POST"))
        return {
            "request": {"method": "POST", "url": f"{base_url}/login"},
            "response": {"status": 200, "duration_ms": 1, "body_bytes": 2,
                         "body_sha256": "0" * 64},
            "error": None,
        }

    with patch.object(core, "_perform_request", perform):
        session.establish()
    return session


class ProofCookiesDisagreeTest(unittest.TestCase):
    """The cookies that proved a session must still carry one value.

    A login that sets the proving cookie twice with one value -- on two paths,
    or host-only and with ``Domain=`` -- establishes, and both copies are the
    proof. A later response replaced one copy with ``sid=guest``. The attach
    check compared the request against every proof value, so the guest was not
    "another" value, and /docs/1 went out as ``sid=guest; sid=attacker``: safe
    2, vulnerable 0, ``liveness.unproven`` empty against a server that reads
    the first occurrence. establish() refuses two values under the proving name
    at login; the same rule now holds on every request after it.
    """

    COOKIE = {"login": _login(), "establishes": {"cookie": "sid"}}

    def _two_paths(self, *later) -> sequence.IdentitySession:
        session = _offline_session(self.COOKIE, _cookie("sid", "attacker"),
                                   _cookie("sid", "attacker", path="/docs"))
        self.assertEqual(session.state, "established", session.reason)
        for cookie in later:
            session.jar.set_cookie(cookie)
        return session

    def _attach(self, session: sequence.IdentitySession, url: str):
        request = Request(url, method="GET")
        return session.attach_cookies(request), request.get_header("Cookie")

    def test_one_proof_path_replaced_with_another_value_is_refused(self) -> None:
        session = self._two_paths(_cookie("sid", "guest", path="/docs"))
        reason, cookie = self._attach(session, "http://127.0.0.1:1/docs/1")
        self.assertEqual(cookie, "sid=guest; sid=attacker")
        self.assertEqual(reason, "session_cookie_ambiguous")

    def test_also_where_only_the_unchanged_copy_would_go_out(self) -> None:
        """Behaviour change: the session is ambiguous, not only this request."""
        session = self._two_paths(_cookie("sid", "guest", path="/docs"))
        reason, cookie = self._attach(session, "http://127.0.0.1:1/m")
        self.assertEqual(cookie, "sid=attacker")
        self.assertEqual(reason, "session_cookie_ambiguous")

    def test_control_the_same_value_set_again_goes_out(self) -> None:
        session = self._two_paths(_cookie("sid", "attacker", path="/docs"))
        reason, cookie = self._attach(session, "http://127.0.0.1:1/docs/1")
        self.assertEqual(cookie, "sid=attacker; sid=attacker")
        self.assertIsNone(reason)

    def test_control_both_copies_rotated_to_one_new_value_go_out(self) -> None:
        session = self._two_paths(_cookie("sid", "rotated"),
                                  _cookie("sid", "rotated", path="/docs"))
        reason, cookie = self._attach(session, "http://127.0.0.1:1/docs/1")
        self.assertEqual(cookie, "sid=rotated; sid=rotated")
        self.assertIsNone(reason)

    def test_control_another_name_on_the_proof_path_goes_out(self) -> None:
        session = self._two_paths(_cookie("other", "guest", path="/docs"))
        reason, _cookie_header = self._attach(session, "http://127.0.0.1:1/docs/1")
        self.assertIsNone(reason)

    def test_a_host_only_and_a_domain_copy_that_disagree_are_refused(self) -> None:
        session = _harvested_session(
            "http://app.example.test",
            "sid=attacker; Path=/", "sid=attacker; Domain=example.test; Path=/")
        self.assertEqual(session.state, "established", session.reason)
        self.assertEqual(len(session._proof), 2)
        self.assertIsNone(self._attach(session, "http://app.example.test/docs/1")[0])
        session.harvest(_Response("sid=guest; Domain=example.test; Path=/"),
                        Request("http://app.example.test/m", method="GET"))
        reason, cookie = self._attach(session, "http://app.example.test/docs/1")
        self.assertEqual(sorted(cookie.split("; ")), ["sid=attacker", "sid=guest"])
        self.assertEqual(reason, "session_cookie_ambiguous")


class CaseVariantCookieNameTest(unittest.TestCase):
    """A second value under the proof's name in another case is a second value.

    ``SID=guest; Path=/docs`` beside ``sid=attacker`` went out as
    ``SID=guest; sid=attacker``: the jar keeps them apart, and the same-name
    check compared names exactly. A server that folds cookie names and reads
    the first occurrence authenticated the guest, whose 404 matched the
    declared denial (safe 2, vulnerable 0).
    """

    _attach = SameNamedCookieOnTheRequestTest._attach
    COOKIE = SameNamedCookieOnTheRequestTest.COOKIE

    def test_a_case_variant_name_beside_the_proof_is_refused(self) -> None:
        reason, cookie = self._attach(self.COOKIE, _cookie("SID", "guest", path="/docs"))
        self.assertEqual(cookie, "SID=guest; sid=attacker")
        self.assertEqual(reason, "session_cookie_ambiguous")

    def test_a_case_variant_beside_a_carried_csrf_cookie_is_refused(self) -> None:
        self.assertEqual(
            SameNamedCookieOnTheRequestTest._csrf(
                self, _cookie("CSRFTOKEN", "other", path="/docs")),
            "session_cookie_ambiguous")

    def test_control_another_name_goes_out(self) -> None:
        reason, cookie = self._attach(self.COOKIE, _cookie("XID", "guest", path="/docs"))
        self.assertEqual(cookie, "XID=guest; sid=attacker")
        self.assertIsNone(reason)

    def test_control_a_case_variant_with_the_proofs_value_goes_out(self) -> None:
        reason, cookie = self._attach(self.COOKIE, _cookie("SID", "attacker", path="/docs"))
        self.assertEqual(cookie, "SID=attacker; sid=attacker")
        self.assertIsNone(reason)


class IPv6LiteralTargetTest(unittest.TestCase):
    """A base_url naming an IPv6 literal gets a working jar, and only for that host.

    The policy's host came from urlsplit().hostname ('::1') and the request's
    from http.cookiejar.request_host() ('[::1]'), so set_ok refused every
    cookie and a session against http://[::1]:port never established
    (not_established, nothing graded). It failed closed; it also never worked.
    """

    def test_a_session_against_an_ipv6_literal_establishes_and_sends(self) -> None:
        session = _harvested_session("http://[::1]:8080", "sid=attacker; Path=/")
        self.assertEqual(session.state, "established", session.reason)
        request = Request("http://[::1]:8080/docs/1", method="GET")
        self.assertIsNone(session.attach_cookies(request))
        self.assertEqual(request.get_header("Cookie"), "sid=attacker")

    def test_the_policy_recognises_its_own_ipv6_host(self) -> None:
        v6 = sequence._SameOriginCookiePolicy("::1")
        self.assertTrue(v6._is_target(Request("http://[::1]:8080/", method="GET")))

    def test_control_another_host_is_still_refused_both_ways(self) -> None:
        session = sequence.IdentitySession(
            "attacker", {"headers": {}, "session": {"login": _login(),
                                                    "establishes": {"cookie": "sid"}}},
            "http://[::1]:8080", 5, {})
        for url in ("http://[::2]:8080/m", "http://127.0.0.1:8080/m",
                    "http://[::1:0]:8080/m"):
            # A response from another host sets nothing ...
            session.harvest(_Response("planted=1; Path=/"), Request(url, method="GET"))
        self.assertEqual(list(session.jar), [])
        # ... and a cookie the jar holds goes to no other host.
        session.jar.set_cookie(http.cookiejar.Cookie(
            0, "sid", "attacker", None, False, "::1", False, False, "/", True,
            False, int(time.time()) + 100, False, None, None, {}))
        for url in ("http://[::2]:8080/docs/1", "http://127.0.0.1:8080/docs/1"):
            other = Request(url, method="GET")
            session.jar.add_cookie_header(other)
            self.assertIsNone(other.get_header("Cookie"), url)

    def test_control_the_bracket_rule_does_not_widen_other_targets(self) -> None:
        policy = sequence._SameOriginCookiePolicy("127.0.0.1")
        self.assertFalse(policy._is_target(Request("http://[::1]:8080/", method="GET")))
        self.assertTrue(policy._is_target(Request("http://127.0.0.1:8080/", method="GET")))
        v6 = sequence._SameOriginCookiePolicy("::1")
        self.assertFalse(v6._is_target(Request("http://[::1:0]:8080/", method="GET")))
        self.assertFalse(v6._is_target(Request("http://127.0.0.1:8080/", method="GET")))


class SessionEpochTest(unittest.TestCase):
    """Which credential a session is sending, as a counter liveness compares.

    A response that replaced the proof cookie (same name, domain and path) was
    treated as rotation, and the marker_probe taken before it went on proving
    denials drawn after it. Each login, and each change of the proof cookie's
    value, now starts a new epoch.
    """

    COOKIE = {"login": _login(), "establishes": {"cookie": "sid"}}

    def _harvest(self, session: sequence.IdentitySession, *set_cookies: str) -> None:
        session.harvest(_Response(*set_cookies), Request("http://127.0.0.1:1/m", method="GET"))

    def _session(self) -> sequence.IdentitySession:
        session = _offline_session(self.COOKIE, _cookie("sid", "attacker"))
        self.assertEqual(session.state, "established", session.reason)
        return session

    def test_a_new_value_for_the_proof_cookie_starts_a_new_epoch(self) -> None:
        session = self._session()
        before = session.epoch
        self._harvest(session, "sid=guest; Path=/")
        self.assertEqual(session.epoch, before + 1)

    def test_a_login_starts_a_new_epoch(self) -> None:
        session = self._session()
        before = session.epoch
        with patch.object(core, "_perform_request", lambda *a, **k: {
                "request": {"method": "POST", "url": "http://127.0.0.1:1/login"},
                "response": {"status": 200, "duration_ms": 1, "body_bytes": 0,
                             "body_sha256": "0" * 64},
                "error": None}):
            session.establish()
        self.assertGreater(session.epoch, before)

    def test_control_the_same_value_set_again_keeps_the_epoch(self) -> None:
        session = self._session()
        before = session.epoch
        self._harvest(session, "sid=attacker; Path=/; Max-Age=500")
        self.assertEqual(session.epoch, before)

    def test_control_other_cookies_keep_the_epoch(self) -> None:
        """Another name, or the proof's name on a path that is not the proof's."""
        session = self._session()
        before = session.epoch
        self._harvest(session, "csrftoken=x; Path=/", "sid=guest; Path=/docs")
        self.assertEqual(session.epoch, before)

    def test_stamp_records_the_epoch_a_request_went_out_under(self) -> None:
        session = self._session()
        session.stamp(("marker",))
        self._harvest(session, "sid=guest; Path=/")
        session.stamp(("check", "c"))
        self.assertEqual(session.sent_epochs[("check", "c")],
                         session.sent_epochs[("marker",)] + 1)


@slow("stands up a loopback HTTP server and runs the engine against it")
class StaleCookieLivenessProofTest(unittest.TestCase):
    """Liveness proven under one value of the proof cookie does not cover another.

    The attacker logs in with ``sid=attacker``; its marker probe (GET /m) runs
    once before the checks, and in these scenarios its response replaces the
    cookie on the same path. The target refuses the attacker on /docs/1 with a
    404 and refuses an unknown or guest session with the same 404, so a working
    boundary and a downgraded session look the same there.
    """

    @staticmethod
    def _execute(late: str | None, *, own_doc_check: bool = False, idor: bool = False):
        def responder(entry: dict):
            who = _who(entry)
            json_type = [("Content-Type", "application/json")]
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", f"sid={who}; Path=/")], b"ok"
            sids = [part.strip()[4:] for part in entry["cookie"].split(";")
                    if part.strip().startswith("sid=")]
            sid = sids[0] if sids else None
            if sid not in ("attacker", "attacker2", "victim"):
                return 404, json_type, b'{"e":"anon"}'
            if entry["path"] == "/m":
                headers = list(json_type)
                if who == "attacker" and late:
                    headers.append(("Set-Cookie", late))
                owner = MARKER_VICTIM if sid == "victim" else MARKER_ATTACKER
                return 200, headers, json.dumps({"m": owner}).encode()
            if entry["path"] == "/docs/2":
                return 200, json_type, json.dumps({"provenance": MARKER_ATTACKER}).encode()
            if sid != "victim" and not idor:
                return 404, json_type, b'{"e":"denied"}'
            return 200, json_type, json.dumps({"provenance": MARKER_VICTIM}).encode()

        identities = _identities(sessions=True)
        for identity in identities.values():
            identity["marker_probe"] = {"method": "GET", "path": "/m"}
        check = _doc_check()
        check["expect"]["attacker"]["status"] = [403, 404]
        checks = [check]
        if own_doc_check:
            checks.append({"id": "own-doc", "request": {"method": "GET", "path": "/docs/2"},
                           "expect": {"attacker": {"status": [200]},
                                      "victim": {"status": [200]}}})
        config = {"version": 1,
                  "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                  "identities": identities, "checks": checks}
        with _server(responder) as (url, log):
            result, _sessions, _ = _run(config, url)
        sent = [entry["cookie"] for entry in log.entries
                if entry["auth"] == ATTACKER_TOKEN and entry["path"] == "/docs/1"]
        unproven = [entry for entry in result["liveness"]["unproven"]
                    if entry["identity"] == "attacker"]
        return result, sent, unproven

    def test_control_nothing_replaced_the_marker_proves_the_denial(self) -> None:
        result, sent, unproven = self._execute(None)
        self.assertEqual(sent, ["sid=attacker"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(unproven, [])

    def test_control_the_same_value_set_again_keeps_the_proof(self) -> None:
        _result, sent, unproven = self._execute("sid=attacker; Path=/")
        self.assertEqual(sent, ["sid=attacker"])
        self.assertEqual(unproven, [])

    def test_a_guest_session_after_the_marker_is_disclosed(self) -> None:
        result, sent, unproven = self._execute("sid=guest; Path=/")
        self.assertEqual(sent, ["sid=guest"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual([(entry["check_id"], entry.get("proof_scope"))
                          for entry in unproven],
                         [("cross-tenant-doc-read", "cookie_value")])
        self.assertIn("different value", unproven[0]["remediation"])
        self.assertNotIn("Give 'attacker' a marker_probe", unproven[0]["remediation"])

    def test_the_same_where_the_route_is_a_live_idor(self) -> None:
        """The round-3 shape: a real session reads /docs/1, the guest gets 404."""
        _result, sent, unproven = self._execute("sid=guest; Path=/", idor=True)
        self.assertEqual(sent, ["sid=guest"])
        self.assertEqual([entry["check_id"] for entry in unproven],
                         ["cross-tenant-doc-read"])

    def test_a_rotation_is_disclosed_too(self) -> None:
        """Behaviour change: rotation and a downgrade are indistinguishable here."""
        _result, sent, unproven = self._execute("sid=attacker2; Path=/")
        self.assertEqual(sent, ["sid=attacker2"])
        self.assertEqual([entry.get("proof_scope") for entry in unproven], ["cookie_value"])

    def test_control_a_2xx_under_the_new_value_proves_it(self) -> None:
        """Served on /docs/2 as attacker2, where the fabricated credential is refused."""
        _result, sent, unproven = self._execute("sid=attacker2; Path=/", own_doc_check=True)
        self.assertEqual(sent, ["sid=attacker2"])
        self.assertEqual(unproven, [])


@slow("stands up a loopback HTTP server and runs the engine against it")
class StaleCookieSequenceLivenessTest(unittest.TestCase):
    """Inside a sequence: a 2xx before the cookie changed does not prove a step after.

    Step 0 serves the attacker GET /m and, in the defect scenario, replaces its
    cookie with ``sid=guest``; step 1 shows an identity with no credential is
    refused on the same request, which is what makes step 0's 2xx proof; step 2
    asserts the attacker is refused on /docs/1, and a guest session is refused
    there too.
    """

    @staticmethod
    def _execute(late: str | None):
        def responder(entry: dict):
            who = _who(entry) if entry["auth"] else "anonymous"
            json_type = [("Content-Type", "application/json")]
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", f"sid={who}; Path=/")], b"ok"
            sid = entry["cookie"].partition("sid=")[2].partition(";")[0]
            if sid not in ("attacker", "victim"):
                return 404, json_type, b'{"e":"anon"}'
            if entry["path"] == "/m":
                headers = list(json_type)
                if who == "attacker" and late:
                    headers.append(("Set-Cookie", late))
                return 200, headers, b'{"m":"ok"}'
            if sid == "attacker":
                return 404, json_type, b'{"e":"denied"}'
            return 200, json_type, json.dumps({"provenance": MARKER_VICTIM}).encode()

        identities = _identities(sessions=True, marker=False)
        identities["anonymous"] = {"headers": {}}
        steps = [
            {"role": "setup", "as": "attacker", "request": {"method": "GET", "path": "/m"},
             "expect": {"status": [200]}},
            {"role": "setup", "as": "anonymous", "request": {"method": "GET", "path": "/m"},
             "expect": {"status": [404]}},
            {"role": "assert", "as": "attacker",
             "request": {"method": "GET", "path": "/docs/1"},
             "expect": {"status": [403, 404]}},
        ]
        config = {"version": 2,
                  "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                  "identities": identities, "checks": [],
                  "sequences": [{"id": "seq", "steps": steps}]}
        with _server(responder) as (url, log):
            result, _sessions, _ = _run(config, url)
        sent = [entry["cookie"] for entry in log.entries
                if entry["auth"] == ATTACKER_TOKEN and entry["path"] == "/docs/1"]
        return result, sent, result["liveness"]["unproven"]

    def test_control_nothing_replaced_the_earlier_step_proves_the_assert(self) -> None:
        result, sent, unproven = self._execute(None)
        self.assertEqual(sent, ["sid=attacker"])
        self.assertEqual(result["summary"]["sequence_steps_matched"], 3)
        self.assertEqual(unproven, [])

    def test_a_guest_cookie_after_the_earlier_step_is_disclosed(self) -> None:
        result, sent, unproven = self._execute("sid=guest; Path=/")
        self.assertEqual(sent, ["sid=guest"])
        self.assertEqual(result["summary"]["sequence_steps_matched"], 3)
        self.assertEqual([(entry["identity"], entry.get("step_index"), entry.get("proof_scope"))
                          for entry in unproven], [("attacker", 2, "cookie_value")])


@slow("stands up a loopback HTTP server and runs the engine against it")
class ProofCookiesDisagreeEndToEndTest(unittest.TestCase):
    """The same through the engine: a server that authenticates the first ``sid``.

    The attacker's login sets ``sid=attacker`` on / and on /docs. Its marker
    probe's response then sets ``late``; /docs/1 is an IDOR any logged-in caller
    reads, and a request whose first ``sid`` is not a session gets 404.
    """

    @staticmethod
    def _execute(late: str):
        def responder(entry: dict):
            who = _who(entry)
            if entry["path"] == "/login":
                return 200, [("Set-Cookie", f"sid={who}; Path=/"),
                             ("Set-Cookie", f"sid={who}; Path=/docs")], b"ok"
            sids = [part.strip()[4:] for part in entry["cookie"].split(";")
                    if part.strip().startswith("sid=")]
            if not sids or sids[0] not in ("attacker", "victim"):
                return 404, [("Content-Type", "application/json")], b'{"e":"anon"}'
            headers = [("Content-Type", "application/json")]
            if entry["path"] == "/m":
                if who == "attacker":
                    headers.append(("Set-Cookie", late))
                owner = MARKER_ATTACKER if who == "attacker" else MARKER_VICTIM
                return 200, headers, json.dumps({"m": owner}).encode()
            return 200, headers, json.dumps({"provenance": MARKER_VICTIM}).encode()

        identities = _identities(sessions=True)
        for identity in identities.values():
            identity["marker_probe"] = {"method": "GET", "path": "/m"}
        check = _doc_check()
        check["expect"]["attacker"]["status"] = [403, 404]
        config = {"version": 1,
                  "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
                  "identities": identities, "checks": [check]}
        with _server(responder) as (url, log):
            result, _sessions, _ = _run(config, url)
        probes = [entry["cookie"] for entry in log.entries
                  if entry["auth"] == ATTACKER_TOKEN and entry["path"] == "/docs/1"]
        return result, probes, _finding_map(result).get(("cross-tenant-doc-read", "attacker"))

    def test_control_a_later_cookie_of_another_name_leaves_the_idor_confirmed(self) -> None:
        result, probes, verdict = self._execute("other=guest; Path=/docs")
        self.assertEqual(probes, ["sid=attacker; other=guest; sid=attacker"])
        self.assertIsNotNone(verdict, f"graded safe: {result['summary']}")
        self.assertEqual((verdict["rule_id"], verdict["verdict"]),
                         ("VERIDOR-AUTHZ-001", "vulnerable"))

    def test_a_guest_value_on_one_proof_path_sends_nothing(self) -> None:
        result, probes, verdict = self._execute("sid=guest; Path=/docs")
        self.assertEqual(probes, [], "the probe reached the target as the guest")
        self.assertIsNotNone(verdict, f"graded safe: {result['summary']}")
        self.assertEqual((verdict["rule_id"], verdict["verdict"]),
                         ("VERIDOR-EXEC-001", "inconclusive"))
        self.assertIn("no longer carry one value", verdict["message"])
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(result["summary"]["safe"], 1)  # the victim's alone


if __name__ == "__main__":
    unittest.main()
