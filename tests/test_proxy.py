"""Where Veridor's requests go when a proxy is configured, and that it says so.

SECURITY.md said Veridor connects to nothing but the target, and the verify
banner said the verifier's values go "there". The opener was
``build_opener(_NoRedirectHandler)``, which adds urllib's default
``ProxyHandler``: it reads ``http_proxy``/``https_proxy`` from the environment
and, on macOS and Windows, falls back to the SYSTEM proxy configuration.
Measured with a counting target and a counting stand-in proxy: with
``http_proxy`` set, or with only a system proxy (simulated by patching urllib's
lookup), the target received 0 requests and the proxy 3, two carrying a bearer
token -- loopback targets included, and a capsule's loopback target included --
and nothing on the terminal said a proxy was in the path.

Now:

* only the environment variables count (``urllib.request.getproxies_environment``
  and its ``no_proxy`` handling); the system configuration is never read;
* a loopback target (``127.0.0.0/8``, ``::1``, ``localhost``) is always reached
  directly, because a proxy resolves "127.0.0.1" on its own host -- which is
  not the machine ``verify``'s loopback rule promises;
* whenever a proxy will carry the requests, one stderr line says which, from
  which variable, and what it sees.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_capsule import (  # noqa: E402
    VERIFIER_ENV,
    _demo_target,
    _TargetOpener,
    _v010_capsule,
)
import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

STAGING = "http://staging.example:8080"
PROXY = "http://proxy.corp.example:3128"


def _without_proxy_variables() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}


@contextlib.contextmanager
def _environment(**proxy_variables: str):
    """Exactly these proxy variables, and no other, for the duration."""
    with patch.dict(os.environ, _without_proxy_variables(), clear=True):
        os.environ.update(proxy_variables)
        yield


@contextlib.contextmanager
def _system_proxy(url: str = "http://system-proxy.example:8888"):
    """Simulate a proxy set in the OS network settings, not the environment.

    ``getproxies`` is what urllib's default ``ProxyHandler()`` consults; on
    macOS and Windows it falls back to the ``_macosx_sysconf`` and
    ``_registry`` lookups patched here as well.
    """
    configured = {"http": url, "https": url}
    with contextlib.ExitStack() as stack:
        for name in ("getproxies", "getproxies_macosx_sysconf", "getproxies_registry"):
            if hasattr(urllib.request, name):
                stack.enter_context(
                    patch.object(urllib.request, name, lambda: dict(configured))
                )
        yield


class _RoutingRecorder:
    """Stands in for ``core._OPENER`` and records where each request would go."""

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def open(self, request, timeout=None):  # noqa: A003 - mirrors OpenerDirector
        self.requests.append(
            {
                "url": request.full_url,
                "connect_to": request.host,
                "tunnel": request._tunnel_host,
                "type": request.type,
                "proxy_authorization": request.get_header("Proxy-authorization"),
                "cookie": request.get_header("Cookie"),
            }
        )
        raise URLError("recorded by the test; nothing was sent")


class _CookieSession:
    """The part of a session ``_perform_request`` calls, with a jar holding one
    Secure cookie for ``secure_cookie_for``."""

    def __init__(self, *, secure_cookie_for: str) -> None:
        import http.cookiejar  # noqa: PLC0415
        import time  # noqa: PLC0415

        self.jar = http.cookiejar.CookieJar()
        self.jar.set_cookie(http.cookiejar.Cookie(
            0, "sid", "s3cr3t-session", None, False, secure_cookie_for, True, False, "/",
            True, True, int(time.time()) + 3600, False, None, None, {}))

    def prepare(self, headers, body, *, method, graded=True):
        return headers, body, None, []

    def attach_cookies(self, request) -> None:
        self.jar.add_cookie_header(request)

    def harvest(self, response, request) -> None:
        return None


def _send(url: str) -> dict:
    recorder = _RoutingRecorder()
    with patch.object(core, "_OPENER", recorder):
        core._perform_request(url, 3, {"method": "GET", "path": "/api/x"}, {"headers": {}})
    return recorder.requests[0]


class ProxyRouteTest(unittest.TestCase):
    def test_no_variable_means_a_direct_connection(self) -> None:
        with _environment():
            self.assertIsNone(core.proxy_route(STAGING))
            self.assertEqual(_send(STAGING)["connect_to"], "staging.example:8080")

    def test_the_system_proxy_configuration_is_never_read(self) -> None:
        with _environment(), _system_proxy():
            # The simulation is real: urllib's own lookup returns the proxy.
            self.assertTrue(urllib.request.getproxies())
            self.assertIsNone(core.proxy_route(STAGING))
            self.assertIsNone(core.proxy_route("https://staging.example"))
            self.assertEqual(_send(STAGING)["connect_to"], "staging.example:8080")

    def test_an_environment_proxy_carries_the_request_and_is_named(self) -> None:
        for variable in ("HTTP_PROXY", "http_proxy"):
            with self.subTest(variable=variable), _environment(**{variable: PROXY}):
                route = core.proxy_route(STAGING)
                self.assertIsNotNone(route)
                self.assertEqual((route.address, route.variable),
                                 ("proxy.corp.example:3128", variable))
                sent = _send(STAGING)
                self.assertEqual(sent["connect_to"], "proxy.corp.example:3128")
                self.assertEqual(sent["url"], f"{STAGING}/api/x")

    def test_the_lower_case_variable_wins_as_it_does_in_urllib(self) -> None:
        with _environment(https_proxy="http://lower.example:1", HTTPS_PROXY=PROXY):
            route = core.proxy_route("https://staging.example")
            self.assertEqual((route.address, route.variable), ("lower.example:1", "https_proxy"))

    def test_https_is_tunnelled_and_uses_the_https_variable(self) -> None:
        with _environment(HTTPS_PROXY=PROXY, HTTP_PROXY="http://wrong.example:9"):
            sent = _send("https://staging.example")
        self.assertEqual(sent["connect_to"], "proxy.corp.example:3128")
        self.assertEqual(sent["tunnel"], "staging.example")

    def test_no_proxy_is_honoured(self) -> None:
        for no_proxy in ("staging.example", ".example", "*", "other.example,staging.example"):
            with self.subTest(no_proxy=no_proxy), _environment(HTTP_PROXY=PROXY,
                                                               NO_PROXY=no_proxy):
                self.assertIsNone(core.proxy_route(STAGING))
                self.assertEqual(_send(STAGING)["connect_to"], "staging.example:8080")

    def test_a_loopback_target_is_always_reached_directly(self) -> None:
        for url in ("http://127.0.0.1:8765", "http://127.9.9.9:8765",
                    "http://localhost:8765", "http://[::1]:8765"):
            with self.subTest(url=url), _environment(HTTP_PROXY=PROXY, HTTPS_PROXY=PROXY):
                self.assertIsNone(core.proxy_route(url))
                self.assertNotEqual(_send(url)["connect_to"], "proxy.corp.example:3128")

    def test_proxy_credentials_are_sent_to_the_proxy_and_never_printed(self) -> None:
        with _environment(HTTP_PROXY="http://alice:s3cr%40t@proxy.corp.example:3128"):
            sent = _send(STAGING)
            notice = core.proxy_notice(STAGING)
        self.assertEqual(sent["proxy_authorization"], "Basic YWxpY2U6czNjckB0")
        self.assertNotIn("alice", notice)
        self.assertNotIn("s3cr", notice)

    def test_the_notice_names_the_proxy_the_variable_and_what_it_sees(self) -> None:
        with _environment(HTTP_PROXY=PROXY, HTTPS_PROXY=PROXY):
            plain = core.proxy_notice(STAGING)
            tls = core.proxy_notice("https://staging.example")
        for notice in (plain, tls):
            self.assertIn("proxy.corp.example:3128", notice)
            self.assertIn("NO_PROXY", notice)
            self.assertNotIn("\n", notice)
        self.assertIn("HTTP_PROXY", plain)
        self.assertIn("credentials included", plain)
        self.assertIn("HTTPS_PROXY", tls)
        # Both cases, because Veridor cannot tell them apart: a tunnel sees
        # the host and port; a proxy that inspects TLS with a CA this machine
        # trusts (Zscaler, Netskope, a Palo Alto) decrypts every request. The
        # notice used to promise the first case unconditionally, and an
        # inspecting proxy decrypted every bearer token under it (measured).
        self.assertIn("host and port", tls)
        self.assertIn("inspects TLS", tls)
        self.assertIn("credentials included", tls)
        self.assertNotIn("sees only the host and port", tls)

    def test_a_malformed_proxy_address_is_refused_and_never_printed(self) -> None:
        """The notice printed the address after unquoting the whole of it, so
        a separator written as %40 turned the password into part of the host:
        `http://puser:Hunter2Secret%40127.0.0.1:19102` printed "through the
        proxy puser:Hunter2Secret@127.0.0.1:19102" (measured). A raw '@' and
        '/' in the password printed a fragment of it. urllib could not have
        connected to either."""
        for value in ("http://puser:Hunter2Secret%40127.0.0.1:19102",
                      "http://u:SeCrEtPw@FraGmEnt/x@proxy.corp.example:3128",
                      "http://proxy.corp.example:3128/some/path",
                      "http://proxy%2ecorp.example:3128"):
            with self.subTest(value=value), _environment(HTTP_PROXY=value):
                with self.assertRaises(core.ConfigError) as refused:
                    core.proxy_route(STAGING)
                message = str(refused.exception)
                for secret in ("Hunter2Secret", "puser", "SeCrEtPw", "FraGmEnt", "some/path"):
                    self.assertNotIn(secret, message)
                self.assertIn("HTTP_PROXY", message)
                self.assertIn("Nothing has been sent", message)

    def test_control_well_formed_proxy_addresses_are_kept(self) -> None:
        for value, address in (("http://proxy.corp.example:3128", "proxy.corp.example:3128"),
                               ("http://proxy.corp.example:3128/", "proxy.corp.example:3128"),
                               ("proxy.corp.example:3128", "proxy.corp.example:3128"),
                               ("http://corp_proxy:3128", "corp_proxy:3128"),
                               ("http://a:b%40c@10.0.0.5:8080", "10.0.0.5:8080"),
                               ("http://[fd00::5]:3128", "[fd00::5]:3128")):
            with self.subTest(value=value), _environment(HTTP_PROXY=value):
                self.assertEqual(core.proxy_route(STAGING).address, address)

    def test_an_https_proxy_for_an_https_target_is_refused(self) -> None:
        """urllib cannot open TLS to a proxy for a tunnel: the CONNECT line and
        the variable's user:password went to the proxy in plaintext, under a
        value that said https:// (measured on the wire)."""
        with _environment(HTTPS_PROXY="https://puser:ProxyPw@proxy.corp.example:3128"):
            with self.assertRaises(core.ConfigError) as refused:
                core.proxy_route("https://staging.example")
            recorder = _RoutingRecorder()
            with patch.object(core, "_OPENER", recorder):
                with self.assertRaises(core.ConfigError):
                    core._perform_request("https://staging.example", 3,
                                          {"method": "GET", "path": "/api/x"}, {"headers": {}})
        self.assertEqual(recorder.requests, [])
        message = str(refused.exception)
        self.assertIn("HTTPS_PROXY", message)
        self.assertIn("plaintext", message)
        self.assertNotIn("ProxyPw", message)

    def test_control_an_https_proxy_for_an_http_target_is_spoken_to_over_tls(self) -> None:
        """For an http:// target urllib does open TLS to an https:// proxy: the
        request's type becomes https and it connects to the proxy host."""
        with _environment(HTTP_PROXY="https://proxy.corp.example:3128"):
            sent = _send(STAGING)
        self.assertEqual((sent["type"], sent["connect_to"], sent["tunnel"]),
                         ("https", "proxy.corp.example:3128", None))

    def test_the_bypass_hint_names_the_variable_urllib_reads(self) -> None:
        """urllib reads a lower-case no_proxy in preference to NO_PROXY, so
        "Set NO_PROXY=staging.example" did nothing when no_proxy was set
        (measured), and for an IPv6 target it compares the bracketed host."""
        with _environment(HTTP_PROXY=PROXY, no_proxy="localhost"):
            notice = core.proxy_notice(STAGING)
            self.assertIn("Add staging.example to no_proxy", notice)
        with _environment(HTTP_PROXY=PROXY, no_proxy="localhost,staging.example"):
            self.assertIsNone(core.proxy_route(STAGING))
        with _environment(HTTP_PROXY=PROXY, NO_PROXY="staging.example", no_proxy="localhost"):
            self.assertIsNotNone(core.proxy_route(STAGING), "the case the old hint led to")
        v6 = "http://[fd00::1]:8080"
        with _environment(HTTP_PROXY=PROXY):
            self.assertIn("NO_PROXY=[fd00::1]", core.proxy_notice(v6))
        with _environment(HTTP_PROXY=PROXY, NO_PROXY="[fd00::1]"):
            self.assertIsNone(core.proxy_route(v6))
        with _environment(HTTP_PROXY=PROXY, NO_PROXY="fd00::1"):
            self.assertIsNotNone(core.proxy_route(v6), "the case the old hint led to")

    def test_control_without_no_proxy_the_hint_sets_it(self) -> None:
        with _environment(HTTP_PROXY=PROXY):
            self.assertIn("Set NO_PROXY=staging.example to connect directly", core.proxy_notice(STAGING))
        with _environment(HTTP_PROXY=PROXY, NO_PROXY="staging.example"):
            self.assertIsNone(core.proxy_route(STAGING))

    def test_a_secure_cookie_is_not_attached_for_an_http_target_behind_an_https_proxy(self) -> None:
        """set_proxy made the request's type https before the session's jar
        attached its cookies, so a Secure cookie went out to an http:// target
        (through the proxy). urllib's own order attaches cookies first."""
        for proxy, target, attached in (("https://proxy.corp.example:3128", STAGING, False),
                                        (None, "https://staging.example", True),
                                        (None, STAGING, False)):
            with self.subTest(proxy=proxy, target=target):
                variables = {"HTTP_PROXY": proxy} if proxy else {}
                session = _CookieSession(secure_cookie_for="staging.example")
                recorder = _RoutingRecorder()
                with _environment(**variables), patch.object(core, "_OPENER", recorder):
                    core._perform_request(target, 3, {"method": "GET", "path": "/api/x"},
                                          {"headers": {}}, session=session)
                self.assertEqual(recorder.requests[0]["cookie"] is not None, attached,
                                 recorder.requests)

    def test_no_notice_when_nothing_goes_through_a_proxy(self) -> None:
        with _environment(HTTP_PROXY=PROXY):
            self.assertIsNone(core.proxy_notice("http://127.0.0.1:8765"))
        with _environment():
            self.assertIsNone(core.proxy_notice(STAGING))


def _config(base_url: str) -> dict:
    return {
        "version": 1,
        "target": {"base_url": base_url, "timeout_seconds": 3},
        "identities": {
            "owner": {"headers": {"Authorization": "Bearer ${VERIDOR_INVOICE_OWNER_TOKEN}"}},
            "other": {"headers": {"Authorization": "Bearer ${VERIDOR_OTHER_TENANT_TOKEN}"}},
        },
        "checks": [{"id": "c1", "request": {"method": "GET", "path": "/api/x"},
                    "expect": {"owner": {"status": [404]}, "other": {"status": [404]}}}],
    }


def _cli(argv_tail: list[str], document: dict, **proxy_variables: str) -> dict:
    recorder = _RoutingRecorder()
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "input.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        argv = [argv_tail[0], *(["--config"] if argv_tail[0] == "run" else []), str(path),
                "--output-dir", str(root / "out"), *argv_tail[1:]]
        with _environment(**proxy_variables), patch.dict(os.environ, VERIFIER_ENV):
            with patch.object(core, "_OPENER", recorder):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = veridor_main(argv)
    return {"code": code, "stderr": stderr.getvalue(), "requests": recorder.requests}


class ProxyRefusalMessageTest(unittest.TestCase):
    """A 407 is a proxy's answer. The finding said "The target refused this
    request" for it, which `run` printed with a 407 proxy in the path while
    the target received nothing (measured)."""

    def _messages(self, status: int) -> list[str]:
        opener = _TargetOpener(lambda method, path, auth: (status, {}))
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "c.json").write_text(json.dumps(_config(STAGING)), encoding="utf-8")
            with _environment(), patch.dict(os.environ, VERIFIER_ENV):
                with patch.object(core, "_OPENER", opener):
                    with contextlib.redirect_stdout(stdout), \
                            contextlib.redirect_stderr(io.StringIO()):
                        veridor_main(["run", "--config", str(root / "c.json"), "--output-dir",
                                      str(root / "out"), "--json", str(root / "r.json")])
            document = json.loads((root / "r.json").read_text(encoding="utf-8"))
        return [finding["message"] for finding in document["findings"]]

    def test_a_407_is_named_as_the_proxy_s_answer(self) -> None:
        messages = self._messages(407)
        self.assertTrue(messages)
        for message in messages:
            self.assertIn("Proxy Authentication Required", message)
            self.assertNotIn("The target refused", message)

    def test_control_a_401_is_still_the_target_s_refusal(self) -> None:
        messages = self._messages(401)
        self.assertTrue(messages)
        for message in messages:
            self.assertIn("The target refused this request", message)


class ProxyAnnouncementTest(unittest.TestCase):
    def test_run_says_once_that_a_proxy_carries_its_requests(self) -> None:
        result = _cli(["run"], _config(STAGING), HTTP_PROXY=PROXY)
        self.assertTrue(result["requests"], result["stderr"])
        self.assertTrue(all(r["connect_to"] == "proxy.corp.example:3128"
                            for r in result["requests"]))
        lines = [line for line in result["stderr"].splitlines() if "proxy.corp.example" in line]
        self.assertEqual(len(lines), 1, result["stderr"])
        self.assertIn("HTTP_PROXY", lines[0])

    def test_a_proxy_variable_urllib_cannot_parse_is_refused_before_sending(self) -> None:
        """urllib raised ValueError from inside the opener for a value with no
        authority, and `run` exited 70, "a bug in Veridor" (measured on the
        tree before this module existed, for a loopback target too)."""
        result = _cli(["run"], _config(STAGING), HTTP_PROXY="http:/alice:s3cret@proxy")
        self.assertEqual(result["code"], 2, result["stderr"])
        self.assertEqual(result["requests"], [])
        self.assertIn("HTTP_PROXY", result["stderr"])
        self.assertNotIn("internal error", result["stderr"])
        self.assertNotIn("s3cret", result["stderr"])

    def test_control_run_without_a_proxy_says_nothing_about_one(self) -> None:
        result = _cli(["run"], _config(STAGING))
        self.assertTrue(result["requests"], result["stderr"])
        self.assertTrue(all(r["connect_to"] == "staging.example:8080"
                            for r in result["requests"]))
        self.assertNotIn("proxy", result["stderr"].lower())

    def test_verify_names_the_proxy_in_its_banner(self) -> None:
        result = _cli(["verify", "--base-url", STAGING], _v010_capsule(), HTTP_PROXY=PROXY)
        banner = next(line for line in result["stderr"].splitlines()
                      if line.startswith("veridor: verifying capsule"))
        self.assertIn("through the proxy proxy.corp.example:3128", banner)
        self.assertIn("HTTP_PROXY", banner)
        self.assertEqual(result["stderr"].count("proxy.corp.example"), 1, result["stderr"])
        self.assertTrue(all(r["connect_to"] == "proxy.corp.example:3128"
                            for r in result["requests"]))

    def test_map_and_mutate_say_it_too(self) -> None:
        """Every verb that sends. A private address needs no acknowledgement
        from `map`, and is not loopback, so a proxy applies to it."""
        spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
                "paths": {"/api/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}
        for verb in ("map", "mutate"):
            with self.subTest(verb=verb), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "c.json").write_text(json.dumps(_config("http://10.1.2.3:8080")))
                (root / "o.json").write_text(json.dumps(spec))
                argv = [verb, "--config", str(root / "c.json"), "--output-dir", str(root / "out")]
                argv += (["--openapi", str(root / "o.json"), "--rate", "10"] if verb == "map"
                         else ["--min-interval", "0"])
                recorder, stderr = _RoutingRecorder(), io.StringIO()
                with _environment(HTTP_PROXY=PROXY), patch.dict(os.environ, VERIFIER_ENV):
                    with patch.object(core, "_OPENER", recorder):
                        with contextlib.redirect_stdout(io.StringIO()), \
                                contextlib.redirect_stderr(stderr):
                            veridor_main(argv)
                self.assertTrue(recorder.requests, stderr.getvalue())
                self.assertEqual({r["connect_to"] for r in recorder.requests},
                                 {"proxy.corp.example:3128"})
                notices = [line for line in stderr.getvalue().splitlines()
                           if "through the proxy proxy.corp.example:3128" in line]
                self.assertEqual(len(notices), 1, stderr.getvalue())

    def test_verify_s_loopback_target_is_reached_directly_whatever_the_environment(self) -> None:
        """The banner says the values go to the capsule's own loopback target.
        With a proxy they went to the proxy, which resolves 127.0.0.1 itself."""
        result = _cli(["verify"], _v010_capsule(), HTTP_PROXY=PROXY, HTTPS_PROXY=PROXY)
        self.assertTrue(result["requests"], result["stderr"])
        self.assertEqual({r["connect_to"] for r in result["requests"]}, {"127.0.0.1:8765"})
        self.assertNotIn("proxy", result["stderr"].lower())


# ---------------------------------------------------------------------------
# End to end, with a real target and a real stand-in proxy on loopback.
# ---------------------------------------------------------------------------

#: A host name the prelude below resolves to 127.0.0.1, so a target can be
#: "not loopback" by name -- and so eligible for a proxy -- and still be local.
NAMED_TARGET = "gate-target.invalid"

_PRELUDE = """
import socket, sys, urllib.request as u
system = {"http": sys.argv.pop(1), "https": None}
system["https"] = system["http"]
# A proxy configured in the OS network settings, not in the environment.
for name in ("getproxies", "getproxies_macosx_sysconf", "getproxies_registry"):
    if hasattr(u, name):
        setattr(u, name, lambda: dict(system))
real = socket.getaddrinfo
socket.getaddrinfo = lambda host, *a, **k: real(
    "127.0.0.1" if host == %r else host, *a, **k)
from veridor.cli import main
raise SystemExit(main(sys.argv[1:]))
""" % NAMED_TARGET


def _counting_server():
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            received.append({"line": self.requestline,
                             "authorization": self.headers.get("Authorization")})
            self.send_response(404)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(httpd)
    return httpd, thread, received


@slow("spawns veridor against a loopback target and a loopback stand-in proxy")
class ProxyEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.target_server, self.target_thread, self.target_log = _counting_server()
        self.proxy_server, self.proxy_thread, self.proxy_log = _counting_server()
        self.target_port = self.target_server.server_port
        self.proxy_port = self.proxy_server.server_port
        self.proxy = f"http://127.0.0.1:{self.proxy_port}"

    def tearDown(self) -> None:
        for httpd, thread in ((self.target_server, self.target_thread),
                              (self.proxy_server, self.proxy_thread)):
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def _veridor(self, argv: list[str], document: dict, *, system_proxy: bool = False,
                 **proxy_variables: str) -> tuple[int, str]:
        self.target_log.clear()
        self.proxy_log.clear()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            env = source_path.child_env(_without_proxy_variables(), **VERIFIER_ENV,
                                        **proxy_variables)
            head = ([sys.executable, "-c", _PRELUDE, self.proxy] if system_proxy
                    else [sys.executable, "-m", "veridor.cli"])
            flag = ["--config"] if argv[0] == "run" else []
            completed = subprocess.run(
                [*head, argv[0], *flag, str(path), "--output-dir",
                 str(Path(directory) / "out"), *argv[1:]],
                capture_output=True, text=True, env=env, cwd=directory, timeout=120,
            )
        return completed.returncode, completed.stdout + completed.stderr

    def test_an_environment_proxy_carries_a_named_target_and_is_announced(self) -> None:
        target = f"http://{NAMED_TARGET}:{self.target_port}"
        code, output = self._veridor(["run"], _config(target), system_proxy=True,
                                     HTTP_PROXY=self.proxy)
        self.assertEqual(len(self.target_log), 0, output)
        self.assertEqual(len(self.proxy_log), 3, output)
        self.assertTrue(all(entry["line"].startswith(f"GET {target}/api/x ")
                            for entry in self.proxy_log), self.proxy_log)
        self.assertIn(f"through the proxy 127.0.0.1:{self.proxy_port}", output)
        self.assertIn("HTTP_PROXY", output)

    def test_without_the_variable_a_system_proxy_is_not_used(self) -> None:
        """The same named target and the same simulated OS proxy, no variable:
        straight to the target, and nothing said about a proxy."""
        target = f"http://{NAMED_TARGET}:{self.target_port}"
        code, output = self._veridor(["run"], _config(target), system_proxy=True)
        self.assertEqual(len(self.proxy_log), 0, output)
        self.assertEqual(len(self.target_log), 3, output)
        self.assertEqual(code, 0, output)
        self.assertNotIn("proxy", output.lower())

    def test_a_loopback_target_is_reached_directly_with_a_proxy_set(self) -> None:
        loopback = f"http://127.0.0.1:{self.target_port}"
        for argv, document in ((["run"], _config(loopback)),
                               (["verify"], _v010_capsule(loopback))):
            with self.subTest(command=argv[0]):
                code, output = self._veridor(argv, document, HTTP_PROXY=self.proxy)
                self.assertEqual(len(self.proxy_log), 0, output)
                self.assertGreater(len(self.target_log), 0, output)
                self.assertIn("Bearer owner-token",
                              [entry["authorization"] for entry in self.target_log])


def _answering_server(answer):
    """A loopback server that answers with ``answer(method, path, auth)``.

    ``answer`` may return ``None`` to mean "forward": the request line is in
    proxy (absolute) form, and it is relayed to the loopback port it names,
    whatever the host -- a stand-in for a forwarding proxy.
    """
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            received.append({"line": self.requestline,
                             "authorization": self.headers.get("Authorization")})
            answered = answer("GET", self.path, self.headers.get("Authorization"))
            if answered is None:
                parts = urllib.parse.urlsplit(self.path)
                upstream = urllib.request.Request(
                    f"http://127.0.0.1:{parts.port}{parts.path}",
                    headers={k: v for k, v in self.headers.items()
                             if k.lower() not in {"host", "connection", "proxy-connection"}})
                try:
                    with _DIRECT.open(upstream, timeout=10) as response:
                        status, body = response.status, response.read()
                except urllib.error.HTTPError as error:
                    status, body = error.code, error.read()
            else:
                status, payload = answered
                body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(httpd)
    return httpd, thread, received


#: The forwarder's own client: straight to loopback, never through a proxy.
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@slow("spawns veridor verify against a loopback target behind loopback stand-in proxies")
class ProxyRefusalEndToEndTest(unittest.TestCase):
    """A proxy that refuses every request is not a target that holds.

    Reproduced before the fix: a vulnerable target behind a proxy answering
    407 to everything (an authenticating corporate proxy urllib cannot satisfy)
    received 0 requests, and `verify` printed NOT_REPRODUCED, "the declared
    expectation held on this target", exit 0.
    """

    def setUp(self) -> None:
        demo = _demo_target(vulnerable=True)
        self.servers = {
            "target": _answering_server(lambda method, path, auth: demo(method, path, auth)),
            "refusing": _answering_server(
                lambda method, path, auth: (407, {"error": "proxy authentication required"})),
            "forwarding": _answering_server(lambda method, path, auth: None),
        }

    def tearDown(self) -> None:
        for httpd, thread, _ in self.servers.values():
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def _verify_through(self, proxy: str) -> tuple[int, str, int, int]:
        target_port = self.servers["target"][0].server_port
        proxy_port = self.servers[proxy][0].server_port
        for _, _, log in self.servers.values():
            log.clear()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(_v010_capsule()), encoding="utf-8")
            env = source_path.child_env(_without_proxy_variables(), **VERIFIER_ENV,
                                        HTTP_PROXY=f"http://127.0.0.1:{proxy_port}")
            completed = subprocess.run(
                [sys.executable, "-m", "veridor.cli", "verify", str(path),
                 "--base-url", f"http://{NAMED_TARGET}:{target_port}",
                 "--output-dir", str(Path(directory) / "out")],
                capture_output=True, text=True, env=env, cwd=directory, timeout=120,
            )
        return (completed.returncode, completed.stdout + completed.stderr,
                len(self.servers["target"][2]), len(self.servers[proxy][2]))

    def test_a_proxy_answering_407_is_inconclusive_and_the_target_saw_nothing(self) -> None:
        code, output, at_target, at_proxy = self._verify_through("refusing")
        self.assertEqual(at_target, 0, output)
        self.assertGreater(at_proxy, 0, output)
        self.assertEqual(code, 2, output)
        self.assertIn("Veridor capsule — INCONCLUSIVE", output)
        self.assertIn("HTTP 407", output)
        self.assertNotIn("NOT_REPRODUCED", output)

    def test_control_the_same_route_through_a_forwarding_proxy_confirms(self) -> None:
        code, output, at_target, at_proxy = self._verify_through("forwarding")
        self.assertGreater(at_target, 0, output)
        self.assertEqual(at_proxy, at_target, output)
        self.assertEqual(code, 1, output)
        self.assertIn("Veridor capsule — CONFIRMED", output)




class ProxyAnswerIsNotAnAnswerTest(unittest.TestCase):
    """A 407 is the proxy's answer; `run` graded it as the target's.

    `verify` reports a 407 as INCONCLUSIVE and `map` records it unmeasured,
    but `run` graded a 407 where [200] was declared as `unexpected_denial` --
    a finding about the target, exit 1 -- although the target never saw the
    request. It now takes the same path as a 429
    or a 5xx: not an answer, an inconclusive finding, exit 3."""

    def _grade(self, status: int) -> list:
        from pathlib import Path  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        check = {
            "id": "own-invoice",
            "request": {"method": "GET", "path": "/doc/1"},
            "expect": {"owner": {"status": [200]}},
        }
        probes = {
            "owner": {
                "request": {"method": "GET", "url": "http://t/doc/1"},
                "error": None,
                "response": {"status": status, "marker_scan": "absent", "from_cache": False,
                             "marker_scan_reason": None, "marker_encodings": []},
            }
        }
        return core._grade_check(check, probes, Path("veridor.json"))

    def test_a_407_is_an_inconclusive_probe_not_a_finding_about_the_target(self) -> None:
        from veridor import core  # noqa: PLC0415

        findings = self._grade(407)
        self.assertEqual([f["verdict"] for f in findings], ["inconclusive"])
        self.assertIn("proxy", findings[0]["message"])
        self.assertNotIn("throttled", findings[0]["message"])
        self.assertFalse(core.probe_answered({"response": {"status": 407}}))

    def test_control_a_401_from_the_target_is_still_a_finding(self) -> None:
        from veridor import core  # noqa: PLC0415

        self.assertEqual([f["verdict"] for f in self._grade(401)], ["unexpected_denial"])
        self.assertTrue(core.probe_answered({"response": {"status": 401}}))


if __name__ == "__main__":
    unittest.main()
