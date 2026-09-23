"""Every request stays on target.base_url's origin, whatever path it was given.

``core._perform_request`` builds each URL as ``urljoin(base + '/',
path.lstrip('/'))``. A path such as ``/http://collector.example/x`` passes a
check that only parses the path as written -- no scheme, no host -- and then
lstrips to an ABSOLUTE URL, so urljoin sends the request, with every identity's
credentials, to a host the configuration never named as its target. Measured
before the fix: ``veridor verify`` on a loopback capsule whose check path was
``/http://127.0.0.1:<collector>/steal`` sent four requests to the collector,
two of them carrying the verifier's own VERIDOR_* tokens, with or without
``--base-url`` and ``--read-only``; ``veridor run`` did the same, and so did an
identity's ``marker_probe.path``.

Two layers now refuse it. The load-time check parses the string the join will
actually see, so a capsule or configuration is refused with exit 2 before
anything is sent. And the one place every request is issued from asserts that
the joined URL has the target's origin before it builds the request, so a path
form nobody has thought of yet cannot leave either.

The fast tests stand in for ``core._OPENER``; the slow ones put a real listener
where the request would go and count what reaches it.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_capsule import (  # noqa: E402
    VERIFIER_ENV,
    _listener,
    _RecordingOpener,
    _v010_capsule,
    _verify,
)
from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

LOOPBACK = "http://127.0.0.1:8765"
COLLECTOR = "collector.attacker.example"

#: Paths that lstrip to an absolute URL, one per spelling that reached the wire
#: or that urljoin reads as absolute.
ESCAPES = (
    f"/http://{COLLECTOR}/steal",
    f"/https://{COLLECTOR}:8443/steal",
    f"/HTTP://{COLLECTOR}/steal",
    f"///http://{COLLECTOR}/steal",
)

#: Not an escape to another host, but urljoin still does not request the path
#: as written: ``/http:x`` resolves RELATIVE to the base (to ``/x``), and
#: ``/a:b`` becomes a URL with the scheme ``a``. Refused for the same reason.
REINTERPRETED = ("/http:/x", "/http:x", "/a:b", "/users:batchGet")

#: Look alike, and are requested exactly as written.
KEPT = ("/api/x:y", "/users", "/api/v1/items?next=http://elsewhere/x", "/a/http://b")


def _escaping_capsule(path: str | None = None, marker_probe_path: str | None = None) -> dict:
    capsule = _v010_capsule()
    if path is not None:
        capsule["check"]["request"]["path"] = path
    if marker_probe_path is not None:
        capsule["identities"]["other_tenant"]["marker_probe"]["path"] = marker_probe_path
    return capsule


def _config_from(capsule: dict) -> dict:
    return {
        "version": 1,
        "target": copy.deepcopy(capsule["target"]),
        "identities": copy.deepcopy(capsule["identities"]),
        "checks": [copy.deepcopy(capsule["check"])],
    }


def _off_target(opener: _RecordingOpener, base_url: str = LOOPBACK) -> list[dict]:
    return [r for r in opener.requests if not r["url"].startswith(base_url.rstrip("/") + "/")]


def _leaving(base: str, path: str) -> str:
    """Stands in for urljoin: every join leaves the target."""
    return f"http://{COLLECTOR}/{path}"


def _run_cli(config: dict, *flags: str) -> dict:
    opener = _RecordingOpener()
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        argv = ["run", "--config", str(path), "--output-dir", str(root / "out"), *flags]
        with patch.dict(os.environ, VERIFIER_ENV):
            with patch.object(core, "_OPENER", opener):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = veridor_main(argv)
    return {"code": code, "stderr": stderr.getvalue(), "requests": opener.requests,
            "opener": opener}


class LoadTimeRefusalTest(unittest.TestCase):
    """``_validate_request`` judges the string the join will see."""

    def test_every_escape_is_refused(self) -> None:
        for path in ESCAPES + REINTERPRETED:
            with self.subTest(path=path):
                with self.assertRaises(core.ConfigError) as raised:
                    core._validate_request({"method": "GET", "path": path}, "check 'c' request")
                self.assertIn("same-origin absolute path", str(raised.exception))

    def test_control_lookalikes_are_kept_and_join_onto_the_target(self) -> None:
        """Without this, a check that refused every path would pass the test above."""
        for path in KEPT:
            with self.subTest(path=path):
                core._validate_request({"method": "GET", "path": path}, "check 'c' request")
                joined = core.urljoin(f"{LOOPBACK}/", path.lstrip("/"))
                self.assertTrue(joined.startswith(LOOPBACK + "/"), joined)

    def test_the_premise_urljoin_really_leaves_the_target(self) -> None:
        """Asserted rather than assumed: this is the join _perform_request does."""
        self.assertEqual(
            core.urljoin(f"{LOOPBACK}/", ESCAPES[0].lstrip("/")),
            f"http://{COLLECTOR}/steal",
        )


class VerifyRefusesAnEscapingCapsuleTest(unittest.TestCase):
    """`veridor verify` on an untrusted capsule: exit 2, and nothing sent."""

    def test_a_check_path_escape_sends_nothing_with_or_without_flags(self) -> None:
        for flags in ((), ("--base-url", LOOPBACK), ("--base-url", LOOPBACK, "--read-only"),
                      ("--read-only",)):
            for path in ESCAPES:
                with self.subTest(flags=flags, path=path):
                    result = _verify(_escaping_capsule(path=path), *flags)
                    self.assertEqual(result["requests"], [], result["stderr"])
                    self.assertEqual(result["code"], 2, result["stderr"])
                    self.assertIn("request.path must be a same-origin absolute path",
                                  result["stderr"])
                    # The banner names where the values are sent. Printed over
                    # a refusal, it named a destination nothing reached.
                    self.assertNotIn("sends the values there", result["stderr"])

    def test_a_marker_probe_path_escape_sends_nothing(self) -> None:
        for flags in ((), ("--base-url", LOOPBACK, "--read-only")):
            with self.subTest(flags=flags):
                result = _verify(_escaping_capsule(marker_probe_path=ESCAPES[0]), *flags)
                self.assertEqual(result["requests"], [], result["stderr"])
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertIn("marker_probe.path must be a same-origin absolute path",
                              result["stderr"])

    def test_control_a_same_origin_capsule_is_sent_to_the_target_only(self) -> None:
        result = _verify(_escaping_capsule())
        self.assertIn("sends the values there", result["stderr"])
        self.assertTrue(result["requests"], result["stderr"])
        self.assertEqual(_off_target(result["opener"]), [])
        self.assertTrue(result["opener"].carried("owner-token"))


class RunRefusesAnEscapingConfigTest(unittest.TestCase):
    """`veridor run` shares the loader, so it shares the refusal."""

    def test_a_check_path_escape_sends_nothing(self) -> None:
        for flags in ((), ("--read-only",)):
            with self.subTest(flags=flags):
                result = _run_cli(_config_from(_escaping_capsule(path=ESCAPES[0])), *flags)
                self.assertEqual(result["requests"], [], result["stderr"])
                self.assertEqual(result["code"], 2, result["stderr"])

    def test_a_login_step_path_escape_sends_nothing(self) -> None:
        config = _config_from(_escaping_capsule())
        config["identities"]["invoice_owner"]["session"] = {
            "login": [{"method": "GET", "path": ESCAPES[0], "expect_status": [200]}],
            "establishes": {"cookie": "sid"},
        }
        result = _run_cli(config)
        self.assertEqual(result["requests"], [], result["stderr"])
        self.assertEqual(result["code"], 2, result["stderr"])
        self.assertIn("same-origin absolute path", result["stderr"])

    def test_a_sequence_step_path_escape_sends_nothing(self) -> None:
        config = _config_from(_escaping_capsule())
        config["version"] = 2
        config["sequences"] = [{
            "id": "s",
            "steps": [{
                "role": "assert", "as": "other_tenant",
                "request": {"method": "GET", "path": ESCAPES[0]},
                "expect": {"status": [404]},
            }],
        }]
        result = _run_cli(config)
        self.assertEqual(result["requests"], [], result["stderr"])
        self.assertEqual(result["code"], 2, result["stderr"])
        self.assertIn("same-origin absolute path", result["stderr"])

    def test_control_the_same_config_with_a_normal_path_reaches_the_target(self) -> None:
        result = _run_cli(_config_from(_escaping_capsule()))
        self.assertTrue(result["requests"], result["stderr"])
        self.assertEqual(_off_target(result["opener"]), [])


class SendPathOriginAssertionTest(unittest.TestCase):
    """The runtime layer, reached directly: validation is bypassed on purpose."""

    def _send(self, path: str, base_url: str = LOOPBACK) -> _RecordingOpener:
        opener = _RecordingOpener()
        with patch.object(core, "_OPENER", opener):
            core._perform_request(
                base_url, 1.0, {"method": "GET", "path": path},
                {"headers": {"Authorization": "Bearer sk-must-not-leave"}},
            )
        return opener

    def test_an_off_origin_join_raises_before_anything_is_built(self) -> None:
        # Not "/http:x": urljoin resolves that onto the base's own origin, so it
        # is the loader's to refuse (above), not an origin question.
        for path in ESCAPES + ("/a:b",):
            for base in (LOOPBACK, LOOPBACK + "/prefix"):
                with self.subTest(path=path, base=base):
                    opener = _RecordingOpener()
                    with patch.object(core, "_OPENER", opener):
                        with self.assertRaises(core.ConfigError) as raised:
                            core._perform_request(
                                base, 1.0, {"method": "GET", "path": path},
                                {"headers": {"Authorization": "Bearer sk-must-not-leave"}},
                            )
                    self.assertEqual(opener.requests, [])
                    self.assertIn("Nothing was sent", str(raised.exception))
                    self.assertNotIn("sk-must-not-leave", str(raised.exception))

    def test_run_stops_with_exit_2_when_the_layer_fires(self) -> None:
        """A path form the loader does not know yet, simulated by making the
        join itself leave the target: the command stops, and nothing is sent."""
        with patch.object(core, "urljoin", _leaving):
            result = _run_cli(_config_from(_escaping_capsule()))
        self.assertEqual(result["requests"], [], result["stderr"])
        self.assertEqual(result["code"], 2, result["stderr"])
        # The reason, not just the code: exit 2 has other causes.
        self.assertIn(f"a request resolved to 'http://{COLLECTOR}'", result["stderr"])
        self.assertIn("Nothing was sent", result["stderr"])

    def test_control_a_same_origin_path_reaches_the_opener(self) -> None:
        opener = self._send("/api/x")
        self.assertEqual([r["url"] for r in opener.requests], [f"{LOOPBACK}/api/x"])

    def test_control_the_default_port_is_the_same_origin(self) -> None:
        opener = self._send("/api/x", "http://example.test")
        self.assertEqual([r["url"] for r in opener.requests], ["http://example.test/api/x"])


#: A base URL with a path, as behind a path-routed gateway.
SERVICE_A = LOOPBACK + "/service-a/"

#: On the target's origin, but not the path you wrote: urljoin removes a
#: literal dot segment (so these went to /service-b/admin), and a gateway that
#: decodes '%2e' routes the encoded ones the same way.
DOT_PATHS = ("/../service-b/admin", "/x/../../service-b/admin", "/%2e%2e/service-b/admin",
             "/%2E%2E/service-b/admin", "/./admin", "/api/%2e/admin")

#: A dot segment carrying a servlet path parameter. Tomcat and Jetty drop the
#: ";..." before normalising, so "/..;/service-b/admin" under a --base-url of
#: https://gateway/service-a/ reaches /service-b/admin. They passed the rule,
#: which compared the whole segment with "." and "..", and were sent (measured,
#: with the verifier's tokens; the servlet side was not measured here).
PATH_PARAMETER_DOTS = ("/..;/service-b/admin", "/.;/admin", "/%2e%2e;/service-b/admin",
                       "/..%3b/service-b/admin", "/..;jsessionid=1/service-b/admin",
                       "/x/.%2E;a=b/service-b/admin")

#: A dot segment joined to the next one by an ENCODED separator. The rule split
#: on a literal '/' and then decoded, so '..%2fservice-b' decoded to
#: '../service-b' -- one segment, not '..' -- and passed at load and at send.
#: A gateway that decodes '%2f' (nginx does, measured) routed
#: '/service-a/..%2fservice-b/admin' to service-b with the verifier's tokens.
#: '%5c' is a backslash, which IIS and a Windows back end read as '/'; '%252f'
#: is the same after a second decode.
ENCODED_SEPARATOR_DOTS = ("/..%2fservice-b/admin", "/..%2Fservice-b/admin",
                          "/..%5cservice-b/admin", "/..%5Cservice-b/admin",
                          "/%2e%2e%2fservice-b/admin", "/..%252fservice-b/admin",
                          "/..%255cservice-b/admin", "/a%2f..%2fservice-b/admin",
                          "/x/.%2fadmin", "/..%2f;x/service-b/admin")

#: The same, encoded more than twice or as overlong UTF-8. The rule decoded
#: exactly twice, so '..%25252f' (three decodes to '../') passed; and it read
#: '%c0%af' -- an overlong, invalid UTF-8 spelling of '/' that IIS 4 and 5 and
#: some Java decoders read as '/' -- as two U+FFFD. Both were accepted at load
#: and at send (reproduced). A segment is now decoded until it stops changing,
#: with an overlong encoding of an ASCII character read as that character.
DEEPLY_ENCODED_DOTS = ("/..%25252fservice-b/admin", "/..%2525252Fservice-b/admin",
                       "/%2525252e%2525252e/service-b/admin", "/..%2525255cservice-b/admin",
                       "/..%c0%afservice-b/admin", "/..%C0%AFservice-b/admin",
                       "/%c0%ae%c0%ae/service-b/admin", "/..%c1%9cservice-b/admin",
                       "/%e0%80%ae%e0%80%ae/service-b/admin", "/..%f0%80%80%afservice-b/admin",
                       "/..%25c0%25afservice-b/admin", "/%c0%a52e%c0%a52e/service-b/admin")

#: '..' percent-encoded ten times over (each round turns one '%25' back into
#: '%'), so still decoding after eight rounds: nothing honest looks like this,
#: and what it becomes cannot be judged, so it is refused.
UNDECIDABLE_PATH = "/" + ("%" + "25" * 9 + "2e") * 2 + "/service-b/admin"

#: Dots that are not dot segments.
DOTS_KEPT = ("/items/1", "/a/..b", "/a/b.c", "/.well-known/x", "/a/b?x=../y",
             "/api/items;v=1", "/a/b;..", "/a/..b;c", "/a/;/b",
             # An encoded separator inside a name is ordinary (GitLab's project
             # paths); only a '.' or '..' piece next to one is refused.
             "/api/groups/group%2Fproject/items", "/files/a%2Fb.txt",
             "/a/x%5Cy", "/v1/x..y%2Fz", "/a/...%2fb",
             # Decoding until stable keeps ordinary encodings: valid UTF-8, a
             # literal '%', and a dotted name that is not a whole segment.
             "/files/caf%C3%A9", "/a/%E2%80%A6", "/v1/100%25", "/a/%252e%252ex",
             "/a/%25%25%25", "/a/%c0")


class BasePathContainmentTest(unittest.TestCase):
    """A request stays under the base URL's path, as `map`'s always did.

    `run` and `verify` contained requests to the base URL's origin only.
    Reproduced with `verify <capsule> --base-url http://127.0.0.1:PORT/service-a/`
    and a check path of `/../service-b/admin`: the banner named service-a, and
    GET /service-b/admin went out with the verifier's tokens; with a DELETE
    capsule and --base-url, DELETE /service-b/admin did. `veridor run` with that
    base_url did the same. `map` refused the path, and sequence steps refused
    dot segments; `run` and `verify` now refuse them too.
    """

    def test_a_dot_segment_is_refused_at_load(self) -> None:
        for path in DOT_PATHS + PATH_PARAMETER_DOTS + ENCODED_SEPARATOR_DOTS:
            with self.subTest(path=path):
                with self.assertRaises(core.ConfigError) as raised:
                    core._validate_request({"method": "GET", "path": path}, "check 'c' request")
                self.assertIn("'.' or '..' segment", str(raised.exception))
                self.assertIn("Nothing has been sent", str(raised.exception))

    def test_control_dots_that_are_not_segments_are_kept(self) -> None:
        for path in DOTS_KEPT:
            with self.subTest(path=path):
                core._validate_request({"method": "GET", "path": path}, "check 'c' request")

    def test_verify_sends_nothing_outside_the_base_path(self) -> None:
        for method in ("GET", "DELETE"):
            for path in DOT_PATHS[:3]:
                with self.subTest(method=method, path=path):
                    capsule = _v010_capsule(method=method)
                    capsule["check"]["request"]["path"] = path
                    result = _verify(capsule, "--base-url", SERVICE_A)
                    self.assertEqual(result["code"], 2, result["stderr"])
                    self.assertIn("'.' or '..' segment", result["stderr"])
                    self.assertEqual(result["opener"].requests, [])

    def test_verify_sends_nothing_for_a_dot_segment_with_a_path_parameter(self) -> None:
        for path in PATH_PARAMETER_DOTS:
            with self.subTest(path=path):
                capsule = _v010_capsule()
                capsule["check"]["request"]["path"] = path
                result = _verify(capsule, "--base-url", SERVICE_A)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertIn("'.' or '..' segment", result["stderr"])
                self.assertEqual(result["opener"].requests, [])

    def test_verify_sends_nothing_for_a_dot_segment_behind_an_encoded_separator(self) -> None:
        for method in ("GET", "DELETE"):
            for path in ENCODED_SEPARATOR_DOTS:
                with self.subTest(method=method, path=path):
                    capsule = _v010_capsule(method=method)
                    capsule["check"]["request"]["path"] = path
                    result = _verify(capsule, "--base-url", SERVICE_A)
                    self.assertEqual(result["code"], 2, result["stderr"])
                    self.assertIn("'.' or '..' segment", result["stderr"])
                    self.assertEqual(result["opener"].requests, [])

    def test_a_deeper_or_overlong_encoding_is_refused_at_load_and_at_send(self) -> None:
        for path in DEEPLY_ENCODED_DOTS + (UNDECIDABLE_PATH,):
            with self.subTest(path=path):
                with self.assertRaises(core.ConfigError) as raised:
                    core._validate_request({"method": "GET", "path": path}, "check 'c' request")
                self.assertIn("'.' or '..' segment", str(raised.exception))
                opener = _RecordingOpener()
                with patch.object(core, "_OPENER", opener):
                    with self.assertRaises(core.ConfigError):
                        core._perform_request(SERVICE_A, 1.0, {"method": "GET", "path": path},
                                              {"headers": {}})
                self.assertEqual(opener.requests, [])

    def test_verify_sends_nothing_for_a_deeper_or_overlong_encoding(self) -> None:
        for path in DEEPLY_ENCODED_DOTS[:1] + DEEPLY_ENCODED_DOTS[4:5]:
            with self.subTest(path=path):
                capsule = _v010_capsule()
                capsule["check"]["request"]["path"] = path
                result = _verify(capsule, "--base-url", SERVICE_A)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertEqual(result["opener"].requests, [])

    def test_the_refusal_says_what_is_judged(self) -> None:
        """It read as covering encoded separators in general while it decoded
        twice. It names what the rule judges, and no more."""
        with self.assertRaises(core.ConfigError) as raised:
            core._validate_request({"method": "GET", "path": "/../x"}, "check 'c' request")
        message = str(raised.exception)
        for judged in ("percent-encoded any number of times", "overlong UTF-8",
                       "';' path parameter", "encoded '/' or '\\'", "eight"):
            self.assertIn(judged, message)

    def test_control_an_encoded_separator_in_a_name_is_sent(self) -> None:
        capsule = _v010_capsule()
        capsule["check"]["request"]["path"] = "/api/groups/group%2Fproject/items"
        result = _verify(capsule, "--base-url", SERVICE_A)
        self.assertIn(SERVICE_A + "api/groups/group%2Fproject/items",
                      [r["url"] for r in result["opener"].requests], result["stderr"])

    def test_the_send_time_layer_holds_a_dot_segment_with_a_path_parameter(self) -> None:
        for path in PATH_PARAMETER_DOTS + ENCODED_SEPARATOR_DOTS:
            with self.subTest(path=path):
                opener = _RecordingOpener()
                with patch.object(core, "_OPENER", opener):
                    with self.assertRaises(core.ConfigError):
                        core._perform_request(SERVICE_A, 1.0, {"method": "GET", "path": path},
                                              {"headers": {}})
                self.assertEqual(opener.requests, [])

    def test_run_sends_nothing_outside_the_base_path(self) -> None:
        for where in ("check", "marker_probe", "login"):
            with self.subTest(where=where):
                config = _config_from(_v010_capsule(SERVICE_A))
                if where == "check":
                    config["checks"][0]["request"]["path"] = "/../service-b/admin"
                elif where == "marker_probe":
                    config["identities"]["other_tenant"]["marker_probe"]["path"] = (
                        "/../service-b/admin")
                else:
                    config["identities"]["invoice_owner"]["session"] = {"login": [{
                        "method": "POST", "path": "/%2e%2e/service-b/login",
                        "json": {"user": "owner"}}]}
                result = _run_cli(config)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertIn("'.' or '..' segment", result["stderr"])
                self.assertEqual(result["requests"], [])

    def test_control_the_same_capsule_stays_under_the_base_path(self) -> None:
        result = _verify(_v010_capsule(), "--base-url", SERVICE_A)
        urls = [r["url"] for r in result["opener"].requests]
        self.assertTrue(urls, result["stderr"])
        self.assertEqual([u for u in urls if not u.startswith(SERVICE_A)], [])
        self.assertIn(SERVICE_A + "api/invoices/inv-100", urls)

    def test_the_send_time_layer_holds_the_base_path(self) -> None:
        """Bypassing the loader: a path produced at run time."""
        for path in ("/../service-b/admin", "/%2e%2e/service-b/admin"):
            with self.subTest(path=path):
                opener = _RecordingOpener()
                with patch.object(core, "_OPENER", opener):
                    with self.assertRaises(core.ConfigError) as raised:
                        core._perform_request(
                            SERVICE_A, 1.0, {"method": "GET", "path": path},
                            {"headers": {"Authorization": "Bearer sk-must-not-leave"}},
                        )
                self.assertEqual(opener.requests, [])
                self.assertIn("outside the path of target.base_url", str(raised.exception))
                self.assertNotIn("sk-must-not-leave", str(raised.exception))

    def test_control_a_base_url_without_a_path_keeps_todays_containment(self) -> None:
        """No path to stay under: the origin is the whole containment, as before."""
        for base in (LOOPBACK, LOOPBACK + "/"):
            with self.subTest(base=base):
                opener = _RecordingOpener()
                with patch.object(core, "_OPENER", opener):
                    core._perform_request(base, 1.0, {"method": "GET", "path": "/service-b/x"},
                                          {"headers": {}})
                self.assertEqual([r["url"] for r in opener.requests],
                                 [f"{LOOPBACK}/service-b/x"])

    def test_the_rule_is_maps_rule(self) -> None:
        """`core` and `matrix._assert_on_target` must agree on every join."""
        from veridor import matrix  # noqa: PLC0415

        cases = [(base, path) for base in (SERVICE_A, LOOPBACK + "/service-a", LOOPBACK,
                                            LOOPBACK + "/api/v2/")
                 for path in DOT_PATHS + PATH_PARAMETER_DOTS + ENCODED_SEPARATOR_DOTS
                 + DOTS_KEPT + ("/service-a", "/service-ab/x")]
        disagree, answers = [], set()
        for base, path in cases:
            try:
                matrix._assert_on_target(base, path, where="op")
                by_map = True
            except matrix.MatrixSafetyError:
                by_map = False
            try:
                core._validate_request({"method": "GET", "path": path}, "c")
                core._assert_same_origin(base, matrix.probe_url(base, path))
                by_core = True
            except core.ConfigError:
                by_core = False
            answers.add(by_map)
            if by_map != by_core:
                disagree.append((base, path, by_map, by_core))
        self.assertEqual(disagree, [])
        # Control: the cases draw both answers, so agreement is not vacuous.
        self.assertEqual(answers, {True, False})


@slow("map paces its requests on a real clock (10 per second at most)")
class MapRuntimeLayerTest(unittest.TestCase):
    """`map` already asserts the origin of every planned path; the send-time
    layer covers it too, and stops it with exit 2."""

    def _map(self, *patches) -> tuple[int, str, _RecordingOpener]:
        opener = _RecordingOpener()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            argv = ["map", "--config", str(ROOT / "fixtures" / "veridor.map-demo.json"),
                    "--openapi", str(ROOT / "fixtures" / "openapi.demo.json"),
                    "--output-dir", str(Path(directory) / "out"), "--rate", "10"]
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(core, "_OPENER", opener))
                for target, name, value in patches:
                    stack.enter_context(patch.object(target, name, value))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                code = veridor_main(argv)
        return code, stderr.getvalue(), opener

    def test_map_stops_with_exit_2_when_the_layer_fires(self) -> None:
        code, stderr, opener = self._map((core, "urljoin", _leaving))
        self.assertEqual(opener.requests, [], stderr)
        self.assertEqual(code, 2, stderr)
        self.assertIn(f"a request resolved to 'http://{COLLECTOR}'", stderr)

    def test_control_map_sends_to_the_target_without_the_simulated_escape(self) -> None:
        code, stderr, opener = self._map()
        self.assertTrue(opener.requests, stderr)
        self.assertEqual(_off_target(opener), [])


# --------------------------------------------------------------------------
# End to end: a real listener stands where the escape would send the request
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _two_listeners():
    with _listener() as (target, target_log), _listener() as (collector, collector_log):
        yield target, target_log, collector, collector_log


def _cli(command: list[str], document: dict, env: dict) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "document.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        argv = [part.replace("{doc}", str(path)) for part in command]
        completed = subprocess.run(
            [sys.executable, "-m", "veridor", *argv, "--output-dir", str(Path(directory) / "out")],
            capture_output=True, text=True, env=source_path.child_env(**env), cwd=directory,
            timeout=120,
        )
    return completed.returncode, completed.stdout + completed.stderr


@slow("runs veridor as a subprocess against two loopback listeners")
class CollectorReceivesNothingTest(unittest.TestCase):
    """The reproduction, with the collector counted rather than inferred."""

    def _capsule(self, target: str, *, path: str | None = None,
                 marker_probe_path: str | None = None) -> dict:
        capsule = _v010_capsule(target)
        if path is not None:
            capsule["check"]["request"]["path"] = path
        if marker_probe_path is not None:
            capsule["identities"]["other_tenant"]["marker_probe"]["path"] = marker_probe_path
        return capsule

    def test_verify_sends_nothing_to_the_collector(self) -> None:
        with _two_listeners() as (target, target_log, collector, collector_log):
            escape = f"/{collector}/steal"
            cases = (
                ("check path, no flags", ["verify", "{doc}"], {"path": escape}),
                ("check path, --base-url", ["verify", "{doc}", "--base-url", target],
                 {"path": escape}),
                ("check path, --base-url --read-only",
                 ["verify", "{doc}", "--base-url", target, "--read-only"], {"path": escape}),
                ("marker_probe path, --base-url --read-only",
                 ["verify", "{doc}", "--base-url", target, "--read-only"],
                 {"marker_probe_path": escape}),
            )
            for label, command, field in cases:
                with self.subTest(case=label):
                    code, output = _cli(command, self._capsule(target, **field), VERIFIER_ENV)
                    self.assertEqual(collector_log, [], output)
                    self.assertEqual(target_log, [], output)
                    self.assertEqual(code, 2, output)

    def test_run_sends_nothing_to_the_collector(self) -> None:
        with _two_listeners() as (target, target_log, collector, collector_log):
            config = _config_from(self._capsule(target, path=f"/{collector}/steal"))
            code, output = _cli(["run", "--config", "{doc}", "--read-only"], config,
                                VERIFIER_ENV)
        self.assertEqual(collector_log, [], output)
        self.assertEqual(target_log, [], output)
        self.assertEqual(code, 2, output)

    def test_control_a_normal_path_reaches_the_target_and_not_the_collector(self) -> None:
        with _two_listeners() as (target, target_log, collector, collector_log):
            code, output = _cli(["verify", "{doc}"], self._capsule(target), VERIFIER_ENV)
        self.assertTrue(target_log, output)
        self.assertIn("Bearer owner-token",
                      [r["headers"].get("Authorization") for r in target_log])
        self.assertEqual(collector_log, [], output)


@slow("runs veridor as a subprocess against a loopback listener")
class SiblingApplicationReceivesNothingTest(unittest.TestCase):
    """The base-path reproduction with a real listener counting what arrives."""

    def test_verify_and_run_send_nothing_outside_the_base_path(self) -> None:
        with _listener() as (target, log):
            base = target + "/service-a/"
            capsule = _v010_capsule(target)
            capsule["check"]["request"]["path"] = "/../service-b/admin"
            cases = (
                ("verify GET", ["verify", "{doc}", "--base-url", base], capsule),
                ("run", ["run", "--config", "{doc}"],
                 _config_from(dict(capsule, target={"base_url": base, "timeout_seconds": 3}))),
            )
            for label, command, document in cases:
                with self.subTest(case=label):
                    code, output = _cli(command, document, VERIFIER_ENV)
                    self.assertEqual(code, 2, output)
                    self.assertEqual(log, [], output)
            delete = _v010_capsule(target, method="DELETE")
            delete["check"]["request"]["path"] = "/../service-b/admin"
            code, output = _cli(["verify", "{doc}", "--base-url", base], delete, VERIFIER_ENV)
            self.assertEqual(code, 2, output)
            self.assertEqual(log, [], output)

    def test_control_a_path_under_the_base_reaches_it(self) -> None:
        with _listener() as (target, log):
            capsule = _v010_capsule(target)
            capsule["check"]["request"]["path"] = "/items/1"
            _cli(["verify", "{doc}", "--base-url", target + "/service-a/"], capsule,
                 VERIFIER_ENV)
        self.assertIn("/service-a/items/1", [r["path"] for r in log])
        self.assertEqual([r["path"] for r in log if not r["path"].startswith("/service-a/")], [])


@slow("stands up loopback servers and runs the sequence engine against them")
class CapturedPathEscapeTest(unittest.TestCase):
    """A path resolved at run time from a value the TARGET chose.

    ``/${loc}`` is not a sole token, so the captured-absolute-URL guard never
    sees it; the resolved ``/http://collector/x`` is re-validated through
    ``_validate_request``, which is the check that had to learn about the join.
    """

    def _config(self, template: str) -> dict:
        from test_sequence import _config, _step  # noqa: PLC0415

        return _config([{
            "id": "escape",
            "steps": [
                _step("setup", "owner", "POST", "/notes", [201],
                      json={"provenance": "${marker:owner}"}, capture={"loc": "$.id"}),
                _step("assert", "attacker", "GET", template, [403, 404],
                      excludes_marker="owner"),
            ],
        }])

    def _run_against(self, captured: str) -> tuple[dict, list, list]:
        from test_sequence import _JSON, _json_body, _run, _server  # noqa: PLC0415

        with _listener() as (collector, collector_log):
            seen: list[str] = []
            value = captured.replace("{collector}", collector)

            def responder(method, path, token, body):
                seen.append(f"{method} {path}")
                if method == "POST":
                    return (201, _JSON, _json_body({"id": value}))
                return (404, _JSON, _json_body({"error": "nope"}))

            with _server(responder) as url:
                result = _run(self._config("/${loc}"), url)
            return result, seen, list(collector_log)

    def test_a_captured_absolute_url_behind_a_slash_is_refused(self) -> None:
        result, seen, collector_log = self._run_against("{collector}/steal")
        self.assertEqual(collector_log, [])
        self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")
        self.assertEqual([s for s in seen if s.startswith("GET")], [])

    def test_control_an_ordinary_captured_id_reaches_the_target(self) -> None:
        result, seen, collector_log = self._run_against("n1")
        self.assertIn("GET /n1", seen)
        self.assertEqual(collector_log, [])
        self.assertIsNone(result["sequences"][0]["abort_reason"])


if __name__ == "__main__":
    unittest.main()
