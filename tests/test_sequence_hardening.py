"""Regression tests for false-SAFE and false-finding defects.

Each class here corresponds to one reproduced defect. Every test drives the
real engine against a real loopback target and asserts on the verdict, because
every one of these defects was invisible from the code and visible only in the
output: a green run over an untested boundary, or a red run over a correct API.

The two directions are held to the same standard. A false SAFE hides a live
vulnerability; a false finding trains an operator to ignore the gate. Neither
is a smaller bug than the other.
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_sequence import (  # noqa: E402
    _JSON,
    ATTACKER_TOKEN,
    MARKER_OWNER,
    OWNER_TOKEN,
    _config,
    _json_body,
    _load,
    _rules,
    _run,
    _server,
    _step,
)

import loopback  # noqa: E402
from tiers import fast, slow  # noqa: E402
from veridor import core, sequence  # noqa: E402


# --------------------------------------------------------------------------
# (1) A captured value must never retarget the probe at another endpoint
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class CapturedPathRetargetingTest(unittest.TestCase):
    """`urljoin` applies RFC 3986 remove_dot_segments to the path it is given.

    A captured `..` therefore rewrites WHICH endpoint the probe hits, the
    declaration's endpoint is never requested, and because the persisted URL is
    the config template the swap leaves no trace in the run document.
    """

    @staticmethod
    def _config(extractor: str, template: str) -> dict:
        return _config(
            [
                {
                    "id": "retarget",
                    "steps": [
                        _step(
                            "setup", "owner", "POST", "/notes", [201],
                            json={"provenance": "${marker:owner}"},
                            capture={"loc": extractor},
                        ),
                        _step(
                            "assert", "attacker", "GET", template, [403, 404],
                            excludes_marker="owner",
                        ),
                    ],
                }
            ]
        )

    @fast("asserts on the declaration, not on a live target")
    def test_urljoin_really_does_normalize_dot_segments(self) -> None:
        """The premise of the defect, asserted rather than assumed."""
        from urllib.parse import urljoin

        # The endpoint the caller named is NOT the endpoint that gets requested.
        self.assertEqual(
            urljoin("http://h/", "api/v2/notes/n1/../../profile"),
            "http://h/api/v2/profile",
        )
        self.assertEqual(
            urljoin("http://h/", "notes/n1/../../profile"), "http://h/profile"
        )

    def test_a_captured_location_with_dot_segments_is_refused(self) -> None:
        seen: list[str] = []

        def responder(method, path, token, body):
            seen.append(f"{method} {path}")
            if method == "POST":
                return (
                    201,
                    {**_JSON, "Location": "/notes/n1/../../profile"},
                    _json_body({"id": "n1"}),
                )
            # Wide open, and it hands back the owner's marker to anyone.
            return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))

        with _server(responder) as url:
            result = _run(self._config("header:Location", "${loc}"), url)

        self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")
        self.assertNotIn("GET /profile", seen)
        self.assertEqual({f["verdict"] for f in result["findings"]}, {"inconclusive"})

    def test_a_captured_mid_path_segment_with_dot_dot_is_refused(self) -> None:
        """The id lands INSIDE the template, so the sole-token guards miss it."""
        seen: list[str] = []

        def responder(method, path, token, body):
            seen.append(f"{method} {path}")
            if method == "POST":
                return (201, _JSON, _json_body({"id": "n1/../../profile"}))
            return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))

        with _server(responder) as url:
            result = _run(self._config("$.id", "/notes/${loc}"), url)

        self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")
        self.assertNotIn("GET /profile", seen)

    def test_a_percent_encoded_dot_segment_is_refused_too(self) -> None:
        def responder(method, path, token, body):
            if method == "POST":
                return (201, _JSON, _json_body({"id": "%2e%2e"}))
            return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))

        with _server(responder) as url:
            result = _run(self._config("$.id", "/notes/${loc}/x"), url)
        self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")

    def test_an_ordinary_captured_id_is_unaffected(self) -> None:
        """The guard must not cost a normal capture."""
        seen: list[str] = []

        def responder(method, path, token, body):
            seen.append(f"{method} {path}")
            if method == "POST":
                return (201, _JSON, _json_body({"id": "n1"}))
            return (404, _JSON, _json_body({"error": "nope"}))

        with _server(responder) as url:
            result = _run(self._config("$.id", "/notes/${loc}"), url)
        self.assertIn("GET /notes/n1", seen)
        self.assertIsNone(result["sequences"][0]["abort_reason"])

    @fast("asserts on the declaration, not on a live target")
    def test_a_dot_only_segment_is_refused(self) -> None:
        self.assertTrue(sequence._has_dot_segment("/a/./b"))
        self.assertTrue(sequence._has_dot_segment("/a/../b"))
        self.assertTrue(sequence._has_dot_segment("/a/.."))
        self.assertFalse(sequence._has_dot_segment("/a/..b"))
        self.assertFalse(sequence._has_dot_segment("/a/b.c"))
        # A dot segment in the QUERY is not a path segment.
        self.assertFalse(sequence._has_dot_segment("/a/b?x=../y"))


# --------------------------------------------------------------------------
# (3) A marker leaked in a response HEADER is a leak
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class HeaderMarkerOracleTest(unittest.TestCase):
    """Response headers are response bytes.

    `Content-Disposition: filename="<other tenant's file>"`, a `Location`
    pointing at a foreign resource, an `ETag` derived from foreign content and
    `X-Owner`-style debug headers are all real leak channels, and every one of
    them used to grade `absent`.
    """

    @staticmethod
    def _check_config() -> dict:
        return _config(
            [],
            checks=[
                {
                    "id": "note-isolation",
                    "request": {"method": "GET", "path": "/notes/n1"},
                    "expect": {
                        "owner": {"status": [200], "contains_marker": "owner"},
                        "attacker": {
                            "status": [403, 404],
                            "excludes_marker": "owner",
                        },
                    },
                }
            ],
        )

    def test_a_marker_in_a_response_header_is_observed(self) -> None:
        """Clean 404, clean body -- and the owner's marker in two headers."""

        def responder(method, path, token, body):
            if token == OWNER_TOKEN:
                return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))
            # Only the attacker's recognised credential gets the headers. Sent
            # to every caller, the liveness sham got them too, which makes the
            # marker a string anybody can read and caps the grade at suspected.
            if token != ATTACKER_TOKEN:
                return (404, _JSON, _json_body({"error": "not found"}))
            return (
                404,
                {
                    **_JSON,
                    "X-Object-Owner-Tag": MARKER_OWNER,
                    "Content-Disposition": f'attachment; filename="{MARKER_OWNER}.pdf"',
                },
                _json_body({"error": "not found"}),
            )

        with _server(responder) as url:
            result = _run(self._check_config(), url)

        self.assertEqual(_rules(result), ["VERIDOR-LEAK-001"])
        finding = result["findings"][0]
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(finding["evidence"]["marker"]["state"], "present")

    def test_the_channel_is_recorded_so_a_reviewer_can_see_where(self) -> None:
        def responder(method, path, token, body):
            if token == OWNER_TOKEN:
                return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))
            return (404, {**_JSON, "X-Owner": MARKER_OWNER}, _json_body({"e": 1}))

        with _server(responder) as url:
            result = _run(self._check_config(), url)
        channels = {
            probe["response"]["marker_channel"] for probe in result["probes"]
        }
        self.assertEqual(channels, {"body", "header"})

    def test_a_clean_denial_with_clean_headers_still_passes(self) -> None:
        def responder(method, path, token, body):
            if token == OWNER_TOKEN:
                return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))
            return (404, _JSON, _json_body({"error": "not found"}))

        with _server(responder) as url:
            result = _run(self._check_config(), url)
        self.assertEqual(result["findings"], [])

    def test_a_header_match_overrides_an_oracle_failure_on_the_body(self) -> None:
        """`unknown` on the body plus a header hit is still positive evidence."""

        def responder(method, path, token, body):
            if token == OWNER_TOKEN:
                return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))
            # As above: the header goes to the attacker's recognised credential
            # only. Sent to the liveness sham too, the marker is a string
            # anybody can read, which is an unverified oracle, not a leak.
            if token != ATTACKER_TOKEN:
                return (404, _JSON, _json_body({"error": "not found"}))
            return (
                404,
                {**_JSON, "Content-Encoding": "br", "X-Owner": MARKER_OWNER},
                _json_body({"error": "not found"}),
            )

        with _server(responder) as url:
            result = _run(self._check_config(), url)
        self.assertEqual(_rules(result), ["VERIDOR-LEAK-001"])
        self.assertEqual(
            result["findings"][0]["evidence"]["marker"]["state"], "present"
        )


# --------------------------------------------------------------------------
# (4) A cached read cannot refute a write, and cannot license a pass
# --------------------------------------------------------------------------


def _cache_config() -> dict:
    return _config(
        [
            {
                "id": "delete",
                "steps": [
                    _step("setup", "owner", "POST", "/n", [201],
                          json={"provenance": "${marker:owner}"},
                          capture={"note": "$.id"}),
                    _step("setup", "owner", "GET", "/n/${note}", [200],
                          contains_marker="owner"),
                    _step("assert", "attacker", "DELETE", "/n/${note}", [403, 404]),
                    _step("assert", "owner", "GET", "/n/${note}", [200],
                          contains_marker="owner"),
                ],
            }
        ]
    )


@slow("stands up a loopback HTTP server and runs the engine against it")
class CachedReadTest(unittest.TestCase):
    """A shared or path-keyed cache in front of the target serves the pre-delete
    copy of the verification read, so the marker is found and Veridor appends an
    exculpation to a finding that describes real data destruction."""

    @staticmethod
    def _stale_cache_target():
        """DELETE really destroys the row; the GET is answered from a cache."""
        state = {"present": False, "cached": None}

        def responder(method, path, token, body):
            if method == "POST":
                state["present"] = True
                return (201, _JSON, _json_body({"id": "n1"}))
            if method == "DELETE":
                state["present"] = False
                return (204, {}, b"")
            if method == "GET":
                if state["cached"] is not None:
                    # The cache is keyed on path only and never revalidates.
                    return (200, {**_JSON, "X-Cache": "HIT"}, state["cached"])
                if not state["present"]:
                    return (404, _JSON, _json_body({"error": "gone"}))
                payload = _json_body({"provenance": MARKER_OWNER})
                state["cached"] = payload
                return (200, {**_JSON, "X-Cache": "MISS"}, payload)
            return (405, _JSON, b"{}")

        return responder

    def test_a_cached_read_does_not_exculpate_a_real_delete(self) -> None:
        with _server(self._stale_cache_target()) as url:
            result = _run(_cache_config(), url)

        authz = [f for f in result["findings"] if f["rule_id"] == "VERIDOR-AUTHZ-001"]
        self.assertEqual(len(authz), 1)
        self.assertNotIn("did not take effect", authz[0]["message"])
        self.assertEqual(
            authz[0]["evidence"]["write_effect"]["state"], "not_verified"
        )

    def test_the_cached_verification_read_is_not_graded_as_a_pass(self) -> None:
        with _server(self._stale_cache_target()) as url:
            result = _run(_cache_config(), url)
        steps = result["sequences"][0]["steps"]
        self.assertEqual(steps[3]["state"], "mismatched")
        self.assertIn("VERIDOR-CACHE-001", _rules(result))
        cache = [f for f in result["findings"] if f["rule_id"] == "VERIDOR-CACHE-001"]
        self.assertEqual(cache[0]["verdict"], "inconclusive")

    def test_veridor_asks_every_hop_not_to_serve_a_cached_copy(self) -> None:
        seen: list[dict] = []

        class _Recorder:
            @staticmethod
            def responder(method, path, token, body):
                return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))

        import http.server

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):  # noqa: N802
                seen.append({k.lower(): v for k, v in self.headers.items()})
                payload = _json_body({"provenance": MARKER_OWNER})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = loopback.start(server)
        try:
            config = _config(
                [],
                checks=[
                    {
                        "id": "c",
                        "request": {"method": "GET", "path": "/n/1"},
                        "expect": {
                            "owner": {"status": [200], "contains_marker": "owner"},
                            "attacker": {"status": [200, 403]},
                        },
                    }
                ],
            )
            _run(config, f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertTrue(seen)
        self.assertEqual(seen[0].get("cache-control"), "no-cache")
        self.assertEqual(seen[0].get("pragma"), "no-cache")

    @fast("asserts on the declaration, not on a live target")
    def test_a_configured_cache_control_cannot_re_enable_caching(self) -> None:
        """Same rule Accept-Encoding already follows: Veridor owns the header."""
        applied = core._apply_forced_headers(
            {"Cache-Control": "max-age=600", "Pragma": "x", "Accept-Encoding": "gzip"}
        )
        self.assertEqual(applied["Cache-Control"], "no-cache")
        self.assertEqual(applied["Pragma"], "no-cache")
        self.assertEqual(applied["Accept-Encoding"], "identity")

    @fast("asserts on the declaration, not on a live target")
    def test_cache_detection_reads_a_closed_set_of_signals(self) -> None:
        hit = core._served_from_cache
        self.assertTrue(hit([("X-Cache", "HIT")]))
        self.assertTrue(hit([("x-cache", "MISS, HIT")]))
        self.assertTrue(hit([("CF-Cache-Status", "STALE")]))
        self.assertTrue(hit([("Age", "42")]))
        self.assertFalse(hit([("Age", "0")]))
        self.assertFalse(hit([("Age", "not-a-number")]))
        self.assertFalse(hit([("X-Cache", "MISS")]))
        self.assertFalse(hit([("Content-Type", "application/json")]))
        self.assertFalse(hit([]))


# --------------------------------------------------------------------------
# (5) A target-chosen value must never crash the run
# --------------------------------------------------------------------------


class NonAsciiCaptureTest(unittest.TestCase):
    """`http.client` encodes the request line as ASCII and headers as latin-1.

    A non-ASCII captured id used to raise UnicodeEncodeError -- a ValueError,
    and so not in the transport except clause -- from inside the opener. It
    escaped through the CLI, killed the process, and no run document was
    written, so every other check in the config produced no result at all.
    """

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_non_ascii_captured_id_aborts_one_sequence_and_no_more(self) -> None:
        config = _config(
            [
                {
                    "id": "unicode",
                    "steps": [
                        _step("setup", "owner", "POST", "/n", [201],
                              capture={"note": "$.id"}),
                        _step("assert", "attacker", "GET", "/n/${note}", [403],
                              excludes_marker="owner"),
                    ],
                },
                {
                    "id": "survivor",
                    "steps": [
                        _step("assert", "attacker", "GET", "/other", [403],
                              excludes_marker="owner"),
                    ],
                },
            ]
        )

        def responder(method, path, token, body):
            if method == "POST":
                return (
                    201,
                    _JSON,
                    json.dumps({"id": "日本-note"}).encode(),
                )
            return (403, _JSON, _json_body({"error": "denied"}))

        with _server(responder) as url:
            result = _run(config, url)

        # The whole point: a run document exists at all, and the OTHER sequence
        # still produced a result.
        self.assertEqual(len(result["sequences"]), 2)
        self.assertEqual(result["sequences"][0]["abort_reason"], "capture_missed")
        self.assertIsNone(result["sequences"][1]["abort_reason"])
        self.assertEqual(
            result["sequences"][0]["steps"][0]["captures"][0]["reason"],
            "unsafe_value",
        )

    def test_the_extractor_refuses_a_non_ascii_value(self) -> None:
        sink = {
            "headers": [("Content-Type", "application/json")],
            "body": json.dumps({"id": "café"}).encode(),
        }
        value, reason = sequence.resolve_extractor("$.id", sink)
        self.assertIsNone(value)
        self.assertEqual(reason, "unsafe_value")

    def test_a_non_ascii_configured_path_is_a_config_error_not_a_crash(self) -> None:
        with self.assertRaises(core.ConfigError):
            core._validate_request({"path": "/café"}, "check request")

    def test_an_unencodable_header_value_is_a_config_error(self) -> None:
        with self.assertRaises(core.ConfigError):
            core._validate_request(
                {"path": "/x", "headers": {"X-Note": "日本"}}, "check request"
            )

    def test_unicode_error_is_handled_as_a_transport_failure(self) -> None:
        self.assertIn("UnicodeError", core._perform_request.__code__.co_names + tuple())


# --------------------------------------------------------------------------
# (6) An oracle FAILURE is not an observation of absence
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class OracleFailureIsNotAbsenceTest(unittest.TestCase):
    """`unknown` means Veridor could not read the body. `absent` means it read
    the body and the marker was not there. Only the second licenses EFFECT-001.
    """

    @staticmethod
    def _config() -> dict:
        return _config(
            [
                {
                    "id": "delete",
                    "steps": [
                        _step("setup", "owner", "POST", "/n", [201],
                              json={"provenance": "${marker:owner}"},
                              capture={"note": "$.id"}),
                        _step("setup", "owner", "GET", "/n/${note}", [200],
                              contains_marker="owner"),
                        _step("assert", "attacker", "DELETE", "/n/${note}",
                              [403, 404]),
                        _step("assert", "owner", "GET", "/n/${note}", [200],
                              contains_marker="owner"),
                    ],
                }
            ]
        )

    @staticmethod
    def _brotli_on_second_read():
        """A CORRECT api. The row is never deleted; only the advertised
        Content-Encoding changes, exactly as a brotli-enabled edge tier does."""
        reads = {"n": 0}

        def responder(method, path, token, body):
            if method == "POST":
                return (201, _JSON, _json_body({"id": "n1"}))
            if method == "DELETE":
                return (403, _JSON, _json_body({"error": "forbidden"}))
            reads["n"] += 1
            headers = dict(_JSON)
            if reads["n"] >= 2:
                headers["Content-Encoding"] = "br"
            return (200, headers, _json_body({"provenance": MARKER_OWNER}))

        return responder

    def test_an_unreadable_body_is_inconclusive_not_a_confirmed_breach(self) -> None:
        with _server(self._brotli_on_second_read()) as url:
            result = _run(self._config(), url)

        self.assertEqual(_rules(result), ["VERIDOR-ORACLE-001"])
        finding = result["findings"][0]
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(finding["evidence"]["marker"]["state"], "unknown")
        self.assertEqual(
            finding["evidence"]["marker"]["reason"], "encoding_unsupported"
        )

    def test_the_artifact_never_says_absent_while_recording_unknown(self) -> None:
        with _server(self._brotli_on_second_read()) as url:
            result = _run(self._config(), url)
        for finding in result["findings"]:
            if finding["evidence"].get("marker", {}).get("state") == "unknown":
                self.assertNotIn("is absent now", finding["message"])

    def test_a_genuinely_absent_marker_still_reaches_effect_001(self) -> None:
        """The fix must not cost the capability it is protecting."""
        state = {"present": False}

        def responder(method, path, token, body):
            if method == "POST":
                state["present"] = True
                return (201, _JSON, _json_body({"id": "n1"}))
            if method == "DELETE":
                state["present"] = False       # silent cross-tenant delete
                return (403, _JSON, _json_body({"error": "forbidden"}))
            if not state["present"]:
                return (200, _JSON, _json_body({"error": "gone"}))
            return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))

        with _server(responder) as url:
            result = _run(self._config(), url)
        self.assertEqual(_rules(result), ["VERIDOR-EFFECT-001"])
        self.assertEqual(result["findings"][0]["evidence_grade"], "confirmed")


# --------------------------------------------------------------------------
# (7) EFFECT-001 must not blame a write against a different object
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class EffectAttributionTest(unittest.TestCase):
    """"issued <METHOD> against this sequence's object" is a factual claim."""

    def test_an_unrelated_foreign_write_does_not_produce_a_finding(self) -> None:
        config = _config(
            [
                {
                    "id": "unrelated",
                    "steps": [
                        _step("setup", "attacker", "POST", "/notes", [201],
                              json={"title": "the attacker's OWN note"}),
                        _step("assert", "owner", "GET", "/search?q=hello", [200],
                              contains_marker="owner"),
                    ],
                }
            ]
        )

        def responder(method, path, token, body):
            if method == "POST":
                return (201, _JSON, _json_body({"id": "a1"}))
            return (200, _JSON, _json_body({"results": [], "q": "hello"}))

        with _server(responder) as url:
            result = _run(config, url)

        # There is no shared object. The honest answer is ORACLE-001.
        self.assertEqual(_rules(result), ["VERIDOR-ORACLE-001"])
        self.assertEqual(result["findings"][0]["verdict"], "inconclusive")

    def test_a_write_to_the_same_path_is_still_attributed(self) -> None:
        config = _config(
            [
                {
                    "id": "same-object",
                    "steps": [
                        _step("assert", "attacker", "DELETE", "/n/1", [403]),
                        _step("assert", "owner", "GET", "/n/1", [200],
                              contains_marker="owner"),
                    ],
                }
            ]
        )

        def responder(method, path, token, body):
            if method == "DELETE":
                return (403, _JSON, b"{}")
            return (200, _JSON, _json_body({"error": "gone"}))

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(_rules(result), ["VERIDOR-EFFECT-001"])
        self.assertIn(
            "against the same path this step reads", result["findings"][0]["message"]
        )

    @fast("asserts on the declaration, not on a live target")
    def test_the_refusal_status_of_the_write_is_deliberately_not_a_condition(
        self,
    ) -> None:
        """A 403 that deletes the row anyway is the case this rule exists for.

        Requiring a 2xx would silently drop the silent cross-tenant delete --
        the exact scenario a status-only check goes green on.
        """
        source = __import__("inspect").getsource(sequence._SequenceRun._prior_foreign_write)
        self.assertIn("STATUS is deliberately NOT a condition", source)

    def test_a_verifier_on_another_path_cannot_exculpate_a_write(self) -> None:
        config = _config(
            [
                {
                    "id": "split",
                    "steps": [
                        _step("assert", "attacker", "DELETE", "/n/1", [403]),
                        _step("assert", "owner", "GET", "/other", [200],
                              contains_marker="owner"),
                    ],
                }
            ]
        )

        def responder(method, path, token, body):
            if method == "DELETE":
                return (200, _JSON, b"{}")     # fails the declaration
            return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))

        with _server(responder) as url:
            result = _run(config, url)
        authz = [f for f in result["findings"] if f["rule_id"] == "VERIDOR-AUTHZ-001"]
        self.assertEqual(len(authz), 1)
        self.assertNotIn("did not take effect", authz[0]["message"])
        self.assertNotIn("write_effect", authz[0]["evidence"])


# --------------------------------------------------------------------------
# (8) Veridor's own marker, echoed back, is not a leak
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class MarkerReflectionTest(unittest.TestCase):
    """The session model already refuses this. The sequence path did not.

    Load-time validation cannot catch it either: the template holds `${prov}`,
    not the marker literal.
    """

    @staticmethod
    def _config(path: str, **extra) -> dict:
        assert_step = _step(
            "assert", "attacker", "GET", path, [200],
            excludes_marker="owner", **extra
        )
        return _config(
            [
                {
                    "id": "reflect",
                    "steps": [
                        _step("setup", "owner", "POST", "/notes", [201],
                              json={"provenance": "${marker:owner}"},
                              capture={"prov": "$.provenance"}),
                        assert_step,
                    ],
                }
            ]
        )

    @staticmethod
    def _echo_target():
        """A correct target: /search owns no data and simply echoes q back."""

        def responder(method, path, token, body):
            if method == "POST":
                payload = json.loads(body or b"{}")
                return (201, _JSON, _json_body(payload))
            echoed = path.split("q=", 1)[-1] if "q=" in path else ""
            return (200, _JSON, _json_body({"message": f"no results for {echoed}"}))

        return responder

    def test_a_captured_marker_is_never_placed_on_the_wire(self) -> None:
        seen: list[str] = []

        def responder(method, path, token, body):
            seen.append(path)
            return self._echo_target()(method, path, token, body)

        with _server(responder) as url:
            result = _run(self._config("/search?q=${prov}"), url)

        self.assertFalse([p for p in seen if MARKER_OWNER in p])
        self.assertEqual(
            result["sequences"][0]["abort_reason"], "marker_reflection_blocked"
        )
        self.assertEqual({f["verdict"] for f in result["findings"]}, {"inconclusive"})

    def test_the_block_reason_names_the_capture_and_not_the_value(self) -> None:
        with _server(self._echo_target()) as url:
            result = _run(self._config("/search?q=${prov}"), url)
        blob = json.dumps(result)
        self.assertNotIn(MARKER_OWNER, blob)
        self.assertIn("'prov' carries 'owner''s marker", result["findings"][0]["message"])

    def test_the_block_gets_configuration_advice_not_network_advice(self) -> None:
        """Nothing was sent; the step's own message is not the shared unsent
        text, so its remediation used to fall through to "Confirm the target is
        reachable from the runner and retry"."""
        with _server(self._echo_target()) as url:
            result = _run(self._config("/search?q=${prov}"), url)
        blocked = [f for f in result["findings"] if "carries" in f["message"]]
        self.assertEqual(len(blocked), 1)
        self.assertNotIn("reachable", blocked[0]["remediation"])
        self.assertIn("not a network problem", blocked[0]["remediation"])

    def test_a_reflected_marker_in_a_body_is_blocked_too(self) -> None:
        with _server(self._echo_target()) as url:
            result = _run(
                self._config("/search", json={"q": "${prov}"}), url
            )
        self.assertEqual(
            result["sequences"][0]["abort_reason"], "marker_reflection_blocked"
        )

    def test_planting_a_marker_from_the_config_is_still_allowed(self) -> None:
        """`${marker:owner}` is the operator planting. Only captures are suspect."""
        config = _config(
            [
                {
                    "id": "plant",
                    "steps": [
                        _step("setup", "owner", "POST", "/notes", [201],
                              json={"provenance": "${marker:owner}"},
                              capture={"id": "$.id"}),
                        _step("assert", "attacker", "GET", "/notes/${id}", [403],
                              excludes_marker="owner"),
                    ],
                }
            ]
        )

        def responder(method, path, token, body):
            if method == "POST":
                return (201, _JSON, _json_body({"id": "n1"}))
            return (403, _JSON, _json_body({"error": "forbidden"}))

        with _server(responder) as url:
            result = _run(config, url)
        # The step is ISSUED -- planting is how a sequence provisions the
        # victim's object. (The pre-existing control ladder still reports
        # inconclusive because nothing read the planted marker back, which is a
        # different and correct rule.)
        self.assertIsNone(result["sequences"][0]["abort_reason"])
        self.assertEqual(_rules(result), ["VERIDOR-ORACLE-001"])
        self.assertEqual({f["verdict"] for f in result["findings"]}, {"inconclusive"})

    def test_an_encoded_captured_marker_is_never_placed_on_the_wire(self) -> None:
        """The load-time guard decodes every surface; the runtime guard was a
        plain substring test. A capture holding the marker base64-, percent- or
        \\u-encoded went out, a decoding echo endpoint sent the marker back, and
        a correct target was graded VERIDOR-LEAK-001 confirmed."""
        encodings = {
            "urlsafe base64": base64.urlsafe_b64encode(
                json.dumps({"p": MARKER_OWNER}).encode()
            ).decode().rstrip("="),
            "percent": MARKER_OWNER.replace("-", "%2D"),
            "unicode escape": MARKER_OWNER.replace("-", "\\u002d"),
        }
        for label, encoded in encodings.items():
            with self.subTest(label):
                seen: list[str] = []

                def responder(method, path, token, body, encoded=encoded):
                    if method == "POST":
                        return (201, _JSON, _json_body({"cursor": encoded}))
                    seen.append(path)
                    # A correct target: it owns no data and echoes c, decoded.
                    return (200, _JSON, _json_body({"echo": MARKER_OWNER}))

                config = _config(
                    [{
                        "id": "reflect",
                        "steps": [
                            _step("setup", "owner", "POST", "/notes", [201],
                                  json={"provenance": "${marker:owner}"},
                                  capture={"cur": "$.cursor"}),
                            _step("assert", "attacker", "GET", "/search?c=${cur}",
                                  [200], excludes_marker="owner"),
                        ],
                    }]
                )
                with _server(responder) as url:
                    result = _run(config, url)
                self.assertEqual(seen, [])
                self.assertEqual(
                    result["sequences"][0]["abort_reason"], "marker_reflection_blocked"
                )
                self.assertEqual(
                    {f["verdict"] for f in result["findings"]}, {"inconclusive"}
                )

    @fast("asserts on an in-process session; nothing is sent")
    def test_an_encoded_marker_in_a_session_capture_is_blocked(self) -> None:
        """``IdentitySession._substitute`` had the same plain substring test."""
        encoded = base64.b64encode(MARKER_OWNER.encode()).decode()
        identity = {"session": {"inject": [{"header": "X-T", "value": "${capture.t}"}]}}
        for value, blocked in ((encoded, "marker_reflection_blocked"),
                               (MARKER_OWNER.replace("-", "%2d"), "marker_reflection_blocked"),
                               ("plain-token-value", None)):
            with self.subTest(value=value):
                session = sequence.IdentitySession(
                    "victim", identity, "http://127.0.0.1:1", 5, {"owner": MARKER_OWNER}
                )
                session._injecting = True
                session._values["t"] = value
                _, _, reason, _ = session.prepare({}, None, method="GET")
                self.assertEqual(reason, blocked)

    def test_a_capture_past_the_decode_cap_is_refused_not_sent(self) -> None:
        """REGRESSION. The decoded check stops at 256 variants, and it kept
        whichever it met first in set order, which follows the per-process
        string hash. A session capture (up to 4096 bytes) of ~160 hex- or
        base64-shaped tokens passes the cap; a marker hidden in one of them
        was checked in some runs and sent in others (7 of 30 seeds), and a
        decoding echo endpoint turned that into a false confirmed
        VERIDOR-LEAK-001. A value whose decodings were not all checked is now
        refused before anything is sent.

        A sequence capture is held to 512 characters, which no shape tried
        here decodes past 256, so the cap is lowered for this run to reach the
        same branch on the sequence path."""
        from unittest import mock

        for count, expected in ((15, "marker_check_incomplete"), (2, None)):
            with self.subTest(tokens=count):
                seen: list[str] = []
                cursor = _hex_tokens(count)

                def responder(method, path, token, body, cursor=cursor):
                    if method == "POST":
                        return (201, _JSON, _json_body({"cursor": cursor}))
                    seen.append(path)
                    return (200, _JSON, _json_body({"echo": "nothing"}))

                config = _config(
                    [{
                        "id": "reflect",
                        "steps": [
                            _step("setup", "owner", "POST", "/notes", [201],
                                  json={"provenance": "${marker:owner}"},
                                  capture={"cur": "$.cursor"}),
                            _step("assert", "attacker", "GET", "/search?c=${cur}",
                                  [200], excludes_marker="owner"),
                        ],
                    }]
                )
                with mock.patch.object(core, "_MAX_DECODE_VARIANTS", 16):
                    with _server(responder) as url:
                        result = _run(config, url)
                sequence_result = result["sequences"][0]
                self.assertEqual(sequence_result["abort_reason"], expected)
                if expected is None:
                    # Control: a short capture is checked whole and sent.
                    self.assertEqual(len(seen), 1)
                    continue
                self.assertEqual(seen, [])
                self.assertEqual({f["verdict"] for f in result["findings"]}, {"inconclusive"})
                error = sequence_result["steps"][1]["error"]
                self.assertIn("capture 'cur'", error)
                self.assertIn("could not be checked", error)
                self.assertIn("this step was not issued", error)
                self.assertNotIn(cursor[:24], json.dumps(result))

    @fast("decodes values in-process; nothing is sent")
    def test_the_decoded_marker_check_never_passes_a_value_it_did_not_finish(self) -> None:
        """``_marker_owner`` answers an owner, or refuses; it no longer
        answers "no marker" for a value whose decodings it stopped short of."""
        markers = {"owner": MARKER_OWNER}
        hidden = base64.b64encode(MARKER_OWNER.encode()).decode()
        crowded = _hex_tokens(160)
        try:
            self.assertEqual(
                sequence._marker_owner(crowded + "," + hidden, markers), "owner")
        except sequence._MarkerUncheckable:
            pass
        with self.assertRaises(sequence._MarkerUncheckable):
            sequence._marker_owner(crowded, markers)
        # A plain marker is still found by the raw test, cap or no cap.
        self.assertEqual(sequence._marker_owner(crowded + "," + MARKER_OWNER, markers), "owner")
        # Controls: a short value is checked whole, either way.
        self.assertEqual(sequence._marker_owner(hidden, markers), "owner")
        self.assertIsNone(sequence._marker_owner(_hex_tokens(3), markers))

    @fast("asserts on an in-process session; nothing is sent")
    def test_a_session_capture_past_the_decode_cap_is_blocked(self) -> None:
        identity = {"session": {"inject": [{"header": "X-T", "value": "${capture.t}"}]}}
        for value, blocked in ((_hex_tokens(150), "marker_check_incomplete"),
                               (_hex_tokens(3), None)):
            with self.subTest(blocked=blocked):
                session = sequence.IdentitySession(
                    "victim", identity, "http://127.0.0.1:1", 5, {"owner": MARKER_OWNER}
                )
                session._injecting = True
                session._values["t"] = value
                _, _, reason, _ = session.prepare({}, None, method="GET")
                self.assertEqual(reason, blocked)
        self.assertIn("marker_check_incomplete", core.UNSENT_REASONS)

    def test_the_decoded_variants_are_the_same_in_every_process(self) -> None:
        """Which 256 variants were kept followed the string hash, so the same
        capture was checked differently from one process to the next. The
        variants kept for a value past the cap are now a function of the value
        alone: identical under every PYTHONHASHSEED."""
        import os
        import subprocess

        src = str(Path(core.__file__).resolve().parents[1])
        program = (
            "import sys, hashlib; sys.path.insert(0, sys.argv[1]); "
            "from veridor import core; "
            "v = core._decode_variants(sys.argv[2]); "
            "print(len(v), hashlib.sha256('\\n'.join(sorted(v)).encode()).hexdigest())"
        )
        value = _hex_tokens(160) + "," + base64.b64encode(MARKER_OWNER.encode()).decode()
        answers = set()
        for seed in range(6):
            done = subprocess.run(
                [sys.executable, "-I", "-c", program, src, value],
                env={**os.environ, "PYTHONHASHSEED": str(seed)},
                capture_output=True, text=True, timeout=60, check=True,
            )
            answers.add(done.stdout.strip())
        self.assertEqual(len(answers), 1, answers)
        self.assertTrue(next(iter(answers)).startswith("256 "), answers)

    @fast("loads configurations; nothing is sent")
    def test_a_request_past_the_decode_cap_is_refused_at_load(self) -> None:
        """REGRESSION. Only the send-time check refused at the decode cap. The
        load-time checks (``core._validate_markers_absent_from_requests`` and
        the sequence load check) read an incomplete decode as "no marker", so
        a check, sequence step or session inject whose value decoded past 256
        variants loaded, with a marker in a variant nobody read (reproduced:
        the same marker alone is refused). Each is refused now, exit 2
        at load, naming the request."""
        # Base64 of a plaintext that sorts after every hex token's decoding,
        # so the sorted walk drops it at the cap; alone, it is found.
        hidden = base64.b64encode(("\U0010fffd" + MARKER_OWNER).encode()).decode()
        crowded = _hex_tokens(160)
        check_request = {"id": "c1", "request": {"method": "POST", "path": "/n"},
                         "expect": {"owner": {"status": [200]},
                                    "attacker": {"status": [403]}}}

        def with_check(value: str) -> dict:
            check = json.loads(json.dumps(check_request))
            check["request"]["json"] = {"q": value}
            return _config([], checks=[check])

        def with_step(value: str) -> dict:
            return _config(
                [{"id": "s", "steps": [
                    _step("setup", "owner", "POST", "/notes", [201], json={"q": value})]}],
                checks=[check_request])

        def with_inject(value: str) -> dict:
            config = _config([], checks=[check_request])
            config["identities"]["owner"]["session"] = {
                "login": [{"method": "POST", "path": "/login", "expect_status": [200],
                           "capture": {"t": {"from": "json_pointer", "pointer": "/t"}}}],
                "establishes": {"capture": "t"},
                "inject": [{"header": "X-Q", "value": value}],
            }
            return config

        for label, make, where in (
            ("check", with_check, "the request sent by check 'c1'"),
            ("sequence step", with_step, "the request sent by sequence 's' step 0"),
            ("session inject", with_inject, "identity 'owner' session inject 0"),
        ):
            with self.subTest(label):
                # Control: the hidden marker alone is found, so the cases below
                # are not refused for a reason the decode cap has nothing to do with.
                with self.assertRaisesRegex(core.ConfigError, "marker appears in"):
                    _load(make(hidden))
                for value in (crowded + "," + hidden, crowded):
                    with self.assertRaises(core.ConfigError) as caught:
                        _load(make(value))
                    message = str(caught.exception)
                    self.assertIn(where, message)
                    self.assertIn("could not be checked for a configured marker", message)
                # Control: a short value is checked whole and loads.
                _load(make(_hex_tokens(3)))

    @fast("loads a configuration; nothing is sent")
    def test_a_value_longer_than_the_surface_bound_is_refused_at_load(self) -> None:
        """The decode reads a 64 KiB prefix of each value, so the rest of a
        longer one was never read; that is an unfinished check as well."""
        config = _config([], checks=[{
            "id": "big", "request": {"method": "POST", "path": "/n",
                                     "json": {"q": "a" * (core._MAX_SURFACE_CHARS + 1)}},
            "expect": {"owner": {"status": [200]}, "attacker": {"status": [403]}}}])
        with self.assertRaisesRegex(core.ConfigError,
                                    "the request sent by check 'big' could not be checked"):
            _load(config)
        # Control: the same value inside the bound loads.
        config["checks"][0]["request"]["json"]["q"] = "a" * 1024
        _load(config)


def _hex_tokens(count: int) -> str:
    """``count`` comma-separated 24-character hex tokens, the same every run:
    each is also base64-shaped, so each yields more than one decoding."""
    import random

    rng = random.Random(1234)
    return ",".join("%024x" % rng.getrandbits(96) for _ in range(count))


# --------------------------------------------------------------------------
# A denial-only assert step proves nothing about a credential nobody tested
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class SequenceStepLivenessTest(unittest.TestCase):
    """An expired static token passed every denial-only assert step.

    Liveness planning read only `checks`, and a sequence step's own degraded
    rule covers session identities only. A static-header identity whose token
    the target rejects with 401 matched `[401, 403, 404]` on every assert
    step, and the run exited 0 under --require-complete with nothing unproven
    -- identical output to a target that really refused a valid token with
    403. The same declaration written as a check exited 3. No fabricated
    credential is sent inside a sequence; such a denial now counts as unproven
    unless the identity is proven live elsewhere, when some identity was
    served in that sequence.
    """

    EXPIRED = "Bearer attacker-EXPIRED"

    def _config(self, *, checks=None, steps=None) -> dict:
        config = _config(
            [
                {
                    "id": "del-seq",
                    "steps": steps or [
                        _step("setup", "owner", "POST", "/docs", [201],
                              json={"t": "x"}, capture={"doc": "$.id"}),
                        _step("assert", "attacker", "DELETE", "/docs/${doc}",
                              [401, 403, 404]),
                        _step("assert", "attacker", "GET", "/docs/${doc}",
                              [401, 403, 404]),
                    ],
                    "teardown": [
                        {"as": "owner",
                         "request": {"method": "DELETE", "path": "/docs/${doc}"},
                         "expect": {"status": [204]}},
                    ],
                }
            ],
            checks=checks,
            marker=False,
        )
        config["identities"]["attacker"]["headers"]["Authorization"] = self.EXPIRED
        return config

    @staticmethod
    def _responder(seen: list):
        def responder(method, path, token, body):
            seen.append((method, path, token))
            if path == "/mine" and token:
                # Serves anyone who sends a token: a stand-in for a target
                # that recognises this one somewhere else.
                return (200, _JSON, b"{}")
            if token != OWNER_TOKEN:
                return (401, _JSON, b"{}")
            if method == "POST":
                return (201, _JSON, _json_body({"id": "1"}))
            if method == "DELETE":
                return (204, {}, b"")
            return (200, _JSON, b"{}")
        return responder

    def _cli(self, config: dict, *flags: str):
        import contextlib
        import io
        import tempfile
        from veridor.cli import main as veridor_main

        seen: list = []
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                _server(self._responder(seen)) as url:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            out = Path(directory) / "run.json"
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main([
                    "run", "--config", str(path), "--base-url", url,
                    "--output-dir", str(Path(directory) / "out"),
                    "--json", str(out), *flags,
                ])
            result = json.loads(out.read_text(encoding="utf-8"))
        return code, result, stdout.getvalue(), stderr.getvalue(), seen

    def test_an_expired_static_token_on_assert_steps_is_unproven(self) -> None:
        code, result, stdout, stderr, seen = self._cli(
            self._config(), "--require-complete")
        self.assertEqual([entry for entry in seen if "veridor-sham-" in entry[2]], [],
                         "no fabricated credential is sent inside a sequence")
        unproven = result["liveness"]["unproven"]
        self.assertEqual(
            [(entry["identity"], entry.get("control"), entry.get("sequence_id"),
              entry.get("step_index")) for entry in unproven],
            [("attacker", "withheld_sequence_step", "del-seq", 1),
             ("attacker", "withheld_sequence_step", "del-seq", 2)],
        )
        self.assertIn("sequence", unproven[0]["statement"])
        self.assertEqual(
            sorted((entry["method"], entry["path"], entry["reason"])
                   for entry in result["liveness"]["requests_not_probed"]),
            [("DELETE", "/docs/${doc}", "sequence_step"),
             ("GET", "/docs/${doc}", "sequence_step")],
        )
        self.assertEqual(code, 3)
        self.assertIn("liveness_unproven",
                      [reason["code"] for reason in result["gate"]["reasons"]])
        self.assertIn("2 sequence assert step(s) accept only denial statuses", stderr)
        self.assertIn("Unproven denials", stdout)

    def test_without_require_complete_it_is_disclosed_not_gated(self) -> None:
        code, result, _, _, _ = self._cli(self._config())
        self.assertEqual(len(result["liveness"]["unproven"]), 2)
        self.assertEqual(code, 0)

    def test_a_route_that_serves_any_credential_proves_nothing(self) -> None:
        """A 2xx proves a credential live only where somebody was refused.

        This test used to be the control below, with this responder: `/mine`
        serves any caller that sends a token, and the attacker's expired one
        drawing a 200 there was taken as proof its token was live. Every
        denial the sequence made of it then left `liveness.unproven`, and the
        run exited 0 under --require-complete. A fabricated credential sent
        to `/mine` is served too, so that 2xx tells a live token from a dead
        one no better than the denials do.
        """
        checks = [{
            "id": "mine",
            "request": {"method": "GET", "path": "/mine"},
            "expect": {"attacker": {"status": [200]}, "owner": {"status": [200]}},
        }]
        code, result, _, _, seen = self._cli(
            self._config(checks=checks), "--require-complete")
        self.assertEqual(
            [entry[1] for entry in seen if "veridor-sham-" in entry[2]], ["/mine"],
            "the 2xx is tested against a credential nobody issued",
        )
        self.assertEqual(
            [(entry["identity"], entry.get("step_index"))
             for entry in result["liveness"]["unproven"]],
            [("attacker", 1), ("attacker", 2)],
        )
        self.assertEqual(code, 3)

    def test_an_identity_served_where_a_sham_is_refused_is_proven_live(self) -> None:
        """The control: a route that refuses a credential nobody issued."""
        checks = [{
            "id": "mine",
            "request": {"method": "GET", "path": "/mine"},
            "expect": {"attacker": {"status": [200]}, "owner": {"status": [200]}},
        }]

        def responder(seen: list):
            inner = type(self)._responder(seen)

            def answer(method, path, token, body):
                if path == "/mine":
                    seen.append((method, path, token))
                    # Recognises the attacker's token here, and nobody else's.
                    return ((200, _JSON, b"{}")
                            if token in (OWNER_TOKEN, self.EXPIRED)
                            else (401, _JSON, b"{}"))
                return inner(method, path, token, body)
            return answer

        with patch.object(self, "_responder", responder):
            code, result, _, _, _ = self._cli(
                self._config(checks=checks), "--require-complete")
        self.assertEqual(result["liveness"]["unproven"], [])
        self.assertEqual(code, 0)

    def _anonymous_mine_config(self, *, anonymous_step: bool) -> dict:
        steps = [
            _step("setup", "owner", "POST", "/docs", [201],
                  json={"t": "x"}, capture={"doc": "$.id"}),
            _step("assert", "attacker", "DELETE", "/docs/${doc}", [401, 403, 404]),
            _step("assert", "attacker", "GET", "/mine", [200]),
        ]
        if anonymous_step:
            steps.append(_step("assert", "anon", "GET", "/mine", [401]))
        config = self._config(steps=steps)
        config["identities"]["anon"] = {"headers": {"Accept": "application/json"}}
        return config

    def test_a_sequence_step_served_where_nobody_is_refused_proves_nothing(
        self,
    ) -> None:
        """The sequence path: no sham rides a step, so a 2xx there needs a refusal.

        The attacker's expired token is served on `/mine`, which serves any
        token. Nothing on that request was refused, so it proved the
        attacker live and the DELETE denial left `liveness.unproven`.
        """
        code, result, _, _, _ = self._cli(
            self._anonymous_mine_config(anonymous_step=False), "--require-complete")
        self.assertEqual(
            [(entry["identity"], entry.get("step_index"))
             for entry in result["liveness"]["unproven"]],
            [("attacker", 1)],
        )
        self.assertEqual(code, 3)

    def test_a_sequence_step_served_where_an_anonymous_caller_is_refused_proves_it(
        self,
    ) -> None:
        """The control: the same request refused an identity with no credential."""
        code, result, _, _, _ = self._cli(
            self._anonymous_mine_config(anonymous_step=True), "--require-complete")
        self.assertEqual(result["liveness"]["unproven"], [])
        self.assertEqual(code, 0)

    def test_a_sequence_where_nobody_was_served_is_not_judged(self) -> None:
        """The same precondition checks have: "nobody may have this"."""
        config = self._config(
            steps=[_step("assert", "attacker", "GET", "/docs/1", [401, 403, 404])])
        del config["sequences"][0]["teardown"]
        code, result, _, _, _ = self._cli(config, "--require-complete")
        self.assertEqual(result["sequences"][0]["steps"][0]["state"], "matched")
        self.assertEqual(result["liveness"]["unproven"], [])


def _shape_base() -> dict:
    """A minimal valid v2 configuration. Every shape mutates a fresh copy."""
    return {
        "version": 2,
        "target": {"base_url": "http://127.0.0.1:9"},
        "identities": {"a": {"headers": {"X": "1"}}, "b": {"headers": {"X": "2"}}},
        "checks": [
            {
                "id": "c",
                "request": {"method": "GET", "path": "/x"},
                "expect": {"a": {"status": [200]}, "b": {"status": [403]}},
            }
        ],
    }


def _shape_sequence(config: dict, steps: list, teardown: list | None = None) -> None:
    sequence: dict = {"id": "s", "steps": steps}
    if teardown is not None:
        sequence["teardown"] = teardown
    config["sequences"] = [sequence]


# Step interpolation is ``${name}``. The session form is ``${capture.name}``.
# They are not interchangeable and the loader refuses the wrong one.


def _capture_then_use(config: dict) -> None:
    """A value captured from one response and used in a later step."""
    _shape_sequence(config, [
        _step("setup", "a", "POST", "/items", [201], capture={"itemId": "$.id"}),
        _step("assert", "b", "GET", "/items/${itemId}", [403]),
    ])


def _captured_credential(config: dict) -> None:
    """A credential captured from one response, sent on a later request."""
    assertion = _step("assert", "b", "GET", "/me", [403])
    assertion["request"]["headers"] = {"Authorization": "Bearer ${tok}"}
    _shape_sequence(config, [
        _step("setup", "a", "POST", "/token", [201], capture={"tok": "$.token"}),
        assertion,
    ])


def _session_cookie_jar(config: dict) -> None:
    """An identity that logs in and keeps a session cookie."""
    config["identities"]["a"]["session"] = {
        "login": [{"method": "POST", "path": "/login", "expect_status": [302]}],
        "establishes": {"cookie": "sid"},
    }


def _session_csrf(config: dict) -> None:
    """A session-bound CSRF token minted by a preceding request.

    Captured on the login step and applied by ``inject``. CSRF is deliberately
    NOT a key of ``establishes``, which names only the cookie or capture that
    proves login succeeded.
    """
    config["identities"]["a"]["session"] = {
        "login": [{
            "method": "GET",
            "path": "/login",
            "expect_status": [200],
            "capture": {"csrf": {"from": "html_meta", "name": "csrf-token"}},
        }],
        "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
        "establishes": {"capture": "csrf"},
    }


def _fixture_with_teardown(config: dict) -> None:
    """Fixture provisioning with teardown, for a destructive check."""
    _shape_sequence(
        config,
        [
            _step("setup", "a", "POST", "/objects", [201], capture={"oid": "$.id"}),
            _step("assert", "b", "DELETE", "/objects/${oid}", [403]),
        ],
        [{"as": "a", "request": {"method": "DELETE", "path": "/objects/${oid}"}}],
    )


def _bad_capture(config: dict) -> None:
    _capture_then_use(config)
    config["sequences"][0]["steps"][1]["request"]["path"] = "/items/${neverDeclared}"


def _bad_credential(config: dict) -> None:
    _captured_credential(config)
    config["sequences"][0]["steps"][1]["request"]["headers"]["Authorization"] = (
        "Bearer ${neverDeclared}"
    )


def _bad_cookie_jar(config: dict) -> None:
    _session_cookie_jar(config)
    # `login` is a list of requests, not a single request.
    config["identities"]["a"]["session"]["login"] = {"method": "POST", "path": "/login"}


def _bad_csrf(config: dict) -> None:
    _session_csrf(config)
    # `from` must name an extractor source the loader knows.
    config["identities"]["a"]["session"]["login"][0]["capture"]["csrf"]["from"] = "telepathy"


def _bad_teardown(config: dict) -> None:
    _fixture_with_teardown(config)
    config["sequences"][0]["teardown"][0]["request"]["path"] = "/objects/${neverDeclared}"


class MultiStepConfigShapeTest(unittest.TestCase):
    """The five config shapes an authorization check needs when one request is
    not enough: response-value capture, a captured credential reused as a
    credential, a session cookie jar, a session-bound CSRF token, and fixture
    provisioning with reset.

    Each is probed twice: a well-formed configuration the loader must ACCEPT and
    a malformed twin it must REFUSE. The twin is the proof. ``load_config``
    validates but returns the document unchanged, so "did not raise" is far too
    weak a signal alone -- verified by mutation: deleting ``session`` from the
    identity schema left an acceptance-only probe green, because unrecognised
    keys are carried straight through.

    This is a claim about the schema, not about any target: only standing a
    target up settles whether it can be driven this way.
    """

    SHAPES = {
        "response_value_capture": (_capture_then_use, _bad_capture),
        "captured_credential": (_captured_credential, _bad_credential),
        "session_cookie_jar": (_session_cookie_jar, _bad_cookie_jar),
        "session_bound_csrf": (_session_csrf, _bad_csrf),
        "fixture_provision_reset": (_fixture_with_teardown, _bad_teardown),
    }

    def _refusal(self, mutate) -> str | None:
        """The loader's refusal of this shape, or None when it loads."""
        import tempfile  # noqa: PLC0415

        config = _shape_base()
        mutate(config)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            try:
                core.load_config(path, None)
            except core.ConfigError as error:
                return str(error)
        return None

    def test_every_shape_still_loads(self) -> None:
        for name, (well_formed, _) in self.SHAPES.items():
            with self.subTest(shape=name):
                self.assertIsNone(self._refusal(well_formed))

    def test_every_malformed_twin_is_refused(self) -> None:
        for name, (_, malformed) in self.SHAPES.items():
            with self.subTest(shape=name):
                self.assertIsNotNone(self._refusal(malformed),
                                     "the validator is not checking this shape")

    def test_no_shape_was_quietly_lost(self) -> None:
        """A table that lost a case would pass while proving less."""
        self.assertEqual(
            set(self.SHAPES),
            {
                "response_value_capture",
                "captured_credential",
                "session_cookie_jar",
                "session_bound_csrf",
                "fixture_provision_reset",
            },
        )


if __name__ == "__main__":
    unittest.main()
