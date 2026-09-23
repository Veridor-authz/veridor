"""Sequence engine: interpolation, capture, failure propagation, fingerprints.

Every test here defends one of the design contract's correctness rules. The
ones that matter most, in order:

* ``FingerprintStabilityTest`` -- a config with no steps must produce ids
  byte-identical to the pre-sequence implementation, or every user's baseline
  breaks. The golden table is frozen and must never be edited.
* ``FailurePropagationTest`` -- a sequence that could not establish its own
  preconditions reports inconclusive at every step position. Never safe, never
  vulnerable.
* ``CaptureConfidentialityTest`` -- a captured value must not appear in the run
  JSON, in SARIF, or in any error string. Asserted by scanning the produced
  artifacts for the literal value, not by reading the code.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import json
import sys
import tempfile
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
from veridor.core import ConfigError, execute_run, load_config, to_sarif  # noqa: E402

MARKER_OWNER = "vdr-Nq4Zt8Wm3Kx7Bv2Ld6Rj9Ph5"
MARKER_OTHER = "vdr-Ac7Fg2Hj5Kl8Mn1Qs4Tv6Wy0"

OWNER_TOKEN = "Bearer owner-token"
ATTACKER_TOKEN = "Bearer attacker-token"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _server(responder):
    """Run a loopback server. ``responder(method, path, token, body)``.

    Returns ``(status, headers, body_bytes)``, or ``None`` to drop the
    connection, which is how the transport-failure paths are exercised.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            payload = self.rfile.read(length) if length else b""
            reply = responder(
                self.command,
                self.path,
                self.headers.get("Authorization", ""),
                payload,
            )
            if reply is None:
                self.close_connection = True
                return
            status, headers, body = reply
            self.send_response(status)
            for name, value in headers.items():
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

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(server)
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _json_body(value) -> bytes:
    return json.dumps(value).encode()


_JSON = {"Content-Type": "application/json"}


def _identities(*, marker: bool = True) -> dict:
    owner = {"headers": {"Authorization": OWNER_TOKEN}}
    attacker = {"headers": {"Authorization": ATTACKER_TOKEN}}
    if marker:
        owner["marker"] = MARKER_OWNER
        attacker["marker"] = MARKER_OTHER
    return {"owner": owner, "attacker": attacker}


def _config(sequences, *, checks=None, marker: bool = True) -> dict:
    return {
        "version": 2,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 5},
        "identities": _identities(marker=marker),
        "checks": checks if checks is not None else [],
        "sequences": sequences,
    }


def _load(config: dict, base_url: str | None = None) -> dict:
    """Write ``config`` to disk and load it, so the env pre-pass really runs."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return load_config(path, base_url)


def _run(config: dict, base_url: str, *, output: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return execute_run(
            path, output_dir=output or Path(directory) / "out", base_url=base_url
        )


def _verdicts(result: dict) -> set[str]:
    return {finding["verdict"] for finding in result["findings"]}


def _rules(result: dict) -> list[str]:
    return [finding["rule_id"] for finding in result["findings"]]


def _step(role: str, identity: str, method: str, path: str, statuses, **extra) -> dict:
    step = {
        "role": role,
        "as": identity,
        "request": {"method": method, "path": path},
        "expect": {"status": statuses},
    }
    for key in ("contains_marker", "excludes_marker"):
        if key in extra:
            step["expect"][key] = extra.pop(key)
    if "json" in extra:
        step["request"]["json"] = extra.pop("json")
    step.update(extra)
    return step


# --------------------------------------------------------------------------
# (1) Fingerprints -- the load-bearing regression test for invariant 3
# --------------------------------------------------------------------------

#: Every 20-hex finding id produced by every committed config fixture, frozen
#: as literals. Captured from the implementation BEFORE any sequence code
#: existed. If a change to Veridor makes one of these move, every user's
#: baseline is invalidated and every finding in their suite reports as new. This
#: table must not be edited -- not in this PR, not in any later one.
GOLDEN_FINDING_IDS: dict[str, str] = {
    "veridor.demo.json|audit-admin-role|administrator|execution": "c7a4cc434ef4bf11aa55",
    "veridor.demo.json|audit-admin-role|administrator|marker": "69cc1bc58a2f8e33123b",
    "veridor.demo.json|audit-admin-role|administrator|oracle": "14b662fc5b376ba6b0ea",
    "veridor.demo.json|audit-admin-role|administrator|status": "bb541e68e3bddb168d87",
    "veridor.demo.json|audit-admin-role|invoice_owner|execution": "e28c511b0eda8d05ebf4",
    "veridor.demo.json|audit-admin-role|invoice_owner|marker": "3bc10fe59d22f37a24e6",
    "veridor.demo.json|audit-admin-role|invoice_owner|oracle": "257cca3659f95a33701f",
    "veridor.demo.json|audit-admin-role|invoice_owner|status": "f5d732076091ce56c184",
    "veridor.demo.json|audit-admin-role|other_tenant|execution": "48b3ea492548b65e259d",
    "veridor.demo.json|audit-admin-role|other_tenant|marker": "48cf0a4818d822b6e1be",
    "veridor.demo.json|audit-admin-role|other_tenant|oracle": "6abb002d1967dff8e2e8",
    "veridor.demo.json|audit-admin-role|other_tenant|status": "9c104f7de81d73117534",
    "veridor.demo.json|invoice-tenant-isolation|anonymous|execution": "18dd13f161df501b331f",
    "veridor.demo.json|invoice-tenant-isolation|anonymous|marker": "afcfd55c708f334ded11",
    "veridor.demo.json|invoice-tenant-isolation|anonymous|oracle": "a43deb840611548c5b83",
    "veridor.demo.json|invoice-tenant-isolation|anonymous|status": "b0bd8929b1d3c91fbe6d",
    "veridor.demo.json|invoice-tenant-isolation|invoice_owner|execution": "024684314b7e5b79f7a3",
    "veridor.demo.json|invoice-tenant-isolation|invoice_owner|marker": "3fb3fedf10899386d6f1",
    "veridor.demo.json|invoice-tenant-isolation|invoice_owner|oracle": "7dc5df758e10f202cfd7",
    "veridor.demo.json|invoice-tenant-isolation|invoice_owner|status": "d387fd57930c9b0417c2",
    "veridor.demo.json|invoice-tenant-isolation|other_tenant|execution": "dd1f4540a02c694fc62c",
    "veridor.demo.json|invoice-tenant-isolation|other_tenant|marker": "adeafb773a0e3db5ec0d",
    "veridor.demo.json|invoice-tenant-isolation|other_tenant|oracle": "b750a54b729ce3041df9",
    "veridor.demo.json|invoice-tenant-isolation|other_tenant|status": "0ec4c5cbd79deaed6e9f",
    "veridor.fleet.json|fleet-device-a-artifact|device_a|execution": "c22d45bca871287fc3b1",
    "veridor.fleet.json|fleet-device-a-artifact|device_a|marker": "3aeb1d838c6004d30f9f",
    "veridor.fleet.json|fleet-device-a-artifact|device_a|oracle": "cb207fcf03784b1e5858",
    "veridor.fleet.json|fleet-device-a-artifact|device_a|status": "2d43f23d8a902273a2f7",
    "veridor.fleet.json|fleet-device-a-artifact|device_b|execution": "2151f23842e5ea750b74",
    "veridor.fleet.json|fleet-device-a-artifact|device_b|marker": "e61218cd6237ffddbdbf",
    "veridor.fleet.json|fleet-device-a-artifact|device_b|oracle": "611f2308cc018915cdda",
    "veridor.fleet.json|fleet-device-a-artifact|device_b|status": "3af10467aa7c2be9bcb8",
    "veridor.fleet.json|fleet-device-b-artifact|anonymous|execution": "1bcf395817664df07553",
    "veridor.fleet.json|fleet-device-b-artifact|anonymous|marker": "ed098b92b51b8af2c5d0",
    "veridor.fleet.json|fleet-device-b-artifact|anonymous|oracle": "528fb90a75d009817f6d",
    "veridor.fleet.json|fleet-device-b-artifact|anonymous|status": "0af2d4ef878364df4925",
    "veridor.fleet.json|fleet-device-b-artifact|device_b|execution": "919ce382731c09cd02cd",
    "veridor.fleet.json|fleet-device-b-artifact|device_b|marker": "d462e3aa9976bf2e4a07",
    "veridor.fleet.json|fleet-device-b-artifact|device_b|oracle": "1a81f814d2ce11a79344",
    "veridor.fleet.json|fleet-device-b-artifact|device_b|status": "0a7a7736efc71f4d7dfa",
}

#: ``_finding_id``'s contract is "this never changes", which is unusual enough
#: to be worth asserting on the source text itself. A refactor that preserves
#: behaviour still has to come here and think about invariant 3 before it can
#: land.
FINDING_ID_SOURCE_SHA256 = (
    "6811fee542022f292cb4eef6fb0823c257a8c9a66b46a7f728330c6abade3ff2"
)


class FingerprintStabilityTest(unittest.TestCase):
    def test_every_fixture_finding_id_matches_the_frozen_table(self) -> None:
        produced: dict[str, str] = {}
        for name in ("veridor.demo.json", "veridor.fleet.json"):
            config = json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))
            for check in config["checks"]:
                for identity, expectation in check["expect"].items():
                    statuses = expectation["status"]
                    statuses = [statuses] if isinstance(statuses, int) else statuses
                    for kind in ("status", "marker", "oracle", "execution"):
                        key = f"{name}|{check['id']}|{identity}|{kind}"
                        produced[key] = core._finding_id(
                            check, identity, kind, statuses
                        )
        self.assertEqual(produced, GOLDEN_FINDING_IDS)

    def test_finding_id_source_is_unchanged(self) -> None:
        self.assertEqual(
            hashlib.sha256(
                inspect.getsource(core._finding_id).encode()
            ).hexdigest(),
            FINDING_ID_SOURCE_SHA256,
        )

    def test_finding_id_has_no_step_index_channel(self) -> None:
        """Structural half of the disjointness argument."""
        self.assertNotIn("step_index", inspect.getsource(core._finding_id))

    def test_a_step_id_differs_from_an_identical_check_id(self) -> None:
        check = {
            "id": "X",
            "request": {"method": "DELETE", "path": "/api/invoices/${invoice_id}"},
        }
        step = {
            "as": "attacker",
            "request": {"method": "DELETE", "path": "/api/invoices/${invoice_id}"},
            "expect": {"status": [403, 404]},
        }
        self.assertNotEqual(
            core._finding_id(check, "attacker", "status", [403, 404]),
            sequence.step_finding_id("X", step, 0, "status"),
        )

    def test_step_ids_are_distinct_per_index_and_per_kind(self) -> None:
        step = {
            "as": "owner",
            "request": {"method": "GET", "path": "/a"},
            "expect": {"status": [200]},
        }
        ids = {
            (index, kind): sequence.step_finding_id("S", step, index, kind)
            for index in range(3)
            for kind in ("status", "marker", "oracle", "execution", "sequence", "effect")
        }
        self.assertEqual(len(set(ids.values())), len(ids))

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_config_without_sequences_produces_todays_document(self) -> None:
        """Invariant 4: no `sequences` key means no new key anywhere."""
        config = {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:1"},
            "identities": _identities(marker=False),
            "checks": [
                {
                    "id": "c",
                    "request": {"method": "GET", "path": "/a"},
                    "expect": {"owner": {"status": [200]}, "attacker": {"status": [404]}},
                }
            ],
        }
        with _server(lambda *_: (200, _JSON, b"{}")) as url:
            result = _run(config, url)
        self.assertEqual(result["schema_version"], 2)
        self.assertNotIn("sequences", result)
        self.assertNotIn("sequences", result["summary"])
        self.assertNotIn("sequence_steps", result["summary"])
        self.assertEqual(result["summary"]["safe"], 1)


@slow("stands up a loopback HTTP server and runs the engine against it")
class RunStabilityTest(unittest.TestCase):
    """Two runs, different resolved ids, byte-identical fingerprints and URLs."""

    def _config(self) -> dict:
        return _config(
            [
                {
                    "id": "seq",
                    "steps": [
                        _step("setup", "owner", "POST", "/things", [201],
                              json={"name": "vd-${run_id}-thing"},
                              capture={"thing_id": "$.id"}),
                        _step("assert", "attacker", "GET", "/things/${thing_id}", [403]),
                    ],
                }
            ],
            marker=False,
        )

    def test_ids_and_urls_are_identical_across_runs(self) -> None:
        counter = {"n": 0}

        def responder(method, path, token, body):
            if method == "POST":
                counter["n"] += 1
                return (201, _JSON, _json_body({"id": f"id-{counter['n']:08d}"}))
            return (200, _JSON, b"{}")

        with _server(responder) as url:
            first = _run(self._config(), url)
            second = _run(self._config(), url)
        self.assertEqual(
            [finding["id"] for finding in first["findings"]],
            [finding["id"] for finding in second["findings"]],
        )
        self.assertEqual(
            [step["request"]["url"] for step in first["sequences"][0]["steps"]],
            [step["request"]["url"] for step in second["sequences"][0]["steps"]],
        )
        self.assertIn(
            "${thing_id}", second["sequences"][0]["steps"][1]["request"]["url"]
        )
        self.assertNotIn(
            "${run_id}", json.dumps(second["sequences"][0]["steps"][1])
        )


# --------------------------------------------------------------------------
# (2) Failure propagation
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class FailurePropagationTest(unittest.TestCase):
    def _ladder(self, fail_at: int, total: int = 4) -> dict:
        steps = [
            _step(
                "setup" if index <= fail_at else "assert",
                "owner" if index % 2 == 0 else "attacker",
                "GET",
                f"/s{index}",
                [200],
            )
            for index in range(total)
        ]
        return _config([{"id": "ladder", "steps": steps}], marker=False)

    def test_a_setup_failure_is_inconclusive_at_every_position(self) -> None:
        for fail_at in range(4):
            with self.subTest(fail_at=fail_at):

                def responder(method, path, token, body, fail_at=fail_at):
                    if path == f"/s{fail_at}":
                        return (500, _JSON, b"{}")
                    return (200, _JSON, b"{}")

                with _server(responder) as url:
                    result = _run(self._ladder(fail_at), url)
                record = result["sequences"][0]
                self.assertEqual(record["outcome"], "aborted")
                self.assertEqual(record["aborted_at_step"], fail_at)
                self.assertEqual(record["abort_reason"], "setup_failed")
                self.assertIn("VERIDOR-SEQ-001", _rules(result))
                self.assertEqual(_verdicts(result), {"inconclusive"})
                self.assertNotIn("vulnerable", _verdicts(result))
                self.assertEqual(result["summary"]["sequences_aborted"], 1)
                # Never safe: the un-run steps are recorded as skipped, not as
                # passing, and they add nothing to summary.safe.
                self.assertEqual(
                    [step["state"] for step in record["steps"][fail_at + 1 :]],
                    ["skipped"] * (3 - fail_at),
                )
                self.assertEqual(result["summary"]["safe"], 0)

    def test_a_setup_failure_at_the_last_position_still_reports_seq_001(self) -> None:
        """Nothing is skipped, so this is the case the emission rule must cover."""
        config = _config(
            [
                {
                    "id": "tail",
                    "steps": [
                        _step("assert", "attacker", "GET", "/a", [200]),
                        _step("setup", "owner", "GET", "/b", [200]),
                    ],
                }
            ],
            marker=False,
        )

        def responder(method, path, token, body):
            return (200 if path == "/a" else 500, _JSON, b"{}")

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(_rules(result), ["VERIDOR-SEQ-001"])
        self.assertEqual(result["findings"][0]["verdict"], "inconclusive")
        self.assertEqual(result["findings"][0]["evidence_grade"], "n/a")
        self.assertEqual(result["findings"][0]["step_index"], 1)

    def test_a_transport_error_aborts_and_is_inconclusive(self) -> None:
        config = _config(
            [
                {
                    "id": "boom",
                    "steps": [
                        _step("setup", "owner", "GET", "/a", [200]),
                        _step("assert", "attacker", "GET", "/b", [403]),
                    ],
                }
            ],
            marker=False,
        )
        with _server(lambda *_: None) as url:
            result = _run(config, url)
        self.assertEqual(_rules(result), ["VERIDOR-EXEC-001", "VERIDOR-SEQ-001"])
        self.assertEqual(_verdicts(result), {"inconclusive"})
        self.assertEqual(result["sequences"][0]["abort_reason"], "execution_error")

    def test_a_failing_assert_does_not_abort(self) -> None:
        """The write-effect step after the attacker's write must stay reachable."""
        config = _config(
            [
                {
                    "id": "keep-going",
                    "steps": [
                        _step("assert", "attacker", "DELETE", "/a", [403]),
                        _step("assert", "owner", "GET", "/b", [200]),
                    ],
                }
            ],
            marker=False,
        )

        def responder(method, path, token, body):
            return (200 if path == "/a" else 200, _JSON, b"{}")

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(result["sequences"][0]["outcome"], "completed")
        self.assertEqual(_rules(result), ["VERIDOR-AUTHZ-001"])
        self.assertEqual(result["sequences"][0]["steps"][1]["state"], "matched")

    def test_the_inconclusive_message_cannot_be_read_as_either_outcome(self) -> None:
        with _server(lambda *_: (500, _JSON, b"{}")) as url:
            result = _run(self._ladder(0), url)
        message = result["findings"][0]["message"]
        self.assertIn("could not be completed", message)
        self.assertIn("Step 0 (setup, as 'owner', GET /s0)", message)
        self.assertIn("received HTTP 500 (declared: one of [200])", message)
        self.assertIn("were not executed", message)
        self.assertIn(
            "No conclusion about authorization was reached: this is neither a "
            "pass nor a failure of the declared expectations.",
            message,
        )


# --------------------------------------------------------------------------
# (3) Capture
# --------------------------------------------------------------------------


class CaptureMissTest(unittest.TestCase):
    def _config(self, extractor: str, role: str = "setup") -> dict:
        return _config(
            [
                {
                    "id": "cap",
                    "steps": [
                        _step("setup", "owner", "GET", "/a", [200],
                              capture={"value": extractor}),
                        _step("assert", "attacker", "GET", "/b/${value}", [403]),
                    ],
                }
            ],
            marker=False,
        )

    def _miss(self, extractor: str, reply) -> dict:
        def responder(method, path, token, body):
            return reply if path == "/a" else (403, _JSON, b"{}")

        with _server(responder) as url:
            return _run(self._config(extractor), url)

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_every_miss_reason_fails_closed(self) -> None:
        cases = [
            ("$.id", (200, {"Content-Type": "text/plain"}, b"id=7"), "not_json"),
            ("$.id", (200, _JSON, b"{not json"), "malformed_json"),
            ("$.id", (200, _JSON, _json_body({"other": 1})), "path_not_found"),
            ("$.id", (200, _JSON, _json_body({"id": 1.5})), "unsupported_type"),
            ("$.id", (200, _JSON, _json_body({"id": True})), "unsupported_type"),
            ("$.id", (200, _JSON, _json_body({"id": None})), "unsupported_type"),
            ("$.a[2]", (200, _JSON, _json_body({"a": [1]})), "path_not_found"),
            ("header:Location", (200, _JSON, b"{}"), "header_absent"),
            ("$.id", (200, _JSON, _json_body({"id": "a b"})), "unsafe_value"),
            ("$.id", (200, _JSON, _json_body({"id": "x" * 513})), "unsafe_value"),
        ]
        for extractor, reply, reason in cases:
            with self.subTest(reason=reason, extractor=extractor):
                result = self._miss(extractor, reply)
                record = result["sequences"][0]
                self.assertEqual(record["abort_reason"], "capture_missed")
                self.assertEqual(
                    record["steps"][0]["captures"][0]["reason"], reason
                )
                self.assertFalse(record["steps"][0]["captures"][0]["resolved"])
                # Never a substitution of the empty string, never a skip and
                # continue: the later step is not sent at all.
                self.assertEqual(record["steps"][1]["state"], "skipped")
                self.assertEqual(_verdicts(result), {"inconclusive"})
                self.assertIn(reason, result["findings"][0]["message"])

    def test_a_repeated_header_with_differing_values_is_ambiguous(self) -> None:
        """A stub that emits the same field twice with different values."""
        sink = {
            "headers": [("Location", "/a/1"), ("Location", "/a/2")],
            "body": b"",
            "body_truncated": False,
        }
        self.assertEqual(
            sequence.resolve_extractor("header:Location", sink),
            (None, "ambiguous_header"),
        )

    def test_a_repeated_header_with_identical_values_resolves(self) -> None:
        sink = {
            "headers": [("Location", "/a/1"), ("Location", "/a/1")],
            "body": b"",
            "body_truncated": False,
        }
        self.assertEqual(
            sequence.resolve_extractor("header:Location", sink), ("/a/1", None)
        )

    def test_a_truncated_body_is_not_a_document(self) -> None:
        sink = {
            "headers": [("Content-Type", "application/json")],
            "body": b'{"id": "x"}',
            "body_truncated": True,
        }
        self.assertEqual(
            sequence.resolve_extractor("$.id", sink), (None, "body_too_large")
        )

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_capture_miss_on_an_assert_step_that_also_mismatched_keeps_the_grade(
        self,
    ) -> None:
        """The graded row wins; the sequence still aborts."""
        config = _config(
            [
                {
                    "id": "both",
                    "steps": [
                        _step("assert", "attacker", "GET", "/a", [403],
                              capture={"value": "$.id"}),
                        _step("assert", "owner", "GET", "/b/${value}", [200]),
                    ],
                }
            ],
            marker=False,
        )

        def responder(method, path, token, body):
            return (200, _JSON, _json_body({"other": 1}))

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(
            _rules(result), ["VERIDOR-AUTHZ-001", "VERIDOR-SEQ-001"]
        )
        self.assertEqual(result["findings"][0]["verdict"], "vulnerable")
        self.assertEqual(result["sequences"][0]["abort_reason"], "capture_missed")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_capture_typed_into_a_json_body_keeps_its_type(self) -> None:
        seen: list[dict] = []

        def responder(method, path, token, body):
            if path == "/a":
                return (200, _JSON, _json_body({"id": 4242}))
            seen.append(json.loads(body))
            return (403, _JSON, b"{}")

        config = _config(
            [
                {
                    "id": "typed",
                    "steps": [
                        _step("setup", "owner", "GET", "/a", [200],
                              capture={"value": "$.id"}),
                        _step("assert", "attacker", "POST", "/b", [403],
                              json={"exact": "${value}", "embedded": "n-${value}"}),
                    ],
                }
            ],
            marker=False,
        )
        with _server(responder) as url:
            _run(config, url)
        self.assertEqual(seen, [{"exact": 4242, "embedded": "n-4242"}])


class CaptureConfidentialityTest(unittest.TestCase):
    SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9-CAPTURED"

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_captured_value_reaches_no_artifact(self) -> None:
        config = _config(
            [
                {
                    "id": "secret",
                    "steps": [
                        _step("setup", "owner", "POST", "/session", [201],
                              capture={"token": "$.token",
                                       "location": "header:Location"}),
                        _step("assert", "attacker", "GET", "/r/${token}", [403],
                              json={"echo": "${location}"}),
                    ],
                }
            ],
            marker=False,
        )

        def responder(method, path, token, body):
            if path == "/session":
                return (
                    201,
                    {**_JSON, "Location": f"/r/{self.SECRET}"},
                    _json_body({"token": self.SECRET}),
                )
            return (200, _JSON, b"{}")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with _server(responder) as url:
                result = _run(config, url, output=output)
            sarif_path = output / "veridor.sarif"
            core.write_json(sarif_path, to_sarif(result))
            artifacts = [
                output / "latest.json",
                sarif_path,
                *sorted((output / "runs").glob("*.json")),
            ]
            self.assertTrue(len(artifacts) >= 3)
            for artifact in artifacts:
                text = artifact.read_text(encoding="utf-8")
                self.assertNotIn(self.SECRET, text, artifact.name)
        # And the in-memory document, which is what the UI and SARIF read.
        blob = json.dumps(result)
        self.assertNotIn(self.SECRET, blob)
        self.assertNotIn(self.SECRET, json.dumps(to_sarif(result)))
        # The narrative survives intact: name, extractor, resolved boolean.
        capture = result["sequences"][0]["steps"][0]["captures"][0]
        self.assertEqual(capture["name"], "token")
        self.assertEqual(capture["extractor"], "$.token")
        self.assertTrue(capture["resolved"])
        self.assertEqual(capture["reason"], None)
        self.assertEqual(
            result["sequences"][0]["steps"][1]["request"]["url"].split("/r/")[1],
            "${token}",
        )

    def test_a_captured_value_is_redacted_out_of_an_error_string(self) -> None:
        values = {"token": self.SECRET, "id": "77"}
        text = f"connection to /r/{self.SECRET} failed after 77 ms"
        redacted = sequence.redact_captures(text, values)
        self.assertNotIn(self.SECRET, redacted)
        self.assertIn("${token}", redacted)
        # A value shorter than four characters is skipped, or every 77 in a URL
        # would be masked and the document made less readable, not safer.
        self.assertIn("77", redacted)

    def test_redaction_masks_the_longest_value_first(self) -> None:
        values = {"short": "abcd", "long": "abcdefgh"}
        self.assertEqual(
            sequence.redact_captures("abcdefgh", values), "${long}"
        )

    def test_no_capture_value_reaches_the_fingerprint(self) -> None:
        """The signature is built only from the config, never from a response."""
        self.assertEqual(
            list(inspect.signature(sequence.step_finding_id).parameters),
            ["sequence_id", "step", "step_index", "kind"],
        )
        body = inspect.getsource(sequence.step_finding_id).split('"""')[-1]
        for banned in ("values", "resolve", "response", "sink"):
            self.assertNotIn(banned, body, banned)


# --------------------------------------------------------------------------
# (4) Load-time validation
# --------------------------------------------------------------------------


class LoadValidationTest(unittest.TestCase):
    def _reject(self, config: dict, pattern: str) -> None:
        with self.assertRaisesRegex(ConfigError, pattern):
            _load(config)

    def test_a_non_object_headers_value_is_a_config_error_not_a_crash(self) -> None:
        """The interpolation scan ran dict() over the headers before the request
        rules could refuse them, so a string, number or list crashed the load
        with an internal error (exit 70) instead of exit 2."""
        for headers in ("x", 5, ["a"], None):
            step = _step("setup", "owner", "GET", "/a", [200])
            step["request"]["headers"] = headers
            with self.subTest(where="step", headers=headers):
                self._reject(
                    _config([{"id": "s", "steps": [step]}], marker=False),
                    r"^sequence 's' step 0\.headers must be an object$",
                )
            teardown = {"as": "owner", "request": {"method": "DELETE", "path": "/a",
                                                   "headers": headers}}
            with self.subTest(where="teardown", headers=headers):
                self._reject(
                    _config(
                        [{
                            "id": "s",
                            "steps": [_step("setup", "owner", "GET", "/a", [200])],
                            "teardown": [teardown],
                        }],
                        marker=False,
                    ),
                    r"^sequence 's' teardown entry 0\.headers must be an object$",
                )

    def test_a_variable_captured_by_another_sequence_is_undefined_here(self) -> None:
        """Names never cross sequences, so this is the plain undefined case.

        The deferred-name set is built across the whole ``sequences`` subtree, so
        ``other_id`` survives environment expansion and is then rejected by
        definition-before-use with the message that says what is actually wrong.
        """
        self._reject(
            _config(
                [
                    {
                        "id": "first",
                        "steps": [
                            _step("setup", "owner", "GET", "/a", [200],
                                  capture={"other_id": "$.id"}),
                        ],
                    },
                    {
                        "id": "second",
                        "steps": [
                            _step("assert", "owner", "GET", "/a/${other_id}", [200]),
                        ],
                    },
                ],
                marker=False,
            ),
            r"references '\$\{other_id\}', which no earlier step captures",
        )

    def test_an_unknown_name_fails_at_load_through_the_environment_gate(self) -> None:
        """A name that is no capture is an environment variable, by definition.

        Leaving unknown names literal was rejected in design: it would turn a
        typo'd ``${API_TOEKN}`` from a load error into a request carrying that
        text to the target. So the failure is loud and it is at load, which is
        the property that matters.
        """
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [_step("assert", "owner", "GET", "/a/${nope}", [200])],
                    }
                ],
                marker=False,
            ),
            r"environment variable 'nope' is not set",
        )

    def test_an_undefined_variable_exits_two(self) -> None:
        """Exit 2 is the contract, not merely 'an error'."""
        from veridor.cli import main as veridor_main

        config = _config(
            [
                {
                    "id": "s",
                    "steps": [_step("assert", "owner", "GET", "/a/${nope}", [200])],
                }
            ],
            marker=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with patch("sys.stderr"):
                code = veridor_main(
                    ["run", "--config", str(path), "--output-dir", directory]
                )
        self.assertEqual(code, 2)

    def test_a_forward_reference_names_the_later_step(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("assert", "owner", "GET", "/a/${later}", [200]),
                            _step("setup", "owner", "GET", "/b", [200],
                                  capture={"later": "$.id"}),
                        ],
                    }
                ],
                marker=False,
            ),
            r"it is captured by step 1, which runs later",
        )

    def test_a_step_cannot_reference_its_own_capture(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("setup", "owner", "GET", "/a/${self_ref}", [200],
                                  capture={"self_ref": "$.id"}),
                        ],
                    }
                ],
                marker=False,
            ),
            r"it is captured by step 0, which runs later",
        )

    def test_capture_names_are_single_assignment(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("setup", "owner", "GET", "/a", [200],
                                  capture={"v": "$.id"}),
                            _step("setup", "owner", "GET", "/b", [200],
                                  capture={"v": "$.id"}),
                        ],
                    }
                ],
                marker=False,
            ),
            r"single-assignment within a sequence",
        )

    def test_role_is_required_with_no_default(self) -> None:
        step = _step("setup", "owner", "GET", "/a", [200])
        del step["role"]
        self._reject(
            _config([{"id": "s", "steps": [step]}], marker=False),
            r"requires role 'setup' or 'assert'",
        )

    def test_sequences_require_config_version_two(self) -> None:
        config = _config(
            [{"id": "s", "steps": [_step("setup", "owner", "GET", "/a", [200])]}],
            marker=False,
        )
        config["version"] = 1
        self._reject(config, r"sequences requires configuration version 2")

    def test_ids_are_unique_across_checks_and_sequences(self) -> None:
        config = _config(
            [{"id": "dup", "steps": [_step("setup", "owner", "GET", "/a", [200])]}],
            checks=[
                {
                    "id": "dup",
                    "request": {"method": "GET", "path": "/a"},
                    "expect": {"owner": {"status": [200]}, "attacker": {"status": [404]}},
                }
            ],
            marker=False,
        )
        self._reject(config, r"duplicate id: dup")

    def test_checks_may_be_absent_when_sequences_are_declared(self) -> None:
        config = _config(
            [{"id": "s", "steps": [_step("setup", "owner", "GET", "/a", [200])]}],
            marker=False,
        )
        del config["checks"]
        self.assertEqual(_load(config)["checks"], [])

    def test_the_historical_checks_message_is_verbatim_without_sequences(self) -> None:
        config = {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:1"},
            "identities": _identities(marker=False),
        }
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        self.assertEqual(str(caught.exception), "checks must be a non-empty list")

    def test_malformed_interpolation_is_rejected(self) -> None:
        for path in ("/a/${", "/a/${}", "/a/${9bad}", "/a/${a b}"):
            with self.subTest(path=path):
                self._reject(
                    _config(
                        [
                            {
                                "id": "s",
                                "steps": [_step("assert", "owner", "GET", path, [200])],
                            }
                        ],
                        marker=False,
                    ),
                    r"malformed interpolation",
                )

    def test_every_illegal_extractor_is_rejected_at_load(self) -> None:
        illegal = [
            "$", "$.", "$..id", "$.items[*]", "$['a b']", "$.items[-1]",
            "$.a.b()", '$["a"]', "header:", "id", "", "$.items[01]",
        ]
        for expression in illegal:
            with self.subTest(expression=expression):
                self._reject(
                    _config(
                        [
                            {
                                "id": "s",
                                "steps": [
                                    _step("setup", "owner", "GET", "/a", [200],
                                          capture={"v": expression}),
                                ],
                            }
                        ],
                        marker=False,
                    ),
                    r"is not a valid extractor",
                )

    def test_every_legal_extractor_parses(self) -> None:
        for expression in (
            "$.id",
            "$.data.items[0].id",
            "$.result[2]",
            "$.attributes.tenant-id",
            "header:Location",
            "header:X-Request-Id",
        ):
            with self.subTest(expression=expression):
                sequence.parse_extractor(expression)

    def test_caps_are_load_errors(self) -> None:
        many = [_step("setup", "owner", "GET", f"/s{i}", [200]) for i in range(13)]
        self._reject(
            _config([{"id": "s", "steps": many}], marker=False),
            r"declares 13 steps; the limit is 12",
        )
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("setup", "owner", "GET", "/a", [200],
                                  capture={f"v{i}": "$.id" for i in range(9)}),
                        ],
                    }
                ],
                marker=False,
            ),
            r"declares 9 captures; the limit is 8",
        )
        self._reject(
            _config(
                [
                    {
                        "id": f"s{i}",
                        "steps": [_step("setup", "owner", "GET", "/a", [200])],
                    }
                    for i in range(65)
                ],
                marker=False,
            ),
            r"declares 65 entries; the limit is 64",
        )

    def test_run_id_is_reserved(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("setup", "owner", "GET", "/a", [200],
                                  capture={"run_id": "$.id"}),
                        ],
                    }
                ],
                marker=False,
            ),
            r"capture name 'run_id' is reserved",
        )

    def test_a_capture_name_colliding_with_an_environment_variable_is_rejected(
        self,
    ) -> None:
        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        _step("setup", "owner", "GET", "/a", [200],
                              capture={"VD_TEST_CAPTURE": "$.id"}),
                    ],
                }
            ],
            marker=False,
        )
        with patch.dict("os.environ", {"VD_TEST_CAPTURE": "1"}):
            self._reject(config, r"collides with an environment variable")

    def test_environment_expansion_is_unchanged_outside_sequences(self) -> None:
        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        _step("setup", "owner", "GET", "/a/${v}", [200]),
                    ],
                }
            ],
            marker=False,
        )
        config["sequences"][0]["steps"].insert(
            0,
            _step("setup", "owner", "GET", "/seed", [200], capture={"v": "$.id"}),
        )
        config["identities"]["owner"]["headers"]["X-Token"] = "${VD_MISSING_VAR}"
        self._reject(config, r"environment variable 'VD_MISSING_VAR' is not set")

    def test_a_deferred_name_is_left_verbatim_in_the_sequences_subtree(self) -> None:
        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        _step("setup", "owner", "GET", "/a", [200],
                              capture={"v": "$.id"}),
                        _step("assert", "owner", "GET", "/b/${v}", [200]),
                    ],
                }
            ],
            marker=False,
        )
        loaded = _load(config)
        self.assertEqual(
            loaded["sequences"][0]["steps"][1]["request"]["path"], "/b/${v}"
        )

    def test_teardown_cannot_declare_a_role_or_a_capture(self) -> None:
        base = {
            "id": "s",
            "steps": [_step("setup", "owner", "GET", "/a", [200])],
        }
        for banned in ("role", "capture", "contains_marker", "excludes_marker"):
            with self.subTest(banned=banned):
                sequence_config = dict(base)
                sequence_config["teardown"] = [
                    {
                        "as": "owner",
                        "request": {"method": "DELETE", "path": "/a"},
                        banned: "setup" if banned == "role" else {"x": "$.id"},
                    }
                ]
                self._reject(
                    _config([sequence_config], marker=False),
                    rf"teardown entries cannot declare '{banned}'",
                )

    def test_teardown_references_are_validated_against_every_step_capture(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "other",
                        "steps": [
                            _step("setup", "owner", "GET", "/a", [200],
                                  capture={"ghost": "$.id"}),
                        ],
                    },
                    {
                        "id": "s",
                        "steps": [_step("setup", "owner", "GET", "/a", [200])],
                        "teardown": [
                            {
                                "as": "owner",
                                "request": {"method": "DELETE", "path": "/a/${ghost}"},
                            }
                        ],
                    },
                ],
                marker=False,
            ),
            r"references '\$\{ghost\}', which no step captures",
        )

    def test_a_near_miss_step_key_fails_closed(self) -> None:
        step = _step("setup", "owner", "GET", "/a", [200])
        step["captures"] = {"v": "$.id"}
        self._reject(
            _config([{"id": "s", "steps": [step]}], marker=False),
            r"has unsupported keys: captures",
        )

    def test_a_near_miss_expect_key_fails_closed(self) -> None:
        step = _step("setup", "owner", "GET", "/a", [200])
        step["expect"]["contain_marker"] = "owner"
        self._reject(
            _config([{"id": "s", "steps": [step]}]),
            r"has unsupported keys: contain_marker",
        )


class MarkerPlantingValidationTest(unittest.TestCase):
    def _reject(self, config: dict, pattern: str) -> None:
        with self.assertRaisesRegex(ConfigError, pattern):
            _load(config)

    def _plant(self, role: str = "setup", identity: str = "owner", owner: str = "owner"):
        return _step(
            role, identity, "POST", "/notes", [201],
            json={"provenance": "${marker:" + owner + "}"},
        )

    def test_a_marker_may_be_planted_in_a_setup_body(self) -> None:
        _load(_config([{"id": "s", "steps": [self._plant()]}]))

    def test_a_marker_may_not_be_planted_on_an_assert_step(self) -> None:
        self._reject(
            _config([{"id": "s", "steps": [self._plant(role="assert")]}]),
            r"may only plant a marker on a 'setup' step",
        )

    def test_a_marker_may_not_be_planted_in_a_path(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("setup", "owner", "GET", "/n/${marker:owner}", [200]),
                        ],
                    }
                ]
            ),
            r"may only plant a marker in a request body",
        )

    def test_a_marker_may_not_be_planted_in_a_header(self) -> None:
        step = _step("setup", "owner", "GET", "/n", [200])
        step["request"]["headers"] = {"X-Ref": "${marker:owner}"}
        self._reject(
            _config([{"id": "s", "steps": [step]}]),
            r"may only plant a marker in a request body",
        )

    def test_an_identity_may_only_plant_its_own_marker(self) -> None:
        self._reject(
            _config([{"id": "s", "steps": [self._plant(owner="attacker")]}]),
            r"may only plant its own marker",
        )

    def test_a_planting_step_cannot_also_declare_a_marker_expectation(self) -> None:
        step = self._plant()
        step["expect"]["contains_marker"] = "owner"
        self._reject(
            _config([{"id": "s", "steps": [step]}]),
            r"plants a marker and cannot also declare contains_marker",
        )

    def test_a_marker_literal_in_a_sequence_is_still_a_hard_error(self) -> None:
        """The reflection guard is retargeted, never weakened."""
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [
                            _step("setup", "owner", "POST", "/n", [201],
                                  json={"provenance": MARKER_OWNER}),
                        ],
                    }
                ]
            ),
            r"marker appears in the request sent by sequence 's' step 0",
        )

    def test_a_marker_literal_in_a_teardown_is_a_hard_error(self) -> None:
        self._reject(
            _config(
                [
                    {
                        "id": "s",
                        "steps": [_step("setup", "owner", "GET", "/a", [200])],
                        "teardown": [
                            {
                                "as": "owner",
                                "request": {
                                    "method": "DELETE",
                                    "path": f"/a/{MARKER_OWNER}",
                                },
                            }
                        ],
                    }
                ]
            ),
            r"marker appears in the request sent by sequence 's' teardown entry 0",
        )

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_planting_step_is_never_scanned(self) -> None:
        """A target that echoes the plant back must not become a control."""
        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        self._plant(),
                        _step("assert", "attacker", "GET", "/n", [403],
                              excludes_marker="owner"),
                    ],
                }
            ]
        )

        def responder(method, path, token, body):
            if method == "POST":
                # A reflector: it echoes the planted marker straight back.
                return (201, _JSON, body)
            return (403, _JSON, b"{}")

        with _server(responder) as url:
            result = _run(config, url)
        plant = result["sequences"][0]["steps"][0]
        self.assertFalse(plant["marker_scanned"])
        self.assertEqual(plant["response"]["marker_scan"], None)
        self.assertEqual(plant["marker_planted"], ["owner"])
        # And the echo licensed nothing: the exclusion is unproven.
        self.assertEqual(_rules(result), ["VERIDOR-ORACLE-001"])
        self.assertEqual(result["findings"][0]["verdict"], "inconclusive")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_sequence_that_plants_ignores_the_identity_probe(self) -> None:
        """A stale probe must not license an assertion about a new object."""
        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        self._plant(),
                        _step("assert", "attacker", "GET", "/n", [403],
                              excludes_marker="owner"),
                    ],
                }
            ]
        )
        config["identities"]["owner"]["marker_probe"] = {
            "method": "GET",
            "path": "/probe",
        }

        def responder(method, path, token, body):
            if path == "/probe":
                return (200, _JSON, _json_body({"ref": MARKER_OWNER}))
            if method == "POST":
                return (201, _JSON, _json_body({"id": "1"}))
            return (403, _JSON, b"{}")

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(_rules(result), ["VERIDOR-ORACLE-001"])
        marker = result["findings"][0]["evidence"]["marker"]
        self.assertEqual(marker["control_source"], "none")
        self.assertIn("plants", marker["control_reason"])

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_prior_step_observation_licenses_a_later_exclusion(self) -> None:
        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        _step("setup", "owner", "GET", "/n/1", [200],
                              contains_marker="owner"),
                        _step("assert", "attacker", "GET", "/n/1", [403],
                              excludes_marker="owner"),
                    ],
                }
            ]
        )

        def responder(method, path, token, body):
            if token == OWNER_TOKEN:
                return (200, _JSON, _json_body({"ref": MARKER_OWNER}))
            return (403, _JSON, _json_body({"error": "no"}))

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["sequences"][0]["outcome"], "completed")


# --------------------------------------------------------------------------
# (5) Runtime path safety
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class RuntimePathTest(unittest.TestCase):
    def _config(self) -> dict:
        return _config(
            [
                {
                    "id": "loc",
                    "steps": [
                        _step("setup", "owner", "POST", "/n", [201],
                              capture={"where": "header:Location"}),
                        _step("assert", "attacker", "DELETE", "${where}", [403]),
                    ],
                }
            ],
            marker=False,
        )

    def _with_location(self, location: str) -> dict:
        def responder(method, path, token, body):
            if method == "POST":
                return (201, {**_JSON, "Location": location}, _json_body({"id": "1"}))
            return (403, _JSON, b"{}")

        with _server(responder) as url:
            return _run(self._config(), url)

    def test_a_relative_location_is_used_as_the_whole_path(self) -> None:
        result = self._with_location("/n/1")
        self.assertEqual(result["sequences"][0]["steps"][1]["state"], "matched")

    def test_a_cross_origin_location_fails_closed_and_sends_nothing(self) -> None:
        for location in (
            "https://evil.example/n/1",
            "http://evil.example/n/1",
            "//evil.example/n/1",
            "http://127.0.0.1:1/n/1",
        ):
            with self.subTest(location=location):
                result = self._with_location(location)
                record = result["sequences"][0]
                self.assertEqual(record["abort_reason"], "path_invalid")
                self.assertEqual(record["steps"][1]["response"], None)
                self.assertEqual(_verdicts(result), {"inconclusive"})

    def test_a_same_origin_absolute_location_is_reduced_to_its_path(self) -> None:
        def responder(method, path, token, body):
            if method == "POST":
                return (
                    201,
                    {**_JSON, "Location": f"{responder.base}/n/1?a=b"},
                    _json_body({"id": "1"}),
                )
            responder.seen = path
            return (403, _JSON, b"{}")

        responder.seen = None
        with _server(lambda *args: responder(*args)) as url:
            responder.base = url
            result = _run(self._config(), url)
        self.assertEqual(responder.seen, "/n/1?a=b")
        self.assertEqual(result["sequences"][0]["steps"][1]["state"], "matched")

    def test_a_substituted_path_is_revalidated(self) -> None:
        def responder(method, path, token, body):
            if method == "POST":
                return (201, {**_JSON, "Location": "n/1"}, _json_body({"id": "1"}))
            return (403, _JSON, b"{}")

        with _server(responder) as url:
            result = _run(self._config(), url)
        # 'n/1' is not a same-origin ABSOLUTE path, so it never reaches the wire.
        self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")

    def _behind_a_base_path(
        self,
        location: str,
        *,
        template: str = "${where}",
        readable: str = "/api/notes/n1",
    ) -> tuple[list[str], dict]:
        """Base URL ``…/api/``; the owner's resource at ``readable`` is readable
        by anyone, and every other route is a 404. The assert step declares the
        common [403, 404], so a probe sent to the wrong route is a clean pass.
        The assert step's path is ``template``, which defaults to the bare
        capture but may build on it (e.g. ``${where}/comments``).
        """
        seen: list[str] = []

        def responder(method, path, token, body):
            if method == "POST":
                return (201, {**_JSON, "Location": location.format(base=responder.base)},
                        _json_body({"id": "n1"}))
            seen.append(path)
            if path == readable:
                return (200, _JSON, _json_body({"owner": "owner", "note": "secret"}))
            return (404, _JSON, b"{}")

        config = _config(
            [{
                "id": "loc",
                "steps": [
                    _step("setup", "owner", "POST", "/notes", [201],
                          capture={"where": "header:Location"}),
                    _step("assert", "attacker", "GET", template, [403, 404]),
                ],
            }],
            marker=False,
        )
        with _server(lambda *args: responder(*args)) as url:
            responder.base = url
            result = _run(config, f"{url}/api/")
        return seen, result

    def test_a_location_from_the_origin_root_is_not_joined_under_the_base_path_twice(
        self,
    ) -> None:
        """A captured URL already carries the base path; joining it under the
        base path again sent /api/api/notes/n1, drew a 404 that matched the
        declared denial, and passed clean over a live IDOR."""
        for location in ("{base}/api/notes/n1", "/api/notes/n1"):
            with self.subTest(location=location):
                seen, result = self._behind_a_base_path(location)
                self.assertEqual(seen, ["/api/notes/n1"])
                self.assertEqual(result["sequences"][0]["steps"][1]["state"], "mismatched")
                self.assertIn("VERIDOR-AUTHZ-001", _rules(result))

    def test_a_captured_origin_root_path_under_a_suffix_is_not_doubled(self) -> None:
        """The capture need not be the whole template. ``${where}/comments``
        with a captured ``/api/notes/n1`` built /api/api/notes/n1/comments: the
        leading captured path carries the base prefix just as the sole-token
        form did, but only the sole-token form was re-expressed. The doubled
        route 404s, matches the declared [403, 404], and the run was clean over
        a live IDOR on /api/notes/n1/comments."""
        seen, result = self._behind_a_base_path(
            "/api/notes/n1",
            template="${where}/comments",
            readable="/api/notes/n1/comments",
        )
        self.assertEqual(seen, ["/api/notes/n1/comments"])
        self.assertEqual(result["sequences"][0]["steps"][1]["state"], "mismatched")
        self.assertIn("VERIDOR-AUTHZ-001", _rules(result))

    def test_a_same_origin_absolute_capture_under_a_suffix_is_re_expressed(
        self,
    ) -> None:
        """REGRESSION. ``${where}/comments`` with a captured
        ``{base}/api/notes/n1`` -- the Location header a target most often
        sends -- was refused as ``not_absolute``: only the sole-token form
        handled a scheme and host, so the leading-capture form left them in the
        path and revalidation threw it out. This test used to pin that refusal
        as fail-closed; it was inconclusive over a boundary Veridor could have
        tested. It now gets the sole token's same-origin check and base-path
        re-expression, and reaches /api/notes/n1/comments."""
        seen, result = self._behind_a_base_path(
            "{base}/api/notes/n1",
            template="${where}/comments",
            readable="/api/notes/n1/comments",
        )
        self.assertEqual(seen, ["/api/notes/n1/comments"])
        self.assertEqual(result["sequences"][0]["steps"][1]["state"], "mismatched")
        self.assertIn("VERIDOR-AUTHZ-001", _rules(result))

    def test_a_capture_with_a_query_under_a_suffix_keeps_the_suffix_on_the_path(
        self,
    ) -> None:
        """REGRESSION. ``${where}/comments`` with a captured
        ``{base}/api/notes/n1?created=1`` (or the origin-root
        ``/api/notes/n1?created=1``) was re-expressed as one string, so the
        suffix landed INSIDE the query: the step requested
        ``/api/notes/n1?created=1/comments`` -- the note itself, not its
        comments. That 404'd here, matched the declared [403, 404], and the run
        passed clean over a live IDOR on /api/notes/n1/comments. The suffix
        belongs on the path, and the captured query follows it."""
        for location in ("{base}/api/notes/n1?created=1", "/api/notes/n1?created=1"):
            with self.subTest(location=location):
                seen, result = self._behind_a_base_path(
                    location,
                    template="${where}/comments",
                    readable="/api/notes/n1/comments?created=1",
                )
                self.assertEqual(seen, ["/api/notes/n1/comments?created=1"])
                self.assertEqual(result["sequences"][0]["steps"][1]["state"], "mismatched")
                self.assertIn("VERIDOR-AUTHZ-001", _rules(result))

    @fast("resolves a path in-process; nothing is sent")
    def test_a_leading_capture_with_a_query_never_moves_the_suffix_into_it(
        self,
    ) -> None:
        """The in-process half of the case above. The template's suffix is
        appended to the captured PATH; the captured query, and then any query
        the template itself declares, follow it. A captured fragment under a
        suffix is refused: it has no place on the wire, and dropping it would
        send a request nobody declared."""
        base = "http://127.0.0.1:8080/api/"
        for (template, captured), expected in {
            ("${c}/comments", "http://127.0.0.1:8080/api/notes/n1?created=1"):
                "/notes/n1/comments?created=1",
            ("${c}/comments", "/api/notes/n1?created=1"): "/notes/n1/comments?created=1",
            ("${c}/comments", "/notes/n1?created=1"): "/notes/n1/comments?created=1",
            ("${c}/comments?page=2", "/api/notes/n1?created=1"):
                "/notes/n1/comments?created=1&page=2",
            ("${c}?page=2", "/api/notes/n1?created=1"): "/notes/n1?created=1&page=2",
            ("${c}/comments?page=2", "/api/notes/n1"): "/notes/n1/comments?page=2",
            ("${c}/comments", "/api/notes/n1?"): "/notes/n1/comments",
        }.items():
            with self.subTest(template=template, captured=captured):
                self.assertEqual(sequence._resolve_path(
                    template, {"c": captured}, "r", {}, base), expected)
        for captured, reason in {
            "http://127.0.0.1:8080/api/notes/n1#top": "fragment",
            "http://127.0.0.1:8080/api/notes/n1?created=1#top": "fragment",
            "/api/notes/n1#top": "fragment",
            "http://evil.example/api/notes/n1?created=1": "cross_origin",
            "http://127.0.0.1:8080/other/n1?created=1": "outside_base_path",
        }.items():
            with self.subTest(captured=captured):
                with self.assertRaises(sequence._PathInvalid) as caught:
                    sequence._resolve_path("${c}/comments", {"c": captured}, "r", {}, base)
                self.assertEqual(caught.exception.reason, reason)

    def test_a_cross_origin_or_outside_capture_under_a_suffix_is_refused(self) -> None:
        """The other side of the case above: a capture from another origin, or
        one on this origin but outside the base path, is still never sent."""
        for location in ("http://evil.example/api/notes/n1",
                         "//evil.example/api/notes/n1",
                         "{base}/other/n1"):
            with self.subTest(location=location):
                seen, result = self._behind_a_base_path(
                    location,
                    template="${where}/comments",
                    readable="/api/notes/n1/comments",
                )
                self.assertEqual(seen, [])
                self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")
                self.assertEqual(_verdicts(result), {"inconclusive"})

    def test_a_base_relative_capture_under_a_suffix_is_unchanged(self) -> None:
        """The control for the case above: a base-relative capture carries no
        base prefix to strip, so ``${where}/comments`` with ``/notes/n1``
        reaches /api/notes/n1/comments on every version."""
        seen, result = self._behind_a_base_path(
            "/notes/n1",
            template="${where}/comments",
            readable="/api/notes/n1/comments",
        )
        self.assertEqual(seen, ["/api/notes/n1/comments"])
        self.assertIn("VERIDOR-AUTHZ-001", _rules(result))

    def test_a_location_relative_to_the_base_path_still_reaches_it(self) -> None:
        """The control, and the behaviour a prefix-stripping gateway relies on."""
        seen, result = self._behind_a_base_path("/notes/n1")
        self.assertEqual(seen, ["/api/notes/n1"])
        self.assertIn("VERIDOR-AUTHZ-001", _rules(result))

    def test_an_absolute_location_outside_the_base_path_is_not_retargeted(self) -> None:
        """``{base}/other/n1`` is on the origin but not under /api; joined
        under the base path it became /api/other/n1, a route nobody wrote."""
        seen, result = self._behind_a_base_path("{base}/other/n1")
        self.assertEqual(seen, [])
        self.assertEqual(result["sequences"][0]["abort_reason"], "path_invalid")
        self.assertEqual(_verdicts(result), {"inconclusive"})

    @fast("resolves a path in-process; nothing is sent")
    def test_the_resolved_path_is_relative_to_the_base_path(self) -> None:
        base = "https://gw.example/service-a/"
        cases = {
            "https://gw.example/service-a/items/5": "/items/5",
            "https://gw.example/service-a/items/5?x=1": "/items/5?x=1",
            "https://gw.example/service-a": "/",
            "/service-a/items/5": "/items/5",
            "/items/5": "/items/5",
        }
        for captured, expected in cases.items():
            with self.subTest(captured=captured):
                self.assertEqual(
                    sequence._resolve_path("${c}", {"c": captured}, "r", {}, base),
                    expected,
                )
        # Without a base path nothing changes.
        self.assertEqual(
            sequence._resolve_path(
                "${c}", {"c": "https://gw.example/service-a/items/5"}, "r", {},
                "https://gw.example",
            ),
            "/service-a/items/5",
        )
        for captured in ("https://gw.example/service-b/items/5",
                         "https://gw.example/service-ab/items/5"):
            with self.subTest(captured=captured):
                with self.assertRaises(sequence._PathInvalid) as caught:
                    sequence._resolve_path("${c}", {"c": captured}, "r", {}, base)
                self.assertEqual(caught.exception.reason, "outside_base_path")

    @fast("resolves a path in-process; nothing is sent")
    def test_a_leading_capture_gets_the_sole_tokens_origin_handling(self) -> None:
        """``${c}/comments`` is held to what ``${c}`` is: a same-origin absolute
        URL is re-expressed under the base path, one from another origin is
        refused as ``cross_origin`` and one outside the base path as
        ``outside_base_path``. A same-origin URL was refused as
        ``not_absolute``, which named neither cause."""
        base = "http://127.0.0.1:8080/api/"
        for captured, expected in {
            "http://127.0.0.1:8080/api/notes/n1": "/notes/n1/comments",
            "HTTP://127.0.0.1:8080/api/notes/n1": "/notes/n1/comments",
            "/api/notes/n1": "/notes/n1/comments",
            "/notes/n1": "/notes/n1/comments",
        }.items():
            with self.subTest(captured=captured):
                self.assertEqual(sequence._resolve_path(
                    "${c}/comments", {"c": captured}, "r", {}, base), expected)
        for captured, reason in {
            "http://evil.example/api/notes/n1": "cross_origin",
            "//evil.example/api/notes/n1": "cross_origin",
            "http://127.0.0.1:9090/api/notes/n1": "cross_origin",
            "https://127.0.0.1:8080/api/notes/n1": "cross_origin",
            "http://127.0.0.1:8080/other/n1": "outside_base_path",
        }.items():
            with self.subTest(captured=captured):
                with self.assertRaises(sequence._PathInvalid) as caught:
                    sequence._resolve_path("${c}/comments", {"c": captured}, "r", {}, base)
                self.assertEqual(caught.exception.reason, reason)


# --------------------------------------------------------------------------
# (6) Write-effect verification
# --------------------------------------------------------------------------


def _write_effect_config() -> dict:
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
                "teardown": [
                    {
                        "as": "owner",
                        "request": {"method": "DELETE", "path": "/n/${note}"},
                        "expect": {"status": [204, 404]},
                    }
                ],
            }
        ]
    )


def _notes_target(*, delete_status: int, really_deletes: bool):
    state = {"present": False}

    def responder(method, path, token, body):
        if method == "POST":
            state["present"] = True
            return (201, _JSON, _json_body({"id": "n1"}))
        if method == "GET":
            if not state["present"]:
                return (404, _JSON, _json_body({"error": "not found"}))
            if token != OWNER_TOKEN:
                return (404, _JSON, _json_body({"error": "not found"}))
            return (200, _JSON, _json_body({"provenance": MARKER_OWNER}))
        if method == "DELETE":
            if token == OWNER_TOKEN:
                state["present"] = False
                return (204, {}, b"")
            if really_deletes:
                state["present"] = False
            return (delete_status, _JSON, _json_body({"ok": True}))
        return (405, _JSON, b"{}")

    return responder


@slow("stands up a loopback HTTP server and runs the engine against it")
class WriteEffectTest(unittest.TestCase):
    def test_a_silent_cross_tenant_delete_is_confirmed(self) -> None:
        """403 to the attacker, row gone anyway. A status-only check goes green."""
        with _server(_notes_target(delete_status=403, really_deletes=True)) as url:
            result = _run(_write_effect_config(), url)
        self.assertEqual(_rules(result), ["VERIDOR-EFFECT-001"])
        finding = result["findings"][0]
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(finding["step_index"], 3)
        marker = finding["evidence"]["marker"]
        self.assertEqual(marker["control_source"], "sequence_prior_step")
        self.assertEqual(marker["control_step_index"], 1)
        # The attacker's own step matched its declaration and produced nothing.
        self.assertEqual(result["sequences"][0]["steps"][2]["state"], "matched")

    def test_the_refusal_downgrade_does_not_apply_to_effect_001(self) -> None:
        """404 to the owner IS the vulnerability, not an unexpected denial."""
        with _server(_notes_target(delete_status=403, really_deletes=True)) as url:
            result = _run(_write_effect_config(), url)
        self.assertEqual(result["findings"][0]["evidence"]["actual_status"], 404)
        self.assertIn(404, core.REFUSAL_STATUSES)
        self.assertEqual(result["findings"][0]["verdict"], "vulnerable")
        self.assertNotIn("unexpected_denial", _verdicts(result))

    def test_a_no_op_two_hundred_is_refuted_by_the_follow_up_read(self) -> None:
        with _server(_notes_target(delete_status=200, really_deletes=False)) as url:
            result = _run(_write_effect_config(), url)
        self.assertEqual(_rules(result), ["VERIDOR-AUTHZ-001"])
        finding = result["findings"][0]
        # NOT downgraded: a 200 to an unauthorized DELETE still fails the
        # declaration. The refutation rides inline instead.
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "ungraded")
        self.assertEqual(
            finding["evidence"]["write_effect"],
            {"verified_by_step": 3, "state": "no_effect_observed"},
        )
        self.assertIn("did not take effect on the object", finding["message"])

    def test_a_real_delete_behind_a_two_hundred_is_reported_as_an_effect(self) -> None:
        with _server(_notes_target(delete_status=200, really_deletes=True)) as url:
            result = _run(_write_effect_config(), url)
        self.assertEqual(
            _rules(result), ["VERIDOR-AUTHZ-001", "VERIDOR-EFFECT-001"]
        )
        self.assertEqual(
            result["findings"][0]["evidence"]["write_effect"],
            {"verified_by_step": 3, "state": "effect_observed"},
        )
        self.assertEqual(result["findings"][1]["evidence_grade"], "confirmed")

    def test_a_correctly_enforced_target_produces_no_finding(self) -> None:
        with _server(_notes_target(delete_status=403, really_deletes=False)) as url:
            result = _run(_write_effect_config(), url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["sequences"][0]["outcome"], "completed")
        self.assertEqual(result["summary"]["sequence_steps_matched"], 4)
        self.assertEqual(result["summary"]["teardown_failures"], 0)

    def test_effect_001_requires_an_earlier_foreign_write(self) -> None:
        """Without one, a missing marker is a broken fixture, not an effect."""
        config = _config(
            [
                {
                    "id": "no-write",
                    "steps": [
                        _step("assert", "owner", "GET", "/n/1", [200],
                              contains_marker="owner"),
                    ],
                }
            ]
        )
        with _server(lambda *_: (200, _JSON, _json_body({"x": 1}))) as url:
            result = _run(config, url)
        self.assertEqual(_rules(result), ["VERIDOR-ORACLE-001"])
        self.assertEqual(result["findings"][0]["verdict"], "inconclusive")

    def test_effect_001_is_suspected_without_a_prior_observation(self) -> None:
        config = _config(
            [
                {
                    "id": "unproven",
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
            return (404, _JSON, b"{}")

        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(_rules(result), ["VERIDOR-EFFECT-001"])
        self.assertEqual(result["findings"][0]["evidence_grade"], "suspected")
        self.assertEqual(
            result["findings"][0]["evidence"]["marker"]["control_source"], "none"
        )


# --------------------------------------------------------------------------
# (7) Teardown and idempotency
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class TeardownTest(unittest.TestCase):
    def test_teardown_runs_after_an_aborted_sequence(self) -> None:
        seen: list[str] = []

        def responder(method, path, token, body):
            seen.append(f"{method} {path}")
            if path == "/a":
                return (201, _JSON, _json_body({"id": "42"}))
            if path == "/b":
                return (500, _JSON, b"{}")
            return (204, {}, b"")

        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        _step("setup", "owner", "POST", "/a", [201],
                              capture={"v": "$.id"}),
                        _step("setup", "owner", "GET", "/b", [200]),
                        _step("assert", "attacker", "GET", "/c", [403]),
                    ],
                    "teardown": [
                        {
                            "as": "owner",
                            "request": {"method": "DELETE", "path": "/z/${v}"},
                            "expect": {"status": [204]},
                        }
                    ],
                }
            ],
            marker=False,
        )
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(seen, ["POST /a", "GET /b", "DELETE /z/42"])
        teardown = result["sequences"][0]["teardown"][0]
        self.assertEqual(teardown["state"], "executed")
        self.assertTrue(teardown["matched"])
        self.assertEqual(teardown["request"]["url"].split("/z/")[1], "${v}")

    def test_an_unresolved_teardown_entry_is_skipped_not_sent(self) -> None:
        seen: list[str] = []

        def responder(method, path, token, body):
            seen.append(path)
            return (500, _JSON, b"{}")

        config = _config(
            [
                {
                    "id": "s",
                    "steps": [
                        _step("setup", "owner", "POST", "/a", [201],
                              capture={"v": "$.id"}),
                    ],
                    "teardown": [
                        {
                            "as": "owner",
                            "request": {"method": "DELETE", "path": "/z/${v}"},
                        }
                    ],
                }
            ],
            marker=False,
        )
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(seen, ["/a"])
        self.assertEqual(
            result["sequences"][0]["teardown"][0]["state"], "skipped_unresolved"
        )
        self.assertEqual(result["summary"]["teardown_failures"], 1)

    def test_a_teardown_mismatch_never_produces_a_finding(self) -> None:
        def responder(method, path, token, body):
            return (200, _JSON, b"{}") if method == "GET" else (500, _JSON, b"{}")

        config = _config(
            [
                {
                    "id": "s",
                    "steps": [_step("assert", "owner", "GET", "/a", [200])],
                    "teardown": [
                        {
                            "as": "owner",
                            "request": {"method": "DELETE", "path": "/a"},
                            "expect": {"status": [204]},
                        }
                    ],
                }
            ],
            marker=False,
        )
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["teardown_failures"], 1)
        self.assertFalse(result["sequences"][0]["teardown"][0]["matched"])

    def test_run_id_is_one_namespace_for_the_whole_run(self) -> None:
        seen: list[dict] = []

        def responder(method, path, token, body):
            seen.append(json.loads(body))
            return (201, _JSON, _json_body({"id": "1"}))

        config = _config(
            [
                {
                    "id": f"s{index}",
                    "steps": [
                        _step("setup", "owner", "POST", "/a", [201],
                              json={"name": "vd-${run_id}-x"}),
                    ],
                }
                for index in range(2)
            ],
            marker=False,
        )
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[0]["name"], f"vd-{result['run_id']}-x")


# --------------------------------------------------------------------------
# (8) Run-document shape and compatibility
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class RunDocumentTest(unittest.TestCase):
    def _result(self) -> dict:
        with _server(_notes_target(delete_status=403, really_deletes=True)) as url:
            return _run(_write_effect_config(), url)

    def test_a_sequence_run_is_schema_version_three(self) -> None:
        result = self._result()
        self.assertEqual(result["schema_version"], 3)
        self.assertIn(3, core.SUPPORTED_RUN_SCHEMA_VERSIONS)

    def test_a_sequence_run_round_trips_through_load_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with _server(_notes_target(delete_status=403, really_deletes=True)) as url:
                _run(_write_effect_config(), url, output=output)
            loaded = core.load_run(output / "latest.json")
        self.assertEqual(loaded["schema_version"], 3)
        self.assertEqual(loaded["findings"][0]["rule_id"], "VERIDOR-EFFECT-001")

    def test_step_requests_are_not_probes(self) -> None:
        result = self._result()
        self.assertEqual(result["summary"]["probes"], 0)
        self.assertEqual(result["summary"]["safe"], 0)
        self.assertEqual(result["summary"]["sequence_steps"], 4)
        self.assertEqual(result["probes"], [])

    def test_every_step_finding_carries_its_own_sequence_context(self) -> None:
        result = self._result()
        context = result["findings"][0]["evidence"]["sequence"]
        self.assertEqual(context["sequence_id"], "delete")
        self.assertEqual(context["step_index"], 3)
        self.assertEqual(context["role"], "assert")
        self.assertEqual(context["outcome"], "completed")
        self.assertEqual(context["skipped_steps"], [])

    def test_sarif_gains_the_new_rules_only_when_referenced(self) -> None:
        plain = {
            "run_id": "r",
            "findings": [
                {
                    "id": "a", "rule_id": "VERIDOR-AUTHZ-001", "level": "error",
                    "message": "m", "location": "c", "check_id": "c",
                    "identity": "i", "verdict": "vulnerable",
                }
            ],
        }
        rule_ids = [
            rule["id"]
            for rule in to_sarif(plain)["runs"][0]["tool"]["driver"]["rules"]
        ]
        self.assertNotIn("VERIDOR-EFFECT-001", rule_ids)
        self.assertNotIn("VERIDOR-SEQ-001", rule_ids)

        sarif = to_sarif(self._result())
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertIn("VERIDOR-EFFECT-001", [rule["id"] for rule in driver["rules"]])
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["stepIndex"], 3)

    def test_sarif_rule_help_mirrors_the_finding_remediation(self) -> None:
        result = self._result()
        sarif = to_sarif(result)
        rules = {
            rule["id"]: rule
            for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
        }
        self.assertEqual(
            rules["VERIDOR-EFFECT-001"]["help"]["text"],
            result["findings"][0]["remediation"],
        )

    def test_the_interpretation_is_amended_only_for_sequence_runs(self) -> None:
        plain = core._interpretation("c")
        amended = core._interpretation("c", has_sequences=True)
        self.assertIn(
            "One identity's marker was observed", plain["confirmed_grade_means"]
        )
        self.assertIn("destroyed", amended["confirmed_grade_means"])
        self.assertEqual(
            self._result()["interpretation"]["confirmed_grade_means"],
            amended["confirmed_grade_means"],
        )

    def test_the_document_holds_no_response_byte(self) -> None:
        result = self._result()
        blob = json.dumps(result)
        self.assertNotIn(MARKER_OWNER, blob)
        self.assertNotIn("not found", blob)


# --------------------------------------------------------------------------
# (9) Non-goals -- assert the doors stay shut
# --------------------------------------------------------------------------


class MainGuardPlacementTest(unittest.TestCase):
    """`python tests/test_x.py` stops at ``unittest.main()``: it runs what is
    defined so far, prints OK, and exits. Classes below the guard never ran
    that way, and nothing said so. The guard must be the last statement."""

    MODULES = ("test_sequence.py", "test_sequence_hardening.py", "test_session.py")

    @staticmethod
    def _is_main_guard(node) -> bool:
        import ast

        return (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
        )

    def test_the_main_guard_is_the_last_statement(self) -> None:
        import ast

        for name in self.MODULES:
            with self.subTest(module=name):
                body = ast.parse((ROOT / "tests" / name).read_text(encoding="utf-8")).body
                guards = [i for i, node in enumerate(body) if self._is_main_guard(node)]
                self.assertEqual(guards, [len(body) - 1], name)


class AbortReasonVocabularyTest(unittest.TestCase):
    def test_every_abort_reason_the_engine_records_is_in_the_vocabulary(self) -> None:
        """ABORT_REASONS was read by nothing and missed four reasons the engine
        writes to the run document, so a consumer trusting it misread aborts."""
        import ast
        from types import SimpleNamespace

        tree = ast.parse(inspect.getsource(sequence._SequenceRun))
        written: set[str] = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_abort" and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)):
                written.add(node.args[1].value)
            if isinstance(node, ast.FunctionDef) and node.name == "_degraded":
                written.update(
                    item.value.value for item in ast.walk(node)
                    if isinstance(item, ast.Return)
                    and isinstance(item.value, ast.Constant)
                    and isinstance(item.value.value, str)
                )
        # The scan itself must find the reasons, or a zero below means nothing.
        self.assertTrue({"setup_failed", "marker_reflection_blocked",
                         "session_not_live"} <= written)
        self.assertEqual(written - sequence.ABORT_REASONS, set())
        self.assertEqual(sequence.ABORT_REASONS - written, set())
        # And a reason outside it cannot be recorded silently.
        with self.assertRaises(AssertionError):
            sequence._SequenceRun._abort(SimpleNamespace(), 0, "not_a_reason", "x")


class NonGoalTest(unittest.TestCase):
    def test_the_engine_has_no_conditional_loop_or_expression_key(self) -> None:
        source = inspect.getsource(sequence)
        for banned in ('"if"', '"unless"', '"when"', '"repeat"', '"for_each"',
                       '"retry"', '"wait_for"', '"regex"', '"transform"'):
            self.assertNotIn(banned, source, banned)

    def test_the_engine_never_imports_a_third_party_module(self) -> None:
        """Invariant 1, asserted on the parse tree rather than on the text."""
        import ast

        # Every name here ships with CPython. The session layer adds `http`
        # (cookiejar), `html` (the meta-tag parser), `sys` and `time`.
        allowed = {
            "__future__", "hashlib", "html", "http", "json", "os", "pathlib",
            "re", "sys", "time", "typing", "urllib", "veridor",
        }
        tree = ast.parse(inspect.getsource(sequence))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported)
        self.assertEqual(imported - allowed, set())

    def test_a_capture_value_map_is_dropped_when_the_sequence_ends(self) -> None:
        source = inspect.getsource(sequence.execute_sequences)
        self.assertIn("values.clear()", source)


@slow("stands up a loopback HTTP server and runs the engine against it")
class SequenceTransientTest(unittest.TestCase):
    """Sequences grade on their own path, and inherited none of the fix.

    `core._grade_check` stopped reading a 429 as an authorization failure; this
    module kept doing it, because the two share a message string and not the
    logic behind it. A rate limit on an assert step came out `vulnerable` --
    the product asserting a boundary failure from a throttle, on the surface
    that also WRITES to the target.
    """

    def _verdict(self, status: int, declared: list[int]):
        def responder(method, path, token, body):
            return (status, _JSON, b"{}")

        config = _config(
            [{"id": "s", "steps": [_step("assert", "attacker", "GET", "/c", declared)]}],
            marker=False,
        )
        with _server(responder) as url:
            result = _run(config, url)
        findings = result["findings"]
        return findings[0]["verdict"] if findings else None

    def test_a_throttle_or_a_server_error_establishes_nothing(self) -> None:
        for status in (429, 500, 502, 503, 504):
            with self.subTest(status=status):
                self.assertEqual(self._verdict(status, [403]), "inconclusive")

    def test_a_real_denial_still_matches(self) -> None:
        self.assertIsNone(self._verdict(403, [403]))

    def test_a_real_leak_is_still_vulnerable(self) -> None:
        """The suppression must not cost the signal it exists beside."""
        self.assertEqual(self._verdict(200, [403]), "vulnerable")

    def test_a_declared_transient_still_matches(self) -> None:
        """If the operator declared 503, receiving 503 is agreement, not doubt."""
        self.assertIsNone(self._verdict(503, [503]))

    def test_the_message_says_it_is_not_evidence_in_either_direction(self) -> None:
        def responder(method, path, token, body):
            return (429, _JSON, b"{}")

        config = _config(
            [{"id": "s", "steps": [_step("assert", "attacker", "GET", "/c", [403])]}],
            marker=False,
        )
        with _server(responder) as url:
            result = _run(config, url)
        message = result["findings"][0]["message"]
        self.assertIn("not an answer from the authorization layer", message)
        self.assertIn("in either direction", message)


@slow("stands up a loopback HTTP server and runs the engine against it")
class SequenceTransientMarkerTest(unittest.TestCase):
    """A leak inside a 500 is still a leak.

    The transient rule says a 429 or a 5xx is not an answer from the
    authorization layer. That is true about the STATUS and says nothing about
    the body, so the one carve-out is a marker actually observed: measured data
    flow outranks status semantics, exactly as it does in `core._grade_check`.

    Without this the claim lived only in a comment -- and removing the carve-out
    left every other test in this module green.
    """

    def _run_with_marker_in(self, status: int) -> list[dict]:
        def responder(method, path, token, body):
            return (status, _JSON, MARKER_OWNER.encode())

        config = _config(
            [{
                "id": "s",
                "steps": [_step("assert", "attacker", "GET", "/c", [403],
                                excludes_marker="owner")],
            }],
        )
        with _server(responder) as url:
            return _run(config, url)["findings"]

    def test_a_marker_in_a_throttled_response_is_still_a_finding(self) -> None:
        findings = self._run_with_marker_in(429)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["verdict"], "vulnerable")
        self.assertEqual(findings[0]["evidence_grade"], "confirmed")

    def test_a_marker_in_a_server_error_is_still_a_finding(self) -> None:
        findings = self._run_with_marker_in(503)
        self.assertEqual(findings[0]["evidence_grade"], "confirmed")

    def test_without_the_marker_the_same_status_is_inconclusive(self) -> None:
        """The control: it is the BODY that changes the answer, not the code."""
        def responder(method, path, token, body):
            return (429, _JSON, b"{}")

        config = _config(
            [{
                "id": "s",
                "steps": [_step("assert", "attacker", "GET", "/c", [403],
                                excludes_marker="owner")],
            }],
        )
        with _server(responder) as url:
            findings = _run(config, url)["findings"]
        self.assertEqual(findings[0]["verdict"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
