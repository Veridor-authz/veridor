"""Marker oracle: encoding, transport, truncation, grading, and safety."""

from __future__ import annotations

import base64
import contextlib
import gzip
import html
import inspect
import io
import json
import re
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
import zlib
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from scripts import demo_server  # noqa: E402
import loopback  # noqa: E402
from tiers import fast, slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402
from veridor.core import (  # noqa: E402
    ConfigError,
    _compare_findings,
    _finding_id,
    _scan_response,
    execute_run,
    generate_marker,
    load_config,
    load_run,
    marker_needles,
    to_sarif,
    validate_marker,
)

MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
OTHER_MARKER = "vdr-Pq4Wz8Jn2Hc6Yt0Bm5Kd7Rx3"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _scan(payload: bytes, marker: str | None = MARKER, encoding: str | None = None):
    """Scan an in-memory payload and return the raw ``_scan_response`` tuple."""
    needles = marker_needles(marker) if marker else None
    return _scan_response(io.BytesIO(payload), encoding, needles)


def _state(payload: bytes, marker: str | None = MARKER, encoding: str | None = None):
    """Return ``(state, reason, encodings_matched)`` for a payload."""
    _, _, state, reason, encodings, _, _, _ = _scan(payload, marker, encoding)
    return state, reason, encodings


@contextlib.contextmanager
def _server(responder):
    """Run a loopback server; ``responder(path, token)`` returns a response.

    Returning ``None`` from the responder drops the connection, which is how the
    transport-failure paths are exercised.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback
            reply = responder(self.path, self.headers.get("Authorization", ""))
            if reply is None:
                self.close_connection = True
                return
            status, headers, body = reply
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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


@contextlib.contextmanager
def _raw_server(handler):
    """Serve verbatim bytes on a loopback socket.

    ``handler(request_bytes)`` returns the exact bytes to put on the wire, then
    the connection is closed. Needed for responses ``http.server`` cannot
    produce: a body cut short of its declared ``Content-Length``, or a first
    line that is not an HTTP status line at all.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)

    def serve() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                payload = handler(connection.recv(65536))
                if payload:
                    connection.sendall(payload)
            except OSError:
                pass
            finally:
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        listener.close()
        thread.join(timeout=5)


def _gzip_member(payload: bytes) -> bytes:
    """One complete gzip member. Concatenated members are legal gzip."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as stream:
        stream.write(payload)
    return buffer.getvalue()


def _probe(url: str, path: str = "/records/1", marker: str | None = MARKER) -> dict:
    return core._execute_probe(
        url,
        5,
        {"id": "records", "request": {"method": "GET", "path": path}},
        "owner",
        {"headers": {}},
        marker=marker,
    )


#: Tokens a leak fixture recognises. Anything else -- notably the fabricated
#: `veridor-sham-…` credential `run` now issues -- is a caller the target does
#: not know, and must not be handed the owner's marker.
#:
#: Without this gate a fixture models a string ANY caller can read, which is
#: not a leak: it is a public build id, and `confirmed` on it was the defect.
#: Modelling ownership is what makes these fixtures
#: tests of a leak rather than tests of a coincidence.
KNOWN_TOKENS = ("Bearer owner-token", "Bearer outsider-token")


def _known(token: str) -> bool:
    return token in KNOWN_TOKENS


def _base_config(markers: bool = True) -> dict:
    owner: dict = {"headers": {"Authorization": "Bearer owner-token"}}
    expect_owner: dict = {"status": [200]}
    expect_outsider: dict = {"status": [404]}
    if markers:
        owner["marker"] = MARKER
        expect_owner["contains_marker"] = "owner"
        expect_outsider["excludes_marker"] = "owner"
    return {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 3},
        "identities": {
            "owner": owner,
            "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
        },
        "checks": [
            {
                "id": "records",
                "name": "Record isolation",
                "request": {"method": "GET", "path": "/records/1"},
                "expect": {"owner": expect_owner, "outsider": expect_outsider},
            }
        ],
    }


class _TempConfig:
    """Write a config dict to a throwaway directory."""

    def __init__(self, config: dict) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.path = self.root / "veridor.json"
        self.path.write_text(json.dumps(config), encoding="utf-8")

    def close(self) -> None:
        self._directory.cleanup()


def _run(config: dict, base_url: str) -> dict:
    holder = _TempConfig(config)
    try:
        return execute_run(
            holder.path, output_dir=holder.root / "out", base_url=base_url
        )
    finally:
        holder.close()


def _finding(result: dict, identity: str, check_id: str | None = None) -> dict:
    for finding in result["findings"]:
        if finding["identity"] == identity and (
            check_id is None or finding["check_id"] == check_id
        ):
            return finding
    raise AssertionError(f"no finding for {identity!r} / {check_id!r}")


def _json_body(value: dict) -> bytes:
    return json.dumps(value).encode()


# --------------------------------------------------------------------------
# (h) fingerprint safety - the most important tests in this file
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class FingerprintStabilityTest(unittest.TestCase):
    @fast("asserts on the declaration, not on a live target")
    def test_finding_id_is_byte_stable(self) -> None:
        invoice = {
            "id": "invoice-tenant-isolation",
            "request": {"method": "GET", "path": "/api/invoices/inv-100"},
        }
        export = {
            "id": "invoice-export-isolation",
            "request": {"method": "GET", "path": "/api/exports/acme.json"},
        }
        compressed = {
            "id": "invoice-compressed-view",
            "request": {"method": "GET", "path": "/api/invoices/inv-100/compressed"},
        }
        self.assertEqual(
            _finding_id(invoice, "other_tenant", "status", [404]),
            "0ec4c5cbd79deaed6e9f",
        )
        self.assertEqual(
            _finding_id(invoice, "other_tenant", "marker", [404]),
            "adeafb773a0e3db5ec0d",
        )
        self.assertEqual(
            _finding_id(invoice, "invoice_owner", "oracle", [200]),
            "7dc5df758e10f202cfd7",
        )
        self.assertEqual(
            _finding_id(invoice, "other_tenant", "execution", [404]),
            "dd1f4540a02c694fc62c",
        )
        self.assertEqual(
            _finding_id(export, "other_tenant", "status", [404]),
            "47bf6278ef1165bf0c7f",
        )
        self.assertEqual(
            _finding_id(compressed, "other_tenant", "status", [404]),
            "5c71c61559dc460ca9f6",
        )

    def test_marker_config_does_not_perturb_finding_id(self) -> None:
        """Adding a marker oracle must not renumber an existing finding."""
        plain = _base_config(markers=False)
        marked = _base_config(markers=True)
        check_plain = plain["checks"][0]
        check_marked = marked["checks"][0]
        self.assertEqual(
            _finding_id(check_plain, "outsider", "status", [404]),
            _finding_id(check_marked, "outsider", "status", [404]),
        )

        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {"Content-Type": "application/json"}, _json_body({"m": MARKER}))

        with _server(responder) as url:
            without = _run(plain, url)
            with_marker = _run(marked, url)
        self.assertEqual(
            _finding(without, "outsider")["id"],
            _finding(with_marker, "outsider")["id"],
        )
        self.assertEqual(_finding(without, "outsider")["evidence_grade"], "ungraded")
        self.assertEqual(_finding(with_marker, "outsider")["evidence_grade"], "confirmed")

    def test_config_without_markers_states_observation_and_declaration_only(
        self,
    ) -> None:
        """A marker-free finding reports what was seen and what was declared.

        Byte-stable on purpose. With no marker there is no evidence of data
        flow at all, so the message must not gesture at one, and the two halves
        must stay attributed: the status is Veridor's observation, the list is
        the operator's declaration.
        """

        def responder(path, token):
            return (200, {}, b"{}")

        with _server(responder) as url:
            result = _run(_base_config(markers=False), url)
        message = _finding(result, "outsider")["message"]
        self.assertEqual(
            message,
            "Identity 'outsider' received HTTP 200 (declared: one of [404]).",
        )
        self.assertNotIn("marker", message)
        self.assertEqual(result["summary"]["ungraded"], 1)
        self.assertEqual(result["regression"]["escalated"], [])

    def test_message_text_is_not_part_of_the_fingerprint(self) -> None:
        """Rewording a finding must never renumber it.

        Message wording is the one part of a finding that is expected to keep
        improving. If it reached ``_finding_id`` every prose edit would report
        a user's whole suite as new and destroy their baseline, so the same
        check/identity/kind/statuses must fingerprint identically no matter how
        differently the finding reads.
        """
        config = _base_config()

        def leaking(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body({"ref": MARKER}))

        def granting(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"rows": [{"ref": MARKER}]}))
            return (200, {}, _json_body({"rows": []}))

        with _server(leaking) as url:
            confirmed = _finding(_run(config, url), "outsider")
        with _server(granting) as url:
            suspected = _finding(_run(config, url), "outsider")

        self.assertNotEqual(confirmed["message"], suspected["message"])
        self.assertNotEqual(
            confirmed["evidence_grade"], suspected["evidence_grade"]
        )
        self.assertEqual(confirmed["id"], suspected["id"])
        self.assertEqual(
            confirmed["id"],
            _finding_id(config["checks"][0], "outsider", "status", [404]),
        )
        # Belt and braces: the signature has no channel for prose to enter by.
        self.assertNotIn(
            "message",
            inspect.signature(_finding_id).parameters,
        )
        source = inspect.getsource(_finding_id)
        for field in ("message", "title", "remediation"):
            self.assertNotIn(field, source)

    @fast("asserts on the declaration, not on a live target")
    def test_leak_and_status_findings_have_distinct_ids(self) -> None:
        check = _base_config()["checks"][0]
        ids = {
            kind: _finding_id(check, "outsider", kind, [404])
            for kind in ("status", "marker", "oracle", "execution")
        }
        self.assertEqual(len(set(ids.values())), 4)


# --------------------------------------------------------------------------
# (e) marker quality
# --------------------------------------------------------------------------


class MarkerQualityTest(unittest.TestCase):
    def test_accepts_a_strong_marker(self) -> None:
        self.assertEqual(validate_marker(MARKER, "marker"), MARKER)
        self.assertEqual(validate_marker(OTHER_MARKER, "marker"), OTHER_MARKER)

    def test_rejects_weak_markers(self) -> None:
        cases = {
            "type": 12345,
            "short": "admin",
            "short-canary": "veridor-canary-a1b2c3",
            "long": "a" * 129,
            "charset": "vdr.Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
            "distinct": "adminadminadminadminadmi",
            "single-char": "0" * 32,
            "run": "vdr-aaaaaaaaXk7Qm2Ls9Rt4Vb8",
            "periodic": "ab" * 14,
        }
        for label, value in cases.items():
            with self.subTest(gate=label):
                with self.assertRaises(ConfigError) as raised:
                    validate_marker(value, "identity 'owner' marker")
                self.assertTrue(
                    str(raised.exception).endswith(
                        " Generate one with: veridor new-marker"
                    ),
                    str(raised.exception),
                )

    def test_rejects_low_entropy_hex_marker(self) -> None:
        """The 0.66% hex case fails closed with an actionable message."""
        with self.assertRaisesRegex(ConfigError, "distinct characters"):
            validate_marker("abc123abc123abc123abc123", "marker")

    def test_boundary_lengths(self) -> None:
        self.assertEqual(len(validate_marker("aB3-dE6_gH9jK2mN5pQ8sT1v", "m")), 24)
        with self.assertRaises(ConfigError):
            validate_marker("aB3-dE6_gH9jK2mN5pQ8sT1", "m")

    def test_generate_marker_always_passes_validation(self) -> None:
        for _ in range(1000):
            marker = generate_marker()
            self.assertEqual(validate_marker(marker, "generated"), marker)
            self.assertTrue(marker.startswith("vdr-"))
            self.assertEqual(len(marker), 28)

    def test_demo_server_marker_is_strong(self) -> None:
        self.assertEqual(
            validate_marker(demo_server.OWNER_MARKER, "demo"),
            demo_server.OWNER_MARKER,
        )

    def test_demo_fixture_marker_matches_demo_server(self) -> None:
        fixture = json.loads(
            (ROOT / "fixtures" / "veridor.demo.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            fixture["identities"]["invoice_owner"]["marker"],
            demo_server.OWNER_MARKER,
        )


# --------------------------------------------------------------------------
# (a) encoding
# --------------------------------------------------------------------------


class EncodingTest(unittest.TestCase):
    def test_needles_are_lowercased_variants(self) -> None:
        needles = marker_needles(MARKER)
        self.assertEqual(needles[0], MARKER.lower().encode())
        self.assertEqual(needles[1], MARKER.lower().encode("utf-16-le"))
        self.assertEqual(needles[2], MARKER.lower().encode("utf-16-be"))

    def test_json_escaping_is_an_identity_transform(self) -> None:
        body = json.dumps({"customer_ref": MARKER}).encode()
        self.assertIn(MARKER.encode(), body)
        self.assertEqual(_state(body)[0], "present")

    def test_html_escaping_is_an_identity_transform(self) -> None:
        body = html.escape(f'<span data-ref="{MARKER}">{MARKER}</span>').encode()
        self.assertEqual(_state(body)[0], "present")

    def test_percent_encoding_is_an_identity_transform(self) -> None:
        self.assertEqual(quote(MARKER, safe=""), MARKER)
        body = f'{{"next":"/records?ref={quote(MARKER, safe="")}"}}'.encode()
        self.assertEqual(_state(body)[0], "present")

    def test_pretty_printed_json_still_matches(self) -> None:
        body = json.dumps({"rows": [{"ref": MARKER}]}, indent=4).encode()
        self.assertEqual(_state(body)[0], "present")

    def test_csv_and_xml_quoting_still_match(self) -> None:
        self.assertEqual(_state(f'id,ref\n1,"{MARKER}"\n'.encode())[0], "present")
        self.assertEqual(_state(f"<ref>{MARKER}</ref>".encode())[0], "present")

    def test_match_is_case_insensitive(self) -> None:
        state, _, encodings = _state(f'{{"ref":"{MARKER.upper()}"}}'.encode())
        self.assertEqual(state, "present")
        self.assertEqual(encodings, ["ascii"])

    def test_case_folding_leaves_non_ascii_bytes_untouched(self) -> None:
        high = bytes(range(0x80, 0x100))
        self.assertEqual(high.lower(), high)

    def test_matches_in_utf16_bodies(self) -> None:
        # Inside a larger UTF-16 document the opposite-endian needle also
        # matches, offset by one byte, because every ASCII character is padded
        # with NUL on both sides. That aliasing widens the label set, never the
        # verdict: the marker really is in these bytes.
        le_state, _, le_encodings = _state(
            f'{{"ref":"{MARKER}"}}'.encode("utf-16-le")
        )
        self.assertEqual(le_state, "present")
        self.assertIn("utf-16le", le_encodings)
        self.assertNotIn("ascii", le_encodings)
        be_state, _, be_encodings = _state(
            f'{{"ref":"{MARKER}"}}'.encode("utf-16-be")
        )
        self.assertEqual(be_state, "present")
        self.assertIn("utf-16be", be_encodings)
        self.assertNotIn("ascii", be_encodings)

    def test_bare_utf16le_marker_matches_only_the_little_endian_needle(self) -> None:
        state, _, encodings = _state(MARKER.encode("utf-16-le"))
        self.assertEqual(state, "present")
        self.assertEqual(encodings, ["utf-16le"])

    def test_matches_inside_a_binary_payload(self) -> None:
        body = b"%PDF-1.7\n\x00\x01\xff\xfe" + MARKER.encode() + b"\x00\xc3\x28endobj"
        self.assertEqual(_state(body)[0], "present")

    def test_utf8_multibyte_haystack_is_safe(self) -> None:
        body = ("héllo wörld " + MARKER + " ☃").encode("utf-8")
        self.assertEqual(_state(body)[0], "present")

    def test_base64_jwt_and_hex_embeddings_are_documented_misses(self) -> None:
        b64 = base64.b64encode(MARKER.encode())
        payload = base64.urlsafe_b64encode(json.dumps({"ref": MARKER}).encode())
        jwt = b"eyJhbGciOiJub25lIn0." + payload + b".sig"
        hexed = MARKER.encode().hex().encode()
        for label, body in (("base64", b64), ("jwt", jwt), ("hex", hexed)):
            with self.subTest(encoding=label):
                # A miss, never a false confirmation: we under-claim by design.
                self.assertEqual(_state(body)[0], "absent")

    def test_empty_body_is_absent_not_unknown(self) -> None:
        self.assertEqual(_state(b""), ("absent", None, []))

    def test_no_oracle_leaves_every_marker_field_empty(self) -> None:
        _, _, state, reason, encodings, encoding, scanned, truncated = _scan(
            b'{"ref":"anything"}', marker=None
        )
        self.assertIsNone(state)
        self.assertIsNone(reason)
        self.assertEqual(encodings, [])
        self.assertEqual(encoding, "identity")
        self.assertEqual(scanned, 0)
        self.assertFalse(truncated)


# --------------------------------------------------------------------------
# (b) transport
# --------------------------------------------------------------------------


class TransportTest(unittest.TestCase):
    def test_gzip_is_decoded_and_scanned(self) -> None:
        body = gzip.compress(_json_body({"ref": MARKER}))
        retained, _, state, reason, _, encoding, scanned, _ = _scan(
            body, encoding="gzip"
        )
        self.assertEqual(state, "present")
        self.assertIsNone(reason)
        self.assertEqual(encoding, "gzip")
        self.assertGreater(scanned, 0)
        self.assertEqual(retained, body, "digest must cover the compressed wire bytes")

    def test_x_gzip_and_deflate_are_supported(self) -> None:
        payload = _json_body({"ref": MARKER})
        self.assertEqual(
            _state(gzip.compress(payload), encoding="x-gzip")[0], "present"
        )
        self.assertEqual(
            _state(zlib.compress(payload), encoding=" Deflate ")[0], "present"
        )

    def test_unsupported_encoding_is_unknown_not_absent(self) -> None:
        for value in ("br", "zstd", "compress", "gzip, br"):
            with self.subTest(content_encoding=value):
                _, _, state, reason, _, encoding, _, _ = _scan(
                    b"anything", encoding=value
                )
                self.assertEqual(state, "unknown")
                self.assertEqual(reason, "encoding_unsupported")
                self.assertEqual(encoding, "unsupported")

    def test_raw_headerless_deflate_fails_closed(self) -> None:
        raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        body = raw.compress(_json_body({"ref": MARKER})) + raw.flush()
        _, _, state, reason, _, encoding, _, _ = _scan(body, encoding="deflate")
        self.assertEqual(state, "unknown")
        self.assertEqual(reason, "decode_failed")
        self.assertEqual(encoding, "unsupported")

    def test_truncated_gzip_stream_is_never_evidence_of_absence(self) -> None:
        # Incompressible payload, so the wire stream is much longer than the
        # prefix we hand back and the member genuinely ends mid-stream.
        complete = gzip.compress(secrets.token_bytes(200_000))
        self.assertGreater(len(complete), 4096)
        _, _, state, reason, _, _, _, _ = _scan(complete[:2048], encoding="gzip")
        self.assertEqual(state, "unknown")
        self.assertEqual(reason, "decode_failed")

    def test_complete_gzip_stream_without_the_marker_is_absent(self) -> None:
        body = gzip.compress(_json_body({"ref": "someone-else"}))
        _, _, state, reason, _, _, _, _ = _scan(body, encoding="gzip")
        self.assertEqual(state, "absent")
        self.assertIsNone(reason)

    def test_multi_member_gzip_is_scanned_past_the_first_member(self) -> None:
        """One decompressobj stops at member 1 and parks the rest in unused_data.

        Concatenated members are legal gzip (RFC 1952 2.2) and are what
        streaming producers emit. Scanning only member 1 and then reporting
        'absent' is a positive claim about a body that was never decoded.
        """
        for members in (2, 3, 5):
            with self.subTest(members=members):
                body = b"".join(
                    _gzip_member(_json_body({"page": index}))
                    for index in range(members - 1)
                ) + _gzip_member(_json_body({"ref": MARKER}))
                self.assertIn(MARKER.encode(), gzip.decompress(body))
                _, _, state, reason, _, _, _, _ = _scan(body, encoding="gzip")
                self.assertEqual(state, "present")
                self.assertIsNone(reason)

    def test_multi_member_gzip_without_the_marker_is_absent(self) -> None:
        body = _gzip_member(b'{"page":1}') + _gzip_member(b'{"page":2}')
        _, _, state, reason, _, _, scanned, _ = _scan(body, encoding="gzip")
        self.assertEqual(state, "absent")
        self.assertIsNone(reason)
        self.assertEqual(scanned, len(gzip.decompress(body)))

    def test_multi_member_gzip_split_across_read_chunks(self) -> None:
        body = _gzip_member(b"." * 400) + _gzip_member(_json_body({"ref": MARKER}))
        with patch.object(core, "_CHUNK_BYTES", 7):
            self.assertEqual(_state(body, encoding="gzip")[0], "present")

    def test_trailing_bytes_after_a_gzip_member_are_not_absence(self) -> None:
        body = _gzip_member(_json_body({"ref": "someone-else"})) + b"NOT-GZIP"
        _, _, state, reason, _, _, _, _ = _scan(body, encoding="gzip")
        self.assertEqual(state, "unknown")
        self.assertEqual(reason, "decode_failed")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_short_content_length_body_is_never_evidence_of_absence(self) -> None:
        """A body cut short on the wire cannot prove the marker is absent.

        http.client returns b'' rather than raising IncompleteRead when a
        Content-Length body ends early, so the read loop sees a normal EOF.
        """
        full = _json_body({"pad": "." * 800, "ref": MARKER})

        def handler(request: bytes) -> bytes:
            head = (
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(full)
            )
            return head + full[:32]

        with _raw_server(handler) as url:
            probe = _probe(url)
        response = probe["response"]
        self.assertIsNone(probe["error"])
        self.assertEqual(response["status"], 200)
        self.assertLess(response["body_bytes"], len(full))
        self.assertEqual(response["marker_scan"], "unknown")
        self.assertEqual(response["marker_scan_reason"], "incomplete_body")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_a_complete_content_length_body_still_reports_absent(self) -> None:
        """The control for the test above: a whole body is still falsifiable."""
        full = _json_body({"ref": "someone-else"})

        def handler(request: bytes) -> bytes:
            head = (
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(full)
            )
            return head + full

        with _raw_server(handler) as url:
            probe = _probe(url)
        self.assertEqual(probe["response"]["marker_scan"], "absent")
        self.assertIsNone(probe["response"]["marker_scan_reason"])

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_bodiless_and_error_responses_are_not_called_incomplete(self) -> None:
        """The short-read guard must not fire where there is nothing to read.

        http.client zeroes `length` for HEAD/204/304 up front, and HTTPError
        delegates it to the same response object, so every one of these is a
        complete body and stays falsifiable.
        """
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - stdlib callback
                code = int(self.path.strip("/"))
                body = _json_body({"note": "no marker here"})
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_HEAD(self) -> None:  # noqa: N802 - stdlib callback
                self.send_response(200)
                self.send_header("Content-Length", "1234")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = loopback.start(server)
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            for code in (200, 204, 304, 401, 403, 404, 500):
                with self.subTest(status=code):
                    probe = _probe(url, path=f"/{code}")
                    self.assertEqual(probe["response"]["marker_scan"], "absent")
                    self.assertIsNone(probe["response"]["marker_scan_reason"])
            head = core._execute_probe(
                url,
                5,
                {"id": "c", "request": {"method": "HEAD", "path": "/200"}},
                "owner",
                {"headers": {}},
                marker=MARKER,
            )
            self.assertEqual(head["response"]["marker_scan"], "absent")
            self.assertIsNone(head["response"]["marker_scan_reason"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_truncated_body_downgrades_the_run_instead_of_passing(self) -> None:
        """End to end: a severed shared-list response must not grade 'safe'.

        Both identities get HTTP 200 from a shared collection endpoint -- the
        documented excludes_marker shape -- and the outsider's body is cut
        short. Reporting 'absent' would make a real leak a passing run.
        """
        full = _json_body({"pad": "." * 800, "ref": MARKER})

        def handler(request: bytes) -> bytes:
            head = (
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(full)
            )
            if b"owner-token" in request:
                return head + full
            return head + full[:32]

        config = _base_config()
        config["checks"][0]["expect"]["outsider"]["status"] = [200]
        with _raw_server(handler) as url:
            result = _run(config, url)
        outsider = _finding(result, "outsider")
        self.assertEqual(outsider["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(outsider["verdict"], "inconclusive")
        self.assertEqual(
            outsider["evidence"]["marker"]["reason"], "incomplete_body"
        )
        self.assertNotEqual(result["status"], "passed")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_multi_member_gzip_leak_is_confirmed_end_to_end(self) -> None:
        """The owner's body is one member; the outsider's leak is in member 2."""
        owner_body = gzip.compress(_json_body({"ref": MARKER}))
        outsider_body = _gzip_member(_json_body({"page": 1})) + _gzip_member(
            _json_body({"ref": MARKER})
        )

        def responder(path, token):
            # Ownership modelled (see KNOWN_TOKENS): the fabricated credential
            # that now checks the marker's uniqueness on this 2xx check is
            # refused, as a stranger is.
            if not _known(token):
                return (404, {}, b"{}")
            body = owner_body if "owner-token" in token else outsider_body
            return (200, {"Content-Encoding": "gzip"}, body)

        config = _base_config()
        config["checks"][0]["expect"]["outsider"]["status"] = [200]
        with _server(responder) as url:
            result = _run(config, url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(finding["evidence"]["marker"]["state"], "present")

    def test_identity_and_missing_encodings_scan_the_wire(self) -> None:
        body = _json_body({"ref": MARKER})
        for value in (None, "", "identity", " IDENTITY "):
            with self.subTest(content_encoding=value):
                _, _, state, _, _, encoding, _, _ = _scan(body, encoding=value)
                self.assertEqual(state, "present")
                self.assertEqual(encoding, "identity")

    def test_decompression_bomb_is_bounded_by_the_scan_ceiling(self) -> None:
        bomb = gzip.compress(b"\x00" * (4 * 1024 * 1024))
        self.assertLess(len(bomb), 64 * 1024)
        with patch.object(core, "_MAX_MARKER_SCAN_BYTES", 4096):
            _, _, state, reason, _, _, scanned, scan_truncated = _scan(
                bomb, encoding="gzip"
            )
        self.assertEqual(state, "unknown")
        self.assertEqual(reason, "truncated")
        self.assertTrue(scan_truncated)
        self.assertLessEqual(scanned, 4096)

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_probe_requests_identity_encoding(self) -> None:
        seen: list[str] = []

        def responder(path, token):
            return (200, {}, b"{}")

        class Recorder(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self) -> None:  # noqa: N802
                seen.extend(self.headers.get_all("Accept-Encoding") or [])
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        thread = loopback.start(server)
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            config = _base_config()
            config["checks"][0]["request"]["headers"] = {"Accept-Encoding": "identity"}
            _run(config, url)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {"identity"})
        # 3, not 2: the liveness control is a third request and carries the
        # same transport headers as any other probe.
        self.assertEqual(len(seen), 3, "exactly one Accept-Encoding header per probe")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_gzip_leak_is_confirmed_end_to_end(self) -> None:
        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            leaked = _json_body({"ref": MARKER})
            return (200, {"Content-Encoding": "gzip"}, gzip.compress(leaked))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(finding["evidence"]["marker"]["state"], "present")
        self.assertEqual(finding["evidence"]["response"]["body_encoding"], "gzip")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_unsupported_encoding_grades_suspected_never_confirmed(self) -> None:
        def responder(path, token):
            return (200, {"Content-Encoding": "br"}, b"\x8b\x00\x80leaked")

        with _server(responder) as url:
            result = _run(_base_config(), url)
        outsider = _finding(result, "outsider")
        self.assertEqual(outsider["evidence_grade"], "suspected")
        self.assertEqual(outsider["evidence"]["marker"]["reason"], "encoding_unsupported")
        # The control also could not be verified, so it is reported too.
        owner = _finding(result, "owner")
        self.assertEqual(owner["rule_id"], "VERIDOR-ORACLE-001")
        self.assertNotIn(
            "confirmed",
            [finding["evidence_grade"] for finding in result["findings"]],
        )


@slow("stands up a loopback HTTP server and runs the engine against it")
class ErrorEvidenceTest(unittest.TestCase):
    """No response bytes reach disk, including through the exception path."""

    def test_a_non_http_first_line_is_never_persisted(self) -> None:
        """A TLS listener or wrong backend behind http:// hands us raw bytes.

        http.client.BadStatusLine's str() is the whole first line, bounded only
        by _MAXLINE (64 KiB), and it used to be copied verbatim into the run
        JSON, the SARIF message, stdout and the Actions annotation.
        """
        payload = json.dumps(
            {"customers": [{"name": "Jane Doe", "ssn": "123-45-6789"}] * 400}
        ).encode()

        def handler(request: bytes) -> bytes:
            return payload[:65000] + b"\r\n\r\n"

        with _raw_server(handler) as url:
            result = _run(_base_config(), url)

        serialized = json.dumps(result) + json.dumps(to_sarif(result))
        self.assertNotIn("123-45-6789", serialized)
        self.assertNotIn("Jane Doe", serialized)
        for probe in result["probes"]:
            self.assertIsNotNone(probe["error"])
            self.assertLessEqual(len(probe["error"]), 200)
            self.assertIn("status line", probe["error"])
        for finding in result["findings"]:
            self.assertEqual(finding["rule_id"], "VERIDOR-EXEC-001")


# --------------------------------------------------------------------------
# (c) truncation
# --------------------------------------------------------------------------


class TruncationTest(unittest.TestCase):
    def test_marker_split_across_read_chunks(self) -> None:
        body = b"x" * 37 + MARKER.encode() + b"y" * 11
        with patch.object(core, "_CHUNK_BYTES", 8):
            self.assertEqual(_state(body)[0], "present")

    def test_utf16_marker_split_across_read_chunks(self) -> None:
        body = b"\x00" * 5 + MARKER.encode("utf-16-le") + b"\x00" * 5
        with patch.object(core, "_CHUNK_BYTES", 8):
            self.assertEqual(_state(body)[0], "present")

    def test_marker_past_the_scan_ceiling_is_unknown(self) -> None:
        body = b"." * 4096 + MARKER.encode()
        with patch.object(core, "_MAX_MARKER_SCAN_BYTES", 512):
            _, _, state, reason, _, _, scanned, scan_truncated = _scan(body)
        self.assertEqual(state, "unknown")
        self.assertEqual(reason, "truncated")
        self.assertTrue(scan_truncated)
        self.assertLessEqual(scanned, 512)

    def test_presence_is_monotone_under_truncation(self) -> None:
        """A hit inside the scanned prefix stands even though the scan stopped."""
        body = MARKER.encode() + b"." * 4096
        with patch.object(core, "_MAX_MARKER_SCAN_BYTES", 512):
            _, _, state, reason, _, _, _, _ = _scan(body)
        self.assertEqual(state, "present")
        self.assertIsNone(reason)

    def test_marker_past_the_persistence_cap_but_inside_the_ceiling(self) -> None:
        body = b"." * (3 * 1024 * 1024) + MARKER.encode()
        retained, body_truncated, state, reason, _, _, scanned, scan_truncated = _scan(
            body
        )
        self.assertEqual(state, "present")
        self.assertIsNone(reason)
        self.assertTrue(body_truncated, "persistence window is still capped at 1 MiB")
        self.assertFalse(scan_truncated)
        self.assertEqual(len(retained), core._MAX_RESPONSE_BYTES + 1)
        self.assertGreater(scanned, core._MAX_RESPONSE_BYTES)

    def test_digest_window_is_unchanged_for_small_bodies(self) -> None:
        import hashlib

        body = _json_body({"ref": MARKER})
        retained, body_truncated, _, _, _, _, _, _ = _scan(body)
        self.assertFalse(body_truncated)
        self.assertEqual(
            hashlib.sha256(retained[: core._MAX_RESPONSE_BYTES]).hexdigest(),
            hashlib.sha256(body).hexdigest(),
        )

    def test_probe_without_an_oracle_reads_only_the_persistence_window(self) -> None:
        body = b"." * (3 * 1024 * 1024)
        _, body_truncated, state, _, _, _, scanned, _ = _scan(body, marker=None)
        self.assertTrue(body_truncated)
        self.assertIsNone(state)
        self.assertEqual(scanned, 0)

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_truncated_scan_grades_suspected_when_the_status_fails(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            return (200, {}, b"." * 8192 + MARKER.encode())

        with patch.object(core, "_MAX_MARKER_SCAN_BYTES", 1024):
            with _server(responder) as url:
                result = _run(_base_config(), url)
        outsider = _finding(result, "outsider")
        self.assertEqual(outsider["evidence_grade"], "suspected")
        self.assertEqual(outsider["evidence"]["marker"]["state"], "unknown")
        self.assertEqual(outsider["evidence"]["marker"]["reason"], "truncated")

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_truncated_scan_with_a_passing_status_reports_the_oracle(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, b"." * 8192 + MARKER.encode())
            return (404, {}, b'{"error":"not found"}')

        with patch.object(core, "_MAX_MARKER_SCAN_BYTES", 1024):
            with _server(responder) as url:
                result = _run(_base_config(), url)
        owner = _finding(result, "owner")
        self.assertEqual(owner["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(owner["verdict"], "inconclusive")
        self.assertEqual(owner["evidence_grade"], "n/a")


# --------------------------------------------------------------------------
# (g) config validation - every failure is a load-time ConfigError
# --------------------------------------------------------------------------


class ConfigValidationTest(unittest.TestCase):
    def _load(self, config: dict) -> dict:
        holder = _TempConfig(config)
        try:
            return load_config(holder.path)
        finally:
            holder.close()

    def _reject(self, config: dict, pattern: str) -> None:
        with self.assertRaisesRegex(ConfigError, pattern):
            self._load(config)

    def test_valid_marker_config_loads(self) -> None:
        loaded = self._load(_base_config())
        self.assertEqual(loaded["identities"]["owner"]["marker"], MARKER)

    def test_unknown_identity_reference(self) -> None:
        config = _base_config()
        config["checks"][0]["expect"]["owner"]["contains_marker"] = "ghost"
        self._reject(config, "references unknown identity 'ghost'")

    def test_identity_without_a_marker_field(self) -> None:
        config = _base_config()
        del config["identities"]["owner"]["marker"]
        self._reject(config, "defines no 'marker' field")

    def test_exclusion_without_a_control(self) -> None:
        config = _base_config()
        del config["checks"][0]["expect"]["owner"]["contains_marker"]
        with self.assertRaises(ConfigError) as raised:
            self._load(config)
        message = str(raised.exception)
        self.assertIn("requires a control in the same check", message)
        self.assertIn('"contains_marker": "owner"', message)

    def test_control_naming_a_different_identity_is_not_a_control(self) -> None:
        config = _base_config()
        config["identities"]["third"] = {"headers": {}, "marker": OTHER_MARKER}
        config["checks"][0]["expect"]["owner"]["contains_marker"] = "third"
        self._reject(config, "requires a control in the same check")

    def test_contains_marker_for_another_identity_is_allowed(self) -> None:
        config = _base_config()
        config["identities"]["admin"] = {"headers": {"X-Role": "admin"}}
        config["checks"][0]["expect"]["admin"] = {
            "status": [200],
            "contains_marker": "owner",
        }
        loaded = self._load(config)
        self.assertEqual(
            loaded["checks"][0]["expect"]["admin"]["contains_marker"], "owner"
        )

    def test_both_contains_and_excludes(self) -> None:
        config = _base_config()
        config["checks"][0]["expect"]["outsider"]["contains_marker"] = "owner"
        self._reject(config, "cannot set both contains_marker and excludes_marker")

    def test_excludes_marker_naming_itself(self) -> None:
        config = _base_config()
        config["identities"]["outsider"]["marker"] = OTHER_MARKER
        config["checks"][0]["expect"]["outsider"]["excludes_marker"] = "outsider"
        self._reject(config, "cannot exclude its own marker")

    def test_marker_echoed_in_the_request_path(self) -> None:
        config = _base_config()
        config["checks"][0]["request"]["path"] = f"/search?q={MARKER}"
        self._reject(config, "appears in the request sent by check")

    def test_marker_echoed_in_the_request_body(self) -> None:
        config = _base_config()
        config["checks"][0]["request"]["method"] = "POST"
        config["checks"][0]["request"]["json"] = {"query": MARKER}
        self._reject(config, "appears in the request sent by check")

    def test_marker_echoed_in_a_request_header(self) -> None:
        config = _base_config()
        config["checks"][0]["request"]["headers"] = {"X-Trace": MARKER}
        self._reject(config, "appears in the request sent by check")

    def test_marker_echoed_in_an_identity_header(self) -> None:
        config = _base_config()
        config["identities"]["outsider"]["headers"]["X-Ref"] = MARKER.upper()
        self._reject(config, "appears in the request sent by check")

    def test_encoded_marker_in_the_request_is_rejected(self) -> None:
        """A literal substring test is defeated by any wire encoding.

        The target decodes a query string, a JSON escape, base64 and hex before
        it echoes them, so every one of these reflects the exact marker bytes
        back into the scan and grades a benign echo 'confirmed'.
        """
        cases = {
            "percent-encoded": lambda c: c["checks"][0]["request"].update(
                {"path": "/search?q=%76" + MARKER[1:]}
            ),
            "double-percent-encoded": lambda c: c["checks"][0]["request"].update(
                {"path": "/search?q=%2576" + MARKER[1:]}
            ),
            "plus-encoded": lambda c: c["checks"][0]["request"].update(
                {"path": "/search?q=" + quote(MARKER, safe="")}
            ),
            "json-escaped-body": lambda c: c["checks"][0]["request"].update(
                {"method": "POST", "body": '{"q":"\\u0076' + MARKER[1:] + '"}'}
            ),
            "html-entity-body": lambda c: c["checks"][0]["request"].update(
                {"method": "POST", "body": "&#118;" + MARKER[1:]}
            ),
            "base64-header": lambda c: c["checks"][0]["request"].update(
                {"headers": {"X-Q": base64.b64encode(MARKER.encode()).decode()}}
            ),
            "base64url-header": lambda c: c["checks"][0]["request"].update(
                {"headers": {"X-Q": base64.urlsafe_b64encode(MARKER.encode()).decode()}}
            ),
            "hex-header": lambda c: c["checks"][0]["request"].update(
                {"headers": {"X-Q": MARKER.encode().hex()}}
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(encoding=label):
                config = _base_config()
                mutate(config)
                self._reject(config, "appears in the request sent by check")

    def test_every_transmitted_component_is_inspected(self) -> None:
        """Method, header NAMES and base_url all reach the target and echo back.

        _HTTP_TOKEN, the alphabet accepted for a method and a header name, is a
        strict superset of the marker alphabet, so a marker is legal in either
        slot; BaseHTTPRequestHandler itself names an unsupported method in its
        error body.
        """
        cases = {
            "method": lambda c: c["checks"][0]["request"].update({"method": MARKER}),
            "request-header-name": lambda c: c["checks"][0]["request"].update(
                {"headers": {MARKER: "1"}}
            ),
            "identity-header-name": lambda c: c["identities"]["outsider"][
                "headers"
            ].update({MARKER: "1"}),
            "base-url-path": lambda c: c["target"].update(
                {"base_url": "http://127.0.0.1:1/" + MARKER}
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(component=label):
                config = _base_config()
                mutate(config)
                self._reject(config, "appears in the request sent by check")

    def test_ordinary_requests_are_not_rejected_by_the_reflection_guard(self) -> None:
        """The guard must not fire on requests that carry no marker."""
        config = _base_config()
        config["checks"][0]["request"].update(
            {
                "method": "POST",
                "path": "/search?q=alice%20smith&page=2",
                "json": {"filter": "status=open", "token": "abc123def456ghi789"},  # gitleaks:allow
                "headers": {"X-Trace": base64.b64encode(b"trace-id-9911").decode()},
            }
        )
        self.assertTrue(self._load(config))

    def test_duplicate_markers(self) -> None:
        config = _base_config()
        config["identities"]["outsider"]["marker"] = MARKER
        self._reject(config, "share the same marker")

    def test_substring_markers(self) -> None:
        config = _base_config()
        config["identities"]["outsider"]["marker"] = MARKER + "Zq"
        self._reject(config, "is a substring of identity")

    def test_typo_in_an_expect_key(self) -> None:
        config = _base_config()
        config["checks"][0]["expect"]["owner"]["contain_marker"] = "owner"
        self._reject(config, "has unsupported keys: contain_marker")

    def test_typo_in_an_identity_key(self) -> None:
        config = _base_config()
        config["identities"]["owner"]["markers"] = MARKER
        self._reject(config, "has unsupported keys: markers")

    def test_a_separator_or_a_capital_is_still_a_typo(self) -> None:
        """The guard normalised these ONTO a known key and then let them past.

        Every caller filters to unknown keys before calling, so a key that
        normalises onto a real one is the worst case in the set, not a safe
        one -- it is accepted at load and then misses at lookup, which runs the
        check with its marker oracle silently switched off. Against the
        vulnerable demo target that is the difference between exit 1 with the
        cross-tenant leak confirmed and exit 0 with '6/6 probes matched'.

        A dropped letter (``contain_marker``, covered above) was always caught.
        These are the likelier slips and were not.
        """
        for spelling in (
            "excludes_marker_",   # trailing underscore
            "Excludes_Marker",    # capitals
            "excludes-marker",    # hyphen for underscore
            "containsmarker",     # separator dropped entirely
        ):
            with self.subTest(spelling=spelling):
                config = _base_config()
                config["checks"][0]["expect"]["owner"][spelling] = "owner"
                self._reject(config, f"has unsupported keys: {spelling}")

    def test_accept_encoding_in_check_headers_loads(self) -> None:
        """Earlier releases accepted this, and _execute_probe overrides it anyway.

        Failing the load would break a previously valid configuration to prevent
        a value that provably cannot reach the wire.
        """
        config = _base_config()
        config["checks"][0]["request"]["headers"] = {"Accept-Encoding": "gzip"}
        self.assertTrue(self._load(config))

    def test_accept_encoding_in_identity_headers_loads(self) -> None:
        config = _base_config()
        config["identities"]["outsider"]["headers"]["accept-encoding"] = "gzip, br"
        self.assertTrue(self._load(config))

    def test_explicit_identity_accept_encoding_is_allowed(self) -> None:
        config = _base_config()
        config["identities"]["outsider"]["headers"]["Accept-Encoding"] = "identity"
        self.assertTrue(self._load(config))

    def test_annotation_keys_are_accepted_on_identities_and_expectations(self) -> None:
        """Regression: strict key rejection broke configurations v1 accepted.

        ``veridor init`` writes ``_comment`` into the config root and into every
        check, teaching that idiom; a user who applied it one level down got
        exit 2 with zero findings produced.
        """
        for key in ("_comment", "description", "note", "owner", "team"):
            with self.subTest(key=key):
                config = _base_config()
                config["identities"]["owner"][key] = "annotation"
                config["checks"][0]["expect"]["owner"][key] = "annotation"
                config["checks"][0][key] = "annotation"
                config["target"][key] = "annotation"
                self.assertTrue(self._load(config))

    def test_near_miss_of_a_real_key_still_fails_closed(self) -> None:
        """A typo of a real key fails silently, so it is still rejected."""
        cases = (
            ("identity", lambda c: c["identities"]["owner"].update({"markers": MARKER})),
            ("identity", lambda c: c["identities"]["owner"].update({"header": {}})),
            (
                "expectation",
                lambda c: c["checks"][0]["expect"]["owner"].update(
                    {"contain_marker": "owner"}
                ),
            ),
            (
                "expectation",
                lambda c: c["checks"][0]["expect"]["owner"].update(
                    {"exclude_marker": "owner"}
                ),
            ),
            (
                "expectation",
                lambda c: c["checks"][0]["expect"]["owner"].update({"statuses": [200]}),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                config = _base_config()
                mutate(config)
                self._reject(config, "has unsupported keys")

    def test_weak_marker_is_rejected_at_load(self) -> None:
        config = _base_config()
        config["identities"]["owner"]["marker"] = "admin"
        self._reject(config, "Generate one with: veridor new-marker")

    def test_weak_marker_exits_two_through_the_cli(self) -> None:
        import contextlib as _contextlib

        config = _base_config()
        config["identities"]["owner"]["marker"] = "0" * 32
        holder = _TempConfig(config)
        try:
            stderr = io.StringIO()
            with _contextlib.redirect_stderr(stderr):
                exit_code = veridor_main(
                    [
                        "run",
                        "--config",
                        str(holder.path),
                        "--output-dir",
                        str(holder.root / "out"),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("veridor new-marker", stderr.getvalue())
        finally:
            holder.close()

    def test_configs_without_markers_still_load(self) -> None:
        self.assertTrue(self._load(_base_config(markers=False)))


# --------------------------------------------------------------------------
# (f) grading cascade
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class GradingTest(unittest.TestCase):
    def test_confirmed_leak_with_a_failing_status(self) -> None:
        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body({"id": 1, "ref": MARKER}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-AUTHZ-001")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        # Strong where the evidence is strong: the flow was measured.
        self.assertIn(
            "declared marker was observed in 'outsider''s response",
            finding["message"],
        )
        self.assertIn("insofar as the marker is unique", finding["message"])
        # Silent where it is not: the declaration is never adjudicated. The
        # hedge disclaims the CORRECTNESS of the declaration, not its
        # existence -- the finding only exists because excludes_marker was
        # declared, so "whether X may see Y's data is your declaration" would
        # understate what the operator already wrote down.
        self.assertIn(
            "Whether that declaration is correct is not something Veridor can check",
            finding["message"],
        )
        self.assertIn(
            "You declared that 'outsider' must not receive 'owner''s data",
            finding["message"],
        )
        self.assertEqual(finding["evidence"]["marker"]["mode"], "excludes")
        self.assertEqual(finding["evidence"]["marker"]["owner_identity"], "owner")
        self.assertEqual(finding["evidence"]["marker"]["control_state"], "present")
        self.assertEqual(finding["evidence"]["marker"]["encodings_matched"], ["ascii"])

    def test_suspected_when_access_is_granted_but_nothing_crossed(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"rows": [{"ref": MARKER}]}))
            return (200, {}, _json_body({"rows": []}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["evidence_grade"], "suspected")
        self.assertIn("data exposure is unproven", finding["message"])
        self.assertIn("response did not contain it", finding["message"])
        self.assertEqual(finding["evidence"]["marker"]["state"], "absent")

    def test_marker_present_with_a_passing_status_is_a_finding(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            # Only a caller the target knows gets the owner's marker back. Sent
            # to every caller, it reached the sham too, which makes it a string
            # anybody can read -- `suspected`, not this test's `confirmed`.
            if _known(token):
                return (403, {}, _json_body({"error": f"cannot access invoice {MARKER}"}))
            return (403, {}, b"{}")

        config = _base_config()
        config["checks"][0]["expect"]["outsider"]["status"] = [403]
        with _server(responder) as url:
            result = _run(config, url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(finding["level"], "error")
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(
            finding["id"], _finding_id(config["checks"][0], "outsider", "marker", [403])
        )

    def test_control_failure_is_reported_and_downgrades_absence(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"id": "inv-100"}))
            return (404, {}, _json_body({"error": "not found"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        owner = _finding(result, "owner")
        self.assertEqual(owner["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(owner["verdict"], "inconclusive")
        self.assertEqual(owner["evidence_grade"], "n/a")
        self.assertIn("exclusion results for this check are unverified", owner["message"])
        # A correct 404 is no longer a clean pass, because absence is meaningless.
        outsider = _finding(result, "outsider")
        self.assertEqual(outsider["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(outsider["evidence"]["marker"]["control_state"], "absent")

    def test_control_failure_still_confirms_a_present_marker(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"id": "inv-100"}))
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body({"ref": MARKER}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        # Presence is presence: a broken control downgrades absence only.
        self.assertEqual(_finding(result, "outsider")["evidence_grade"], "confirmed")

    def test_control_failure_downgrades_a_failing_status_to_suspected(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"id": "inv-100"}))
            return (200, {}, _json_body({"id": "inv-100"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        outsider = _finding(result, "outsider")
        self.assertEqual(outsider["evidence_grade"], "suspected")
        self.assertIn(
            "the control probe did not observe its own marker", outsider["message"]
        )

    def test_control_transport_failure_degrades_the_whole_check(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return None
            return (404, {}, _json_body({"error": "not found"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        owner = _finding(result, "owner")
        self.assertEqual(owner["rule_id"], "VERIDOR-EXEC-001")
        self.assertEqual(owner["evidence_grade"], "n/a")
        self.assertEqual(owner["evidence"]["marker"]["state"], "unknown")
        self.assertEqual(owner["evidence"]["marker"]["reason"], "request_failed")
        outsider = _finding(result, "outsider")
        self.assertEqual(outsider["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(outsider["evidence"]["marker"]["control_state"], "unknown")

    def test_contains_marker_never_confirms_a_failed_status(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (500, {}, _json_body({"ref": MARKER}))
            return (404, {}, _json_body({"error": "not found"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        owner = _finding(result, "owner")
        # The point of this test -- a marker in a FAILED-status response never
        # upgrades the grade -- still holds, and now holds harder. A 500 is not
        # an answer from the authorization layer at all, so the probe is
        # unmeasured rather than a weakly-graded finding. The carve-out that
        # lets a marker outrank the status is for `excludes_marker`, where a
        # marker present means another identity's data came back; here the
        # owner is seeing its OWN marker, which proves nothing either way.
        self.assertEqual(owner["rule_id"], "VERIDOR-EXEC-001")
        self.assertEqual(owner["verdict"], "inconclusive")
        self.assertNotEqual(owner["evidence_grade"], "confirmed")
        self.assertIn("not an answer from the authorization layer", owner["message"])

    def test_clean_pass_emits_no_finding(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            return (404, {}, b"")

        with _server(responder) as url:
            result = _run(_base_config(), url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["safe"], 2)

    def test_at_most_one_finding_per_probe(self) -> None:
        def responder(path, token):
            if path == "/records/1" and token == "Bearer owner-token":
                return (500, {}, _json_body({"ref": MARKER}))
            if path == "/records/1":
                return (200, {}, _json_body({"ref": MARKER}))
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"id": 2}))
            return None

        config = _base_config()
        config["checks"].append(
            {
                "id": "other-records",
                "request": {"method": "GET", "path": "/records/2"},
                "expect": {
                    "owner": {"status": [200], "contains_marker": "owner"},
                    "outsider": {"status": [404], "excludes_marker": "owner"},
                },
            }
        )
        with _server(responder) as url:
            result = _run(config, url)
        summary = result["summary"]
        self.assertEqual(summary["probes"], 4)
        self.assertEqual(summary["safe"], summary["probes"] - len(result["findings"]))
        self.assertEqual(
            summary["confirmed"] + summary["suspected"] + summary["ungraded"],
            summary["vulnerable"],
        )
        self.assertEqual(
            len({(f["check_id"], f["identity"]) for f in result["findings"]}),
            len(result["findings"]),
        )

    def test_findings_follow_expect_insertion_order(self) -> None:
        def responder(path, token):
            return (500, {}, b"{}")

        with _server(responder) as url:
            result = _run(_base_config(), url)
        self.assertEqual(
            [finding["identity"] for finding in result["findings"]],
            ["owner", "outsider"],
        )


# --------------------------------------------------------------------------
# demo server integration - the shipped confirmed/suspected/gzip cases
# --------------------------------------------------------------------------


def _demo_config(base_url: str = "http://127.0.0.1:1") -> dict:
    return {
        "version": 1,
        "target": {"base_url": base_url, "timeout_seconds": 5},
        "identities": {
            "invoice_owner": {
                "headers": {"Authorization": "Bearer owner-token"},
                "marker": demo_server.OWNER_MARKER,
            },
            "other_tenant": {"headers": {"Authorization": "Bearer outsider-token"}},
        },
        "checks": [
            {
                "id": "invoice-tenant-isolation",
                "request": {"method": "GET", "path": "/api/invoices/inv-100"},
                "expect": {
                    "invoice_owner": {
                        "status": [200],
                        "contains_marker": "invoice_owner",
                    },
                    "other_tenant": {
                        "status": [404],
                        "excludes_marker": "invoice_owner",
                    },
                },
            },
            {
                "id": "invoice-export-isolation",
                "request": {"method": "GET", "path": "/api/exports/acme.json"},
                "expect": {
                    "invoice_owner": {
                        "status": [200],
                        "contains_marker": "invoice_owner",
                    },
                    "other_tenant": {
                        "status": [404],
                        "excludes_marker": "invoice_owner",
                    },
                },
            },
            {
                "id": "invoice-compressed-view",
                "request": {
                    "method": "GET",
                    "path": "/api/invoices/inv-100/compressed",
                },
                "expect": {
                    "invoice_owner": {
                        "status": [200],
                        "contains_marker": "invoice_owner",
                    },
                    "other_tenant": {
                        "status": [404],
                        "excludes_marker": "invoice_owner",
                    },
                },
            },
        ],
    }


@contextlib.contextmanager
def _demo(vulnerable: bool = False, leak_marker: bool = True):
    server = demo_server.create_server("127.0.0.1", 0, vulnerable, leak_marker)
    thread = loopback.start(server)
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@slow("stands up a loopback HTTP server and runs the engine against it")
class DemoServerIntegrationTest(unittest.TestCase):
    def test_safe_server_is_entirely_clean(self) -> None:
        with _demo() as url:
            result = _run(_demo_config(), url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["safe"], 6)
        self.assertEqual(result["schema_version"], 2)

    def test_vulnerable_without_a_leaked_marker_is_all_suspected(self) -> None:
        with _demo(vulnerable=True, leak_marker=False) as url:
            result = _run(_demo_config(), url)
        self.assertEqual(result["summary"]["confirmed"], 0)
        self.assertEqual(result["summary"]["suspected"], 3)
        self.assertEqual(result["summary"]["vulnerable"], 3)

    def test_vulnerable_with_a_leaked_marker_confirms_two_of_three(self) -> None:
        with _demo(vulnerable=True, leak_marker=True) as url:
            result = _run(_demo_config(), url)
        self.assertEqual(result["summary"]["confirmed"], 2)
        self.assertEqual(result["summary"]["suspected"], 1)
        invoice = _finding(result, "other_tenant", "invoice-tenant-isolation")
        self.assertEqual(invoice["evidence_grade"], "confirmed")
        self.assertEqual(invoice["evidence"]["marker"]["state"], "present")
        compressed = _finding(result, "other_tenant", "invoice-compressed-view")
        self.assertEqual(compressed["evidence_grade"], "confirmed")
        self.assertEqual(compressed["evidence"]["response"]["body_encoding"], "gzip")
        export = _finding(result, "other_tenant", "invoice-export-isolation")
        self.assertEqual(export["evidence_grade"], "suspected")
        self.assertEqual(export["evidence"]["marker"]["control_state"], "present")

    def test_suspected_to_confirmed_is_an_escalation(self) -> None:
        with _demo(vulnerable=True, leak_marker=False) as url:
            unproven = _run(_demo_config(), url)
        with _demo(vulnerable=True, leak_marker=True) as url:
            proven = _run(_demo_config(), url)
        regression = _compare_findings(proven["findings"], unproven)
        self.assertEqual(regression["new"], [])
        self.assertEqual(len(regression["unchanged"]), 3)
        self.assertEqual(len(regression["escalated"]), 2)
        self.assertEqual(
            {finding["check_id"] for finding in regression["escalated"]},
            {"invoice-tenant-isolation", "invoice-compressed-view"},
        )


# --------------------------------------------------------------------------
# (i) schema, baselines, escalation
# --------------------------------------------------------------------------


class SchemaTest(unittest.TestCase):
    def _write_run(self, value: dict) -> Path:
        directory = tempfile.mkdtemp()
        path = Path(directory) / "run.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def _v1_finding(self) -> dict:
        return {
            "id": "0ec4c5cbd79deaed6e9f",
            "rule_id": "VERIDOR-AUTHZ-001",
            "level": "error",
            "message": "boom",
            "location": "veridor.json",
            "check_id": "records",
            "identity": "outsider",
            "verdict": "vulnerable",
        }

    @slow("stands up a loopback HTTP server and runs the engine against it")
    def test_runs_are_written_as_schema_version_two(self) -> None:
        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body({"ref": MARKER}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        self.assertEqual(result["schema_version"], 2)
        for finding in result["findings"]:
            self.assertIn(finding["evidence_grade"], core.EVIDENCE_GRADES)

    def test_load_run_accepts_v1_documents_without_evidence_grade(self) -> None:
        path = self._write_run({"run_id": "run-1", "findings": [self._v1_finding()]})
        self.assertEqual(load_run(path)["run_id"], "run-1")

    def test_load_run_requires_evidence_grade_for_v2(self) -> None:
        path = self._write_run(
            {"schema_version": 2, "run_id": "run-1", "findings": [self._v1_finding()]}
        )
        with self.assertRaisesRegex(ConfigError, "requires an evidence_grade"):
            load_run(path)

    def test_load_run_rejects_future_schema_version(self) -> None:
        # 3 is the sequence-run schema and is now supported; 4 is the next
        # unknown one. The property under test is unchanged: a document this
        # binary cannot fully render fails closed rather than being summarized
        # with the parts it does not understand silently dropped.
        path = self._write_run({"schema_version": 4, "run_id": "run-1", "findings": []})
        with self.assertRaisesRegex(
            ConfigError,
            r"unsupported run schema_version: 4; this Veridor supports \[1, 2, 3\]",
        ):
            load_run(path)

    def test_v1_baseline_still_matches(self) -> None:
        baseline = {"run_id": "v1-run", "findings": [self._v1_finding()]}
        current = [
            {
                "id": "0ec4c5cbd79deaed6e9f",
                "evidence_grade": "confirmed",
                "verdict": "vulnerable",
            }
        ]
        regression = _compare_findings(current, baseline)
        self.assertEqual(regression["new"], [])
        self.assertEqual(len(regression["unchanged"]), 1)
        self.assertEqual(len(regression["escalated"]), 1)
        self.assertEqual(regression["baseline_run_id"], "v1-run")

    def test_upgrading_ungraded_to_suspected_is_not_an_escalation(self) -> None:
        baseline = {"run_id": "b", "findings": [{"id": "a1", "evidence_grade": "ungraded"}]}
        current = [{"id": "a1", "evidence_grade": "suspected"}]
        regression = _compare_findings(current, baseline)
        self.assertEqual(regression["escalated"], [])
        self.assertEqual(len(regression["unchanged"]), 1)

    def test_confirmed_staying_confirmed_is_not_an_escalation(self) -> None:
        baseline = {"run_id": "b", "findings": [{"id": "a1", "evidence_grade": "confirmed"}]}
        current = [{"id": "a1", "evidence_grade": "confirmed"}]
        self.assertEqual(_compare_findings(current, baseline)["escalated"], [])

    def test_escalated_is_a_view_over_unchanged(self) -> None:
        baseline = {
            "run_id": "b",
            "findings": [
                {"id": "a1", "evidence_grade": "suspected"},
                {"id": "a2", "evidence_grade": "ungraded"},
            ],
        }
        current = [
            {"id": "a1", "evidence_grade": "confirmed"},
            {"id": "a3", "evidence_grade": "confirmed"},
        ]
        regression = _compare_findings(current, baseline)
        self.assertEqual(len(regression["new"]), 1)
        self.assertEqual(len(regression["resolved"]), 1)
        self.assertEqual(len(regression["unchanged"]), 1)
        self.assertEqual(len(regression["escalated"]), 1)
        self.assertEqual(
            len(current), len(regression["new"]) + len(regression["unchanged"])
        )


# --------------------------------------------------------------------------
# SARIF + evidence safety
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class EvidenceSafetyTest(unittest.TestCase):
    def _leaky_run(self) -> dict:
        secret_body = {
            "ref": MARKER,
            "customer": "Very Secret Customer Name",
            "email": "victim@example.test",
        }

        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body(secret_body))

        with _server(responder) as url:
            return _run(_base_config(), url)

    def test_response_body_and_marker_are_never_persisted(self) -> None:
        result = self._leaky_run()
        serialized = json.dumps(result) + json.dumps(to_sarif(result))
        self.assertNotIn(MARKER, serialized)
        self.assertNotIn(MARKER.lower(), serialized.lower())
        self.assertNotIn("Very Secret Customer Name", serialized)
        self.assertNotIn("victim@example.test", serialized)

    def test_probe_evidence_is_closed_vocabulary_only(self) -> None:
        result = self._leaky_run()
        response = result["probes"][0]["response"]
        self.assertEqual(
            set(response),
            {
                "status",
                "duration_ms",
                "body_bytes",
                "body_sha256",
                "body_truncated",
                "marker_scan",
                "marker_scan_reason",
                "marker_encodings",
                "marker_channel",
                "body_encoding",
                "body_scanned_bytes",
                "body_scan_truncated",
                "from_cache",
                "retry_after",
            },
        )
        self.assertIn(response["marker_scan"], {"present", "absent", "unknown", None})
        self.assertIn(response["marker_channel"], {"body", "header", None})
        self.assertIsInstance(response["from_cache"], bool)
        # Presence, never the value: a header this module derives a boolean
        # from must not be able to smuggle target-controlled text into an
        # artifact, which is the whole reason this closed vocabulary exists.
        self.assertIsInstance(response["retry_after"], bool)
        self.assertTrue(
            set(response["marker_encodings"]) <= {"ascii", "utf-16le", "utf-16be"}
        )

    def test_retry_after_is_presence_only_and_case_insensitive(self) -> None:
        """``matrix`` aborts on this boolean; it must never carry the delay.

        The value is target-controlled and is either a number of seconds or an
        HTTP-date. A boolean cannot be echoed into an artifact and cannot talk
        this process into sleeping for an hour on a target's say-so.
        """
        self.assertTrue(core._retry_after_requested([("Retry-After", "60")]))
        self.assertTrue(core._retry_after_requested([("retry-after", "0")]))
        self.assertTrue(
            core._retry_after_requested([("RETRY-AFTER", "Wed, 21 Oct 2026 07:28:00 GMT")])
        )
        self.assertFalse(core._retry_after_requested([]))
        self.assertFalse(core._retry_after_requested([("X-Retry-After", "60")]))
        self.assertFalse(core._retry_after_requested([("Retry-After-Ms", "60")]))
        self.assertIs(core._retry_after_requested([("Retry-After", "60")]), True)

    def test_marker_evidence_names_an_identity_not_a_literal(self) -> None:
        result = self._leaky_run()
        marker = _finding(result, "outsider")["evidence"]["marker"]
        self.assertEqual(marker["owner_identity"], "owner")
        self.assertNotIn(MARKER, json.dumps(marker))

    def test_written_artifacts_never_contain_the_marker(self) -> None:
        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body({"ref": MARKER}))

        holder = _TempConfig(_base_config())
        try:
            with _server(responder) as url:
                output = holder.root / "out"
                execute_run(holder.path, output_dir=output, base_url=url)
            written = list(output.rglob("*.json"))
            self.assertTrue(written)
            for path in written:
                self.assertNotIn(MARKER, path.read_text(encoding="utf-8"))
        finally:
            holder.close()

    def test_sarif_exposes_grades_and_marker_state(self) -> None:
        result = self._leaky_run()
        sarif = to_sarif(result)
        rules = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(
            rules,
            {
                "VERIDOR-AUTHZ-001",
                "VERIDOR-LEAK-001",
                "VERIDOR-EXEC-001",
                "VERIDOR-ORACLE-001",
            },
        )
        entry = sarif["runs"][0]["results"][0]
        self.assertEqual(entry["properties"]["evidenceGrade"], "confirmed")
        self.assertEqual(entry["properties"]["markerState"], "present")
        self.assertEqual(
            entry["partialFingerprints"]["veridorFindingId/v1"],
            _finding(result, "outsider")["id"],
        )

    @fast("asserts on the declaration, not on a live target")
    def test_sarif_defaults_grade_for_v1_runs(self) -> None:
        sarif = to_sarif(
            {
                "run_id": "run-1",
                "findings": [
                    {
                        "id": "a1",
                        "rule_id": "VERIDOR-AUTHZ-001",
                        "level": "error",
                        "message": "boom",
                        "location": "veridor.json",
                        "check_id": "records",
                        "identity": "outsider",
                        "verdict": "vulnerable",
                    }
                ],
            }
        )
        entry = sarif["runs"][0]["results"][0]
        self.assertEqual(entry["properties"]["evidenceGrade"], "ungraded")
        self.assertNotIn("markerState", entry["properties"])


# --------------------------------------------------------------------------
# (i) per-principal-scoped APIs: identity-level marker control probes
#
# The oracle used to assume the marker owner and the caller under test address
# ONE url inside ONE check. A per-principal-scoped API paths the resource by
# the CALLER's own principal, so they never can. These tests pin the decoupled
# control: the marker is proven live by an identity-level probe, and an
# exclusion is trusted only when that proof exists.
# --------------------------------------------------------------------------


DEVICE_B_MARKER = "vdr-lWJ25HBfPp4Y3_MeEkYhL9Gu"


def _scoped_config(*, probe: bool = True, probe_path: str | None = None) -> dict:
    """device_a and device_b live on disjoint, principal-scoped paths."""
    device_a: dict = {
        "headers": {"Authorization": "Bearer device-a-token"},
        "marker": MARKER,
    }
    if probe:
        device_a["marker_probe"] = {
            "method": "GET",
            "path": probe_path or "/fleet/device-a/artifact",
        }
    return {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 3},
        "identities": {
            "device_a": device_a,
            "device_b": {"headers": {"Authorization": "Bearer device-b-token"}},
            "anonymous": {"headers": {}},
        },
        "checks": [
            {
                "id": "fleet",
                "name": "Fleet artifact isolation",
                # ONLY device_b's own path. device_a can never be probed here.
                "request": {"method": "GET", "path": "/fleet/device-b/artifact"},
                "expect": {
                    "device_b": {"status": [200], "excludes_marker": "device_a"},
                    "anonymous": {"status": [401]},
                },
            }
        ],
    }


def _scoped_responder(
    *, leak: bool = False, marker_live: bool = True, encoding: str | None = None
):
    """A per-principal-scoped fleet API. Each device sees only its own path."""

    def responder(path: str, token: str):
        principal = {
            "Bearer device-a-token": "device-a",
            "Bearer device-b-token": "device-b",
        }.get(token)
        if principal is None:
            return 401, {}, _json_body({"error": "unauthenticated"})
        if not path.startswith(f"/fleet/{principal}/"):
            return 403, {}, _json_body({"error": "principal mismatch"})
        if path != f"/fleet/{principal}/artifact":
            return 404, {}, _json_body({"error": "not found"})
        headers = {"Content-Type": "application/json"}
        if encoding:
            headers["Content-Encoding"] = encoding
        if principal == "device-a":
            body = {"device": "device-a"}
            if marker_live:
                body["provenance"] = MARKER
            return 200, headers, _json_body(body)
        body = {"device": "device-b"}
        if leak:
            body["provenance"] = MARKER
        return 200, headers, _json_body(body)

    return responder


class ScopedControlConfigTest(unittest.TestCase):
    """Load-time contract for identity-level marker probes."""

    def _load(self, config: dict) -> dict:
        holder = _TempConfig(config)
        try:
            return load_config(holder.path)
        finally:
            holder.close()

    def _reject(self, config: dict, pattern: str) -> None:
        with self.assertRaisesRegex(ConfigError, pattern):
            self._load(config)

    def test_scoped_exclusion_loads_when_the_owner_proves_its_marker(self) -> None:
        loaded = self._load(_scoped_config())
        self.assertEqual(
            loaded["identities"]["device_a"]["marker_probe"]["path"],
            "/fleet/device-a/artifact",
        )

    def test_scoped_exclusion_without_any_control_is_still_rejected(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self._load(_scoped_config(probe=False))
        message = str(raised.exception)
        # Both remedies are offered; neither is optional.
        self.assertIn("requires a control in the same check", message)
        self.assertIn("marker_probe", message)

    def test_marker_probe_without_a_marker_fails_the_load(self) -> None:
        config = _scoped_config()
        del config["identities"]["device_a"]["marker"]
        self._reject(config, "defines no 'marker' field")

    def test_marker_probe_without_a_marker_exits_two(self) -> None:
        config = _scoped_config()
        del config["identities"]["device_a"]["marker"]
        holder = _TempConfig(config)
        try:
            with contextlib.redirect_stderr(io.StringIO()) as captured:
                code = veridor_main(
                    ["run", "--config", str(holder.path),
                     "--output-dir", str(holder.root / "out")]
                )
            self.assertEqual(code, 2)
            self.assertIn("marker_probe", captured.getvalue())
        finally:
            holder.close()

    def test_marker_probe_must_be_an_object(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"] = "/fleet/device-a/artifact"
        self._reject(config, "marker_probe must be an object")

    def test_marker_probe_method_must_be_an_http_token(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"]["method"] = "GET /x"
        self._reject(config, "marker_probe.method must be an HTTP token")

    def test_marker_probe_path_must_be_same_origin(self) -> None:
        for path in ("https://evil.example/x", "//evil.example/x", "relative", "/x#f"):
            with self.subTest(path=path):
                config = _scoped_config()
                config["identities"]["device_a"]["marker_probe"]["path"] = path
                self._reject(config, "marker_probe.path must be a same-origin")

    def test_marker_probe_headers_are_validated(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"]["headers"] = {
            "X-Trace": "a\r\nInjected: 1"
        }
        self._reject(config, "marker_probe.headers contains an invalid value")

    def test_marker_probe_body_is_validated(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"]["method"] = "POST"
        config["identities"]["device_a"]["marker_probe"]["body"] = 7
        self._reject(config, "marker_probe.body must be a string")

    def test_marker_probe_near_miss_key_fails_closed(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"]["methd"] = "GET"
        self._reject(config, "marker_probe has unsupported keys: methd")

    def test_marker_in_the_probe_path_is_a_reflection_and_is_rejected(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"]["path"] = f"/echo/{MARKER}"
        self._reject(config, "appears in the marker_probe request")

    def test_encoded_marker_in_the_probe_path_is_rejected(self) -> None:
        config = _scoped_config()
        encoded = quote(MARKER[:6], safe="") + MARKER[6:]
        config["identities"]["device_a"]["marker_probe"]["path"] = f"/echo/{encoded}"
        self._reject(config, "appears in the marker_probe request")

    def test_marker_in_a_probe_header_is_rejected(self) -> None:
        config = _scoped_config()
        config["identities"]["device_a"]["marker_probe"]["headers"] = {
            "X-Trace": MARKER
        }
        self._reject(config, "appears in the marker_probe request")

    def test_another_identitys_marker_in_a_probe_is_rejected(self) -> None:
        config = _scoped_config()
        config["identities"]["device_b"]["marker"] = OTHER_MARKER
        config["identities"]["device_a"]["marker_probe"]["path"] = (
            f"/fleet/device-a/{OTHER_MARKER}"
        )
        self._reject(config, "appears in the marker_probe request")

    def test_marker_probe_is_ignored_by_configs_that_never_exclude(self) -> None:
        """A probe on an identity no exclusion names is legal, and just runs."""
        config = _base_config()
        config["identities"]["owner"]["marker_probe"] = {"path": "/owner/self"}
        self.assertIn("marker_probe", self._load(config)["identities"]["owner"])


@slow("stands up a loopback HTTP server and runs the engine against it")
class ScopedControlGradingTest(unittest.TestCase):
    """The correctness property: a vacuous exclusion never reads as a pass."""

    def test_live_marker_licenses_a_clean_exclusion(self) -> None:
        with _server(_scoped_responder()) as url:
            result = _run(_scoped_config(), url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "passed")
        control = result["marker_controls"][0]
        self.assertEqual(control["identity"], "device_a")
        self.assertEqual(control["state"], "verified")
        self.assertIsNone(control["reason"])

    def test_a_dead_marker_never_passes_the_exclusion(self) -> None:
        """The whole point. device_a's marker is not live, so device_b's
        response lacking it proves nothing and must not be graded as safe."""
        with _server(_scoped_responder(marker_live=False)) as url:
            result = _run(_scoped_config(), url)
        finding = _finding(result, "device_b")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(finding["rule_id"], "VERIDOR-ORACLE-001")
        # `inconclusive`, not `failed`: every finding here is a probe that
        # could not be graded, and calling that a failure is what made the
        # artifact contradict the exit code.
        self.assertEqual(result["status"], "inconclusive")
        marker = finding["evidence"]["marker"]
        self.assertEqual(marker["control_source"], "identity_probe")
        self.assertEqual(marker["control_state"], "missing")
        self.assertIn("not known to be live", marker["control_reason"])
        self.assertIn("marker probe for 'device_a'", finding["message"])
        self.assertEqual(result["marker_controls"][0]["state"], "unverified")

    def test_a_probe_pointed_at_the_wrong_path_never_passes(self) -> None:
        with _server(_scoped_responder()) as url:
            result = _run(
                _scoped_config(probe_path="/fleet/device-a/nothing-here"), url
            )
        finding = _finding(result, "device_b")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(result["marker_controls"][0]["response"]["status"], 404)

    def test_a_failed_control_request_never_passes(self) -> None:
        with _server(_scoped_responder()) as url:
            dead = url
        # The server is gone; the control request cannot complete.
        result = _run(_scoped_config(), dead)
        control = result["marker_controls"][0]
        self.assertEqual(control["state"], "unverified")
        self.assertIn("marker probe for 'device_a' failed", control["reason"])
        self.assertEqual(_finding(result, "device_b")["verdict"], "inconclusive")

    def test_an_unscannable_control_body_never_passes(self) -> None:
        responder = _scoped_responder(encoding="br")
        with _server(responder) as url:
            result = _run(_scoped_config(), url)
        control = result["marker_controls"][0]
        self.assertEqual(control["state"], "unverified")
        self.assertEqual(control["response"]["marker_scan"], "unknown")
        self.assertIn("could not be fully scanned", control["reason"])
        self.assertEqual(_finding(result, "device_b")["verdict"], "inconclusive")

    def test_confirmed_survives_an_unverified_control(self) -> None:
        """(d) A confirmed grade comes from the ATTACKER's own scan and is
        independent of any control. Do not regress it."""
        responder = _scoped_responder(leak=True, marker_live=False)
        with _server(responder) as url:
            result = _run(_scoped_config(), url)
        finding = _finding(result, "device_b")
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(result["marker_controls"][0]["state"], "unverified")

    def test_a_leak_is_confirmed_when_the_control_is_verified(self) -> None:
        with _server(_scoped_responder(leak=True)) as url:
            result = _run(_scoped_config(), url)
        finding = _finding(result, "device_b")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        marker = finding["evidence"]["marker"]
        self.assertEqual(marker["control_source"], "identity_probe")
        self.assertEqual(marker["control_state"], "present")

    def test_a_same_check_control_stays_authoritative(self) -> None:
        """Precedence is conservative: an identity probe cannot paper over a
        declared same-check control that failed."""
        config = _scoped_config()
        config["checks"][0]["request"]["path"] = "/fleet/device-b/artifact"
        config["checks"][0]["expect"]["device_a"] = {
            "status": [403],
            "contains_marker": "device_a",
        }
        with _server(_scoped_responder()) as url:
            result = _run(config, url)
        finding = _finding(result, "device_b")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(finding["evidence"]["marker"]["control_source"], "check")
        self.assertEqual(finding["evidence"]["marker"]["control_state"], "absent")
        # ...even though the identity control did prove the marker live.
        self.assertEqual(result["marker_controls"][0]["state"], "verified")

    def test_status_failure_without_a_live_marker_is_suspected_not_confirmed(
        self,
    ) -> None:
        config = _scoped_config()
        config["checks"][0]["expect"]["device_b"]["status"] = [404]
        with _server(_scoped_responder(marker_live=False)) as url:
            result = _run(config, url)
        finding = _finding(result, "device_b")
        self.assertEqual(finding["evidence_grade"], "suspected")
        self.assertIn("marker probe for 'device_a'", finding["message"])


@slow("stands up a loopback HTTP server and runs the engine against it")
class ScopedControlAccountingTest(unittest.TestCase):
    """Controls are not checks, and must not look like them."""

    def test_controls_are_not_probes_and_do_not_move_the_tally(self) -> None:
        with _server(_scoped_responder()) as url:
            result = _run(_scoped_config(), url)
        self.assertEqual(result["summary"]["checks"], 1)
        self.assertEqual(result["summary"]["probes"], 2)
        self.assertEqual(result["summary"]["safe"], 2)
        self.assertEqual(len(result["probes"]), 2)
        self.assertEqual(
            [p["identity"] for p in result["probes"]], ["device_b", "anonymous"]
        )
        self.assertEqual(len(result["marker_controls"]), 1)
        # A control carries no check_id, because it belongs to no check.
        self.assertNotIn("check_id", result["marker_controls"][0])

    def test_controls_never_produce_findings(self) -> None:
        with _server(_scoped_responder(marker_live=False)) as url:
            result = _run(_scoped_config(), url)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["identity"], "device_b")

    def test_absent_key_when_no_identity_configures_a_probe(self) -> None:
        with _server(lambda path, token: (404, {}, b"{}")) as url:
            result = _run(_base_config(), url)
        self.assertNotIn("marker_controls", result)

    def test_one_control_request_per_identity_per_run(self) -> None:
        seen: list[str] = []

        def responder(path: str, token: str):
            seen.append(path)
            return _scoped_responder()(path, token)

        config = _scoped_config()
        # Two checks that both depend on device_a's marker being live.
        second = json.loads(json.dumps(config["checks"][0]))
        second["id"] = "fleet-2"
        config["checks"].append(second)
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(seen.count("/fleet/device-a/artifact"), 1)
        # 5, not 4: two check probes each for two checks, plus ONE liveness
        # control -- deduplicated by request, so the second check reuses it.
        # That dedup is the point: the cost is per request, not per identity.
        self.assertEqual(seen.count("/fleet/device-b/artifact"), 5)

    def test_a_control_uses_its_own_identitys_headers(self) -> None:
        seen: list[tuple[str, str]] = []

        def responder(path: str, token: str):
            seen.append((path, token))
            return _scoped_responder()(path, token)

        with _server(responder) as url:
            _run(_scoped_config(), url)
        # The control reuses device_a's own credentials, and runs before any
        # check probe touches the target.
        self.assertEqual(seen[0], ("/fleet/device-a/artifact", "Bearer device-a-token"))
        self.assertIn(("/fleet/device-b/artifact", "Bearer device-b-token"), seen)
        self.assertNotIn(("/fleet/device-a/artifact", ""), seen)

    def test_the_control_never_persists_the_marker_or_a_body(self) -> None:
        holder = _TempConfig(_scoped_config())
        try:
            with _server(_scoped_responder()) as url:
                out = holder.root / "out"
                execute_run(holder.path, output_dir=out, base_url=url)
            for artifact in [out / "latest.json", *sorted((out / "runs").glob("*.json"))]:
                text = artifact.read_text(encoding="utf-8")
                self.assertNotIn(MARKER, text)
                self.assertNotIn("provenance", text)
        finally:
            holder.close()

    def test_the_persisted_run_still_loads(self) -> None:
        holder = _TempConfig(_scoped_config())
        try:
            with _server(_scoped_responder(marker_live=False)) as url:
                out = holder.root / "out"
                execute_run(holder.path, output_dir=out, base_url=url)
            self.assertEqual(load_run(out / "latest.json")["schema_version"], 2)
        finally:
            holder.close()


@slow("stands up a loopback HTTP server and runs the engine against it")
class ScopedControlFingerprintTest(unittest.TestCase):
    """(3) Adding a marker probe must not renumber a single finding."""

    def test_adding_a_marker_probe_leaves_every_finding_id_untouched(self) -> None:
        without = _scoped_config(probe=False)
        # Give the no-probe variant a same-check control so it loads at all.
        without["checks"][0]["request"]["path"] = "/fleet/device-b/artifact"
        without["checks"][0]["expect"]["device_a"] = {
            "status": [403],
            "contains_marker": "device_a",
        }
        with_probe = json.loads(json.dumps(without))
        with_probe["identities"]["device_a"]["marker_probe"] = {
            "path": "/fleet/device-a/artifact"
        }
        with _server(_scoped_responder(marker_live=False)) as url:
            before = _run(without, url)
            after = _run(with_probe, url)
        self.assertEqual(
            [f["id"] for f in before["findings"]],
            [f["id"] for f in after["findings"]],
        )
        self.assertTrue(before["findings"])

    def test_a_baseline_written_without_probes_reports_nothing_new(self) -> None:
        without = _scoped_config(probe=False)
        without["checks"][0]["expect"]["device_a"] = {
            "status": [403],
            "contains_marker": "device_a",
        }
        with_probe = json.loads(json.dumps(without))
        with_probe["identities"]["device_a"]["marker_probe"] = {
            "path": "/fleet/device-a/artifact"
        }
        with _server(_scoped_responder(marker_live=False)) as url:
            baseline = _run(without, url)
            holder = _TempConfig(with_probe)
            try:
                baseline_path = holder.root / "baseline.json"
                baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
                current = execute_run(
                    holder.path,
                    output_dir=holder.root / "out",
                    baseline_path=baseline_path,
                    base_url=url,
                )
            finally:
                holder.close()
        self.assertEqual(current["summary"]["new"], 0)
        self.assertEqual(current["summary"]["resolved"], 0)
        self.assertTrue(current["summary"]["unchanged"])


@slow("stands up a loopback HTTP server and runs the engine against it")
class ScopedFixtureTest(unittest.TestCase):
    """The shipped fleet fixture against the shipped demo server."""

    @staticmethod
    @contextlib.contextmanager
    def _api(vulnerable: bool = False):
        server = demo_server.create_server("127.0.0.1", 0, vulnerable=vulnerable)
        thread = loopback.start(server)
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @staticmethod
    def _fixture() -> dict:
        return json.loads(
            (ROOT / "fixtures" / "veridor.fleet.json").read_text(encoding="utf-8")
        )

    @fast("asserts on the declaration, not on a live target")
    def test_fixture_markers_match_the_demo_server(self) -> None:
        fixture = self._fixture()
        self.assertEqual(
            fixture["identities"]["device_a"]["marker"], demo_server.DEVICE_A_MARKER
        )
        self.assertEqual(
            fixture["identities"]["device_b"]["marker"], demo_server.DEVICE_B_MARKER
        )
        for marker in (demo_server.DEVICE_A_MARKER, demo_server.DEVICE_B_MARKER):
            self.assertEqual(validate_marker(marker, "demo"), marker)

    def test_safe_fleet_run_passes_with_verified_controls(self) -> None:
        with self._api() as url:
            result = _run(self._fixture(), url)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            {c["identity"]: c["state"] for c in result["marker_controls"]},
            {"device_a": "verified", "device_b": "verified"},
        )

    def test_vulnerable_fleet_run_confirms_the_crossover(self) -> None:
        with self._api(vulnerable=True) as url:
            result = _run(self._fixture(), url)
        leak = _finding(result, "device_b", "fleet-device-b-artifact")
        self.assertEqual(leak["evidence_grade"], "confirmed")
        self.assertEqual(leak["evidence"]["marker"]["control_source"], "identity_probe")
        self.assertEqual(leak["evidence"]["marker"]["control_state"], "present")
        # device_b's own marker stopped being observable, so the exclusion that
        # depends on it degrades rather than silently passing.
        other = _finding(result, "device_a", "fleet-device-a-artifact")
        self.assertEqual(other["verdict"], "inconclusive")

    def test_the_fleet_fixture_never_persists_a_marker(self) -> None:
        holder = _TempConfig(self._fixture())
        try:
            with self._api(vulnerable=True) as url:
                out = holder.root / "out"
                result = execute_run(holder.path, output_dir=out, base_url=url)
                sarif = json.dumps(to_sarif(result))
            texts = [sarif] + [
                p.read_text(encoding="utf-8")
                for p in [out / "latest.json", *sorted((out / "runs").glob("*.json"))]
            ]
            for text in texts:
                self.assertNotIn(demo_server.DEVICE_A_MARKER, text)
                self.assertNotIn(demo_server.DEVICE_B_MARKER, text)
        finally:
            holder.close()


# --------------------------------------------------------------------------
# (j) declaration scoping - the tool must not claim more than it measured
# --------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class DeclarationScopeTest(unittest.TestCase):
    """Veridor consumes a policy statement; it never audits one.

    One case is the reason this class exists: a deliberately over-strict
    expectation on a legitimate, entitled administrative read produced a
    'confirmed' finding announcing that data had crossed an authorization
    boundary. The marker really was there,
    because the admin really was allowed to see it. Nothing was wrong with the
    target; the declaration was wrong. Every assertion Veridor emits must
    therefore be scoped to the declaration, so that a wrong declaration reads
    as a wrong declaration and not as a breach.
    """

    #: Phrasings that assert the boundary itself, which Veridor never
    #: establishes. Any of these in an emitted string is the defect returning.
    _OVERCLAIMS = (
        "crossed the authorization boundary",
        "crossed the boundary",
        "authorization boundary was crossed",
        "is vulnerable",
        "is not authorized",
        "unauthorized access",
        "should not have",
    )

    def _confirmed_run(self) -> dict:
        def responder(path, token):
            if not _known(token):
                return (404, {}, b"{}")
            return (200, {}, _json_body({"ref": MARKER}))

        with _server(responder) as url:
            return _run(_base_config(), url)

    def _emitted_strings(self, result: dict) -> list[str]:
        """Every string a human or a downstream tool will actually read."""
        strings: list[str] = []
        for finding in result["findings"]:
            strings.extend(
                [finding["message"], finding["title"], finding["remediation"]]
            )
        sarif = to_sarif(result)
        driver = sarif["runs"][0]["tool"]["driver"]
        for rule in driver["rules"]:
            strings.append(rule["shortDescription"]["text"])
            strings.append(rule["fullDescription"]["text"])
            strings.append(rule["help"]["text"])
        strings.append(driver["shortDescription"]["text"])
        strings.append(driver["fullDescription"]["text"])
        strings.extend(item["message"]["text"] for item in sarif["runs"][0]["results"])
        strings.append(core.DECLARATION_SCOPE)
        return strings

    def test_no_emitted_string_asserts_a_boundary_was_crossed(self) -> None:
        for text in self._emitted_strings(self._confirmed_run()):
            lowered = text.lower()
            for overclaim in self._OVERCLAIMS:
                self.assertNotIn(overclaim, lowered, text)

    def test_every_data_flow_claim_carries_its_premise(self) -> None:
        """The SARIF rule text said flatly "That is proof of data flow".

        The finding message was reworded to "insofar as the marker is unique"
        after a counterexample falsified the unconditional claim, but the
        LEAK-001 rule description -- shipped in driver.rules on every run, leak
        or not -- kept it, garbled ("that is data another"), and _OVERCLAIMS had
        no pattern for it. `confirmed_grade_means` read "That is evidence flow".
        """
        result = self._confirmed_run()
        strings = self._emitted_strings(result) + [
            value for value in result["interpretation"].values()
            if isinstance(value, str)
        ]
        claims = [text for text in strings if "proof of data flow" in text.lower()]
        self.assertGreaterEqual(len(claims), 3, "finding, rule, interpretation")
        for text in claims:
            self.assertIn("insofar as the marker is unique", text.lower(), text)
        for text in strings:
            self.assertNotIn("that is data another", text.lower(), text)
            self.assertNotIn("evidence flow", text.lower(), text)

    def test_confirmed_message_states_the_flow_and_owns_the_limit(self) -> None:
        finding = _finding(self._confirmed_run(), "outsider")
        message = finding["message"]
        # The measurement, stated without hedging: this is what a marker buys.
        self.assertIn("received HTTP 200", message)
        self.assertIn("declared marker was observed in 'outsider''s response", message)
        # The declaration, attributed to the operator rather than to Veridor.
        self.assertIn("declared: one of [404]", message)
        # The hedge names WHICH half is unaudited. The operator did declare the
        # flow impermissible via excludes_marker; what Veridor cannot check is
        # whether that declaration is right, not whether one exists.
        self.assertIn(
            "You declared that 'outsider' must not receive 'owner''s data, and "
            "Veridor measured that it did.",
            message,
        )
        self.assertIn(
            "Whether that declaration is correct is not something Veridor can check",
            message,
        )
        self.assertNotIn("may see", message)

    def test_leak_finding_scopes_a_passing_status_the_same_way(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            # The sham must not get the marker, or it is not owner-specific
            # and, beside this matched 404, the probe is VERIDOR-ORACLE-001
            # inconclusive; see KNOWN_TOKENS and the test below.
            if _known(token):
                return (404, {}, _json_body({"error": f"missing {MARKER}"}))
            return (404, {}, b"{}")

        with _server(responder) as url:
            result = _run(_base_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertIn(
            "declared marker was observed in 'outsider''s response",
            finding["message"],
        )
        self.assertIn("insofar as the marker is unique", finding["message"])
        self.assertIn(
            "Whether that declaration is correct is not something Veridor can check",
            finding["message"],
        )
        self.assertNotIn("disclosed", finding["title"])

    def test_a_sham_that_gets_the_marker_beside_a_matched_status(self) -> None:
        """The case the fixture above avoids: the fabricated credential gets
        the marker too. The comment there still graded this case `suspected`;
        a non-unique marker beside a status that matched the declaration is
        now an unverified oracle, not a finding."""
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            return (404, {}, _json_body({"error": f"missing {MARKER}"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(finding["evidence_grade"], "n/a")
        self.assertEqual(result["status"], "inconclusive")

    def test_run_document_carries_a_machine_readable_interpretation(self) -> None:
        result = self._confirmed_run()
        interpretation = result["interpretation"]
        self.assertEqual(interpretation["summary"], core.DECLARATION_SCOPE)
        for key in (
            "measures",
            "finding_means",
            "finding_does_not_mean",
            "confirmed_grade_means",
            "policy_source",
            "reference",
        ):
            self.assertTrue(interpretation[key], key)
        self.assertIn("cannot audit it", interpretation["finding_does_not_mean"])
        self.assertIn("never proof of policy", interpretation["confirmed_grade_means"])
        self.assertEqual(interpretation["reference"],
                         "https://github.com/Veridor-authz/veridor#confirmed-proves-data-flow-never-policy")

    @fast("reads the statement, pyproject.toml and the README, no target")
    def test_the_reference_is_a_page_a_reader_of_the_report_can_open(self) -> None:
        """This value travels into someone else's CI artifact and SARIF upload.

        A path relative to this repository names nothing there: the wheel and
        the image ship no docs/. It has to be this project's own page, at a
        section that exists, so renaming either the repository or the README
        heading fails here instead of leaving every report with a dead link.
        """
        def anchors(readme: str) -> set[str]:
            return {
                re.sub(r"[^\w\- ]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
                for line in readme.splitlines() if line.startswith("#")
            }

        repository = re.search(r'^Repository = "(.+)"$',
                               (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        page, _, anchor = core._interpretation()["reference"].partition("#")
        self.assertEqual(page, repository.group(1))
        self.assertIn(anchor, anchors(readme))
        # Control: the slug rule can miss, so a heading that is not there is not found.
        self.assertNotIn(anchor, anchors(readme.replace("proves data flow", "shows data flow")))

    def test_interpretation_survives_the_run_json_round_trip(self) -> None:
        holder = _TempConfig(_base_config())
        try:

            def responder(path, token):
                return (200, {}, _json_body({"ref": MARKER}))

            with _server(responder) as url:
                result = execute_run(
                    holder.path, output_dir=holder.root / "out", base_url=url
                )
            reloaded = load_run(holder.root / "out" / "latest.json")
            self.assertEqual(reloaded["interpretation"], result["interpretation"])
        finally:
            holder.close()

    def test_sarif_run_properties_carry_the_interpretation(self) -> None:
        sarif = to_sarif(self._confirmed_run())
        properties = sarif["runs"][0]["properties"]["interpretation"]
        self.assertEqual(properties["summary"], core.DECLARATION_SCOPE)

    def test_sarif_from_a_v1_run_without_interpretation_still_scopes_itself(
        self,
    ) -> None:
        """A pre-existing run document must not lose the caveat on re-report."""
        result = self._confirmed_run()
        legacy = {key: value for key, value in result.items() if key != "interpretation"}
        legacy["schema_version"] = 1
        sarif = to_sarif(legacy)
        self.assertEqual(
            sarif["runs"][0]["properties"]["interpretation"]["summary"],
            core.DECLARATION_SCOPE,
        )
        self.assertEqual(
            sarif["runs"][0]["tool"]["driver"]["fullDescription"]["text"],
            core.DECLARATION_SCOPE,
        )

    def test_interpretation_is_not_persisted_response_content(self) -> None:
        """The new block is derived text only: no marker, no body bytes."""
        result = self._confirmed_run()
        self.assertNotIn(MARKER, json.dumps(result["interpretation"]))

    @fast("asserts on the declaration, not on a live target")
    def test_declaration_scope_is_printable_on_any_console(self) -> None:
        """Printed on every run, so it must survive a non-UTF-8 stdout."""
        core.DECLARATION_SCOPE.encode("ascii")

    @fast("asserts on the declaration, not on a live target")
    def test_pass_scope_is_printable_on_any_console(self) -> None:
        core.PASS_SCOPE.encode("ascii")

    def test_no_remediation_orders_a_target_change_without_the_alternative(
        self,
    ) -> None:
        """Remediation is an emitted string and gets the same scoping as the rest.

        A bare imperative to change the server ("Enforce authorization ...
        before returning data") asserts the target is the broken half. It is
        also the more expensive of the two hypotheses; README calls eliminating
        the declaration the cheaper one. Every remediation must therefore offer
        the declaration as the alternative.
        """
        runs = [self._confirmed_run(), self._denied_run(), self._leak_run()]
        seen = set()
        for result in runs:
            for finding in result["findings"]:
                text = finding["remediation"]
                seen.add(finding["rule_id"])
                if finding["rule_id"] in {"VERIDOR-EXEC-001", "VERIDOR-ORACLE-001"}:
                    # Procedural, not a claim about who is at fault.
                    continue
                self.assertIn("declar", text.lower(), text)
                self.assertNotIn(
                    "enforce authorization for this resource", text.lower(), text
                )
        self.assertIn("VERIDOR-AUTHZ-001", seen)
        self.assertIn("VERIDOR-LEAK-001", seen)

    def test_finding_remediation_matches_the_sarif_help_for_the_same_rule(
        self,
    ) -> None:
        """One rule, one piece of advice.

        The SARIF consumer and the run-JSON/UI consumer must not read different
        guidance for the identical finding.
        """
        for result in (self._confirmed_run(), self._leak_run()):
            sarif = to_sarif(result)
            helps = {
                rule["id"]: rule["help"]["text"]
                for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
            }
            for finding in result["findings"]:
                if finding["rule_id"] in {"VERIDOR-AUTHZ-001", "VERIDOR-LEAK-001"}:
                    self.assertEqual(
                        finding["remediation"], helps[finding["rule_id"]]
                    )

    def _denied_run(self) -> dict:
        def responder(path, token):
            return (404, {}, _json_body({"error": "no such route"}))

        config = _base_config(markers=False)
        config["checks"][0]["expect"]["owner"]["status"] = [200]
        with _server(responder) as url:
            return _run(config, url)

    def _leak_run(self) -> dict:
        # The 404 leaks the owner's marker to the outsider only. Serving it to
        # every caller, sham included, modelled a string anybody can read --
        # which is an unverified oracle, not a leak (see KNOWN_TOKENS).
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            if _known(token):
                return (404, {}, _json_body({"error": f"missing {MARKER}"}))
            return (404, {}, _json_body({"error": "missing"}))

        with _server(responder) as url:
            return _run(_base_config(), url)


@slow("stands up a loopback HTTP server and runs the engine against it")
class RefusedProbeVerdictTest(unittest.TestCase):
    """A probe the target REFUSED is not a disclosure.

    coverage.status_class calls 403 and 404 authorization denials, and
    DEFAULT_DENIAL_STATUSES is exactly {403, 404}. Grading an observed denial
    'vulnerable' contradicts Veridor's own model and attaches a remediation
    ("stop returning data") that is incoherent on a 404 that returned none.
    """

    def _run_denied(self, owner_status: list[int], outsider_status: list[int]) -> dict:
        def responder(path, token):
            return (404, {}, _json_body({"error": "not found"}))

        config = _base_config(markers=False)
        config["checks"][0]["expect"]["owner"]["status"] = owner_status
        config["checks"][0]["expect"]["outsider"]["status"] = outsider_status
        with _server(responder) as url:
            return _run(config, url)

    def test_an_observed_denial_is_not_graded_vulnerable(self) -> None:
        result = self._run_denied([200], [403])
        for identity in ("owner", "outsider"):
            finding = _finding(result, identity)
            self.assertEqual(finding["verdict"], "unexpected_denial", identity)
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(result["summary"]["unexpected_denial"], 2)

    def test_a_refused_probe_is_never_told_to_stop_returning_data(self) -> None:
        finding = _finding(self._run_denied([200], [403]), "owner")
        self.assertNotIn("before returning data", finding["remediation"])
        self.assertIn("refused this request", finding["message"])

    def test_a_refused_probe_is_still_a_finding_and_still_fails_the_gate(self) -> None:
        """Narrowing the verdict must not soften the gate."""
        result = self._run_denied([200], [403])
        self.assertEqual(len(result["findings"]), 2)
        # STILL `failed`. These are unexpected_denial findings -- statements
        # about the target -- and the three-valued status must not soften one.
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"]["safe"], 0)
        for finding in result["findings"]:
            self.assertEqual(finding["level"], "error")

    def test_an_observed_allow_outside_the_declaration_is_still_vulnerable(
        self,
    ) -> None:
        def responder(path, token):
            return (200, {}, _json_body({"ok": True}))

        config = _base_config(markers=False)
        config["checks"][0]["expect"]["outsider"]["status"] = [403]
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(_finding(result, "outsider")["verdict"], "vulnerable")

    def test_a_refusal_that_carries_the_marker_stays_vulnerable(self) -> None:
        """A 404 whose error body leaks the victim's marker disclosed data."""

        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            if not _known(token):
                return (403, {}, _json_body({"error": "forbidden"}))
            return (403, {}, _json_body({"error": f"owned by {MARKER}"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "confirmed")

    def test_the_verdict_change_does_not_move_a_fingerprint(self) -> None:
        """Invariant 3: verdict is a property and is absent from _finding_id."""
        signature = inspect.getsource(core._finding_id)
        self.assertNotIn("verdict", signature)
        finding = _finding(self._run_denied([200], [403]), "owner")
        check = {
            "id": "records",
            "request": {"method": "GET", "path": "/records/1"},
        }
        self.assertEqual(finding["id"], _finding_id(check, "owner", "status", [200]))


@slow("stands up a loopback HTTP server and runs the engine against it")
class VacuousExclusionTest(unittest.TestCase):
    """An identity marker_probe must not license an oracle this path cannot bear.

    The mandatory-control gate exists because the absence of a marker is
    unfalsifiable without a control. The identity marker_probe was an escape
    hatch through that gate: it proves the marker is live SOMEWHERE, so a check
    whose endpoint can never surface a marker for anyone passed clean and
    green, which is the exact failure the gate exists to prevent.
    """

    #: alice owns the marker and can prove it live at her own profile. The
    #: resource under test serves alice's data to everyone and carries no
    #: marker in any projection, so no exclusion is falsifiable there.
    def _config(self, *, in_check: bool, probe: bool = True) -> dict:
        alice: dict = {
            "headers": {"Authorization": "Bearer alice-token"},
            "marker": MARKER,
        }
        if probe:
            alice["marker_probe"] = {"method": "GET", "path": "/a/profile"}
        expect: dict = {}
        if in_check:
            expect["alice"] = {"status": [200]}
        expect["bob"] = {"status": [200], "excludes_marker": "alice"}
        if not in_check:
            # A check needs two identities; 'carol' stands in for alice so the
            # marker owner is genuinely absent from this check.
            expect["carol"] = {"status": [200]}
        return {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 3},
            "identities": {
                "alice": alice,
                "bob": {"headers": {"Authorization": "Bearer bob-token"}},
                "carol": {"headers": {"Authorization": "Bearer carol-token"}},
            },
            "checks": [
                {
                    "id": "shared",
                    "name": "Shared resource",
                    "request": {"method": "GET", "path": "/shared/resource"},
                    "expect": expect,
                }
            ],
        }

    def _responder(self, *, marker_at_shared: bool = False):
        def responder(path, token):
            # Ownership modelled (see KNOWN_TOKENS): a credential nobody
            # issued is refused, so a marker it does not get back is the
            # owner's and a crossing can be `confirmed`.
            if token not in ("Bearer alice-token", "Bearer bob-token",
                             "Bearer carol-token"):
                return (401, {}, b"{}")
            if path == "/a/profile":
                return (200, {}, _json_body({"user": "alice", "ref": MARKER}))
            body = {"owner": "alice", "note": "alice private data"}
            if marker_at_shared:
                body["ref"] = MARKER
            return (200, {}, _json_body(body))

        return responder

    def test_a_probe_cannot_license_an_oracle_the_check_disproves(self) -> None:
        with _server(self._responder()) as url:
            result = _run(self._config(in_check=True), url)
        finding = _finding(result, "bob")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(finding["rule_id"], "VERIDOR-ORACLE-001")
        # `inconclusive`, not `failed`: every finding here is a probe that
        # could not be graded, and calling that a failure is what made the
        # artifact contradict the exit code.
        self.assertEqual(result["status"], "inconclusive")
        marker = finding["evidence"]["marker"]
        self.assertEqual(marker["control_source"], "check_observed")
        self.assertEqual(marker["control_state"], "missing")
        self.assertIn("was served this exact request", marker["control_reason"])

    def test_the_same_assertion_grades_the_same_with_either_control(self) -> None:
        """The declared same-check control and the observed one must agree.

        Before the fix these two byte-identical assertions against the same
        target disagreed: the declared control reported the oracle unverified
        and failed the build, while the marker_probe route reported a clean
        green pass.
        """
        declared = self._config(in_check=True, probe=False)
        declared["checks"][0]["expect"]["alice"]["contains_marker"] = "alice"
        with _server(self._responder()) as url:
            observed_result = _run(self._config(in_check=True), url)
            declared_result = _run(declared, url)
        self.assertEqual(observed_result["status"], declared_result["status"])
        self.assertEqual(
            _finding(observed_result, "bob")["verdict"],
            _finding(declared_result, "bob")["verdict"],
        )

    def test_an_observed_control_that_sees_its_marker_licenses_the_pass(self) -> None:
        """No false positives: a path that CAN surface the marker still passes."""
        with _server(self._responder(marker_at_shared=True)) as url:
            result = _run(self._config(in_check=True), url)
        # alice's marker is at this path, and bob's response carries it too,
        # so this is a measured flow rather than an unverifiable oracle.
        finding = _finding(result, "bob")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(finding["evidence"]["marker"]["control_source"], "check_observed")

    def test_a_refused_owner_probe_falls_back_to_the_identity_probe(self) -> None:
        """A denial to the owner says nothing, so it must not veto the probe.

        This is the per-principal-scoped shape the marker_probe exists for: the
        owner cannot be served at the attacker's path, so the absence of the
        owner's marker there is expected and carries no information.
        """

        def responder(path, token):
            if path == "/a/profile":
                return (200, {}, _json_body({"user": "alice", "ref": MARKER}))
            if token == "Bearer alice-token":
                return (403, {}, _json_body({"error": "principal mismatch"}))
            return (200, {}, _json_body({"owner": "bob"}))

        config = self._config(in_check=True)
        config["checks"][0]["expect"]["alice"]["status"] = [403]
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(result["status"], "passed")
        # One licence by the identity probe. This target also serves any
        # unknown bearer at alice's path, so the fabricated-credential control
        # is served too and is disclosed beside it, under its own source.
        by_source = Counter(entry["control_source"]
                            for entry in result["oracle_disclosures"])
        self.assertEqual(by_source, {"identity_probe": 1, "fabricated_credential": 1})
        self.assertEqual(result["summary"]["probe_licensed_exclusions"], 1)

    def test_an_unprobed_owner_still_uses_the_identity_probe(self) -> None:
        with _server(self._responder()) as url:
            result = _run(self._config(in_check=False), url)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["probe_licensed_exclusions"], 1)

    def test_the_implicit_control_scan_persists_no_body(self) -> None:
        """Invariant 2: scanning an extra response must not persist one."""
        with _server(self._responder()) as url:
            result = _run(self._config(in_check=True), url)
        self.assertNotIn(MARKER, json.dumps(result))
        for probe in result["probes"]:
            self.assertNotIn("body", probe["response"])


@slow("stands up a loopback HTTP server and runs the engine against it")
class PassDisclosureTest(unittest.TestCase):
    """A green run must disclose what it did not establish.

    Both of these outcomes emit NO finding, so before this they were invisible
    in every human-facing channel: the console never mentioned them, SARIF
    emits nothing for a passing check, and the UI rendered neither.
    """

    def _permissive_config(self) -> dict:
        config = _base_config(markers=False)
        config["checks"][0]["expect"]["owner"]["status"] = [200, 401, 403, 404]
        config["checks"][0]["expect"]["outsider"]["status"] = [200, 401, 403, 404]
        return config

    def test_an_expectation_that_asserts_nothing_is_disclosed_on_a_pass(self) -> None:
        def responder(path, token):
            return (200, {}, _json_body({"ok": True}))

        with _server(responder) as url:
            result = _run(self._permissive_config(), url)
        # The run genuinely passed; the compatibility promise forbids turning
        # this into a finding that would change an existing config's exit code.
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["non_asserting"], 2)
        statements = [
            entry["statement"] for entry in result["non_asserting_expectations"]
        ]
        for statement in statements:
            self.assertIn("asserts nothing about the boundary", statement)

    def test_a_denial_only_expectation_is_not_flagged(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ok": True}))
            return (404, {}, _json_body({"error": "no"}))

        with _server(responder) as url:
            result = _run(_base_config(markers=False), url)
        self.assertEqual(result["summary"]["non_asserting"], 0)
        self.assertNotIn("non_asserting_expectations", result)

    @fast("asserts on the declaration, not on a live target")
    def test_the_run_uses_the_same_classifier_the_coverage_report_uses(self) -> None:
        """One definition of 'asserts nothing', shared by both commands."""
        from veridor.coverage import classify_expectation

        self.assertEqual(classify_expectation([200, 403]), "permissive")
        self.assertEqual(classify_expectation([403, 404]), "denial_only")
        source = inspect.getsource(core._non_asserting_expectations)
        self.assertIn("classify_expectation", source)

    def test_interpretation_scopes_a_pass_as_well_as_a_finding(self) -> None:
        def responder(path, token):
            return (200, {}, _json_body({"ok": True}))

        with _server(responder) as url:
            result = _run(self._permissive_config(), url)
        interpretation = result["interpretation"]
        self.assertEqual(interpretation["pass_means"], core.PASS_SCOPE)
        self.assertIn("boundary is enforced", interpretation["pass_does_not_mean"])

    def test_sarif_carries_the_pass_disclosures_it_emits_no_result_for(self) -> None:
        def responder(path, token):
            return (200, {}, _json_body({"ok": True}))

        with _server(responder) as url:
            result = _run(self._permissive_config(), url)
        properties = to_sarif(result)["runs"][0]["properties"]
        self.assertEqual(len(properties["nonAssertingExpectations"]), 2)
        self.assertEqual(properties["interpretation"]["pass_means"], core.PASS_SCOPE)

    def test_a_suite_with_nothing_to_disclose_gains_no_keys(self) -> None:
        def responder(path, token):
            if token == "Bearer owner-token":
                return (200, {}, _json_body({"ref": MARKER}))
            return (404, {}, _json_body({"error": "no"}))

        with _server(responder) as url:
            result = _run(_base_config(), url)
        self.assertNotIn("oracle_disclosures", result)
        self.assertNotIn("non_asserting_expectations", result)
        self.assertNotIn("unreviewed_promotion_stubs", result)
        properties = to_sarif(result)["runs"][0]["properties"]
        self.assertNotIn("nonAssertingExpectations", properties)
        self.assertNotIn("unreviewedPromotionStubs", properties)


@slow("stands up a loopback HTTP server and runs the engine against it")
class RunVocabularyTest(unittest.TestCase):
    """The vocabulary police covered `map` and not `run`.

    `blastradius.BANNED_CANDIDATE_WORDS` extends `coverage.BANNED_CLAIM_WORDS`
    and a test renders every candidate rule against it -- but `run` is where
    the STRONGEST claim this product makes lives, and nothing scanned it. So
    `confirmed` was outside the contract entirely, which is how "data owned by
    X reached Y" survived until a counterexample falsified it.

    Scoped deliberately. `run` may legitimately say `vulnerable` -- that is a
    verdict it earned by comparing an observation against a declaration -- so
    BANNED_CANDIDATE_WORDS does not apply here. What must never appear is the
    language of a GUARANTEE.
    """

    #: From `coverage.BANNED_CLAIM_WORDS`, minus two that appear in legitimate
    #: hedges rather than as claims: `safe` is a verdict name, and `verified`
    #: occurs in "unverified rather than verified", which is the disclaimer.
    #: The rest have no honest use in a finding about somebody's target.
    FORBIDDEN = ("secure", "protected", "compliant", "guaranteed")

    def _strings(self, result: dict) -> list[str]:
        out: list[str] = []
        for finding in result["findings"]:
            out += [str(finding.get(key, "")) for key in
                    ("title", "message", "remediation")]
        interpretation = result.get("interpretation") or {}
        out += [str(v) for v in interpretation.values()]
        out += [str(entry.get("statement", ""))
                for entry in result.get("liveness", {}).get("unproven", [])]
        return out

    def _leaky(self) -> dict:
        body = json.dumps({"id": 1, "ref": MARKER}).encode()

        def responder(path, token):
            if _known(token):
                return 200, {"Content-Type": "application/json"}, body
            return 404, {}, b"{}"

        with _server(responder) as url:
            return _run(_base_config(), url)

    def test_a_confirmed_finding_makes_no_guarantee(self) -> None:
        for text in self._strings(self._leaky()):
            for word in self.FORBIDDEN:
                with self.subTest(word=word, text=text[:60]):
                    self.assertNotIn(word, text.lower())

    def test_an_inconclusive_run_makes_no_guarantee(self) -> None:
        def responder(path, token):
            return (500, {}, b"{}")

        with _server(responder) as url:
            result = _run(_base_config(), url)
        for text in self._strings(result):
            for word in self.FORBIDDEN:
                with self.subTest(word=word):
                    self.assertNotIn(word, text.lower())

    def test_the_confirmed_claim_states_its_own_premise(self) -> None:
        """The falsified sentence must not come back."""
        messages = " ".join(self._strings(self._leaky()))
        self.assertNotIn("data owned by", messages)
        self.assertIn("insofar as the marker is unique", messages)


@slow("stands up a loopback HTTP server and runs the engine against it")
class MarkerUniquenessTest(unittest.TestCase):
    """`confirmed` was issued on a value that belonged to nobody.

    A config pointed at a target returning the same build
    id to every caller, where that id happened to be the declared marker:

        owner    200 bfdc4bfb483e237b 40
        attacker 200 bfdc4bfb483e237b 40

    Byte-identical. Nothing crossed any boundary. Veridor issued its strongest
    verdict -- the one `--fail-on confirmed` gates a release on.

    The obvious fix is wrong and this class exists partly to keep it out. A
    body-equality gate would demote the FLAGSHIP true positive: the shipped
    demo IDOR serves the attacker the victim's record verbatim, so identical
    bytes is the signature of a real leak, not a fake one. `blastradius`
    reached the same conclusion at TAG_IDENTICAL_BODY -- "used only to rank
    down, never to raise a candidate, and never to drop one".

    What separates them is whether the marker is owner-specific, and the sham
    credential answers it: a string that comes back to a caller the target
    cannot possibly recognise is not gated on being the owner.
    """

    OWNER = "Bearer owner-token"

    def _config(self) -> dict:
        config = _base_config()
        config["checks"][0]["expect"]["outsider"]["status"] = [404]
        return config

    def test_a_marker_anybody_can_read_is_not_confirmed(self) -> None:
        body = json.dumps({"build": MARKER}).encode()

        def responder(path, token):
            return 200, {"Content-Type": "application/json"}, body

        with _server(responder) as url:
            result = _run(self._config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "suspected")
        self.assertIn("not unique to its data", finding["message"])

    def test_a_real_leak_is_still_confirmed_on_identical_bytes(self) -> None:
        """The control, and the reason body equality is not the gate.

        This is what an IDOR looks like: the attacker reads the victim's
        record verbatim, so owner and attacker get the SAME bytes. A gate on
        byte equality demotes exactly this -- the product's headline finding.
        """
        body = json.dumps({"id": 1, "ref": MARKER}).encode()

        def responder(path, token):
            if token in (self.OWNER, "Bearer outsider-token"):
                return 200, {"Content-Type": "application/json"}, body
            return 404, {}, b"{}"

        with _server(responder) as url:
            result = _run(self._config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        owner, outsider = (
            next(p for p in result["probes"] if p["identity"] == name)
            for name in ("owner", "outsider")
        )
        self.assertEqual(
            owner["response"]["body_sha256"], outsider["response"]["body_sha256"],
            "the fixture must produce identical bytes or it tests nothing",
        )

    def _accepting_config(self) -> dict:
        """The outsider may read this request; its body must not carry the marker."""
        config = self._config()
        config["checks"][0]["expect"]["outsider"]["status"] = [200]
        return config

    def test_a_marker_served_to_everyone_on_a_2xx_check_is_not_confirmed(self) -> None:
        """The uniqueness control ran only beside a denial-only expectation.

        A list endpoint the outsider may read, whose body must not carry the
        owner's marker, never got a fabricated credential, so a build id
        served to every caller was graded VERIDOR-LEAK-001 `confirmed` -- in
        the same run that graded the same id `not unique` on a 403 check.
        """
        body = json.dumps({"footer": MARKER}).encode()
        seen: list = []

        def responder(path, token):
            seen.append(token)
            if token in KNOWN_TOKENS:
                return 200, {"Content-Type": "application/json"}, body
            # An error page with the same footer.
            return 401, {"Content-Type": "application/json"}, body

        stderr = io.StringIO()
        with _server(responder) as url, contextlib.redirect_stderr(stderr):
            result = _run(self._accepting_config(), url)
        self.assertEqual(len([t for t in seen if "veridor-sham-" in t]), 1)
        self.assertIn("1 extra request(s) carrying a credential", stderr.getvalue())
        self.assertIn("(1 of them) excludes an owner's marker", stderr.getvalue())
        self.assertEqual(result["liveness"]["requests_issued"], 1)
        finding = _finding(result, "outsider")
        self.assertNotEqual(finding.get("evidence_grade"), "confirmed")
        self.assertEqual(finding["rule_id"], "VERIDOR-ORACLE-001")
        self.assertIn("not unique to its data", finding["message"])
        self.assertNotIn("marker_uniqueness_not_checked", result["liveness"])

    def test_a_real_leak_on_a_2xx_check_is_still_confirmed(self) -> None:
        """The control: the fabricated credential is refused without the marker."""
        body = json.dumps({"id": 1, "ref": MARKER}).encode()

        def responder(path, token):
            if token in KNOWN_TOKENS:
                return 200, {"Content-Type": "application/json"}, body
            return 401, {}, b"{}"

        with _server(responder) as url:
            result = _run(self._accepting_config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(finding["evidence_grade"], "confirmed")

    def test_the_marker_request_is_counted_in_the_plan(self) -> None:
        reasons = core.plan_liveness_reasons(self._accepting_config())
        self.assertEqual(reasons, {("GET", "/records/1"): {"excludes_marker"}})
        from veridor import mutation  # noqa: PLC0415

        self.assertEqual(mutation._liveness_requests(self._accepting_config(), True), 1)

    def test_a_shared_marker_beside_the_declared_status_is_not_confirmed(self) -> None:
        """The cap held only when the status ALSO mismatched.

        The outsider is declared [404] and gets 404, so the only thing left to
        grade is the marker -- and the sham got that marker back too. The
        matched-status branch issued LEAK-001 `confirmed` without asking, which
        is a pure false positive on the grade `--fail-on confirmed` gates on.

        Capping it at LEAK-001 `suspected` was not enough: the verdict stayed
        `vulnerable`, so the default `new+confirmed` gate still failed the run
        on a finding whose own message said the crossing proved nothing. With
        the status matched and the marker disproved, nothing in the probe is
        evidence of a leak; it is an oracle that could not be verified, graded
        the way an unverified excludes_marker already is.
        """
        body = json.dumps({"build": MARKER}).encode()

        def responder(path, token):
            if token == self.OWNER:
                return 200, {"Content-Type": "application/json"}, body
            return 404, {"Content-Type": "application/json"}, body

        with _server(responder) as url:
            result = _run(self._config(), url)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(finding["evidence_grade"], "n/a")
        self.assertEqual(finding["level"], "warning")
        self.assertIn("not unique to its data", finding["message"])
        self.assertNotIn("proof the string crossed", finding["message"])
        self.assertFalse(
            [f for f in result["findings"] if f["verdict"] == "vulnerable"],
            "a disproved marker beside a matched status is no evidence of a leak",
        )

    def test_a_shared_marker_beside_the_declared_status_does_not_fail_the_gate(
        self,
    ) -> None:
        """The exit code a CI job reads, under the default gate and under
        --require-complete, which is where an unverified oracle belongs."""
        body = json.dumps({"build": MARKER}).encode()

        def responder(path, token):
            if token == self.OWNER:
                return 200, {"Content-Type": "application/json"}, body
            return 404, {"Content-Type": "application/json"}, body

        codes = {}
        for label, extra in (("default", []), ("complete", ["--require-complete"])):
            holder = _TempConfig(self._config())
            try:
                with _server(responder) as url, contextlib.redirect_stdout(
                    io.StringIO()
                ), contextlib.redirect_stderr(io.StringIO()):
                    codes[label] = veridor_main([
                        "run", "--config", str(holder.path), "--base-url", url,
                        "--output-dir", str(holder.root / "out"), *extra,
                    ])
            finally:
                holder.close()
        self.assertEqual(codes, {"default": 0, "complete": 3})

    def test_a_later_check_on_the_same_request_does_not_unscan_the_sham(self) -> None:
        """The sham's marker was last-wins per (method, path).

        A status-only check appended on the same request set that marker to
        None, so the sham was not scanned and an earlier check's shared build
        id graded `confirmed`. Prepending the same check graded `suspected`.
        """
        body = json.dumps({"build": MARKER}).encode()

        def responder(path, token):
            return 200, {"Content-Type": "application/json"}, body

        for position in ("after", "before"):
            config = self._config()
            status_only = {
                "id": "records-status-only",
                "request": {"method": "GET", "path": "/records/1"},
                "expect": {"owner": {"status": [200]}, "outsider": {"status": [200]}},
            }
            if position == "after":
                config["checks"].append(status_only)
            else:
                config["checks"].insert(0, status_only)
            with self.subTest(position=position), _server(responder) as url:
                result = _run(config, url)
                finding = _finding(result, "outsider", "records")
                self.assertEqual(finding["evidence_grade"], "suspected")
                self.assertIn("not unique to its data", finding["message"])

    def test_each_check_is_graded_against_its_own_owner_marker(self) -> None:
        """Two checks on one request that exclude different owners' markers.

        Last-wins scanned the sham for the second owner's marker only, so the
        first owner's shared build id was never compared and graded
        `confirmed`.
        """
        body = json.dumps({"build": MARKER}).encode()

        def responder(path, token):
            return 200, {"Content-Type": "application/json"}, body

        # Both orders: the first owner's marker is scanned on the wire, every
        # further one in the bytes that response already left in memory.
        for position in ("after", "before"):
            config = self._config()
            config["identities"]["outsider"]["marker"] = OTHER_MARKER
            reverse = {
                "id": "records-reverse",
                "request": {"method": "GET", "path": "/records/1"},
                "expect": {
                    "owner": {"status": [200], "excludes_marker": "outsider"},
                    "outsider": {"status": [200], "contains_marker": "outsider"},
                },
            }
            if position == "after":
                config["checks"].append(reverse)
            else:
                config["checks"].insert(0, reverse)
            with self.subTest(position=position), _server(responder) as url:
                result = _run(config, url)
                finding = _finding(result, "outsider", "records")
                self.assertEqual(finding["evidence_grade"], "suspected")
                self.assertIn("not unique to its data", finding["message"])
                self.assertEqual(result["liveness"]["requests_issued"], 1)

    def test_the_claim_no_longer_asserts_exclusive_ownership(self) -> None:
        """The falsified sentence, gone from the finding it was emitted on."""
        body = json.dumps({"id": 1, "ref": MARKER}).encode()

        def responder(path, token):
            if token in (self.OWNER, "Bearer outsider-token"):
                return 200, {"Content-Type": "application/json"}, body
            return 404, {}, b"{}"

        with _server(responder) as url:
            result = _run(self._config(), url)
        message = _finding(result, "outsider")["message"]
        self.assertNotIn("data owned by", message)
        self.assertIn("proof the string crossed", message)
        self.assertIn("insofar as the marker is unique", message)


@slow("stands up a loopback HTTP server and runs the engine against it")
class LivenessControlTest(unittest.TestCase):
    """A denial-only expectation is satisfied by a boundary AND by a dead token.

    Reproduced, and it is the worst shape in the report
    because it is invisible on every channel and one character wide. Two configs
    byte-identical except `outsider-token` -> `outsider-token-EXPIRED`:

        valid   -> 1/2 matched, 1 vulnerable, [confirmed], EXIT=1
        expired -> 2/2 matched, 0 vulnerable, 0 inconclusive, EXIT=0

    The cross-tenant read is still live. The target answers 404 to any
    unrecognised token, so `"status": [404]` passes vacuously. This is what
    happens the week your test tokens rotate.

    The control is one probe carrying a credential Veridor fabricated. If the
    target answers it exactly as it answered the declared identity, that
    identity's credential distinguished nothing.
    """

    OWNER = "Bearer owner-token"

    #: The credential the target actually honours. The leak is real and lives
    #: here regardless of what the config declares.
    LIVE_OUTSIDER = "Bearer outsider-token"

    def _leaky(self, declared_outsider: str) -> dict:
        """A target that leaks to LIVE_OUTSIDER, probed with `declared_outsider`.

        The whole defect is the gap between those two. The target is identical
        in both arms; only the token in the config changes, which is exactly
        what happens the week your test credentials rotate.
        """
        body = json.dumps({"id": 1, "ref": MARKER}).encode()

        def responder(path, token):
            if token in (self.OWNER, self.LIVE_OUTSIDER):
                return 200, {"Content-Type": "application/json"}, body
            return 404, {}, b"{}"

        config = _base_config()
        config["identities"]["outsider"]["headers"]["Authorization"] = declared_outsider
        with _server(responder) as url:
            return _run(config, url)

    def test_a_live_attacker_credential_still_finds_the_leak(self) -> None:
        """The control: liveness must not suppress a real finding."""
        result = self._leaky("Bearer outsider-token")
        finding = _finding(result, "outsider")
        self.assertEqual(finding["verdict"], "vulnerable")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertNotEqual(finding["rule_id"], "VERIDOR-CRED-001")

    def test_a_dead_attacker_credential_is_disclosed_not_passed(self) -> None:
        """Disclosed, not a finding -- and the distinction is the design.

        An identity asserted only to be denied and never served anywhere is the
        ORDINARY shape of an authorization suite. Emitting a finding fired on
        the majority of correct configurations; `mutate`'s M6 refused the same
        move for the same reason. The fact is recorded and printed on every
        run; `--require-complete` decides whether it moves an exit code.
        """
        result = self._leaky("Bearer outsider-token-EXPIRED")
        self.assertEqual(result["findings"], [])
        unproven = result["liveness"]["unproven"]
        self.assertEqual(len(unproven), 1)
        self.assertEqual(unproven[0]["identity"], "outsider")
        self.assertIn("fabricated", unproven[0]["statement"])
        self.assertIn("marker_probe", unproven[0]["remediation"])

    def test_a_uniform_404_target_is_disclosed_not_a_finding(self) -> None:
        """The acceptance case: existence hidden from everyone.

        The declared identity and the sham genuinely cannot be told apart, and
        no probing from outside will separate them. Saying so is honest;
        inventing a finding about the target would be a guess.
        """
        def responder(path, token):
            return (200, {"Content-Type": "application/json"},
                    json.dumps({"id": 1, "ref": MARKER}).encode()) \
                if token == self.OWNER else (404, {}, b"{}")

        with _server(responder) as url:
            result = _run(_base_config(), url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["liveness"]["unproven"]), 1)

    def test_a_provably_live_credential_is_not_disclosed(self) -> None:
        """Served anywhere in the run settles it, and the noise disappears.

        This is the remediation the disclosure recommends, and the reason the
        shipped demo fixture now gives `other_tenant` a resource it owns.
        """
        body = json.dumps({"id": 1, "ref": MARKER}).encode()
        own = json.dumps({"id": 2, "ref": "vdr-outsiderownmarker0001"}).encode()

        def responder(path, token):
            if path == "/mine" and token == "Bearer outsider-token":
                return 200, {"Content-Type": "application/json"}, own
            if token == self.OWNER:
                return 200, {"Content-Type": "application/json"}, body
            return 404, {}, b"{}"

        config = _base_config()
        config["identities"]["outsider"]["marker"] = "vdr-outsiderownmarker0001"
        config["identities"]["outsider"]["marker_probe"] = {
            "method": "GET", "path": "/mine",
        }
        with _server(responder) as url:
            result = _run(config, url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["liveness"]["unproven"], [])

    def test_it_can_be_turned_off(self) -> None:
        body = json.dumps({"id": 1, "ref": MARKER}).encode()

        def responder(path, token):
            return ((200, {"Content-Type": "application/json"}, body)
                    if token == self.OWNER else (404, {}, b"{}"))

        holder = _TempConfig(_base_config())
        try:
            with _server(responder) as url:
                result = execute_run(
                    holder.path, output_dir=holder.root / "out", base_url=url,
                    prove_liveness=False,
                )
        finally:
            holder.close()
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["liveness"]["enabled"])
        self.assertEqual(result["liveness"]["requests_issued"], 0)

    def test_the_extra_requests_are_disclosed_in_the_artifact(self) -> None:
        result = self._leaky("Bearer outsider-token")
        liveness = result["liveness"]
        self.assertTrue(liveness["enabled"])
        self.assertEqual(liveness["requests_issued"], 1)
        self.assertEqual(liveness["requests"],
                         [{"method": "GET", "path": "/records/1"}])

    def test_a_disclosure_never_becomes_a_sarif_result(self) -> None:
        """It is not a finding, so it must not arrive as one."""
        result = self._leaky("Bearer outsider-token-EXPIRED")
        sarif = to_sarif(result)
        self.assertEqual(sarif["runs"][0]["results"], [])

    @contextlib.contextmanager
    def _write_target(self, seen: list):
        """Owner is served on every method; anyone else is refused with 404.

        Records (method, path, Authorization) so a test can show what was, and
        was not, sent.
        """

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _answer(self) -> None:
                token = self.headers.get("Authorization", "")
                seen.append((self.command, self.path, token))
                status = 200 if token in (LivenessControlTest.OWNER,
                                          "Bearer outsider-token") else 404
                if self.path == "/api/public":
                    status = 200  # serves every caller, credential or not
                if self.path == "/records/1" and token == "Bearer outsider-token":
                    status = 404
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_DELETE = do_POST = do_PUT = do_PATCH = _answer  # noqa: N815

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

    def _write_config(self, outsider_token: str) -> dict:
        config = _base_config(markers=False)
        config["identities"]["outsider"]["headers"]["Authorization"] = outsider_token
        config["checks"][0]["request"]["method"] = "DELETE"
        return config

    def test_a_dead_attacker_credential_on_a_write_is_unproven(self) -> None:
        """A write check is not shammed, and that used to mean not checked.

        The planner dropped every non-GET/HEAD/OPTIONS check, so an expired
        token on DELETE passed with exit 0 under --require-complete, the run
        document said liveness was on with nothing unproven, and nothing on
        either channel said write checks were left out. Veridor still never
        sends a fabricated credential with a method that can change state; the
        denial is counted unproven instead, unless the identity is shown live
        some other way.
        """
        seen: list = []
        holder = _TempConfig(self._write_config("Bearer outsider-token-EXPIRED"))
        out = holder.root / "run.json"
        stderr, stdout = io.StringIO(), io.StringIO()
        try:
            with self._write_target(seen) as url, \
                    contextlib.redirect_stderr(stderr), \
                    contextlib.redirect_stdout(stdout):
                code = veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"),
                    "--json", str(out), "--require-complete",
                ])
            result = json.loads(out.read_text(encoding="utf-8"))
        finally:
            holder.close()
        self.assertEqual(
            [entry for entry in seen if "veridor-sham-" in entry[2]], [],
            "a fabricated credential must never ride a DELETE",
        )
        self.assertEqual(code, 3)
        liveness = result["liveness"]
        self.assertEqual(liveness["requests_issued"], 0)
        self.assertEqual(liveness["requests_not_probed"],
                         [{"method": "DELETE", "path": "/records/1",
                           "reason": "unsafe_method"}])
        self.assertEqual([entry["identity"] for entry in liveness["unproven"]],
                         ["outsider"])
        self.assertIn("DELETE", liveness["unproven"][0]["statement"])
        self.assertIn("1 DELETE request(s) accept only denial statuses",
                      stderr.getvalue())
        # Every console sentence about the entry must be true of a write: the
        # generic "a credential Veridor fabricated received too" alone is not.
        self.assertIn("or that no fabricated credential was sent to compare with",
                      stderr.getvalue())
        self.assertIn("or where no fabricated credential was sent to compare with",
                      stdout.getvalue())

    def test_a_write_denial_is_proven_by_a_credential_served_elsewhere(self) -> None:
        """The control: the same route GET checks already have out of it."""
        seen: list = []
        config = self._write_config("Bearer outsider-token")
        config["checks"].append({
            "id": "mine",
            "request": {"method": "GET", "path": "/mine"},
            "expect": {"owner": {"status": [200]}, "outsider": {"status": [200]}},
        })
        with self._write_target(seen) as url:
            result = _run(config, url)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["liveness"]["unproven"], [])
        self.assertEqual(
            [entry for entry in seen if "veridor-sham-" in entry[2]
             and entry[0] != "GET"], [],
        )

    def _uniqueness_run(self, *flags: str, method: str = "POST",
                        anonymous_only: bool = False):
        config = _base_config()
        config["checks"][0]["request"]["method"] = method
        if anonymous_only:
            for name in ("owner", "outsider"):
                config["identities"][name]["headers"] = {"Accept": "a/b"}
        seen: list = []
        holder = _TempConfig(config)
        out = holder.root / "run.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with self._write_target(seen) as url, \
                    contextlib.redirect_stderr(stderr), \
                    contextlib.redirect_stdout(stdout):
                veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"),
                    "--json", str(out), *flags,
                ])
            result = json.loads(out.read_text(encoding="utf-8"))
        finally:
            holder.close()
        return result, stdout.getvalue() + stderr.getvalue(), seen

    def test_marker_uniqueness_not_checked_is_said_where_no_sham_is_sent(
        self,
    ) -> None:
        """No fabricated credential, no uniqueness check -- and it is said.

        A marker that crosses on such a request is graded `confirmed` on the
        operator's premise alone, so the run says the check did not happen,
        on the console and in the run document, with the reason.
        """
        for label, kwargs, flags, reason in (
            ("write", {"method": "POST"}, (), "unsafe_method"),
            ("no header", {"method": "GET", "anonymous_only": True}, (),
             "no_credential_header"),
            ("switched off", {"method": "GET"}, ("--no-prove-liveness",),
             "prove_liveness_off"),
        ):
            with self.subTest(case=label):
                result, console, seen = self._uniqueness_run(*flags, **kwargs)
                self.assertEqual([e for e in seen if "veridor-sham-" in e[2]], [])
                self.assertEqual(
                    result["liveness"]["marker_uniqueness_not_checked"],
                    [{"method": kwargs["method"], "path": "/records/1",
                      "owner": "owner", "reason": reason}],
                )
                self.assertIn("Marker uniqueness not checked", console)
                self.assertIn(f"{kwargs['method']} /records/1", console)

    def test_both_notices_name_the_requests_left_without_a_control(self) -> None:
        """The CHANGELOG and README say these requests are named on the console.

        The `--no-prove-liveness` notice printed only a count, and the
        prove-on banners a count and the verbs: neither named a request, so an
        operator could not tell which declarations went unchecked.
        """
        config = self._write_config("Bearer outsider-token-EXPIRED")
        config["checks"].append({
            "id": "read", "request": {"method": "GET", "path": "/docs/7"},
            "expect": {"owner": {"status": [200]}, "outsider": {"status": [404]}},
        })
        for flags in ((), ("--no-prove-liveness",)):
            with self.subTest(flags=flags):
                holder = _TempConfig(config)
                stderr = io.StringIO()
                try:
                    with self._write_target([]) as url, \
                            contextlib.redirect_stderr(stderr), \
                            contextlib.redirect_stdout(io.StringIO()):
                        veridor_main([
                            "run", "--config", str(holder.path), "--base-url", url,
                            "--output-dir", str(holder.root / "out"), *flags,
                        ])
                finally:
                    holder.close()
                notices = [line for line in stderr.getvalue().splitlines()
                           if line.startswith("veridor: liveness controls")]
                write = [line for line in notices if "DELETE /records/1" in line]
                self.assertEqual(len(write), 1, notices)
                if flags:
                    self.assertIn("GET /docs/7", write[0])

    def test_a_public_route_does_not_prove_a_write_denial(self) -> None:
        """A 2xx on a route that serves an anonymous caller proves nothing.

        Any 2xx anywhere in the run used to prove the identity's credential
        live, so one check on a public route removed every write denial from
        `liveness.unproven`: a dead attacker token on a DELETE exited 0 under
        --require-complete, where the same config without the public check
        exited 3.
        """
        config = self._write_config("Bearer outsider-token-EXPIRED")
        config["checks"][0]["expect"]["owner"] = {"status": [200]}
        config["identities"]["anonymous"] = {"headers": {}}
        config["checks"].append({
            "id": "public",
            "request": {"method": "GET", "path": "/api/public"},
            "expect": {name: {"status": [200]}
                       for name in ("owner", "outsider", "anonymous")},
        })
        seen: list = []
        holder = _TempConfig(config)
        out = holder.root / "run.json"
        try:
            with self._write_target(seen) as url, \
                    contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"),
                    "--json", str(out), "--require-complete",
                ])
            result = json.loads(out.read_text(encoding="utf-8"))
        finally:
            holder.close()
        self.assertEqual(
            [(entry["identity"], entry.get("control"))
             for entry in result["liveness"]["unproven"]],
            [("outsider", "withheld_unsafe_method")],
        )
        self.assertEqual(code, 3)

    def test_the_banner_and_the_reports_describe_a_write_denial_truthfully(
        self,
    ) -> None:
        """No sham rides a write, so no sentence may say one was received.

        The unsafe-method banner said "A denial there counts as unproven" with
        no qualifier, though an identity that presents no credential never
        counts; the no-header banner already said "by an identity that
        presents a credential". And the gate's reason text, which every report
        format prints, still said the denial was one "a fabricated credential
        also received" -- on a DELETE, where none is ever sent.
        """
        seen: list = []
        holder = _TempConfig(self._write_config("Bearer outsider-token-EXPIRED"))
        out = holder.root / "run.json"
        stderr = io.StringIO()
        reports = {}
        try:
            with self._write_target(seen) as url, \
                    contextlib.redirect_stderr(stderr), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"),
                    "--json", str(out), "--require-complete",
                ])
            for fmt in ("markdown", "junit"):
                rendered = io.StringIO()
                with contextlib.redirect_stdout(rendered), \
                        contextlib.redirect_stderr(io.StringIO()):
                    veridor_main(["report", "--from-run", str(out), "--format", fmt])
                reports[fmt] = rendered.getvalue()
        finally:
            holder.close()
        self.assertEqual(code, 3)
        banner = [line for line in stderr.getvalue().splitlines()
                  if "DELETE request(s) accept only denial statuses" in line]
        self.assertEqual(len(banner), 1, stderr.getvalue())
        # The qualifier, and the served-identity precondition beside it: see
        # LivenessBannerPreconditionTest.
        self.assertIn(
            "A denial there counts as unproven when the identity presents a "
            "credential, some identity was served in the same check", banner[0],
        )
        for fmt, text in reports.items():
            with self.subTest(format=fmt):
                self.assertIn("liveness", text.lower())
                self.assertNotIn("fabricated credential also received", text)
                self.assertIn("no fabricated credential was sent", text)


class LivenessPlanTest(unittest.TestCase):
    """Which requests get a fabricated credential, and why. Socket-free."""

    @staticmethod
    def _config(*, anonymous_expect=None) -> dict:
        config = _base_config(markers=False)
        config["checks"][0]["request"]["method"] = "DELETE"
        mine = {"owner": {"status": [200]}, "outsider": {"status": [200]}}
        if anonymous_expect is not None:
            config["identities"]["anonymous"] = {"headers": {"Accept": "a/b"}}
            mine["anonymous"] = {"status": anonymous_expect}
        config["checks"].append({
            "id": "mine", "request": {"method": "GET", "path": "/mine"},
            "expect": mine,
        })
        return config

    def test_a_2xx_that_must_prove_a_credential_live_gets_a_sham(self) -> None:
        self.assertEqual(core.plan_liveness_reasons(self._config()),
                         {("GET", "/mine"): {"proves_live"}})

    def test_not_for_proof_where_the_check_already_refuses_an_anonymous_caller(
        self,
    ) -> None:
        # Still one sham, for the anonymous caller's denial-only expectation,
        # as before; it is not a second reason to send one.
        self.assertEqual(
            core.plan_liveness_reasons(self._config(anonymous_expect=[401])),
            {("GET", "/mine"): {"denial_only"}})

    def test_a_public_route_still_gets_the_proof_sham(self) -> None:
        """Rewritten twice. It first pinned the proof sham here; a later fix made a
        route declared public draw none, on the premise that a 2xx there proves
        nothing. That premise is false for a target that refuses a bad token
        even on a public route (GitHub answers 401 'Bad credentials'): the
        sham's refusal is exactly what turns the identity's 2xx into proof, and
        without it a suite whose only served check is public exited 3. The
        sham is planned again; a public route only loses the 'fabricated
        credential served' disclosure (see PublicRouteProofShamTest).
        """
        self.assertEqual(
            core.plan_liveness_reasons(self._config(anonymous_expect=[200])),
            {("GET", "/mine"): {"proves_live"}})

    def test_a_public_declaration_on_another_check_keeps_the_proof_sham(self) -> None:
        config = self._config()
        config["identities"]["anonymous"] = {"headers": {}}
        config["checks"].append({
            "id": "mine-public", "request": {"method": "GET", "path": "/mine"},
            "expect": {"anonymous": {"status": [200]}},
        })
        self.assertEqual(core.plan_liveness_reasons(config), {("GET", "/mine"): {"proves_live"}})

    def test_a_public_route_keeps_a_sham_planned_for_a_denial(self) -> None:
        config = self._config(anonymous_expect=[200])
        config["checks"][1]["expect"]["outsider"] = {"status": [403]}
        self.assertEqual(core.plan_liveness_reasons(config),
                         {("GET", "/mine"): {"denial_only"}})

    def test_nobody_needing_proof_means_no_sham(self) -> None:
        config = self._config()
        config["checks"][0]["expect"]["outsider"] = {"status": [204]}
        self.assertEqual(core.plan_liveness_reasons(config), {})


@slow("stands up a loopback HTTP server and runs the engine against it")
class PublicRouteProofShamTest(unittest.TestCase):
    """A route a credential-less identity is declared served on.

    The sham is sent there: a target that refuses a bad token even on a
    public route turns the identity's 2xx into proof that its credential is
    live. Where the route serves the sham too, that is what the declaration
    says the route does, so it is not reported as "fabricated credential
    served" (it was, on every run, before an earlier fix suppressed the sham).
    """

    def _config(self) -> dict:
        config = _base_config(markers=False)
        config["identities"]["anon"] = {"headers": {}}
        config["checks"] = [
            {"id": "admin-only", "request": {"method": "GET", "path": "/admin"},
             "expect": {"owner": {"status": [200]}, "outsider": {"status": [403]},
                        "anon": {"status": [401]}}},
            {"id": "public", "request": {"method": "GET", "path": "/public"},
             "expect": {"outsider": {"status": [200]}, "anon": {"status": [200]}}},
        ]
        return config

    def test_a_public_route_that_serves_the_sham_is_not_reported(self) -> None:
        seen: list[tuple[str, str]] = []

        def responder(path, token):
            seen.append((path, token))
            if path == "/public" or token == "Bearer owner-token":
                return 200, {}, b"{}"
            if token == "Bearer outsider-token":
                return 403, {}, b"{}"
            return 401, {}, b"{}"

        with _server(responder) as url, contextlib.redirect_stderr(io.StringIO()):
            result = _run(self._config(), url)
        self.assertEqual(
            sorted(path for path, token in seen if "veridor-sham-" in token), ["/admin", "/public"])
        self.assertEqual(
            [entry for entry in result.get("oracle_disclosures") or ()
             if entry.get("control_source") == "fabricated_credential"], [])
        self.assertEqual(result["liveness"]["unproven"], [])

    def test_a_target_that_refuses_a_bad_token_on_a_public_route_proves_it(self) -> None:
        """The case: the outsider is denied only on a write (no sham
        is ever sent with DELETE) and served only on a public route. A target
        that answers the fabricated credential 401 there, as GitHub does, has
        refused it on the same request the outsider was served, which proves
        the outsider's credential live."""
        config = self._config()
        config["checks"] = [
            {"id": "delete-doc", "request": {"method": "DELETE", "path": "/docs/1"},
             "expect": {"owner": {"status": [204]}, "outsider": {"status": [403]}}},
            config["checks"][1],
        ]

        seen: list[tuple[str, str, str]] = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _answer(self) -> None:
                token = self.headers.get("Authorization", "")
                seen.append((self.command, self.path, token))
                if "veridor-sham-" in token:
                    status = 401
                elif self.path == "/public":
                    status = 200
                elif token == "Bearer owner-token":
                    status = 204
                else:
                    status = 403
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_DELETE = _answer  # noqa: N815

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = loopback.start(server)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                result = _run(config, f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        # Control: the write was really answered with the outsider's denial.
        self.assertIn(("DELETE", "/docs/1", "Bearer outsider-token"), seen)
        self.assertNotIn("DELETE", {method for method, _, token in seen if "veridor-sham-" in token})
        self.assertEqual(result["liveness"]["unproven"], [])


@slow("stands up a loopback HTTP server and runs the engine against it")
class FabricatedCredentialServedTest(unittest.TestCase):
    """A credential nobody issued that the target SERVES says nothing about a marker.

    Reproduced: a target that only checks a Bearer
    header is present, with the tenant filter removed from a list endpoint.
    Owner [200] contains its marker, outsider [200] excludes it, anonymous
    [401]. The anonymous expectation is denial-only, so a sham is sent; the
    target serves it the whole list, marker included, and the run read that as
    "the marker is not unique to its owner" -- ORACLE-001 inconclusive, exit 0
    -- where the same leak without the anonymous line was LEAK-001 confirmed,
    exit 1. Declaring more made the leak grade weaker.
    """

    NOTES = _json_body({"rows": [{"owner": "owner", "ref": MARKER}]})

    def _config(self) -> dict:
        config = _base_config()
        config["identities"]["anonymous"] = {"headers": {}}
        config["checks"][0]["expect"]["outsider"]["status"] = [200]
        config["checks"][0]["expect"]["anonymous"] = {"status": [401]}
        return config

    def _run_cli(self, responder, *flags: str) -> tuple[int, dict, str]:
        holder = _TempConfig(self._config())
        out = holder.root / "run.json"
        stdout = io.StringIO()
        try:
            with _server(responder) as url, contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"), "--json", str(out),
                    *flags,
                ])
            return code, json.loads(out.read_text(encoding="utf-8")), stdout.getvalue()
        finally:
            holder.close()

    def _presence_only(self, path, token):
        """Any Bearer at all is served; the list carries the owner's row."""
        if token.startswith("Bearer "):
            return 200, {"Content-Type": "application/json"}, self.NOTES
        return 401, {}, b"{}"

    def test_a_served_sham_does_not_make_the_leak_inconclusive(self) -> None:
        code, result, stdout = self._run_cli(self._presence_only)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(finding["verdict"], "vulnerable")
        # Suspected, not confirmed: the run cannot show the marker is unique
        # to the owner when a credential nobody issued is served it too.
        self.assertEqual(finding["evidence_grade"], "suspected")
        self.assertIn("served", finding["message"])
        self.assertNotIn("is therefore not unique", finding["message"])
        self.assertEqual(code, 1, "the default new+confirmed gate fails on it")
        served = [entry for entry in result.get("oracle_disclosures") or ()
                  if entry.get("control_source") == "fabricated_credential"]
        self.assertEqual(len(served), 1, result.get("oracle_disclosures"))
        self.assertEqual(served[0]["status"], 200)
        self.assertIn("accepted a credential", served[0]["statement"])
        self.assertIn("accepted a credential", stdout)
        # Not an exclusion licensed by a marker_probe, so not counted as one.
        self.assertEqual(result["summary"]["probe_licensed_exclusions"], 0)

    def test_fail_on_confirmed_does_not_fail_on_it(self) -> None:
        code, result, _ = self._run_cli(self._presence_only, "--fail-on", "confirmed")
        self.assertEqual(_finding(result, "outsider")["evidence_grade"], "suspected")
        self.assertEqual(code, 0)

    def test_a_refused_sham_that_got_the_marker_stays_inconclusive(self) -> None:
        """The control: a REFUSED fabricated credential still disproves uniqueness."""
        def responder(path, token):
            if _known(token):
                return 200, {"Content-Type": "application/json"}, self.NOTES
            if token.startswith("Bearer "):
                return 403, {}, _json_body({"error": f"no access to {MARKER}"})
            return 401, {}, b"{}"

        code, result, _ = self._run_cli(responder)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-ORACLE-001")
        self.assertEqual(finding["verdict"], "inconclusive")
        self.assertEqual(code, 0)
        self.assertNotIn("oracle_disclosures", result)

    def test_a_strict_target_still_grades_the_leak_confirmed(self) -> None:
        """The other control: a sham the target refuses without the marker."""
        def responder(path, token):
            if _known(token):
                return 200, {"Content-Type": "application/json"}, self.NOTES
            return 401, {}, b"{}"

        code, result, _ = self._run_cli(responder)
        finding = _finding(result, "outsider")
        self.assertEqual(finding["rule_id"], "VERIDOR-LEAK-001")
        self.assertEqual(finding["evidence_grade"], "confirmed")
        self.assertEqual(code, 1)

    def test_a_served_sham_is_disclosed_even_without_a_marker(self) -> None:
        """Whenever any sham is served, the run says the target accepted it."""
        config = _base_config(markers=False)
        config["identities"]["anonymous"] = {"headers": {}}
        config["checks"][0]["expect"]["anonymous"] = {"status": [401]}
        config["checks"][0]["expect"]["outsider"] = {"status": [200]}

        def responder(path, token):
            return (200, {}, b"{}") if token.startswith("Bearer ") else (401, {}, b"{}")

        with _server(responder) as url:
            result = _run(config, url)
        served = [entry for entry in result.get("oracle_disclosures") or ()
                  if entry.get("control_source") == "fabricated_credential"]
        self.assertEqual([(entry["check_id"], entry["status"]) for entry in served],
                         [("records", 200)])

    def test_the_disclosure_says_only_what_was_measured(self) -> None:
        """A served sham shows the target accepted it, not what it was given.

        The statement said "what this request returns, it returns to any
        caller that presents a credential-shaped header". With the tenant
        filter in place the target served the fabricated credential 200 and an
        EMPTY list: the run was clean, yet the disclosure claimed the owner's
        data went to anyone with a header. What was measured is the status.
        """
        def responder(path, token):
            if _known(token):
                return 200, {"Content-Type": "application/json"}, self.NOTES
            if token.startswith("Bearer "):
                return 200, {"Content-Type": "application/json"}, b'{"rows": []}'
            return 401, {}, b"{}"

        code, result, stdout = self._run_cli(responder)
        served = [entry for entry in result.get("oracle_disclosures") or ()
                  if entry.get("control_source") == "fabricated_credential"]
        self.assertEqual(len(served), 1)
        statement = served[0]["statement"]
        self.assertIn("the fabricated credential was served HTTP 200", statement)
        self.assertIn("accepted a credential it never issued", statement)
        for overclaim in ("returns it to any caller", "returns to any caller",
                          "credential-shaped header"):
            with self.subTest(overclaim=overclaim):
                self.assertNotIn(overclaim, statement)
                self.assertNotIn(overclaim, stdout)


@slow("stands up a loopback HTTP server and runs the engine against it")
class LivenessControlErrorTest(unittest.TestCase):
    """A fabricated-credential request that errored proves nothing either way.

    A withheld control (a write, or no header to shape one on) already counted
    as unproven; an errored one -- the sham timed out or its connection was
    reset -- returned "not unproven", so every denial on that request passed as
    established. A target slow on, or dropping, unknown tokens turned the
    expired-credential check off: `--require-complete` exited 0, the run
    document said nothing about the error, and the console said "2/2 probes
    matched".
    """

    OWNER = "Bearer owner-token"

    def _cli(self, responder, config: dict) -> tuple[int, dict, str, str]:
        holder = _TempConfig(config)
        out = holder.root / "run.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with _server(responder) as url, contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                code = veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"), "--json", str(out),
                    "--require-complete",
                ])
            return (code, json.loads(out.read_text(encoding="utf-8")),
                    stdout.getvalue(), stderr.getvalue())
        finally:
            holder.close()

    def _config(self) -> dict:
        config = _base_config(markers=False)
        config["identities"]["outsider"]["headers"]["Authorization"] = (
            "Bearer outsider-EXPIRED")
        config["checks"][0]["expect"]["outsider"] = {"status": [401, 403, 404]}
        return config

    def _dead_outsider(self, sham_reply):
        def responder(path, token):
            if token == self.OWNER:
                return 200, {}, b"{}"
            if "veridor-sham-" in token:
                return sham_reply()
            return 401, {}, b"{}"
        return responder

    def _assert_unproven_with_error(self, code, result, stdout, stderr) -> None:
        unproven = result["liveness"]["unproven"]
        self.assertEqual([(entry["identity"], entry.get("control"))
                          for entry in unproven], [("outsider", "control_errored")])
        self.assertTrue(unproven[0]["control_error"])
        self.assertIn("failed", unproven[0]["statement"])
        requests = result["liveness"]["requests"]
        self.assertEqual(len(requests), 1)
        self.assertTrue(requests[0].get("error"), requests)
        self.assertEqual(code, 3)
        self.assertIn("Unproven denials", stdout)
        self.assertIn("fabricated credential's own request failed", stdout)
        # A failed request is not deterministic, and the gate must not say so.
        self.assertIn("may be answered differently on a re-run", stderr)
        self.assertNotIn("a re-run reports identically", stderr)

    def test_a_reset_control_leaves_the_denial_unproven(self) -> None:
        code, result, stdout, stderr = self._cli(
            self._dead_outsider(lambda: None), self._config())
        self._assert_unproven_with_error(code, result, stdout, stderr)

    def test_a_timed_out_control_leaves_the_denial_unproven(self) -> None:
        config = self._config()
        config["target"]["timeout_seconds"] = 0.5

        def slow():
            time.sleep(1.2)
            return 401, {}, b"{}"

        code, result, stdout, stderr = self._cli(self._dead_outsider(slow), config)
        self._assert_unproven_with_error(code, result, stdout, stderr)

    def test_an_answered_control_that_differs_still_proves_it(self) -> None:
        """The control: a sham the target refused differently is evidence."""
        code, result, _, _ = self._cli(
            self._dead_outsider(lambda: (403, {}, b"{}")), self._config())
        self.assertEqual(result["liveness"]["unproven"], [])
        self.assertNotIn("error", result["liveness"]["requests"][0])
        self.assertEqual(code, 0)


@slow("stands up a loopback HTTP server and runs the engine against it")
class UninformativeShamAnswerTest(unittest.TestCase):
    """A fabricated credential's answer tells credentials apart only if it is
    a refusal or a success.

    A sham drawing 400 (a parser rejecting a non-JWT bearer), 406, 407 (a
    proxy), 429 (a limiter, and the sham goes out after the run's own
    requests) or a 5xx differs from a dead token's 401 without the
    application having recognised either credential. `_liveness_unproven`
    read any difference as proof, so the expired token passed with exit 0
    under --require-complete. scripts/patched_pairs.py's
    `_tells_a_credential_apart` already refused exactly this; the CLI did not.
    """

    def _run_with_sham(self, sham_status: int) -> tuple[int, dict, str]:
        def responder(path, token):
            if token == "Bearer owner-token":
                return 200, {}, b"{}"
            if "veridor-sham-" in token:
                return sham_status, {}, b"{}"
            return 401, {}, b"{}"

        config = _base_config(markers=False)
        config["identities"]["outsider"]["headers"]["Authorization"] = (
            "Bearer outsider-EXPIRED")
        config["checks"][0]["expect"]["outsider"] = {"status": [401, 403, 404]}
        holder = _TempConfig(config)
        out = holder.root / "run.json"
        stdout = io.StringIO()
        try:
            with _server(responder) as url, contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"), "--json", str(out),
                    "--require-complete",
                ])
            return code, json.loads(out.read_text(encoding="utf-8")), stdout.getvalue()
        finally:
            holder.close()

    def test_a_status_that_tells_no_credential_apart_is_not_proof(self) -> None:
        for status in (400, 406, 407, 429, 500, 503):
            with self.subTest(sham=status):
                code, result, stdout = self._run_with_sham(status)
                unproven = result["liveness"]["unproven"]
                self.assertEqual(
                    [(entry["identity"], entry.get("control"), entry.get("control_status"))
                     for entry in unproven],
                    [("outsider", "control_uninformative", status)],
                )
                self.assertIn(f"HTTP {status}", unproven[0]["statement"])
                self.assertIn("neither a refusal nor a success", unproven[0]["statement"])
                self.assertIn("neither a refusal nor a success", stdout)
                self.assertEqual(code, 3)

    def test_a_refusal_or_a_success_still_proves_it(self) -> None:
        """The controls: a different refusal, a redirect, a 2xx are evidence."""
        for status in (403, 404, 302, 200):
            with self.subTest(sham=status):
                code, result, _ = self._run_with_sham(status)
                self.assertEqual(result["liveness"]["unproven"], [])
                self.assertEqual(code, 0)

    def test_the_same_refusal_is_still_unproven_the_old_way(self) -> None:
        code, result, _ = self._run_with_sham(401)
        unproven = result["liveness"]["unproven"]
        self.assertEqual([(entry["identity"], entry.get("control")) for entry in unproven],
                         [("outsider", None)])
        self.assertEqual(code, 3)


@slow("stands up a loopback HTTP server and runs the engine against it")
class LivenessBannerPreconditionTest(unittest.TestCase):
    """Every liveness banner states when a denial actually counts as unproven.

    The banners said a denial "counts as unproven unless it is proven live
    elsewhere". `_liveness_unproven` also requires that some identity was
    served in the same check, so on an all-deny check -- attacker [403] and
    anonymous [403] on a DELETE -- the banner printed, liveness.unproven
    stayed empty and --require-complete exited 0. The console promised a
    judgement the run never made.
    """

    CONDITION = (
        "counts as unproven when the identity presents a credential, some "
        "identity was served in the same check, and nothing else in this run "
        "proves the identity live (a 2xx it drew on a request where an identity "
        "with no credential, or the fabricated credential, was refused; or its "
        "marker_probe)"
    )

    def _banners(self, config: dict) -> list[str]:
        def responder(path, token):
            return (200, {}, b"{}") if token == "Bearer owner-token" else (403, {}, b"{}")

        holder = _TempConfig(config)
        stderr = io.StringIO()
        try:
            with _server(responder) as url, contextlib.redirect_stderr(stderr), \
                    contextlib.redirect_stdout(io.StringIO()):
                veridor_main([
                    "run", "--config", str(holder.path), "--base-url", url,
                    "--output-dir", str(holder.root / "out"),
                ])
        finally:
            holder.close()
        return [line for line in stderr.getvalue().splitlines()
                if line.startswith("veridor: liveness controls --")]

    def test_every_banner_names_the_served_identity_precondition(self) -> None:
        shaped = _base_config(markers=False)
        shaped["checks"].append({
            "id": "del", "request": {"method": "DELETE", "path": "/records/1"},
            "expect": {"owner": {"status": [200]}, "outsider": {"status": [403]}},
        })
        unshaped = json.loads(json.dumps(shaped))
        for name in ("owner", "outsider"):
            unshaped["identities"][name] = {"headers": {"Accept": "application/json"}}
        for label, config, count in (("shaped", shaped, 2), ("unshaped", unshaped, 2)):
            with self.subTest(config=label):
                banners = self._banners(config)
                self.assertEqual(len(banners), count, banners)
                for banner in banners:
                    self.assertIn(self.CONDITION, banner)


@slow("stands up a loopback HTTP server and runs the engine against it")
class UnreviewedPromotionStubTest(unittest.TestCase):
    """A stub pasted in unedited must not reach SARIF looking hand-written.

    ``map --promote`` writes ``name: "TODO: describe the boundary you are
    asserting"`` and an otherwise complete, immediately loadable check. Pasted
    in unchanged it grades normally and reaches SARIF as an ``error``-level
    result at grade ``confirmed`` -- the strongest thing this tool emits. That
    part is correct: ``run`` cannot audit a declaration. What was wrong is that
    the only trace of "no human agreed to this" was the ``TODO`` name, and the
    name reached neither the console nor the SARIF. It appeared many times in
    ``latest.json`` and zero times in both places anyone actually reads.
    """

    STUB_NAME = "TODO: describe the boundary you are asserting"

    def _stub_config(self) -> dict:
        config = _base_config(markers=False)
        config["checks"][0]["id"] = "candidate-marker-reach-19f5457e"
        config["checks"][0]["name"] = self.STUB_NAME
        return config

    def _responder(self):
        def responder(path, token):
            return (200, {}, _json_body({"ok": True}))

        return responder

    def _run_stub(self) -> dict:
        with _server(self._responder()) as url:
            return _run(self._stub_config(), url)

    def test_the_run_document_names_the_unreviewed_checks(self) -> None:
        result = self._run_stub()
        entries = result["unreviewed_promotion_stubs"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["check_id"], "candidate-marker-reach-19f5457e")
        self.assertEqual(entries[0]["name"], self.STUB_NAME)
        self.assertIn("has not been reviewed", entries[0]["statement"])

    def test_the_marker_reaches_the_sarif(self) -> None:
        sarif = to_sarif(self._run_stub())
        run = sarif["runs"][0]
        self.assertEqual(len(run["properties"]["unreviewedPromotionStubs"]), 1)
        # And on every result, so a UI that renders results but not run
        # properties still sees it.
        for entry in run["results"]:
            self.assertEqual(entry["properties"]["checkName"], self.STUB_NAME)
        self.assertIn("TODO", json.dumps(sarif))

    def test_the_marker_reaches_the_console(self) -> None:
        from veridor import cli

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            cli._print_summary(self._run_stub())
        printed = buffer.getvalue()
        self.assertIn("Unreviewed:", printed)
        self.assertIn(self.STUB_NAME, printed)
        self.assertIn("candidate-marker-reach-19f5457e", printed)

    def test_a_hand_written_check_is_not_flagged(self) -> None:
        with _server(self._responder()) as url:
            result = _run(_base_config(markers=False), url)
        self.assertNotIn("unreviewed_promotion_stubs", result)

    @fast("asserts on the declaration, not on a live target")
    def test_the_stub_promote_writes_is_the_one_the_run_flags(self) -> None:
        """One spelling of the marker, shared by the writer and the reader.

        Without this, ``promotion_stub`` could rename its TODO and the run
        would quietly stop flagging it -- the exact silence this repairs.
        """
        from veridor import blastradius

        candidate = blastradius.Candidate(
            rule="marker_reach",
            identity="administrator",
            operation="GET /api/admin/audit",
            specimen=None,
            url_path="/api/admin/audit",
            explanation="the marker owner's marker was observed for another identity",
            marker_owner="invoice_owner",
        )
        stub = blastradius.promotion_stub(candidate)
        config = {"checks": [{"id": stub["id"], "name": stub["name"]}]}
        self.assertEqual(len(core._unreviewed_promotion_stubs(config)), 1)

    @fast("asserts on the declaration, not on a live target")
    def test_only_the_stub_name_is_flagged(self) -> None:
        def flagged(name: str) -> bool:
            return bool(
                core._unreviewed_promotion_stubs({"checks": [{"id": "c", "name": name}]})
            )

        self.assertTrue(flagged(self.STUB_NAME))
        self.assertTrue(flagged("todo: still deciding"))
        self.assertTrue(flagged("  TODO  "))
        self.assertFalse(flagged("Invoice tenant isolation"))
        self.assertFalse(flagged("Audit log administrator role"))
        # A word that merely starts with the same letters is not the marker.
        self.assertFalse(flagged("Today's boundary"))


if __name__ == "__main__":
    unittest.main()
