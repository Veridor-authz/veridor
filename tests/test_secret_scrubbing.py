"""No expanded ``${NAME}`` value reaches anything Veridor writes or prints.

SECURITY.md said credentials are not written to any artifact, and README that
no token is ever written to disk. Both held for header credentials only.
Reproduced before this change, with ``${NAME}`` references to five distinct
values in one configuration:

* a path segment (``/api/items/${VERIDOR_PATHSEC}``) was written verbatim to
  ``probes[].request.url``, ``findings[].evidence.request.url``,
  ``liveness.requests[].path`` -- in ``--json``, ``latest.json`` and
  ``runs/*.json`` -- and to the GitLab SAST report's ``details.request.value``;
* a ``;jsessionid=`` path parameter went to the same places;
* a query value was redacted in the URLs, but ``liveness.requests[].path``
  kept the raw path, query and all;
* a JSON body value and a header value appeared nowhere.

Veridor now records every value it expands and puts the ``${NAME}`` reference
back in every string it writes (run documents, history, every report format,
matrices, drift) and in everything it prints, longest value first. A value
shorter than :data:`veridor.redaction.MIN_SCRUB_LENGTH` is not scrubbed -- it
cannot be told apart from ordinary text -- and the command says so on stderr.
The liveness block also stores its paths through ``_safe_url`` now, so a query
value is redacted there as in every other stored URL, typed-in values included.

The controls matter as much as the assertions: with scrubbing switched off the
same grep must find the path and ``;param`` values, and the query, body and
header values must be shown to have gone on the wire, or "absent from every
file" would say nothing.
"""

from __future__ import annotations

import contextlib
import email.message
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.response
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, quote_plus, unquote_plus

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"

#: One distinct value per place a credential can be put. Every one is long
#: enough to be scrubbed, and none is a substring of another.
SECRETS = {
    "VERIDOR_PATHSEC": "PATHSEC-9a8b7c6d",
    "VERIDOR_QUERYSEC": "QUERYSEC-1f2e3d4c",
    "VERIDOR_MATRIXSEC": "MATRIXSEC-5b6a7988",
    "VERIDOR_BODYSEC": "BODYSEC-0c1d2e3f",
    "VERIDOR_HDRSEC": "HDRSEC-77aa88bb",
}
#: Written verbatim in URLs unless scrubbed, so the no-scrubbing control must
#: find them.
URL_SECRETS = ("VERIDOR_PATHSEC", "VERIDOR_MATRIXSEC")
#: Kept out without scrubbing too -- headers and bodies are never stored, and a
#: query value is redacted in every stored URL (the liveness block included,
#: since it stopped storing the raw path) -- so the control shows they were
#: really sent instead.
WIRE_ONLY = ("VERIDOR_QUERYSEC", "VERIDOR_BODYSEC", "VERIDOR_HDRSEC")

REPORT_FORMATS = ("junit", "gitlab-sast", "codequality", "markdown")


def _check(check_id: str, request: dict) -> dict:
    return {
        "id": check_id, "name": check_id, "request": request,
        "expect": {"owner": {"status": [200], "contains_marker": "owner"},
                   "other": {"status": [404], "excludes_marker": "owner"}},
    }


def _config(base_url: str) -> dict:
    return {
        "version": 1,
        "target": {"base_url": base_url, "timeout_seconds": 3},
        "identities": {
            "owner": {"headers": {"Authorization": "Bearer owner-token-xyz"}, "marker": MARKER},
            "other": {"headers": {"Authorization": "Bearer ${VERIDOR_HDRSEC}"}},
        },
        "checks": [
            _check("path", {"method": "GET", "path": "/api/items/${VERIDOR_PATHSEC}"}),
            _check("query", {"method": "GET",
                             "path": "/api/items/1?api_key=${VERIDOR_QUERYSEC}"}),
            _check("matrix-param", {"method": "GET",
                                    "path": "/api/items/2;jsessionid=${VERIDOR_MATRIXSEC}"}),
            _check("body", {"method": "POST", "path": "/api/search",
                            "json": {"token": "${VERIDOR_BODYSEC}"}}),
        ],
    }


def _forms(value: str) -> set[bytes]:
    """Every spelling of ``value`` a writer could produce.

    Including the two Veridor's own URL handling produces: ``_safe_url``
    stores the host lower-cased, and ``_redact_query`` decodes and re-encodes
    a query parameter NAME (``%2f`` becomes ``%2F``, ``%20`` becomes ``+``).
    """
    return {form.encode() for form in (value, quote(value, safe=""), quote_plus(value),
                                       json.dumps(value)[1:-1], value.lower(),
                                       quote_plus(unquote_plus(value)))}


def _hits(blobs: dict[str, bytes], value: str) -> list[str]:
    return sorted(name for name, blob in blobs.items()
                  if any(form in blob for form in _forms(value)))


class _VulnerableOpener:
    """Stands in for ``core._OPENER``: answers 200 with the owner's marker to
    everyone, so every denial expectation becomes a finding with evidence."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def open(self, request, timeout=None):  # noqa: A003 - mirrors OpenerDirector
        self.sent.append(
            (request.full_url + "\n" + "\n".join(f"{k}: {v}" for k, v in request.header_items())
             ).encode() + b"\n" + (request.data or b"")
        )
        body = json.dumps({"owner": MARKER}).encode()
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
        return urllib.response.addinfourl(io.BytesIO(body), headers, request.full_url, 200)


def _run_everything(root: Path, env: dict[str, str],
                    config: dict | None = None) -> tuple[dict[str, bytes], list[bytes]]:
    """``run`` with every output, then ``report`` from the run document, in-process.

    Returns every byte written under ``root`` (bar the configuration) plus the
    captured stdout and stderr of both commands, and what went on the wire.
    """
    if config is None:
        config = _config("http://127.0.0.1:8765")
    (root / "veridor.json").write_text(json.dumps(config), encoding="utf-8")
    argv = ["run", "--config", str(root / "veridor.json"), "--output-dir", str(root / "out"),
            "--json", str(root / "run.json"), "--sarif", str(root / "run.sarif")]
    for fmt in REPORT_FORMATS:
        argv += ["--report", f"{fmt}={root / ('report.' + fmt)}"]
    opener = _VulnerableOpener()
    captured: dict[str, bytes] = {}
    with patch.dict(os.environ, env):
        with patch.object(core, "_OPENER", opener):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(argv)
            captured["<run stdout>"] = stdout.getvalue().encode()
            captured["<run stderr>"] = stderr.getvalue().encode()
            if code != 1:
                raise AssertionError(f"expected findings (exit 1), got {code}: {stderr.getvalue()}")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                veridor_main(["report", "--from-run", str(root / "run.json"),
                              "--format", "gitlab-sast"])
            captured["<report stdout>"] = stdout.getvalue().encode()
            captured["<report stderr>"] = stderr.getvalue().encode()
    for path in root.rglob("*"):
        if path.is_file() and path.name != "veridor.json":
            captured[str(path.relative_to(root))] = path.read_bytes()
    return captured, opener.sent


class ArtifactScrubbingTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_no_expanded_value_reaches_any_file_or_output(self) -> None:
        blobs, sent = _run_everything(self.root, SECRETS)
        self.assertGreaterEqual(len(blobs), 10, sorted(blobs))
        for name, value in SECRETS.items():
            with self.subTest(variable=name):
                self.assertEqual(_hits(blobs, value), [])
        # The reference is what stands in the value's place.
        run = json.loads(blobs["run.json"])
        urls = [probe["request"]["url"] for probe in run["probes"]]
        self.assertIn("http://127.0.0.1:8765/api/items/${VERIDOR_PATHSEC}", urls)
        self.assertIn("http://127.0.0.1:8765/api/items/2;jsessionid=${VERIDOR_MATRIXSEC}", urls)

    def test_control_without_scrubbing_the_same_grep_finds_them(self) -> None:
        from veridor import redaction  # noqa: PLC0415

        with patch.object(redaction, "scrub", lambda value: value), \
                patch.object(redaction, "scrub_text", lambda text: text):
            blobs, sent = _run_everything(self.root, SECRETS)
        for name in URL_SECRETS:
            with self.subTest(variable=name):
                self.assertTrue(_hits(blobs, SECRETS[name]), f"{name} was never written")
        wire = {"<wire>": b"\n".join(sent)}
        for name in WIRE_ONLY + URL_SECRETS:
            with self.subTest(variable=name, where="wire"):
                self.assertEqual(_hits(wire, SECRETS[name]), ["<wire>"])

    def test_a_short_value_is_left_and_the_command_says_so(self) -> None:
        env = dict(SECRETS, VERIDOR_PATHSEC="p4th")
        blobs, _ = _run_everything(self.root, env)
        stderr = blobs["<run stderr>"].decode()
        self.assertIn("${VERIDOR_PATHSEC}", stderr)
        self.assertIn("fewer than 8 characters", stderr)
        self.assertTrue(_hits(blobs, "/api/items/p4th"))
        # The long ones are still scrubbed next to it.
        self.assertEqual(_hits(blobs, SECRETS["VERIDOR_MATRIXSEC"]), [])


#: Values placed where Veridor's own URL handling re-spells them: a host label
#: (stored lower-cased) and two query parameter names (decoded and re-encoded).
NORMALISED = {
    "VERIDOR_HOSTTOK": "TnT7kQ2xPz9Wm4Rv",
    "VERIDOR_QNAME": "qn%2fSeCrEt55aa77",
    "VERIDOR_QNAME2": "qn2%20SeCrEt66bb88",
}


def _normalised_env() -> dict[str, str]:
    return dict(NORMALISED, VERIDOR_HDRSEC=SECRETS["VERIDOR_HDRSEC"])


def _normalised_config() -> dict:
    config = _config("http://${VERIDOR_HOSTTOK}.tenants.localhost:8765")
    config["checks"] = [
        _check("qname", {"method": "GET", "path": "/api/items/1?${VERIDOR_QNAME}=1"}),
        _check("qname2", {"method": "GET", "path": "/api/items/2?${VERIDOR_QNAME2}=1"}),
    ]
    return config


class NormalisedFormTest(unittest.TestCase):
    """A value Veridor re-spells on its way to disk is scrubbed in that spelling.

    `redaction.register` knew three spellings (as written, percent-encoded,
    `+`-encoded), and its docstring said nothing in Veridor re-encodes a value
    any other way. `_safe_url` does, twice. Reproduced: a mixed-case
    `${VERIDOR_HOSTTOK}` in the base URL's host was written lower-cased to
    run.json, the history copies, the GitLab SAST report, the Markdown report
    and stdout's `Target:` line -- a working equivalent, since host names are
    case-insensitive -- and query parameter names `qn%2f...` and `qn2%20...`
    were stored as `qn%2F...` and `qn2+...`.
    """

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_the_lower_cased_host_and_re_encoded_names_are_scrubbed(self) -> None:
        blobs, sent = _run_everything(self.root, _normalised_env(), _normalised_config())
        for name, value in NORMALISED.items():
            with self.subTest(variable=name):
                self.assertEqual(_hits(blobs, value), [])
        run = json.loads(blobs["run.json"])
        self.assertEqual(run["target"], "http://${VERIDOR_HOSTTOK}.tenants.localhost:8765")
        urls = {probe["request"]["url"] for probe in run["probes"]}
        self.assertIn("http://${VERIDOR_HOSTTOK}.tenants.localhost:8765/api/items/1"
                      "?${VERIDOR_QNAME}=%5BREDACTED%5D", urls)
        self.assertIn("http://${VERIDOR_HOSTTOK}.tenants.localhost:8765/api/items/2"
                      "?${VERIDOR_QNAME2}=%5BREDACTED%5D", urls)
        # The values went on the wire as written.
        wire = b"\n".join(sent)
        for value in NORMALISED.values():
            self.assertIn(value.encode(), wire)

    def test_control_with_three_spellings_the_same_grep_finds_them(self) -> None:
        from veridor import redaction  # noqa: PLC0415

        def three(value: str) -> tuple[str, ...]:
            return (value, quote(value, safe=""), quote_plus(value))

        with patch.object(redaction, "_spellings", three):
            blobs, _ = _run_everything(self.root, _normalised_env(), _normalised_config())
        for name, value in NORMALISED.items():
            with self.subTest(variable=name):
                self.assertIn("run.json", _hits(blobs, value))
        self.assertIn("<run stdout>", _hits(blobs, NORMALISED["VERIDOR_HOSTTOK"]))


class LivenessQueryRedactionTest(unittest.TestCase):
    """Query values are redacted in stored URLs -- the liveness block was the
    one place that stored the raw path, query and all. That holds for a value
    typed into the configuration too, which scrubbing cannot recognise."""

    def test_a_literal_query_value_is_redacted_in_the_liveness_block(self) -> None:
        config = _config("http://127.0.0.1:8765")
        config["identities"]["other"]["headers"]["Authorization"] = "Bearer other-token"
        config["checks"] = [_check("query", {"method": "GET",
                                             "path": "/api/items/1?api_key=LITERAL-Q-777"})]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with patch.object(core, "_OPENER", _VulnerableOpener()):
                result = core.execute_run(path, output_dir=Path(directory) / "out")
        liveness = [entry["path"] for entry in result["liveness"]["requests"]]
        self.assertEqual(liveness, ["/api/items/1?api_key=%5BREDACTED%5D"])
        # Control: the probe URL was already redacted the same way.
        self.assertIn("api_key=%5BREDACTED%5D", result["probes"][0]["request"]["url"])
        self.assertNotIn("LITERAL-Q-777", json.dumps(result))


class RedactionUnitTest(unittest.TestCase):
    def setUp(self) -> None:
        from veridor import redaction  # noqa: PLC0415

        self.redaction = redaction
        redaction.reset()
        self.addCleanup(redaction.reset)

    def test_longest_value_first(self) -> None:
        self.redaction.register("SHORTER", "abcdefghij")
        self.redaction.register("LONGER", "abcdefghijKLMN")
        self.assertEqual(self.redaction.scrub_text("x abcdefghijKLMN y abcdefghij z"),
                         "x ${LONGER} y ${SHORTER} z")

    def test_structures_keys_and_encoded_forms(self) -> None:
        self.redaction.register("TOK", "a b/c+d=e&12345")
        value = {"a b/c+d=e&12345": ["/x/a%20b%2Fc%2Bd%3De%2612345", "q=a+b%2Fc%2Bd%3De%2612345"]}
        self.assertEqual(self.redaction.scrub(value), {"${TOK}": ["/x/${TOK}", "q=${TOK}"]})

    def test_the_spellings_core_safe_url_produces(self) -> None:
        """Each one on its own: the host `_safe_url` lower-cases, and a query
        parameter name `_redact_query` decodes and re-encodes."""
        self.redaction.register("HOST", "TnT7kQ2xPz9Wm4Rv")
        self.redaction.register("SLASH", "qn%2fSeCrEt55aa77")
        self.redaction.register("SPACE", "qn2%20SeCrEt66bb88")
        for text, expected in (
            ("http://tnt7kq2xpz9wm4rv.example", "http://${HOST}.example"),
            ("http://TnT7kQ2xPz9Wm4Rv.example", "http://${HOST}.example"),
            ("?qn%2FSeCrEt55aa77=x", "?${SLASH}=x"),
            ("?qn2+SeCrEt66bb88=x", "?${SPACE}=x"),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.redaction.scrub_text(text), expected)
        # Control: another value in the same shapes is left alone.
        self.assertEqual(self.redaction.scrub_text("http://tnt7kq2xpz9wm4rX.example"),
                         "http://tnt7kq2xpz9wm4rX.example")

    def test_a_short_value_is_not_registered_for_scrubbing(self) -> None:
        self.redaction.register("PIN", "1234")
        self.assertEqual(self.redaction.scrub_text("1234 and 2026-12-34"), "1234 and 2026-12-34")
        self.assertEqual(self.redaction.short_names(), ["PIN"])

    def test_reset_forgets(self) -> None:
        self.redaction.register("TOK", "0123456789")
        self.redaction.reset()
        self.assertEqual(self.redaction.scrub_text("0123456789"), "0123456789")

    def test_control_nothing_registered_changes_nothing(self) -> None:
        document = {"url": "http://h/a", "n": 1, "flag": True, "none": None}
        self.assertEqual(self.redaction.scrub(document), document)


# --------------------------------------------------------------------------
# End to end: a real process against a real listener
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _vulnerable_target():
    sent: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _reply(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body_in = self.rfile.read(length) if length else b""
            sent.append(f"{self.command} {self.path}\n{self.headers}".encode() + body_in)
            body = json.dumps({"owner": MARKER}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _reply  # noqa: N815
        do_POST = _reply  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(server)
    try:
        yield f"http://127.0.0.1:{server.server_port}", sent
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@slow("map paces its requests on a real clock (10 per second at most)")
class MapScrubbingTest(unittest.TestCase):
    """A specimen id from the environment lands in matrix cells and in what
    `map` prints; the matrix, blast radius, candidates and drift go through
    the same writer."""

    SPECIMEN = "inv-SPECIMEN-4455aa"

    def test_a_specimen_value_reaches_no_map_artifact(self) -> None:
        config = json.loads((ROOT / "fixtures" / "veridor.map-demo.json").read_text("utf-8"))
        config["matrix"]["specimens"]["/api/invoices/{id}"][0]["values"]["id"] = (
            "${VERIDOR_SPECIMEN}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "veridor.json").write_text(json.dumps(config), encoding="utf-8")
            opener = _VulnerableOpener()
            blobs: dict[str, bytes] = {}
            base = ["map", "--config", str(root / "veridor.json"),
                    "--openapi", str(ROOT / "fixtures" / "openapi.demo.json"),
                    "--output-dir", str(root / "out"), "--rate", "10"]
            with patch.dict(os.environ, {"VERIDOR_SPECIMEN": self.SPECIMEN}), \
                    patch.object(core, "_OPENER", opener):
                for label, extra in (("record", ["--matrix", str(root / "base.json")]),
                                     ("drift", ["--baseline", str(root / "base.json"),
                                                "--drift", str(root / "drift.json")])):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        veridor_main(base + extra)
                    blobs[f"<{label} stdout>"] = stdout.getvalue().encode()
                    blobs[f"<{label} stderr>"] = stderr.getvalue().encode()
            for path in root.rglob("*"):
                if path.is_file() and path.name != "veridor.json":
                    blobs[str(path.relative_to(root))] = path.read_bytes()
        self.assertIn("drift.json", blobs)
        self.assertEqual(_hits(blobs, self.SPECIMEN), [])
        self.assertIn(b"${VERIDOR_SPECIMEN}", blobs["base.json"])
        # Control: the value was really used, on the wire.
        self.assertEqual(_hits({"<wire>": b"\n".join(opener.sent)}, self.SPECIMEN), ["<wire>"])


@slow("runs veridor as a subprocess against a loopback listener")
class ProcessScrubbingTest(unittest.TestCase):
    def test_every_byte_a_real_run_writes_or_prints(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _vulnerable_target() as (url, sent):
            root = Path(directory)
            (root / "veridor.json").write_text(json.dumps(_config(url)), encoding="utf-8")
            argv = ["run", "--config", "veridor.json", "--output-dir", "out",
                    "--json", "run.json", "--sarif", "run.sarif"]
            for fmt in REPORT_FORMATS:
                argv += ["--report", f"{fmt}=report.{fmt}"]
            completed = subprocess.run(
                [sys.executable, "-m", "veridor", *argv], cwd=root, capture_output=True,
                env=source_path.child_env(**SECRETS), timeout=120,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr.decode())
            blobs = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*")
                     if p.is_file() and p.name != "veridor.json"}
            blobs["<stdout>"], blobs["<stderr>"] = completed.stdout, completed.stderr
            self.assertIn("out/latest.json", blobs)
            for name, value in SECRETS.items():
                with self.subTest(variable=name):
                    self.assertEqual(_hits(blobs, value), [])
            # Control: every value reached the listener, so absence means scrubbed.
            wire = {"<wire>": b"\n".join(sent)}
            for name, value in SECRETS.items():
                with self.subTest(variable=name, where="wire"):
                    self.assertEqual(_hits(wire, value), ["<wire>"])


if __name__ == "__main__":
    unittest.main()
