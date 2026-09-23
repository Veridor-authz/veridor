"""A drift baseline as `map` really records it, then the gate that reads it.

`test_drift` holds the comparison rules on hand-built matrices. This module
records the baseline with `veridor map` itself -- in-process, with
``core._OPENER`` standing in for the target -- and then gates a second run
against the file on disk, because both defects here lived between the two:

* a baseline recorded while the target redirected every request was accepted
  as a measurement, so the gate over it could not fail;
* the file on disk is scrubbed (``${NAME}`` stands where an expanded value
  was) and the current matrix in memory was not, so a join key that contained
  an expanded value no longer lined up with itself.

`map` paces its requests on a real clock (10 per second at most, a limit no
option lifts), so the end-to-end cases are slow-tier. The comparison in the
middle is also held here in the fast tier, on `_emit_drift` directly.
"""

from __future__ import annotations

import contextlib
import email.message
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.response
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor import core, redaction  # noqa: E402
from veridor.cli import _parser  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
INVOICE = "inv-100"


class _Target:
    """The demo target's invoice and audit routes, as ``core._OPENER``.

    ``mode`` is ``fixed`` (the invoice is served to its owner only),
    ``vulnerable`` (also to the other tenant, with no marker in the body, so
    only reach can show it) or ``redirect`` (every request gets a 302 to a
    login page, as behind an SSO proxy).
    """

    def __init__(self, mode: str, invoice: str = INVOICE) -> None:
        self.mode = mode
        self.invoice = invoice
        self.sent: list[str] = []

    def open(self, request, timeout=None):  # noqa: A003 - mirrors OpenerDirector
        token = request.get_header("Authorization") or ""
        path = "/" + request.full_url.split("/", 3)[3]
        self.sent.append(f"{request.get_method()} {path} {token}")
        extra: dict[str, str] = {}
        if self.mode == "redirect":
            status, body = 302, {}
            extra["Location"] = "https://sso.example.invalid/login"
        elif not token:
            status, body = 401, {}
        elif path == f"/api/invoices/{self.invoice}":
            served = token == "Bearer owner-token" or (
                self.mode == "vulnerable" and token == "Bearer outsider-token")
            status, body = ((200, {"id": self.invoice, "ref": MARKER}
                             if token == "Bearer owner-token" else {"id": self.invoice})
                            if served else (404, {}))
        elif path == "/api/admin/audit":
            status, body = (200, {}) if token == "Bearer admin-token" else (403, {})
        else:
            status, body = 404, {}
        data = json.dumps(body).encode()
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
        for name, value in extra.items():
            headers[name] = value
        return urllib.response.addinfourl(io.BytesIO(data), headers, request.full_url, status)


def _config() -> dict:
    config = json.loads((ROOT / "fixtures" / "veridor.map-demo.json").read_text("utf-8"))
    config.pop("checks")
    return config


def _map(root: Path, config: dict, target: _Target, extra: list[str],
         env: dict[str, str] | None = None) -> tuple[int, str, str]:
    (root / "veridor.json").write_text(json.dumps(config), encoding="utf-8")
    argv = ["map", "--config", str(root / "veridor.json"),
            "--openapi", str(ROOT / "fixtures" / "openapi.demo.json"),
            "--output-dir", str(root / "out"), "--rate", "10", *extra]
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.dict(os.environ, env or {}), patch.object(core, "_OPENER", target), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = veridor_main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _gate(root: Path, config: dict, baseline: Path, target: _Target, policy: str = "opened",
          env: dict[str, str] | None = None) -> tuple[int, dict, str]:
    drift_path = root / f"drift-{policy}-{target.mode}.json"
    code, _, stderr = _map(root, config, target, [
        "--baseline", str(baseline), "--fail-on-drift", policy, "--drift", str(drift_path),
    ], env)
    return code, json.loads(drift_path.read_text("utf-8")), stderr


@slow("map paces its requests on a real clock (10 per second at most)")
class RedirectBaselineTest(unittest.TestCase):
    """Recorded while every request was redirected, the baseline measured nothing.

    Before: the recording exited 0 with no warning, and `--fail-on-drift
    opened` against it exited 0 while the other tenant was being served the
    invoice (12 cells "measured in both"; reach_appeared 3, status_changed 9).
    """

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_a_redirect_baseline_records_nothing_and_gates_nothing(self) -> None:
        code, _, stderr = _map(self.root, _config(), _Target("redirect"),
                               ["--matrix", str(self.root / "redirect.json")])
        self.assertEqual(code, 3, stderr)
        self.assertIn("records nothing", stderr)
        self.assertIn("redirect", stderr)
        cells = json.loads((self.root / "redirect.json").read_text("utf-8"))["cells"]
        # What the file holds: answered cells, all redirects -- not unknown ones.
        self.assertTrue(any(cell["status"] == 302 for cell in cells))
        self.assertEqual({cell["reach"] for cell in cells if cell["status"] == 302},
                         {"indeterminate"})

        vulnerable = _Target("vulnerable")
        code, report, stderr = _gate(self.root, _config(), self.root / "redirect.json",
                                     vulnerable)
        self.assertEqual(code, 3, stderr)
        self.assertEqual(report["measured_in_both_cells"], 0)
        self.assertIn("It is not a pass", stderr)
        # The regression was really on the wire in the gated run.
        self.assertIn(f"GET /api/invoices/{INVOICE} Bearer outsider-token", vulnerable.sent)

        for policy in ("opened", "any"):
            with self.subTest(still_redirecting=policy):
                code, report, _ = _gate(self.root, _config(), self.root / "redirect.json",
                                        _Target("redirect"), policy)
                self.assertEqual(code, 3)

    def test_control_a_measured_baseline_catches_the_same_read(self) -> None:
        code, _, stderr = _map(self.root, _config(), _Target("fixed"),
                               ["--matrix", str(self.root / "fixed.json")])
        self.assertEqual(code, 0, stderr)
        code, report, _ = _gate(self.root, _config(), self.root / "fixed.json",
                                _Target("vulnerable"))
        self.assertEqual(code, 1)
        self.assertIn("reach_opened", report["counts"])


#: An id of 8+ characters, so it is registered for scrubbing, used where the
#: natural config puts it: the specimen's value, and the specimen's label.
SPECIMEN_ID = "inv-000123456"


def _specimen_config(label: str, login: str | None = None) -> dict:
    config = _config()
    config["matrix"]["specimens"]["/api/invoices/{id}"] = [
        {"label": label, "values": {"id": "${VERIDOR_INV}"}}]
    if login is not None:
        config["identities"]["other_tenant"]["headers"]["X-Login"] = login
    return config


def _cell(identity: str, specimen: str, reach: str, status: int) -> dict:
    return {"operation": "GET /api/invoices/{id}", "identity": identity,
            "specimen": specimen, "reach": reach, "status": status, "marker_scan": "absent"}


def _matrix(cells: list[dict], base_url: str = "http://127.0.0.1:8765") -> dict:
    return {"kind": "veridor.matrix", "target": {"base_url": base_url}, "cells": cells}


class JoinKeyScrubbingTest(unittest.TestCase):
    """The baseline on disk is scrubbed; the current matrix in memory was not.

    `core.write_json` puts every expanded value back as its `${NAME}`, keys
    included, so a specimen label or an identity name that contains an
    expanded value is stored as the reference. `_emit_drift` compared that file
    with this run's matrix straight from memory, where the same key still held
    the value, so the cell existed "in only one run" on each side. Reproduced
    with `veridor map`: label 'invoice inv-000123456' for a specimen whose id is
    `${VERIDOR_INV}` made 16 cells incomparable and the gate exited 0 under
    `opened` and `any` against a target serving the invoice to the other
    tenant; the same config with scrubbing patched out exited 1.
    """

    def setUp(self) -> None:
        redaction.reset()
        self.addCleanup(redaction.reset)
        redaction.register("VERIDOR_INV", SPECIMEN_ID)
        redaction.register("VERIDOR_HOST", "tenant-host-7")

    def _emit(self, baseline: dict, current: dict) -> tuple[int, dict]:
        from veridor.cli import _emit_drift  # noqa: PLC0415

        namespace = _parser().parse_args([
            "map", "--config", "c.json", "--openapi", "s.json",
            "--baseline", "b.json", "--fail-on-drift", "opened",
        ])
        with tempfile.TemporaryDirectory() as directory:
            namespace.output_dir = Path(directory)
            namespace.drift_path = Path(directory) / "drift.json"
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = _emit_drift(namespace, current, baseline, "map-id")
            return code, json.loads(namespace.drift_path.read_text("utf-8"))

    def _pair(self, label: str) -> tuple[dict, dict]:
        """(baseline as written to disk, current as held in memory)."""
        refused = [_cell("invoice_owner", label, "reached", 200),
                   _cell("other_tenant", label, "refused", 404)]
        opened = [_cell("invoice_owner", label, "reached", 200),
                  _cell("other_tenant", label, "reached", 200)]
        return redaction.scrub(_matrix(refused)), _matrix(opened)

    def test_a_label_that_names_the_scrubbed_id_still_lines_up(self) -> None:
        baseline, current = self._pair(f"invoice {SPECIMEN_ID}")
        # The premise: the file really holds the reference, memory the value.
        self.assertEqual(baseline["cells"][0]["specimen"], "invoice ${VERIDOR_INV}")
        self.assertEqual(current["cells"][0]["specimen"], f"invoice {SPECIMEN_ID}")
        code, report = self._emit(baseline, current)
        self.assertEqual(report["incomparable_cells"], 0, report["counts"])
        self.assertEqual(report["counts"], {"reach_opened": 1})
        self.assertEqual(code, 1)

    def test_an_identity_named_like_a_scrubbed_value_still_lines_up(self) -> None:
        redaction.register("VERIDOR_LOGIN", "other_tenant")
        baseline, current = self._pair("owner_invoice")
        self.assertIn("${VERIDOR_LOGIN}", {cell["identity"] for cell in baseline["cells"]})
        code, report = self._emit(baseline, current)
        self.assertEqual(report["incomparable_cells"], 0, report["counts"])
        self.assertEqual(code, 1)

    def test_a_baseline_that_still_holds_the_raw_value_lines_up_too(self) -> None:
        """Written by a build that did not scrub, or before the id moved into
        `${NAME}`. Scrubbing only the current side would break this one."""
        label = f"invoice {SPECIMEN_ID}"
        _, current = self._pair(label)
        raw_baseline = _matrix([_cell("invoice_owner", label, "reached", 200),
                                _cell("other_tenant", label, "refused", 404)])
        code, report = self._emit(raw_baseline, current)
        self.assertEqual(report["incomparable_cells"], 0)
        self.assertEqual(code, 1)

    def test_a_scrubbed_base_url_is_the_same_target(self) -> None:
        baseline = redaction.scrub(_matrix([], "http://tenant-host-7.example:8765"))
        self.assertEqual(baseline["target"]["base_url"], "http://${VERIDOR_HOST}.example:8765")
        from veridor import drift  # noqa: PLC0415

        text = drift.render(drift.compare(baseline,
                                          _matrix([], "http://tenant-host-7.example:8765")))
        self.assertNotIn("different targets", text)

    def test_control_a_label_without_the_value_lines_up(self) -> None:
        baseline, current = self._pair("owner_invoice")
        code, report = self._emit(baseline, current)
        self.assertEqual((code, report["incomparable_cells"]), (1, 0))

    def test_control_really_different_labels_still_do_not_line_up(self) -> None:
        """Scrubbing is not a fuzzy join: a re-seeded specimen is still a
        different cell."""
        baseline, _ = self._pair("seed-a")
        _, current = self._pair("seed-b")
        _, report = self._emit(baseline, current)
        self.assertEqual(report["incomparable_cells"], 4)


@slow("map paces its requests on a real clock (10 per second at most)")
class JoinKeyEndToEndTest(unittest.TestCase):
    """The same, recorded and gated by `veridor map` itself."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def _record_then_gate(self, config: dict, env: dict[str, str],
                          policy: str = "opened") -> tuple[int, dict, _Target]:
        env = {"VERIDOR_INV": SPECIMEN_ID, **env}
        code, _, stderr = _map(self.root, config, _Target("fixed", SPECIMEN_ID),
                               ["--matrix", str(self.root / "base.json")], env)
        self.assertEqual(code, 0, stderr)
        vulnerable = _Target("vulnerable", SPECIMEN_ID)
        code, report, _ = _gate(self.root, config, self.root / "base.json", vulnerable,
                                policy, env)
        self.assertIn(f"GET /api/invoices/{SPECIMEN_ID} Bearer outsider-token",
                      vulnerable.sent)
        return code, report, vulnerable

    def test_a_label_naming_the_id_catches_the_read(self) -> None:
        config = _specimen_config(f"invoice {SPECIMEN_ID}")
        for policy in ("opened", "any"):
            with self.subTest(policy=policy):
                code, report, _ = self._record_then_gate(config, {}, policy)
                self.assertIn(b"invoice ${VERIDOR_INV}",
                              (self.root / "base.json").read_bytes())
                self.assertEqual(report["incomparable_cells"], 0, report["counts"])
                self.assertIn("reach_opened", report["counts"])
                self.assertEqual(code, 1)

    def test_an_identity_named_like_a_value_catches_the_read(self) -> None:
        config = _specimen_config("owner_invoice", login="${VERIDOR_LOGIN}")
        code, report, _ = self._record_then_gate(config, {"VERIDOR_LOGIN": "other_tenant"})
        self.assertEqual(report["incomparable_cells"], 0, report["counts"])
        self.assertEqual(code, 1)

    def test_control_an_unrelated_label_catches_the_read(self) -> None:
        code, report, _ = self._record_then_gate(_specimen_config("owner_invoice"), {})
        self.assertEqual((code, report["incomparable_cells"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
