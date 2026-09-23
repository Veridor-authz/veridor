"""An output must not overwrite an input, whatever case its name is spelled in.

The output-path checks compared ``Path.resolve()`` strings, and ``resolve()``
keeps the case it was given. On a case-insensitive filesystem -- the default
for APFS on macOS, and NTFS -- ``VERIDOR.DEMO.JSON`` and ``veridor.demo.json``
are one file with two spellings, so ``--json VERIDOR.DEMO.JSON`` sailed past the
refusal and the run document replaced the configuration. Reproduced on this
repository's macOS volume for ``--json``, ``--sarif``, ``--report``, a
``--baseline``, the managed history, ``report --output`` over its own input and
``init --force --output`` over the specification.

Paths are now compared as FILES: by device and inode when both exist, and by
the nearest existing directory plus the case rule that directory's filesystem
actually applies (detected by looking, never assumed from the platform) when
one does not exist yet.

Every expectation here follows the filesystem the test runs on. On a
case-insensitive one the case-variant name must be refused and the input left
byte-for-byte alone; on a case-sensitive one it is a different file and must be
written. So the suite asserts the right thing on a Mac and on Linux CI alike.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_capsule import _RecordingOpener  # noqa: E402
from veridor import cli, core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

DEMO_CONFIG = ROOT / "fixtures" / "veridor.demo.json"
DEMO_SPEC = ROOT / "fixtures" / "openapi.demo.json"


def _filesystem_is_case_insensitive(directory: Path) -> bool:
    """The test's own probe, independent of the code under test."""
    probe = directory / "case-probe.txt"
    probe.write_text("x", encoding="utf-8")
    try:
        other = directory / "CASE-PROBE.TXT"
        return other.exists() and os.path.samefile(probe, other)
    finally:
        probe.unlink()


def _capture(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(core, "_OPENER", _RecordingOpener()):
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = veridor_main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class _Workspace(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.insensitive = _filesystem_is_case_insensitive(self.root)
        self.config = self.root / "veridor.demo.json"
        self.config.write_bytes(DEMO_CONFIG.read_bytes())

    def run_veridor(self, *extra: str) -> tuple[int, str, str]:
        return _capture(["run", "--config", str(self.config),
                         "--output-dir", str(self.root / "out"), *extra])

    def assertCaseVariantHandled(self, protected: Path, code: int, stderr: str,  # noqa: N802
                                 before: bytes, message: str) -> None:
        if self.insensitive:
            self.assertEqual(code, 2, stderr)
            self.assertIn(message, stderr)
            self.assertEqual(protected.read_bytes(), before, "the input was overwritten")
        else:
            self.assertNotIn(message, stderr)
            self.assertEqual(protected.read_bytes(), before)


class ProbeTest(unittest.TestCase):
    """Every case-variant test below branches on this probe, so it is tested
    for both answers. It used to assert only that the probe returned a bool,
    and a probe hard-coded to True or to False passed that."""

    def test_the_probe_agrees_with_an_independent_look(self) -> None:
        """On the real directory: a file opened by its swapped-case name is
        the same file exactly when the probe says insensitive."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Independent.txt").write_text("x", encoding="utf-8")
            try:
                with open(root / "INDEPENDENT.TXT", encoding="utf-8") as handle:
                    expected = handle.read() == "x"
            except FileNotFoundError:
                expected = False
            self.assertEqual(_filesystem_is_case_insensitive(root), expected)

    def test_the_probe_can_say_both_things(self) -> None:
        """Whatever this filesystem is, the probe must be able to return the
        other answer: a swapped-case name that does not exist is sensitive, one
        that is the same file is insensitive. A genuinely different name is
        never the same file."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.txt").write_text("1", encoding="utf-8")
            self.assertFalse((root / "two.txt").exists())
            real_exists = Path.exists

            def sensitive(path: Path, *args, **kwargs) -> bool:
                if path.name != path.name.lower():
                    return False
                return real_exists(path, *args, **kwargs)

            with patch.object(Path, "exists", sensitive):
                self.assertFalse(_filesystem_is_case_insensitive(root))
            with patch.object(Path, "exists", lambda path, *a, **k: True), \
                    patch.object(os.path, "samefile", lambda a, b: True):
                self.assertTrue(_filesystem_is_case_insensitive(root))
            # The same-file half is not decided by existence alone.
            with patch.object(Path, "exists", lambda path, *a, **k: True), \
                    patch.object(os.path, "samefile", lambda a, b: False):
                self.assertFalse(_filesystem_is_case_insensitive(root))


class RunOutputTest(_Workspace):
    MESSAGE = "must not overwrite a configuration, baseline, or specification"

    def test_json_sarif_and_report_spelled_in_another_case(self) -> None:
        before = self.config.read_bytes()
        for flags in (("--json", str(self.root / "VERIDOR.DEMO.JSON")),
                      ("--sarif", str(self.root / "Veridor.Demo.Json")),
                      ("--report", f"markdown={self.root / 'VERIDOR.DEMO.JSON'}")):
            with self.subTest(flags=flags[0]):
                self.config.write_bytes(before)  # each case starts from the real config
                code, _, stderr = self.run_veridor(*flags)
                self.assertCaseVariantHandled(self.config, code, stderr, before, self.MESSAGE)

    def test_a_baseline_spelled_in_another_case(self) -> None:
        baseline = self.root / "baseline.json"
        code, _, stderr = self.run_veridor("--json", str(baseline))
        self.assertNotEqual(code, 2, stderr)
        before = baseline.read_bytes()
        code, _, stderr = self.run_veridor("--baseline", str(baseline),
                                           "--json", str(self.root / "BASELINE.json"))
        self.assertCaseVariantHandled(baseline, code, stderr, before, self.MESSAGE)

    def test_managed_history_spelled_in_another_case(self) -> None:
        code, _, stderr = self.run_veridor()
        self.assertNotEqual(code, 2, stderr)
        latest = self.root / "out" / "latest.json"
        before = latest.read_bytes()
        runs = sorted((self.root / "out" / "runs").iterdir())
        for target in (self.root / "OUT" / "LATEST.json",
                       self.root / "OUT" / "RUNS" / "x.json"):
            with self.subTest(target=target.name):
                code, _, stderr = self.run_veridor("--json", str(target))
                if self.insensitive:
                    self.assertEqual(code, 2, stderr)
                    self.assertIn("conflicts with managed run history", stderr)
                else:
                    self.assertNotIn("conflicts with managed run history", stderr)
        if self.insensitive:
            self.assertEqual(latest.read_bytes(), before)
            self.assertEqual(sorted((self.root / "out" / "runs").iterdir()), runs)

    def test_two_new_outputs_that_differ_only_in_case(self) -> None:
        """Neither exists yet, so there is no inode to compare: the directory
        they share and that directory's case rule decide."""
        code, _, stderr = self.run_veridor("--json", str(self.root / "fresh.json"),
                                           "--sarif", str(self.root / "FRESH.json"))
        if self.insensitive:
            self.assertEqual(code, 2, stderr)
            self.assertIn("must use different paths", stderr)
        else:
            self.assertNotIn("must use different paths", stderr)

    def test_control_the_same_spelling_is_still_refused(self) -> None:
        before = self.config.read_bytes()
        code, _, stderr = self.run_veridor("--json", str(self.config))
        self.assertEqual(code, 2)
        self.assertIn(self.MESSAGE, stderr)
        self.assertEqual(self.config.read_bytes(), before)

    def test_control_a_different_file_is_still_written(self) -> None:
        before = self.config.read_bytes()
        result = self.root / "result.json"
        code, _, stderr = self.run_veridor("--json", str(result))
        self.assertNotEqual(code, 2, stderr)
        self.assertTrue(result.is_file())
        self.assertEqual(self.config.read_bytes(), before)


class OtherCommandTest(_Workspace):
    def test_report_output_spelled_like_its_input(self) -> None:
        run = self.root / "run.json"
        self.run_veridor("--json", str(run))
        before = run.read_bytes()
        code, _, stderr = _capture(["report", "--from-run", str(run), "--format", "markdown",
                                    "--output", str(self.root / "RUN.JSON")])
        self.assertCaseVariantHandled(run, code, stderr, before,
                                      "must not overwrite the input run")

    def test_init_output_spelled_like_the_specification(self) -> None:
        spec = self.root / "openapi.demo.json"
        spec.write_bytes(DEMO_SPEC.read_bytes())
        before = spec.read_bytes()
        code, _, stderr = _capture(["init", "--openapi", str(spec), "--force",
                                    "--output", str(self.root / "OPENAPI.DEMO.JSON")])
        self.assertCaseVariantHandled(spec, code, stderr, before,
                                      "must not overwrite the OpenAPI specification")


class CapsuleOutputTest(_Workspace):
    """`veridor capsule --output` was written with no destination check.

    Reproduced: `--output veridor.json` over the `--config` file, the upper-case
    spelling on a case-insensitive volume and `./sub/../veridor.json` each
    replaced the configuration with the capsule and exited 0; `--from-run X
    --output X` replaced the run document. The configuration here uses
    `${VERIDOR_*}` references, because the demo fixture's literal token makes
    `capsule` refuse before it writes anything, which would hide the bug.
    """

    MESSAGE = "must not overwrite a configuration, baseline, or specification"

    def setUp(self) -> None:
        super().setUp()
        from test_capsule import _config  # noqa: PLC0415

        self.config.write_text(json.dumps(_config()), encoding="utf-8")
        self.before = self.config.read_bytes()

    def _capsule(self, *extra: str) -> tuple[int, str]:
        code, _, stderr = _capture(["capsule", "--config", str(self.config),
                                    "--check", "tenant-isolation", *extra])
        return code, stderr

    def test_output_over_the_configuration(self) -> None:
        (self.root / "sub").mkdir()
        for spelling in (self.config, self.root / "sub" / ".." / self.config.name):
            with self.subTest(output=str(spelling)):
                self.config.write_bytes(self.before)
                code, stderr = self._capsule("--output", str(spelling))
                self.assertEqual(code, 2, stderr)
                self.assertIn(self.MESSAGE, stderr)
                self.assertEqual(self.config.read_bytes(), self.before)
        self.config.write_bytes(self.before)
        code, stderr = self._capsule("--output", str(self.root / "VERIDOR.DEMO.JSON"))
        self.assertCaseVariantHandled(self.config, code, stderr, self.before, self.MESSAGE)

    def test_output_over_the_run_it_reads(self) -> None:
        run = self.root / "run.json"
        run.write_text(json.dumps({"run_id": "r", "findings": []}), encoding="utf-8")
        before = run.read_bytes()
        code, stderr = self._capsule("--from-run", str(run), "--output", str(run))
        self.assertEqual(code, 2, stderr)
        self.assertIn("must not overwrite the input run", stderr)
        self.assertEqual(run.read_bytes(), before)

    def test_control_an_output_elsewhere_is_written(self) -> None:
        proof = self.root / "proof.json"
        code, stderr = self._capsule("--output", str(proof))
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(proof.read_text("utf-8"))["kind"], "veridor.capsule")
        self.assertEqual(self.config.read_bytes(), self.before)


class SameFileTest(unittest.TestCase):
    """The comparison itself, including the half that needs no existing file."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.insensitive = _filesystem_is_case_insensitive(self.root)

    def test_existing_files(self) -> None:
        a = self.root / "a.json"
        a.write_text("{}", encoding="utf-8")
        other = self.root / "other.json"
        other.write_text("{}", encoding="utf-8")
        self.assertTrue(cli._same_file(a, a))
        self.assertEqual(cli._same_file(a, self.root / "A.JSON"), self.insensitive)
        self.assertFalse(cli._same_file(a, other))

    def test_a_hard_link_is_the_same_file(self) -> None:
        a = self.root / "a.json"
        a.write_text("{}", encoding="utf-8")
        link = self.root / "link.json"
        os.link(a, link)
        self.assertTrue(cli._same_file(a, link))

    def test_names_that_do_not_exist_yet(self) -> None:
        self.assertEqual(cli._same_file(self.root / "n.json", self.root / "N.json"),
                         self.insensitive)
        self.assertEqual(
            cli._same_file(self.root / "new" / "deeper" / "n.json",
                           self.root / "NEW" / "Deeper" / "N.JSON"),
            self.insensitive)
        self.assertFalse(cli._same_file(self.root / "n.json", self.root / "m.json"))
        self.assertFalse(cli._same_file(self.root / "new" / "n.json", self.root / "n.json"))

    def test_the_detector_reports_what_the_filesystem_does(self) -> None:
        (self.root / "entry.txt").write_text("x", encoding="utf-8")
        self.assertEqual(cli._case_insensitive(self.root), self.insensitive)

    def test_control_the_detector_can_answer_case_sensitive(self) -> None:
        """Simulated: a directory whose swapped-case entry is missing is
        case-sensitive, whatever platform this is."""
        (self.root / "entry.txt").write_text("x", encoding="utf-8")
        real = os.path.samefile

        def sensitive(a, b):
            if Path(a).name != Path(b).name:
                raise FileNotFoundError(b)
            return real(a, b)

        with patch.object(cli.os.path, "samefile", sensitive):
            self.assertFalse(cli._case_insensitive(self.root))
            self.assertFalse(cli._same_file(self.root / "n.json", self.root / "N.json"))


class _DemoTarget:
    """The demo target's two checked routes, as ``core._OPENER``.

    ``vulnerable`` serves the owner's invoice to the other tenant too, with no
    marker in the body -- a suspected, unconfirmed finding, which the default
    `--fail-on new+confirmed` gates on only while it is new.
    """

    MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"

    def __init__(self, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.sent: list[str] = []

    def open(self, request, timeout=None):  # noqa: A003 - mirrors OpenerDirector
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        token = request.get_header("Authorization") or ""
        path = "/" + request.full_url.split("/", 3)[3]
        self.sent.append(f"{request.get_method()} {path} {token}")
        if token not in ("Bearer owner-token", "Bearer outsider-token", "Bearer admin-token"):
            status, body = 401, {}
        elif path == "/api/invoices/inv-100":
            if token == "Bearer owner-token":
                status, body = 200, {"id": "inv-100", "ref": self.MARKER}
            elif token == "Bearer outsider-token" and self.vulnerable:
                status, body = 200, {"id": "inv-100"}
            else:
                status, body = 404, {}
        elif path == "/api/admin/audit":
            status, body = (200, {}) if token == "Bearer admin-token" else (403, {})
        else:
            status, body = 404, {}
        data = json.dumps(body).encode()
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
        return urllib.response.addinfourl(io.BytesIO(data), headers, request.full_url, status)


class ManagedHistoryAsInputTest(_Workspace):
    """An input may not be the file the command writes its own result to.

    `run --baseline .veridor/latest.json` was accepted, and the run replaced
    its baseline with its own document. Measured against the demo target with
    a new unconfirmed cross-tenant read: run 1 exited 1, and the identical
    re-run exited 0 ("0 new, 0 resolved, 1 unchanged") with the finding live,
    under the default `--fail-on new+confirmed` and under `new`.
    `--config out/latest.json --output-dir out` replaced the configuration
    with a run document the same way.
    """

    MESSAGE = "is the file this command writes its own result to"

    def _run(self, target: _DemoTarget, *extra: str) -> tuple[int, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["run", "--config", str(self.config),
                "--output-dir", str(self.root / "out"), *extra]
        with patch.object(core, "_OPENER", target), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = veridor_main(argv)
        return code, stderr.getvalue()

    def _history(self) -> Path:
        """A clean run in the managed history, as a checkout or CI cache has."""
        code, stderr = self._run(_DemoTarget(vulnerable=False))
        self.assertEqual(code, 0, stderr)
        return self.root / "out" / "latest.json"

    def test_the_ratchet_is_refused_before_anything_is_sent(self) -> None:
        latest = self._history()
        spellings = [latest, self.root / "out" / "." / "latest.json",
                     self.root / "out" / ".." / "out" / "latest.json"]
        if self.insensitive:
            spellings.append(self.root / "OUT" / "LATEST.JSON")
        for policy in ("new+confirmed", "new"):
            for spelling in spellings:
                with self.subTest(policy=policy, baseline=str(spelling)):
                    before = latest.read_bytes()
                    runs = sorted((self.root / "out" / "runs").iterdir())
                    target = _DemoTarget(vulnerable=True)
                    first, stderr = self._run(target, "--baseline", str(spelling),
                                              "--fail-on", policy)
                    again, _ = self._run(_DemoTarget(vulnerable=True),
                                         "--baseline", str(spelling), "--fail-on", policy)
                    self.assertEqual((first, again), (2, 2), stderr)
                    self.assertIn(self.MESSAGE, stderr)
                    self.assertEqual(target.sent, [])
                    self.assertEqual(latest.read_bytes(), before)
                    self.assertEqual(sorted((self.root / "out" / "runs").iterdir()), runs)

    def test_a_configuration_there_is_not_replaced(self) -> None:
        (self.root / "out").mkdir()
        inside = self.root / "out" / "latest.json"
        inside.write_bytes(DEMO_CONFIG.read_bytes())
        before = inside.read_bytes()
        spellings = [inside] + ([self.root / "OUT" / "LATEST.JSON"] if self.insensitive else [])
        for spelling in spellings:
            with self.subTest(config=str(spelling)):
                target = _DemoTarget(vulnerable=True)
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(core, "_OPENER", target), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = veridor_main(["run", "--config", str(spelling),
                                         "--output-dir", str(self.root / "out")])
                self.assertEqual(code, 2, stderr.getvalue())
                self.assertIn(self.MESSAGE, stderr.getvalue())
                self.assertEqual(target.sent, [])
                self.assertEqual(inside.read_bytes(), before)

    def test_control_a_pinned_copy_keeps_failing_on_the_re_run(self) -> None:
        """What the refusal tells you to do, and why: the pinned baseline does
        not move, so the same regression fails the re-run too."""
        latest = self._history()
        pinned = self.root / "baseline.json"
        pinned.write_bytes(latest.read_bytes())
        for policy in ("new+confirmed", "new"):
            with self.subTest(policy=policy):
                target = _DemoTarget(vulnerable=True)
                first, stderr = self._run(target, "--baseline", str(pinned), "--fail-on", policy)
                again, _ = self._run(_DemoTarget(vulnerable=True),
                                     "--baseline", str(pinned), "--fail-on", policy)
                self.assertEqual((first, again), (1, 1), stderr)
                self.assertNotIn(self.MESSAGE, stderr)
                self.assertTrue(target.sent)

    def test_control_a_run_in_the_history_is_a_valid_baseline(self) -> None:
        """``runs/<run_id>.json`` is never rewritten, so it is not refused."""
        latest = self._history()
        clean = json.loads(latest.read_text("utf-8"))["run_id"]
        recorded = self.root / "out" / "runs" / f"{clean}.json"
        self.assertTrue(recorded.is_file())
        for attempt in ("first", "again"):
            with self.subTest(attempt=attempt):
                target = _DemoTarget(vulnerable=True)
                code, stderr = self._run(target, "--baseline", str(recorded), "--fail-on", "new")
                self.assertEqual(code, 1, stderr)
                self.assertTrue(target.sent)

    def test_verify_does_not_replace_its_capsule(self) -> None:
        from test_capsule import VERIFIER_ENV, _v010_capsule  # noqa: PLC0415

        (self.root / "out").mkdir()
        capsule = self.root / "out" / "latest.json"
        capsule.write_text(json.dumps(_v010_capsule()), encoding="utf-8")
        before = capsule.read_bytes()
        for output_dir, expected in ((self.root / "out", 2), (self.root / "elsewhere", None)):
            with self.subTest(output_dir=output_dir.name):
                target = _DemoTarget(vulnerable=True)
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.dict(os.environ, VERIFIER_ENV), \
                        patch.object(core, "_OPENER", target), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = veridor_main(["verify", str(capsule), "--output-dir", str(output_dir)])
                if expected is not None:
                    self.assertEqual(code, expected, stderr.getvalue())
                    self.assertIn(self.MESSAGE, stderr.getvalue())
                    self.assertEqual(target.sent, [])
                else:
                    # Control: the same capsule, another --output-dir, runs.
                    self.assertNotIn(self.MESSAGE, stderr.getvalue())
                    self.assertTrue(target.sent)
                self.assertEqual(capsule.read_bytes(), before)

    def test_mutate_does_not_replace_its_configuration(self) -> None:
        reports = self.root / "out" / "mutation"
        reports.mkdir(parents=True)
        inside = reports / "mutation.json"
        inside.write_bytes(DEMO_CONFIG.read_bytes())
        before = inside.read_bytes()
        code, _, stderr = _capture(["mutate", "--config", str(inside),
                                    "--output-dir", str(self.root / "out")])
        self.assertEqual(code, 2, stderr)
        self.assertIn(self.MESSAGE, stderr)
        self.assertEqual(inside.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
