"""A command whose results cannot be written sends nothing.

Measured before the preflight existed: ``veridor run`` with an unwritable
``--output-dir`` sent every probe to the target and then exited 2 with nothing
but ``[Errno 13] Permission denied: <dir>``. The finding was lost, exit 2 read
as "configuration refused" about a run that had already happened, and a
write-mode configuration would already have changed the target. The release
image runs as uid 10001, so a root-owned directory mounted at /work reproduces
it exactly.

Every verb that sends requests and writes results -- run, verify <capsule>,
map, mutate -- now proves it can create each output directory and write a file
in it before the first request, and refuses with exit 2 naming the path, the
effective uid:gid and the fix.

Fast tests drive ``cli.main`` in-process with the sending function replaced by
a counter. The slow tests run the real CLI in a subprocess against a loopback
listener that counts requests: 0 when the directory is unwritable, more than 0
for the same command with a writable one (the control).
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import cli  # noqa: E402

FIXTURES = ROOT / "fixtures"


def _capture(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


def _config(base_url: str) -> dict:
    return {
        "version": 1,
        "target": {"base_url": base_url, "timeout_seconds": 3},
        "identities": {
            "owner": {"headers": {"Authorization": "Bearer owner"}},
            "other": {"headers": {"Authorization": "Bearer other"}},
        },
        "checks": [{
            "id": "c1",
            "request": {"method": "GET", "path": "/a"},
            "expect": {"owner": {"status": [200]}, "other": {"status": [403]}},
        }],
    }


def _capsule(base_url: str) -> dict:
    config = _config(base_url)
    return {
        "kind": "veridor.capsule",
        "schema_version": 1,
        "claim": {"check_id": "c1"},
        "target": config["target"],
        "identities": config["identities"],
        "check": config["checks"][0],
        "requires_environment": [],
    }


def _map_config(base_url: str) -> dict:
    config = json.loads((FIXTURES / "veridor.map-demo.json").read_text(encoding="utf-8"))
    config["target"]["base_url"] = base_url
    return config


class _Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        # A directory under a regular file cannot be created, by any user,
        # root included -- unlike a 0555 directory, which root writes through.
        self.blocker = self.root / "not-a-directory"
        self.blocker.write_text("", encoding="utf-8")
        self.unwritable = self.blocker / "out"
        self.config = self.root / "veridor.json"
        self.config.write_text(json.dumps(_config("http://127.0.0.1:9")), encoding="utf-8")

    def assert_refusal(self, stderr: str, flag: str, path: Path) -> None:
        self.assertIn(f"{flag} {path}", stderr)
        self.assertIn(f"as uid:gid {os.geteuid()}:{os.getegid()}", stderr)
        self.assertIn("Nothing has been sent", stderr)
        self.assertIn('docker run --user "$(id -u):$(id -g)"', stderr)


class _Counter:
    def __init__(self, result=None) -> None:
        self.calls = 0
        self.result = result

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return copy.deepcopy(self.result)


class RunPreflightTest(_Workspace):
    def run_cli(self, *extra: str) -> tuple[int, str, str, int]:
        counter = _Counter(RuntimeError("stop after the preflight"))
        with mock.patch.object(cli, "execute_run", counter):
            code, stdout, stderr = _capture(["run", "--config", str(self.config), *extra])
        return code, stdout, stderr, counter.calls

    def test_an_unwritable_output_dir_is_refused_before_the_run(self) -> None:
        code, _, stderr, calls = self.run_cli("--output-dir", str(self.unwritable))
        self.assertEqual(code, 2, stderr)
        self.assertEqual(calls, 0)
        self.assert_refusal(stderr, "--output-dir", self.unwritable)
        self.assertIn("--output-dir /tmp/veridor", stderr)

    def test_the_control_a_writable_output_dir_reaches_the_run(self) -> None:
        code, _, stderr, calls = self.run_cli("--output-dir", str(self.root / "out"))
        self.assertEqual(calls, 1, stderr)
        self.assertEqual(code, 70)  # the RuntimeError the counter raised

    def test_each_file_destination_is_checked(self) -> None:
        writable = self.root / "out"
        for flag, value in (
            ("--json", str(self.unwritable / "run.json")),
            ("--sarif", str(self.unwritable / "run.sarif")),
            ("--report", f"junit={self.unwritable / 'junit.xml'}"),
        ):
            with self.subTest(flag=flag):
                code, _, stderr, calls = self.run_cli("--output-dir", str(writable), flag, value)
                self.assertEqual((code, calls), (2, 0), stderr)
                self.assertIn(str(self.unwritable), stderr)
                self.assertIn(f"point {flag} at a directory", stderr)

    def test_a_destination_that_is_a_directory_is_refused(self) -> None:
        existing = self.root / "a-directory"
        existing.mkdir()
        code, _, stderr, calls = self.run_cli(
            "--output-dir", str(self.root / "out"), "--json", str(existing))
        self.assertEqual((code, calls), (2, 0), stderr)
        self.assertIn("is an existing directory", stderr)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes through 0555")
    def test_a_read_only_parent_is_refused_with_permission_denied(self) -> None:
        locked = self.root / "locked"
        locked.mkdir()
        locked.chmod(0o555)
        self.addCleanup(locked.chmod, 0o755)
        code, _, stderr, calls = self.run_cli("--output-dir", str(locked / "out"))
        self.assertEqual((code, calls), (2, 0), stderr)
        self.assertIn("Permission denied", stderr)
        self.assert_refusal(stderr, "--output-dir", locked / "out")

    def test_the_preflight_leaves_nothing_behind(self) -> None:
        """It creates the directories to prove it can, then removes what it
        created, so a refusal later on finds the tree as it was."""
        out = self.root / "deep" / "er" / "out"
        before = sorted(p.name for p in self.root.rglob("*"))
        cli._preflight_writable("run", [("--output-dir", out, True),
                                        ("--json", self.root / "j" / "run.json", False)])
        self.assertEqual(sorted(p.name for p in self.root.rglob("*")), before)
        existing = self.root / "kept"
        existing.mkdir()
        cli._preflight_writable("run", [("--output-dir", existing, True)])
        self.assertEqual(list(existing.iterdir()), [], "the probe file was left behind")

    def test_the_probe_can_fail(self) -> None:
        """Control for the helper itself: it reports a failure it did not cause
        and passes a directory it can write."""
        self.assertIsNone(cli._probe_directory(self.root / "fresh"))
        failure = cli._probe_directory(self.unwritable)
        self.assertIsNotNone(failure)
        self.assertEqual(failure[0], "create")


class VerifyCapsulePreflightTest(_Workspace):
    def test_verify_refuses_before_the_run(self) -> None:
        capsule = self.root / "proof.json"
        capsule.write_text(json.dumps(_capsule("http://127.0.0.1:9")), encoding="utf-8")
        for output_dir, expected_calls in ((self.unwritable, 0), (self.root / "out", 1)):
            with self.subTest(output_dir=str(output_dir)):
                counter = _Counter(RuntimeError("stop after the preflight"))
                with mock.patch.object(cli, "execute_run", counter):
                    code, _, stderr = _capture(
                        ["verify", str(capsule), "--output-dir", str(output_dir)])
                self.assertEqual(counter.calls, expected_calls, stderr)
                if expected_calls == 0:
                    self.assertEqual(code, 2)
                    self.assert_refusal(stderr, "--output-dir", output_dir)
                    self.assertNotIn("verifying capsule check", stderr)


class MapPreflightTest(_Workspace):
    def setUp(self) -> None:
        super().setUp()
        self.config.write_text(json.dumps(_map_config("http://127.0.0.1:9")), encoding="utf-8")

    def run_map(self, *extra: str) -> tuple[int, str, int]:
        counter = _Counter(RuntimeError("stop after the preflight"))
        with mock.patch.object(cli, "execute_matrix", counter):
            code, _, stderr = _capture(["map", "--config", str(self.config), "--openapi",
                                        str(FIXTURES / "openapi.demo.json"), *extra])
        return code, stderr, counter.calls

    def test_map_refuses_before_the_matrix(self) -> None:
        code, stderr, calls = self.run_map("--output-dir", str(self.unwritable))
        self.assertEqual((code, calls), (2, 0), stderr)
        self.assert_refusal(stderr, "--output-dir", self.unwritable / "matrix")
        code, stderr, calls = self.run_map("--output-dir", str(self.root / "out"),
                                           "--matrix", str(self.unwritable / "m.json"))
        self.assertEqual((code, calls), (2, 0), stderr)
        self.assertIn("--matrix", stderr)

    def test_the_control_reaches_the_matrix(self) -> None:
        _, stderr, calls = self.run_map("--output-dir", str(self.root / "out"))
        self.assertEqual(calls, 1, stderr)

    def test_dry_run_writes_nothing_and_is_not_refused(self) -> None:
        code, stderr, calls = self.run_map("--output-dir", str(self.unwritable), "--dry-run")
        self.assertEqual((code, calls), (0, 0), stderr)


class MutatePreflightTest(_Workspace):
    def run_mutate(self, *extra: str) -> tuple[int, str, int]:
        from veridor import mutation  # noqa: PLC0415

        counter = _Counter(RuntimeError("stop after the preflight"))
        with mock.patch.object(mutation, "analyze", counter):
            code, _, stderr = _capture(["mutate", "--config", str(self.config), *extra])
        return code, stderr, counter.calls

    def test_mutate_refuses_before_the_analysis(self) -> None:
        code, stderr, calls = self.run_mutate("--output-dir", str(self.unwritable))
        self.assertEqual((code, calls), (2, 0), stderr)
        self.assert_refusal(stderr, "--output-dir", self.unwritable / "mutation")
        code, stderr, calls = self.run_mutate("--output-dir", str(self.root / "out"),
                                              "--text", str(self.unwritable / "m.txt"))
        self.assertEqual((code, calls), (2, 0), stderr)
        self.assertIn("--text", stderr)

    def test_the_control_reaches_the_analysis(self) -> None:
        _, stderr, calls = self.run_mutate("--output-dir", str(self.root / "out"))
        self.assertEqual(calls, 1, stderr)


class _CountingTarget:
    """A loopback target that answers 200 to the owner and 403 to anyone
    else, and counts every request it receives."""

    def __enter__(self) -> "_CountingTarget":
        self.requests: list[str] = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _answer(self) -> None:
                requests.append(f"{self.command} {self.path}")
                owner = self.headers.get("Authorization") == "Bearer owner-token"
                body = b'{"ok": true}'
                self.send_response(200 if owner else 403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_OPTIONS = _answer  # noqa: N815

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = loopback.start(self.server)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@slow("spawns veridor as a subprocess against a loopback listener")
class PreflightOnTheWireTest(unittest.TestCase):
    """The failing-first measurement, as a test: requests the target saw.

    Before the preflight the unwritable rows saw every probe (the run then
    exited 2). Each verb is run twice, unwritable and writable, and the
    writable row is the control that the listener does count requests."""

    def run_verb(self, argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "veridor", *argv], capture_output=True,
                              text=True, env=source_path.child_env(), cwd=cwd, timeout=120)

    def test_no_request_reaches_the_target_when_the_results_cannot_be_written(self) -> None:
        with _CountingTarget() as target, tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "blocker").write_text("", encoding="utf-8")
            unwritable = root / "blocker" / "out"
            config = _config(target.url)
            config["identities"]["owner"]["headers"]["Authorization"] = "Bearer owner-token"
            (root / "run.json").write_text(json.dumps(config), encoding="utf-8")
            (root / "map.json").write_text(json.dumps(_map_config(target.url)), encoding="utf-8")
            capsule = _capsule(target.url)
            capsule["identities"] = config["identities"]
            (root / "proof.json").write_text(json.dumps(capsule), encoding="utf-8")
            verbs = {
                "run": ["run", "--config", str(root / "run.json")],
                "verify": ["verify", str(root / "proof.json")],
                "map": ["map", "--config", str(root / "map.json"),
                        "--openapi", str(FIXTURES / "openapi.demo.json"), "--rate", "10"],
                "mutate": ["mutate", "--config", str(root / "run.json"), "--min-interval", "0"],
            }
            for verb, argv in verbs.items():
                with self.subTest(verb=verb, writable=False):
                    target.requests.clear()
                    result = self.run_verb([*argv, "--output-dir", str(unwritable)], root)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(target.requests, [], result.stderr)
                    self.assertIn("Nothing has been sent", result.stderr)
                    self.assertIn(str(unwritable), result.stderr)
                with self.subTest(verb=verb, writable=True):
                    target.requests.clear()
                    result = self.run_verb([*argv, "--output-dir", str(root / f"{verb}-out")], root)
                    self.assertGreater(len(target.requests), 0, result.stderr)
                    self.assertNotIn("Nothing has been sent", result.stderr)


if __name__ == "__main__":
    unittest.main()
