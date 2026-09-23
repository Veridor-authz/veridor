"""How the process ends when the command itself does not finish.

A CI job reads one number. Three ways of ending used to be indistinguishable
from, or worse than, a result:

* An uncaught exception exited ``1`` -- the code for "the gate failed on a
  finding" -- so a crash inside Veridor was reported as a finding about the
  target.
* ``SIGTERM`` (Kubernetes pod termination, a Job deadline, a CI runner
  cancelling) killed the interpreter outright. ``SIGINT`` raised
  ``KeyboardInterrupt``, so sequence teardown ran in its ``finally``; SIGTERM
  skipped it and left the fixtures a sequence created on the target.
* ``python -m veridor`` did not exist, so an integration that runs Veridor
  from a source checkout had no entry point that did not depend on a console
  script being installed.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import __version__, cli  # noqa: E402
from veridor.core import ConfigError  # noqa: E402


def _main_with(replacement, argv: list[str]) -> tuple[int, str]:
    stderr = io.StringIO()
    with patch.object(cli, "_new_marker", replacement), contextlib.redirect_stderr(stderr):
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(argv)
    return code, stderr.getvalue()


class InternalErrorExitTest(unittest.TestCase):
    """A bug in Veridor must never read as a finding about the target."""

    def test_an_uncaught_exception_exits_70_not_1(self) -> None:
        def explode(args):
            raise RuntimeError("synthetic defect for the exit-code test")

        code, stderr = _main_with(explode, ["new-marker"])
        self.assertEqual(code, 70)
        self.assertNotEqual(code, 1)
        self.assertIn("veridor: internal error", stderr)
        # The traceback is the bug report; swallowing it would make the crash
        # unreportable.
        self.assertIn("Traceback (most recent call last)", stderr)
        self.assertIn("RuntimeError: synthetic defect for the exit-code test", stderr)
        self.assertIn("not a finding about your target", stderr)
        self.assertIn("https://github.com/Veridor-authz/veridor/issues", stderr)

    def test_a_configuration_error_still_exits_2(self) -> None:
        """Control: the typed refusal path is unchanged."""

        def refuse(args):
            raise ConfigError("synthetic refusal")

        code, stderr = _main_with(refuse, ["new-marker"])
        self.assertEqual(code, 2)
        self.assertIn("veridor: synthetic refusal", stderr)
        self.assertNotIn("internal error", stderr)

    def test_keyboard_interrupt_still_exits_130(self) -> None:
        def interrupt(args):
            raise KeyboardInterrupt

        code, stderr = _main_with(interrupt, ["new-marker"])
        self.assertEqual(code, 130)
        self.assertNotIn("internal error", stderr)

    def test_system_exit_passes_through_untouched(self) -> None:
        def leave(args):
            raise SystemExit(5)

        with self.assertRaises(SystemExit) as caught:
            _main_with(leave, ["new-marker"])
        self.assertEqual(caught.exception.code, 5)

    def test_main_leaves_the_sigterm_disposition_as_it_found_it(self) -> None:
        """main() is called in-process by the whole suite; it must not leave
        its handler installed in the test runner."""
        before = signal.getsignal(signal.SIGTERM)
        _main_with(lambda args: 0, ["new-marker"])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_sigterm_during_a_command_takes_the_interrupt_path(self) -> None:
        """In-process half of the SIGTERM contract: the handler main() installs
        turns SIGTERM into an exception every `finally` sees, and main maps it
        to 143. The subprocess test below proves it against a real target."""
        seen: list[str] = []

        def terminated(args):
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler), "main() installed no SIGTERM handler")
            try:
                handler(signal.SIGTERM, None)
            finally:
                seen.append("finally ran")

        code, stderr = _main_with(terminated, ["new-marker"])
        self.assertEqual(code, 143)
        self.assertEqual(seen, ["finally ran"])
        self.assertIn("SIGTERM", stderr)


MARKER_VICTIM = "vdr-Nq4Zt8Wm3Kx7Bv2Ld6Rj9Ph5"
MARKER_ATTACKER = "vdr-Ac7Fg2Hj5Kl8Mn1Qs4Tv6Wy0"


@contextlib.contextmanager
def _hanging_target():
    """A loopback target whose attacker read hangs until released.

    Records every request. The hang is what lets the test deliver a signal at a
    known point: after setup created a fixture, before the sequence finished.
    The first teardown DELETE (``/docs/42``) also parks until
    ``release_teardown`` is set, so a test can signal DURING teardown.
    """
    log: list[tuple[str, str]] = []
    hanging = threading.Event()
    release = threading.Event()
    in_teardown = threading.Event()
    release_teardown = threading.Event()
    release_teardown.set()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length:
                self.rfile.read(length)
            auth = self.headers.get("Authorization", "")
            log.append((self.command, self.path))
            if self.command == "POST":
                status, body = 201, json.dumps({"id": 42}).encode()
            elif self.command == "DELETE":
                if self.path == "/docs/42":
                    in_teardown.set()
                    release_teardown.wait(30)
                status, body = 204, b""
            elif auth == "Bearer victim-token":
                status, body = 200, json.dumps({"note": MARKER_VICTIM}).encode()
            else:
                hanging.set()
                release.wait(30)
                status, body = 403, b'{"e":1}'
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)
            except OSError:
                pass

        do_GET = _dispatch  # noqa: N815 - stdlib callback names
        do_POST = _dispatch  # noqa: N815
        do_DELETE = _dispatch  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(httpd)
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", log, hanging, (
            in_teardown, release_teardown
        )
    finally:
        release.set()
        release_teardown.set()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _sequence_config(base_url: str) -> dict:
    return {
        "version": 2,
        "target": {"base_url": base_url, "timeout_seconds": 30},
        "identities": {
            "victim": {
                "headers": {"Authorization": "Bearer victim-token"},
                "marker": MARKER_VICTIM,
            },
            "attacker": {
                "headers": {"Authorization": "Bearer attacker-token"},
                "marker": MARKER_ATTACKER,
            },
        },
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


def _env() -> dict[str, str]:
    return source_path.child_env()


def _default_sigint() -> None:
    """Start the child with SIGINT at its default disposition.

    A shell without job control starts a background job (``cmd &``) with
    SIGINT ignored, every process it spawns inherits that, and a Python child
    keeps an inherited SIG_IGN instead of installing its KeyboardInterrupt
    handler. Run that way, the SIGINT tests below measured the harness: the
    child ignored the signal and the test timed out (measured: the full slow
    tier, launched as ``( ... ) &``, failed both SIGINT tests; the same tests
    in the foreground passed). SIGTERM is not affected, so it needs no reset.
    """
    signal.signal(signal.SIGINT, signal.SIG_DFL)


@slow("spawns veridor as a subprocess against a loopback target and signals it")
class SignalTeardownTest(unittest.TestCase):
    """SIGTERM must reach the same `finally` SIGINT reaches.

    Measured before the fix, on the target below: SIGINT exited 130 with the
    teardown DELETE observed and nothing written to --output-dir; SIGTERM was
    killed by the signal (returncode -15) with no DELETE -- the fixture the
    sequence created stayed on the target.
    """

    def _interrupt(self, signum: int, *, again_during_teardown: bool = False) -> dict:
        with _hanging_target() as (url, log, hanging, teardown), tempfile.TemporaryDirectory() as tmp:
            in_teardown, release_teardown = teardown
            root = Path(tmp)
            config = root / "veridor.json"
            document = _sequence_config(url)
            if again_during_teardown:
                release_teardown.clear()
                document["sequences"][0]["teardown"].append(
                    {
                        "as": "victim",
                        "request": {"method": "DELETE", "path": "/other/${doc_id}"},
                        "expect": {"status": [204]},
                    }
                )
            config.write_text(json.dumps(document), encoding="utf-8")
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "veridor.cli", "run",
                    "--config", str(config),
                    "--output-dir", str(root / "out"),
                    "--no-prove-liveness",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_env(),
                cwd=tmp,
                preexec_fn=_default_sigint,
            )
            try:
                self.assertTrue(
                    hanging.wait(30), "the sequence never reached the hanging step"
                )
                # The request is in flight; deliver the signal mid-sequence.
                process.send_signal(signum)
                if again_during_teardown:
                    self.assertTrue(in_teardown.wait(30), "teardown never started")
                    process.send_signal(signum)
                    # Give the second signal time to be handled before the
                    # parked DELETE returns and teardown moves on.
                    time.sleep(0.5)
                    release_teardown.set()
                stdout, stderr = process.communicate(timeout=30)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            written = sorted(
                str(path.relative_to(root))
                for path in (root / "out").rglob("*")
                if path.is_file()
            ) if (root / "out").exists() else []
            return {
                "code": process.returncode,
                "requests": list(log),
                "written": written,
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
            }

    def test_sigint_runs_teardown_and_exits_130(self) -> None:
        """The control: the path SIGTERM must now share."""
        result = self._interrupt(signal.SIGINT)
        self.assertEqual(result["code"], 130, result["stderr"])
        self.assertIn(("DELETE", "/docs/42"), result["requests"])

    def test_sigterm_runs_teardown_and_exits_143(self) -> None:
        result = self._interrupt(signal.SIGTERM)
        self.assertEqual(result["code"], 143, result["stderr"])
        self.assertIn(("DELETE", "/docs/42"), result["requests"])
        # The DELETE comes after the POST that created the fixture.
        methods = [method for method, _ in result["requests"]]
        self.assertLess(methods.index("POST"), methods.index("DELETE"))
        self.assertIn("SIGTERM", result["stderr"])

    def test_a_second_sigterm_during_teardown_does_not_cut_it_short(self) -> None:
        """Two teardown entries; the second SIGTERM lands while the first is in
        flight. Both DELETEs must still reach the target."""
        result = self._interrupt(signal.SIGTERM, again_during_teardown=True)
        self.assertEqual(result["code"], 143, result["stderr"])
        self.assertIn(("DELETE", "/docs/42"), result["requests"])
        self.assertIn(("DELETE", "/other/42"), result["requests"])

    def test_sigterm_writes_exactly_what_sigint_writes(self) -> None:
        interrupted = self._interrupt(signal.SIGINT)
        terminated = self._interrupt(signal.SIGTERM)
        self.assertEqual(terminated["written"], interrupted["written"])
        self.assertEqual(terminated["stdout"], interrupted["stdout"])


@slow("spawns the interpreter to run the package as a module")
class ModuleEntryPointTest(unittest.TestCase):
    def test_python_dash_m_veridor_prints_the_package_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [sys.executable, "-m", "veridor", "--version"],
                capture_output=True,
                text=True,
                env=_env(),
                cwd=tmp,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), f"veridor {__version__}")

    def test_python_dash_m_veridor_propagates_the_exit_code(self) -> None:
        """A refusal through the module entry point is still exit 2."""
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [sys.executable, "-m", "veridor", "run"],
                capture_output=True,
                text=True,
                env=_env(),
                cwd=tmp,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("veridor:", completed.stderr)




@slow("spawns python children to read the SIGINT disposition they start with")
class ChildSigintDispositionTest(unittest.TestCase):
    """The signal tests' children start with SIGINT's default disposition,
    whatever the test process inherited."""

    PROBE = "import signal; print(signal.getsignal(signal.SIGINT) is signal.default_int_handler)"

    def _child_sees_default(self, *preexec) -> bool:
        def run_all() -> None:
            for step in preexec:
                step()
        out = subprocess.run([sys.executable, "-c", self.PROBE], capture_output=True,
                             text=True, preexec_fn=run_all, check=True).stdout.strip()
        return out == "True"

    def _ignore(self) -> None:
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def test_the_harness_resets_an_inherited_ignore(self) -> None:
        self.assertTrue(self._child_sees_default(self._ignore, _default_sigint))

    def test_control_an_inherited_ignore_is_kept_without_the_reset(self) -> None:
        self.assertFalse(self._child_sees_default(self._ignore))


if __name__ == "__main__":
    unittest.main()
