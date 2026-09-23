"""``--wait-for-target SECONDS``: hold the first request until the target's
port accepts a TCP connection, or the time is up. Never a verdict.

Measured motivation: in the Argo CD PostSync end-to-end run the gate Job was
created in the same second its new target pod turned Ready, three probes got
ECONNREFUSED, and the gate exited 3 (1 run in 4). A retry of the Job would
hide that; a wait before the first request does not change what the probes
measure, only when they start.

Fast tests: the argument (a whole, non-negative number of seconds), its
refusal next to a capsule, the wait loop on a fake clock, and that the gate
ignores the record. Slow tests: the real CLI in a subprocess against a
listener that starts accepting after about 2 s, a port that never accepts,
and SIGTERM during the wait.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import cli, core, gate  # noqa: E402
from veridor.core import ConfigError  # noqa: E402

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


class ArgumentTest(unittest.TestCase):
    def test_run_and_map_take_a_whole_non_negative_number(self) -> None:
        parser = cli._parser()
        for verb in (["run", "--config", "c.json"],
                     ["map", "--config", "c.json", "--openapi", "o.json"]):
            with self.subTest(verb=verb[0]):
                self.assertEqual(parser.parse_args(verb).wait_for_target, 0)
                self.assertEqual(parser.parse_args([*verb, "--wait-for-target", "0"]).wait_for_target, 0)
                self.assertEqual(parser.parse_args([*verb, "--wait-for-target", "60"]).wait_for_target, 60)
                # The GitHub Action passes the input as typed.
                self.assertEqual(parser.parse_args([*verb, "--wait-for-target", "007"]).wait_for_target, 7)
                for bad in ("-1", "1.5", "abc", "", " 5", "5s", "0x10"):
                    with self.subTest(value=bad):
                        code, _, stderr = _capture([*verb, "--wait-for-target", bad])
                        self.assertEqual(code, 2)
                        self.assertIn("--wait-for-target", stderr)

    def test_run_passes_the_value_to_the_engine(self) -> None:
        seen: dict = {}

        def execute(*args, **kwargs):
            seen.update(kwargs)
            raise ConfigError("stop here")

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "c.json"
            config.write_text(json.dumps(_config("http://127.0.0.1:9")), encoding="utf-8")
            with mock.patch.object(cli, "execute_run", execute):
                _capture(["run", "--config", str(config), "--output-dir", str(Path(tmp) / "o"),
                          "--wait-for-target", "7"])
                self.assertEqual(seen["wait_for_target_seconds"], 7)
                _capture(["run", "--config", str(config), "--output-dir", str(Path(tmp) / "o")])
                self.assertEqual(seen["wait_for_target_seconds"], 0)

    def test_a_capsule_refuses_it_rather_than_ignoring_it(self) -> None:
        """verify's allowlist is what refuses it; nothing was added to it."""
        self.assertNotIn("wait_for_target", cli._CAPSULE_OPTIONS)
        with tempfile.TemporaryDirectory() as tmp:
            capsule = Path(tmp) / "proof.json"
            config = _config("http://127.0.0.1:9")
            capsule.write_text(json.dumps({
                "kind": "veridor.capsule", "schema_version": 1, "claim": {"check_id": "c1"},
                "target": config["target"], "identities": config["identities"],
                "check": config["checks"][0], "requires_environment": [],
            }), encoding="utf-8")
            calls: list[int] = []
            with mock.patch.object(cli, "execute_run", lambda *a, **k: calls.append(1)):
                code, _, stderr = _capture(["verify", str(capsule), "--wait-for-target", "5",
                                            "--output-dir", str(Path(tmp) / "o")])
                self.assertEqual((code, calls), (2, []), stderr)
                self.assertIn("does not apply --wait-for-target", stderr)
                # Control: the same capsule without the flag is not refused.
                code, _, stderr = _capture(["verify", str(capsule),
                                            "--output-dir", str(Path(tmp) / "o")])
                self.assertEqual(calls, [1], stderr)


class _FakeTime:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 3))
        self.now += seconds


class _Connection:
    def __enter__(self) -> "_Connection":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class WaitLoopTest(unittest.TestCase):
    def wait(self, seconds: int, outcomes: list, *, connect_cost: float = 0.0,
             base_url: str = "http://svc.example:8080") -> tuple[dict, list, _FakeTime, str]:
        fake = _FakeTime()
        calls: list[tuple] = []

        def connect(address, timeout):
            calls.append((address, round(timeout, 3), fake.now))
            fake.now += connect_cost
            outcome = outcomes.pop(0) if outcomes else ConnectionRefusedError(61, "Connection refused")
            if isinstance(outcome, BaseException):
                raise outcome
            return _Connection()

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            record = core.wait_for_target(base_url, seconds, connect=connect,
                                          clock=fake.clock, sleep=fake.sleep)
        return record, calls, fake, err.getvalue()

    def test_it_stops_at_the_first_accepted_connection(self) -> None:
        refused = ConnectionRefusedError(61, "Connection refused")
        record, calls, fake, stderr = self.wait(60, [refused, refused, "ok"])
        self.assertEqual([c[2] - 100.0 for c in calls], [0.0, 1.0, 2.0], "one attempt a second")
        self.assertEqual(calls[0][0], ("svc.example", 8080))
        self.assertEqual(record, {"requested_seconds": 60, "address": "svc.example:8080",
                                  "accepted": True, "elapsed_seconds": 2.0, "attempts": 3})
        self.assertEqual(stderr.count("\n"), 1)
        self.assertIn("target svc.example:8080 accepted a connection after 2s", stderr)

    def test_it_gives_up_at_the_deadline_and_says_the_run_goes_ahead(self) -> None:
        record, calls, fake, stderr = self.wait(2, [])
        self.assertEqual([c[2] - 100.0 for c in calls], [0.0, 1.0, 2.0])
        self.assertEqual(fake.now, 102.0)
        self.assertFalse(record["accepted"])
        self.assertEqual(record["attempts"], 3)
        self.assertEqual(record["last_error"], "[Errno 61] Connection refused")
        self.assertEqual(stderr.count("\n"), 1)
        self.assertIn("did not accept a connection within 2s", stderr)
        self.assertIn("running anyway, probes will record their own transport errors", stderr)

    def test_behind_a_proxy_the_line_says_the_check_is_direct(self) -> None:
        """The TCP check goes straight to the target while the requests go
        through the proxy; a name only the proxy resolves waited the full
        SECONDS and reported "nodename nor servname", and the run then
        succeeded through the proxy (measured). Now the line says which path
        each takes."""
        proxied = {"HTTP_PROXY": "http://proxy.corp.example:3128"}
        with mock.patch.dict("os.environ", proxied):
            _, _, _, accepted = self.wait(60, ["ok"])
            _, _, _, refused = self.wait(1, [])
        for stderr in (accepted, refused):
            self.assertEqual(stderr.count("\n"), 1, stderr)
            self.assertIn("directly", stderr)
            self.assertIn("proxy.corp.example:3128", stderr)
            self.assertIn("HTTP_PROXY", stderr)

    def test_control_without_a_proxy_the_line_names_none(self) -> None:
        clean = {k: v for k, v in __import__("os").environ.items()
                 if not k.lower().endswith("_proxy")}
        with mock.patch.dict("os.environ", clean, clear=True):
            _, _, _, stderr = self.wait(60, ["ok"])
        self.assertNotIn("proxy", stderr)

    def test_a_slow_connect_does_not_stretch_the_deadline(self) -> None:
        """A connect that times out costs its own second; the loop does not add
        another second of sleep on top, and never runs past the deadline."""
        record, calls, fake, _ = self.wait(3, [], connect_cost=1.0)
        self.assertEqual(fake.now, 103.0)
        self.assertEqual([c[2] - 100.0 for c in calls], [0.0, 1.0, 2.0])
        self.assertTrue(all(timeout <= 1.0 for _, timeout, _ in calls))
        self.assertEqual(fake.sleeps, [0.0, 0.0])
        self.assertEqual((record["accepted"], record["attempts"]), (False, 3))

    def test_zero_seconds_is_one_attempt(self) -> None:
        record, calls, _, _ = self.wait(0, [])
        self.assertEqual(len(calls), 1)
        self.assertFalse(record["accepted"])

    def test_the_port_comes_from_the_scheme(self) -> None:
        for url, address in (("https://api.example", ("api.example", 443)),
                             ("http://api.example", ("api.example", 80)),
                             ("http://[::1]:8443/base", ("::1", 8443))):
            with self.subTest(url=url):
                _, calls, _, _ = self.wait(0, ["ok"], base_url=url)
                self.assertEqual(calls[0][0], address)

    def test_the_engine_looks_up_connect_at_call_time(self) -> None:
        """So the fast tier's network guard sees a wait that forgot to inject
        its connect -- the control that this whole class is not touching the
        network by accident."""
        with mock.patch.object(core.socket, "create_connection",
                               side_effect=ConnectionRefusedError(61, "patched")) as patched:
            with contextlib.redirect_stderr(io.StringIO()):
                record = core.wait_for_target("http://x.example:1", 0, sleep=lambda s: None)
        patched.assert_called_once()
        self.assertEqual(record["last_error"], "[Errno 61] patched")


class NeverAVerdictTest(unittest.TestCase):
    def test_the_gate_ignores_the_record(self) -> None:
        from test_gate import scenarios  # noqa: PLC0415

        waited = {"requested_seconds": 60, "address": "a:1", "accepted": False,
                  "elapsed_seconds": 60.0, "attempts": 60, "last_error": "refused"}
        for name, document in scenarios().items():
            with self.subTest(scenario=name):
                with_wait = dict(copy.deepcopy(document), target_wait=waited)
                for flags in ({}, {"require_complete": True}):
                    self.assertEqual(
                        gate.evaluate(with_wait, **flags).to_document(),
                        gate.evaluate(document, **flags).to_document(),
                    )

    def test_validate_run_accepts_the_record_and_refuses_a_wrong_shape(self) -> None:
        from test_gate import scenarios  # noqa: PLC0415

        document = scenarios()["clean"]
        core.validate_run(dict(document, target_wait={"accepted": True}))
        with self.assertRaises(ConfigError):
            core.validate_run(dict(document, target_wait="60"))


class _Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    seen: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        type(self).seen.append(self.path)
        body = b"{}"
        self.send_response(200 if self.headers.get("Authorization") == "Bearer owner" else 403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextlib.contextmanager
def _late_listener(delay: float):
    """A target on a fixed port that starts accepting ``delay`` seconds from now.

    The port is free and refused until then. It comes from outside the
    ephemeral range (loopback.unallocated_port) because it sits closed for
    ``delay`` seconds: a port from bind(0) could be handed to another process
    -- a parallel slow-tier shard -- in that gap, and this bind would fail or
    the probes would reach that process instead.
    """
    port = loopback.unallocated_port()
    servers: list[ThreadingHTTPServer] = []

    def start() -> None:
        time.sleep(delay)
        server = ThreadingHTTPServer(("127.0.0.1", port), _Target)
        servers.append(server)
        loopback.serve(server)

    thread = threading.Thread(target=start, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        deadline = time.monotonic() + delay + 5
        while not servers and time.monotonic() < deadline:
            time.sleep(0.05)
        for server in servers:
            server.shutdown()
            server.server_close()


@slow("spawns veridor against loopback listeners and signals it")
class WaitOnTheWireTest(unittest.TestCase):
    def run_veridor(self, base_url: str, *extra: str, verb: str = "run") -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "c.json"
            config.write_text(json.dumps(_config(base_url)), encoding="utf-8")
            started = time.monotonic()
            result = subprocess.run(
                [sys.executable, "-m", "veridor", "run", "--config", str(config),
                 "--output-dir", str(root / "o"), "--json", str(root / "run.json"),
                 "--no-prove-liveness", *extra],
                capture_output=True, text=True, env=source_path.child_env(), cwd=tmp, timeout=120)
            document = (json.loads((root / "run.json").read_text(encoding="utf-8"))
                        if (root / "run.json").exists() else {})
        return {"code": result.returncode, "stderr": result.stderr, "document": document,
                "seconds": time.monotonic() - started}

    def test_a_late_target_is_measured_with_the_wait(self) -> None:
        with _late_listener(2.0) as url:
            waited = self.run_veridor(url, "--wait-for-target", "10")
        self.assertEqual(waited["code"], 0, waited["stderr"])
        probes = waited["document"]["probes"]
        self.assertEqual(len(probes), 2)
        self.assertEqual([p["error"] for p in probes], [None, None])
        record = waited["document"]["target_wait"]
        self.assertTrue(record["accepted"])
        self.assertGreaterEqual(record["attempts"], 2)
        self.assertGreaterEqual(record["elapsed_seconds"], 1.0)
        self.assertIn("accepted a connection after", waited["stderr"])

    def test_the_control_without_the_wait_the_early_probes_fail(self) -> None:
        with _late_listener(2.0) as url:
            hurried = self.run_veridor(url)
        self.assertEqual(hurried["code"], 3, hurried["stderr"])
        self.assertTrue(all(p["error"] for p in hurried["document"]["probes"]))
        self.assertNotIn("target_wait", hurried["document"])
        self.assertNotIn("accept a connection", hurried["stderr"])

    def test_a_target_that_never_accepts_waits_then_runs_and_exits_3(self) -> None:
        url = f"http://127.0.0.1:{loopback.unallocated_port()}"
        result = self.run_veridor(url, "--wait-for-target", "2")
        self.assertEqual(result["code"], 3, result["stderr"])
        record = result["document"]["target_wait"]
        self.assertFalse(record["accepted"])
        self.assertGreaterEqual(record["elapsed_seconds"], 1.9)
        self.assertLess(record["elapsed_seconds"], 3.5)
        self.assertGreaterEqual(result["seconds"], 1.9)
        self.assertIn("did not accept a connection within 2s", result["stderr"])
        self.assertTrue(all(p["error"] for p in result["document"]["probes"]))

    def test_sigterm_during_the_wait_exits_143(self) -> None:
        url = f"http://127.0.0.1:{loopback.unallocated_port()}"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "c.json"
            config.write_text(json.dumps(_config(url)), encoding="utf-8")
            process = subprocess.Popen(
                [sys.executable, "-m", "veridor", "run", "--config", str(config),
                 "--output-dir", str(root / "o"), "--wait-for-target", "60"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=source_path.child_env(), cwd=tmp)
            try:
                # The liveness disclosure is printed just before the wait, so
                # once it is on stderr the SIGTERM handler is installed and the
                # process is waiting.
                banner = process.stderr.readline()
                self.assertIn("liveness controls", banner)
                time.sleep(0.5)
                sent = time.monotonic()
                process.send_signal(signal.SIGTERM)
                _, stderr = process.communicate(timeout=30)
                took = time.monotonic() - sent
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            self.assertEqual(process.returncode, 143, stderr)
            self.assertIn("stopped by SIGTERM", stderr)
            self.assertLess(took, 5.0)
            self.assertFalse((root / "o" / "latest.json").exists())

    def test_map_waits_too(self) -> None:
        with _late_listener(2.0) as url, tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = json.loads((FIXTURES / "veridor.map-demo.json").read_text(encoding="utf-8"))
            config["target"]["base_url"] = url
            (root / "m.json").write_text(json.dumps(config), encoding="utf-8")
            _Target.seen = []
            result = subprocess.run(
                [sys.executable, "-m", "veridor", "map", "--config", str(root / "m.json"),
                 "--openapi", str(FIXTURES / "openapi.demo.json"), "--rate", "10",
                 "--output-dir", str(root / "o"), "--wait-for-target", "10"],
                capture_output=True, text=True, env=source_path.child_env(), cwd=tmp, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("accepted a connection after", result.stderr)
        self.assertNotIn("not one of", result.stderr)
        self.assertGreater(len(_Target.seen), 0)


if __name__ == "__main__":
    unittest.main()
