"""Every loopback test server starts through tests/loopback.py, and a port
used after it was released comes from outside the ephemeral range.

REGRESSION, in cost rather than correctness. 34 call sites in 19 test modules
ran ``threading.Thread(target=server.serve_forever)``, so every
``server.shutdown()`` waited for the stdlib's 0.5 s poll, about 486 ms after a
request. Nothing failed, so nothing said so. The guard below
refuses a ``serve_forever`` anywhere under tests/ except the helper, and the
slow test measures that the helper's servers really do stop quickly.

The scan reads source, so it cannot see a server reached indirectly:
``operator.methodcaller("serve_forever")``, ``getattr`` with a name built at
run time, ``vars(BaseServer)[...]``, or a stdlib helper such as
``http.server.test`` that calls ``serve_forever()`` itself. A planted slow
test starting its server with ``methodcaller`` left this module green
(measured). ``ServerGuardTest`` holds the runtime half: in a test process
every one of those routes is refused before it serves.
"""

from __future__ import annotations

import ast
import contextlib
import http.server
import io
import json
import operator
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))

import loopback  # noqa: E402
from scripts import run_tests  # noqa: E402
from tiers import slow  # noqa: E402

TESTS = ROOT / "tests"
HELPER = TESTS / "loopback.py"
NAME = "serve_forever"


def references(source: str, name: str) -> list[str]:
    """Each place ``source`` reaches ``serve_forever``: an attribute -- called,
    or handed to a thread as its target -- or a ``getattr`` by that name."""
    found = []
    for node in ast.walk(ast.parse(source, filename=name)):
        if isinstance(node, ast.Attribute) and node.attr == NAME:
            found.append(f"{name}:{node.lineno}")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "getattr" and len(node.args) >= 2
              and isinstance(node.args[1], ast.Constant) and node.args[1].value == NAME):
            found.append(f"{name}:{node.lineno}")
    return found


def scan(exempt: tuple[Path, ...] = (HELPER,)) -> tuple[list[str], int]:
    """Every reference under tests/ outside ``exempt``, and how many files were read.

    A file whose text does not contain the name is not parsed: it cannot reach
    the attribute, and parsing all of tests/ costs about 0.3 s, which is more
    than any test left in this tier spends."""
    found: list[str] = []
    files = sorted(TESTS.rglob("*.py"))
    for path in files:
        text = path.read_text(encoding="utf-8")
        if path not in exempt and NAME in text:
            found += references(text, path.relative_to(ROOT).as_posix())
    return found, len(files)


class OneWayToStartAServerTest(unittest.TestCase):
    def test_no_test_calls_serve_forever_except_through_the_helper(self) -> None:
        found, _ = scan()
        self.assertEqual(found, [], "start test servers with loopback.start(server) "
                                    "or loopback.serve(server); see tests/loopback.py")

    def test_control_every_form_the_suite_used_is_named(self) -> None:
        """The 34 call sites were of the first three forms; the rest are the
        other ways to write the same thing."""
        forms = {
            "inline thread": "threading.Thread(target=server.serve_forever, daemon=True).start()\n",
            "thread then start": "t = threading.Thread(target=cls.server.serve_forever, daemon=True)\nt.start()\n",
            "called directly": "server.serve_forever()\n",
            "with a poll interval": "server.serve_forever(poll_interval=0.05)\n",
            "unbound": "socketserver.BaseServer.serve_forever(server)\n",
            "getattr": 'getattr(server, "serve_forever")()\n',
        }
        for form, source in forms.items():
            with self.subTest(form=form):
                self.assertEqual(len(references(source, "x.py")), 1, source)
        self.assertEqual(references("loopback.start(server)\nloopback.serve(server)\n", "x.py"), [])
        # A mention in prose or in a string is not a server.
        self.assertEqual(references('"""serve_forever"""\nx = "serve_forever"\n', "x.py"), [])

    def test_control_the_scan_reads_the_real_tree(self) -> None:
        """With nothing exempt it finds the helper's own call (and its guard's
        references to BaseServer.serve_forever), so the walk reaches real
        files and the match fires on real code -- in that file only."""
        found, files = scan(exempt=())
        self.assertGreater(files, 50)
        self.assertEqual({hit.split(":")[0] for hit in found}, {"tests/loopback.py"})
        self.assertGreaterEqual(len(found), 1)

    def test_the_helper_polls_often_and_passes_its_interval(self) -> None:
        self.assertGreater(loopback.POLL_INTERVAL, 0)  # 0 would spin a core per server
        self.assertLessEqual(loopback.POLL_INTERVAL, 0.05)
        tree = ast.parse(HELPER.read_text(encoding="utf-8"))
        (call,) = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute) and node.func.attr == NAME]
        self.assertEqual([(k.arg, getattr(k.value, "id", None)) for k in call.keywords],
                         [("poll_interval", "POLL_INTERVAL")])


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


@slow("stands up loopback servers and times their shutdown")
class ShutdownLatencyTest(unittest.TestCase):
    """What the guard is for, measured: one request, then shutdown()."""

    def shutdown_after_one_request(self) -> float:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
        thread = loopback.start(server)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as reply:
                reply.read()
            began = time.perf_counter()
            server.shutdown()
            return time.perf_counter() - began
        finally:
            server.server_close()
            thread.join(timeout=5)

    def test_a_helper_server_stops_without_waiting_out_the_default_poll(self) -> None:
        # About 35 ms measured; the stdlib default costs about 486 ms.
        self.assertLess(self.shutdown_after_one_request(), 0.25)

    def test_control_at_the_stdlib_default_the_same_measurement_fails(self) -> None:
        # The slowest of three: any connection that reaches the server while
        # shutdown() waits wakes its select early, so one measurement can come
        # back fast for a reason that has nothing to do with the interval. It
        # did once (31 us), in a worker, while two other slow tiers ran on the
        # machine; eleven runs alone did not repeat it.
        with mock.patch.object(loopback, "POLL_INTERVAL", 0.5):
            slowest = max(self.shutdown_after_one_request() for _ in range(3))
        self.assertGreaterEqual(slowest, 0.25)


class _Server(ThreadingHTTPServer):
    """A subclass, so http.server.test's class-level address_family write
    lands here, and so a server it makes can be found and stopped."""

    made: list[ThreadingHTTPServer] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.made.append(self)


def _answers(server: ThreadingHTTPServer) -> int:
    with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as reply:
        return reply.status


def _refusal(start, *args: object) -> BaseException | None:
    """What ``start(*args)`` raised within two seconds, or None if it was still
    serving then -- in which case every server it made is stopped, so a guard
    that refuses nothing fails this test instead of hanging it."""
    raised: list[BaseException] = []
    _Server.made.clear()

    def run() -> None:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                start(*args)
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            raised.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=2)
    if thread.is_alive():
        for server in _Server.made:
            server.shutdown()
        thread.join(timeout=5)
        return None
    return raised[0] if raised else None


@slow("stands up loopback servers")
class ServerGuardTest(unittest.TestCase):
    """At run time, every route to serve_forever that the scan cannot read is
    refused in a test process, and the helper's is not."""

    def test_importing_tiers_alone_installs_the_guard(self) -> None:
        """Asked of a fresh interpreter that imports tiers and nothing else.

        This used to be asked in-process, where it could not fail: this module
        imports loopback itself, and run_tests.py imports it too, so the guard
        was installed whether or not tiers.py did it. Measured: with
        `import loopback` deleted from tiers.py the in-process test still
        passed, while a fresh `import tiers` left the stdlib's serve_forever in
        place. A direct `python -m unittest test_x` of a module that does not
        import loopback gets the guard only through tiers."""
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); import socketserver, tiers; "
                 "print(bool(getattr(socketserver.BaseServer.serve_forever, '_loopback_guard', False)))")
        done = subprocess.run([sys.executable, "-c", probe, str(TESTS)], capture_output=True, text=True,
                              timeout=60, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "True",
                         "a fresh `import tiers` leaves BaseServer.serve_forever the stdlib's")

    def test_a_refused_server_can_still_be_shut_down(self) -> None:
        """The guard's refusal marks the server shut down as well as closing it.

        BaseServer creates its shut-down Event unset and only the stdlib's
        serve_forever sets it, in a `finally`. The guard raises before that
        runs, so an owner's shutdown() -- a cleanup, typically -- waited on it
        for ever: a refused server with addCleanup(server.shutdown) hung the
        serial slow tier (measured, killed at 45 s), and under --jobs failed
        only when the shard timeout fired. Run in a thread and joined with a
        bound, so a regression fails here instead of hanging the suite."""
        server = self.server()
        refused = _refusal(operator.methodcaller("serve_" + "forever"), server)
        self.assertIsInstance(refused, RuntimeError)
        stopper = threading.Thread(target=server.shutdown, daemon=True)
        stopper.start()
        stopper.join(timeout=5)
        self.assertFalse(stopper.is_alive(), "shutdown() of a refused server is still waiting after 5 s")

    def server(self) -> ThreadingHTTPServer:
        server = _Server(("127.0.0.1", 0), _Ok)
        self.addCleanup(server.server_close)
        return server

    def test_every_route_the_scan_cannot_read_is_refused(self) -> None:
        name = "serve_" + "forever"
        routes = {
            "methodcaller": lambda server: operator.methodcaller(name)(server),
            "getattr by a name": lambda server: getattr(server, name)(),
            "vars()": lambda server: vars(socketserver.BaseServer)[name](server),
            "the class __dict__": lambda server: socketserver.BaseServer.__dict__[name](server),
            "unbound": lambda server: getattr(socketserver.BaseServer, NAME)(server),
        }
        for route, start in routes.items():
            with self.subTest(route=route):
                server = self.server()
                refused = _refusal(start, server)
                self.assertIsInstance(refused, RuntimeError, f"{route}: served instead of being refused")
                self.assertIn("loopback.start(server)", str(refused))
                # Refused, not left listening: a client fails at once instead
                # of waiting for its own timeout, or forever without one.
                with self.assertRaises(ConnectionRefusedError):
                    socket.create_connection(server.server_address, timeout=5).close()
        refused = _refusal(lambda: http.server.test(HandlerClass=_Ok, ServerClass=_Server, port=0,
                                                    bind="127.0.0.1"))
        self.assertIsInstance(refused, RuntimeError, "http.server.test served instead of being refused")
        self.assertIn("poll_interval=0.5", str(refused))
        for server in _Server.made:
            server.server_close()

    def test_control_the_helper_and_a_fast_poll_are_served(self) -> None:
        server = self.server()
        thread = loopback.start(server)
        self.assertEqual(_answers(server), 200)
        server.shutdown()
        thread.join(timeout=5)
        # A script's own server at the helper's interval is not a cost.
        server = self.server()
        thread = threading.Thread(target=operator.methodcaller(NAME, poll_interval=loopback.POLL_INTERVAL),
                                  args=(server,), daemon=True)
        thread.start()
        self.assertEqual(_answers(server), 200)
        server.shutdown()
        thread.join(timeout=5)

    def test_control_without_the_guard_the_same_route_reaches_the_stdlib(self) -> None:
        stdlib = getattr(socketserver.BaseServer, NAME).__wrapped__
        with mock.patch.object(socketserver.BaseServer, NAME, stdlib):
            server = self.server()
            thread = threading.Thread(target=operator.methodcaller(NAME), args=(server,), daemon=True)
            thread.start()
            self.assertEqual(_answers(server), 200, "the methodcaller route serves once nothing refuses it")
            server.shutdown()
            thread.join(timeout=5)
            # Installing the guard over the stdlib's wraps it once, and its
            # restore puts the stdlib's back.
            restore = loopback.install_server_guard()
            self.assertIs(getattr(socketserver.BaseServer, NAME).__wrapped__, stdlib)
            self.assertIsNotNone(loopback.install_server_guard(), "a second install must not wrap the first")
            self.assertIs(getattr(socketserver.BaseServer, NAME).__wrapped__, stdlib)
            restore()
            self.assertIs(getattr(socketserver.BaseServer, NAME), stdlib)


class PortShareTest(unittest.TestCase):
    """Under --jobs, two workers' unallocated_port() picks can never meet."""

    def test_the_shares_are_disjoint_and_cover_every_candidate(self) -> None:
        low, high = 49152, 65535
        every = loopback.candidate_ports(low, high)
        for count in (1, 2, 4, 7):
            with self.subTest(count=count):
                shares = [set(loopback.candidate_ports(low, high, (index, count))) for index in range(count)]
                self.assertEqual(sum(len(share) for share in shares), len(every))
                self.assertEqual(set().union(*shares), set(every))

    def test_control_without_shares_two_pickers_draw_from_the_same_ports(self) -> None:
        """What made the collision possible: every process drew from one list."""
        low, high = 49152, 65535
        self.assertEqual(loopback.candidate_ports(low, high), loopback.candidate_ports(low, high, (0, 1)))

    def test_the_share_is_read_from_the_runner_variable_and_nonsense_is_refused(self) -> None:
        """A path of INDEX/COUNT levels, one per --jobs run it is nested in."""
        for value, share in (("", ((0, 1),)), ("0/1", ((0, 1),)), ("3/4", ((3, 4),)),
                             ("1/4,0/2", ((1, 4), (0, 2)))):
            with self.subTest(value=value), mock.patch.dict(os.environ, {loopback.WORKER_ENV: value}):
                self.assertEqual(loopback.worker_share(), share)
        for value in ("4/4", "1", "a/b", "-1/2", "1/0", "1/4,2/2", "1/4,", ",1/4"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {loopback.WORKER_ENV: value}):
                with self.assertRaises(RuntimeError):
                    loopback.worker_share()

    def test_a_nested_run_splits_only_its_parents_share(self) -> None:
        """The suite runs --jobs inside --jobs. The runner used to overwrite the
        share, so a nested worker's `1/2` split every port again and overlapped
        the outer workers' shares: seed 7 picked port 25305 under both `1/4` and
        `1/2` (measured 2026-09-27). Now it appends a level, and a nested worker
        picks only inside the worker that started it."""
        low, high = 49152, 65535
        outer = {i: set(loopback.candidate_ports(low, high, ((i, 4),))) for i in range(4)}
        for parent in range(4):
            nested = [set(loopback.candidate_ports(low, high, ((parent, 4), (j, 2)))) for j in range(2)]
            with self.subTest(parent=parent):
                self.assertEqual(nested[0] | nested[1], outer[parent], "the nested shares cover the parent's")
                self.assertFalse(nested[0] & nested[1], "nested siblings are disjoint")
                for other in set(outer) - {parent}:
                    self.assertFalse((nested[0] | nested[1]) & outer[other],
                                     f"a worker nested under {parent} can pick worker {other}'s port")
        # The runner builds the nested value by appending, never by replacing.
        self.assertEqual(run_tests.nested_share("", 1, 4), "1/4")
        self.assertEqual(run_tests.nested_share("1/4", 0, 2), "1/4,0/2")
        self.assertEqual(run_tests.nested_share("1/4,0/2", 1, 3), "1/4,0/2,1/3")

    def test_control_a_replaced_share_overlaps_the_other_outer_workers(self) -> None:
        """What the overwrite did: a flat `1/2` inside worker `1/4` reaches
        ports every other outer worker owns."""
        low, high = 49152, 65535
        flat = set(loopback.candidate_ports(low, high, ((1, 2),)))
        others = set().union(*(loopback.candidate_ports(low, high, ((i, 4),)) for i in (0, 2, 3)))
        self.assertTrue(flat & others)


#: Two processes pick a port with the same seed; the second listens on its
#: pick; the first connects to its own. argv: seed. Prints the pick.
_PICK = """
import random, sys
sys.path.insert(0, sys.argv[2])
import loopback
random.seed(int(sys.argv[1]))
print(loopback.unallocated_port())
"""


@slow("starts processes that bind loopback ports")
class PortShareProcessTest(unittest.TestCase):
    def pick(self, seed: int, share: str | None) -> int:
        env = {key: value for key, value in os.environ.items() if key != loopback.WORKER_ENV}
        if share is not None:
            env[loopback.WORKER_ENV] = share
        done = subprocess.run([sys.executable, "-c", _PICK, str(seed), str(TESTS)], env=env,
                              capture_output=True, text=True, timeout=60, check=True)
        return int(done.stdout)

    def test_two_workers_seeded_alike_pick_different_ports(self) -> None:
        self.assertNotEqual(self.pick(7, "0/2"), self.pick(7, "1/2"))

    def test_control_two_processes_seeded_alike_outside_workers_pick_the_same_port(self) -> None:
        self.assertEqual(self.pick(7, None), self.pick(7, None))


@slow("binds loopback ports")
class UnallocatedPortTest(unittest.TestCase):
    """A port released and used later must be one the kernel gives nobody else.

    REGRESSION risk rather than an observed failure: _free_port in
    test_wait_for_target, _closed_port in test_action and the serve probe in
    test_packaging each bound port 0, closed it, and used the number later --
    up to two seconds later -- while any other process, a parallel shard
    included, could be handed it by its own bind(0) or connect()."""

    def test_the_port_is_free_refused_and_outside_the_ephemeral_range(self) -> None:
        low, high = loopback.ephemeral_range()
        for _ in range(5):
            port = loopback.unallocated_port()
            self.assertFalse(low <= port <= high, (port, low, high))
            with socket.socket() as client:
                client.settimeout(5)
                self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)

    def test_control_the_kernel_hands_out_ports_only_inside_that_range(self) -> None:
        """If ephemeral_range() misread this kernel, "outside it" would mean
        nothing; bind(0) shows where the kernel really draws from."""
        low, high = loopback.ephemeral_range()
        drawn = []
        for _ in range(20):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                drawn.append(probe.getsockname()[1])
        self.assertEqual([port for port in drawn if not low <= port <= high], [], (low, high))


if __name__ == "__main__":
    unittest.main()
