"""The tier split is a product feature, so it is held to a contract.

Veridor is meant to run on every commit. A suite that takes two and
a half minutes does not get run on every commit, and during this product's
construction it stopped being run reliably for exactly that reason. Splitting
it is therefore not housekeeping; it is the same claim discipline applied to
the tool's own build.

Two properties matter and both are asserted here:

* the two tiers are a partition -- every test is in exactly one, and no test
  can be lost by being in neither;
* the fast tier cannot silently acquire a socket, because the guard that makes
  that impossible is itself tested.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import io
import os
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import tiers  # noqa: E402
from scripts import run_tests  # noqa: E402
from tiers import (  # noqa: E402
    ALL,
    ATTRIBUTE,
    FAST,
    SLOW,
    TierViolation,
    fast,
    filter_suite,
    iter_tests,
    slow,
    tier_of,
)


def _whole_suite() -> unittest.TestSuite:
    loader = unittest.TestLoader()
    return loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))


class PartitionTest(unittest.TestCase):
    """A test in neither tier runs in no CI job at all. That must be unbuildable."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = _whole_suite()
        cls.everything = [test.id() for test in iter_tests(cls.suite)]

    def test_the_two_tiers_together_are_the_whole_suite(self) -> None:
        fast_ids = [test.id() for test in iter_tests(filter_suite(self.suite, FAST))]
        slow_ids = [test.id() for test in iter_tests(filter_suite(self.suite, SLOW))]
        self.assertEqual(sorted(fast_ids + slow_ids), sorted(self.everything))

    def test_no_test_is_in_both_tiers(self) -> None:
        fast_ids = {test.id() for test in iter_tests(filter_suite(self.suite, FAST))}
        slow_ids = {test.id() for test in iter_tests(filter_suite(self.suite, SLOW))}
        self.assertEqual(fast_ids & slow_ids, set())

    def test_all_selects_everything(self) -> None:
        selected = [test.id() for test in iter_tests(filter_suite(self.suite, ALL))]
        self.assertEqual(sorted(selected), sorted(self.everything))

    def test_both_tiers_are_non_empty(self) -> None:
        """A collapsed tier would pass every other assertion here."""
        self.assertGreater(filter_suite(self.suite, FAST).countTestCases(), 100)
        self.assertGreater(filter_suite(self.suite, SLOW).countTestCases(), 100)

    def test_an_unknown_tier_is_refused_rather_than_silently_empty(self) -> None:
        with self.assertRaises(ValueError) as caught:
            filter_suite(self.suite, "quick")
        self.assertIn("quick", str(caught.exception))


class MarkerTest(unittest.TestCase):
    def test_a_class_marker_covers_its_methods(self) -> None:
        @slow("example")
        class Example(unittest.TestCase):
            def test_x(self) -> None:  # pragma: no cover - never run
                pass

        self.assertEqual(tier_of(Example("test_x")), SLOW)

    def test_a_method_marker_beats_its_class_marker_both_ways(self) -> None:
        @slow("example")
        class Example(unittest.TestCase):
            @fast("pure")
            def test_pure(self) -> None:  # pragma: no cover - never run
                pass

            def test_live(self) -> None:  # pragma: no cover - never run
                pass

        self.assertEqual(tier_of(Example("test_pure")), FAST)
        self.assertEqual(tier_of(Example("test_live")), SLOW)

    def test_an_unmarked_test_is_fast(self) -> None:
        class Example(unittest.TestCase):
            def test_x(self) -> None:  # pragma: no cover - never run
                pass

        self.assertEqual(tier_of(Example("test_x")), FAST)

    def test_a_marker_without_a_reason_is_refused(self) -> None:
        """The reason is how a reader learns the cost without running it."""
        for decorator in (slow, fast):
            with self.subTest(decorator=decorator.__name__):
                with self.assertRaises(ValueError):
                    decorator("")
                with self.assertRaises(ValueError):
                    decorator("   ")

    def test_every_marker_in_the_suite_carries_a_reason(self) -> None:
        suite = _whole_suite()
        for test in iter_tests(suite):
            holder = getattr(test, test._testMethodName, None)
            for obj in (holder, type(test)):
                if getattr(obj, ATTRIBUTE, None) is not None:
                    reason = getattr(obj, ATTRIBUTE + "_reason", "")
                    self.assertTrue(reason.strip(), f"{test.id()} has a bare marker")


class GuardTest(unittest.TestCase):
    """The guard is what makes 'unmarked means fast' safe rather than hopeful."""

    def setUp(self) -> None:
        self.addCleanup(tiers.install_fast_tier_guard())

    def test_a_listening_socket_is_refused(self) -> None:
        with self.assertRaises(TierViolation) as caught:
            socket.socket().bind(("127.0.0.1", 0))
        self.assertIn("@slow", str(caught.exception))

    def test_an_outbound_connection_is_refused(self) -> None:
        with self.assertRaises(TierViolation):
            socket.socket().connect(("127.0.0.1", 9))

    def test_a_subprocess_is_refused(self) -> None:
        with self.assertRaises(TierViolation):
            subprocess.run([sys.executable, "-c", "pass"], check=False)

    def test_the_message_names_the_marker_a_reader_needs(self) -> None:
        with self.assertRaises(TierViolation) as caught:
            socket.socket().bind(("127.0.0.1", 0))
        self.assertIn("tests/tiers.py", str(caught.exception))


# ---------------------------------------------------------------------------
# Every route to the network or to a new process, not only the three the guard
# first knew. REGRESSION: with the guard installed, connect_ex reached the
# kernel (errno 61), a UDP sendto and sendmsg went out, getaddrinfo and
# gethostbyname resolved, listen() on an unbound socket bound it to 0.0.0.0,
# _socket.socket().connect bypassed the patched Python class, and os.system,
# os.posix_spawn(p), os.spawnv, os.fork, os.forkpty, os.exec* and
# multiprocessing (fork and spawn) all started processes (measured, python3.12,
# macOS). Each probe below is harmless if it escapes: exec targets a path that
# does not exist, forked children exit at once, datagrams go to loopback:9.
# ---------------------------------------------------------------------------

_NO_SUCH_PROGRAM = "/nonexistent/veridor-tier-guard-probe"


def _on_socket(action, kind: int = socket.SOCK_STREAM):
    """Run ``action`` on a fresh socket that is closed whatever happens."""
    def call() -> object:
        with socket.socket(socket.AF_INET, kind) as sock:
            return action(sock)

    return call


def _fork_and_reap(fork) -> object:
    result = fork()
    pid = result[0] if isinstance(result, tuple) else result
    if pid == 0:
        os._exit(0)
    if isinstance(result, tuple):
        os.close(result[1])
    return os.waitpid(pid, 0)


def _start_process() -> object:
    import multiprocessing  # noqa: PLC0415

    process = multiprocessing.get_context("fork").Process(target=os.getpid)
    process.start()
    process.join(10)
    return process.exitcode


def _spawn(function) -> object:
    pid = function(sys.executable, [sys.executable, "-c", "pass"], dict(os.environ))
    return os.waitpid(pid, 0)


def _fork_exec() -> object:
    import _posixsubprocess  # noqa: PLC0415

    # Unguarded, this raises TypeError (wrong arguments) and starts nothing;
    # guarded, the guard answers before the arguments are looked at.
    return _posixsubprocess.fork_exec()


def _c_socket_connect() -> object:
    import _socket  # noqa: PLC0415

    sock = _socket.socket()
    try:
        return sock.connect(("127.0.0.1", 9))
    finally:
        sock.close()


def _create_connection() -> object:
    with socket.create_connection(("127.0.0.1", 9), timeout=1):
        return None


def _create_server() -> object:
    with socket.create_server(("127.0.0.1", 0)):
        return None


#: name -> a call that reaches the network or starts a process when unguarded.
ESCAPE_ROUTES: dict[str, object] = {
    "socket.connect_ex": _on_socket(lambda s: s.connect_ex(("127.0.0.1", 9))),
    "socket.sendto": _on_socket(lambda s: s.sendto(b"x", ("127.0.0.1", 9)), socket.SOCK_DGRAM),
    "socket.sendmsg": _on_socket(
        lambda s: s.sendmsg([b"x"], [], 0, ("127.0.0.1", 9)), socket.SOCK_DGRAM
    ),
    "socket.listen on an unbound socket": _on_socket(lambda s: s.listen(1)),
    "socket.getaddrinfo": lambda: socket.getaddrinfo("localhost", 80),
    "socket.gethostbyname": lambda: socket.gethostbyname("localhost"),
    "socket.gethostbyname_ex": lambda: socket.gethostbyname_ex("localhost"),
    "socket.gethostbyaddr": lambda: socket.gethostbyaddr("127.0.0.1"),
    "socket.getnameinfo": lambda: socket.getnameinfo(("127.0.0.1", 80), 0),
    "socket.getfqdn": lambda: socket.getfqdn("127.0.0.1"),
    "socket.create_connection": _create_connection,
    "socket.create_server": _create_server,
    "_socket.socket.connect (the C class)": _c_socket_connect,
    "os.system": lambda: os.system("true"),
    "os.popen": lambda: os.popen("true").read(),
    "os.posix_spawn": lambda: _spawn(os.posix_spawn),
    "os.posix_spawnp": lambda: _spawn(os.posix_spawnp),
    "os.spawnv": lambda: os.spawnv(os.P_WAIT, sys.executable, [sys.executable, "-c", "pass"]),
    "os.fork": lambda: _fork_and_reap(os.fork),
    "os.forkpty": lambda: _fork_and_reap(os.forkpty),
    "os.execv": lambda: os.execv(_NO_SUCH_PROGRAM, ["x"]),
    "os.execve": lambda: os.execve(_NO_SUCH_PROGRAM, ["x"], {}),
    "os.execl": lambda: os.execl(_NO_SUCH_PROGRAM, "x"),
    "os.execle": lambda: os.execle(_NO_SUCH_PROGRAM, "x", {}),
    "os.execlp": lambda: os.execlp(_NO_SUCH_PROGRAM, "x"),
    "os.execlpe": lambda: os.execlpe(_NO_SUCH_PROGRAM, "x", {}),
    "os.execvp": lambda: os.execvp(_NO_SUCH_PROGRAM, ["x"]),
    "os.execvpe": lambda: os.execvpe(_NO_SUCH_PROGRAM, ["x"], {}),
    "multiprocessing Process.start": _start_process,
    "_posixsubprocess.fork_exec": _fork_exec,
}


class GuardEscapeRouteTest(unittest.TestCase):
    """Each route raises TierViolation under the guard, by name."""

    def setUp(self) -> None:
        self.addCleanup(tiers.install_fast_tier_guard())

    def test_every_escape_route_is_refused(self) -> None:
        for name, call in ESCAPE_ROUTES.items():
            with self.subTest(route=name):
                with self.assertRaises(TierViolation) as caught:
                    call()
                self.assertIn("@slow", str(caught.exception))


@slow("runs each escape route in a child python, which spawns a process and opens sockets")
class GuardEscapeRouteControlTest(unittest.TestCase):
    """The control: every route the guard refuses works without it.

    Without this, a route that is simply broken on this machine -- a missing
    /usr/bin/true, a sandbox without DNS -- would pass the refusal test for a
    reason that has nothing to do with the guard. Each route runs in a child
    python twice: guarded (must be refused), then after restore() (must reach
    the OS). The exec routes would replace the child, so for them "reached the
    OS" is the FileNotFoundError of a missing program; the real exec is its
    own test below.
    """

    SCRIPT = r'''
import os, socket, sys
sys.path.insert(0, sys.argv[1])
import tiers, test_tiers
call = test_tiers.ESCAPE_ROUTES[sys.argv[2]]
def attempt():
    try:
        call()
    except tiers.TierViolation:
        return "refused"
    except BaseException as error:  # the OS answered: refused connection, ENOENT, ...
        return "reached:" + type(error).__name__
    return "reached"
restore = tiers.install_fast_tier_guard()
guarded = attempt()
restore()
print(guarded, attempt(), flush=True)
'''

    def test_every_route_is_refused_only_under_the_guard(self) -> None:
        for name in ESCAPE_ROUTES:
            with self.subTest(route=name):
                completed = subprocess.run(
                    [sys.executable, "-c", self.SCRIPT, str(ROOT / "tests"), name],
                    capture_output=True, text=True, timeout=60, cwd=str(ROOT),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                guarded, restored = completed.stdout.split()
                self.assertEqual(guarded, "refused", completed.stderr)
                self.assertTrue(restored.startswith("reached"), restored)

    def test_multiprocessing_spawn_is_refused_only_under_the_guard(self) -> None:
        """The spawn start method (macOS's default) goes through
        _posixsubprocess.fork_exec, not os.fork; it is run for real here."""
        script = r'''
import multiprocessing, os, sys
sys.path.insert(0, sys.argv[1])
import tiers
def start():
    process = multiprocessing.get_context("spawn").Process(target=os.getpid)
    process.start()
    process.join(30)
    return process.exitcode
restore = tiers.install_fast_tier_guard()
try:
    start()
    guarded = "reached"
except tiers.TierViolation:
    guarded = "refused"
restore()
print(guarded, start(), flush=True)
'''
        completed = subprocess.run(
            [sys.executable, "-c", script, str(ROOT / "tests")],
            capture_output=True, text=True, timeout=120, cwd=str(ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.split(), ["refused", "0"], completed.stderr)

    def test_a_real_exec_happens_after_restore(self) -> None:
        """The exec routes' control above sees ENOENT; this one sees the
        process actually replaced."""
        script = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import tiers
restore = tiers.install_fast_tier_guard()
try:
    os.execv(sys.executable, [sys.executable, "-c", "print('exec-guarded')"])
except tiers.TierViolation:
    print("refused", flush=True)
restore()
os.execv(sys.executable, [sys.executable, "-c", "print('exec-ran')"])
'''
        completed = subprocess.run(
            [sys.executable, "-c", script, str(ROOT / "tests")],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT),
        )
        self.assertEqual(completed.stdout.split(), ["refused", "exec-ran"], completed.stderr)


class SleepClaimTest(unittest.TestCase):
    """tiers.py described the fast tier as having "no sleeping", which nothing
    enforced and run_tests.py contradicts (the rate-limiter tests sleep on a
    real clock). The docstring now says what is enforced and what is not."""

    def test_the_docstring_does_not_claim_an_unenforced_rule(self) -> None:
        doc = tiers.__doc__ or ""
        self.assertNotIn("no sleeping", doc.lower())
        self.assertIn("not blocked", doc)
        # What IS enforced is listed where it is enforced.
        for route in ("getaddrinfo", "connect_ex", "posix_spawn", "fork", "exec"):
            self.assertIn(route, doc)


class GuardRestorationTest(unittest.TestCase):
    def test_restore_puts_the_real_functions_back(self) -> None:
        """`--tier all` runs both tiers in one process; the guard must lift."""
        before = (socket.socket.bind, socket.socket.connect, subprocess.Popen.__init__)
        restore = tiers.install_fast_tier_guard()
        self.assertIsNot(socket.socket.bind, before[0])
        restore()
        self.assertEqual(
            (socket.socket.bind, socket.socket.connect, subprocess.Popen.__init__),
            before,
        )


class GuardNestingTest(unittest.TestCase):
    """The fast tier installs one guard for the whole process and GuardTest
    installs another per test; lifting the inner one must not lift the outer."""

    def test_restore_puts_every_route_back_exactly(self) -> None:
        before = [
            (owner, name, getattr(owner, name), name in vars(owner))
            for owner, name, _ in tiers._guarded()
        ]
        self.assertGreater(len(before), 25, "the route list collapsed")
        depth = tiers._ACTIVE_GUARDS
        restore = tiers.install_fast_tier_guard()
        self.assertEqual(tiers._ACTIVE_GUARDS, depth + 1)
        for owner, name, original, _ in before:
            self.assertIsNot(getattr(owner, name), original, name)
        restore()
        restore()  # a second call is a no-op, not a second lift
        self.assertEqual(tiers._ACTIVE_GUARDS, depth)
        for owner, name, original, own in before:
            with self.subTest(route=name):
                self.assertEqual(getattr(owner, name), original)
                # An inherited method is not left pinned on the subclass.
                self.assertEqual(name in vars(owner), own)

    def test_an_inner_restore_leaves_the_outer_guard_on(self) -> None:
        outer = tiers.install_fast_tier_guard()
        self.addCleanup(outer)
        inner = tiers.install_fast_tier_guard()
        inner()
        with self.assertRaises(TierViolation):
            socket.getaddrinfo("localhost", 80)
        with self.assertRaises(TierViolation):
            os.system("true")


class StdoutLeakTest(unittest.TestCase):
    """The fast tier's own output is an artifact, and it has to stay clean.

    REGRESSION. A test called the CLI's ``report`` verb without redirecting
    stdout, so ``Wrote SARIF report to /var/folders/.../report.sarif`` printed
    after unittest's ``OK`` in the output of the one command the README asks
    contributors to run on every commit. It read as though the test run had
    emitted an artifact into a temp directory.
    """

    def _run(self, case: type[unittest.TestCase]) -> run_tests._TimedResult:
        suite = unittest.TestLoader().loadTestsFromTestCase(case)
        runner = unittest.TextTestRunner(
            stream=io.StringIO(), resultclass=run_tests._TimedResult
        )
        return runner.run(suite)  # type: ignore[return-value]

    def test_a_test_that_prints_is_named(self) -> None:
        class Leaky(unittest.TestCase):
            def test_prints(self) -> None:
                print("Wrote SARIF report to /tmp/whatever.sarif")

        result = self._run(Leaky)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(len(result.printed), 1)
        leaked = next(iter(result.printed.values()))
        self.assertIn("Wrote SARIF report", leaked)

    def test_a_quiet_test_is_not_named(self) -> None:
        class Quiet(unittest.TestCase):
            def test_silent(self) -> None:
                self.assertTrue(True)

        self.assertEqual(self._run(Quiet).printed, {})

    def _main_on(self, case: type[unittest.TestCase]) -> tuple[int, str]:
        """``run_tests.main(["--tier", "fast"])`` with discovery answering
        one planted class: the real command, end to end, in this process."""
        planted = unittest.TestLoader().loadTestsFromTestCase(case)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(unittest.TestLoader, "discover", lambda self, *args, **kwargs: planted), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_tests.main(["--tier", "fast"])
        return code, err.getvalue()

    def test_a_leak_makes_the_command_exit_non_zero(self) -> None:
        """Detection was tested; the CONSEQUENCE was not, and that is the half
        that matters.

        REGRESSION, and an expensive one. Eight tests leaked for 28 commits
        while `run_tests.py --tier fast` printed `OK` and exited `1`. Every
        test above proves the leak is *detected*. None proved the command
        *fails*, so a reader grepping the output for `OK` -- which is what a
        human and a careless script both do -- saw a passing run. The exit code
        is the only part CI reads, and it was the only part untested.

        This used to assert only that main() held SOME constant `return 1`,
        and it had four: removing the leak branch's own left it green
        (measured). It now drives main() on a planted leaky test, so the exit
        code is the one the leak branch returns.
        """
        class Leaky(unittest.TestCase):
            def test_prints(self) -> None:
                print("Wrote SARIF report to /tmp/whatever.sarif")

        code, err = self._main_on(Leaky)
        self.assertIn("FAST TIER WROTE TO STDOUT", err)
        self.assertIn("Wrote SARIF report", err)
        self.assertEqual(code, 1, err)

    def test_control_a_quiet_run_of_the_command_exits_zero(self) -> None:
        class Quiet(unittest.TestCase):
            def test_silent(self) -> None:
                self.assertTrue(True)

        code, err = self._main_on(Quiet)
        self.assertNotIn("FAST TIER WROTE TO STDOUT", err)
        self.assertEqual(code, 0, err)

    def test_the_leak_branch_returns_before_it_can_fall_through(self) -> None:
        """A leak must not be reported and then followed by `return 0`."""
        leaky = io.StringIO()
        result = self._run(type("Leaky", (unittest.TestCase,), {
            "test_prints": lambda self: print("leaked"),
        }))
        self.assertTrue(result.printed, "the fixture did not leak")
        # The reporting block and the failing return live together: removing
        # the return would leave `printed` populated and the command green,
        # which is exactly the state that survived 28 commits.
        source = Path(run_tests.__file__).read_text(encoding="utf-8")
        block = source[source.index("FAST TIER WROTE TO STDOUT"):]
        self.assertIn("return 1", block[:block.index("_over_budget")])

    def test_capturing_stdout_inside_the_test_is_not_a_leak(self) -> None:
        class Polite(unittest.TestCase):
            def test_captures(self) -> None:
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    print("Wrote SARIF report to /tmp/whatever.sarif")
                assert "Wrote SARIF report" in captured.getvalue()

        self.assertEqual(self._run(Polite).printed, {})

    def test_stdout_is_restored_after_the_run(self) -> None:
        before = sys.stdout

        class Leaky(unittest.TestCase):
            def test_prints(self) -> None:
                print("noise")

        self._run(Leaky)
        self.assertIs(sys.stdout, before)


class FixtureBudgetTest(unittest.TestCase):
    """The per-test budget covers class and module fixtures too.

    REGRESSION. The clock ran from startTest to stopTest, and unittest runs
    setUpClass, setUpModule and their teardowns outside that window. A class
    whose setUpClass slept 1.5 s recorded 0.0 s and the fast tier exited 0
    (measured), so the scale work the budget exists to keep out of the tier
    could sit in a fixture. The budget is cut to 0.02 s here so the planted
    fixtures can stay cheap."""

    BUDGET = 0.02
    SLEEP = 0.06

    def planted(self, **fixtures: object) -> unittest.TestSuite:
        """One class in a module of its own, carrying ``fixtures`` (class or
        module level, by name) that sleep past the cut budget."""
        import types  # noqa: PLC0415

        module = types.ModuleType("planted_fixture_budget")
        sleep = self.SLEEP
        body: dict[str, object] = {"__module__": module.__name__, "test_quick": lambda self: None}
        for name, where in fixtures.items():
            if where == "class":
                body[name] = classmethod(lambda cls: time.sleep(sleep))
            elif where == "body":
                body["test_quick"] = lambda self: time.sleep(sleep)
            else:
                setattr(module, name, lambda: time.sleep(sleep))
        case = type("Planted", (unittest.TestCase,), body)
        module.Planted = case
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        return unittest.TestLoader().loadTestsFromTestCase(case)

    def main_on(self, suite: unittest.TestSuite) -> tuple[int, str]:
        err = io.StringIO()
        with mock.patch.object(unittest.TestLoader, "discover", lambda self, *args, **kwargs: suite), \
                mock.patch.object(run_tests, "FAST_TEST_BUDGET_SECONDS", self.BUDGET), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = run_tests.main(["--tier", "fast"])
        return code, err.getvalue()

    def test_a_slow_class_or_module_fixture_fails_the_fast_tier(self) -> None:
        for name, where in (("setUpClass", "class"), ("tearDownClass", "class"),
                            ("setUpModule", "module"), ("tearDownModule", "module")):
            with self.subTest(fixture=name):
                code, err = self.main_on(self.planted(**{name: where}))
                self.assertIn("FAST TIER BUDGET EXCEEDED", err)
                self.assertIn("planted_fixture_budget.Planted", err)
                self.assertIn("class and module fixtures", err)
                self.assertEqual(code, 1, err)

    def test_control_the_same_sleep_in_a_test_body_fails_and_a_quick_fixture_does_not(self) -> None:
        code, err = self.main_on(self.planted(body="body"))
        self.assertEqual(code, 1, err)
        self.assertIn("planted_fixture_budget.Planted.test_quick", err)
        self.assertNotIn("class and module fixtures", err)
        code, err = self.main_on(self.planted())
        self.assertEqual(code, 0, err)
        self.assertNotIn("FAST TIER BUDGET EXCEEDED", err)


class BudgetMeasureTest(unittest.TestCase):
    """The budget reads what a test spends, not how long the machine took.

    REGRESSION. It read the wall clock, so a test waiting for a core counted
    against it: under load, runs that printed "OK" exited 1 naming a different
    test each time (measured). A wait is planted here because it is what a
    descheduled test looks like from inside: time passes, nothing is spent."""

    WAIT = 0.06
    BUDGET = 0.02

    def main_on(self, body: object, **limits: float) -> tuple[int, str]:
        case = type("Planted", (unittest.TestCase,), {"__module__": __name__, "test_planted": body})
        suite = unittest.TestLoader().loadTestsFromTestCase(case)
        limits = {"FAST_TEST_BUDGET_SECONDS": self.BUDGET, **limits}
        err = io.StringIO()
        with mock.patch.object(unittest.TestLoader, "discover", lambda self, *args, **kwargs: suite), \
                mock.patch.multiple(run_tests, **limits), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = run_tests.main(["--tier", "fast"])
        return code, err.getvalue()

    def test_time_a_test_did_not_spend_does_not_fail_the_tier(self) -> None:
        wait = self.WAIT
        code, err = self.main_on(lambda self: threading.Event().wait(wait))
        self.assertEqual(code, 0, err)
        self.assertNotIn("FAST TIER BUDGET EXCEEDED", err)
        # Below the ceiling it is still reported: it may be a real wait.
        self.assertIn("on the wall clock but not in CPU time and sleep", err)
        self.assertIn("test_planted", err)

    def test_control_cpu_past_the_budget_fails_and_says_the_tests_passed(self) -> None:
        def burn(self: unittest.TestCase, seconds: float = self.WAIT) -> None:
            end = time.process_time() + seconds
            while time.process_time() < end:
                pass

        code, err = self.main_on(burn)
        self.assertEqual(code, 1, err)
        self.assertIn("FAST TIER BUDGET EXCEEDED", err)
        self.assertIn("test_planted", err)
        self.assertIn("Every test passed; this failure is the time alone.", err)

    def test_a_sleep_counts_as_asked_even_when_taken_as_a_default_argument(self) -> None:
        """core.py and matrix.py bind time.sleep as a default when imported, so
        the meter has to be in place before discovery imports them."""
        wait = self.WAIT
        planted = []

        def discover(loader: unittest.TestLoader, *args: object, **kwargs: object) -> unittest.TestSuite:
            def body(self: unittest.TestCase, sleep: object = time.sleep) -> None:
                sleep(wait)
            planted.append(type("Planted", (unittest.TestCase,), {"__module__": __name__, "test_planted": body}))
            return loader.loadTestsFromTestCase(planted[0])

        err = io.StringIO()
        with mock.patch.object(unittest.TestLoader, "discover", discover), \
                mock.patch.object(run_tests, "FAST_TEST_BUDGET_SECONDS", self.BUDGET), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = run_tests.main(["--tier", "fast"])
        self.assertEqual(code, 1, err.getvalue())
        self.assertIn("FAST TIER BUDGET EXCEEDED", err.getvalue())

    def test_a_wait_past_the_wall_clock_ceiling_fails_and_says_why(self) -> None:
        wait = self.WAIT
        code, err = self.main_on(lambda self: threading.Event().wait(wait),
                                 FAST_TEST_WALL_CEILING_SECONDS=self.BUDGET)
        self.assertEqual(code, 1, err)
        self.assertIn("FAST TIER WALL-CLOCK CEILING EXCEEDED", err)
        self.assertIn("test_planted", err)
        self.assertIn("this machine stalled", err)
        self.assertNotIn("FAST TIER BUDGET EXCEEDED", err)

    def test_a_tier_that_adds_up_past_its_ceiling_fails_and_says_why(self) -> None:
        """Tests that each wait just under the per-test ceiling had no limit at
        all: 29 s, 3 s and 3 s in three tests exited 0 with a note. Mutant: without
        the check in main this exits 0. Control: the test above, under the real
        limit, the same wait passes."""
        wait = self.WAIT
        code, err = self.main_on(lambda self: threading.Event().wait(wait),
                                 FAST_TIER_WALL_CEILING_SECONDS=self.BUDGET)
        self.assertEqual(code, 1, err)
        self.assertIn("the whole tier may take", err)
        self.assertIn("Every test passed; this failure is the time alone.", err)
        self.assertNotIn("FAST TIER BUDGET EXCEEDED", err)

    def test_only_time_sleep_is_metered_and_the_ceilings_hold_the_rest(self) -> None:
        """The comment on the budget said a sleep past it fails whatever the
        machine does. asyncio.sleep and a select timeout are sleeps it never sees.
        If the meter learns them, this fails and the comment and CONTRIBUTING
        change with it."""
        wait = self.WAIT
        for label, body in (("select", lambda self: select.select([], [], [], wait)),
                            ("asyncio", lambda self: asyncio.run(asyncio.sleep(wait)))):
            with self.subTest(wait=label):
                code, err = self.main_on(body)
                self.assertEqual(code, 0, err)
                self.assertIn("on the wall clock but not in CPU time and sleep", err)
                code, err = self.main_on(body, FAST_TEST_WALL_CEILING_SECONDS=self.BUDGET)
                self.assertEqual(code, 1, err)
                self.assertIn("FAST TIER WALL-CLOCK CEILING EXCEEDED", err)

    def test_a_test_near_the_budget_is_warned_about_and_does_not_fail(self) -> None:
        """Nothing failed without this warning: a test one slower machine away
        from red went unreported. Mutant: crowding = [] fails the first assertion
        below, and a different fraction fails the second pair."""
        def burn(self: unittest.TestCase, seconds: float = self.WAIT) -> None:
            end = time.process_time() + seconds
            while time.process_time() < end:
                pass

        code, err = self.main_on(burn, FAST_TEST_BUDGET_SECONDS=self.WAIT * 2)
        self.assertEqual(code, 0, err)
        self.assertIn("Green here, at risk on a slower runner", err)
        self.assertIn("test_planted", err)
        code, err = self.main_on(burn, FAST_TEST_BUDGET_SECONDS=self.WAIT * 200)
        self.assertEqual(code, 0, err)
        self.assertNotIn("Green here, at risk on a slower runner", err)

    def test_a_sleep_is_capped_at_the_window_it_happened_in(self) -> None:
        """A thread left over from an earlier test can sleep during this one, and
        that must not be charged here. Mutant: without min(), the first is 5.1."""
        result = run_tests._TimedResult(io.StringIO(), False, 0)
        self.assertEqual(result._charge("leftover", (0.0, 0.0, 0.0), (1.0, 0.1, 5.0)), 1.0)
        self.assertAlmostEqual(result.costs["leftover"], 1.1)
        result._charge("own", (0.0, 0.0, 0.0), (1.0, 0.1, 0.5))
        self.assertAlmostEqual(result.costs["own"], 0.6)

    def test_a_failure_is_not_described_as_every_test_passing(self) -> None:
        def fail_late(self: unittest.TestCase, seconds: float = self.WAIT) -> None:
            end = time.process_time() + seconds
            while time.process_time() < end:
                pass
            self.fail("planted")

        code, err = self.main_on(fail_late)
        self.assertEqual(code, 1, err)
        self.assertNotIn("Every test passed", err)

    def test_the_fast_tier_puts_time_sleep_back(self) -> None:
        before = time.sleep
        self.main_on(lambda self: None)
        self.assertIs(time.sleep, before)


class BudgetNumbersTest(unittest.TestCase):
    """The README and CONTRIBUTING state these limits, and they are the contract.

    BudgetMeasureTest patches the constants, so it cannot see them. Moving the
    budget from 2 to 200, or the ceiling from 30 to 3000, failed nothing, and the
    docs went on saying two seconds and 30: a document describing a stricter suite
    than the one that ran."""

    WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5}

    def stated(self, name: str) -> tuple[float, float, float]:
        prose = " ".join((ROOT / name).read_text(encoding="utf-8").split())
        limits = re.search(r"more than (\w+) seconds of CPU time and sleep, or (\d+) on the wall clock\. "
                           r"The whole tier may take (\d+) seconds\.", prose)
        self.assertIsNotNone(limits, f"{name} no longer states the limits")
        assert limits is not None
        return float(self.WORDS[limits.group(1)]), float(limits.group(2)), float(limits.group(3))

    def test_the_documents_state_the_limits_the_runner_applies(self) -> None:
        for name in ("docs/guide.md", "CONTRIBUTING.md"):
            with self.subTest(document=name):
                self.assertEqual(self.stated(name), (run_tests.FAST_TEST_BUDGET_SECONDS,
                                                     run_tests.FAST_TEST_WALL_CEILING_SECONDS,
                                                     run_tests.FAST_TIER_WALL_CEILING_SECONDS))

    def test_the_warning_fraction_is_the_margin_its_comment_gives(self) -> None:
        """The message says "within ~5x", which is this fraction's inverse."""
        self.assertAlmostEqual(1 / run_tests.FAST_TEST_HEADROOM_FRACTION, 5.0)


class ListTest(unittest.TestCase):
    """``--list`` must work at every tier, most of all the default one.

    It did not: ``filter_suite`` returns the raw discovered suite for ``all``,
    which is nested one TestSuite per module, and ``main`` iterated it directly
    and called ``.id()`` on each item. The two filtered tiers came back flat by
    accident of construction, so the flag worked everywhere except the bare
    invocation the script's own ``--help`` advertises.
    """

    def _list(self, argv: list[str]) -> list[str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = run_tests.main(argv)
        self.assertEqual(code, 0)
        return buffer.getvalue().splitlines()

    def test_the_default_tier_lists_ids_rather_than_crashing(self) -> None:
        listed = self._list(["--list"])
        self.assertGreater(len(listed), 100)
        # Match on the suffix, not on ``__name__``: run_tests discovers with the
        # tests directory as top level and emits ``test_tiers.…``, while
        # ``python -m unittest tests.test_tiers`` makes __name__ ``tests.test_tiers``.
        # Pinning either spelling fails under the other invocation, which is a
        # defect in the test and not in the thing under test.
        suffix = "test_tiers.ListTest.test_every_tier_lists_ids"
        self.assertTrue(
            any(line.endswith(suffix) for line in listed),
            f"no listed id ends with {suffix!r}",
        )

    def test_every_tier_lists_ids(self) -> None:
        listed = {tier: self._list(["--tier", tier, "--list"]) for tier in (FAST, SLOW, ALL)}
        for tier, ids in listed.items():
            with self.subTest(tier=tier):
                self.assertGreater(len(ids), 100, tier)
                # Every line is a test id, never a repr of a container.
                self.assertNotIn("TestSuite", "".join(ids))
        self.assertEqual(
            sorted(listed[FAST] + listed[SLOW]), sorted(listed[ALL])
        )


# ---------------------------------------------------------------------------
# --jobs: the slow tier over N processes. The defect this project keeps having
# is a control that reads as enforcing while enforcing nothing, and a sharded
# run is one: a test handed to no worker, or a worker that dies, reads as
# fewer failures. So a sharded run has to start exactly the serial selection
# -- every test once -- and a worker that does not finish has to fail the run.
# ---------------------------------------------------------------------------


class ShardPartitionTest(unittest.TestCase):
    """The units --jobs hands out are the REAL slow tier's serial selection,
    once each, whole classes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.slow = filter_suite(_whole_suite(), SLOW)
        cls.serial = [test.id() for test in iter_tests(cls.slow)]
        cls.units = [[test.id() for test in unit] for unit in run_tests.shard_units(cls.slow)]

    @staticmethod
    def classes(unit: list[str]) -> set[str]:
        return {test_id.rsplit(".", 1)[0] for test_id in unit}

    def test_the_units_of_the_real_slow_tier_are_the_serial_selection_exactly_once(self) -> None:
        self.assertGreater(len(self.serial), 100)
        self.assertGreater(len(self.units), 50)
        # The union, in the serial order, with multiplicity: nothing missing,
        # nothing added, nothing twice.
        self.assertEqual([test_id for unit in self.units for test_id in unit], self.serial)
        self.assertEqual(run_tests.run_problems(self.serial, [
            [{"event": "start", "id": test_id} for test_id in unit] for unit in self.units]), [])
        # Whole classes: one class per unit, and each class in one unit.
        self.assertTrue(all(len(self.classes(unit)) == 1 for unit in self.units))
        names = [next(iter(self.classes(unit))) for unit in self.units]
        self.assertEqual(len(names), len(set(names)))

    def test_control_a_dropped_a_doubled_or_a_foreign_test_is_named(self) -> None:
        def started(units: list[list[str]]) -> list[list[dict]]:
            return [[{"event": "start", "id": test_id} for test_id in unit] for unit in units]

        first = self.units[0][0]
        self.assertEqual(run_tests.run_problems(self.serial, started([self.units[0][1:], *self.units[1:]])),
                         [f"started by no worker: {first}"])
        self.assertEqual(run_tests.run_problems(self.serial, started([*self.units, [first]])),
                         [f"started more than once: {first}"])
        self.assertEqual(run_tests.run_problems(self.serial, started([*self.units, ["test_x.Nowhere.test_y"]])),
                         ["started, and not in the serial selection: test_x.Nowhere.test_y"])
        # A class its setUpClass skipped is selected and not started, as in a serial run...
        skipped = [[{"event": "fixture", "id": f"setUpClass ({first.rsplit('.', 1)[0]})"}]]
        without = [unit for unit in self.units if first not in unit]
        self.assertEqual(run_tests.run_problems(self.serial, started(without) + skipped), [])
        # ...and the skip covers that class only.
        other = self.units[1][0]
        self.assertEqual(run_tests.run_problems(self.serial, started(without) + [
            [{"event": "fixture", "id": f"setUpClass ({other.rsplit('.', 1)[0]})"}]])[:1],
                         [f"started by no worker: {first}"])

    def test_list_is_the_same_with_jobs(self) -> None:
        def listed(argv: list[str]) -> list[str]:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(run_tests.main(argv), 0)
            return buffer.getvalue().splitlines()

        self.assertEqual(listed(["--tier", SLOW, "--jobs", "4", "--list"]), self.serial)
        self.assertEqual(listed(["--tier", SLOW, "--list"]), self.serial)


class JobsRefusalTest(unittest.TestCase):
    """--jobs is the slow tier's alone: the fast tier's guard, budget and stdout
    check assume one process, and `all` runs the fast tier."""

    def run_main(self, argv: list[str]) -> tuple[int, str]:
        from unittest import mock  # noqa: PLC0415

        err = io.StringIO()
        # Refused means nothing ran: neither runner may be reached.
        with mock.patch.object(run_tests, "_run_sharded", side_effect=AssertionError("ran")), \
                mock.patch.object(run_tests, "_run_worker", side_effect=AssertionError("ran")), \
                mock.patch.object(run_tests.unittest.TextTestRunner, "run",
                                  side_effect=AssertionError("ran")), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = run_tests.main(argv)
        return code, err.getvalue()

    def test_jobs_with_the_fast_tier_or_all_is_refused(self) -> None:
        original = os.environ.pop(tiers.ENV_VAR, None)
        self.addCleanup(lambda: original is None or os.environ.__setitem__(tiers.ENV_VAR, original))
        for argv in (["--tier", FAST, "--jobs", "2"], ["--tier", ALL, "--jobs", "4"], ["--jobs", "4"],
                     ["--tier", FAST, "--jobs", "4", "--list"]):
            with self.subTest(argv=argv):
                code, err = self.run_main(argv)
                self.assertEqual(code, 2)
                self.assertIn("slow tier only", err)
                self.assertIn("Nothing was run", err)

    def test_nonsense_counts_and_a_misused_worker_flag_are_refused(self) -> None:
        for argv in (["--tier", SLOW, "--jobs", "0"], ["--tier", SLOW, "--jobs", "-3"],
                     ["--tier", FAST, "--worker", "5,6"], ["--tier", SLOW, "--jobs", "2", "--worker", "5,6"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_main(argv)[0], 2)

    def test_control_the_slow_tier_takes_jobs_and_one_is_the_default(self) -> None:
        self.assertIsNone(run_tests.jobs_refusal(4, SLOW))
        self.assertIsNone(run_tests.jobs_refusal(1, FAST))
        self.assertEqual(run_tests._parser().parse_args([]).jobs, 1)
        self.assertIn("slow tier only", run_tests.jobs_refusal(2, FAST) or "")


_IDENTITY = {"python": "/usr/bin/python3.12", "version": "3.12.0", "veridor": "/src/veridor"}


def _events(*ids: str, done: bool = True, **header: str) -> list[dict]:
    events: list[dict] = [{"event": "worker", **_IDENTITY, **header}]
    for test_id in ids:
        events += [{"event": "start", "id": test_id}, {"event": "outcome", "id": test_id, "outcome": "ok"}]
    if done:
        events.append({"event": "done", "tests_run": len(ids), "successful": True})
    return events


class WorkerAccountingTest(unittest.TestCase):
    """A worker's report counts only if it ran exactly what it was handed, to the end."""

    HANDED = ["m.C.test_a", "m.C.test_b", "m.D.test_c"]

    def problems(self, events: list[dict], returncode: int | None = 0, **kwargs) -> list[str]:
        return run_tests.worker_problems(self.HANDED, events, returncode, _IDENTITY, **kwargs)

    def test_control_a_worker_that_ran_what_it_was_handed_is_clean(self) -> None:
        self.assertEqual(self.problems(_events(*self.HANDED)), [])

    def test_a_worker_killed_inside_a_test_names_the_test(self) -> None:
        events = _events(*self.HANDED, done=False)[:-1]  # started m.D.test_c, never finished it
        self.assertEqual(self.problems(events, -9),
                         ["stopped inside m.D.test_c", "died (exit -9) before it finished"])

    def test_a_worker_that_wrote_nothing_is_not_clean(self) -> None:
        self.assertEqual(self.problems([], 1),
                         ["wrote no report (exit 1): it stopped before running a test"])

    def test_a_timeout_is_named(self) -> None:
        events = _events(*self.HANDED[:1], done=False) + [{"event": "start", "id": "m.C.test_b"}]
        self.assertEqual(self.problems(events, -9, timed_out=1200.0),
                         ["timed out after 1200s and was killed", "stopped inside m.C.test_b"])

    def test_a_test_skipped_silently_or_run_extra_is_named(self) -> None:
        self.assertEqual(self.problems(_events(*self.HANDED[:2])),
                         ["never started 1 of the tests it was handed, first m.D.test_c"])
        self.assertEqual(self.problems(_events(*self.HANDED, "m.E.test_d")),
                         ["ran a test it was not handed: m.E.test_d"])
        self.assertEqual(self.problems(_events(*self.HANDED, "m.C.test_a")),
                         ["ran a test it was not handed: m.C.test_a"])

    def test_tests_its_discovery_does_not_have_are_named(self) -> None:
        events = _events(done=False) + [{"event": "unknown", "ids": ["m.C.test_a", "m.C.test_b"]}]
        self.assertEqual(self.problems(events, 1)[:2],
                         ["was handed 2 test(s) its discovery does not have, first m.C.test_a",
                          "died (exit 1) before it finished"])

    def test_a_class_whose_setup_skipped_is_not_missing_as_in_a_serial_run(self) -> None:
        events = _events("m.D.test_c", done=False) + [
            {"event": "fixture", "id": "setUpClass (m.C)", "outcome": "skip"},
            {"event": "done", "tests_run": 1, "successful": True}]
        self.assertEqual(self.problems(events), [])

    def test_control_a_fixture_covers_its_own_class_only(self) -> None:
        for fixture in ("setUpClass (m.D)", "setUpClass (m.C.test)", "setUpClass (m.)",
                        "tearDownClass (m.C)"):
            with self.subTest(fixture=fixture):
                events = _events("m.D.test_c", done=False) + [
                    {"event": "fixture", "id": fixture, "outcome": "skip"},
                    {"event": "done", "tests_run": 1, "successful": True}]
                self.assertEqual(self.problems(events),
                                 ["never started 2 of the tests it was handed, first m.C.test_a"])
        module = _events("m.D.test_c", done=False) + [
            {"event": "fixture", "id": "setUpModule (m)", "outcome": "error"},
            {"event": "done", "tests_run": 1, "successful": False}]
        self.assertEqual(self.problems(module, 1), [])

    def test_success_with_a_failing_exit_or_another_veridor_is_named(self) -> None:
        self.assertEqual(self.problems(_events(*self.HANDED), 1),
                         ["reported success and exited 1"])
        self.assertEqual(self.problems(_events(*self.HANDED, veridor="/site-packages/veridor")),
                         ["ran against /usr/bin/python3.12 and /site-packages/veridor, "
                          "not /usr/bin/python3.12 and /src/veridor"])

    def test_a_torn_last_line_is_dropped_not_fatal(self) -> None:
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.jsonl"
            path.write_text('{"event": "worker"}\n{"event": "start", "id": "a"}\n{"event": "outc',
                            encoding="utf-8")
            self.assertEqual(run_tests.read_report(path),
                             [{"event": "worker"}, {"event": "start", "id": "a"}])
            self.assertEqual(run_tests.read_report(Path(tmp) / "absent.jsonl"), [])


class SerialAccountingTest(unittest.TestCase):
    """A serial tier counts only if it started what it selected.

    REGRESSION. unittest catches only Exception in a class or module fixture,
    so a SystemExit there -- argparse's --version in a setUpClass that calls a
    CLI's main() -- left ``runner.run()`` and ended the fast tier, the serial
    slow tier and ``all`` with exit 0, no "Ran" line and nothing after it run
    (measured on a planted copy). Only --jobs noticed."""

    SELECTED = ["m.C.test_a", "m.C.test_b", "m.D.test_c"]

    @staticmethod
    def started(*ids: str) -> list[dict]:
        return [{"event": "start", "id": test_id} for test_id in ids]

    def test_control_a_run_that_started_everything_is_clean(self) -> None:
        self.assertEqual(run_tests.serial_problems(self.SELECTED, self.started(*self.SELECTED)), [])

    def test_a_setup_skip_excuses_its_class_as_unittest_does(self) -> None:
        recorded = self.started("m.C.test_a", "m.C.test_b") + [
            {"event": "fixture", "id": "setUpClass (m.D)", "outcome": "skip"}]
        self.assertEqual(run_tests.serial_problems(self.SELECTED, recorded), [])

    def test_a_run_that_stopped_early_names_what_never_started(self) -> None:
        self.assertEqual(run_tests.serial_problems(self.SELECTED, self.started("m.C.test_a")),
                         ["never started 2 of the 3 selected tests, first m.C.test_b"])

    def test_a_system_exit_is_named_even_after_every_test_started(self) -> None:
        """A tearDownClass or tearDownModule can raise it after the last test."""
        problems = run_tests.serial_problems(self.SELECTED, self.started(*self.SELECTED), SystemExit(0))
        self.assertEqual(len(problems), 1)
        self.assertIn("SystemExit(0) escaped unittest", problems[0])

    def test_control_the_runner_really_lets_a_fixture_system_exit_escape(self) -> None:
        """What the serial path guards against, in process: the runner raises,
        and what the result recorded before it names the tests that never ran."""

        class Exits(unittest.TestCase):
            @classmethod
            def setUpClass(cls) -> None:
                raise SystemExit(0)

            def test_never(self) -> None:  # pragma: no cover - never runs
                pass

        class Later(unittest.TestCase):
            def test_later(self) -> None:  # pragma: no cover - never runs
                pass

        load = unittest.defaultTestLoader.loadTestsFromTestCase
        suite = unittest.TestSuite([load(Exits), load(Later)])
        selected = [test.id() for test in iter_tests(suite)]
        made: list = []

        def result_class(*args: object, **kwargs: object) -> run_tests._TimedResult:
            made.append(run_tests._TimedResult(*args, **kwargs))
            return made[-1]

        with self.assertRaises(SystemExit):
            unittest.TextTestRunner(stream=io.StringIO(), resultclass=result_class).run(suite)
        self.assertEqual(run_tests.serial_problems(selected, made[0].recorded),
                         [f"never started 2 of the 2 selected tests, first {selected[0]}"])


#: The runner, its helpers and one planted test module, as a tree of their own.
_HELPERS = ("tiers.py", "source_path.py", "loopback.py")

#: A class fixture that ends the process the way argparse's --version does,
#: then a test that must fail if it ever runs; in both tiers.
_EXIT_PLANT = """
import argparse, unittest
from tiers import slow

def _version():
    parser = argparse.ArgumentParser(prog="veridor")
    parser.add_argument("--version", action="version", version="veridor 0")
    parser.parse_args(["--version"])

class FastFixtureExit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _version()
    def test_x(self):
        pass

class FastLater(unittest.TestCase):
    def test_must_not_run(self):
        self.fail("ran after the fixture's SystemExit")

@slow("planted")
class SlowFixtureExit(FastFixtureExit):
    pass

@slow("planted")
class SlowLater(FastLater):
    pass
"""

#: A holds a lock for two seconds; B's setUpClass skips while it is held. A
#: serial run finishes A first; --jobs 2 runs them side by side.
_LOCK_PLANT_A = """
import time, unittest
from pathlib import Path
from tiers import slow
HERE = Path(__file__).parent

@slow("planted")
class HoldsTheLock(unittest.TestCase):
    def test_hold(self):
        (HERE / "lock").write_text("x")
        time.sleep(2)
        (HERE / "lock").unlink()
        (HERE / "released").write_text("x")
"""
_LOCK_PLANT_B = """
import time, unittest
from pathlib import Path
from tiers import slow
HERE = Path(__file__).parent

@slow("planted")
class SkipsWhileLocked(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deadline = time.monotonic() + 10
        while not (HERE / "lock").exists() and not (HERE / "released").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("the lock plant never started")
            time.sleep(0.02)
        if not (HERE / "released").exists():
            raise unittest.SkipTest("the lock is held")
    def test_runs(self):
        pass

@slow("planted")
class RecordsItsShare(unittest.TestCase):
    def test_share(self):
        import os
        (HERE / f"share-{os.getpid()}").write_text(os.environ.get("VERIDOR_TEST_WORKER", "-"))
"""


@slow("runs scripts/run_tests.py on planted test trees")
class PlantedRunTest(unittest.TestCase):
    """The runner end to end, as a process, on a tree whose tests are planted."""

    def tree(self, modules: dict[str, str]) -> Path:
        import shutil  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        root = Path(tempfile.mkdtemp(prefix="veridor-planted-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "scripts").mkdir()
        (root / "tests").mkdir()
        shutil.copy2(ROOT / "scripts" / "run_tests.py", root / "scripts")
        for helper in _HELPERS:
            shutil.copy2(ROOT / "tests" / helper, root / "tests")
        (root / "src").symlink_to(ROOT / "src", target_is_directory=True)
        for name, text in modules.items():
            (root / "tests" / name).write_text(text, encoding="utf-8")
        return root

    def run_tier(self, root: Path, *args: str) -> tuple[int, str, str]:
        env = {key: value for key, value in os.environ.items() if key != tiers.ENV_VAR}
        done = subprocess.run([sys.executable, str(root / "scripts" / "run_tests.py"), *args], cwd=root,
                              env=env, capture_output=True, text=True, timeout=180, check=False)
        return done.returncode, done.stdout, done.stderr

    MODES = (("--tier", "fast"), ("--tier", "slow"), (), ("--tier", "slow", "--jobs", "2"))

    def test_a_fixture_system_exit_fails_every_tier(self) -> None:
        root = self.tree({"test_planted.py": _EXIT_PLANT})
        for mode in self.MODES:
            with self.subTest(mode=mode):
                code, out, err = self.run_tier(root, *mode)
                self.assertEqual(code, 1, out + err)
                if "--jobs" not in mode:
                    self.assertIn("SystemExit(0) escaped unittest", err)

    def test_control_the_same_plant_without_the_exit_passes_every_tier(self) -> None:
        plant = _EXIT_PLANT.replace("        _version()", "        pass").replace(
            'self.fail("ran after the fixture\'s SystemExit")', "pass")
        self.assertNotEqual(plant, _EXIT_PLANT)
        root = self.tree({"test_planted.py": plant})
        for mode in self.MODES:
            with self.subTest(mode=mode):
                code, out, err = self.run_tier(root, *mode)
                self.assertEqual(code, 0, out + err)

    def test_a_tree_with_no_test_fails_every_tier(self) -> None:
        """unittest reports an empty run as a success; so did every tier."""
        root = self.tree({})
        for mode in self.MODES:
            with self.subTest(mode=mode):
                code, out, err = self.run_tier(root, *mode)
                self.assertEqual(code, 1, out + err)
                self.assertIn("Running nothing is not a pass", err)

    def test_a_setup_skip_caused_by_another_worker_runs_again_alone(self) -> None:
        """Serially the class runs; under --jobs 2 its setUpClass skipped
        because another worker held the lock, and the run passed with the
        class excused (3 runs of 3, before this). Now it runs again, alone."""
        root = self.tree({"test_a_lock.py": _LOCK_PLANT_A, "test_b_lock.py": _LOCK_PLANT_B})
        code, out, err = self.run_tier(root, "--tier", "slow")
        self.assertEqual(code, 0, out + err)
        self.assertIn("Ran 3 tests", err)
        self.assertNotIn("skipped", err)
        for name in ("lock", "released", *[path.name for path in (root / "tests").glob("share-*")]):
            (root / "tests" / name).unlink(missing_ok=True)
        code, out, err = self.run_tier(root, "--tier", "slow", "--jobs", "2")
        self.assertEqual(code, 0, out + err)
        self.assertIn("ran 3, 0 failed, 0 errors, 0 skipped", out)
        self.assertIn("setUpClass or setUpModule skipped 1 class(es) in a worker; run again, alone, they "
                      "started 1 test(s); skipped again, as a serial run would: none", out)
        # The one worker that ran RecordsItsShare drew its ports from a share
        # nested under this process's own: when this suite is itself sharded
        # (CI runs it with --jobs), that is `k/4,0/2`, not a flat `0/2`, so the
        # nested run cannot reach the ports of this worker's siblings. Only
        # that one worker is asserted here; the nesting as such is
        # test_loopback.PortShareTest's.
        parent = os.environ.get(run_tests.WORKER_ENV, "")
        shares = {path.read_text() for path in (root / "tests").glob("share-*")}
        self.assertLessEqual(shares, {run_tests.nested_share(parent, index, 2) for index in range(2)})
        self.assertEqual(len(shares), 1)

    def test_control_a_setup_that_always_skips_is_excused_as_a_serial_run_would(self) -> None:
        always = _LOCK_PLANT_B.replace("        if not (HERE / \"released\").exists():\n", "        if True:\n")
        self.assertNotEqual(always, _LOCK_PLANT_B)
        root = self.tree({"test_a_lock.py": _LOCK_PLANT_A, "test_b_lock.py": always})
        code, out, err = self.run_tier(root, "--tier", "slow", "--jobs", "2")
        self.assertEqual(code, 0, out + err)
        self.assertIn("skipped again, as a serial run would: setUpClass (test_b_lock.SkipsWhileLocked)", out)
        self.assertIn("ran 2, 0 failed, 0 errors, 1 skipped", out)


class ReportEventsTest(unittest.TestCase):
    """What _TimedResult writes is what the parent counts, so it is pinned."""

    def test_every_outcome_and_a_skipped_class_fixture_are_recorded(self) -> None:
        import functools  # noqa: PLC0415
        import json  # noqa: PLC0415

        class Mixed(unittest.TestCase):
            def test_ok(self) -> None:
                pass

            def test_fail(self) -> None:
                self.fail("no")

            def test_error(self) -> None:
                raise RuntimeError("no")

            def test_skip(self) -> None:
                self.skipTest("no")

            def test_subtest(self) -> None:
                for n in (1, 2):
                    with self.subTest(n=n):
                        self.assertEqual(n, 1)

        class Skipped(unittest.TestCase):
            @classmethod
            def setUpClass(cls) -> None:
                raise unittest.SkipTest("no git index")

            def test_never(self) -> None:  # pragma: no cover - never runs
                pass

        events = io.StringIO()
        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Mixed),
                                    unittest.defaultTestLoader.loadTestsFromTestCase(Skipped)])
        unittest.TextTestRunner(stream=io.StringIO(), resultclass=functools.partial(
            run_tests._TimedResult, events=events)).run(suite)
        lines = [json.loads(line) for line in events.getvalue().splitlines()]
        outcomes = {event["id"].rsplit(".", 1)[1]: event["outcome"]
                    for event in lines if event["event"] == "outcome"}
        self.assertEqual(outcomes, {"test_ok": "ok", "test_fail": "fail", "test_error": "error",
                                    "test_skip": "skip", "test_subtest": "fail"})
        started = [event["id"].rsplit(".", 1)[1] for event in lines if event["event"] == "start"]
        self.assertEqual(sorted(started), sorted(outcomes))  # test_never never started
        fixtures = [event for event in lines if event["event"] == "fixture"]
        self.assertEqual(len(fixtures), 1)
        self.assertTrue(fixtures[0]["id"].startswith("setUpClass ("), fixtures[0])
        self.assertEqual(fixtures[0]["outcome"], "skip")
        # And the parent reads it as a serial run would: test_never is covered.
        never = f"{Skipped.__module__}.{Skipped.__qualname__}.test_never"
        self.assertTrue(run_tests._covered_by_a_fixture(never, [fixtures[0]["id"]]))


#: A stand-in worker for the end-to-end tests. It speaks the worker protocol --
#: classes arrive as JSON lines on one pipe, each is acknowledged on the other,
#: the report is JSON lines -- and then does what MODE says. argv: report,
#: the two pipe descriptors, mode, identity, a directory for child pids.
_FAKE_WORKER = r"""
import json, os, signal, subprocess, sys, time
report_path, fds, mode, identity, piddir = sys.argv[1:6]
identity = json.loads(identity)
command_fd, ack_fd = (int(fd) for fd in fds.split(","))
commands, acks = os.fdopen(command_fd), os.fdopen(ack_fd, "w")
if mode == "die-at-start":
    os.kill(os.getpid(), signal.SIGKILL)
n = 0
with open(report_path, "w") as report:
    def emit(**event):
        report.write(json.dumps(event) + "\n")
        report.flush()
    emit(event="worker", **identity)
    for line in commands:
        unit = json.loads(line)
        if mode == "setup-skip-then-die" and ".Beta." in unit["ids"][0]:
            # The first time, Beta's setUpClass skips; the retry dies in it.
            flag = os.path.join(piddir, "beta-skipped")
            if os.path.exists(flag):
                os.kill(os.getpid(), signal.SIGKILL)
            open(flag, "w").close()
            emit(event="fixture", id=f"setUpClass ({unit['ids'][0].rsplit('.', 1)[0]})", outcome="skip")
            acks.write(f"{unit['unit']}\n")
            acks.flush()
            continue
        for test_id in unit["ids"]:
            emit(event="start", id=test_id)
            if (mode == "die" and n == 1) or (mode == "die-in-alpha" and ".Alpha." in test_id):
                os.kill(os.getpid(), signal.SIGKILL)
            if mode == "hang":
                child = subprocess.Popen(["sleep", "60"])
                with open(os.path.join(piddir, f"{os.getpid()}.child"), "w") as out:
                    out.write(str(child.pid))
                time.sleep(60)
            emit(event="outcome", id=test_id, outcome="fail" if mode.startswith("fail") else "ok")
            n += 1
        acks.write(f"{unit['unit']}\n")
        acks.flush()
    failed = mode.startswith("fail")
    emit(event="done", tests_run=n, failures=n if failed else 0, errors=0, skipped=0,
         successful=not failed)
sys.exit(1 if mode == "fail" else 0)
"""


def _alive(pid: int) -> bool:
    """Whether ``pid`` is running. A zombie -- exited, not yet reaped -- is not.

    ``os.kill(pid, 0)`` alone succeeds on a zombie, and a killed worker's
    orphaned child is reaped by PID 1: where PID 1 is this suite itself (a
    container started without --init), nothing reaps it, and the hung-worker
    test failed with "a hung worker's child outlived the kill" in 2 runs of 2,
    and passed with --init (measured, python:3.12-slim)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    status = Path(f"/proc/{pid}/status")
    if Path("/proc/self/status").exists():  # Linux
        try:
            state = next((line.split()[1] for line in status.read_text().splitlines()
                          if line.startswith("State:")), "")
        except OSError:
            return False
        return state not in ("Z", "X")
    ps = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False)
    return ps.returncode == 0 and not ps.stdout.strip().startswith(("Z", "X"))


@slow("starts worker processes, and kills some")
class ShardedRunTest(unittest.TestCase):
    """The parent end to end, against real processes: a worker that fails,
    dies or hangs fails the run, and the real worker runs what it is handed."""

    @staticmethod
    def suite() -> unittest.TestSuite:
        class Alpha(unittest.TestCase):
            def test_one(self) -> None:  # pragma: no cover - the fake worker never runs it
                pass

            def test_two(self) -> None:  # pragma: no cover
                pass

        class Beta(unittest.TestCase):
            def test_three(self) -> None:  # pragma: no cover
                pass

            def test_four(self) -> None:  # pragma: no cover
                pass

        class Gamma(unittest.TestCase):
            def test_five(self) -> None:  # pragma: no cover
                pass

        load = unittest.defaultTestLoader.loadTestsFromTestCase
        return unittest.TestSuite([load(Alpha), load(Beta), load(Gamma)])

    def setUp(self) -> None:
        import tempfile  # noqa: PLC0415

        self.tmp = tempfile.mkdtemp(prefix="veridor-shard-test-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def sharded(self, suite: unittest.TestSuite, mode: str | None, timeout: float = 60) -> tuple[int, str]:
        import argparse  # noqa: PLC0415
        import json  # noqa: PLC0415

        identity = json.dumps(run_tests._identity())
        command = run_tests.worker_command if mode is None else (
            lambda report, fds, verbose: [sys.executable, "-c", _FAKE_WORKER, str(report),
                                          f"{fds[0]},{fds[1]}", mode, identity, self.tmp])
        self.report = Path(self.tmp) / "merged.jsonl"
        args = argparse.Namespace(jobs=2, shard_timeout=timeout, verbose=0, report=str(self.report))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = run_tests._run_sharded(suite, args, command=command)
        return code, err.getvalue()

    def started(self) -> list[str]:
        import json  # noqa: PLC0415

        return sorted(event["id"].rsplit(".", 2)[-2] + "." + event["id"].rsplit(".", 1)[1]
                      for event in map(json.loads, self.report.read_text(encoding="utf-8").splitlines())
                      if event["event"] == "start")

    def test_control_workers_that_finish_pass_and_start_everything_once(self) -> None:
        code, err = self.sharded(self.suite(), "ok")
        self.assertEqual(code, 0, err)
        self.assertNotIn("FAILED", err)
        self.assertEqual(self.started(), ["Alpha.test_one", "Alpha.test_two", "Beta.test_four",
                                          "Beta.test_three", "Gamma.test_five"])

    def test_a_worker_whose_tests_fail_fails_the_run(self) -> None:
        """Its report is complete and honest, so accounting finds nothing; the
        failures alone must still fail the run."""
        for mode in ("fail", "fail-but-exit-0"):
            with self.subTest(mode=mode):
                code, err = self.sharded(self.suite(), mode)
                self.assertEqual(code, 1, err)
                self.assertIn("SHARDED RUN FAILED", err)

    def test_a_worker_killed_mid_class_fails_the_run_and_the_queue_still_drains(self) -> None:
        code, err = self.sharded(self.suite(), "die-in-alpha")
        self.assertEqual(code, 1, err)
        self.assertIn("SHARDED RUN FAILED", err)
        self.assertIn(f"died (exit -{int(signal.SIGKILL)}) before it finished", err)
        self.assertIn("stopped inside", err)
        # The other worker took Beta and Gamma: what was left still ran.
        self.assertIn("Gamma.test_five", self.started())
        self.assertIn("Beta.test_three", self.started())

    def test_workers_that_all_die_leave_classes_no_worker_ran(self) -> None:
        code, err = self.sharded(self.suite(), "die-at-start")
        self.assertEqual(code, 1, err)
        self.assertIn("wrote no report", err)
        self.assertIn("started by no worker", err)
        # At least the third class was handed to no one (the first two may
        # have reached the dead workers' pipes), and that is said outright.
        self.assertRegex(err, r"the queue: [123] of 3 classes were handed to no worker")

    def test_a_hung_worker_is_killed_with_what_it_started_and_fails_the_run(self) -> None:
        import time  # noqa: PLC0415

        began = time.monotonic()
        code, err = self.sharded(self.suite(), "hang", timeout=2)
        self.assertLess(time.monotonic() - began, 30)
        self.assertEqual(code, 1, err)
        self.assertIn("timed out after 2s and was killed", err)
        # Each hung worker's own child (sleep 60) died with it: the parent
        # kills the worker's whole session, not only the worker.
        children = [int(path.read_text()) for path in Path(self.tmp).glob("*.child")]
        self.assertEqual(len(children), 2)
        deadline = time.monotonic() + 10
        alive = children
        while alive and time.monotonic() < deadline:
            alive = [pid for pid in alive if _alive(pid)]
            time.sleep(0.1)
        self.assertEqual(alive, [], "a hung worker's child outlived the kill")

    def test_a_retry_that_dies_fails_the_run_and_the_first_skip_no_longer_excuses_it(self) -> None:
        code, err = self.sharded(self.suite(), "setup-skip-then-die")
        self.assertEqual(code, 1, err)
        self.assertIn("the retry worker: died", err)
        self.assertIn("started by no worker: ", err)
        self.assertRegex(err, r"started by no worker: \S+\.Beta\.test_")

    def test_zombies_are_not_alive_and_running_processes_are(self) -> None:
        """REGRESSION for _alive itself: a child that exited and was not
        reaped answers os.kill(pid, 0), which the old check read as alive."""
        import time  # noqa: PLC0415

        exited = subprocess.Popen([sys.executable, "-c", "pass"])
        running = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(running.wait)
        self.addCleanup(running.kill)
        self.addCleanup(exited.wait)
        deadline = time.monotonic() + 10
        while _alive(exited.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        os.kill(exited.pid, 0)  # control: unreaped, so the old check said "alive" here
        self.assertFalse(_alive(exited.pid), "an exited, unreaped child reads as alive")
        self.assertTrue(_alive(running.pid))
        running.kill()
        running.wait()
        self.assertFalse(_alive(running.pid), "a reaped process reads as alive")

    def test_the_real_worker_runs_exactly_what_it_is_handed(self) -> None:
        slow_tier = filter_suite(_whole_suite(), SLOW)
        cheap = unittest.TestSuite(test for test in iter_tests(slow_tier)
                                   if test.id().split(".")[1] in ("UnallocatedPortTest", "ShutdownLatencyTest"))
        self.assertEqual(cheap.countTestCases(), 4)
        code, err = self.sharded(cheap, None)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.started(), sorted(test.id().split(".", 1)[1] for test in iter_tests(cheap)))

    def test_control_a_real_worker_handed_a_test_it_cannot_find_fails_the_run(self) -> None:
        code, err = self.sharded(self.suite(), None)
        self.assertEqual(code, 1, err)
        self.assertIn("its discovery does not have", err)
        self.assertIn("before it finished", err)


#: Stands in for the fast tier in a planted repository: red or green by the
#: `state` file of the tree it was run from, saying which it saw.
_STATE_RUNNER = """\
import sys
import threading
from pathlib import Path
state = (Path(__file__).resolve().parents[1] / "state").read_text().strip()
print(f"fast tier saw {state}")
sys.exit(1 if state == "red" else 0)
"""


@slow("creates git repositories and pushes through scripts/pre-push")
class PrePushHookTest(unittest.TestCase):
    """scripts/pre-push, installed the way its header says, on a planted
    repository whose fast tier is red or green by one file.

    REGRESSION. The hook ran the fast tier on the working tree, never on the
    commits being pushed, and ignored the refs git hands it on stdin. A red
    commit with its fix uncommitted, or `git push origin <red branch>` from a
    green checkout, went out (both reproduced end to end)."""

    def setUp(self) -> None:
        import shutil  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        base = Path(tempfile.mkdtemp(prefix="veridor-pre-push-"))
        self.addCleanup(shutil.rmtree, base, True)
        self.remote, self.work = base / "remote.git", base / "work"
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
                    "VERIDOR_PYTHON": sys.executable}
        self.git("init", "-q", "--bare", str(self.remote), cwd=base)
        self.git("init", "-q", "-b", "main", str(self.work), cwd=base)
        (self.work / "scripts").mkdir()
        (self.work / "scripts" / "run_tests.py").write_text(_STATE_RUNNER, encoding="utf-8")
        (self.work / ".git" / "hooks" / "pre-push").symlink_to(ROOT / "scripts" / "pre-push")
        self.git("remote", "add", "origin", str(self.remote))
        self.commit("green")
        self.assertEqual(self.push("main")[0], 0, "control: a green commit from a green tree pushes")

    def git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=cwd or self.work, env=self.env, capture_output=True,
                              text=True, timeout=300, check=False)

    def commit(self, state: str) -> None:
        (self.work / "state").write_text(state, encoding="utf-8")
        self.git("add", "-A")
        self.assertEqual(self.git("commit", "-q", "-m", state).returncode, 0)

    def push(self, *refs: str) -> tuple[int, str]:
        done = self.git("push", "origin", *refs)
        return done.returncode, done.stdout + done.stderr

    def remote_state(self, branch: str) -> str:
        return self.git("--git-dir", str(self.remote), "show", f"{branch}:state").stdout.strip()

    def test_a_red_commit_is_refused_though_the_working_tree_is_green(self) -> None:
        self.commit("red")
        (self.work / "state").write_text("green", encoding="utf-8")  # the fix, uncommitted
        code, out = self.push("main")
        self.assertNotEqual(code, 0, out)
        self.assertIn("pre-push: REFUSED", out)
        self.assertIn("fast tier saw red", out)
        self.assertEqual(self.remote_state("main"), "green")

    def test_a_red_branch_is_refused_from_a_green_checkout(self) -> None:
        self.git("checkout", "-q", "-b", "redbranch")
        self.commit("red")
        self.git("checkout", "-q", "main")
        self.assertEqual((self.work / "state").read_text(encoding="utf-8"), "green")
        code, out = self.push("redbranch")
        self.assertNotEqual(code, 0, out)
        self.assertIn("fast tier saw red", out)
        self.assertEqual(self.git("--git-dir", str(self.remote), "branch", "--list", "redbranch").stdout, "")

    def test_control_a_green_commit_pushes_though_the_working_tree_is_red(self) -> None:
        self.commit("green again")
        (self.work / "state").write_text("red", encoding="utf-8")
        code, out = self.push("main")
        self.assertEqual(code, 0, out)
        self.assertIn("fast tier saw green", out)
        self.assertNotIn("fast tier saw red", out)

    def test_control_red_in_both_is_refused(self) -> None:
        self.commit("red")
        code, out = self.push("main")
        self.assertNotEqual(code, 0, out)
        self.assertEqual(self.remote_state("main"), "green")

    def test_a_deletion_pushes_nothing_to_test(self) -> None:
        self.git("branch", "gone")
        self.assertEqual(self.push("gone")[0], 0)
        (self.work / "state").write_text("red", encoding="utf-8")
        code, out = self.push(":gone")
        self.assertEqual(code, 0, out)
        self.assertNotIn("fast tier saw", out)

    def test_the_fast_tier_runs_once_per_distinct_tip_in_its_own_tree(self) -> None:
        """What the header says: two refs at one tip are one run, two tips are
        two, and each run sees its own tip's tree."""
        self.git("branch", "same")
        code, out = self.push("main", "same")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("fast tier saw"), 1, out)
        self.git("checkout", "-q", "-b", "other")
        self.commit("green on other")
        self.git("checkout", "-q", "main")
        self.commit("green on main")
        code, out = self.push("main", "other")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(line for line in out.splitlines() if "fast tier saw" in line),
                         ["fast tier saw green on main", "fast tier saw green on other"])

    def test_an_annotated_tag_shares_the_run_of_the_commit_it_tags(self) -> None:
        """git hands the hook the tag object's sha for an annotated tag, not
        the commit's. The hook deduped on that sha, so `git push origin main
        v1` with v1 annotated on main's tip ran the fast tier twice, the
        second time naming the tag object as the commit (reproduced)."""
        self.commit("green on main")
        self.assertEqual(self.git("tag", "-a", "-m", "v1", "v1").returncode, 0)
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        tag_object = self.git("rev-parse", "v1").stdout.strip()
        self.assertNotEqual(commit, tag_object, "control: v1 is an annotated tag, its own object")
        code, out = self.push("main", "v1")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("fast tier saw"), 1, out)
        self.assertIn(f"running the fast tier on {commit},", out)
        self.assertNotIn(tag_object, out)
        # Control: an annotated tag on a commit of its own is still a run of
        # its own, held to that commit's fast tier.
        self.commit("red")
        self.assertEqual(self.git("tag", "-a", "-m", "v2", "v2").returncode, 0)
        self.git("reset", "-q", "--hard", "HEAD~1")
        code, out = self.push("main", "v2")
        self.assertNotEqual(code, 0, out)
        self.assertIn("fast tier saw red", out)
        self.assertIn(f"fails on {self.git('rev-parse', 'v2^{commit}').stdout.strip()},", out)

    def test_an_old_tag_is_tested_in_its_own_tree_and_may_refuse(self) -> None:
        """Pushing a tag on an old red commit runs that commit's fast tier,
        not the current one, and is refused though main is green."""
        self.commit("red")
        self.git("tag", "old-red")
        self.commit("green")
        self.assertEqual(self.push("main")[0], 0)
        code, out = self.push("old-red")
        self.assertNotEqual(code, 0, out)
        self.assertIn("fast tier saw red", out)


class PrePushHeaderTest(unittest.TestCase):
    """The header is what a contributor reads before installing the hook. It
    said what is tested (each pushed tip, in a scratch export) but not that
    the fast tier runs once per distinct tip, so pushing several refs or an
    old tag runs it several times, each in that tip's own tree, and an old
    ref is held to its own fast tier."""

    def test_the_header_says_it_runs_once_per_distinct_tip_in_that_tip_s_tree(self) -> None:
        text = (ROOT / "scripts" / "pre-push").read_text(encoding="utf-8")
        header = " ".join(line.lstrip("#").strip() for line in text[:text.index("set -euo pipefail")].splitlines())
        for words in ("runs the fast tier once per distinct tip",
                      "in that tip's own tree",
                      # It said refs sharing a tip share one run, while an
                      # annotated tag and its commit ran twice.
                      "Refs that share a tip commit share one run, an annotated tag and the commit it tags included",
                      "pushing an old tag or an archived branch runs that commit's own fast tier"):
            self.assertIn(words, " ".join(header.split()))


class DefaultTierTest(unittest.TestCase):
    def test_the_environment_variable_selects_a_tier(self) -> None:
        import os

        original = os.environ.get(tiers.ENV_VAR)
        self.addCleanup(
            lambda: os.environ.__setitem__(tiers.ENV_VAR, original)
            if original is not None
            else os.environ.pop(tiers.ENV_VAR, None)
        )
        os.environ[tiers.ENV_VAR] = "FAST"
        self.assertEqual(tiers.default_tier(), FAST)
        os.environ.pop(tiers.ENV_VAR)
        self.assertEqual(tiers.default_tier(), ALL)
        os.environ[tiers.ENV_VAR] = "nightly"
        with self.assertRaises(ValueError):
            tiers.default_tier()


if __name__ == "__main__":
    unittest.main()
