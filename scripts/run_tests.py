#!/usr/bin/env python3
"""Run one tier of the Veridor test suite.

    python3.12 scripts/run_tests.py --tier fast    # every commit
    python3.12 scripts/run_tests.py --tier slow    # before merge
    python3.12 scripts/run_tests.py                # both, the old behaviour

``python3.12 -m unittest discover -s tests`` still runs everything and is
unchanged; this script exists because unittest has no way to select a tier and
no way to hold one to a budget.

The fast tier is not a naming convention. It runs with
``tiers.install_fast_tier_guard()`` active, so a test that opens a listening
socket, connects to anything, or spawns a subprocess fails by name, and it is
held to a per-test budget so a pure test that grows into a four-second scale
test cannot quietly sit in the tier you run on every commit. The budget counts
what the test itself spends, CPU time and sleeps, so a busy machine does not
fail a run in which every test passed.

Every tier fails unless it started every test it selected, or a class or
module fixture skipped or failed it as unittest does, and a tier that selects
no test at all fails: running nothing is not a pass.

``--jobs N`` runs the slow tier in N worker processes that take whole test
classes from one queue, in discovery order, and fails unless every worker
finished and together they started exactly the tests a serial run selects,
each once. A class that a setUpClass or setUpModule skipped in a worker runs
again, alone, after the others finish, so a skip caused by another worker
cannot excuse it. The fast tier and ``all`` refuse ``--jobs``: the fast guard,
its budget and its stdout check assume one process.
"""

from __future__ import annotations

import argparse
import collections
import functools
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

#: The oldest interpreter this project runs on, matching ``requires-python``.
MINIMUM_PYTHON = (3, 11)

if sys.version_info < MINIMUM_PYTHON:
    # On macOS the bare ``python3`` is 3.9, and this script is one of the two
    # commands the README asks a contributor to run. Without this guard 3.9
    # does not refuse: it collects the handful of modules that happen to import
    # cleanly and reports "Ran 34 tests ... FAILED (failures=3, errors=14)",
    # which reads as a broken repository rather than a wrong interpreter.
    sys.stderr.write(
        "run_tests.py needs Python {}.{} or newer; this is {}.{} ({}).\n"
        "Nothing was run. On macOS the bare `python3` is 3.9 -- name the "
        "version instead:\n"
        "    python3.12 scripts/run_tests.py --tier fast\n".format(
            MINIMUM_PYTHON[0],
            MINIMUM_PYTHON[1],
            sys.version_info[0],
            sys.version_info[1],
            sys.executable,
        )
    )
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
# src/ goes first unless VERIDOR_TEST_AGAINST=installed; see tests/source_path.py.
import source_path  # noqa: E402,F401

from loopback import WORKER_ENV  # noqa: E402 -- each worker's share of the test ports


def nested_share(parent: str, index: int, count: int) -> str:
    """The share worker INDEX of COUNT runs under: a level appended to the
    share of the process that started it, not a new one. A --jobs run started
    inside a worker (the suite does this) splits that worker's share only; the
    runner used to overwrite the variable, so a nested worker's ports
    overlapped every outer worker's but its own parent's (measured)."""
    return ",".join(part for part in (parent, f"{index}/{count}") if part)
from tiers import (  # noqa: E402
    ALL,
    FAST,
    SLOW,
    TIERS,
    default_tier,
    filter_suite,
    install_fast_tier_guard,
    iter_tests,
)

#: No fast-tier test may cost more than this, in CPU seconds plus the seconds
#: it asked time.sleep for. The one scale test that used to cost four seconds
#: cannot come back unnoticed on any machine, and the costliest test left spends
#: about 0.25 s of CPU on an Apple M4 (measured), so a slower machine has room.
#:
#: It was one second on a wall clock. On a machine doing other work a test waits
#: for a core, so runs that printed "OK" exited 1 naming a different test each
#: time: with 30 busy processes on 10 CPUs, one such test took 1.22 s and spent
#: 0.38 s (measured). Waiting for a core costs a test no CPU and no sleep. A
#: time.sleep is counted as asked for, so a test or fixture that calls it past
#: the budget still fails, whatever the machine is doing. Only time.sleep is
#: metered: the ceiling below is all that holds any other wait. CPU time does
#: grow on a slower core: at background priority the same test spent 1.47 s,
#: which is why the limit also moved from one second to two.
FAST_TEST_BUDGET_SECONDS = 2.0

#: The limit on the wall clock, 15 times the budget. A test can wait without
#: calling time.sleep (Event.wait, a lock, a queue, asyncio.sleep, a select
#: timeout), which the budget cannot see, and this is what stops that wait
#: growing without limit. So such a test passes with a note up to here, where
#: under a one-second wall clock it failed: that is the price of not failing a
#: busy machine. This limit and the next can still be tripped by a busy machine,
#: so they sit well above the worst measured stall and their messages say so.
FAST_TEST_WALL_CEILING_SECONDS = 30.0

#: The limit on the whole tier's wall clock. Without it, tests that each wait
#: just under the ceiling add up with nothing to stop them, and a tier nobody
#: waits for is the thing the split exists to prevent. The tier takes about 15 s
#: on an Apple M4 (measured), so this is 20 times that; no ratio to a real runner
#: has been measured, so that is a margin and not a measurement.
FAST_TIER_WALL_CEILING_SECONDS = 300.0

#: Warn at this fraction of the budget. CPU time still grows on a slower
#: machine, and a shared CI runner is usually slower than a laptop. A test that
#: passes every local run can miss the budget there, after the merge, where it
#: blocks the jobs behind it. A green local run that is one slower machine away
#: from red is not information anybody can act on, so say it before it fails.
#:
#: 0.20 allows for a machine 5 times slower. No ratio to a real runner has been
#: measured for this tree, so that is a margin and not a measurement.
FAST_TEST_HEADROOM_FRACTION = 0.20

#: With --jobs, a worker still running this long after the start is killed,
#: with everything it started, and the run fails naming the test it was in. The
#: whole serial slow tier takes about five minutes; the CI job's own timeout
#: would stop a hung run too, but say nothing about where it hung.
SHARD_TIMEOUT_SECONDS = 1200

#: How a worker's report file ends when the worker got to the end.
_DONE = "done"


def _emit(events: io.TextIOBase | None, **event: object) -> None:
    """One line of a report, flushed at once so a worker that dies leaves it.
    ``at`` is seconds on this process's monotonic clock."""
    if events is not None:
        events.write(json.dumps({**event, "at": round(time.monotonic(), 3)}, sort_keys=True) + "\n")
        events.flush()


class _SleepMeter:
    """Stands in for time.sleep during the fast tier and adds up what it was
    asked for. It goes in before discovery, because core.py and matrix.py take
    ``time.sleep`` as a default argument when they are imported. A test that
    mocks time.sleep replaces this too, and sleeps for nothing."""

    def __init__(self, real: object) -> None:
        self.real = real
        self.slept = 0.0

    def __call__(self, seconds: float) -> None:
        self.real(seconds)  # type: ignore[operator]
        self.slept += seconds


class _TimedResult(unittest.TextTestResult):
    """A result that remembers what each test cost, and what it printed.

    Stdout is captured per test so a test that forgets to redirect it can be
    named. One did: ``report`` prints the path it wrote, and an uncaptured
    ``main()`` call put an absolute ``/var/folders/...`` temp path on stdout
    after unittest's own ``OK`` line, in the output of the one command this
    project asks contributors to run on every commit. Unittest writes its own
    progress to stderr, so nothing here interferes with the report.

    It records each test's start, each test's outcome, and each class or
    module fixture that failed or skipped, in ``recorded``; with ``events`` (a
    text file) it also writes them as JSON lines as the run goes, flushed as
    they happen, so a worker that dies leaves behind exactly how far it got.

    ``fixture_durations`` is the time between one class's last test and the
    next class's first, and before the first and after the last: where
    unittest runs setUpClass, setUpModule and their teardowns, outside every
    startTest-stopTest window. The budget used to read only ``durations``, so
    a class that slept 1.5 s in setUpClass recorded 0.0 s and the fast tier
    exited 0 (measured).

    Those two hold wall-clock seconds. ``costs`` holds, under the same names,
    what the budget reads: the process's CPU time over that window plus what
    ``meter`` saw it sleep, the sleep capped at the window's own length because
    a thread left over from an earlier test can sleep during this one.
    """

    def __init__(self, *args: object, events: io.TextIOBase | None = None,
                 meter: _SleepMeter | None = None, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.durations: dict[str, float] = {}
        self.fixture_durations: dict[str, float] = {}
        self.costs: dict[str, float] = {}
        self.meter = meter
        self.printed: dict[str, str] = {}
        self.events = events
        self.recorded: list[dict] = []
        self._started = (0.0, 0.0, 0.0)
        self._buffer: io.StringIO | None = None
        self._stdout: object = None
        self._outcome: str | None = None
        self._boundary: tuple[float, float, float] | None = None
        self._last_class: str | None = None

    def _now(self) -> tuple[float, float, float]:
        """(wall clock, CPU time, seconds slept) as of now."""
        return (time.perf_counter(), time.process_time(),
                self.meter.slept if self.meter is not None else 0.0)

    def _charge(self, name: str, since: tuple[float, float, float],
                now: tuple[float, float, float]) -> float:
        """Record what ``name`` cost between two readings; return its wall time."""
        wall = now[0] - since[0]
        self.costs[name] = now[1] - since[1] + min(now[2] - since[2], wall)
        return wall

    def _fixtures(self, after: str | None, before: str | None) -> None:
        """Charge the time since the last boundary to the class and module
        fixtures between class ``after`` and class ``before``."""
        if self._boundary is None:
            return
        where = " and ".join(part for part in (
            f"after {after}" if after else "", f"before {before}" if before else "") if part)
        name = f"class and module fixtures {where}"
        self.fixture_durations[name] = self._charge(name, self._boundary, self._now())

    def startTestRun(self) -> None:
        super().startTestRun()
        self._boundary = self._now()

    def stopTestRun(self) -> None:
        if self._last_class is not None:
            self._fixtures(self._last_class, None)
        super().stopTestRun()

    def emit(self, **event: object) -> None:
        self.recorded.append(dict(event))
        _emit(self.events, **event)

    def startTest(self, test: unittest.TestCase) -> None:
        case = f"{type(test).__module__}.{type(test).__qualname__}"
        if case != self._last_class:
            self._fixtures(self._last_class, case)
            self._last_class = case
        self.emit(event="start", id=test.id())
        self._outcome = None
        self._buffer = io.StringIO()
        self._stdout = sys.stdout
        sys.stdout = self._buffer
        self._started = self._now()
        super().startTest(test)

    def stopTest(self, test: unittest.TestCase) -> None:
        super().stopTest(test)
        self._boundary = self._now()
        self.durations[test.id()] = self._charge(test.id(), self._started, self._boundary)
        self.emit(event="outcome", id=test.id(), outcome=self._outcome or "ok",
                  seconds=round(self.durations[test.id()], 3))
        if self._buffer is not None:
            sys.stdout = self._stdout  # type: ignore[assignment]
            leaked = self._buffer.getvalue()
            if leaked.strip():
                self.printed[test.id()] = leaked
            self._buffer = None

    def _note(self, test: object, outcome: str) -> None:
        # A class or module fixture's error or skip arrives as unittest's
        # _ErrorHolder, which is not a TestCase and was never started.
        if not isinstance(test, unittest.TestCase):
            self.emit(event="fixture", id=str(test), outcome=outcome)
        elif self._outcome in (None, "ok"):
            self._outcome = outcome

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._note(test, "ok")

    def addFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addFailure(test, err)  # type: ignore[arg-type]
        self._note(test, "fail")

    def addError(self, test: unittest.TestCase, err: object) -> None:
        super().addError(test, err)  # type: ignore[arg-type]
        self._note(test, "error")

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._note(test, "skip")

    def addExpectedFailure(self, test: unittest.TestCase, err: object) -> None:
        super().addExpectedFailure(test, err)  # type: ignore[arg-type]
        self._note(test, "expected-failure")

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self._note(test, "unexpected-success")

    def addSubTest(self, test: unittest.TestCase, subtest: unittest.TestCase,
                   err: object) -> None:
        super().addSubTest(test, subtest, err)  # type: ignore[arg-type]
        if err is not None:
            failed = issubclass(err[0], test.failureException)  # type: ignore[index]
            self._note(test, "fail" if failed else "error")


def _wall(result: _TimedResult) -> dict[str, float]:
    """Every test's wall-clock time, and every stretch of class and module fixtures."""
    return {**result.durations, **result.fixture_durations}


def _over_budget(result: _TimedResult) -> list[tuple[str, float]]:
    """What spent more than the budget in CPU and sleep."""
    return sorted(
        (
            (test_id, seconds)
            for test_id, seconds in result.costs.items()
            if seconds > FAST_TEST_BUDGET_SECONDS
        ),
        key=lambda item: -item[1],
    )


def _over_ceiling(result: _TimedResult) -> list[tuple[str, float]]:
    """What took longer than the wall-clock ceiling, whatever it spent."""
    return sorted(
        (
            (test_id, seconds)
            for test_id, seconds in _wall(result).items()
            if seconds > FAST_TEST_WALL_CEILING_SECONDS
        ),
        key=lambda item: -item[1],
    )


def _near_budget(result: _TimedResult) -> list[tuple[str, float]]:
    """Tests that pass here and would fail on a machine a fifth as fast.

    Reported, never fatal. The budget is the contract; this is the warning
    track in front of it.
    """
    floor = FAST_TEST_BUDGET_SECONDS * FAST_TEST_HEADROOM_FRACTION
    return sorted(
        (
            (test_id, seconds)
            for test_id, seconds in result.costs.items()
            if floor < seconds <= FAST_TEST_BUDGET_SECONDS
        ),
        key=lambda item: -item[1],
    )


def _waited(result: _TimedResult) -> list[tuple[str, float]]:
    """What took longer than the budget on the wall clock and is within it in
    CPU and sleep: the machine was busy, or the test waits on something the
    budget cannot see. Reported, so such a wait is not invisible below the
    ceiling; never fatal."""
    return sorted(
        (
            (test_id, seconds)
            for test_id, seconds in _wall(result).items()
            if seconds > FAST_TEST_BUDGET_SECONDS >= result.costs.get(test_id, 0.0)
            and seconds <= FAST_TEST_WALL_CEILING_SECONDS
        ),
        key=lambda item: -item[1],
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one tier of the Veridor test suite.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "fast -- pure unit tests, no sockets, no subprocesses. "
            "Run on every commit.\n"
            "slow -- live loopback targets and subprocesses. "
            "Run before merge.\n"
            "all  -- both, in one process, with no guard."
        ),
    )
    parser.add_argument(
        "--tier",
        choices=TIERS,
        default=None,
        help=f"which tier to run (default: $VERIDOR_TEST_TIER, else {ALL})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="pass through to unittest; repeat for more",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the selected test ids and exit without running them",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="slow tier only: run it in N worker processes taking whole test "
        "classes from one queue, and fail unless every worker finished and "
        "together they started exactly the serial selection (default: 1, this "
        "process)",
    )
    parser.add_argument(
        "--shard-timeout",
        type=float,
        default=SHARD_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"with --jobs: kill every worker still running this long after the "
        f"start, and fail (default: {SHARD_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="write each test's start and outcome, and each class or module "
        "fixture that failed or skipped, to PATH as JSON lines",
    )
    # How --jobs starts a worker: the two pipe descriptors it talks to the parent on.
    parser.add_argument("--worker", metavar="FDS", help=argparse.SUPPRESS)
    return parser


def jobs_refusal(jobs: int, tier: str, worker: str | None = None) -> str | None:
    """Why this combination of --jobs, --tier and --worker cannot run, or None."""
    if jobs < 1:
        return f"--jobs {jobs}: the number of worker processes must be 1 or more. Nothing was run."
    if jobs > 1 and tier != SLOW:
        return (
            f"--jobs shards the slow tier only, not the {tier} tier. The fast tier's "
            "guard, its per-test budget and its stdout check each assume one "
            "process, and `all` runs the fast tier. Nothing was run."
        )
    if worker is not None and (tier != SLOW or jobs != 1):
        return "--worker is one slow-tier worker for --jobs, alone. Nothing was run."
    return None


# ---------------------------------------------------------------------------
# --jobs: the slow tier over N processes
# ---------------------------------------------------------------------------


def shard_units(suite: unittest.TestSuite) -> list[list[unittest.TestCase]]:
    """The selected tests grouped by test class, in discovery order.

    A class is the smallest thing a worker is handed. Split, its setUpClass
    would run in two processes and its tests would stop sharing what it set
    up. Loader errors (unittest's _FailedTest) are one class, so a module that
    failed to import still fails whichever worker takes it.
    """
    units: dict[type, list[unittest.TestCase]] = {}
    for test in iter_tests(suite):
        units.setdefault(type(test), []).append(test)
    return list(units.values())


def _identity() -> dict[str, str]:
    """Which interpreter and which Veridor this process runs the tests against."""
    import veridor  # noqa: PLC0415 -- after source_path, so it is the one the tests import

    return {"python": sys.executable, "version": sys.version.split()[0],
            "veridor": str(Path(veridor.__file__).resolve().parent)}


def read_report(path: Path) -> list[dict]:
    """A worker's JSON lines; a torn last line (the worker died mid-write) is dropped."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    events = []
    for line in text.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            break
    return events


def _covered_by_a_fixture(test_id: str, fixtures: list[str]) -> bool:
    """Whether a setUpClass or setUpModule that failed or skipped kept this test
    from starting, as it would in a serial run. unittest names them
    ``setUpClass (module.Class)`` and ``setUpModule (module)``."""
    for description in fixtures:
        scope = description.rpartition(" (")[2].rstrip(")")
        if description.startswith(("setUpClass (", "setUpModule (")) and test_id.startswith(scope + "."):
            return True
    return False


def _started_and_fixtures(events: list[dict]) -> tuple[list[str], list[str]]:
    return ([event["id"] for event in events if event.get("event") == "start"],
            [event["id"] for event in events if event.get("event") == "fixture"])


def worker_problems(assigned: list[str], events: list[dict], returncode: int | None,
                    identity: dict[str, str], timed_out: float | None = None) -> list[str]:
    """Why one worker's run does not count as having run what it was handed, or [].

    A worker counts only if it started every test it was handed (or unittest
    skipped them with their class, as a serial run would), started nothing
    else, ran them against the same interpreter and Veridor as this process,
    reached the end, and exited 0. Failing tests are its own report's
    business; this is whether the report can be trusted at all.
    """
    problems = []
    header = next((event for event in events if event.get("event") == "worker"), None)
    done = events[-1] if events and events[-1].get("event") == _DONE else None
    started, fixtures = _started_and_fixtures(events)
    finished = {event["id"] for event in events if event.get("event") == "outcome"}
    unknown = [test_id for event in events if event.get("event") == "unknown" for test_id in event["ids"]]
    if timed_out is not None:
        problems.append(f"timed out after {timed_out:g}s and was killed")
    if header is None:
        problems.append(f"wrote no report (exit {returncode}): it stopped before running a test")
    elif {key: header.get(key) for key in identity} != identity:
        problems.append(f"ran against {header.get('python')} and {header.get('veridor')}, "
                        f"not {identity['python']} and {identity['veridor']}")
    if unknown:
        problems.append(f"was handed {len(unknown)} test(s) its discovery does not have, first {unknown[0]}")
    in_flight = [test_id for test_id in started if test_id not in finished]
    if in_flight:
        problems.append(f"stopped inside {in_flight[-1]}")
    if done is None and header is not None and timed_out is None:
        problems.append(f"died (exit {returncode}) before it finished")
    extra = collections.Counter(started) - collections.Counter(assigned)
    problems += [f"ran a test it was not handed: {test_id}" for test_id in sorted(extra)]
    missing = collections.Counter(assigned) - collections.Counter(started)
    unexplained = sorted(test_id for test_id in missing if not _covered_by_a_fixture(test_id, fixtures))
    if unexplained and done is not None:
        problems.append(f"never started {len(unexplained)} of the tests it was handed, first {unexplained[0]}")
    if done is not None and done.get("successful") and returncode != 0:
        problems.append(f"reported success and exited {returncode}")
    return problems


def serial_problems(selected: list[str], recorded: list[dict],
                    escaped: BaseException | None = None) -> list[str]:
    """Why a serial run does not count as having run its selection, or [].

    unittest catches only Exception in setUpClass, setUpModule, tearDownClass
    and tearDownModule, so a SystemExit there -- argparse's --version or --help
    in a fixture that calls a CLI's main() -- leaves ``runner.run`` and ends
    the process with its code. It ended every serial tier with exit 0, no
    "Ran" line and nothing after it run (measured); only --jobs noticed. The
    run counts only if it got to the end and started every selected test, or
    a class or module fixture skipped or failed it, as unittest does."""
    problems = []
    if escaped is not None:
        code = escaped.code if isinstance(escaped, SystemExit) else None
        problems.append(f"{type(escaped).__name__}({code!r}) escaped unittest from a class or module "
                        "fixture, which unittest does not catch, and stopped the run there")
    started, fixtures = _started_and_fixtures(recorded)
    missing = collections.Counter(selected) - collections.Counter(started)
    never = sorted(test_id for test_id in missing if not _covered_by_a_fixture(test_id, fixtures))
    if never:
        problems.append(f"never started {len(never)} of the {len(selected)} selected tests, first {never[0]}")
    return problems


def run_problems(selected: list[str], reports: list[list[dict]]) -> list[str]:
    """Whether the workers, between them, started exactly what a serial run
    selects -- each test once. A test a class fixture skipped or failed counts
    as it would serially: selected, not started."""
    started: collections.Counter = collections.Counter()
    fixtures: list[str] = []
    for events in reports:
        ids, found = _started_and_fixtures(events)
        started.update(ids)
        fixtures += found
    wanted = collections.Counter(selected)
    problems = [f"started by no worker: {test_id}" for test_id in sorted(wanted - started)
                if not _covered_by_a_fixture(test_id, fixtures)]
    for test_id in sorted(started - wanted):
        problems.append(f"started more than once: {test_id}" if test_id in wanted
                        else f"started, and not in the serial selection: {test_id}")
    return problems


def _kill(process: subprocess.Popen) -> None:
    """The worker and everything it started: it leads its own session."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    process.wait()


class _UnitsFromParent(unittest.TestSuite):
    """A worker's suite: the tests of each class the parent hands it, as they arrive.

    unittest's own TestSuite.run does the rest -- setUpClass and tearDownClass
    as the class changes, and the result -- exactly as in a serial run. The
    parent is told a class is done when the worker asks for the next one.
    """

    _cleanup = False  # _removeTestAtIndex indexes _tests, which this suite never fills

    def __init__(self, commands: io.TextIOBase, acks: io.TextIOBase,
                 tests: dict[str, collections.deque], events: io.TextIOBase) -> None:
        super().__init__()
        self.commands, self.acks, self.tests, self.events = commands, acks, tests, events

    def __iter__(self):
        for line in self.commands:
            unit = json.loads(line)
            missing = [test_id for test_id in unit["ids"] if not self.tests.get(test_id)]
            if missing:
                _emit(self.events, event="unknown", ids=missing)
                raise RuntimeError(f"the parent handed this worker {len(missing)} test(s) "
                                   f"its discovery does not have, first {missing[0]}")
            yield from [self.tests[test_id].popleft() for test_id in unit["ids"]]
            self.acks.write(f"{unit['unit']}\n")
            self.acks.flush()


def _run_worker(suite: unittest.TestSuite, fds: str, args: argparse.Namespace) -> int:
    """A worker: run each class the parent hands it until the parent has no more."""
    if not args.report:
        print("--worker needs --report: the report is how the parent counts what ran.",
              file=sys.stderr)
        return 2
    command_fd, ack_fd = (int(fd) for fd in fds.split(","))
    for fd in (command_fd, ack_fd):
        os.set_inheritable(fd, False)  # a test's own subprocesses must not hold them
    tests: dict[str, collections.deque] = collections.defaultdict(collections.deque)
    for test in iter_tests(suite):
        tests[test.id()].append(test)
    with open(args.report, "w", encoding="utf-8") as events, \
            os.fdopen(command_fd, "r", encoding="utf-8") as commands, \
            os.fdopen(ack_fd, "w", encoding="utf-8") as acks:
        _emit(events, event="worker", **_identity())
        runner = unittest.TextTestRunner(verbosity=1 + args.verbose,
                                         resultclass=functools.partial(_TimedResult, events=events))
        result = runner.run(_UnitsFromParent(commands, acks, tests, events))
        _emit(events, event=_DONE, tests_run=result.testsRun, failures=len(result.failures),
              errors=len(result.errors), skipped=len(result.skipped),
              successful=result.wasSuccessful())
    return 0 if result.wasSuccessful() else 1


def worker_command(report: Path, fds: tuple[int, int], verbose: int = 0) -> list[str]:
    """How --jobs starts one worker: this script, this interpreter, its flags."""
    return [sys.executable, *subprocess._args_from_interpreter_flags(), str(Path(__file__).resolve()),
            "--tier", SLOW, "--worker", f"{fds[0]},{fds[1]}", "--report", str(report),
            *["-v"] * verbose]


def _feed(worker: dict, units: list[list[str]], queue: collections.deque,
          lock: threading.Lock) -> None:
    """Hand one worker classes from the shared queue, one at a time, until the
    queue is empty or the worker is gone; then close its command pipe."""
    try:
        while True:
            with lock:
                if not queue:
                    return
                index = queue.popleft()
            try:
                worker["commands"].write(json.dumps({"unit": index, "ids": units[index]}) + "\n")
                worker["commands"].flush()
            except OSError:  # it died between classes; this class is reported as handed to no one
                return
            worker["handed"].append(index)
            if not worker["acks"].readline():  # it died with this class in hand
                return
    finally:
        try:
            worker["commands"].close()
        except OSError:
            pass


def _usable_cpus() -> int | None:
    """The CPUs this process may run on (a container's cpuset, not the host's count)."""
    if hasattr(os, "sched_getaffinity"):
        return len(os.sched_getaffinity(0))
    return os.cpu_count()


def _is_setup_skip(event: dict) -> bool:
    """A setUpClass or setUpModule that raised SkipTest in a worker."""
    return (event.get("event") == "fixture" and event.get("outcome") == "skip"
            and str(event.get("id", "")).startswith(("setUpClass (", "setUpModule (")))


def skipped_by_a_setup(units: list[list[str]], reports: list[list[dict]]) -> list[int]:
    """The classes no worker started because a setUpClass or setUpModule
    skipped them.

    A serial run excuses those tests too, but the skip was decided in a
    worker, with other workers running beside it -- and setUpModule runs once
    per worker. A skip that depends on the machine (a lock, a busy port, a git
    call that failed under contention) can happen there and not serially: a
    class that skipped while another class held a lock ran serially and was
    excused under --jobs 2, 3 runs of 3 each, and the run passed (measured).
    So these classes run again, alone, after every other worker has finished."""
    started, fixtures = set(), []
    for events in reports:
        ids, found = _started_and_fixtures(events)
        started.update(ids)
        fixtures += [event["id"] for event in events if _is_setup_skip(event)]
    return [index for index, unit in enumerate(units)
            if not started.intersection(unit)
            and all(_covered_by_a_fixture(test_id, fixtures) for test_id in unit)]


def _start_workers(units: list[list[str]], indices: list[int], jobs: int, args: argparse.Namespace,
                   command, workdir: Path, label: str) -> list[dict]:
    """Up to ``jobs`` workers pulling the classes ``indices`` names from one
    queue, in that order; each worker is killed, with everything it started,
    if it is still running --shard-timeout after the start. Returns each
    worker with what it was handed, its exit, its report and its output."""
    queue = collections.deque(indices)
    lock = threading.Lock()
    count = max(1, min(jobs, len(indices)))
    workers: list[dict] = []
    try:
        for index in range(count):
            command_read, command_write = os.pipe()
            ack_read, ack_write = os.pipe()
            log = open(workdir / f"{label}-{index}.log", "w+", encoding="utf-8")
            report = workdir / f"{label}-{index}.jsonl"
            try:
                process = subprocess.Popen(
                    command(report, (command_read, ack_write), args.verbose),
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    pass_fds=(command_read, ack_write), start_new_session=True,
                    env={**os.environ, WORKER_ENV: nested_share(os.environ.get(WORKER_ENV, ""), index, count)})
            finally:
                os.close(command_read)
                os.close(ack_write)
            worker = {"index": index, "count": count, "label": label, "log": log, "report": report,
                      "process": process, "commands": os.fdopen(command_write, "w", encoding="utf-8"),
                      "acks": os.fdopen(ack_read, "r", encoding="utf-8"),
                      "handed": [], "began": time.perf_counter(), "timed_out": None}
            worker["feeder"] = threading.Thread(target=_feed, args=(worker, units, queue, lock),
                                                daemon=True)
            worker["feeder"].start()
            workers.append(worker)
        deadline = time.monotonic() + args.shard_timeout
        running = list(workers)
        while running:
            for worker in list(running):
                if worker["process"].poll() is not None:
                    worker["seconds"] = time.perf_counter() - worker["began"]
                    running.remove(worker)
            if running and time.monotonic() > deadline:
                for worker in running:
                    worker["timed_out"] = args.shard_timeout
                    _kill(worker["process"])
                    worker["seconds"] = time.perf_counter() - worker["began"]
                running = []
            time.sleep(0.05)
    except BaseException:
        for worker in workers:
            _kill(worker["process"])
        raise
    finally:
        for worker in workers:
            worker["feeder"].join(timeout=5)
            if not worker["feeder"].is_alive():  # else it is blocked reading acks; leave them
                worker["acks"].close()
            worker["log"].seek(0)
            worker["output"] = worker["log"].read()
            worker["log"].close()
            worker["events"] = read_report(worker["report"])
            worker.setdefault("seconds", time.perf_counter() - worker["began"])
    return workers


def _run_sharded(suite: unittest.TestSuite, args: argparse.Namespace,
                 command=worker_command) -> int:
    """The slow tier over ``args.jobs`` workers pulling whole classes from one
    queue, in discovery order, then the classes a setUpClass or setUpModule
    skipped again, alone (skipped_by_a_setup). Fails unless every worker
    finished, each started exactly what it was handed, and together they
    started exactly the serial selection."""
    units = [[test.id() for test in unit] for unit in shard_units(suite)]
    selected = [test.id() for test in iter_tests(suite)]
    identity = _identity()
    workdir = Path(tempfile.mkdtemp(prefix="veridor-shards-"))
    started = time.perf_counter()
    retried: list[int] = []
    retry: list[dict] = []
    try:
        workers = _start_workers(units, list(range(len(units))), args.jobs, args, command, workdir, "worker")
        retried = skipped_by_a_setup(units, [worker["events"] for worker in workers])
        if retried:
            retry = _start_workers(units, retried, 1, args, command, workdir, "retry")
    finally:
        elapsed = time.perf_counter() - started
        shutil.rmtree(workdir, ignore_errors=True)

    failed: list[tuple[str, list[str]]] = []
    totals: collections.Counter = collections.Counter()
    for worker in workers + retry:
        returncode = worker["process"].returncode
        assigned = [test_id for index in worker["handed"] for test_id in units[index]]
        problems = worker_problems(assigned, worker["events"], returncode, identity,
                                   worker["timed_out"])
        done = worker["events"][-1] if worker["events"] and worker["events"][-1].get("event") == _DONE else {}
        for key in ("tests_run", "failures", "errors", "skipped"):
            totals[key] += done.get(key, 0)
        who = (f"worker {worker['index'] + 1}" if worker["label"] == "worker"
               else "the retry worker")
        of = f" of {worker['count']}" if worker["label"] == "worker" else ", alone"
        sys.stderr.write(f"\n--- {who}{of}: {len(worker['handed'])} classes, {len(assigned)} tests, "
                         f"{worker['seconds']:.1f}s, exit {returncode} ---\n")
        sys.stderr.write(worker["output"])
        sys.stderr.flush()
        if problems or returncode != 0 or done.get("successful") is not True:
            failed.append((who, problems or [f"exit {returncode}: its tests failed (above)"]))
    for label, wanted, pool in (("the queue", range(len(units)), workers), ("the retry", retried, retry)):
        never = sorted(set(wanted) - {i for worker in pool for i in worker["handed"]})
        if never:
            failed.append((label, [f"{len(never)} of {len(wanted)} classes were handed to no "
                                   f"worker, first {units[never[0]][0].rsplit('.', 1)[0]}"]))
    # A class that ran again is accounted for by the retry alone: the skip that
    # excused it in the first pass no longer counts.
    first_pass = [[event for event in worker["events"] if not (retried and _is_setup_skip(event))]
                  for worker in workers]
    totals["skipped"] -= sum(len(worker["events"]) - len(events)
                             for worker, events in zip(workers, first_pass))
    whole = run_problems(selected, first_pass + [worker["events"] for worker in retry])
    if whole:
        failed.append(("the run", whole[:10] + ([f"... and {len(whole) - 10} more"] if len(whole) > 10 else [])))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as report:
            _emit(report, event="run", tier=SLOW, workers=len(workers), **identity)
            for worker in workers + retry:
                tag = worker["index"] + 1 if worker["label"] == "worker" else "retry"
                for event in worker["events"]:
                    report.write(json.dumps({**event, "worker": tag}, sort_keys=True) + "\n")
            _emit(report, event=_DONE, successful=not failed, **totals)

    print(f"\n{SLOW} tier: {len(selected)} tests in {elapsed:.1f}s, {len(workers)} worker "
          f"processes, {len(units)} classes, {_usable_cpus()} CPUs; ran {totals['tests_run']}, "
          f"{totals['failures']} failed, {totals['errors']} errors, {totals['skipped']} skipped")
    if retried:
        again = sorted({event["id"] for worker in retry for event in worker["events"] if _is_setup_skip(event)})
        ran = sum(1 for worker in retry for event in worker["events"] if event.get("event") == "start")
        print(f"setUpClass or setUpModule skipped {len(retried)} class(es) in a worker; run again, alone, "
              f"they started {ran} test(s); skipped again, as a serial run would: {', '.join(again) or 'none'}")
    print("The fast tier holds the rest; run it too before you trust a green run.")
    if failed:
        print(f"\nSHARDED RUN FAILED: {len(failed)} of {len(workers) + len(retry)} workers or checks.",
              file=sys.stderr)
        for who, problems in failed:
            for problem in problems:
                print(f"  {who}: {problem}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    tier = args.tier or default_tier()
    refusal = jobs_refusal(args.jobs, tier, args.worker)
    if refusal:
        print(refusal, file=sys.stderr)
        return 2
    if tier != FAST:
        return _select_and_run(args, tier, None)
    meter = _SleepMeter(time.sleep)
    time.sleep = meter  # type: ignore[assignment]
    try:
        return _select_and_run(args, tier, meter)
    finally:
        time.sleep = meter.real  # type: ignore[assignment]


def _select_and_run(args: argparse.Namespace, tier: str, meter: _SleepMeter | None) -> int:
    loader = unittest.TestLoader()
    discovered = loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))
    suite = filter_suite(discovered, tier)
    selected = suite.countTestCases()

    if args.list:
        # Flattened, never iterated directly. ``filter_suite`` returns the raw
        # discovered suite for the ALL tier -- which is nested, one TestSuite
        # per module -- and only the two filtered tiers happen to come back
        # flat. Iterating the nested one yields TestSuite objects, which have
        # no ``.id()``, so the DEFAULT invocation was the one that crashed.
        for test in iter_tests(suite):
            print(test.id())
        return 0

    if args.worker is not None:
        return _run_worker(suite, args.worker, args)
    if selected == 0:
        # unittest's own runner reports success for an empty suite ("NO TESTS
        # RAN", exit 0), and so did every tier here, with --jobs too: a
        # discovery that found no test module passed every CI step (measured).
        print(f"the {tier} tier selected no tests: discovery under {ROOT / 'tests'} found none. "
              "Running nothing is not a pass.", file=sys.stderr)
        return 1
    if args.jobs > 1:
        return _run_sharded(suite, args)

    events = open(args.report, "w", encoding="utf-8") if args.report else None
    restore = install_fast_tier_guard() if tier == FAST else None
    made: list[_TimedResult] = []

    def result_class(*given: object, **kwargs: object) -> _TimedResult:
        made.append(_TimedResult(*given, events=events, meter=meter, **kwargs))
        return made[-1]

    escaped: SystemExit | None = None
    # Before the run: unittest empties a suite as it runs it.
    selected_ids = [test.id() for test in iter_tests(suite)]
    started = time.perf_counter()
    try:
        runner = unittest.TextTestRunner(verbosity=1 + args.verbose, resultclass=result_class)
        if events is not None:
            _emit(events, event="run", tier=tier, **_identity())
        try:
            result = runner.run(suite)
        except SystemExit as exc:  # from a fixture; see serial_problems
            escaped = exc
        else:
            _emit(events, event=_DONE, tests_run=result.testsRun, failures=len(result.failures),
                  errors=len(result.errors), skipped=len(result.skipped),
                  successful=result.wasSuccessful())
    finally:
        if restore is not None:
            restore()
        if events is not None:
            events.close()
    elapsed = time.perf_counter() - started

    print(f"\n{tier} tier: {selected} tests in {elapsed:.1f}s")
    if tier == SLOW:
        print("The fast tier holds the rest; run it too before you trust a green run.")
    incomplete = serial_problems(selected_ids, made[0].recorded if made else [], escaped)
    if incomplete:
        print(f"\nTHE {tier.upper()} TIER DID NOT RUN ITS SELECTION:", file=sys.stderr)
        for problem in incomplete:
            print(f"  {problem}", file=sys.stderr)
        return 1
    result = made[0]

    if tier == FAST:
        leaks = getattr(result, "printed", {})
        if leaks:
            print(
                "\nFAST TIER WROTE TO STDOUT: a test printed where the tier's "
                "own output goes, so its text lands after unittest's OK line.",
                file=sys.stderr,
            )
            for test_id, text in sorted(leaks.items()):
                first = text.strip().splitlines()[0]
                print(f"  {test_id}\n    {first}", file=sys.stderr)
            print(
                "Wrap the call in contextlib.redirect_stdout and assert on what "
                "it printed. Do not silence it.",
                file=sys.stderr,
            )
            return 1

        verdict = ("Every test passed; this failure is the time alone."
                   if result.wasSuccessful() else "Separately, tests failed; see above.")
        overruns = _over_budget(result)  # type: ignore[arg-type]
        if overruns:
            print(
                f"\nFAST TIER BUDGET EXCEEDED: no fast test may spend more than "
                f"{FAST_TEST_BUDGET_SECONDS:.1f}s of CPU time and sleep. {verdict}",
                file=sys.stderr,
            )
            for test_id, seconds in overruns:
                print(f"  {seconds:6.2f}s  {test_id}", file=sys.stderr)
            print(
                'Mark it @slow("...") or make it cheaper. A fast tier nobody '
                "waits for is the whole point.",
                file=sys.stderr,
            )
            return 1

        stalls = _over_ceiling(result)  # type: ignore[arg-type]
        if stalls:
            print(
                f"\nFAST TIER WALL-CLOCK CEILING EXCEEDED: no fast test may take longer than "
                f"{FAST_TEST_WALL_CEILING_SECONDS:.0f}s. {verdict}",
                file=sys.stderr,
            )
            for test_id, seconds in stalls:
                print(f"  {seconds:6.2f}s  {test_id}", file=sys.stderr)
            print(
                "Either it waits on something without sleeping (mark it @slow(\"...\") or "
                "stop the wait), or this machine stalled for that long; if so, run it again.",
                file=sys.stderr,
            )
            return 1

        if elapsed > FAST_TIER_WALL_CEILING_SECONDS:
            print(
                f"\nFAST TIER WALL-CLOCK CEILING EXCEEDED: the whole tier may take "
                f"{FAST_TIER_WALL_CEILING_SECONDS:.0f}s and this run took {elapsed:.0f}s. {verdict} "
                "Either its tests wait without sleeping, or this machine was very busy; "
                "if so, run it again.",
                file=sys.stderr,
            )
            return 1

        waits = _waited(result)  # type: ignore[arg-type]
        if waits:
            print(
                f"\nfast tier: {len(waits)} test(s) took over {FAST_TEST_BUDGET_SECONDS:.1f}s on "
                "the wall clock but not in CPU time and sleep. Not a failure. "
                "Either this machine was busy or they wait without sleeping:",
                file=sys.stderr,
            )
            for test_id, seconds in waits:
                print(f"  {seconds:6.2f}s  {test_id}", file=sys.stderr)

        # Not a failure. A test at 20% of the budget here is at 120% on a
        # runner six times slower, and the first anyone hears of it is a red
        # main with the E2E job stuck behind it.
        crowding = _near_budget(result)  # type: ignore[arg-type]
        if crowding:
            budget = FAST_TEST_BUDGET_SECONDS
            print(
                f"\nfast tier: {len(crowding)} test(s) above "
                f"{budget * FAST_TEST_HEADROOM_FRACTION:.2f}s, so within ~5x of "
                f"the {budget:.1f}s budget. Green here, at risk on a slower runner:",
                file=sys.stderr,
            )
            for test_id, seconds in crowding:
                print(
                    f"  {seconds:6.2f}s  ({seconds / budget:.0%} of budget)  {test_id}",
                    file=sys.stderr,
                )

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
