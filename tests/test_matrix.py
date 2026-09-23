"""The access matrix is the most dangerous thing Veridor can do.

Every test in this file exists because one of these gets it wrong exactly once:

* A run that sends ``|routes| x |identities|`` requests without showing the
  operator the number first, or without a cap, is a scanner.
* A run that probes mutating verbs because a flag was truthy is an incident.
* A cell that cannot tell "we did not measure this" apart from "the target
  refused this" understates blast radius, which is the dangerous direction: it
  reports a compromised account as reaching less than it does.
* An artifact carrying a token, a cookie, a header, or a response body breaks
  the invariant the whole product rests on.

So the assertions are deliberately blunt: count the requests, grep the JSON.
"""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import io
import json
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import matrix as matrix_module  # noqa: E402
from veridor.matrix import (  # noqa: E402
    ABORT_CONSECUTIVE_RATE_LIMITED,
    ABORT_CONSECUTIVE_SERVER_ERROR,
    ABORT_CONSECUTIVE_TRANSPORT,
    ABORT_HOSTILE_MINIMUM,
    ABORT_HOSTILE_SHARE,
    ABORT_TOTAL_RATE_LIMITED,
    CLAIM,
    MATRIX_ABSOLUTE_MAX_BUDGET,
    MATRIX_ABSOLUTE_MAX_RUN_SECONDS,
    MATRIX_DEFAULT_BUDGET,
    MATRIX_DEFAULT_RPS,
    MATRIX_KIND,
    MATRIX_MAX_RPS,
    MATRIX_MAX_SPECIMENS_PER_OPERATION,
    MATRIX_MAX_TIMEOUT_SECONDS,
    MATRIX_MUTATING_BUDGET,
    MATRIX_SAFE_METHODS,
    MUTATING_ACKNOWLEDGEMENT,
    OUTCOME_OBSERVED,
    OUTCOME_UNKNOWN,
    REACH_INDETERMINATE,
    REACH_REACHED,
    REACH_REFUSED,
    REACH_UNKNOWN,
    REFUSAL_ABSENT_OR_DENIED,
    REFUSAL_FORBIDDEN,
    REFUSAL_METHOD_NOT_SUPPORTED,
    REFUSAL_UNAUTHENTICATED,
    SCHEMA_VERSION,
    UNKNOWN_REASONS,
    AccessMatrix,
    MatrixBudgetError,
    MatrixError,
    MatrixOptions,
    MatrixSafetyError,
    classify_reach,
    classify_target,
    default_prober,
    execute_matrix,
    load_matrix,
    matrix_document,
    plan_matrix,
    probe_url,
    same_origin,
)
from veridor.openapi import (  # noqa: E402
    ALL_METHODS,
    DEFAULT_METHODS,
    RouteInventory,
    load_inventory,
    parse_spec,
)

FIXTURES = ROOT / "tests" / "fixtures"
MATRIX_CONFIG = FIXTURES / "matrix.demo.json"
MATRIX_SPEC = FIXTURES / "openapi.matrix.json"
MATRIX_SOURCE = (ROOT / "src" / "veridor" / "matrix.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def spec(paths: dict[str, Any], *, servers: list[dict[str, str]] | None = None) -> dict:
    document: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": paths,
    }
    if servers is not None:
        document["servers"] = servers
    return document


def inventory(
    paths: dict[str, Any],
    *,
    methods: frozenset[str] = ALL_METHODS,
    servers: list[dict[str, str]] | None = None,
) -> RouteInventory:
    return parse_spec(spec(paths, servers=servers), methods=methods)


def get_only(*templates: str) -> dict[str, Any]:
    return {template: {"get": {"responses": {"200": {"description": "ok"}}}} for template in templates}


def config(
    identities: dict[str, Any] | None = None,
    *,
    base_url: str = "http://127.0.0.1:8765",
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "version": 1,
        "target": {"base_url": base_url, "timeout_seconds": 3},
        "identities": identities
        if identities is not None
        else {
            "alice": {"headers": {"Authorization": "Bearer alice"}},
            "mallory": {"headers": {"Authorization": "Bearer mallory"}},
        },
        "checks": [],
    }
    if matrix is not None:
        document["matrix"] = matrix
    return document


def result(
    status: int | None = 200,
    *,
    error: str | None = None,
    body_bytes: int = 12,
    digest: str = "a" * 64,
    marker_scan: str | None = None,
    url: str = "http://127.0.0.1:8765/api/x",
    retry_after: bool = False,
    retry_after_in_response: bool = False,
) -> dict[str, Any]:
    """A dict shaped exactly like ``core._perform_request``'s return value.

    ``retry_after`` is the top-level key the ``Prober`` protocol documents for a
    custom prober; ``retry_after_in_response`` is where ``core`` puts the same
    presence-only boolean, and therefore what the DEFAULT prober returns. Both
    spellings exist here because only the first was ever exercised, which is how
    the abort branch came to be untestably unreachable in the shipped path.
    """
    document: dict[str, Any] = {
        "request": {"method": "GET", "url": url},
        "response": {
            "status": status,
            "duration_ms": 1.5,
            "body_bytes": body_bytes,
            "body_sha256": digest,
            "body_truncated": False,
            "marker_scan": marker_scan,
            "marker_scan_reason": None,
            "marker_encodings": [],
            "body_encoding": "identity",
            "body_scanned_bytes": body_bytes,
            "body_scan_truncated": False,
            "retry_after": retry_after_in_response,
        },
        "error": error,
    }
    if retry_after:
        document["retry_after"] = True
    return document


class RecordingProber:
    """Counts calls. The budget tests assert this stays at zero."""

    def __init__(self, responder: Callable[[Any], dict[str, Any]] | None = None) -> None:
        self.calls: list[Any] = []
        self._responder = responder or (lambda probe: result())

    def __call__(self, probe: Any) -> dict[str, Any]:
        self.calls.append(probe)
        return self._responder(probe)

    @property
    def count(self) -> int:
        return len(self.calls)


class FakeClock:
    """A monotonic clock that only advances when the sleeper sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def run(
    plan: Any, prober: Any, clock: FakeClock | None = None
) -> AccessMatrix:
    clock = clock or FakeClock()
    return execute_matrix(plan, prober=prober, clock=clock.time, sleeper=clock.sleep)


# ---------------------------------------------------------------------------
# 1. the budget refuses BEFORE anything is sent
# ---------------------------------------------------------------------------


class BudgetTest(unittest.TestCase):
    def test_over_budget_plan_refuses_and_sends_nothing(self) -> None:
        templates = get_only(*[f"/api/thing{index}" for index in range(30)])
        prober = RecordingProber()
        with self.assertRaises(MatrixBudgetError) as raised:
            plan_matrix(
                config(),
                inventory(templates),
                options=MatrixOptions(max_requests=10),
            )
        self.assertEqual(prober.count, 0)
        message = str(raised.exception)
        self.assertIn("60 requests", message)
        self.assertIn("budget of 10", message)
        self.assertIn("Nothing has been sent", message)
        # The operator is told the exact override that would permit it, and
        # what it would cost in wall clock.
        # Spelled as it is typed. The keyword form is what this module
        # takes; the operator reading it is holding a command line.
        self.assertIn("--max-requests 60", message)
        self.assertIn("req/s this run would take", message)

    def test_execute_rechecks_the_budget_itself(self) -> None:
        """A plan built inside the budget, then re-pointed at a smaller one."""
        plan = plan_matrix(config(), inventory(get_only("/a", "/b", "/c")))
        shrunk = dataclasses.replace(plan, options=MatrixOptions(max_requests=2))
        prober = RecordingProber()
        with self.assertRaises(MatrixBudgetError):
            run(shrunk, prober)
        self.assertEqual(prober.count, 0)

    def test_absolute_maximum_cannot_be_overridden(self) -> None:
        with self.assertRaises(MatrixSafetyError) as raised:
            MatrixOptions(max_requests=MATRIX_ABSOLUTE_MAX_BUDGET + 1)
        self.assertIn("cannot be overridden", str(raised.exception))

    def test_absolute_maximum_is_rechecked_on_a_hand_built_plan(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/a")))
        # One request over the real maximum, not twice it: the safety pass
        # before the budget check reads every probe, and 40,002 of them cost
        # 0.15 s idle and 0.30 s under load. At exactly one over, a check that
        # let MAX + 1 through fails here; at twice the maximum it passed.
        oversized = dataclasses.replace(
            plan,
            probes=plan.probes[:1] * (MATRIX_ABSOLUTE_MAX_BUDGET + 1),
            options=MatrixOptions(max_requests=MATRIX_ABSOLUTE_MAX_BUDGET),
        )
        self.assertEqual(oversized.requests_planned, MATRIX_ABSOLUTE_MAX_BUDGET + 1)
        prober = RecordingProber()
        with self.assertRaises(MatrixBudgetError) as raised:
            run(oversized, prober)
        self.assertEqual(prober.count, 0)
        self.assertIn("absolute maximum", str(raised.exception))

    def test_the_mutating_budget_reads_the_method_not_the_flag(self) -> None:
        # REGRESSION. The mutating budget and the banner's per-request listing
        # counted PlannedProbe.mutating, a free field. A hand-built plan whose
        # DELETE probes said mutating=False passed both, and could send up to
        # max_requests DELETEs with no MUTATING block in the banner.
        plan = plan_matrix(config(), inventory(get_only("/a")))
        options = MatrixOptions(
            max_requests=500,
            allow_mutating_methods=frozenset({"DELETE"}),
            mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT,
        )
        for flag in (True, False):
            with self.subTest(mutating=flag):
                delete = dataclasses.replace(
                    plan.probes[0], method="DELETE", mutating=flag
                )
                rogue = dataclasses.replace(
                    plan, probes=(delete,) * (MATRIX_MUTATING_BUDGET * 4), options=options
                )
                self.assertEqual(rogue.mutating_planned, MATRIX_MUTATING_BUDGET * 4)
                self.assertIn("MUTATING REQUESTS ARE ENABLED", rogue.banner())
                prober = RecordingProber()
                with self.assertRaises(MatrixBudgetError) as raised:
                    run(rogue, prober)
                self.assertEqual(prober.count, 0)
                self.assertIn("mutating budget", str(raised.exception))

    def test_default_budget_is_the_documented_number(self) -> None:
        self.assertEqual(MatrixOptions().max_requests, MATRIX_DEFAULT_BUDGET)
        self.assertEqual(MatrixOptions().requests_per_second, MATRIX_DEFAULT_RPS)
        self.assertEqual(MatrixOptions().allow_mutating_methods, frozenset())

    def test_banner_shows_the_number_before_anything_is_sent(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/a", "/b")))
        banner = plan.banner()
        self.assertIn("this will issue 4 requests to 127.0.0.1:8765", banner)
        self.assertIn("only against systems you own", banner)
        self.assertIn("read-only", banner)
        self.assertIn("sequential", banner)
        self.assertEqual(plan.requests_planned, 4)


# ---------------------------------------------------------------------------
# 2. read-only by default; mutating needs two gates
# ---------------------------------------------------------------------------


MUTATING_SPEC = {
    "/api/invoices/{id}": {
        "get": {"responses": {"200": {"description": "ok"}}},
        "delete": {"responses": {"204": {"description": "gone"}}},
    }
}
SPECIMENS = {"specimens": {"/api/invoices/{id}": [{"label": "one", "values": {"id": "inv-1"}}]}}


class ReadOnlyDefaultTest(unittest.TestCase):
    def plan(self, options: MatrixOptions | None = None) -> Any:
        return plan_matrix(
            config(matrix=dict(SPECIMENS)),
            inventory(MUTATING_SPEC),
            options=options or MatrixOptions(),
        )

    def test_mutating_verbs_are_not_probed_by_default(self) -> None:
        plan = self.plan()
        self.assertEqual({probe.method for probe in plan.probes}, {"GET"})
        skipped = {item.method: item.unknown_reason for item in plan.skipped}
        self.assertEqual(skipped, {"DELETE": "skipped_mutating"})

    def test_skipped_mutating_cells_exist_and_are_unknown_not_refused(self) -> None:
        matrix = run(self.plan(), RecordingProber())
        cell = matrix.cell("DELETE /api/invoices/{id}", "mallory", "one")
        self.assertIsNotNone(cell)
        assert cell is not None
        self.assertEqual(cell.reach, REACH_UNKNOWN)
        self.assertEqual(cell.outcome, OUTCOME_UNKNOWN)
        self.assertEqual(cell.unknown_reason, "skipped_mutating")
        self.assertIsNone(cell.refusal_kind)
        self.assertIsNone(cell.status)
        self.assertFalse(cell.measured)

    def test_verb_list_alone_is_refused(self) -> None:
        with self.assertRaises(MatrixSafetyError) as raised:
            MatrixOptions(allow_mutating_methods=frozenset({"DELETE"}))
        self.assertIn("acknowledgement", str(raised.exception))

    def test_acknowledgement_alone_is_refused(self) -> None:
        with self.assertRaises(MatrixSafetyError) as raised:
            MatrixOptions(mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT)
        self.assertIn("enables nothing", str(raised.exception))

    def test_wrong_acknowledgement_string_is_refused(self) -> None:
        for wrong in ("yes", MUTATING_ACKNOWLEDGEMENT.upper(), MUTATING_ACKNOWLEDGEMENT + "."):
            with self.subTest(wrong=wrong):
                with self.assertRaises(MatrixSafetyError):
                    MatrixOptions(
                        allow_mutating_methods=frozenset({"DELETE"}),
                        mutating_acknowledgement=wrong,
                    )

    def test_wildcards_are_refused(self) -> None:
        for wildcard in ("*", "ALL", "ANY"):
            with self.subTest(wildcard=wildcard):
                with self.assertRaises(MatrixSafetyError) as raised:
                    MatrixOptions(
                        allow_mutating_methods=frozenset({wildcard}),
                        mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT,
                    )
                self.assertIn("named literally", str(raised.exception))

    def test_both_gates_permit_exactly_the_named_verb(self) -> None:
        options = MatrixOptions(
            allow_mutating_methods=frozenset({"DELETE"}),
            mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT,
        )
        plan = self.plan(options)
        self.assertEqual({probe.method for probe in plan.probes}, {"GET", "DELETE"})
        self.assertEqual(plan.mutating_planned, 2)
        banner = plan.banner()
        self.assertIn("MUTATING REQUESTS ARE ENABLED", banner)
        # Every mutating request is listed, grouped by verb, before the first
        # one is sent.
        self.assertIn("DELETE (2)", banner)
        self.assertIn("/api/invoices/inv-1 as alice", banner)
        self.assertIn("/api/invoices/inv-1 as mallory", banner)

    def test_a_named_verb_does_not_enable_its_neighbours(self) -> None:
        paths = {
            "/api/x": {
                "delete": {"responses": {"204": {"description": "gone"}}},
                "post": {"responses": {"201": {"description": "made"}}},
            }
        }
        plan = plan_matrix(
            config(),
            inventory(paths),
            options=MatrixOptions(
                allow_mutating_methods=frozenset({"DELETE"}),
                mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT,
            ),
        )
        self.assertEqual({probe.method for probe in plan.probes}, {"DELETE"})
        self.assertEqual(
            {item.method for item in plan.skipped},
            {"POST"},
        )

    def test_execute_refuses_a_plan_whose_options_no_longer_permit_it(self) -> None:
        plan = self.plan(
            MatrixOptions(
                allow_mutating_methods=frozenset({"DELETE"}),
                mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT,
            )
        )
        stripped = dataclasses.replace(plan, options=MatrixOptions())
        prober = RecordingProber()
        with self.assertRaises(MatrixSafetyError):
            run(stripped, prober)
        self.assertEqual(prober.count, 0)

    def test_mutating_budget_is_separate_and_pre_flight(self) -> None:
        paths = {
            f"/api/thing{index}": {"delete": {"responses": {"204": {"description": "x"}}}}
            for index in range(MATRIX_MUTATING_BUDGET)
        }
        prober = RecordingProber()
        with self.assertRaises(MatrixBudgetError) as raised:
            plan_matrix(
                config(),
                inventory(paths),
                options=MatrixOptions(
                    allow_mutating_methods=frozenset({"DELETE"}),
                    mutating_acknowledgement=MUTATING_ACKNOWLEDGEMENT,
                ),
            )
        self.assertEqual(prober.count, 0)
        self.assertIn("mutating budget", str(raised.exception))

    def test_safe_methods_are_exactly_get_and_head(self) -> None:
        self.assertEqual(MATRIX_SAFE_METHODS, frozenset({"GET", "HEAD"}))


# ---------------------------------------------------------------------------
# 3. rate limiting
# ---------------------------------------------------------------------------


class RateLimitTest(unittest.TestCase):
    def test_n_requests_sleep_exactly_n_minus_one_intervals(self) -> None:
        plan = plan_matrix(
            config(), inventory(get_only("/a", "/b", "/c"))
        )  # 3 operations x 2 identities
        clock = FakeClock()
        run(plan, RecordingProber(), clock)
        interval = 1.0 / MATRIX_DEFAULT_RPS
        self.assertEqual(len(clock.sleeps), plan.requests_planned - 1)
        for slept in clock.sleeps:
            self.assertAlmostEqual(slept, interval, places=9)
        self.assertAlmostEqual(
            sum(clock.sleeps), (plan.requests_planned - 1) * interval, places=9
        )

    def test_the_rate_is_global_not_per_identity(self) -> None:
        """Six requests across two identities still cost five intervals."""
        plan = plan_matrix(config(), inventory(get_only("/a", "/b", "/c")))
        clock = FakeClock()
        run(plan, RecordingProber(), clock)
        self.assertEqual(plan.requests_planned, 6)
        self.assertEqual(len(clock.sleeps), 5)

    def test_the_limiter_really_delays_on_a_real_clock(self) -> None:
        plan = plan_matrix(
            config(),
            inventory(get_only("/a", "/b")),
            options=MatrixOptions(requests_per_second=MATRIX_MAX_RPS),
        )
        started = time.monotonic()
        execute_matrix(plan, prober=RecordingProber())
        elapsed = time.monotonic() - started
        # 4 requests at 10 req/s is 3 enforced intervals of 100ms.
        self.assertGreaterEqual(elapsed, 3 * (1.0 / MATRIX_MAX_RPS) * 0.95)

    def test_rate_over_the_ceiling_is_refused(self) -> None:
        with self.assertRaises(MatrixSafetyError) as raised:
            MatrixOptions(requests_per_second=MATRIX_MAX_RPS + 0.1)
        self.assertIn("ceiling", str(raised.exception))

    def test_non_positive_rate_is_refused(self) -> None:
        for value in (0, -1.0):
            with self.subTest(value=value):
                with self.assertRaises(MatrixSafetyError):
                    MatrixOptions(requests_per_second=value)

    def test_estimated_seconds_is_shown_before_the_run(self) -> None:
        plan = plan_matrix(
            config(),
            inventory(get_only("/a", "/b")),
            options=MatrixOptions(requests_per_second=1.0),
        )
        self.assertAlmostEqual(plan.estimated_seconds, 3.0)
        self.assertIn("estimated:  3s", plan.banner())

    def test_there_is_no_concurrency_switch(self) -> None:
        """v1 is sequential, deliberately, and offers no way to change that."""
        fields = {field.name for field in dataclasses.fields(MatrixOptions)}
        self.assertFalse(
            {"workers", "concurrency", "threads", "parallel"} & fields,
            "v1 must not expose a concurrency knob",
        )


# ---------------------------------------------------------------------------
# 4. unknown is never a denial
# ---------------------------------------------------------------------------


class UnknownIsNotDenialTest(unittest.TestCase):
    def test_reach_table(self) -> None:
        expected = {
            200: (REACH_REACHED, None, None),
            204: (REACH_REACHED, None, None),
            301: (REACH_INDETERMINATE, None, None),
            302: (REACH_INDETERMINATE, None, None),
            400: (REACH_INDETERMINATE, None, None),
            409: (REACH_INDETERMINATE, None, None),
            422: (REACH_INDETERMINATE, None, None),
            401: (REACH_REFUSED, REFUSAL_UNAUTHENTICATED, None),
            # The proxy's answer, not the target's: unmeasured (it was pinned
            # as a refusal of the credential, which let a drift gate pass).
            407: (REACH_UNKNOWN, None, "proxy_auth_required"),
            403: (REACH_REFUSED, REFUSAL_FORBIDDEN, None),
            404: (REACH_REFUSED, REFUSAL_ABSENT_OR_DENIED, None),
            405: (REACH_REFUSED, REFUSAL_METHOD_NOT_SUPPORTED, None),
            501: (REACH_REFUSED, REFUSAL_METHOD_NOT_SUPPORTED, None),
            418: (REACH_INDETERMINATE, None, None),
            429: (REACH_UNKNOWN, None, "rate_limited"),
            500: (REACH_UNKNOWN, None, "server_error"),
            503: (REACH_UNKNOWN, None, "server_error"),
            None: (REACH_UNKNOWN, None, "transport_error"),
        }
        for status, want in expected.items():
            with self.subTest(status=status):
                self.assertEqual(classify_reach(status), want)

    def test_a_throttle_and_a_crash_are_not_denials(self) -> None:
        for status in (429, 500, 503):
            reach, refusal, _ = classify_reach(status)
            self.assertNotEqual(reach, REACH_REFUSED)
            self.assertIsNone(refusal)

    def test_every_kind_of_unmeasured_cell_is_distinguishable_from_a_denial(self) -> None:
        """The correctness rule that keeps blast radius from being understated.

        Unprobed, skipped, errored, throttled and crashed cells all exist in the
        grid, all read ``unknown``, and none of them can be mistaken for the
        403 sitting next to them.
        """
        paths = {
            "/api/ok": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/denied": {"get": {"responses": {"403": {"description": "no"}}}},
            "/api/boom": {"get": {"responses": {"500": {"description": "no"}}}},
            "/api/throttled": {"get": {"responses": {"429": {"description": "no"}}}},
            "/api/broken": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/ignored": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/gone/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/deleteme": {"delete": {"responses": {"204": {"description": "ok"}}}},
        }
        responses = {
            "/api/ok": result(200),
            "/api/denied": result(403),
            "/api/boom": result(500),
            "/api/throttled": result(429),
            "/api/broken": result(None, error="the connection timed out"),
        }
        plan = plan_matrix(
            config(matrix={"ignore": ["/api/ignored"]}),
            inventory(paths),
        )
        matrix = run(plan, RecordingProber(lambda probe: responses[probe.path]))

        def cell(operation: str, specimen: str | None = None) -> Any:
            found = matrix.cell(operation, "alice", specimen)
            self.assertIsNotNone(found, operation)
            return found

        denial = cell("GET /api/denied")
        self.assertEqual(denial.reach, REACH_REFUSED)
        self.assertEqual(denial.refusal_kind, REFUSAL_FORBIDDEN)
        self.assertEqual(denial.outcome, OUTCOME_OBSERVED)
        self.assertTrue(denial.measured)

        unmeasured = {
            "GET /api/boom": "server_error",
            "GET /api/throttled": "rate_limited",
            "GET /api/broken": "transport_error",
            "GET /api/ignored": "skipped_ignored",
            "GET /api/gone/{id}": "skipped_no_specimen",
            "DELETE /api/deleteme": "skipped_mutating",
        }
        for operation, reason in unmeasured.items():
            with self.subTest(operation=operation):
                found = cell(operation)
                self.assertEqual(found.reach, REACH_UNKNOWN)
                self.assertEqual(found.outcome, OUTCOME_UNKNOWN)
                self.assertEqual(found.unknown_reason, reason)
                self.assertIn(reason, UNKNOWN_REASONS)
                self.assertIsNone(found.refusal_kind)
                self.assertFalse(found.measured)
                self.assertNotEqual(found.reach, denial.reach)

        # And the projection any consumer will write -- "count the refusals" --
        # cannot pick up a single unmeasured cell.
        refused = [item for item in matrix.cells if item.reach == REACH_REFUSED]
        self.assertEqual(
            {item.operation for item in refused}, {"GET /api/denied"}
        )

    def test_the_grid_is_dense(self) -> None:
        plan = plan_matrix(
            config(matrix={"ignore": ["/api/b"]}),
            inventory(get_only("/api/a", "/api/b", "/api/c")),
        )
        matrix = run(plan, RecordingProber())
        self.assertEqual(len(matrix.cells), len(plan.rows) * len(plan.identities))
        self.assertEqual(len(matrix.cells), 6)
        # every (row, identity) pair resolves; nothing is absent
        for operation, specimen in plan.rows:
            for identity in plan.identities:
                self.assertIsNotNone(matrix.cell(operation, identity, specimen))

    def test_a_redirect_is_never_folded_into_reach_or_refusal(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        matrix = run(plan, RecordingProber(lambda probe: result(302)))
        for cell in matrix.cells:
            self.assertEqual(cell.reach, REACH_INDETERMINATE)
            self.assertEqual(cell.status_class, "redirect")
            self.assertIsNone(cell.refusal_kind)

    def test_an_empty_body_is_still_reach(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        matrix = run(plan, RecordingProber(lambda probe: result(200, body_bytes=0)))
        for cell in matrix.cells:
            self.assertEqual(cell.reach, REACH_REACHED)
            self.assertTrue(cell.body_empty)


# ---------------------------------------------------------------------------
# 5. abort on hostile signals
# ---------------------------------------------------------------------------


class AbortTest(unittest.TestCase):
    def _plan(self, operations: int = 20) -> Any:
        return plan_matrix(
            config(),
            inventory(get_only(*[f"/api/thing{index}" for index in range(operations)])),
        )

    def test_three_consecutive_429s_abort(self) -> None:
        plan = self._plan()
        prober = RecordingProber(lambda probe: result(429))
        matrix = run(plan, prober)
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "rate_limited")
        self.assertEqual(prober.count, ABORT_CONSECUTIVE_RATE_LIMITED)
        self.assertEqual(matrix.issued, ABORT_CONSECUTIVE_RATE_LIMITED)
        self.assertLess(matrix.issued, matrix.planned)

    def test_a_polite_429_gets_the_same_tolerance_as_a_rude_one(self) -> None:
        """Not less, which is what reading the header as "go away" produced.

        Measured on one throttling target, 15 runs per arm with identical
        seeded 429 positions: with the header, 15/15 runs aborted and median
        grid coverage was 22%. With the SAME 429s and the header stripped,
        2/15 aborted and coverage was 78%. Being spec-compliant cost 3.5x.
        """
        plan = self._plan()
        prober = RecordingProber(lambda probe: result(429, retry_after=True))
        matrix = run(plan, prober)
        self.assertTrue(matrix.aborted)
        # The reason still names the header rather than the rule: the run did
        # stop because the target asked, it just asked three times.
        self.assertEqual(matrix.abort_reason, "retry_after_requested")
        self.assertEqual(prober.count, ABORT_CONSECUTIVE_RATE_LIMITED)
        self.assertEqual(matrix.retry_after_seen, ABORT_CONSECUTIVE_RATE_LIMITED)

    def test_stop_on_retry_after_is_still_available(self) -> None:
        """The old behaviour, now a choice rather than the only option."""
        plan = plan_matrix(
            config(),
            inventory(get_only(*[f"/api/thing{index}" for index in range(20)])),
            options=MatrixOptions(on_retry_after="stop"),
        )
        prober = RecordingProber(lambda probe: result(429, retry_after=True))
        matrix = run(plan, prober)
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "retry_after_requested")
        self.assertEqual(prober.count, 1)
        self.assertEqual(matrix.on_retry_after, "stop")

    def test_an_unknown_retry_after_policy_is_refused(self) -> None:
        with self.assertRaises(MatrixSafetyError):
            MatrixOptions(on_retry_after="sleep")

    def test_retry_after_aborts_from_the_core_result_shape_too(self) -> None:
        """The spelling the DEFAULT prober actually produces.

        This branch was reachable only through the top-level key a custom
        prober sets, which no shipped code path sets. ``_perform_request``
        carries the boolean inside ``response``, so a target that said
        "Retry-After" on its first 429 fell through to the consecutive-429 rule
        and received two more requests -- three times the documented politeness.
        """
        plan = self._plan()
        prober = RecordingProber(
            lambda probe: result(429, retry_after_in_response=True)
        )
        matrix = run(plan, prober)
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "retry_after_requested")
        self.assertEqual(matrix.retry_after_seen, ABORT_CONSECUTIVE_RATE_LIMITED)

    def test_the_same_429_without_the_header_still_takes_three(self) -> None:
        """The control: the two paths must be distinguishable."""
        plan = self._plan()
        prober = RecordingProber(lambda probe: result(429))
        matrix = run(plan, prober)
        self.assertEqual(matrix.abort_reason, "rate_limited")
        self.assertEqual(prober.count, ABORT_CONSECUTIVE_RATE_LIMITED)

    def test_five_consecutive_server_errors_abort(self) -> None:
        plan = self._plan()
        prober = RecordingProber(lambda probe: result(500))
        matrix = run(plan, prober)
        self.assertEqual(matrix.abort_reason, "server_error")
        self.assertEqual(prober.count, ABORT_CONSECUTIVE_SERVER_ERROR)

    def test_ten_consecutive_transport_errors_abort(self) -> None:
        plan = self._plan()
        prober = RecordingProber(
            lambda probe: result(None, error="the connection timed out")
        )
        matrix = run(plan, prober)
        self.assertEqual(matrix.abort_reason, "transport")
        self.assertEqual(prober.count, ABORT_CONSECUTIVE_TRANSPORT)

    def test_a_sustained_bad_rate_aborts_even_without_a_streak(self) -> None:
        plan = self._plan(operations=30)
        states = {"issued": 0}

        def responder(probe: Any) -> dict[str, Any]:
            states["issued"] += 1
            # every third request fails: no streak ever reaches its own
            # threshold, but a third of the run is hostile.
            return result(503) if states["issued"] % 3 == 0 else result(200)

        matrix = run(plan, RecordingProber(responder))
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "hostile_rate")
        self.assertGreaterEqual(matrix.issued, ABORT_HOSTILE_MINIMUM)

    def test_a_streak_that_recovers_does_not_abort(self) -> None:
        plan = self._plan(operations=4)
        pattern = [429, 429, 200, 500, 500, 200, 200, 200]
        states = {"index": 0}

        def responder(probe: Any) -> dict[str, Any]:
            status = pattern[states["index"]]
            states["index"] += 1
            return result(status)

        matrix = run(plan, RecordingProber(responder))
        self.assertFalse(matrix.aborted)
        self.assertIsNone(matrix.abort_reason)
        self.assertEqual(matrix.issued, matrix.planned)

    def test_abort_retains_partial_results_and_marks_the_rest_aborted(self) -> None:
        plan = self._plan(operations=10)
        states = {"issued": 0}

        def responder(probe: Any) -> dict[str, Any]:
            states["issued"] += 1
            return result(200) if states["issued"] <= 4 else result(429)

        matrix = run(plan, RecordingProber(responder))
        self.assertTrue(matrix.aborted)
        reached = [cell for cell in matrix.cells if cell.reach == REACH_REACHED]
        self.assertEqual(len(reached), 4, "everything already probed is retained")
        aborted = [cell for cell in matrix.cells if cell.unknown_reason == "aborted"]
        self.assertTrue(aborted)
        for cell in aborted:
            self.assertEqual(cell.reach, REACH_UNKNOWN)
            self.assertIsNone(cell.refusal_kind)
        self.assertEqual(
            len(matrix.cells),
            len(reached) + len(aborted) + ABORT_CONSECUTIVE_RATE_LIMITED,
        )
        document = matrix_document(matrix)
        self.assertTrue(document["safety"]["aborted"])
        self.assertEqual(document["safety"]["abort_reason"], "rate_limited")
        self.assertLess(document["safety"]["issued"], document["safety"]["planned"])

    def test_no_retries_are_ever_issued(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        prober = RecordingProber(
            lambda probe: result(None, error="the connection timed out")
        )
        run(plan, prober)
        self.assertEqual(prober.count, plan.requests_planned)


# ---------------------------------------------------------------------------
# 6. nothing sensitive reaches an artifact
# ---------------------------------------------------------------------------


SECRETS = {
    "authorization_header": "Bearer super-secret-token-value",
    "cookie": "session=9f8e7d6c5b4a3210deadbeef",
    "token": "tok_live_51H8xQz2eZvKYlo2C",  # gitleaks:allow
    "body": "{\"ssn\": \"123-45-6789\", \"note\": \"top secret body text\"}",
}


class NoSecretsInArtifactTest(unittest.TestCase):
    def test_a_prober_that_returns_everything_leaks_nothing(self) -> None:
        """The prober hands the matrix all four forbidden things at once.

        A cell is built from an allow-list of scalars, so the extra keys are
        simply never read. This test greps the serialized JSON rather than the
        key set: a future refactor that splices ``result`` into a cell wholesale
        fails here.
        """

        def leaky(probe: Any) -> dict[str, Any]:
            document = result(200)
            document["request"]["headers"] = {
                "Authorization": SECRETS["authorization_header"],
                "Cookie": SECRETS["cookie"],
            }
            document["response"]["headers"] = [
                ("Set-Cookie", SECRETS["cookie"]),
                ("X-Api-Token", SECRETS["token"]),
                ("Retry-After", "120"),
            ]
            document["response"]["body"] = SECRETS["body"]
            document["response"]["body_text"] = SECRETS["body"]
            document["identity_headers"] = {
                "Authorization": SECRETS["authorization_header"]
            }
            return document

        plan = plan_matrix(config(), inventory(get_only("/api/a", "/api/b")))
        matrix = run(plan, RecordingProber(leaky))
        serialized = json.dumps(matrix_document(matrix), indent=2)
        for label, value in SECRETS.items():
            with self.subTest(label=label):
                self.assertNotIn(value, serialized)
        for word in ("Authorization", "Cookie", "Set-Cookie", "ssn", "123-45-6789"):
            with self.subTest(word=word):
                self.assertNotIn(word, serialized)

    def test_query_values_never_reach_a_cell(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        matrix = run(
            plan,
            RecordingProber(
                lambda probe: result(
                    200, url="http://127.0.0.1:8765/api/a?token=secret-query-value"
                )
            ),
        )
        serialized = json.dumps(matrix_document(matrix))
        self.assertNotIn("secret-query-value", serialized)
        for cell in matrix.cells:
            self.assertEqual(cell.url_path, "/api/a")
            self.assertNotIn("?", cell.url_path)

    def test_a_specimen_may_not_carry_a_marker(self) -> None:
        marker = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
        document = config(
            identities={
                "alice": {"headers": {}, "marker": marker},
                "mallory": {"headers": {}},
            },
            matrix={
                "specimens": {
                    "/api/invoices/{id}": [
                        {"label": "planted", "values": {"id": marker}}
                    ]
                }
            },
        )
        with self.assertRaises(MatrixError) as raised:
            plan_matrix(document, inventory(MUTATING_SPEC))
        self.assertIn("marker", str(raised.exception))

    def test_a_specimen_may_not_target_a_query_parameter(self) -> None:
        document = config(
            matrix={
                "specimens": {
                    "/api/invoices/{id}": [
                        {"label": "q", "values": {"id": "inv-1", "api_key": "x"}}
                    ]
                }
            }
        )
        with self.assertRaises(MatrixError) as raised:
            plan_matrix(document, inventory(MUTATING_SPEC))
        self.assertIn("path parameter", str(raised.exception))

    def test_a_specimen_value_cannot_invent_a_path_segment(self) -> None:
        """A value is percent-encoded into one segment, and one that is still
        a dot segment once a gateway decodes it is refused. This used to pin
        '../../admin' planned as '/api/invoices/..%2F..%2Fadmin' -- which nginx
        decodes and routes as '../../admin' (measured for '..%2f' under a
        path-routed gateway), so "one segment" held only on the wire."""
        document = config(
            matrix={
                "specimens": {
                    "/api/invoices/{id}": [
                        {"label": "escape", "values": {"id": "../../admin"}}
                    ]
                }
            }
        )
        with self.assertRaises(MatrixSafetyError) as refused:
            plan_matrix(document, inventory(MUTATING_SPEC))
        self.assertIn("'/api/invoices/..%2F..%2Fadmin'", str(refused.exception))
        self.assertIn("Nothing has been sent", str(refused.exception))

    def test_control_a_slash_inside_a_specimen_value_stays_in_its_segment(self) -> None:
        document = config(
            matrix={
                "specimens": {
                    "/api/invoices/{id}": [
                        {"label": "nested", "values": {"id": "group/project"}}
                    ]
                }
            }
        )
        plan = plan_matrix(document, inventory(MUTATING_SPEC))
        self.assertTrue(plan.probes)
        for probe in plan.probes:
            self.assertEqual(probe.path, "/api/invoices/group%2Fproject")

    def test_body_digest_is_run_salted(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        first = run(plan, RecordingProber())
        second = run(plan, RecordingProber())
        digests = {cell.body_digest for cell in first.cells}
        self.assertEqual(len(digests), 1, "same bytes compare equal within a run")
        self.assertNotEqual(
            digests, {cell.body_digest for cell in second.cells},
            "a digest is not comparable across runs, by design",
        )
        # and it is not core's unsalted body_sha256
        self.assertNotIn("a" * 64, json.dumps(matrix_document(first)))


class SessionIdentityTest(unittest.TestCase):
    """An identity the matrix cannot authenticate as must stop the run.

    ``matrix`` builds every probe from ``identities[name]["headers"]`` and calls
    ``core._perform_request`` with no jar and no login. A cookie-authenticated
    identity was therefore probed ANONYMOUSLY and the anonymous reach recorded
    under its name -- ``map``'s answer to "what would a compromise of this
    identity reach?" came back SMALLER than reality, which is the false-SAFE
    direction and the worst failure this product has. Nothing said so: no
    banner, note or artifact contained the word "session".
    """

    def _session_config(self) -> dict[str, Any]:
        return config(
            identities={
                "cookie_user": {
                    "session": {
                        "login": [
                            {"method": "GET", "path": "/login", "expect_status": [200]}
                        ],
                        "establishes": {"cookie": "sessionid"},
                    }
                },
                "header_user": {"headers": {"Cookie": "sessionid=abc123"}},
            }
        )

    def test_planning_refuses_before_a_socket_is_opened(self) -> None:
        prober = RecordingProber()
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(self._session_config(), inventory(get_only("/api/a", "/api/b")))
        self.assertEqual(prober.count, 0)
        message = str(caught.exception)
        self.assertIn("cookie_user", message)
        self.assertIn("session", message)
        # It has to say what to do instead, or the refusal is a dead end.
        self.assertIn("veridor run", message)
        self.assertIn("nothing has been sent", message.lower())

    def test_the_refusal_names_every_session_identity(self) -> None:
        document = self._session_config()
        document["identities"]["another_cookie_user"] = {
            "session": {"establishes": {"cookie": "sid"}}
        }
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(document, inventory(get_only("/api/a")))
        self.assertIn("another_cookie_user, cookie_user", str(caught.exception))

    def test_the_refusal_does_not_quote_the_credential(self) -> None:
        document = self._session_config()
        document["identities"]["cookie_user"]["session"]["login"][0]["body"] = (
            "password=hunter2"
        )
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(document, inventory(get_only("/api/a")))
        self.assertNotIn("hunter2", str(caught.exception))
        self.assertNotIn("sessionid=abc123", str(caught.exception))

    def test_a_header_only_configuration_still_plans(self) -> None:
        """The guard must not fire on the configurations map is for."""
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        self.assertEqual(plan.requests_planned, 2)


# ---------------------------------------------------------------------------
# 7. target posture
# ---------------------------------------------------------------------------


class TargetPostureTest(unittest.TestCase):
    def test_classification(self) -> None:
        expected = {
            "127.0.0.1": "loopback",
            "::1": "loopback",
            "localhost": "loopback",
            "api.localhost": "loopback",
            "10.0.0.4": "private",
            "192.168.1.10": "private",
            "172.16.0.1": "private",
            "fd00::1": "private",
            "169.254.1.1": "private",
            "100.64.0.1": "private",
            # TEST-NET-3 is documentation-only and not globally routable, so it
            # needs no acknowledgement: nothing real is there to be hit.
            "203.0.113.10": "private",
            "93.184.216.34": "public",
            "api.example.com": "public",
            # A name this process cannot verify offline is treated as public,
            # which demands the acknowledgement rather than waiving it.
            "internal-api": "public",
        }
        for host, want in expected.items():
            with self.subTest(host=host):
                self.assertEqual(classify_target(host), want)

    def test_loopback_needs_no_acknowledgement(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        self.assertEqual(plan.target_class, "loopback")

    def test_private_needs_no_acknowledgement(self) -> None:
        plan = plan_matrix(
            config(base_url="http://10.1.2.3:8080"), inventory(get_only("/api/a"))
        )
        self.assertEqual(plan.target_class, "private")

    def test_public_without_the_exact_string_is_refused(self) -> None:
        document = config(base_url="https://api.example.com")
        prober = RecordingProber()
        with self.assertRaises(MatrixSafetyError) as raised:
            plan_matrix(document, inventory(get_only("/api/a")))
        self.assertEqual(prober.count, 0)
        self.assertIn("I am authorized to test api.example.com", str(raised.exception))
        self.assertIn("friction, not a security boundary", str(raised.exception))

    def test_public_with_the_wrong_host_in_the_string_is_refused(self) -> None:
        document = config(base_url="https://api.example.com")
        with self.assertRaises(MatrixSafetyError):
            plan_matrix(
                document,
                inventory(get_only("/api/a")),
                options=MatrixOptions(
                    target_acknowledgement="I am authorized to test other.example.com"
                ),
            )

    def test_public_with_the_exact_string_is_permitted(self) -> None:
        document = config(base_url="https://api.example.com")
        plan = plan_matrix(
            document,
            inventory(get_only("/api/a")),
            options=MatrixOptions(
                target_acknowledgement="I am authorized to test api.example.com"
            ),
        )
        self.assertEqual(plan.target_class, "public")
        self.assertEqual(plan.requests_planned, 2)

    def test_a_non_http_scheme_is_refused_with_no_override(self) -> None:
        for url in ("file:///etc/passwd", "ftp://example.com", "gopher://x"):
            with self.subTest(url=url):
                with self.assertRaises(MatrixError):
                    plan_matrix(config(base_url=url), inventory(get_only("/api/a")))

    def test_there_is_no_host_denylist(self) -> None:
        self.assertNotIn("denylist", MATRIX_SOURCE)
        self.assertNotIn("blocklist", MATRIX_SOURCE)


# ---------------------------------------------------------------------------
# 8. the module reuses core rather than forking it
# ---------------------------------------------------------------------------


def module_scope_imports(source: str) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


class ProbeMachineryTest(unittest.TestCase):
    def test_no_module_scope_import_of_core(self) -> None:
        imports = module_scope_imports(MATRIX_SOURCE)
        self.assertNotIn("veridor.core", imports)
        self.assertIn("veridor.openapi", imports)
        self.assertIn("veridor.coverage", imports)

    def test_the_module_builds_no_opener_of_its_own(self) -> None:
        """Redirects must never be followed, so there is one opener, in core."""
        self.assertNotIn("build_opener", MATRIX_SOURCE)
        self.assertNotIn("urlopen", MATRIX_SOURCE)
        self.assertNotIn("urllib.request", module_scope_imports(MATRIX_SOURCE))
        self.assertNotIn("http.client", module_scope_imports(MATRIX_SOURCE))

    def test_the_module_never_passes_a_sink(self) -> None:
        self.assertNotIn("sink=", MATRIX_SOURCE)

    def test_default_prober_delegates_to_core_perform_request(self) -> None:
        from veridor import core

        calls: list[tuple[Any, ...]] = []

        def recorder(base_url, timeout, request_config, identity, **kwargs):
            calls.append((base_url, timeout, request_config, identity, kwargs))
            return result(200)

        original = core._perform_request
        core._perform_request = recorder  # type: ignore[assignment]
        try:
            document = config(
                identities={
                    "alice": {
                        "headers": {"Authorization": "Bearer alice"},
                        "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
                    },
                    "mallory": {"headers": {"Authorization": "Bearer mallory"}},
                }
            )
            plan = plan_matrix(document, inventory(get_only("/api/a")))
            matrix = run(plan, default_prober(document))
        finally:
            core._perform_request = original  # type: ignore[assignment]

        self.assertEqual(len(calls), 2)
        base_url, timeout, request_config, identity, kwargs = calls[0]
        self.assertEqual(base_url, "http://127.0.0.1:8765")
        self.assertEqual(timeout, 3.0)
        self.assertEqual(request_config, {"method": "GET", "path": "/api/a"})
        self.assertEqual(identity, document["identities"]["alice"])
        self.assertEqual(kwargs, {"marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"})
        self.assertNotIn("sink", kwargs)
        self.assertEqual(len(matrix.cells), 2)

    def test_core_no_redirect_handler_is_still_the_one_in_use(self) -> None:
        from urllib.request import HTTPRedirectHandler

        from veridor import core

        self.assertIsNone(
            core._NoRedirectHandler().redirect_request(
                None, None, 302, "Found", {}, "http://elsewhere.example/"
            )
        )
        self.assertTrue(issubclass(core._NoRedirectHandler, HTTPRedirectHandler))


# ---------------------------------------------------------------------------
# 9. specimens
# ---------------------------------------------------------------------------


class SpecimenTest(unittest.TestCase):
    def test_a_templated_operation_without_a_specimen_is_unknown_not_omitted(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/invoices/{id}")))
        self.assertEqual(plan.requests_planned, 0)
        self.assertEqual(
            {item.unknown_reason for item in plan.skipped}, {"skipped_no_specimen"}
        )
        matrix = run(plan, RecordingProber())
        self.assertEqual(len(matrix.cells), 2)
        for cell in matrix.cells:
            self.assertEqual(cell.reach, REACH_UNKNOWN)

    def test_the_specimen_cap_is_enforced(self) -> None:
        entries = [
            {"label": f"s{index}", "values": {"id": f"inv-{index}"}}
            for index in range(MATRIX_MAX_SPECIMENS_PER_OPERATION + 1)
        ]
        with self.assertRaises(MatrixError) as raised:
            plan_matrix(
                config(matrix={"specimens": {"/api/invoices/{id}": entries}}),
                inventory(MUTATING_SPEC),
            )
        self.assertIn("enumerator", str(raised.exception))

    def test_each_specimen_is_its_own_row_against_the_budget(self) -> None:
        entries = [
            {"label": "a", "values": {"id": "inv-1"}},
            {"label": "b", "values": {"id": "inv-2"}},
        ]
        plan = plan_matrix(
            config(matrix={"specimens": {"/api/invoices/{id}": entries}}),
            inventory(MUTATING_SPEC),
        )
        self.assertEqual(plan.requests_planned, 4)
        self.assertEqual(
            sorted(probe.path for probe in plan.probes),
            ["/api/invoices/inv-1"] * 2 + ["/api/invoices/inv-2"] * 2,
        )

    def test_per_identity_specimens_mark_the_row_not_comparable(self) -> None:
        entries = [
            {
                "label": "own",
                "per_identity": {
                    "alice": {"id": "inv-1"},
                    "mallory": {"id": "inv-2"},
                },
            }
        ]
        plan = plan_matrix(
            config(matrix={"specimens": {"/api/invoices/{id}": entries}}),
            inventory(MUTATING_SPEC),
        )
        matrix = run(plan, RecordingProber())
        self.assertFalse(matrix.is_shared_specimen("GET /api/invoices/{id}", "own"))
        document = matrix_document(matrix)
        row = next(row for row in document["rows"] if row["specimen"] == "own")
        self.assertFalse(row["shared_specimen"])

    def test_shared_specimens_are_marked_comparable(self) -> None:
        plan = plan_matrix(
            config(matrix=dict(SPECIMENS)), inventory(MUTATING_SPEC)
        )
        matrix = run(plan, RecordingProber())
        self.assertTrue(matrix.is_shared_specimen("GET /api/invoices/{id}", "one"))
        self.assertTrue(matrix.is_shared_specimen("GET /api/invoices/{id}", "one"))

    def test_a_per_identity_specimen_omitting_an_identity_is_unknown(self) -> None:
        entries = [{"label": "own", "per_identity": {"alice": {"id": "inv-1"}}}]
        plan = plan_matrix(
            config(matrix={"specimens": {"/api/invoices/{id}": entries}}),
            inventory(MUTATING_SPEC),
        )
        matrix = run(plan, RecordingProber())
        omitted = matrix.cell("GET /api/invoices/{id}", "mallory", "own")
        assert omitted is not None
        self.assertEqual(omitted.reach, REACH_UNKNOWN)
        self.assertEqual(omitted.unknown_reason, "skipped_no_specimen")

    def test_a_specimen_missing_a_parameter_is_a_config_error(self) -> None:
        with self.assertRaises(MatrixError) as raised:
            plan_matrix(
                config(
                    matrix={
                        "specimens": {
                            "/api/tenants/{tid}/users/{uid}": [
                                {"label": "p", "values": {"tid": "t-1"}}
                            ]
                        }
                    }
                ),
                inventory(get_only("/api/tenants/{tid}/users/{uid}")),
            )
        self.assertIn("uid", str(raised.exception))

    def test_a_typo_in_the_matrix_section_fails_loudly(self) -> None:
        with self.assertRaises(MatrixError) as raised:
            plan_matrix(config(matrix={"specimen": {}}), inventory(get_only("/api/a")))
        self.assertIn("unsupported keys", str(raised.exception))

    def test_projection_keys_are_accepted_and_ignored(self) -> None:
        plan = plan_matrix(
            config(
                matrix={
                    "peer_groups": {"tenant": ["alice", "mallory"]},
                    "privilege_order": ["mallory", "alice"],
                    "unauthenticated": "mallory",
                }
            ),
            inventory(get_only("/api/a")),
        )
        self.assertEqual(plan.requests_planned, 2)


# ---------------------------------------------------------------------------
# 10. paths, markers, serialisation
# ---------------------------------------------------------------------------


class DocumentTest(unittest.TestCase):
    def test_document_shape_and_round_trip(self) -> None:
        plan = plan_matrix(
            config(matrix=dict(SPECIMENS)), inventory(MUTATING_SPEC)
        )
        matrix = run(plan, RecordingProber(lambda probe: result(403)))
        document = matrix_document(matrix)
        self.assertEqual(document["kind"], MATRIX_KIND)
        self.assertEqual(document["schema_version"], SCHEMA_VERSION)
        self.assertEqual(document["claim"], CLAIM)
        self.assertIn("OPERATION level", document["limitation"])
        self.assertFalse(document["safety"]["follows_redirects"])
        self.assertEqual(document["safety"]["concurrency"], "sequential")
        self.assertEqual(document["safety"]["retries"], 0)
        self.assertTrue(document["safety"]["read_only"])
        self.assertEqual(document["counts"]["cells"], len(matrix.cells))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            restored = load_matrix(path)
        self.assertEqual(restored.cells, matrix.cells)
        self.assertEqual(restored.identities, matrix.identities)
        self.assertEqual(restored.rows, matrix.rows)
        self.assertEqual(
            restored.is_shared_specimen("GET /api/invoices/{id}", "one"),
            matrix.is_shared_specimen("GET /api/invoices/{id}", "one"),
        )

    def test_load_refuses_a_cell_that_hides_an_unknown(self) -> None:
        document = {
            "kind": MATRIX_KIND,
            "schema_version": SCHEMA_VERSION,
            "cells": [
                {
                    "operation": "GET /a",
                    "identity": "alice",
                    "specimen": None,
                    "url_path": "/a",
                    "outcome": "unknown",
                    "reach": "unknown",
                    "unknown_reason": "because",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(MatrixError) as raised:
                load_matrix(path)
        self.assertIn("closed set", str(raised.exception))

    def test_a_row_that_does_not_say_shared_is_not_shared(self) -> None:
        # REGRESSION. matrix_from_document read `row.get("shared_specimen",
        # True)`, so a row that left the key out -- or said "false" as a
        # string -- was shared, and peer_divergence compared two identities'
        # answers about two different objects. is_shared_specimen promises
        # the opposite: the unknown case suppresses a comparison.
        document = json.loads((FIXTURES / "matrix.idor.json").read_text(encoding="utf-8"))
        row = next(
            item for item in document["rows"]
            if item["operation"] == "GET /api/invoices/{id}"
            and item["specimen"] == "owner_invoice"
        )
        self.assertIs(row["shared_specimen"], True)
        self.assertTrue(
            matrix_module.matrix_from_document(document).is_shared_specimen(
                "GET /api/invoices/{id}", "owner_invoice"
            )
        )
        del row["shared_specimen"]
        self.assertFalse(
            matrix_module.matrix_from_document(document).is_shared_specimen(
                "GET /api/invoices/{id}", "owner_invoice"
            )
        )
        for wrong in ("false", 1, None):
            with self.subTest(value=wrong):
                row["shared_specimen"] = wrong
                with self.assertRaises(MatrixError) as raised:
                    matrix_module.matrix_from_document(document)
                self.assertIn("shared_specimen", str(raised.exception))

    def test_load_refuses_a_foreign_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            path.write_text(json.dumps({"kind": "veridor.run"}), encoding="utf-8")
            with self.assertRaises(MatrixError):
                load_matrix(path)

    def test_the_document_carries_the_posture_and_the_claim(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        document = matrix_document(run(plan, RecordingProber()))
        self.assertIn("systems you own", document["safety"]["posture"])
        self.assertIn("never findings", document["claim"]["statement"])

    def test_base_url_in_the_document_carries_no_credentials(self) -> None:
        plan = plan_matrix(
            config(base_url="http://127.0.0.1:8765"), inventory(get_only("/api/a"))
        )
        matrix = dataclasses.replace(
            run(plan, RecordingProber()),
            base_url="http://user:hunter2@127.0.0.1:8765/base",
        )
        serialized = json.dumps(matrix_document(matrix))
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("user", serialized)


class BasePathTest(unittest.TestCase):
    def test_a_spec_server_prefix_is_applied(self) -> None:
        plan = plan_matrix(
            config(base_url="http://127.0.0.1:8765"),
            inventory(get_only("/widgets"), servers=[{"url": "http://x/v2"}]),
        )
        self.assertEqual(plan.probes[0].path, "/v2/widgets")
        self.assertEqual(plan.probes[0].operation, "GET /v2/widgets")

    def test_a_prefix_the_base_url_already_carries_is_not_repeated(self) -> None:
        plan = plan_matrix(
            config(base_url="http://127.0.0.1:8765/v2"),
            inventory(get_only("/widgets"), servers=[{"url": "http://x/v2"}]),
        )
        self.assertEqual(plan.probes[0].path, "/widgets")

    def test_an_explicit_base_path_wins(self) -> None:
        plan = plan_matrix(
            config(matrix={"base_path": "/api"}),
            inventory(get_only("/widgets"), servers=[{"url": "http://x/v2"}]),
        )
        self.assertEqual(plan.probes[0].path, "/api/widgets")


class MarkerTest(unittest.TestCase):
    def test_the_marker_owner_is_recorded_on_a_scanned_cell(self) -> None:
        document = config(
            identities={
                "alice": {"headers": {}, "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"},
                "mallory": {"headers": {}},
            }
        )
        plan = plan_matrix(document, inventory(get_only("/api/a")))
        self.assertEqual(plan.marker_owner, "alice")
        matrix = run(
            plan, RecordingProber(lambda probe: result(200, marker_scan="present"))
        )
        cell = matrix.cell("GET /api/a", "mallory")
        assert cell is not None
        self.assertEqual(cell.marker_scan, "present")
        self.assertEqual(cell.marker_owner, "alice")
        serialized = json.dumps(matrix_document(matrix))
        self.assertNotIn("vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1", serialized)

    def test_several_markers_require_an_explicit_owner(self) -> None:
        document = config(
            identities={
                "alice": {"headers": {}, "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"},
                "mallory": {"headers": {}, "marker": "vdr-Qq3Wm8Ls2Rt7Vb1Nc9Zp4Wf6"},
            }
        )
        with self.assertRaises(MatrixError) as raised:
            plan_matrix(document, inventory(get_only("/api/a")))
        self.assertIn("matrix.marker_owner", str(raised.exception))


# ---------------------------------------------------------------------------
# 11. the shipped fixtures
# ---------------------------------------------------------------------------


class FixtureTest(unittest.TestCase):
    def test_the_demo_config_loads_as_a_real_veridor_config(self) -> None:
        from veridor.core import load_config

        document = load_config(MATRIX_CONFIG)
        self.assertIn("matrix", document)

    def test_the_demo_plan_is_dense_read_only_and_within_budget(self) -> None:
        from veridor.core import load_config

        document = load_config(MATRIX_CONFIG)
        route_inventory = load_inventory(MATRIX_SPEC, methods=ALL_METHODS)
        plan = plan_matrix(document, route_inventory)
        self.assertLessEqual(plan.requests_planned, MATRIX_DEFAULT_BUDGET)
        self.assertEqual({probe.method for probe in plan.probes}, {"GET"})
        self.assertEqual(
            plan.requests_planned + len(plan.skipped),
            len(plan.rows) * len(plan.identities),
        )
        reasons = {item.unknown_reason for item in plan.skipped}
        self.assertEqual(
            reasons, {"skipped_mutating", "skipped_ignored", "skipped_no_specimen"}
        )

    def test_the_canned_observed_matrix_loads_and_carries_both_kinds_of_cell(
        self,
    ) -> None:
        """``matrix.observed.json`` is what the projection module tests offline.

        It must round-trip, and it must contain measured AND unmeasured cells:
        a fixture with no unknowns would let a rule that mishandles unknowns
        pass every test.
        """
        matrix = load_matrix(FIXTURES / "matrix.observed.json")
        self.assertEqual(len(matrix.cells), len(matrix.rows) * len(matrix.identities))
        reaches = {cell.reach for cell in matrix.cells}
        self.assertIn(REACH_REACHED, reaches)
        self.assertIn(REACH_REFUSED, reaches)
        self.assertIn(REACH_UNKNOWN, reaches)
        unknowns = {
            cell.unknown_reason for cell in matrix.cells if cell.reach == REACH_UNKNOWN
        }
        self.assertTrue(unknowns <= UNKNOWN_REASONS)
        self.assertIn("skipped_mutating", unknowns)
        for cell in matrix.cells:
            if cell.reach == REACH_UNKNOWN:
                self.assertIsNone(cell.refusal_kind)
        text = (FIXTURES / "matrix.observed.json").read_text(encoding="utf-8")
        for forbidden in ("Authorization", "Bearer", "Set-Cookie", "session="):
            self.assertNotIn(forbidden, text)

    def test_every_canned_matrix_is_one_its_paired_config_could_produce(self) -> None:
        """A canned matrix is the plan its config makes, plus observations.

        matrix.observed.json once recorded GET /health as measured for every
        identity, anonymous included, with ``ignored: []`` and 53 requests,
        while matrix.demo.json ignores /health and plans 48. Every test that
        paired the two exercised a request the shipped config never sends, and
        no shipped pair drove the ``ignored`` echo at all. The generated
        precision pair is pinned to its generator in test_blastradius instead.
        """
        from veridor.core import load_config

        for canned, config, spec in (
            ("matrix.observed.json", "matrix.demo.json", "openapi.matrix.json"),
            ("matrix.sibling.json", "blastradius.sibling.json", "openapi.sibling.json"),
            ("matrix.shared.json", "blastradius.shared.json", "openapi.shared.json"),
        ):
            with self.subTest(matrix=canned):
                plan = plan_matrix(
                    load_config(FIXTURES / config, require_checks=False),
                    load_inventory(FIXTURES / spec, methods=ALL_METHODS),
                )
                matrix = load_matrix(FIXTURES / canned)
                self.assertEqual(matrix.rows, plan.rows)
                self.assertEqual(matrix.identities, plan.identities)
                self.assertEqual(matrix.ignored, plan.ignored)
                self.assertEqual(matrix.planned, plan.requests_planned)
                cells = {
                    (cell.operation, cell.identity, cell.specimen): cell
                    for cell in matrix.cells
                }
                for item in plan.skipped:
                    self.assertEqual(
                        cells[(item.operation, item.identity, item.specimen)].unknown_reason,
                        item.unknown_reason,
                        f"{item.operation} as {item.identity} is never sent",
                    )
                for probe in plan.probes:
                    reason = cells[(probe.operation, probe.identity, probe.specimen)].unknown_reason
                    self.assertFalse(
                        (reason or "").startswith("skipped_"),
                        f"{probe.operation} as {probe.identity} is sent, not {reason}",
                    )
                self.assertEqual(matrix.on_retry_after, plan.options.on_retry_after)

    def test_every_canned_matrix_is_the_document_matrix_document_writes(self) -> None:
        """A canned matrix carries every key, at every depth, that a run writes.

        The comparison above reads a canned matrix through ``load_matrix``,
        which fills a missing key with its default, so it cannot see a key the
        canned document lacks. matrix.observed.json, matrix.sibling.json and
        matrix.shared.json all lacked ``safety.on_retry_after`` and
        ``safety.retry_after_seen`` after ``matrix_document`` began emitting
        them. Re-serialising each canned matrix must give back the file as
        shipped: the same keys, and the same values wherever the writer derives
        them (counts, claim, limitation, posture). A stored value the writer
        copies through unchanged, such as ``retry_after_seen``, is checked for
        presence only; the comparison above checks it against the plan where
        the plan decides it.
        """

        def paths(value: Any, prefix: str = "") -> set[str]:
            found: set[str] = set()
            if isinstance(value, dict):
                for key, item in value.items():
                    found.add(f"{prefix}.{key}")
                    found |= paths(item, f"{prefix}.{key}")
            elif isinstance(value, list):
                for item in value:
                    found |= paths(item, f"{prefix}[]")
            return found

        canned = sorted(
            path
            for path in FIXTURES.glob("*.json")
            if json.loads(path.read_text(encoding="utf-8")).get("kind") == MATRIX_KIND
        )
        self.assertGreaterEqual(len(canned), 5)
        for path in canned:
            with self.subTest(matrix=path.name):
                shipped = json.loads(path.read_text(encoding="utf-8"))
                written = json.loads(json.dumps(matrix_document(load_matrix(path))))
                self.assertEqual(
                    sorted(paths(written) - paths(shipped)), [], "keys the file lacks"
                )
                self.assertEqual(
                    sorted(paths(shipped) - paths(written)), [], "keys no run writes"
                )
                self.assertEqual(shipped, written)

    def test_the_default_method_set_still_hides_mutating_verbs(self) -> None:
        route_inventory = load_inventory(MATRIX_SPEC, methods=DEFAULT_METHODS)
        from veridor.core import load_config

        plan = plan_matrix(load_config(MATRIX_CONFIG), route_inventory)
        self.assertEqual({probe.method for probe in plan.probes}, {"GET"})


# ---------------------------------------------------------------------------
# 12. against a real server
# ---------------------------------------------------------------------------


LIVE_COOKIE = "session=live-cookie-9f8e7d6c"
LIVE_TOKEN = "tok_live_ABCDEFGH12345678"  # gitleaks:allow
LIVE_BODY = '{"secret_body_text": "do-not-persist-me"}'


def live_server() -> tuple[ThreadingHTTPServer, str]:
    """A target that hands back every forbidden thing on every response."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            authorization = self.headers.get("Authorization", "")
            if self.path == "/api/public":
                status, payload = 200, LIVE_BODY.encode()
            elif not authorization:
                status, payload = 401, b'{"error":"unauthenticated"}'
            elif "owner" in authorization:
                status, payload = 200, LIVE_BODY.encode()
            elif self.path == "/api/reports/quarterly":
                status, payload = 200, LIVE_BODY.encode()
            else:
                status, payload = 403, b'{"error":"forbidden"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Set-Cookie", LIVE_COOKIE)
            self.send_header("X-Api-Token", LIVE_TOKEN)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(server)
    host, port = server.server_address[:2]
    return server, f"http://{host}:{port}"


@slow("stands up a loopback HTTP server and runs the engine against it")
class LiveTargetTest(unittest.TestCase):
    def test_a_real_run_records_reach_and_leaks_nothing(self) -> None:
        server, base_url = live_server()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        document = config(
            identities={
                "owner": {"headers": {"Authorization": "Bearer owner-token"}},
                "other": {"headers": {"Authorization": "Bearer other-token"}},
                "anonymous": {"headers": {}},
            },
            base_url=base_url,
        )
        route_inventory = inventory(
            get_only("/api/public", "/api/reports/daily", "/api/reports/quarterly")
        )
        plan = plan_matrix(
            document,
            route_inventory,
            options=MatrixOptions(requests_per_second=MATRIX_MAX_RPS),
        )
        matrix = execute_matrix(plan, prober=default_prober(document))

        self.assertEqual(matrix.issued, 9)
        self.assertFalse(matrix.aborted)
        owner = {
            cell.operation: cell.reach for cell in matrix.row("owner")
        }
        self.assertEqual(
            owner,
            {
                "GET /api/public": REACH_REACHED,
                "GET /api/reports/daily": REACH_REACHED,
                "GET /api/reports/quarterly": REACH_REACHED,
            },
        )
        other = {cell.operation: cell.reach for cell in matrix.row("other")}
        self.assertEqual(other["GET /api/reports/daily"], REACH_REFUSED)
        self.assertEqual(other["GET /api/reports/quarterly"], REACH_REACHED)
        anonymous = {
            cell.operation: cell.refusal_kind for cell in matrix.row("anonymous")
        }
        self.assertEqual(
            anonymous["GET /api/reports/daily"], REFUSAL_UNAUTHENTICATED
        )

        serialized = json.dumps(matrix_document(matrix), indent=2)
        for secret in (LIVE_COOKIE, LIVE_TOKEN, LIVE_BODY, "owner-token", "Bearer"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, serialized)
        # the same bytes for two identities produce the same digest, which is
        # the only thing the digest exists for
        digests = {
            cell.identity: cell.body_digest
            for cell in matrix.column("GET /api/public")
        }
        self.assertEqual(len(set(digests.values())), 1)


#: A ``Retry-After`` delay no other number in a matrix document can be.
RETRY_AFTER_SENTINEL = "31337"


def throttling_server(with_retry_after: bool) -> tuple[ThreadingHTTPServer, str]:
    """A target that says 429 to everything, optionally politely."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            payload = b'{"error":"slow down"}'
            self.send_response(429)
            if with_retry_after:
                self.send_header("Retry-After", RETRY_AFTER_SENTINEL)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = loopback.start(server)
    host, port = server.server_address[:2]
    return server, f"http://{host}:{port}"


class UnfinishablePlanTest(unittest.TestCase):
    """The banner printed the estimate and the stop and never compared them.

    The wall clock usually binds first: at the default 2 req/s it caps any run
    at 3,600 requests, well under the 20,000 budget ceiling, so an ordinary
    1,000-operation spec across five identities already exceeds it. The cells
    the clock cuts off read `unknown`, which drift can never later report as
    more access -- so the run went quiet in exactly the direction that hides a
    regression, thirty minutes after it could have said so.
    """

    def _plan(self, operations: int, **options: Any) -> Any:
        paths = {
            f"/api/thing{index}/{{id}}": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
            for index in range(operations)
        }
        document = config(
            identities={
                f"i{n}": {"headers": {"Authorization": f"Bearer {n}"}}
                for n in range(5)
            }
        )
        document["matrix"] = {
            "specimens": {
                path: [{"label": "s", "values": {"id": "1"}}] for path in paths
            }
        }
        return plan_matrix(document, inventory(paths), options=MatrixOptions(**options))

    def test_a_plan_the_clock_cannot_cover_says_so_before_it_starts(self) -> None:
        # A SHORT clock rather than a huge plan. The arithmetic is the same --
        # requests / rate against max_run_seconds -- and building 5,000 probes
        # to prove it cost more than a second, which the fast tier refuses.
        banner = self._plan(20, max_requests=200, max_run_seconds=5).banner()
        self.assertIn("THIS PLAN CANNOT FINISH", banner)
        self.assertIn("'unknown', not 'no access'", banner)
        self.assertIn("--max-run-seconds", banner)

    @slow("builds a 20,000-probe plan to reach the request ceiling")
    def test_the_advice_is_one_the_operator_can_actually_take(self) -> None:
        """At 2 req/s no wall clock covers 20,000 requests; do not send them there."""
        banner = self._plan(4000, max_requests=20000).banner()
        self.assertIn("THIS PLAN CANNOT FINISH", banner)
        self.assertNotIn("Raise --max-run-seconds", banner)
        self.assertIn("--rate", banner)

    @slow("builds two 14,400-probe plans to sit exactly on the ceiling")
    def test_the_advice_matches_the_arithmetic_at_the_ceiling(self) -> None:
        """A plan the ceiling covers EXACTLY was told no clock could cover it.

        `raisable` was re-derived with `<=` against the planned count while the
        warning's own `unreachable` figure is computed from count - 1, so the
        boundary plan got the advice for the plan one request larger.
        """
        rps = MATRIX_DEFAULT_RPS
        covered = int(MATRIX_ABSOLUTE_MAX_RUN_SECONDS * rps)  # 14,400 at 2 req/s
        identities = 5
        exactly = self._plan(covered // identities, max_requests=covered,
                             requests_per_second=rps)
        self.assertEqual(exactly.requests_planned, covered)
        banner = exactly.banner()
        self.assertIn("CANNOT FINISH", banner)
        self.assertIn("Raise --max-run-seconds", banner)

        over = self._plan(covered // identities + 1, max_requests=covered + identities,
                          requests_per_second=rps)
        self.assertGreater(over.requests_planned, covered + 1)
        self.assertIn("--rate", over.banner())
        self.assertNotIn("Raise --max-run-seconds", over.banner())

    def test_a_plan_that_fits_says_nothing(self) -> None:
        self.assertNotIn("CANNOT FINISH", self._plan(20, max_requests=500).banner())

    def test_raising_the_clock_removes_the_warning(self) -> None:
        banner = self._plan(20, max_requests=200, max_run_seconds=3600).banner()
        self.assertNotIn("CANNOT FINISH", banner)


class IncludeSelectionTest(unittest.TestCase):
    """`--include` is a promise about a set, and the rules were written nowhere.

    Matching is by PATH PREFIX. Nothing said so -- not the help text, not the
    README, not a test -- so `--include 'GET /api/v1/invoices/{id}'` selected
    five operations when the operator asked for one (five times the requests
    they authorised), and `--include '.../*'` selected none and produced a full,
    clean-looking report over a grid where nothing was sent.
    """

    def _inventory(self) -> Any:
        paths = {
            path: {"get": {"responses": {"200": {"description": "ok"}}}}
            for path in (
                "/api/v1/invoices",
                "/api/v1/invoices/{id}",
                "/api/v1/invoices/{id}/lines",
                "/api/v1/invoices/{id}/pdf",
                "/api/v1/invoicesx",
            )
        }
        return inventory(paths)

    def _config(self) -> dict:
        document = config()
        document["matrix"] = {
            "specimens": {
                path: [{"label": "s", "values": {"id": "1"}}]
                for path in (
                    "/api/v1/invoices/{id}",
                    "/api/v1/invoices/{id}/lines",
                    "/api/v1/invoices/{id}/pdf",
                )
            }
        }
        return document

    def _plan(self, *include: str) -> Any:
        return plan_matrix(
            self._config(), self._inventory(), options=MatrixOptions(include=include)
        )

    def test_an_include_that_matches_nothing_is_refused(self) -> None:
        with self.assertRaises(MatrixError) as caught:
            self._plan("GET /api/v1/invoices/*")
        message = str(caught.exception)
        self.assertIn("matched none of the 5 operations", message)
        self.assertIn("PATH PREFIX", message)
        self.assertIn("'*' is an ordinary character", message)
        # The refusal has to show what the spec DOES declare, or the operator
        # is left guessing at the spelling that would have worked.
        self.assertIn("GET /api/v1/invoices/{id}", message)

    def test_a_partial_miss_rides_on_the_plan_and_prints_nothing(self) -> None:
        """One include-list across several specifications must not fail them all.

        And the warning belongs to the PLAN, not to stdout. `plan_matrix` is
        "a complete, socket-free description of what a run would do" and had no
        print() at all before this feature: printing from it put 600 bytes on a
        programmatic caller's stdout and left the warning invisible in the
        object that caller was handed.
        """
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            plan = self._plan("GET /api/v1/invoices/{id}/pdf", "GET /nope")
        self.assertEqual(stdout.getvalue(), "", "plan_matrix wrote to stdout")
        # One operation, both identities: the selection is a set of routes.
        self.assertEqual(
            {probe.operation for probe in plan.probes},
            {"GET /api/v1/invoices/{id}/pdf"},
        )
        self.assertEqual(plan.unmatched_include, (("GET", "/nope"),))
        banner = " ".join(plan.banner().split())
        self.assertIn("/nope", banner)
        self.assertIn("the run continues", banner)

    def test_a_partly_ignored_include_rides_on_the_plan_too(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            plan = plan_matrix(
                self._config(), self._inventory(),
                options=MatrixOptions(
                    # `ignore` matches by prefix too, so it must not name a
                    # path that also covers the pattern meant to survive.
                    include=("GET /api/v1/invoices/{id}/pdf", "GET /api/v1/invoicesx"),
                    ignore=("GET /api/v1/invoicesx",),
                ),
            )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(plan.ignored_only_include, (("GET", "/api/v1/invoicesx"),))
        # Normalised: the banner wraps, and a test about vocabulary should not
        # fail because a line break landed mid-phrase.
        self.assertIn("`ignore` removes", " ".join(plan.banner().split()))

    def test_planning_never_writes_to_stdout(self) -> None:
        """The layering rule, asserted rather than assumed.

        `core.execute_run` prints a mutating-request disclosure before its first
        request, which is an execution function doing an execution thing. The
        planning layer has no such licence.
        """
        tree = ast.parse(
            Path(matrix_module.__file__).read_text(encoding="utf-8")
        )
        printed = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ]
        self.assertEqual(printed, [], f"matrix.py prints at line(s) {printed}")

    def test_include_does_not_swallow_the_no_specimen_gate(self) -> None:
        """The regression `--include` introduced, and the worst kind.

        `elif include:` consumed the branch, so the two clauses below it --
        `skipped_mutating` and `skipped_no_specimen` -- stopped running for
        anything a pattern selected. A templated route with no specimen was
        then probed with the LITERAL `{id}` in its path. The target 404s, a 404
        is recorded `refused`, and a grid of refusals is what a boundary that
        holds looks like: exit 0, no warning, nothing measured. The existing
        tests here could not see it because this fixture gives every templated
        path a specimen.
        """
        paths = {"/api/v1/invoices/{id}":
                 {"get": {"responses": {"200": {"description": "ok"}}}}}
        plan = plan_matrix(
            config(), inventory(paths),
            options=MatrixOptions(include=("GET /api/v1/invoices/{id}",)),
        )
        self.assertEqual([probe.path for probe in plan.probes], [])
        self.assertEqual(
            {skipped.unknown_reason for skipped in plan.skipped},
            {"skipped_no_specimen"},
        )

    def test_include_does_not_swallow_the_mutating_gate(self) -> None:
        paths = {"/api/orders": {
            "get": {"responses": {"200": {"description": "ok"}}},
            "delete": {"responses": {"204": {"description": "gone"}}},
        }}
        plan = plan_matrix(
            config(), inventory(paths),
            options=MatrixOptions(include=("/api/orders",)),
        )
        self.assertEqual({probe.method for probe in plan.probes}, {"GET"})
        self.assertIn(
            "skipped_mutating", {s.unknown_reason for s in plan.skipped}
        )

    def test_an_include_matched_only_by_ignore_says_which(self) -> None:
        """"You spelled it wrong" and "ignore ate it" are opposite instructions."""
        paths = {"/api/a": {"get": {"responses": {"200": {"description": "ok"}}}}}
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(
                config(), inventory(paths),
                options=MatrixOptions(include=("GET /api/a",), ignore=("GET /api/a",)),
            )
        message = str(caught.exception)
        self.assertIn("matched only operations that `ignore` removes", message)
        self.assertNotIn("matched none of", message)

    def test_a_prefix_selects_everything_beneath_it(self) -> None:
        """The behaviour itself is kept -- only its silence was the defect."""
        plan = self._plan("GET /api/v1/invoices/{id}")
        self.assertEqual(
            {probe.operation for probe in plan.probes},
            {
                "GET /api/v1/invoices/{id}",
                "GET /api/v1/invoices/{id}/lines",
                "GET /api/v1/invoices/{id}/pdf",
            },
        )

    def test_a_prefix_does_not_select_a_longer_sibling(self) -> None:
        # `operations` is the whole inventory; what --include selects is the
        # set that becomes probes.
        plan = self._plan("GET /api/v1/invoices")
        probed = {probe.operation for probe in plan.probes}
        self.assertIn("GET /api/v1/invoices", probed)
        self.assertNotIn("GET /api/v1/invoicesx", probed)


class EmptySelectionTest(unittest.TestCase):
    """An `ignore` or `--include` that leaves no operation is refused at plan time.

    Excluded operations became deliberate skips, so they stopped counting as
    probed-but-unmeasured. That was right for a partial exclusion and wrong
    for a total one: `--ignore '/'` planned 0 requests, sent nothing, wrote a
    grid of `skipped_ignored` cells and exited 0, `--require-complete`
    included, while the README said a grid that measured nothing exits 3. An
    `--include` that matched nothing was already refused before a socket; an
    exclusion that empties the grid by any other route now is too.
    """

    PATHS = ("/api/a", "/api/b", "/api/b/{id}")

    def _inventory(self) -> Any:
        return inventory({
            path: {"get": {"responses": {"200": {"description": "ok"}}}}
            for path in self.PATHS
        })

    def _config(self, **matrix: Any) -> dict:
        document = config()
        document["matrix"] = {
            "specimens": {"/api/b/{id}": [{"label": "s", "values": {"id": "1"}}]},
            **matrix,
        }
        return document

    def _refusal(self, document: dict, **options: Any) -> str:
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(document, self._inventory(), options=MatrixOptions(**options))
        message = " ".join(str(caught.exception).split())
        self.assertIn("Nothing has been sent", message)
        self.assertIn("none of the 3 operations", message)
        return message

    def test_an_ignore_option_that_covers_every_operation_is_refused(self) -> None:
        message = self._refusal(self._config(), ignore=("/",))
        self.assertIn("--ignore", message)

    def test_a_matrix_ignore_that_covers_every_operation_is_refused(self) -> None:
        message = self._refusal(self._config(ignore=["/api"]))
        self.assertIn("matrix.ignore", message)

    def test_ignore_and_include_that_empty_the_grid_together_are_refused(self) -> None:
        """Neither include refusal fires: each pattern is only a PARTIAL miss.

        One pattern names an operation `ignore` removes, the other names none,
        and every other operation is outside the selection. No single rule
        emptied the grid, so no rule above saw it.
        """
        self._refusal(self._config(), include=("GET /api/a", "GET /nope"),
                      ignore=("GET /api/a",))

    def test_control_an_ignore_that_leaves_one_operation_plans_it(self) -> None:
        plan = plan_matrix(self._config(), self._inventory(),
                           options=MatrixOptions(ignore=("/api/b",)))
        self.assertEqual({probe.operation for probe in plan.probes}, {"GET /api/a"})

    def test_control_an_all_mutating_spec_is_not_refused_here(self) -> None:
        """The read-only posture declining every verb is a separate decision
        (`test_a_matrix_that_probed_nothing_is_not_gated_here`); nothing the
        operator excluded emptied that grid."""
        paths = {"/api/orders": {"delete": {"responses": {"204": {"description": "gone"}}}}}
        plan = plan_matrix(config(), inventory(paths), options=MatrixOptions())
        self.assertEqual(plan.probes, ())
        self.assertEqual({s.unknown_reason for s in plan.skipped}, {"skipped_mutating"})


class SelectionThatProbesNothingTest(unittest.TestCase):
    """A selection that leaves only operations the plan never probes is refused.

    The refusal above fired only when the selection excluded EVERY operation in
    the specification, counting ones the read-only posture would never have
    sent. `--ignore 'GET /'` on a spec of three GETs and two writes, or an
    `--include` naming only a DELETE, planned 0 requests, sent nothing and
    exited 0 under `--require-complete`, while the README, the exit-code
    paragraph and the `--require-complete` help all said such a selection is
    refused with exit 2. The operator's selection is what emptied the grid
    there, exactly as with `--ignore '/'`.
    """

    def _inventory(self) -> Any:
        return inventory({
            "/api/a": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "delete": {"responses": {"204": {"description": "gone"}}},
            },
            "/api/b/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
        })

    def _refusal(self, document: dict, **options: Any) -> str:
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(document, self._inventory(), options=MatrixOptions(**options))
        message = " ".join(str(caught.exception).split())
        self.assertIn("Nothing has been sent", message)
        self.assertIn("the matrix would send nothing", message)
        return message

    def test_an_ignore_that_leaves_only_a_write_is_refused(self) -> None:
        message = self._refusal(config(), ignore=("GET /",))
        self.assertIn("--ignore", message)
        self.assertIn("1 skipped as non-read-only", message)

    def test_an_include_naming_only_a_write_is_refused(self) -> None:
        message = self._refusal(config(), include=("DELETE /api/a",))
        self.assertIn("--include leaves 1 of the 3 operations", message)
        self.assertIn("1 skipped as non-read-only", message)
        self.assertIn("Widen --include", message)
        self.assertNotIn("ignore entry", message)

    def test_an_include_naming_only_a_route_without_a_specimen_is_refused(self) -> None:
        message = self._refusal(config(), include=("GET /api/b",))
        self.assertIn("1 for want of a specimen", message)

    def test_a_selection_left_with_no_specimen_names_the_specimen_fix(self) -> None:
        """The route is kept and is not probed for want of a specimen.

        The refusal said only "Widen --include" or "Remove an ignore entry",
        which changes WHICH operations are selected; the operation the
        operator did select would be probed by giving it a specimen, and the
        refusal never said so. Control: a selection left with only a write
        does not mention specimens, which would not help it.
        """
        for options, selection_fix in (
            ({"include": ("GET /api/b",)}, "Widen --include"),
            ({"ignore": ("/api/a",)}, "Remove an ignore entry"),
        ):
            with self.subTest(**options):
                message = self._refusal(config(), **options)
                self.assertIn(selection_fix, message)
                self.assertIn(
                    "add a matrix.specimens entry naming a real object for each "
                    "templated route without one",
                    message,
                )
        written = self._refusal(config(), include=("DELETE /api/a",))
        self.assertNotIn("matrix.specimens", written)

    def test_a_matrix_ignore_that_leaves_only_a_write_is_refused(self) -> None:
        document = config()
        document["matrix"] = {"ignore": ["GET /"]}
        self.assertIn("matrix.ignore", self._refusal(document))

    def test_control_a_selection_that_leaves_a_probe_plans_it(self) -> None:
        plan = plan_matrix(config(), self._inventory(),
                           options=MatrixOptions(include=("/api/a",)))
        self.assertEqual({probe.operation for probe in plan.probes}, {"GET /api/a"})

    def test_control_a_selection_that_excluded_nothing_is_the_unselected_case(
        self,
    ) -> None:
        """An ignore entry naming no operation in an all-mutating spec changed
        nothing about the plan, so it is the deliberate no-selection case and
        stays unrefused."""
        document = config()
        document["matrix"] = {"ignore": ["/health"]}
        paths = {"/api/orders": {"delete": {"responses": {"204": {"description": "gone"}}}}}
        plan = plan_matrix(document, inventory(paths), options=MatrixOptions())
        self.assertEqual(plan.probes, ())


@slow("stands up a loopback HTTP server and runs the engine against it")
class LiveRetryAfterTest(unittest.TestCase):
    """"The target asked us to stop" has to work with the prober we ship.

    The abort branch existed and was unit-tested through a key only a custom
    prober sets. Through ``default_prober`` -- the only prober ``map`` ever uses
    -- a 429 carrying ``Retry-After`` was indistinguishable from a bare 429, so
    a target that asked to be left alone got two more requests anyway.
    """

    def _run(self, with_retry_after: bool, on_retry_after: str = "continue") -> Any:
        server, base_url = throttling_server(with_retry_after)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        document = config(base_url=base_url)
        plan = plan_matrix(
            document,
            inventory(get_only(*[f"/api/thing{index}" for index in range(20)])),
            options=MatrixOptions(
                requests_per_second=MATRIX_MAX_RPS, on_retry_after=on_retry_after
            ),
        )
        return execute_matrix(plan, prober=default_prober(document))

    def test_a_polite_429_is_read_through_the_shipped_prober(self) -> None:
        matrix = self._run(True)
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "retry_after_requested")
        # Three, not one: a target that asks to be slowed down is not asking to
        # be abandoned, and the header used to buy a THIRD of the tolerance a
        # target that sent nothing got.
        self.assertEqual(matrix.issued, ABORT_CONSECUTIVE_RATE_LIMITED)
        self.assertEqual(matrix.retry_after_seen, ABORT_CONSECUTIVE_RATE_LIMITED)

    def test_stop_on_retry_after_still_stops_at_one(self) -> None:
        matrix = self._run(True, on_retry_after="stop")
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "retry_after_requested")
        self.assertEqual(matrix.issued, 1)

    def test_a_bare_429_still_takes_three(self) -> None:
        """Without this the previous test would pass on a broken build too."""
        matrix = self._run(False)
        self.assertEqual(matrix.abort_reason, "rate_limited")
        self.assertEqual(matrix.issued, ABORT_CONSECUTIVE_RATE_LIMITED)

    def test_the_header_value_never_reaches_an_artifact(self) -> None:
        """Presence only: the delay is target-controlled input.

        The abort REASON is allowed to say ``retry_after_requested`` -- that is
        Veridor's own vocabulary. What must never appear is anything the target
        chose.
        """
        matrix = self._run(True)
        serialized = json.dumps(matrix_document(matrix), indent=2)
        self.assertNotIn(RETRY_AFTER_SENTINEL, serialized)
        self.assertNotIn("slow down", serialized)


# ---------------------------------------------------------------------------
# 12. every request stays on the declared target's origin
# ---------------------------------------------------------------------------


class OriginContainmentTest(unittest.TestCase):
    """An OpenAPI document is untrusted input.

    ``core._perform_request`` builds the URL as
    ``urljoin(base + '/', path.lstrip('/'))``, so a spec path of
    ``/http://elsewhere/x`` lstrips to ``http://elsewhere/x`` and resolves as an
    ABSOLUTE URL. The identity's headers travel with it, and three controls miss
    it at once: ``classify_target`` reads only ``base_url``'s hostname, so a
    loopback base URL demands no acknowledgement; ``banner()`` reports the wrong
    host; and the cell keeps only ``urlsplit(url).path``, so the artifact shows
    ``/steal`` with no host at all.
    """

    ESCAPES = (
        "/http://attacker.example.com/collect",
        "/https://attacker.example.com/collect",
        "/HTTP://attacker.example.com/collect",
        "/http:%2f%2fattacker.example.com/x",
        "/http://user:pw@attacker.example.com/x",
    )

    def test_core_would_really_send_these_off_target(self) -> None:
        # The premise, asserted rather than assumed: probe_url reproduces core's
        # join exactly, so what follows is testing a real escape.
        self.assertEqual(
            probe_url("http://127.0.0.1:8765", "/http://attacker.example.com/collect"),
            "http://attacker.example.com/collect",
        )
        self.assertEqual(
            probe_url("http://127.0.0.1:8765", "/api/x"), "http://127.0.0.1:8765/api/x"
        )

    def test_a_spec_path_that_leaves_the_origin_is_refused_before_planning(self) -> None:
        for path in self.ESCAPES:
            with self.subTest(path=path):
                escaped = probe_url("http://127.0.0.1:8765", path)
                if same_origin("http://127.0.0.1:8765", escaped):
                    continue  # percent-encoded forms that do not actually escape
                with self.assertRaises(MatrixSafetyError) as raised:
                    plan_matrix(config(), inventory(get_only("/api/reports", path)))
                message = str(raised.exception)
                self.assertIn("different origin", message)
                self.assertIn("Nothing has been sent", message)

    def test_a_loopback_target_cannot_be_aimed_at_a_public_host(self) -> None:
        # The acknowledgement gate is computed from base_url alone, so this is
        # the shape that defeats it: loopback base URL, public probe.
        with self.assertRaises(MatrixSafetyError):
            plan_matrix(
                config(base_url="http://127.0.0.1:8080"),
                inventory(get_only("/https://attacker.example.com/collect")),
            )

    def test_a_hand_built_plan_is_refused_by_the_gate_execute_re_checks(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/reports")))
        smuggled = dataclasses.replace(
            plan.probes[0], path="/http://attacker.example.com/collect"
        )
        rogue = dataclasses.replace(plan, probes=(smuggled,) + plan.probes[1:])
        with self.assertRaises(MatrixSafetyError):
            rogue.refuse_if_unsafe()
        prober = RecordingProber()
        with self.assertRaises(MatrixSafetyError):
            run(rogue, prober)
        self.assertEqual(prober.count, 0, "nothing may be sent")

    def test_a_prober_that_answers_from_another_origin_abandons_the_run(self) -> None:
        # Covers the caller-supplied prober, which is arbitrary code. Without
        # this the cell would record url_path='/steal' with no host and the
        # operator could not see that a request left the target.
        plan = plan_matrix(config(), inventory(get_only("/api/reports")))
        prober = RecordingProber(
            lambda probe: result(200, url="http://attacker.example.com/steal")
        )
        with self.assertRaises(MatrixSafetyError) as raised:
            run(plan, prober)
        self.assertIn("not on target.base_url's origin", str(raised.exception))

    def test_a_path_escaping_the_base_url_prefix_is_refused(self) -> None:
        # openapi.normalize_path already collapses `..`, so this is defence in
        # depth for a hand-built plan rather than a reachable spec shape --
        # which is exactly why refuse_if_unsafe has to check it too.
        plan = plan_matrix(
            config(base_url="http://127.0.0.1:8765/api/v2"),
            inventory(get_only("/reports")),
        )
        smuggled = dataclasses.replace(plan.probes[0], path="/../../admin")
        rogue = dataclasses.replace(plan, probes=(smuggled,))
        with self.assertRaises(MatrixSafetyError) as raised:
            rogue.refuse_if_unsafe()
        self.assertIn("escapes the base path", str(raised.exception))

    def test_ordinary_paths_are_untouched(self) -> None:
        plan = plan_matrix(
            config(base_url="http://127.0.0.1:8765/api"),
            inventory(get_only("/api/reports", "/api/reports/detail")),
        )
        self.assertEqual(
            sorted({probe.path for probe in plan.probes}),
            ["/reports", "/reports/detail"],
        )
        for probe in plan.probes:
            self.assertTrue(
                same_origin(plan.base_url, probe_url(plan.base_url, probe.path))
            )

    def test_the_module_does_not_claim_an_invariant_it_does_not_hold(self) -> None:
        # The docstring used to assert "Every recorded URL has been through
        # core._safe_url", which was simply false: matrix.py never calls it.
        self.assertNotIn("_safe_url", MATRIX_SOURCE.split('"""')[1])


# ---------------------------------------------------------------------------
# 13. the rate limit is a gate, not a convention
# ---------------------------------------------------------------------------


class RateLimitIsAGateTest(unittest.TestCase):
    def plan(self, count: int = 4) -> Any:
        return plan_matrix(
            config({"alice": {"headers": {}}}),
            inventory(get_only(*[f"/api/r{index}" for index in range(count)])),
            options=MatrixOptions(requests_per_second=MATRIX_MAX_RPS),
        )

    def elapsed(self, **kwargs: Any) -> float:
        plan = self.plan()
        started = time.monotonic()
        execute_matrix(plan, prober=RecordingProber(), **kwargs)
        return time.monotonic() - started

    def test_a_no_op_sleeper_cannot_disable_the_limiter(self) -> None:
        # ``sleeper`` is a public keyword defaulting to time.sleep and was the
        # one safety gate execute_matrix did not re-check: sleeper=lambda _:None
        # turned a declared 1 req/s into 400,000 req/s with nothing raised,
        # while the plan, the banner and the artifact all went on reporting the
        # declared rate. A --no-throttle flag was one keyword away.
        floor = 3 * (1.0 / MATRIX_MAX_RPS) * 0.95
        self.assertGreaterEqual(self.elapsed(sleeper=lambda _seconds: None), floor)

    def test_a_clock_that_never_advances_cannot_disable_the_limiter_either(self) -> None:
        floor = 3 * (1.0 / MATRIX_MAX_RPS) * 0.95
        self.assertGreaterEqual(
            self.elapsed(clock=lambda: 0.0, sleeper=lambda _seconds: None), floor
        )

    @slow("waits out the real-clock rate floor once per clock and sleeper (1.3 s measured)")
    def test_a_clock_that_runs_fast_cannot_disable_the_limiter(self) -> None:
        # REGRESSION. The real-clock fallback only ran when the injected clock
        # LAGGED. A clock that runs ahead of real time -- a counter, a clock in
        # milliseconds -- satisfied every deadline without any wait: 40
        # requests at a declared 1 req/s went out in 0.0005s, and the run
        # document still said 1 req/s.
        floor = 3 * (1.0 / MATRIX_MAX_RPS) * 0.95
        ticks = iter(range(10**6))
        clocks = {
            "counter": lambda: float(next(ticks)),
            "milliseconds": lambda: time.monotonic() * 1000,
        }
        for name, clock in clocks.items():
            with self.subTest(clock=name):
                for sleeper in (lambda _seconds: None, time.sleep):
                    self.assertGreaterEqual(
                        self.elapsed(clock=clock, sleeper=sleeper), floor
                    )

    def test_the_honest_test_seam_still_costs_no_real_time(self) -> None:
        # A fake clock that advances when its sleeper is called -- the ordinary
        # test shape -- must still satisfy the deadline without sleeping, or
        # every test in this file gets slower.
        clock = FakeClock()
        plan = self.plan(count=40)
        started = time.monotonic()
        run(plan, RecordingProber(), clock)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(len(clock.sleeps), plan.requests_planned - 1)

    @staticmethod
    def still_then_jump() -> Any:
        """A monotonic clock that holds still across the sleeper calls, then jumps.

        Per request: one read for ``last_started``, three throttle reads that
        each ask the sleeper for a full interval, then a final read that jumps
        forward by the total asked.
        """
        interval = 1.0 / MATRIX_MAX_RPS
        state = {"now": 0.0, "reads": 0}

        def clock() -> float:
            state["reads"] += 1
            if state["reads"] % 5 == 0:
                state["now"] += 3 * interval
            return state["now"]

        return clock

    @staticmethod
    def reads_backwards() -> Any:
        """A clock whose first throttle read is far in the past."""
        state = {"now": 0.0, "reads": 0}

        def clock() -> float:
            state["reads"] += 1
            phase = state["reads"] % 4
            if phase == 1:
                state["now"] += 1.0
                return state["now"]
            if phase == 2:
                return state["now"] - 1000.0
            return state["now"] + 0.5

        return clock

    def test_the_injected_clock_shapes_the_docstrings_call_trusted_are_unchecked(self) -> None:
        # The docstrings said the one injected shape still trusted was a
        # sleeper that advances its fake clock by exactly the wait. The check
        # measures the clock against the waits it asked for, and those are
        # computed from the clock's own readings, so it cannot tell that seam
        # from a clock that holds still and then jumps, or one that reads
        # backwards: both get under the floor with a sleeper that does
        # nothing. Library-only -- the CLI passes neither keyword. This pins
        # what the docstrings now say; if it starts failing, the limiter got
        # stricter and the docstrings should say so.
        floor = 3 * (1.0 / MATRIX_MAX_RPS) * 0.95
        for name, clock in (("still_then_jump", self.still_then_jump()),
                            ("reads_backwards", self.reads_backwards())):
            with self.subTest(clock=name):
                self.assertLess(
                    self.elapsed(clock=clock, sleeper=lambda _seconds: None), floor
                )
        # Control: the same clocks are served in real time once the default
        # clock is in charge, whatever the sleeper does.
        self.assertGreaterEqual(
            self.elapsed(clock=time.monotonic, sleeper=lambda _seconds: None), floor
        )

    def test_a_fake_clock_that_also_advances_in_the_prober_costs_real_time(self) -> None:
        # The other side of the same check: a fake clock that ALSO advances
        # outside the sleeper (simulated latency) runs ahead of the waits asked
        # for and is not trusted, so every request costs a real interval.
        clock = FakeClock()

        def slow_prober(probe: Any) -> Any:
            clock.now += 0.02
            return RecordingProber()(probe)

        floor = 3 * (1.0 / MATRIX_MAX_RPS) * 0.95
        started = time.monotonic()
        execute_matrix(self.plan(), prober=slow_prober, clock=clock.time,
                       sleeper=clock.sleep)
        self.assertGreaterEqual(time.monotonic() - started, floor)

    def test_the_clock_docstrings_promise_no_more_than_the_limiter_checks(self) -> None:
        # REGRESSION (docs). Three docstrings named "the one shape still
        # trusted" -- a sleeper that advances its clock by exactly the wait --
        # as though every other injected clock were caught. The two tests
        # above show it is not. Each passage must now say an injected clock is
        # trusted rather than checked, name the shapes that are caught, and
        # say the real-time guarantee is the default clock's.
        from veridor import matrix as matrix_module

        passages = {
            "module": matrix_module.__doc__ or "",
            "_throttle": matrix_module._throttle.__doc__ or "",
            "execute_matrix": matrix_module.execute_matrix.__doc__ or "",
        }
        for name, text in passages.items():
            prose = " ".join(text.split())
            with self.subTest(docstring=name):
                self.assertNotIn("one shape still trusted", prose)
                self.assertNotIn("one shape trusted", prose)
                self.assertNotIn("remains trusted is that one shape", prose)
                self.assertIn("trusted, not checked", prose)
                self.assertIn("holds still", prose)
                self.assertIn("reads backwards", prose)
                self.assertIn("runs ahead", prose)
                self.assertIn("default", prose)


# ---------------------------------------------------------------------------
# 14. throttling that stays under a percentage is still throttling
# ---------------------------------------------------------------------------


class ThrottleAbortTest(unittest.TestCase):
    @staticmethod
    def plan(operations: int = 1000) -> Any:
        return plan_matrix(
            config({"alice": {"headers": {}}}),
            inventory(get_only(*[f"/api/r{index}" for index in range(operations)])),
            options=MatrixOptions(max_requests=operations),
        )

    def issue(self, every: int, plan: Any) -> Any:
        """Answer 429 on every ``every``-th request of ``plan``; run until it stops."""
        state = {"issued": 0}

        def responder(_probe: Any) -> dict[str, Any]:
            state["issued"] += 1
            return result(429 if state["issued"] % every == 0 else 200)

        return run(plan, RecordingProber(responder))

    def test_a_leaky_bucket_throttle_stops_the_run(self) -> None:
        # A burst draws a 429 and the bucket refills: the ordinary production
        # shape. The 429s are neither consecutive (streak rule needs 3) nor a
        # large enough share (20%, and the comparison was strict so the cliff
        # was really 25%), so a 10,000-request plan ran to completion having
        # ignored 2,000 throttle responses.
        # One plan for all five: planning 1,000 operations was two thirds of
        # this test's cost, and a MatrixPlan is frozen, all tuples, so a run
        # cannot change what the next one is handed.
        plan = self.plan()
        for every in (5, 6, 10, 20, 100):
            with self.subTest(one_in=every):
                matrix = self.issue(every, plan)
                self.assertTrue(matrix.aborted, f"1-in-{every} ground through")
                self.assertLess(matrix.issued, matrix.planned)
                self.assertLessEqual(
                    matrix.issued // every,
                    ABORT_TOTAL_RATE_LIMITED,
                    "no more 429s than the cumulative cap may be ignored",
                )

    def test_the_documented_hostile_share_is_the_real_threshold(self) -> None:
        # `>` rather than `>=` put the documented 20% cliff at 25%.
        plan = plan_matrix(
            config({"alice": {"headers": {}}}),
            inventory(get_only(*[f"/api/r{index}" for index in range(40)])),
        )
        state = {"issued": 0}

        def responder(_probe: Any) -> dict[str, Any]:
            state["issued"] += 1
            # 503 rather than 429 so the cumulative-429 cap is not what fires.
            return result(503) if state["issued"] % 5 == 0 else result(200)

        matrix = run(plan, RecordingProber(responder))
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "hostile_rate")
        self.assertEqual(matrix.issued, ABORT_HOSTILE_MINIMUM)
        self.assertAlmostEqual(ABORT_HOSTILE_SHARE, 0.20)

    def test_a_healthy_target_still_runs_to_completion(self) -> None:
        plan = plan_matrix(
            config({"alice": {"headers": {}}}),
            inventory(get_only(*[f"/api/r{index}" for index in range(60)])),
        )
        matrix = run(plan, RecordingProber())
        self.assertFalse(matrix.aborted)
        self.assertEqual(matrix.issued, matrix.planned)

    def test_an_isolated_throttle_below_the_cap_does_not_abort(self) -> None:
        plan = plan_matrix(
            config({"alice": {"headers": {}}}),
            inventory(get_only(*[f"/api/r{index}" for index in range(60)])),
        )
        state = {"issued": 0}

        def responder(_probe: Any) -> dict[str, Any]:
            state["issued"] += 1
            return result(429) if state["issued"] in (5, 25) else result(200)

        matrix = run(plan, RecordingProber(responder))
        self.assertFalse(matrix.aborted)
        self.assertEqual(matrix.issued, matrix.planned)


# ---------------------------------------------------------------------------
# 15. every envelope knob has a ceiling, including the ones made of time
# ---------------------------------------------------------------------------


class TimeCeilingTest(unittest.TestCase):
    def test_an_unbounded_timeout_is_refused(self) -> None:
        # max_requests, requests_per_second and specimens all had hard ceilings;
        # timeout_seconds had none, and it is the one knob that can make a plan
        # sized in minutes run for hours against a half-open socket.
        for value in (10**9, MATRIX_MAX_TIMEOUT_SECONDS + 0.1):
            with self.subTest(value=value):
                with self.assertRaises(MatrixSafetyError) as raised:
                    MatrixOptions(timeout_seconds=value)
                self.assertIn("ceiling", str(raised.exception))
        self.assertEqual(
            MatrixOptions(timeout_seconds=MATRIX_MAX_TIMEOUT_SECONDS).timeout_seconds,
            MATRIX_MAX_TIMEOUT_SECONDS,
        )

    def test_the_config_timeout_is_held_to_the_same_ceiling(self) -> None:
        document = config()
        document["target"]["timeout_seconds"] = 10**9
        with self.assertRaises(MatrixSafetyError):
            plan_matrix(document, inventory(get_only("/api/a")))
        with self.assertRaises(MatrixSafetyError):
            default_prober(document)

    def test_nan_is_refused_by_every_numeric_knob(self) -> None:
        """NaN is neither <= 0 nor over a ceiling, so every comparison let it
        through: MatrixOptions accepted it for the rate, the wall clock and the
        timeout, and `map --rate nan` / `--max-run-seconds nan` then crashed
        with exit 70 (measured) instead of being refused."""
        for knob in ("requests_per_second", "max_run_seconds", "timeout_seconds"):
            with self.subTest(knob=knob):
                with self.assertRaises(MatrixSafetyError) as raised:
                    MatrixOptions(**{knob: float("nan")})
                self.assertIn(knob, str(raised.exception))
                self.assertIn("finite", str(raised.exception))
        # Control: the same knobs take an ordinary value.
        self.assertEqual(
            MatrixOptions(requests_per_second=1.0, max_run_seconds=60.0,
                          timeout_seconds=5.0).max_run_seconds, 60.0)

    def test_map_refuses_nan_with_exit_2_before_anything_is_sent(self) -> None:
        from veridor.cli import main as veridor_main  # noqa: PLC0415

        spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
                "paths": {"/api/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}
        for flag in ("--rate", "--max-run-seconds", "--timeout"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "c.json").write_text(json.dumps(config()), encoding="utf-8")
                (root / "o.json").write_text(json.dumps(spec), encoding="utf-8")
                stderr = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(stderr):
                    code = veridor_main(["map", "--config", str(root / "c.json"),
                                         "--openapi", str(root / "o.json"),
                                         "--output-dir", str(root / "out"), flag, "nan"])
                self.assertEqual(code, 2, stderr.getvalue())
                self.assertIn("finite", stderr.getvalue())
                self.assertNotIn("internal error", stderr.getvalue())

    @slow("runs `veridor map` end to end through the CLI (1.0 s measured)")
    def test_map_timeout_is_the_timeout_every_request_uses(self) -> None:
        # REGRESSION. `--timeout` reached plan.timeout_seconds, whose only
        # reader was the banner; default_prober rebuilt the timeout from
        # target.timeout_seconds. The banner said 1.5s and every request
        # waited 3s.
        from veridor import core  # noqa: PLC0415
        from veridor.cli import main as veridor_main  # noqa: PLC0415

        spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
                "paths": {"/api/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}
        for flags, expected in (((), 3.0), (("--timeout", "1.5"), 1.5)):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "c.json").write_text(json.dumps(config()), encoding="utf-8")
                (root / "o.json").write_text(json.dumps(spec), encoding="utf-8")
                timeouts: list[float] = []

                def recorder(base_url, timeout, request_config, identity, **kwargs):
                    timeouts.append(timeout)
                    return result(200)

                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(core, "_perform_request", recorder), \
                        contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    veridor_main(["map", "--config", str(root / "c.json"),
                                  "--openapi", str(root / "o.json"),
                                  "--output-dir", str(root / "out"), *flags])
                self.assertTrue(timeouts, stderr.getvalue())
                self.assertEqual(set(timeouts), {expected})
                self.assertIn(
                    f"{expected:g}s per request", stdout.getvalue() + stderr.getvalue()
                )

    def test_the_run_has_a_wall_clock_and_it_cannot_be_raised_without_limit(self) -> None:
        with self.assertRaises(MatrixSafetyError) as raised:
            MatrixOptions(max_run_seconds=MATRIX_ABSOLUTE_MAX_RUN_SECONDS + 1)
        self.assertIn("cannot be overridden", str(raised.exception))

    def test_a_slow_target_stops_at_the_wall_clock_with_a_usable_matrix(self) -> None:
        # estimated_seconds counts the rate limiter and explicitly excludes
        # response time, so a slow or half-open target used to run past the
        # number the banner showed with no ceiling at all. The consecutive
        # transport abort does not help: a socket that hangs until the timeout
        # returns normally.
        plan = plan_matrix(
            config({"alice": {"headers": {}}}),
            inventory(get_only(*[f"/api/r{index}" for index in range(30)])),
            options=MatrixOptions(
                requests_per_second=MATRIX_MAX_RPS, max_run_seconds=0.25
            ),
        )

        def slow(_probe: Any) -> dict[str, Any]:
            time.sleep(0.05)
            return result(200)

        prober = RecordingProber(slow)
        started = time.monotonic()
        matrix = run(plan, prober)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0)
        self.assertTrue(matrix.aborted)
        self.assertEqual(matrix.abort_reason, "time_limit")
        self.assertLess(matrix.issued, matrix.planned)
        # partial results are kept and the rest are unknown, never refused
        self.assertEqual(len(matrix.cells), len(plan.rows) * len(plan.identities))
        for cell in matrix.cells:
            if cell.unknown_reason == "aborted":
                self.assertEqual(cell.reach, REACH_UNKNOWN)
                self.assertIsNone(cell.refusal_kind)

    def test_the_banner_shows_the_wall_clock_and_the_timeout(self) -> None:
        plan = plan_matrix(config(), inventory(get_only("/api/a")))
        banner = plan.banner()
        self.assertIn("the run stops at", banner)
        self.assertIn("timeout:", banner)


if __name__ == "__main__":
    unittest.main()
