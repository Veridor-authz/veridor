"""Matrix drift: the path where the operator declares nothing.

Every other verb costs the user a declaration. This one costs two credentials
and a spec, records reality on the first run, and diffs on every run after --
the bargain snapshot testing makes, and the reason snapshot tests were adopted
where hand-written assertions were not.

Two properties carry the weight here:

* the ORDER in which the baseline is resolved. `map` writes its matrix into the
  same directory a user passes as ``--baseline``, so resolving it afterwards
  makes a run its own baseline: zero drift, and it reads like good news.
* what drift is ALLOWED to say. A change is an observation. Reach that opened
  may be a feature; reach that closed may be a broken deploy. Nothing here is a
  finding and `map` still exits 0 unless the operator asked drift to gate.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from veridor import drift  # noqa: E402
from veridor.cli import _parser  # noqa: E402


def _matrix(cells: list[dict], base_url: str = "http://127.0.0.1:8765") -> dict:
    return {"kind": "veridor.matrix", "target": {"base_url": base_url}, "cells": cells}


def _cell(operation="GET /a", identity="attacker", reach="refused",
          status=403, marker_scan="absent", **extra) -> dict:
    cell = {
        "operation": operation, "identity": identity, "specimen": None,
        "reach": reach, "status": status, "marker_scan": marker_scan,
    }
    cell.update(extra)
    return cell


class ChangeDetectionTest(unittest.TestCase):
    def test_a_refusal_that_became_a_success_is_significant(self) -> None:
        report = drift.compare(
            _matrix([_cell(reach="refused", status=403)]),
            _matrix([_cell(reach="reached", status=200)]),
        )
        self.assertEqual(report["counts"], {drift.REACH_OPENED: 1})
        self.assertEqual(report["significant"], 1)

    def test_a_marker_that_appeared_is_significant(self) -> None:
        """The strongest signal available without any declaration."""
        report = drift.compare(
            _matrix([_cell(reach="reached", marker_scan="absent")]),
            _matrix([_cell(reach="reached", marker_scan="present", marker_owner="owner")]),
        )
        self.assertEqual(report["counts"], {drift.MARKER_APPEARED: 1})
        self.assertIn("'owner'", report["changes"][0]["note"])

    def test_reach_that_closed_is_reported_but_not_significant(self) -> None:
        """It may be a fix. It may be a feature that broke. Veridor cannot tell."""
        report = drift.compare(
            _matrix([_cell(reach="reached", status=200)]),
            _matrix([_cell(reach="refused", status=403)]),
        )
        self.assertEqual(report["counts"], {drift.REACH_CLOSED: 1})
        self.assertEqual(report["significant"], 0)
        self.assertIn("may be a fix", report["changes"][0]["note"])

    def test_unknown_becoming_reached_is_a_measurement_not_a_change(self) -> None:
        """The baseline never measured it, so nothing is known about access.

        This used to be reported as `reach_appeared`. The name was the least of
        it: what matters is that a cell nobody measured cannot be compared, and
        saying anything else about it invents a fact.
        """
        report = drift.compare(
            _matrix([_cell(reach="unknown", status=None)]),
            _matrix([_cell(reach="reached", status=200)]),
        )
        self.assertEqual(report["counts"], {drift.MEASUREMENT_GAINED: 1})
        self.assertEqual(report["significant"], 0)
        self.assertEqual(report["blind_cells"], 1)


class NoiseFloorTest(unittest.TestCase):
    """Every case here was a false positive measured against a real target.

    `scripts/noise_floor_study.py` runs `map` repeatedly against an API whose
    authorization boundary never changes and whose everything-else moves the
    way a real one does. Before these fixes it reported change on 100% of runs
    and failed the build on 20% of them. That is not a tuning problem: a gate
    that cries wolf is switched off, and then it is worth nothing on the week
    it matters.
    """

    def test_a_rate_limited_cell_is_not_reach_that_closed(self) -> None:
        """A 429 was reported as "this identity was served here and is not now.
        That may be a fix, or a feature that broke" -- about a rate limit."""
        report = drift.compare(
            _matrix([_cell(reach="reached", status=200)]),
            _matrix([_cell(reach="unknown", status=429)]),
        )
        self.assertEqual(report["counts"], {drift.MEASUREMENT_LOST: 1})
        self.assertEqual(report["significant"], 0)
        self.assertIn("Nothing follows about access", report["changes"][0]["note"])

    def test_two_different_failures_are_not_a_status_change(self) -> None:
        """A timeout in one run and a 429 in the other are two absences. This
        fell through to "the status code changed without changing whether the
        identity was served", about two requests nobody answered."""
        report = drift.compare(
            _matrix([_cell(reach="unknown", status=None)]),
            _matrix([_cell(reach="unknown", status=429)]),
        )
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["unmeasured_cells"], 1)

    def test_the_marker_in_its_own_owners_response_is_not_a_crossing(self) -> None:
        """The dominant false gate, and a category error rather than noise.

        The owner is supposed to see their own data. Whether page one of a
        collection sorted by "recently updated" still holds the marked record
        has nothing to do with authorization -- and `marker_appeared` is
        SIGNIFICANT, so this failed builds on up to 75% of runs against a
        target whose boundary never moved. `blastradius.marker_reach` already
        skipped `owner == identity`; this rule had not carried it over.
        """
        for before, after in (("absent", "present"), ("present", "absent")):
            with self.subTest(transition=f"{before}->{after}"):
                report = drift.compare(
                    _matrix([_cell(identity="owner", reach="reached",
                                   marker_scan=before, marker_owner="owner")]),
                    _matrix([_cell(identity="owner", reach="reached",
                                   marker_scan=after, marker_owner="owner")]),
                )
                self.assertEqual(report["changes"], [])

    def test_a_marker_crossing_to_someone_else_is_still_caught(self) -> None:
        """The suppression above must not cost the real signal."""
        report = drift.compare(
            _matrix([_cell(identity="attacker", reach="reached",
                           marker_scan="absent", marker_owner="owner")]),
            _matrix([_cell(identity="attacker", reach="reached",
                           marker_scan="present", marker_owner="owner")]),
        )
        self.assertEqual(report["counts"], {drift.MARKER_APPEARED: 1})
        self.assertEqual(report["significant"], 1)

    def test_no_policy_gates_on_an_unmeasured_cell(self) -> None:
        """Including `any`. These alone made it fire on 100% of runs.

        A second cell is measured in both runs, so this is a comparison that
        saw something and the 503 is the only difference. With that cell alone
        the comparison measured nothing at all, which is exit 3 under a gate
        (see NothingMeasuredInBothTest) -- and still never the drift code 1.
        """
        report = drift.compare(
            _matrix([_cell(reach="reached"), _cell(operation="GET /b")]),
            _matrix([_cell(reach="unknown", status=503), _cell(operation="GET /b")]),
        )
        for policy in ("none", "opened", "any"):
            with self.subTest(policy=policy):
                self.assertEqual(drift.exit_code(report, policy), 0)
        alone = drift.compare(
            _matrix([_cell(reach="reached")]),
            _matrix([_cell(reach="unknown", status=503)]),
        )
        for policy in ("opened", "any"):
            with self.subTest(policy=policy, cells=1):
                self.assertNotEqual(drift.exit_code(alone, policy), 1)

    def test_any_still_gates_on_a_real_difference(self) -> None:
        report = drift.compare(
            _matrix([_cell(reach="reached", status=200)]),
            _matrix([_cell(reach="refused", status=403)]),
        )
        self.assertEqual(drift.exit_code(report, "any"), 1)

    def test_a_blind_baseline_is_reported_above_everything_else(self) -> None:
        """The failure a gate must never have silently.

        A baseline recorded through one bad minute missed a genuine boundary
        opening on 8 runs out of 8 -- while reporting nothing significant,
        because every comparison there is `unknown -> something`. The report
        cannot prevent that, but it must never let it read as a clean bill.
        """
        report = drift.compare(
            _matrix([_cell(reach="unknown", status=429)]),
            _matrix([_cell(reach="reached", status=200)]),
        )
        self.assertEqual(report["blind_cells"], 1)
        text = drift.render(report)
        self.assertIn("THE BASELINE NEVER MEASURED", text)
        self.assertIn("BLIND", text)
        self.assertIn("Re-record the baseline", text)
        # And it must come before the changes it qualifies.
        self.assertLess(text.index("BLIND"), text.index("measurement_gained"))

    def test_map_warns_when_the_matrix_it_wrote_is_a_poor_baseline(self) -> None:
        from veridor.cli import _baseline_quality_advice  # noqa: PLC0415

        advice = _baseline_quality_advice({"cells": [
            {"unknown_reason": "rate_limited"},
            {"unknown_reason": "server_error"},
            {"unknown_reason": "skipped_no_specimen"},
            {"unknown_reason": None},
        ]})
        self.assertIn("2 cell(s)", advice)
        self.assertIn("NOT fine as a baseline", advice)
        # Deliberate skips recur identically every run and compare cleanly, so
        # warning about them would be noise about noise.
        self.assertNotIn("skipped_no_specimen", advice)

    def test_a_clean_matrix_produces_no_baseline_warning(self) -> None:
        from veridor.cli import _baseline_quality_advice  # noqa: PLC0415

        self.assertEqual(_baseline_quality_advice({"cells": [
            {"unknown_reason": None}, {"unknown_reason": "skipped_mutating"},
        ]}), "")

    def test_an_identical_matrix_produces_no_change(self) -> None:
        report = drift.compare(_matrix([_cell()]), _matrix([_cell()]))
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["significant"], 0)

    def test_inventory_changes_are_recorded_on_both_sides(self) -> None:
        report = drift.compare(
            _matrix([_cell(operation="GET /gone")]),
            _matrix([_cell(operation="GET /new")]),
        )
        self.assertEqual(
            report["counts"],
            {drift.OPERATION_ADDED: 1, drift.OPERATION_REMOVED: 1},
        )

    def test_an_identity_added_later_is_not_silently_compared(self) -> None:
        report = drift.compare(
            _matrix([_cell(identity="a")]),
            _matrix([_cell(identity="a"), _cell(identity="b")]),
        )
        self.assertEqual(report["counts"], {drift.IDENTITY_ADDED: 1})
        self.assertIn("not probed for the baseline", report["changes"][0]["note"])


class ClaimDisciplineTest(unittest.TestCase):
    """Drift observes. It never concludes."""

    def test_no_change_is_ever_called_a_vulnerability(self) -> None:
        report = drift.compare(
            _matrix([_cell(reach="refused")]),
            _matrix([_cell(reach="reached", marker_scan="present", marker_owner="o")]),
        )
        blob = json.dumps(report).lower() + drift.render(report).lower()
        for word in ("vulnerab", "exploit", "insecure", "breach", "proven"):
            with self.subTest(word=word):
                self.assertNotIn(word, blob)

    def test_an_empty_diff_is_not_reported_as_a_clean_bill_of_health(self) -> None:
        text = drift.render(drift.compare(_matrix([_cell()]), _matrix([_cell()])))
        self.assertIn("Nothing moved", text)
        self.assertIn("not a clean bill of health", text)
        # The specific blindness has to be named, or "nothing moved" reads as
        # "nothing is wrong".
        self.assertIn("open to everyone since the first run", text)

    def test_comparing_two_different_targets_is_called_out(self) -> None:
        text = drift.render(drift.compare(
            _matrix([_cell()], base_url="http://a"),
            _matrix([_cell()], base_url="http://b"),
        ))
        self.assertIn("different targets", text)

    def test_the_specimen_is_printed_when_there_is_one(self) -> None:
        """Drift on one object is not the same claim as drift on the operation."""
        text = drift.render(drift.compare(
            _matrix([_cell(specimen="owner_invoice", reach="refused")]),
            _matrix([_cell(specimen="owner_invoice", reach="reached")]),
        ))
        self.assertIn("[specimen owner_invoice]", text)

    def test_notes_are_wrapped_rather_than_run_off_a_terminal(self) -> None:
        text = drift.render(drift.compare(
            _matrix([_cell(reach="refused")]),
            _matrix([_cell(reach="reached", marker_scan="present", marker_owner="o")]),
        ))
        widest = max(len(line) for line in text.splitlines())
        self.assertLess(widest, 100, f"a {widest}-char line will wrap unreadably")

    def test_the_claim_states_what_drift_is_blind_to(self) -> None:
        self.assertIn("did not change", drift.CLAIM["blind_to"])
        self.assertIn("feature", drift.CLAIM["does_not_measure"])


class UnmeasuredAttributionTest(unittest.TestCase):
    """A cell the plan never sent is not a cell the target failed to answer.

    Both are `unknown`, and reading only the reach made every CRUD-shaped spec
    print two alarming warnings above `0 change(s)`, forever: a rate limit that
    never happened, and the advice to re-record against a quiet target, which
    produces byte-identical output every time it is followed.
    """

    def _structural(self, count: int = 8, clean: int = 12) -> dict:
        cells = [
            _cell(operation=f"GET /r{index}", reach="refused") for index in range(clean)
        ] + [
            _cell(operation=f"POST /r{index}", reach="unknown", status=None,
                  unknown_reason="skipped_mutating")
            for index in range(count)
        ]
        return drift.compare(_matrix(cells), _matrix(cells))

    def test_the_reasons_are_the_ones_the_matrix_can_record(self) -> None:
        # The literals are duplicated on purpose -- matrix imports nothing from
        # drift -- so the duplication is pinned rather than trusted.
        from veridor.matrix import UNKNOWN_REASONS

        self.assertTrue(drift.NOT_PROBED_REASONS <= UNKNOWN_REASONS)
        self.assertEqual(
            UNKNOWN_REASONS - drift.NOT_PROBED_REASONS,
            {"transport_error", "rate_limited", "server_error", "proxy_auth_required", "aborted"},
        )

    def test_cells_the_plan_never_sent_are_not_reported_as_a_rate_limit(self) -> None:
        text = drift.render(self._structural())
        self.assertNotIn("rate limit", text)
        self.assertNotIn("Re-record the baseline", text)
        self.assertIn("WERE NEVER PROBED", text)
        self.assertIn("skipped_mutating x8", text)
        self.assertIn("re-running changes nothing", text)

    def test_a_real_transient_still_gets_the_loud_wording(self) -> None:
        base = [_cell(operation=f"GET /r{index}") for index in range(12)]
        now = [_cell(operation=f"GET /r{index}") for index in range(9)] + [
            _cell(operation=f"GET /r{index}", reach="unknown", status=429,
                  unknown_reason="rate_limited")
            for index in range(9, 12)
        ]
        text = drift.render(drift.compare(_matrix(base), _matrix(now)))
        self.assertIn("a rate limit, a server error, a timeout,", text)
        self.assertNotIn("WERE NEVER PROBED", text)

    def test_an_unrecorded_reason_stays_on_the_transient_side(self) -> None:
        """An older matrix, or one built by hand, keeps the wording it had."""
        base = [_cell(reach="unknown", status=None)]
        report = drift.compare(_matrix(base), _matrix([_cell(reach="refused")]))
        self.assertEqual(report["blind_cells"], 1)
        self.assertEqual(report["blind_cells_not_probed"], 0)
        self.assertIn("Re-record the baseline", drift.render(report))

    def test_each_census_names_only_the_cells_its_warning_counts(self) -> None:
        # The baseline is blind on three cells for one reason; five further
        # cells go unmeasured this run for another. Naming both reasons in both
        # warnings is the misattribution, one layer down.
        base = [
            _cell(operation=f"GET /s{index}", reach="unknown", status=None,
                  unknown_reason="skipped_no_specimen") for index in range(3)
        ] + [_cell(operation=f"POST /m{index}") for index in range(5)] + [
            _cell(operation=f"GET /o{index}") for index in range(12)
        ]
        now = [
            _cell(operation=f"GET /s{index}", reach="unknown", status=None,
                  unknown_reason="skipped_no_specimen") for index in range(3)
        ] + [
            _cell(operation=f"POST /m{index}", reach="unknown", status=None,
                  unknown_reason="skipped_mutating") for index in range(5)
        ] + [_cell(operation=f"GET /o{index}") for index in range(12)]
        report = drift.compare(_matrix(base), _matrix(now))
        self.assertEqual(report["blind_reasons"], {"skipped_no_specimen": 3})
        blind, rest = drift.render(report).split("further comparable")
        self.assertIn("skipped_no_specimen x3", blind)
        self.assertNotIn("skipped_mutating", blind)
        self.assertIn("skipped_mutating x5", rest)
        self.assertNotIn("skipped_no_specimen", rest)

    def test_the_census_sums_to_the_count_it_explains(self) -> None:
        # Counted per RUN rather than per CELL, a cell unknown in both runs for
        # two reasons was credited twice, so the census exceeded the number of
        # cells it claimed to break down.
        base = [_cell(operation="GET /a", reach="unknown", status=429,
                      unknown_reason="rate_limited")] + [
            _cell(operation=f"POST /m{index}", reach="unknown", status=None,
                  unknown_reason="skipped_mutating") for index in range(8)
        ]
        now = [_cell(operation="GET /a", reach="unknown", status=None,
                     unknown_reason="skipped_mutating")] + [
            _cell(operation=f"POST /m{index}", reach="unknown", status=None,
                  unknown_reason="skipped_mutating") for index in range(8)
        ]
        report = drift.compare(_matrix(base), _matrix(now))
        self.assertEqual(sum(report["unmeasured_reasons"].values()),
                         report["unmeasured_cells"])
        self.assertEqual(sum(report["blind_reasons"].values()), report["blind_cells"])

    def test_the_grid_share_is_stated_once_not_inside_a_warning(self) -> None:
        # "1 of 9 could not be measured ... drift saw 0% of the grid" blamed a
        # single rate limit for a loss eight structural cells caused.
        base = [_cell(operation="GET /q", reach="unknown", status=429,
                      unknown_reason="rate_limited")] + [
            _cell(operation=f"POST /m{index}", reach="unknown", status=None,
                  unknown_reason="skipped_mutating") for index in range(8)
        ]
        now = [_cell(operation="GET /q")] + [
            _cell(operation=f"POST /m{index}", reach="unknown", status=None,
                  unknown_reason="skipped_mutating") for index in range(8)
        ]
        text = drift.render(drift.compare(_matrix(base), _matrix(now)))
        self.assertEqual(text.count("of the grid"), 1)
        share = [line for line in text.splitlines() if "of the grid" in line][0]
        self.assertNotIn("!!", share)
        self.assertNotIn("rate limit", share)
        self.assertIn("drift saw 0% of the grid", share)

    def test_every_line_survives_a_wide_reason_census(self) -> None:
        # The existing wrap test renders a fixture with no unmeasured cell at
        # all, so it never sees this block.
        cells = []
        for reason, count in (("skipped_mutating", 24), ("skipped_no_specimen", 12),
                              ("skipped_ignored", 9), ("skipped_budget", 4),
                              ("not_probed", 2)):
            cells += [
                _cell(operation=f"GET /{reason}{index}", reach="unknown", status=None,
                      unknown_reason=reason) for index in range(count)
            ]
        cells += [_cell(operation=f"GET /o{index}") for index in range(9)]
        text = drift.render(drift.compare(_matrix(cells), _matrix(cells)))
        widest = max(len(line) for line in text.splitlines())
        self.assertLess(widest, 100, f"a {widest}-char line will wrap unreadably")

    def test_unmeasured_still_gates_nothing(self) -> None:
        report = self._structural()
        for policy in ("opened", "any"):
            self.assertEqual(drift.exit_code(report, policy), 0)


class IncomparableCellTest(unittest.TestCase):
    """Two matrices whose cells do not line up produce no changes.

    So does an empty run. `_key` carries the specimen, but only whole
    operations and whole identities are diffed for add/remove -- so re-seeding
    a fixture, which changes the specimen LABEL, made every affected cell
    vanish from the comparison. No change, no census, and "Nothing moved.
    Every comparable cell reads the same as the baseline." printed over a
    measured cross-tenant read carrying the victim's marker.
    """

    def _reseeded(self) -> dict:
        return drift.compare(
            _matrix([_cell(specimen="seed-a", reach="refused", status=403)]),
            _matrix([_cell(specimen="seed-b", reach="reached", status=200,
                           marker_scan="present", marker_owner="victim")]),
        )

    def test_a_cell_only_one_run_holds_is_counted(self) -> None:
        report = self._reseeded()
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["comparable_cells"], 0)
        self.assertEqual(report["incomparable_cells"], 2)

    def test_nothing_moved_is_not_printed_over_a_void_comparison(self) -> None:
        text = drift.render(self._reseeded())
        self.assertNotIn("Nothing moved", text)
        self.assertIn("EXIST IN ONLY ONE OF THE TWO RUNS", text)
        self.assertIn("Nothing to compare", text)

    def test_a_real_quiet_run_still_says_nothing_moved(self) -> None:
        """The control: the reassuring sentence must survive where it is true."""
        text = drift.render(drift.compare(
            _matrix([_cell(reach="refused")]), _matrix([_cell(reach="refused")])
        ))
        self.assertIn("Nothing moved", text)

    def test_a_void_comparison_is_not_a_pass_under_a_gate(self) -> None:
        from veridor.cli import _emit_drift

        namespace = _parser().parse_args([
            "map", "--config", "c.json", "--openapi", "s.json",
            "--baseline", "b.json", "--fail-on-drift", "opened",
        ])
        with tempfile.TemporaryDirectory() as directory:
            namespace.output_dir = Path(directory)
            namespace.drift_path = None
            baseline = _matrix([_cell(specimen="seed-a", reach="refused")])
            current = _matrix([_cell(specimen="seed-b", reach="reached", status=200)])
            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()):
                with contextlib.redirect_stderr(stderr):
                    code = _emit_drift(namespace, current, baseline, "map-id")
        self.assertEqual(code, 3)
        self.assertIn("compared nothing", stderr.getvalue())

    def test_a_malformed_cell_is_an_input_error(self) -> None:
        """Not an AttributeError traceback on the exit-1 gate path."""
        with self.assertRaises(drift.DriftError) as caught:
            drift.compare({"cells": ["not a cell"]}, _matrix([_cell()]))
        self.assertIn("not an object", str(caught.exception))

    def test_the_grid_share_never_rounds_up_to_complete(self) -> None:
        base = [_cell(operation=f"GET /o{index}") for index in range(1000)]
        now = [_cell(operation=f"GET /o{index}") for index in range(996)] + [
            _cell(operation=f"GET /o{index}", reach="unknown", status=429,
                  unknown_reason="rate_limited")
            for index in range(996, 1000)
        ]
        text = drift.render(drift.compare(_matrix(base), _matrix(now)))
        share = [line for line in text.splitlines() if "of the grid" in line][0]
        self.assertIn("99% of the grid", share)
        self.assertNotIn("100% of the grid", share)


def _unmeasured(operation="GET /a", identity="attacker", reason="transport_error") -> dict:
    return _cell(operation=operation, identity=identity, reach="unknown", status=None,
                 marker_scan=None, unknown_reason=reason)


class NothingMeasuredInBothTest(unittest.TestCase):
    """A gate that compared no measured cell has not passed.

    Reproduced with `veridor map`: a baseline recorded while the target was
    down (every cell `unknown`, map itself said "it is not a baseline") was
    committed, and `--fail-on-drift opened` and `any` then exited 0 against a
    target serving a cross-tenant read. Every comparison against that baseline
    is `unknown -> something`, which no policy gates on, so the gate could not
    fail. The "compared nothing" guard fired only when no cell appeared in both
    runs; here every cell did, and none was measured in both.
    """

    GRID = (("GET /a", "attacker"), ("GET /a", "owner"), ("GET /b", "attacker"))

    def _down(self) -> dict:
        return _matrix([_unmeasured(op, who) for op, who in self.GRID])

    def _fixed(self) -> dict:
        return _matrix([_cell(operation=op, identity=who, reach="refused")
                        for op, who in self.GRID])

    def _vulnerable(self) -> dict:
        return _matrix([_cell(operation=op, identity=who, reach="reached", status=200)
                        for op, who in self.GRID])

    def _emit(self, baseline: dict, current: dict, policy: str) -> tuple[int, str, str]:
        from veridor.cli import _emit_drift

        namespace = _parser().parse_args([
            "map", "--config", "c.json", "--openapi", "s.json",
            "--baseline", "b.json", "--fail-on-drift", policy,
        ])
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            namespace.output_dir = Path(directory)
            namespace.drift_path = None
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = _emit_drift(namespace, current, baseline, "map-id")
        return code, stdout.getvalue(), stderr.getvalue()

    def test_an_all_unmeasured_baseline_is_not_a_pass_under_either_gate(self) -> None:
        report = drift.compare(self._down(), self._vulnerable())
        self.assertEqual(report["comparable_cells"], 3)
        self.assertEqual(report["measured_in_both_cells"], 0)
        self.assertEqual(report["baseline"]["measured_cells"], 0)
        self.assertEqual(report["current"]["measured_cells"], 3)
        for policy in ("opened", "any"):
            with self.subTest(policy=policy):
                self.assertEqual(drift.exit_code(report, policy), 3)
                code, _, stderr = self._emit(self._down(), self._vulnerable(), policy)
                self.assertEqual(code, 3)
                self.assertIn("0 of its 3 cell(s)", stderr)
                self.assertIn("It is not a pass", stderr)

    def test_a_current_run_that_measured_nothing_is_not_a_pass_either(self) -> None:
        report = drift.compare(self._fixed(), self._down())
        self.assertEqual(report["measured_in_both_cells"], 0)
        for policy in ("opened", "any"):
            with self.subTest(policy=policy):
                self.assertEqual(drift.exit_code(report, policy), 3)

    def test_a_grid_of_deliberate_skips_compares_nothing_too(self) -> None:
        """Every cell skipped by the plan on both sides: the gate cannot fail."""
        skipped = _matrix([_unmeasured(op, who, "skipped_mutating") for op, who in self.GRID])
        report = drift.compare(skipped, copy.deepcopy(skipped))
        self.assertEqual(drift.exit_code(report, "opened"), 3)

    def test_discovery_still_exits_zero(self) -> None:
        report = drift.compare(self._down(), self._vulnerable())
        self.assertEqual(drift.exit_code(report, "none"), 0)

    def test_control_a_measured_baseline_still_catches_the_opening(self) -> None:
        report = drift.compare(self._fixed(), self._vulnerable())
        self.assertEqual(report["measured_in_both_cells"], 3)
        self.assertEqual(drift.exit_code(report, "opened"), 1)
        self.assertEqual(self._emit(self._fixed(), self._vulnerable(), "opened")[0], 1)

    def test_control_a_quiet_measured_comparison_still_passes(self) -> None:
        report = drift.compare(self._fixed(), self._fixed())
        self.assertEqual(drift.exit_code(report, "opened"), 0)
        self.assertEqual(drift.exit_code(report, "any"), 0)

    def test_control_partial_blindness_stays_a_warning(self) -> None:
        """README makes a partly blind baseline a warning, not a gate. One cell
        measured in both runs is a comparison, and it keeps exit 0."""
        baseline = self._down()
        baseline["cells"][0] = _cell(operation="GET /a", identity="attacker", reach="refused")
        report = drift.compare(baseline, self._fixed())
        self.assertEqual(report["measured_in_both_cells"], 1)
        self.assertEqual(drift.exit_code(report, "opened"), 0)
        self.assertEqual(drift.exit_code(report, "any"), 0)

    def test_the_report_says_the_gate_measured_nothing(self) -> None:
        text = drift.render(drift.compare(self._down(), self._vulnerable()))
        self.assertIn("NOT ONE CELL WAS MEASURED IN BOTH RUNS", text)
        self.assertNotIn("Nothing moved", text)


def _answered(operation: str, identity: str, status: int, **extra) -> dict:
    """A cell exactly as `map` records a response with this status."""
    from veridor.matrix import classify_reach  # noqa: PLC0415

    reach, refusal_kind, unknown_reason = classify_reach(status)
    return _cell(operation=operation, identity=identity, reach=reach, status=status,
                 refusal_kind=refusal_kind, unknown_reason=unknown_reason, **extra)


class RedirectIsNotAMeasurementTest(unittest.TestCase):
    """A 302 was counted as a measured cell, so a redirect gate never failed.

    `matrix.classify_reach` records a 3xx as `indeterminate` because Veridor
    never follows a redirect, and calls what is behind it "genuinely
    unobserved". The exit-3 rule counted every cell that was not `unknown` as
    measured, so a 3xx counted. Reproduced with `veridor map` against a
    listener that answered every request with 302: recording the baseline
    exited 0 with no warning; gating `--fail-on-drift opened` with it against
    the demo target serving another tenant's invoice exited 0 (12 cells
    "measured in both", counts reach_appeared 3 and status_changed 9); and
    with the target still redirecting, `opened` and `any` both exited 0 on
    a comparison in which no request reached the application in either run.
    """

    GRID = (("GET /a", "attacker"), ("GET /a", "owner"), ("GET /b", "attacker"))

    def _grid(self, status: int) -> dict:
        return _matrix([_answered(op, who, status) for op, who in self.GRID])

    def _vulnerable(self) -> dict:
        return self._grid(200)

    def _fixed(self) -> dict:
        return _matrix([_answered("GET /a", "attacker", 404), _answered("GET /a", "owner", 200),
                        _answered("GET /b", "attacker", 403)])

    def test_a_redirect_baseline_against_a_vulnerable_target_is_not_a_pass(self) -> None:
        report = drift.compare(self._grid(302), self._vulnerable())
        self.assertEqual(report["measured_in_both_cells"], 0)
        self.assertEqual(report["redirect_cells"], 3)
        self.assertEqual(report["baseline"]["measured_cells"], 0)
        self.assertEqual(report["current"]["measured_cells"], 3)
        self.assertEqual(drift.exit_code(report, "opened"), 3)

    def test_redirect_against_redirect_is_not_a_pass_under_either_gate(self) -> None:
        for status in (301, 302, 303, 307, 308):
            report = drift.compare(self._grid(status), self._grid(status))
            for policy in ("opened", "any"):
                with self.subTest(status=status, policy=policy):
                    self.assertEqual(drift.exit_code(report, policy), 3)

    def test_a_redirect_on_only_the_current_side_is_not_measured_either(self) -> None:
        report = drift.compare(self._fixed(), self._grid(302))
        self.assertEqual(report["measured_in_both_cells"], 0)
        self.assertEqual(drift.exit_code(report, "opened"), 3)

    def test_control_a_measured_baseline_still_catches_the_opening(self) -> None:
        report = drift.compare(self._fixed(), self._vulnerable())
        self.assertEqual(report["measured_in_both_cells"], 3)
        self.assertEqual(report.get("redirect_cells", 0), 0)
        self.assertEqual(drift.exit_code(report, "opened"), 1)

    def test_control_a_quiet_measured_comparison_still_passes(self) -> None:
        report = drift.compare(self._fixed(), self._fixed())
        self.assertEqual(drift.exit_code(report, "opened"), 0)
        self.assertEqual(drift.exit_code(report, "any"), 0)

    def test_a_session_apps_login_redirect_is_still_a_partial_comparison(self) -> None:
        """Anonymous -> 302 /login is the ordinary denial in a session app. With
        the other cells measured, the comparison is partial, not empty: an
        opening elsewhere still fails the gate and a quiet one still passes."""
        baseline = _matrix([_answered("GET /a", "anonymous", 302),
                            _answered("GET /a", "attacker", 403),
                            _answered("GET /a", "owner", 200)])
        opened = copy.deepcopy(baseline)
        opened["cells"][1] = _answered("GET /a", "attacker", 200)
        quiet = drift.compare(baseline, copy.deepcopy(baseline))
        self.assertEqual(quiet["measured_in_both_cells"], 2)
        self.assertEqual(drift.exit_code(quiet, "opened"), 0)
        self.assertEqual(drift.exit_code(quiet, "any"), 0)
        self.assertEqual(drift.exit_code(drift.compare(baseline, opened), "opened"), 1)

    def test_a_login_redirect_that_became_served_is_said_every_time(self) -> None:
        """Anonymous 302 -> 200 is `reach_appeared`, which `opened` does not
        count: a 3xx is unobserved, and counting it would fail the gate on every
        trailing-slash or http->https fix. That is a design choice, not a pass.
        It exited 0 under `opened` with "0 that mean more access" and a note
        saying "the baseline never measured it", over what may be an
        authentication bypass in a session app. The console and the drift
        document now say, each time, how many redirect cells became served,
        that `opened` does not count them, and that `any` does."""
        baseline = _matrix([_answered("GET /a", "anonymous", 302),
                            _answered("GET /a", "attacker", 403),
                            _answered("GET /a", "owner", 200)])
        current = copy.deepcopy(baseline)
        current["cells"][0] = _answered("GET /a", "anonymous", 200)
        report = drift.compare(baseline, current)
        # The decision is kept; what changes is that it is never silent.
        self.assertEqual(drift.exit_code(report, "opened"), 0)
        self.assertEqual(drift.exit_code(report, "any"), 1)
        self.assertEqual(report["redirect_now_served_cells"], 1)
        (change,) = report["changes"]
        self.assertEqual(change["kind"], drift.REACH_APPEARED)
        self.assertIn("redirect", change["note"])
        self.assertIn("--fail-on-drift any", change["note"])
        self.assertNotIn("never measured", change["note"])
        text = drift.render(report)
        self.assertIn("1 cell(s) answered with a redirect in the baseline", text)
        self.assertIn("--fail-on-drift opened does not count", text)
        self.assertIn("--fail-on-drift any", text)
        from veridor.reports.markdown import render_drift  # noqa: PLC0415

        markdown = render_drift(report)
        self.assertIn("1 cell(s) answered with a redirect in the baseline", markdown)
        self.assertIn("`--fail-on-drift opened` does not count", markdown)
        code, _, stderr = NothingMeasuredInBothTest._emit(self, baseline, current, "opened")
        self.assertEqual(code, 0)
        self.assertIn("1 cell(s) answered with a redirect in the baseline", stderr)
        self.assertIn("--fail-on-drift any", stderr)
        # Control: a refusal that became a success is counted, and nothing about
        # redirects is said where there were none.
        refused = copy.deepcopy(baseline)
        refused["cells"][0] = _answered("GET /a", "anonymous", 401)
        control = drift.compare(refused, current)
        self.assertEqual(drift.exit_code(control, "opened"), 1)
        self.assertEqual(control["redirect_now_served_cells"], 0)
        self.assertNotIn("answered with a redirect in the baseline", drift.render(control))

    def test_the_headline_and_the_readme_say_where_redirect_cells_are_named(self) -> None:
        """Two places still understated a baseline redirect that became served.
        The first line of the text report and the bold Markdown headline read
        "1 change(s), 0 that mean more access" with the `!!` line about the
        redirect only further down, and README said those cells are named "on
        stdout, on stderr and in the Markdown report" although `_emit_drift`
        deliberately prints nothing on stderr under `--fail-on-drift any`,
        which fails on them instead."""
        baseline = _matrix([_answered("GET /a", "anonymous", 302),
                            _answered("GET /a", "attacker", 403),
                            _answered("GET /a", "owner", 200)])
        current = copy.deepcopy(baseline)
        current["cells"][0] = _answered("GET /a", "anonymous", 200)
        report = drift.compare(baseline, current)
        from veridor.reports.markdown import render_drift  # noqa: PLC0415

        headline = drift.render(report).splitlines()[0]
        bold = next(line for line in render_drift(report).splitlines()
                    if line.startswith("**"))
        for name, line in (("text", headline), ("markdown", bold)):
            with self.subTest(headline=name):
                self.assertIn("0 that mean more access", line)
                self.assertIn("1 baseline redirect(s) now served", line)
                self.assertIn("--fail-on-drift opened", line)
                self.assertIn("does not count them", line)
        # Control: no redirect cell, no redirect words in the headline.
        refused = copy.deepcopy(baseline)
        refused["cells"][0] = _answered("GET /a", "anonymous", 401)
        control = drift.compare(refused, current)
        self.assertNotIn("redirect", drift.render(control).splitlines()[0])
        self.assertNotIn("redirect", next(line for line in render_drift(control).splitlines()
                                          if line.startswith("**")))
        # The stderr behaviour the README has to describe.
        emitted = {policy: NothingMeasuredInBothTest._emit(self, baseline, current, policy)
                   for policy in ("none", "opened", "any")}
        self.assertEqual({policy: code for policy, (code, _, _) in emitted.items()},
                         {"none": 0, "opened": 0, "any": 1})
        for policy, (_, stdout, stderr) in emitted.items():
            with self.subTest(policy=policy):
                self.assertIn("answered with a redirect in the baseline", stdout)
                if policy == "any":
                    self.assertEqual(stderr, "")
                else:
                    self.assertIn("answered with a redirect in the baseline", stderr)
        readme = " ".join((ROOT / "docs" / "guide.md").read_text(encoding="utf-8").split())
        start = readme.index("`opened` does not count a cell the baseline answered with a redirect")
        passage = readme[start:readme.index("`--fail-on-drift` without", start)]
        self.assertNotIn("on stdout, on stderr and in the Markdown report", passage)
        self.assertIn("on stderr under every policy but `any`", passage)
        # README then said the cells are "named in the report's headline". The
        # headline and the `!!` line give a count; the cell itself appears only
        # in the list of changes, with a note saying its baseline redirected.
        for name, line in (("text", headline), ("markdown", bold)):
            with self.subTest(headline_does_not_name=name):
                self.assertNotIn("GET /a", line)
        text = drift.render(report)
        self.assertIn("[reach_appeared] GET /a anonymous", text)
        listed = [c for c in report["changes"]
                  if (c["operation"], c["identity"]) == ("GET /a", "anonymous")]
        self.assertEqual(len(listed), 1)
        self.assertIn("baseline was answered with a redirect", listed[0]["note"])
        self.assertNotIn("named in the report's headline", passage)
        self.assertIn("counted in `redirect_now_served_cells` and in the report's headline",
                      passage)
        self.assertIn("listed one by one with the report's changes", passage)

    def test_a_4xx_the_handler_answered_is_still_a_measurement(self) -> None:
        """`classify_reach` says a 400, 409 or 422 reached the handler. Those
        are `indeterminate` too, and they stay measured: only the redirect is
        unobserved."""
        for status in (400, 409, 422):
            report = drift.compare(self._grid(status), self._grid(status))
            with self.subTest(status=status):
                self.assertEqual(report["measured_in_both_cells"], 3)
                self.assertEqual(drift.exit_code(report, "opened"), 0)

    def test_the_marker_still_fires_against_a_redirect_baseline(self) -> None:
        """The one signal that is measured from the current run alone: another
        identity's marker in a response. The baseline's redirect must not
        switch it off."""
        leaked = _matrix([
            _answered("GET /a", "attacker", 200, marker_scan="present", marker_owner="owner"),
            _answered("GET /a", "owner", 200),
            _answered("GET /b", "attacker", 200),
        ])
        report = drift.compare(self._grid(302), leaked)
        self.assertIn(drift.MARKER_APPEARED, report["counts"])
        self.assertEqual(drift.exit_code(report, "opened"), 1)

    def test_the_text_report_says_so_and_does_not_claim_a_share(self) -> None:
        text = drift.render(drift.compare(self._grid(302), self._vulnerable()))
        self.assertIn("NOT ONE CELL WAS MEASURED IN BOTH RUNS", text)
        self.assertIn("redirect", text)
        self.assertIn("drift saw 0% of the grid", text)
        self.assertNotIn("Nothing moved", text)

    def test_the_gate_names_the_redirect_on_stderr(self) -> None:
        emit = NothingMeasuredInBothTest._emit
        code, _, stderr = emit(self, self._grid(302), self._vulnerable(), "opened")
        self.assertEqual(code, 3)
        self.assertIn("It is not a pass", stderr)
        self.assertIn("redirect", stderr)

    def test_observed_agrees_with_classify_reach_for_every_status(self) -> None:
        """The rule, pinned to the classifier it has to agree with: a cell is
        observed unless `classify_reach` could not measure it (`unknown`) or it
        is a redirect nobody followed."""
        from veridor.matrix import REACH_UNKNOWN, classify_reach  # noqa: PLC0415

        disagree = []
        for status in [None, *range(100, 600)]:
            reach, _, _ = classify_reach(status)
            unobserved = reach == REACH_UNKNOWN or (status is not None and 300 <= status <= 399)
            if drift.observed({"reach": reach, "status": status}) == unobserved:
                disagree.append(status)
        self.assertEqual(disagree, [])
        # Control: the comparison can disagree. A rule that called every
        # answered cell observed -- the one this replaced -- differs on 3xx.
        self.assertFalse(drift.observed({"reach": "indeterminate", "status": 302}))
        self.assertTrue(drift.observed({"reach": "indeterminate", "status": 400}))


class BaselineRatchetTest(unittest.TestCase):
    """A gate compares against a fixed artifact, or it is not a gate.

    `--baseline <dir>` resolves to the NEWEST matrix in the directory, and `map`
    writes one more into that same directory on every run. Measured against a
    live cross-tenant read: run 1 exits 1 on reach_opened and marker_appeared,
    and the identical command re-run -- the first thing anybody does with a red
    build -- reports "Nothing moved" and exits 0 with the leak still live.
    """

    def _args(self, baseline, policy: str):
        namespace = _parser().parse_args([
            "map", "--config", "c.json", "--openapi", "s.json",
            "--baseline", str(baseline), "--fail-on-drift", policy,
        ])
        return namespace

    def test_a_directory_baseline_is_refused_under_a_gate(self) -> None:
        from veridor.cli import ConfigError, _load_drift_baseline

        with tempfile.TemporaryDirectory() as directory:
            for policy in ("opened", "any"):
                with self.subTest(policy=policy):
                    with self.assertRaises(ConfigError) as caught:
                        _load_drift_baseline(self._args(directory, policy))
                    message = str(caught.exception)
                    self.assertIn("is a directory", message)
                    self.assertIn("ratchets", message)
                    self.assertIn("veridor/baseline-matrix.json", message)

    def test_a_directory_baseline_still_works_for_discovery(self) -> None:
        """Without a gate the directory form is the honest one: report, do not fail."""
        from veridor.cli import _load_drift_baseline

        with tempfile.TemporaryDirectory() as directory:
            recorded = Path(directory) / "20260101T000000Z-aaaaaa.json"
            recorded.write_text(json.dumps(_matrix([_cell()])), encoding="utf-8")
            loaded = _load_drift_baseline(self._args(directory, "none"))
            self.assertEqual(len(loaded["cells"]), 1)

    def test_a_file_baseline_is_accepted_under_a_gate(self) -> None:
        from veridor.cli import _load_drift_baseline

        with tempfile.TemporaryDirectory() as directory:
            pinned = Path(directory) / "baseline-matrix.json"
            pinned.write_text(json.dumps(_matrix([_cell()])), encoding="utf-8")
            loaded = _load_drift_baseline(self._args(pinned, "opened"))
            self.assertEqual(len(loaded["cells"]), 1)

    def test_the_scaffold_recommends_a_command_the_gate_accepts(self) -> None:
        # The scaffold recommended `--baseline .veridor/matrix --fail-on-drift
        # opened`, which is now refused. A tool that prints a command it will
        # not run is worse than one that prints nothing.
        from veridor.cli import DRIFT_BASELINE

        self.assertNotIn(".veridor", DRIFT_BASELINE)
        self.assertTrue(DRIFT_BASELINE.endswith(".json"))


class ExitPolicyTest(unittest.TestCase):
    """`map` does not gate a build unless asked. That invariant is the product."""

    def setUp(self) -> None:
        self.opened = drift.compare(
            _matrix([_cell(reach="refused")]), _matrix([_cell(reach="reached")]))
        self.closed = drift.compare(
            _matrix([_cell(reach="reached")]), _matrix([_cell(reach="refused")]))
        self.same = drift.compare(_matrix([_cell()]), _matrix([_cell()]))

    def test_none_never_fails(self) -> None:
        for report in (self.opened, self.closed, self.same):
            self.assertEqual(drift.exit_code(report, "none"), 0)

    def test_opened_fails_only_on_more_access(self) -> None:
        self.assertEqual(drift.exit_code(self.opened, "opened"), 1)
        self.assertEqual(drift.exit_code(self.closed, "opened"), 0)
        self.assertEqual(drift.exit_code(self.same, "opened"), 0)

    def test_any_fails_on_any_change(self) -> None:
        self.assertEqual(drift.exit_code(self.closed, "any"), 1)
        self.assertEqual(drift.exit_code(self.same, "any"), 0)

    def test_the_default_policy_is_not_to_gate(self) -> None:
        args = _parser().parse_args(["map", "--config", "c.json", "--openapi", "s.json"])
        self.assertEqual(args.fail_on_drift, "none")
        self.assertIsNone(args.baseline)


class BaselineResolutionTest(unittest.TestCase):
    def test_a_directory_resolves_to_its_most_recent_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "20260101T000000Z-aaa.json").write_text(
                json.dumps(_matrix([_cell(status=401)])), encoding="utf-8")
            (path / "20260202T000000Z-bbb.json").write_text(
                json.dumps(_matrix([_cell(status=403)])), encoding="utf-8")
            self.assertEqual(drift.load_matrix(path)["cells"][0]["status"], 403)

    def test_an_empty_directory_says_how_to_record_a_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(drift.DriftError) as caught:
                drift.load_matrix(Path(directory))
            self.assertIn("without --baseline", str(caught.exception))

    def test_a_non_matrix_document_is_refused_by_kind(self) -> None:
        """Guessed the kind wrong once; `veridor.matrix`, not `access_matrix`."""
        with self.assertRaises(drift.DriftError) as caught:
            drift.compare({"kind": "veridor.blast_radius", "cells": []}, _matrix([]))
        self.assertIn("not a Veridor access matrix", str(caught.exception))

    def test_drift_errors_are_config_errors(self) -> None:
        """So the CLI prints `veridor: ...` and exit 2, not a traceback."""
        from veridor.core import ConfigError  # noqa: PLC0415

        self.assertTrue(issubclass(drift.DriftError, ConfigError))

    def test_fail_on_drift_without_a_baseline_is_refused(self) -> None:
        """Otherwise it silently never gates, which is the worst outcome:
        a green build that was never actually comparing anything."""
        import argparse  # noqa: PLC0415

        from veridor.cli import _load_drift_baseline  # noqa: PLC0415
        from veridor.core import ConfigError  # noqa: PLC0415

        args = argparse.Namespace(baseline=None, fail_on_drift="opened")
        with self.assertRaises(ConfigError) as caught:
            _load_drift_baseline(args)
        self.assertIn("needs --baseline", str(caught.exception))
        self.assertIsNone(_load_drift_baseline(
            argparse.Namespace(baseline=None, fail_on_drift="none")))

    def test_drift_without_a_baseline_is_refused_before_anything_is_sent(self) -> None:
        """`map --drift PATH` with no `--baseline` was accepted and ignored: no
        file at PATH, no word on stdout or stderr, exit 0. A CI step that reads
        PATH afterwards finds nothing, for the same reason the sibling flag is
        refused above."""
        from unittest import mock  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415
        from veridor.cli import main as veridor_main  # noqa: PLC0415

        sent: list[str] = []

        class Recorder:
            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                sent.append(request.full_url)
                raise AssertionError("a request was sent")

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "drift.json"
            stderr = io.StringIO()
            with mock.patch.object(core, "_OPENER", Recorder()), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(stderr):
                code = veridor_main([
                    "map", "--config", str(ROOT / "fixtures" / "veridor.map-demo.json"),
                    "--openapi", str(ROOT / "fixtures" / "openapi.demo.json"),
                    "--output-dir", str(Path(directory) / "out"),
                    "--drift", str(report),
                ])
            self.assertEqual(code, 2, stderr.getvalue())
            self.assertIn("--drift needs --baseline", stderr.getvalue())
            self.assertEqual(sent, [])
            self.assertFalse(report.exists())
            self.assertFalse((Path(directory) / "out").exists())


class NoDeclarationRequiredTest(unittest.TestCase):
    """The config a team has BEFORE they have written a policy.

    Drift is only plug-and-play if the file it needs is one the user already
    has. Requiring a non-empty `checks` list before Veridor will look at an API
    charges a declaration for the one command that evaluates none -- which is
    the whole adoption wall this path exists to remove.
    """

    MINIMAL = {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:8765"},
        "identities": {
            "owner": {"headers": {"Authorization": "Bearer owner-token"}},
            "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
        },
    }

    def _write(self, directory: str, config: dict) -> Path:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def test_map_loads_a_config_with_no_checks_at_all(self) -> None:
        from veridor.core import load_config  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self.MINIMAL)
            config = load_config(path, require_checks=False)
        # Normalised to a list so every downstream consumer sees the same shape.
        self.assertEqual(config["checks"], [])

    def test_run_still_refuses_a_config_with_no_checks(self) -> None:
        """A gate with nothing to gate on is a different mistake, still refused.
        The message is a compatibility promise and is quoted verbatim."""
        from veridor.core import ConfigError, load_config  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self.MINIMAL)
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertEqual(str(caught.exception), "checks must be a non-empty list")

    def test_an_empty_checks_list_is_also_accepted_by_map(self) -> None:
        from veridor.core import load_config  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {**self.MINIMAL, "checks": []})
            self.assertEqual(load_config(path, require_checks=False)["checks"], [])

    def test_a_malformed_checks_value_is_still_refused(self) -> None:
        """Relaxing "non-empty" must not relax "a list"."""
        from veridor.core import ConfigError, load_config  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {**self.MINIMAL, "checks": {"id": "x"}})
            with self.assertRaises(ConfigError):
                load_config(path, require_checks=False)

    def test_two_identities_are_still_required(self) -> None:
        """Not a wall worth removing: one principal cannot express a boundary."""
        from veridor.core import ConfigError, load_config  # noqa: PLC0415

        lone = {**self.MINIMAL,
                "identities": {"solo": {"headers": {"Authorization": "x"}}}}
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, lone)
            with self.assertRaises(ConfigError) as caught:
                load_config(path, require_checks=False)
        self.assertIn("at least two", str(caught.exception))

    def test_the_readme_minimal_config_actually_loads(self) -> None:
        """The README calls that JSON block "the whole configuration". A
        documented minimal config that does not load is the worst possible
        first five minutes."""
        import re  # noqa: PLC0415

        readme = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
        section = readme.split("### Drift: catching a regression", 1)[1]
        block = re.search(r"```json\n(.*?)```", section, re.DOTALL)
        self.assertIsNotNone(block, "the drift section lost its config example")
        config = json.loads(block.group(1))
        self.assertNotIn("checks", config, "the minimal example grew a policy")

        from veridor.core import load_config  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            # The example uses ${...} references, which is the documented way
            # to keep credentials out of a file people commit.
            os.environ.setdefault("OWNER_TOKEN", "t1")
            os.environ.setdefault("OUTSIDER_TOKEN", "t2")
            path = self._write(directory, config)
            loaded = load_config(path, require_checks=False)
        self.assertEqual(loaded["checks"], [])
        self.assertEqual(len(loaded["identities"]), 2)

    def test_map_accepts_a_checkless_config_end_to_end(self) -> None:
        """Behavioural, not a source string: `_map` also passes require_checks
        to _emit_coverage, so grepping the function body cannot tell whether
        the config load itself was relaxed. --dry-run sends nothing."""
        from veridor.cli import main as veridor_main  # noqa: PLC0415

        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self.MINIMAL)
            # Captured, not silenced: --dry-run's entire product is the banner
            # it prints, so a test that discarded it would assert only that the
            # call did not raise.
            with contextlib.redirect_stdout(buffer):
                code = veridor_main([
                    "map", "--config", str(path),
                    # Absolute, not "fixtures/...". A relative literal here makes
                    # the assertion depend on the process cwd, which passes only
                    # because every caller happens to run from the repo root.
                    "--openapi", str(ROOT / "fixtures" / "openapi.demo.json"),
                    "--output-dir", str(Path(directory) / "out"), "--dry-run",
                ])
        self.assertEqual(code, 0)
        printed = buffer.getvalue()
        self.assertIn("Veridor access matrix", printed)
        self.assertIn("this will issue", printed)

    def test_run_refuses_the_same_checkless_config(self) -> None:
        """The relaxation is scoped to `map`. If `run` ever picks it up, a gate
        silently stops gating."""
        from veridor.cli import main as veridor_main  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self.MINIMAL)
            code = veridor_main([
                "run", "--config", str(path),
                "--output-dir", str(Path(directory) / "out"),
            ])
        self.assertEqual(code, 2)


class OutputPathTest(unittest.TestCase):
    """A drift report written over the baseline breaks the NEXT run, which is
    the worst place for a path mistake to surface."""

    def _map(self, *extra: str) -> tuple[int, str]:
        from veridor.cli import main as veridor_main  # noqa: PLC0415

        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = veridor_main([
                "map", "--config", "fixtures/veridor.map-demo.json",
                "--openapi", "fixtures/openapi.demo.json", *extra,
            ])
        return code, stderr.getvalue()

    def test_drift_may_not_be_written_over_the_baseline(self) -> None:
        """Against a REAL baseline file. With `b.json` missing, as this test
        had it, `_load_drift_baseline` exits 2 with "cannot read matrix"
        whether or not `--baseline` is protected, so removing the protection
        left this test -- and 229 others -- green. The message and the bytes
        are what tell the refusal apart."""
        from unittest import mock  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Refuse:
            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                raise AssertionError(f"a request was sent: {request.full_url}")

        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "b.json"
            baseline.write_text(json.dumps(_matrix([_cell(status=403)])), encoding="utf-8")
            before = baseline.read_bytes()
            with mock.patch.object(core, "_OPENER", Refuse()):
                code, stderr = self._map(
                    "--output-dir", str(Path(directory) / "out"),
                    "--baseline", str(baseline), "--drift", str(baseline))
            self.assertEqual(code, 2, stderr)
            self.assertIn("--drift must not overwrite a configuration, baseline, "
                          "or specification", stderr)
            self.assertEqual(baseline.read_bytes(), before)

    def test_drift_may_not_collide_with_another_output(self) -> None:
        """Asserts the message, not only exit 2: with no --baseline, `--drift`
        alone is now refused with exit 2 too, so the code cannot tell this
        refusal from that one."""
        code, stderr = self._map("--drift", "out.json", "--candidates", "out.json")
        self.assertEqual(code, 2)
        self.assertIn("--candidates and --drift must use different paths", stderr)


class OrderingHazardTest(unittest.TestCase):
    """The bug that would make this feature quietly useless.

    `map` writes its matrix into `.veridor/matrix/`, which is exactly the
    directory a CI job passes as `--baseline`. Resolve the baseline after
    writing and the newest file is THIS run: zero drift, exit 0, and it reads
    like good news forever.
    """

    def test_the_baseline_is_resolved_before_anything_is_probed(self) -> None:
        source = (ROOT / "src" / "veridor" / "cli.py").read_text(encoding="utf-8")
        body = source.split("def _map(", 1)[1]
        resolve = body.index("_load_drift_baseline(args)")
        for later in ("plan_matrix(", "execute_matrix(", "write_json("):
            with self.subTest(step=later):
                self.assertLess(resolve, body.index(later), later)

    def test_load_matrix_warns_callers_about_the_ordering(self) -> None:
        self.assertIn("BEFORE the current run writes", drift.load_matrix.__doc__)


def _noise_floor_study():
    """``scripts/noise_floor_study.py``, without letting its own ``src/``
    insert outlive the import (VERIDOR_TEST_AGAINST=installed must hold)."""
    saved = list(sys.path)
    try:
        from scripts import noise_floor_study  # noqa: PLC0415
    finally:
        sys.path[:] = saved
    return noise_floor_study


class _StoppedServer:
    server_port = 1

    def serve_forever(self) -> None:
        pass

    def shutdown(self) -> None:
        pass

    def server_close(self) -> None:
        pass


class NoiseFloorStudyPostureTest(unittest.TestCase):
    """`--verb run` must measure the gate people ship, not the bare CLI.

    The GitHub Action, the GitLab component and the Helm chart all default
    `require_complete` on, and GitLab's `allow_unmeasured: false` fails the
    job on exit 3. The study ran `veridor run` without `--require-complete`
    and counted only exit 1, so at its default noise it printed FALSE GATE
    RATE 0/10 while 6 of those 10 runs exit 3 under the shipped flag and
    fail the build.
    """

    def test_the_study_runs_the_gate_with_require_complete(self) -> None:
        study = _noise_floor_study()
        seen: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            seen.append(list(argv))
            output = Path(argv[argv.index("--json") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text('{"findings": []}', encoding="utf-8")
            return study.subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            original = study.subprocess.run
            study.subprocess.run = fake_run
            try:
                study._run_gate(Path(directory) / "veridor.json",
                                "http://127.0.0.1:1", Path(directory) / "run-0")
            finally:
                study.subprocess.run = original
        self.assertEqual(len(seen), 1)
        self.assertIn("--require-complete", seen[0])

    def _study_run(self, codes: list[int]) -> tuple[int, str]:
        study = _noise_floor_study()
        answers = iter(codes)
        original = study._run_gate
        study._run_gate = lambda *_args: (next(answers), {"findings": []})
        args = argparse.Namespace(detect=False, runs=len(codes))
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                code = study._study_run(args, Path("."), Path("veridor.json"),
                                        "http://127.0.0.1:1", _StoppedServer(),
                                        study.Noise(seed=7))
        finally:
            study._run_gate = original
        return code, stdout.getvalue()

    def test_an_inconclusive_exit_is_a_failed_build(self) -> None:
        code, text = self._study_run([3, 0, 3, 0])
        self.assertEqual(code, 1, text)
        self.assertIn("FALSE GATE RATE  2/4", text)
        self.assertIn("2 exited 3", text)

    def test_a_quiet_run_still_reads_zero(self) -> None:
        """The control: the counting must not fire on clean exits."""
        code, text = self._study_run([0, 0, 0])
        self.assertEqual(code, 0, text)
        self.assertIn("FALSE GATE RATE  0/3", text)

    def _main(self, *argv: str, codes: list[int]) -> tuple[int, str]:
        """``main()`` end to end, with each `veridor run` answered by a code."""
        study = _noise_floor_study()
        answers = iter(codes)
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(study, "_run_gate",
                                  lambda *_args: (next(answers), {"findings": []})), \
                mock.patch.object(study.tempfile, "mkdtemp", return_value=directory), \
                mock.patch.object(study, "create_server",
                                  lambda *_args: _StoppedServer()), \
                mock.patch.object(sys, "argv", ["noise_floor_study.py", *argv]), \
                contextlib.redirect_stdout(stdout):
            code = study.main()
        return code, stdout.getvalue()

    def test_detect_mode_names_the_posture_it_ran(self) -> None:
        """--detect passes --require-complete like every other `run`, but its
        label read '--fail-on new' alone, and the header still said the
        boundary was fixed and every change a false positive -- in the one
        mode that opens the boundary on purpose."""
        code, text = self._main("--verb", "run", "--runs", "2", "--detect",
                                codes=[1, 1])
        self.assertEqual(code, 0, text)
        detection = next(line for line in text.splitlines() if "DETECTION RATE" in line)
        self.assertIn("2/2", detection)
        self.assertIn("--fail-on new --require-complete", detection)
        self.assertNotIn("boundary fixed", text)
        self.assertNotIn("FALSE POSITIVE by construction", text)
        self.assertIn("boundary opened", text)

    def test_the_false_gate_header_is_unchanged_without_detect(self) -> None:
        """The control: outside --detect the boundary IS fixed and the header
        must keep saying so."""
        code, text = self._main("--verb", "run", "--runs", "2", codes=[0, 0])
        self.assertEqual(code, 0, text)
        self.assertIn("boundary fixed for the whole run", text)
        self.assertIn("FALSE POSITIVE by construction", text)




class ProxyAuthIsNotAMeasurementTest(unittest.TestCase):
    """A 407 is Proxy Authentication Required: a proxy's own answer, before
    the request reached the target. `matrix.classify_reach` recorded it as a
    refusal of the credential -- a measured cell -- so a drift gate behind a
    proxy that answered 407 to everything compared a run that reached nothing
    against a measured baseline and could pass (run and verify already treat
    a 407 as the proxy's answer; map did not)."""

    GRID = RedirectIsNotAMeasurementTest.GRID

    def test_a_407_is_unknown_not_a_refusal(self) -> None:
        from veridor.matrix import REACH_UNKNOWN, classify_reach  # noqa: PLC0415

        self.assertEqual(classify_reach(407), (REACH_UNKNOWN, None, "proxy_auth_required"))

    def test_a_gate_behind_a_407_proxy_cannot_pass(self) -> None:
        baseline = RedirectIsNotAMeasurementTest()._fixed()
        current = _matrix([_answered(op, who, 407) for op, who in self.GRID])
        report = drift.compare(baseline, current)
        self.assertEqual(report["measured_in_both_cells"], 0)
        self.assertEqual(drift.exit_code(report, "opened"), 3)
        self.assertEqual(drift.exit_code(report, "any"), 3)

    def test_control_the_same_gate_against_a_reachable_vulnerable_target_fails(self) -> None:
        report = drift.compare(RedirectIsNotAMeasurementTest()._fixed(),
                               RedirectIsNotAMeasurementTest()._vulnerable())
        self.assertEqual(drift.exit_code(report, "opened"), 1)


if __name__ == "__main__":
    unittest.main()
