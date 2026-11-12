"""The three-verb surface: `map`, `run`, `mutate`, and what stays subordinate.

Four capabilities shipped before this file existed and a user could reach none
of the new ones: ``cli.py`` imported neither ``matrix``, ``blastradius``,
``mutation`` nor ``sequence``. These tests are the wiring's contract.

What each class defends, and why it is worth a test rather than a comment:

``HelpShapeTest``
    The shape of ``--help`` is the product decision. Nine equal commands in an
    alphabetical list is the state this work exists to leave behind, and
    nothing else in the suite would notice it coming back.
``MapTest``
    ``map`` end to end against a live loopback target, including the two things
    that must be true of a discovery command forever: it exits 0 whatever it
    finds, and none of what it finds reaches the run history or a SARIF file.
``MapSafetyTest``
    The budget refusal, the dry run and the acknowledgement gates, asserted at
    the CLI rather than only at the library, because the CLI is the layer that
    could have skipped them.
``SequenceReachabilityTest``
    A sequence, a response capture and a session, invoked the only way a user
    can invoke them: ``veridor run --config``.
``MutateTierOneTest`` / ``MutateTierTwoRefusalTest`` / ``MutateTierTwoTest``
    Tier 1 end to end, and every refusal that stands between an operator and
    Veridor executing a command they supplied.
``BackwardCompatibilityTest``
    Exit codes and artifacts for the paths that existed before this file did.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fixtures"))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from scripts.demo_server import OWNER_MARKER  # noqa: E402
from scripts.demo_server import create_server as create_demo_server  # noqa: E402
import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import blastradius, cli, mutation  # noqa: E402
from veridor.cli import (  # noqa: E402
    _OVERVIEW,
    _TIER2_ACK_FLAG,
    _parser,
    _specimen_reachability_advice,
    main,
)
from veridor.core import ConfigError  # noqa: E402
from veridor.coverage import BANNED_CLAIM_WORDS  # noqa: E402
from veridor_mutation_fixture import ORDER_OWNER_MARKER  # noqa: E402
from veridor_mutation_fixture import create_server as create_mutation_server  # noqa: E402

MAP_CONFIG = ROOT / "fixtures" / "veridor.map-demo.json"
DEMO_SPEC = ROOT / "fixtures" / "openapi.demo.json"
DEMO_CONFIG = ROOT / "fixtures" / "veridor.demo.json"
GUARD_TOGGLE = ROOT / "fixtures" / "tier2_guard_toggle.py"

#: The rules measured for precision and shipped. ``map`` must run these and
#: only these: a rule that was
#: removed for precision must not reappear through the CLI, and a rule that
#: survived must not silently stop running.
SHIPPED_RULES: frozenset[str] = frozenset(
    {
        "inverted_guard",
        "marker_reach",
        "method_asymmetry",
        "peer_divergence",
        "sibling_asymmetry",
        "unauthenticated_reach",
    }
)

DEAD_TARGET = "http://127.0.0.1:1"


def _capture(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI in-process and return ``(exit_code, stdout, stderr)``."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _only(directory: Path) -> Path:
    entries = sorted(directory.glob("*.json"))
    if len(entries) != 1:
        raise AssertionError(f"expected one artifact in {directory}, got {entries}")
    return entries[0]


class _Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.workspace = Path(self._workspace.name)
        self.output = self.workspace / "out"

    def write(self, name: str, value: object) -> Path:
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")
        return path


@slow("stands up a loopback HTTP server and runs the engine against it")
class _DemoTarget(_Workspace):
    """The shipped demo API, in its deliberately broken mode."""

    vulnerable = True

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_demo_server("127.0.0.1", 0, vulnerable=cls.vulnerable)
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)


# ---------------------------------------------------------------------------
# the shape of the surface
# ---------------------------------------------------------------------------


class HelpShapeTest(unittest.TestCase):
    """`--help` is the first-run experience, so it is snapshotted."""

    def setUp(self) -> None:
        self.help = _parser().format_help()

    def test_the_overview_is_what_help_prints(self) -> None:
        self.assertIn(_OVERVIEW.strip(), self.help)

    def test_the_overview_claims_no_more_than_a_run_shows(self) -> None:
        """A match "is not evidence that the boundary is enforced", and the
        README lists "No proof of security" as a non-goal. The first line of
        --help said "Prove that your authorization boundary holds", and no check
        read it: the banned claim words cover report surfaces, and have no form
        of prove."""
        words = "|".join(BANNED_CLAIM_WORDS)

        def problems(text: str) -> list[str]:
            return re.findall(rf"(?i)\b(?:{words}|prov(?:e|es|en|ing))\b", text)

        self.assertEqual(problems(_OVERVIEW), [])
        # Control: the line this replaced. "proof" stays allowed, because a
        # capsule is a proof of one finding, which is a narrower thing.
        self.assertEqual(
            problems("Prove that your authorization boundary holds, and keep proving it."),
            ["Prove", "proving"])
        self.assertEqual(problems("this is safe"), ["safe"])
        self.assertEqual(problems("a portable, runnable proof of ONE finding"), [])

    def test_the_three_verbs_are_named_as_the_product(self) -> None:
        self.assertIn("THE THREE VERBS", self.help)
        for verb in ("map", "run", "mutate"):
            self.assertRegex(self.help, rf"(?m)^  {verb}\s+\S", msg=verb)

    def test_the_utilities_are_named_as_utilities(self) -> None:
        self.assertIn("UTILITIES", self.help)
        utilities = self.help.split("UTILITIES", 1)[1]
        for utility in ("init", "coverage", "new-marker", "report", "serve"):
            self.assertIn(utility, utilities, utility)

    def test_every_verb_is_listed_before_every_utility(self) -> None:
        """The ordering is the claim. A utility above a verb inverts it."""
        verbs = self.help.index("THE THREE VERBS")
        utilities = self.help.index("UTILITIES")
        self.assertLess(verbs, utilities)
        for verb in ("map", "run", "mutate"):
            self.assertLess(self.help.index(f"  {verb} "), utilities, verb)

    def test_argparse_does_not_also_print_a_flat_list_of_equals(self) -> None:
        """The regression this file exists to prevent: nine peers, alphabetical."""
        commands = self.help.split("commands:", 1)[1]
        for name in ("map", "run", "mutate", "coverage", "serve"):
            self.assertNotIn(f"    {name} ", commands, name)

    def test_the_journey_is_stated_in_order(self) -> None:
        prose = " ".join(self.help.split())
        self.assertIn("Discover, declare, gate, then verify the gate.", prose)

    def test_the_verify_alias_is_still_documented_and_still_parses(self) -> None:
        # Asserted as a property, not as a sentence. The line now also documents
        # the capsule form, and pinning its punctuation made a purely additive
        # change look like a regression.
        self.assertIn("`verify` remains an alias for `run`", self.help)
        args = _parser().parse_args(["verify", "--config", "x.json"])
        self.assertEqual(args.command, "verify")

    def test_verify_also_documents_the_capsule_form(self) -> None:
        """The maintainer-facing form: one command against a file they were sent."""
        self.assertIn("veridor verify proof.json", self.help)
        self.assertIn("CONFIRMED / NOT_REPRODUCED / INCONCLUSIVE", self.help)
        args = _parser().parse_args(["verify", "proof.json"])
        self.assertEqual(args.capsule, Path("proof.json"))

    def test_every_command_has_its_own_help(self) -> None:
        for name in (
            "map",
            "run",
            "mutate",
            "coverage",
            "init",
            "new-marker",
            "report",
            "serve",
            "capsule",
        ):
            with self.subTest(command=name), self.assertRaises(SystemExit) as caught:
                with contextlib.redirect_stdout(io.StringIO()):
                    _parser().parse_args([name, "--help"])
            self.assertEqual(caught.exception.code, 0)

    def test_map_help_states_that_a_candidate_is_not_a_finding(self) -> None:
        text = io.StringIO()
        with contextlib.redirect_stdout(text), self.assertRaises(SystemExit):
            _parser().parse_args(["map", "--help"])
        prose = " ".join(text.getvalue().split())
        self.assertIn("Nothing here is a finding", prose)

    def test_the_liveness_help_says_what_moves_the_exit_code(self) -> None:
        """The help said "ON by default ... Turn it off and an expired token
        reads as a passing gate", implying that with it on the gate fails. It
        does not: under the default flags an expired token on a deny-only
        identity exits 0 either way, and only `--require-complete` moves it to
        3 (`gate._liveness_exit_code`, deliberately). The help is held to the
        code it describes."""
        from veridor import gate  # noqa: PLC0415

        run = _parser()._subparsers._group_actions[0].choices["run"]  # noqa: SLF001
        (action,) = [a for a in run._actions if "--no-prove-liveness" in a.option_strings]  # noqa: SLF001
        prose = " ".join(action.help.split())
        unproven = {"liveness": {"unproven": [{"identity": "outsider"}]}}
        self.assertEqual(gate._liveness_exit_code(gate.Options(), unproven), 0)
        self.assertEqual(
            gate._liveness_exit_code(gate.Options(require_complete=True), unproven), 3)
        self.assertNotIn("expired token reads as a passing gate", prose)
        self.assertIn("--require-complete", prose)
        self.assertIn("liveness.unproven", prose)
        # README's no-flag vacuity bullet offered "an expired token" as a case
        # it catches; a 401 is an answer, so that run never reaches it.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        bullet = readme.split("**Not one probe answered", 1)[1].split("\n- ", 1)[0]
        self.assertNotIn("expired token", bullet)

    def test_mutate_help_states_that_a_mutant_is_not_a_finding(self) -> None:
        text = io.StringIO()
        with contextlib.redirect_stdout(text), self.assertRaises(SystemExit):
            _parser().parse_args(["mutate", "--help"])
        prose = " ".join(text.getvalue().split())
        self.assertIn("nothing it reports is a finding", prose)
        self.assertIn("emits no SARIF", prose)


# ---------------------------------------------------------------------------
# map
# ---------------------------------------------------------------------------


class MapTest(_DemoTarget):
    def run_map(self, *extra: str) -> tuple[int, str, str]:
        return _capture(
            [
                "map",
                "--config",
                str(MAP_CONFIG),
                "--openapi",
                str(DEMO_SPEC),
                "--base-url",
                self.base_url,
                "--output-dir",
                str(self.output),
                "--rate",
                "10",
                *extra,
            ]
        )

    def test_map_produces_all_three_artifacts_and_exits_zero(self) -> None:
        code, stdout, _ = self.run_map()
        self.assertEqual(code, 0, stdout)
        for directory, kind in (
            ("matrix", "veridor.matrix"),
            ("blast-radius", "veridor.blast_radius"),
            ("candidates", "veridor.candidates"),
        ):
            with self.subTest(artifact=directory):
                document = _json(_only(self.output / directory))
                self.assertEqual(document["kind"], kind)

    def test_map_renders_the_whole_journey_in_one_report(self) -> None:
        _, stdout, _ = self.run_map()
        for heading in (
            "Veridor access matrix",
            "Veridor blast radius",
            "Veridor boundary coverage",
            "Veridor anomaly candidates",
        ):
            self.assertIn(heading, stdout, heading)
        # The order is the journey, not an accident of implementation.
        self.assertLess(stdout.index("blast radius"), stdout.index("boundary coverage"))
        self.assertLess(
            stdout.index("boundary coverage"), stdout.index("anomaly candidates")
        )

    def test_map_surfaces_the_planted_cross_tenant_read_as_a_candidate(self) -> None:
        _, stdout, _ = self.run_map()
        document = _json(_only(self.output / "candidates"))
        rules = {candidate["rule"] for candidate in document["candidates"]}
        self.assertIn("marker_reach", rules)
        self.assertIn("[marker_reach]", stdout)

    def test_map_runs_exactly_the_rules_phase_one_shipped(self) -> None:
        self.assertEqual(frozenset(blastradius.RULES), SHIPPED_RULES)
        self.run_map()
        document = _json(_only(self.output / "candidates"))
        self.assertEqual(frozenset(document["counts"]["by_rule"]), SHIPPED_RULES)
        self.assertEqual(
            {entry["rule"] for entry in document["rules"]}, SHIPPED_RULES
        )

    def test_a_candidate_never_becomes_a_finding(self) -> None:
        _, stdout, _ = self.run_map()
        document = _json(_only(self.output / "candidates"))
        self.assertTrue(document["candidates"])
        for candidate in document["candidates"]:
            self.assertIn("candidate_id", candidate)
            # The keys core requires of a finding. None may appear.
            for key in ("finding_id", "rule_id", "verdict", "evidence_grade"):
                self.assertNotIn(key, candidate, key)
        self.assertIn("never findings", " ".join(stdout.split()))

    def test_map_writes_nothing_into_the_run_history(self) -> None:
        self.run_map()
        self.assertFalse((self.output / "latest.json").exists())
        self.assertFalse((self.output / "runs").exists())
        self.assertEqual(
            sorted(entry.name for entry in self.output.iterdir()),
            ["blast-radius", "candidates", "matrix"],
        )

    def test_map_produces_no_sarif_anywhere(self) -> None:
        self.run_map()
        self.assertEqual(list(self.output.rglob("*.sarif")), [])
        for path in self.output.rglob("*.json"):
            document = _json(path)
            # The SARIF shape, not the word: every candidate document says in
            # prose that it produces no SARIF result, which is the point.
            self.assertNotIn("runs", document)
            self.assertNotEqual(document.get("version"), "2.1.0")

    def test_map_exits_zero_even_when_it_finds_candidates(self) -> None:
        """Discovery is not a gate. `run` is the gate."""
        code, _, _ = self.run_map()
        document = _json(_only(self.output / "candidates"))
        self.assertTrue(document["candidates"])
        self.assertEqual(code, 0)

    def test_operator_copies_are_written_in_addition_to_the_managed_ones(self) -> None:
        matrix = self.workspace / "matrix.json"
        radius = self.workspace / "radius.json"
        candidates = self.workspace / "candidates.json"
        code, _, _ = self.run_map(
            "--matrix",
            str(matrix),
            "--blast-radius",
            str(radius),
            "--candidates",
            str(candidates),
        )
        self.assertEqual(code, 0)
        self.assertEqual(_json(matrix)["kind"], "veridor.matrix")
        self.assertEqual(_json(radius)["kind"], "veridor.blast_radius")
        self.assertEqual(_json(candidates)["kind"], "veridor.candidates")
        self.assertTrue(_only(self.output / "matrix").exists())

    def test_promote_writes_incomplete_stubs_and_says_so(self) -> None:
        promote = self.workspace / "promote.json"
        code, stdout, _ = self.run_map("--promote", str(promote))
        self.assertEqual(code, 0)
        document = _json(promote)
        self.assertTrue(document["checks"])
        for check in document["checks"]:
            self.assertIn("TODO", check["name"])
        self.assertIn("promotion stub", stdout)

    def test_coverage_artifacts_are_written_by_map_too(self) -> None:
        coverage = self.workspace / "coverage.json"
        badge = self.workspace / "badge.json"
        code, _, _ = self.run_map("--coverage", str(coverage), "--badge", str(badge))
        self.assertEqual(code, 0)
        self.assertIn("covered", json.dumps(_json(coverage)))
        self.assertEqual(_json(badge)["schemaVersion"], 1)

    def test_map_refuses_to_overwrite_its_own_inputs(self) -> None:
        code, _, stderr = self.run_map("--matrix", str(MAP_CONFIG))
        self.assertEqual(code, 2)
        self.assertIn("must not overwrite", stderr)

    def test_the_report_bridges_discovery_to_declaration(self) -> None:
        _, stdout, _ = self.run_map()
        prose = " ".join(stdout.split())
        self.assertIn("nothing above is a finding", prose)
        self.assertIn("`veridor run`", prose)
        self.assertIn("`veridor mutate`", prose)


class SpecimenReachabilityTest(unittest.TestCase):
    """A wrong-but-well-formed id produces a report that looks like a pass.

    `inv-42` where the real invoice is `inv-100` 404s. A 404 is recorded as
    `refused`. A grid of refusals is what a boundary that holds looks like.
    Measured on the demo fixture: exit 0 in both arms, `0 candidates.` in both,
    and the only difference is reach counts nobody draws a conclusion from --
    the marker owner refused its own data, with nothing anywhere saying so.
    """

    def _matrix(self, cells: list[tuple[str, str, str, str]]) -> dict:
        rows, seen = [], set()
        for operation, _identity, specimen, _reach in cells:
            if (operation, specimen) not in seen:
                seen.add((operation, specimen))
                rows.append({"operation": operation, "specimen": specimen})
        return {
            "kind": "veridor.matrix",
            "marker_owner": "owner",
            "rows": rows,
            "cells": [
                {"operation": operation, "identity": identity,
                 "specimen": specimen, "reach": reach}
                for operation, identity, specimen, reach in cells
            ],
        }

    def test_a_specimen_nobody_reached_is_named(self) -> None:
        advice = _specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "owner_invoice", "refused"),
            ("GET /api/invoices/{id}", "other", "owner_invoice", "refused"),
        ]))
        self.assertIn("SERVED TO NOBODY", advice)
        self.assertIn("owner_invoice", advice)

    def test_a_shared_label_does_not_mask_a_dead_specimen(self) -> None:
        """`init --for drift` labels every specimen "specimen".

        Aggregating by the bare label therefore made the collision the DEFAULT
        state of a scaffold: one reachable specimen satisfied the 0-of-N test
        for every dead one sharing its name. This is the partly-edited-scaffold
        case the warning was built for, and it was silent in it.
        """
        advice = _specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "specimen", "reached"),
            ("GET /api/orders/{id}", "owner", "specimen", "refused"),
        ]))
        self.assertIn("SERVED TO NOBODY", advice)
        self.assertIn("/api/orders/{id}", advice)
        self.assertNotIn("/api/invoices/{id}", advice)

    def test_a_partly_measured_specimen_is_not_called_universal(self) -> None:
        """"Every identity that was measured" must mean every identity."""
        self.assertEqual(_specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "owner_invoice", "unknown"),
            ("GET /api/invoices/{id}", "other", "owner_invoice", "refused"),
        ])), "")

    def test_a_specimen_its_owner_reached_is_not(self) -> None:
        """The correct configuration, which is by far the common one."""
        self.assertEqual(_specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "owner_invoice", "reached"),
            ("GET /api/invoices/{id}", "other", "owner_invoice", "refused"),
        ])), "")

    def test_an_admin_only_object_is_not_named(self) -> None:
        """Served to somebody is served: the id exists, the scope is narrow."""
        self.assertEqual(_specimen_reachability_advice(self._matrix([
            ("GET /api/audit/{id}", "owner", "audit_record", "refused"),
            ("GET /api/audit/{id}", "admin", "audit_record", "reached"),
        ])), "")

    def test_one_unimplemented_method_does_not_condemn_the_specimen(self) -> None:
        """The unit is the specimen VALUE, across every row that uses it.

        Grouped by ROW, a DELETE that 405s on an id the GET serves would be
        reported as an id nobody was served -- a warning about a correct
        configuration, printed on most CRUD specs.
        """
        self.assertEqual(_specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "owner_invoice", "reached"),
            ("DELETE /api/invoices/{id}", "owner", "owner_invoice", "refused"),
            ("DELETE /api/invoices/{id}", "other", "owner_invoice", "refused"),
        ])), "")

    def test_an_unmeasured_specimen_is_not_named(self) -> None:
        """Nobody was refused; nobody was asked."""
        self.assertEqual(_specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "owner_invoice", "unknown"),
            ("GET /api/invoices/{id}", "other", "owner_invoice", "unknown"),
        ])), "")

    def test_no_specimens_no_advice(self) -> None:
        self.assertEqual(_specimen_reachability_advice(
            {"rows": [{"operation": "GET /api/x", "specimen": None}], "cells": []}
        ), "")

    def test_it_never_becomes_a_finding_or_an_exit_code(self) -> None:
        advice = _specimen_reachability_advice(self._matrix([
            ("GET /api/invoices/{id}", "owner", "owner_invoice", "refused"),
        ]))
        # Normalised, so a rewrap does not fail a test about vocabulary.
        prose = " ".join(advice.split())
        self.assertIn("Nothing here is a finding", prose)
        self.assertIn("nothing here changed the exit code", prose)
        for banned in ("vulnerable", "proves", "confirmed", "misconfigured"):
            self.assertNotIn(banned, advice)


class DriftAgainstABlindBaselineTest(_DemoTarget):
    """The reproduction, end to end through `map`.

    A baseline recorded while the target was down measures nothing. It was
    accepted under `--fail-on-drift`, and against the vulnerable demo target
    -- another tenant's invoice served -- the gate exited 0 under `opened` and
    under `any`, because every comparison with that baseline is `unknown ->
    something` and no policy gates on that.
    """

    def _map(self, base_url: str, *extra: str) -> tuple[int, str, str]:
        # --rate 10, as MapTest: the ceiling, never above it (MATRIX_MAX_RPS is
        # deliberate). These tests assert exit codes and messages, not pacing;
        # at the default 2 req/s they and MapSafetyTest's unmeasurable-matrix
        # test took 42.7 s, at 10 req/s 8.9 s (medians of 3, 2026-09-27).
        return _capture(["map", "--config", str(MAP_CONFIG), "--openapi", str(DEMO_SPEC),
                         "--base-url", base_url, "--output-dir", str(self.output),
                         "--rate", "10", *extra])

    def _record(self, base_url: str, name: str) -> tuple[int, Path]:
        path = self.workspace / name
        code, _, _ = self._map(base_url, "--matrix", str(path))
        self.assertTrue(path.is_file())
        return code, path

    def test_a_baseline_recorded_against_a_dead_target_does_not_pass_the_gate(self) -> None:
        code, blind = self._record(DEAD_TARGET, "blind.json")
        self.assertEqual(code, 3)
        for policy in ("opened", "any"):
            with self.subTest(policy=policy):
                code, stdout, stderr = self._map(
                    self.base_url, "--baseline", str(blind), "--fail-on-drift", policy)
                self.assertEqual(code, 3, stderr)
                self.assertIn("not one of", stderr)
                self.assertIn("measured in both", stderr)
                self.assertNotIn("the matrix moved", stdout)
                self.assertIn("compared nothing", stdout)

    def test_control_discovery_against_the_same_baseline_still_exits_zero(self) -> None:
        _, blind = self._record(DEAD_TARGET, "blind.json")
        code, _, stderr = self._map(self.base_url, "--baseline", str(blind))
        self.assertEqual(code, 0, stderr)

    def test_control_a_baseline_from_the_fixed_target_catches_the_regression(self) -> None:
        fixed = create_demo_server("127.0.0.1", 0, vulnerable=False)
        thread = loopback.start(fixed)
        try:
            code, baseline = self._record(f"http://127.0.0.1:{fixed.server_port}", "fixed.json")
        finally:
            fixed.shutdown()
            fixed.server_close()
            thread.join(timeout=5)
        self.assertEqual(code, 0)
        code, stdout, stderr = self._map(
            self.base_url, "--baseline", str(baseline), "--fail-on-drift", "opened")
        self.assertEqual(code, 1, stderr)
        self.assertIn("the matrix moved", stdout)


class MapSafetyTest(_Workspace):
    """The safety posture, asserted at the layer that could have skipped it."""

    def run_map(self, *extra: str, config: Path | None = None) -> tuple[int, str, str]:
        return _capture(
            [
                "map",
                "--config",
                str(config or MAP_CONFIG),
                "--openapi",
                str(DEMO_SPEC),
                "--base-url",
                DEAD_TARGET,
                "--output-dir",
                str(self.output),
                *extra,
            ]
        )

    @slow("connects to a dead port, so the matrix records nothing")
    def test_an_unmeasurable_matrix_does_not_blame_the_drift_policy(self) -> None:
        """Exit 3, and the sentence explaining it named the wrong cause.

        This is step 3 of the drift on-ramp -- "records the baseline. Finds
        nothing, and says so" -- against a target that is not answering. The
        exit code is right: a matrix that measured nothing is not a baseline.
        The explanation said "you passed --fail-on-drift 'none' and the matrix
        moved", about a comparison that never ran, under a policy that cannot
        gate.
        """
        code, stdout, stderr = self.run_map("--rate", "10")  # the ceiling, as MapTest
        self.assertEqual(code, 3)
        self.assertIn("was measured", stderr)
        self.assertNotIn("--fail-on-drift", stdout)
        self.assertNotIn("your drift policy did", stdout)
        self.assertIn("what the run could not measure did", stdout)

    def test_a_dry_run_sends_nothing_and_writes_nothing(self) -> None:
        code, stdout, _ = self.run_map("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("nothing was sent", stdout)
        self.assertFalse(self.output.exists())

    def test_the_plan_is_refused_over_budget_before_the_first_request(self) -> None:
        code, stdout, stderr = self.run_map("--max-requests", "2")
        self.assertEqual(code, 2)
        self.assertIn("Nothing has been sent", stderr)
        self.assertIn("budget of 2", stderr)
        # The banner is printed by _map AFTER planning, so a refused plan must
        # not have printed one: nothing was decided, nothing was announced.
        self.assertNotIn("this will issue", stdout)
        self.assertFalse(self.output.exists())

    def test_a_dry_run_refuses_an_over_budget_plan_as_the_run_does(self) -> None:
        """REGRESSION. `--dry-run --max-requests 5` printed "Over budget" and
        exited 0 on a plan `map --max-requests 5` refuses with exit 2, so a
        script that dry-runs first was told the plan would go ahead. It still
        prints the plan, which is what an operator narrows it with, and then
        gives the run's refusal and its exit code."""
        code, stdout, stderr = self.run_map("--max-requests", "2")
        self.assertEqual(code, 2)
        dry_code, dry_stdout, dry_stderr = self.run_map("--max-requests", "2", "--dry-run")
        self.assertEqual(dry_code, code, dry_stdout + dry_stderr)
        self.assertIn(stderr.strip().removeprefix("veridor: "), dry_stderr)
        self.assertIn("Without --dry-run, `map` refuses this plan", dry_stderr)
        self.assertIn("this will issue", dry_stdout)
        self.assertIn("nothing was sent", dry_stdout)
        self.assertFalse(self.output.exists())
        # Control: within budget, the same dry run exits 0 and refuses nothing.
        code, stdout, stderr = self.run_map("--dry-run")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("budget:", stdout)

    def test_an_ignore_that_empties_the_grid_is_refused_before_the_first_request(
        self,
    ) -> None:
        """It exited 0 having planned 0 requests, `--require-complete` included.

        Not `--dry-run`: the refusal has to stop a real run, and the fast
        tier's socket guard would raise if this one reached the target.
        """
        code, stdout, stderr = self.run_map("--ignore", "/", "--require-complete")
        self.assertEqual(code, 2, stderr)
        self.assertIn("Nothing has been sent", stderr)
        self.assertNotIn("this will issue", stdout)
        self.assertFalse(self.output.exists())

    def test_a_selection_that_leaves_only_writes_is_refused_before_the_first_request(
        self,
    ) -> None:
        """The demo spec is three GETs, a DELETE and a POST. Ignoring the GETs,
        or including only the DELETE, planned 0 requests and exited 0 under
        `--require-complete`: the refusal counted the two writes as operations
        left to probe, though the read-only posture never sends them."""
        for selection in (("--ignore", "GET /"), ("--include", "DELETE /api/invoices")):
            with self.subTest(selection=selection):
                code, stdout, stderr = self.run_map(*selection, "--require-complete")
                self.assertEqual(code, 2, stdout + stderr)
                self.assertIn("Nothing has been sent", stderr)
                self.assertIn("skipped as non-read-only", stderr)
                self.assertNotIn("this will issue", stdout)
                self.assertFalse(self.output.exists())

    def test_the_banner_states_the_posture_before_anything_is_sent(self) -> None:
        _, stdout, _ = self.run_map("--dry-run")
        self.assertIn("(read-only)", stdout)
        self.assertIn("rate:", stdout)
        self.assertIn("budget:", stdout)
        self.assertIn("systems you own or are explicitly authorised to test", stdout)

    def test_read_only_is_the_default_and_mutating_verbs_are_skipped(self) -> None:
        _, stdout, _ = self.run_map("--dry-run")
        self.assertIn("methods:    GET (read-only)", stdout)
        self.assertIn("skipped as non-read-only", stdout)

    def test_a_mutating_verb_alone_enables_nothing(self) -> None:
        code, _, stderr = self.run_map("--dry-run", "--allow-mutating-method", "DELETE")
        self.assertEqual(code, 2)
        self.assertIn("acknowledgement", stderr)
        self.assertIn("Nothing has been sent", stderr)

    def test_a_wildcard_mutating_verb_is_refused(self) -> None:
        code, _, stderr = self.run_map("--dry-run", "--allow-mutating-method", "*")
        self.assertEqual(code, 2)
        self.assertIn("wildcard", stderr)

    def test_an_acknowledgement_alone_enables_nothing(self) -> None:
        code, _, stderr = self.run_map("--dry-run", "--acknowledge-mutating", "yes")
        self.assertEqual(code, 2)
        self.assertIn("enables nothing", stderr)

    def test_a_public_target_requires_the_hostname_typed_out(self) -> None:
        code, _, stderr = self.run_map(
            "--dry-run", "--base-url", "https://api.example.com"
        )
        self.assertEqual(code, 2)
        self.assertIn("I am authorized to test api.example.com", stderr)
        self.assertIn("Nothing has been sent", stderr)

    def test_the_rate_ceiling_is_not_adjustable(self) -> None:
        code, _, stderr = self.run_map("--dry-run", "--rate", "500")
        self.assertEqual(code, 2)
        self.assertIn("ceiling", stderr)


# ---------------------------------------------------------------------------
# run -- sequences are reachable through it
# ---------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class SequenceReachabilityTest(_Workspace):
    """Steps, captures and sessions, invoked the only way a user can."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.state: dict[str, dict] = {}

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _reply(self, status: int, body: dict) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:  # noqa: N802 - stdlib callback
                length = int(self.headers.get("Content-Length", "0") or 0)
                self.rfile.read(length)
                cls.state["n-1"] = {"id": "n-1", "provenance": OWNER_MARKER}
                self._reply(201, {"id": "n-1"})

            def do_GET(self) -> None:  # noqa: N802 - stdlib callback
                token = self.headers.get("Authorization", "")
                record = cls.state.get(self.path.rsplit("/", 1)[-1])
                if record is None:
                    self._reply(404, {"error": "not found"})
                elif token == "Bearer owner-token":
                    self._reply(200, record)
                else:
                    self._reply(404, {"error": "not found"})

            def do_DELETE(self) -> None:  # noqa: N802 - stdlib callback
                cls.state.pop(self.path.rsplit("/", 1)[-1], None)
                self._reply(204, {})

            def log_message(self, *args: object) -> None:
                return

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def config(self) -> Path:
        return self.write(
            "sequenced.json",
            {
                "version": 2,
                "target": {"base_url": self.base_url, "timeout_seconds": 5},
                "identities": {
                    "owner": {
                        "headers": {"Authorization": "Bearer owner-token"},
                        "marker": OWNER_MARKER,
                    },
                    "attacker": {
                        "headers": {"Authorization": "Bearer attacker-token"}
                    },
                },
                "checks": [],
                "sequences": [
                    {
                        "id": "note-isolation",
                        "name": "A note created by the owner is not readable by anyone else",
                        "steps": [
                            {
                                "role": "setup",
                                "as": "owner",
                                "request": {
                                    "method": "POST",
                                    "path": "/api/notes",
                                    "json": {"title": "seed"},
                                },
                                "expect": {"status": [201]},
                                "capture": {"note": "$.id"},
                            },
                            {
                                "role": "assert",
                                "as": "owner",
                                "request": {
                                    "method": "GET",
                                    "path": "/api/notes/${note}",
                                },
                                "expect": {
                                    "status": [200],
                                    "contains_marker": "owner",
                                },
                            },
                            {
                                "role": "assert",
                                "as": "attacker",
                                "request": {
                                    "method": "GET",
                                    "path": "/api/notes/${note}",
                                },
                                "expect": {
                                    "status": [404],
                                    "excludes_marker": "owner",
                                },
                            },
                        ],
                        "teardown": [
                            {
                                "as": "owner",
                                "request": {
                                    "method": "DELETE",
                                    "path": "/api/notes/${note}",
                                },
                                "expect": {"status": [204]},
                            }
                        ],
                    }
                ],
            },
        )

    def test_a_user_can_invoke_steps_captures_and_teardown_through_run(self) -> None:
        run_json = self.workspace / "run.json"
        code, stdout, stderr = _capture(
            [
                "run",
                "--config",
                str(self.config()),
                "--output-dir",
                str(self.output),
                "--json",
                str(run_json),
            ]
        )
        self.assertEqual(code, 0, stdout + stderr)
        document = _json(run_json)
        self.assertEqual(len(document["sequences"]), 1)
        record = document["sequences"][0]
        self.assertEqual(record["sequence_id"], "note-isolation")
        self.assertEqual(record["outcome"], "completed")
        self.assertEqual(len(record["steps"]), 3)
        self.assertEqual(document["summary"]["sequence_steps_matched"], 3)

    def test_the_console_reports_the_sequence_a_run_executed(self) -> None:
        """It ran before this change; it said nothing, which is not reachable."""
        _, stdout, _ = _capture(
            ["run", "--config", str(self.config()), "--output-dir", str(self.output)]
        )
        self.assertIn("Sequences: 1 executed", stdout)
        self.assertIn("3/3 steps matched", stdout)
        self.assertIn("note-isolation: completed", stdout)

    def test_a_captured_value_never_reaches_the_run_document(self) -> None:
        run_json = self.workspace / "run.json"
        _capture(
            [
                "run",
                "--config",
                str(self.config()),
                "--output-dir",
                str(self.output),
                "--json",
                str(run_json),
            ]
        )
        self.assertNotIn("n-1", run_json.read_text(encoding="utf-8"))

    def test_require_clean_teardown_stays_opt_in(self) -> None:
        code, _, _ = _capture(
            [
                "run",
                "--config",
                str(self.config()),
                "--output-dir",
                str(self.output),
                "--require-clean-teardown",
            ]
        )
        self.assertEqual(code, 0)

    def test_a_run_without_sequences_prints_no_sequence_line(self) -> None:
        """The console output of every existing suite is unchanged."""
        _, stdout, _ = _capture(
            [
                "run",
                "--config",
                str(DEMO_CONFIG),
                "--base-url",
                DEAD_TARGET,
                "--output-dir",
                str(self.output),
                "--fail-on",
                "none",
            ]
        )
        self.assertNotIn("Sequences:", stdout)


# ---------------------------------------------------------------------------
# mutate
# ---------------------------------------------------------------------------


@slow("stands up a loopback HTTP server and runs the engine against it")
class _MutationTarget(_Workspace):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guard_dir = tempfile.TemporaryDirectory()
        cls.guard_path = Path(cls.guard_dir.name) / "tenant-guard"
        cls.guard_path.write_text("present\n", encoding="utf-8")
        cls.server = create_mutation_server("127.0.0.1", 0, guard_path=cls.guard_path)
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.guard_dir.cleanup()

    def setUp(self) -> None:
        super().setUp()
        self.guard_path.write_text("present\n", encoding="utf-8")

    def config(self, checks: list | None = None) -> Path:
        return self.write(
            "config.json",
            {
                "version": 1,
                "target": {"base_url": self.base_url, "timeout_seconds": 5},
                "identities": {
                    "order_owner": {
                        "headers": {"Authorization": "Bearer order-owner-token"},
                        "marker": ORDER_OWNER_MARKER,
                    },
                    "outsider": {
                        "headers": {"Authorization": "Bearer outsider-token"}
                    },
                    "anonymous": {"headers": {}},
                },
                "checks": checks
                or [
                    {
                        "id": "order-tenant-isolation",
                        "request": {"method": "GET", "path": "/api/orders/o-1"},
                        "expect": {
                            "order_owner": {
                                "status": [200],
                                "contains_marker": "order_owner",
                            },
                            "outsider": {
                                "status": [404],
                                "excludes_marker": "order_owner",
                            },
                            "anonymous": {"status": [401]},
                        },
                    }
                ],
            },
        )


class MutateTierOneTest(_MutationTarget):
    def test_mutate_writes_its_reports_and_returns_the_mutation_exit_code(self) -> None:
        code, stdout, _ = _capture(
            ["mutate", "--config", str(self.config()), "--output-dir", str(self.output),
             "--min-interval", "0"]
        )
        directory = self.output / "mutation"
        report = _json(directory / "mutation.json")
        self.assertEqual(code, mutation.exit_code(report))
        self.assertEqual(
            sorted(entry.name for entry in directory.iterdir()),
            ["mutation-badge.json", "mutation.json", "mutation.txt"],
        )
        self.assertIn("Wrote mutation json", stdout)

    def test_require_evaluable_counts_only_what_limits_on_the_evidence_prints(
        self,
    ) -> None:
        """The flag's help says those mutants sit under LIMITS ON THE EVIDENCE.

        On this fixture the outsider's M6 is a real limit (the target hides
        existence uniformly), so exit 3 is right. The owner's M3 is a
        structural not_applicable that prints nowhere; before the fix it was
        counted too, and the stderr said 2 where the report listed 1.
        """
        code, _, stderr = _capture(
            ["mutate", "--config", str(self.config()), "--output-dir",
             str(self.output), "--min-interval", "0", "--require-evaluable"]
        )
        report = _json(self.output / "mutation" / "mutation.json")
        notes = sum(
            1
            for check in report["checks"]
            for note in check["evidence_notes"]
            if note != check.get("marker_note")
        )
        self.assertEqual(notes, 1)
        self.assertEqual(report["summary"]["limited"], notes)
        self.assertEqual(code, 3)
        self.assertIn(f"{notes} mutant(s) could not be evaluated", stderr)

    def test_a_vacuous_check_leaves_a_survivor_and_exits_one(self) -> None:
        """A permissive expectation matches whatever the target does."""
        config = self.config(
            [
                {
                    "id": "wide-open",
                    "request": {"method": "GET", "path": "/api/wide/w-1"},
                    "expect": {
                        "order_owner": {"status": [200, 403, 404]},
                        "outsider": {"status": [200, 403, 404]},
                    },
                }
            ]
        )
        code, stdout, _ = _capture(
            ["mutate", "--config", str(config), "--output-dir", str(self.output),
             "--min-interval", "0"]
        )
        report = _json(self.output / "mutation" / "mutation.json")
        self.assertTrue(report["survivors"])
        self.assertEqual(code, 1)
        self.assertIn("SURVIV", stdout.upper())

    def test_a_survivor_carries_a_diagnosis(self) -> None:
        config = self.config(
            [
                {
                    "id": "wide-open",
                    "request": {"method": "GET", "path": "/api/wide/w-1"},
                    "expect": {
                        "order_owner": {"status": [200, 403, 404]},
                        "outsider": {"status": [200, 403, 404]},
                    },
                }
            ]
        )
        _capture(["mutate", "--config", str(config), "--output-dir", str(self.output),
             "--min-interval", "0"])
        report = _json(self.output / "mutation" / "mutation.json")
        for survivor in report["survivors"]:
            self.assertTrue(survivor["diagnosis"].strip(), survivor)

    def test_no_mutant_ever_becomes_a_finding_or_a_sarif_result(self) -> None:
        _capture(
            ["mutate", "--config", str(self.config()), "--output-dir", str(self.output),
             "--min-interval", "0"]
        )
        self.assertEqual(list(self.output.rglob("*.sarif")), [])
        self.assertFalse((self.output / "latest.json").exists())
        report = _json(self.output / "mutation" / "mutation.json")
        self.assertNotIn("findings", report)
        self.assertEqual(
            sorted(entry.name for entry in self.output.iterdir()), ["mutation"]
        )

    def test_operator_copies_are_written_in_addition(self) -> None:
        report_json = self.workspace / "m.json"
        report_text = self.workspace / "m.txt"
        badge = self.workspace / "m-badge.json"
        _capture(
            [
                "mutate",
                "--config",
                str(self.config()),
                "--output-dir",
                str(self.output),
                "--json",
                str(report_json),
                "--text",
                str(report_text),
                "--badge",
                str(badge),
                "--min-interval",
                "0",
            ]
        )
        self.assertEqual(_json(report_json)["tier"], 1)
        self.assertIn("mutation", report_text.read_text(encoding="utf-8").lower())
        self.assertEqual(_json(badge)["label"], mutation.BADGE_LABEL)

    def test_the_request_budget_is_honoured(self) -> None:
        code, _, _ = _capture(
            [
                "mutate",
                "--config",
                str(self.config()),
                "--output-dir",
                str(self.output),
                "--request-budget",
                "0",
                "--min-interval",
                "0",
            ]
        )
        report = _json(self.output / "mutation" / "mutation.json")
        self.assertEqual(report["summary"]["mutation_requests"], 0)
        self.assertEqual(code, mutation.exit_code(report))

    def test_mutate_refuses_to_overwrite_its_own_config(self) -> None:
        config = self.config()
        code, _, stderr = _capture(
            [
                "mutate",
                "--config",
                str(config),
                "--output-dir",
                str(self.output),
                "--json",
                str(config),
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("must not overwrite", stderr)


class MutateSafetyEnvelopeTest(_MutationTarget):
    """`mutate` sends real traffic and had no envelope at all.

    ``map`` refuses an oversized plan, throttles to 2 req/s and offers
    ``--dry-run``; ``run`` offers ``--read-only``. ``mutate`` re-issues every
    request the operator declared -- ``DELETE`` included -- and then adds its
    own probes, and it shipped with no ``--read-only``, a rate limit defaulting
    to zero, an unlimited request budget and no write disclosure of any kind. A
    60-check ``DELETE`` suite measured 120 requests in 0.031 s: 3,900 req/s.
    """

    def write_config(self, method: str = "DELETE", checks: int = 2) -> Path:
        return self.config(
            [
                {
                    "id": f"c{index}",
                    "request": {"method": method, "path": f"/api/orders/o-{index}"},
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [404]},
                    },
                }
                for index in range(checks)
            ]
        )

    def test_read_only_refuses_a_writing_configuration_before_any_request(self) -> None:
        code, stdout, stderr = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config()),
                "--output-dir",
                str(self.output),
                "--read-only",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("--read-only refuses DELETE", stderr)
        # Nothing was sent, so nothing was written.
        self.assertFalse(self.output.exists())
        self.assertNotIn("Veridor mutation --", stdout)

    def test_read_only_refuses_at_tier_two_as_well(self) -> None:
        hooks = self.write(
            "hooks.json",
            {
                "hooks": [
                    {
                        "name": "drop-guard",
                        "removes": "a guard",
                        "apply_command": ["/usr/bin/true"],
                        "restore_command": ["/usr/bin/true"],
                    }
                ]
            },
        )
        code, _, stderr = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config()),
                "--output-dir",
                str(self.output),
                "--read-only",
                "--tier",
                "2",
                "--hooks",
                str(hooks),
                _TIER2_ACK_FLAG,
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("--read-only refuses DELETE", stderr)

    def test_read_only_lets_a_read_only_configuration_through(self) -> None:
        code, stdout, _ = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config(method="GET")),
                "--output-dir",
                str(self.output),
                "--read-only",
                "--min-interval",
                "0",
            ]
        )
        self.assertIn(code, {0, 1, 2})
        self.assertIn("read-only: verified", stdout)

    def test_the_default_rate_limit_covers_the_baseline_probes(self) -> None:
        """The reproduced defect was 120 BASELINE requests at 3,900 req/s.

        Throttling only the additional probes would have left that number
        exactly where it was, so the limiter has to cover both halves.
        """
        started = time.monotonic()
        code, stdout, _ = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config(method="GET", checks=2)),
                "--output-dir",
                str(self.output),
                # No --min-interval: this test is about the DEFAULT.
                "--request-budget",
                "0",
            ]
        )
        elapsed = time.monotonic() - started
        self.assertIn(code, {0, 1, 2})
        # Four baseline probes, zero additional ones. Three gaps at 0.5s.
        self.assertGreaterEqual(elapsed, 3 * cli.MUTATE_DEFAULT_MIN_INTERVAL)
        self.assertIn("2 req/s", stdout)

    def test_min_interval_zero_turns_the_limiter_off(self) -> None:
        started = time.monotonic()
        _capture(
            [
                "mutate",
                "--config",
                str(self.write_config(method="GET", checks=2)),
                "--output-dir",
                str(self.output),
                "--min-interval",
                "0",
            ]
        )
        self.assertLess(time.monotonic() - started, 3 * cli.MUTATE_DEFAULT_MIN_INTERVAL)

    def test_the_preflight_banner_discloses_the_write_before_sending(self) -> None:
        code, stdout, _ = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config()),
                "--output-dir",
                str(self.output),
                "--min-interval",
                "0",
            ]
        )
        prose = " ".join(stdout.split())
        self.assertIn("Veridor mutation --", prose)
        self.assertIn("re-issue your 4 declared request(s)", prose)
        self.assertIn("This configuration issues DELETE", prose)
        self.assertIn("WRITES to the target", prose)
        self.assertIn("Pass --read-only", prose)
        # And before the report, not after it.
        self.assertLess(stdout.index("Veridor mutation --"), stdout.index("Wrote mutation"))

    def test_a_read_only_configuration_gets_no_write_disclosure(self) -> None:
        _, stdout, _ = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config(method="GET")),
                "--output-dir",
                str(self.output),
                "--min-interval",
                "0",
            ]
        )
        self.assertNotIn("WRITES to the target", stdout)

    def test_the_default_request_budget_is_finite(self) -> None:
        _, stdout, _ = _capture(
            [
                "mutate",
                "--config",
                str(self.write_config(method="GET")),
                "--output-dir",
                str(self.output),
                "--min-interval",
                "0",
            ]
        )
        self.assertIn(
            f"up to {cli.MUTATE_DEFAULT_REQUEST_BUDGET:,} additional probe(s)", stdout
        )
        self.assertNotIn("unlimited", stdout)


class MutateEnvelopeParserTest(unittest.TestCase):
    """The flag surface itself. Reads the parser, opens no socket."""

    def test_the_envelope_flags_exist_on_the_parser(self) -> None:
        """argparse rejected --read-only outright."""
        parsed = _parser().parse_args(
            ["mutate", "--config", "x", "--read-only", "--min-interval", "0"]
        )
        self.assertTrue(parsed.read_only)
        self.assertEqual(parsed.min_interval, 0.0)
        # Unset stays None so "the operator passed this" is still detectable,
        # which is what the tier-2 refusal below depends on. The defaults are
        # applied in _mutate, not by argparse.
        default = _parser().parse_args(["mutate", "--config", "x"])
        self.assertIsNone(default.min_interval)
        self.assertIsNone(default.request_budget)
        self.assertFalse(default.read_only)

    def test_the_help_states_the_defaults_it_actually_applies(self) -> None:
        help_text = " ".join(
            _parser()._subparsers._group_actions[0]  # noqa: SLF001 - argparse has no API
            .choices["mutate"]
            .format_help()
            .split()
        )
        self.assertIn(f"default: {cli.MUTATE_DEFAULT_MIN_INTERVAL:g}", help_text)
        self.assertIn(f"default: {cli.MUTATE_DEFAULT_REQUEST_BUDGET:,}", help_text)
        self.assertIn(f"default: {cli.MUTATE_DEFAULT_MAX_REQUESTS:,}", help_text)

    def test_the_ceiling_help_says_what_tier_two_charges_and_what_it_does_not(
        self,
    ) -> None:
        """REGRESSION. The help said the flag bounded "the WHOLE plan" and that
        "at tier 2 the baseline is charged once per hook", after tier 2 began
        charging an unmutated run and each run's liveness controls, and while
        session logins and sequence steps went uncounted there. README and the
        pre-flight banner were corrected; this string was not.
        """
        action = next(
            action
            for action in _parser()._subparsers._group_actions[0]  # noqa: SLF001
            .choices["mutate"]
            ._actions
            if action.dest == "max_requests"
        )
        help_text = " ".join(action.help.split())
        self.assertNotIn("WHOLE plan", help_text)
        self.assertIn("once per hook plus once for the unmutated run", help_text)
        self.assertIn("liveness control", help_text)
        self.assertIn("Session logins and sequence steps are not counted at tier 2", help_text)

    def test_readme_and_docstring_do_not_say_the_ceiling_bounds_the_whole_plan(
        self,
    ) -> None:
        """REGRESSION. After the help stopped saying "WHOLE plan", README's
        ``--max-requests`` bullet still said the flag "bounds the *whole* plan"
        and ``refuse_if_over_total``'s docstring charged it "against the *whole*
        plan". At tier 2 neither session logins nor ``sequences`` steps are
        counted (``planned_requests`` adds nothing for a 50-step sequence), so
        "whole" overstated the bound in both places.
        """
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start = readme.index("- **`--max-requests`**")
        end = readme.index("\n\n", start)
        bullet = " ".join(readme[start:end].split())
        docstring = " ".join((mutation.refuse_if_over_total.__doc__ or "").split())
        planned = " ".join((mutation.planned_requests.__doc__ or "").split())
        # The count refuse_if_over_total compares made the same claim.
        self.assertNotIn("Every request this invocation may put on the wire", planned)
        self.assertIn("not counted at tier 2", planned)
        self.assertIn("baseline included", bullet)  # the passage that was found
        for name, text in (("README", bullet), ("docstring", docstring)):
            with self.subTest(source=name):
                self.assertNotIn("*whole*", text)
                self.assertNotIn("whole plan", text.lower())
                self.assertIn("not counted at tier 2", text)
        # The exception has to stay attached to the claim it qualifies.
        self.assertIn("Session logins and `sequences` steps are not counted", bullet)


class MutateVolumeCeilingTest(unittest.TestCase):
    """``--min-interval`` bounds the rate; this bounds the VOLUME.

    The two are not substitutes. A 5,000-check configuration put 10,500 requests
    on the wire, correctly disclosed by the pre-flight banner and not refused --
    at the default rate that is roughly 85 minutes against somebody's API, and a
    disclosure the operator can only act on with Ctrl-C is not a control. ``map``
    has always refused an oversized plan before the first socket; this brings
    ``mutate`` to the same posture.

    Opens no socket: every number is derived from the configuration offline,
    which is the property that lets the refusal happen before anything is sent.
    """

    def _config(self, checks: int) -> dict[str, object]:
        return {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:8765"},
            "identities": {"owner": {"headers": {}}, "other": {"headers": {}}},
            "checks": [
                {
                    "id": f"c{index}",
                    "request": {"method": "GET", "path": f"/api/invoices/{index}"},
                    "expect": {
                        "owner": {"status": [200]},
                        "other": {"status": [404]},
                    },
                }
                for index in range(checks)
            ],
        }

    def test_the_plan_counts_the_baseline_not_only_the_extra_probes(self) -> None:
        # The gap was precisely that --request-budget charges
        # only the additional probes, so it cannot bound a large baseline.
        config = self._config(10)
        self.assertEqual(mutation._baseline_requests(config), 20)
        self.assertEqual(
            mutation.planned_requests(config, request_budget=500), 520
        )
        # Tier 2 replays the whole baseline once per hook.
        self.assertEqual(
            mutation.planned_requests(config, request_budget=None, suite_runs=3), 60
        )

    def test_an_oversized_plan_is_refused_and_names_the_number(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            mutation.refuse_if_over_total(
                self._config(3000),
                max_requests=cli.MUTATE_DEFAULT_MAX_REQUESTS,
                request_budget=500,
                min_interval_seconds=0.5,
            )
        message = str(caught.exception)
        self.assertIn("6,500", message)
        self.assertIn("Nothing has been sent.", message)
        # The way out is in the message, with the number already worked out.
        self.assertIn("--max-requests 6500", message)

    def test_a_plan_inside_the_ceiling_is_not_refused(self) -> None:
        mutation.refuse_if_over_total(
            self._config(10),
            max_requests=cli.MUTATE_DEFAULT_MAX_REQUESTS,
            request_budget=500,
            min_interval_seconds=0.5,
        )

    def test_the_ceiling_can_be_raised_explicitly(self) -> None:
        mutation.refuse_if_over_total(
            self._config(3000),
            max_requests=99_999,
            request_budget=500,
            min_interval_seconds=0.5,
        )

    def test_the_ceiling_applies_at_tier_two_charged_per_hook(self) -> None:
        # One hook fits; three replays of the same baseline do not.
        config = self._config(1200)
        mutation.refuse_if_over_total(
            config,
            max_requests=cli.MUTATE_DEFAULT_MAX_REQUESTS,
            request_budget=None,
            min_interval_seconds=0.0,
            suite_runs=1,
        )
        with self.assertRaises(ConfigError) as caught:
            mutation.refuse_if_over_total(
                config,
                max_requests=cli.MUTATE_DEFAULT_MAX_REQUESTS,
                request_budget=None,
                min_interval_seconds=0.0,
                suite_runs=3,
            )
        self.assertIn("7,200", str(caught.exception))

    def _tier_two(self, max_requests: int, checks: int = 10) -> tuple[int, str, bool]:
        """``mutate --tier 2`` with one hook; returns (code, stderr, applied)."""
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            config = root / "veridor.json"
            config.write_text(json.dumps(self._config(checks)), encoding="utf-8")
            applied = root / "applied"
            hooks = root / "hooks.json"
            hooks.write_text(
                json.dumps(
                    {
                        "hooks": [
                            {
                                "name": "h",
                                "removes": "the guard",
                                "apply_command": [
                                    sys.executable,
                                    "-c",
                                    f"open({str(applied)!r}, 'w')",
                                ],
                                "restore_command": [sys.executable, "-c", "pass"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            code, _, err = _capture(
                [
                    "mutate",
                    "--config",
                    str(config),
                    "--tier",
                    "2",
                    "--hooks",
                    str(hooks),
                    _TIER2_ACK_FLAG,
                    "--output-dir",
                    str(root / "out"),
                    "--max-requests",
                    str(max_requests),
                ]
            )
            return code, err, applied.exists()

    def test_tier_two_charges_the_unmutated_run_as_well(self) -> None:
        """One hook is two suite runs: the target as it is, then mutated.

        A ceiling of exactly one run's declared requests must refuse it before
        anything runs, and the hook's apply command must not have run.
        """
        code, err, applied = self._tier_two(30)
        self.assertEqual(code, 2, err)
        self.assertIn("Nothing has been sent.", err)
        self.assertFalse(applied)

    def test_tier_two_charges_the_liveness_controls_each_run_sends(self) -> None:
        """Each suite run is execute_run, which sends one liveness control per
        denial-only request. Measured before the fix: 60 allowed, 90 sent.

        Here: 20 declared + 10 liveness controls, twice (unmutated + one hook).
        """
        code, err, applied = self._tier_two(40)
        self.assertEqual(code, 2, err)
        self.assertIn("--max-requests 60", err)
        self.assertFalse(applied)

    def test_the_ceiling_is_not_a_tier_one_only_flag(self) -> None:
        # --min-interval and --request-budget are refused at tier 2; this one
        # must not be, because tier 2 is where the baseline is replayed most.
        args = _parser().parse_args(
            [
                "mutate",
                "--config",
                "x",
                "--tier",
                "2",
                "--hooks",
                "h",
                _TIER2_ACK_FLAG,
                "--max-requests",
                "10",
            ]
        )
        cli._validate_mutate_args(args)
        self.assertEqual(args.max_requests, 10)

    def test_an_unset_ceiling_stays_none_so_the_default_is_applied_in_mutate(
        self,
    ) -> None:
        self.assertIsNone(_parser().parse_args(["mutate", "--config", "x"]).max_requests)

    def test_the_tier_one_envelope_is_still_refused_at_tier_two(self) -> None:
        for flag, value in (("--min-interval", "0.1"), ("--request-budget", "5")):
            with self.subTest(flag=flag):
                args = _parser().parse_args(
                    [
                        "mutate",
                        "--config",
                        "x",
                        "--tier",
                        "2",
                        "--hooks",
                        "h",
                        _TIER2_ACK_FLAG,
                        flag,
                        value,
                    ]
                )
                with self.assertRaises(ConfigError) as caught:
                    cli._validate_mutate_args(args)
                self.assertIn(flag, str(caught.exception))


class MutateTierTwoRefusalTest(_MutationTarget):
    """Everything standing between an operator and Veridor running a command."""

    def hooks_file(self, *entries: dict, name: str = "hooks.json") -> Path:
        return self.write(name, {"hooks": list(entries)})

    def good_hook(self, **overrides) -> dict:
        entry = {
            "name": "drop-tenant-filter",
            "removes": "the tenant predicate on /api/orders/o-1",
            "apply_command": [
                sys.executable,
                str(GUARD_TOGGLE),
                "remove",
                str(self.guard_path),
            ],
            "restore_command": [
                sys.executable,
                str(GUARD_TOGGLE),
                "restore",
                str(self.guard_path),
            ],
            "timeout_seconds": 60,
        }
        entry.update(overrides)
        return entry

    def mutate(self, *extra: str) -> tuple[int, str, str]:
        return _capture(
            [
                "mutate",
                "--config",
                str(self.config()),
                "--output-dir",
                str(self.output),
                *extra,
            ]
        )

    def test_tier_two_without_hooks_is_refused(self) -> None:
        code, _, stderr = self.mutate("--tier", "2", _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("--tier 2 requires --hooks", stderr)
        self.assertTrue(self.guard_path.exists())

    def test_tier_two_without_the_acknowledgement_flag_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook())
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path))
        self.assertEqual(code, 2)
        self.assertIn(_TIER2_ACK_FLAG, stderr)
        self.assertIn("Nothing has been run", stderr)
        self.assertTrue(self.guard_path.exists())

    def test_a_hook_without_a_restore_command_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook(restore_command=[]))
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("restore_command", stderr)
        self.assertIn("non-empty list of strings", stderr)
        self.assertTrue(self.guard_path.exists())

    def test_a_missing_restore_command_key_is_refused(self) -> None:
        entry = self.good_hook()
        del entry["restore_command"]
        path = self.hooks_file(entry)
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("restore_command", stderr)
        self.assertTrue(self.guard_path.exists())

    def test_an_argv_that_is_a_bare_string_is_refused(self) -> None:
        """`tuple("git")` is four one-character arguments, which is not a command."""
        path = self.hooks_file(self.good_hook(apply_command="./mutate.sh --guard x"))
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("a single string is not a command line", stderr)

    def test_a_non_string_argv_element_is_refused(self) -> None:
        path = self.hooks_file(
            self.good_hook(apply_command=["./mutate.sh", "--port", 8080])
        )
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("apply_command[2]", stderr)
        self.assertIn("non-empty string", stderr)

    def test_an_empty_argv_element_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook(apply_command=["./mutate.sh", ""]))
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("apply_command[1]", stderr)

    def test_a_hook_that_names_no_guard_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook(removes="  "))
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("which guard it removes", stderr)

    def test_an_unknown_hook_key_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook(shell=True))
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("unsupported keys: shell", stderr)

    def test_a_duplicate_hook_name_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook(), self.good_hook())
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("declared twice", stderr)

    def test_the_whole_file_is_refused_when_any_hook_is_bad(self) -> None:
        """Hook 3 failing after hooks 1 and 2 ran is a mess, not a diagnostic."""
        path = self.hooks_file(
            self.good_hook(),
            self.good_hook(name="second", restore_command=[]),
        )
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("second", stderr)
        self.assertTrue(self.guard_path.exists())
        self.assertFalse((self.output / "mutation").exists())

    def test_hooks_without_tier_two_is_refused(self) -> None:
        path = self.hooks_file(self.good_hook())
        code, _, stderr = self.mutate("--hooks", str(path))
        self.assertEqual(code, 2)
        self.assertIn("--hooks requires --tier 2", stderr)

    def test_the_acknowledgement_flag_without_tier_two_is_refused(self) -> None:
        code, _, stderr = self.mutate(_TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("requires --tier 2", stderr)

    def test_tier_one_flags_are_refused_on_tier_two(self) -> None:
        path = self.hooks_file(self.good_hook())
        code, _, stderr = self.mutate(
            "--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG,
            "--request-budget", "5",
        )
        self.assertEqual(code, 2)
        self.assertIn("tier 1 only", stderr)

    def test_a_malformed_hooks_file_is_refused(self) -> None:
        path = self.write("hooks.json", {"hooks": []})
        code, _, stderr = self.mutate("--tier", "2", "--hooks", str(path), _TIER2_ACK_FLAG)
        self.assertEqual(code, 2)
        self.assertIn("non-empty list of hooks", stderr)

    def test_a_missing_hooks_file_is_refused(self) -> None:
        code, _, stderr = self.mutate(
            "--tier", "2", "--hooks", str(self.workspace / "absent.json"),
            _TIER2_ACK_FLAG,
        )
        self.assertEqual(code, 2)
        self.assertIn("hooks file not found", stderr)


class MutateTierTwoTest(_MutationTarget):
    """The exposed path, run for real against the shipped worked example."""

    def hooks_path(self) -> Path:
        return self.write(
            "hooks.json",
            {
                "hooks": [
                    {
                        "name": "drop-tenant-filter",
                        "removes": "the tenant predicate on /api/orders/o-1",
                        "apply_command": [
                            sys.executable,
                            str(GUARD_TOGGLE),
                            "remove",
                            str(self.guard_path),
                        ],
                        "restore_command": [
                            sys.executable,
                            str(GUARD_TOGGLE),
                            "restore",
                            str(self.guard_path),
                        ],
                        "timeout_seconds": 60,
                    }
                ]
            },
        )

    def run_tier2(self, config: Path | None = None) -> tuple[int, str, str]:
        return _capture(
            [
                "mutate",
                "--config",
                str(config or self.config()),
                "--output-dir",
                str(self.output),
                "--tier",
                "2",
                "--hooks",
                str(self.hooks_path()),
                _TIER2_ACK_FLAG,
            ]
        )

    def test_the_disclosure_is_printed_before_anything_runs(self) -> None:
        _, stdout, _ = self.run_tier2()
        prose = " ".join(stdout.split())
        self.assertIn("TIER 2 EXECUTES THE COMMANDS BELOW ON THIS MACHINE", prose)
        self.assertIn("NO SHELL", prose)
        self.assertIn("restore_command is expected to put it back", prose)
        # Both argv lists, in full, before the report.
        self.assertLess(stdout.index("TIER 2 EXECUTES"), stdout.index("apply:"))
        self.assertLess(stdout.index("apply:"), stdout.index("restore:"))
        self.assertLess(stdout.index("restore:"), stdout.index("Wrote mutation"))

    def test_a_covered_guard_is_killed_and_the_target_is_restored(self) -> None:
        code, _, _ = self.run_tier2()
        report = _json(self.output / "mutation" / "mutation-tier2.json")
        self.assertEqual(report["tier"], 2)
        self.assertEqual(report["summary"][mutation.KILLED], 1)
        self.assertEqual(code, 0)
        self.assertTrue(self.guard_path.exists())
        self.assertTrue(report["checks"][0]["restore_verified"])

    def test_tier_two_produces_no_sarif_and_no_run_history(self) -> None:
        self.run_tier2()
        self.assertEqual(list(self.output.rglob("*.sarif")), [])
        self.assertFalse((self.output / "latest.json").exists())

    def test_the_suite_evidence_directory_is_named_and_qualified(self) -> None:
        """Those run documents are full of findings by design. Say so."""
        _, stdout, _ = self.run_tier2()
        prose = " ".join(stdout.split())
        self.assertIn("Wrote tier-2 suite evidence to", prose)
        self.assertIn("deliberately mutated build", prose)
        self.assertIn("not results about your real target", prose)
        # Except the one run before any hook, which is said apart.
        self.assertIn("unmutated/ ran against the target as it is", prose)
        self.assertTrue(list((self.output / "mutation" / "tier2-runs" / "unmutated").rglob("*.json")))
        # They exist, they are shaped like runs, and they stay in their own tree.
        evidence = self.output / "mutation" / "tier2-runs"
        self.assertTrue(list(evidence.rglob("latest.json")))
        self.assertEqual(list(evidence.rglob("*.sarif")), [])

    def test_a_green_unmutated_run_is_described_as_green(self) -> None:
        _, stdout, _ = self.run_tier2()
        report = _json(self.output / "mutation" / "mutation-tier2.json")
        self.assertEqual(report["unmutated_run"]["outcome"], mutation.UNMUTATED_PASSED)
        prose = " ".join(stdout.split())
        self.assertIn(
            "unmutated/ ran against the target as it is, before any hook, and the "
            "suite passed there",
            prose,
        )

    def test_a_red_unmutated_run_is_not_described_as_a_pass(self) -> None:
        """REGRESSION. With the suite already red against the real target, every
        hook was ruled not applicable and the run exited 2, and the closing line
        still said unmutated/ was there "to show the suite passes without a
        mutation" -- describing evidence of a pass that did not happen.
        """
        red = self.config(
            [
                {
                    "id": "order-tenant-isolation",
                    "request": {"method": "GET", "path": "/api/orders/o-1"},
                    "expect": {
                        "order_owner": {"status": [200], "contains_marker": "order_owner"},
                        # The fixture answers this identity 404.
                        "outsider": {"status": [403], "excludes_marker": "order_owner"},
                    },
                }
            ]
        )
        code, stdout, _ = self.run_tier2(red)
        self.assertEqual(code, 2)
        report = _json(self.output / "mutation" / "mutation-tier2.json")
        self.assertEqual(report["checks"][0]["outcome"], mutation.NOT_APPLICABLE)
        self.assertEqual(report["unmutated_run"]["outcome"], mutation.NOT_APPLICABLE)
        prose = " ".join(stdout.split())
        self.assertNotIn("deliberately mutated build", prose)
        self.assertNotIn("suite passes without a mutation", prose)
        self.assertNotIn("suite passed there", prose)
        # The green branch's "The one under unmutated/" leans on "run documents"
        # before it; this branch has no such sentence, so it must name the thing.
        self.assertNotIn("The one under unmutated/", prose)
        self.assertIn(
            "Do not publish it. The run documents under unmutated/ are from the "
            "suite run against the target as it is, before any hook. The suite "
            "already reported findings there, so no hook was applied",
            prose,
        )

    def test_an_unmeasured_unmutated_run_is_not_described_as_a_pass(self) -> None:
        dead = self.config()
        document = _json(dead)
        document["target"]["base_url"] = DEAD_TARGET
        dead.write_text(json.dumps(document), encoding="utf-8")
        code, stdout, _ = self.run_tier2(dead)
        self.assertEqual(code, 2)
        report = _json(self.output / "mutation" / "mutation-tier2.json")
        self.assertEqual(report["unmutated_run"]["outcome"], mutation.ERRORED)
        prose = " ".join(stdout.split())
        self.assertNotIn("suite passes without a mutation", prose)
        self.assertNotIn("suite passed there", prose)
        self.assertNotIn("deliberately mutated build", prose)
        self.assertNotIn("The one under unmutated/", prose)
        self.assertIn(
            "Do not publish it. The run documents under unmutated/ are from the "
            "suite run against the target as it is, before any hook. The suite "
            "could not run or could not grade every result there, so no hook was "
            "applied",
            prose,
        )

    def test_the_tier_two_badge_is_labelled_apart_from_the_tier_one_one(self) -> None:
        self.run_tier2()
        badge = _json(self.output / "mutation" / "mutation-tier2-badge.json")
        self.assertEqual(badge["label"], mutation.TIER2_BADGE_LABEL)
        self.assertNotEqual(mutation.TIER2_BADGE_LABEL, mutation.BADGE_LABEL)


# ---------------------------------------------------------------------------
# nothing that already worked may have moved
# ---------------------------------------------------------------------------


class BackwardCompatibilityTest(_DemoTarget):
    vulnerable = False

    def test_every_pre_existing_subcommand_still_parses(self) -> None:
        parser = _parser()
        for argv in (
            ["run", "--config", "c.json"],
            ["verify", "--config", "c.json"],
            ["coverage", "--config", "c.json", "--openapi", "s.json"],
            ["init", "--openapi", "s.json", "--output", "c.json"],
            ["new-marker"],
            ["report", "--input", "r.json", "--sarif", "o.sarif"],
            ["serve"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(parser.parse_args(argv).command, argv[0])

    def test_every_fail_on_policy_is_unchanged(self) -> None:
        """Every previously-valid policy still parses and still means itself.

        The DEFAULT moved to `new+confirmed`, deliberately: `new` alone is a set
        difference against a file the README asks you to commit, so a pull
        request that adds a finding id to `baseline.json` turns a live
        `confirmed` leak green. Nobody who passes `--fail-on new` is affected;
        the policy is intact and still opt-in-able.
        """
        parser = _parser()
        for policy in ("new", "any", "confirmed", "none", "new+confirmed"):
            args = parser.parse_args(
                ["run", "--config", "c.json", "--fail-on", policy]
            )
            self.assertEqual(args.fail_on, policy)
        self.assertEqual(
            parser.parse_args(["run", "--config", "c.json"]).fail_on,
            "new+confirmed",
        )

    def test_a_green_run_still_exits_zero_and_writes_the_same_artifacts(self) -> None:
        run_json = self.workspace / "run.json"
        sarif = self.workspace / "run.sarif"
        code, stdout, _ = _capture(
            [
                "run",
                "--config",
                str(DEMO_CONFIG),
                "--base-url",
                self.base_url,
                "--output-dir",
                str(self.output),
                "--json",
                str(run_json),
                "--sarif",
                str(sarif),
            ]
        )
        self.assertEqual(code, 0, stdout)
        document = _json(run_json)
        self.assertEqual(document["status"], "passed")
        self.assertEqual(document["schema_version"], 2)
        self.assertTrue((self.output / "latest.json").exists())
        self.assertEqual(_json(sarif)["version"], "2.1.0")
        self.assertIn("Veridor run", stdout)
        self.assertIn("Regression diff:", stdout)

    def test_new_marker_and_report_still_work(self) -> None:
        code, marker, _ = _capture(["new-marker"])
        self.assertEqual(code, 0)
        self.assertTrue(marker.strip())

        run_json = self.workspace / "run.json"
        _capture(
            [
                "run",
                "--config",
                str(DEMO_CONFIG),
                "--base-url",
                self.base_url,
                "--output-dir",
                str(self.output),
                "--json",
                str(run_json),
            ]
        )
        sarif = self.workspace / "converted.sarif"
        code, stdout, _ = _capture(
            ["report", "--input", str(run_json), "--sarif", str(sarif)]
        )
        self.assertEqual(code, 0)
        self.assertEqual(_json(sarif)["version"], "2.1.0")
        self.assertIn("Wrote SARIF report", stdout)

    def test_coverage_alone_still_exits_zero_and_issues_no_request(self) -> None:
        code, stdout, _ = _capture(
            [
                "coverage",
                "--config",
                str(DEMO_CONFIG),
                "--openapi",
                str(DEMO_SPEC),
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("Authorization boundary coverage", stdout)

    def test_a_bad_configuration_still_exits_two(self) -> None:
        code, _, stderr = _capture(
            ["run", "--config", str(self.write("bad.json", {"version": 9}))]
        )
        self.assertEqual(code, 2)
        self.assertIn("veridor:", stderr)

    def test_the_new_verbs_did_not_take_a_flag_name_run_already_used(self) -> None:
        parser = _parser()
        args = parser.parse_args(
            [
                "run",
                "--config",
                "c.json",
                "--baseline",
                "b.json",
                "--json",
                "j.json",
                "--sarif",
                "s.sarif",
                "--read-only",
                "--require-clean-teardown",
                "--openapi",
                "o.json",
                "--coverage",
                "cov.json",
                "--badge",
                "badge.json",
                "--allow-no-matches",
            ]
        )
        self.assertTrue(args.read_only)
        self.assertTrue(args.require_clean_teardown)
        self.assertTrue(args.allow_no_matches)


class FirstKeystrokeTest(unittest.TestCase):
    """What the binary says before the user has read anything.

    REGRESSION. The bare binary emitted an argparse usage line and "the
    following arguments are required: <command>" -- naming neither the three
    verbs nor the flag that lists them -- while ``--help`` is the best-shaped
    page this tool has.
    """

    def test_the_bare_binary_prints_the_three_verbs(self) -> None:
        code, stdout, _ = _capture([])
        self.assertEqual(code, 2)
        for verb in ("map", "run", "mutate"):
            self.assertIn(verb, stdout)
        self.assertIn("THE THREE VERBS", stdout)

    def test_an_unknown_command_points_at_help(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            _capture(["no-such-command"])
        self.assertEqual(caught.exception.code, 2)


@slow("stands up a loopback HTTP server and runs the engine against it")
class TargetDisclosureTest(unittest.TestCase):
    """A green run has to say what it was green against.

    REGRESSION. The quickstart backgrounds ``scripts/demo_server.py``; on a
    busy port that bind failed with a raw traceback that scrolls past, and the
    very next ``veridor run`` probed whatever else owned the port. Every line
    of the summary read identically either way, so a first-time user could be
    handed a fully green run against an unrelated process.
    """

    def test_the_run_summary_names_the_target(self) -> None:
        api = create_demo_server("127.0.0.1", 0, vulnerable=True)
        thread = loopback.start(api)
        try:
            base_url = f"http://127.0.0.1:{api.server_port}"
            with tempfile.TemporaryDirectory() as directory:
                code, stdout, _ = _capture(
                    [
                        "run",
                        "--config",
                        str(DEMO_CONFIG),
                        "--base-url",
                        base_url,
                        "--output-dir",
                        str(Path(directory) / "out"),
                    ]
                )
        finally:
            api.shutdown()
            api.server_close()
        self.assertEqual(code, 1)
        self.assertIn(f"Target: {base_url}", stdout)

    def test_the_demo_server_refuses_a_busy_port_instead_of_crashing(self) -> None:
        held = create_demo_server("127.0.0.1", 0)
        try:
            argv = [
                sys.executable,
                str(ROOT / "scripts" / "demo_server.py"),
                "--port",
                str(held.server_port),
            ]
            finished = subprocess.run(
                argv, capture_output=True, text=True, timeout=30
            )
        finally:
            held.server_close()
        self.assertEqual(finished.returncode, 2)
        self.assertNotIn("Traceback", finished.stderr)
        self.assertIn("cannot listen on", finished.stderr)
        self.assertIn("did NOT start", finished.stderr)
        # and it says what that means for whatever the reader runs next
        self.assertIn("probing that other process", finished.stderr)


class UnauthenticatedExposureGuardTest(unittest.TestCase):
    """The viewer has no authentication, so the bind address is the whole gate.

    This guard had zero body coverage across the entire suite: nothing ever
    executed its raise path, and the hole that left was not hypothetical. ``""``
    was listed as a loopback address, and to ``socket.bind`` it means INADDR_ANY
    -- every interface. Measured before the fix: ``--host ""`` was accepted, the
    socket came up on ``*:PORT``, and a request from another address on the LAN
    carrying ``Host: localhost`` was answered 200 with every run document in it.
    """

    def _verdict(self, host: str, acknowledged: bool = False) -> str:
        namespace = argparse.Namespace(
            host=host, acknowledge_exposure=acknowledged
        )
        try:
            cli._refuse_unauthenticated_exposure(namespace)
        except ConfigError:
            return "refused"
        return "allowed"

    def test_loopback_binds_are_allowed(self) -> None:
        for host in ("127.0.0.1", "localhost", "::1", "[::1]", "LOCALHOST"):
            with self.subTest(host=host):
                self.assertEqual(self._verdict(host), "allowed")

    def test_every_public_bind_is_refused(self) -> None:
        # "" is the one that used to pass. It is not a spelling anybody types by
        # accident, which is exactly why nothing caught it.
        for host in ("", "  ", "0.0.0.0", "::", "192.168.6.87", "example.test"):
            with self.subTest(host=host):
                self.assertEqual(self._verdict(host), "refused")

    def test_the_acknowledgement_still_opts_in(self) -> None:
        """Refusing must stay a speed bump, not a wall -- the flag is the point."""
        for host in ("", "0.0.0.0", "192.168.6.87"):
            with self.subTest(host=host):
                self.assertEqual(
                    self._verdict(host, acknowledged=True), "allowed"
                )


if __name__ == "__main__":
    unittest.main()
