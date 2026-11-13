"""The exit-code policy of `veridor run`, and the `gate` object it writes.

`veridor.gate.evaluate` is the one computation behind the process exit code
AND the run document's `gate` object. These tests hold three things:

* the decision itself -- precedence, the flags, reasons and not-enforced
  conditions -- on synthetic run documents;
* that the exit code a process returns and the `gate.exit_code` written into
  `latest.json`, `runs/<id>.json` and `--json` are the same number, for every
  scenario below under four flag sets (the engine is stubbed, so this is fast);
* the same equality on real runs against the demo target (slow).
"""

from __future__ import annotations

import contextlib
import copy
import io
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import cli, core, gate  # noqa: E402
from veridor.core import validate_run  # noqa: E402
from veridor.coverage import BANNED_CLAIM_WORDS  # noqa: E402

ANSWERED = {"check_id": "c1", "identity": "owner", "response": {"status": 200}, "error": None}
DEAD = {"check_id": "c1", "identity": "other", "response": {}, "error": "timed out"}
UNAUTH = {"state": "failed", "transient": False, "reason": "login_status_mismatch"}


def finding(fid: str, verdict: str = "vulnerable", grade: str = "suspected",
            identity: str = "other", session: dict | None = None) -> dict:
    return {
        "id": fid, "rule_id": "VERIDOR-AUTHZ-001", "level": "error",
        "verdict": verdict, "evidence_grade": grade, "title": f"t-{fid}",
        "message": f"m-{fid}", "check_id": "c1", "identity": identity,
        "location": "veridor.json", "remediation": f"r-{fid}",
        "evidence": {"session": session} if session else {},
    }


def document(probes, findings, new=None, unchanged=None, checks=1, **extra) -> dict:
    new = findings if new is None else new
    result = {
        "schema_version": 2, "run_id": "20260924T000000Z-abcdef",
        "started_at": "2026-09-24T00:00:00+00:00",
        "completed_at": "2026-09-24T00:00:01+00:00",
        "target": "http://127.0.0.1:9", "config": "veridor.json", "status": "passed",
        "summary": {
            "checks": checks, "probes": len(probes), "safe": len(probes) - len(findings),
            "vulnerable": sum(f["verdict"] == "vulnerable" for f in findings),
            "unexpected_denial": 0,
            "inconclusive": sum(f["verdict"] == "inconclusive" for f in findings),
            "non_asserting": 0, "probe_licensed_exclusions": 0, "confirmed": 0,
            "suspected": 0, "ungraded": 0, "new": len(new), "resolved": 0,
            "unchanged": len(unchanged or ()), "escalated": 0,
        },
        "findings": findings,
        "liveness": {"enabled": True, "requests_issued": 0, "requests": [],
                     "sham_token_prefix": "veridor-sham-", "unproven": []},
        "regression": {"baseline_run_id": None, "baseline_digest": None, "new": new,
                       "resolved": [], "unchanged": unchanged or [], "escalated": []},
        "probes": probes,
    }
    result.update(extra)
    return result


UNPROVEN = [{"check_id": "c1", "identity": "other", "statement": "s", "remediation": "r"}]
NON_ASSERTING = [{"check_id": "c1", "identity": "other", "statuses": [200, 404],
                  "classification": "permissive", "statement": "accepts both"}]
UNCLEAN = [{"sequence_id": "seq1", "outcome": "completed", "teardown_state": "failed",
            "steps": [], "teardown": []}]


def scenarios() -> dict[str, dict]:
    built = {
        "clean": document([ANSWERED, ANSWERED], []),
        "new_suspected": document([ANSWERED, ANSWERED], [finding("a")]),
        "baselined_confirmed": document(
            [ANSWERED], [finding("a", grade="confirmed")], new=[],
            unchanged=[finding("a", grade="confirmed")]),
        "baselined_suspected": document(
            [ANSWERED], [finding("a")], new=[], unchanged=[finding("a")]),
        "inconclusive_partial": document(
            [ANSWERED, DEAD], [finding("i", verdict="inconclusive", grade="n/a")]),
        "nothing_answered": document(
            [DEAD, DEAD], [finding("i1", verdict="inconclusive", grade="n/a"),
                           finding("i2", verdict="inconclusive", grade="n/a")]),
        "unauthenticated": document(
            [ANSWERED], [finding("u", verdict="inconclusive", grade="n/a",
                                 identity="bob", session=UNAUTH)]),
        "unclean_teardown": document([ANSWERED], [], sequences=UNCLEAN),
        "non_asserting": document([ANSWERED], [], non_asserting_expectations=NON_ASSERTING),
        "liveness": document([ANSWERED], []),
        "everything": document(
            [ANSWERED, DEAD],
            [finding("a", grade="confirmed"),
             finding("i1", verdict="inconclusive", grade="n/a"),
             finding("u", verdict="inconclusive", grade="n/a", identity="bob",
                     session=UNAUTH)],
            sequences=UNCLEAN, non_asserting_expectations=NON_ASSERTING),
    }
    built["liveness"]["liveness"]["unproven"] = list(UNPROVEN)
    built["everything"]["liveness"]["unproven"] = list(UNPROVEN)
    return built


FLAGS = list(itertools.product(gate.FAIL_ON_CHOICES, (False, True), (False, True)))


class DecisionTest(unittest.TestCase):
    def _decide(self, name: str, fail_on: str = "new+confirmed", **flags) -> gate.GateDecision:
        return gate.evaluate(scenarios()[name], fail_on=fail_on, **flags)

    def test_the_first_reason_decides_the_exit_code(self) -> None:
        """The invariant every report leans on, over every scenario and flag."""
        for name, result in scenarios().items():
            for fail_on, complete, teardown in FLAGS:
                for coverage in (0, 2):
                    with self.subTest(name=name, fail_on=fail_on, complete=complete,
                                      teardown=teardown, coverage=coverage):
                        decision = gate.evaluate(
                            result, fail_on=fail_on, require_complete=complete,
                            require_clean_teardown=teardown, coverage_status=coverage)
                        expected = decision.reasons[0]["exit_code"] if decision.reasons else 0
                        self.assertEqual(decision.exit_code, expected)
                        codes = [r["code"] for r in decision.reasons]
                        self.assertEqual(
                            codes, sorted(codes, key=gate.REASON_CODES.index),
                            "reasons are listed in precedence order")
                        for entry in decision.not_enforced:
                            self.assertEqual(entry["exit_code"], 0)
                            self.assertTrue(entry["enforced_by"])

    def test_the_documented_codes(self) -> None:
        cases = [
            ("clean", {}, 0),
            ("new_suspected", {}, 1),
            ("baselined_confirmed", {}, 1),         # proof gates regardless of age
            ("baselined_suspected", {}, 0),
            ("baselined_suspected", {"fail_on": "any"}, 1),
            ("inconclusive_partial", {}, 0),
            ("inconclusive_partial", {"require_complete": True}, 3),
            ("nothing_answered", {}, 3),            # no flag needed
            ("nothing_answered", {"fail_on": "none"}, 0),
            ("unauthenticated", {}, 3),
            ("unauthenticated", {"fail_on": "none"}, 0),
            ("unclean_teardown", {}, 0),
            ("unclean_teardown", {"require_clean_teardown": True}, 3),
            ("unclean_teardown", {"require_clean_teardown": True, "fail_on": "none"}, 3),
            ("non_asserting", {"require_complete": True}, 3),
            ("liveness", {"require_complete": True}, 3),
            ("liveness", {"require_complete": True, "fail_on": "none"}, 0),
            ("everything", {"require_complete": True}, 1),   # a finding always wins
        ]
        for name, flags, expected in cases:
            with self.subTest(name=name, flags=flags):
                self.assertEqual(self._decide(name, **flags).exit_code, expected)

    def test_coverage_ranks_below_a_finding_and_above_exit_three(self) -> None:
        self.assertEqual(gate.evaluate(scenarios()["new_suspected"],
                                       coverage_status=2).exit_code, 1)
        self.assertEqual(gate.evaluate(scenarios()["nothing_answered"],
                                       coverage_status=2).exit_code, 2)
        self.assertEqual(gate.evaluate(scenarios()["clean"], fail_on="none",
                                       coverage_status=2).exit_code, 0)

    def test_a_non_finding_exit_carries_its_reason(self) -> None:
        decision = self._decide("nothing_answered")
        self.assertEqual([r["code"] for r in decision.reasons], [gate.NOTHING_ANSWERED])
        self.assertEqual(decision.reasons[0]["count"], 2)
        unauthenticated = self._decide("unauthenticated")
        self.assertEqual(unauthenticated.reasons[0]["identities"], ["bob"])

    def test_findings_are_reported_by_grade(self) -> None:
        decision = self._decide("everything", require_complete=True)
        findings = decision.reasons[0]
        self.assertEqual(findings["code"], gate.FINDINGS)
        self.assertEqual(findings["by_grade"], {"confirmed": 1})
        self.assertEqual(findings["finding_ids"], ["a"])

    def test_a_condition_the_policy_ignores_is_still_reported(self) -> None:
        decision = self._decide("inconclusive_partial")
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(decision.reasons, ())
        (entry,) = decision.not_enforced
        self.assertEqual(entry["code"], gate.INCONCLUSIVE)
        self.assertEqual(entry["enforced_by"], "--require-complete")
        baselined = self._decide("baselined_suspected")
        self.assertEqual(baselined.not_enforced[0]["code"], gate.FINDINGS)
        self.assertEqual(baselined.not_enforced[0]["enforced_by"], "--fail-on any")

    def test_the_stderr_lines_are_the_ones_the_cli_always_printed(self) -> None:
        decision = self._decide("nothing_answered", fail_on="none", require_complete=True)
        self.assertEqual(decision.messages, (
            "veridor: 2 probe(s) were never answered, so those boundaries are "
            "unverified rather than verified. Re-run when the target is healthy.",
            "veridor: not one of 2 probe(s) was answered, so this run established "
            "nothing. It is not a pass. Check the target URL, the credentials, and "
            "that the target is up.",
        ))

    def test_an_unknown_policy_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            gate.evaluate(scenarios()["clean"], fail_on="new-and-confirmed")

    def test_the_capsule_reasons_make_no_claim_and_keep_the_verdict(self) -> None:
        """`veridor verify` writes these; `run`'s precedence never sees them."""
        for code, text in gate.CAPSULE_REASON_TEXT.items():
            for word in BANNED_CLAIM_WORDS:
                with self.subTest(code=code, word=word):
                    self.assertNotIn(word, text.lower())
            self.assertNotIn(code, gate.REASON_CODES)
        self.assertEqual(gate.capsule_gate("INCONCLUSIVE", "a 500.")["exit_code"], 2)
        self.assertEqual(gate.capsule_gate("CONFIRMED", "x", ["f1"])["reasons"][0]["finding_ids"],
                         ["f1"])
        passed = gate.capsule_gate("NOT_REPRODUCED", "held")
        self.assertEqual((passed["exit_code"], passed["reasons"]), (0, []))
        self.assertIsNone(passed["fail_on"])
        # A CONFIRMED capsule is about the target; INCONCLUSIVE is not, so
        # every report renders it as unmeasured rather than as a finding.
        self.assertIn(gate.CAPSULE_CONFIRMED, gate.FINDING_REASON_CODES)
        self.assertNotIn(gate.CAPSULE_INCONCLUSIVE, gate.FINDING_REASON_CODES)
        self.assertEqual(
            gate.describe({"code": gate.CAPSULE_INCONCLUSIVE, "detail": "it drew a 500."}),
            gate.CAPSULE_REASON_TEXT[gate.CAPSULE_INCONCLUSIVE] + ": it drew a 500",
        )

    def test_the_reason_text_makes_no_claim(self) -> None:
        texts = [(code, text) for code, text in gate.REASON_TEXT.items()]
        texts += [(code, text) for code, pair in gate.REASON_COUNTED.items() for text in pair]
        for code, text in texts:
            for word in BANNED_CLAIM_WORDS:
                with self.subTest(code=code, word=word):
                    self.assertNotIn(word, text.lower())
        self.assertEqual(set(gate.REASON_TEXT), set(gate.REASON_CODES))
        # Every code evaluate() gives a count has a counted wording.
        self.assertEqual(set(gate.REASON_COUNTED),
                         set(gate.REASON_CODES) - {gate.COVERAGE_NOT_MEASURED})
        for code, pair in gate.REASON_COUNTED.items():
            with self.subTest(code=code):
                self.assertTrue(all("{count}" in text for text in pair))


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class RecordedGateTest(unittest.TestCase):
    """The process exit code and every persisted copy of `gate.exit_code` agree."""

    def test_every_copy_of_the_document_carries_the_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "veridor.json"
            config.write_text("{}", encoding="utf-8")
            seen: set[int] = set()
            # Four flag sets per scenario, not all twenty: the pure invariant
            # above covers every combination, and this one pays for a CLI run
            # and four file writes each, inside the fast tier's budget.
            flag_sets = (("new+confirmed", False, False), ("none", True, False),
                         ("any", True, False), ("confirmed", True, True))
            for name, result in scenarios().items():
                for fail_on, complete, teardown in flag_sets:
                    history = root / "history" / name
                    out = root / "out" / f"{name}.json"
                    argv = ["run", "--config", str(config), "--output-dir", str(history),
                            "--json", str(out), "--fail-on", fail_on]
                    if complete:
                        argv.append("--require-complete")
                    if teardown:
                        argv.append("--require-clean-teardown")
                    snapshot = copy.deepcopy(result)
                    with self.subTest(name=name, argv=argv[6:]), mock.patch.object(
                        cli, "execute_run", lambda *a, _d=snapshot, **k: copy.deepcopy(_d)
                    ):
                        code, _, _ = _run_cli(argv)
                        seen.add(code)
                        for path in (out, history / "latest.json",
                                     history / "runs" / f"{result['run_id']}.json"):
                            persisted = json.loads(path.read_text(encoding="utf-8"))
                            validate_run(persisted)
                            self.assertEqual(persisted["gate"]["exit_code"], code, path)
                            self.assertEqual(persisted["gate"]["fail_on"], fail_on)
            # A check that only ever saw exit 0 would prove nothing.
            self.assertEqual(seen, {0, 1, 3})

    def test_a_coverage_error_is_recorded_as_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "veridor.json"
            config.write_text("{}", encoding="utf-8")
            spec = root / "openapi.json"
            spec.write_text("{}", encoding="utf-8")
            with mock.patch.object(cli, "execute_run",
                                   lambda *a, **k: copy.deepcopy(scenarios()["clean"])), \
                    mock.patch.object(cli, "_emit_coverage", lambda *a, **k: 2):
                code, _, _ = _run_cli(["run", "--config", str(config), "--output-dir",
                                       str(root / "h"), "--openapi", str(spec)])
            latest = json.loads((root / "h" / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 2)
            self.assertEqual(latest["gate"]["exit_code"], 2)
            self.assertEqual(latest["gate"]["reasons"][0]["code"],
                             gate.COVERAGE_NOT_MEASURED)


class PersistOncePerStageTest(unittest.TestCase):
    """`run` writes the run document twice -- before the gate is decided, and
    again with `gate` added -- to `runs/<id>.json`, `latest.json` and `--json`.

    Each stage serializes it once (`core.write_json_many`). It used to
    serialize it once per file: six `json.dumps(indent=2)` for a `run --json`,
    the largest single cost of a large run on 3.11 and 3.12 (measured). Both
    writes, the file set and the bytes are unchanged; these tests hold all four.
    """

    @staticmethod
    def _is_run_document(value: object) -> bool:
        return isinstance(value, dict) and "run_id" in value and "probes" in value

    def test_both_stages_write_every_copy_from_one_serialization(self) -> None:
        from test_output_path_identity import _DemoTarget  # noqa: PLC0415
        from veridor import core  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history, out = root / "history", root / "run.json"

            def copies() -> dict[str, bytes | None]:
                runs = sorted((history / "runs").glob("*.json"))
                paths = {"runs/<id>.json": runs[0] if len(runs) == 1 else None,
                         "latest.json": history / "latest.json", "--json": out}
                return {name: path.read_bytes() if path and path.exists() else None
                        for name, path in paths.items()}

            stage_one: dict[str, bytes | None] = {}
            record_gate = cli._record_gate  # noqa: SLF001

            def before_the_gate(args, result, decision):  # noqa: ANN001, ANN202
                stage_one.update(copies())
                return record_gate(args, result, decision)

            with mock.patch.object(core, "_OPENER", _DemoTarget(vulnerable=False)), \
                    mock.patch.object(cli, "_record_gate", before_the_gate), \
                    mock.patch.object(core.json, "dumps", wraps=json.dumps) as dumps:
                code, _, err = _run_cli(["run", "--config", str(ROOT / "fixtures" / "veridor.demo.json"),
                                         "--output-dir", str(history), "--json", str(out)])
            self.assertEqual(code, 0, err)
            serialized = [c for c in dumps.call_args_list if self._is_run_document(c.args[0])]
            stage_two = copies()
            for stage, found in (("before the gate", stage_one), ("after the gate", stage_two)):
                with self.subTest(stage=stage):
                    missing = [name for name, data in found.items() if data is None]
                    self.assertEqual(missing, [], f"not written {stage}")
                    self.assertEqual(len(set(found.values())), 1, f"the copies differ {stage}")
            self.assertNotIn(b'"gate"', stage_one["latest.json"])
            self.assertIn(b'"gate"', stage_two["latest.json"])
            self.assertEqual(len(serialized), 2, "the run document was serialized "
                             f"{len(serialized)} times for two write stages, expected once each")

    def test_every_path_is_replaced_by_a_new_file_with_the_same_bytes(self) -> None:
        """What action.yml's fresh() relies on, for each path, not just the first."""
        import os  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name / "doc.json" for name in ("a", "b", "c")]
            before = {}
            for path in paths:
                path.parent.mkdir()
                path.write_text("stale", encoding="utf-8")
                before[path] = os.stat(path).st_ino
            core.write_json_many(paths, {"run_id": "fresh"})
            self.assertEqual({path.read_bytes() for path in paths}, {b'{\n  "run_id": "fresh"\n}\n'})
            for path in paths:
                self.assertNotEqual(os.stat(path).st_ino, before[path], path)
            self.assertEqual(sorted(p.name for p in Path(directory).rglob("*.tmp")), [])


class ConfigurationWithheldVacuityTest(unittest.TestCase):
    """Every probe withheld by the configuration is not a network problem.

    A run whose every probe was withheld for injection_not_applicable (or
    marker_reflection_blocked, credential_slot_interpolation,
    unresolved_reference) sent nothing and exited 3 with "Check the target
    URL, the credentials, and that the target is up" -- pointing at a healthy
    network while the fix was in the operator's own configuration. Each
    finding's remediation said "Confirm the target is reachable" for three of
    the four.
    """

    REASONS = ("injection_not_applicable", "marker_reflection_blocked",
               "credential_slot_interpolation", "unresolved_reference")

    def _withheld(self, reason: str) -> dict:
        error = core.UNSENT_REASONS[reason]
        probes = [{"check_id": "c1", "identity": name, "response": {"status": None},
                   "error": error} for name in ("owner", "other")]
        return document(probes, [finding(f"i{n}", verdict="inconclusive", grade="n/a")
                                 for n in range(2)])

    def test_the_vacuity_message_gives_configuration_advice(self) -> None:
        for reason in self.REASONS:
            with self.subTest(reason=reason):
                decision = gate.evaluate(self._withheld(reason))
                self.assertEqual(decision.exit_code, 3)
                message = next(m for m in decision.messages if "not one of" in m)
                self.assertNotIn("that the target is up", message)
                self.assertIn("not a network problem", message)
                self.assertIn(reason, message)
                self.assertIn("configuration", message)

    def test_each_finding_gets_configuration_advice(self) -> None:
        for reason in self.REASONS:
            with self.subTest(reason=reason):
                advice = core._transport_remediation(core.UNSENT_REASONS[reason], {})
                self.assertNotIn("reachable", advice)
                self.assertIn("not a network problem", advice)

    def test_control_a_transport_failure_keeps_its_network_advice(self) -> None:
        decision = gate.evaluate(scenarios()["nothing_answered"])
        message = next(m for m in decision.messages if "not one of" in m)
        self.assertIn("that the target is up", message)
        self.assertNotIn("not a network problem", message)

    def test_a_mix_names_the_withheld_ones_beside_the_network_advice(self) -> None:
        result = self._withheld("unresolved_reference")
        result["probes"][1] = dict(DEAD)
        decision = gate.evaluate(result)
        message = next(m for m in decision.messages if "not one of" in m)
        self.assertIn("that the target is up", message)
        # Counted over requests, as the withheld counter reads them; "1 of
        # them" followed a head that counts assert steps in a sequences run.
        self.assertIn("1 of the 2 unanswered request(s)", message)
        self.assertIn("unresolved_reference", message)


class SkippedAfterWithheldStepVacuityTest(unittest.TestCase):
    """Steps skipped because an earlier step was withheld count as withheld.

    Reproduced end to end before this fix: a sequences-only run whose first step
    was withheld for injection_not_applicable skipped its second step, the
    skipped step counted as unanswered and not withheld, and the run ended
    "Check the target URL, the credentials, and that the target is up. 1 of
    them were not sent because the configuration withheld them" -- the
    target was healthy and nothing but the login was sent.
    """

    WITHHELD = core.UNSENT_REASONS["injection_not_applicable"]

    def _sequence(self, first_error: str, *, sequence_id: str = "seq") -> dict:
        return {
            "sequence_id": sequence_id, "outcome": "aborted",
            "aborted_at_step": 0, "abort_reason": "execution_error",
            "steps": [
                {"index": 0, "as": "victim", "role": "setup", "state": "errored",
                 "response": None, "error": first_error},
                {"index": 1, "as": "attacker", "role": "assert", "state": "skipped",
                 "response": None, "error": None},
                {"index": 2, "as": "attacker", "role": "assert", "state": "skipped",
                 "response": None, "error": None},
            ],
            "teardown": [], "teardown_state": "not_required",
        }

    def _message(self, *sequences: dict) -> str:
        result = document([], [finding("s1", verdict="inconclusive", grade="n/a")],
                          checks=0, sequences=list(sequences))
        decision = gate.evaluate(result)
        self.assertEqual(decision.exit_code, 3)
        return next(m for m in decision.messages if "not one of" in m)

    def test_a_run_whose_first_step_was_withheld_gets_no_network_advice(self) -> None:
        message = self._message(self._sequence(self.WITHHELD))
        self.assertNotIn("that the target is up", message)
        self.assertIn("not a network problem", message)
        self.assertIn("injection_not_applicable (3)", message)
        # "not one of 2 assert step(s) ... withheld every
        # one (injection_not_applicable (3))" counted two things as one.
        self.assertIn("withheld all 3 request(s)", message)
        self.assertNotIn("every one", message)

    def test_control_skipped_after_a_transport_failure_keeps_network_advice(
        self,
    ) -> None:
        message = self._message(self._sequence("connection refused"))
        self.assertIn("that the target is up", message)
        self.assertNotIn("withheld", message)

    def test_a_mix_counts_only_the_withheld_sequence_s_steps(self) -> None:
        message = self._message(
            self._sequence(self.WITHHELD),
            self._sequence("connection refused", sequence_id="other"),
        )
        self.assertIn("that the target is up", message)
        self.assertIn("3 of the 6 unanswered request(s)", message)
        self.assertIn("injection_not_applicable (3)", message)


class AnsweredSetupVacuityTest(unittest.TestCase):
    """A run the target answered, that graded nothing, gets no network advice.

    Reproduced through `veridor run` before this fix, every request answered 200:
    a sequences-only config whose one sequence has setup steps only, and one
    whose setup drew 200 where 201 was declared so its assert was skipped.
    Both rightly exit 3 -- no declaration was graded -- and both said "not one
    of 1 probe(s) was answered ... Check the target URL, the credentials, and
    that the target is up" about a target that had answered.
    """

    def _setup(self, status: int | None, state: str) -> dict:
        return {"index": 0, "as": "victim", "role": "setup", "state": state,
                "response": {"status": status} if status else None,
                "error": None if status else "connection refused"}

    def _vacuous(self, *sequences: dict, findings: list | None = None) -> tuple:
        result = document([], findings or [], checks=0, sequences=list(sequences))
        decision = gate.evaluate(result)
        self.assertEqual(decision.exit_code, 3)
        self.assertEqual([r["code"] for r in decision.reasons], [gate.NOTHING_ANSWERED])
        return decision, next(m for m in decision.messages if "established nothing" in m)

    def test_setup_steps_alone_are_named_as_declaring_nothing_to_grade(self) -> None:
        record = {"sequence_id": "seq", "outcome": "completed",
                  "steps": [self._setup(200, "matched")],
                  "teardown": [], "teardown_state": "not_required"}
        decision, message = self._vacuous(record)
        self.assertIn("declares nothing to grade", message)
        self.assertIn("answered 1 of 1 setup step(s)", message)
        self.assertNotIn("that the target is up", message)
        self.assertNotIn("not one of", message)
        self.assertNotIn("that the target is up", message)
        # Control: a setup the target did not answer keeps the network advice.
        down = {"sequence_id": "seq", "outcome": "aborted", "aborted_at_step": 0,
                "abort_reason": "setup_failed", "steps": [self._setup(None, "errored")],
                "teardown": [], "teardown_state": "not_required"}
        _, down_message = self._vacuous(
            down, findings=[finding("s1", verdict="inconclusive", grade="n/a")])
        self.assertIn("answered 0 of 1 setup step(s)", down_message)
        self.assertIn("that the target is up", down_message)
        # Nothing gradable went unanswered: there was nothing gradable.
        self.assertEqual(decision.reasons[0]["count"], 0)
        # Every report renders the reason through gate.describe, which said
        # "not one probe was answered ... (0 unanswered)" here.
        self.assertIs(decision.reasons[0].get("nothing_graded"), True)
        described = gate.describe(decision.reasons[0])
        self.assertIn("declares nothing to grade", described)
        self.assertNotIn("was answered", described)

    def test_asserts_skipped_behind_an_answered_setup_get_no_network_advice(self) -> None:
        record = {"sequence_id": "seq", "outcome": "aborted", "aborted_at_step": 0,
                  "abort_reason": "setup_failed",
                  "steps": [self._setup(200, "mismatched"),
                            {"index": 1, "as": "attacker", "role": "assert",
                             "state": "skipped", "response": None, "error": None}],
                  "teardown": [], "teardown_state": "not_required"}
        _, message = self._vacuous(
            record, findings=[finding("s1", verdict="inconclusive", grade="n/a")])
        self.assertIn("not one of 1 assert step(s) was answered", message)
        self.assertIn("1 step(s) were skipped", message)
        self.assertIn("the target did answer", message)
        self.assertNotIn("that the target is up", message)

    def test_control_a_setup_the_target_did_not_answer_keeps_network_advice(self) -> None:
        for status in (503, None):
            with self.subTest(status=status):
                record = {"sequence_id": "seq", "outcome": "aborted",
                          "aborted_at_step": 0, "abort_reason": "setup_failed",
                          "steps": [self._setup(status, "errored"),
                                    {"index": 1, "as": "attacker", "role": "assert",
                                     "state": "skipped", "response": None,
                                     "error": None}],
                          "teardown": [], "teardown_state": "not_required"}
                _, message = self._vacuous(
                    record, findings=[finding("s1", verdict="inconclusive", grade="n/a")])
                self.assertIn("that the target is up", message)
                self.assertNotIn("were skipped", message)

    def test_the_cli_says_what_the_answered_run_did_not_grade(self) -> None:
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Up:
            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                headers = email.message.Message()
                headers["Content-Length"] = "2"
                headers["Content-Type"] = "application/json"
                return urllib.response.addinfourl(io.BytesIO(b"{}"), headers,
                                                  request.full_url, 200)

        setup = {"role": "setup", "as": "a",
                 "request": {"method": "GET", "path": "/x"},
                 "expect": {"status": [200]}}
        probe = {"role": "assert", "as": "b",
                 "request": {"method": "GET", "path": "/y"},
                 "expect": {"status": [200]}}
        shapes = {
            "setup only": ([setup], "declares nothing to grade"),
            "setup mismatched": ([{**setup, "expect": {"status": [201]}}, probe],
                                 "the target did answer"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, (steps, said) in shapes.items():
                config = {
                    "version": 2,
                    "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
                    "identities": {"a": {"headers": {"Authorization": "Bearer a-token"}},
                                   "b": {"headers": {"Authorization": "Bearer b-token"}}},
                    "checks": [],
                    "sequences": [{"id": "s", "steps": steps}],
                }
                path = root / f"{name.replace(' ', '-')}.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                with self.subTest(shape=name), mock.patch.object(core, "_OPENER", Up()):
                    code, out, err = _run_cli(["run", "--config", str(path),
                                               "--output-dir", str(root / path.stem)])
                    self.assertEqual(code, 3, err)
                    self.assertIn(said, err)
                    self.assertNotIn("that the target is up", err)
                    self.assertNotIn("probe(s) was answered", out)
                    if name == "setup only":
                        markdown = root / f"{path.stem}.md"
                        with mock.patch.object(core, "_OPENER", Up()):
                            _run_cli(["run", "--config", str(path), "--output-dir",
                                      str(root / f"{path.stem}-r"), "--report",
                                      f"markdown={markdown}"])
                        text = markdown.read_text(encoding="utf-8")
                        self.assertIn("declares nothing to grade", text)
                        self.assertNotIn("not one probe was answered", text)


def _sequence_record(*statuses: int | None, state: str = "errored") -> dict:
    """One sequence whose executed steps came back with ``statuses``.

    Step 0 is the setup and every later step an assert, which is the shape a
    real sequence has. Every step used to be a ``setup``, which was harmless
    only while any answered step counted as an answer; a setup grades no
    declaration, so an "answered" sequence built that way measured nothing.
    """
    steps = [
        {"index": i, "as": "victim", "role": "setup" if i == 0 else "assert",
         "state": state,
         "response": {"status": status} if status else None,
         "error": None if status else "connection refused"}
        for i, status in enumerate(statuses)
    ]
    return {"sequence_id": "seq", "outcome": "completed", "steps": steps,
            "teardown": [], "teardown_state": "not_required"}


class SequencesOnlyVacuityTest(unittest.TestCase):
    """`checks: []` plus sequences, against a target that answers nothing.

    `result["probes"]` holds CHECK probes only, so with no checks the guard
    behind "not one probe answered -> exit 3, no flag required" read an empty
    list and could never fire. A sequences-only config against a target that
    was down, or answered 503 to every step, exited 0 under the default
    `--fail-on` with an empty gate and nothing on stderr; the only trace was a
    not-enforced `inconclusive` entry in the run document.
    """

    STEP_INCONCLUSIVE = finding("s1", verdict="inconclusive", grade="n/a",
                                identity="victim")

    def test_a_sequences_only_run_that_answered_nothing_exits_three(self) -> None:
        for name, statuses in (("503", (503, None)), ("refused", (None, None))):
            with self.subTest(target=name):
                result = document([], [dict(self.STEP_INCONCLUSIVE)], checks=0,
                                  sequences=[_sequence_record(*statuses)])
                decision = gate.evaluate(result)
                self.assertEqual(decision.exit_code, 3)
                self.assertEqual([r["code"] for r in decision.reasons],
                                 [gate.NOTHING_ANSWERED])
                self.assertTrue(any("established nothing" in m
                                    for m in decision.messages), decision.messages)

    def test_control_a_sequences_only_run_that_was_answered_passes(self) -> None:
        # checks=0: what a real `checks: []` run writes into summary.checks.
        result = document([], [], checks=0,
                          sequences=[_sequence_record(201, 200, 403, state="matched")])
        decision = gate.evaluate(result)
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(decision.reasons, ())

    def test_checks_still_decide_when_there_are_any(self) -> None:
        """Unchanged: answered check probes are not vacuous whatever the steps did."""
        result = document([ANSWERED], [dict(self.STEP_INCONCLUSIVE)],
                          sequences=[_sequence_record(503)])
        self.assertEqual(gate.evaluate(result).exit_code, 0)

    def test_the_cli_exits_three_on_a_down_target(self) -> None:
        """End to end through `veridor run`, with the opener standing in."""
        import email.message  # noqa: PLC0415
        import urllib.error  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Unavailable:
            def __init__(self, refuse: bool) -> None:
                self.refuse = refuse

            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                if self.refuse:
                    raise urllib.error.URLError(ConnectionRefusedError(61, "refused"))
                headers = email.message.Message()
                headers["Content-Length"] = "0"
                return urllib.response.addinfourl(io.BytesIO(b""), headers,
                                                  request.full_url, 503)

        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
            "identities": {
                "victim": {"headers": {"Authorization": "Bearer victim-token"}},
                "attacker": {"headers": {"Authorization": "Bearer attacker-token"}},
            },
            "checks": [],
            "sequences": [{
                "id": "seq",
                "steps": [
                    {"role": "setup", "as": "victim",
                     "request": {"method": "POST", "path": "/docs", "json": {}},
                     "expect": {"status": [201]}, "capture": {"doc_id": "$.id"}},
                    {"role": "assert", "as": "attacker",
                     "request": {"method": "GET", "path": "/docs/${doc_id}"},
                     "expect": {"status": [403]}},
                ],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            for refuse in (False, True):
                with self.subTest(refuse=refuse), mock.patch.object(
                    core, "_OPENER", Unavailable(refuse)
                ):
                    history = root / f"h{int(refuse)}"
                    code, out, err = _run_cli(["run", "--config", str(path),
                                               "--output-dir", str(history)])
                    self.assertEqual(code, 3, err)
                    self.assertIn("established nothing", err)
                    # One assert step: the setup grades no declaration, so it
                    # is not counted among the requests that went unanswered.
                    self.assertIn("not one of 1 assert step(s) was answered", out)
                    latest = json.loads((history / "latest.json").read_text("utf-8"))
                    self.assertEqual([r["code"] for r in latest["gate"]["reasons"]],
                                     [gate.NOTHING_ANSWERED])


class ChecksWithoutProbesVacuityTest(unittest.TestCase):
    """Declared checks, and not one probe sent, because no session came up.

    `core.execute_run` skips every probe for an identity whose session did not
    establish. When every login drew a 503 -- transient, so the deterministic
    `identity_unauthenticated` guard rightly stays out of it -- a checks-only
    run appended no probe at all. The vacuity rule read the empty probe list
    as "no checks", fell back to sequence steps, found none, and the run exited
    0 having sent nothing but logins. The same outage written as a sequence
    exited 3. A declared check none of whose probes was sent is a check that
    was not answered.
    """

    SESSION_DOWN = [finding(f"x{i}", verdict="inconclusive", grade="n/a", identity=who,
                            session={"state": "failed", "transient": True,
                                     "reason": "login_status_mismatch"})
                    for i, who in enumerate(("owner", "attacker"))]

    def test_a_checks_only_run_that_sent_no_probe_exits_three(self) -> None:
        result = document([], [dict(f) for f in self.SESSION_DOWN])
        decision = gate.evaluate(result)
        self.assertEqual(decision.exit_code, 3)
        self.assertEqual([r["code"] for r in decision.reasons], [gate.NOTHING_ANSWERED])
        self.assertTrue(any("not one of 2 probe(s)" in m for m in decision.messages),
                        decision.messages)

    def test_fail_on_none_still_reports_only(self) -> None:
        result = document([], [dict(f) for f in self.SESSION_DOWN])
        decision = gate.evaluate(result, fail_on="none")
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual([e["code"] for e in decision.not_enforced
                          if e["code"] == gate.NOTHING_ANSWERED], [gate.NOTHING_ANSWERED])

    def test_unsent_and_unanswered_check_probes_are_judged_alike(self) -> None:
        """A probe never sent counts the same as one sent and not answered.

        So the exit code does not depend on whether the outage hit the login
        or the request after it. Both are judged together with the sequence
        steps: beside a sequence the target answered, the run measured a
        boundary and is not vacuous; beside one it did not, it is.

        This test used to assert exit 3 beside an ANSWERED sequence. That
        pinned the overreach it should have caught: the declared checks
        decided alone, so a run whose check sessions all drew a 503 while a
        sequence on other identities was answered 200 and 401 exited 3 and
        said it "established nothing", though the sequence had measured a
        boundary. Vacuous means nothing answered across check probes and
        sequence steps together.
        """
        answered_sequence = [_sequence_record(201, 200, state="matched")]
        dead_sequence = [_sequence_record(None, None)]
        for name, probes in (("timed out", [DEAD, DEAD]), ("never sent", [])):
            with self.subTest(probes=name, sequence="answered"):
                result = document(probes, [dict(f) for f in self.SESSION_DOWN],
                                  sequences=answered_sequence)
                decision = gate.evaluate(result)
                self.assertEqual(decision.exit_code, 0, decision.messages)
                self.assertNotIn(gate.NOTHING_ANSWERED,
                                 [r["code"] for r in decision.reasons])
                self.assertFalse(any("established nothing" in m
                                     for m in decision.messages), decision.messages)
                # Not a silent pass: the unanswered probes are inconclusive,
                # disclosed as not enforced, and gate under --require-complete.
                self.assertIn("inconclusive",
                              [e["code"] for e in decision.not_enforced])
                strict = gate.evaluate(result, require_complete=True)
                self.assertEqual(strict.exit_code, 3)
                self.assertNotIn(gate.NOTHING_ANSWERED,
                                 [r["code"] for r in strict.reasons])
            with self.subTest(probes=name, sequence="unanswered"):
                result = document(probes, [dict(f) for f in self.SESSION_DOWN],
                                  sequences=dead_sequence)
                decision = gate.evaluate(result)
                self.assertEqual(decision.exit_code, 3)
                self.assertEqual([r["code"] for r in decision.reasons],
                                 [gate.NOTHING_ANSWERED])

    def test_control_an_answered_check_still_passes(self) -> None:
        self.assertEqual(gate.evaluate(document([ANSWERED], [])).exit_code, 0)

    def test_an_answered_setup_is_not_an_answer(self) -> None:
        """Only an assert step grades a declaration, so only it is an answer.

        A setup that came back 201 while the assert behind it drew a 503 has
        provisioned state and measured no boundary. Counting any answered step
        made such a run, with every check probe unanswered or with no checks at
        all, not vacuous: it exited 0 with an empty gate. Control: the same
        sequence with its assert answered is not vacuous.
        """
        setup_only = [_sequence_record(201, 503)]
        assert_answered = [_sequence_record(201, 403, state="matched")]
        for name, probes, checks in (("check probes timed out", [DEAD, DEAD], 1),
                                     ("check sessions down", [], 1),
                                     ("sequences only", [], 0)):
            with self.subTest(case=name, assert_step="503"):
                result = document(probes, [dict(f) for f in self.SESSION_DOWN],
                                  checks=checks, sequences=setup_only)
                decision = gate.evaluate(result)
                self.assertEqual(decision.exit_code, 3, decision.messages)
                self.assertEqual([r["code"] for r in decision.reasons],
                                 [gate.NOTHING_ANSWERED])
                self.assertTrue(gate._established_nothing(result))
            with self.subTest(case=name, assert_step="403"):
                result = document(probes, [dict(f) for f in self.SESSION_DOWN],
                                  checks=checks, sequences=assert_answered)
                decision = gate.evaluate(result)
                self.assertEqual(decision.exit_code, 0, decision.messages)
                self.assertFalse(gate._is_vacuous(result))

    def test_the_cli_exits_three_when_every_login_is_unavailable(self) -> None:
        """End to end through `veridor run`, with the opener standing in.

        Control: the same config with the login served and the check answered
        503 has always exited 3, so the harness can tell the gate firing from
        it not firing.
        """
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Target:
            def __init__(self, login_up: bool) -> None:
                self.login_up = login_up
                self.paths: list[str] = []

            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                path = request.full_url.split("127.0.0.1:9", 1)[1]
                self.paths.append(f"{request.get_method()} {path}")
                headers = email.message.Message()
                headers["Content-Length"] = "0"
                status = 503
                if path == "/login" and self.login_up:
                    status = 200
                    headers["Set-Cookie"] = "sid=s1; Path=/"
                return urllib.response.addinfourl(io.BytesIO(b""), headers,
                                                  request.full_url, status)

        def session(user: str) -> dict:
            return {"login": [{"method": "POST", "path": "/login", "body": f"u={user}",
                               "expect_status": [200]}],
                    "establishes": {"cookie": "sid"}}

        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
            "identities": {"owner": {"session": session("o")},
                           "attacker": {"session": session("a")}},
            "checks": [{"id": "doc", "request": {"method": "GET", "path": "/docs/1"},
                        "expect": {"owner": {"status": [200]},
                                   "attacker": {"status": [403]}}}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            for login_up, wire in ((False, ["POST /login"] * 2),
                                   (True, ["POST /login"] * 2 + ["GET /docs/1"] * 2)):
                target = Target(login_up)
                with self.subTest(login_up=login_up), mock.patch.object(
                    core, "_OPENER", target
                ):
                    history = root / f"h{int(login_up)}"
                    code, out, err = _run_cli(["run", "--config", str(path),
                                               "--output-dir", str(history)])
                    self.assertEqual(sorted(target.paths), sorted(wire))
                    self.assertEqual(code, 3, err)
                    self.assertIn("established nothing", err)
                    self.assertIn("not one of 2 probe(s) was answered", out)
                    latest = json.loads((history / "latest.json").read_text("utf-8"))
                    self.assertEqual([r["code"] for r in latest["gate"]["reasons"]],
                                     [gate.NOTHING_ANSWERED])

    def test_the_cli_does_not_call_an_answered_sequence_vacuous(self) -> None:
        """Check sessions down, a sequence on other identities answered.

        The reproduction: owner and attacker log in through a session that
        draws a 503, so their check sends no probe; svc reads /items/1 (200)
        and anon is refused it (401). That run measured a boundary. It exited
        3 with `nothing_answered` and told the operator to check whether the
        target was up. Control: with the sequence's requests answered 503 too,
        nothing was answered anywhere and the run still exits 3.
        """
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Target:
            def __init__(self, items_up: bool) -> None:
                self.items_up = items_up
                self.wire: list[tuple[str, int]] = []

            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                path = request.full_url.split("127.0.0.1:9", 1)[1]
                status = 503
                if path == "/items/1" and self.items_up:
                    status = 200 if request.get_header("Authorization") else 401
                self.wire.append((f"{request.get_method()} {path}", status))
                headers = email.message.Message()
                headers["Content-Length"] = "0"
                return urllib.response.addinfourl(io.BytesIO(b""), headers,
                                                  request.full_url, status)

        def session(user: str) -> dict:
            return {"login": [{"method": "POST", "path": "/login", "body": f"u={user}",
                               "expect_status": [200]}],
                    "establishes": {"cookie": "sid"}}

        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
            "identities": {"owner": {"session": session("o")},
                           "attacker": {"session": session("a")},
                           "svc": {"headers": {"Authorization": "Bearer svc-token"}},
                           "anon": {}},
            "checks": [{"id": "doc", "request": {"method": "GET", "path": "/docs/1"},
                        "expect": {"owner": {"status": [200]},
                                   "attacker": {"status": [403]}}}],
            "sequences": [{"id": "s", "steps": [
                {"role": "setup", "as": "svc",
                 "request": {"method": "GET", "path": "/items/1"},
                 "expect": {"status": [200]}},
                {"role": "assert", "as": "anon",
                 "request": {"method": "GET", "path": "/items/1"},
                 "expect": {"status": [401]}},
            ]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            for items_up, expected in ((True, 0), (False, 3)):
                target = Target(items_up)
                with self.subTest(items_up=items_up), mock.patch.object(
                    core, "_OPENER", target
                ):
                    history = root / f"h{int(items_up)}"
                    code, out, err = _run_cli(["run", "--config", str(path),
                                               "--output-dir", str(history)])
                    self.assertIn(("GET /items/1", 200 if items_up else 503),
                                  target.wire)
                    self.assertEqual(code, expected, err)
                    latest = json.loads((history / "latest.json").read_text("utf-8"))
                    # No check probe was sent: the sessions never came up. The
                    # one GET /docs/1 on the wire is the liveness control's
                    # fabricated credential, which is not a probe.
                    self.assertEqual(latest["probes"], [])
                    reasons = [r["code"] for r in latest["gate"]["reasons"]]
                    if items_up:
                        self.assertNotIn("established nothing", err)
                        self.assertNotIn("None of those was measured", out)
                        self.assertEqual(reasons, [])
                    else:
                        self.assertIn("established nothing", err)
                        self.assertEqual(reasons, [gate.NOTHING_ANSWERED])


    def test_the_cli_does_not_count_an_answered_setup(self) -> None:
        """The reproduction: the setup is served, the assert draws a 503.

        svc's setup GET /items/1 is answered 200 and anon's assert GET
        /items/2 is answered 503, with the check sessions down beside it and,
        separately, with no checks at all. Not one declaration was graded, so
        nothing was measured; both runs exited 0 with an empty gate because the
        setup's 200 counted as an answer. Control: the assert answered 401
        exits 0 with no reason in both shapes.
        """
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Target:
            def __init__(self, assert_up: bool) -> None:
                self.assert_up = assert_up
                self.wire: list[tuple[str, int]] = []

            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                path = request.full_url.split("127.0.0.1:9", 1)[1]
                status = 503
                if path == "/items/1":
                    status = 200
                if path == "/items/2" and self.assert_up:
                    status = 200 if request.get_header("Authorization") else 401
                self.wire.append((f"{request.get_method()} {path}", status))
                headers = email.message.Message()
                headers["Content-Length"] = "0"
                return urllib.response.addinfourl(io.BytesIO(b""), headers,
                                                  request.full_url, status)

        def session(user: str) -> dict:
            return {"login": [{"method": "POST", "path": "/login", "body": f"u={user}",
                               "expect_status": [200]}],
                    "establishes": {"cookie": "sid"}}

        checks = [{"id": "doc", "request": {"method": "GET", "path": "/docs/1"},
                   "expect": {"owner": {"status": [200]},
                              "attacker": {"status": [403]}}}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for shape in ("checks", "sequences only"):
                config = {
                    "version": 2,
                    "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
                    "identities": {"owner": {"session": session("o")},
                                   "attacker": {"session": session("a")},
                                   "svc": {"headers": {"Authorization": "Bearer svc-token"}},
                                   "anon": {}},
                    "checks": checks if shape == "checks" else [],
                    "sequences": [{"id": "s", "steps": [
                        {"role": "setup", "as": "svc",
                         "request": {"method": "GET", "path": "/items/1"},
                         "expect": {"status": [200]}},
                        {"role": "assert", "as": "anon",
                         "request": {"method": "GET", "path": "/items/2"},
                         "expect": {"status": [401]}},
                    ]}],
                }
                path = root / f"{shape.replace(' ', '-')}.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                for assert_up, expected in ((False, 3), (True, 0)):
                    target = Target(assert_up)
                    with self.subTest(shape=shape, assert_up=assert_up), \
                            mock.patch.object(core, "_OPENER", target):
                        history = root / f"h-{path.stem}-{int(assert_up)}"
                        code, out, err = _run_cli(["run", "--config", str(path),
                                                   "--output-dir", str(history)])
                        self.assertIn(("GET /items/1", 200), target.wire)
                        self.assertIn(("GET /items/2", 401 if assert_up else 503),
                                      target.wire)
                        self.assertEqual(code, expected, err)
                        latest = json.loads((history / "latest.json").read_text("utf-8"))
                        reasons = [r["code"] for r in latest["gate"]["reasons"]]
                        if assert_up:
                            self.assertEqual(reasons, [])
                            self.assertNotIn("established nothing", err)
                            continue
                        self.assertEqual(reasons, [gate.NOTHING_ANSWERED])
                        self.assertIn("established nothing", err)
                        if shape == "sequences only":
                            # Not "2 sequence step(s)": the setup WAS answered.
                            self.assertIn("not one of 1 assert step(s) was answered",
                                          out)
                            self.assertNotIn("sequence step(s) was answered", out)

@slow("stands up the demo API on loopback and runs the engine against it")
class LiveRecordedGateTest(unittest.TestCase):
    """Real runs: the number the process exits with is the number on disk."""

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.demo_server import create_server  # noqa: PLC0415

        cls.servers = {}
        cls.threads = []
        for vulnerable in (True, False):
            server = create_server("127.0.0.1", 0, vulnerable=vulnerable)
            thread = loopback.start(server)
            cls.servers[vulnerable] = server
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls) -> None:
        for server in cls.servers.values():
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=5)

    def test_vulnerable_clean_and_unreachable(self) -> None:
        config = ROOT / "fixtures" / "veridor.demo.json"
        dead = "http://127.0.0.1:9"  # discard port: nothing answers
        cases = (
            (f"http://127.0.0.1:{self.servers[True].server_port}", 1),
            (f"http://127.0.0.1:{self.servers[False].server_port}", 0),
            (dead, 3),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for base_url, expected in cases:
                with self.subTest(base_url=base_url):
                    history = root / f"h{expected}"
                    reports = {fmt: root / f"r{expected}.{fmt}" for fmt in
                               ("sarif", "junit", "gitlab-sast", "codequality", "markdown")}
                    argv = ["run", "--config", str(config), "--base-url", base_url,
                            "--output-dir", str(history)]
                    for fmt, path in reports.items():
                        argv += ["--report", f"{fmt}={path}"]
                    code, _, _ = _run_cli(argv)
                    self.assertEqual(code, expected)
                    latest = json.loads((history / "latest.json").read_text("utf-8"))
                    self.assertEqual(latest["gate"]["exit_code"], code)
                    # Written whatever the gate decided.
                    for path in reports.values():
                        self.assertTrue(path.is_file(), path)
                    self.assertIn(f"exit {code}", reports["markdown"].read_text("utf-8"))


class LivenessAdviceTest(unittest.TestCase):
    """The unproven-denial line tells each identity what would actually prove it.

    It said "Give the identity a marker_probe" for every unproven entry. An
    identity with ``"reestablish": "check"`` has its marker_probe counted for
    nothing (it runs under the first login, and every check logs in again),
    and one whose session cookie the target replaced was proven before the
    change: both already have the marker_probe the line told them to add.
    """

    PLAIN = {"check_id": "c1", "identity": "other", "statement": "s", "remediation": "r"}
    LOGIN = {**PLAIN, "identity": "relogger", "proof_scope": "login"}
    COOKIE = {**PLAIN, "identity": "rotated", "proof_scope": "cookie_value"}

    def _line(self, *entries) -> str:
        built = document([ANSWERED], [])
        built["liveness"]["unproven"] = [dict(entry) for entry in entries]
        messages = gate.evaluate(built, require_complete=True).messages
        lines = [line for line in messages if "satisfied by a denial" in line]
        self.assertEqual(len(lines), 1, messages)
        return lines[0]

    def test_control_a_plain_entry_keeps_the_marker_probe_advice(self) -> None:
        line = self._line(self.PLAIN)
        self.assertIn("Give the identity a marker_probe naming something it should "
                      "be served, or accept", line)
        self.assertNotIn("reestablish", line)

    def test_a_relogin_entry_is_not_told_to_add_a_marker_probe(self) -> None:
        line = self._line(self.LOGIN)
        self.assertNotIn("Give the identity a marker_probe", line)
        self.assertIn("For 'relogger'", line)
        self.assertIn('"reestablish": "run"', line)
        self.assertIn("proves only the first login", line)

    def test_a_replaced_cookie_entry_is_told_to_prove_the_new_value(self) -> None:
        line = self._line(self.COOKIE)
        self.assertNotIn("Give the identity a marker_probe", line)
        self.assertIn("For 'rotated'", line)
        self.assertIn("a 2xx sent with the new value", line)

    def test_a_mix_names_each_case(self) -> None:
        line = self._line(self.PLAIN, self.LOGIN, self.COOKIE)
        self.assertIn("Give the identity a marker_probe naming something it should "
                      "be served (for 'relogger'", line)
        self.assertIn("; for 'rotated'", line)

    def test_the_require_complete_docs_say_the_same(self) -> None:
        """README's two require_complete rows and action.yml's input."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        rows = [line for line in readme.splitlines()
                if line.startswith(("| `require_complete` |", "| `require-complete` |"))]
        action = " ".join((ROOT / "action.yml").read_text(encoding="utf-8").split())
        self.assertEqual(len(rows), 2)
        for text in (*rows, action):
            with self.subTest(text=text[:40]):
                self.assertNotRegex(text, r"Give that identity a `?marker_probe`?(\.| \|)")
                self.assertIn("proves only the first login", text)
                self.assertIn("a 2xx sent with the new value", text)
                self.assertIn("only under the same login and session cookie value", text)


if __name__ == "__main__":
    unittest.main()
