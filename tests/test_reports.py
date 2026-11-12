"""The report formats in `veridor.reports`, and the CLI that writes them.

Every assertion the tests of the standalone converters made is here, pointed
at the renderers that replaced them, plus the regression tests for what those
converters got wrong:

* a sequence finding was an `<error>` on a test case made up for it;
* an exit 3 that is not a finding (nothing answered, a vacuous expectation)
  rendered as a clean pass in JUnit and as `scan.status: success` in GitLab;
* no converter checked `schema_version`, and `{}` or a matrix document
  converted "successfully" into an empty, green report;
* an unanswered probe became a GitLab vulnerability of severity Unknown;
* a lone surrogate crashed two converters and made the third write XML no
  parser accepts;
* the GitLab scanner version was the literal "0.1.0".

GitLab's schema is not vendored and the suite takes no third-party
dependency, so the SAST checks below are structural: every constraint of the
15.2.5 schema a Veridor report can reach, restated, with a control that proves
the restated checks reject a broken report.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import re
import sys
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import veridor  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import cli, core, gate, reports  # noqa: E402
from veridor.blastradius import banned_words_in  # noqa: E402
from veridor.core import DECLARATION_SCOPE, PASS_SCOPE, ConfigError  # noqa: E402
from veridor.coverage import BANNED_CLAIM_WORDS  # noqa: E402
from veridor.reports import codequality, gitlab_sast, markdown  # noqa: E402

RUN_ID = "20260924T000000Z-abcdef"


def _finding(fid: str, **fields) -> dict:
    base = {
        "id": fid, "rule_id": "VERIDOR-AUTHZ-001", "level": "error",
        "verdict": "vulnerable", "evidence_grade": "suspected",
        "title": "Invoice tenant isolation", "check_id": "invoice-tenant-isolation",
        "check_name": "Invoice tenant isolation", "identity": "other_tenant",
        "location": "veridor.json", "location_line": 48,
        # The bracket is the point: it is what the run measured.
        "message": "received HTTP 200 (declared: one of [404]); marker crossed",
        "remediation": "Enforce tenant ownership on the invoice route.",
        "evidence": {"expected_statuses": [404], "actual_status": 200,
                     "request": {"method": "GET", "url": "http://127.0.0.1:9/api/invoices/inv-100"}},
    }
    base.update(fields)
    return base


def _run(findings=None, *, probes=None, **extra) -> dict:
    findings = [_finding("0ec4c5cbd79deaed6e9f")] if findings is None else findings
    probes = probes if probes is not None else [
        {"check_id": "invoice-tenant-isolation", "identity": "invoice_owner",
         "response": {"status": 200, "duration_ms": 12}, "error": None},
        {"check_id": "invoice-tenant-isolation", "identity": "other_tenant",
         "response": {"status": 200, "duration_ms": 9}, "error": None},
    ]
    document = {
        "schema_version": 2, "run_id": RUN_ID,
        "started_at": "2026-09-24T00:00:00.123456+00:00",
        "completed_at": "2026-09-24T00:00:02.500000+00:00",
        "target": "http://127.0.0.1:9", "config": "veridor.json",
        "status": "failed" if findings else "passed",
        "summary": {
            "checks": 1, "probes": len(probes),
            "safe": len(probes) - sum(1 for f in findings if "step_index" not in f),
            **{verdict: sum(f["verdict"] == verdict for f in findings)
               for verdict in ("vulnerable", "unexpected_denial", "inconclusive")},
            **{grade: sum(f.get("evidence_grade") == grade for f in findings)
               for grade in ("confirmed", "suspected", "ungraded")},
            "new": len(findings), "resolved": 0, "unchanged": 0, "escalated": 0,
        },
        "findings": findings,
        "liveness": {"enabled": True, "unproven": []},
        "regression": {"new": [f for f in findings], "unchanged": [], "resolved": []},
        "probes": probes,
    }
    document.update(extra)
    return document


def _with_gate(document: dict, **flags) -> dict:
    document = copy.deepcopy(document)
    document["gate"] = gate.evaluate(document, **flags).to_document()
    return core.validate_run(document)


def _sequence_run() -> dict:
    step_finding = _finding(
        "f" * 20, rule_id="VERIDOR-EFFECT-001", evidence_grade="confirmed",
        check_id="note-cross-tenant-delete", identity="invoice_owner", step_index=3,
        title="Write crossed a boundary", message="the owner's marker was gone",
    )
    del step_finding["check_name"]  # a sequence finding has none
    return _with_gate(_run(
        [step_finding],
        schema_version=3,
        sequences=[{
            "sequence_id": "note-cross-tenant-delete", "outcome": "completed",
            "aborted_at_step": None, "teardown_state": "clean",
            "steps": [
                {"index": 0, "as": "invoice_owner", "role": "setup", "state": "matched"},
                {"index": 1, "as": "invoice_owner", "role": "setup", "state": "matched"},
                {"index": 2, "as": "other_tenant", "role": "probe", "state": "matched"},
                {"index": 3, "as": "invoice_owner", "role": "assert", "state": "mismatched"},
            ],
        }],
    ))


def _vacuous_exit_three() -> dict:
    """The I-vacuous case: exit 3, no findings at all."""
    return _with_gate(_run(
        [], non_asserting_expectations=[{
            "check_id": "invoice-tenant-isolation", "identity": "other_tenant",
            "statuses": [200, 404], "classification": "permissive",
            "statement": "expectation for 'other_tenant' accepts both access and denial",
        }],
    ), require_complete=True)


def _vacuous_with_not_enforced() -> dict:
    """The same vacuous run without --require-complete: the reason is listed
    under ``not_enforced``, with the identities it names."""
    document = _vacuous_exit_three()
    del document["gate"]
    document = _with_gate(document)
    assert document["gate"]["not_enforced"], document["gate"]
    return document


def _teardown_reason(enforced: bool) -> dict:
    """A run whose gate carries a teardown_unclean reason naming a sequence,
    as ``gate.evaluate`` writes it -- enforced (--require-clean-teardown) or
    listed under not_enforced."""
    document = _with_gate(_run([]))
    detail = {"code": gate.TEARDOWN_UNCLEAN, "count": 1, "sequences": ["note-delete"]}
    if enforced:
        document["gate"].update(exit_code=3, reasons=[{**detail, "exit_code": 3}])
    else:
        document["gate"]["not_enforced"] = [
            {**detail, "exit_code": 0, "enforced_by": "--require-clean-teardown"}]
    return core.validate_run(document)


def _unreachable(fail_on: str = "new+confirmed") -> dict:
    probes = [{"check_id": "invoice-tenant-isolation", "identity": name,
               "response": {}, "error": "timed out"}
              for name in ("invoice_owner", "other_tenant")]
    findings = [
        _finding(str(index) * 20, rule_id="VERIDOR-EXEC-001", level="warning",
                 verdict="inconclusive", evidence_grade="n/a", identity=name,
                 title=f"Could not verify as {name}", message="Request failed: timed out")
        for index, name in enumerate(("invoice_owner", "other_tenant"), start=1)
    ]
    return _with_gate(_run(findings, probes=probes, status="inconclusive"), fail_on=fail_on)


def _junit(document: dict) -> ET.Element:
    return ET.fromstring(reports.render("junit", document).encode("utf-8"))


def _cases(root: ET.Element) -> dict[str, ET.Element]:
    return {case.get("name"): case for case in root.iter("testcase")}


def _capture(argv: list[str]) -> tuple[int, str, str]:
    """Exit code, stdout, stderr. An argparse refusal raises SystemExit(2)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# the input contract
# ---------------------------------------------------------------------------


class LoadRunContractTest(unittest.TestCase):
    """Renderers are fed only through core.load_run / core.validate_run."""

    def _write(self, directory: Path, value) -> Path:
        path = directory / "run.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_a_wrong_schema_version_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for version in (99, 0, "2", True):
                with self.subTest(version=version):
                    path = self._write(Path(directory), {**_run(), "schema_version": version})
                    with self.assertRaisesRegex(ConfigError, "unsupported run schema_version"):
                        reports.load_run(path)

    def test_json_that_is_not_a_run_is_refused(self) -> None:
        cases = {
            "empty object": ({}, "run must be a Veridor run JSON document"),
            "array": ([], "not a Veridor run JSON document"),
            "matrix": ({"kind": "veridor.matrix", "cells": [], "run_id": "x",
                        "findings": []}, "'veridor.matrix' document, not a Veridor run"),
            "drift": ({"kind": "veridor.matrix_drift", "changes": []},
                      "--from-drift"),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, (value, message) in cases.items():
                with self.subTest(case=name):
                    with self.assertRaisesRegex(ConfigError, re.escape(message)):
                        reports.load_run(self._write(Path(directory), value))

    def test_a_malformed_container_is_refused_not_crashed_on(self) -> None:
        """`evidence` as a string raised AttributeError in `report`: exit 1."""
        cases = {
            "evidence": {**_run(), "findings": [_finding("a", evidence="oops")]},
            "probes": {**_run(), "probes": "oops"},
            "probe entry": {**_run(), "probes": ["oops"]},
            "gate": {**_run(), "gate": []},
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ConfigError):
                    core.validate_run(value)

    def test_a_wrongly_shaped_nested_field_is_refused_naming_it(self) -> None:
        """validate_run checked the top-level containers only. Each field below
        crashed a renderer (AttributeError, TypeError or KeyError, so exit 70,
        "a bug in Veridor") when a hand-edited document gave it the wrong shape
        -- measured by mutating every nested field of these documents."""
        def na(doc):
            return doc["non_asserting_expectations"][0]

        cases = [
            ("probes[0].response", _with_gate(_run()),
             lambda d: d["probes"][0].update(response="200")),
            ("finding 0 evidence.request", _with_gate(_run()),
             lambda d: d["findings"][0]["evidence"].update(request="GET /x")),
            ("gate.reasons[0].finding_ids", _with_gate(_run()),
             lambda d: d["gate"]["reasons"][0].update(finding_ids=True)),
            ("gate.not_enforced[0].identities", _vacuous_with_not_enforced(),
             lambda d: d["gate"]["not_enforced"][0].update(identities=7)),
            # The third list a renderer joins (reason_sentence): validate_run
            # checked finding_ids and identities only, so these were exit 70
            # in markdown, junit, gitlab-sast and codequality (measured).
            ("gate.reasons[0].sequences", _teardown_reason(True),
             lambda d: d["gate"]["reasons"][0].update(sequences=5)),
            ("gate.not_enforced[0].sequences", _teardown_reason(False),
             lambda d: d["gate"]["not_enforced"][0].update(sequences=[1.5])),
            ("liveness.unproven", _with_gate(_run()),
             lambda d: d["liveness"].update(unproven=True)),
            ("regression.new", _with_gate(_run()),
             lambda d: d["regression"].update(new=1)),
            ("regression.unchanged", _with_gate(_run()),
             lambda d: d["regression"].update(unchanged=True)),
            ("regression.resolved", _with_gate(_run()),
             lambda d: d["regression"].update(resolved=0)),
            ("sequences[0].steps", _sequence_run(),
             lambda d: d["sequences"][0].update(steps=4)),
            ("non_asserting_expectations[0].check_id", _vacuous_exit_three(),
             lambda d: na(d).pop("check_id")),
            ("non_asserting_expectations[0].statement", _vacuous_exit_three(),
             lambda d: na(d).update(statement=None)),
        ]
        for field, document, mutate in cases:
            with self.subTest(field=field):
                # Control: the unmutated document renders in every format.
                for fmt in reports.FORMATS:
                    reports.render(fmt, core.validate_run(copy.deepcopy(document)))
                broken = copy.deepcopy(document)
                mutate(broken)
                with self.assertRaises(ConfigError) as raised:
                    core.validate_run(broken)
                self.assertIn(field, str(raised.exception))

    def test_report_exits_two_on_the_two_reported_shapes(self) -> None:
        """The two reproductions: both were exit 70."""
        for field, mutate in (
            ("probes[0].response", lambda d: d["probes"][0].update(response="x")),
            ("gate.reasons[0].finding_ids",
             lambda d: d["gate"]["reasons"][0].update(finding_ids=False)),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                document = _with_gate(_run())
                mutate(document)
                path = self._write(Path(directory), document)
                code, stdout, stderr = _capture(
                    ["report", "--from-run", str(path), "--format", "markdown"])
                self.assertEqual(code, 2, stderr)
                self.assertEqual(stdout, "")
                self.assertIn(field, stderr)
                self.assertNotIn("internal error", stderr)

    def test_a_gate_whose_code_disagrees_with_its_reasons_is_refused(self) -> None:
        document = _with_gate(_run())
        document["gate"]["exit_code"] = 0
        with self.assertRaisesRegex(ConfigError, "first reason says 1"):
            core.validate_run(document)

    def test_the_cli_exits_two_and_names_the_problem(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(Path(directory), {**_run(), "schema_version": 9})
            code, stdout, stderr = _capture(
                ["report", "--from-run", str(path), "--format", "junit"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("unsupported run schema_version: 9", stderr)
            self.assertIn("upgrade", stderr)


def _liveness_unproven_run() -> dict:
    """A run whose gate lists a reason carrying ``identities``."""
    document = _run()
    document["liveness"] = {"enabled": True, "unproven": [{
        "check_id": "invoice-tenant-isolation", "identity": "other_tenant",
        "statement": "held against a denial a fabricated credential got too",
        "remediation": "give other_tenant a marker_probe"}]}
    return _with_gate(document)


def _nested_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield prefix + (key,)
            yield from _nested_paths(item, prefix + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield prefix + (index,)
            yield from _nested_paths(item, prefix + (index,))


_DELETE = object()


@slow("renders every report format some 2,000 times over mutated run documents")
class NestedShapeSweepTest(unittest.TestCase):
    """Every field below the top level, in every wrong shape: refused (exit 2)
    or rendered, never a renderer crash (exit 70). Before validate_run checked
    nested fields, this sweep found 14 field paths that crashed."""

    def test_every_nested_field_in_a_wrong_shape_is_refused_or_rendered(self) -> None:
        documents = {
            "gated": _with_gate(_run()), "sequence": _sequence_run(),
            "unreachable": _unreachable(), "vacuous": _vacuous_exit_three(),
            "liveness": _liveness_unproven_run(),
            "pass disclosures": _pass_disclosure_run(),
        }
        crashes, refused, rendered = [], 0, 0
        for name, document in documents.items():
            for path in _nested_paths(document):
                if len(path) < 2:
                    continue  # the top level has its own tests
                for wrong in ("x", True, 7, [], {}, None, _DELETE):
                    mutated = copy.deepcopy(document)
                    parent = mutated
                    for step in path[:-1]:
                        parent = parent[step]
                    if wrong is _DELETE:
                        del parent[path[-1]]
                    else:
                        parent[path[-1]] = wrong
                    try:
                        checked = core.validate_run(mutated)
                    except ConfigError:
                        refused += 1
                        continue
                    for fmt in reports.FORMATS:
                        try:
                            reports.render(fmt, checked)
                            rendered += 1
                        except ConfigError:
                            refused += 1
                        except Exception as error:  # noqa: BLE001 - that is the finding
                            crashes.append((name, path, repr(wrong), fmt,
                                            type(error).__name__))
        self.assertEqual(crashes, [])
        # Control: the sweep drew both outcomes, so an empty list means something.
        self.assertGreater(refused, 0)
        self.assertGreater(rendered, 0)


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


class SarifTest(unittest.TestCase):
    def _sarif(self, document: dict | None = None) -> dict:
        return json.loads(reports.render("sarif", document or _run()))

    def test_the_version_is_the_package_version(self) -> None:
        """It was the literal "0.1.0"; a non-default value proves it is read."""
        with mock.patch.object(veridor, "__version__", "9.8.7"):
            driver = self._sarif()["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["semanticVersion"], "9.8.7")

    def test_every_rule_is_tagged_security(self) -> None:
        rules = _sequence_run_rules = self._sarif(_sequence_run())["runs"][0]["tool"]["driver"]["rules"]
        self.assertGreaterEqual(len(_sequence_run_rules), 5)
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                self.assertIn("security", rule["properties"]["tags"])

    def test_target_rules_carry_a_numeric_security_severity(self) -> None:
        rules = {r["id"]: r for r in
                 self._sarif(_sequence_run())["runs"][0]["tool"]["driver"]["rules"]}
        for rule_id in ("VERIDOR-AUTHZ-001", "VERIDOR-LEAK-001", "VERIDOR-EFFECT-001"):
            with self.subTest(rule=rule_id):
                value = rules[rule_id]["properties"]["security-severity"]
                self.assertIsInstance(value, str)
                self.assertRegex(value, r"^\d+\.\d$")
                self.assertTrue(0.0 < float(value) < 9.0)

    def test_a_rule_that_measured_nothing_gets_no_security_severity(self) -> None:
        rules = {r["id"]: r for r in
                 self._sarif(_unreachable())["runs"][0]["tool"]["driver"]["rules"]}
        for rule_id in ("VERIDOR-EXEC-001", "VERIDOR-ORACLE-001"):
            with self.subTest(rule=rule_id):
                self.assertNotIn("security-severity", rules[rule_id]["properties"])

    def test_the_category_is_stable_and_the_id_unique(self) -> None:
        run = self._sarif()["runs"][0]
        self.assertEqual(run["automationDetails"]["id"], f"veridor/{RUN_ID}")
        other = self._sarif({**_run(), "run_id": "20260925T000000Z-123456"})["runs"][0]
        category = run["automationDetails"]["id"].rsplit("/", 1)[0]
        self.assertEqual(category, other["automationDetails"]["id"].rsplit("/", 1)[0])
        self.assertNotEqual(run["automationDetails"]["id"], other["automationDetails"]["id"])

    def test_partial_fingerprints_are_unchanged(self) -> None:
        result = self._sarif()["runs"][0]["results"][0]
        self.assertEqual(result["partialFingerprints"],
                         {"veridorFindingId/v1": "0ec4c5cbd79deaed6e9f"})

    def test_it_is_byte_identical_to_run_sarif(self) -> None:
        document = _run()
        self.assertEqual(reports.render("sarif", document),
                         json.dumps(core.to_sarif(document), indent=2) + "\n")

    def test_the_docs_do_not_say_sarif_reads_the_gate(self) -> None:
        """`report --help` and docs/report-formats.md said EVERY format reads
        the recorded gate, "so a run that exited 3 ... never renders as a
        pass". SARIF does not: it is byte-identical to `run --sarif`, written
        before the gate is decided, and a run gated to 3 only by liveness or
        teardown renders zero results -- the same bytes as exit 0. The
        exception is now stated where the promise is made."""
        passed = _with_gate(_run([]))
        gated = copy.deepcopy(passed)
        gated["gate"].update(exit_code=3, reasons=[
            {"code": gate.LIVENESS_UNPROVEN, "exit_code": 3, "count": 1}])
        # The fact the prose has to describe.
        self.assertEqual(reports.render("sarif", passed), reports.render("sarif", gated))
        description = " ".join(
            cli._parser()._subparsers._group_actions[0]  # noqa: SLF001
            .choices["report"].description.split())
        intro = " ".join((ROOT / "docs" / "report-formats.md").read_text(
            encoding="utf-8").split("\n## ", 1)[0].split())
        # The README's report section made the same promise a third time
        # ("every format renders it") and the first version of this test did
        # not read it. Its paragraph opens with this sentence.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        opening = "Reports are written whatever the gate decides."
        self.assertIn(opening, readme)
        readme_passage = " ".join(
            readme.split(opening, 1)[1].split("\n\n", 1)[0].split())
        # The package docstring made it a fourth time ("Each format now reads
        # the run document's gate object") and was corrected with the README,
        # but nothing read it, so it could drift back unseen. It is for
        # maintainers, not operators, so it is not held to naming the exit
        # code; it has to name the exception and what SARIF renders instead.
        docstring = " ".join((reports.__doc__ or "").split())
        self.assertTrue(docstring)
        for name, prose in (("report --help", description), ("report-formats.md", intro),
                            ("README.md", readme_passage),
                            ("reports/__init__.py", docstring)):
            with self.subTest(where=name):
                self.assertNotIn("Every format reads", prose)
                self.assertNotIn("Each format now reads", prose)
                self.assertNotIn("every one of them reads", prose)
                self.assertNotIn("every format renders it", prose)
                self.assertIn("except SARIF", prose)
                if name == "reports/__init__.py":
                    self.assertIn("byte-identical to ``run --sarif``", prose)
                    self.assertIn("zero results", prose)
                else:
                    self.assertIn("exit code", prose)


# ---------------------------------------------------------------------------
# JUnit
# ---------------------------------------------------------------------------


class JUnitTest(unittest.TestCase):
    def test_one_case_per_probe_plus_the_gate(self) -> None:
        root = _junit(_with_gate(_run()))
        cases = _cases(root)
        self.assertEqual(len(cases), 2 + 1)
        self.assertIn("veridor.gate", cases)
        failed = [name for name, case in cases.items() if case.find("failure") is not None]
        self.assertEqual(sorted(failed),
                         ["invoice-tenant-isolation as other_tenant", "veridor.gate"])

    def test_counts_match_the_cases_written(self) -> None:
        for document in (_with_gate(_run()), _sequence_run(), _vacuous_exit_three(),
                         _unreachable(), _run()):
            root = _junit(document)
            cases = list(root.iter("testcase"))
            for element in (root, root.find("testsuite")):
                with self.subTest(element=element.tag, run=document.get("run_id")):
                    self.assertEqual(int(element.get("tests")), len(cases))
                    self.assertEqual(int(element.get("failures")),
                                     sum(c.find("failure") is not None for c in cases))
                    self.assertEqual(int(element.get("errors")),
                                     sum(c.find("error") is not None for c in cases))
                    self.assertEqual(element.get("skipped"), "0")
            for case in cases:
                outcome = [child.tag for child in case if child.tag in ("failure", "error", "skipped")]
                self.assertLessEqual(len(outcome), 1, case.get("name"))
                self.assertNotIn("skipped", outcome)

    def test_a_finding_message_with_xml_metacharacters_survives(self) -> None:
        document = _with_gate(_run([_finding("a", message="a <b> & c \"d\" 'e' [404]")]))
        failure = _junit(document).find(".//testcase/failure")
        self.assertIn("<b>", failure.text)
        self.assertIn("[404]", failure.text)

    def test_a_finding_with_no_matching_probe_is_never_dropped(self) -> None:
        """Losing a finding to a bookkeeping mismatch is the worst failure here."""
        document = _with_gate(_run([_finding("a", identity="nobody_probed_this")]))
        cases = _cases(_junit(document))
        orphan = [c for n, c in cases.items() if "no probe record" in n]
        self.assertEqual(len(orphan), 1)
        # By verdict now: a vulnerable orphan is a failure, not an error.
        self.assertIsNotNone(orphan[0].find("failure"))
        inconclusive = _with_gate(_run([_finding(
            "b", identity="nobody_probed_this", verdict="inconclusive",
            evidence_grade="n/a", rule_id="VERIDOR-EXEC-001")]))
        orphan = [c for n, c in _cases(_junit(inconclusive)).items() if "no probe record" in n]
        self.assertIsNotNone(orphan[0].find("error"))

    def test_a_sequence_finding_fails_its_own_step(self) -> None:
        """It was an <error> on a case made up for it: steps were not cases."""
        cases = _cases(_junit(_sequence_run()))
        step = cases["note-cross-tenant-delete step 3 (assert) as invoice_owner"]
        failure = step.find("failure")
        self.assertIsNotNone(failure)
        self.assertEqual(failure.get("type"), "VERIDOR-EFFECT-001")
        self.assertIn("the owner's marker was gone", failure.text)
        self.assertFalse([n for n in cases if "no probe record" in n])
        passed = cases["note-cross-tenant-delete step 0 (setup) as invoice_owner"]
        self.assertEqual([child.tag for child in passed], [])

    def test_a_step_that_never_ran_is_an_error_not_a_skip(self) -> None:
        document = _sequence_run()
        document["sequences"][0]["steps"][2]["state"] = "skipped"
        document["sequences"][0]["aborted_at_step"] = 1
        case = _cases(_junit(document))[
            "note-cross-tenant-delete step 2 (probe) as other_tenant"]
        self.assertIsNotNone(case.find("error"))
        self.assertIsNone(case.find("skipped"))

    def test_an_unanswered_probe_is_never_a_pass(self) -> None:
        cases = _cases(_junit(_unreachable()))
        for name in ("invoice-tenant-isolation as invoice_owner",
                     "invoice-tenant-isolation as other_tenant"):
            with self.subTest(case=name):
                self.assertIsNotNone(cases[name].find("error"))

    def test_a_non_finding_exit_three_fails_the_gate_case(self) -> None:
        """I-vacuous: exit 3, zero findings. It rendered 0 failures, 0 errors."""
        root = _junit(_vacuous_exit_three())
        gate_case = _cases(root)["veridor.gate"]
        failure = gate_case.find("failure")
        self.assertIsNotNone(failure)
        self.assertEqual(failure.get("type"), "exit-3")
        # The fixture declares exactly one non-asserting expectation.
        self.assertIn("1 expectation accepts both access and denial, so it asserts "
                      "nothing about the boundary", failure.get("message"))
        self.assertGreater(int(root.get("failures")), 0)

    def test_exit_three_is_not_flattened_into_exit_one(self) -> None:
        """Ported from the Azure completion table: 3 is its own outcome."""
        three = _cases(_junit(_unreachable()))["veridor.gate"].find("failure")
        one = _cases(_junit(_with_gate(_run())))["veridor.gate"].find("failure")
        self.assertEqual((three.get("type"), one.get("type")), ("exit-3", "exit-1"))

    def test_the_gate_case_passes_only_on_exit_zero_and_says_what_that_means(self) -> None:
        clean = _with_gate(_run([]))
        case = _cases(_junit(clean))["veridor.gate"]
        self.assertIsNone(case.find("failure"))
        self.assertIn(PASS_SCOPE, case.find("system-out").text)
        none_policy = _unreachable(fail_on="none")
        case = _cases(_junit(none_policy))["veridor.gate"]
        self.assertIsNone(case.find("failure"))
        self.assertIn("Not gated", case.find("system-out").text)

    def test_the_scope_travels_as_properties(self) -> None:
        properties = {p.get("name"): p.get("value")
                      for p in _junit(_with_gate(_run())).iter("property")}
        self.assertEqual(properties["veridor.scope"], DECLARATION_SCOPE)
        self.assertEqual(properties["veridor.pass_scope"], PASS_SCOPE)
        self.assertEqual(properties["veridor.gate.exit_code"], "1")
        self.assertEqual(properties["veridor.gate.recorded"], "true")

    def test_a_run_without_a_recorded_gate_says_so(self) -> None:
        properties = {p.get("name"): p.get("value") for p in _junit(_run()).iter("property")}
        self.assertEqual(properties["veridor.gate.recorded"], "false")

    def test_characters_xml_cannot_carry_do_not_break_the_file(self) -> None:
        for text in ("x\ud800y", "x\x01y", "x￿y"):
            with self.subTest(text=repr(text)):
                document = _with_gate(_run([_finding("a", message=text)]))
                rendered = reports.render("junit", document)
                ET.fromstring(rendered.encode("utf-8", "strict"))
                self.assertIn("x�y", rendered)

    def test_non_asserting_and_unproven_probes_say_so(self) -> None:
        document = _vacuous_exit_three()
        case = _cases(_junit(document))["invoice-tenant-isolation as other_tenant"]
        self.assertIn("Non-asserting", case.find("system-out").text)

    def test_an_unproven_sequence_step_reaches_its_step_testcase(self) -> None:
        """Unproven entries were attached per (check_id, identity) only.

        A sequence step's entry carries the sequence id in check_id and its
        step index, and sequence testcases are keyed by step, so nothing
        matched: the assert steps rendered as clean passes with no
        system-out, while the same denial declared as a check carried its
        note. It must not land on a check testcase of the same id either.
        """
        document = _sequence_run()
        document["liveness"] = {"enabled": True, "unproven": [{
            "check_id": "note-cross-tenant-delete", "sequence_id": "note-cross-tenant-delete",
            "step_index": 2, "identity": "other_tenant", "status": 401,
            "control": "withheld_sequence_step",
            "statement": "'other_tenant' received HTTP 401 on step 2 (DELETE)",
        }]}
        document["probes"] = list(document.get("probes") or ()) + [{
            "check_id": "note-cross-tenant-delete", "identity": "other_tenant",
            "response": {"status": 404}, "error": None,
        }]
        cases = _cases(_junit(document))
        step = cases["note-cross-tenant-delete step 2 (probe) as other_tenant"]
        self.assertIsNotNone(step.find("system-out"))
        self.assertIn("Unproven denial: 'other_tenant' received HTTP 401 on step 2",
                      step.find("system-out").text)
        self.assertIsNone(step.find("failure"))
        check = cases["note-cross-tenant-delete as other_tenant"]
        self.assertIsNone(check.find("system-out"))


# ---------------------------------------------------------------------------
# GitLab SAST
# ---------------------------------------------------------------------------

#: The constraints of sast-report-format.json (self.version 15.2.5) that a
#: Veridor report can reach, restated with the standard library.
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_SEVERITIES = {"Info", "Unknown", "Low", "Medium", "High", "Critical"}


def _sast_problems(report: dict) -> list[str]:
    problems = []
    for key in ("scan", "version", "vulnerabilities"):
        if key not in report:
            problems.append(f"missing {key}")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(report.get("version"))):
        problems.append("version pattern")
    scan = report.get("scan") or {}
    for key in ("analyzer", "end_time", "scanner", "start_time", "status", "type"):
        if key not in scan:
            problems.append(f"missing scan.{key}")
    for key in ("start_time", "end_time"):
        if not _TIME.match(str(scan.get(key))):
            problems.append(f"scan.{key} pattern")
    if scan.get("status") not in ("success", "failure"):
        problems.append("scan.status enum")
    if scan.get("type") != "sast":
        problems.append("scan.type enum")
    for part in ("analyzer", "scanner"):
        tool = scan.get(part) or {}
        for key in ("id", "name", "version"):
            if not isinstance(tool.get(key), str) or not tool.get(key):
                problems.append(f"scan.{part}.{key}")
        if not (tool.get("vendor") or {}).get("name"):
            problems.append(f"scan.{part}.vendor.name")
    for message in scan.get("messages", []):
        if message.get("level") not in ("info", "warn", "fatal") or not message.get("value"):
            problems.append("scan.messages entry")
    for index, vulnerability in enumerate(report.get("vulnerabilities") or []):
        for key in ("id", "identifiers", "location"):
            if key not in vulnerability:
                problems.append(f"vulnerabilities[{index}] missing {key}")
        if not vulnerability.get("id"):
            problems.append(f"vulnerabilities[{index}].id empty")
        if vulnerability.get("severity") not in _SEVERITIES:
            problems.append(f"vulnerabilities[{index}].severity enum")
        if len(vulnerability.get("name", "")) > 255:
            problems.append(f"vulnerabilities[{index}].name length")
        if len(vulnerability.get("solution", "")) > 7000:
            problems.append(f"vulnerabilities[{index}].solution length")
        identifiers = vulnerability.get("identifiers") or []
        if not identifiers:
            problems.append(f"vulnerabilities[{index}].identifiers empty")
        for identifier in identifiers:
            if not all(identifier.get(k) for k in ("type", "name", "value")):
                problems.append(f"vulnerabilities[{index}] identifier incomplete")
        for key, detail in (vulnerability.get("details") or {}).items():
            if not detail.get("name") or detail.get("type") != "text" or not isinstance(
                detail.get("value"), str
            ):
                problems.append(f"vulnerabilities[{index}].details.{key}")
    return problems


class GitLabSastTest(unittest.TestCase):
    def _report(self, document: dict) -> dict:
        return json.loads(reports.render("gitlab-sast", document))

    def test_the_structural_check_can_fail(self) -> None:
        """Control: the restated schema rejects a report broken three ways."""
        broken = self._report(_with_gate(_run()))
        broken["scan"]["start_time"] = "2026-09-24T00:00:00+00:00"
        broken["vulnerabilities"][0]["severity"] = "Bogus"
        broken["vulnerabilities"][0]["identifiers"] = []
        self.assertEqual(len(_sast_problems(broken)), 3, _sast_problems(broken))

    def test_every_report_carries_what_the_schema_requires(self) -> None:
        for document in (_with_gate(_run()), _sequence_run(), _vacuous_exit_three(),
                         _unreachable(), _unreachable("none"), _run()):
            with self.subTest(run=document.get("run_id"), gate=document.get("gate")):
                self.assertEqual(_sast_problems(self._report(document)), [])

    def test_the_schema_version_and_scanner(self) -> None:
        with mock.patch.object(veridor, "__version__", "9.8.7"):
            report = self._report(_with_gate(_run()))
        self.assertEqual(report["version"], gitlab_sast.SCHEMA_VERSION)
        self.assertEqual(gitlab_sast.SCHEMA_VERSION, "15.2.5")
        for part in ("analyzer", "scanner"):
            self.assertEqual(report["scan"][part]["id"], "veridor")
            self.assertEqual(report["scan"][part]["version"], "9.8.7")
        self.assertEqual(report["scan"]["type"], "sast")
        self.assertEqual(report["scan"]["start_time"], "2026-09-24T00:00:00")
        self.assertEqual(report["scan"]["end_time"], "2026-09-24T00:00:02")

    def test_ids_are_stable_uuids_derived_from_the_fingerprint(self) -> None:
        """GitLab dedupes on id; a fresh id every run is a fresh alert every run."""
        first = self._report(_with_gate(_run()))["vulnerabilities"][0]["id"]
        again = self._report(copy.deepcopy(_with_gate(_run())))["vulnerabilities"][0]["id"]
        self.assertEqual(first, again)
        uuid.UUID(first)
        other = self._report(_with_gate(_run([_finding("1" * 20)])))["vulnerabilities"][0]["id"]
        self.assertNotEqual(first, other)
        # Independent of the run: a later run of the same finding, same id.
        later = self._report(_with_gate({**_run(), "run_id": "20260925T000000Z-999999"}))
        self.assertEqual(later["vulnerabilities"][0]["id"], first)

    def test_the_finding_id_namespace_did_not_move(self) -> None:
        """REGRESSION. The test above compares ids within one process, so a
        domain rename by search and replace changed every id GitLab dedupes on
        with the whole suite green (measured). The literals here are the
        contract: change them only to re-identify every finding on purpose."""
        from veridor.reports._common import FINDING_ID_NAMESPACE, stable_uuid  # noqa: PLC0415

        self.assertEqual(str(FINDING_ID_NAMESPACE), "5ec096cf-02ff-5d16-a95c-17c40bf2257a")
        self.assertEqual(stable_uuid("fingerprint-a"), "fe8aa596-effa-5b5a-94d4-32b6945444b0")

    def test_a_sequence_finding_is_a_vulnerability(self) -> None:
        (vulnerability,) = self._report(_sequence_run())["vulnerabilities"]
        self.assertEqual(vulnerability["severity"], "High")
        self.assertIn({"type": "veridor_check", "name": "note-cross-tenant-delete",
                       "value": "note-cross-tenant-delete/invoice_owner/step-3"},
                      vulnerability["identifiers"])

    def test_an_unanswered_probe_is_not_a_vulnerability(self) -> None:
        report = self._report(_unreachable())
        self.assertEqual(report["vulnerabilities"], [])
        self.assertEqual(report["scan"]["status"], "failure")
        values = " ".join(m["value"] for m in report["scan"]["messages"])
        self.assertIn("not one probe was answered", values)

    def test_nothing_answered_fails_the_scan_even_under_report_only(self) -> None:
        self.assertEqual(self._report(_unreachable("none"))["scan"]["status"], "failure")

    def test_a_non_finding_exit_fails_the_scan_with_messages(self) -> None:
        report = self._report(_vacuous_exit_three())
        self.assertEqual(report["scan"]["status"], "failure")
        warnings = [m for m in report["scan"]["messages"] if m["level"] == "warn"]
        self.assertTrue(any("exit 3" in m["value"] for m in warnings), warnings)

    def test_a_finding_alone_is_a_successful_scan(self) -> None:
        self.assertEqual(self._report(_with_gate(_run()))["scan"]["status"], "success")

    def test_severity_mapping(self) -> None:
        denial = _with_gate(_run([_finding("d", verdict="unexpected_denial",
                                           evidence_grade="n/a")]))
        self.assertEqual(self._report(denial)["vulnerabilities"][0]["severity"], "Info")
        for grade in ("confirmed", "suspected", "ungraded"):
            with self.subTest(grade=grade):
                document = _with_gate(_run([_finding("v", evidence_grade=grade)]))
                self.assertEqual(self._report(document)["vulnerabilities"][0]["severity"],
                                 "High")

    def test_the_location_is_the_config_line_relative_to_the_root(self) -> None:
        document = _with_gate(_run([_finding("a", location="/work/repo/veridor.json")]))
        report = json.loads(reports.render("gitlab-sast", document, root=Path("/work/repo")))
        location = report["vulnerabilities"][0]["location"]
        self.assertEqual(location, {"file": "veridor.json", "start_line": 48, "end_line": 48})
        outside = json.loads(reports.render("gitlab-sast", document, root=Path("/elsewhere")))
        self.assertEqual(outside["vulnerabilities"][0]["location"]["file"],
                         "/work/repo/veridor.json")

    def test_a_lone_surrogate_does_not_crash_it(self) -> None:
        document = _with_gate(_run([_finding("a", message="x\ud800y")]))
        rendered = reports.render("gitlab-sast", document)
        rendered.encode("utf-8", "strict")
        self.assertIn("x�y", rendered)


# ---------------------------------------------------------------------------
# Code Quality
# ---------------------------------------------------------------------------


class CodeQualityTest(unittest.TestCase):
    def _issues(self, document: dict) -> list[dict]:
        return json.loads(reports.render("codequality", document))

    def test_every_issue_has_what_gitlab_reads(self) -> None:
        for document in (_with_gate(_run()), _sequence_run(), _vacuous_exit_three(),
                         _unreachable()):
            issues = self._issues(document)
            self.assertIsInstance(issues, list)
            self.assertTrue(issues)
            fingerprints = [issue["fingerprint"] for issue in issues]
            self.assertEqual(len(fingerprints), len(set(fingerprints)))
            for issue in issues:
                with self.subTest(issue=issue["check_name"]):
                    for key in ("description", "check_name", "fingerprint"):
                        self.assertIsInstance(issue[key], str)
                        self.assertTrue(issue[key])
                    self.assertIn(issue["severity"], codequality.SEVERITIES)
                    self.assertIsInstance(issue["location"]["path"], str)
                    begin = issue["location"]["lines"]["begin"]
                    self.assertIsInstance(begin, int)
                    self.assertGreaterEqual(begin, 1)

    def test_fingerprints_are_stable_across_runs(self) -> None:
        first = self._issues(_with_gate(_run()))
        later = self._issues(_with_gate({**_run(), "run_id": "20260925T000000Z-999999"}))
        self.assertEqual([i["fingerprint"] for i in first], [i["fingerprint"] for i in later])

    def test_a_non_finding_exit_is_an_issue(self) -> None:
        issues = self._issues(_vacuous_exit_three())
        gate_issue = [i for i in issues if i["check_name"] == "veridor.gate"]
        self.assertEqual(len(gate_issue), 1)
        self.assertEqual(gate_issue[0]["severity"], "major")
        self.assertIn("exit 3", gate_issue[0]["description"])
        vacuous = [i for i in issues if i["check_name"] == "VERIDOR-VACUOUS-001"]
        self.assertEqual(len(vacuous), 1)

    def test_severity_by_verdict(self) -> None:
        cases = {("vulnerable", "confirmed"): "critical", ("vulnerable", "suspected"): "major",
                 ("unexpected_denial", "n/a"): "minor", ("inconclusive", "n/a"): "info"}
        for (verdict, grade), expected in cases.items():
            with self.subTest(verdict=verdict, grade=grade):
                document = _with_gate(_run([_finding("a", verdict=verdict,
                                                     evidence_grade=grade)]))
                (issue,) = [i for i in self._issues(document) if i["check_name"] != "veridor.gate"]
                self.assertEqual(issue["severity"], expected)


# ---------------------------------------------------------------------------
# Pass disclosures, in every format
# ---------------------------------------------------------------------------

#: One dropped field per kind of request `inject` reaches, each a token no
#: other part of the document carries, so a count of it is a count of that
#: disclosure.
_INJECTION_FIELDS = {"check": "csrf_check_token", "sequence_step": "csrf_step_token",
                     "teardown": "csrf_teardown_token", "marker_probe": "csrf_marker_token"}


def _injection_disclosures() -> list[dict]:
    """The entries core writes, from core's own builder, so the statements
    are the ones a run carries."""
    return core._injection_disclosures(
        [{"check_id": "invoice-tenant-isolation", "identity": "other_tenant",
          "injection_not_applied": [_INJECTION_FIELDS["check"]]}],
        [{"sequence_id": "note-cross-tenant-delete",
          "steps": [{"index": 2, "as": "other_tenant",
                     "injection_not_applied": [_INJECTION_FIELDS["sequence_step"]]}],
          "teardown": [{"index": 0, "as": "invoice_owner",
                        "injection_not_applied": [_INJECTION_FIELDS["teardown"]]}]}],
        [{"identity": "invoice_owner",
          "injection_not_applied": [_INJECTION_FIELDS["marker_probe"]]}],
    )


_ORACLE_URL = "http://127.0.0.1:9/api/me/oracle-probe"


def _pass_disclosure_run(findings=None) -> dict:
    """A run that passed (or failed on ``findings``) over every kind of pass
    disclosure the console prints: an injection drop on each kind of request,
    an exclusion licensed by a marker_probe, and a fabricated credential the
    target served."""
    disclosures = _injection_disclosures()
    assert sorted(entry["source"] for entry in disclosures) == sorted(_INJECTION_FIELDS), disclosures
    return _with_gate(_run(
        [] if findings is None else findings,
        schema_version=3,
        sequences=[{
            "sequence_id": "note-cross-tenant-delete", "outcome": "completed",
            "aborted_at_step": None, "teardown_state": "clean",
            "steps": [
                {"index": 0, "as": "invoice_owner", "role": "setup", "state": "matched"},
                {"index": 1, "as": "invoice_owner", "role": "setup", "state": "matched"},
                {"index": 2, "as": "other_tenant", "role": "probe", "state": "matched"},
            ],
        }],
        injection_disclosures=disclosures,
        oracle_disclosures=[
            {"check_id": "invoice-tenant-isolation", "identity": "other_tenant",
             "owner_identity": "invoice_owner", "control_source": "identity_probe",
             "control_state": "present", "control_url": _ORACLE_URL,
             "request_path": "/api/invoices/inv-100",
             "statement": f"licensed by a marker_probe live at {_ORACLE_URL}"},
            {"check_id": "invoice-tenant-isolation", "identity": "fabricated credential",
             "control_source": "fabricated_credential", "request_method": "GET",
             "request_path": "/api/invoices/inv-100", "status": 200,
             "statement": "the target answered HTTP 200 carrying sham-credential-statement"},
        ],
    ))


#: A token from each pass disclosure in `_pass_disclosure_run`.
_PASS_DISCLOSURE_TOKENS = (*_INJECTION_FIELDS.values(), "oracle-probe", "sham-credential-statement")


class PassDisclosureTest(unittest.TestCase):
    """The console, the web UI and SARIF qualify a pass with every disclosure
    the run carries. JUnit read only non-asserting expectations and unproven
    denials, Code Quality only non-asserting expectations, and Markdown and
    GitLab SAST none: a GET probe that went out without its CSRF field and
    matched its declared denial was an unqualified pass in all four, which
    are the formats a merge request widget shows."""

    def test_every_format_carries_every_pass_disclosure(self) -> None:
        document = _pass_disclosure_run()
        self.assertEqual(document["gate"]["exit_code"], 0)
        for fmt in reports.FORMATS:
            text = reports.render(fmt, document)
            for token in _PASS_DISCLOSURE_TOKENS:
                with self.subTest(fmt=fmt, token=token):
                    # Markdown escapes the underscores; it renders as the token.
                    self.assertIn(markdown.cell(token) if fmt == "markdown" else token, text)
        # Control: the same run without the disclosures carries none of them.
        bare = {key: value for key, value in document.items()
                if key not in ("injection_disclosures", "oracle_disclosures")}
        for fmt in reports.FORMATS:
            text = reports.render(fmt, bare)
            self.assertEqual([token for token in _PASS_DISCLOSURE_TOKENS
                              if token in text or markdown.cell(token) in text], [], fmt)

    def test_junit_puts_each_on_the_case_it_qualifies(self) -> None:
        cases = _cases(_junit(_pass_disclosure_run()))

        def out(name: str) -> str:
            element = cases[name].find("system-out")
            return "" if element is None else element.text

        probe = out("invoice-tenant-isolation as other_tenant")
        self.assertIn("Injection not applied: ", probe)
        self.assertIn(_INJECTION_FIELDS["check"], probe)
        self.assertIn(_ORACLE_URL, probe)
        step = out("note-cross-tenant-delete step 2 (probe) as other_tenant")
        self.assertIn(_INJECTION_FIELDS["sequence_step"], step)
        gate_case = out("veridor.gate")
        for source in ("teardown", "marker_probe"):
            self.assertIn(_INJECTION_FIELDS[source], gate_case)
        self.assertIn("sham-credential-statement", gate_case)
        # Each lands once, and not on a case it does not qualify.
        whole = reports.render("junit", _pass_disclosure_run())
        for token in _PASS_DISCLOSURE_TOKENS:
            self.assertEqual(whole.count(token), 1, token)
        self.assertEqual(out("invoice-tenant-isolation as invoice_owner"), "")
        self.assertEqual(out("note-cross-tenant-delete step 0 (setup) as invoice_owner"), "")

    def test_junit_keeps_them_when_the_gate_fails(self) -> None:
        cases = _cases(_junit(_pass_disclosure_run([_finding("a", identity="invoice_owner")])))
        failure = cases["veridor.gate"].find("failure")
        self.assertIsNotNone(failure)
        self.assertIn(_INJECTION_FIELDS["teardown"], failure.text)
        # A step case that did not pass keeps its note, after its outcome.
        document = copy.deepcopy(_pass_disclosure_run())
        document["sequences"][0]["steps"][2]["state"] = "mismatched"
        case = _cases(_junit(core.validate_run(document)))[
            "note-cross-tenant-delete step 2 (probe) as other_tenant"]
        self.assertEqual([child.tag for child in case], ["error", "system-out"])
        self.assertIn(_INJECTION_FIELDS["sequence_step"], case.find("system-out").text)

    def test_code_quality_has_an_info_issue_for_each(self) -> None:
        issues = json.loads(reports.render("codequality", _pass_disclosure_run()))
        injected = [i for i in issues if i["check_name"] == "veridor.injection_not_applied"]
        self.assertEqual(len(injected), len(_INJECTION_FIELDS))
        for token in _INJECTION_FIELDS.values():
            self.assertEqual(sum(token in i["description"] for i in injected), 1, token)
        self.assertEqual({i["severity"] for i in injected}, {"info"})
        for name, token in (("veridor.unproven_oracle", _ORACLE_URL),
                            ("veridor.fabricated_credential_served", "sham-credential-statement")):
            (issue,) = [i for i in issues if i["check_name"] == name]
            self.assertIn(token, issue["description"])
        fingerprints = [i["fingerprint"] for i in issues]
        self.assertEqual(len(fingerprints), len(set(fingerprints)))
        later = json.loads(reports.render(
            "codequality", {**_pass_disclosure_run(), "run_id": "20260925T000000Z-999999"}))
        self.assertEqual(fingerprints, [i["fingerprint"] for i in later])

    def test_gitlab_sast_lists_each_as_a_scan_message(self) -> None:
        report = json.loads(reports.render("gitlab-sast", _pass_disclosure_run()))
        self.assertEqual(_sast_problems(report), [])
        self.assertEqual(report["scan"]["status"], "success")
        self.assertEqual(report["vulnerabilities"], [])
        info = [m["value"] for m in report["scan"]["messages"] if m["level"] == "info"]
        for token in _PASS_DISCLOSURE_TOKENS:
            self.assertEqual(sum(token in value for value in info), 1, token)

    def test_markdown_lists_them_under_the_verdict_escaped(self) -> None:
        document = _pass_disclosure_run()
        text = reports.render("markdown", document)
        self.assertIn("**Gate passed (exit 0).**", text)
        self.assertIn("#### What the matched probes do not establish", text)
        self.assertLess(text.index("What the matched probes do not establish"), text.index("#### Findings"))
        crafted = copy.deepcopy(document)
        crafted["injection_disclosures"][0]["statement"] = "x <img src=x onerror=alert(1)> [y](https://e.example)"
        text = reports.render("markdown", core.validate_run(crafted))
        self.assertNotIn("<img", text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", text)
        self.assertNotIn("[y](", text)

    def test_the_report_formats_page_says_every_format_carries_them(self) -> None:
        # test_docs.InjectionNotApplicableDocumentationTest reads the README.
        formats = " ".join((ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8").split())
        self.assertIn("Every format also carries the pass disclosures the console prints", formats)
        self.assertIn("each pass disclosure is an `info` issue", formats)


# ---------------------------------------------------------------------------
# Gate reasons, as each format words them
# ---------------------------------------------------------------------------

#: A count glued in front of a clause that already has its own subject. A run
#: against an unreachable target rendered "6 not one probe was answered, so the
#: run established nothing about the target" in all four formats below.
CLAUSE_GLUE = re.compile(
    r"(?<![\w.-])\d+ (?:not|no|none|nothing|never|the|a|an|was|were|is|are|so|but"
    r"|and|or|if|this|that|it|they|there)\b"
)
#: A plural hedge. A sentence that knows its count can agree with it.
HEDGE = re.compile(r"\w\((?:s|es|ies)\)")

REASON_FORMATS = ("markdown", "junit", "gitlab-sast", "codequality")
REASON_COUNTS = (1, 2, 6)
_REASON_EXIT = {gate.FINDINGS: 1, gate.COVERAGE_NOT_MEASURED: 2}


def _reason_entry(code: str, count: int | None, *, enforced: bool) -> dict:
    entry: dict = {"code": code, "exit_code": _REASON_EXIT.get(code, 3) if enforced else 0}
    if count is not None:
        entry["count"] = count
    if code in (gate.IDENTITY_UNAUTHENTICATED, gate.LIVENESS_UNPROVEN):
        entry["identities"] = [f"identity_{index}" for index in range(count or 1)]
    if code == gate.TEARDOWN_UNCLEAN:
        entry["sequences"] = [f"sequence_{index}" for index in range(count or 1)]
    if code == gate.FINDINGS:
        entry["finding_ids"] = ["0ec4c5cbd79deaed6e9f"][: count or 1]
        entry["by_grade"] = {"suspected": count or 1}
    if not enforced:
        entry["enforced_by"] = "--require-complete"
    return entry


def _reason_document(entry: dict, *, enforced: bool) -> dict:
    document = copy.deepcopy(_run())
    document["gate"] = {
        "fail_on": "new+confirmed", "require_complete": False,
        "require_clean_teardown": False,
        "exit_code": entry["exit_code"] if enforced else 0,
        "reasons": [entry] if enforced else [],
        "not_enforced": [] if enforced else [entry],
    }
    return core.validate_run(document)


def _strings(fmt: str, text: str) -> list[str]:
    """Every human-readable string in a rendered report."""
    if fmt == "markdown":
        return [text]
    if fmt == "junit":
        root = ET.fromstring(text.encode("utf-8"))
        return [value for element in root.iter()
                for value in [element.text or "", *element.attrib.values()]]
    found: list[str] = []

    def walk(value) -> None:
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)

    walk(json.loads(text))
    return found


def _renders_the_reason(fmt: str, code: str, *, enforced: bool) -> bool:
    """Code Quality lists findings as issues of their own, and a gate issue only
    for a non-finding reason that gates, or for a run that answered nothing."""
    if fmt != "codequality":
        return True
    return (enforced and code != gate.FINDINGS) or (not enforced and code == gate.NOTHING_ANSWERED)


def _reason_cases():
    for code in gate.REASON_CODES:
        counts = (None,) if code == gate.COVERAGE_NOT_MEASURED else REASON_COUNTS
        for count in counts:
            for enforced in (True, False):
                entry = _reason_entry(code, count, enforced=enforced)
                yield code, count, enforced, entry, _reason_document(entry, enforced=enforced)


def _reason_problems(fmt: str, entry: dict, document: dict, *, enforced: bool) -> list[str]:
    """What is wrong with how ``fmt`` words ``entry``; empty when nothing is."""
    from veridor.reports._common import reason_sentence

    problems: list[str] = []
    sentence = reason_sentence(entry)
    # Markdown escapes what it prints; the words are the same.
    printed = markdown.cell(sentence) if fmt == "markdown" else sentence
    strings = _strings(fmt, reports.render(fmt, document))
    for string in strings:
        problems += [f"count glued to a clause: {m.group(0)!r} in {string[:160]!r}"
                     for m in CLAUSE_GLUE.finditer(string)]
    if HEDGE.search(sentence):
        problems.append(f"plural hedge in {sentence!r}")
    if fmt == "markdown":
        verdict = next(s for s in strings[0].splitlines() if s.startswith("**Gate"))
        if HEDGE.search(verdict):
            problems.append(f"plural hedge in the verdict line {verdict!r}")
    count = entry.get("count")
    if isinstance(count, int) and not re.search(rf"(?<!\d){count}(?!\d)", sentence):
        problems.append(f"count {count} missing from {sentence!r}")
    if _renders_the_reason(fmt, entry["code"], enforced=enforced) and not any(
        printed in string for string in strings
    ):
        problems.append(f"{fmt} does not contain {printed!r}")
    return problems


class GateReasonWordingTest(unittest.TestCase):
    """Every reason code, at counts 1, 2 and 6, enforced and not, in every
    format that prints gate reasons."""

    def test_every_reason_reads_as_a_sentence_in_every_format(self) -> None:
        checked = 0
        for code, count, enforced, entry, document in _reason_cases():
            for fmt in REASON_FORMATS:
                with self.subTest(code=code, count=count, enforced=enforced, fmt=fmt):
                    self.assertEqual(_reason_problems(fmt, entry, document, enforced=enforced), [])
                    checked += 1
        # 7 counted codes x 3 counts + 1 countless code, x 2, x 4 formats.
        self.assertEqual(checked, (7 * 3 + 1) * 2 * 4)

    def test_singular_and_plural_differ_and_agree(self) -> None:
        from veridor.reports._common import reason_sentence

        for code in gate.REASON_CODES:
            if code == gate.COVERAGE_NOT_MEASURED:
                continue
            with self.subTest(code=code):
                one = reason_sentence(_reason_entry(code, 1, enforced=True))
                two = reason_sentence(_reason_entry(code, 2, enforced=True))
                self.assertIn("1", one)
                self.assertIn("2", two)
                if code != gate.NOTHING_ANSWERED:
                    self.assertNotEqual(one.replace("1", "N"), two.replace("2", "N"))

    def test_a_finding_the_policy_did_not_select_is_not_called_selected(self) -> None:
        """`--fail-on confirmed` leaves a suspected finding ungated. Every
        format said it was "selected by the --fail-on policy" beside "--fail-on
        any would gate on it"."""
        document = _with_gate(_run(), fail_on="confirmed")
        (quiet,) = document["gate"]["not_enforced"]
        self.assertEqual(quiet["code"], gate.FINDINGS)
        for fmt in REASON_FORMATS:
            with self.subTest(fmt=fmt):
                self.assertNotIn("selected by", reports.render(fmt, document))

    def test_an_unknown_reason_code_keeps_its_count_apart(self) -> None:
        """A document from a newer Veridor can carry a code this one does not
        know. Its count is shown, and not glued to the code."""
        from veridor.reports._common import reason_sentence

        sentence = reason_sentence({"code": "some_new_reason", "exit_code": 3, "count": 4})
        self.assertIn("some_new_reason", sentence)
        self.assertIn("4", sentence)
        self.assertNotRegex(sentence, r"^4 ")


class GateReasonWordingControlTest(unittest.TestCase):
    """The checks above catch the wording that shipped."""

    def test_the_detectors_flag_the_shipped_sentences(self) -> None:
        self.assertRegex("6 not one probe was answered, so the run established nothing", CLAUSE_GLUE)
        self.assertRegex("2 identity(ies) never authenticated", HEDGE)
        self.assertRegex("1 finding(s) about the target", HEDGE)
        for fine in ("Veridor gate exit 3 under --fail-on any.", "6 findings about the target",
                     "(6 unanswered)", "0 confirmed, 0 suspected", "version 0.1.0 is"):
            with self.subTest(fine=fine):
                self.assertNotRegex(fine, CLAUSE_GLUE)

    def test_the_old_renderer_fails_in_every_format(self) -> None:
        def glued(reason) -> str:
            text = gate.REASON_TEXT.get(str(reason.get("code")), str(reason.get("code")))
            count = reason.get("count")
            return f"{count} {text}" if isinstance(count, int) else text[:1].upper() + text[1:]

        from veridor.reports import _common, junit

        entry = _reason_entry(gate.NOTHING_ANSWERED, 6, enforced=True)
        document = _reason_document(entry, enforced=True)
        modules = (_common, markdown, junit, gitlab_sast, codequality)
        patches = [mock.patch.object(module, "reason_sentence", glued) for module in modules]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        for fmt in REASON_FORMATS:
            with self.subTest(fmt=fmt):
                problems = _reason_problems(fmt, entry, document, enforced=True)
                self.assertTrue(any("6 not one" in problem for problem in problems), problems)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _markdown_documents() -> dict[str, dict]:
    """One document per branch of the renderer."""
    coverage = copy.deepcopy(_run([]))
    coverage["gate"] = gate.evaluate(coverage, coverage_status=2).to_document()
    unauthenticated = _with_gate(_run([_finding(
        "u", verdict="inconclusive", evidence_grade="n/a", identity="bob",
        evidence={"session": {"state": "failed", "transient": False}})]))
    return {
        "exit 0": _with_gate(_run([])),
        "exit 1": _with_gate(_run()),
        "exit 2": core.validate_run(coverage),
        "exit 3 vacuous": _vacuous_exit_three(),
        "exit 3 unreachable": _unreachable(),
        "exit 3 identity": unauthenticated,
        "report only": _unreachable("none"),
        "sequence": _sequence_run(),
        "no gate recorded": _run(),
        "pass disclosures": _pass_disclosure_run(),
    }


class MarkdownTest(unittest.TestCase):
    def test_the_verdict_line_is_the_gate(self) -> None:
        for name, document in _markdown_documents().items():
            with self.subTest(case=name):
                text = reports.render("markdown", document)
                verdict = next(line for line in text.splitlines() if line.startswith("**Gate"))
                recorded = reports._common.gate_of(document)
                code = recorded["exit_code"]
                self.assertIn(f"exit {code}", verdict)
                unmeasured = any(r["code"] == gate.NOTHING_ANSWERED
                                 for r in recorded["not_enforced"])
                if code == 0 and not unmeasured:
                    self.assertIn("passed", verdict)
                else:
                    self.assertNotIn("passed", verdict)

    def test_report_only_over_a_run_that_measured_nothing_is_not_a_pass(self) -> None:
        text = reports.render("markdown", _unreachable("none"))
        self.assertIn("**Gate exit 0, and nothing was measured.**", text)
        self.assertIn("This is not a pass.", text)

    def test_exit_three_reads_as_incomplete_never_as_a_pass(self) -> None:
        text = reports.render("markdown", _unreachable())
        self.assertIn("**Gate incomplete (exit 3):**", text)
        self.assertIn("This is not a pass.", text)

    def test_the_scope_sentences_are_the_consoles(self) -> None:
        for name, document in _markdown_documents().items():
            with self.subTest(case=name):
                text = reports.render("markdown", document)
                self.assertIn(f"Scope: {DECLARATION_SCOPE}", text)
                self.assertIn(f"Pass: {PASS_SCOPE}", text)

    def test_no_banned_claim_word_in_any_branch(self) -> None:
        for name, document in _markdown_documents().items():
            text = reports.render("markdown", document).lower()
            for word in BANNED_CLAIM_WORDS:
                with self.subTest(case=name, word=word):
                    self.assertNotIn(word, text)

    def test_the_banned_word_check_can_fail(self) -> None:
        """Control: the same check fires on a finding message that says it."""
        document = _with_gate(_run([_finding("a", message="now secure")]))
        text = reports.render("markdown", document).lower()
        self.assertTrue(any(word in text for word in BANNED_CLAIM_WORDS))

    def test_counts_and_reasons_are_there(self) -> None:
        text = reports.render("markdown", _unreachable())
        self.assertIn("| Probes | Matched their declaration |", text)
        self.assertIn("`nothing_answered` (exit 3)", text)
        report_only = reports.render("markdown", _unreachable("none"))
        self.assertIn("not gated under this policy", report_only)
        self.assertIn("would gate on it", report_only)

    def test_a_derived_gate_is_labelled(self) -> None:
        self.assertIn("records no gate decision", reports.render("markdown", _run()))
        self.assertNotIn("records no gate decision",
                         reports.render("markdown", _with_gate(_run())))

    def test_a_cell_cannot_break_the_table_or_inject_markup(self) -> None:
        """Ported: a newline never escapes the row; the brackets stay readable."""
        message = "first | second\nthird <img src=x> [404] `code`"
        text = reports.render("markdown", _with_gate(_run([_finding("a", message=message)])))
        row = next(line for line in text.splitlines() if "first" in line)
        # Eight cells: nine unescaped pipes, so ten pieces including the ends.
        self.assertEqual(len(re.split(r"(?<!\\)\|", row)), 10, row)
        self.assertNotIn("<img", text)
        self.assertIn("&lt;img src=x&gt;", row)
        self.assertIn("\\[404\\]", row)
        self.assertNotIn("\n", row)

    def test_it_stays_under_the_limit_and_says_what_it_cut(self) -> None:
        # Each message is 600 characters and about 2,200 bytes once rendered:
        # `<` and `>` escape to four bytes each and the euro sign is three in
        # UTF-8. So 600 findings cross the real 1 MiB limit, where it took
        # 4,000 plain ASCII ones, most of them built and rendered only to be
        # cut; and a limit counted in characters, or before escaping, overruns
        # here where it did not with ASCII.
        count = 600
        findings = [_finding(f"{index:020d}", message="<€>" * 200) for index in range(count)]
        document = _with_gate(_run(findings))
        text = reports.render("markdown", document)
        size = len(text.encode("utf-8"))
        self.assertLessEqual(size, markdown.MAX_BYTES)
        self.assertGreater(size, markdown.MAX_BYTES - 4096)
        self.assertGreater(size - len(text), 4096,
                           "a limit counted in characters would no longer overrun this")
        shown = sum(1 for line in text.splitlines() if line.startswith("| vulnerable"))
        self.assertIn(f"_{count - shown} more finding(s) not shown", text)
        self.assertIn(f"Scope: {DECLARATION_SCOPE}", text)

    def test_a_small_run_is_not_truncated(self) -> None:
        self.assertNotIn("not shown", reports.render("markdown", _with_gate(_run())))


class DriftMarkdownTest(unittest.TestCase):
    def _drift(self) -> dict:
        from veridor import drift  # noqa: PLC0415

        cell = {"operation": "GET /api/invoices/{id}", "identity": "other_tenant",
                "specimen": "inv-100"}
        baseline = {"kind": drift.MATRIX_KIND, "target": {"base_url": "http://a"},
                    "cells": [
                        {**cell, "reach": "refused", "status": 404, "marker_scan": "absent"},
                        {"operation": "GET /api/me", "identity": "other_tenant",
                         "reach": "reached", "status": 200},
                        {"operation": "DELETE /api/x", "identity": "admin",
                         "reach": "unknown", "unknown_reason": "rate_limited"}]}
        current = {"kind": drift.MATRIX_KIND, "target": {"base_url": "http://a"},
                   "cells": [
                       {**cell, "reach": "reached", "status": 200, "marker_scan": "present",
                        "marker_owner": "invoice_owner"},
                       {"operation": "GET /api/me", "identity": "other_tenant",
                        "reach": "refused", "status": 403},
                       {"operation": "DELETE /api/x", "identity": "admin",
                        "reach": "refused", "status": 403}]}
        return drift.compare(baseline, current)

    def test_it_renders_every_change_and_says_it_is_not_a_finding(self) -> None:
        document = self._drift()
        self.assertTrue(document["changes"])
        text = reports.render_drift(document)
        self.assertIn("A change is an observation, not a finding", text)
        for change in document["changes"]:
            self.assertIn(change["kind"], text)

    def test_a_comparison_that_measured_nothing_says_so(self) -> None:
        """The summary a CI job shows for an all-unmeasured baseline. It listed
        the changes (all `measurement_gained`) and never said the gate could not
        have fired; for a grid nobody measured it said "Nothing moved"."""
        from veridor import drift  # noqa: PLC0415

        cell = {"operation": "GET /a", "identity": "other_tenant", "reach": "unknown",
                "unknown_reason": "transport_error"}
        blind = {"kind": drift.MATRIX_KIND, "target": {"base_url": "http://a"},
                 "cells": [cell]}
        served = {"kind": drift.MATRIX_KIND, "target": {"base_url": "http://a"},
                  "cells": [{**cell, "reach": "reached", "status": 200,
                             "unknown_reason": None}]}
        skipped = {**blind, "cells": [{**cell, "unknown_reason": "skipped_mutating"}]}
        # Recorded while every request was redirected: answered, never followed.
        redirected = {**blind, "cells": [{**cell, "reach": "indeterminate", "status": 302,
                                          "unknown_reason": None}]}
        for label, document in (("blind baseline", drift.compare(blind, served)),
                                ("nothing probed", drift.compare(skipped, skipped)),
                                ("redirect baseline", drift.compare(redirected, served))):
            with self.subTest(label):
                text = reports.render_drift(document)
                self.assertIn("Not one cell was measured in both runs", text)
                self.assertNotIn("Nothing moved", text)
        self.assertIn("answered with a redirect",
                      reports.render_drift(drift.compare(redirected, served)))
        # Control: a comparison that measured something does not say it.
        self.assertNotIn("Not one cell was measured in both runs",
                         reports.render_drift(self._drift()))

    def test_no_banned_word_from_either_list(self) -> None:
        """Whole words, the way blastradius polices candidates: "Veridor"
        contains "idor", so a substring check would flag the product's name."""
        text = reports.render_drift(self._drift())
        self.assertEqual(banned_words_in(text), ())
        # Control: the matcher does fire on the drift module's own claim text,
        # which is why the renderer does not quote it.
        from veridor import drift  # noqa: PLC0415

        self.assertIn("broken", banned_words_in(drift.CLAIM["does_not_measure"]))

    def test_the_cli_refuses_to_render_drift_as_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "drift.json"
            path.write_text(json.dumps(self._drift()), encoding="utf-8")
            for fmt in ("sarif", "junit", "gitlab-sast", "codequality"):
                with self.subTest(fmt=fmt):
                    code, _, stderr = _capture(
                        ["report", "--from-drift", str(path), "--format", fmt])
                    self.assertEqual(code, 2)
                    self.assertIn("markdown only", stderr)
            code, stdout, _ = _capture(
                ["report", "--from-drift", str(path), "--format", "markdown"])
            self.assertEqual(code, 0)
            self.assertIn("## Veridor access-matrix drift", stdout)

    #: A drift count a hand-edited or supplied document turned into markup.
    _CRAFTED = "1** <img src=x onerror=alert(1)> [click](https://evil.example) **"
    #: Every count the Markdown drift report prints, as a path into the document.
    _COUNTS = (("redirect_now_served_cells",), ("redirect_cells",), ("blind_cells",),
               ("comparable_cells",), ("incomparable_cells",), ("unmeasured_cells",),
               ("measured_in_both_cells",), ("baseline", "cells"), ("current", "cells"),
               ("counts", "reach_opened"))

    def _crafted(self, path: tuple[str, ...], value) -> dict:
        document = copy.deepcopy(self._drift())
        parent = document
        for step in path[:-1]:
            parent = parent[step]
        parent[path[-1]] = value
        return document

    def test_a_count_that_is_not_an_integer_is_refused(self) -> None:
        # load_drift checked kind, schema_version and the containers, not the
        # counts, so a string in redirect_now_served_cells was pasted into the
        # bold headline: raw HTML and a link under "N that mean more access".
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "drift.json"
            for path in self._COUNTS:
                for value in (self._CRAFTED, "3", True, -1, 2.5, None, [3]):
                    with self.subTest(path=path, value=value):
                        target.write_text(json.dumps(self._crafted(path, value)), encoding="utf-8")
                        with self.assertRaisesRegex(ConfigError, re.escape(".".join(path))):
                            reports.load_drift(target)
            target.write_text(json.dumps(self._crafted(("redirect_now_served_cells",), self._CRAFTED)),
                              encoding="utf-8")
            code, stdout, stderr = _capture(["report", "--from-drift", str(target), "--format", "markdown"])
            self.assertEqual(code, 2, stdout)
            self.assertNotIn("<img", stdout + stderr)
            # Control: the shipped shape, and one written before the field existed, load.
            target.write_text(json.dumps(self._crafted(("redirect_now_served_cells",), 3)), encoding="utf-8")
            loaded = reports.load_drift(target)
            text = reports.render_drift(loaded)
            self.assertIn(f"**{len(loaded['changes'])} change(s), 2 that mean more access than the "
                          "baseline, 3 baseline redirect(s) now served", text)
            self.assertIn("3 cell(s) answered with a redirect in the baseline are served now", text)
            older = self._drift()
            del older["redirect_now_served_cells"], older["measured_in_both_cells"]
            target.write_text(json.dumps(older), encoding="utf-8")
            reports.load_drift(target)

    def test_the_report_formats_page_says_a_count_is_refused(self) -> None:
        text = " ".join((ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8").split())
        self.assertIn("So is a drift document whose counts", text)
        self.assertIn("are not non-negative integers", text)

    def test_a_count_that_is_not_an_integer_is_escaped_if_rendered(self) -> None:
        # render_drift is public; a caller that skips load_drift still gets
        # no markup from a count.
        for path in ((("redirect_now_served_cells",), ("blind_cells",), ("baseline", "cells"),
                      ("current", "cells"), ("comparable_cells",), ("incomparable_cells",),
                      ("counts", "reach_opened"))):
            with self.subTest(path=path):
                text = reports.render_drift(self._crafted(path, self._CRAFTED))
                self.assertNotIn("<img", text)
                self.assertNotIn("[click](", text)
                self.assertIn("&lt;img src=x", text)

    def test_a_run_is_not_a_drift_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            path.write_text(json.dumps(_run()), encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "not a Veridor drift report"):
                reports.load_drift(path)


# ---------------------------------------------------------------------------
# the CLI
# ---------------------------------------------------------------------------


class ReportCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.run_json = self.root / "run.json"
        self.run_json.write_text(json.dumps(_with_gate(_run())), encoding="utf-8")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_every_format_to_stdout(self) -> None:
        for fmt in reports.FORMATS:
            for extra in ([], ["--output", "-"]):
                with self.subTest(fmt=fmt, extra=extra):
                    code, stdout, stderr = _capture(
                        ["report", "--from-run", str(self.run_json), "--format", fmt, *extra])
                    self.assertEqual((code, stderr), (0, ""))
                    self.assertEqual(stdout, reports.render(
                        fmt, reports.load_run(self.run_json), root=Path.cwd()))
        self.assertFalse((Path.cwd() / "-").exists())

    def test_to_a_file(self) -> None:
        target = self.root / "out" / "veridor-junit.xml"
        code, stdout, _ = _capture(["report", "--from-run", str(self.run_json),
                                    "--format", "junit", "--output", str(target)])
        self.assertEqual(code, 0)
        self.assertIn(f"Wrote JUnit report to {target}", stdout)
        ET.fromstring(target.read_bytes())

    def test_the_old_spelling_still_works(self) -> None:
        sarif = self.root / "report.sarif"
        code, stdout, _ = _capture(["report", "--input", str(self.run_json),
                                    "--sarif", str(sarif)])
        self.assertEqual(code, 0)
        self.assertIn("Wrote SARIF report", stdout)
        self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")

    def test_refusals_exit_two_and_say_why(self) -> None:
        cases = [
            (["--from-run", str(self.run_json)], "needs --format"),
            (["--format", "junit"], "exactly one input"),
            (["--from-run", str(self.run_json), "--from-drift", str(self.run_json),
              "--format", "markdown"], "exactly one input"),
            (["--from-run", str(self.run_json), "--sarif", "x.sarif", "--format", "sarif"],
             "older spelling"),
            (["--from-run", str(self.run_json), "--format", "junit",
              "--output", str(self.run_json)], "must not overwrite the input run"),
        ]
        for extra, message in cases:
            with self.subTest(extra=extra):
                code, _, stderr = _capture(["report", *extra])
                self.assertEqual(code, 2)
                self.assertIn(message, stderr)


    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes through 0555")
    def test_an_unwritable_output_names_the_output_path(self) -> None:
        """REGRESSION. Into a read-only directory, `report --output ro/j.xml`
        printed ``[Errno 13] Permission denied: 'ro/.j.xml.42f6df0f81e22ee1.tmp'``:
        the temporary sibling write_text creates first, never the path the
        operator typed."""
        locked = self.root / "ro"
        locked.mkdir()
        locked.chmod(0o555)
        # Not addCleanup: tearDown removes the tree first, and TemporaryDirectory
        # already restores permissions on the way out.
        for target, where in ((locked / "j.xml", "writing into its parent directory"),
                              (locked / "new" / "j.xml", "creating its parent directory")):
            with self.subTest(target=target):
                code, _, stderr = _capture(["report", "--from-run", str(self.run_json),
                                            "--format", "junit", "--output", str(target)])
                self.assertEqual(code, 2, stderr)
                self.assertIn(f"could not write the JUnit report to {target}", stderr)
                self.assertIn("Permission denied", stderr)
                self.assertIn(where, stderr)
                self.assertNotIn(".tmp", stderr)
                self.assertNotIn("[Errno", stderr)
                self.assertFalse(target.exists())
        # Control: the same command into a writable directory writes the file.
        locked.chmod(0o755)
        code, stdout, stderr = _capture(["report", "--from-run", str(self.run_json),
                                         "--format", "junit", "--output",
                                         str(locked / "j.xml")])
        self.assertEqual(code, 0, stderr)
        self.assertIn("Wrote JUnit report", stdout)

    def test_a_failed_write_after_a_run_names_the_report_path(self) -> None:
        """`run --report` reached the same raw OSError when a write failed after
        the preflight (a full disk), temporary file name included."""
        target = self.root / "r.xml"
        temporary = self.root / ".r.xml.0123456789abcdef.tmp"
        full = OSError(28, "No space left on device", str(temporary))
        message = cli._write_failure("the junit report", target, full)
        self.assertIn(f"could not write the junit report to {target}", message)
        self.assertIn("No space left on device", message)
        self.assertNotIn(temporary.name, message)
        self.assertNotIn("uid:gid", message, "not a permission problem")


class RunReportFlagTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.config = self.root / "veridor.json"
        self.config.write_text("{}", encoding="utf-8")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def _run(self, document: dict, *extra: str) -> tuple[int, str, str]:
        with mock.patch.object(cli, "execute_run",
                               lambda *a, **k: copy.deepcopy(document)):
            return _capture(["run", "--config", str(self.config), "--output-dir",
                             str(self.root / "h"), *extra])

    def test_reports_are_written_when_the_gate_fails(self) -> None:
        for document, expected in ((_run(), 1), (_unreachable(), 3), (_run([]), 0)):
            document = {k: v for k, v in document.items() if k != "gate"}
            paths = {fmt: self.root / f"{expected}.{fmt}" for fmt in reports.FORMATS}
            argv = [arg for fmt, path in paths.items()
                    for arg in ("--report", f"{fmt}={path}")]
            argv += ["--json", str(self.root / f"{expected}.json")]
            with self.subTest(expected=expected):
                code, stdout, _ = self._run(document, *argv)
                self.assertEqual(code, expected)
                for fmt, path in paths.items():
                    self.assertTrue(path.is_file(), fmt)
                    self.assertIn(f"Wrote {fmt} report to {path}", stdout)
                # The same bytes `report --from-run` produces from the saved run.
                saved = self.root / f"{expected}.json"
                for fmt, path in paths.items():
                    code, rendered, _ = _capture(
                        ["report", "--from-run", str(saved), "--format", fmt])
                    self.assertEqual(rendered, path.read_text(encoding="utf-8"), fmt)
                self.assertIn(f"exit {expected}", paths["markdown"].read_text())

    def test_stdout_is_refused_for_run(self) -> None:
        code, _, stderr = self._run(_run(), "--report", "junit=-")
        self.assertEqual(code, 2)
        self.assertIn("--report", stderr)
        self.assertIn("--output -", stderr)

    def test_an_unknown_format_is_refused(self) -> None:
        code, _, stderr = self._run(_run(), "--report", "sast=x.json")
        self.assertEqual(code, 2)
        self.assertIn("unknown report format 'sast'", stderr)

    def test_report_paths_get_the_output_path_protections(self) -> None:
        cases = [
            (["--report", f"junit={self.config}"],
             "must not overwrite a configuration, baseline, or specification"),
            (["--report", f"junit={self.root / 'h' / 'latest.json'}"],
             "conflicts with managed run history"),
            (["--report", f"junit={self.root / 'x'}", "--json", str(self.root / "x")],
             "must use different paths"),
            (["--report", f"junit={self.root / 'y'}", "--report", f"markdown={self.root / 'y'}"],
             "must use different paths"),
        ]
        for extra, message in cases:
            with self.subTest(extra=extra):
                code, _, stderr = self._run(_run(), *extra)
                self.assertEqual(code, 2)
                self.assertIn(message, stderr)
        self.assertFalse((self.root / "h").exists(), "validated before the run")

    def test_an_unwritable_report_path_is_refused_before_the_run(self) -> None:
        """This used to be reached only after the run: the probes went out, the
        report failed, and the exit was 2 (or 1 on a failing gate). The write
        preflight now refuses before execute_run is called at all, naming the
        path, because a result that cannot be written should not be measured."""
        blocker = self.root / "file"
        blocker.write_text("", encoding="utf-8")
        target = blocker / "sub" / "r.xml"  # a directory under a regular file
        calls: list[int] = []

        def execute(*args, **kwargs):
            calls.append(1)
            return copy.deepcopy(_run())

        with mock.patch.object(cli, "execute_run", execute):
            code, _, stderr = _capture(["run", "--config", str(self.config), "--output-dir",
                                        str(self.root / "h"), "--report", f"junit={target}"])
        self.assertEqual(code, 2)
        self.assertEqual(calls, [], "the run went ahead with an unwritable report path")
        self.assertIn(f"--report junit={target}", stderr)
        self.assertIn("Nothing has been sent", stderr)
        # Control: the same run with a writable path does call execute_run.
        with mock.patch.object(cli, "execute_run", execute):
            code, _, _ = _capture(["run", "--config", str(self.config), "--output-dir",
                                   str(self.root / "h"), "--report",
                                   f"junit={self.root / 'ok.xml'}"])
        self.assertEqual((code, calls), (1, [1]))

    def test_a_report_that_fails_after_the_run_is_still_loud(self) -> None:
        """The preflight proves a directory accepts a file; the write itself can
        still fail afterwards (a full disk). That path stays loud."""
        full = OSError(28, "No space left on device")
        target = self.root / "r.xml"
        with mock.patch.object(cli.reports, "write_text", side_effect=full):
            code, _, stderr = self._run(_run([]), "--report", f"junit={target}")
        self.assertEqual(code, 2)
        self.assertIn("could not write the junit report", stderr)
        # ...but a failing gate keeps its more specific code.
        with mock.patch.object(cli.reports, "write_text", side_effect=full):
            code, _, _ = self._run(_run(), "--report", f"junit={target}")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
