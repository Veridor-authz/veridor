from __future__ import annotations

import contextlib
import inspect
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor.cli import _emit_github_annotations, _gate_exit_code, _parser, main
from veridor.terminal import ECHO_LIMIT
from veridor import cli, core  # noqa: E402
from veridor.core import (
    DECLARATION_SCOPE,
    PASS_SCOPE,
    ConfigError,
    load_config,
    validate_marker,
)

DEAD_TARGET = "http://127.0.0.1:1"


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _config(root: Path, *, base_url: str = DEAD_TARGET) -> Path:
    return _write(
        root / "veridor.json",
        {
            "version": 1,
            "target": {"base_url": base_url, "timeout_seconds": 1},
            "identities": {"owner": {"headers": {}}, "other": {"headers": {}}},
            "checks": [
                {
                    "id": "widget-isolation",
                    "request": {"method": "GET", "path": "/widgets/w1"},
                    "expect": {
                        "owner": {"status": [200]},
                        "other": {"status": [403]},
                    },
                }
            ],
        },
    )


def _spec(root: Path, *paths: str, name: str = "openapi.json") -> Path:
    return _write(
        root / name,
        {
            "openapi": "3.0.3",
            "info": {"title": "Fixture", "version": "1"},
            "paths": {
                path: {"get": {"responses": {"200": {"description": "ok"}}}}
                for path in paths
            },
        },
    )


def _run(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _result(*grades: str, new: int = 0, verdict: str = "vulnerable") -> dict:
    """A run document with `len(grades)` findings.

    Every finding carries a verdict, because every real one does. The gate now
    distinguishes findings about the TARGET from `inconclusive` -- Veridor
    saying it could not measure -- and a fixture without the key would test a
    document Veridor never writes.
    """
    findings = [
        {"id": str(index), "evidence_grade": grade, "verdict": verdict}
        for index, grade in enumerate(grades)
    ]
    return {"findings": findings, "regression": {"new": findings[:new]}}


class CommandTest(unittest.TestCase):
    def test_verify_is_a_run_alias(self) -> None:
        args = _parser().parse_args(["verify", "--config", "veridor.json"])
        self.assertEqual(args.command, "verify")

    def test_report_converts_persisted_run_to_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run.json"
            sarif = root / "report.sarif"
            run.write_text(
                json.dumps({"run_id": "run-1", "findings": []}),
                encoding="utf-8",
            )
            # Captured, not leaked. `report` prints the path it wrote, and an
            # uncaptured `main()` put that absolute temp path on stdout AFTER
            # unittest's own `OK` line -- in the output of the one command the
            # README asks contributors to run on every commit.
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["report", "--input", str(run), "--sarif", str(sarif)])
            self.assertEqual(exit_code, 0)
            self.assertIn("Wrote SARIF report", stdout.getvalue())
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")

    def test_rejects_output_that_overwrites_managed_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            config.write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--config",
                        str(config),
                        "--output-dir",
                        str(root),
                        "--sarif",
                        str(root / "latest.json"),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("conflicts with managed run history", stderr.getvalue())


class AnnotationTest(unittest.TestCase):
    def test_escapes_github_workflow_commands(self) -> None:
        result = {
            "findings": [
                {
                    "level": "error",
                    "message": "bad%value\r\nnext",
                    "title": "tenant: owner,other",
                    "location": "config,name.json",
                }
            ]
        }
        stderr = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with contextlib.redirect_stderr(stderr):
                _emit_github_annotations(result)
        annotation = stderr.getvalue()
        self.assertIn("bad%25value%0D%0Anext", annotation)
        self.assertIn("title=tenant%3A owner%2Cother", annotation)
        self.assertIn("file=config%2Cname.json", annotation)


class BaselineTamperTest(unittest.TestCase):
    """`--fail-on new` is a set difference against a file in the diff.

    The README asks you to commit `baseline.json`. Finding ids are
    deterministic and stable across runs -- that is what makes the diff useful,
    and it is the whole problem. Adding an id to that file in a pull request
    moves a live `confirmed` cross-tenant leak from `new` to `unchanged`, and
    `--fail-on new` sees nothing. Measured on the demo target: exit 1 becomes
    exit 0, with "1 vulnerable" still printed above it.

    No baseline validation fixes this. A tampered baseline and a triaged one
    are the same bytes. So the gate stopped depending on the file.
    """

    def _result(self, *, grade: str = "confirmed") -> dict:
        finding = {
            "id": "abc123", "verdict": "vulnerable", "evidence_grade": grade,
            "check_id": "iso", "identity": "attacker",
            "message": "the response carried the owner's marker",
        }
        return {
            "findings": [finding],
            # The baseline already contains it, so it is `unchanged`, and
            # `new` is empty. This is exactly the post-tamper state.
            "regression": {"new": [], "resolved": [], "unchanged": [finding],
                           "escalated": []},
        }

    def test_new_alone_is_defeated_by_the_baseline(self) -> None:
        """Kept as a test, not fixed: `new` still means what it says."""
        self.assertEqual(_gate_exit_code("new", self._result()), 0)

    def test_the_default_is_not_defeated(self) -> None:
        self.assertEqual(_gate_exit_code("new+confirmed", self._result()), 1)

    def test_the_default_is_the_parser_default(self) -> None:
        """A safe policy nobody selects is not a fix."""
        args = _parser().parse_args(["run", "--config", "c.json"])
        self.assertEqual(args.fail_on, "new+confirmed")

    def test_the_default_still_fires_on_a_novel_unproven_finding(self) -> None:
        """The union must not have lost the `new` half."""
        finding = {"id": "z", "verdict": "vulnerable", "evidence_grade": "suspected"}
        result = {"findings": [finding],
                  "regression": {"new": [finding], "resolved": [], "unchanged": [],
                                 "escalated": []}}
        self.assertEqual(_gate_exit_code("new+confirmed", result), 1)

    def test_a_suppressed_but_unproven_finding_does_not_gate(self) -> None:
        """`suspected` in the baseline stays accepted: triage still works."""
        self.assertEqual(
            _gate_exit_code("new+confirmed", self._result(grade="suspected")), 0
        )

    def test_a_clean_run_is_still_clean(self) -> None:
        clean = {"findings": [], "regression": {"new": [], "resolved": [],
                                                "unchanged": [], "escalated": []}}
        for policy in ("new", "new+confirmed", "confirmed", "any"):
            with self.subTest(policy=policy):
                self.assertEqual(_gate_exit_code(policy, clean), 0)

    def test_the_summary_names_what_the_baseline_absorbs(self) -> None:
        """"0 new, 1 unchanged" reads as resolved to anybody skimming."""
        out = io.StringIO()
        result = {
            **self._result(), "summary": {"probes": 2, "safe": 1, "new": 0, "resolved": 0,
                                          "unchanged": 1, "matched": 1,
                                          "vulnerable": 1, "unexpected_denial": 0,
                                          "inconclusive": 0, "confirmed": 1,
                                          "suspected": 0, "ungraded": 0,
                                          "escalated": 0},
            "run_id": "r", "target": "http://127.0.0.1:1", "probes": [
                {"response": {"status": 200}}],
        }
        with contextlib.redirect_stdout(out):
            cli._print_summary(result)
        printed = out.getvalue()
        self.assertIn("Suppressed by the baseline", printed)
        self.assertIn("abc123", printed)
        self.assertIn("regardless of age", printed)


class AnsweredProbeTest(unittest.TestCase):
    """One definition of "answered", shared by the verdict and the exit code.

    They were two, and they disagreed. `cli._answered_probes` counted any
    arriving status, so a target returning `500` to every probe was "answered",
    `_is_vacuous` was false, and the no-flag vacuity exit never fired -- while
    `core` graded those same probes `inconclusive` and printed "this probe
    establishes nothing... in either direction" directly above `exit 0`. The
    README promised "not one probe answered -> exit 3, no flag required", and
    that sentence was false for every uniformly-5xx target.
    """

    #: The shapes `core` refuses to call an answer, and the one it accepts.
    CASES = (
        ("clean 200", {"response": {"status": 200}}, True),
        ("throttled 429", {"response": {"status": 429}}, False),
        ("handler fell over 500", {"response": {"status": 500}}, False),
        ("unavailable 503", {"response": {"status": 503}}, False),
        ("transport error", {"error": "timed out", "response": {}}, False),
        ("scan truncated",
         {"response": {"status": 200, "body_scan_truncated": True}}, False),
        ("body truncated",
         {"response": {"status": 200, "body_truncated": True}}, False),
        ("no status at all", {"response": {}}, False),
    )

    def test_the_two_definitions_agree(self) -> None:
        for name, probe, answered in self.CASES:
            with self.subTest(case=name):
                self.assertEqual(core.probe_answered(probe), answered)
                # And the count `cli` derives from it moves with it.
                self.assertEqual(
                    cli._answered_probes({"probes": [probe]}), int(answered)
                )

    def test_cli_does_not_carry_its_own_copy(self) -> None:
        """The docstring claimed the definitions were unified. Now it is true."""
        source = inspect.getsource(cli._answered_probes)
        self.assertIn("probe_answered", source)
        self.assertNotIn("TRANSIENT", source)
        self.assertNotIn('"status"', source)

    def test_every_transient_status_is_not_an_answer(self) -> None:
        """Pinned to core's own set, so adding a status cannot desynchronise them."""
        for status in sorted(core.TRANSIENT_STATUSES):
            with self.subTest(status=status):
                self.assertFalse(core.probe_answered({"response": {"status": status}}))

    def test_a_uniformly_transient_run_is_vacuous(self) -> None:
        for status in (429, 500, 503):
            with self.subTest(status=status):
                result = {"probes": [{"response": {"status": status}}] * 4,
                          "findings": []}
                self.assertTrue(cli._is_vacuous(result))
                self.assertTrue(cli._established_nothing(result))


class EstablishedNothingTest(unittest.TestCase):
    """The console said "not a finding about your target" over a finding.

    `result["probes"]` holds CHECK probes only; sequence findings arrive from a
    separate engine. So a config whose checks all time out while a sequence step
    serves another tenant's order is vacuous by probe count AND carries a
    confirmed cross-tenant read. The exit code always tested both halves; the
    console sentence, extracted from it later, got only the first.
    """

    def _result(self, verdict: str) -> dict:
        return {
            "probes": [{"error": "timed out"}, {"error": "timed out"}],
            "findings": [{
                "check_id": "seq-checkout", "identity": "attacker",
                "verdict": verdict, "message": "step 3 served another tenant's order",
                "evidence_grade": "confirmed",
            }],
            "summary": {"probes": 2, "new": 1, "resolved": 0, "unchanged": 0},
            "target": "http://127.0.0.1:1",
        }

    def test_the_sentence_is_withheld_when_a_finding_is_present(self) -> None:
        self.assertFalse(core.__dict__ and False)  # keep the import meaningful
        from veridor.cli import _established_nothing, _is_vacuous

        result = self._result("vulnerable")
        self.assertTrue(_is_vacuous(result), "the probe half must still be true")
        self.assertFalse(_established_nothing(result))

    def test_the_sentence_still_fires_on_a_genuinely_empty_run(self) -> None:
        from veridor.cli import _established_nothing

        result = self._result("inconclusive")
        self.assertTrue(_established_nothing(result))

    def test_the_console_and_the_exit_code_share_one_predicate(self) -> None:
        """They disagreed once; a test is cheaper than noticing again."""
        import inspect

        from veridor import cli

        summary = inspect.getsource(cli._print_summary)
        exit_code = inspect.getsource(cli._vacuous_exit_code)
        self.assertIn("_established_nothing(result)", summary)
        self.assertIn("_established_nothing(result)", exit_code)


class FindingLocationTest(unittest.TestCase):
    """Every SARIF result anchored to `veridor.json:1`.

    Eight findings, eight identical locations, on the config's opening brace.
    The fingerprints were distinct -- which is why deduplication worked and
    triage-by-location did not: code scanning had nothing to sort or group by,
    and the GitHub annotations put every one of them on the same line of the
    same file.
    """

    def _config(self) -> dict:
        return {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:9"},
            "identities": {
                "owner": {"headers": {"Authorization": "Bearer owner"}},
                "other": {"headers": {"Authorization": "Bearer other"}},
            },
            "checks": [
                {
                    "id": "alpha",
                    "request": {"method": "GET", "path": "/api/a"},
                    "expect": {"owner": "allow", "other": "deny"},
                },
                {
                    "id": "beta",
                    "request": {"method": "GET", "path": "/api/b"},
                    "expect": {"owner": "allow", "other": "deny"},
                },
            ],
        }

    def _annotated(self, config: dict, findings: list[dict]) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(config, indent=2), encoding="utf-8")
            core._annotate_finding_lines(findings, path, config)
        return findings

    def test_each_finding_anchors_to_the_expectation_it_graded(self) -> None:
        findings = [
            {"check_id": "alpha", "identity": "other"},
            {"check_id": "beta", "identity": "other"},
            {"check_id": "beta", "identity": "owner"},
        ]
        self._annotated(self._config(), findings)
        lines = [finding["location_line"] for finding in findings]
        self.assertEqual(len(set(lines)), 3, f"findings share a line: {lines}")
        self.assertEqual(lines, sorted(lines) if lines[1] < lines[2] else lines)
        # And each one really is the identity key it graded.
        text = json.dumps(self._config(), indent=2).splitlines()
        self.assertIn('"other"', text[findings[0]["location_line"] - 1])
        self.assertIn('"owner"', text[findings[2]["location_line"] - 1])

    def test_a_config_that_changed_under_the_run_is_not_anchored(self) -> None:
        """A positional anchor against shifted text points at the neighbour.

        The file is re-read after every probe has been issued -- a window as
        long as the run -- so an edit in that window would move a finding onto
        somebody else's declaration. Nothing is worse than being confidently
        wrong about which line a finding is about.
        """
        config = self._config()
        on_disk = self._config()
        on_disk["checks"].insert(0, {
            "id": "inserted",
            "request": {"method": "GET", "path": "/api/z"},
            "expect": {"owner": "allow"},
        })
        findings = [{"check_id": "alpha", "identity": "other"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(on_disk, indent=2), encoding="utf-8")
            core._annotate_finding_lines(findings, path, config)
        self.assertNotIn("location_line", findings[0])

    def test_an_equal_count_edit_does_not_anchor_to_the_neighbour(self) -> None:
        """Length alone let a delete-plus-add shift every line unnoticed."""
        config = self._config()
        on_disk = self._config()
        on_disk["checks"][0] = {
            "id": "replaced",
            "request": {"method": "GET", "path": "/api/z"},
            "expect": {"owner": "allow", "other": "deny", "third": "deny"},
        }
        findings = [{"check_id": "beta", "identity": "owner"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(on_disk, indent=2), encoding="utf-8")
            core._annotate_finding_lines(findings, path, config)
        self.assertNotIn("location_line", findings[0])

    def test_a_cosmetic_anchor_never_costs_a_finished_run(self) -> None:
        """It must not RAISE. Every probe is already paid for by the time it runs.

        Three shapes reached uncaught exception types -- a config that is a
        list, a `checks` value that is not one, an undecodable byte -- turning a
        finished run into a traceback and exit 1 for the sake of a line number
        whose absence is the tested fallback.
        """
        for content in ("[1, 2, 3]", '{"checks": "not a list"}',
                        '{"checks": [null, null]}', "\udcff", "{}"):
            with self.subTest(content=content):
                findings = [{"check_id": "alpha", "identity": "other"}]
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "veridor.json"
                    path.write_bytes(content.encode("utf-8", "surrogateescape"))
                    core._annotate_finding_lines(findings, path, self._config())
                # Whatever it decided, the run survived and SARIF still converts.
                self.assertIsInstance(core._sarif_line(findings[0]), int)

    def test_an_unreadable_or_broken_config_falls_back_to_line_one(self) -> None:
        for content in ("not json at all", '{"checks": [{"id": "a"}', ""):
            with self.subTest(content=content):
                findings = [{"check_id": "alpha", "identity": "other"}]
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "veridor.json"
                    path.write_text(content, encoding="utf-8")
                    core._annotate_finding_lines(findings, path, self._config())
                self.assertNotIn("location_line", findings[0])
                self.assertEqual(core._sarif_line(findings[0]), 1)

    def test_an_older_run_document_still_converts(self) -> None:
        """`report --input run.json` on a document written before this existed."""
        self.assertEqual(core._sarif_line({}), 1)
        self.assertEqual(core._sarif_line({"location_line": 0}), 1)
        self.assertEqual(core._sarif_line({"location_line": True}), 1)
        self.assertEqual(core._sarif_line({"location_line": 42}), 42)

    def test_an_id_appearing_in_a_request_body_does_not_mislocate(self) -> None:
        """A text search for the check id cannot tell these two apart."""
        config = self._config()
        config["checks"][0]["request"] = {
            "method": "POST", "path": "/api/a", "json": {"id": "beta"},
        }
        findings = [{"check_id": "beta", "identity": "owner"}]
        self._annotated(config, findings)
        text = json.dumps(config, indent=2).splitlines()
        anchored = text[findings[0]["location_line"] - 1]
        self.assertIn('"owner"', anchored)

    def test_an_annotation_shows_no_more_of_a_long_value_than_any_other_line(self) -> None:
        """The check name reaches the title whole, and the title is one line of
        the log. Mutant: without the cut in _emit_github_annotations this prints
        all 1200 characters of it, and all 5000 of the message."""
        result = {"findings": [{
            "level": "error", "location": "veridor.json",
            "title": "Authorization expectation failed for " + "R" * 1200,
            "message": "Sent to " + " " * 1500 + "S" * 5000,
        }]}
        stderr = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with contextlib.redirect_stderr(stderr):
                _emit_github_annotations(result)
        annotation = stderr.getvalue()
        self.assertEqual(annotation.count("\n"), 1, annotation[:200])
        self.assertLessEqual(annotation.count("R"), ECHO_LIMIT)
        self.assertIn("more characters)", annotation.split("::")[1])
        self.assertLessEqual(annotation.count("S"), 2000)
        self.assertNotIn("  ", annotation)
        self.assertIn("file=veridor.json", annotation)

    def test_control_a_short_annotation_is_not_cut(self) -> None:
        """A limit that cut every title would pass the test above."""
        result = {"findings": [{"level": "error", "location": "veridor.json",
                                "title": "Authorization expectation failed for invoice",
                                "message": "Identity 'owner' received HTTP 404"}]}
        stderr = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with contextlib.redirect_stderr(stderr):
                _emit_github_annotations(result)
        self.assertEqual(
            stderr.getvalue().strip(),
            "::error file=veridor.json,line=1,title=Authorization expectation failed for invoice"
            "::Identity 'owner' received HTTP 404")

    def test_the_annotation_uses_the_same_line_as_the_sarif_result(self) -> None:
        result = {"findings": [{
            "level": "error", "message": "m", "title": "t",
            "location": "veridor.json", "location_line": 37,
        }]}
        stderr = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with contextlib.redirect_stderr(stderr):
                _emit_github_annotations(result)
        self.assertIn("line=37", stderr.getvalue())


class GatePolicyTest(unittest.TestCase):
    """`new`, `any`, and `none` keep their meaning for findings about the target.

    One deliberate narrowing, measured before it was made: they used to fire on
    `inconclusive` as well, so a rate limit or a 5xx failed the build. Against a
    target whose boundary never moved that was 70% of runs. A gate that fires
    when nothing was measured is not strict, it is wrong -- and coverage still
    cannot fail silently, because `--require-complete` turns an unanswered probe
    into exit 3.
    """

    def test_an_inconclusive_probe_is_not_a_security_finding(self) -> None:
        """The measured defect: `run` graded a 429 as `vulnerable` and failed
        the build. Nothing that went unanswered may reach a security policy."""
        unanswered = _result("n/a", new=1, verdict="inconclusive")
        for policy in ("new", "any", "confirmed", "none"):
            with self.subTest(policy=policy):
                self.assertEqual(_gate_exit_code(policy, unanswered), 0)

    def test_a_real_finding_beside_an_inconclusive_still_gates(self) -> None:
        mixed = {
            "findings": [
                {"id": "a", "evidence_grade": "n/a", "verdict": "inconclusive"},
                {"id": "b", "evidence_grade": "confirmed", "verdict": "vulnerable"},
            ],
        }
        mixed["regression"] = {"new": mixed["findings"]}
        for policy in ("new", "any", "confirmed"):
            with self.subTest(policy=policy):
                self.assertEqual(_gate_exit_code(policy, mixed), 1)

    def test_an_unexpected_denial_is_still_a_finding_about_the_target(self) -> None:
        """It is a failed declaration, not an unanswered probe."""
        self.assertEqual(
            _gate_exit_code("any", _result("ungraded", verdict="unexpected_denial")), 1
        )

    def test_new_is_unchanged_and_ignores_grades(self) -> None:
        self.assertEqual(_gate_exit_code("new", _result("confirmed", new=0)), 0)
        self.assertEqual(_gate_exit_code("new", _result("ungraded", new=1)), 1)

    def test_any_is_unchanged_and_ignores_grades(self) -> None:
        self.assertEqual(_gate_exit_code("any", _result()), 0)
        self.assertEqual(_gate_exit_code("any", _result("n/a")), 1)

    def test_none_is_unchanged(self) -> None:
        self.assertEqual(_gate_exit_code("none", _result("confirmed", new=1)), 0)

    def test_confirmed_fires_only_on_proof(self) -> None:
        self.assertEqual(_gate_exit_code("confirmed", _result("confirmed")), 1)
        self.assertEqual(
            _gate_exit_code("confirmed", _result("suspected", "ungraded", "n/a")), 0
        )
        self.assertEqual(_gate_exit_code("confirmed", _result()), 0)

    def test_confirmed_ignores_novelty(self) -> None:
        # A pre-existing proven leak is still a proven leak, so this gate fires
        # for an unchanged finding where --fail-on new stays silent.
        unchanged = _result("confirmed", new=0)
        self.assertEqual(_gate_exit_code("new", unchanged), 0)
        self.assertEqual(_gate_exit_code("confirmed", unchanged), 1)

    def test_parser_offers_exactly_the_documented_policies(self) -> None:
        action = next(
            item
            for item in _parser()._subparsers._group_actions[0]  # type: ignore[attr-defined]
            .choices["run"]
            ._actions
            if item.dest == "fail_on"
        )
        self.assertEqual(
            set(action.choices),
            {"new+confirmed", "new", "any", "confirmed", "none"},
        )
        # The default is the union, not `new`: `new` alone is decided by a file
        # the README asks you to commit. See BaselineTamperTest.
        self.assertEqual(action.default, "new+confirmed")


class CoverageWiringTest(unittest.TestCase):
    def test_coverage_flags_require_a_specification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            for flag, value in (
                ("--coverage", str(root / "c.json")),
                ("--badge", str(root / "b.json")),
                ("--base-path", "/api"),
            ):
                code, _, stderr = _run(
                    ["run", "--config", str(config), "--output-dir",
                     str(root / "h"), flag, value]
                )
                self.assertEqual(code, 2, flag)
                self.assertIn(f"{flag} requires --openapi", stderr)
            code, _, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--allow-no-matches"]
            )
            self.assertEqual(code, 2)
            self.assertIn("--allow-no-matches requires --openapi", stderr)

    def test_coverage_outputs_get_the_run_path_protections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/widgets/{id}")
            history = root / "history"
            cases = [
                (["--coverage", str(history / "latest.json")],
                 "conflicts with managed run history"),
                (["--badge", str(history / "runs" / "b.json")],
                 "conflicts with managed run history"),
                (["--coverage", str(config)],
                 "must not overwrite a configuration, baseline, or specification"),
                (["--badge", str(spec)],
                 "must not overwrite a configuration, baseline, or specification"),
                (["--coverage", str(root / "same.json"),
                  "--badge", str(root / "same.json")],
                 "must use different paths"),
            ]
            for extra, expected in cases:
                code, _, stderr = _run(
                    ["run", "--config", str(config), "--output-dir", str(history),
                     "--openapi", str(spec), *extra]
                )
                self.assertEqual(code, 2, extra)
                self.assertIn(expected, stderr)
            self.assertFalse(history.exists(), "paths are validated before probing")

    def test_json_and_sarif_conflict_message_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            code, _, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--json", str(root / "x.json"), "--sarif", str(root / "x.json")]
            )
            self.assertEqual(code, 2)
            self.assertIn("--json and --sarif must use different paths", stderr)

    @slow("drives a live HTTP target over the network")
    def test_run_writes_coverage_report_and_badge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/widgets", "/widgets/{id}")
            report = root / "coverage.json"
            badge = root / "badge.json"
            code, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none", "--openapi", str(spec),
                 "--coverage", str(report), "--badge", str(badge)]
            )
            self.assertEqual(code, 0)
            self.assertIn("Authorization boundary coverage: 1/2 operations", stdout)
            self.assertIn("does not measure whether authorization is ENFORCED", stdout)
            written = json.loads(report.read_text())
            self.assertEqual(written["status"], "measured")
            self.assertEqual(written["coverage"], 0.5)
            self.assertEqual(json.loads(badge.read_text())["message"], "50.0% asserted")

    @slow("drives a live HTTP target over the network")
    def test_undefined_coverage_fails_even_when_the_gate_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/totally/unrelated")
            badge = root / "badge.json"
            code, stdout, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "confirmed", "--openapi", str(spec), "--badge", str(badge)]
            )
            self.assertEqual(code, 2)
            self.assertIn("not measured (no_matches)", stdout)
            self.assertIn("boundary coverage was not measured", stderr)
            # Never leave a stale green badge behind an undefined measurement.
            self.assertEqual(json.loads(badge.read_text())["message"], "unknown")
            self.assertTrue(json.loads(badge.read_text())["isError"])

    @slow("drives a live HTTP target over the network")
    def test_fail_on_none_never_fails_even_when_coverage_is_undefined(self) -> None:
        """Regression: 'none never fails' is the documented contract.

        A report-only pipeline that also passes --openapi must not start failing
        the build the moment the spec drifts out of alignment with the config.
        The report and every artifact are still produced.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/totally/unrelated")
            badge = root / "badge.json"
            coverage = root / "coverage.json"
            code, stdout, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none", "--openapi", str(spec),
                 "--badge", str(badge), "--coverage", str(coverage)]
            )
            self.assertEqual(code, 0)
            self.assertIn("not measured (no_matches)", stdout)
            self.assertIn("boundary coverage was not measured", stderr)
            self.assertEqual(json.loads(badge.read_text())["message"], "unknown")
            self.assertTrue(coverage.exists())

    @staticmethod
    def _with_coverage_block(config: Path, block: object) -> Path:
        document = json.loads(config.read_text(encoding="utf-8"))
        document["coverage"] = block
        config.write_text(json.dumps(document), encoding="utf-8")
        return config

    def test_coverage_refuses_a_misspelt_coverage_key_before_computing(self) -> None:
        """A misspelt `denial_statuses`, a null one, or a `coverage` that was
        not an object loaded, and the figure was computed against the default
        403 and 404 with exit 0. Each is refused now, nothing is printed as a
        measurement, and the badge is `unknown`."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets/{id}")
            badge = root / "badge.json"
            # Control: the real key is read, and the check is covered.
            config = self._with_coverage_block(_config(root), {"denial_statuses": [403]})
            code, stdout, _ = _run(["coverage", "--config", str(config),
                                    "--openapi", str(spec)])
            self.assertEqual(code, 0)
            self.assertIn("Denial statuses in use (declared by config): [403]", stdout)
            for block, says in (
                ({"Denial_Statuses": [418]}, "did you mean 'denial_statuses' for "
                                             "'Denial_Statuses'"),
                ({"denial_statuses": None}, "coverage.denial_statuses"),
                ([403], "coverage must be an object"),
            ):
                with self.subTest(block=block):
                    config = self._with_coverage_block(_config(root), block)
                    code, stdout, stderr = _run(
                        ["coverage", "--config", str(config), "--openapi", str(spec),
                         "--badge", str(badge)]
                    )
                    self.assertEqual(code, 2)
                    self.assertIn("boundary coverage was not measured", stderr)
                    self.assertIn(says, stderr)
                    self.assertNotIn("Authorization boundary coverage:", stdout)
                    self.assertEqual(json.loads(badge.read_text())["message"], "unknown")

    def test_a_refused_measurement_rewrites_a_stale_coverage_file(self) -> None:
        """REGRESSION. A refusal rewrote --badge as unknown but left the file
        at --coverage as it was, so a later step that read it after exit 2
        found an old "measured" figure (pre-seeded and reproduced). It is now
        rewritten as not measured, with the reason, on every refusal --
        including a configuration that does not load, which left the badge
        stale as well."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets/{id}")
            broken_spec = root / "broken.json"
            broken_spec.write_text("{not json", encoding="utf-8")
            badge = root / "badge.json"
            coverage = root / "coverage.json"

            def seed() -> None:
                coverage.write_text(json.dumps(
                    {"status": "measured", "coverage": 0.4, "stale": True}), encoding="utf-8")
                badge.write_text(json.dumps(
                    {"schemaVersion": 1, "message": "40.0% asserted", "stale": True}),
                    encoding="utf-8")

            def run(config: Path, openapi: Path) -> tuple[int, str]:
                seed()
                code, _, stderr = _run(
                    ["coverage", "--config", str(config), "--openapi", str(openapi),
                     "--coverage", str(coverage), "--badge", str(badge)])
                return code, stderr

            # Control: a measurement replaces the seed with the real figure.
            config = self._with_coverage_block(_config(root), {"denial_statuses": [403]})
            code, _ = run(config, spec)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(coverage.read_text())["status"], "measured")
            self.assertNotIn("stale", json.loads(coverage.read_text()))

            def unloadable(path: Path) -> Path:
                document = json.loads(path.read_text(encoding="utf-8"))
                document["Sequences"] = []
                path.write_text(json.dumps(document), encoding="utf-8")
                return path

            for label, make, openapi in (
                ("a status outside the rule",
                 lambda: self._with_coverage_block(_config(root), {"denial_statuses": [401]}),
                 spec),
                ("a misspelt key",
                 lambda: self._with_coverage_block(_config(root), {"Denial_Statuses": [403]}),
                 spec),
                ("a specification that does not load", lambda: _config(root), broken_spec),
                ("a configuration that does not load", lambda: unloadable(_config(root)), spec),
            ):
                with self.subTest(label):
                    code, stderr = run(make(), openapi)
                    self.assertEqual(code, 2, stderr)
                    written = json.loads(coverage.read_text())
                    self.assertEqual(written["status"], "not_measured", written)
                    self.assertIsNone(written["coverage"])
                    self.assertNotIn("stale", written)
                    self.assertEqual(written["kind"], "veridor.coverage")
                    self.assertTrue(written["reason"])
                    self.assertEqual(json.loads(badge.read_text())["message"], "unknown")

    def test_a_configuration_that_cannot_be_read_rewrites_both_files(self) -> None:
        """REGRESSION. Only ConfigError rewrote the two files, so a
        configuration that failed to load with an OSError -- a directory, or
        a file the runner cannot read -- exited 2 and left the previous run's
        "measured" coverage file and green badge in place, on `run --openapi`
        and on `coverage` alike, while the README says a configuration that
        does not load rewrites both."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets/{id}")
            badge = root / "badge.json"
            coverage = root / "coverage.json"
            unreadable = root / "veridor.d"
            unreadable.mkdir()
            for verb in (["run", "--output-dir", str(root / "h")], ["coverage"]):
                with self.subTest(verb=verb[0]):
                    coverage.write_text(json.dumps(
                        {"status": "measured", "coverage": 0.4, "stale": True}), encoding="utf-8")
                    badge.write_text(json.dumps(
                        {"schemaVersion": 1, "message": "40.0% asserted", "color": "green",
                         "stale": True}), encoding="utf-8")
                    code, _, stderr = _run(
                        [verb[0], "--config", str(unreadable), *verb[1:],
                         "--openapi", str(spec), "--coverage", str(coverage),
                         "--badge", str(badge)])
                    self.assertEqual(code, 2, stderr)
                    written = json.loads(coverage.read_text(encoding="utf-8"))
                    self.assertEqual((written["status"], written["coverage"]),
                                     ("not_measured", None))
                    self.assertTrue(written["reason"])
                    self.assertEqual(json.loads(badge.read_text())["message"], "unknown")

    def test_run_with_openapi_rewrites_both_files_when_the_config_does_not_load(self) -> None:
        """REGRESSION. `run --openapi --coverage X --badge Y` loads the
        configuration in execute_run, before coverage is reached, so a
        configuration that did not load exited 2 and left the previous run's
        "measured" file and green badge in place, while the README says such a
        refusal rewrites both. Both are rewritten as not measured now."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets/{id}")
            badge = root / "badge.json"
            coverage = root / "coverage.json"
            coverage.write_text(json.dumps(
                {"status": "measured", "coverage": 0.4, "stale": True}), encoding="utf-8")
            badge.write_text(json.dumps(
                {"schemaVersion": 1, "message": "40.0% asserted", "color": "green",
                 "stale": True}), encoding="utf-8")
            config = _config(root)
            document = json.loads(config.read_text(encoding="utf-8"))
            document["Sequences"] = []
            config.write_text(json.dumps(document), encoding="utf-8")
            code, _, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--openapi", str(spec), "--coverage", str(coverage),
                 "--badge", str(badge)])
            self.assertEqual(code, 2, stderr)
            self.assertIn("did you mean 'sequences'", stderr)
            written = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual((written["status"], written["coverage"]), ("not_measured", None))
            self.assertEqual(written["kind"], "veridor.coverage")
            self.assertNotIn("stale", written)
            self.assertIn("Sequences", written["reason"])
            self.assertEqual(json.loads(badge.read_text())["message"], "unknown")
            # Nothing was probed: the refusal came at load.
            self.assertFalse((root / "h" / "latest.json").exists())

    def test_run_does_not_rewrite_coverage_files_when_its_paths_are_refused(self) -> None:
        """Control for the rewrite above: a path refusal (here --coverage
        naming the configuration itself) comes before anything is written, and
        must not be turned into a write over the very file it protected."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets/{id}")
            config = _config(root)
            before = config.read_bytes()
            code, _, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--openapi", str(spec), "--coverage", str(config)])
            self.assertEqual(code, 2, stderr)
            self.assertEqual(config.read_bytes(), before)

    @slow("drives a live HTTP target over the network")
    def test_run_with_openapi_refuses_a_misspelt_coverage_key(self) -> None:
        """`run --openapi` measures coverage after the probes, as it always has,
        and a misspelt key in the block is not measured: exit 2 unless a
        finding wins, as for any other coverage that could not be measured."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._with_coverage_block(_config(root), {"denail_statuses": [401]})
            spec = _spec(root, "/widgets/{id}")
            code, stdout, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "confirmed", "--openapi", str(spec)]
            )
            self.assertEqual(code, 2)
            self.assertIn("boundary coverage was not measured", stderr)
            self.assertIn("did you mean 'denial_statuses' for 'denail_statuses'", stderr)
            self.assertNotIn("Authorization boundary coverage: 1/1", stdout)

    def test_dedicated_coverage_command_still_gates_under_any_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/totally/unrelated")
            code, _, stderr = _run(
                ["coverage", "--config", str(config), "--openapi", str(spec)]
            )
            self.assertEqual(code, 2)
            self.assertIn("boundary coverage was not measured", stderr)

    @slow("drives a live HTTP target over the network")
    def test_allow_no_matches_downgrades_the_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/totally/unrelated")
            code, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none", "--openapi", str(spec), "--allow-no-matches"]
            )
            self.assertEqual(code, 0)
            self.assertIn("not measured (no_matches)", stdout)

    @slow("drives a live HTTP target over the network")
    def test_a_broken_spec_never_hides_the_run_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = root / "openapi.json"
            spec.write_text("openapi: 3.0.3\npaths: {}\n", encoding="utf-8")
            code, stdout, stderr = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "any", "--openapi", str(spec)]
            )
            # The probes ran, their findings were printed, and the gate decided.
            self.assertIn("probes matched their declaration", stdout)
            # Never 0. There is no target here, so every probe is inconclusive
            # and none is a security finding -- but a run that answered nothing
            # is vacuous and must not read as a pass. The spec error outranks it
            # numerically (exit 2 is "your inputs are wrong"), and neither
            # message is hidden by that.
            self.assertEqual(code, 2)
            self.assertIn("established nothing", stderr)
            self.assertIn("not JSON", stderr)

    def test_standalone_coverage_never_touches_the_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root, base_url="https://unreachable.invalid")
            spec = _spec(root, "/widgets", "/widgets/{id}")
            badge = root / "badge.json"
            code, stdout, _ = _run(
                ["coverage", "--config", str(config), "--openapi", str(spec),
                 "--badge", str(badge)]
            )
            self.assertEqual(code, 0)
            self.assertIn("Authorization boundary coverage: 1/2 operations", stdout)
            self.assertEqual(json.loads(badge.read_text())["color"], "orange")

    def test_standalone_coverage_protects_its_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            spec = _spec(root, "/widgets")
            code, _, stderr = _run(
                ["coverage", "--config", str(config), "--openapi", str(spec),
                 "--coverage", str(spec)]
            )
            self.assertEqual(code, 2)
            self.assertIn("must not overwrite", stderr)


@slow("drives a live HTTP target over the network")
class SummaryTest(unittest.TestCase):
    def test_evidence_grades_reach_the_console(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            _, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none"]
            )
            self.assertIn("Evidence: 0 confirmed, 0 suspected", stdout)
            self.assertIn("escalated since the baseline", stdout)

    def test_evidence_counts_are_always_followed_by_their_scope(self) -> None:
        """The grades read as verdicts on the target; the contract says why not.

        A run with no findings at all still prints it: the operator who never
        sees a finding is exactly the one most likely to read a green run as a
        statement about their API rather than about their declarations.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            _, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none"]
            )
            lines = stdout.splitlines()
            evidence = next(
                i for i, line in enumerate(lines) if line.startswith("Evidence:")
            )
            self.assertEqual(lines[evidence + 1], f"Scope: {DECLARATION_SCOPE}")
            self.assertIn("does not establish that the declaration is correct", stdout)

    def test_a_pass_carries_its_own_scope_line(self) -> None:
        """The Scope line qualifies a FINDING. Nothing qualified a PASS.

        A green run was the one outcome carrying no caveat, and it is the
        outcome a reader is most likely to over-read.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            _, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none"]
            )
            lines = stdout.splitlines()
            scope = next(
                i for i, line in enumerate(lines) if line.startswith("Scope:")
            )
            self.assertEqual(lines[scope + 1], f"Pass: {PASS_SCOPE}")

    def test_the_console_never_calls_a_matched_probe_safe(self) -> None:
        """`safe` is in coverage.BANNED_CLAIM_WORDS for this exact reason."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            _, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none"]
            )
            self.assertIn("probes matched their declaration", stdout)
            self.assertNotIn("probes safe", stdout)


@slow("drives a live HTTP target over the network")
class PassDisclosureConsoleTest(unittest.TestCase):
    """Outcomes that emit no finding still have to reach the console.

    Both were recorded only in the raw run JSON, so a reviewer reading a green
    Veridor run could not see them at all.
    """

    def _permissive_config(self, root: Path) -> Path:
        return _write(
            root / "veridor.json",
            {
                "version": 1,
                "target": {"base_url": DEAD_TARGET, "timeout_seconds": 1},
                "identities": {"owner": {"headers": {}}, "other": {"headers": {}}},
                "checks": [
                    {
                        "id": "widget-isolation",
                        "request": {"method": "GET", "path": "/widgets/w1"},
                        "expect": {
                            "owner": {"status": [200, 403]},
                            "other": {"status": [200, 403]},
                        },
                    }
                ],
            },
        )

    def test_a_permissive_expectation_is_named_on_the_console(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._permissive_config(root)
            _, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none"]
            )
            self.assertIn("Non-asserting: 2 expectation(s)", stdout)
            self.assertIn("asserts nothing about the boundary", stdout)
            self.assertIn("widget-isolation / owner", stdout)

    def test_a_suite_that_asserts_something_prints_no_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            _, stdout, _ = _run(
                ["run", "--config", str(config), "--output-dir", str(root / "h"),
                 "--fail-on", "none"]
            )
            self.assertNotIn("Non-asserting:", stdout)
            self.assertNotIn("Unproven oracle:", stdout)


class InitTest(unittest.TestCase):
    def _generated(self, root: Path, *extra: str) -> dict:
        spec = _write(
            root / "openapi.json",
            {
                "openapi": "3.0.3",
                "info": {"title": "Fixture", "version": "1"},
                "servers": [{"url": "https://staging.fixture.test/api/v1"}],
                "paths": {
                    "/widgets": {
                        "get": {"operationId": "listWidgets",
                                "responses": {"200": {"description": "ok"}}},
                        "post": {"responses": {"201": {"description": "made"}}},
                    },
                    "/widgets/{id}": {
                        "delete": {"responses": {"204": {"description": "gone"}}},
                    },
                },
            },
        )
        output = root / "generated.json"
        code, stdout, stderr = _run(
            ["init", "--openapi", str(spec), "--output", str(output), *extra]
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("Wrote 3 checks", stdout)
        self.last_stdout = stdout
        return json.loads(output.read_text())

    def test_generated_config_is_accepted_by_the_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self._generated(root)
            environment = {
                "VERIDOR_OWNER_TOKEN": "owner-token",
                "VERIDOR_OTHER_TENANT_TOKEN": "other-token",
            }
            with patch.dict(os.environ, environment):
                loaded = load_config(root / "generated.json")
            self.assertEqual(len(loaded["checks"]), 3)
            self.assertEqual(
                [check["id"] for check in document["checks"]],
                ["list-widgets", "post-widgets", "delete-widgets-id"],
            )
            self.assertEqual(
                document["target"]["base_url"], "https://staging.fixture.test/api/v1"
            )
            # The base URL came from the spec, so the operator is told to check it.
            self.assertIn("staging.fixture.test", self.last_stdout)
            self.assertIn("test environment", self.last_stdout)
            validate_marker(document["identities"]["owner"]["marker"], "generated")

    def test_every_generated_check_asserts_a_denial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self._generated(Path(directory))
            for check in document["checks"]:
                self.assertEqual(check["expect"]["other_tenant"]["status"], [403, 404])
                self.assertTrue(
                    all(200 <= status < 300 for status in check["expect"]["owner"]["status"])
                )
                self.assertIn("_comment", check)

    def test_an_operation_the_spec_marks_public_is_not_scaffolded_denied(self) -> None:
        """`security: []` says anyone may call it; 'other_tenant denied' did not.

        Reproduced: `init` on a spec whose /v1/health declared `security: []`
        wrote `other_tenant: [403, 404]`, a guaranteed red finding against a
        target doing exactly what its spec says. The challenger now gets a
        placeholder that accepts both access and denial, which `run` reports
        as asserting nothing, and the note says why.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _write(
                root / "openapi.json",
                {
                    "openapi": "3.0.3",
                    "info": {"title": "Fixture", "version": "1"},
                    "security": [{"bearer": []}],
                    "paths": {
                        "/health": {"get": {"security": [],
                                            "responses": {"200": {"description": "ok"}}}},
                        "/status": {"get": {"security": [{}],
                                            "responses": {"200": {"description": "ok"}}}},
                        "/widgets": {"get": {"responses": {"200": {"description": "ok"}}}},
                    },
                },
            )
            output = root / "generated.json"
            code, _, stderr = _run(
                ["init", "--openapi", str(spec), "--output", str(output)]
            )
            self.assertEqual(code, 0, stderr)
            checks = {
                check["request"]["path"]: check
                for check in json.loads(output.read_text())["checks"]
            }
            for public in ("/health", "/status"):
                with self.subTest(path=public):
                    check = checks[public]
                    statuses = check["expect"]["other_tenant"]["status"]
                    self.assertIn(200, statuses)
                    self.assertTrue({403, 404} <= set(statuses))
                    self.assertIn("public", check["_comment"])
                    self.assertNotIn("'other_tenant' denied", check["_comment"])
            # Inherited document-level security is still a boundary.
            self.assertEqual(
                checks["/widgets"]["expect"]["other_tenant"]["status"], [403, 404]
            )
            environment = {
                "VERIDOR_OWNER_TOKEN": "owner-token",
                "VERIDOR_OTHER_TENANT_TOKEN": "other-token",
            }
            with patch.dict(os.environ, environment):
                loaded = load_config(output)
            # The placeholder is what `run` reports as asserting nothing, and
            # nothing else in the scaffold is.
            self.assertEqual(
                {entry["check_id"] for entry in core._non_asserting_expectations(loaded)},
                {checks["/health"]["id"], checks["/status"]["id"]},
            )

    def test_missing_token_is_reported_before_any_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._generated(root)
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ConfigError) as raised:
                    load_config(root / "generated.json")
            self.assertIn("VERIDOR_OWNER_TOKEN", str(raised.exception))

    def test_path_placeholders_are_flagged_for_the_reader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self._generated(Path(directory))
            templated = next(
                check for check in document["checks"]
                if "{id}" in check["request"]["path"]
            )
            self.assertIn("Replace {id}", templated["_comment"])

    def test_refuses_to_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets")
            output = root / "generated.json"
            output.write_text("keep me", encoding="utf-8")
            code, _, stderr = _run(
                ["init", "--openapi", str(spec), "--output", str(output)]
            )
            self.assertEqual(code, 2)
            self.assertIn("pass --force to replace it", stderr)
            self.assertEqual(output.read_text(), "keep me")
            code, _, _ = _run(
                ["init", "--openapi", str(spec), "--output", str(output), "--force"]
            )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text())["version"], 1)

    def test_never_overwrites_the_specification_even_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets")
            code, _, stderr = _run(
                ["init", "--openapi", str(spec), "--output", str(spec), "--force"]
            )
            self.assertEqual(code, 2)
            self.assertIn("must not overwrite the OpenAPI specification", stderr)
            self.assertIn("openapi", json.loads(spec.read_text()))

    def test_spec_without_operations_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _write(
                root / "openapi.json",
                {"openapi": "3.0.3", "info": {"title": "Empty", "version": "1"},
                 "paths": {"/widgets": {"head": {"responses": {}}}}},
            )
            code, _, stderr = _run(
                ["init", "--openapi", str(spec), "--output", str(root / "out.json")]
            )
            self.assertEqual(code, 2)
            self.assertIn("declares no in-scope operations", stderr)
            self.assertFalse((root / "out.json").exists())

    def test_unusable_server_url_falls_back_to_a_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _write(
                root / "openapi.json",
                {
                    "openapi": "3.0.3",
                    "info": {"title": "Relative", "version": "1"},
                    "servers": [{"url": "/api/v2"}],
                    "paths": {"/widgets": {"get": {"responses": {}}}},
                },
            )
            output = root / "out.json"
            code, stdout, _ = _run(
                ["init", "--openapi", str(spec), "--output", str(output)]
            )
            self.assertEqual(code, 0)
            self.assertIn("placeholder", stdout)
            document = json.loads(output.read_text())
            self.assertEqual(
                document["target"]["base_url"], "https://staging.example.com"
            )
            # The prefix the server url carried still reaches the request path.
            self.assertEqual(
                document["checks"][0]["request"]["path"], "/api/v2/widgets"
            )

    def test_templated_server_url_resolves_its_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _write(
                root / "openapi.json",
                {
                    "openapi": "3.0.3",
                    "info": {"title": "Templated", "version": "1"},
                    "servers": [
                        {
                            "url": "https://{env}.example.test/api",
                            "variables": {"env": {"default": "staging"}},
                        },
                    ],
                    "paths": {"/widgets": {"get": {"responses": {}}}},
                },
            )
            output = root / "out.json"
            self.assertEqual(
                _run(["init", "--openapi", str(spec), "--output", str(output)])[0], 0
            )
            self.assertEqual(
                json.loads(output.read_text())["target"]["base_url"],
                "https://staging.example.test/api",
            )

    def test_unresolvable_server_template_never_reaches_the_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _write(
                root / "openapi.json",
                {
                    "openapi": "3.0.3",
                    "info": {"title": "Templated", "version": "1"},
                    "servers": [{"url": "https://{env}.example.test/api"}],
                    "paths": {"/widgets": {"get": {"responses": {}}}},
                },
            )
            output = root / "out.json"
            self.assertEqual(
                _run(["init", "--openapi", str(spec), "--output", str(output)])[0], 0
            )
            base_url = json.loads(output.read_text())["target"]["base_url"]
            self.assertNotIn("{", base_url)
            self.assertEqual(base_url, "https://staging.example.com")

    def test_base_url_override_wins_over_the_specification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self._generated(root, "--base-url", "http://127.0.0.1:8765/")
            self.assertEqual(document["target"]["base_url"], "http://127.0.0.1:8765")

    def test_rejected_base_url_override_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = _spec(root, "/widgets")
            output = root / "out.json"
            code, _, stderr = _run(
                ["init", "--openapi", str(spec), "--output", str(output),
                 "--base-url", "ftp://example.com"]
            )
            self.assertEqual(code, 2)
            self.assertIn("--base-url", stderr)
            self.assertFalse(output.exists())

    def test_generated_config_is_measurable_by_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._generated(root)
            # Coverage issues no request, but it still loads and validates the
            # configuration, so the referenced variables must resolve.
            environment = {
                "VERIDOR_OWNER_TOKEN": "placeholder",
                "VERIDOR_OTHER_TENANT_TOKEN": "placeholder-other",
            }
            with patch.dict(os.environ, environment):
                code, stdout, _ = _run(
                    ["coverage", "--config", str(root / "generated.json"),
                     "--openapi", str(root / "openapi.json")]
                )
            self.assertEqual(code, 0)
            # `init` writes the spec's path templates verbatim and tells the
            # user to replace them. Until they do, the DELETE /widgets/{id}
            # check names no concrete resource, so it earns no coverage: 2/3,
            # not a 100% brightgreen badge over an unedited file.
            self.assertIn("2/3 operations (66.6%)", stdout)
            self.assertIn("templated_check_path", stdout)
            self.assertNotIn("This does not mean all are correctly enforced", stdout)

    def test_substituting_the_placeholders_earns_full_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self._generated(root)
            for check in document["checks"]:
                check["request"]["path"] = check["request"]["path"].replace(
                    "{id}", "w-1"
                )
            (root / "generated.json").write_text(json.dumps(document), encoding="utf-8")
            environment = {
                "VERIDOR_OWNER_TOKEN": "placeholder",
                "VERIDOR_OTHER_TENANT_TOKEN": "placeholder-other",
            }
            with patch.dict(os.environ, environment):
                code, stdout, _ = _run(
                    ["coverage", "--config", str(root / "generated.json"),
                     "--openapi", str(root / "openapi.json")]
                )
            self.assertEqual(code, 0)
            self.assertIn("3/3 operations (100.0%)", stdout)
            self.assertIn("This does not mean all are correctly enforced", stdout)
            self.assertNotIn("templated_check_path", stdout)


class NewMarkerTest(unittest.TestCase):
    def test_prints_a_marker_the_validator_accepts(self) -> None:
        code, stdout, _ = _run(["new-marker"])
        self.assertEqual(code, 0)
        self.assertEqual(validate_marker(stdout.strip(), "printed"), stdout.strip())

    def test_two_invocations_differ(self) -> None:
        _, first, _ = _run(["new-marker"])
        _, second, _ = _run(["new-marker"])
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
