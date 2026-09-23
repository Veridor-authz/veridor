"""Regressions for hollow passes, wrong verdicts and misleading messages.

Each class names one defect a user could hit with only the wheel and the docs:
what Veridor did, why that was wrong, and the test that keeps it fixed. The file
is organised by defect rather than by the module the fix lives in, because most
of these crossed modules.

Two shapes recur:

* a gate that goes green when its credentials stop working, which is worse than
  no gate because it earns trust it is not holding;
* `run`, the only command that gates a build, ignoring a hollow pass that
  another verb (`mutate`, `map`) already knew how to detect.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor import capsule, core  # noqa: E402
from veridor.core import ConfigError, load_config  # noqa: E402

DEAD = "http://127.0.0.1:1"


def _config(**target) -> dict:
    return {
        "version": 1,
        "target": {"base_url": DEAD, **target},
        "identities": {
            "owner": {"headers": {"Authorization": "Bearer a"}},
            "outsider": {"headers": {"Authorization": "Bearer b"}},
        },
        "checks": [{
            "id": "c",
            "request": {"method": "GET", "path": "/a"},
            "expect": {"owner": {"status": [200]}, "outsider": {"status": [403]}},
        }],
    }


def _load(config: dict, **kwargs):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return load_config(path, **kwargs)


class VerdictDirectionTest(unittest.TestCase):
    """`vulnerable` means the target HANDED SOMETHING OVER.

    It was decided by an allow-list of four denial statuses, so every other
    non-success code fell through to `vulnerable` at SARIF `error`. Of 16
    status codes swept, nine landed on the wrong side: 204, 301, 302, 400, 405,
    409, 418, 422, 451.

    The worst is 302. A redirect to a login page is the standard denial in
    every session-based application, and Veridor never follows redirects, so
    not one byte of protected content was served -- reported as a breach.
    """

    def test_a_redirect_to_login_is_not_a_breach(self) -> None:
        self.assertFalse(core._target_served(302))

    def test_no_non_success_status_reads_as_vulnerable(self) -> None:
        for status in (301, 302, 304, 400, 405, 409, 418, 422, 451, 503):
            with self.subTest(status=status):
                self.assertFalse(core._target_served(status))

    def test_every_success_still_reads_as_served(self) -> None:
        """Including 204, deliberately: a
        204 to an attacker's DELETE is the target performing the write, and for
        a mutating request success IS the harm, body or no body."""
        for status in (200, 201, 202, 204, 206, 299):
            with self.subTest(status=status):
                self.assertTrue(core._target_served(status))

    def test_no_response_at_all_is_not_served(self) -> None:
        self.assertFalse(core._target_served(None))


class CrashTest(unittest.TestCase):
    """Every one of these exited 1 -- which this project's own table reads as
    "the gate failed". CI would report an authorization regression because the
    tool fell over on a malformed input."""

    def test_an_unbounded_timeout_is_refused_not_crashed(self) -> None:
        """`matrix` has always enforced a ceiling; `run` checked only "> 0",
        so 1e30 reached socket.settimeout and raised OverflowError."""
        for value in (1e30, 1e300):
            with self.subTest(timeout=value):
                with self.assertRaises(ConfigError) as caught:
                    _load(_config(timeout_seconds=value))
                self.assertIn("no more than", str(caught.exception))

    def test_a_nan_timeout_is_refused(self) -> None:
        """NaN fails every comparison, so `timeout <= 0` let it through and
        socket.settimeout raised ValueError."""
        with self.assertRaises(ConfigError):
            _load(_config(timeout_seconds=float("nan")))

    def test_the_ceiling_matches_the_one_matrix_enforces(self) -> None:
        from veridor.matrix import MATRIX_MAX_TIMEOUT_SECONDS  # noqa: PLC0415

        self.assertEqual(core.MAX_TIMEOUT_SECONDS, MATRIX_MAX_TIMEOUT_SECONDS)

    def test_a_deeply_nested_document_is_refused(self) -> None:
        """json.loads recurses per level, so the stack blew inside the decoder
        rather than raising JSONDecodeError."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertIn("nested too deeply", str(caught.exception))

    def test_a_binary_file_is_not_a_capsule(self) -> None:
        """The config and OpenAPI loaders both refuse this cleanly; the capsule
        loader was missed."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_bytes(bytes([0xCF, 0xFA, 0xED, 0xFE] + [0] * 40))
            with self.assertRaises(capsule.CapsuleError) as caught:
                capsule.load(path)
        self.assertIn("not valid UTF-8", str(caught.exception))


class BlindGridTest(unittest.TestCase):
    """`map --fail-on-drift` exited 0 with the target switched off.

    A gate that cannot reach its target must not pass. `run` grew this exact
    guard earlier and the argument for it was never carried across -- a CI job reads an exit code,
    not a summary line, and "Drift saw 0% of the grid" printed in full above a
    green build.
    """

    @staticmethod
    def _matrix(cells: list[dict]) -> dict:
        return {"cells": cells}

    def _code(self, cells: list[dict], require_complete: bool = False) -> int:
        import argparse  # noqa: PLC0415

        from veridor.cli import _map_coverage_exit_code  # noqa: PLC0415

        return _map_coverage_exit_code(
            argparse.Namespace(require_complete=require_complete),
            self._matrix(cells),
        )

    def test_a_grid_where_nothing_was_measured_exits_three(self) -> None:
        cells = [{"reach": "unknown", "unknown_reason": "transport_error"}] * 6
        self.assertEqual(self._code(cells), 3)

    def test_it_needs_no_flag(self) -> None:
        """The same reasoning as run's vacuous guard: a green build that
        measured nothing is a stronger overclaim than any false positive."""
        cells = [{"reach": "unknown", "unknown_reason": "rate_limited"}] * 4
        self.assertEqual(self._code(cells, require_complete=False), 3)

    def test_deliberate_skips_are_not_a_coverage_failure(self) -> None:
        """A CRUD API is ~50% mutating and `map` is read-only by design. If
        those counted as unmeasured, every such API would gate forever."""
        cells = [
            {"reach": "unknown", "unknown_reason": "skipped_mutating"},
            {"reach": "unknown", "unknown_reason": "skipped_no_specimen"},
            {"reach": "reached", "unknown_reason": None},
        ]
        self.assertEqual(self._code(cells), 0)
        self.assertEqual(self._code(cells, require_complete=True), 0)

    def test_an_operators_exclusion_is_a_deliberate_skip(self) -> None:
        """`--ignore`, `matrix.ignore` and a non-empty `--include` record every
        operation they leave out as `skipped_ignored`. Counted as probed and
        unmeasured, `map --require-complete --ignore X` exited 3 against a
        healthy target and told the operator to re-run when it was healthy --
        the same coverage tuple as a route that really answered 503."""
        cells = [
            {"reach": "unknown", "unknown_reason": "skipped_ignored"},
            {"reach": "reached", "unknown_reason": None},
            {"reach": "refused", "unknown_reason": None},
        ]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self._code(cells, require_complete=True), 0)
        self.assertEqual(stderr.getvalue(), "")
        # Control: a real loss beside the exclusion still gates on request.
        lost = cells + [{"reach": "unknown", "unknown_reason": "rate_limited"}]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self._code(lost, require_complete=True), 3)

    def test_a_partial_loss_gates_only_when_asked(self) -> None:
        """Transients are why the noise floor measured zero. A gate that fires
        on one rate limit is a gate somebody switches off."""
        cells = [
            {"reach": "reached", "unknown_reason": None},
            {"reach": "unknown", "unknown_reason": "rate_limited"},
        ]
        self.assertEqual(self._code(cells), 0)
        self.assertEqual(self._code(cells, require_complete=True), 3)

    def test_a_fully_measured_grid_never_gates(self) -> None:
        cells = [{"reach": "reached", "unknown_reason": None},
                 {"reach": "refused", "unknown_reason": None}]
        for flag in (False, True):
            with self.subTest(require_complete=flag):
                self.assertEqual(self._code(cells, require_complete=flag), 0)

    def test_a_grid_of_redirects_records_nothing_either(self) -> None:
        """Veridor never follows a redirect, so nothing behind one is observed.
        Measured: recorded against a listener that answered everything with
        302, `map` exited 0 with no warning, and that file then made
        `--fail-on-drift opened` exit 0 against a cross-tenant read."""
        cells = [{"reach": "indeterminate", "status": 302, "unknown_reason": None}] * 4
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self._code(cells), 3)
        self.assertIn("records nothing", stderr.getvalue())
        self.assertIn("redirect", stderr.getvalue())

    def test_a_login_redirect_beside_measured_cells_is_not_a_coverage_failure(self) -> None:
        """An anonymous 302 to /login is a session app's ordinary denial. It
        must not trip the records-nothing arm, nor `--require-complete`."""
        cells = [{"reach": "indeterminate", "status": 302, "unknown_reason": None},
                 {"reach": "reached", "status": 200, "unknown_reason": None}]
        for flag in (False, True):
            with self.subTest(require_complete=flag):
                self.assertEqual(self._code(cells, require_complete=flag), 0)

    def test_control_a_grid_of_handler_rejections_is_measured(self) -> None:
        """A 400 is `indeterminate` too, but the handler answered it."""
        cells = [{"reach": "indeterminate", "status": 400, "unknown_reason": None}] * 4
        self.assertEqual(self._code(cells), 0)

    def test_a_matrix_that_probed_nothing_is_not_gated_here(self) -> None:
        """`--dry-run` and an all-mutating spec both land here; the empty-plan
        problem is a different one and is not this guard's to claim."""
        self.assertEqual(self._code([]), 0)


class HollowPassTest(unittest.TestCase):
    """A green run in which nothing was verified.

    Veridor already knew how to detect a hollow pass, and `run`, the only
    command that gates a build, did not use that knowledge. On one config, in
    the same second, `run` printed `2/2 probes matched their declaration` and exit 0
    while `mutate` printed `[SURVIVED] M6 sham-credential`.

    This covers the case that needs no probe at all to detect.
    """

    def test_two_identities_with_one_credential_are_refused(self) -> None:
        """A copy-pasted identity block with the name changed and not the token.
        Every probe was the owner talking to itself; the run said 2/2 matched."""
        config = _config()
        config["identities"]["outsider"]["headers"]["Authorization"] = "Bearer a"
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        message = str(caught.exception)
        self.assertIn("identical credentials", message)
        self.assertIn("without testing anything", message)

    def test_it_compares_what_goes_on_the_wire(self) -> None:
        """Two DIFFERENT env vars holding the same token are still one caller.
        The comparison is after expansion for exactly that reason."""
        import os  # noqa: PLC0415

        os.environ["VDR_STUDY_A"] = os.environ["VDR_STUDY_B"] = "same-token"
        config = _config()
        config["identities"]["owner"]["headers"]["Authorization"] = "${VDR_STUDY_A}"
        config["identities"]["outsider"]["headers"]["Authorization"] = "${VDR_STUDY_B}"
        with self.assertRaises(ConfigError):
            _load(config)

    def test_a_cookie_identity_is_covered_too(self) -> None:
        config = _config()
        for name in ("owner", "outsider"):
            config["identities"][name]["headers"] = {"Cookie": "sid=1"}
        with self.assertRaises(ConfigError):
            _load(config)

    def test_deliberate_anonymity_is_not_a_collision(self) -> None:
        """More than one identity sending nothing is a real configuration --
        anonymous and unauthenticated callers are declared that way on purpose."""
        config = _config()
        config["identities"] = {
            "anon_a": {"headers": {}},
            "anon_b": {"headers": {}},
            "owner": {"headers": {"Authorization": "Bearer a"}},
        }
        config["checks"][0]["expect"] = {
            "anon_a": {"status": [401]}, "owner": {"status": [200]},
        }
        self.assertEqual(len(_load(config)["identities"]), 3)

    @staticmethod
    def _session(body: str) -> dict:
        return {
            "login": [{"method": "POST", "path": "/login", "body": body,
                       "expect_status": [200]}],
            "establishes": {"cookie": "sid"},
        }

    def test_a_copy_pasted_session_is_refused(self) -> None:
        """The guard skipped every identity with a session, and with it the
        static headers that identity also sends. Both arms loaded."""
        for static in ({}, {"Authorization": "Bearer a"}):
            with self.subTest(static=static):
                config = _config()
                for name in ("owner", "outsider"):
                    config["identities"][name] = {
                        "headers": dict(static), "session": self._session("u=alice&p=pw"),
                    }
                with self.assertRaises(ConfigError) as caught:
                    _load(config)
                self.assertIn("identical credentials", str(caught.exception))

    def test_two_different_logins_are_two_callers(self) -> None:
        """The control: a session is compared on what it logs in with."""
        config = _config()
        config["identities"]["owner"] = {"session": self._session("u=alice&p=pw")}
        config["identities"]["outsider"] = {"session": self._session("u=bob&p=pw")}
        self.assertEqual(len(_load(config)["identities"]), 2)

    def test_a_shared_custom_credential_header_is_refused(self) -> None:
        """Only six header names were compared, so X-Access-Token loaded."""
        for header in ("X-Access-Token", "PRIVATE-TOKEN"):
            with self.subTest(header=header):
                config = _config()
                for name in ("owner", "outsider"):
                    config["identities"][name]["headers"] = {header: "same-value"}
                with self.assertRaises(ConfigError) as caught:
                    _load(config)
                self.assertIn("identical credentials", str(caught.exception))

    def test_different_custom_credential_headers_are_two_callers(self) -> None:
        config = _config()
        for name in ("owner", "outsider"):
            config["identities"][name]["headers"] = {"X-Access-Token": f"t-{name}"}
        self.assertEqual(len(_load(config)["identities"]), 2)

    def test_identical_headers_that_carry_no_credential_are_anonymity(self) -> None:
        """Two anonymous callers that both send Accept are still anonymous."""
        config = _config()
        for name in ("owner", "outsider"):
            config["identities"][name]["headers"] = {"Accept": "application/json"}
        self.assertEqual(len(_load(config)["identities"]), 2)

    def test_a_shared_non_credential_header_is_not_a_collision(self) -> None:
        config = _config()
        for name, token in (("owner", "Bearer a"), ("outsider", "Bearer b")):
            config["identities"][name]["headers"] = {
                "Authorization": token, "X-Tenant": "acme",
            }
        self.assertEqual(len(_load(config)["identities"]), 2)


class AnsweredNotMatchedTest(unittest.TestCase):
    """"Not one probe was answered" fired on a run where both were answered.

    The guard tested `summary.safe` -- probes that MATCHED -- rather than
    probes that got a response. A HEAD request has no body for the marker
    oracle, so both probes came back 200 and both graded inconclusive, and the
    operator was told to go and check whether their target was up.
    """

    def _code(self, probes: list[dict], findings: list[dict] | None = None) -> int:
        import argparse  # noqa: PLC0415

        from veridor.cli import _vacuous_exit_code  # noqa: PLC0415

        return _vacuous_exit_code(
            argparse.Namespace(fail_on="new"),
            {"probes": probes, "findings": findings or [], "summary": {"safe": 0}},
        )

    def test_answered_but_unmatched_probes_are_not_called_unanswered(self) -> None:
        answered = [{"error": None, "response": {"status": 200}}] * 2
        self.assertEqual(self._code(answered), 0)

    def test_a_genuinely_dead_target_still_exits_three(self) -> None:
        dead = [{"error": "timed out", "response": {}}] * 2
        self.assertEqual(self._code(dead), 3)

    def test_a_partial_answer_is_not_vacuous(self) -> None:
        mixed = [{"error": None, "response": {"status": 200}},
                 {"error": "timed out", "response": {}}]
        self.assertEqual(self._code(mixed), 0)


class OfflineCoverageTest(unittest.TestCase):
    """`coverage` sends nothing, so it must not demand live credentials.

    Its own help says "Issues no request" and groups its flags under
    "(offline, static)" -- then it exited 2 with `environment variable
    'ALICE_TOKEN' is not set`, because the config loader expands `${VAR}`
    for every verb alike. A team wanting a coverage badge in CI without
    provisioning secrets was blocked for no reason.
    """

    CONFIG = {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:8765"},
        "identities": {
            "a": {"headers": {"Authorization": "Bearer ${VDR_ABSENT_A}"}},
            "b": {"headers": {"Authorization": "Bearer ${VDR_ABSENT_B}"}},
        },
        "checks": [{
            "id": "c",
            "request": {"method": "GET", "path": "/api/invoices/inv-100"},
            "expect": {"a": {"status": [200]}, "b": {"status": [404]}},
        }],
    }

    def setUp(self) -> None:
        import os  # noqa: PLC0415

        for name in ("VDR_ABSENT_A", "VDR_ABSENT_B"):
            os.environ.pop(name, None)

    def test_a_missing_credential_does_not_block_a_static_reading(self) -> None:
        loaded = _load(self.CONFIG, allow_missing_env=True)
        self.assertEqual(len(loaded["identities"]), 2)

    def test_the_verbs_that_authenticate_still_refuse(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            _load(self.CONFIG)
        self.assertIn("VDR_ABSENT_A", str(caught.exception))

    def test_absent_credentials_stay_distinguishable(self) -> None:
        """A single shared sentinel made every unset token identical, which
        tripped the indistinguishable-identity guard added in the same batch
        and refused a config whose only sin was not exporting secrets."""
        loaded = _load(self.CONFIG, allow_missing_env=True)
        values = {
            identity["headers"]["Authorization"]
            for identity in loaded["identities"].values()
        }
        self.assertEqual(len(values), 2)

    def test_the_placeholder_is_recognisable_if_it_ever_escapes(self) -> None:
        loaded = _load(self.CONFIG, allow_missing_env=True)
        self.assertIn("absent:", loaded["identities"]["a"]["headers"]["Authorization"])


class MessageAccuracyTest(unittest.TestCase):
    def test_the_version_error_names_every_supported_version(self) -> None:
        """It said "must be an object with version 1" while accepting 2 -- the
        version `run --help` refers to and the one sequences require."""
        config = dict(_config(), version=3)
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        message = str(caught.exception)
        self.assertIn("1, 2", message)
        self.assertIn("sequences", message)

    def test_the_yaml_remedy_does_not_name_another_verb(self) -> None:
        """It ended `Then: veridor coverage --config ...` for every verb, so a
        user who ran `init` was sent to a different command with a flag `init`
        rejects: `unrecognized arguments: --config veridor.json`."""
        from veridor.openapi import _YAML_REMEDY  # noqa: PLC0415

        remedy = _YAML_REMEDY.format(name="spec.yaml")
        self.assertIn("re-run the same command", remedy)
        self.assertNotIn("veridor coverage", remedy)
        self.assertNotIn("--config", remedy)

    def test_the_yaml_remedy_warns_that_pyyaml_is_absent_here(self) -> None:
        """The one-liner failed inside Veridor's own venv -- we have no
        dependencies, so PyYAML is not there. It could only work on a
        system Python the README says is too old to run us."""
        from veridor.openapi import _YAML_REMEDY  # noqa: PLC0415

        self.assertIn("NOT in Veridor's own virtualenv", _YAML_REMEDY)


@slow("spawns the CLI in a subprocess")
class ExitCodeTest(unittest.TestCase):
    """A malformed input is exit 2. Only a finding is exit 1."""

    def _run(self, *argv: str) -> int:
        import os  # noqa: PLC0415

        return subprocess.run(
            [sys.executable, "-m", "veridor.cli", *argv],
            cwd=ROOT, env=source_path.child_env(),
            capture_output=True, text=True,
        ).returncode

    def test_hostile_inputs_never_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {}
            for label, value in (("huge", 1e30), ("nan", float("nan"))):
                path = root / f"{label}.json"
                path.write_text(json.dumps(_config(timeout_seconds=value)),
                                encoding="utf-8")
                cases[label] = ("run", "--config", str(path),
                                "--output-dir", str(root / label))
            deep = root / "deep.json"
            deep.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
            cases["deep"] = ("run", "--config", str(deep),
                             "--output-dir", str(root / "deep-out"))
            binary = root / "bin.json"
            binary.write_bytes(bytes([0xCF, 0xFA, 0xED, 0xFE] + [0] * 40))
            cases["binary"] = ("verify", str(binary))

            for label, argv in cases.items():
                with self.subTest(case=label):
                    self.assertEqual(self._run(*argv), 2)


class ReportAccuracyTest(unittest.TestCase):
    """Messages that stated something the run had not established."""

    def test_the_budget_refusal_arithmetic_checks_out(self) -> None:
        """It printed "620 requests (246 rows x 5 identities)" -- 246 x 5 is
        1230. `rows` is the SPEC's row count; the planned rows were 124. A
        reader doing capacity maths off that line was off by a factor of two."""
        import json as _json  # noqa: PLC0415
        import re as _re  # noqa: PLC0415
        import tempfile as _tempfile  # noqa: PLC0415

        from veridor.matrix import MatrixError, plan_matrix  # noqa: PLC0415
        from veridor.openapi import load_spec, parse_spec  # noqa: PLC0415

        root = Path(_tempfile.mkdtemp())
        spec = root / "openapi.json"
        # Half the operations are mutating, so `rows` and planned rows diverge.
        spec.write_text(_json.dumps({
            "openapi": "3.0.3", "info": {"title": "b", "version": "1"},
            "servers": [{"url": "http://127.0.0.1:8765"}],
            "paths": {
                f"/api/r{index}": {
                    "get": {"responses": {"200": {"description": "ok"}}},
                    "delete": {"responses": {"204": {"description": "ok"}}},
                }
                for index in range(123)
            },
        }), encoding="utf-8")
        config = root / "veridor.json"
        config.write_text(_json.dumps({
            "version": 1, "target": {"base_url": "http://127.0.0.1:8765"},
            "identities": {
                f"id{index}": {"headers": {"Authorization": f"Bearer t{index}"}}
                for index in range(5)
            },
        }), encoding="utf-8")
        inventory = parse_spec(load_spec(spec), source=str(spec))
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(load_config(config, require_checks=False), inventory)
        message = str(caught.exception)
        match = _re.search(
            r"is ([\d,]+) requests \((\d+) operation-specimen rows x (\d+) identities",
            message,
        )
        self.assertIsNotNone(match, message)
        requests = int(match.group(1).replace(",", ""))
        self.assertEqual(int(match.group(2)) * int(match.group(3)), requests)

    def test_a_diagnostic_code_never_runs_into_its_message(self) -> None:
        """`templated_check_path` is exactly the old hard-coded field width, so
        it padded to nothing: `templated_check_pathcheck 'get-org' ...`, 102
        times in one run. The width now comes from the data."""
        from veridor.coverage import render_text  # noqa: PLC0415

        source = Path(ROOT / "src" / "veridor" / "coverage.py").read_text(
            encoding="utf-8")
        self.assertIn("width = max(len(str(entry[\"code\"])) for entry in shown) + 2",
                      source)
        self.assertNotIn('{entry[\'code\']:<20}', source)

    def test_the_unmatched_warning_does_not_rule_out_what_it_has_not_checked(
        self,
    ) -> None:
        """The old text blamed "the base path or the spec"; a config with 102 of
        124 checks unmatched had BOTH correct. The replacement must also
        not assert the base path is fine unless it resolved every check."""
        source = Path(ROOT / "src" / "veridor" / "coverage.py").read_text(
            encoding="utf-8")
        self.assertIn("unsubstituted path", source)
        self.assertIn('matched == report["base_path"]["check_paths"]', source)

    def test_the_zero_declaration_path_does_not_report_a_failure(self) -> None:
        """`veridor: boundary coverage was not measured` used to print on 100%
        of drift runs, with the prefix that means "this command refused", above
        the plan banner. Declaring no checks is what `--for drift` IS."""
        from veridor.coverage import CoverageError  # noqa: PLC0415

        self.assertTrue(hasattr(CoverageError, "reason"))
        source = Path(ROOT / "src" / "veridor" / "cli.py").read_text(encoding="utf-8")
        self.assertIn('== "no_declaration" and not require_checks', source)
        self.assertIn("Nothing is wrong.", source)

    def test_the_oracle_disclosure_describes_a_pass_not_a_declaration(self) -> None:
        """It said "the absence of 'owner''s marker ... was licensed by" on a
        finding where the marker was PRESENT, because it was appended at the top
        of the grading loop before the probe was graded at all."""
        source = Path(ROOT / "src" / "veridor" / "core.py").read_text(encoding="utf-8")
        body = source.split("def _grade_check(", 1)[1].split("\ndef ", 1)[0]
        append_at = body.index("disclosures.append")
        resolve_at = body.index("_resolve_control(")
        self.assertGreater(
            append_at, resolve_at,
            "the disclosure must be appended on the pass path, not at the top "
            "of the loop",
        )
        self.assertIn("probe PASSED", body)


class CachedResponseTest(unittest.TestCase):
    """A cached response cannot license a pass -- the README always said so.

    It was true only for sequences. `VERIDOR-CACHE-001` was emitted from
    exactly one site, in `sequence.py`, while `core._grade_check` -- the grader
    for every single-request check -- never read `from_cache` at all. Both the
    rule's SARIF entry and its remediation text already lived in `core.py`,
    dead. A target that answered the attacker's probe with `Age: 600` got
    "2/2 probes matched their declaration", status `passed`, exit 0.
    """

    def _grade(self, from_cache: bool, scan: str = "absent", status: int = 404):
        check = {
            "id": "iso",
            "request": {"method": "GET", "path": "/doc/1"},
            "expect": {"attacker": {"status": [404], "excludes_marker": "owner"}},
        }
        probes = {
            "attacker": {
                "request": {"method": "GET", "url": "http://t/doc/1"},
                "error": None,
                "response": {
                    "status": status, "marker_scan": scan, "from_cache": from_cache,
                    "marker_scan_reason": None, "marker_encodings": [],
                },
            },
            "owner": {
                "request": {"method": "GET", "url": "http://t/doc/1"},
                "error": None,
                "response": {
                    "status": 200, "marker_scan": "present", "from_cache": False,
                    "marker_scan_reason": None, "marker_encodings": [],
                },
            },
        }
        check["expect"]["owner"] = {"status": [200], "contains_marker": "owner"}
        return core._grade_check(check, probes, Path("veridor.json"))

    def test_a_cached_exclusion_no_longer_passes_silently(self) -> None:
        findings = {f["identity"]: f for f in self._grade(from_cache=True)}
        self.assertIn("attacker", findings)
        self.assertEqual(findings["attacker"]["rule_id"], "VERIDOR-CACHE-001")
        self.assertEqual(findings["attacker"]["verdict"], "inconclusive")
        self.assertIn("served from a cache", findings["attacker"]["message"])

    def test_a_fresh_response_still_passes(self) -> None:
        self.assertEqual(
            [f for f in self._grade(from_cache=False) if f["identity"] == "attacker"],
            [],
        )

    def test_an_observed_marker_outranks_the_cache(self) -> None:
        """A cache cannot make bytes that were on the wire not have been there.
        Placement is load-bearing: this branch sits after the leak branch."""
        findings = {
            f["identity"]: f for f in self._grade(from_cache=True, scan="present")
        }
        self.assertEqual(findings["attacker"]["evidence_grade"], "confirmed")
        self.assertEqual(findings["attacker"]["verdict"], "vulnerable")

    def test_a_status_mismatch_is_never_softened_into_a_warning(self) -> None:
        findings = {
            f["identity"]: f for f in self._grade(from_cache=True, status=200)
        }
        self.assertEqual(findings["attacker"]["level"], "error")

    def test_a_cached_control_licenses_nothing(self) -> None:
        """The other half of the same README sentence: a stale control must not
        license a live exclusion. `sequence.py` has always refused this."""
        from veridor.core import _resolve_control  # noqa: PLC0415

        check = {"expect": {
            "owner": {"status": [200], "contains_marker": "owner"},
            "attacker": {"status": [404], "excludes_marker": "owner"},
        }}
        probes = {"owner": {"response": {"marker_scan": "present", "from_cache": True}}}
        source, state, detail = _resolve_control(check, "owner", probes, {})
        self.assertEqual(source, "check")
        self.assertNotEqual(state, "present")
        self.assertIn("cache", detail)

    def test_a_cached_identity_marker_probe_licenses_nothing(self) -> None:
        """The third site of the same rule. `_execute_marker_controls` issues a
        real request, so the reason function is the testable seam -- and it is
        the string an operator actually reads when their exclusion is refused."""
        from veridor.core import _control_reason  # noqa: PLC0415

        cached = {
            "error": None,
            "response": {
                "status": 200, "marker_scan": "present", "from_cache": True,
                "marker_scan_reason": None,
            },
        }
        reason = _control_reason("owner", "present", cached)
        self.assertIn("answered from a cache", reason)
        self.assertIn("earlier time", reason)

    def test_the_verified_flag_consults_the_cache(self) -> None:
        """`_execute_marker_controls` opens a socket, so this pins the
        condition at the source. Paired with the reason test above, a revert
        cannot pass both."""
        source = Path(ROOT / "src" / "veridor" / "core.py").read_text(encoding="utf-8")
        body = source.split("def _execute_marker_controls(", 1)[1].split(
            "\ndef ", 1)[0]
        self.assertIn('not result["response"]["from_cache"]', body)


class UnsubstitutedPathTest(unittest.TestCase):
    """`run` sent `/api/v1/orgs/{id}` verbatim and called the 404 a finding.

    A freshly scaffolded 250-route config produced 100 findings reading
    "[unexpected_denial] get-org / owner: Identity 'owner' received HTTP 404
    (declared: one of [200]). The target refused this request..." -- with
    nothing anywhere saying the cause was its own placeholder. Meanwhile
    `map` refuses to send `REPLACE-WITH-A-REAL-ID` before opening a socket.
    Two commands, opposite postures, the same mistake.
    """

    def _load(self, path: str, **kwargs):
        config = _config()
        config["checks"][0]["request"]["path"] = path
        return _load(config, **kwargs)

    def test_a_placeholder_is_refused_by_the_verbs_that_send_it(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self._load("/api/v1/orgs/{id}", require_concrete_paths=True)
        message = str(caught.exception)
        self.assertIn("unsubstituted path placeholder", message)
        self.assertIn("/api/v1/orgs/{id}", message)

    def test_every_offender_is_named_at_once(self) -> None:
        """Refusing one at a time would mean 100 runs to enumerate 100 -- the
        complaint `--read-only` already earns."""
        config = _config()
        config["checks"] = [
            {
                "id": f"c{index}",
                "request": {"method": "GET", "path": f"/api/r{index}/{{id}}"},
                "expect": {"owner": {"status": [200]}, "outsider": {"status": [403]}},
            }
            for index in range(4)
        ]
        with self.assertRaises(ConfigError) as caught:
            _load(config, require_concrete_paths=True)
        message = str(caught.exception)
        self.assertIn("4 check(s)", message)
        for index in range(4):
            self.assertIn(f"c{index}", message)

    def test_the_static_verbs_still_read_a_scaffold(self) -> None:
        """`init` writes placeholders deliberately and `coverage` already
        reports them as `templated_check_path` with zero credit. Refusing at
        load time would make the tool's own scaffold unloadable by every
        command -- a worse first five minutes than the defect."""
        self.assertEqual(
            self._load("/api/v1/orgs/{id}")["checks"][0]["request"]["path"],
            "/api/v1/orgs/{id}",
        )

    def test_a_brace_in_a_query_string_is_not_a_placeholder(self) -> None:
        """Matching the whole path+query would refuse a legitimate config --
        the same false-positive class this guard exists to remove."""
        loaded = self._load("/api/search?filter={a}", require_concrete_paths=True)
        self.assertIn("filter=", loaded["checks"][0]["request"]["path"])

    def test_percent_encoded_braces_are_the_escape_hatch(self) -> None:
        """RFC 3986 excludes braces from pchar, so a raw brace in a
        request-target is already malformed. A resource genuinely named with
        braces is spelled %7B / %7D, and that already goes on the wire intact."""
        loaded = self._load("/api/v1/orgs/%7Bid%7D", require_concrete_paths=True)
        self.assertIn("%7Bid%7D", loaded["checks"][0]["request"]["path"])


class UnauthenticatedIdentityTest(unittest.TestCase):
    """A mistyped password produced a fully green build.

    The session never established, every probe as that identity reported
    inconclusive, and the run exited 0 under the default policy -- with the
    attacker's boundary untested. The vacuous guard cannot catch it: the other
    identity answered fine, so "not one probe was answered" is false.

    What makes this gateable where a rate limit is not is that it is
    DETERMINISTIC: the target read the credential and refused it, and it will
    refuse identically tomorrow.
    """

    def test_a_refused_login_is_deterministic(self) -> None:
        from veridor.sequence import is_transient_session_failure as transient  # noqa: PLC0415

        self.assertFalse(transient("login_status_mismatch", 401))
        self.assertFalse(transient("login_status_mismatch", 403))
        self.assertFalse(transient("login_capture_failed", 200))

    def test_a_throttled_or_broken_login_stays_transient(self) -> None:
        """Same rule as a 429 on a probe: it did not decide anything, so it
        must not gate. Otherwise the noise floor comes straight back."""
        from veridor.sequence import is_transient_session_failure as transient  # noqa: PLC0415

        for status in (408, 425, 429, 500, 502, 503):
            with self.subTest(status=status):
                self.assertTrue(transient("login_status_mismatch", status))
        self.assertTrue(transient("login_transport_error", None))

    def _code(self, transient: bool, fail_on: str = "new") -> int:
        import argparse  # noqa: PLC0415

        from veridor.cli import _unauthenticated_identity_exit_code  # noqa: PLC0415

        return _unauthenticated_identity_exit_code(
            argparse.Namespace(fail_on=fail_on),
            {"findings": [{
                "identity": "bob",
                "verdict": "inconclusive",
                "evidence": {"session": {
                    "state": "failed", "reason": "login_status_mismatch (HTTP 401)",
                    "reason_code": "login_status_mismatch", "transient": transient,
                }},
            }]},
        )

    def test_a_deterministic_failure_exits_three(self) -> None:
        self.assertEqual(self._code(transient=False), 3)

    def test_a_transient_failure_does_not_gate(self) -> None:
        self.assertEqual(self._code(transient=True), 0)

    def test_report_only_still_never_fails(self) -> None:
        self.assertEqual(self._code(transient=False, fail_on="none"), 0)

    def test_the_gate_reads_a_field_not_the_prose(self) -> None:
        """The reason string carries a step index and a status; a gate that
        matched on wording would break the first time the message is reflowed.

        The policy moved from cli.py to veridor/gate.py (one computation for
        the exit code and the run document's `gate` object), and the field is
        read by the predicate the exit-code function calls. Docstrings are
        stripped before the check, so prose that MENTIONS the field cannot
        satisfy it."""
        import ast  # noqa: PLC0415

        source = Path(ROOT / "src" / "veridor" / "gate.py").read_text(encoding="utf-8")
        functions = {
            node.name: node for node in ast.parse(source).body
            if isinstance(node, ast.FunctionDef)
        }

        def code_of(name: str) -> str:
            node = functions[name]
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                getattr(body[0], "value", None), ast.Constant
            ):
                body = body[1:]
            return "\n".join(ast.unparse(statement) for statement in body)

        self.assertIn("_unauthenticated_identities(result)",
                      code_of("_unauthenticated_identity_exit_code"))
        predicate = code_of("_unauthenticated_identities")
        self.assertIn("'transient'", predicate)
        self.assertNotIn('.startswith(', predicate)


class DirectRunTest(unittest.TestCase):
    """`python3.12 tests/<this file>` must run every test in it.

    The `__main__` guard sat mid-file, and `unittest.main()` exits, so a
    direct run never defined the classes after it and still reported OK.
    Discovery imports the module, so CI ran them; a developer did not.
    """

    def test_the_main_guard_is_the_last_statement(self) -> None:
        import ast  # noqa: PLC0415

        body = ast.parse(Path(__file__).read_text(encoding="utf-8")).body
        guards = [index for index, node in enumerate(body)
                  if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)]
        self.assertEqual(guards, [len(body) - 1],
                         "unittest.main() runs before the statements after it exist")


if __name__ == "__main__":
    unittest.main()
