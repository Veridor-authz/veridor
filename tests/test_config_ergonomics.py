"""The mistakes a first config makes, and what Veridor says about them.

Everything here came out of the blind-config study
(``scripts/blind_config_study.py``). The study's finding was not that Veridor
crashes on a bad configuration -- it almost never does -- but that three
plausible mistakes were ACCEPTED, and an accepted mistake is the expensive kind.
A refusal costs thirty seconds. A configuration that loads and quietly measures
less than the reader thinks costs them the belief that the tool works.

The three, and why each one is silent rather than loud:

* headers written one level too high. The identity authenticates with nothing,
  so it is probed anonymously under its own name, and a boundary looks held
  because nobody was ever logged in.
* a lower-case method. The safety envelope matches on ``method.upper()`` while
  the request goes out verbatim, so the gate and the wire reason about
  different verbs.
* an identity named in ``matrix.peer_groups`` that does not exist. The rule it
  feeds cannot fire, and a report with no candidates reads as a clean target
  rather than a misconfigured run.
"""

from __future__ import annotations

import copy
import json
import re
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
from veridor.core import ConfigError, load_config  # noqa: E402
from veridor.matrix import MatrixError, plan_matrix  # noqa: E402
from veridor.openapi import load_spec, parse_spec  # noqa: E402

BASE = {
    "version": 1,
    "target": {"base_url": "http://127.0.0.1:8765"},
    "identities": {
        "owner": {"headers": {"Authorization": "Bearer owner-token"}},
        "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
    },
    "checks": [
        {
            "id": "c", "name": "n",
            "request": {"method": "GET", "path": "/api/invoices/inv-100"},
            "expect": {"owner": {"status": [200]}, "outsider": {"status": [404]}},
        }
    ],
}


def _load(config: dict, **kwargs):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return load_config(path, **kwargs)


class MisplacedHeadersTest(unittest.TestCase):
    def test_credentials_one_level_too_high_are_refused(self) -> None:
        config = copy.deepcopy(BASE)
        config["identities"] = {
            "owner": {"Authorization": "Bearer owner-token"},
            "outsider": {"Authorization": "Bearer outsider-token"},
        }
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        message = str(caught.exception)
        self.assertIn("probed anonymously under its own name", message)
        # The fix has to be in the message, shaped like the file it goes in.
        self.assertIn('"headers"', message)
        self.assertIn("Authorization", message)

    def test_a_deliberately_anonymous_identity_is_accepted(self) -> None:
        """`"headers": {}` is how you say "this one carries no credentials",
        and it must stay distinguishable from having forgotten them."""
        config = copy.deepcopy(BASE)
        config["identities"]["anonymous"] = {"headers": {}}
        self.assertEqual(_load(config)["identities"]["anonymous"]["headers"], {})

    def test_an_annotation_beside_real_keys_is_still_accepted(self) -> None:
        """Unrecognised keys stay legal as annotations. Only an identity with
        NOTHING recognisable is a mistake."""
        config = copy.deepcopy(BASE)
        config["identities"]["owner"]["note"] = "the tenant that owns inv-100"
        self.assertIn("note", _load(config)["identities"]["owner"])

    def test_an_underscore_annotation_alone_is_not_treated_as_credentials(self) -> None:
        config = copy.deepcopy(BASE)
        config["identities"]["owner"] = {"_comment": "TODO: add a token"}
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        # It is still refused -- it authenticates with nothing -- but as an
        # identity that defines none of the real keys, not as a typo.
        self.assertIn("defines none of", str(caught.exception))


class CheckKeyTypoTest(unittest.TestCase):
    """A misspelt check key is named, with the keys a check takes.

    ``"expectt"`` was refused as "check 'c' must expect results for at least
    two users": true of the check once the typo had dropped its expectations,
    and no help to someone who had declared two. A misspelt ``request`` was
    reported as a missing request, and ``descriptionn`` loaded silently.
    """

    def _refusal(self, **keys: object) -> str:
        config = copy.deepcopy(BASE)
        check = config["checks"][0]
        for old, new in keys.items():
            check[new] = check.pop(old) if old in check else "x"
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        return str(caught.exception)

    def test_a_misspelt_expect_names_the_key_and_the_allowed_keys(self) -> None:
        message = self._refusal(expect="expectt")
        self.assertIn("check 'c' has unsupported keys: expectt", message)
        self.assertIn("description, expect, id, name, request", message)
        self.assertNotIn("at least two users", message)

    def test_other_slips_are_named_too(self) -> None:
        for old, new in (("request", "reqeust"), ("name", "Name"),
                         ("description", "descriptionn")):
            with self.subTest(key=new):
                message = self._refusal(**{old: new})
                self.assertIn(f"unsupported keys: {new}", message)
                self.assertIn("did you mean one of", message)

    def test_a_check_with_no_id_is_still_named(self) -> None:
        config = copy.deepcopy(BASE)
        check = config["checks"][0]
        check["Id"] = check.pop("id")
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        self.assertIn("a check has unsupported keys: Id", str(caught.exception))

    def test_control_annotations_and_real_keys_still_load(self) -> None:
        """Unrelated keys stay annotations, as they are on every other block,
        and `_` keeps a near-miss as one deliberately."""
        config = copy.deepcopy(BASE)
        config["checks"][0].update(
            description="owner reads, outsider is refused",
            notes="added after the 2026 incident", _expectt="kept on purpose",
        )
        loaded = _load(config)
        self.assertEqual(loaded["checks"][0]["id"], "c")
        # The two-user rule is unchanged for a check that really declares one.
        config = copy.deepcopy(BASE)
        del config["checks"][0]["expect"]["outsider"]
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        self.assertIn("at least two users", str(caught.exception))


class MethodCaseTest(unittest.TestCase):
    def test_a_lower_case_method_is_refused_with_the_replacement(self) -> None:
        for written, wanted in (("get", "GET"), ("post", "POST"), ("delete", "DELETE")):
            with self.subTest(method=written):
                config = copy.deepcopy(BASE)
                config["checks"][0]["request"]["method"] = written
                with self.assertRaises(ConfigError) as caught:
                    _load(config)
                self.assertIn(f"write {wanted!r}", str(caught.exception))

    def test_an_upper_case_method_is_untouched(self) -> None:
        for method in ("GET", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                config = copy.deepcopy(BASE)
                config["checks"][0]["request"]["method"] = method
                self.assertEqual(
                    _load(config)["checks"][0]["request"]["method"], method)

    def test_a_marker_in_the_method_slot_is_still_a_marker_leak(self) -> None:
        """Ordering. A marker is mixed case, so a naive casing check would
        pre-empt the reflection guard and report a leak as a style problem.
        Upper-casing instead of refusing would be worse still: it would destroy
        the string the guard exists to find."""
        marker = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
        config = copy.deepcopy(BASE)
        config["identities"]["owner"]["marker"] = marker
        config["checks"][0]["request"]["method"] = marker
        with self.assertRaises(ConfigError) as caught:
            _load(config)
        self.assertIn("appears in the request sent by check", str(caught.exception))


class MatrixIdentityReferenceTest(unittest.TestCase):
    """A name that cannot resolve is part of the plan, so it is refused with
    the plan -- before a single request, not after a full probe."""

    def setUp(self) -> None:
        spec = ROOT / "fixtures" / "openapi.demo.json"
        self.inventory = parse_spec(load_spec(spec), source=str(spec))
        self.config = copy.deepcopy(BASE)
        self.config["matrix"] = {
            "specimens": {
                "/api/invoices/{id}": [{"label": "inv", "values": {"id": "inv-100"}}]
            }
        }

    def _plan(self, matrix: dict):
        config = copy.deepcopy(self.config)
        config["matrix"].update(matrix)
        loaded = _load(config, require_checks=False)
        return plan_matrix(loaded, self.inventory)

    def test_every_section_that_names_an_identity_is_checked(self) -> None:
        for section in (
            {"peer_groups": {"tenants": ["owner", "ghost"]}},
            {"privilege_order": ["outsider", "ghost"]},
            {"unauthenticated": "ghost"},
            {"marker_owner": "ghost"},
        ):
            with self.subTest(section=sorted(section)):
                with self.assertRaises(MatrixError) as caught:
                    self._plan(section)
                message = str(caught.exception)
                self.assertIn("'ghost'", message)
                # Naming the alternatives is what turns a typo into a one-line
                # fix rather than a re-read of the documentation.
                self.assertIn("owner", message)
                self.assertIn("outsider", message)

    def test_valid_references_still_plan(self) -> None:
        self.config["identities"]["owner"]["marker"] = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
        plan = self._plan({
            "peer_groups": {"tenants": ["owner", "outsider"]},
            "privilege_order": ["outsider", "owner"],
            "marker_owner": "owner",
        })
        self.assertGreater(len(plan.probes), 0)

    def test_the_refusal_happens_at_plan_time(self) -> None:
        """`plan_matrix` issues nothing by construction, so a refusal raised
        from it cannot have cost anybody a probe. `blastradius.peer_groups`
        still guards the same thing, but it runs on a finished matrix."""
        with self.assertRaises(MatrixError):
            self._plan({"peer_groups": {"tenants": ["ghost"]}})


@slow("runs the blind-config study as a subprocess")
class BlindConfigStudyTest(unittest.TestCase):
    """The study is a regression guard, not a one-off measurement.

    Its findings were only findable because nothing else in this repository
    fails when the documentation drifts. Running it here means a README edit
    that drops a key, or breaks a documented example, fails the build like any
    other defect.
    """

    def test_the_study_reports_no_gaps(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "blind_config_study.py")],
            cwd=ROOT, capture_output=True, text=True,
        )
        # The report is the diagnosis: it goes in both messages, and the text
        # is checked first. The study writes nothing to stderr on a gap.
        report = "the blind-config study found a gap:\n" + result.stdout + result.stderr
        self.assertIn("TOTAL GAPS: 0", result.stdout, report)
        self.assertEqual(result.returncode, 0, report)


class BlindConfigSyntaxTest(unittest.TestCase):
    """A documented configuration with a JSON syntax error is a gap.

    Every ```json block that failed json.loads was classed a `fragment`, and
    fragments count toward nothing, so doubling a comma in the README's one
    complete run config turned "2/2 load, TOTAL GAPS: 0" into "1/1 load,
    TOTAL GAPS: 0": the broken example left the denominator and the study
    stayed green -- the most common way a documented example breaks.
    """

    @staticmethod
    def _study(readme: str) -> tuple[int, str]:
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        from scripts import blind_config_study  # noqa: PLC0415

        original = blind_config_study.README
        blind_config_study.README = readme
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                code = blind_config_study.main([])
        finally:
            blind_config_study.README = original
        return code, stdout.getvalue()

    @staticmethod
    def _readme() -> str:
        return (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")

    def _broken(self) -> tuple[str, int]:
        """The README with the first comma of its first complete run config
        doubled, and that block's index."""
        readme = self._readme()
        blocks = list(re.finditer(r"```json\n(.*?)```", readme, re.DOTALL))
        for index, block in enumerate(blocks):
            document = json.loads(block.group(1)) if block.group(1).lstrip().startswith("{") else None
            if isinstance(document, dict) and {"version", "target", "identities", "checks"} <= set(document):
                comma = block.start(1) + block.group(1).index(",")
                return readme[:comma] + ",," + readme[comma + 1:], index
        self.fail("the README has no complete run configuration")

    def test_a_syntax_error_in_a_complete_example_is_a_gap(self) -> None:
        readme, index = self._broken()
        code, text = self._study(readme)
        self.assertNotIn("TOTAL GAPS: 0", text)
        self.assertIn(f"BROKEN block {index}: not valid JSON", text)

    def test_a_gap_fails_the_exit_code(self) -> None:
        """main() returned 0 whatever it counted, so the script run by hand
        exited 0 above "TOTAL GAPS: 1"; only the text check in
        BlindConfigStudyTest enforced it."""
        readme, _index = self._broken()
        code, text = self._study(readme)
        self.assertIn("TOTAL GAPS: 1", text)
        self.assertEqual(code, 1, text)

    def test_the_ci_gate_names_the_broken_block_when_it_fails(self) -> None:
        """BlindConfigStudyTest is what CI runs, so its failure message is the
        whole diagnosis anyone sees. Once the study exited 1 on a gap, the
        exit-code assertion fired before the text check, with the study's
        stderr -- empty -- as its message: CI printed "1 != 0 : " and nothing
        about which block was broken."""
        from unittest import mock  # noqa: PLC0415

        readme, index = self._broken()
        code, text = self._study(readme)
        self.assertEqual(code, 1, text)  # the precondition: the study did fail
        report = subprocess.CompletedProcess([], code, stdout=text, stderr="")
        result = unittest.TestResult()
        with mock.patch.object(subprocess, "run", return_value=report):
            BlindConfigStudyTest("test_the_study_reports_no_gaps").run(result)
        self.assertEqual(len(result.failures), 1, result.failures + result.errors)
        self.assertIn(f"BROKEN block {index}: not valid JSON", result.failures[0][1])

    def test_the_readme_as_shipped_has_no_gap(self) -> None:
        """The control: the deliberate fragments (`"matrix": {...}` and the
        like) are still fragments, not gaps."""
        code, text = self._study(self._readme())
        self.assertIn("TOTAL GAPS: 0", text, text)
        self.assertNotIn("not valid JSON", text)
        self.assertEqual(code, 0, text)


class TransportDiagnosisTest(unittest.TestCase):
    """A timeout and a refused connection are different problems.

    The generic advice -- "confirm the target is reachable from the runner" --
    fits the second and misleads on the first. Measured against a healthy target
    answering in 2.5s with `timeout_seconds: 1`, every probe reported it, which
    sends an operator to their firewall rules when the fix is one number in
    their own configuration.
    """

    def _remediation(self, error: str, timeout: int = 1) -> str:
        from veridor.core import _transport_remediation  # noqa: PLC0415

        return _transport_remediation(error, {"timeout_seconds": timeout})

    def test_a_timeout_names_the_setting_and_its_current_value(self) -> None:
        # The measured case above: the target accepted the connection and was
        # slow, which the engine now records as a response-phase timeout. This
        # used to pass a bare "timed out" and assert "not a reachability
        # problem" -- advice every timeout got, including a connect timeout
        # where nothing was reached (tests/test_core.py TimeoutAdviceTest).
        advice = self._remediation(
            "timed out waiting for a response: a TCP connection was established "
            "and the request written, but no response arrived within 3s",
            timeout=3,
        )
        self.assertIn("target.timeout_seconds", advice)
        self.assertIn("3s", advice)
        self.assertIn("raise that value", advice)
        # And says what was measured, because the firewall is the wrong turning.
        self.assertIn("connection was established", advice)

    def test_a_refused_connection_is_not_blamed_on_the_timeout(self) -> None:
        advice = self._remediation("[Errno 61] Connection refused")
        self.assertNotIn("timeout_seconds", advice)
        self.assertIn("Nothing was listening", advice)

    def test_dns_and_tls_get_their_own_answers(self) -> None:
        # One resolver failure, three C libraries' words for it: macOS, glibc,
        # and musl, which the release image runs on (measured there as
        # "[Errno -2] Name does not resolve").
        for said in ("nodename nor servname provided", "[Errno -2] Name or service not known",
                     "[Errno -2] Name does not resolve"):
            with self.subTest(said):
                self.assertIn("did not resolve", self._remediation(said))
        self.assertIn("TLS", self._remediation("certificate verify failed"))

    def test_an_unrecognised_error_keeps_the_general_advice(self) -> None:
        """A wrong specific guess is worse than an honest general one."""
        self.assertIn("Confirm the target is reachable",
                      self._remediation("something nobody anticipated"))


class BudgetRefusalTest(unittest.TestCase):
    """The first wall a real-sized API hits, so its message is load-bearing.

    200 collection routes x 4 identities is 800 requests, over the 500 default,
    and the refusal is the entire first impression. It gets the arithmetic, the
    wall-clock cost and three named remedies right -- but it told the operator
    to raise the budget "with max_requests=800", which is the keyword this
    module takes and not the flag they are holding a command line for.

    `RemediationFlagTest` cannot catch this one: it scans for `--flags` that do
    not exist, and the broken form contains no `--` at all. A message that
    should name a flag and does not is invisible to that guard, so it is pinned
    here directly.
    """

    def _refusal(self, identities: int, operations: int) -> str:
        import json as _json  # noqa: PLC0415
        import tempfile as _tempfile  # noqa: PLC0415

        from veridor.core import load_config  # noqa: PLC0415

        directory = Path(_tempfile.mkdtemp())
        spec = directory / "openapi.json"
        spec.write_text(_json.dumps({
            "openapi": "3.0.3", "info": {"title": "B", "version": "1"},
            "servers": [{"url": "http://127.0.0.1:8765"}],
            "paths": {
                f"/api/r{index}": {"get": {"responses": {"200": {"description": "ok"}}}}
                for index in range(operations)
            },
        }), encoding="utf-8")
        config = directory / "veridor.json"
        config.write_text(_json.dumps({
            "version": 1, "target": {"base_url": "http://127.0.0.1:8765"},
            "identities": {
                f"id{index}": {"headers": {"Authorization": f"Bearer t{index}"}}
                for index in range(identities)
            },
        }), encoding="utf-8")
        inventory = parse_spec(load_spec(spec), source=str(spec))
        with self.assertRaises(MatrixError) as caught:
            plan_matrix(load_config(config, require_checks=False), inventory)
        return str(caught.exception)

    def test_the_remedy_is_a_flag_the_operator_can_paste(self) -> None:
        message = self._refusal(identities=4, operations=200)
        self.assertIn("--max-requests 800", message)
        self.assertNotIn("max_requests=", message)

    def test_the_refusal_shows_its_arithmetic_and_its_cost(self) -> None:
        """A budget refusal without the numbers is a wall with no door."""
        message = self._refusal(identities=4, operations=200)
        self.assertIn("800 requests", message)
        self.assertIn("200 operation-specimen rows x 4 identities", message)
        self.assertIn("Nothing has been sent", message)
        self.assertIn("would take", message)

    def test_it_offers_narrowing_before_raising(self) -> None:
        """Raising the ceiling is the last resort, not the first suggestion."""
        message = self._refusal(identities=4, operations=200)
        self.assertLess(message.index("Narrow"), message.index("--max-requests"))


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
