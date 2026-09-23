"""Mutation engine tests.

Every positive test here is a deliberately vacuous configuration -- a check that
passes green against the fixture target and proves nothing -- paired with the
operator that must catch it. The negative control is the one that matters most:
a genuinely good check must score 1.0. An engine that flags everything as
vacuous is exactly as useless as one that flags nothing, and only the pair of
assertions distinguishes the two.

The remaining tests hold the engine to the rules it must not bend: mutation
results never reach the findings list, the SARIF document, or the run's exit
code; the target is never mutated in tier 1; no credential and no response body
reaches the report; and an unauthenticated request is never sent for a mutating
verb.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import io
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "fixtures"))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import graded_vacuity_fixture as graded  # noqa: E402
import tier2_guard_toggle as guard_toggle  # noqa: E402
import veridor_mutation_fixture as shipped_fixture  # noqa: E402

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import core, coverage, mutation  # noqa: E402
from veridor.core import ConfigError  # noqa: E402
from veridor_mutation_fixture import (  # noqa: E402
    ECHO_SECRET,
    ORDER_OWNER_MARKER,
    WIDE_OWNER_MARKER,
)
from veridor_mutation_principal_fixture import (  # noqa: E402
    OTHER_TENANT_MARKER,
    ROLELESS_TOKEN,
    create_server,
)

DEMO_CONFIG = ROOT / "fixtures" / "veridor.mutation-demo.json"


def prose(text: str) -> str:
    """Read rendered output the way a reader does, not the way it is wrapped."""
    return re.sub(r"\s+", " ", text)


@slow("stands up a loopback HTTP server and runs the engine against it")
class _FixtureTarget(unittest.TestCase):
    """A live fixture API, shared by every test in the module.

    The server is ``veridor_mutation_principal_fixture``, a superset of the
    shipped one: every vacuity route is inherited unchanged, and
    ``/api/orders/o-1`` additionally tells a credential it does not recognise
    apart from a principal it does. That distinction is what ``M6`` measures, so
    a target that does not make it cannot host the engine's negative control --
    see :class:`IndistinguishablePrincipalTest`, which runs the SHIPPED fixture
    to hold the opposite case.
    """

    guard_dir: tempfile.TemporaryDirectory
    guard_path: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.guard_dir = tempfile.TemporaryDirectory()
        cls.guard_path = Path(cls.guard_dir.name) / "tenant-guard"
        cls.guard_path.write_text("present\n", encoding="utf-8")
        cls.server = create_server("127.0.0.1", 0, guard_path=cls.guard_path)
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.guard_dir.cleanup()

    def setUp(self) -> None:
        self.guard_path.write_text("present\n", encoding="utf-8")
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.workspace = Path(self._workspace.name)

    # -- helpers ------------------------------------------------------------

    def write(self, config: dict, name: str = "config.json") -> Path:
        path = self.workspace / name
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return path

    def analyze(self, config: dict, **kwargs) -> dict:
        return mutation.analyze(self.write(config), base_url=self.base_url, **kwargs)

    def mutants(self, report: dict, operator: str, identity: str | None = None):
        found = [
            mutant
            for check in report["checks"]
            for mutant in check["mutants"]
            if mutant["operator"] == operator
            and (identity is None or mutant["identity"] == identity)
        ]
        self.assertTrue(found, f"no {operator} mutant for identity {identity!r}")
        return found

    def outcome(self, report: dict, operator: str, identity: str | None = None) -> str:
        found = self.mutants(report, operator, identity)
        self.assertEqual(len(found), 1, f"expected one {operator} mutant, got {found}")
        return found[0]["outcome"]

    # -- configuration shorthands -------------------------------------------

    def base(self, identities: dict, checks: list) -> dict:
        return {
            "version": 1,
            "target": {"base_url": self.base_url, "timeout_seconds": 5},
            "identities": identities,
            "checks": checks,
        }

    def good_config(self) -> dict:
        """The negative control: a check that can actually fail."""
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"},
                    "marker": ORDER_OWNER_MARKER,
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
                "anonymous": {"headers": {}},
            },
            [
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
        )


class GenuinelyGoodCheckTest(_FixtureTarget):
    """The negative control. Everything must be killed and the score must be 1.0."""

    def test_every_operator_is_killed(self) -> None:
        report = self.analyze(self.good_config())
        self.assertEqual(report["survivors"], [])
        self.assertEqual(report["summary"]["score"], 1.0)
        self.assertEqual(report["summary"][mutation.SURVIVED], 0)
        self.assertEqual(report["summary"][mutation.ABERRANT], 0)
        self.assertEqual(report["summary"][mutation.ERRORED], 0)
        self.assertEqual(mutation.exit_code(report), 0)

    def test_each_operator_actually_ran(self) -> None:
        """A score of 1.0 earned by generating nothing would be a lie."""
        report = self.analyze(self.good_config())
        operators = {
            mutant["operator"]
            for check in report["checks"]
            for mutant in check["mutants"]
            if mutant["outcome"] in {mutation.KILLED, mutation.SURVIVED}
        }
        self.assertEqual(operators, {"M1", "M2", "M3", "M4", "M5", "M6"})

    def test_the_marker_operator_is_killed_where_the_marker_can_be_seen(self) -> None:
        """The exclusion is killed; the contains assertion is not mutated at all.

        A contains_marker fails the moment the marker is absent, so a passing
        one has already shown its oracle fires. Mutating it could only produce a
        kill that was guaranteed before the mutant existed.
        """
        report = self.analyze(self.good_config())
        self.assertEqual(self.outcome(report, "M3", "outsider"), mutation.KILLED)
        owner = self.mutants(report, "M3", "order_owner")[0]
        self.assertEqual(owner["outcome"], mutation.NOT_APPLICABLE)
        self.assertIn("falsifiable by construction", owner["diagnosis"])

    def test_the_exclusion_kill_records_where_the_marker_was_seen(self) -> None:
        report = self.analyze(self.good_config())
        killed = self.mutants(report, "M3", "outsider")[0]
        self.assertTrue(killed["marker_observable_at_path"])
        self.assertIn(killed["marker_control_source"], {"check", "check_observed"})

    def test_the_good_config_has_no_limits_on_its_evidence(self) -> None:
        """M3's structural not_applicable is bookkeeping, not a limit.

        Measured before the fix: this config printed "0.89 of 9 generated +
        limited (1 could not be evaluated)" over an empty LIMITS block, and
        ``mutate --require-evaluable`` exited 3 on it.
        """
        report = self.analyze(self.good_config())
        self.assertEqual(report["summary"]["limited"], 0)
        self.assertNotIn("could not be evaluated", mutation.render_text(report))

    def test_an_identity_with_no_credential_is_skipped_not_scored(self) -> None:
        """M4 has nothing to strip from an anonymous identity."""
        report = self.analyze(self.good_config())
        self.assertEqual(self.outcome(report, "M4", "anonymous"), mutation.SKIPPED)
        self.assertEqual(self.outcome(report, "M4", "order_owner"), mutation.KILLED)


class InvalidCredentialTest(_FixtureTarget):
    """Both identities get 401 because neither is authenticated."""

    def config(self) -> dict:
        return self.base(
            {
                "stale_reader": {
                    "headers": {"Authorization": "Bearer report-tokne"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "report-access",
                    "request": {"method": "GET", "path": "/api/reports/r-9"},
                    "expect": {
                        "stale_reader": {"status": [401]},
                        "outsider": {"status": [401]},
                    },
                }
            ],
        )

    def test_the_run_itself_is_green(self) -> None:
        """The premise: this vacuous check passes, which is why it is dangerous."""
        result = core.execute_run(
            self.write(self.config()),
            output_dir=self.workspace / "out",
            base_url=self.base_url,
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "passed")

    def test_strip_credential_survives_for_both_identities(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(self.outcome(report, "M4", "stale_reader"), mutation.SURVIVED)
        self.assertEqual(self.outcome(report, "M4", "outsider"), mutation.SURVIVED)
        self.assertEqual(mutation.exit_code(report), 1)

    def test_the_diagnosis_names_the_defect(self) -> None:
        report = self.analyze(self.config())
        diagnosis = self.mutants(report, "M4", "stale_reader")[0]["diagnosis"]
        self.assertIn("not authenticated", diagnosis)
        self.assertIn("cannot distinguish identities", diagnosis)
        self.assertIn("may be vacuous", diagnosis)

    def test_a_one_sided_invalid_token_is_caught_too(self) -> None:
        """The sharper real case: the owner works, only the attacker is stale."""
        config = self.base(
            {
                "report_owner": {"headers": {"Authorization": "Bearer report-token"}},
                "stale_outsider": {
                    "headers": {"Authorization": "Bearer outsider-tokne"}
                },
            },
            [
                {
                    "id": "report-boundary",
                    "request": {"method": "GET", "path": "/api/reports/r-9"},
                    "expect": {
                        "report_owner": {"status": [200]},
                        "stale_outsider": {"status": [401]},
                    },
                }
            ],
        )
        report = self.analyze(config)
        self.assertEqual(self.outcome(report, "M4", "report_owner"), mutation.KILLED)
        self.assertEqual(
            self.outcome(report, "M4", "stale_outsider"), mutation.SURVIVED
        )
        # The positive control holds -- the route does serve somebody -- so the
        # only thing wrong here is the attacker's credential.
        self.assertEqual(self.outcome(report, "M5"), mutation.KILLED)


class MissingResourceTest(_FixtureTarget):
    """A route that 404s for everyone. The attacker's 404 proves nothing."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "ghost-isolation",
                    "request": {"method": "GET", "path": "/api/ghost/g-1"},
                    "expect": {
                        "order_owner": {"status": [404]},
                        "outsider": {"status": [404]},
                    },
                }
            ],
        )

    def test_positive_control_survives(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(self.outcome(report, "M5"), mutation.SURVIVED)

    def test_the_diagnosis_explains_what_a_404_here_is_worth(self) -> None:
        report = self.analyze(self.config())
        diagnosis = self.mutants(report, "M5")[0]["diagnosis"]
        self.assertIn("no identity in this check received a successful response", diagnosis)
        self.assertIn("absent route", diagnosis)
        self.assertNotIn("vulnerab", diagnosis)

    def test_the_positive_control_is_killed_when_the_route_serves_someone(self) -> None:
        report = self.analyze(self.good_config())
        killed = self.mutants(report, "M5")[0]
        self.assertEqual(killed["outcome"], mutation.KILLED)
        self.assertEqual(killed["positive_control"], "order_owner")


class OverWideExpectationTest(_FixtureTarget):
    """`[200, 403, 404]` over a route that really does serve the outsider."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "widget-read",
                    "request": {"method": "GET", "path": "/api/wide/w-1"},
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [200, 403, 404]},
                    },
                }
            ],
        )

    def test_the_run_itself_is_green_despite_the_cross_tenant_read(self) -> None:
        result = core.execute_run(
            self.write(self.config()),
            output_dir=self.workspace / "out",
            base_url=self.base_url,
        )
        self.assertEqual(result["findings"], [])

    def test_invert_denial_survives(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(self.outcome(report, "M1", "outsider"), mutation.SURVIVED)

    def test_the_diagnosis_names_the_status_that_was_accepted(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M1", "outsider")[0]
        self.assertEqual(mutant["observed_status"], 200)
        self.assertEqual(mutant["mutant_statuses"], [200])
        self.assertIn("cannot tell allowed from denied", mutant["diagnosis"])

    def test_invert_denial_is_killed_when_the_attacker_is_really_denied(self) -> None:
        report = self.analyze(self.good_config())
        self.assertEqual(self.outcome(report, "M1", "outsider"), mutation.KILLED)


class MarkerFreeCheckTest(_FixtureTarget):
    """A status-only check. There is no data-flow evidence to drop."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "settings-read",
                    "request": {"method": "GET", "path": "/api/settings/s-1"},
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [403]},
                    },
                }
            ],
        )

    def test_status_only_evidence_is_a_property_not_a_mutant(self) -> None:
        """It cannot be killed, so it must not sit in the score.

        The old ``absent`` mutant was SURVIVED by construction: there is nothing
        to drop, so no mutation of it could ever change a verdict. That put an
        unkillable entry in the denominator, repeated one identical paragraph
        per marker-less check at the top of the survivor list, and on a DELETE
        answering 204 asked for a marker the operator cannot supply.
        """
        report = self.analyze(self.config())
        check = report["checks"][0]
        self.assertEqual(check["marker_evidence"], "status_only")
        self.assertEqual(check["marker_assertions"], [])
        self.assertEqual(
            [mutant for mutant in check["mutants"] if mutant["operator"] == "M3"], []
        )
        self.assertNotIn(
            "M3", {mutant["operator"] for mutant in report["survivors"]}
        )

    def test_the_note_says_the_proof_was_status_only(self) -> None:
        report = self.analyze(self.config())
        note = report["checks"][0]["marker_note"]
        self.assertIn("only evidence is the status code", note)
        self.assertIn("contains_marker", note)
        self.assertIn("LIMITS ON THE EVIDENCE", mutation.render_text(report))
        self.assertIn(note.split(".")[0], prose(mutation.render_text(report)))

    def test_a_bodiless_operation_is_not_asked_for_an_impossible_marker(self) -> None:
        """A DELETE answering 204 cannot carry a marker. Do not ask for one."""
        config = self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "settings-read-204",
                    "request": {"method": "GET", "path": "/api/settings/s-1"},
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [403]},
                    },
                }
            ],
        )
        report = self.analyze(config)
        served = report["checks"][0]
        self.assertEqual(served["marker_evidence"], "status_only")
        # This fixture route does return a body, so the actionable remediation
        # is the one that applies. The bodiless branch is asserted directly,
        # because no fixture route answers 204.
        self.assertIn("Add contains_marker", served["marker_note"])
        bodiless = mutation._marker_evidence(
            mutation._Observation(
                check={"id": "x", "expect": {"a": {"status": [204]}}},
                probes={
                    "a": {
                        "error": None,
                        "response": {"status": 204, "body_bytes": 0},
                    }
                },
                findings={},
            )
        )
        self.assertIn("nothing here to mark", bodiless["marker_note"])
        self.assertNotIn("Add contains_marker", bodiless["marker_note"])

    def test_the_rest_of_the_check_still_discriminates(self) -> None:
        """A status-only check is weak, not worthless; do not overstate it."""
        report = self.analyze(self.config())
        self.assertEqual(self.outcome(report, "M1", "outsider"), mutation.KILLED)
        self.assertEqual(self.outcome(report, "M2", "order_owner"), mutation.KILLED)
        self.assertEqual(self.outcome(report, "M4", "outsider"), mutation.KILLED)


class PermissiveAllowTest(_FixtureTarget):
    """`[200, 403]` for the owner: nobody would notice the owner losing access."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "wrong_owner": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "settings-owner-access",
                    "request": {"method": "GET", "path": "/api/settings/s-1"},
                    "expect": {
                        "order_owner": {"status": [200]},
                        # Declared to succeed, actually refused, and the
                        # declaration accepts both.
                        "wrong_owner": {"status": [200, 403]},
                    },
                }
            ],
        )

    def test_invert_allow_survives(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M2", "wrong_owner")[0]
        self.assertEqual(mutant["outcome"], mutation.SURVIVED)
        self.assertIn("losing access", mutant["diagnosis"])

    def test_invert_allow_is_killed_for_an_owner_that_is_really_served(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(self.outcome(report, "M2", "order_owner"), mutation.KILLED)


class AberrantOutcomeTest(_FixtureTarget):
    """A verdict that changes the WRONG way is not a kill."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "backwards-policy",
                    "request": {"method": "GET", "path": "/api/backwards/b-1"},
                    "expect": {
                        "order_owner": {"status": [403]},
                        "outsider": {"status": [403]},
                    },
                }
            ],
        )

    def test_a_more_permissive_anonymous_response_is_aberrant(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M4", "order_owner")[0]
        self.assertEqual(mutant["outcome"], mutation.ABERRANT)
        self.assertEqual(mutant["observed_status"], 403)
        self.assertEqual(mutant["uncredentialed_status"], 200)
        self.assertIn("MORE permissive", mutant["diagnosis"])

    def test_aberrant_is_not_counted_as_killed(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(report["summary"][mutation.ABERRANT], 2)
        self.assertIn(
            mutation.ABERRANT, {mutant["outcome"] for mutant in report["survivors"]}
        )
        self.assertEqual(mutation.exit_code(report), 2)


class IsolationTest(_FixtureTarget):
    """Rule 1 and rule 2: no findings, no SARIF, no target mutation."""

    def test_a_mutation_report_carries_no_findings_and_no_sarif_keys(self) -> None:
        report = self.analyze(self.good_config())
        self.assertNotIn("findings", report)
        self.assertNotIn("regression", report)
        self.assertNotIn("probes", report)
        # No rule id, either. A rule id names a FINDING, and CI greps logs: a
        # healthy suite echoing VERIDOR-AUTHZ-001 eight times is the false alarm
        # this whole module exists to avoid.
        serialized = json.dumps(report)
        self.assertNotIn("VERIDOR-", serialized)

    def test_killed_mutants_never_reach_the_run_or_its_exit_code(self) -> None:
        """The same config, run both ways. The run must not notice the mutants."""
        config_path = self.write(self.good_config())
        report = mutation.analyze(config_path, base_url=self.base_url)
        self.assertEqual(report["summary"][mutation.KILLED], 8)

        result = core.execute_run(
            config_path, output_dir=self.workspace / "out", base_url=self.base_url
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["vulnerable"], 0)
        self.assertEqual(result["summary"]["inconclusive"], 0)
        self.assertEqual(core.to_sarif(result)["runs"][0]["results"], [])

    def test_a_surviving_mutant_does_not_turn_a_green_run_red(self) -> None:
        config_path = self.write(MissingResourceTest.config(self))
        report = mutation.analyze(config_path, base_url=self.base_url)
        self.assertEqual(mutation.exit_code(report), 1)

        result = core.execute_run(
            config_path, output_dir=self.workspace / "out", base_url=self.base_url
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["findings"], [])
        self.assertEqual(core.to_sarif(result)["runs"][0]["results"], [])

    def test_the_configuration_file_is_never_written(self) -> None:
        config_path = self.write(self.good_config())
        before = config_path.read_bytes()
        mutation.analyze(config_path, base_url=self.base_url)
        self.assertEqual(config_path.read_bytes(), before)

    def test_the_loaded_check_is_never_mutated_in_place(self) -> None:
        config = core.load_config(self.write(self.good_config()))
        config["target"]["base_url"] = self.base_url
        # One budget for both halves: it rate-limits the baseline probes and
        # charges only the additional ones. See _Budget.
        budget = mutation._Budget(None, 0.0)
        observations, controls, _, _ = mutation._observe(
            config, Path("config.json"), budget
        )
        snapshot = json.dumps(config["checks"], sort_keys=True)
        context = mutation._Context(
            config=config,
            config_path=Path("config.json"),
            marker_controls=controls,
            budget=budget,
            sham_token="veridor-sham-test",
        )
        for observation in observations:
            mutation._mutate_check(context, observation)
        self.assertEqual(json.dumps(config["checks"], sort_keys=True), snapshot)

    def test_the_report_states_that_the_target_is_never_altered(self) -> None:
        report = self.analyze(self.good_config())
        statement = report["interpretation"]["statement"]
        self.assertIn("The target is observed, never altered.", statement)
        self.assertIn("Nothing in this report is a finding", statement)
        self.assertIn("may be vacuous", mutation.render_text(report).lower())


class NoSecretsInArtifactsTest(_FixtureTarget):
    """Rule 4. The fixture hands back both a credential and a body; grep for them."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {
                        "Authorization": "Bearer order-owner-token",
                        "Cookie": "session=super-secret-cookie-value",
                    },
                    "marker": ORDER_OWNER_MARKER,
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "echo-reflection",
                    "request": {
                        "method": "GET",
                        "path": "/api/echo",
                        "headers": {"X-Api-Key": "request-level-api-key"},
                    },
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [200]},
                    },
                }
            ],
        )

    def test_no_credential_and_no_body_reaches_the_report(self) -> None:
        report = self.analyze(self.config())
        serialized = json.dumps(report)
        for secret in (
            "order-owner-token",
            "outsider-token",
            "super-secret-cookie-value",
            "request-level-api-key",
            ECHO_SECRET,
            ORDER_OWNER_MARKER,
            WIDE_OWNER_MARKER,
        ):
            self.assertNotIn(secret, serialized, f"{secret!r} reached the report")

    def test_no_credential_reaches_the_rendered_text(self) -> None:
        text = mutation.render_text(self.analyze(self.config()))
        for secret in ("order-owner-token", "super-secret-cookie-value", ECHO_SECRET):
            self.assertNotIn(secret, text)

    def test_header_names_are_reported_but_values_are_not(self) -> None:
        """Naming what was stripped is useful; naming its value would not be."""
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M4", "order_owner")[0]
        self.assertIn("the Authorization header", mutant["mutation"])
        self.assertIn("the Cookie header", mutant["mutation"])
        self.assertNotIn("Bearer", mutant["mutation"])


class RequestDisciplineTest(_FixtureTarget):
    """Rule 3: M4 is the only operator that touches the network, and it is bounded."""

    def test_a_mutating_verb_never_gets_an_unauthenticated_request(self) -> None:
        config = self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "order-delete",
                    "request": {"method": "DELETE", "path": "/api/orders/o-1"},
                    "expect": {
                        "order_owner": {"status": [403]},
                        "outsider": {"status": [403]},
                    },
                }
            ],
        )
        report = self.analyze(config)
        self.assertEqual(report["summary"]["mutation_requests"], 0)
        for mutant in self.mutants(report, "M4"):
            self.assertEqual(mutant["outcome"], mutation.SKIPPED)
            self.assertIn("unauthenticated DELETE is never issued", mutant["observed"])

    def test_the_request_budget_is_respected(self) -> None:
        report = self.analyze(self.good_config(), request_budget=1)
        self.assertEqual(report["summary"]["mutation_requests"], 1)
        skipped = [
            mutant
            for mutant in self.mutants(report, "M4")
            if mutant["outcome"] == mutation.SKIPPED
        ]
        self.assertTrue(
            any("budget is exhausted" in mutant["observed"] for mutant in skipped)
        )

    def test_a_zero_budget_sends_nothing(self) -> None:
        report = self.analyze(self.good_config(), request_budget=0)
        self.assertEqual(report["summary"]["mutation_requests"], 0)

    def test_only_the_network_operators_are_charged_a_request(self) -> None:
        """M1, M2 and M3 re-grade what the baseline already collected."""
        report = self.analyze(self.good_config())
        charged = {
            mutant["operator"]
            for check in report["checks"]
            for mutant in check["mutants"]
            if mutant["requests_issued"]
        }
        self.assertEqual(charged, {"M4", "M5", "M6"})

    def test_every_issued_request_is_counted_in_the_budget(self) -> None:
        report = self.analyze(self.good_config())
        issued = sum(
            mutant["requests_issued"]
            for check in report["checks"]
            for mutant in check["mutants"]
        )
        self.assertEqual(report["summary"]["mutation_requests"], issued)

    def test_a_negative_budget_is_a_configuration_error(self) -> None:
        with self.assertRaises(ConfigError):
            self.analyze(self.good_config(), request_budget=-1)

    def test_a_rate_limit_is_accepted_and_applied(self) -> None:
        report = self.analyze(self.good_config(), min_interval_seconds=0.01)
        # Two M4 strips (owner, outsider), one M5 negative control, one M6 sham.
        self.assertEqual(report["summary"]["mutation_requests"], 4)

    def test_no_fabricated_credential_is_sent_on_a_mutating_verb(self) -> None:
        config = self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "order-delete",
                    "request": {"method": "DELETE", "path": "/api/orders/o-1"},
                    "expect": {
                        "order_owner": {"status": [403]},
                        "outsider": {"status": [403]},
                    },
                }
            ],
        )
        report = self.analyze(config, request_budget=0)
        for mutant in self.mutants(report, "M6"):
            self.assertEqual(mutant["outcome"], mutation.SKIPPED)
            self.assertIn("DELETE", mutant["observed"])
            self.assertEqual(mutant["requests_issued"], 0)
        self.assertEqual(report["summary"]["mutation_requests"], 0)


class NotApplicableTest(_FixtureTarget):
    """A check that already fails has no passing verdict to measure."""

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "already-red",
                    "request": {"method": "GET", "path": "/api/settings/s-1"},
                    # The outsider really gets 403; declaring 404 makes the
                    # baseline red before any mutation happens.
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [404]},
                    },
                }
            ],
        )

    def test_a_failing_expectation_is_not_applicable_not_survived(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(
            self.outcome(report, "M1", "outsider"), mutation.NOT_APPLICABLE
        )
        self.assertEqual(self.outcome(report, "M4", "outsider"), mutation.NOT_APPLICABLE)
        self.assertEqual(self.outcome(report, "M5"), mutation.NOT_APPLICABLE)
        # Nothing survives: a check that is already failing has no passing
        # verdict whose discriminating power could be measured, and the
        # status-only note is a property of the check rather than a survivor.
        self.assertEqual(report["survivors"], [])
        self.assertEqual(report["checks"][0]["marker_evidence"], "status_only")

    def test_the_baseline_reason_is_given_without_a_rule_id(self) -> None:
        report = self.analyze(self.config())
        observed = self.mutants(report, "M1", "outsider")[0]["observed"]
        self.assertIn("the baseline already reports a finding", observed)
        self.assertNotIn("VERIDOR-", observed)

    def test_not_applicable_is_outside_the_score(self) -> None:
        report = self.analyze(self.config())
        summary = report["summary"]
        self.assertEqual(
            summary["generated"],
            summary[mutation.KILLED]
            + summary[mutation.SURVIVED]
            + summary[mutation.ABERRANT]
            + summary[mutation.ERRORED],
        )
        self.assertGreater(summary[mutation.NOT_APPLICABLE], 0)


class UnansweredBaselineTest(unittest.TestCase):
    """A probe nobody answered is not a check that does not apply.

    The two are opposite claims that looked identical in a summary.
    `not_applicable` is structural -- this operator has nothing to rewrite on
    this check -- and it recurs identically every run, so dropping it from the
    denominator is right. A baseline probe lost to a rate limit or a 5xx is
    neither structural nor permanent: that mutant would have been evaluated on
    a quieter afternoon.

    Measured against a target whose boundary never moved, treating the second
    as the first took a run from 15 generated mutants to 11 and still reported
    a score of 1.00 and exit 0 -- a full third of the intended population gone,
    and the number that describes it unchanged.
    """

    @staticmethod
    def _observation(verdict: str | None, error: str | None = None):
        findings = {}
        if verdict is not None:
            findings["outsider"] = {
                "verdict": verdict, "message": "m", "rule_id": "VERIDOR-X",
            }
        return SimpleNamespace(
            probes={"outsider": {"error": error}},
            findings=findings,
        )

    def test_a_rate_limited_baseline_is_errored_not_not_applicable(self) -> None:
        outcome = mutation._blocked_outcome(
            self._observation("inconclusive"), "outsider")
        self.assertEqual(outcome, mutation.ERRORED)

    def test_a_transport_error_baseline_is_errored_too(self) -> None:
        """It was already blocked, but silently: this is the same class of
        non-measurement and had the same effect on the denominator."""
        outcome = mutation._blocked_outcome(
            self._observation(None, error="timed out"), "outsider")
        self.assertEqual(outcome, mutation.ERRORED)

    def test_a_genuinely_failing_baseline_stays_not_applicable(self) -> None:
        """The structural case must not move. A check that is really red has no
        passing verdict whose discriminating power could be measured, and that
        is true on every run."""
        for verdict in ("vulnerable", "unexpected_denial"):
            with self.subTest(verdict=verdict):
                self.assertEqual(
                    mutation._blocked_outcome(self._observation(verdict), "outsider"),
                    mutation.NOT_APPLICABLE,
                )

    def test_an_unmeasured_baseline_is_not_described_as_already_failing(self) -> None:
        """The old wording drew a conclusion about the operator's declaration
        from a 429."""
        blocked = mutation._baseline_blocked(
            self._observation("inconclusive"), "outsider")
        self.assertIn("never answered", blocked[0])
        self.assertNotIn("already reports a finding", blocked[0])
        self.assertIn("not measured", blocked[1])

    def test_errored_makes_the_run_say_it_does_not_know(self) -> None:
        """The whole point of the reclassification: `not_applicable` leaves the
        exit code at 0, `errored` makes it 2."""
        report = {"summary": {
            mutation.ABERRANT: 0, mutation.ERRORED: 1, "generated": 5,
            mutation.SURVIVED: 0,
        }}
        self.assertEqual(mutation.exit_code(report), 2)
        report["summary"][mutation.ERRORED] = 0
        report["summary"][mutation.NOT_APPLICABLE] = 1
        self.assertEqual(mutation.exit_code(report), 0)


@slow("stands up a target that rate-limits every request")
class ThrottledTargetTest(unittest.TestCase):
    """The whole pipeline against a target that answers nothing.

    The unit tests above pin `_blocked_outcome`, which is where the rule lives
    -- but the rule is applied at five separate call sites, and reverting those
    to a hard-coded `not_applicable` left every one of those tests green. This
    is the test that fails when they drift, and it earns its slow tier by
    running the real engine end to end.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.noisy_server import Noise  # noqa: PLC0415
        from scripts.noisy_server import create_server as noisy  # noqa: PLC0415

        # Every request throttled. Not a plausible production API -- a
        # deterministic one, so the assertion is about the engine rather than
        # about luck.
        cls.server = noisy("127.0.0.1", 0, Noise(seed=1, rate_limit=1.0))
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _report(self) -> dict:
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        path = Path(workspace.name) / "config.json"
        path.write_text(json.dumps({
            "version": 1,
            "target": {"base_url": self.base_url, "timeout_seconds": 2},
            "identities": {
                "invoice_owner": {"headers": {"Authorization": "Bearer owner-token"}},
                "other_tenant": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            "checks": [{
                "id": "invoice-tenant-isolation",
                "request": {"method": "GET", "path": "/api/invoices/inv-100"},
                "expect": {
                    "invoice_owner": {"status": [200]},
                    "other_tenant": {"status": [404]},
                },
            }],
        }), encoding="utf-8")
        return mutation.analyze(path, base_url=self.base_url)

    def test_a_throttled_baseline_errors_rather_than_vanishing(self) -> None:
        summary = self._report()["summary"]
        self.assertGreater(
            summary[mutation.ERRORED], 0,
            "every baseline probe was a 429; those mutants must be reported as "
            "unresolved, not quietly dropped from the denominator",
        )

    def test_a_throttled_run_says_it_does_not_know(self) -> None:
        """Exit 0 here would be a score computed over whatever survived the
        throttling, presented exactly like a score over the whole suite."""
        self.assertEqual(mutation.exit_code(self._report()), 2)

    def test_the_reason_names_the_probe_and_not_the_declaration(self) -> None:
        unresolved = self._report()["unresolved"]
        self.assertTrue(unresolved)
        observed = " ".join(str(entry.get("observed", "")) for entry in unresolved)
        self.assertNotIn("already reports a finding", observed)


class SessionRefusalTest(_FixtureTarget):
    """Fail closed rather than manufacture a survivor.

    The guard is asserted against an already-loaded configuration rather than
    through ``load_config``, so it keeps testing the refusal itself while the
    session schema is still moving.
    """

    def test_session_identities_are_refused_rather_than_probed_anonymously(
        self,
    ) -> None:
        config = self.good_config()
        config["identities"]["order_owner"]["session"] = {"login": []}
        with self.assertRaises(ConfigError) as caught:
            mutation._refuse_session_identities(config)
        message = str(caught.exception)
        self.assertIn("does not model session-authenticated identities", message)
        self.assertIn("order_owner", message)
        self.assertIn("vacuity it manufactured itself", message)

    def test_a_credential_only_configuration_is_accepted(self) -> None:
        mutation._refuse_session_identities(self.good_config())


class RenderingTest(_FixtureTarget):
    def test_survivors_are_published_prominently_with_their_diagnosis(self) -> None:
        text = mutation.render_text(self.analyze(MissingResourceTest.config(self)))
        self.assertIn("SURVIVING MUTANTS", text)
        self.assertIn("M5 positive-control", text)
        self.assertIn("means:", text)

    def test_the_header_disclaims_findings_before_any_number(self) -> None:
        text = mutation.render_text(self.analyze(self.good_config()))
        header, _, rest = text.partition("Mutation score")
        self.assertIn("Nothing in this report is a finding", prose(header))
        self.assertIn("The target is observed, never altered.", prose(header))
        self.assertTrue(rest)

    def test_a_clean_report_does_not_claim_the_boundary_is_enforced(self) -> None:
        text = mutation.render_text(self.analyze(self.good_config()))
        self.assertIn("No surviving mutants", text)
        self.assertIn(
            "a mutation score of 1.0 does not mean the boundary is enforced",
            prose(text).lower(),
        )

    def test_the_output_is_ascii(self) -> None:
        text = mutation.render_text(self.analyze(self.good_config()))
        text.encode("ascii", errors="strict")

    def test_a_survivor_is_never_described_as_a_vulnerability(self) -> None:
        """The header may DISCLAIM the word; the survivors must not use it."""
        text = mutation.render_text(self.analyze(MissingResourceTest.config(self)))
        survivors = prose(text.partition("SURVIVING MUTANTS")[2].partition("Per check")[0])
        self.assertTrue(survivors.strip())
        for word in ("vulnerab", "insecure", "exploit", "breach", "unprotected"):
            self.assertNotIn(word, survivors.lower())
        self.assertIn("may be vacuous", prose(text).lower())

    def test_no_rule_id_is_echoed_into_the_rendered_text(self) -> None:
        text = mutation.render_text(self.analyze(self.good_config()))
        self.assertNotIn("VERIDOR-", text)


class DemoFixtureTest(_FixtureTarget):
    """The shipped fixture: one check that can fail, one that cannot."""

    def test_the_demo_config_scores_exactly_what_it_claims(self) -> None:
        report = mutation.analyze(DEMO_CONFIG, base_url=self.base_url)
        by_check = {check["check_id"]: check for check in report["checks"]}
        self.assertEqual(by_check["order-tenant-isolation"]["score"], 1.0)
        self.assertLess(by_check["widget-read-permissive"]["score"], 1.0)
        self.assertEqual(mutation.exit_code(report), 1)

    def test_the_demo_run_is_green_which_is_the_whole_point(self) -> None:
        result = core.execute_run(
            DEMO_CONFIG,
            output_dir=self.workspace / "out",
            base_url=self.base_url,
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "passed")


class TargetMutationTest(_FixtureTarget):
    """Tier 2, with the fixture's guard file standing in for a real build."""

    def _hook(self, name: str, apply_args: list[str], restore_args: list[str]):
        return mutation.TargetMutationHook(
            name=name,
            removes="the tenant predicate on /api/orders/o-1",
            apply_command=[sys.executable, "-c", *apply_args],
            restore_command=[sys.executable, "-c", *restore_args],
            timeout_seconds=60,
        )

    def test_removing_a_covered_guard_is_killed(self) -> None:
        guard = str(self.guard_path)
        hook = self._hook(
            "drop-tenant-filter",
            [f"import pathlib; pathlib.Path({guard!r}).unlink()"],
            [f"import pathlib; pathlib.Path({guard!r}).write_text('present')"],
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.KILLED)
        self.assertTrue(record["restore_verified"])
        self.assertGreater(record["findings_while_mutated"], 0)
        self.assertEqual(mutation.exit_code(report), 0)
        self.assertTrue(self.guard_path.exists())

    def test_removing_an_uncovered_guard_survives(self) -> None:
        unrelated = self.workspace / "unrelated-guard"
        unrelated.write_text("present", encoding="utf-8")
        hook = self._hook(
            "drop-unrelated-filter",
            [f"import pathlib; pathlib.Path({str(unrelated)!r}).unlink()"],
            [f"import pathlib; pathlib.Path({str(unrelated)!r}).write_text('present')"],
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.SURVIVED)
        self.assertIn("No check in this configuration covers", record["diagnosis"])
        self.assertEqual(mutation.exit_code(report), 1)

    def test_a_failed_restore_is_reported_as_the_loudest_thing_here(self) -> None:
        guard = str(self.guard_path)
        hook = self._hook(
            "drop-tenant-filter",
            [f"import pathlib; pathlib.Path({guard!r}).unlink()"],
            ["import sys; sys.exit(3)"],
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertFalse(record["restore_verified"])
        self.assertIn("THE TARGET MAY STILL BE MUTATED", record["diagnosis"])
        self.assertEqual(mutation.exit_code(report), 2)

    def test_an_unreachable_target_is_not_a_kill(self) -> None:
        """The apply command broke the service; nothing was graded.

        core reports an unrunnable probe as a finding too, so a tier-2 kill test
        that only counts findings scores "your suite caught the guard removal"
        for a target that never answered at all. That is the vacuity this whole
        module exists to catch, one level up, and it inflates the tier-2 score
        in the most dangerous possible direction.

        Driven through ``_run_hook``, the apply-suite-restore step itself:
        ``run_target_mutations`` now runs the suite against the unmutated target
        first and applies nothing when that run is not green, so an address
        nothing listens on never reaches the mutated-build run through it. The
        whole-run behaviour for that address is pinned just below.
        """
        guard = str(self.guard_path)
        hook = self._hook(
            "drop-tenant-filter",
            [f"import pathlib; pathlib.Path({guard!r}).unlink()"],
            [f"import pathlib; pathlib.Path({guard!r}).write_text('present')"],
        )
        record = mutation._run_hook(
            hook,
            self.write(self.good_config()),
            self.workspace / "tier2",
            # Nothing listens here, so every probe fails to execute.
            "http://127.0.0.1:1",
        )
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertNotEqual(record["outcome"], mutation.KILLED)
        self.assertIn("did not complete", record["observed"])
        self.assertIn("NOT a kill", record["diagnosis"])
        # The restore still ran, and the hook contributed no kill to the score.
        self.assertTrue(record["restore_verified"])
        self.assertTrue(self.guard_path.exists())
        self.assertEqual(mutation.summarize([record], checks=1)["killed"], 0)

    def test_an_unreachable_target_applies_no_hook(self) -> None:
        """The unmutated run cannot be graded, so nothing is applied or killed."""
        applied = self.workspace / "applied"
        hook = self._hook(
            "drop-tenant-filter",
            [f"import pathlib; pathlib.Path({str(applied)!r}).write_text('x')"],
            ["pass"],
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url="http://127.0.0.1:1",
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertIn("unmutated target", record["observed"])
        self.assertIsNone(record["restore_verified"])
        self.assertFalse(applied.exists())
        self.assertEqual(mutation.exit_code(report), 2)

    def test_a_failed_apply_tests_nothing_and_says_so(self) -> None:
        hook = self._hook(
            "broken-build",
            ["import sys; sys.exit(1)"],
            ["pass"],
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertIn("nothing was tested", record["diagnosis"])

    def test_tier2_reports_counts_and_never_the_findings_themselves(self) -> None:
        guard = str(self.guard_path)
        hook = self._hook(
            "drop-tenant-filter",
            [f"import pathlib; pathlib.Path({guard!r}).unlink()"],
            [f"import pathlib; pathlib.Path({guard!r}).write_text('present')"],
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        serialized = json.dumps(report)
        self.assertNotIn("VERIDOR-LEAK-001", serialized)
        self.assertNotIn(ORDER_OWNER_MARKER, serialized)
        self.assertNotIn("order-owner-token", serialized)
        self.assertNotIn("findings", set(report))
        self.assertEqual(report["tier"], 2)

    def test_a_suite_already_red_does_not_kill_a_hook_that_changes_nothing(self) -> None:
        """Measured before the fix: killed, score 1.00, exit 0, for a no-op hook.

        The outsider is declared [403] and the fixture answers it 404 with the
        guard in place, so the suite is red before anything is removed.
        """
        config = self.good_config()
        config["checks"][0]["expect"]["outsider"]["status"] = [403]
        applied = self.workspace / "applied"
        hook = self._hook(
            "no-op",
            [f"import pathlib; pathlib.Path({str(applied)!r}).write_text('x')"],
            ["pass"],
        )
        report = mutation.run_target_mutations(
            self.write(config),
            [hook],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.NOT_APPLICABLE)
        self.assertEqual(report["summary"]["killed"], 0)
        self.assertNotEqual(mutation.exit_code(report), 0)
        # A red suite measures nothing about the hook, so it is never applied.
        self.assertFalse(applied.exists())


class Tier2GradingTest(unittest.TestCase):
    """What tier 2 counts as a kill, and what it needs before it counts anything.

    ``core.execute_run`` and the hook commands are replaced, so this runs with no
    socket and no subprocess: the rule under test is arithmetic over findings.
    """

    def _run(self, unmutated: list[dict], mutated: list[dict]) -> tuple[dict, list]:
        # Chosen by the evidence directory each run writes to, not by call
        # order, so a run against the mutated build is told apart from the
        # unmutated one whichever happens first -- or if only one happens.
        runs = {"unmutated": unmutated, "mutated": mutated}
        invoked: list = []

        def execute_run(config_path, *, output_dir, **kwargs):
            return {"findings": list(runs[Path(output_dir).name])}

        def invoke(hook, command):
            invoked.append(list(command))
            return 0

        hook = mutation.TargetMutationHook(
            name="drop-guard",
            removes="the guard",
            apply_command=["apply"],
            restore_command=["restore"],
        )
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        original = (core.execute_run, mutation._invoke)
        core.execute_run, mutation._invoke = execute_run, invoke
        try:
            report = mutation.run_target_mutations(
                Path(workspace.name) / "veridor.json",
                [hook],
                output_dir=Path(workspace.name) / "tier2",
            )
        finally:
            core.execute_run, mutation._invoke = original
        return report, invoked

    @staticmethod
    def _finding(
        rule_id: str,
        verdict: str,
        identity: str = "outsider",
        check_id: str = "note",
        *,
        declared: list[int] | None = None,
        got: int | None = None,
    ) -> dict:
        finding = {
            "rule_id": rule_id,
            "verdict": verdict,
            "identity": identity,
            "check_id": check_id,
        }
        if declared is not None:
            finding["evidence"] = {"expected_statuses": declared, "actual_status": got}
        return finding

    def test_a_graded_finding_on_a_green_suite_is_a_kill(self) -> None:
        """The control: a real kill still counts."""
        report, invoked = self._run(
            [], [self._finding("VERIDOR-AUTHZ-001", "vulnerable")]
        )
        self.assertEqual(report["checks"][0]["outcome"], mutation.KILLED)
        self.assertEqual(mutation.exit_code(report), 0)
        self.assertEqual(invoked, [["apply"], ["restore"]])

    def test_a_suite_red_before_the_hook_runs_kills_nothing(self) -> None:
        red = [self._finding("VERIDOR-AUTHZ-001", "vulnerable")]
        report, invoked = self._run(red, red)
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.NOT_APPLICABLE)
        self.assertIn("unmutated", record["observed"])
        self.assertEqual(invoked, [])
        self.assertNotEqual(mutation.exit_code(report), 0)

    def test_an_unmeasured_unmutated_run_kills_nothing(self) -> None:
        """A run that could not grade every check is not a green baseline."""
        report, invoked = self._run(
            [self._finding("VERIDOR-EXEC-001", "inconclusive")],
            [self._finding("VERIDOR-AUTHZ-001", "vulnerable")],
        )
        self.assertEqual(report["checks"][0]["outcome"], mutation.ERRORED)
        self.assertEqual(invoked, [])
        self.assertEqual(mutation.exit_code(report), 2)

    def test_an_inconclusive_finding_alone_is_not_a_kill(self) -> None:
        """Measured before the fix: a hook that only stripped the owner's marker
        from a 200 was killed on two inconclusive ORACLE-001 findings, exit 0."""
        for rule_id in ("VERIDOR-ORACLE-001", "VERIDOR-CACHE-001"):
            with self.subTest(rule_id=rule_id):
                report, invoked = self._run(
                    [], [self._finding(rule_id, "inconclusive")]
                )
                record = report["checks"][0]
                self.assertEqual(record["outcome"], mutation.ERRORED)
                self.assertIn("NOT a kill", record["diagnosis"])
                self.assertEqual(mutation.exit_code(report), 2)
                # The hook was applied and restored; only the grading changed.
                self.assertEqual(invoked, [["apply"], ["restore"]])

    def test_a_partial_outage_is_not_a_kill(self) -> None:
        """The owner 503s, so the outsider's excludes_marker loses its control."""
        report, _ = self._run(
            [],
            [
                self._finding("VERIDOR-EXEC-001", "inconclusive"),
                self._finding("VERIDOR-ORACLE-001", "inconclusive"),
            ],
        )
        self.assertEqual(report["checks"][0]["outcome"], mutation.ERRORED)

    def test_a_refused_owner_is_aberrant_and_never_a_kill(self) -> None:
        """Measured before the fix: killed, score 1.00, exit 0.

        A hook whose apply rebuilt the target and lost its fixtures answered the
        owner 404, so the suite reported AUTHZ-001 unexpected_denial for the
        owner and ORACLE-001 inconclusive for the outsider whose control was
        gone. No guard was removed. Removing a guard grants access; it does not
        refuse the identity the build is meant to serve.
        """
        report, invoked = self._run(
            [],
            [
                self._finding("VERIDOR-AUTHZ-001", "unexpected_denial", "owner"),
                self._finding("VERIDOR-ORACLE-001", "inconclusive", "outsider"),
            ],
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.ABERRANT)
        self.assertEqual(report["summary"]["killed"], 0)
        self.assertEqual(report["summary"]["aberrant"], 1)
        # The reason names who was refused, and where.
        self.assertIn("refused identity 'owner'", record["observed"])
        self.assertIn("'note'", record["observed"])
        self.assertIn("NOT a kill", record["diagnosis"])
        # Verdict names are internal; the report speaks in directions.
        self.assertNotIn("unexpected_denial", json.dumps(report))
        # Aberrant means exactly what it means at tier 1: exit 2.
        self.assertEqual(mutation.exit_code(report), 2)
        self.assertEqual(invoked, [["apply"], ["restore"]])
        self.assertIn(record, report["unresolved"])

    def test_a_refusal_alone_is_aberrant(self) -> None:
        report, _ = self._run(
            [], [self._finding("VERIDOR-AUTHZ-001", "unexpected_denial", "owner")]
        )
        self.assertEqual(report["checks"][0]["outcome"], mutation.ABERRANT)
        self.assertEqual(mutation.exit_code(report), 2)

    def test_every_refused_identity_is_named(self) -> None:
        report, _ = self._run(
            [],
            [
                self._finding("VERIDOR-AUTHZ-001", "unexpected_denial", "owner"),
                self._finding(
                    "VERIDOR-AUTHZ-001", "unexpected_denial", "admin", "audit-log"
                ),
            ],
        )
        observed = report["checks"][0]["observed"]
        self.assertIn("'owner'", observed)
        self.assertIn("'admin'", observed)
        self.assertIn("'audit-log'", observed)

    def test_a_different_refusal_of_a_refused_identity_is_not_called_serving(
        self,
    ) -> None:
        """REGRESSION. An identity the declaration expects to be REFUSED that
        drew a different refusal -- anonymous declared [401] got 302, an
        attacker declared [403] got 404 -- is aberrant too, but the reason
        said "the build refused an identity it should serve" and sent the user
        to check data and credentials, which is false for that identity. A
        guard removal that turns 403 into 404 lands here."""
        for identity, declared, got in (("anonymous", [401], 302), ("attacker", [403], 404)):
            with self.subTest(identity=identity):
                report, _ = self._run([], [self._finding(
                    "VERIDOR-AUTHZ-001", "unexpected_denial", identity,
                    declared=declared, got=got)])
                record = report["checks"][0]
                self.assertEqual(record["outcome"], mutation.ABERRANT)
                self.assertEqual(mutation.exit_code(report), 2)
                self.assertIn(
                    f"answered identity '{identity}' on check 'note' with HTTP {got}, "
                    f"a refusal other than the declared one of {declared}",
                    record["observed"])
                self.assertNotIn("should serve", record["diagnosis"])
                self.assertIn(f"still refused identity '{identity}'", record["diagnosis"])
                self.assertIn("NOT a kill", record["diagnosis"])

    def test_a_changed_refusal_is_not_claimed_to_be_anything_but_what_was_seen(
        self,
    ) -> None:
        """REGRESSION. The reason said a changed refusal "(403 to 404, say) is
        not a guard's removal", and the closing line that "the guard's removal
        is not what the suite saw". Veridor cannot know either: a guard removal
        that turns 403 into 404 lands in exactly this case (see
        ``_refusals``). The diagnosis now says what was observed and that the
        cause is not known, and still that it is not a kill."""
        report, _ = self._run([], [self._finding(
            "VERIDOR-AUTHZ-001", "unexpected_denial", "attacker",
            declared=[403], got=404)])
        diagnosis = report["checks"][0]["diagnosis"]
        self.assertNotIn("is not a guard's removal", diagnosis)
        self.assertNotIn("the guard's removal is not what the suite saw", diagnosis)
        self.assertIn("Veridor cannot tell whether the guard's removal caused it",
                      diagnosis)
        self.assertIn("NOT a kill", diagnosis)
        self.assertIn("still refused identity 'attacker'", diagnosis)

    def test_each_refused_identity_gets_the_reason_that_applies_to_it(self) -> None:
        """An owner refused beside an attacker refused differently: the
        reason names both, each for what happened to it."""
        report, _ = self._run([], [
            self._finding("VERIDOR-AUTHZ-001", "unexpected_denial", "owner",
                          declared=[200], got=404),
            self._finding("VERIDOR-AUTHZ-001", "unexpected_denial", "attacker",
                          declared=[403], got=404),
        ])
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.ABERRANT)
        self.assertIn("refused identity 'owner' on check 'note' with HTTP 404", record["observed"])
        self.assertIn("answered identity 'attacker' on check 'note' with HTTP 404",
                      record["observed"])
        self.assertIn("refused identity 'owner', which its declaration expects it to serve",
                      record["diagnosis"])
        self.assertIn("still refused identity 'attacker'", record["diagnosis"])

    def test_a_served_identity_beside_a_refusal_is_still_a_kill(self) -> None:
        """The control for the rule above: the suite DID see access granted."""
        report, _ = self._run(
            [],
            [
                self._finding("VERIDOR-AUTHZ-001", "unexpected_denial", "owner"),
                self._finding("VERIDOR-LEAK-001", "vulnerable", "outsider"),
            ],
        )
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.KILLED)
        self.assertEqual(mutation.exit_code(report), 0)


@slow("stands up a loopback HTTP server and runs tier-2 hooks as subprocesses")
class Tier2RefusedOwnerTest(unittest.TestCase):
    """The reproduction, against a real target and the real suite.

    The hook's apply removes no guard: it sets a flag that makes the target
    answer every credentialed ``GET /notes/1`` with 404, as a rebuild that
    reset the store would. Before the fix the hook scored killed, 1.00, exit 0,
    on the owner's refusal alone. The ``guard`` mode is the control: the same
    flag removes the tenant filter instead, and that must still be a kill.
    """

    OWNER_MARKER = "vdr-Nq4Zt8Wm3Kx7Bv2Ld6Rj9Ph5"
    ATTACKER_MARKER = "vdr-Ac7Fg2Hj5Kl8Mn1Qs4Tv6Wy0"

    def setUp(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.flag = self.workspace / "mutated"
        self.mode = "wipe"
        test = self
        users = {"Bearer owner-token": "owner", "Bearer attacker-token": "attacker"}

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self) -> None:  # noqa: N802 - http.server's name
                who = users.get(self.headers.get("Authorization", ""))
                status, body = 404, b'{"e":"nf"}'
                if self.path == "/notes/1":
                    note = json.dumps({"t": test.OWNER_MARKER}).encode()
                    if who is None:
                        status, body = 401, b""
                    elif test.flag.exists() and test.mode == "wipe":
                        status = 404
                    elif who == "owner" or (
                        test.flag.exists() and test.mode == "guard"
                    ):
                        status, body = 200, note
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = loopback.start(server)

        def stop() -> None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop)
        self.config = self.workspace / "veridor.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "target": {
                        "base_url": f"http://127.0.0.1:{server.server_port}",
                        "timeout_seconds": 5,
                    },
                    "identities": {
                        "owner": {
                            "headers": {"Authorization": "Bearer owner-token"},
                            "marker": self.OWNER_MARKER,
                        },
                        "attacker": {
                            "headers": {"Authorization": "Bearer attacker-token"},
                            "marker": self.ATTACKER_MARKER,
                        },
                        "anonymous": {"headers": {}},
                    },
                    "checks": [
                        {
                            "id": "note",
                            "request": {"method": "GET", "path": "/notes/1"},
                            "expect": {
                                "owner": {
                                    "status": [200],
                                    "contains_marker": "owner",
                                },
                                "attacker": {
                                    "status": [404],
                                    "excludes_marker": "owner",
                                },
                                "anonymous": {"status": [401]},
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def _run(self) -> dict:
        flag = str(self.flag)
        hook = mutation.TargetMutationHook(
            name="drop-tenant-filter",
            removes="the tenant predicate on /notes/{id}",
            apply_command=[sys.executable, "-c", f"open({flag!r}, 'w').close()"],
            restore_command=[
                sys.executable,
                "-c",
                f"import os; os.path.exists({flag!r}) and os.remove({flag!r})",
            ],
            timeout_seconds=60,
        )
        return mutation.run_target_mutations(
            self.config, [hook], output_dir=self.workspace / "tier2"
        )

    def test_a_build_that_refuses_the_owner_is_aberrant(self) -> None:
        report = self._run()
        record = report["checks"][0]
        self.assertEqual(
            report["unmutated_run"], {"outcome": mutation.UNMUTATED_PASSED}
        )
        self.assertEqual(record["outcome"], mutation.ABERRANT, record["observed"])
        self.assertIn("refused identity 'owner'", record["observed"])
        self.assertEqual(report["summary"]["killed"], 0)
        self.assertEqual(mutation.exit_code(report), 2)
        self.assertTrue(record["restore_verified"])
        self.assertFalse(self.flag.exists())
        rendered = mutation.render_text(report)
        self.assertIn("[ABERRANT]", rendered)
        self.assertIn("'owner'", rendered)

    def test_the_control_a_removed_guard_is_still_a_kill(self) -> None:
        self.mode = "guard"
        report = self._run()
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.KILLED, record["observed"])
        self.assertEqual(mutation.exit_code(report), 0)


class ScoreArithmeticTest(unittest.TestCase):
    """The score, on hand-built tallies. No server, no target, no ambiguity."""

    def tally(self, **outcomes: int) -> list[dict]:
        """``tally(killed=3, survived=1)`` -- outcomes spread over operators."""
        operators = list(mutation.OPERATORS)
        mutants = []
        for index, (outcome, count) in enumerate(outcomes.items()):
            for _ in range(count):
                mutants.append(
                    {"operator": operators[index % len(operators)], "outcome": outcome}
                )
        return mutants

    def test_the_score_is_killed_over_generated(self) -> None:
        summary = mutation.summarize(
            self.tally(killed=3, survived=1), checks=2
        )
        self.assertEqual(summary["generated"], 4)
        self.assertEqual(summary["score"], 0.75)
        self.assertEqual(summary["survivors"], 1)

    def test_aberrant_and_errored_sit_in_the_denominator_only(self) -> None:
        summary = mutation.summarize(
            self.tally(killed=2, aberrant=1, errored=1), checks=1
        )
        self.assertEqual(summary["generated"], 4)
        self.assertEqual(summary["score"], 0.5)
        # An aberrant mutant is unresolved, so it is published as a survivor.
        self.assertEqual(summary["survivors"], 1)

    def test_unmutatable_outcomes_never_raise_the_score(self) -> None:
        """Otherwise a suite could score 1.0 by being impossible to mutate."""
        summary = mutation.summarize(
            self.tally(killed=1, survived=1, skipped=8, not_applicable=8), checks=4
        )
        self.assertEqual(summary["generated"], 2)
        self.assertEqual(summary["score"], 0.5)

    def test_a_suite_that_generated_nothing_scores_null_not_one(self) -> None:
        summary = mutation.summarize(
            self.tally(skipped=3, not_applicable=2), checks=1
        )
        self.assertEqual(summary["generated"], 0)
        self.assertIsNone(summary["score"])

    def test_zero_checks_does_not_divide_by_zero(self) -> None:
        summary = mutation.summarize([], checks=0)
        self.assertEqual(summary["generated"], 0)
        self.assertIsNone(summary["score"])
        self.assertEqual(summary["survivors"], 0)
        self.assertIsNone(mutation.score(0, 0))
        self.assertIsNone(mutation.score(0, -1))

    def test_every_operator_appears_in_the_breakdown_even_when_idle(self) -> None:
        """'M4 killed everything' and 'M4 never ran' are opposite facts."""
        summary = mutation.summarize(
            [{"operator": "M1", "outcome": mutation.KILLED}], checks=1
        )
        self.assertEqual(set(summary["by_operator"]), set(mutation.OPERATORS))
        self.assertEqual(summary["by_operator"]["M1"]["score"], 1.0)
        self.assertIsNone(summary["by_operator"]["M4"]["score"])
        self.assertEqual(summary["by_operator"]["M4"]["generated"], 0)

    def test_the_breakdown_sums_to_the_overall_tally(self) -> None:
        summary = mutation.summarize(
            self.tally(killed=7, survived=3, errored=1), checks=3
        )
        for outcome in mutation.OUTCOMES:
            with self.subTest(outcome=outcome):
                self.assertEqual(
                    sum(
                        tally[outcome] for tally in summary["by_operator"].values()
                    ),
                    summary[outcome],
                )

    def test_the_scoring_rule_is_published_with_its_weighting_decision(self) -> None:
        self.assertEqual(mutation.SCORING["formula"], "killed / generated")
        self.assertIn("every operator counts once", mutation.SCORING["weighting"])
        self.assertTrue(mutation.SCORING["why_unweighted"].strip())


class LimitedCountTest(unittest.TestCase):
    """``limited`` counts what LIMITS ON THE EVIDENCE prints, and nothing else.

    ``--require-evaluable`` gates on it, so a structural not_applicable counted
    there fires the gate on a correct config and makes the flag useless.
    """

    @staticmethod
    def _mutant(
        operator: str, variant: str, diagnosis: str, *, limit: bool = False
    ) -> dict:
        return {
            "operator": operator,
            "outcome": mutation.NOT_APPLICABLE,
            "identity": "outsider",
            "variant": variant,
            "diagnosis": diagnosis,
            "evidence_limit": limit,
        }

    def test_only_a_limit_on_the_evidence_is_limited(self) -> None:
        structural = self._mutant(
            "M3", "contains_is_self_falsifying",
            "this assertion is falsifiable by construction",
        )
        summary = mutation.summarize([structural], checks=1)
        self.assertEqual(summary[mutation.NOT_APPLICABLE], 1)
        self.assertEqual(summary["limited"], 0)

    def test_the_limited_count_matches_the_printed_notes(self) -> None:
        """The control: a real M6 limit is still counted, and printed."""
        limit = self._mutant(
            "M6", "sham_credential", "hiding existence uniformly", limit=True
        )
        structural = self._mutant(
            "M3", "contains_is_self_falsifying",
            "this assertion is falsifiable by construction",
        )
        mutants = [limit, structural]
        summary = mutation.summarize(mutants, checks=1)
        notes = mutation._evidence_notes({}, mutants)
        self.assertEqual(summary["limited"], 1)
        self.assertEqual(len(notes), summary["limited"])


class EmptyReportTest(unittest.TestCase):
    """A report with nothing in it still renders, and never claims a pass."""

    def report(self) -> dict:
        return {
            "tier": 1,
            "target": None,
            "config": "veridor.json",
            "summary": mutation.summarize([], checks=0),
            "survivors": [],
            "checks": [],
            "operators": mutation.OPERATORS,
        }

    def test_the_text_renders_and_says_there_is_no_score(self) -> None:
        text = mutation.render_text(self.report())
        self.assertIn("Mutation score: n/a", text)
        self.assertIn("No mutant was generated", prose(text))
        self.assertIn("That is not a pass", prose(text))

    def test_no_all_clear_is_printed_over_a_null_score(self) -> None:
        # REGRESSION. "No surviving mutants. Every generated mutant changed the
        # verdict in the required direction" is vacuously true of an empty set,
        # and it used to print three lines under `Mutation score: n/a`. A
        # reader skimming saw a green-sounding paragraph over a measurement
        # that never happened.
        text = prose(mutation.render_text(self.report()))
        self.assertIn("No mutant was generated", text)
        self.assertNotIn("No surviving mutants", text)
        self.assertNotIn("would have caught the change", text)

    def test_an_unreachable_baseline_is_stated_before_the_score(self) -> None:
        # REGRESSION. Nothing in the report said the target was unreachable:
        # the only symptoms were `not applicable` counts and a null score.
        report = self.report()
        report["target"] = "http://127.0.0.1:8766"
        report["baseline_transport"] = {
            "requests": 5,
            "failed": 5,
            "reasons": ["[Errno 61] Connection refused"],
        }
        text = mutation.render_text(report)
        self.assertIn("THE BASELINE DID NOT REACH THE TARGET", text)
        flat = prose(text)
        self.assertIn("5 of 5 baseline request(s)", flat)
        self.assertIn("http://127.0.0.1:8766", flat)
        self.assertIn("Connection refused", flat)
        self.assertLess(text.index("DID NOT REACH"), text.index("Mutation score"))

    def test_a_reachable_baseline_prints_no_transport_banner(self) -> None:
        report = self.report()
        report["baseline_transport"] = {"requests": 5, "failed": 0, "reasons": []}
        self.assertNotIn("DID NOT REACH", mutation.render_text(report))

    def test_the_badge_is_unknown_rather_than_green(self) -> None:
        badge = mutation.render_badge(self.report())
        self.assertEqual(badge["message"], "unknown")
        self.assertEqual(badge["color"], "lightgrey")
        self.assertTrue(badge["isError"])

    def test_a_summary_block_of_an_empty_report_is_still_honest(self) -> None:
        summary = mutation.mutation_summary(self.report())
        self.assertIsNone(summary["score"])
        self.assertEqual(summary["survivors"], 0)
        self.assertIn("ENFORCED", summary["relationship"])

    def test_measuring_nothing_does_not_exit_zero(self) -> None:
        """Exit 0 would tell a CI gate the checks are sound. Nothing was read."""
        self.assertEqual(mutation.exit_code(self.report()), 2)


class BadgeTest(_FixtureTarget):
    """The badge is the artifact that travels furthest from its context."""

    def test_the_shape_matches_the_coverage_badge(self) -> None:
        reference = coverage.render_badge(
            {
                "status": "measured",
                "coverage": 0.5,
                "summary": {"covered": 1, "operations": 2},
            }
        )
        badge = mutation.render_badge(self.analyze(self.good_config()))
        self.assertEqual(set(badge), set(reference))
        self.assertEqual(badge["schemaVersion"], reference["schemaVersion"])
        self.assertEqual(badge["cacheSeconds"], reference["cacheSeconds"])

    def test_an_undefined_measurement_matches_the_coverage_unknown_badge(self) -> None:
        self.assertEqual(
            set(mutation.render_badge({})), set(coverage.render_badge({}))
        )

    def test_the_label_says_what_the_number_is_about(self) -> None:
        badge = mutation.render_badge(self.analyze(self.good_config()))
        self.assertEqual(badge["label"], mutation.BADGE_LABEL)
        self.assertIn("killed", badge["message"])
        for word in coverage.BANNED_CLAIM_WORDS:
            self.assertNotIn(word, f"{badge['label']} {badge['message']}".lower())

    def test_a_suite_where_everything_is_killed_is_green(self) -> None:
        badge = mutation.render_badge(self.analyze(self.good_config()))
        self.assertEqual(badge["message"], "100.0% killed")
        self.assertEqual(badge["color"], "brightgreen")

    def test_a_survivor_shows_in_the_badge(self) -> None:
        badge = mutation.render_badge(self.analyze(MissingResourceTest.config(self)))
        self.assertNotEqual(badge["message"], "100.0% killed")
        self.assertNotIn(badge["color"], {"brightgreen", "green"})

    def test_an_unresolved_mutant_never_renders_green(self) -> None:
        """The engine does not know whether those checks discriminate."""
        report = self.analyze(AberrantOutcomeTest.config(self))
        report["summary"][mutation.KILLED] = 19
        report["summary"]["generated"] = 20
        badge = mutation.render_badge(report)
        self.assertEqual(badge["message"], "95.0% killed")
        self.assertEqual(badge["color"], "yellow")

    def test_the_percentage_is_floored_and_never_rounds_up_to_100(self) -> None:
        report = {
            "tier": 1,
            "summary": {
                "generated": 2000,
                mutation.KILLED: 1999,
                mutation.ABERRANT: 0,
                mutation.ERRORED: 0,
            },
        }
        self.assertEqual(mutation.render_badge(report)["message"], "99.9% killed")

    def test_tier_two_gets_its_own_label(self) -> None:
        badge = mutation.render_badge({"tier": 2, "summary": {}})
        self.assertEqual(badge["label"], mutation.TIER2_BADGE_LABEL)
        self.assertNotEqual(mutation.TIER2_BADGE_LABEL, mutation.BADGE_LABEL)


class DiagnosisTest(_FixtureTarget):
    """A survivor with no actionable diagnosis is a number nobody will act on."""

    def every_mutant(self):
        configs = [
            self.good_config(),
            InvalidCredentialTest.config(self),
            MissingResourceTest.config(self),
            OverWideExpectationTest.config(self),
            MarkerFreeCheckTest.config(self),
            PermissiveAllowTest.config(self),
            AberrantOutcomeTest.config(self),
            NotApplicableTest.config(self),
        ]
        for index, config in enumerate(configs):
            report = mutation.analyze(
                self.write(config, f"config-{index}.json"), base_url=self.base_url
            )
            for check in report["checks"]:
                yield from check["mutants"]

    def test_every_actionable_outcome_carries_a_diagnosis(self) -> None:
        seen = set()
        for mutant in self.every_mutant():
            outcome = mutant["outcome"]
            seen.add(outcome)
            if outcome in {mutation.SURVIVED, mutation.ABERRANT, mutation.ERRORED}:
                with self.subTest(mutant=mutant["id"]):
                    self.assertTrue(
                        (mutant["diagnosis"] or "").strip(),
                        f"{mutant['id']} survived with no diagnosis",
                    )
        # The corpus has to have contained the outcomes being asserted about.
        self.assertLessEqual({mutation.SURVIVED, mutation.ABERRANT}, seen)

    def test_a_killed_mutant_stays_silent(self) -> None:
        """Nothing to act on, so nothing is said. Report noise buries survivors."""
        killed = [
            mutant
            for mutant in self.every_mutant()
            if mutant["outcome"] == mutation.KILLED
        ]
        self.assertTrue(killed)
        for mutant in killed:
            self.assertIsNone(mutant["diagnosis"], mutant["id"])

    def test_no_diagnosis_asserts_a_defect_in_the_target(self) -> None:
        for mutant in self.every_mutant():
            if not mutant["diagnosis"]:
                continue
            with self.subTest(mutant=mutant["id"]):
                for word in mutation.BANNED_DIAGNOSIS_WORDS:
                    self.assertNotIn(word, mutant["diagnosis"].lower())

    def test_the_static_prose_is_free_of_the_same_words(self) -> None:
        prose_sources = [
            value
            for meta in mutation.OPERATORS.values()
            for value in meta.values()
        ]
        prose_sources.extend(mutation.TARGET_OPERATOR["T1"].values())
        prose_sources.extend(mutation.SCORING.values())
        prose_sources.extend(mutation.TIER2_CONTRACT)
        prose_sources.append(mutation.RELATIONSHIP)
        for operator in [*mutation.OPERATORS, "T1"]:
            for outcome in (mutation.SURVIVED, mutation.ABERRANT, mutation.ERRORED):
                prose_sources.append(mutation._default_diagnosis(operator, outcome))
        for text in prose_sources:
            with self.subTest(text=text[:40]):
                for word in mutation.BANNED_DIAGNOSIS_WORDS:
                    self.assertNotIn(word, text.lower())

    def test_the_fallback_diagnosis_is_used_when_an_operator_writes_none(self) -> None:
        """The guarantee is structural, not a convention each operator recalls."""
        observation = mutation._Observation(
            check={"id": "some-check", "expect": {}}, probes={}, findings={}
        )
        record = mutation._record(
            "M2",
            observation,
            "outsider",
            variant="allow_to_denial",
            mutation="declare 'outsider' is denied",
            outcome=mutation.SURVIVED,
            observed="the mutated expectation still passed",
        )
        self.assertIn("may be vacuous", record["diagnosis"])
        self.assertIn("M2", record["diagnosis"])

    def test_every_diagnosis_hedges_or_tells_the_reader_what_to_change(self) -> None:
        """A survivor with no actionable diagnosis is a number nobody will act on.

        Either it hedges -- 'may be vacuous', 'cannot distinguish', 'unknown',
        which is the honest register -- or it names the edit that would fix the
        check. A sentence that does neither is a shrug with a score attached.
        """
        hedge_or_action = re.compile(
            r"\b(may|cannot|could not|nothing|unknown|inert|not observable|add|"
            r"declare|narrow|restore|confirm)\b",
            re.IGNORECASE,
        )
        checked = 0
        for mutant in self.every_mutant():
            diagnosis = mutant["diagnosis"] or ""
            if mutant["outcome"] not in {
                mutation.SURVIVED,
                mutation.ABERRANT,
                mutation.ERRORED,
            }:
                continue
            checked += 1
            with self.subTest(mutant=mutant["id"]):
                # Long enough to be a sentence, not a label.
                self.assertGreater(len(diagnosis), 60, diagnosis)
                if mutant["outcome"] == mutation.SURVIVED:
                    self.assertRegex(diagnosis, hedge_or_action)
        self.assertGreater(checked, 0)

    def test_no_diagnosis_echoes_a_grader_verdict_name(self) -> None:
        """'vulnerable' is a core VERDICT, and CI greps console output.

        A healthy suite produces that verdict on purpose, once per killed
        mutant. Echoing the identifier would print it all over a green run.
        """
        report = self.analyze(PermissiveAllowTest.config(self))
        rendered = mutation.render_text(report)
        self.assertIn("SURVIVING MUTANTS", rendered)
        self.assertNotIn("vulnerable", json.dumps(report))
        self.assertNotIn("unexpected_denial", json.dumps(report))
        self.assertNotIn("vulnerable", rendered)


class HonestFramingTest(_FixtureTarget):
    """Coverage says ASSERTED, mutation says WOULD CATCH, neither says ENFORCED."""

    def test_the_relationship_is_stated_before_the_number(self) -> None:
        text = mutation.render_text(self.analyze(self.good_config()))
        header = prose(text.partition("Mutation score")[0])
        self.assertIn("ASSERTED", header)
        self.assertIn("WOULD CATCH A REGRESSION", header)
        self.assertIn("ENFORCED", header)

    def test_the_two_surfaces_use_one_word_for_the_coverage_claim(self) -> None:
        """The claim words are the product's credibility; they must not drift.

        ``coverage.py`` has always said a denial is ASSERTED -- deliberately
        weaker than "tested", because a check existing is not a check working.
        ``mutation.py`` described the same measurement as TESTED, so the two
        headline numbers disagreed about what the first one claims. Read the
        word out of coverage rather than hard-coding it here, so this test keeps
        holding if the wording is revised again.
        """
        from veridor import coverage  # noqa: PLC0415 - local, mirrors the module

        claim = "ASSERTED"
        self.assertIn(claim, coverage._CLAIM_PARAGRAPH)
        self.assertIn(claim.lower(), coverage.BADGE_LABEL)
        self.assertIn(claim.lower(), coverage.CLAIM["measures"])
        self.assertIn(claim, mutation.RELATIONSHIP)
        # And the weaker word is gone from the module entirely, not merely
        # absent from this one string.
        source = Path(mutation.__file__).read_text(encoding="utf-8")
        self.assertNotIn("TESTED", source)

    def test_the_relationship_travels_in_the_json(self) -> None:
        report = self.analyze(self.good_config())
        self.assertEqual(report["interpretation"]["relationship"], mutation.RELATIONSHIP)
        self.assertEqual(
            mutation.mutation_summary(report)["relationship"], mutation.RELATIONSHIP
        )

    def test_the_relationship_names_both_measurements_without_merging_them(
        self,
    ) -> None:
        self.assertIn("Boundary coverage", mutation.RELATIONSHIP)
        self.assertIn("Neither says", mutation.RELATIONSHIP)
        for word in coverage.BANNED_CLAIM_WORDS:
            self.assertNotIn(word, mutation.RELATIONSHIP.lower())

    def test_the_scoring_rule_travels_with_the_report(self) -> None:
        report = self.analyze(self.good_config())
        self.assertEqual(report["scoring"]["formula"], "killed / generated")
        self.assertIn("unweighted", mutation.render_text(report))

    def test_the_per_operator_breakdown_is_rendered(self) -> None:
        text = mutation.render_text(self.analyze(MissingResourceTest.config(self)))
        self.assertIn("Per operator", text)
        self.assertIn("M5 positive-control", text)


class ArtifactTest(_FixtureTarget):
    """Human text, machine JSON and a badge. No SARIF, and no secrets."""

    def write_all(self, config: dict) -> tuple[dict, dict]:
        report = self.analyze(config)
        paths = mutation.write_reports(report, self.workspace / "mutation-out")
        return report, paths

    def test_three_artifacts_are_written(self) -> None:
        report, paths = self.write_all(self.good_config())
        self.assertEqual(set(paths), {"json", "text", "badge"})
        for path in paths.values():
            self.assertTrue(path.exists(), path)
        self.assertEqual(
            json.loads(paths["json"].read_text(encoding="utf-8")), report
        )
        self.assertEqual(paths["text"].read_text(encoding="utf-8"), mutation.render_text(report))
        self.assertEqual(
            json.loads(paths["badge"].read_text(encoding="utf-8")),
            mutation.render_badge(report),
        )

    def test_no_artifact_carries_a_credential_a_body_or_a_rule_id(self) -> None:
        _, paths = self.write_all(NoSecretsInArtifactsTest.config(self))
        for name, path in paths.items():
            text = path.read_text(encoding="utf-8")
            with self.subTest(artifact=name):
                for secret in (
                    "order-owner-token",
                    "super-secret-cookie-value",
                    "request-level-api-key",
                    ECHO_SECRET,
                    ORDER_OWNER_MARKER,
                    "VERIDOR-",
                ):
                    self.assertNotIn(secret, text)

    def test_no_sarif_is_produced(self) -> None:
        _, paths = self.write_all(self.good_config())
        directory = paths["json"].parent
        self.assertEqual(
            sorted(entry.name for entry in directory.iterdir()),
            ["mutation-badge.json", "mutation.json", "mutation.txt"],
        )

    def test_the_summary_block_reports_counts_and_not_prose(self) -> None:
        report = self.analyze(MissingResourceTest.config(self))
        summary = mutation.mutation_summary(report)
        self.assertEqual(summary["survivors"], len(report["survivors"]))
        self.assertEqual(summary["killed"], report["summary"][mutation.KILLED])
        self.assertEqual(summary["score"], report["summary"]["score"])


class TargetMutationContractTest(_FixtureTarget):
    """Tier 2 alters somebody's target. The contract is enforced, not documented."""

    def toggle(self) -> Path:
        return ROOT / "fixtures" / "tier2_guard_toggle.py"

    def hook(self, **overrides) -> mutation.TargetMutationHook:
        fields = {
            "name": "drop-tenant-filter",
            "removes": "the tenant predicate on /api/orders/o-1",
            "apply_command": [
                sys.executable,
                str(self.toggle()),
                "remove",
                str(self.guard_path),
            ],
            "restore_command": [
                sys.executable,
                str(self.toggle()),
                "restore",
                str(self.guard_path),
            ],
            "timeout_seconds": 60,
        }
        fields.update(overrides)
        return mutation.TargetMutationHook(**fields)

    def run_hooks(self, hooks) -> dict:
        return mutation.run_target_mutations(
            self.write(self.good_config()),
            hooks,
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )

    def witness(self, name: str) -> tuple[Path, list[str]]:
        """A command that proves it ran by creating a file."""
        path = self.workspace / name
        return path, [
            sys.executable,
            "-c",
            f"import pathlib; pathlib.Path({str(path)!r}).write_text('ran')",
        ]

    # -- the refusal ---------------------------------------------------------

    def test_a_hook_without_a_restore_command_is_refused(self) -> None:
        marker, apply_command = self.witness("applied")
        with self.assertRaises(ConfigError) as caught:
            self.run_hooks([self.hook(apply_command=apply_command, restore_command=[])])
        message = str(caught.exception)
        self.assertIn("no restore command", message)
        self.assertIn("puts it back", message)
        # Refused BEFORE anything ran: the apply command never executed.
        self.assertFalse(marker.exists())

    def test_one_bad_hook_refuses_the_whole_run(self) -> None:
        """Discovering it after hook 1 applied would leave a mess behind."""
        marker, apply_command = self.witness("applied")
        with self.assertRaises(ConfigError):
            self.run_hooks(
                [
                    self.hook(name="first", apply_command=apply_command),
                    self.hook(name="second", restore_command=[]),
                ]
            )
        self.assertFalse(marker.exists())

    def test_an_empty_apply_command_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self.run_hooks([self.hook(apply_command=[])])
        self.assertIn("no apply command", str(caught.exception))

    def test_a_duplicate_hook_name_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self.run_hooks([self.hook(), self.hook()])
        self.assertIn("declared twice", str(caught.exception))

    def test_a_hook_that_does_not_say_what_it_removes_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self.run_hooks([self.hook(removes="   ")])
        self.assertIn("must say which guard it removes", str(caught.exception))

    def test_a_non_positive_timeout_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self.run_hooks([self.hook(timeout_seconds=0)])
        self.assertIn("non-positive timeout", str(caught.exception))

    # -- the restore ---------------------------------------------------------

    def test_restore_runs_when_the_apply_command_fails(self) -> None:
        restored, restore_command = self.witness("restored")
        report = self.run_hooks(
            [
                self.hook(
                    apply_command=[sys.executable, "-c", "import sys; sys.exit(7)"],
                    restore_command=restore_command,
                )
            ]
        )
        record = report["checks"][0]
        self.assertTrue(restored.exists(), "the restore command did not run")
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertTrue(record["restore_verified"])
        self.assertIn("the apply command exited 7", record["observed"])
        self.assertIn("nothing was tested", record["diagnosis"])

    def test_restore_runs_when_the_suite_cannot_run_at_all(self) -> None:
        """Driven through ``_run_hook``: the suite raising AFTER the apply.

        ``run_target_mutations`` now runs the suite against the unmutated target
        before applying anything, so a suite that cannot run at all is caught
        there and no hook is applied (pinned just below). The restore-in-finally
        guarantee is a property of the apply-suite-restore step, so it is held
        on that step directly.
        """
        restored, restore_command = self.witness("restored")
        record = mutation._run_hook(
            self.hook(restore_command=restore_command),
            self.workspace / "there-is-no-config-here.json",
            self.workspace / "tier2",
            self.base_url,
        )
        self.assertTrue(restored.exists())
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertTrue(record["restore_verified"])
        self.assertIn("unknown", record["diagnosis"])

    def test_a_suite_that_cannot_run_applies_no_hook(self) -> None:
        applied, apply_command = self.witness("applied")
        report = mutation.run_target_mutations(
            self.workspace / "there-is-no-config-here.json",
            [self.hook(apply_command=apply_command)],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )
        record = report["checks"][0]
        self.assertFalse(applied.exists())
        self.assertEqual(record["outcome"], mutation.ERRORED)
        self.assertIsNone(record["restore_verified"])
        self.assertIn("unknown", record["diagnosis"])

    def test_restore_runs_when_the_suite_goes_red(self) -> None:
        report = self.run_hooks([self.hook()])
        self.assertEqual(report["checks"][0]["outcome"], mutation.KILLED)
        self.assertTrue(self.guard_path.exists())

    def test_a_later_hook_is_abandoned_after_an_unverified_restore(self) -> None:
        applied, apply_command = self.witness("second-applied")
        report = self.run_hooks(
            [
                self.hook(
                    name="unrestorable",
                    restore_command=[sys.executable, "-c", "import sys; sys.exit(4)"],
                ),
                self.hook(name="never-reached", apply_command=apply_command),
            ]
        )
        first, second = report["checks"]
        self.assertEqual(first["outcome"], mutation.ERRORED)
        self.assertFalse(first["restore_verified"])
        self.assertEqual(second["outcome"], mutation.SKIPPED)
        self.assertIsNone(second["restore_verified"])
        self.assertIn("'unrestorable'", second["observed"])
        self.assertFalse(applied.exists(), "a second mutation was applied anyway")
        self.assertEqual(mutation.exit_code(report), 2)
        # Skipped is outside the denominator, exactly as a skipped M4 is.
        self.assertEqual(report["summary"]["generated"], 1)
        # Left mutated by the failing hook; put it back for the next test.
        self.guard_path.write_text("present\n", encoding="utf-8")

    def test_no_hooks_is_an_empty_report_rather_than_a_crash(self) -> None:
        report = self.run_hooks([])
        self.assertEqual(report["checks"], [])
        self.assertIsNone(report["summary"]["score"])
        self.assertIn("No mutant was generated", prose(mutation.render_text(report)))
        self.assertEqual(mutation.exit_code(report), 2)

    # -- the worked example --------------------------------------------------

    def test_the_shipped_worked_example_is_a_working_hook(self) -> None:
        report = self.run_hooks([self.hook()])
        record = report["checks"][0]
        self.assertEqual(record["outcome"], mutation.KILLED)
        self.assertTrue(record["restore_verified"])
        self.assertGreater(record["findings_while_mutated"], 0)
        self.assertTrue(self.guard_path.exists())
        self.assertEqual(
            self.guard_path.read_text(encoding="utf-8"), guard_toggle.GUARD_CONTENT
        )

    def test_the_worked_example_restore_is_idempotent(self) -> None:
        """It runs on every path, including after a remove that half-failed."""
        self.assertEqual(guard_toggle.main(["restore", str(self.guard_path)]), 0)
        self.assertEqual(guard_toggle.main(["restore", str(self.guard_path)]), 0)
        self.assertTrue(self.guard_path.exists())

    def test_the_worked_example_fails_loudly_when_there_is_nothing_to_remove(
        self,
    ) -> None:
        """A mutate command that silently does nothing manufactures a survivor."""
        self.assertEqual(guard_toggle.main(["remove", str(self.guard_path)]), 0)
        complaint = io.StringIO()
        with contextlib.redirect_stderr(complaint):
            again = guard_toggle.main(["remove", str(self.guard_path)])
        self.assertNotEqual(again, 0)
        self.assertIn("already absent", complaint.getvalue())
        self.assertEqual(guard_toggle.main(["restore", str(self.guard_path)]), 0)

    # -- the report ----------------------------------------------------------

    def test_the_contract_is_printed_in_the_report(self) -> None:
        report = self.run_hooks([self.hook()])
        text = prose(mutation.render_text(report))
        self.assertIn("restore_command", text)
        self.assertIn("It is MANDATORY", text)
        self.assertIn("Per hook:", mutation.render_text(report))
        self.assertEqual(
            report["interpretation"]["contract"], list(mutation.TIER2_CONTRACT)
        )

    def test_a_tier_two_report_renders_and_badges_like_a_tier_one_one(self) -> None:
        report = self.run_hooks([self.hook()])
        paths = mutation.write_reports(
            report, self.workspace / "tier2-out", stem="mutation-tier2"
        )
        self.assertEqual(set(paths), {"json", "text", "badge"})
        badge = json.loads(paths["badge"].read_text(encoding="utf-8"))
        self.assertEqual(badge["label"], mutation.TIER2_BADGE_LABEL)
        self.assertNotIn("VERIDOR-", paths["json"].read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Regressions. Each class below is one reproduced defect, and each holds BOTH
# directions: the vacuous configuration the engine must now flag, and the
# genuinely good one on the same route that it must still leave alone.
# ---------------------------------------------------------------------------


class NonPrincipalAttackerTest(_FixtureTarget):
    """The attacker is refused for a reason the boundary under test never sees.

    ``M4`` cannot detect this. On a target that answers 401 to a missing header
    and 403 to an unrecognised one -- the common split -- stripping the
    credential CHANGES the status, so ``M4`` reports a kill for an identity that
    the ownership predicate never even reaches. The check then scores a perfect
    1.00 with no survivors while being unable to notice the guard it names being
    deleted. ``M6`` is the operator that separates the two.
    """

    def config(self, attacker_token: str) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"},
                    "marker": ORDER_OWNER_MARKER,
                },
                "attacker": {"headers": {"Authorization": attacker_token}},
            },
            [
                {
                    "id": "scoped-invoice-isolation",
                    "request": {"method": "GET", "path": "/api/scoped/inv-7"},
                    "expect": {
                        "order_owner": {
                            "status": [200],
                            "contains_marker": "order_owner",
                        },
                        "attacker": {
                            "status": [403] if "roleless" in attacker_token else [404],
                            "excludes_marker": "order_owner",
                        },
                    },
                }
            ],
        )

    def findings_with_the_guard_removed(self, config: dict) -> int:
        self.guard_path.unlink()
        self.addCleanup(self.guard_path.write_text, "present\n", encoding="utf-8")
        result = core.execute_run(
            self.write(config, "regression.json"),
            output_dir=self.workspace / "broken",
            base_url=self.base_url,
        )
        return len(result["findings"])

    def test_a_roleless_principal_is_reported_as_possibly_vacuous(self) -> None:
        report = self.analyze(self.config(ROLELESS_TOKEN))
        self.assertEqual(self.outcome(report, "M6", "attacker"), mutation.SURVIVED)
        self.assertLess(report["summary"]["score"], 1.0)
        self.assertEqual(mutation.exit_code(report), 1)

    def test_m4_alone_would_have_called_that_check_perfect(self) -> None:
        """The premise. Without M6 every operator is killed and nothing is said."""
        report = self.analyze(self.config(ROLELESS_TOKEN))
        self.assertEqual(self.outcome(report, "M4", "attacker"), mutation.KILLED)
        without_m6 = [
            mutant
            for mutant in report["survivors"]
            if mutant["operator"] != "M6"
        ]
        self.assertEqual(without_m6, [])

    def test_the_vacuous_check_really_does_miss_the_regression(self) -> None:
        """The survivor is not pedantry: the check cannot catch the change."""
        self.assertEqual(
            self.findings_with_the_guard_removed(self.config(ROLELESS_TOKEN)), 0
        )

    def test_a_real_other_tenant_principal_scores_a_clean_one(self) -> None:
        report = self.analyze(self.config("Bearer outsider-token"))
        self.assertEqual(self.outcome(report, "M6", "attacker"), mutation.KILLED)
        self.assertEqual(report["survivors"], [])
        self.assertEqual(report["summary"]["score"], 1.0)
        self.assertEqual(mutation.exit_code(report), 0)

    def test_and_the_control_really_does_catch_the_regression(self) -> None:
        self.assertEqual(
            self.findings_with_the_guard_removed(self.config("Bearer outsider-token")),
            1,
        )

    def test_the_diagnosis_says_may_be_vacuous_not_vulnerable(self) -> None:
        report = self.analyze(self.config(ROLELESS_TOKEN))
        mutant = self.mutants(report, "M6", "attacker")[0]
        self.assertIn("belongs to nobody", mutant["diagnosis"])
        self.assertIn("may be vacuous", mutant["diagnosis"])
        for banned in mutation.BANNED_DIAGNOSIS_WORDS:
            self.assertNotIn(banned, mutant["diagnosis"].lower())

    def test_an_identity_that_was_served_is_not_asked_the_question(self) -> None:
        """M6 is about the meaning of a DENIAL. There is no denial for the owner."""
        report = self.analyze(self.config("Bearer outsider-token"))
        owner = [
            mutant for mutant in self.mutants(report, "M6") if mutant["identity"] == "order_owner"
        ]
        self.assertEqual(owner, [])

    def test_the_fabricated_credential_never_reaches_an_artifact(self) -> None:
        report = self.analyze(self.config(ROLELESS_TOKEN))
        text = json.dumps(report) + mutation.render_text(report)
        self.assertNotIn(ROLELESS_TOKEN, text)
        self.assertNotIn("roleless-principal-token", text)
        # The sham value is a credential-shaped string of this module's own
        # making, and it is no more welcome in an artifact than a real one.
        self.assertNotIn("Bearer veridor-sham", text)


@slow("stands up a loopback HTTP server and runs the engine against it")
class IndistinguishablePrincipalTest(unittest.TestCase):
    """The shipped fixture answers ANY non-owner token 404. Say so, do not score it.

    ``veridor_mutation_fixture`` hides the record's existence from every
    credential it does not recognise, so its ``outsider`` is -- from outside --
    indistinguishable from an expired token. That is a true statement about that
    target, and the honest report of it is M6 as ``not_applicable`` -- neither a
    survivor nor a kill, because nothing was measured -- left out of the score.
    The score over what was measured is still 1.00, so it is printed with the
    limit beside it: the question M6 asks cannot be answered from outside.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = shipped_fixture.create_server("127.0.0.1", 0)
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.workspace = Path(self._workspace.name)

    def test_a_target_that_cannot_distinguish_is_reported_as_such(self) -> None:
        path = self.workspace / "config.json"
        path.write_text(
            json.dumps(
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
                    },
                    "checks": [
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
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        report = mutation.analyze(path, base_url=self.base_url)
        mutant = next(
            mutant
            for mutant in report["checks"][0]["mutants"]
            if mutant["operator"] == "M6"
        )
        # Not a survivor: a 404 is given to everyone the route does not serve,
        # so its equality with a fabricated credential's 404 carries no
        # information in either direction, and there is nothing the operator
        # could change. Not a kill either -- nothing was measured.
        self.assertEqual(mutant["outcome"], mutation.NOT_APPLICABLE)
        self.assertIn("hiding existence uniformly", mutant["diagnosis"])
        self.assertEqual(report["survivors"], [])
        # The class docstring once called the honest report "a survivor, not a
        # 1.00" while the engine reported not_applicable and scored 1.0. It
        # must name the outcome measured here, and the score.
        doc = prose(type(self).__doc__)
        self.assertIn(f"``{mutant['outcome']}``", doc)
        self.assertNotIn("is a survivor", doc)
        self.assertEqual(report["summary"]["score"], 1.0)
        self.assertIn("1.00", doc)

    def test_the_fixture_docstring_names_every_operator_its_orders_route_does_not_kill(self) -> None:
        # The shipped fixture's docstring called /api/orders/o-1 the negative
        # control on which "every mutation operator should be killed". M6 is
        # not_applicable there (the route 404s every non-owner token), and the
        # real negative control is the principal fixture's override.
        config = json.loads(DEMO_CONFIG.read_text(encoding="utf-8"))
        config["target"]["base_url"] = self.base_url
        config["checks"] = [
            check for check in config["checks"] if check["id"] == "order-tenant-isolation"
        ]
        path = self.workspace / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        report = mutation.analyze(path, base_url=self.base_url)
        unkilled = {
            mutant["operator"]
            for mutant in report["checks"][0]["mutants"]
            if mutant["outcome"] not in (mutation.KILLED, mutation.SKIPPED)
        }
        # control: the outcome that motivated this is really there
        self.assertIn("M6", unkilled)
        paragraph = prose(
            shipped_fixture.__doc__.split("``/api/orders/o-1``", 1)[1].split("``/api/", 1)[0]
        )
        for operator in sorted(unkilled):
            with self.subTest(operator=operator):
                self.assertIn(f"``{operator}``", paragraph)
        self.assertIn("veridor_mutation_principal_fixture", paragraph)

    def test_the_unanswered_question_is_printed_beside_the_score(self) -> None:
        """A 1.00 with no survivors must not travel without the limit on it."""
        path = self.workspace / "config.json"
        path.write_text(
            json.dumps(
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
                    },
                    "checks": [
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
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        report = mutation.analyze(path, base_url=self.base_url)
        text = prose(mutation.render_text(report))
        self.assertIn("LIMITS ON THE EVIDENCE", text)
        self.assertIn("cannot be measured from outside this target", text)


class InertExclusionTest(_FixtureTarget):
    """An excludes_marker no observation could ever falsify.

    The exclusion names an identity this check never probes; it is licensed
    only by that identity's own ``marker_probe`` of an unrelated path, and the
    path under test 404s for everyone, so the owner's marker could not appear
    there under ANY authorization state. Inverting the assertion produces a
    finding -- a passing exclusion guarantees one, which is why the finding
    alone was never evidence -- and the operator must not bank it as a kill.
    """

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"},
                    "marker": ORDER_OWNER_MARKER,
                    "marker_probe": {"method": "GET", "path": "/api/orders/o-1"},
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
                "support": {"headers": {"Authorization": ROLELESS_TOKEN}},
            },
            [
                {
                    "id": "ghost-exclusion",
                    "request": {"method": "GET", "path": "/api/ghost/g-1"},
                    "expect": {
                        "outsider": {
                            "status": [404],
                            "excludes_marker": "order_owner",
                        },
                        "support": {"status": [404]},
                    },
                }
            ],
        )

    def test_the_baseline_passes_which_is_why_this_matters(self) -> None:
        result = core.execute_run(
            self.write(self.config()),
            output_dir=self.workspace / "out",
            base_url=self.base_url,
        )
        self.assertEqual(result["findings"], [])

    def test_an_inert_exclusion_survives(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M3", "outsider")[0]
        self.assertEqual(mutant["outcome"], mutation.SURVIVED)
        self.assertFalse(mutant["marker_observable_at_path"])
        self.assertEqual(mutant["marker_control_source"], "identity_probe")

    def test_the_diagnosis_says_the_oracle_could_not_have_fired(self) -> None:
        report = self.analyze(self.config())
        diagnosis = self.mutants(report, "M3", "outsider")[0]["diagnosis"]
        self.assertIn("could not have fired", diagnosis)
        self.assertIn("DIFFERENT path", diagnosis)

    def test_an_inconclusive_regrading_is_never_banked_as_a_kill(self) -> None:
        """The specific defect: any finding at all used to count, including one
        whose whole content is 'the oracle could no longer be satisfied'."""
        report = self.analyze(self.config())
        for mutant in self.mutants(report, "M3"):
            if mutant["outcome"] == mutation.KILLED:
                self.assertTrue(mutant["marker_observable_at_path"])

    def test_a_live_exclusion_on_the_same_target_is_still_killed(self) -> None:
        report = self.analyze(self.good_config())
        self.assertEqual(self.outcome(report, "M3", "outsider"), mutation.KILLED)


class SoftNotFoundEnvelopeTest(_FixtureTarget):
    """`200 {"data": null}` is not a resource, and a caller echo is not a control.

    Every id under ``/api/self/docs/`` answers a success envelope that echoes
    the CALLER's marker. That satisfies ``contains_marker`` on the owner and it
    satisfies "somebody got a 2xx", while there is nothing behind the route at
    all -- which is exactly the case a positive control exists to rule out.
    """

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"},
                    "marker": ORDER_OWNER_MARKER,
                },
                "outsider": {
                    "headers": {"Authorization": "Bearer outsider-token"},
                    "marker": OTHER_TENANT_MARKER,
                },
            },
            [
                {
                    "id": "self-doc-isolation",
                    "request": {"method": "GET", "path": "/api/self/docs/d-404"},
                    "expect": {
                        "order_owner": {
                            "status": [200],
                            "contains_marker": "order_owner",
                        },
                        "outsider": {
                            "status": [404],
                            "excludes_marker": "order_owner",
                        },
                    },
                }
            ],
        )

    def test_the_run_is_green_and_the_marker_oracle_is_satisfied(self) -> None:
        result = core.execute_run(
            self.write(self.config()),
            output_dir=self.workspace / "out",
            base_url=self.base_url,
        )
        self.assertEqual(result["findings"], [])

    def test_the_positive_control_survives(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M5")[0]
        self.assertEqual(mutant["outcome"], mutation.SURVIVED)
        self.assertEqual(
            mutant["positive_control_evidence"], "refuted_by_negative_control"
        )
        self.assertEqual(mutant["absent_resource_status"], 200)

    def test_the_diagnosis_names_the_echo_rather_than_the_resource(self) -> None:
        report = self.analyze(self.config())
        diagnosis = self.mutants(report, "M5")[0]["diagnosis"]
        self.assertIn("cannot name anything", diagnosis)
        self.assertIn("echoes back from the caller", diagnosis)

    def test_a_real_resource_is_still_a_positive_control(self) -> None:
        report = self.analyze(self.good_config())
        mutant = self.mutants(report, "M5")[0]
        self.assertEqual(mutant["outcome"], mutation.KILLED)
        self.assertEqual(mutant["positive_control"], "order_owner")
        self.assertEqual(mutant["positive_control_evidence"], "negative_control")
        self.assertNotEqual(mutant["absent_resource_status"], 200)

    def test_a_2xx_belonging_to_someone_else_is_not_a_positive_control(self) -> None:
        """An administrator's success says nothing about the owner's resource."""
        config = self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"},
                    "marker": ORDER_OWNER_MARKER,
                    "marker_probe": {"method": "GET", "path": "/api/orders/o-1"},
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
                "bystander": {"headers": {}},
            },
            [
                {
                    # 'order_owner' owns the data the exclusion protects and is
                    # itself refused here; the only 2xx in the check belongs to
                    # an unrelated caller and is not a control for anything.
                    "id": "hidden-with-a-bystander",
                    "request": {"method": "GET", "path": "/api/backwards/b-1"},
                    "expect": {
                        "order_owner": {"status": [403]},
                        "outsider": {
                            "status": [403],
                            "excludes_marker": "order_owner",
                        },
                        "bystander": {"status": [200]},
                    },
                }
            ],
        )
        report = self.analyze(config)
        mutant = self.mutants(report, "M5")[0]
        self.assertEqual(mutant["outcome"], mutation.SURVIVED)
        self.assertIsNone(mutant["positive_control"])

    def test_an_exhausted_budget_does_not_turn_the_survivor_into_a_kill(self) -> None:
        """The negative control was never sent, so the soft 404 was never ruled out.

        Measured before the fix: with no budget left this survivor was banked as
        a kill, the score went from 0.86 to 1.00 and the exit code from 1 to 0.
        """
        report = self.analyze(self.config(), request_budget=0)
        mutant = self.mutants(report, "M5")[0]
        self.assertEqual(mutant["outcome"], mutation.SKIPPED)
        self.assertEqual(mutant["skip_reason"], "budget_exhausted")


class UncorroboratedPositiveControlTest(unittest.TestCase):
    """An ``M5`` whose negative control was not sent, or did not complete, is no kill.

    The 2xx is only a positive control once a fabricated id on the same route is
    seen NOT to receive one. Without that request the soft-404 explanation is
    exactly as open as it was before, so the mutant is skipped or errored -- the
    same rule ``M4`` and ``M6`` follow -- and never killed on the status alone.
    """

    def _corroborate(
        self,
        *,
        method: str = "GET",
        path: str = "/api/docs/d-1",
        allowance: int | None = None,
        answer: dict | None = None,
    ) -> dict:
        sent: list[dict] = []

        def send(request, *, headers=None):
            sent.append(request)
            return answer or {"error": None, "response": {"status": 404}}

        context = SimpleNamespace(
            budget=mutation._Budget(allowance, 0),
            sham_token="veridor-sham-0123456789ab",  # gitleaks:allow
            config={"identities": {"owner": {"headers": {"Authorization": "x"}}}},
            send=send,
        )
        observation = mutation._Observation(
            check={"id": "c", "request": {"method": method, "path": path}},
            probes={},
            findings={},
        )
        mutant = mutation._m5_corroborate(context, observation, "m", "owner", 200)
        mutant["sent"] = len(sent)
        return mutant

    def test_a_corroborated_2xx_is_still_a_kill(self) -> None:
        """The control: the method can tell a corroborated kill from the rest."""
        mutant = self._corroborate()
        self.assertEqual(mutant["outcome"], mutation.KILLED)
        self.assertEqual(mutant["positive_control_evidence"], "negative_control")

    def test_an_exhausted_budget_is_skipped(self) -> None:
        mutant = self._corroborate(allowance=0)
        self.assertEqual(mutant["outcome"], mutation.SKIPPED)
        self.assertEqual(mutant["skip_reason"], "budget_exhausted")
        self.assertEqual(mutant["sent"], 0)

    def test_a_mutating_verb_is_skipped(self) -> None:
        mutant = self._corroborate(method="DELETE")
        self.assertEqual(mutant["outcome"], mutation.SKIPPED)
        self.assertEqual(mutant["skip_reason"], "mutating_verb")
        self.assertEqual(mutant["sent"], 0)

    def test_a_path_with_no_resource_id_is_skipped(self) -> None:
        mutant = self._corroborate(path="/")
        self.assertEqual(mutant["outcome"], mutation.SKIPPED)
        self.assertEqual(mutant["skip_reason"], "no_resource_id")

    def test_a_negative_control_that_did_not_complete_is_errored(self) -> None:
        mutant = self._corroborate(
            answer={"error": "timed out", "response": {"status": None}}
        )
        self.assertEqual(mutant["outcome"], mutation.ERRORED)
        self.assertTrue(mutant["diagnosis"])
        self.assertEqual(mutant["requests_issued"], 1)


class ExistenceHidingTest(_FixtureTarget):
    """404 to everyone but the owner is the SAFER design. Do not call it vacuous.

    ``M4`` used to compare one identity's status against itself uncredentialed
    and stop there, so a route that hides existence uniformly produced a
    survivor -- refuted, in the same ``_Observation``, by the owner's 200.
    """

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"},
                    "marker": ORDER_OWNER_MARKER,
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "invoice-existence-hiding",
                    "request": {"method": "GET", "path": "/api/hidden/inv-42"},
                    "expect": {
                        "order_owner": {
                            "status": [200],
                            "contains_marker": "order_owner",
                        },
                        "outsider": {
                            "status": [404],
                            "excludes_marker": "order_owner",
                        },
                    },
                }
            ],
        )

    def test_uniform_hiding_is_not_reported_as_a_survivor(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M4", "outsider")[0]
        self.assertEqual(mutant["outcome"], mutation.NOT_APPLICABLE)
        self.assertIn("hiding existence uniformly", mutant["diagnosis"])
        # Nor by the operator that asks the neighbouring question.
        self.assertEqual(
            self.outcome(report, "M6", "outsider"), mutation.NOT_APPLICABLE
        )

    def test_uniform_hiding_is_printed_under_limits_for_m4_too(self) -> None:
        report = self.analyze(self.config())
        notes = " ".join(report["checks"][0]["evidence_notes"])
        self.assertIn("Stripping the credential cannot measure", notes)

    def test_an_already_failing_baseline_is_not_a_limit(self) -> None:
        """The control on the other side: bookkeeping stays out of LIMITS."""
        config = self.config()
        config["checks"][0]["expect"]["outsider"]["status"] = [403]
        report = self.analyze(config)
        blocked = [
            mutant
            for mutant in self.mutants(report, "M4", "outsider")
            + self.mutants(report, "M6", "outsider")
            if mutant["outcome"] == mutation.NOT_APPLICABLE
        ]
        self.assertTrue(blocked)
        notes = " ".join(report["checks"][0]["evidence_notes"])
        self.assertNotIn("already failing", notes)
        self.assertEqual(report["summary"]["limited"], 0)

    def test_the_unmeasurable_mutant_stays_out_of_the_denominator(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(report["summary"][mutation.SURVIVED], 0)
        self.assertEqual(report["summary"]["score"], 1.0)

    def test_the_engines_own_evidence_refutes_the_old_claim(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(self.outcome(report, "M1", "outsider"), mutation.KILLED)
        self.assertEqual(self.outcome(report, "M4", "order_owner"), mutation.KILLED)
        self.assertEqual(self.outcome(report, "M5"), mutation.KILLED)

    def test_the_check_does_catch_the_regression_it_exists_for(self) -> None:
        self.guard_path.unlink()
        self.addCleanup(self.guard_path.write_text, "present\n", encoding="utf-8")
        result = core.execute_run(
            self.write(self.config()),
            output_dir=self.workspace / "broken",
            base_url=self.base_url,
        )
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["evidence_grade"], "confirmed")

    def test_a_genuinely_credential_blind_path_still_survives(self) -> None:
        """The narrowing must not silence the case M4 exists for."""
        config = self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "ghost-blind",
                    "request": {"method": "GET", "path": "/api/ghost/g-1"},
                    "expect": {
                        "order_owner": {"status": [404]},
                        "outsider": {"status": [404]},
                    },
                }
            ],
        )
        report = self.analyze(config)
        self.assertEqual(self.outcome(report, "M4", "outsider"), mutation.SURVIVED)


class PublicReadTest(_FixtureTarget):
    """A route that is public by design has no identity distinction to measure.

    There is no waiver, acknowledge or baseline concept in this module, so a
    survivor here would reappear on every CI run forever with nothing the
    operator could do about it.
    """

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "public-health-read",
                    "request": {"method": "GET", "path": "/api/public/health"},
                    "expect": {
                        "order_owner": {"status": [200]},
                        "outsider": {"status": [200]},
                    },
                }
            ],
        )

    def test_a_public_read_produces_no_survivor(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(report["survivors"], [])
        for identity in ("order_owner", "outsider"):
            mutant = self.mutants(report, "M4", identity)[0]
            self.assertEqual(mutant["outcome"], mutation.NOT_APPLICABLE)
            self.assertIn("public read", mutant["diagnosis"])

    def test_it_does_not_go_red_on_every_run_forever(self) -> None:
        self.assertEqual(mutation.exit_code(self.analyze(self.config())), 0)

    def test_the_public_read_is_printed_beside_the_score(self) -> None:
        """A 1.00 with no survivors must not travel without its reason.

        The module docstring promised this limit in LIMITS ON THE EVIDENCE;
        measured before the fix, only the generic status-only note was there.
        """
        report = self.analyze(self.config())
        notes = report["checks"][0]["evidence_notes"]
        self.assertEqual(
            sum("public read" in note for note in notes), 2, notes
        )
        self.assertEqual(report["summary"]["limited"], 2)
        self.assertIn("public read", prose(mutation.render_text(report)))


class DenyEveryoneTest(_FixtureTarget):
    """"No tenant identity may read the admin audit log" is an ordinary check.

    There is no owner to declare on that resource, so "declare an identity that
    must succeed here" is not a remediation, and the survivor's claim -- that
    the denial is equally well explained by an absent route -- is refuted by the
    403 the engine just observed.
    """

    def config(self) -> dict:
        return self.base(
            {
                "order_owner": {
                    "headers": {"Authorization": "Bearer order-owner-token"}
                },
                "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
            },
            [
                {
                    "id": "admin-audit-denied",
                    "request": {"method": "GET", "path": "/api/admin/audit"},
                    "expect": {
                        "order_owner": {"status": [403]},
                        "outsider": {"status": [403]},
                    },
                }
            ],
        )

    def test_an_explicit_refusal_is_not_a_missing_positive_control(self) -> None:
        report = self.analyze(self.config())
        mutant = self.mutants(report, "M5")[0]
        self.assertEqual(mutant["outcome"], mutation.NOT_APPLICABLE)
        self.assertNotIn("absent route", mutant["diagnosis"])
        self.assertIn("cannot be given one", mutant["diagnosis"])

    def test_the_check_is_not_vacuous_and_the_report_does_not_say_it_is(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(report["survivors"], [])
        self.guard_path.unlink()
        self.addCleanup(self.guard_path.write_text, "present\n", encoding="utf-8")
        result = core.execute_run(
            self.write(self.config()),
            output_dir=self.workspace / "broken",
            base_url=self.base_url,
        )
        self.assertEqual(len(result["findings"]), 2)

    def test_the_sham_operator_stays_quiet_on_a_deny_everyone_check(self) -> None:
        """A nobody being refused too is the declaration holding, not a defect."""
        report = self.analyze(self.config())
        for identity in ("order_owner", "outsider"):
            mutant = self.mutants(report, "M6", identity)[0]
            self.assertEqual(mutant["outcome"], mutation.NOT_APPLICABLE)
            self.assertIn("no identity in this check was served", mutant["observed"])
        self.assertEqual(mutation.exit_code(report), 0)

    def test_a_404_to_everyone_still_survives(self) -> None:
        """The 404 case is the one the operator was built for. Keep it."""
        report = self.analyze(MissingResourceTest.config(self))
        mutant = self.mutants(report, "M5")[0]
        self.assertEqual(mutant["outcome"], mutation.SURVIVED)
        self.assertIn("absent route", mutant["diagnosis"])


class GuardSeamDocumentationTest(_FixtureTarget):
    """The principal fixture's docstring names every route its guard opens.

    It once listed three routes behind ``guard_path`` while the code gated five:
    /api/scoped/inv-7 and /api/admin/audit open too, and the audit route was
    described as readable by nobody. DenyEveryoneTest relies on that audit
    branch, so a reader of the docstring could not tell why it expects two
    findings.
    """

    ROUTES = (
        "/api/orders/o-1",
        "/api/scoped/inv-7",
        "/api/self/docs/d-1",
        "/api/hidden/inv-42",
        "/api/public/health",
        "/api/admin/audit",
    )

    def statuses(self) -> dict[tuple[str, str], int]:
        import http.client  # noqa: PLC0415

        observed = {}
        for route in self.ROUTES:
            for token in ("", "Bearer outsider-token", ROLELESS_TOKEN):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", self.server.server_port, timeout=5
                )
                try:
                    connection.request(
                        "GET", route, headers={"Authorization": token} if token else {}
                    )
                    response = connection.getresponse()
                    response.read()
                    observed[(route, token)] = response.status
                finally:
                    connection.close()
        return observed

    def test_every_route_the_guard_opens_is_named_where_the_seam_is_described(self) -> None:
        import veridor_mutation_principal_fixture as principal  # noqa: PLC0415

        present = self.statuses()
        self.guard_path.unlink()
        self.addCleanup(self.guard_path.write_text, "present\n", encoding="utf-8")
        removed = self.statuses()
        opened = {
            route
            for (route, token), status in removed.items()
            if status != present[(route, token)]
        }
        # control: the public route is not gated, and the probe can tell
        self.assertNotIn("/api/public/health", opened)
        self.assertIn("/api/orders/o-1", opened)
        seam = prose(principal.__doc__.split("``guard_path``", 1)[1])
        named = {
            route
            for route in self.ROUTES
            if f"``{route}``" in seam
            or (route.startswith("/api/self/docs/") and "``/api/self/docs/*``" in seam)
        }
        self.assertEqual(named, opened)


class UnresolvedRenderingTest(_FixtureTarget):
    """An errored mutant must reach the artifact a human reads."""

    def report_with_an_errored_mutant(self) -> dict:
        report = self.analyze(self.good_config())
        errored = dict(report["checks"][0]["mutants"][0])
        errored.update(
            outcome=mutation.ERRORED,
            diagnosis="the credential could not be tested, so this is unknown",
            observed="the uncredentialed request did not complete",
        )
        report["checks"][0]["mutants"] = [errored]
        report["checks"][0].update(mutation._tally([errored]))
        report["summary"] = mutation.summarize([errored], checks=1)
        report["survivors"] = []
        report["unresolved"] = [errored]
        return report

    def test_an_errored_mutant_is_printed(self) -> None:
        text = mutation.render_text(self.report_with_an_errored_mutant())
        self.assertIn("could not be tested", prose(text))
        self.assertIn("[ERRORED]", text)

    def test_the_all_clear_is_not_printed_over_an_errored_mutant(self) -> None:
        text = mutation.render_text(self.report_with_an_errored_mutant())
        self.assertNotIn("No surviving mutants", text)
        self.assertIn("nothing here was measured", text)

    def test_the_count_that_says_to_read_above_points_at_something(self) -> None:
        report = self.report_with_an_errored_mutant()
        text = mutation.render_text(report)
        self.assertIn("to read above", text)
        printed = text.count("[ERRORED]") + text.count("[SURVIVED]")
        self.assertEqual(printed, len(report["unresolved"]))

    def test_a_genuinely_clean_report_still_says_so(self) -> None:
        text = mutation.render_text(self.analyze(self.good_config()))
        self.assertIn("No surviving mutants", text)


class UnmutatedSequenceTest(_FixtureTarget):
    """A v2 config's sequences are never mutated. Never publish over them silently."""

    def config(self) -> dict:
        config = self.good_config()
        config["version"] = 2
        config["sequences"] = [
            {
                "id": f"seq-{index}",
                "steps": [
                    {
                        "role": "assert",
                        "as": "outsider",
                        "request": {"method": "GET", "path": "/api/orders/o-1"},
                        "expect": {"status": [404]},
                    }
                ],
            }
            for index in range(3)
        ]
        return config

    def test_the_sequences_are_counted(self) -> None:
        report = self.analyze(self.config())
        self.assertEqual(report["summary"]["unmutated_sequences"], 3)
        self.assertEqual(
            [entry["id"] for entry in report["unmutated_declarations"]],
            ["seq-0", "seq-1", "seq-2"],
        )

    def test_the_report_says_which_ones_and_that_it_did_not_measure_them(self) -> None:
        report = self.analyze(self.config())
        text = prose(mutation.render_text(report))
        self.assertIn("NOT MEASURED", text)
        self.assertIn("seq-1", text)
        self.assertIn("3 declared sequence(s)", text)
        self.assertIn("seq-2", report["interpretation"]["not_measured"])

    def test_an_embedded_summary_carries_the_gap_too(self) -> None:
        block = mutation.mutation_summary(self.analyze(self.config()))
        self.assertEqual(block["unmutated_sequences"], 3)
        self.assertIn("sequence", block["not_measured"])

    def test_a_config_with_no_sequences_says_nothing_was_missed(self) -> None:
        report = self.analyze(self.good_config())
        self.assertEqual(report["summary"]["unmutated_sequences"], 0)
        self.assertEqual(report["unmutated_declarations"], [])
        self.assertNotIn("NOT MEASURED", mutation.render_text(report))


class BadgeSeverityTest(unittest.TestCase):
    """A known survivor must not colour better than an unexplained aberrant."""

    def badge(self, **summary) -> dict:
        base = {
            "generated": 0,
            "killed": 0,
            "survived": 0,
            "aberrant": 0,
            "errored": 0,
        }
        return mutation.render_badge({"tier": 1, "summary": {**base, **summary}})

    def test_survivors_never_render_green(self) -> None:
        badge = self.badge(generated=100, killed=95, survived=5)
        self.assertEqual(badge["message"], "95.0% killed")
        self.assertNotIn(badge["color"], {"green", "brightgreen"})

    def test_a_known_survivor_is_not_treated_more_leniently_than_an_aberrant(
        self,
    ) -> None:
        survivor = self.badge(generated=100, killed=95, survived=5)
        aberrant = self.badge(generated=40, killed=39, aberrant=1)
        self.assertEqual(survivor["color"], aberrant["color"])

    def test_a_clean_sweep_is_still_green(self) -> None:
        self.assertEqual(
            self.badge(generated=40, killed=40)["color"], "brightgreen"
        )


class HookArgvTest(unittest.TestCase):
    """Tier 2 must never crash out of the finally that restores the target.

    ``subprocess.run`` raises ``TypeError`` -- caught by neither ``OSError`` nor
    ``SubprocessError`` -- for an argv element that is not a string. On the
    restore command that exception propagated out of ``_run_hook``'s ``finally``
    and out of the whole run: no report, ``restore_verified`` never set, no "THE
    TARGET MAY STILL BE MUTATED", and the guard the apply command had already
    deleted still deleted. A JSON- or YAML-driven hook definition yields ints
    for numeric arguments as a matter of course.
    """

    def hook(self, **overrides) -> mutation.TargetMutationHook:
        return mutation.TargetMutationHook(
            **{
                "name": "drop-tenant-filter",
                "removes": "the tenant predicate",
                "apply_command": ("true",),
                "restore_command": ("true",),
                **overrides,
            }
        )

    def test_a_non_string_in_the_restore_argv_is_refused_before_anything_runs(
        self,
    ) -> None:
        hook = self.hook(restore_command=["./mutate.sh", "--port", 8080])
        with self.assertRaises(ConfigError) as raised:
            mutation._validate_hooks([hook])
        self.assertIn("restore_command[2]", str(raised.exception))
        self.assertIn("int", str(raised.exception))

    def test_a_non_string_in_the_apply_argv_is_refused_too(self) -> None:
        hook = self.hook(apply_command=["./mutate.sh", 3])
        with self.assertRaises(ConfigError):
            mutation._validate_hooks([hook])

    def test_a_restore_command_of_none_is_a_config_error_not_a_type_error(
        self,
    ) -> None:
        with self.assertRaises(ConfigError):
            mutation._validate_hooks([self.hook(restore_command=None)])

    def test_a_bare_string_command_is_refused_rather_than_split_into_letters(
        self,
    ) -> None:
        with self.assertRaises(ConfigError):
            mutation._validate_hooks([self.hook(apply_command="git checkout .")])

    @slow("spawns a subprocess")
    def test_invoke_reports_a_failure_instead_of_raising(self) -> None:
        """Defence in depth: nothing in the restore path may propagate."""
        self.assertEqual(
            mutation._invoke(self.hook(), ["./mutate.sh", 8080]), -1
        )
        self.assertEqual(mutation._invoke(self.hook(), [object()]), -1)

    def test_a_non_numeric_timeout_is_refused(self) -> None:
        with self.assertRaises(ConfigError):
            mutation._validate_hooks([self.hook(timeout_seconds="60")])


class CheckLevelCredentialTest(unittest.TestCase):
    """M4's unauthenticated copy drops every credential the check itself sends.

    Only Cookie, Authorization and Proxy-Authorization used to go. A check that
    authenticates with X-Api-Key kept it on the "unauthenticated" copy, so an
    identity with no headers of its own was skipped as having nothing to strip,
    and a 2xx through the surviving key was read as a public route.
    """

    def check(self, headers: dict) -> dict:
        return {
            "id": "c",
            "request": {"method": "GET", "path": "/api/x/1", "headers": headers},
            "expect": {"svc": {"status": [200]}},
        }

    def test_a_credential_named_check_header_is_stripped(self) -> None:
        surface = mutation._credential_surface(
            {"headers": {}}, self.check({"X-Api-Key": "k", "Accept": "a"})
        )
        self.assertEqual(surface["strips"], ["X-Api-Key"])
        self.assertEqual(surface["request"]["headers"], {"Accept": "a"})

    def test_authorization_is_still_stripped(self) -> None:
        """The control: the three names that always went still go."""
        surface = mutation._credential_surface(
            {"headers": {}}, self.check({"Authorization": "Bearer k"})
        )
        self.assertEqual(surface["strips"], ["Authorization"])
        self.assertEqual(surface["request"]["headers"], {})

    def test_the_key_only_check_is_measured_not_skipped(self) -> None:
        sent: list[dict] = []

        def send(request, *, headers=None):
            sent.append(request)
            keyed = "X-Api-Key" in (request.get("headers") or {})
            return {"error": None, "response": {"status": 200 if keyed else 401}}

        context = SimpleNamespace(
            config={"identities": {"svc": {"headers": {}}}},
            budget=mutation._Budget(None, 0),
            send=send,
        )
        observation = mutation._Observation(
            check=self.check({"X-Api-Key": "k"}),
            probes={"svc": {"error": None, "response": {"status": 200}}},
            findings={},
        )
        mutant = mutation._m4(context, observation)[0]
        self.assertEqual(mutant["outcome"], mutation.KILLED, mutant["observed"])
        self.assertEqual(len(sent), 1)
        self.assertNotIn("X-Api-Key", sent[0]["headers"])


class RequestEnvelopeTest(unittest.TestCase):
    """The rate limit has to cover the baseline, which is most of the traffic.

    The reproduced defect was 120 requests -- all of them BASELINE, all of them
    ``DELETE`` -- in 0.031 s. A limiter that charged only the additional ``M4``
    probes would have left that number exactly where it was.
    """

    def test_the_budget_charges_only_the_additional_requests(self) -> None:
        budget = mutation._Budget(2, 0.0)
        budget.wait()
        budget.wait()
        budget.wait()
        self.assertEqual(budget.spent, 0)
        self.assertFalse(budget.exhausted)
        budget.take()
        budget.take()
        self.assertEqual(budget.spent, 2)
        self.assertTrue(budget.exhausted)

    def test_waiting_and_taking_share_one_rate_limit(self) -> None:
        """Otherwise the two halves interleave at twice the declared rate."""
        budget = mutation._Budget(None, 0.05)
        started = time.monotonic()
        for step in range(6):
            budget.wait() if step % 2 else budget.take()
        # Five gaps between six requests, whichever method opened them.
        self.assertGreaterEqual(time.monotonic() - started, 5 * 0.05)

    def test_the_baseline_probes_go_through_the_limiter(self) -> None:
        """Asserted on the source, because the alternative is a live 60s test."""
        source = inspect.getsource(mutation._observe)
        self.assertIn("budget.wait()", source)
        self.assertIn("pace=budget.wait", source)

    def test_a_read_only_analysis_refuses_a_writing_configuration(self) -> None:
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        config_path = Path(workspace.name) / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "target": {"base_url": "http://127.0.0.1:1"},
                    "identities": {
                        "a": {"headers": {"Authorization": "Bearer a"}},
                        "b": {"headers": {}},
                    },
                    "checks": [
                        {
                            "id": "c",
                            "request": {"method": "DELETE", "path": "/api/thing"},
                            "expect": {"a": {"status": [200]}, "b": {"status": [401]}},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ConfigError) as caught:
            mutation.analyze(config_path, read_only=True)
        self.assertIn("--read-only refuses DELETE", str(caught.exception))
        # The refusal is the flag's, not the configuration's: the same file
        # loads without it. Asserted on the load rather than on a full analyze,
        # which would open a socket.
        core.load_config(config_path)


class PreflightBannerTest(unittest.TestCase):
    """`mutate` sent everything `run` sends, plus more, and disclosed nothing."""

    def config(self, method: str = "DELETE") -> dict:
        return {
            "target": {"base_url": "http://127.0.0.1:8765"},
            "identities": {
                "a": {
                    "headers": {"Authorization": "Bearer a"},
                    "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
                    "marker_probe": {"method": "GET", "path": "/me"},
                },
                "b": {"headers": {}},
            },
            "checks": [
                {
                    "id": "c",
                    "request": {"method": method, "path": "/api/thing"},
                    "expect": {"a": {"status": [200]}, "b": {"status": [401]}},
                }
            ],
        }

    def banner(self, method: str = "DELETE", **overrides) -> str:
        return mutation.preflight_banner(
            self.config(method),
            **{"min_interval_seconds": 0.5, "request_budget": 500, **overrides},
        )

    def test_the_baseline_count_is_exact(self) -> None:
        """Two check identities plus one marker_probe."""
        self.assertIn("re-issue your 3 declared request(s)", self.banner())

    def test_the_write_disclosure_names_the_verb(self) -> None:
        banner = self.banner()
        self.assertIn("This configuration issues DELETE", banner)
        self.assertIn("WRITES to the target", banner)
        self.assertIn("--read-only", banner)

    def test_a_read_only_configuration_says_so_instead(self) -> None:
        banner = self.banner("GET", read_only=True)
        self.assertNotIn("WRITES to the target", banner)
        self.assertIn("read-only: verified", banner)

    def test_the_rate_and_the_budget_are_both_stated(self) -> None:
        banner = self.banner()
        self.assertIn("2 req/s (0.5s apart), sequential", banner)
        self.assertIn("up to 500 additional probe(s)", banner)

    def test_no_limit_is_said_out_loud_rather_than_omitted(self) -> None:
        self.assertIn("no limit", self.banner(min_interval_seconds=0.0))

    def test_no_additional_probes_is_not_rendered_as_unlimited(self) -> None:
        """Tier 2 issues none. 'unlimited' would be the opposite of true."""
        banner = self.banner(request_budget=None, suite_runs=3)
        self.assertIn("no additional probes", banner)
        self.assertNotIn("unlimited", banner)
        self.assertIn("3 time(s)", banner)

    def test_tier_two_names_the_liveness_controls_each_run_sends(self) -> None:
        """'No additional probes' was false at tier 2: every suite run is an
        execute_run, and this GET's denial-only 'b' gets a liveness control."""
        banner = self.banner(
            "GET", request_budget=None, suite_runs=3, prove_liveness=True
        )
        self.assertIn("plus 1 liveness control(s) per run", banner)
        self.assertNotIn("no additional probes", banner)
        self.assertEqual(
            mutation.planned_requests(
                self.config("GET"),
                request_budget=None,
                suite_runs=3,
                prove_liveness=True,
            ),
            (3 + 1) * 3,
        )

    def test_the_banner_carries_no_credential(self) -> None:
        self.assertNotIn("Bearer", self.banner())
        self.assertNotIn("vdr-", self.banner())

    def test_the_write_surface_is_the_one_run_discloses(self) -> None:
        """One definition of a write, shared with `run`'s own disclosure."""
        source = inspect.getsource(mutation.preflight_banner)
        self.assertIn("_mutating_disclosure_surface", source)


class EvidenceContainmentTest(unittest.TestCase):
    """Tier-2 evidence must land under --output-dir, whatever the hook is called.

    ``output_dir / f"{index:02d}-{hook.name}"`` prefixed only the FIRST path
    component, and the hook name was the one field in the hooks file with no
    validation at all. A name of ``../../../public/docs`` scattered the run
    documents -- the ones the CLI prints "Do not publish them" about -- outside
    the directory it announced, and the announced directory was left empty.
    """

    #: Names that must not be able to write outside the parent, plus the ones
    #: that used to sanitise to nothing and would then BE the parent.
    ESCAPES = (
        "..",
        ".",
        "...",
        "/",
        "/etc/passwd",
        "../../../../tmp/vd-ESCAPED",
        "a/../../../../vd-ESCAPED",
        "..\\..\\windows",
        "~/.ssh",
        "   ",
        "!!!",
        "中文",
        "\x00evil",
        "x" * 500,
    )

    def test_no_hook_name_can_write_outside_the_parent(self) -> None:
        parent = Path("/veridor-out/mutation/tier2-runs")
        for index, name in enumerate(self.ESCAPES):
            with self.subTest(name=name):
                component = mutation.evidence_component(index, name)
                self.assertNotIn("/", component)
                self.assertNotIn("\\", component)
                self.assertNotIn("\x00", component)
                self.assertEqual((parent / component).resolve().parent, parent)

    def test_an_unnameable_hook_still_gets_a_usable_directory(self) -> None:
        """Empty is not an option: it would resolve to the parent itself."""
        for index, name in enumerate(("..", ".", "...", "   ", "!!!", "中文")):
            with self.subTest(name=name):
                component = mutation.evidence_component(index, name)
                self.assertEqual(component, f"{index:02d}-hook")

    def test_distinct_hooks_never_share_a_directory(self) -> None:
        """Sanitising collapses names; the index is what keeps them apart."""
        components = [
            mutation.evidence_component(index, name)
            for index, name in enumerate(("../x", "..\\x", "!!!", "???"))
        ]
        self.assertEqual(len(set(components)), len(components))

    def test_a_readable_name_survives_sanitising(self) -> None:
        self.assertEqual(
            mutation.evidence_component(3, "drop-tenant-filter"), "03-drop-tenant-filter"
        )
        self.assertEqual(
            mutation.evidence_component(0, "drop the tenant filter"),
            "00-drop-the-tenant-filter",
        )

    def test_no_component_is_hidden_or_a_relative_segment(self) -> None:
        for index, name in enumerate(self.ESCAPES):
            with self.subTest(name=name):
                component = mutation.evidence_component(index, name)
                _, _, tail = component.partition("-")
                self.assertNotIn("..", component)
                self.assertFalse(tail.startswith("."))
                self.assertTrue(tail)


@slow("stands up the loopback fixture and runs the real suite against it")
class EvidenceContainmentRunTest(_FixtureTarget):
    """:class:`EvidenceContainmentTest`, end to end, through a hook that RAN.

    This used to point at ``http://127.0.0.1:1``. Once tier 2 started running
    the suite against the unmutated target first, that run errored, no hook was
    applied, and no hook evidence directory was ever made -- so the test kept
    passing with ``evidence_component`` replaced by the old interpolation it
    exists to catch. It now runs against the live fixture, where the unmutated
    suite is green and the no-op hook survives, and asserts that it did.
    """

    def test_the_run_writes_evidence_only_under_output_dir(self) -> None:
        escape = self.workspace / "OUTSIDE"
        output_dir = self.workspace / "inside"
        hook = mutation.TargetMutationHook(
            name=f"a/../../{escape.name}",
            removes="nothing; this hook exists to name a directory",
            apply_command=("true",),
            restore_command=("true",),
        )
        report = mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook],
            output_dir=output_dir,
            base_url=self.base_url,
        )
        # The hook has to have run, or no hook evidence directory was ever
        # made and the containment assertions below hold vacuously.
        self.assertEqual(report["checks"][0]["outcome"], mutation.SURVIVED)
        self.assertFalse(escape.exists(), f"{escape} was created outside --output-dir")
        hook_dir = output_dir / mutation.evidence_component(0, hook.name)
        self.assertTrue(any(hook_dir.rglob("*.json")), f"nothing written under {hook_dir}")
        written = [path for path in output_dir.rglob("*") if path.is_file()]
        for path in written:
            self.assertTrue(path.resolve().is_relative_to(output_dir.resolve()), path)


def _graded_check(check_id: str, path: str, expect: dict) -> dict:
    return {"id": check_id, "request": {"method": "GET", "path": path}, "expect": expect}


@slow("stands up a loopback HTTP server and runs the engine against it")
class GradedVacuityTest(unittest.TestCase):
    """Both arms of fixtures/graded_vacuity_fixture.py, run.

    The graded target was shipped with nothing that ran it, so its routes could
    rot and its two questions -- does the engine catch the vacuous checks, and
    does it leave the good ones alone -- went unasked. Each arm is asserted
    here, because either alone is meaningless: an engine that flags everything
    catches every vacuity.
    """

    GOOD = (
        _graded_check("docs-alice", "/api/docs/d-alice", {
            "alice": {"status": [200], "contains_marker": "alice"},
            "mallory": {"status": [403], "excludes_marker": "alice"},
        }),
        _graded_check("docs-mallory", "/api/docs/d-mallory", {
            "mallory": {"status": [200], "contains_marker": "mallory"},
            "alice": {"status": [403], "excludes_marker": "mallory"},
        }),
        _graded_check("invoices-alice", "/api/invoices/inv-alice", {
            "alice": {"status": [200], "contains_marker": "alice"},
            "mallory": {"status": [404], "excludes_marker": "alice"},
        }),
        _graded_check("projects-alice", "/api/projects/p-alice", {
            "alice": {"status": [200], "contains_marker": "alice"},
            "mallory": {"status": [403], "excludes_marker": "alice"},
        }),
        _graded_check("exports-alice", "/api/exports/e-alice", {
            "alice": {"status": [200], "contains_marker": "alice"},
            "mallory": {"status": [404], "excludes_marker": "alice"},
            "anonymous": {"status": [401]},
        }),
        _graded_check("admin-audit", "/api/admin/audit", {
            "root": {"status": [200], "contains_marker": "root"},
            "alice": {"status": [403]},
            "mallory": {"status": [403]},
        }),
    )

    #: ``(check, the survivor that names its vacuity)``
    VACUOUS = (
        (_graded_check("docs-alice-stale", "/api/docs/d-alice", {
            "alice": {"status": [200], "contains_marker": "alice"},
            "stale": {"status": [401, 403], "excludes_marker": "alice"},
        }), ("M4", "stale")),
        (_graded_check("ghost", "/api/ghost/g-1", {
            "alice": {"status": [404]},
            "mallory": {"status": [404]},
        }), ("M5", None)),
        (_graded_check("wide", "/api/wide/w-1", {
            "alice": {"status": [200]},
            "mallory": {"status": [200, 403, 404]},
        }), ("M1", "mallory")),
        (_graded_check("beta", "/api/beta/b-1", {
            "alice": {"status": [200]},
            "mallory": {"status": [403]},
        }), ("M6", "mallory")),
        (_graded_check("public-notice", "/api/public/notice", {
            "alice": {"status": [200]},
            "anonymous": {"status": [200, 401]},
        }), ("M1", "anonymous")),
        (_graded_check("reports", "/api/reports/r-9", {
            "alice": {"status": [401]},
            "mallory": {"status": [401]},
        }), ("M4", "alice")),
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.guard_dir = tempfile.TemporaryDirectory()
        cls.guard_path = Path(cls.guard_dir.name) / "tenant-guard"
        cls.guard_path.write_text("present\n", encoding="utf-8")
        cls.server = graded.create_server("127.0.0.1", 0, guard_path=cls.guard_path)
        cls.thread = loopback.start(cls.server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.guard_dir.cleanup()

    def setUp(self) -> None:
        self.guard_path.write_text("present\n", encoding="utf-8")
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.workspace = Path(self._workspace.name)

    def write(self, check: dict) -> Path:
        path = self.workspace / f"{check['id']}.json"
        path.write_text(json.dumps({
            "version": 1,
            "target": {"base_url": self.base_url, "timeout_seconds": 5},
            "identities": {
                "alice": {"headers": {"Authorization": graded.ALICE_TOKEN},
                          "marker": graded.ALICE_MARKER},
                "mallory": {"headers": {"Authorization": graded.MALLORY_TOKEN},
                            "marker": graded.MALLORY_MARKER},
                "root": {"headers": {"Authorization": graded.ROOT_TOKEN},
                         "marker": graded.ROOT_MARKER},
                "stale": {"headers": {"Authorization": graded.STALE_TOKEN}},
                "anonymous": {"headers": {}},
            },
            "checks": [check],
        }), encoding="utf-8")
        return path

    def survivors(self, check: dict) -> tuple[dict, set]:
        report = mutation.analyze(self.write(check), base_url=self.base_url)
        (graded_check,) = report["checks"]
        return graded_check, {
            (mutant["operator"], mutant["identity"])
            for mutant in graded_check["mutants"]
            if mutant["outcome"] == mutation.SURVIVED
        }

    def assert_green(self, check: dict) -> None:
        # Both arms pass a plain run: a vacuous check is one that passes and
        # proves nothing, and a check that fails has no survivors to count.
        result = core.execute_run(
            self.write(check),
            output_dir=self.workspace / f"run-{check['id']}",
            base_url=self.base_url,
        )
        self.assertEqual(result["findings"], [], f"{check['id']} is not green")

    def test_no_good_check_is_flagged(self) -> None:
        for check in self.GOOD:
            with self.subTest(check=check["id"]):
                self.assert_green(check)
                summary, survived = self.survivors(check)
                self.assertEqual(survived, set())
                self.assertEqual(summary["errored"], 0)
                self.assertGreater(summary["killed"], 0)

    def test_every_vacuous_check_is_caught_for_its_own_reason(self) -> None:
        for check, expected in self.VACUOUS:
            with self.subTest(check=check["id"]):
                self.assert_green(check)
                _, survived = self.survivors(check)
                self.assertIn(expected, survived)

    def test_the_markerless_boundary_cannot_be_declared_as_though_it_had_one(self) -> None:
        # /api/settings/s-alice carries no marker. An excludes_marker over it
        # is refused at load for want of a control, and the status-only form
        # says that status is its only evidence instead of passing as more.
        with self.assertRaisesRegex(ConfigError, "requires a control"):
            mutation.analyze(self.write(_graded_check("settings", "/api/settings/s-alice", {
                "alice": {"status": [200]},
                "mallory": {"status": [403], "excludes_marker": "alice"},
            })), base_url=self.base_url)
        summary, _ = self.survivors(_graded_check("settings", "/api/settings/s-alice", {
            "alice": {"status": [200]},
            "mallory": {"status": [403]},
        }))
        self.assertEqual(summary["marker_evidence"], "status_only")

    def test_the_guard_seam_opens_alices_document_to_mallory(self) -> None:
        check = self.GOOD[0]
        clean = core.execute_run(
            self.write(check), output_dir=self.workspace / "clean", base_url=self.base_url
        )
        self.assertEqual(clean["findings"], [])
        self.guard_path.unlink()
        broken = core.execute_run(
            self.write(check), output_dir=self.workspace / "broken", base_url=self.base_url
        )
        self.assertEqual(
            {finding["identity"] for finding in broken["findings"]}, {"mallory"}
        )


class GradedVacuityDocumentationTest(unittest.TestCase):
    """The graded fixture's summary of its suite says what the suite requires.

    The summary once said the suite requires a survivor on each VACUOUS check,
    while the fixture's own VACUOUS list includes ``/api/settings/s-alice``,
    which GradedVacuityTest pins as refused at load or disclosed as
    status-only -- never as a survivor. A VACUOUS route with no survivor entry
    must be named in the summary as the exception, and nowhere in the summary
    may a survivor still be asked of it.
    """

    def summary(self) -> str:
        return prose(graded.__doc__.split("\n\n")[1])

    def routes_without_survivor(self) -> set[str]:
        listed = set(re.findall(
            r"^``(/api/[^`]+)``",
            graded.__doc__.split("VACUOUS routes", 1)[1].split("Every route rejects", 1)[0],
            re.MULTILINE,
        ))
        with_survivor = {check["request"]["path"] for check, _ in GradedVacuityTest.VACUOUS}
        # control: the parse finds the survivor routes it should
        self.assertLessEqual(with_survivor, listed)
        without = listed - with_survivor
        self.assertTrue(without)
        return without

    def test_every_vacuous_route_without_a_survivor_is_named_in_the_summary(self) -> None:
        summary = self.summary()
        for route in sorted(self.routes_without_survivor()):
            self.assertIn(f"``{route}``", summary, f"{route} has no survivor entry")

    def test_the_summary_asks_no_survivor_of_a_route_that_has_none(self) -> None:
        # Naming the route is not enough. A summary that named
        # /api/settings/s-alice and still said its survivor was required
        # passed the test above. Each such route must be named in the
        # exception to the survivor requirement and not before it, the
        # exception must not ask for a survivor either, and no other sentence
        # that names the route may mention a survivor at all.
        sentences = re.split(r"(?<=[.;?])\s+", self.summary())
        requirement = [
            sentence
            for sentence in sentences
            if re.search(r"\bsurvivor\b.*\brequired\b", sentence)
        ]
        # control: the survivor requirement is found, and found once
        self.assertEqual(len(requirement), 1, requirement)
        rule, marker, exception = requirement[0].partition(" except ")
        self.assertTrue(marker, f"the survivor requirement has no exception: {rule!r}")
        self.assertNotIn("survivor", exception)
        for route in sorted(self.routes_without_survivor()):
            tag = f"``{route}``"
            self.assertNotIn(tag, rule, f"{route} is inside the survivor requirement")
            self.assertIn(tag, exception, f"{route} is not in its exception")
            for sentence in sentences:
                if tag in sentence and sentence is not requirement[0]:
                    self.assertNotIn("survivor", sentence, f"{route}: {sentence!r}")


class UnrestoredTargetRenderingTest(_FixtureTarget):
    """The loudest thing this module says has to reach the page it is on."""

    def report(self) -> dict:
        guard = str(self.guard_path)
        hook = mutation.TargetMutationHook(
            name="drop-tenant-filter",
            removes="the tenant predicate on /api/orders/o-1",
            apply_command=[
                sys.executable,
                "-c",
                f"import pathlib; pathlib.Path({guard!r}).unlink()",
            ],
            restore_command=[sys.executable, "-c", "raise SystemExit(3)"],
            timeout_seconds=60,
        )
        return mutation.run_target_mutations(
            self.write(self.good_config()),
            [hook, mutation.TargetMutationHook(
                name="drop-role-check",
                removes="the role check",
                apply_command=[sys.executable, "-c", "pass"],
                restore_command=[sys.executable, "-c", "pass"],
                timeout_seconds=60,
            )],
            output_dir=self.workspace / "tier2",
            base_url=self.base_url,
        )

    def test_the_json_still_records_it(self) -> None:
        report = self.report()
        self.assertIs(report["checks"][0]["restore_verified"], False)
        self.assertEqual(mutation.exit_code(report), 2)

    def test_the_rendered_text_shouts_it_before_anything_else(self) -> None:
        text = mutation.render_text(self.report())
        self.assertIn("THE TARGET MAY STILL BE MUTATED", text)
        self.assertLess(
            text.index("THE TARGET MAY STILL BE MUTATED"),
            text.index("Mutation score"),
        )
        self.assertIn("restore command", prose(text))

    def test_the_all_clear_is_never_printed_over_a_stranded_target(self) -> None:
        text = mutation.render_text(self.report())
        self.assertNotIn("No surviving mutants", text)

    def test_the_written_artifact_carries_it_too(self) -> None:
        paths = mutation.write_reports(self.report(), self.workspace / "out")
        self.assertIn(
            "THE TARGET MAY STILL BE MUTATED",
            paths["text"].read_text(encoding="utf-8"),
        )


class SkipReasonTest(unittest.TestCase):
    """`skipped 3` published a number whose reasons lived only in the JSON.

    The LIMITS block covers `not_applicable`. `skipped` was the one count a
    reader could not act on: nothing on the console distinguished "the budget
    ran out" from "there was nothing here to strip", and the two ask for
    entirely different responses.
    """

    def _skipped(self, reason: str) -> dict:
        return {"outcome": mutation.SKIPPED, "skip_reason": reason, "operator": "M4"}

    def test_the_reasons_partition_the_count(self) -> None:
        summary = mutation.summarize(
            [
                self._skipped("budget_exhausted"),
                self._skipped("no_credential_to_strip"),
                self._skipped("no_credential_to_strip"),
                {"outcome": mutation.KILLED, "operator": "M4"},
            ],
            checks=1,
        )
        self.assertEqual(
            sum(summary["skipped_reasons"].values()), summary[mutation.SKIPPED]
        )
        self.assertEqual(summary["skipped_reasons"]["no_credential_to_strip"], 2)

    def test_every_skip_site_carries_a_known_reason(self) -> None:
        """An untagged site would add to `skipped` and to no reason, silently.

        Asserted STRUCTURALLY. The first version of this test grepped for
        `skip_reason="..."` and compared the set it found against SKIP_REASONS
        -- which is exactly what a NEW untagged site does not contain, so the
        one failure the docstring names was the one failure it could not see.
        """
        tree = ast.parse(Path(mutation.__file__).read_text(encoding="utf-8"))
        sites = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            names = {kw.arg for kw in node.keywords if kw.arg}
            marks_skipped = any(
                kw.arg == "outcome"
                and isinstance(kw.value, ast.Name)
                and kw.value.id == "SKIPPED"
                for kw in node.keywords
            )
            if marks_skipped:
                sites.append((node.lineno, names))
        self.assertTrue(sites, "no call marks a mutant SKIPPED; did the API move?")
        untagged = [line for line, names in sites if "skip_reason" not in names]
        self.assertEqual(
            untagged, [], f"outcome=SKIPPED without skip_reason at line(s) {untagged}"
        )
        # Every tag names a declared reason, and every declared reason is used.
        # Two spellings, both real: `skip_reason="x"` passed straight to the
        # recorder, and `skip_reason = "x"` assigned per branch and passed by
        # name. Collecting only the first is why the reverse check needs both.
        tagged = {
            kw.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for kw in node.keywords
            if kw.arg == "skip_reason" and isinstance(kw.value, ast.Constant)
        } | {
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and any(
                isinstance(target, ast.Name) and target.id == "skip_reason"
                for target in node.targets
            )
        }
        self.assertEqual(tagged - set(mutation.SKIP_REASONS), set())
        self.assertEqual(set(mutation.SKIP_REASONS) - tagged, set())

    def _rendered(self, mutants: list[dict]) -> str:
        return mutation.render_text({
            "tier": 1,
            "config": "veridor.json",
            "summary": mutation.summarize(mutants, checks=1),
            "survivors": [],
            "checks": [],
            "operators": {},
        })

    def test_the_render_prints_the_reasons_with_their_counts(self) -> None:
        text = self._rendered(
            [self._skipped("budget_exhausted"), self._skipped("already_served")]
        )
        self.assertIn("skipped, by reason", text)
        self.assertIn("the mutation request budget is exhausted", text)
        self.assertIn("no denial", text)
        self.assertIn("whose meaning is in question", text)

    def test_a_summary_with_no_skips_prints_no_block(self) -> None:
        text = self._rendered([{"outcome": mutation.KILLED, "operator": "M4"}])
        self.assertNotIn("skipped, by reason", text)

    def test_the_mutating_verb_reason_names_the_real_safe_set(self) -> None:
        """OPTIONS is safe and IS mutated; a reason saying "GET or HEAD" is false."""
        reason = mutation.SKIP_REASONS["mutating_verb"]
        for method in sorted(core.SAFE_METHODS):
            self.assertIn(method, reason)


class OperatorCatalogueTest(unittest.TestCase):
    def test_every_operator_states_the_defect_it_catches(self) -> None:
        for name, meta in mutation.OPERATORS.items():
            with self.subTest(operator=name):
                self.assertTrue(meta["catches"].strip())
                self.assertTrue(meta["kill_direction"].strip())
                self.assertTrue(meta["mutates"].strip())

    def test_the_scored_outcomes_partition_the_generated_count(self) -> None:
        self.assertEqual(
            set(mutation.OUTCOMES) - mutation._SCORED,
            {mutation.NOT_APPLICABLE, mutation.SKIPPED},
        )


if __name__ == "__main__":
    unittest.main()
