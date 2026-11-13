"""A credential the target refused everywhere is named as the likely cause.

Reproduced on the journey lane: ``VERIDOR_GLOBEX_TOKEN`` set to an expired
value drew 401 on every probe globex sent, its marker_probe included, and the
run printed four ``unexpected_denial`` findings whose remediation named "an
absent route, an unshipped feature, or an over-restriction" -- everything but
the token. Nothing in the output said the four shared one cause.

The hint is a hint: it never changes a verdict, a grade or an exit code, and
it is never printed for an identity that was refused only where it was
declared to be (an anonymous caller expected to draw 401).
"""

from __future__ import annotations

import contextlib
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

from test_capsule import VERIFIER_ENV, _demo_target, _TargetOpener, _v010_capsule  # noqa: E402
from test_sequence import OWNER_TOKEN, _JSON, _server, _step  # noqa: E402
from test_sequence import _config as _sequence_config  # noqa: E402
from test_sequence import _run as _sequence_run  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

HINT = "credential looks expired or invalid"
#: The hand-built results below name identities "a" and "anonymous"; "a"
#: presents a credential, "anonymous" does not.
CREDENTIALED = ("a",)


def _config() -> dict:
    capsule = _v010_capsule()
    return {
        "version": 1,
        "target": capsule["target"],
        "identities": capsule["identities"],
        "checks": [capsule["check"]],
    }


def _run(answer, *, env: dict | None = None, config: dict | None = None) -> dict:
    opener = _TargetOpener(answer)
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "veridor.json"
        path.write_text(json.dumps(config or _config()), encoding="utf-8")
        argv = ["run", "--config", str(path), "--output-dir", str(root / "out")]
        with patch.dict(os.environ, VERIFIER_ENV if env is None else env), \
                patch.object(core, "_OPENER", opener):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(argv)
        document = json.loads((root / "out" / "latest.json").read_text())
    return {"code": code, "stdout": stdout.getvalue(), "stderr": stderr.getvalue(),
            "document": document}


def _expired(**extra: str) -> dict:
    env = dict(VERIFIER_ENV)
    env["VERIDOR_OTHER_TENANT_TOKEN"] = "expired-token"
    env.update(extra)
    return env


class CredentialHintRunTest(unittest.TestCase):
    def test_an_identity_refused_401_everywhere_is_named(self) -> None:
        result = _run(_demo_target(vulnerable=False), env=_expired())
        hints = [line for line in result["stdout"].splitlines() if HINT in line]
        self.assertEqual(len(hints), 1, result["stdout"])
        self.assertIn("other_tenant", hints[0])
        self.assertIn("VERIDOR_*", hints[0])
        # anonymous drew 401 too, on every probe -- as it was declared to.
        self.assertNotIn("anonymous", hints[0])

    def test_the_hint_changes_no_verdict_and_no_exit_code(self) -> None:
        result = _run(_demo_target(vulnerable=False), env=_expired())
        verdicts = [
            (finding["identity"], finding["verdict"])
            for finding in result["document"]["findings"]
        ]
        self.assertEqual(verdicts, [("other_tenant", "unexpected_denial")])
        self.assertEqual(result["code"], 1)

    def test_control_a_working_credential_draws_no_hint(self) -> None:
        result = _run(_demo_target(vulnerable=False))
        self.assertEqual(result["code"], 0, result["stdout"] + result["stderr"])
        self.assertNotIn(HINT, result["stdout"])

    def test_an_anonymous_identity_declared_served_is_not_named(self) -> None:
        """`"headers": {}` declared [200] on an authenticated route draws 401.

        Reproduced on the journey lane: the run printed "anonymous was refused
        ... its credential looks expired or invalid -- check the VERIDOR_*
        variable that supplies it" for an identity that sends no credential.
        """
        config = _config()
        self.assertEqual(config["identities"]["anonymous"], {"headers": {}})
        config["checks"][0]["expect"]["anonymous"] = {"status": [200]}
        result = _run(_demo_target(vulnerable=False), config=config)
        self.assertIn(("anonymous", "unexpected_denial"),
                      [(f["identity"], f["verdict"]) for f in result["document"]["findings"]])
        self.assertNotIn(HINT, result["stdout"])
        self.assertNotIn("credential_suspects", result["document"])

    def test_the_run_document_records_whom_the_hint_named(self) -> None:
        result = _run(_demo_target(vulnerable=False), env=_expired())
        self.assertEqual(result["document"]["credential_suspects"], ["other_tenant"])

    def test_a_marker_probe_the_target_served_rules_the_hint_out(self) -> None:
        """One 200 anywhere proves the credential worked."""
        demo = _demo_target(vulnerable=False)

        def answer(method, path, authorization):
            if authorization == "Bearer expired-token":
                if path == "/api/invoices/inv-200":
                    return 200, {"id": "inv-200"}
                return 401, {"error": "unknown credential"}
            return demo(method, path, authorization)

        result = _run(answer, env=_expired())
        self.assertIn("unexpected_denial",
                      [finding["verdict"] for finding in result["document"]["findings"]])
        self.assertNotIn(HINT, result["stdout"])

    def test_the_denial_remediation_names_the_credential_for_401(self) -> None:
        result = _run(_demo_target(vulnerable=False), env=_expired())
        (finding,) = result["document"]["findings"]
        self.assertIn("expired/invalid credential", finding["remediation"])


class CredentialSuspectsTest(unittest.TestCase):
    @staticmethod
    def _probe(identity: str, status: int | None) -> dict:
        return {"identity": identity, "response": {"status": status}}

    @staticmethod
    def _denied(identity: str) -> dict:
        return {"identity": identity, "verdict": "unexpected_denial"}

    def test_407_counts_as_a_credential_refusal(self) -> None:
        result = {"probes": [self._probe("a", 407), self._probe("a", 401)],
                  "findings": [self._denied("a")]}
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), ["a"])

    def test_a_served_sequence_step_rules_the_hint_out(self) -> None:
        result = {
            "probes": [self._probe("a", 401)],
            "sequences": [{"steps": [{"as": "a", "response": {"status": 200}}]}],
            "findings": [self._denied("a")],
        }
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), [])

    def test_a_served_teardown_entry_rules_the_hint_out(self) -> None:
        """A teardown record keeps its status at the top level, not in a response."""
        result = {
            "probes": [self._probe("a", 401)],
            "sequences": [{"steps": [], "teardown": [
                {"as": "a", "status": 204, "state": "executed", "error": None},
            ]}],
            "findings": [self._denied("a")],
        }
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), [])
        result["sequences"][0]["teardown"][0]["status"] = 401
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), ["a"])

    def test_a_marker_probe_answered_otherwise_rules_the_hint_out(self) -> None:
        result = {
            "probes": [self._probe("a", 401)],
            "marker_controls": [{"identity": "a", "response": {"status": 403}}],
            "findings": [self._denied("a")],
        }
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), [])

    def test_an_unanswered_probe_is_neither_a_refusal_nor_a_pass(self) -> None:
        result = {"probes": [self._probe("a", None)], "findings": [self._denied("a")]}
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), [])
        result["probes"].append(self._probe("a", 401))
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), ["a"])

    def test_an_identity_with_no_credential_is_never_named(self) -> None:
        """It sends nothing that could expire; its 401 is the boundary answering."""
        result = {"probes": [self._probe("anonymous", 401)],
                  "findings": [self._denied("anonymous")]}
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), [])
        self.assertEqual(core.credential_suspects(result, ("anonymous",)), ["anonymous"])

    def test_declared_refusals_alone_name_nobody(self) -> None:
        result = {"probes": [self._probe("anonymous", 401)], "findings": []}
        self.assertEqual(core.credential_suspects(result, CREDENTIALED), [])

    def test_other_denial_statuses_keep_the_old_remediation(self) -> None:
        for status in (403, 404, 500, None):
            with self.subTest(status=status):
                self.assertEqual(core.denial_remediation(status), core._DENIAL_REMEDIATION)
                self.assertNotIn("credential", core.denial_remediation(status))
        for status in (401, 407):
            with self.subTest(status=status):
                self.assertIn("expired/invalid credential", core.denial_remediation(status))


@slow("runs a sequence against a loopback listener")
class CredentialSuspectsSequenceRunTest(unittest.TestCase):
    """The record shapes a real sequence run writes, not hand-built ones.

    The owner's assert step draws 401 (an unexpected_denial) and its teardown
    DELETE is served 204: the credential demonstrably worked, so naming the
    owner as "refused on every request" would be false.
    """

    def _suspects(self, teardown_status: int) -> list[str]:
        def responder(method, path, token, body):
            if token == OWNER_TOKEN:
                if method == "DELETE":
                    return (teardown_status, {}, b"")
                return (401, _JSON, b"{}")
            return (403, _JSON, b"{}")

        config = _sequence_config(
            [{
                "id": "s",
                "steps": [
                    _step("assert", "owner", "GET", "/a", [200]),
                    _step("assert", "attacker", "GET", "/a", [403]),
                ],
                "teardown": [{
                    "as": "owner",
                    "request": {"method": "DELETE", "path": "/z"},
                    "expect": {"status": [204]},
                }],
            }],
            marker=False,
        )
        with contextlib.redirect_stderr(io.StringIO()), _server(responder) as url:
            result = _sequence_run(config, url)
        self.assertIn(("owner", "unexpected_denial"),
                      [(f["identity"], f["verdict"]) for f in result["findings"]])
        return result.get("credential_suspects", [])

    def test_a_teardown_the_target_served_rules_the_hint_out(self) -> None:
        self.assertEqual(self._suspects(204), [])

    def test_control_a_refused_teardown_keeps_the_hint(self) -> None:
        self.assertEqual(self._suspects(401), ["owner"])


if __name__ == "__main__":
    unittest.main()
