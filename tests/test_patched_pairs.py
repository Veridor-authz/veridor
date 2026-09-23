"""scripts/patched_pairs.py: what it runs, which images, and which Veridor.

The harness needs docker and real builds, and CI's detection-baseline jobs run
it. What decides WHAT it runs (every pair, or --pair), WHICH images (the
digest pins, the local-tag check, --pull) and WHICH Veridor (the installed-mode
guard) is plain code, tested here without docker: every function that would
touch docker is replaced by a stub, and the fast tier's guard fails any test
that forgets one. The one slow test runs the real guard in a real interpreter.
"""

from __future__ import annotations

import contextlib
import copy
import fnmatch
import importlib.util
import io
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402

SCRIPT = ROOT / "scripts" / "patched_pairs.py"
_LOADS = itertools.count()


def load_harness():
    """A fresh copy of the module, so a test's PAIRS_DIR never leaks into another's."""
    spec = importlib.util.spec_from_file_location(f"patched_pairs_under_test_{next(_LOADS)}", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(name: str = "gitea-private-org-members.json") -> dict:
    return json.loads((ROOT / "fixtures" / "pairs" / name).read_text(encoding="utf-8"))


def digest(fill: str) -> str:
    return "sha256:" + fill * 64


def declared_probes(pair: dict, **statuses: int) -> list[dict]:
    """A run document's `probes` in which every identity drew the first
    status its expectation declares, on every check; `statuses` overrides an
    identity's status everywhere."""
    return [{"check_id": check["id"], "identity": name,
             "response": {"status": statuses.get(name, expectation["status"][0])}}
            for check in pair["config"]["checks"] for name, expectation in check["expect"].items()]


def passing_result(pair: dict) -> dict:
    """What evaluate() returns for a pair that passed, without docker."""
    pin = "_sha256" if "build" in pair else "_digest"
    return {
        "name": pair["name"], "advisory": pair["advisory"], "image": pair["image"],
        "vulnerable_tag": pair["vulnerable"], "patched_tag": pair["patched"],
        "vulnerable_image": f"{pair['image']}:{pair['vulnerable']}@{pair.get('vulnerable_digest')}",
        "patched_image": f"{pair['image']}:{pair['patched']}@{pair.get('patched_digest')}",
        "vulnerable_pin": pair["vulnerable" + pin], "patched_pin": pair["patched" + pin],
        "built_from": pair.get("build"),
        "checks": {"stubbed": True}, "passed": True,
        "vulnerable": {"exit_code": 1, "findings": 1, "graded": 1, "expected_grade": "ungraded", "message": ""},
        "patched": {"exit_code": 0, "findings": 0, "endpoint_present": True},
    }


class SelectionCliTest(unittest.TestCase):
    """Every pair, or --pair, through main(), with no docker.

    Two pairs in a temporary PAIRS_DIR, each with its own digests so a pull
    can fail for one and not the other. There used to be a light and a heavy
    pair here, for --light and --heavy; both flags and the "heavy" key are
    gone, and the tests for them now pin that they are refused."""

    UNDER_TEST = "/opt/venv/lib/python3.12/site-packages/veridor"

    def setUp(self) -> None:
        self.harness = load_harness()
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-pairs-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.harness.PAIRS_DIR = self.tmp
        base = fixture()
        self.one = {**base, "name": "pair-one", "vulnerable_digest": digest("1"), "patched_digest": digest("2")}
        self.two = {**base, "name": "pair-two", "vulnerable_digest": digest("3"), "patched_digest": digest("4")}
        self.evaluated: list[str] = []

    def write(self, *pairs: dict) -> None:
        for pair in pairs:
            (self.tmp / f"{pair['name']}.json").write_text(json.dumps(pair), encoding="utf-8")

    def stub_evaluate(self, pair: dict) -> dict:
        self.evaluated.append(pair["name"])
        return passing_result(pair)

    def run_main(self, *argv: str, reach_docker: bool = True, pull=None) -> tuple[int, str, str]:
        """main(argv) with every docker-touching step stubbed. With
        reach_docker False, reaching the guard or the docker check at all fails
        the test: that is how "reported before docker" is shown."""
        def unreachable(*_args: object) -> object:
            raise AssertionError("main() went past the selection before refusing it")

        out, err = io.StringIO(), io.StringIO()
        stubs = {
            "evaluate": self.stub_evaluate if reach_docker else unreachable,
            "veridor_under_test": (lambda: (self.UNDER_TEST, None)) if reach_docker else unreachable,
            "docker_on_path": (lambda: True) if reach_docker else unreachable,
            "check_local_tags": (lambda pairs: ({"match": 0, "absent": 2 * len(pairs)}, [])) if reach_docker
            else unreachable,
            "_pull_one": pull or (lambda ref: (True, "0.0s")),
            "build_side": (lambda pair, side: f"{pair['image']}:{pair[side]}-stub") if reach_docker
            else unreachable,
        }
        with contextlib.ExitStack() as stack:
            for name, stub in stubs.items():
                stack.enter_context(mock.patch.object(self.harness, name, stub))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            try:
                code = self.harness.main(list(argv))
            except SystemExit as exit_:
                code = exit_.code
        return code, out.getvalue(), err.getvalue()

    def test_an_empty_selection_exits_2_and_says_why(self) -> None:
        # No fixture at all.
        code, out, err = self.run_main(reach_docker=False)
        self.assertEqual(code, 2, out + err)
        self.assertIn(f"no pair in {self.tmp}", err)
        self.write(self.one, self.two)
        code, _, err = self.run_main("--pair", "nothing-by-this-name", reach_docker=False)
        self.assertEqual(code, 2, err)
        self.assertIn("no pair matched 'nothing-by-this-name'", err)
        self.assertIn("a run of nothing is not a pass, so nothing was run", err)
        with self.assertRaises(self.harness.PairError) as raised:
            self.harness.select_pairs([])
        self.assertIn("a run of nothing is not a pass", str(raised.exception))
        self.assertEqual(self.evaluated, [])
        # Control: the same directory with a selection that matches runs it.
        self.assertEqual(self.run_main("--pair", "pair-one")[0], 0)
        self.assertEqual(self.evaluated, ["pair-one"])

    def test_the_light_and_heavy_flags_are_gone(self) -> None:
        """They selected a subset by the "heavy" key; every pair runs now, and
        a job still passing one fails before anything runs instead of
        quietly running something else."""
        self.write(self.one, self.two)
        for flag in ("--light", "--heavy"):
            with self.subTest(flag):
                code, _, err = self.run_main(flag, "--pull", reach_docker=False)
                self.assertEqual(code, 2, err)
                self.assertIn(f"unrecognized arguments: {flag}", err)
        self.assertEqual(self.evaluated, [])
        # Control: with no flag, both pairs run.
        self.assertEqual(self.run_main("--pull")[0], 0)
        self.assertEqual(self.evaluated, ["pair-one", "pair-two"])

    def test_a_pair_marked_heavy_stops_the_run_before_anything_runs(self) -> None:
        self.write(self.one, {**self.two, "heavy": False})
        code, out, err = self.run_main(reach_docker=False)
        self.assertEqual(code, 2, out + err)
        self.assertIn('pair-two.json: "heavy" is not a fixture field any more. Every pair runs everywhere', err)
        self.assertEqual(self.evaluated, [], "the other pair must not run either: the fixtures are refused whole")
        # Control: without the key, both run.
        self.write(self.two)
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.evaluated, ["pair-one", "pair-two"])

    def test_every_skipped_pair_is_named_with_its_reason(self) -> None:
        self.write(self.one, self.two)
        code, out, err = self.run_main("--pair", "pair-one", "--json")
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual(document["skipped"], [{"name": "pair-two", "reason": "--pair pair-one names another pair"}])
        # `selection` also names every directory the pairs were read from, so a
        # run that took pairs from a --pairs-dir says so in its own document.
        self.assertEqual(document["selection"]["pair"], "pair-one")
        # PAIRS_DIR as the harness holds it (ROOT is already resolved in a real
        # run); a --pairs-dir is resolved, so a relative one is unambiguous.
        self.assertEqual(document["selection"]["pairs_dirs"], [str(self.tmp)])
        self.assertEqual(set(document["selection"]), {"pair", "pairs_dirs"})
        self.assertEqual([result["name"] for result in document["pairs"]], ["pair-one"])
        self.assertEqual(document["veridor_under_test"], self.UNDER_TEST)
        self.assertIn(f"veridor under test: {self.UNDER_TEST}", err, "--json keeps progress off stdout")

        self.evaluated.clear()
        code, out, _ = self.run_main("--pair", "pair-two")
        self.assertEqual(code, 0)
        self.assertEqual(self.evaluated, ["pair-two"])
        self.assertIn("skipped  pair-one: --pair pair-two names another pair", out)
        self.assertIn("1 skipped, not run: pair-one.", out)
        self.assertIn(f"veridor under test: {self.UNDER_TEST}", out)
        # Control: with nothing excluded, nothing is reported skipped.
        self.evaluated.clear()
        code, out, _ = self.run_main("--json")
        self.assertEqual((code, json.loads(out)["skipped"], self.evaluated), (0, [], ["pair-one", "pair-two"]))

    def test_a_failed_pull_fails_only_the_pairs_that_need_it(self) -> None:
        self.write(self.one, self.two)
        failing = f"{self.two['image']}@{digest('3')}"
        reason = "docker pull exited 1: Error response from daemon: manifest unknown"

        def pull(ref: str) -> tuple[bool, str]:
            return (False, reason) if ref == failing else (True, "0.1s")

        code, out, err = self.run_main("--pull", "--json", pull=pull)
        self.assertEqual(code, 1, err)
        document = json.loads(out)
        results = {result["name"]: result for result in document["pairs"]}
        self.assertFalse(results["pair-two"]["passed"])
        self.assertEqual(results["pair-two"]["error"], f"could not pull {failing}: {reason}")
        self.assertTrue(results["pair-one"]["passed"])
        self.assertEqual(self.evaluated, ["pair-one"], "the other pair must still run")
        self.assertEqual(len(document["pulls"]), 4)
        self.assertEqual([p["image"] for p in document["pulls"] if not p["pulled"]], [failing])
        self.assertIn(f"FAILED  {failing}  ({reason})", err)
        # Control: every pull succeeding, both pairs run and the run passes.
        self.evaluated.clear()
        code, out, _ = self.run_main("--pull", "--json")
        self.assertEqual((code, sorted(self.evaluated)), (0, ["pair-one", "pair-two"]))

    def test_pulls_run_concurrently_and_at_most_four_at_once(self) -> None:
        lock, running, peak = threading.Lock(), [0], [0]

        def pull(ref: str) -> tuple[bool, str]:
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.03)
            with lock:
                running[0] -= 1
            return True, "0.0s"

        refs = [f"example/image@{digest(str(n))}" for n in range(10)]
        said: list[str] = []
        with mock.patch.object(self.harness, "_pull_one", pull):
            outcomes = self.harness.pull_images(refs, said.append)
        self.assertEqual(self.harness.PULL_CONCURRENCY, 4)
        self.assertEqual(peak[0], 4, "exactly the cap: fewer means the pulls ran one by one")
        self.assertEqual([o["image"] for o in outcomes], sorted(refs))
        self.assertEqual(sorted(line.split()[1] for line in said), sorted(refs))


class FailingChecksTest(unittest.TestCase):
    """RVC-2. The Bugsink pair's second check is the direct route -- the
    attacker naming the owner's own issue -- and the CHANGELOG says it is
    refused on 2.1.3 as on 2.2.0. evaluate() asked only that the vulnerable
    build fail with one confirmed finding, so a 2.1.3 that leaked through the
    direct route as well passed the pair unchanged (measured with the stub
    documents below). Now the vulnerable build must fail exactly the checks a
    pair declares."""

    DIRECT = "owners-event-must-not-be-readable-through-the-owners-issue"
    UNSCOPED = "event-must-not-be-readable-through-another-projects-issue"

    def evaluate(self, vulnerable: list[str], patched: list[str]) -> dict:
        harness = load_harness()

        def build(pair: dict, side: str, workdir: Path) -> dict:
            leaks = vulnerable if side == "vulnerable" else patched
            # Each identity is served on one of the two checks, so every
            # denial is proven without a fabricated request.
            return {"exit_code": 1 if leaks else 0, "endpoint_present": True, "marker_reachable_by_owner": True,
                    "document": {"findings": [{"check_id": check, "evidence_grade": "confirmed", "message": check}
                                              for check in leaks],
                                 "probes": declared_probes(pair),
                                 "liveness": {"enabled": True, "unproven": []}}}

        with mock.patch.object(harness, "_evaluate_build", build):
            return harness.evaluate(fixture("bugsink-event-cross-project-read.json"))

    def test_control_the_measured_outcome_passes(self) -> None:
        result = self.evaluate([self.UNSCOPED], [])
        self.assertTrue(result["passed"], result["checks"])
        self.assertEqual(result["vulnerable"]["failing_checks"], [self.UNSCOPED])

    def test_a_vulnerable_build_that_also_leaks_through_the_direct_route_fails_the_pair(self) -> None:
        for leaks in ([self.UNSCOPED, self.DIRECT], [self.DIRECT]):
            with self.subTest(leaks=leaks):
                result = self.evaluate(leaks, [])
                self.assertFalse(result["passed"])
                self.assertFalse(result["checks"]["vulnerable_fails_exactly_the_declared_checks"])

    def test_control_a_leak_on_the_patched_build_still_fails_the_pair(self) -> None:
        result = self.evaluate([self.UNSCOPED], [self.DIRECT])
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["patched_build_passes"])
        self.assertTrue(result["checks"]["vulnerable_fails_exactly_the_declared_checks"])

    def graded(self, grades: dict[str, str]) -> dict:
        """evaluate() on the Ghost pair, the one that declares two failing
        checks, with the vulnerable build grading each check as given."""
        harness = load_harness()

        def build(pair: dict, side: str, workdir: Path) -> dict:
            findings = [{"check_id": check, "evidence_grade": grade, "message": check}
                        for check, grade in grades.items()] if side == "vulnerable" else []
            # The pair's session check serves the contributor, which proves
            # its 403s without a fabricated request.
            return {"exit_code": 1 if findings else 0, "endpoint_present": True, "marker_reachable_by_owner": True,
                    "document": {"findings": findings, "probes": declared_probes(pair),
                                 "liveness": {"enabled": True, "unproven": []}}}

        with mock.patch.object(harness, "_evaluate_build", build):
            return harness.evaluate(fixture("ghost-integration-admin-key-read.json"))

    def test_each_declared_check_must_reach_the_expected_grade(self) -> None:
        """The docstring promises `confirmed` evidence from each declared
        check; evaluate() asked for one confirmed finding among them, so a
        second check that fell to `suspected` or `ungraded` passed the pair
        (measured with these stubs)."""
        browse, one = fixture("ghost-integration-admin-key-read.json")["vulnerable_failing_checks"]
        for weaker in ("suspected", "ungraded"):
            for grades in ({browse: "confirmed", one: weaker}, {browse: weaker, one: "confirmed"}):
                with self.subTest(grades=grades):
                    result = self.graded(grades)
                    self.assertFalse(result["checks"]["vulnerable_evidence_confirmed"], result["checks"])
                    self.assertFalse(result["passed"])
                    self.assertEqual(result["vulnerable"]["below_grade"],
                                     [check for check, grade in grades.items() if grade == weaker])
        # Control: both confirmed passes, so the stubs can produce a pass.
        result = self.graded({browse: "confirmed", one: "confirmed"})
        self.assertTrue(result["passed"], result["checks"])
        self.assertEqual(result["vulnerable"]["below_grade"], [])

    def load(self, change) -> list[dict]:
        harness = load_harness()
        with tempfile.TemporaryDirectory() as directory:
            for name in ("bugsink-event-cross-project-read.json", "gitea-private-org-members.json"):
                pair = fixture(name)
                change(name, pair)
                (Path(directory) / name).write_text(json.dumps(pair), encoding="utf-8")
            harness.PAIRS_DIR = Path(directory)
            return harness.load_pairs(None)

    def test_a_pair_with_several_checks_names_the_failing_ones_and_only_real_ones(self) -> None:
        self.assertEqual(len(self.load(lambda name, pair: None)), 2)
        harness = load_harness()
        for label, change, message in (
                ("undeclared", lambda name, pair: pair.pop("vulnerable_failing_checks", None),
                 "2 checks and no vulnerable_failing_checks"),
                ("unknown", lambda name, pair: pair.__setitem__("vulnerable_failing_checks", ["no-such-check"]),
                 "must list distinct check ids"),
                ("empty", lambda name, pair: pair.__setitem__("vulnerable_failing_checks", []),
                 "must list distinct check ids")):
            with self.subTest(label):
                with self.assertRaisesRegex(Exception, message) as caught:
                    self.load(lambda name, pair, change=change: change(name, pair)
                              if name.startswith("bugsink") else None)
                self.assertEqual(type(caught.exception).__name__, harness.PairError.__name__)
        # A one-check pair may leave it out: its one check is the failing one.
        self.assertNotIn("vulnerable_failing_checks", fixture("gitea-private-org-members.json"))


class PatchedLivenessTest(unittest.TestCase):
    """A denial on the patched build certifies the fix only if the attacker's
    credential is live. Veridor records a denial that a credential it
    fabricated drew too in `liveness.unproven`, as a disclosure that changes no
    exit code without --require-complete. The harness passed no such flag and
    never read the field, so a dead attacker session certified the fix."""

    CHECK = "public-only-token-must-not-reach-a-private-org-team"
    PROVEN = {"enabled": True, "unproven": []}

    def evaluate(self, liveness: object, *, pair: dict | None = None, probes: dict | None = None,
                 fabricated: object = 401) -> dict:
        """`fabricated` is the status the harness's fabricated-credential
        request drew on every denial, a dict of (check, identity) to status,
        an error string, or None for no request at all."""
        harness = load_harness()
        pair = pair or fixture("gitea-public-only-team.json")
        check = pair["config"]["checks"][0]["id"]

        def controls() -> list[dict]:
            entries = []
            for each in pair["config"]["checks"]:
                for name, expectation in each["expect"].items():
                    if not harness._denial_only(expectation):
                        continue
                    drew = fabricated.get((each["id"], name)) if isinstance(fabricated, dict) else fabricated
                    entry = {"check_id": each["id"], "identity": name, "method": "GET", "status": drew}
                    if isinstance(drew, str):
                        entry.update(status=None, error=drew)
                    entries.append(entry)
            return entries

        def build(pair: dict, side: str, workdir: Path) -> dict:
            document: dict = {"findings": [], "probes": declared_probes(pair, **(probes or {}))}
            result = {"exit_code": 1 if side == "vulnerable" else 0, "endpoint_present": True,
                      "marker_reachable_by_owner": True, "document": document}
            if side == "vulnerable":
                document["findings"] = [{"check_id": check, "evidence_grade": "confirmed", "message": check}]
                document["liveness"] = {"enabled": True, "unproven": []}
                return result
            if liveness is not None:
                document["liveness"] = liveness
            if fabricated is not None:
                result["fabricated"] = controls()
            return result

        with mock.patch.object(harness, "_evaluate_build", build):
            return harness.evaluate(pair)

    def test_an_unproven_denial_on_the_patched_build_fails_the_pair(self) -> None:
        """Veridor's own disclosure still fails the pair, even when the
        harness's fabricated request drew a different status."""
        unproven = {"enabled": True, "unproven": [{
            "check_id": self.CHECK, "identity": "public_only_token", "status": 403}]}
        result = self.evaluate(unproven)
        self.assertFalse(result["passed"])
        self.assertTrue(result["checks"]["patched_build_passes"], "the gap: exit 0 and no finding")
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertEqual(result["patched"]["unproven"],
                         [f"public_only_token: {self.CHECK} (HTTP 403); Veridor's own fabricated "
                          "credential drew the same answer (liveness.unproven)"])

    def test_a_denial_a_fabricated_credential_also_draws_fails_the_pair(self) -> None:
        """Veridor recorded nothing, as it does when nobody is served on the
        check; the harness's own fabricated request drew the same 403."""
        result = self.evaluate(self.PROVEN, fabricated=403)
        self.assertTrue(result["checks"]["patched_build_passes"], "the gap: exit 0 and no finding")
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertEqual(result["patched"]["unproven"],
                         [f"public_only_token: {self.CHECK} (HTTP 403); never served in the run, "
                          "and a fabricated credential drew HTTP 403 too"])

    def test_a_denial_with_no_fabricated_answer_fails_the_pair(self) -> None:
        """No evidence is not proof: a fabricated request that errored, or
        none at all, leaves the denial unproven."""
        for fabricated, reason in (("URLError: <urlopen error [Errno 61] Connection refused>",
                                    "the fabricated-credential request did not answer (URLError: "),
                                   (None, "no fabricated-credential request was made on it")):
            with self.subTest(fabricated=fabricated):
                result = self.evaluate(self.PROVEN, fabricated=fabricated)
                self.assertFalse(result["passed"])
                self.assertEqual(len(result["patched"]["unproven"]), 1, result["patched"]["unproven"])
                self.assertIn(f"public_only_token: {self.CHECK} (HTTP 403); never served in the run, and {reason}",
                              result["patched"]["unproven"][0])

    def test_a_fabricated_answer_that_is_not_a_refusal_or_a_success_proves_nothing(self) -> None:
        """Vikunja: the owner draws 403 and the attacker 404, and nobody is
        served. A sham that drew a different denial, or a 2xx/3xx, was treated
        differently from the real credential, so the real one is live. A 429,
        a 5xx or a 400 says the sham hit a rate limiter, a server error or a
        parser, not that the credential was told apart; the sham is sent after
        Veridor's whole run, exactly when a limiter trips. Any non-equal status
        used to count, so a dead attacker's 404 was certified by a 429."""
        harness = load_harness()
        pair = fixture("vikunja-task-comment-idor.json")
        check = "comment-must-not-be-readable-through-another-task"
        probes = declared_probes(pair)
        self.assertEqual({probe["identity"]: probe["response"]["status"] for probe in probes},
                         {"owner": 403, "attacker": 404})

        def unproven(sham: int) -> list[str]:
            return harness.unproven_denials(pair, {"document": {"probes": probes}, "fabricated": [
                {"check_id": check, "identity": name, "method": "GET", "status": sham}
                for name in ("owner", "attacker")]})

        # Control: the method can fail. A sham drawing the attacker's own 404.
        self.assertEqual(unproven(404), [f"attacker: {check} (HTTP 404); never served in the run, "
                                         "and a fabricated credential drew HTTP 404 too"])
        for sham in (401, 405, 200, 204, 302):
            with self.subTest(sham=sham):
                self.assertEqual(unproven(sham), [])
        for sham in (429, 500, 502, 503, 400):
            with self.subTest(sham=sham):
                self.assertEqual(unproven(sham), [
                    f"{name}: {check} (HTTP {status}); never served in the run, and the fabricated-credential "
                    f"request drew HTTP {sham}, neither a refusal nor a success, which shows nothing about "
                    "the credential"
                    for name, status in (("owner", 403), ("attacker", 404))])
        # REGRESSION. A 407 is in DENIAL_ONLY_STATUSES, which this rule took
        # whole, but it is a proxy's answer: the sham never reached the
        # application, so it told no credential apart from another.
        self.assertEqual(unproven(407), [
            f"{name}: {check} (HTTP {status}); never served in the run, and the fabricated-credential "
            "request drew HTTP 407, a proxy's answer before the request reached the application, "
            "which shows nothing about the credential"
            for name, status in (("owner", 403), ("attacker", 404))])
        # Through evaluate(), the way a run decides the pair.
        result = self.evaluate(self.PROVEN, pair=pair, fabricated=407)
        self.assertTrue(result["checks"]["patched_build_passes"])
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertFalse(result["passed"])
        result = self.evaluate(self.PROVEN, pair=pair, fabricated=429)
        self.assertTrue(result["checks"]["patched_build_passes"], "the gap: exit 0 and no finding")
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertFalse(result["passed"])

    def test_an_identity_whose_own_probe_drew_a_proxy_407_is_unproven(self) -> None:
        """REGRESSION. The other side of the 407 above: when the IDENTITY's
        own request drew 407, a proxy refused it before it reached the
        application, so nothing shows the credential live -- and a sham that
        drew 403 was still read as the application telling the two apart,
        because 403 differs from 407 and is a refusal. A dead attacker behind
        a proxy was certified live (reproduced on the vikunja pair)."""
        harness = load_harness()
        pair = fixture("vikunja-task-comment-idor.json")
        check = "comment-must-not-be-readable-through-another-task"
        probes = copy.deepcopy(declared_probes(pair))
        for probe in probes:
            if probe["identity"] == "attacker":
                probe["response"]["status"] = 407

        def unproven(sham: int) -> list[str]:
            return harness.unproven_denials(pair, {"document": {"probes": probes}, "fabricated": [
                {"check_id": check, "identity": name, "method": "GET", "status": sham}
                for name in ("owner", "attacker")]})

        proxy = (f"attacker: {check} (HTTP 407); the identity's own request drew HTTP 407, a "
                 "proxy's answer before the request reached the application, so nothing shows "
                 "its credential live")
        for sham in (401, 403, 404, 200, 302):
            with self.subTest(sham=sham):
                self.assertIn(proxy, unproven(sham))
        # Control: the owner's own 403 is still proven by a sham that differs.
        self.assertEqual(unproven(401), [proxy])
        # And the identity-side 407 does not need a sham at all to fail.
        self.assertEqual(harness.unproven_denials(pair, {"document": {"probes": probes}}),
                         [f"owner: {check} (HTTP 403); never served in the run, and no "
                          "fabricated-credential request was made on it", proxy])

    def test_a_proxy_407_is_unproven_even_for_an_identity_served_elsewhere(self) -> None:
        """REGRESSION. The identity-side 407 rule ran after the `name in
        served` skip, so an identity served a 2xx on one check whose own
        request on its denial-only check drew a proxy's 407 was skipped there:
        a proxy's answer was accepted as the application's denial (reproduced
        on the bugsink pair: `[]`). Being live on another check says nothing
        about a request that never reached the application."""
        harness = load_harness()
        pair = fixture("bugsink-event-cross-project-read.json")
        check = "owners-event-must-not-be-readable-through-the-owners-issue"
        probes = copy.deepcopy(declared_probes(pair))
        # Control: as declared, both identities are served somewhere, and
        # nothing is unproven.
        self.assertEqual(harness.unproven_denials(pair, {"document": {"probes": probes}}), [])
        for probe in probes:
            if probe["identity"] == "attacker" and probe["check_id"] == check:
                self.assertEqual(probe["response"]["status"], 403)
                probe["response"]["status"] = 407
        self.assertIn("attacker", {probe["identity"] for probe in probes
                                   if probe["response"]["status"] == 200})
        self.assertEqual(
            harness.unproven_denials(pair, {"document": {"probes": probes}}),
            [f"attacker: {check} (HTTP 407); the identity's own request drew HTTP 407, a "
             "proxy's answer before the request reached the application, so nothing shows "
             "its credential live"])

    def test_a_denial_with_no_probe_in_the_run_fails_the_pair(self) -> None:
        harness = load_harness()
        pair = fixture("gitea-public-only-team.json")
        build = {"document": {"probes": [probe for probe in declared_probes(pair)
                                         if probe["identity"] != "public_only_token"]},
                 "fabricated": [{"check_id": self.CHECK, "identity": "public_only_token", "status": 401}]}
        self.assertEqual(harness.unproven_denials(pair, build),
                         [f"public_only_token: {self.CHECK}; no answer to this identity in the run, "
                          "so nothing shows its credential live"])

    def test_an_identity_served_on_another_check_needs_no_fabricated_request(self) -> None:
        """Bugsink: the owner is 403 on the attacker's route and 200 on its
        own, the attacker the other way round."""
        result = self.evaluate(self.PROVEN, pair=fixture("bugsink-event-cross-project-read.json"),
                               fabricated=None)
        self.assertTrue(result["checks"]["patched_denials_reach_a_live_credential"], result["patched"])
        # Control: the same pair with the attacker never served.
        result = self.evaluate(self.PROVEN, pair=fixture("bugsink-event-cross-project-read.json"),
                               probes={"attacker": 403}, fabricated=None)
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertEqual([entry.split(";")[0] for entry in result["patched"]["unproven"]],
                         ["attacker: owners-event-must-not-be-readable-through-the-owners-issue (HTTP 403)"])

    def test_an_identity_that_presents_no_credential_is_not_held_to_it(self) -> None:
        """Datasette's anonymous identity sends nothing, so it has no
        credential to be dead; its 403 is the boundary working."""
        result = self.evaluate(self.PROVEN, pair=fixture("datasette-private-instance-api-explorer.json"),
                               fabricated=None)
        self.assertTrue(result["checks"]["patched_denials_reach_a_live_credential"], result["patched"])
        self.assertEqual(result["patched"]["unproven"], [])

    def test_liveness_that_was_off_or_missing_proves_nothing(self) -> None:
        for liveness in ({"enabled": False, "unproven": []}, None):
            with self.subTest(liveness=liveness):
                result = self.evaluate(liveness)
                self.assertFalse(result["passed"])
                self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])

    def test_control_proven_denials_pass(self) -> None:
        result = self.evaluate({"enabled": True, "unproven": []})
        self.assertTrue(result["passed"], result["checks"])
        self.assertEqual(result["patched"]["unproven"], [])


class FabricatedControlsTest(unittest.TestCase):
    """What the harness sends as a credential nobody issued, with _http
    replaced: the identity's own header templates with every provisioned
    value fabricated, on the check's own path, never the real value, and
    never a write."""

    def controls(self, pair: dict, environment: dict, answer=None) -> tuple[list[dict], list[tuple]]:
        harness = load_harness()
        sent = []

        def http(url: str, *, method: str = "GET", headers: dict | None = None, **_: object) -> tuple[int, str]:
            sent.append((method, url, dict(headers or {})))
            if isinstance(answer, BaseException):
                raise answer
            return answer or 401, "{}"

        with mock.patch.object(harness, "_http", http):
            return harness._fabricated_controls(pair["config"], "http://127.0.0.1:1", environment), sent

    def test_the_identity_s_own_template_with_the_credential_fabricated(self) -> None:
        pair = fixture("vikunja-task-comment-idor.json")
        controls, sent = self.controls(pair, _VIKUNJA_ENV)
        check = "comment-must-not-be-readable-through-another-task"
        self.assertEqual([(entry["check_id"], entry["identity"], entry["status"]) for entry in controls],
                         [(check, "owner", 401), (check, "attacker", 401)])
        # Owner and attacker share a template, so one request answers both.
        self.assertEqual(len(sent), 1, sent)
        method, url, headers = sent[0]
        self.assertEqual((method, url), ("GET", "http://127.0.0.1:1/api/v1/tasks/22/comments/7"))
        self.assertRegex(headers["Authorization"], r"^Bearer veridor-pair-sham-[0-9a-f]{16}$")
        for name in ("VERIDOR_PAIR_OWNER_TOKEN", "VERIDOR_PAIR_ATTACKER_TOKEN"):
            self.assertNotIn(_VIKUNJA_ENV[name], json.dumps(sent))

    def test_a_cookie_keeps_its_name_and_only_denials_are_controlled(self) -> None:
        pair = fixture("ghost-integration-admin-key-read.json")
        controls, sent = self.controls(pair, _GHOST_ENV)
        self.assertEqual({entry["identity"] for entry in controls}, {"contributor"})
        self.assertEqual([entry["check_id"] for entry in controls], pair["vulnerable_failing_checks"])
        self.assertEqual(len(sent), 2)
        for _, _, headers in sent:
            self.assertRegex(headers["Cookie"], r"^ghost-admin-api-session=veridor-pair-sham-[0-9a-f]{16}$")

    def test_the_module_docstring_names_both_proofs(self) -> None:
        """It said every patched denial reached a credential the run proved
        live while reading only liveness.unproven, which Veridor leaves empty
        on the Vikunja pair. It now describes what unproven_denials does."""
        doc = " ".join(load_harness().__doc__.split())
        claim = doc[doc.index("2. the patched build is green"):doc.index("3. the endpoint is STILL THERE")]
        for words in ("served a 2xx on some check of the patched run",
                      "drew a different status from the identity's, and that status is itself a "
                      "refusal or a 2xx/3xx",
                      "a 429, a 5xx or a 400 is a rate limiter, a server error or a parser answering, "
                      "and counts as a request that did not answer",
                      "Anything else fails the pair, naming the check and identity"):
            self.assertIn(words, claim)

    def test_the_denial_statuses_are_veridor_s(self) -> None:
        """The harness's copy of what counts as a denial-only expectation
        must not drift from the one Veridor grades by."""
        from veridor import core  # noqa: PLC0415
        self.assertEqual(load_harness().DENIAL_ONLY_STATUSES, core.DENIAL_ONLY_STATUSES)
        self.assertEqual(load_harness().SAFE_METHODS, core.SAFE_METHODS)

    def test_no_request_on_a_write_and_an_error_is_recorded_not_raised(self) -> None:
        pair = fixture("vikunja-task-comment-idor.json")
        pair["config"]["checks"][0]["request"]["method"] = "DELETE"
        controls, sent = self.controls(pair, _VIKUNJA_ENV)
        self.assertEqual(sent, [])
        self.assertEqual({entry["status"] for entry in controls}, {None})
        self.assertTrue(all("write" in entry["error"] for entry in controls), controls)

        import urllib.error  # noqa: PLC0415
        controls, sent = self.controls(fixture("vikunja-task-comment-idor.json"), _VIKUNJA_ENV,
                                       answer=urllib.error.URLError("refused"))
        self.assertEqual(len(sent), 1)
        self.assertEqual({entry["status"] for entry in controls}, {None})
        self.assertTrue(all(entry["error"].startswith("URLError") for entry in controls), controls)


#: What the Ghost provisioner returns, as the stub below knows it.
_GHOST_ENV = {"VERIDOR_PAIR_OWNER_SESSION": "s%3Aowner-stub-cookie.0123456789",
              "VERIDOR_PAIR_CONTRIBUTOR_SESSION": "s%3Acontrib-stub-cookie.0123456789",
              "VERIDOR_PAIR_INTEGRATION_ID": "6123abcdef0123456789abcd"}


def _ghost_stub(marker: str, *, leaks: bool, contributor_live: bool):
    """A loopback Ghost Admin API with only the routes the pair touches. Any
    cookie it does not know -- a fabricated one, or a dead contributor -- is
    403 everywhere, as both real builds answer a fabricated cookie."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: PLC0415

    sessions = {_GHOST_ENV["VERIDOR_PAIR_OWNER_SESSION"]: "owner"}
    if contributor_live:
        sessions[_GHOST_ENV["VERIDOR_PAIR_CONTRIBUTOR_SESSION"]] = "contributor"
    leaking = {"/ghost/api/v4/admin/integrations/?include=api_keys",
               f"/ghost/api/v4/admin/integrations/{_GHOST_ENV['VERIDOR_PAIR_INTEGRATION_ID']}/?include=api_keys"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            cookie = (self.headers.get("Cookie") or "").partition("ghost-admin-api-session=")[2]
            who = sessions.get(cookie)
            if self.path in leaking and (who == "owner" or (who == "contributor" and leaks)):
                status, body = 200, {"integrations": [{"name": marker, "description": f"private-{marker}"}]}
            elif self.path == "/ghost/api/v4/admin/users/me/?include=roles" and who:
                status, body = 200, {"users": [{"roles": [{"name": "Owner" if who == "owner" else "Contributor"}]}]}
            elif self.path in leaking or self.path.startswith("/ghost/api/v4/admin/users/"):
                status, body = 403, {"errors": [{"type": "NoPermissionError"}]}
            else:
                status, body = 404, {"errors": [{"type": "NotFoundError"}]}
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


@slow("stands up loopback Ghost stubs and runs the real veridor against each")
class PatchedLivenessRunTest(unittest.TestCase):
    """The Ghost pair end to end through evaluate() and the real `veridor run`,
    with docker replaced by loopback stubs: a contributor whose session is dead
    on the patched build is 403 like a fabricated cookie, and used to pass the
    pair (reproduced). Its denial is now unproven and fails it; a live one is
    proven by the pair's own check that the contributor reads /users/me/."""

    def evaluate(self, contributor_live: bool, pair: dict | None = None) -> dict:
        harness = load_harness()
        pair = pair or fixture("ghost-integration-admin-key-read.json")
        urls = {}
        for side, leaks in (("vulnerable", True), ("patched", False)):
            server = _ghost_stub(pair["marker"], leaks=leaks,
                                 contributor_live=contributor_live or side == "vulnerable")
            loopback.start(server)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            urls[side] = f"http://127.0.0.1:{server.server_port}"
        with mock.patch.object(harness, "_start", lambda pair, side, container: urls[side]), \
                mock.patch.object(harness, "_wait_healthy", lambda base_url, path: None), \
                mock.patch.object(harness, "_remove_container", lambda container: (True, [])), \
                mock.patch.dict(harness.PROVISIONERS,
                                {pair["provision"]: lambda container, base_url, marker: dict(_GHOST_ENV)}):
            return harness.evaluate(pair)

    @staticmethod
    def without_the_session_check() -> dict:
        """The pair as it was before it carried a check the contributor is
        served: only the two declared failing checks."""
        pair = fixture("ghost-integration-admin-key-read.json")
        pair["config"]["checks"] = [check for check in pair["config"]["checks"]
                                    if check["id"] in pair["vulnerable_failing_checks"]]
        return pair

    def test_a_dead_contributor_on_the_patched_build_fails_the_pair(self) -> None:
        """REGRESSION, reproduced: exit 0 and no finding on the patched build,
        both 403s disclosed as unproven, and the pair passed."""
        result = self.evaluate(contributor_live=False, pair=self.without_the_session_check())
        self.assertEqual(result["patched"]["exit_code"], 0)
        self.assertEqual(result["patched"]["findings"], 0)
        self.assertFalse(result["passed"], result["checks"])
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertEqual(len(result["patched"]["unproven"]), 2, result["patched"]["unproven"])
        self.assertTrue(all(entry.startswith("contributor: ") for entry in result["patched"]["unproven"]),
                        result["patched"]["unproven"])

    def test_without_the_session_check_a_live_contributor_is_unproven_too(self) -> None:
        """Why the fixture carries a check the vulnerable build passes: its
        two leaking routes are 403 to a fabricated cookie as well, so on the
        patched build nothing else in the run tells a live contributor from a
        dead one."""
        result = self.evaluate(contributor_live=True, pair=self.without_the_session_check())
        self.assertFalse(result["passed"], result["checks"])
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])

    def test_the_shipped_pair_fails_a_dead_contributor_and_passes_a_live_one(self) -> None:
        dead = self.evaluate(contributor_live=False)
        self.assertFalse(dead["passed"], dead["checks"])
        # The session check itself fails on a dead session, so the patched
        # build is no longer green either.
        self.assertFalse(dead["checks"]["patched_build_passes"])
        live = self.evaluate(contributor_live=True)
        self.assertTrue(live["passed"], (live["checks"], live["patched"], live["vulnerable"]))
        self.assertEqual(live["patched"]["unproven"], [])


#: What the Vikunja provisioner returns, as the stub below knows it.
_VIKUNJA_ENV = {"VERIDOR_PAIR_OWNER_TOKEN": "owner-stub-jwt.0123456789",  # gitleaks:allow
                "VERIDOR_PAIR_ATTACKER_TOKEN": "attacker-stub-jwt.0123456789",  # gitleaks:allow
                "VERIDOR_PAIR_OWNER_TASK_ID": "11",
                "VERIDOR_PAIR_ATTACKER_TASK_ID": "22",
                "VERIDOR_PAIR_COMMENT_ID": "7"}


def _vikunja_stub(marker: str, *, leaks: bool, attacker_live: bool, unknown_token: int):
    """A loopback Vikunja with the two routes the pair touches. The owner is
    403 on the attacker's task and the attacker 403 on the owner's, as both
    real tags answer; the attacker reads the comment through its own task only
    when `leaks`, and is 404 there otherwise. A token the stub does not know --
    a fabricated one, or a dead attacker -- draws `unknown_token` everywhere."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: PLC0415

    tokens = {_VIKUNJA_ENV["VERIDOR_PAIR_OWNER_TOKEN"]: "owner"}
    if attacker_live:
        tokens[_VIKUNJA_ENV["VERIDOR_PAIR_ATTACKER_TOKEN"]] = "attacker"
    comment = _VIKUNJA_ENV["VERIDOR_PAIR_COMMENT_ID"]
    owners_route = f"/api/v1/tasks/{_VIKUNJA_ENV['VERIDOR_PAIR_OWNER_TASK_ID']}/comments/{comment}"
    attackers_route = f"/api/v1/tasks/{_VIKUNJA_ENV['VERIDOR_PAIR_ATTACKER_TASK_ID']}/comments/{comment}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            who = tokens.get((self.headers.get("Authorization") or "").removeprefix("Bearer "))
            served = {"id": int(comment), "comment": marker}
            if self.path not in (owners_route, attackers_route):
                status, body = 404, {"message": "Not found"}
            elif who is None:
                status, body = unknown_token, {"message": "invalid or expired token"}
            elif self.path == owners_route:
                status, body = (200, served) if who == "owner" else (403, {"message": "Forbidden"})
            elif who == "owner":
                status, body = 403, {"message": "Forbidden"}
            else:
                status, body = (200, served) if leaks else (404, {"message": "The task comment does not exist."})
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


@slow("stands up loopback Vikunja stubs and runs the real veridor against each")
class VikunjaLivenessRunTest(unittest.TestCase):
    """The Vikunja pair end to end through evaluate() and the real `veridor
    run`, docker replaced by loopback stubs. Its one check expects the owner
    403 and the attacker 404, so no identity is served on it and Veridor never
    records either denial as unproven: a dead attacker whose token draws the
    same 404 a fabricated one draws used to pass the pair (reproduced). The
    harness now decides it: an identity never served in the run must draw a
    different status from a fabricated credential on the same request."""

    def evaluate(self, *, attacker_live: bool, unknown_token: int) -> dict:
        harness = load_harness()
        pair = fixture("vikunja-task-comment-idor.json")
        urls = {}
        for side, leaks in (("vulnerable", True), ("patched", False)):
            server = _vikunja_stub(pair["marker"], leaks=leaks, unknown_token=unknown_token,
                                   attacker_live=attacker_live or side == "vulnerable")
            loopback.start(server)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            urls[side] = f"http://127.0.0.1:{server.server_port}"
        with mock.patch.object(harness, "_start", lambda pair, side, container: urls[side]), \
                mock.patch.object(harness, "_wait_healthy", lambda base_url, path: None), \
                mock.patch.object(harness, "_remove_container", lambda container: (True, [])), \
                mock.patch.dict(harness.PROVISIONERS,
                                {pair["provision"]: lambda container, base_url, marker: dict(_VIKUNJA_ENV)}):
            return harness.evaluate(pair)

    def test_a_dead_attacker_drawing_the_fabricated_credential_s_404_fails_the_pair(self) -> None:
        """REGRESSION, reproduced: exit 0, no finding, nothing in
        liveness.unproven, and the pair passed."""
        result = self.evaluate(attacker_live=False, unknown_token=404)
        self.assertEqual(result["patched"]["exit_code"], 0)
        self.assertEqual(result["patched"]["findings"], 0)
        self.assertTrue(result["checks"]["patched_build_passes"], "the gap: the patched build is green")
        self.assertFalse(result["passed"], result["checks"])
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])
        self.assertEqual(
            [entry for entry in result["patched"]["unproven"] if entry.startswith("attacker: ")],
            ["attacker: comment-must-not-be-readable-through-another-task (HTTP 404); never served in the "
             "run, and a fabricated credential drew HTTP 404 too"],
            result["patched"]["unproven"])

    def test_a_live_attacker_whose_404_a_fabricated_credential_does_not_draw_passes(self) -> None:
        result = self.evaluate(attacker_live=True, unknown_token=401)
        self.assertTrue(result["passed"], (result["checks"], result["patched"]))
        self.assertEqual(result["patched"]["unproven"], [])

    def test_control_a_live_attacker_drawing_the_fabricated_credential_s_404_still_fails(self) -> None:
        """The run cannot tell this from a dead attacker, so it does not
        certify it: the same 404 to a token nobody issued proves nothing."""
        result = self.evaluate(attacker_live=True, unknown_token=404)
        self.assertFalse(result["passed"], result["checks"])
        self.assertFalse(result["checks"]["patched_denials_reach_a_live_credential"])


class GhostSweepClaimTest(unittest.TestCase):
    """The Ghost provisioner's docstring and the fixture's note describe one
    measured sweep. The note was corrected from "four routes" to the two it
    names; the docstring kept "4 routes". Named routes are what a test can
    compare, so the docstring names them too."""

    def test_the_provisioner_names_the_routes_the_fixture_measured(self) -> None:
        note = " ".join(fixture("ghost-integration-admin-key-read.json")["advisory"]["note"])
        routes = re.search(r"carried the\s+marker on exactly two, (\S+) and (\S+),", note)
        self.assertIsNotNone(routes, "the fixture no longer names the owner's marker routes")
        doc = load_harness()._provision_ghost_integration_keys.__doc__
        flat = " ".join(doc.split())
        # The pair, not each route alone: "/integrations/" is a prefix of the
        # leaking route the docstring names anyway.
        self.assertIn("found the marker on exactly two, {} and {}".format(*routes.groups()), flat)
        self.assertNotIn("4 routes", flat)


class PinnedImageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = load_harness()

    def test_each_build_runs_as_image_tag_at_the_pinned_digest(self) -> None:
        """What reaches `docker run` for every side of every pair."""
        calls: list[tuple[str, ...]] = []

        def docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
            calls.append(args)
            return subprocess.CompletedProcess(["docker", *args], 0, "", "")

        pairs = self.harness.load_pairs(None)
        registry = [pair for pair in pairs if not self.harness.is_built(pair)]
        built = [pair for pair in pairs if self.harness.is_built(pair)]
        self.assertGreaterEqual(len(registry), 8)
        self.assertGreaterEqual(len(built), 1)
        with mock.patch.object(self.harness, "_docker", docker), \
                mock.patch.object(self.harness, "_free_port", lambda: 40000):
            for pair in registry:
                for side, field in self.harness.SIDES:
                    calls.clear()
                    self.harness._start(pair, side, "c")
                    run = next(call for call in calls if call[0] == "run")
                    pinned = f"{pair['image']}:{pair[side]}@{pair[field]}"
                    self.assertEqual(run[-1], pinned)
                    self.assertEqual(self.harness.pull_ref(pair, side), f"{pair['image']}@{pair[field]}")
            # Control: the bare tag, which is what ran before, is not what runs now.
            self.assertNotEqual(run[-1], f"{pair['image']}:{pair['patched']}")
            # A built pair runs the tag its own build was given, which names
            # every input, and --pull fetches only the pinned base.
            for pair in built:
                for side, _ in self.harness.SIDES:
                    calls.clear()
                    self.harness._start(pair, side, "c")
                    run = next(call for call in calls if call[0] == "run")
                    self.assertEqual(run[-1], self.harness.build_tag(pair, side))
                    self.assertTrue(run[-1].startswith(f"{self.harness.BUILT_PREFIX}"), run[-1])
                    self.assertEqual(self.harness.pull_ref(pair, side), pair["build"]["base"])

    def test_a_local_tag_is_compared_with_the_pin(self) -> None:
        status = self.harness.local_tag_status
        pinned, other = digest("a"), digest("b")
        match = ("match", None)
        self.assertEqual(status("gitea/gitea", "1.26.4", pinned, 0, json.dumps([f"gitea/gitea@{pinned}"]), ""), match)
        self.assertEqual(status("gitea/gitea", "1.26.4", pinned, 0,
                                json.dumps([f"docker.io/gitea/gitea@{other}", f"docker.io/gitea/gitea@{pinned}"]), ""),
                         match)
        for label, stdout in (("re-pushed", [f"gitea/gitea@{other}"]), ("built here", []),
                              ("same digest, another repository", [f"someone/gitea@{pinned}"])):
            with self.subTest(label):
                found, problem = status("gitea/gitea", "1.26.4", pinned, 0, json.dumps(stdout), "")
                self.assertEqual(found, "moved")
                self.assertIn(f"but the fixture pins {pinned}", problem)
                self.assertIn("re-pushed upstream", problem)
        self.assertEqual(status("gitea/gitea", "1.26.4", pinned, 1, "",
                                "Error response from daemon: No such image: gitea/gitea:1.26.4"), ("absent", None))
        for label, returncode, stdout, stderr in (
                ("daemon down", 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"),
                ("not JSON", 0, "<no value>", ""), ("not a list", 0, "null", "")):
            with self.subTest(label):
                self.assertEqual(status("gitea/gitea", "1.26.4", pinned, returncode, stdout, stderr)[0], "error")

    def test_a_tag_that_moved_stops_the_run_before_anything_runs(self) -> None:
        """A stub docker holds every tag the fixtures name, each at its pin,
        except the one a test moves."""
        pairs = self.harness.load_pairs(None)
        held = {f"{p['image']}:{p[side]}": f"{p['image']}@{p[field]}"
                for p in pairs if not self.harness.is_built(p) for side, field in self.harness.SIDES}
        built_names = sorted(p["name"] for p in pairs if self.harness.is_built(p))
        self.assertTrue(built_names)
        pair = next(p for p in pairs if not self.harness.is_built(p))
        builds: list[str] = []
        tag = f"{pair['image']}:{pair['vulnerable']}"

        def docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
            self.assertEqual(args[:4], ("image", "inspect", "--format", "{{json .RepoDigests}}"))
            return subprocess.CompletedProcess(["docker", *args], 0, json.dumps([held[args[4]]]), "")

        def run_all() -> tuple[int, str]:
            evaluated: list[str] = []
            builds.clear()
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(self.harness, "_docker", docker), \
                    mock.patch.object(self.harness, "evaluate", lambda p: evaluated.append(p["name"]) or
                                      passing_result(p)), \
                    mock.patch.object(self.harness, "build_side", lambda p, side: builds.append(p["name"]) or "t"), \
                    mock.patch.object(self.harness, "veridor_under_test", lambda: ("/x/veridor", None)), \
                    mock.patch.object(self.harness, "docker_on_path", lambda: True), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = self.harness.main([])
            return code, out.getvalue() + err.getvalue(), evaluated

        # Control first: every tag at its pin, and every pair runs.
        code, output, evaluated = run_all()
        self.assertEqual(code, 0, output)
        self.assertIn(pair["name"], evaluated)
        self.assertRegex(output, r"local tags against the pins: \d+ match, 0 not held here")
        self.assertNotIn("nothing was run", output)
        self.assertEqual(sorted(set(builds)), built_names, "the built pairs are built when the run goes ahead")
        held[tag] = f"{pair['image']}@{digest('f')}"
        code, output, evaluated = run_all()
        self.assertEqual((code, evaluated, builds), (2, [], []), output)
        self.assertIn(f"{tag} on this Docker is {pair['image']}@{digest('f')}, but the fixture pins "
                      f"{pair['vulnerable_digest']}", output)
        self.assertIn("A pinned tag no longer names the pinned build, so nothing was run.", output)
        self.assertNotIn("Docker could not say", output)

    def test_a_docker_that_cannot_answer_is_not_reported_as_a_moved_tag(self) -> None:
        """Every `docker image inspect` failing, as with the daemon down, used
        to end with the moved-tag summary: measured with DOCKER_HOST naming a
        socket that does not exist."""
        down = ("failed to connect to the docker API at unix:///nonexistent/docker.sock; check if the path is "
                "correct and if the daemon is running")
        pairs = self.harness.load_pairs(None)
        moved = {f"{p['image']}:{p['vulnerable']}" for p in pairs if not self.harness.is_built(p)}

        def run_all(answer) -> tuple[int, str, list[str]]:
            evaluated: list[str] = []
            out = io.StringIO()
            with mock.patch.object(self.harness, "_docker", answer), \
                    mock.patch.object(self.harness, "evaluate", lambda p: evaluated.append(p["name"]) or
                                      passing_result(p)), \
                    mock.patch.object(self.harness, "build_side", lambda p, side: evaluated.append("built")), \
                    mock.patch.object(self.harness, "veridor_under_test", lambda: ("/x/veridor", None)), \
                    mock.patch.object(self.harness, "docker_on_path", lambda: True), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                code = self.harness.main([])
            return code, out.getvalue(), evaluated

        def daemon_down(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(["docker", *args], 1, "", down)

        code, output, evaluated = run_all(daemon_down)
        self.assertEqual((code, evaluated), (2, []), output)
        self.assertIn(f"exited 1: {down}", output)
        self.assertIn("Docker could not say which build a pinned tag names here, so nothing was run.", output)
        self.assertNotIn("no longer names the pinned build", output)

        def some_down_some_moved(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
            if args[4] in moved:
                return subprocess.CompletedProcess(["docker", *args], 0, json.dumps([f"x/y@{digest('e')}"]), "")
            return daemon_down(*args)

        # Control: with both kinds present, each summary is given once.
        code, output, _ = run_all(some_down_some_moved)
        self.assertEqual(code, 2)
        self.assertEqual(output.count("A pinned tag no longer names the pinned build, so nothing was run."), 1)
        self.assertEqual(output.count("Docker could not say which build a pinned tag names here"), 1)


class BuiltPairTest(unittest.TestCase):
    """A pair whose two builds are made here from published package files.

    Datasette publishes no image for the release that fixed CVE-2023-40570, so
    its pair is built: each side is the release's published file, pinned by its
    sha256, installed on a base image pinned by digest. Every rule below is the
    registry pair's pinning rule restated for that shape, and every refusal has
    its control: the shipped fixture, loaded as it is."""

    NAME = "datasette-private-instance-api-explorer"

    def setUp(self) -> None:
        self.harness = load_harness()
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-built-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        shutil.copytree(ROOT / "fixtures" / "pairs" / self.harness.BUILD_RECIPES, self.tmp / self.harness.BUILD_RECIPES)
        self.harness.PAIRS_DIR = self.tmp
        self.base = fixture(f"{self.NAME}.json")

    def load(self, *pairs: dict) -> list[dict]:
        for index, pair in enumerate(pairs):
            (self.tmp / f"p{index or ''}.json").write_text(json.dumps(pair), encoding="utf-8")
        return self.harness.load_pairs(None)

    def test_a_built_pair_that_pins_less_than_a_registry_pair_is_refused(self) -> None:
        pin, build = self.base["vulnerable_sha256"], self.base["build"]
        without = {key: value for key, value in self.base.items() if key != "patched_sha256"}
        refused = {
            "no recipe": ({**self.base, "build": {**build, "recipe": ""}}, "must name a recipe, a base and a package"),
            "build as a string": ({**self.base, "build": "datasette"}, "must name a recipe, a base and a package"),
            "a recipe outside build/": ({**self.base, "build": {**build, "recipe": "../../scripts"}},
                                        "one directory name under recipes/"),
            "a recipe that is not there": ({**self.base, "build": {**build, "recipe": "nothing-here"}}, "no recipe at"),
            "a base by tag": ({**self.base, "build": {**build, "base": "python:3.12-slim"}}, "by digest"),
            "a base digest cut short": ({**self.base, "build": {**build, "base": "python@sha256:f77ac9e4"}},
                                        "by digest"),
            "registry digests too": ({**self.base, "vulnerable_digest": digest("1"), "patched_digest": digest("2")},
                                     "names both a build and registry digests"),
            # One the harness has a runtime for, so this rule and not a missing
            # runtime is what refuses it: its built tag would shadow the pull.
            "an image a registry holds": ({**self.base, "image": "gitea/gitea"}, "must start 'veridor-pair-build/'"),
            "a side with no file hash": (without, "patched_sha256 must be the sha256"),
            "upper-case hex": ({**self.base, "vulnerable_sha256": pin.upper()}, "vulnerable_sha256 must be"),
            "cut short": ({**self.base, "vulnerable_sha256": pin[:12]}, "vulnerable_sha256 must be"),
            "with its algorithm": ({**self.base, "vulnerable_sha256": "sha256:" + pin}, "vulnerable_sha256 must be"),
            "one file on both sides": ({**self.base, "patched_sha256": pin}, "are one file"),
        }
        for label, (pair, message) in refused.items():
            with self.subTest(label):
                with self.assertRaises(self.harness.PairError) as caught:
                    self.load(pair)
                self.assertTrue(str(caught.exception).startswith("p.json: "), caught.exception)
                self.assertIn(message, str(caught.exception))
        # Control: the fixture as it is loads, and names its recipe.
        [pair] = self.load(self.base)
        self.assertTrue(self.harness.is_built(pair))
        self.assertEqual(self.harness.recipe_dir(pair), self.tmp / "recipes" / "datasette")

    def test_a_file_hash_on_a_registry_pair_is_refused(self) -> None:
        """A registry pair carrying *_sha256 reads as if the file were checked;
        nothing would check it."""
        registry = {**fixture(), "vulnerable_sha256": "a" * 64, "patched_sha256": "b" * 64}
        with self.assertRaisesRegex(self.harness.PairError, r"names a package file hash \(\*_sha256\) but no build"):
            self.load(registry)
        self.assertEqual(len(self.load(fixture())), 1)

    def test_the_tag_changes_with_every_input_and_only_with_them(self) -> None:
        [pair] = self.load(self.base)
        tag = self.harness.build_tag(pair, "vulnerable")
        self.assertRegex(tag, r"^veridor-pair-build/datasette:1\.0a3-[0-9a-f]{16}$")
        self.assertEqual(self.harness.build_tag(json.loads(json.dumps(pair)), "vulnerable"), tag, "same inputs")
        stamp = tag.rpartition("-")[2]
        changes = {
            "the base": lambda p: p["build"].__setitem__("base", "python@" + digest("e")),
            "the package": lambda p: p["build"].__setitem__("package", "datasette-fork"),
            "the release": lambda p: p.__setitem__("vulnerable", "1.0a2"),
            "the file hash": lambda p: p.__setitem__("vulnerable_sha256", "e" * 64),
        }
        for label, change in changes.items():
            with self.subTest(label):
                changed = json.loads(json.dumps(pair))
                change(changed)
                self.assertNotEqual(self.harness.build_tag(changed, "vulnerable").rpartition("-")[2], stamp)
        recipe = self.harness.recipe_dir(pair)
        serve = recipe / "serve.py"
        original = serve.read_bytes()
        serve.write_bytes(original + b"\n# edited\n")
        self.assertNotEqual(self.harness.build_tag(pair, "vulnerable"), tag, "a recipe file edited")
        serve.write_bytes(original)
        (recipe / "added.txt").write_text("x", encoding="utf-8")
        self.assertNotEqual(self.harness.build_tag(pair, "vulnerable"), tag, "a recipe file added")
        (recipe / "added.txt").unlink()
        self.assertEqual(self.harness.build_tag(pair, "vulnerable"), tag, "control: the recipe restored")

    def test_a_build_is_held_to_the_release_it_names_from_inside_the_image(self) -> None:
        [pair] = self.load(self.base)
        calls: list[tuple[str, ...]] = []
        answer = {"stdout": "1.0a3\n", "code": 0}

        def docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
            calls.append(args)
            if args[0] == "run":
                return subprocess.CompletedProcess(["docker", *args], answer["code"], answer["stdout"], "why")
            return subprocess.CompletedProcess(["docker", *args], 0, "", "")

        with mock.patch.object(self.harness, "_docker", docker):
            tag = self.harness.build_side(pair, "vulnerable")
            self.assertEqual(tag, self.harness.build_tag(pair, "vulnerable"))
            build, probe = calls
            self.assertEqual(build[:4], ("build", "--quiet", "--tag", tag))
            for argument in (f"BASE={pair['build']['base']}", "PACKAGE=datasette", "VERSION=1.0a3",
                             f"SHA256={pair['vulnerable_sha256']}"):
                self.assertIn(argument, build)
            self.assertEqual(build[-1], str(self.harness.recipe_dir(pair)))
            # The probe runs with no network, as python, in the image just built.
            self.assertEqual(probe[:6], ("run", "--rm", "--network", "none", "--entrypoint", "python"))
            self.assertEqual((probe[6], probe[-2:]), (tag, ("datasette", "1.0a3")))
            for label, stdout, code in (("another release", "1.0a4\n", 3), ("nothing installed", "", 1),
                                        ("the right release but the probe failed", "1.0a3\n", 1)):
                with self.subTest(label):
                    answer.update(stdout=stdout, code=code)
                    with self.assertRaisesRegex(self.harness.PairError, "holds datasette .*, not 1.0a3"):
                        self.harness.build_side(pair, "vulnerable")

    def test_the_version_probe_answers_with_the_release_and_fails_on_another(self) -> None:
        """The probe build_side runs in the image, run here in-process against
        a stubbed installed version."""
        def run(installed: str, wanted: str) -> tuple[object, str]:
            out = io.StringIO()
            with mock.patch("importlib.metadata.version", lambda name: installed), \
                    mock.patch.object(sys, "argv", ["-c", "datasette", wanted]), contextlib.redirect_stdout(out):
                try:
                    exec(self.harness.PYTHON_VERSION_PROBE, {})  # noqa: S102 -- the harness's own constant
                except SystemExit as exit_:
                    return exit_.code, out.getvalue()
            return None, out.getvalue()

        self.assertEqual(run("1.0a3", "1.0a3"), (0, "1.0a3\n"))
        self.assertEqual(run("1.0a4", "1.0a3"), (3, "1.0a4\n"))

    def test_the_local_tag_check_never_asks_about_a_built_pair(self) -> None:
        [pair] = self.load(self.base)

        def docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
            raise AssertionError(f"asked docker {args[:2]}")

        with mock.patch.object(self.harness, "_docker", docker):
            self.assertEqual(self.harness.check_local_tags([pair]), ({"match": 0, "absent": 0}, []))
            # Control: a registry pair is asked about.
            with self.assertRaisesRegex(AssertionError, "asked docker"):
                self.harness.check_local_tags([{**fixture(), "_file": "r.json"}])

    def test_a_failed_build_fails_only_its_own_pair_and_every_build_comes_first(self) -> None:
        registry = {**fixture(), "name": "pair-registry", "vulnerable_digest": digest("1"),
                    "patched_digest": digest("2")}
        order: list[str] = []
        failing = {"side": "patched"}

        def build(pair: dict, side: str) -> str:
            order.append(f"build {side}")
            if side == failing["side"]:
                raise self.harness.PairError("pip refused the file: THESE PACKAGES DO NOT MATCH THE HASHES")
            return "tag"

        def evaluate(pair: dict) -> dict:
            order.append(f"evaluate {pair['name']}")
            return passing_result(pair)

        def run() -> tuple[int, dict, str]:
            order.clear()
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(self.harness, "build_side", build), \
                    mock.patch.object(self.harness, "evaluate", evaluate), \
                    mock.patch.object(self.harness, "veridor_under_test", lambda: ("/x/veridor", None)), \
                    mock.patch.object(self.harness, "docker_on_path", lambda: True), \
                    mock.patch.object(self.harness, "check_local_tags", lambda pairs: ({"match": 0, "absent": 2}, [])), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = self.harness.main(["--json"])
            return code, json.loads(out.getvalue()), err.getvalue()

        self.load(self.base, registry)
        code, document, err = run()
        results = {result["name"]: result for result in document["pairs"]}
        self.assertEqual(code, 1)
        self.assertEqual(results[self.NAME], {
            "name": self.NAME, "passed": False,
            "error": "could not build the patched side: PairError: pip refused the file: THESE PACKAGES DO NOT "
                     "MATCH THE HASHES"})
        self.assertTrue(results["pair-registry"]["passed"])
        self.assertEqual(order, ["build vulnerable", "build patched", "evaluate pair-registry"])
        self.assertIn(f"FAILED  build of {self.NAME} (patched)", err)
        # Control: both sides build, and the built pair is evaluated after them.
        failing["side"] = None
        code, document, _ = run()
        self.assertEqual(code, 0)
        self.assertEqual(order[:2], ["build vulnerable", "build patched"])
        self.assertEqual(sorted(order[2:]), [f"evaluate {self.NAME}", "evaluate pair-registry"])
        self.assertEqual(document["pairs"][0]["built_from"], self.base["build"])

    def test_no_recipe_file_is_one_the_repository_ignores(self) -> None:
        """The recipes first lived under fixtures/pairs/build/, and .gitignore's
        `build/` ignores every directory of that name: the fixture would have
        been committed without its recipe, and CI would have refused the pair
        at load. `git check-ignore` agreed on both paths; this reads the
        patterns without git, which a source archive does not carry."""
        patterns = [line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith(("#", "!"))]

        def ignored_by(relative: str) -> list[str]:
            parts = relative.split("/")
            hits = []
            for pattern in patterns:
                body, directory_only = pattern.rstrip("/"), pattern.endswith("/")
                if "/" in body:
                    prefixes = ["/".join(parts[:end]) for end in range(1, len(parts) + (0 if directory_only else 1))]
                    matched = any(fnmatch.fnmatch(prefix, body.lstrip("/")) for prefix in prefixes)
                else:
                    matched = any(fnmatch.fnmatch(name, body) for name in (parts[:-1] if directory_only else parts))
                if matched:
                    hits.append(pattern)
            return hits

        files = sorted(path.relative_to(ROOT).as_posix()
                       for path in (ROOT / "fixtures" / "pairs" / self.harness.BUILD_RECIPES).rglob("*") if path.is_file())
        self.assertGreaterEqual(len(files), 3)
        for relative in files:
            self.assertEqual(ignored_by(relative), [], relative)
        # Controls: where the recipes first lived, and a file pattern.
        self.assertEqual(ignored_by("fixtures/pairs/build/datasette/Dockerfile"), ["build/"])
        self.assertEqual(ignored_by("fixtures/pairs/recipes/datasette/serve.pyc"), ["*.py[cod]"])

    def test_a_base_that_did_not_pull_is_not_built_and_the_pull_is_the_reason(self) -> None:
        self.load(self.base)
        base = self.base["build"]["base"]
        built: list[str] = []
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.harness, "build_side", lambda pair, side: built.append(side) or "tag"), \
                mock.patch.object(self.harness, "evaluate", lambda pair: self.fail("evaluated without its base")), \
                mock.patch.object(self.harness, "_pull_one", lambda ref: (False, "manifest unknown")), \
                mock.patch.object(self.harness, "veridor_under_test", lambda: ("/x/veridor", None)), \
                mock.patch.object(self.harness, "docker_on_path", lambda: True), \
                mock.patch.object(self.harness, "check_local_tags", lambda pairs: ({"match": 0, "absent": 0}, [])), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.harness.main(["--pull", "--json"])
        self.assertEqual((code, built), (1, []))
        [result] = json.loads(out.getvalue())["pairs"]
        self.assertEqual(result["error"], f"could not pull {base}: manifest unknown")
        # Control: the same run with the pull succeeding builds both sides.
        with mock.patch.object(self.harness, "build_side", lambda pair, side: built.append(side) or "tag"), \
                mock.patch.object(self.harness, "evaluate", passing_result), \
                mock.patch.object(self.harness, "_pull_one", lambda ref: (True, "0.1s")), \
                mock.patch.object(self.harness, "veridor_under_test", lambda: ("/x/veridor", None)), \
                mock.patch.object(self.harness, "docker_on_path", lambda: True), \
                mock.patch.object(self.harness, "check_local_tags", lambda pairs: ({"match": 0, "absent": 0}, [])), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.harness.main(["--pull"]), 0)
        self.assertEqual(built, ["vulnerable", "patched"])

    def test_every_recipe_builds_only_from_its_base_and_hash_pinned_files(self) -> None:
        """A recipe is a build input the pins cannot see into: a second FROM,
        or a pip install without --require-hashes, would fetch whatever an
        index or a tag names on the day."""
        def froms(text: str) -> list[str]:
            return [line.split()[1] for line in text.splitlines() if line.strip().upper().startswith("FROM ")]

        recipes = sorted(path for path in (ROOT / "fixtures" / "pairs" / "recipes").iterdir() if path.is_dir())
        self.assertTrue(recipes)
        for recipe in recipes:
            with self.subTest(recipe=recipe.name):
                dockerfile = (recipe / "Dockerfile").read_text(encoding="utf-8")
                self.assertEqual(froms(dockerfile), ["${BASE}"])
                if "pip install" in dockerfile:
                    self.assertIn("--require-hashes", dockerfile)
                    self.assertIn("--only-binary=:all:", dockerfile)
                for requirements in recipe.glob("*.txt"):
                    lines = [line for line in requirements.read_text(encoding="utf-8").splitlines()
                             if line.strip() and not line.startswith("#")]
                    self.assertTrue(lines)
                    for line in lines:
                        self.assertRegex(line, r"^[A-Za-z0-9._-]+==\S+( --hash=sha256:[0-9a-f]{64})+$")
        # Control: a second stage from an image by tag is seen.
        self.assertEqual(froms("FROM ${BASE}\nFROM python:3.12 AS x\n"), ["${BASE}", "python:3.12"])


class FakeDocker:
    """subprocess.run for the harness: records each docker subcommand, and
    answers from `answers` (subcommand -> CompletedProcess, or an exception
    class to raise the way subprocess.run would). Anything unlisted exits 0."""

    def __init__(self, **answers: object) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        if argv[0] != "docker":
            raise AssertionError(f"only docker is faked here, not {argv[0]}")
        self.calls.append(list(argv))
        answer = self.answers.get(argv[1])
        if answer is subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if isinstance(answer, subprocess.CompletedProcess):
            return answer
        return subprocess.CompletedProcess(argv, 0, "", "")

    def subcommands(self) -> list[str]:
        return [argv[1] for argv in self.calls]


class DockerFailureTest(unittest.TestCase):
    """What a pair reports when docker hangs or fails, and what it cleans up."""

    PAIR = "gitea-revoked-collaborator-starred-leak"

    def setUp(self) -> None:
        self.harness = load_harness()
        self.pair = next(p for p in self.harness.load_pairs(None) if p["name"] == self.PAIR)
        self.workdir = Path(tempfile.mkdtemp(prefix="veridor-pairs-docker-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def run_main(self, docker: FakeDocker, *argv: str, healthy=None) -> tuple[int, str]:
        """main() on one pair, with docker faked at subprocess.run and nothing
        but the provisioner between `docker run` and the fake."""
        out = io.StringIO()
        with mock.patch.object(self.harness.subprocess, "run", docker), \
                mock.patch.object(self.harness, "_start", lambda pair, side, container: "http://127.0.0.1:9"), \
                mock.patch.object(self.harness, "_wait_healthy", healthy or (lambda base_url, path: None)), \
                mock.patch.object(self.harness, "veridor_under_test", lambda: ("/x/veridor", None)), \
                mock.patch.object(self.harness, "docker_on_path", lambda: True), \
                mock.patch.object(self.harness, "check_local_tags", lambda pairs: ({"match": 0, "absent": 2}, [])), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.harness.main(["--pair", self.PAIR, *argv])
        return code, out.getvalue()

    def test_a_docker_timeout_names_the_subcommand_and_never_the_arguments(self) -> None:
        docker = FakeDocker(exec=subprocess.TimeoutExpired)
        code, output = self.run_main(docker)
        passwords = {argv[argv.index("--password") + 1] for argv in docker.calls if "--password" in argv}
        # Control: the provisioner did put a password on the command line, and
        # the exception subprocess.run raises for it carries the whole line.
        self.assertEqual(len(passwords), 1, docker.calls)
        password = passwords.pop()
        self.assertIn(password, str(subprocess.TimeoutExpired(docker.calls[0], 600)))
        self.assertEqual(code, 1)
        self.assertIn("could not evaluate: PairError: docker exec gave no answer in 600s", output)
        self.assertNotIn(password, output)
        self.assertEqual(docker.subcommands(), ["exec", "stop", "rm"])
        code, output = self.run_main(docker, "--json")
        self.assertNotIn(password, output)
        with mock.patch.object(self.harness.subprocess, "run", FakeDocker(exec=subprocess.TimeoutExpired)), \
                self.assertRaises(self.harness.PairError) as raised:
            self.harness._docker("exec", "c", "gitea", "--password", password)
        self.assertTrue(raised.exception.__suppress_context__, "a traceback must not print the command either")

    def test_a_hung_stop_neither_replaces_the_failure_nor_skips_the_rm(self) -> None:
        def unhealthy(base_url: str, path: str) -> None:
            raise self.harness.PairError("distinctive-original-reason")

        docker = FakeDocker(stop=subprocess.TimeoutExpired)
        code, output = self.run_main(docker, healthy=unhealthy)
        self.assertEqual(code, 1)
        self.assertIn("could not evaluate: PairError: distinctive-original-reason; and removing veridor-pair-", output)
        self.assertIn("docker stop: PairError: docker stop gave no answer in 600s", output)
        self.assertEqual(docker.subcommands(), ["stop", "rm"], "rm -f must run after a stop that hung")
        # Control: a stop that answers leaves the original reason and nothing else.
        docker = FakeDocker()
        code, output = self.run_main(docker, healthy=unhealthy)
        self.assertIn("could not evaluate: PairError: distinctive-original-reason\n", output)
        self.assertEqual(docker.subcommands(), ["stop", "rm"])

    def test_a_container_that_could_not_be_removed_fails_the_pair(self) -> None:
        result = passing_result(self.pair)

        def evaluate(docker: FakeDocker) -> object:
            with mock.patch.object(self.harness.subprocess, "run", docker), \
                    mock.patch.object(self.harness, "_run_build", lambda *args: result):
                try:
                    return self.harness._evaluate_build(self.pair, "vulnerable", self.workdir)
                except self.harness.PairError as error:
                    return error

        stuck = evaluate(FakeDocker(rm=subprocess.CompletedProcess([], 1, "", "Error: removal of container in progress")))
        self.assertIsInstance(stuck, self.harness.PairError)
        self.assertIn("may still be running, a known-vulnerable build on loopback", str(stuck))
        self.assertIn("docker rm -f exited 1: Error: removal of container in progress", str(stuck))
        hung = evaluate(FakeDocker(rm=subprocess.TimeoutExpired))
        self.assertIn("docker rm -f: PairError: docker rm gave no answer in 600s", str(hung))
        # Controls: removed, after a stop that hung, or of a container that is
        # already gone, is the pair's own result.
        self.assertIs(evaluate(FakeDocker()), result)
        self.assertIs(evaluate(FakeDocker(stop=subprocess.TimeoutExpired)), result)
        gone = subprocess.CompletedProcess([], 1, "", "Error response from daemon: No such container: c")
        self.assertIs(evaluate(FakeDocker(stop=gone, rm=gone)), result)


class VeridorUnderTestDecisionTest(unittest.TestCase):
    """The installed-mode guard's rule, given what the probe printed."""

    def setUp(self) -> None:
        self.harness = load_harness()
        self.src = Path(os.path.realpath(self.harness.SRC))
        self.venv = "/opt/venv/lib/python3.12/site-packages/veridor"

    def decide(self, mode: str, returncode: int, stdout: str = "", stderr: str = "") -> tuple:
        return self.harness.veridor_under_test_decision(mode, returncode, stdout, stderr, python="/opt/venv/bin/python")

    @staticmethod
    def answer(package: str | None, installed: bool) -> str:
        """What UNDER_TEST_PROBE prints for veridor/cli.py in `package`."""
        return json.dumps({"module": package and f"{package}/cli.py", "installed": installed}) + "\n"

    def test_installed_mode_accepts_only_an_installed_package(self) -> None:
        self.assertEqual(self.decide("installed", 0, self.answer(self.venv, True)), (self.venv, None))
        path, refusal = self.decide("installed", 1, stderr="Traceback (most recent call last):\n  ...\n"
                                    "ModuleNotFoundError: No module named 'veridor'\n")
        self.assertIsNone(path)
        self.assertIn("/opt/venv/bin/python cannot import veridor (ModuleNotFoundError: No module named 'veridor')",
                      refusal)
        for installed in (True, False):
            path, refusal = self.decide("installed", 0, self.answer(f"{self.src}/veridor", installed))
            self.assertIsNone(path)
            self.assertIn(f"inside this checkout's {self.src}", refusal)
            self.assertIn("would test the checkout, not the package", refusal)
        self.assertIn("printed no path", self.decide("installed", 0, "\n")[1])
        # A directory whose name only starts with src/'s is not inside it.
        sibling = f"{self.src}-copy/veridor"
        self.assertEqual(self.decide("installed", 0, self.answer(sibling, True)), (sibling, None))

    def test_installed_mode_refuses_what_no_installed_distribution_lists(self) -> None:
        """Each of these was accepted: the probe printed veridor.__file__ and
        the rule was only "not inside src/"."""
        # A bare veridor/ in the working directory, nothing installed: the
        # probe now imports veridor.cli, and that fails.
        path, refusal = self.decide("installed", 1, stderr="ModuleNotFoundError: No module named 'veridor.cli'\n")
        self.assertIsNone(path)
        self.assertIn("cannot import veridor (ModuleNotFoundError: No module named 'veridor.cli')", refusal)
        # A copy of the package that no distribution's RECORD lists.
        path, refusal = self.decide("installed", 0, self.answer("/work/cwd-copy/veridor", False))
        self.assertIsNone(path)
        self.assertIn("imports veridor from /work/cwd-copy/veridor, and no installed distribution's RECORD lists it",
                      refusal)
        self.assertIn("imported veridor.cli from no file", self.decide("installed", 0, self.answer(None, False))[1])
        # What the old probe printed is not an answer; nor is anything else.
        for printed in (f"{self.venv}/__init__.py\n", "None\n", "[]\n", '{"module": "/x/cli.py"}\n',
                        '{"module": "/x/cli.py", "installed": "yes"}\n'):
            with self.subTest(printed=printed):
                path, refusal = self.decide("installed", 0, printed)
                self.assertIsNone(path)
                self.assertIn("not the probe's answer", refusal)
        # Control: the same copy, listed by a distribution, is accepted.
        self.assertEqual(self.decide("installed", 0, self.answer("/work/cwd-copy/veridor", True)),
                         ("/work/cwd-copy/veridor", None))

    def test_control_source_mode_is_the_mirror_image(self) -> None:
        inside = f"{self.src}/veridor"
        self.assertEqual(self.decide("source", 0, self.answer(inside, False)), (inside, None))
        self.assertIn("not from", self.decide("source", 0, self.answer(self.venv, True))[1])
        self.assertIn("cannot import veridor", self.decide("source", 1, stderr="ImportError: x")[1])
        self.assertNotIn("Install the wheel", self.decide("source", 1, stderr="ImportError: x")[1])


class VeridorProcessTest(unittest.TestCase):
    """The guard's probe and the pairs launch Veridor the same way."""

    def test_the_probe_asks_the_interpreter_environment_and_directory_the_pairs_run_with(self) -> None:
        harness = load_harness()
        calls: list[tuple[list[str], dict]] = []

        def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            calls.append((list(argv), dict(kwargs)))
            answer = {"module": f"{harness.SRC}/veridor/cli.py", "installed": False}
            return subprocess.CompletedProcess(argv, 0, json.dumps(answer) if "-c" in argv else "", "")

        provisioned = {"VERIDOR_PAIR_OWNER_TOKEN": "owner-token", "VERIDOR_PAIR_ATTACKER_TOKEN": "attacker-token"}
        work = Path(tempfile.mkdtemp(prefix="veridor-pairs-launch-"))
        self.addCleanup(shutil.rmtree, work, True)
        with mock.patch.object(harness.subprocess, "run", run):
            harness.veridor_under_test()
            harness._run_veridor(work / "c.json", "http://127.0.0.1:9", work / "out", provisioned)
        (probe, probe_kwargs), (pair, pair_kwargs) = calls
        self.assertEqual(launch_differences(probe, probe_kwargs, pair, pair_kwargs, provisioned), [])
        self.assertEqual(probe[:2], [sys.executable, "-c"])
        self.assertIn("import veridor.cli", probe[2])
        self.assertEqual(pair[:3], [sys.executable, "-m", "veridor.cli"])
        self.assertEqual(probe_kwargs["env"].get("PYTHONPATH"), source_path.child_env().get("PYTHONPATH"))
        # Controls: each divergence that used to pass every test is named.
        self.assertEqual(len(launch_differences(probe, dict(probe_kwargs, cwd="/"), pair, pair_kwargs, provisioned)), 1)
        kept = dict(pair_kwargs, env={**pair_kwargs["env"], "PYTHONPATH": "/elsewhere"})
        self.assertEqual(len(launch_differences(probe, probe_kwargs, pair, kept, provisioned)), 1)
        self.assertEqual(len(launch_differences(["/usr/bin/python3", *probe[1:]], probe_kwargs, pair, pair_kwargs,
                                                provisioned)), 1)


def launch_differences(probe: list[str], probe_kwargs: dict, pair: list[str], pair_kwargs: dict,
                       provisioned: dict[str, str]) -> list[str]:
    """How the probe's launch differs from a pair's, beyond what the pair adds
    on purpose: its own arguments, its timeout, and the provisioner's values."""
    differences = []
    if probe[0] != pair[0]:
        differences.append(f"interpreter: probe {probe[0]}, pair {pair[0]}")
    pair_env = {key: value for key, value in pair_kwargs.get("env", {}).items() if key not in provisioned}
    if probe_kwargs.get("env") != pair_env:
        changed = sorted(set(probe_kwargs.get("env") or {}) ^ set(pair_env)
                         | {k for k in pair_env if (probe_kwargs.get("env") or {}).get(k) != pair_env[k]})
        differences.append(f"environment differs in {changed}")
    if probe_kwargs.get("cwd") != pair_kwargs.get("cwd"):
        differences.append(f"cwd: probe {probe_kwargs.get('cwd')!r}, pair {pair_kwargs.get('cwd')!r}")
    return differences


@slow("creates virtual environments and runs scripts/patched_pairs.py in them")
class InstalledGuardRunTest(unittest.TestCase):
    """The guard, run for real by interpreters in fresh virtual environments.

    PATH holds no docker, so no run can start a container: a run the guard
    refuses stops at the guard, and one it accepts gets past it to the docker
    check."""

    def test_installed_mode_without_veridor_exits_2_and_source_mode_passes_the_guard(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="veridor-guard-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(tmp / "venv")],
                       check=True, capture_output=True, timeout=120)
        python = tmp / "venv" / "bin" / "python"
        (tmp / "no-docker").mkdir()
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        env["PATH"] = str(tmp / "no-docker")

        def run(mode: str) -> subprocess.CompletedProcess:
            return subprocess.run([str(python), str(SCRIPT)], cwd=tmp, capture_output=True, text=True,
                                  env={**env, "VERIDOR_TEST_AGAINST": mode}, timeout=120, check=False)

        installed = run("installed")
        self.assertEqual(installed.returncode, 2, installed.stdout + installed.stderr)
        self.assertIn("VERIDOR_TEST_AGAINST=installed, and", installed.stderr)
        self.assertIn("cannot import veridor (ModuleNotFoundError: No module named 'veridor')", installed.stderr)
        self.assertNotIn("veridor under test", installed.stdout)
        self.assertNotIn("docker is not on PATH", installed.stderr, "the guard must stop it first")

        source = run("source")
        self.assertEqual(source.returncode, 2, source.stdout + source.stderr)
        self.assertIn(f"veridor under test: {os.path.realpath(ROOT / 'src' / 'veridor')}\n", source.stdout)
        self.assertIn("docker is not on PATH", source.stderr)

    def test_installed_mode_runs_only_a_package_an_installed_distribution_lists(self) -> None:
        """Before, from a working directory holding a bare `veridor/`, the
        probe printed None, the guard accepted the working directory, and the
        pairs failed on "No module named veridor.cli" with
        vulnerable_build_fails marked ok (measured on the vikunja pair). A copy
        of the package in the working directory was accepted and tested in
        place of the wheel."""
        tmp = Path(tempfile.mkdtemp(prefix="veridor-guard-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(tmp / "venv")],
                       check=True, capture_output=True, timeout=120)
        python = tmp / "venv" / "bin" / "python"
        purelib = Path(subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                                      check=True, capture_output=True, text=True, timeout=60).stdout.strip())
        for name in ("no-docker", "plain", "bare/veridor", "copy"):
            (tmp / name).mkdir(parents=True)
        shutil.copytree(ROOT / "src" / "veridor", tmp / "copy" / "veridor")
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        env.update(PATH=str(tmp / "no-docker"), VERIDOR_TEST_AGAINST="installed")

        def run(cwd: str) -> subprocess.CompletedProcess:
            return subprocess.run([str(python), str(SCRIPT)], cwd=tmp / cwd, capture_output=True,
                                  text=True, env=env, timeout=120, check=False)

        def refused(result: subprocess.CompletedProcess, why: str) -> None:
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn(why, result.stderr)
            self.assertNotIn("veridor under test", result.stdout)
            self.assertNotIn("docker is not on PATH", result.stderr, "the guard must stop it first")

        refused(run("bare"), "cannot import veridor (ModuleNotFoundError: No module named 'veridor.cli')")
        refused(run("copy"), f"imports veridor from {os.path.realpath(tmp / 'copy' / 'veridor')}, and no installed "
                             "distribution's RECORD lists it")
        # The package in site-packages, the way a wheel lays it out, but with
        # no distribution to list it: refused.
        shutil.copytree(ROOT / "src" / "veridor", purelib / "veridor")
        refused(run("plain"), "and no installed distribution's RECORD lists it")
        # Control: with the dist-info a pip install writes, the same files run.
        info = purelib / "veridor-0.0.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: veridor\nVersion: 0.0.0\n", encoding="utf-8")
        listed = sorted(str(path.relative_to(purelib)) for path in (purelib / "veridor").rglob("*") if path.is_file())
        (info / "RECORD").write_text("".join(f"{entry},,\n" for entry in listed), encoding="utf-8")
        accepted = run("plain")
        self.assertEqual(accepted.returncode, 2, accepted.stdout + accepted.stderr)
        self.assertIn(f"veridor under test: {os.path.realpath(purelib / 'veridor')}\n", accepted.stdout)
        self.assertIn("docker is not on PATH", accepted.stderr)




class OwnPairsDirectoryTest(unittest.TestCase):
    """`--pairs-dir DIR` runs pairs the repository cannot carry.

    A fixture describes the bug it tests, so a finding whose details are not
    public cannot ship in fixtures/pairs/: publishing one would disclose it.
    Such pairs live outside the repository and are named with --pairs-dir or
    VERIDOR_PAIRS_DIR. What is pinned here is the fail-safe half: a directory
    that does not exist, a pair name already used, and an extension that
    rebinds a shipped provisioner are each refused, because any of them could
    drop a published advisory from the run while the output still read as a pass.
    """

    def setUp(self) -> None:
        self.harness = load_harness()
        self.shipped = Path(tempfile.mkdtemp(prefix="veridor-shipped-"))
        self.own = Path(tempfile.mkdtemp(prefix="veridor-own-"))
        for directory in (self.shipped, self.own):
            self.addCleanup(shutil.rmtree, directory, True)
        self.harness.PAIRS_DIR = self.shipped
        base = fixture()
        self.write(self.shipped, {**base, "name": "shipped-pair",
                                  "vulnerable_digest": digest("1"), "patched_digest": digest("2")})
        self.mine = {**base, "name": "my-own-pair", "image": "example/private",
                    "provision": "private_thing",
                    "vulnerable_digest": digest("3"), "patched_digest": digest("4")}

    def write(self, directory: Path, pair: dict) -> None:
        (directory / f"{pair['name']}.json").write_text(json.dumps(pair), encoding="utf-8")

    def extension(self, body: str) -> None:
        (self.own / self.harness.EXTENSION).write_text(body, encoding="utf-8")

    ADDS = ("def register(runtimes, provisioners):\n"
            "    runtimes['example/private'] = lambda base_url: ['--tmpfs', '/data']\n"
            "    provisioners['private_thing'] = lambda container, base_url, marker: {}\n")

    def test_a_pair_in_another_directory_runs_and_is_marked_as_not_shipped(self) -> None:
        self.write(self.own, self.mine)
        self.extension(self.ADDS)
        pairs = self.harness.load_pairs(extra_dirs=[str(self.own)])
        self.assertEqual([p["name"] for p in pairs], ["shipped-pair", "my-own-pair"])
        self.assertEqual([p["_shipped"] for p in pairs], [True, False])
        self.assertEqual(pairs[1]["_dir"], str(self.own.resolve()))
        # Control: without the directory, only the shipped pair is read.
        self.assertEqual([p["name"] for p in self.harness.load_pairs()], ["shipped-pair"])

    def test_the_same_directory_named_twice_is_read_once(self) -> None:
        self.write(self.own, self.mine)
        self.extension(self.ADDS)
        pairs = self.harness.load_pairs(extra_dirs=[str(self.own), str(self.own) + "/"])
        self.assertEqual([p["name"] for p in pairs], ["shipped-pair", "my-own-pair"])

    def test_a_directory_that_is_not_one_is_refused(self) -> None:
        missing = str(self.own / "nope")
        with self.assertRaises(self.harness.PairError) as raised:
            self.harness.load_pairs(extra_dirs=[missing])
        self.assertIn("not a directory", str(raised.exception))

    def test_a_pair_name_used_twice_is_refused_whichever_directory_it_is_in(self) -> None:
        """A private directory that reused a shipped name would shadow it: the
        published advisory would stop running while the run still named the pair."""
        self.extension(self.ADDS)
        self.write(self.own, {**self.mine, "name": "shipped-pair"})
        with self.assertRaises(self.harness.PairError) as raised:
            self.harness.load_pairs(extra_dirs=[str(self.own)])
        self.assertIn("already used by", str(raised.exception))

    def test_an_extension_may_add_but_never_rebind_what_the_harness_ships(self) -> None:
        self.write(self.own, self.mine)
        shipped_image = next(iter(self.harness.RUNTIMES))
        shipped_provisioner = next(iter(self.harness.PROVISIONERS))
        for label, body in {
            "a rebound runtime": f"def register(runtimes, provisioners):\n"
                                 f"    runtimes[{shipped_image!r}] = lambda base_url: []\n",
            "a rebound provisioner": f"def register(runtimes, provisioners):\n"
                                     f"    provisioners[{shipped_provisioner!r}] = lambda *a: {{}}\n",
        }.items():
            with self.subTest(label):
                self.extension(body)
                with self.assertRaises(self.harness.PairError) as raised:
                    self.harness.load_pairs(extra_dirs=[str(self.own)])
                self.assertIn("rebinds the", str(raised.exception))
        # Control: the same module shape that only ADDS is accepted, and the
        # shipped entries are untouched afterwards.
        self.extension(self.ADDS)
        self.assertEqual(len(self.harness.load_pairs(extra_dirs=[str(self.own)])), 2)
        self.assertIn(shipped_image, self.harness.RUNTIMES)
        self.assertIn(shipped_provisioner, self.harness.PROVISIONERS)

    def test_an_extension_without_register_is_refused(self) -> None:
        self.write(self.own, self.mine)
        self.extension("WHAT = 1\n")
        with self.assertRaises(self.harness.PairError) as raised:
            self.harness.load_pairs(extra_dirs=[str(self.own)])
        self.assertIn("must define register(", str(raised.exception))

    def test_a_pair_whose_runtime_the_extension_never_added_is_refused(self) -> None:
        """The ordinary load check still applies to a private pair: no runtime,
        no run. Without an extension at all, the pair names one nothing has."""
        self.write(self.own, self.mine)
        with self.assertRaises(self.harness.PairError) as raised:
            self.harness.load_pairs(extra_dirs=[str(self.own)])
        self.assertIn("no runtime for image", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
