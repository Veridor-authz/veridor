"""The README is an emitted artifact and is held to the same claim contract.

Two failures motivate this file.

1. The README promised a guarantee the code no longer makes: "Veridor requires
   the matching control in the same check". The identity-level ``marker_probe``
   is a second, weaker control that the loader accepts and that the error
   message actively recommends -- and it appeared nowhere in the README, in
   docs/, or in any fixture. An operator was pointed at a key with no
   documented schema and no statement of its weaker guarantee.

2. The Verdicts table defined ``vulnerable`` with the word "disclosed", which
   asserts the flow was improper. tests/test_marker.py already bans that word
   from emitted finding titles; it survived in the document that defines the
   vocabulary.

This is not the only file holding the README to a contract:
``tests/test_session.DocumentationTest`` covers the write-safety and session
keys. Check both before reflowing a paragraph.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor.cli import _parser, main  # noqa: E402
from veridor.core import load_config  # noqa: E402
from veridor.coverage import BADGE_LABEL  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")

def _prose(text: str) -> str:
    """Read a passage the way a reader does: no emphasis, no code fences.

    Prose in the README is hard-wrapped and carries markdown emphasis, so a
    sentence-level assertion has to read it the way a reader does rather than
    the way it is stored. This drops backticks too, which :data:`PROSE` keeps;
    both exist because the older assertions quote code spans deliberately.
    Blockquote markers go too: the write-safety warning is a blockquote, and a
    reader does not read ``>`` in the middle of a sentence.
    """
    text = re.sub(r"^\s*>\s?", "", text, flags=re.MULTILINE)
    return re.sub(r"\s+", " ", text.replace("**", "").replace("*", "").replace("`", ""))


#: The whole README, unwrapped, with emphasis removed but code spans intact.
PROSE = re.sub(r"\s+", " ", README.replace("**", "").replace("*", ""))
SCOPE_ANCHOR = "#what-a-veridor-finding-does-and-does-not-mean"


def _section(heading: str) -> str:
    """Return the README text under one ``##`` heading."""
    match = re.search(
        rf"^## {re.escape(heading)}$(.*?)(?=^## |\Z)", README, re.MULTILINE | re.DOTALL
    )
    if match is None:  # pragma: no cover - failure path
        raise AssertionError(f"README has no '## {heading}' section")
    return match.group(1)


class MarkerProbeDocumentationTest(unittest.TestCase):
    def test_the_readme_documents_the_key_its_own_error_recommends(self) -> None:
        self.assertIn("marker_probe", README)

    def test_the_readme_shows_a_marker_probe_schema(self) -> None:
        """Pointing at a key without a schema is not documentation."""
        self.assertRegex(README, r'"marker_probe":\s*\{\s*"method"')
        self.assertIn("takes the same keys as a check `request`", PROSE)

    def test_the_readme_states_the_weaker_guarantee(self) -> None:
        """The two controls are not equivalent and the code knows it."""
        self.assertIn("live somewhere", PROSE.lower())
        self.assertIn("not that the path under test can surface it", PROSE)

    def test_the_readme_no_longer_promises_a_same_check_control_is_the_only_one(
        self,
    ) -> None:
        self.assertNotIn("requires the matching control in the same check", PROSE)
        # The requirement that SOME control exists is unchanged and must stay.
        self.assertIn("requires a control behind every exclusion", PROSE)

    def test_the_readme_documents_the_disclosure_channel(self) -> None:
        """A run that leans on the weaker control says so; say where."""
        self.assertIn("oracle_disclosures", README)


class VerdictVocabularyTest(unittest.TestCase):
    def test_the_readme_does_not_define_a_verdict_with_a_policy_word(self) -> None:
        """'disclosed' asserts the flow was improper; the tests already ban it."""
        self.assertNotIn("disclosed", README)

    def test_the_verdicts_section_links_back_to_the_scoping_section(self) -> None:
        """It is the section a reader jumps to while triaging a report."""
        self.assertIn(SCOPE_ANCHOR, _section("Verdicts"))

    def test_every_emitted_verdict_is_documented(self) -> None:
        verdicts = _section("Verdicts")
        for verdict in ("safe", "vulnerable", "unexpected_denial", "inconclusive"):
            self.assertIn(f"`{verdict}`", verdicts, verdict)

    def test_the_refusal_verdict_is_documented_as_still_failing(self) -> None:
        """Narrowing the label must not read as softening the gate."""
        self.assertIn(
            "still trips the gates",
            re.sub(r"\s+", " ", _section("Verdicts")),
        )


class ThreeVerbShapeTest(unittest.TestCase):
    """The README is the other place the product's shape is stated.

    ``tests/test_cli_verbs.HelpShapeTest`` holds ``--help`` to it. Holding the
    README to it as well is what stops the two drifting apart, which is how a
    tool ends up with a coherent CLI and a document describing nine peers.
    """

    def test_the_readme_leads_with_the_three_verbs(self) -> None:
        self.assertIn("## The three verbs", README)
        verbs = README.index("## The three verbs")
        for later in ("## Install", "## Quickstart", "## Exit codes"):
            self.assertLess(verbs, README.index(later), later)

    def test_the_journey_is_stated(self) -> None:
        self.assertIn("Discover, declare, gate, then verify the gate.", PROSE)

    def test_each_verb_has_its_own_section(self) -> None:
        for heading in (
            "## Map: what would a compromise reach?",
            "## Mutate: would my suite catch a regression?",
        ):
            self.assertIn(heading, README, heading)

    def test_the_utilities_are_named_as_subordinate(self) -> None:
        self.assertIn(
            "are utilities you reach for while using the three verbs, not "
            "headline commands",
            PROSE,
        )

    def test_the_utilities_listed_are_the_ones_help_lists(self) -> None:
        """The list left out `capsule`, which `veridor --help` shows."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            main(["--help"])
        utilities = out.getvalue().split("UTILITIES", 1)[1]
        in_help = re.findall(r"^  ([a-z][a-z-]+)  ", utilities, re.M)
        self.assertIn("capsule", in_help)  # control: the help was read
        sentence = PROSE[:PROSE.index("are utilities you reach for")]
        sentence = sentence[sentence.rindex(".") + 1:]
        self.assertEqual(re.findall(r"\b[a-z][a-z-]+\b", sentence.replace(" and ", " ")), in_help)

    def test_only_run_is_documented_as_gating_on_what_it_found(self) -> None:
        """`map` failing a build over something it DISCOVERED would be a defect.

        `--fail-on-drift` is the one way `map` can exit non-zero, and it is a
        different claim: two matrices differ. It is opt-in, and the README has
        to say both halves — that discovery never gates, and that this one
        thing can — or the exception quietly swallows the rule.
        """
        prose = _prose(README)
        # _prose strips emphasis, so quote the sentence as a reader reads it.
        self.assertIn("Only run gates on what it discovered.", prose)
        self.assertIn("map exits 0 no matter what it finds", prose)
        self.assertIn("The single exception is opt-in", prose)

    def test_the_drift_exception_is_documented_as_not_a_finding(self) -> None:
        """The moment `map` can fail a build, the reason it still is not a
        scanner has to travel with it."""
        section = _prose(_section("Map: what would a compromise reach?"))
        self.assertIn("A change is an observation, not a verdict.", section)
        self.assertIn("drift produces no SARIF", section)
        # The blindness is the honest half and the easiest to quietly drop.
        self.assertIn("blind to anything that did not change", section)

    def test_drift_does_not_gate_unless_asked(self) -> None:
        section = _prose(_section("Map: what would a compromise reach?"))
        self.assertIn("no exit code unless you ask", section)
        self.assertIn("never — the report is printed and map still exits 0", section)

    def test_a_candidate_is_documented_as_not_a_finding(self) -> None:
        self.assertIn("### A candidate is not a finding", README)
        self.assertIn("produces no SARIF result", _prose(README))

    def test_a_mutation_score_is_documented_as_measuring_the_declaration(self) -> None:
        self.assertIn("measures your declaration, not your target.", _prose(README))

    def test_tier_two_is_documented_as_executing_operator_commands(self) -> None:
        """Understating this would be the documentation failing at its one job."""
        self.assertIn("### Tier 2 runs commands you supply", README)
        self.assertIn(
            "are executed on your machine, as you, with your environment.",
            _prose(_section("Mutate: would my suite catch a regression?")),
        )
        self.assertIn("run as an argv list with no shell", _prose(README))
        self.assertIn("A hook with no restore_command is refused.", _prose(README))
        self.assertIn("--i-understand-tier-2-runs-my-commands", README)

    def test_a_tier_two_kill_is_documented_as_needing_access_granted(self) -> None:
        """The README said any status failure was a kill, a refusal included.

        mutation.py now scores a mutated build that only refused an identity it
        should serve as aberrant: removing a guard grants access, so a refusal
        is the build breaking, not the suite noticing the removal.
        """
        section = _prose(_section("Mutate: would my suite catch a regression?"))
        self.assertNotIn("Only a status or data-flow failure counts as red", section)
        self.assertIn(
            "A hook is killed only when the suite, with the guard removed, sees "
            "an identity served what its declaration refuses",
            section,
        )
        # The aberrant case is wider than "refused an identity it should
        # serve": a different refusal of an identity expected refused lands
        # there too, and the README described only the first.
        self.assertIn(
            "A mutated build that only refuses is reported aberrant, because a "
            "kill needs the suite to see an identity served what its declaration "
            "refuses and it saw only refusals: whether it refuses an identity the "
            "suite expects it to serve", section
        )
        # An earlier fix dropped the cause from the report's reason: a
        # guard removal can turn 403 into 404, so "the guard's removal is not
        # what the suite saw" may be false. This test pinned that sentence.
        self.assertIn(
            "or refuses an identity the suite expects refused with a different "
            "status (401 declared, 302 drawn; 403 declared, 404 drawn). Veridor "
            "cannot tell whether the guard's removal caused a changed refusal; "
            "a guard that hid existence can turn 403 into 404. The report names "
            "each identity and what it drew, and words the reason for that "
            "case.", section
        )
        self.assertNotIn("the guard's removal is not what the suite saw", section)
        self.assertIn("an inconclusive result is never a kill", section)

    def test_the_matrix_safety_posture_is_documented(self) -> None:
        section = _prose(_section("Map: what would a compromise reach?"))
        for promise in (
            "Read-only by default.",
            "The plan is refused before the first request.",
            "Rate limited and sequential.",
            "--dry-run sends nothing.",
        ):
            self.assertIn(promise, section, promise)

    def test_the_readme_still_denies_route_discovery(self) -> None:
        """`map` enumerates a spec you supplied. It must not be sold as crawling."""
        self.assertIn("No API discovery.", README)
        self.assertIn("never crawls or guesses routes", _prose(README))


def _bash_blocks() -> list[str]:
    """Every fenced ```bash block in the README, as raw text."""
    return re.findall(r"^```bash\n(.*?)^```", README, re.MULTILINE | re.DOTALL)


def _veridor_invocations() -> list[list[str]]:
    """Every `veridor ...` command line in the README, tokenised.

    Continuations are joined, comments dropped, and a trailing ``&`` (the
    quickstart backgrounds the demo server) removed.
    """
    commands: list[list[str]] = []
    for block in _bash_blocks():
        joined = block.replace("\\\n", " ")
        for line in joined.splitlines():
            line = line.split("#", 1)[0].strip().rstrip("&").strip()
            if not line.startswith("veridor "):
                continue
            tokens = shlex.split(line)
            if tokens[1].startswith("-"):
                continue  # `veridor --version`; no subcommand to check
            commands.append(tokens)
    return commands


class ExecutableReadmeTest(unittest.TestCase):
    """A README with a command that does not work is worse than no README.

    Every ``veridor`` line in the document is checked against the real parser:
    the subcommand must exist and every flag must be one that subcommand
    accepts. This does not send a request, so it costs nothing and runs in the
    fast tier, but it is what stops the document drifting from the CLI.
    """

    @classmethod
    def setUpClass(cls) -> None:
        parser = _parser()
        action = next(
            item
            for group in parser._subparsers._group_actions
            for item in [group]
            if isinstance(item, argparse._SubParsersAction)
        )
        cls.subcommands = action.choices

    def test_the_readme_actually_invokes_veridor(self) -> None:
        """A guard on the extractor: silently matching nothing would pass."""
        self.assertGreaterEqual(len(_veridor_invocations()), 8)

    def test_every_documented_subcommand_exists(self) -> None:
        for command in _veridor_invocations():
            with self.subTest(command=" ".join(command)):
                self.assertIn(command[1], self.subcommands)

    def test_every_documented_flag_exists_on_its_subcommand(self) -> None:
        for command in _veridor_invocations():
            subparser = self.subcommands[command[1]]
            known = set(subparser._option_string_actions)
            for token in command[2:]:
                if token.startswith("--"):
                    flag = token.split("=", 1)[0]
                    with self.subTest(command=" ".join(command), flag=flag):
                        self.assertIn(flag, known)

    def test_every_fixture_the_readme_names_exists(self) -> None:
        """The quickstart is worthless if the file it points at is gone."""
        named = set(re.findall(r"(fixtures/[\w.\-]+\.(?:json|py))", README))
        named |= set(re.findall(r"(scripts/[\w.\-]+\.py)", README))
        self.assertGreaterEqual(len(named), 5)
        for relative in sorted(named):
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).exists(), relative)


class ReadmeConfigLoadsTest(unittest.TestCase):
    """Every JSON configuration the README shows must actually load.

    The flagship session example did not. It declared `capture.csrf` on a login
    step AND on the session, which is a load error by design -- one flat
    namespace per identity, single-assignment -- so anyone who copied the
    document's own example was stopped at exit 2 before a single request. The
    flag checker above cannot see this: it reads commands, not configurations.
    """

    def _session_example(self) -> dict:
        block = re.search(
            r'\{\n  "identities": \{\n    "victim".*?\n\}\n', README, re.S
        )
        self.assertIsNotNone(block, "the README session example moved or vanished")
        return json.loads(block.group(0))

    def test_the_session_example_loads(self) -> None:
        document = self._session_example()
        document["version"] = 1
        document["target"] = {"base_url": "http://127.0.0.1:1"}
        # The example shows one identity because it is about one session; a
        # loadable config needs the second, and a check to grade.
        document["identities"]["attacker"] = {"headers": {"Authorization": "Bearer a"}}
        document["checks"] = [{
            "id": "c",
            "request": {"method": "GET", "path": "/api/x"},
            "expect": {"victim": {"status": [200]}, "attacker": {"status": [403]}},
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with patch.dict(os.environ, {"VICTIM_PASSWORD": "x"}):
                load_config(path, None)

    def test_the_example_uses_two_capture_names(self) -> None:
        """The guard on the guard: one name is what made it unloadable."""
        session = self._session_example()["identities"]["victim"]["session"]
        step_names = {
            name
            for step in session["login"]
            for name in (step.get("capture") or {})
        }
        self.assertTrue(step_names)
        self.assertEqual(step_names & set(session.get("capture") or {}), set())

    def test_the_document_states_the_namespace_rule(self) -> None:
        self.assertIn("one flat namespace per identity", README)
        self.assertIn("more than once", README)


class ReadmeShapeTest(unittest.TestCase):
    """The document follows the journey, not the order features were built.

    Four workflows appended to this file. The order below is the product's
    shape: what it is, how to install it, something real in sixty seconds, the
    three verbs, CI, and only then the limits and the non-goals.
    """

    ORDER = (
        "# Veridor",
        "## The three verbs",
        "## Install",
        "## Quickstart",
        "## Map: what would a compromise reach?",
        "## Run: does the boundary hold, and did it change?",
        "## Mutate: would my suite catch a regression?",
        "## Continuous integration",
        "## What a Veridor finding does and does not mean",
        "## Non-goals",
    )

    def test_the_sections_appear_in_the_journey_order(self) -> None:
        positions = []
        for heading in self.ORDER:
            self.assertIn(heading, README, heading)
            positions.append(README.index(heading))
        self.assertEqual(positions, sorted(positions), self.ORDER)

    def test_the_first_run_produces_a_real_result(self) -> None:
        """A quickstart that prints nothing is a tutorial, not a first run."""
        quickstart = _section("Quickstart: your first 60 seconds")
        self.assertIn("scripts/demo_server.py --vulnerable", quickstart)
        self.assertIn("veridor run --config fixtures/veridor.demo.json", quickstart)
        self.assertIn("1 vulnerable", quickstart)
        self.assertIn("Exit code 1", _prose(quickstart))

    def test_each_verb_section_carries_a_runnable_example(self) -> None:
        for heading in (
            "Map: what would a compromise reach?",
            "Run: does the boundary hold, and did it change?",
            "Mutate: would my suite catch a regression?",
        ):
            with self.subTest(heading=heading):
                self.assertRegex(_section(heading), r"```bash\n(.|\n)*?veridor ")


class CoverageBlockProseTest(unittest.TestCase):
    """What the README says the `coverage` block holds, and what it refuses.

    It said the block "accepts only 4xx statuses other than 401 and 407
    (anything else exits 2)", while a misspelt `Denial_Statuses`, a `null`, or
    a `coverage` that was a list loaded and was measured against the default
    403 and 404 with exit 0. The passage now names each refusal, and each one
    is driven through `veridor coverage` on the demo config here.
    """

    SHAPE = "The block holds denial_statuses and _ annotations and nothing else."
    REFUSED = (
        "A status outside that rule, a null, a misspelt or unknown key in the block "
        "(a near-miss is named), or a coverage that is not an object is refused before "
        "the figure is computed: veridor coverage exits 2, and run --openapi reports "
        "coverage as not measured."
    )
    #: One case per clause of REFUSED, in order.
    CASES = (
        ("a status outside that rule", {"denial_statuses": [401]}),
        ("a null", {"denial_statuses": None}),
        ("a misspelt key", {"Denial_Statuses": [403]}),
        ("an unknown key", {"denial_statuses": [403], "fail_under": 80}),
        ("not an object", [403]),
    )

    def _coverage(self, block: object, directory: str) -> tuple[int, str, str]:
        document = json.loads((ROOT / "fixtures" / "veridor.demo.json").read_text())
        document["coverage"] = block
        config = Path(directory) / "veridor.json"
        config.write_text(json.dumps(document), encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["coverage", "--config", str(config),
                         "--openapi", str(ROOT / "fixtures" / "openapi.demo.json")])
        return code, stdout.getvalue(), stderr.getvalue()

    REWRITTEN = (
        "On that refusal, and on a configuration or specification that does not "
        "load, a --coverage file is rewritten with \"status\": \"not_measured\", a "
        "null figure and the reason, and a --badge file as unknown, so neither keeps "
        "a previous run's figure."
    )

    def test_the_passage_says_a_refusal_rewrites_both_files(self) -> None:
        """The badge was rewritten and the --coverage file was not, and the
        README said only that the badge was; both are now, and it says so."""
        self.assertTrue(self.REWRITTEN in _prose(README),
                        f"the README no longer says {self.REWRITTEN!r}")
        with tempfile.TemporaryDirectory() as directory:
            coverage = Path(directory) / "coverage.json"
            coverage.write_text('{"status": "measured", "coverage": 0.4}', encoding="utf-8")
            document = json.loads((ROOT / "fixtures" / "veridor.demo.json").read_text())
            document["coverage"] = {"denial_statuses": [401]}
            config = Path(directory) / "veridor.json"
            config.write_text(json.dumps(document), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = main(["coverage", "--config", str(config), "--openapi",
                             str(ROOT / "fixtures" / "openapi.demo.json"),
                             "--coverage", str(coverage)])
            self.assertEqual(code, 2)
            written = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual((written["status"], written["coverage"]), ("not_measured", None))
            self.assertTrue(written["reason"])

    def test_the_passage_says_what_the_block_holds_and_refuses(self) -> None:
        prose = _prose(README)
        # assertTrue, not assertIn: a miss would print the whole README.
        self.assertTrue(self.SHAPE in prose, f"the README no longer says {self.SHAPE!r}")
        self.assertTrue(self.REFUSED in prose, f"the README no longer says {self.REFUSED!r}")
        self.assertFalse("(anything else exits 2)" in prose,
                         "the README still says only the status rule exits 2")

    def test_each_refusal_it_names_is_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            # Control: the declared block is read, so the cases below are
            # refused for their shape and not for the config around them.
            code, stdout, _ = self._coverage(
                {"denial_statuses": [403], "_note": "an annotation"}, directory)
            self.assertEqual(code, 0)
            self.assertIn("Denial statuses in use (declared by config): [403]", stdout)
            for clause, block in self.CASES:
                with self.subTest(clause):
                    code, stdout, stderr = self._coverage(block, directory)
                    self.assertEqual(code, 2, stdout)
                    self.assertIn("boundary coverage was not measured", stderr)
                    self.assertNotIn("Authorization boundary coverage:", stdout)
            _, _, stderr = self._coverage({"Denial_Statuses": [403]}, directory)
            self.assertIn("did you mean 'denial_statuses'", stderr, "a near-miss is named")


class NonGoalsTrafficTest(unittest.TestCase):
    """Someone pointing this at staging with lockout rules reads this section to
    learn what it will send. It said "one request per check per identity, byte
    for byte", and a demo run sends 9 requests for 6 declared probes, every one
    with forced headers."""

    PROMISES = r"(?i)exactly (?:the requests|as written)|byte for byte"

    def test_the_section_admits_what_a_run_adds(self) -> None:
        section = " ".join(_section("Non-goals").split())
        self.assertNotRegex(section, self.PROMISES)
        for named in ("marker_probe", "--no-prove-liveness", "fabricated", "Cache-Control",
                      "Accept-Encoding"):
            with self.subTest(named=named):
                self.assertIn(named, section)

    def test_the_configure_section_does_not_promise_it_either(self) -> None:
        section = " ".join(_section("Run: does the boundary hold, and did it change?").split())
        self.assertNotRegex(section, self.PROMISES)
        self.assertIn("A run also sends requests of its own", section)


class ClaimBoundaryTest(unittest.TestCase):
    """The claim ladder is the product's credibility. It must survive edits.

    Each of these is a distinct claim, and collapsing any two of them is the
    failure mode this tool exists to avoid: coverage does not mean tested,
    tested does not mean it would catch a regression, and none of them means
    the boundary is enforced.
    """

    def test_coverage_is_asserted_and_never_enforced(self) -> None:
        prose = _prose(README)
        self.assertIn("A cross-identity denial is asserted for this operation", prose)
        self.assertIn("a fact about your configuration", prose)
        self.assertIn("That the boundary is enforced", prose)

    def test_a_mutation_score_is_a_different_claim_again(self) -> None:
        self.assertIn("would catch a regression", _prose(README))

    def test_the_two_scores_are_documented_as_multiplying(self) -> None:
        prose = _prose(README)
        self.assertIn("multiply rather than add", prose)
        self.assertIn("Full coverage made of checks that cannot fail is worth", prose)

    def test_veridor_is_documented_as_unable_to_audit_the_policy(self) -> None:
        prose = _prose(README)
        self.assertIn("Veridor consumes a policy statement; it cannot audit one", prose)
        self.assertIn(
            "A wrong declaration and a real vulnerability produce the same finding",
            prose,
        )

    def test_a_candidate_is_documented_as_a_hypothesis(self) -> None:
        self.assertIn("a hypothesis to declare and test", _prose(README))

    def test_blast_radius_counts_operations_and_not_objects(self) -> None:
        prose = _prose(README)
        self.assertIn("counts operations reached, never objects", prose)
        self.assertIn("How many objects those operations expose", prose)

    def test_sequencing_is_documented_as_writing_to_the_target(self) -> None:
        prose = _prose(_section("Run: does the boundary hold, and did it change?"))
        self.assertIn("Veridor a tool that writes to the target", prose)
        self.assertIn("This is for systems you own.", prose)

    def test_every_non_goal_is_kept(self) -> None:
        non_goals = _section("Non-goals")
        for promise in (
            "**No API discovery.**",
            "**No policy invention.**",
            "**No fuzzing and no payloads.**",
            "**No injection classes.**",
            "**No authentication-strength testing.**",
        ):
            self.assertIn(promise, non_goals, promise)


class EvidenceGradeTableTest(unittest.TestCase):
    """The grade table says what produces each grade, and the engine changed.

    A marker that a credential Veridor fabricated also got back is not unique
    to its owner. Beside a status that differed from the declaration it grades
    AUTHZ-001 `suspected` on the status alone; beside a status that matched,
    nothing else in the probe suggests a leak and it is ORACLE-001
    inconclusive (`n/a`). The table said the `confirmed` grade "caps at
    `suspected`" in both cases and defined `suspected` as a status mismatch
    with no marker observed, which described neither.
    """

    @staticmethod
    def _row(grade: str) -> str:
        match = re.search(rf"^\| `{re.escape(grade)}` \|(.*)$", README, re.MULTILINE)
        if match is None:  # pragma: no cover - failure path
            raise AssertionError(f"README grade table has no `{grade}` row")
        return _prose(match.group(1))

    def test_confirmed_does_not_claim_one_cap_for_both_cases(self) -> None:
        row = self._row("confirmed")
        self.assertIn("fabricated", row)
        self.assertNotIn("caps at suspected", row)

    def test_suspected_covers_a_marker_that_is_not_unique(self) -> None:
        row = self._row("suspected")
        self.assertIn("differed from the declared one", row)
        self.assertIn("fabricated", row)
        self.assertIn("not unique", row)

    def test_n_a_covers_a_marker_that_is_not_unique_beside_the_declared_status(
        self,
    ) -> None:
        row = self._row("n/a")
        self.assertIn("VERIDOR-ORACLE-001", row)
        self.assertIn("matched the declaration", row)
        self.assertIn("fabricated", row)


class LivenessReasonDocumentationTest(unittest.TestCase):
    """docs/report-formats.md's `liveness_unproven` row.

    It said exit 3 happens when "a denial was also received by a fabricated
    credential". It now also fires when none was sent: a
    write, which never carries one, or a configuration with no header to shape
    one on. And it never fires for an identity that presents no credential.
    """

    def test_the_row_covers_every_cause_and_names_the_credential_condition(
        self,
    ) -> None:
        text = (ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8")
        match = re.search(r"^\| `liveness_unproven` \|(.*)$", text, re.MULTILINE)
        self.assertIsNotNone(match, "report-formats.md has no liveness_unproven row")
        row = _prose(match.group(1))
        self.assertIn("presents a credential", row)
        self.assertIn("received the same denial", row)
        self.assertIn("a write", row)
        # A credential header: a benign one no longer shapes a sham.
        self.assertIn("no identity declares a credential header", row)
        self.assertIn("proven live elsewhere", row)

    def test_the_row_states_every_precondition_core_applies_to_both_causes(
        self,
    ) -> None:
        """`_liveness_unproven` returns False unless some identity in the
        check was served, and returns False when the identity is proven live,
        before it splits on whether a sham was sent. The row left the first
        precondition out and attached the second to the no-sham cause only,
        which reads as if a same-denial sham fires even for a live identity."""
        text = (ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8")
        match = re.search(r"^\| `liveness_unproven` \|(.*)$", text, re.MULTILINE)
        self.assertIsNotNone(match, "report-formats.md has no liveness_unproven row")
        row = _prose(match.group(1))
        self.assertIn("in a check where some identity was served", row)
        live = row.find("not proven live elsewhere")
        self.assertNotEqual(live, -1, row)
        for cause in ("received the same denial", "none was sent to compare with"):
            with self.subTest(cause=cause):
                self.assertIn(cause, row)
                self.assertLess(live, row.index(cause),
                                "the liveness condition must govern both causes")

    def test_the_chart_prose_covers_a_denial_no_sham_was_sent_against(self) -> None:
        """The chart README's "Exit 3" paragraph and the values.yaml comment on
        `gate.requireComplete` still defined the reason as "a made-up token got
        the same answer" after the row above was widened. A denial on a write,
        or in a configuration with no header to shape a sham on, exits 3 with
        no made-up token sent at all, and an adopter reading either passage
        could not tell why."""
        chart = ROOT / "deploy" / "helm" / "veridor-gate"
        readme = (chart / "README.md").read_text(encoding="utf-8")
        match = re.search(r"^\*\*Exit 3\.\*\*(.*?)(?=\n\n)", readme, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, "the chart README has no **Exit 3.** paragraph")
        values = (chart / "values.yaml").read_text(encoding="utf-8")
        comment = re.search(r"((?:^  #.*\n)+)  requireComplete:", values, re.MULTILINE)
        self.assertIsNotNone(comment, "values.yaml has no comment above gate.requireComplete")
        argocd = (ROOT / "deploy" / "argocd" / "README.md").read_text(encoding="utf-8")
        step = re.search(r"^4\. Veridor's exit code decides the Job:(.*?)(?=\n5\. )", argocd, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(step, "the Argo CD README has no step 4 on the exit code")
        for name, passage in (
            ("chart README", match.group(1)),
            ("Argo CD README", step.group(1)),
            ("values.yaml", re.sub(r"^\s*#", "", comment.group(1), flags=re.MULTILINE)),
        ):
            prose = _prose(passage)
            with self.subTest(document=name):
                self.assertIn("liveness_unproven", prose)
                self.assertIn("fabricated credential", prose)
                self.assertIn("a write", prose)
                # A credential header: a benign one no longer shapes a sham.
                self.assertIn("declares a credential header", prose)
                self.assertIn("marker_probe", prose)


class LivenessPreconditionProseTest(unittest.TestCase):
    """Every passage that describes an unproven denial states when it fires.

    The README, the Helm chart README and values.yaml, and the Argo CD README
    said a denial on a write "counts as unproven unless the identity is
    proven live some other way". `_liveness_unproven` first requires that
    some identity was served in the same check, so the usual write check --
    attacker [403] and anonymous [403] on a DELETE -- exited 0 under
    --require-complete with nothing unproven, right after the run's own
    banner promised otherwise. Only docs/report-formats.md stated the
    condition. Each passage must also say the fabricated credential rides
    GET, HEAD and OPTIONS only, and only when a credential header exists to
    shape it on.
    """

    @staticmethod
    def _passages() -> dict[str, str]:
        start = README.index("- **A denial that proves nothing says so.**")
        readme = README[start:README.index("\n- Either way the message prints", start)]
        report = (ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8")
        row = re.search(r"^\| `liveness_unproven` \|(.*)$", report, re.MULTILINE).group(1)
        chart = ROOT / "deploy" / "helm" / "veridor-gate"
        exit3 = re.search(r"^\*\*Exit 3\.\*\*(.*?)(?=\n\n)",
                          (chart / "README.md").read_text(encoding="utf-8"),
                          re.MULTILINE | re.DOTALL).group(1)
        values = re.search(r"((?:^  #.*\n)+)  requireComplete:",
                           (chart / "values.yaml").read_text(encoding="utf-8"),
                           re.MULTILINE).group(1)
        argocd = re.search(r"^4\. Veridor's exit code decides the Job:(.*?)(?=\n5\. )",
                           (ROOT / "deploy" / "argocd" / "README.md").read_text(
                               encoding="utf-8"),
                           re.MULTILINE | re.DOTALL).group(1)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        bullet_start = changelog.index("  - **A denial on a write")
        bullet = changelog[bullet_start:changelog.index("\n  - **", bullet_start + 4)]
        return {
            "README": readme,
            "report-formats.md": row,
            "chart README": exit3,
            "values.yaml": re.sub(r"^\s*#", "", values, flags=re.MULTILINE),
            "Argo CD README": argocd,
            "CHANGELOG": bullet,
        }

    def test_each_passage_states_the_served_identity_precondition(self) -> None:
        for name, passage in self._passages().items():
            prose = _prose(passage)
            with self.subTest(document=name):
                self.assertIn("presents a credential", prose)
                self.assertIn("some identity was served", prose)
                self.assertRegex(prose, r"prove[nds]? (the identity |it )?live")
                self.assertIn("credential header", prose)
                self.assertRegex(prose, r"GET, HEAD (and|or) OPTIONS")

    def test_the_readme_names_every_cause_and_sequences(self) -> None:
        prose = _prose(self._passages()["README"])
        for phrase in ("sequence", "failed", "neither a refusal nor a success",
                       "requests_not_probed", "exits 3"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, prose)


class RequireCompleteIntegrationDocsTest(unittest.TestCase):
    """The GitHub Action and the GitLab component name unproven denials.

    Both turn require-complete on by default, and since write-method denials
    count as unproven, a config that exited 0 can exit 3 under them. Their
    require-complete descriptions said only an unanswered probe exits 3, and
    their exit-3 messages listed "an unanswered probe, nothing answered, an
    unauthenticated identity, an unclean teardown" -- none of which happened.
    The README's input tables and exit-code table repeated the omission.
    """

    @staticmethod
    def _passages() -> dict[str, str]:
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        start = action.index("  require-complete:\n")
        template = (ROOT / "templates" / "veridor.yml").read_text(encoding="utf-8")
        tstart = template.index("    require_complete:\n")
        return {
            "action.yml require-complete": action[start:action.index("    required:", start)],
            "action.yml exit 3": next(
                line for line in action.splitlines()
                if "Veridor exited 3: the security gate passed" in line),
            "veridor.yml require_complete": template[
                tstart:template.index("      type:", tstart)],
            "veridor.yml exit 3": next(
                line for line in template.splitlines()
                if "INCOMPLETE, failing the job" in line),
            "README Action inputs": next(
                line for line in README.splitlines()
                if line.startswith("| `require-complete` |")),
            "README GitLab inputs": next(
                line for line in README.splitlines()
                if line.startswith("| `require_complete` |")),
            "README exit codes": next(
                line for line in README.splitlines()
                if line.startswith("| `3` | The security gate passed")),
        }

    def test_each_names_an_unproven_denial(self) -> None:
        for name, passage in self._passages().items():
            with self.subTest(passage=name):
                self.assertIn("unproven", passage)
                self.assertIn("unanswered", passage)


class UnprovenCauseProseTest(unittest.TestCase):
    """Every integration passage on unproven denials gives every cause and
    precondition, as docs/report-formats.md and the Helm README do.

    The GitLab require_complete description and the README's Action and
    GitLab rows said "a denial-only expectation nothing in the run ties to a
    live credential" with no precondition, and the template's example (an
    expired token refused on a write) is a case the code does not judge when
    nobody was served in that check. action.yml and values.yaml gave only
    "drew the same denial, or none was sent", leaving out a fabricated
    request that failed and an answer that is neither a refusal nor a
    success; values.yaml and the Argo CD README said "in a check" and never
    mentioned sequence assert steps. RequireCompleteIntegrationDocsTest only
    asserted the word "unproven", so none of that could fail a test.
    """

    #: (what, pattern) every passage must carry.
    REQUIRED = (
        ("cause: the same denial", r"same denial"),
        ("cause: none was sent", r"none was sent"),
        ("cause: the fabricated request failed", r"\bfailed\b"),
        ("cause: an uninformative answer", r"neither a refusal nor a success"),
        ("precondition: presents a credential", r"presents a credential"),
        ("precondition: someone was served", r"some identity was served"),
        ("precondition: sequence assert steps", r"sequence assert step"),
        ("precondition: not proven live", r"prove[nds]? (the identity |it )?live"),
        ("remedy: marker_probe", r"marker_probe"),
    )

    @staticmethod
    def _passages() -> dict[str, str]:
        template = (ROOT / "templates" / "veridor.yml").read_text(encoding="utf-8")
        tstart = template.index("    require_complete:\n")
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        astart = action.index("  require-complete:\n")
        chart = ROOT / "deploy" / "helm" / "veridor-gate"
        values = re.search(r"((?:^  #.*\n)+)  requireComplete:",
                           (chart / "values.yaml").read_text(encoding="utf-8"),
                           re.MULTILINE).group(1)
        report = (ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8")
        return {
            "veridor.yml require_complete": template[
                tstart:template.index("      type:", tstart)],
            "README Action inputs": next(
                line for line in README.splitlines()
                if line.startswith("| `require-complete` |")),
            "README GitLab inputs": next(
                line for line in README.splitlines()
                if line.startswith("| `require_complete` |")),
            "action.yml require-complete": action[
                astart:action.index("    required:", astart)],
            "values.yaml": re.sub(r"^\s*#", "", values, flags=re.MULTILINE),
            "Argo CD README": re.search(
                r"^4\. Veridor's exit code decides the Job:(.*?)(?=\n5\. )",
                (ROOT / "deploy" / "argocd" / "README.md").read_text(encoding="utf-8"),
                re.MULTILINE | re.DOTALL).group(1),
            # The two that already did: kept here so they stay that way.
            "report-formats.md": re.search(
                r"^\| `liveness_unproven` \|(.*)$", report, re.MULTILINE).group(1),
            "chart README": re.search(
                r"^\*\*Exit 3\.\*\*(.*?)(?=\n\n)",
                (chart / "README.md").read_text(encoding="utf-8"),
                re.MULTILINE | re.DOTALL).group(1),
        }

    def test_each_passage_gives_every_cause_and_precondition(self) -> None:
        for name, passage in self._passages().items():
            prose = _prose(passage.replace('\\"', '"'))
            for what, pattern in self.REQUIRED:
                with self.subTest(passage=name, required=what):
                    self.assertRegex(prose, pattern)

    #: A remedy that offers a check where the identity is served.
    SERVED_REMEDY = re.compile(
        r"check (?:or a step )?where (?:that identity|the identity|it) is served"
        r"[^.]*", re.IGNORECASE)

    def test_a_served_check_remedy_names_the_refusal_it_needs(self) -> None:
        """The chart README offered "or a check where that identity is
        served" on its own. A 2xx proves a credential live only where the
        fabricated credential or an identity with no credential is refused on
        the same request; a check on a public route served the identity and
        proved nothing, and an adopter who followed the remedy still exited
        3. Every passage that offers that remedy must carry the refusal."""
        offered = 0
        for name, passage in self._passages().items():
            prose = _prose(passage.replace('\\"', '"'))
            for match in self.SERVED_REMEDY.finditer(prose):
                offered += 1
                with self.subTest(passage=name, remedy=match.group(0)):
                    self.assertRegex(match.group(0), r"refused on the same request")
        # The chart README offers it: a passage list that lost it would make
        # this test pass on nothing.
        self.assertGreater(offered, 0)


class LivenessHelpTest(unittest.TestCase):
    """`run --no-prove-liveness` and `--require-complete` help, and the
    capsule-verify sentence, state the liveness rule as the code applies it.

    The help still promised one fabricated-credential probe "for each request
    whose declaration accepts only denial statuses". After the merge that
    probe is sent only with GET, HEAD or OPTIONS and only when an identity
    declares a credential header to shape it on, and the other requests are
    judged without one. `--require-complete` said it exits 3 for an
    unanswered probe, though an unproven denial exits 3 under it too. The
    README said capsule verify's NOT_REPRODUCED needs only "no denial a
    fabricated credential drew as well", though any unproven entry for the
    check blocks it, including one where no fabricated credential was sent.
    """

    @staticmethod
    def _run_help() -> dict[str, str]:
        parser = _parser()
        sub = next(action for action in parser._actions
                   if isinstance(action, argparse._SubParsersAction))
        return {
            option: _prose(action.help or "")
            for action in sub.choices["run"]._actions
            for option in action.option_strings
        }

    def test_no_prove_liveness_help_states_where_the_probe_goes(self) -> None:
        text = self._run_help()["--no-prove-liveness"]
        for phrase in (
            "for each GET, HEAD or OPTIONS request",
            "credential header",
            "none is sent with POST, PUT, PATCH or DELETE, inside a sequence",
            "some identity was served",
            "nothing else in the run proved live",
            "liveness.unproven",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        self.assertNotIn("for each request whose declaration", text)

    def test_require_complete_help_names_unproven_denials(self) -> None:
        text = self._run_help()["--require-complete"]
        self.assertIn("unanswered", text)
        self.assertIn("unproven", text)
        self.assertIn("liveness.unproven", text)

    def test_capsule_verify_names_every_unproven_cause(self) -> None:
        start = README.index("`NOT_REPRODUCED` needs a measurement behind it")
        passage = _prose(README[start:README.index("\n\n", start)])
        self.assertIn("liveness.unproven", passage)
        self.assertIn("no fabricated credential was sent", passage)
        self.assertIn("neither a refusal nor a success", passage)

    def test_capsule_verify_states_the_write_rule(self) -> None:
        """A write capsule is NOT_REPRODUCED only with a marker_probe.

        The README gave NOT_REPRODUCED's liveness condition in terms of a
        fabricated credential drawing the same denial, which read literally is
        met on a DELETE, where none is ever sent -- yet such a capsule is
        INCONCLUSIVE unless the denied identity's marker_probe proves it live.
        """
        start = README.index("`NOT_REPRODUCED` needs a measurement behind it")
        passage = _prose(README[start:README.index("\n\n", start)])
        for phrase in ("POST, PUT, PATCH or DELETE capsule", "marker_probe",
                       "INCONCLUSIVE", "--no-prove-liveness"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, passage)


class TestTierDocumentationTest(unittest.TestCase):
    """Both tiers must be documented, or one of them stops being run."""

    def test_both_tier_commands_are_documented(self) -> None:
        for command in (
            "scripts/run_tests.py --tier fast",
            "scripts/run_tests.py --tier slow",
        ):
            self.assertIn(command, README, command)

    def test_the_documented_tier_commands_name_the_interpreter_version(self) -> None:
        # A bare `python3` is 3.9 on macOS, which cannot import this package.
        # The scripts refuse it now, but the documented command should not walk
        # a contributor into the refusal in the first place.
        for command in (
            "python3.12 scripts/run_tests.py --tier fast",
            "python3.12 scripts/run_tests.py --tier slow",
            "python3.12 scripts/e2e_validation.py",
        ):
            self.assertIn(command, README, command)
        self.assertNotIn("python3 scripts/run_tests.py", README)
        self.assertNotIn("python3 scripts/e2e_validation.py", README)

    def test_the_tier_boundary_is_documented_as_enforced(self) -> None:
        prose = _prose(README)
        self.assertIn("The boundary is enforced, not conventional.", prose)
        self.assertIn("no fast test may spend more than two seconds of CPU time and sleep", prose)

    def test_the_unchanged_whole_suite_command_still_works_and_is_documented(
        self,
    ) -> None:
        self.assertIn("python3.12 -m unittest discover -s tests", README)


class InterpreterGuardTest(unittest.TestCase):
    """The two scripts a new user runs must refuse an interpreter they need.

    Both are invoked from the README, and both used to fail unhelpfully under
    the macOS system ``python3`` (3.9): ``run_tests.py`` collected the handful
    of modules that imported cleanly and reported ``Ran 34 tests ... FAILED
    (failures=3, errors=14)``, and ``e2e_validation.py`` raised an ImportError
    naming ``datetime.UTC`` from inside ``veridor/cli.py``. Both read as a
    broken repository rather than a wrong interpreter.
    """

    SCRIPTS = ("scripts/run_tests.py", "scripts/e2e_validation.py")

    def _minimum(self, script: str) -> tuple[int, int]:
        source = (ROOT / script).read_text(encoding="utf-8")
        match = re.search(r"^MINIMUM_PYTHON = \((\d+), (\d+)\)$", source, re.M)
        self.assertIsNotNone(match, f"{script} declares no MINIMUM_PYTHON")
        assert match is not None
        return (int(match.group(1)), int(match.group(2)))

    def test_each_script_guards_its_interpreter_before_importing_the_package(
        self,
    ) -> None:
        for script in self.SCRIPTS:
            with self.subTest(script=script):
                source = (ROOT / script).read_text(encoding="utf-8")
                guard = source.index("if sys.version_info < MINIMUM_PYTHON:")
                package = min(
                    (
                        source.index(needle)
                        for needle in ("from veridor", "from tiers")
                        if needle in source
                    ),
                    default=len(source),
                )
                self.assertLess(
                    guard,
                    package,
                    f"{script} imports the package before checking the version",
                )
                self.assertIn("Nothing was run.", source)
                self.assertIn("python3.12", source)

    def test_the_guard_agrees_with_requires_python(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'requires-python = ">=(\d+)\.(\d+)"', pyproject)
        self.assertIsNotNone(match)
        assert match is not None
        declared = (int(match.group(1)), int(match.group(2)))
        for script in self.SCRIPTS:
            with self.subTest(script=script):
                self.assertEqual(self._minimum(script), declared)


class BadgeDocumentationTest(unittest.TestCase):
    def test_the_readme_quotes_the_label_the_code_emits(self) -> None:
        self.assertIn(f"`{BADGE_LABEL}`", README)

    def test_the_readme_no_longer_quotes_the_old_enforcement_wording(self) -> None:
        self.assertNotIn("authz boundary tested", README)


class WorkedExampleTest(unittest.TestCase):
    """Every worked example states its own prerequisites.

    Four separate first-run failures came from this file omitting one line:
    the `mutate` example's fixture server, the `map` example's target state,
    the install section's virtual environment, and the quickstart's behaviour
    on a busy port.
    """

    @staticmethod
    def _sample_under(command: str) -> str:
        """The unlabelled output block right after ```bash\\ncommand\\n```."""
        pattern = rf"^```bash\n{re.escape(command)}\n```\n\n```\n(.*?)^```$"
        found = re.search(pattern, README, re.M | re.S)
        assert found is not None, f"no output block under {command!r}"
        return found.group(1)

    @staticmethod
    def _printed(*argv: str) -> str:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        assert code == 0, err.getvalue()
        return err.getvalue() + out.getvalue()

    def test_the_init_sample_is_what_init_prints(self) -> None:
        """Not marked abridged, so it has to be whole. It had lost the first
        line's suffix and the closing paragraph about `init --for drift`."""
        command = "veridor init --openapi openapi.json --output veridor.json"
        spec = (ROOT / "fixtures" / "openapi.demo.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            Path("openapi.json").write_text(spec, encoding="utf-8")
            printed = self._printed(*shlex.split(command)[1:])
        self.assertEqual(printed.strip(), self._sample_under(command).strip())

    def test_the_coverage_sample_is_what_coverage_prints(self) -> None:
        command = "veridor coverage --config fixtures/veridor.demo.json --openapi fixtures/openapi.demo.json"
        with contextlib.chdir(ROOT):
            printed = self._printed(*shlex.split(command)[1:])
        self.assertEqual(printed.strip(), self._sample_under(command).strip())

    def test_the_init_example_names_the_file_its_own_command_writes(self) -> None:
        # REGRESSION. The command said `--output veridor.json`; the output
        # block under it said `starter.json`, and so did its step 3. A reader
        # copying both pointed `run` at a file that does not exist.
        section = _section("Quickstart: your first 60 seconds")
        self.assertIn("veridor init --openapi openapi.json --output veridor.json", section)
        self.assertNotIn("starter.json", README)

    def test_the_mutate_example_names_the_target_it_needs(self) -> None:
        # REGRESSION. fixtures/veridor.mutation-demo.json points at port 8766,
        # which only fixtures/veridor_mutation_fixture.py listens on, and the
        # README mentioned neither. The documented command scored `n/a`.
        section = _section("Mutate: would my suite catch a regression?")
        self.assertIn("fixtures/veridor_mutation_fixture.py", section)
        self.assertIn("8766", section)
        self.assertLess(
            section.index("veridor_mutation_fixture.py"),
            section.index("veridor mutate --config"),
            "the fixture must be started before the command that needs it",
        )

    def test_the_map_example_states_which_target_state_it_assumes(self) -> None:
        # REGRESSION. The quickstart tells the reader to restart the demo
        # without --vulnerable; the map example's output was captured with it.
        section = _prose(_section("Map: what would a compromise reach?"))
        self.assertIn("vulnerable", section)
        self.assertIn("0 candidates.", section)

    def test_the_install_section_explains_the_virtual_environment(self) -> None:
        # REGRESSION. `python3 -m pip install .` is refused by PEP 668 on
        # Homebrew and Debian Python, and macOS's bare python3 is 3.9.
        section = _prose(_section("Install"))
        self.assertIn("venv", section)
        self.assertIn("externally-managed-environment", section)
        self.assertIn("3.9", section)

    def test_the_quickstart_documents_the_busy_port(self) -> None:
        # REGRESSION. The demo server was backgrounded with `&`; a bind failure
        # scrolled past and the next command probed an unrelated process.
        section = _prose(_section("Quickstart: your first 60 seconds"))
        self.assertIn("cannot listen on", section)
        self.assertIn("--base-url http://127.0.0.1:8799", section)
        self.assertIn("Target:", section)


@slow("stands up the mutation demo fixture and runs `veridor mutate` against it")
class MutateSampleTest(unittest.TestCase):
    """The mutate section's sample output is what the demo prints today.

    REGRESSION. The README calls these numbers frozen, and nothing read them.
    After `limited` stopped counting notes LIMITS ON THE EVIDENCE does not
    print, the demo said ``0.86 of 14 generated + limited (1 could not be
    evaluated)`` while the README still showed ``0.80 of 15 ... (2 ...)``.

    The block is abridged, so every line it shows must appear in a fresh run,
    verbatim and in the same order; lines it leaves out are allowed.
    """

    def _sample(self) -> list[str]:
        section = _section("Mutate: would my suite catch a regression?")
        match = re.search(r"^Abridged\b.*?^```\n(.*?)^```", section, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, "the mutate section lost its sample output block")
        lines = [line.rstrip() for line in match.group(1).splitlines() if line.strip()]
        self.assertTrue(any(line.startswith("Mutation score:") for line in lines))
        return lines

    def _fresh_run(self) -> str:
        sys.path.insert(0, str(ROOT / "fixtures"))
        import loopback
        from veridor_mutation_fixture import create_server

        server = create_server("127.0.0.1", 0)
        thread = loopback.start(server)
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main([
                "mutate",
                "--config", str(ROOT / "fixtures" / "veridor.mutation-demo.json"),
                "--base-url", f"http://127.0.0.1:{server.server_port}",
                "--output-dir", holder.name,
            ])
        self.assertEqual(code, 1, "the demo has exactly one survivor and exits 1")
        return out.getvalue()

    def test_every_sample_line_is_printed_in_order_by_a_fresh_run(self) -> None:
        sample = self._sample()
        printed = [line.rstrip() for line in self._fresh_run().splitlines()]
        position = 0
        for line in sample:
            found = line in printed[position:]
            self.assertTrue(
                found,
                f"README mutate sample line not printed (in order) by the demo:\n"
                f"  {line!r}\nfresh run:\n" + "\n".join(printed),
            )
            position = printed.index(line, position) + 1


@slow("stands up the demo target twice and runs `veridor map` against it")
class DriftSampleTest(unittest.TestCase):
    """The drift section's sample is what the demo prints.

    REGRESSION. It said "baseline 5 cells" for a plan of 20, named identities
    the configuration above it does not have, and left out the blind-cell
    warning the README says every such report carries. Every line it shows
    must appear, in order, in a fresh run of the commands it names."""

    def _sample(self) -> list[str]:
        section = _section("Map: what would a compromise reach?")
        match = re.search(r"^```\n(Access-matrix drift.*?)^```", section, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, "the drift section lost its sample output block")
        return [line.rstrip() for line in match.group(1).splitlines() if line.strip()]

    def _map(self, vulnerable: bool, *argv: str) -> str:
        sys.path.insert(0, str(ROOT / "scripts"))
        import loopback
        from demo_server import create_server

        server = create_server("127.0.0.1", 0, vulnerable=vulnerable)
        thread = loopback.start(server)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = main(["map", "--config", str(ROOT / "fixtures" / "veridor.map-demo.json"),
                             "--openapi", str(ROOT / "fixtures" / "openapi.demo.json"),
                             "--base-url", f"http://127.0.0.1:{server.server_port}", *argv])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
        self.assertEqual(code, 0)
        return out.getvalue()

    def test_every_sample_line_is_printed_in_order_by_a_fresh_run(self) -> None:
        sample = self._sample()
        self.assertTrue(any("WERE NEVER PROBED" in line for line in sample), "the blind-cell warning")
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            self._map(False, "--matrix", "veridor/baseline-matrix.json")
            printed = [line.rstrip() for line in
                       self._map(True, "--baseline", "veridor/baseline-matrix.json").splitlines()]
        position = 0
        for line in sample:
            self.assertIn(line, printed[position:],
                          f"README drift sample line not printed (in order):\n  {line!r}\nfresh run:\n"
                          + "\n".join(printed))
            position = printed.index(line, position) + 1


class MapDemoCommentTest(unittest.TestCase):
    """fixtures/veridor.map-demo.json describes its checks as they are.

    Its ``_comment`` said the checks were "the SAME two checks
    veridor.demo.json declares". The ids and operations matched, but
    audit-admin-role asserted anonymous -> 401 where veridor.demo.json asserts
    other_tenant -> 403, so the map example said nothing about other_tenant on
    /api/admin/audit and nothing compared the two files.
    """

    def test_every_check_that_differs_from_the_demo_is_named_in_the_comment(self) -> None:
        def checks(name: str) -> dict:
            document = json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))
            return {check["id"]: check for check in document["checks"]}, document

        demo, _ = checks("veridor.demo.json")
        mapped, document = checks("veridor.map-demo.json")
        comment = " ".join(document["_comment"])
        self.assertEqual(sorted(mapped), sorted(demo))
        differing = []
        for check_id in sorted(mapped):
            self.assertEqual(mapped[check_id]["request"], demo[check_id]["request"])
            ours, theirs = mapped[check_id]["expect"], demo[check_id]["expect"]
            for identity in sorted(set(ours) | set(theirs)):
                if ours.get(identity) != theirs.get(identity):
                    differing.append((check_id, identity))
        # control: the comparison sees the difference that is really there
        self.assertIn(("audit-admin-role", "other_tenant"), differing)
        self.assertNotIn("SAME two checks", comment)
        for check_id, identity in differing:
            with self.subTest(check=check_id, identity=identity):
                self.assertIn(f"`{check_id}`", comment)
                self.assertIn(f"`{identity}`", comment)


@slow("shells out to git to read the index")
class CommittedFilesTest(unittest.TestCase):
    """Existing on this disk is not the same as existing in a clone.

    REGRESSION. ``fixtures/veridor.map-demo.json`` and ``scripts/run_tests.py``
    were untracked, so the ``map`` worked example and the whole "Working on
    Veridor itself" section were unrunnable for anyone who obtained the
    repository the only way a stranger can: by cloning it.
    ``test_every_fixture_the_readme_names_exists`` above could not see this,
    because it asks the working tree.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # This class is the one thing in the suite that needs the index rather
        # than the working tree, so it is also the one thing that cannot run
        # without one. A source zip from GitHub's "Download ZIP" or a vendored
        # copy has every file and no ``.git``, and the README asks the reader
        # to run the whole suite: raising CalledProcessError there reports a
        # green product as a failing one. Skip instead, and say why. (Not an
        # sdist: it carries no tests at all -- MANIFEST.in prunes them.)
        try:
            listed = subprocess.run(
                ["git", "-C", str(ROOT), "ls-files", "-z"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise unittest.SkipTest(
                "no git index to read at "
                f"{ROOT} ({exc}); this checkout is not a clone, so whether a "
                "path is committed cannot be established here. Every other "
                "test in this file ran."
            ) from exc
        cls.tracked = {name for name in listed.stdout.split("\0") if name}

    def test_the_index_was_read(self) -> None:
        """A guard on the guard: an empty set would pass everything below."""
        self.assertIn("README.md", self.tracked)

    def test_every_repository_path_the_readme_names_is_tracked(self) -> None:
        """Present on this disk and named by the README means: committed.

        A path that does not exist here is an illustration of the reader's own
        tree -- ``./scripts/mutate.sh`` in the tier-2 hooks example is theirs,
        not ours -- and is not this test's business. A path that DOES exist and
        is not in the index is the defect: it works for whoever wrote it and
        for nobody who clones.
        """
        named = {
            relative
            for relative in re.findall(
                r"((?:fixtures|scripts|tests)/[\w.\-]+\.\w+)", README
            )
            if (ROOT / relative).exists()
        }
        self.assertGreaterEqual(len(named), 6)
        for relative in sorted(named):
            with self.subTest(path=relative):
                self.assertIn(relative, self.tracked, f"{relative} is not committed")

    def test_the_test_helpers_the_readme_names_are_tracked(self) -> None:
        for relative in ("tests/tiers.py", "tests/test_tiers.py"):
            with self.subTest(path=relative):
                self.assertIn(relative, self.tracked)


class TargetAcknowledgementDocumentationTest(unittest.TestCase):
    """Which `map` targets need --acknowledge-target, stated as the code decides it.

    README's safety posture and SECURITY.md said every non-loopback target needs
    the acknowledgement, and SECURITY.md called probing a non-loopback host
    without it a vulnerability. matrix.classify_target waives it, deliberately
    and pinned by test_private_needs_no_acknowledgement, for every address that
    is not globally routable -- RFC 1918, CGNAT, ULA, link-local including
    169.254.169.254, the documentation ranges -- so the docs described a
    stricter product than ships. Checked against classify_target itself, so the
    named ranges cannot drift from the rule either.
    """

    SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    @staticmethod
    def _passage(text: str, start: str) -> str:
        if start not in text:
            raise AssertionError(f"no passage starting {start!r}")
        return _prose(text.split(start, 1)[1].split("\n- **", 1)[0])

    def test_no_doc_says_every_non_loopback_target_needs_it(self) -> None:
        for name, text in (("README.md", README), ("SECURITY.md", self.SECURITY)):
            with self.subTest(document=name):
                self.assertNotRegex(_prose(text), r"non-loopback (target|host)")

    def test_the_waived_ranges_are_named_and_the_code_waives_them(self) -> None:
        from veridor.matrix import classify_target  # noqa: PLC0415
        import ipaddress  # noqa: PLC0415

        # Control: the classifier can say "public", so a "private" below is
        # an answer and not a default.
        self.assertEqual(classify_target("8.8.8.8"), "public")
        self.assertEqual(classify_target("staging.example.com"), "public")
        readme = self._passage(README, "**A public target must be typed out.**")
        security = self._passage(self.SECURITY, "**`map` sends live requests**")
        for name, passage in (("README.md", readme), ("SECURITY.md", security)):
            with self.subTest(document=name):
                self.assertIn("169.254.169.254", passage)
                self.assertEqual(classify_target("169.254.169.254"), "private")
                for word in ("link-local", "CGNAT", "hostname"):
                    self.assertIn(word, passage)
        networks = re.findall(r"\b([0-9a-f.:]+/\d+)\b", readme)
        self.assertGreaterEqual(len(networks), 6, networks)
        for network in networks:
            with self.subTest(network=network):
                host = str(next(ipaddress.ip_network(network).hosts()))
                self.assertEqual(classify_target(host), "private")


class TierTableTest(unittest.TestCase):
    """The tier tables are claims about this repository, so they are checked.

    They are hand-maintained in two documents and have gone stale three times
    in three days -- 1,058 when the suite held 1,066, then 1,066 when it held
    1,115 -- because a number nobody derives is a number nobody checks. The
    counts below come from the same discovery the runner uses, so the table
    cannot drift from the suite again.

    Wall-clock timings are deliberately NOT asserted: they are a property of
    whichever laptop ran them, and a test that fails on a slow CI box teaches
    people to delete the test. Only the counts are contractual.
    """

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        import unittest as ut

        from tiers import ALL, FAST, SLOW, filter_suite, iter_tests

        discovered = ut.TestLoader().discover(
            str(ROOT / "tests"), top_level_dir=str(ROOT / "tests")
        )
        cls.counts = {
            tier: len(list(iter_tests(filter_suite(discovered, tier))))
            for tier in (FAST, SLOW, ALL)
        }
        cls.fast, cls.slow, cls.all = (
            cls.counts[FAST],
            cls.counts[SLOW],
            cls.counts[ALL],
        )

    def test_the_two_tiers_still_partition_the_suite(self) -> None:
        self.assertEqual(
            self.fast + self.slow,
            self.all,
            "a test is in both tiers or in neither",
        )

    def _numbers_in(self, text: str, label: str) -> set[int]:
        """Every integer on a table row naming this tier, commas stripped."""
        found: set[int] = set()
        for line in text.splitlines():
            if not line.startswith("|") or label not in line:
                continue
            for cell in line.split("|"):
                token = cell.strip().replace(",", "").replace("**", "")
                if token.isdigit():
                    found.add(int(token))
        return found

    @staticmethod
    def _documents() -> list[tuple[str, str]]:
        """The documents the suite can rely on. Only tracked ones: a file a fresh
        clone does not have would make the published suite fail on the one thing
        a new contributor runs first."""
        return [("README.md", README)]

    def test_present_documents_carry_the_real_counts(self) -> None:
        for name, text in self._documents():
            for label, expected in (
                ("fast", self.fast),
                ("slow", self.slow),
            ):
                with self.subTest(document=name, tier=label):
                    self.assertIn(
                        expected,
                        self._numbers_in(text, f"`{label}`")
                        or self._numbers_in(text, f"--tier {label}"),
                        f"{name}'s {label}-tier row does not carry {expected:,}. "
                        f"Real counts now: fast {self.fast:,}, slow {self.slow:,}, "
                        f"both {self.all:,}.",
                    )

    def test_present_documents_carry_the_real_total(self) -> None:
        rendered = f"{self.all:,}"
        for name, text in self._documents():
            with self.subTest(document=name):
                self.assertIn(
                    rendered,
                    text,
                    f"{name} does not mention the real total {rendered}. "
                    f"Update the tier table: fast {self.fast:,}, "
                    f"slow {self.slow:,}, both {self.all:,}.",
                )


class InjectionNotApplicableDocumentationTest(unittest.TestCase):
    """The README sentence about a declared inject field the body cannot carry.

    It read 'not sent and graded `inconclusive`; only a GET, HEAD or OPTIONS
    goes out without it', which is false for teardown: teardown is never graded,
    and the request is now sent rather than refused and the fixture orphaned.
    """

    def test_the_readme_scopes_the_refusal_to_graded_requests(self) -> None:
        prose = _prose(README)
        self.assertIn(
            "A graded request whose body cannot carry the declared field is not sent",
            prose,
        )
        self.assertIn("any teardown request, goes out without it", prose)
        self.assertIn("teardown is cleanup that is never graded", prose)
        # The old claim that ONLY a safe method goes out without the field
        # described teardown wrongly and must be gone.
        self.assertNotIn(
            "only a GET, HEAD or OPTIONS with no body goes out without it", prose
        )

    def test_the_readme_says_the_dropped_field_is_recorded(self) -> None:
        self.assertIn("the run records which field was dropped", _prose(README))

    def test_the_readme_says_the_drop_is_reported_on_the_console(self) -> None:
        """A record only in the raw JSON is one an operator never reads."""
        self.assertIn(
            "reports it on the console alongside the other pass disclosures",
            _prose(README),
        )

    def test_the_readme_says_every_kind_of_request_is_disclosed(self) -> None:
        """The sentence once held for check probes only: a graded sequence step
        went out without the field with nothing recorded or said, and teardown
        and marker-probe drops never reached the console. The README names all
        four, and test_session.InjectionDisclosureEveryRequestTest runs each of
        them through ``veridor run`` to hold the sentence to the product."""
        prose = _prose(README)
        self.assertIn(
            "a check probe, sequence step, teardown entry or marker probe alike",
            prose,
        )
        self.assertIn(
            "the run records which field was dropped on that request's own record",
            prose,
        )

    def test_the_readme_names_the_dashboard_and_sarif_channels(self) -> None:
        """Its siblings reach the dashboard and the SARIF run properties; this
        disclosure reached the console only. test_ui and
        test_session.InjectionDisclosureEveryRequestTest hold the two channels
        the sentence names, and test_reports.PassDisclosureTest the four
        `veridor report` formats, which the sentence left out while they left
        the disclosure out."""
        self.assertIn(
            "lists it under injection_disclosures in the run JSON, on the "
            "dashboard, in runs[0].properties.injectionDisclosures in SARIF, "
            "and in the JUnit, Code Quality, GitLab SAST and Markdown reports",
            _prose(README),
        )
        self.assertIn(
            "on the console and in the dashboard, and in the JUnit, Code "
            "Quality, GitLab SAST and Markdown reports, and records it under "
            "oracle_disclosures",
            _prose(README),
        )



class MapEmptySelectionDocumentationTest(unittest.TestCase):
    """"A grid that measured nothing exits 3" has to hold for every grid that ran.

    Excluded operations became deliberate skips, after which a map whose
    `--ignore`, `matrix.ignore` or `--include` excluded every operation sent
    nothing and exited 0 -- under the README's exit-code paragraph and the
    `--require-complete` help, both of which said an empty grid exits 3. Such
    a selection is now refused at plan time, and both passages say so beside
    the sentence it would otherwise contradict. test_matrix.EmptySelectionTest
    and test_cli_verbs.MapSafetyTest hold the behaviour.

    The first version of these passages said "leaves no operation in the
    specification to probe", and the refusal matched it word for word: it
    counted writes the read-only posture never sends, so `--ignore 'GET /'`
    or an `--include` naming only a DELETE planned 0 requests and exited 0.
    The refusal now fires when the selection leaves nothing the plan probes
    (test_matrix.SelectionThatProbesNothingTest), and the passages name both
    halves, plus the unselected all-writes case that still exits 0.
    """

    def test_the_exit_code_paragraph_lists_the_refusal(self) -> None:
        prose = _prose(_section("Exit codes"))
        self.assertIn(
            "It also exits 3 when its own grid probed cells and measured none "
            "of them",
            prose,
        )
        self.assertIn(
            "A plan with nothing to probe and no selection that emptied it (a "
            "specification of writes alone, under the read-only posture) sends "
            "nothing and exits 0.",
            prose,
        )
        self.assertIn(
            "a --fail-on-drift without a --baseline, an --ignore, matrix.ignore "
            "or --include that leaves nothing to probe, counting writes the "
            "read-only posture skips and routes with no specimen as nothing) or "
            "could not load its inputs",
            prose,
        )

    def test_the_include_and_ignore_bullet_names_every_route_to_an_empty_grid(
        self,
    ) -> None:
        prose = _prose(README)
        self.assertIn(
            "so is an --ignore, matrix.ignore or --include, alone or together, "
            "that leaves nothing to probe: no operation in the specification, "
            "or only writes the read-only posture skips and routes with no "
            "specimen (exit 2).",
            prose,
        )
        self.assertNotIn("leaves no operation in the specification to probe", prose)

    def test_the_require_complete_help_says_such_a_selection_never_runs(self) -> None:
        parser = _parser()
        subcommands = next(
            item for item in parser._subparsers._group_actions
            if isinstance(item, argparse._SubParsersAction)
        ).choices
        help_text = " ".join(
            subcommands["map"]._option_string_actions["--require-complete"].help.split()
        )
        self.assertIn("exits 3 with or without this flag", help_text)
        self.assertIn(
            "An --ignore, matrix.ignore or --include that leaves nothing to "
            "probe -- no operation, or only writes the read-only posture skips "
            "and routes with no specimen -- is refused before the first request "
            "(exit 2)",
            help_text,
        )


class VacuityAcrossProbesAndStepsDocumentationTest(unittest.TestCase):
    """The no-flag exit 3 bullet says what "answered nothing" covers.

    The rule was changed twice in one cycle: first a checks-only run whose
    sessions all failed sent no probe and exited 0, then the fix let declared
    checks decide alone, so a run whose check sessions failed beside a
    sequence the target answered exited 3 saying it established nothing. The
    bullet said neither. Then any answered sequence step counted, so a setup
    served beside an assert that drew a 503 exited 0. test_gate.
    ChecksWithoutProbesVacuityTest holds the behaviour.
    """

    def test_the_bullet_judges_probes_and_steps_together(self) -> None:
        bullet = _prose(
            README.split("**Not one probe answered", 1)[1].split("\n- ", 1)[0]
        )
        self.assertIn(
            "Check probes and sequence assert steps are judged together, and a "
            "probe never sent because its identity's session did not come up "
            "counts as unanswered: the run exits 3 here when neither a check "
            "probe nor an assert step was answered.",
            bullet,
        )
        # Any answered step used to count, so a served setup beside
        # an assert that drew a 503 exited 0 having measured nothing.
        self.assertIn(
            "A setup step grades no declaration, so an answered setup is not an "
            "answer: a sequence whose setup was served and whose assert drew a "
            "503 measured nothing.",
            bullet,
        )
        self.assertIn(
            "Unanswered probes beside an answered assert step are inconclusive "
            "instead, and gate under --require-complete.",
            bullet,
        )
        # A setup-only run, and asserts skipped behind an answered
        # setup, both told an operator whose target had answered to check it.
        self.assertIn(
            "A run that declares no check and no assert step grades nothing "
            "however the target answers, and the message says so rather than "
            "blaming the network; so does one whose asserts were all skipped "
            "because the setup before them was answered with a status it did "
            "not declare.",
            bullet,
        )

    def test_the_reason_table_row_says_the_same(self) -> None:
        """docs/report-formats.md's `nothing_answered` row states the rule too.

        It was rewritten for the judged-together rule and no test read it, so
        it could drift from the README bullet and the gate without a failure.
        Like the bullet, it must say that only assert steps are answers.
        """
        text = (ROOT / "docs" / "report-formats.md").read_text(encoding="utf-8")
        match = re.search(r"^\| `nothing_answered` \| 3 \|(.*)$", text, re.MULTILINE)
        self.assertIsNotNone(match, "report-formats.md has no nothing_answered row")
        row = _prose(match.group(1))
        self.assertIn(
            "not one check probe and not one sequence assert step was answered "
            "(an answered setup step grades no declaration and is not counted), "
            "and nothing about the target was found (any policy but none)",
            row,
        )
        self.assertIn(
            "A run that declares neither a check nor an assert step gets it too, "
            "with count 0 and nothing_graded: true, and every report says it "
            "declares nothing to grade",
            row,
        )


class NothingGradedStatusDocumentationTest(unittest.TestCase):
    """README said a nothing_answered run is `inconclusive` in `status`. A run
    of setup steps only gets that reason with no finding, so its `status` is
    `passed` (core.run_status reads findings alone), and the two read as
    contradicting each other."""

    def test_the_status_section_names_the_passed_case(self) -> None:
        prose = _prose(README)
        # "has no finding, so it is passed" held only when
        # every setup matched; a setup that failed is an inconclusive finding
        # (both measured through `veridor run`).
        self.assertIn(
            "A run that declares nothing to grade (no check, and sequences of "
            "setup steps only) is passed here beside that same reason when every "
            "setup matched, since it has no finding, and the viewer shows it as "
            "passed · gate exit 3; a setup the target did not answer, or answered "
            "with a status it did not declare, is an inconclusive finding.",
            prose,
        )


class PublicRouteProofDocumentationTest(unittest.TestCase):
    """A rewrite of the README's public-route rule had no test reading it
    (reverting that hunk failed only the count tests); and the rule's limit, a
    target that tells a malformed credential from a well-formed expired one,
    was stated nowhere."""

    def test_the_liveness_paragraph_states_the_rule_and_its_limit(self) -> None:
        prose = _prose(README)
        self.assertIn(
            "a target that refuses a bad token even there proves the credential "
            "live, and one that serves the fabricated credential is doing what "
            "the declaration says, so that is not reported as a served sham",
            prose,
        )
        self.assertIn(
            "The fabricated credential is not shaped like your token, so a target "
            "that refuses a malformed credential but serves a well-formed expired "
            "one as anonymous can let its refusal prove an expired token live.",
            prose,
        )


class AnnotationUpgradeDocumentationTest(unittest.TestCase):
    """Plain annotation keys that read as a slip of a real key (root
    ``checksum``, an identity's ``remark``) loaded before the near-miss rules
    were tightened and are refused now. That is an upgrade break, and neither
    the CHANGELOG's Changed list nor the README's description of annotations
    said so; the refusal's own advice (start it with ``_``) is the fix, so
    both must name it, and the keys they name must behave as they say."""

    KEYS = {"checksum": None, "schema": None, "versions": None, "x-version": None,
            "remark": "owner"}

    def test_the_readme_names_the_refused_annotations_and_the_way_out(self) -> None:
        prose = _prose(README)
        self.assertIn(
            "That is refused with exit 2 even when it was meant as a note, so a root "
            "checksum (read as checks), schema ($schema), versions or x-version "
            "(version), or an identity's remark (marker) stops the run. "
            "Start such a key with _ "
            "(_checksum, _remark), as every such refusal says.",
            prose,
        )

    #: Each object the README lists as taking a '_' annotation, and where it
    #: is in tests/test_schema_parity.py's annotated configuration.
    ANNOTATED_IN = {
        "the root": [""],
        "target": ["target"],
        "an identity": ["identities/owner"],
        "its marker_probe": ["identities/owner/marker_probe"],
        "its session": ["identities/owner/session"],
        "a login step": ["identities/owner/session/login/0"],
        "a capture": ["identities/owner/session/capture/csrf",
                      "identities/owner/session/login/0/capture/csrf_login"],
        "an inject entry": ["identities/owner/session/inject/0"],
        "a check": ["checks/0"],
        "a check's request": ["checks/0/request"],
        "an expectation": ["checks/0/expect/attacker"],
        "a sequence": ["sequences/0"],
        "a step": ["sequences/0/steps/0"],
        "a teardown entry": ["sequences/0/teardown/0"],
        "their requests": ["sequences/0/steps/0/request", "sequences/0/teardown/0/request"],
        "their expect blocks": ["sequences/0/steps/0/expect", "sequences/0/teardown/0/expect"],
        "coverage": ["coverage"],
    }
    #: Each object it says takes none.
    NOT_ANNOTATED_IN = {
        "establishes": ["identities", "owner", "session", "establishes"],
        "matrix": ["matrix"],
        "a specimen": ["matrix", "specimens", "/docs/{id}", 0],
    }

    def test_the_readme_lists_exactly_where_an_annotation_is_taken(self) -> None:
        """REGRESSION. The list named the root, an identity, a session, a
        check's expectations, a sequence and its steps, and said "as the
        refusal says" when only the root and identity refusals said it. Each
        place listed now takes `_comment` (loader and schema both), and each
        place it says takes none refuses one."""
        import copy

        from test_schema_parity import (  # noqa: PLC0415
            _MATRIX, _base, coverage_refusal, loader_refusal, schema_errors)

        prose = _prose(README)
        found = re.search(r"A key starting with _ is an annotation, and Veridor never "
                          r"reads it, in each of these: ([^.]+)\. Only ([^.]+) take none\.",
                          prose)
        self.assertIsNotNone(found, "the README no longer lists where '_' is taken")

        def listed(phrase: str) -> set[str]:
            return {re.sub(r"^and ", "", item.strip())
                    for item in re.split(r",\s*|\s+and\s+", phrase)}

        self.assertEqual(listed(found.group(1)), set(self.ANNOTATED_IN))
        self.assertEqual(listed(found.group(2)), set(self.NOT_ANNOTATED_IN))

        def node_at(document: dict, pointer: str) -> dict:
            node = document
            for part in (part for part in pointer.split("/") if part):
                node = node[int(part)] if isinstance(node, list) else node[part]
            return node

        for place, pointers in self.ANNOTATED_IN.items():
            for pointer in pointers:
                with self.subTest(place=place, pointer=pointer):
                    document = _base()
                    document["coverage"] = {"denial_statuses": [403]}
                    node_at(document, pointer)["_remark"] = "a note"
                    self.assertIsNone(loader_refusal(document))
                    self.assertIsNone(coverage_refusal(document))
                    self.assertEqual(schema_errors(document), [])
                    # Control: the schema refuses the same key without the
                    # '_' there, so its acceptance above is the '_' itself.
                    node = node_at(document, pointer)
                    node["remark"] = node.pop("_remark")
                    self.assertNotEqual(schema_errors(document), [],
                                        f"{place}: the schema takes 'remark' too")
        for place, path in self.NOT_ANNOTATED_IN.items():
            with self.subTest(place=place):
                document = _base()
                document["matrix"] = copy.deepcopy(_MATRIX)
                node = document
                for part in path:
                    node = node[part]
                node["_remark"] = "a note"
                self.assertIsNotNone(loader_refusal(document), place)
                self.assertNotEqual(schema_errors(document), [], place)

    def test_a_keyed_map_reads_an_underscore_key_as_a_name(self) -> None:
        """The README said only establishes, matrix and a specimen take no
        annotation, so a reader could put a `_remark` note in `identities`,
        a check's `expect`, a `capture` map or `headers`. Each reads the key
        as one more name: the first three refuse the note, and `headers`
        sends it (measured with a recording opener)."""
        from test_schema_parity import _base, loader_refusal  # noqa: PLC0415

        prose = _prose(README)
        self.assertIn(
            "A map keyed by names you choose has no annotations either, because "
            "a _ key there is one more name: in identities, a check's expect and "
            "a capture map, \"_remark\": \"a note\" is refused as an identity, an "
            "expectation or a capture, and in headers it is sent as a header.",
            prose,
        )
        refused = {
            "identities": ["identities"],
            "a check's expect": ["checks", 0, "expect"],
            "a session capture map": ["identities", "owner", "session", "capture"],
            "a login step capture map": ["identities", "owner", "session", "login", 0, "capture"],
            "a sequence step capture map": ["sequences", 0, "steps", 0, "capture"],
        }
        for place, path in refused.items():
            with self.subTest(place=place):
                document = _base()
                node = document
                for part in path:
                    node = node[part]
                node["_remark"] = "a note"
                self.assertIsNotNone(loader_refusal(document), place)
        document = _base()
        document["identities"]["attacker"]["headers"]["_remark"] = "a note"
        self.assertIsNone(loader_refusal(document))

    def test_the_changelog_states_the_break_under_changed(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        # The release section, not the first one: [Unreleased] sits above it, empty.
        release = re.search(r"^## \[0\.1\.0\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.M | re.S).group(1)
        changed = _prose(release.split("\n### Changed\n", 1)[1].split("\n### ", 1)[0])
        self.assertIn(
            "Upgrading: this refuses plain annotation keys that loaded before. A root "
            "checksum (read as checks), schema ($schema), versions or x-version "
            "(version), and an identity's remark (the letters of marker), now exit 2; "
            "start an annotation with _ (_checksum, _remark), as the refusal says.",
            changed,
        )

    def test_the_named_keys_behave_as_documented(self) -> None:
        """Each key the prose names is refused, the refusal says to start it
        with '_', and the prefixed key loads."""
        from veridor.core import ConfigError

        base = json.loads((ROOT / "fixtures" / "veridor.demo.json").read_text(encoding="utf-8"))
        environment = {name: "placeholder-value" for name in
                       re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", json.dumps(base))}
        owner = next(iter(base["identities"]))
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, environment):
            path = Path(directory) / "veridor.json"
            for key, identity in self.KEYS.items():
                for written, refused in ((key, True), (f"_{key}", False)):
                    with self.subTest(key=written):
                        document = json.loads(json.dumps(base))
                        target = document["identities"][owner] if identity else document
                        target[written] = "a note"
                        path.write_text(json.dumps(document), encoding="utf-8")
                        if not refused:
                            load_config(path)
                            continue
                        with self.assertRaises(ConfigError) as caught:
                            load_config(path)
                        self.assertIn("with '_' if it is an annotation", str(caught.exception))

class ShamShapeDocumentationTest(unittest.TestCase):
    """README's liveness paragraph says which headers the fabricated
    credential fills, as core._sham_header_names fills them: every declared
    header but a benign one, a shared non-credential value unchanged, and a
    per-identity header such as X-Remote-User fabricated (an earlier version left it out
    and said so, which made an auth-proxy suite exit 3)."""

    def test_the_paragraph_names_the_fabricated_and_the_unchanged_headers(self) -> None:
        prose = _prose(README)
        self.assertIn("in every header your identities declare except a standard request header", prose)
        self.assertIn("is sent with that value instead", prose)
        # A fabricated X-Tenant-Id beside Authorization
        # proved an expired token live on a tenant-first target.
        self.assertIn("Any other is left out when every identity declaring it also "
                      "sends a credential-named header or has a session", prose)
        self.assertIn("gets the fabricated value", prose)
        self.assertIn("the X-Remote-User an auth proxy names the caller by", prose)
        self.assertNotIn("is left out. Whether an identity presents", prose)


class MainGuardPlacementTest(unittest.TestCase):
    """`unittest.main()` runs the classes defined ABOVE it and then exits.

    In this file the guard sat above DocsOnlyTrialDocumentationTest, so
    `python3.12 tests/test_docs.py` ran 55 tests instead of 62 and reported OK;
    discovery, which imports the module, ran all 62. A guard anywhere but last
    drops every class after it from a direct run without a word.
    """

    #: Either operand order, optional parentheses, and a CRLF line end: each of
    #: those made a real guard invisible, and a file with no visible guard is
    #: one `_misplaced` never flags.
    _GUARD = re.compile(
        r"""^if\s*\(?\s*(?:__name__\s*==\s*(["'])__main__\1"""
        r"""|(["'])__main__\2\s*==\s*__name__)\s*\)?\s*:[ \t]*(?:#[^\r\n]*)?\r?$""",
        re.MULTILINE)

    @classmethod
    def _misplaced(cls, source: str) -> bool:
        """More than one guard, or a top-level line after the FIRST guard. The
        first, not the last: a direct run stops at the first one, so a second
        guard at the end hid every class between them. Read as text, not with
        ``ast``: parsing every test file cost 0.24 s here, and a slower machine
        runs it against the fast tier's same budget."""
        guards = list(cls._GUARD.finditer(source))
        if not guards:
            return False
        if len(guards) > 1:
            return True
        after = source[guards[0].end():]
        return re.search(r"^[^\s#]", after, re.MULTILINE) is not None

    def test_control_a_guard_above_a_class_is_caught(self) -> None:
        self.assertTrue(self._misplaced(
            'import unittest\nif __name__ == "__main__":\n    unittest.main()\n\n\n'
            'class A:\n    pass\n'))
        self.assertFalse(self._misplaced(
            'class A:\n    pass\n\n\nif __name__ == "__main__":\n    unittest.main()\n'))

    def test_control_every_guard_shape_and_a_second_guard_are_caught(self) -> None:
        """A merge left this file with two guards, and the check split on the
        LAST one, so a class between them would be dropped from a direct run
        while the check stayed green. A trailing comment or single quotes made
        the guard invisible to it altogether."""
        guard = 'if __name__ == "__main__":\n    unittest.main()\n'
        class_a = 'import unittest\n\n\nclass A:\n    pass\n\n\n'
        class_b = 'class B:\n    pass\n\n\n'
        cases = {
            "a class between two guards": class_a + guard + "\n\n" + class_b + guard,
            "two adjacent guards": class_a + guard + "\n\n" + guard,
            "a guard with a trailing comment above a class":
                'import unittest\nif __name__ == "__main__":  # pragma: no cover\n'
                "    unittest.main()\n\n\n" + class_b,
            "a single-quoted guard above a class":
                "import unittest\nif __name__ == '__main__':\n"
                "    unittest.main()\n\n\n" + class_b,
        }
        for name, source in cases.items():
            with self.subTest(name):
                self.assertTrue(self._misplaced(source))
        for last in ('if __name__ == "__main__":  # pragma: no cover\n',
                     "if __name__ == '__main__':\n"):
            with self.subTest(last):
                self.assertFalse(self._misplaced(
                    class_a + last + "    unittest.main()\n"))

    def test_control_crlf_parenthesised_and_reversed_guards_are_seen(self) -> None:
        """REGRESSION. A file with CRLF line endings, `if (__name__ ==
        "__main__"):` or `if "__main__" == __name__:` had a guard the pattern
        could not see, so it counted as having none and was never flagged,
        whatever followed it (measured: `_misplaced` returned False for each
        shape with a class after the guard)."""
        class_b = "class B:\n    pass\n"
        cases = {
            "crlf": 'import unittest\r\nif __name__ == "__main__":\r\n'
                    "    unittest.main()\r\n\r\n\r\n" + class_b.replace("\n", "\r\n"),
            "parenthesised": 'import unittest\nif (__name__ == "__main__"):\n'
                             "    unittest.main()\n\n\n" + class_b,
            "reversed": 'import unittest\nif "__main__" == __name__:\n'
                        "    unittest.main()\n\n\n" + class_b,
            "reversed, single-quoted, in parentheses":
                "import unittest\nif ('__main__' == __name__):  # direct run\n"
                "    unittest.main()\n\n\n" + class_b,
        }
        for name, source in cases.items():
            with self.subTest(name):
                self.assertEqual(len(self._GUARD.findall(source)), 1, name)
                self.assertTrue(self._misplaced(source), name)
                # Control: the same guard as the last statement is not flagged.
                guard_and_main = source[source.index("if"):source.index("class B")]
                last = "import unittest\n" + class_b + "\n\n" + guard_and_main.rstrip()
                self.assertFalse(self._misplaced(last), name)

    def test_the_guard_is_the_last_statement_of_every_test_file(self) -> None:
        paths = sorted((ROOT / "tests").glob("test_*.py"))
        self.assertGreater(len(paths), 40)
        # Every file has exactly one guard the pattern can SEE. `_misplaced`
        # passes a file with none, so a guard spelt in a way the pattern
        # missed was a file this test never judged.
        counts = {path.name: len(self._GUARD.findall(path.read_text(encoding="utf-8")))
                  for path in paths}
        self.assertEqual({name: count for name, count in counts.items() if count != 1}, {},
                         "a test file without exactly one detected main guard")
        misplaced = {
            path.name for path in paths
            if self._misplaced(path.read_text(encoding="utf-8"))
        }
        # Twelve files had it when this test was written; every guard was then
        # moved to the end of its file, so none is tolerated.
        self.assertEqual(misplaced, set(), "guard is not last")


class CapsuleCarriesWhatRunArtifactsDoNotTest(unittest.TestCase):
    """README and SECURITY.md said the marker literal and header values were
    never written to any artifact. A capsule carries both by design (each
    identity's marker, and every literal header that is not a credential:
    tests/test_capsule.py pins the second). The sentences name the exception."""

    SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    def test_neither_document_claims_every_artifact(self) -> None:
        for name, text in (("README.md", _prose(README)), ("SECURITY.md", _prose(self.SECURITY))):
            with self.subTest(document=name):
                self.assertNotIn("never written to any artifact", text)

    def test_both_name_the_capsule_as_the_exception(self) -> None:
        readme = _prose(README)
        start = readme.index("The marker literal itself")
        self.assertIn("capsule", readme[start:start + 300].lower())
        security = _prose(self.SECURITY)
        start = security.index("Header values are not written")
        self.assertIn("capsule", security[start:start + 300].lower())

    def test_a_capsule_really_carries_the_marker(self) -> None:
        """The exception the prose names is real: if capsules stopped carrying
        the marker, the sentence would describe a looser product than ships."""
        from veridor import capsule  # noqa: PLC0415
        config = json.loads((ROOT / "fixtures" / "veridor.demo.json").read_text(encoding="utf-8"))
        for identity in config["identities"].values():
            if "Authorization" in identity.get("headers", {}):
                identity["headers"]["Authorization"] = "Bearer ${VERIDOR_X}"
        marker = config["identities"]["invoice_owner"]["marker"]
        built = capsule.build(config, "invoice-tenant-isolation")
        self.assertIn(marker, json.dumps(built))


class PullRequestGateRecommendationTest(unittest.TestCase):
    """The regression-gate section said `--fail-on new` was "not what this
    README recommends for CI" and, ten lines on, "Use `new` as the pull-request
    gate"; the `run` example passed `--fail-on new`. The code's default and the
    Action's example are `new+confirmed`, so that is the one recommendation."""

    def test_new_is_never_recommended_as_the_gate(self) -> None:
        text = " ".join(README.split())
        self.assertNotIn("Use `new` as the pull-request gate", text)
        self.assertIn("use the default, `new+confirmed`, as the pull-request gate", text)

    def test_no_example_command_gates_on_new_alone(self) -> None:
        # Commands only: a sample of the tool's output may name the flag.
        blocks = re.findall(r"^```(?:bash|yaml)\n(.*?)^```", README, re.M | re.S)
        self.assertTrue(any("--fail-on new+confirmed" in block for block in blocks))  # control
        self.assertEqual([block for block in blocks if re.search(r"--fail-on new(?![+\w])", block)], [])


class NoUnreleasedHistoryTest(unittest.TestCase):
    """No version has been released, so no reader saw an earlier one. These
    phrases told them about behaviour they never had ("loaded in earlier
    versions", "the older spelling, still works", "it used to exit 1", a
    Before/After table); the docs state what ships and what was measured, and
    the CHANGELOG holds the history."""

    PHRASES = ("earlier versions", "older spelling", "used to exit", "| Before | After |",
               "Noisy target, before", 'earlier "about', "used to be supplied by the test")

    def test_the_published_docs_do_not_narrate_a_history(self) -> None:
        for path in ("README.md", "docs/report-formats.md", "ci/README.md"):
            text = " ".join((ROOT / path).read_text(encoding="utf-8").split())
            for phrase in self.PHRASES:
                with self.subTest(path=path, phrase=phrase):
                    self.assertNotIn(phrase, text)


class GateAndVerdictWordingTest(unittest.TestCase):
    """`--fail-on any` was "Any finding exists at all", but an inconclusive
    finding does not trip it (measured: exit 0 with only inconclusive findings,
    3 with --require-complete). `unexpected_denial` was "refused (401, 403,
    404)", but every non-2xx outside the declared set that is not inconclusive
    grades that way (measured: 400, 405, 409 and 302)."""

    def test_any_says_inconclusive_does_not_count(self) -> None:
        row = next(line for line in README.splitlines() if line.startswith("| `any` | Any finding"))
        self.assertIn("`inconclusive` one does not count", row)
        from veridor import gate  # noqa: PLC0415
        findings = [{"id": "x", "verdict": "inconclusive"}]
        self.assertEqual(gate._policy_findings("any", {"findings": findings}), [])  # what the row says

    def test_unexpected_denial_names_more_than_the_classic_three(self) -> None:
        text = " ".join(README[README.index("- `unexpected_denial` — "):].split("\n- ")[0].split())
        for status in ("`400`", "`405`", "`302`"):
            with self.subTest(status=status):
                self.assertIn(status, text)
        from veridor import core  # noqa: PLC0415
        for status in (400, 405, 409, 302):
            self.assertFalse(core._target_served(status))  # so not `vulnerable`


class DocsOnlyTrialDocumentationTest(unittest.TestCase):
    """Statements eight docs-only trials acted on and found untrue.

    Every one of these was invisible from inside the project: they are wrong
    only for a reader who does not already know the answer.
    """

    def test_the_quickstart_says_it_needs_a_checkout(self) -> None:
        """Two of the eight docs-only trials reported this as the worst point of the run. The first command
        in the README is `--config fixtures/veridor.demo.json`, and a wheel
        ships neither `scripts/` nor `fixtures/` -- so minute zero is
        `configuration not found`, which reads as a broken install."""
        # _prose unwraps the hard-wrapped paragraph the way a reader reads it.
        quickstart = _prose(_section("Quickstart: your first 60 seconds"))
        self.assertIn("not in the distribution", quickstart)
        self.assertIn("configuration not found", quickstart)

    def test_the_front_door_says_a_spec_is_not_required_to_gate(self) -> None:
        """The README said "start from a specification. There are two
        on-ramps", both `--openapi`. A team with no spec reads that and
        leaves -- while `run`, `mutate`, `capsule` and `verify` need none, and
        one docs-only trial built the entire gate by hand to prove it."""
        prose = _prose(README)
        self.assertIn("You do not need an OpenAPI specification to gate a build",
                      prose)
        for verb in ("map", "init", "coverage"):
            self.assertIn(verb, prose)

    def test_the_spec_stub_that_unlocks_the_other_verbs_is_shown(self) -> None:
        """Empty operation objects are enough, and it is ten minutes of work
        for a team that knows its endpoints. It was documented nowhere."""
        self.assertIn('"paths": {"/api/invoices": {"get": {}}', README)

    def test_the_control_is_documented_as_required(self) -> None:
        """The README told you the same-check control binds without being
        declared. The loader refuses exactly that config, at load time."""
        prose = _prose(README)
        self.assertIn("You must declare it.", prose)
        self.assertNotIn("You do not have to declare it for it to bind", prose)

    def test_the_ci_example_does_not_pass_a_baseline_that_cannot_exist(self) -> None:
        """`baseline: baseline.json` on a first run is a hard exit 2, and the
        block a platform engineer copies was the one that did not run."""
        workflow = README[README.index("## Continuous integration"):]
        self.assertNotIn("\n      baseline: baseline.json", workflow)

    def test_the_committed_baseline_lives_outside_the_ignored_directory(self) -> None:
        """We told people to commit a file inside `.veridor/`, which every team
        gitignores because it is the tool's own run history."""
        self.assertNotIn(".veridor/baseline-matrix.json", README)

    def test_the_mode_guard_admits_what_it_cannot_catch(self) -> None:
        """"Refused, never ignored" was false three ways: the check compares
        each input to its default, so a default value on the wrong step is
        indistinguishable from an absent one."""
        prose = _prose(README)
        self.assertIn("cannot tell", prose)
        self.assertIn("accepted silently", prose)


if __name__ == "__main__":
    unittest.main()
