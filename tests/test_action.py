"""The GitHub Action is a surface with real branching and no other test.

Everything else in this repository is exercised by calling Python. The Action
is a shell program embedded in YAML and wired together with GitHub expressions,
and it is the form most users will meet Veridor through. So it is tested the
way GitHub runs it: ``tests/action_harness.py`` executes every step of
``action.yml`` in order, under the runner's own bash flags, with the step
``env:`` evaluated from ``inputs``, real ``GITHUB_OUTPUT`` /
``GITHUB_STEP_SUMMARY`` files, and the ``outputs:`` block read back through
``steps.veridor.outputs``.

Two kinds of slow test use it. ``ActionArgvTest`` points the action at a stub
``veridor`` package that records its argv, which is the only way to catch the
failure that matters there: an input silently dropped, so a workflow waits on a
file that was never going to be written, or a gate runs without a flag the
author thought they had set. ``ActionEndToEndTest`` runs the real package
against ``scripts/demo_server.py`` and checks the verdicts a workflow sees.
Each carries a mutation control: a copy of ``action.yml`` with the defect
reintroduced must fail the same assertion.

The two modes exist because ``run`` and ``map --fail-on-drift`` exit non-zero
for different reasons. Mixing them into one step would give a workflow one exit
code covering two claims, and no way to tell which one failed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from action_harness import (  # noqa: E402
    Context,
    ExpressionError,
    HarnessError,
    YAMLSubsetError,
    evaluate,
    evaluate_condition,
    load_yaml,
    parse_file_commands,
    run_action,
)
import loopback  # noqa: E402
from tiers import slow  # noqa: E402
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed
from veridor import core  # noqa: E402

ACTION_TEXT = (ROOT / "action.yml").read_text(encoding="utf-8")
ACTION = load_yaml(ACTION_TEXT)
INPUTS: dict = ACTION["inputs"]
OUTPUTS: dict = ACTION["outputs"]
STEPS: list = ACTION["runs"]["steps"]
MAIN = next(step for step in STEPS if step.get("id") == "veridor")
VERDICT = STEPS[-1]

BOOLEAN_INPUTS = ("read-only", "require-complete", "require-clean-teardown",
                  "allow-no-matches", "summary")
RUN_ONLY_INPUTS = ("baseline", "json", "sarif", "junit", "fail-on")
DRIFT_ONLY_INPUTS = ("matrix-baseline", "fail-on-drift", "drift", "matrix",
                     "acknowledge-target", "max-requests", "rate")


def _variable(name: str) -> str:
    return "INPUT_" + name.upper().replace("-", "_")


# ---------------------------------------------------------------------------
# Fast: the YAML itself, and the harness's own refusals
# ---------------------------------------------------------------------------


class ActionMetadataTest(unittest.TestCase):
    """Checks on the parsed action.yml. No bash, no subprocess."""

    def test_it_is_a_composite_action_with_a_verdict_step_last(self) -> None:
        self.assertEqual(ACTION["runs"]["using"], "composite")
        self.assertEqual(MAIN["id"], "veridor")
        self.assertIn("steps.veridor.outputs.exit-code", VERDICT["env"]["VERIDOR_EXIT_CODE"])

    def test_every_declared_input_reaches_the_script_through_env(self) -> None:
        """An input nobody reads is a promise the Action does not keep."""
        env = MAIN["env"]
        script = MAIN["run"]
        for name in INPUTS:
            with self.subTest(input=name):
                variable = _variable(name)
                self.assertIn(env.get(variable), (f"${{{{ inputs.{name} }}}}",
                                                  f"${{{{ inputs['{name}'] }}}}"))
                self.assertIn("$" + variable, script.replace("{", ""))
                # And it is covered by the line-break refusal.
                names = re.search(r"names=\((.*?)\)", script, re.S).group(1).split()
                self.assertIn(variable.removeprefix("INPUT_"), names)

    def test_every_input_variable_the_step_sets_is_a_declared_input(self) -> None:
        for variable in MAIN["env"]:
            with self.subTest(variable=variable):
                name = variable.removeprefix("INPUT_").lower().replace("_", "-")
                self.assertIn(name, INPUTS)

    def test_no_run_block_contains_an_expression(self) -> None:
        """`${{ }}` inside `run:` is substituted into the script text before
        bash sees it, so an input would be executable. Values come through
        env: only. (A comment containing the characters counts: GitHub
        evaluates those too, and an empty one fails the step at runtime.)"""
        for step in STEPS:
            with self.subTest(step=step.get("name")):
                self.assertNotIn("${{", step["run"])

    def test_every_output_reads_the_main_step_and_the_script_writes_it(self) -> None:
        script = MAIN["run"]
        for name, spec in OUTPUTS.items():
            with self.subTest(output=name):
                self.assertEqual(spec["value"], f"${{{{ steps.veridor.outputs.{name} }}}}")
                # A path output is one "NAME=$path" pair of the loop that
                # writes it only when this step wrote the file.
                written = (f"printf '{name}=" in script or f'emit("{name}"' in script
                           or f"'{name}=%s" in script or f'"{name}=$' in script)
                self.assertTrue(written, f"{name} is declared but the script never writes it")

    def test_mode_specific_inputs_default_to_empty(self) -> None:
        """A default of `veridor.sarif` made `sarif: veridor.sarif` on a drift
        step indistinguishable from no `sarif` at all, so the cross-mode
        refusal could only compare against the default and let it through.
        Empty defaults make "not given" visible; the effective defaults are
        applied in the script and stated in each description."""
        for name in RUN_ONLY_INPUTS + DRIFT_ONLY_INPUTS:
            with self.subTest(input=name):
                self.assertEqual(INPUTS[name].get("default"), "")

    def test_each_mode_specific_input_is_named_in_the_other_mode_s_refusal(self) -> None:
        script = MAIN["run"]
        run_branch = script[script.index("\n  run)"):script.index("\n  drift)")]
        drift_branch = script[script.index("\n  drift)"):script.index("\n  *)")]
        for name in DRIFT_ONLY_INPUTS:
            with self.subTest(input=name):
                self.assertIn(f'"{name}=${_variable(name)}"', run_branch)
        for name in RUN_ONLY_INPUTS:
            with self.subTest(input=name):
                self.assertIn(f'"{name}=${_variable(name)}"', drift_branch)

    def test_booleans_are_parsed_strictly(self) -> None:
        script = MAIN["run"]
        for name in BOOLEAN_INPUTS:
            with self.subTest(input=name):
                self.assertIn(INPUTS[name]["default"], ("true", "false"))
                self.assertRegex(script, rf'parse_boolean \w+ {re.escape(name)} "\${_variable(name)}"')
        self.assertNotRegex(script, r'"\$INPUT_[A-Z_]+" == "?true', "a raw string comparison is back")

    def test_veridor_runs_from_the_action_checkout_without_an_install(self) -> None:
        script = MAIN["run"]
        self.assertIn('PYTHONPATH="$src" "$python" -P -m veridor "$@"', script)
        self.assertIn('src="${GITHUB_ACTION_PATH}/src"', script)
        for step in STEPS:
            self.assertNotIn("pip install", step["run"])

    def test_run_mode_stays_the_default(self) -> None:
        """Existing workflows pin a ref and must not change behaviour."""
        self.assertEqual(INPUTS["mode"]["default"], "run")
        self.assertEqual(INPUTS["require-complete"]["default"], "true")
        self.assertEqual(INPUTS["summary"]["default"], "true")

    def test_the_drift_default_divergence_from_the_cli_is_documented(self) -> None:
        """`veridor map` defaults to none and this defaults to opened. A
        divergence a user discovers by having a build fail is a defect; one
        they read in the input description is a decision."""
        self.assertIn("differs from `veridor map`, where it is none",
                      INPUTS["fail-on-drift"]["description"])
        self.assertIn('"${INPUT_FAIL_ON_DRIFT:-opened}"', MAIN["run"])


README = (ROOT / "README.md").read_text(encoding="utf-8")


def _readme_section() -> str:
    start = README.index("### GitHub Action\n")
    end = README.index("\n### ", start + 1)
    return README[start:end]


def _table(section: str, header: str) -> dict[str, list[str]]:
    """Rows of the markdown table that starts with `header`, keyed by the backticked name."""
    lines = section[section.index(header):].splitlines()
    rows: dict[str, list[str]] = {}
    for line in lines[2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        rows[cells[0].strip("`")] = cells[1:]
    return rows


def readme_table_problems(section: str) -> list[str]:
    """Where the README's input and output tables disagree with action.yml."""
    problems = []
    inputs = _table(section, "| Input | Default | Mode |")
    for name in sorted(set(INPUTS) ^ set(inputs)):
        problems.append(f"input {name}: in {'action.yml' if name in INPUTS else 'README'} only")
    for name, spec in INPUTS.items():
        if name not in inputs:
            continue
        default = spec.get("default")
        expected_default = ("required" if default is None else "—" if default == "" else f"`{default}`")
        mode = ("run" if name in RUN_ONLY_INPUTS + ("read-only", "require-clean-teardown")
                else "drift" if name in DRIFT_ONLY_INPUTS else "both")
        if inputs[name][:2] != [expected_default, mode]:
            problems.append(f"input {name}: README says {inputs[name][:2]}, "
                            f"action.yml means {[expected_default, mode]}")
    outputs = _table(section, "| Output | Mode |")
    for name in sorted(set(OUTPUTS) ^ set(outputs)):
        problems.append(f"output {name}: in {'action.yml' if name in OUTPUTS else 'README'} only")
    return problems


def sarif_upload_problems(section: str) -> list[str]:
    """Every upload-sarif step in the section's examples that could upload a
    file this run did not write. It must run on the Veridor step's own
    `sarif` output (set only when that step wrote the file) and upload that
    path. `hashFiles('veridor.sarif') != ''` is true for a file an earlier
    step left there, so after a refusal it uploaded that file as this run's."""
    problems = []
    for block in re.findall(r"^```yaml\n(.*?)^```", section, re.M | re.S):
        document = load_yaml(textwrap.dedent(block))
        steps = document.get("steps", []) if isinstance(document, dict) else document
        if not isinstance(steps, list):
            continue
        ids = [step.get("id") for step in steps
               if isinstance(step, dict) and str(step.get("uses", "")).startswith("Veridor-authz/veridor@")]
        for step in steps:
            if not (isinstance(step, dict) and str(step.get("uses", "")).startswith("github/codeql-action/upload-sarif@")):
                continue
            condition, uploaded = str(step.get("if", "")), str((step.get("with") or {}).get("sarif_file", ""))
            if "hashFiles(" in condition:
                problems.append(f"upload-sarif runs on {condition}: true for a file an earlier step left")
            if not any(f"steps.{i}.outputs.sarif != ''" in condition for i in ids if i):
                problems.append(f"upload-sarif does not run on the Veridor step's sarif output: {condition!r}")
            if not any(uploaded == f"${{{{ steps.{i}.outputs.sarif }}}}" for i in ids if i):
                problems.append(f"upload-sarif uploads {uploaded!r}, not the Veridor step's sarif output")
    return problems


class ReadmeActionSectionTest(unittest.TestCase):
    """The README's GitHub Action section against action.yml, and as YAML."""

    def test_the_sarif_upload_example_uploads_only_this_run_s_file(self) -> None:
        section = _readme_section()
        self.assertIn("github/codeql-action/upload-sarif@", section)
        self.assertEqual(sarif_upload_problems(section), [])

    def test_control_the_hashfiles_example_is_named(self) -> None:
        section = _readme_section()
        old = re.sub(r"(?m)^  - if: \$\{\{ always\(\) && steps\.veridor\.outputs\.sarif != '' \}\}$",
                     "  - if: ${{ always() && hashFiles('veridor.sarif') != '' }}", section)
        old = old.replace("      sarif_file: ${{ steps.veridor.outputs.sarif }}", "      sarif_file: veridor.sarif")
        self.assertNotEqual(old, section, "the mutation did not apply")
        self.assertEqual(len(sarif_upload_problems(old)), 3, sarif_upload_problems(old))

    def test_every_input_and_output_is_documented_as_declared(self) -> None:
        self.assertEqual(readme_table_problems(_readme_section()), [])

    def test_control_a_missing_row_or_a_wrong_default_is_caught(self) -> None:
        section = _readme_section()
        dropped = re.sub(r"^\| `rate` \|.*\n", "", section, flags=re.M)
        self.assertNotEqual(dropped, section)
        self.assertIn("input rate: in action.yml only", readme_table_problems(dropped))
        wrong = section.replace("| `summary` | `true` |", "| `summary` | `false` |")
        self.assertNotEqual(wrong, section)
        self.assertTrue(any(p.startswith("input summary:") for p in readme_table_problems(wrong)))
        dropped = re.sub(r"^\| `gate-reasons` \|.*\n", "", section, flags=re.M)
        self.assertIn("output gate-reasons: in action.yml only", readme_table_problems(dropped))

    def test_every_yaml_example_in_the_section_parses(self) -> None:
        """The outputs example was invalid YAML: a plain scalar with ': ' in it."""
        blocks = re.findall(r"^```yaml\n(.*?)^```", _readme_section(), re.M | re.S)
        self.assertGreaterEqual(len(blocks), 3)
        for block in blocks:
            with self.subTest(block=block[:60]):
                load_yaml(textwrap.dedent(block))  # a steps fragment may be indented
        with self.assertRaises(YAMLSubsetError):
            load_yaml('- run: gh pr comment "$PR" --body "Veridor: 1 vulnerable"\n')

    def test_the_section_does_not_claim_a_release(self) -> None:
        section = _readme_section()
        # Dated, because the sentence goes false at the first tag and nothing
        # about an undated one says when it was written.
        prose = " ".join(section.split())
        self.assertRegex(prose, r"As of \d{4}-\d{2}-\d{2}, no release has been tagged\.")
        # The runner claim names the run it rests on and when it happened.
        ran = r"passed on GitHub-hosted runners on \d{4}-\d{2}-\d{2} \(CI run \d+\)"
        self.assertRegex(prose, ran)
        self.assertNotRegex(re.sub(r"\d{4}-\d{2}-\d{2}", "recently", prose), ran)
        self.assertNotRegex(prose, r"(?i)(?:tagged|observed|seen) yet")
        self.assertNotRegex(section, r"Veridor-authz/veridor@v\d")


class YAMLSubsetTest(unittest.TestCase):
    """The harness parser: what it reads, and -- the control -- what it refuses."""

    def test_the_forms_action_yml_uses(self) -> None:
        document = load_yaml(
            "a: plain  # comment\n"
            'b: "x: y"\n'
            "c: 'it''s'\n"
            "d: >-\n  one\n  two\n\n  three\n"
            "e: |\n  line 1\n    indented\n  # not a comment\n"
            "f:\n  - x\n  - k: v\n    j: w\n"
            "g: [a, \"b\"]\n"
            "h:\n"
        )
        self.assertEqual(document["a"], "plain")
        self.assertEqual(document["b"], "x: y")
        self.assertEqual(document["c"], "it's")
        self.assertEqual(document["d"], "one two\nthree")
        self.assertEqual(document["e"], "line 1\n  indented\n# not a comment\n")
        self.assertEqual(document["f"], ["x", {"k": "v", "j": "w"}])
        self.assertEqual(document["g"], ["a", "b"])
        self.assertIsNone(document["h"])

    def test_it_refuses_what_it_does_not_implement(self) -> None:
        for text in ("a: &anchor x\n", "a: *alias\n", "a: !!str x\n", "a: {b: c}\n",
                     "a: x\na: y\n", "a: b: c\n", "a:\n\tb: c\n", "---\na: b\n",
                     "a: 'unterminated\n", "a: >+\n  x\n"):
            with self.subTest(text=text):
                with self.assertRaises(YAMLSubsetError):
                    load_yaml(text)


class ExpressionTest(unittest.TestCase):
    """The evaluator resolves the subset and raises on everything else."""

    def _context(self, **overrides) -> Context:
        context = Context(
            inputs={"read-only": "false", "config": "c.json"},
            declared_inputs={"read-only", "config"},
            action_path="/action", workspace="/ws", runner_temp="/tmp/rt",
            env={"HOME": "/home"}, step_ids=["veridor", "later"],
            completed_steps={"veridor": {"exit-code": "1"}},
        )
        for key, value in overrides.items():
            setattr(context, key, value)
        return context

    def test_the_supported_references(self) -> None:
        context = self._context()
        cases = {
            "${{ inputs.config }}": "c.json",
            "${{ inputs['read-only'] }}": "false",
            "${{ inputs.read-only }}": "false",
            "${{ github.action_path }}/src": "/action/src",
            "${{ github.workspace }}": "/ws",
            "${{ runner.temp }}": "/tmp/rt",
            "${{ env.HOME }}": "/home",
            "${{ steps.veridor.outputs.exit-code }}": "1",
            "${{ steps.veridor.outputs.never-written }}": "",
            "no expression": "no expression",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(evaluate(text, context), expected)

    def test_anything_else_raises_rather_than_reading_as_empty(self) -> None:
        context = self._context()
        for text in ("${{ inputs.read-onyl }}", "${{ github.token }}",
                     "${{ secrets.X }}", "${{ inputs.a || 'b' }}",
                     "${{ format('{0}', inputs.config) }}", "${{ env.UNSET }}",
                     "${{ steps.nope.outputs.x }}", "${{ steps.later.outputs.x }}",
                     "${{ }}", "${{ inputs.config"):
            with self.subTest(text=text):
                with self.assertRaises(ExpressionError):
                    evaluate(text, context)

    def test_step_conditions(self) -> None:
        self.assertTrue(evaluate_condition(None, self._context()))
        self.assertFalse(evaluate_condition(None, self._context(failed=True)))
        self.assertTrue(evaluate_condition("${{ always() }}", self._context(failed=True)))
        self.assertTrue(evaluate_condition("failure()", self._context(failed=True)))
        with self.assertRaises(ExpressionError):
            evaluate_condition("inputs.summary == 'true'", self._context())


class DocumentIdentityTest(unittest.TestCase):
    """action.yml's fresh() accepts a document only when a different file
    (device, inode) sits at its path after Veridor ran. That holds because
    Veridor's writer renames a new file over the path. Checked here against
    the real writer; an in-place rewrite, which fresh() would not accept, is
    the control."""

    @staticmethod
    def identity(path: Path) -> tuple[int, int]:
        found = os.lstat(path)
        return found.st_dev, found.st_ino

    def test_veridor_writes_a_document_as_a_new_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.json"
            path.write_text('{"run_id": "stale"}', encoding="utf-8")
            stale = self.identity(path)
            core.write_json(path, {"run_id": "fresh"})
            self.assertNotEqual(self.identity(path), stale)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"run_id": "fresh"})

    def test_veridor_writes_a_report_as_a_new_file(self) -> None:
        """The JUnit and Markdown path outputs rely on it too: --report and
        `report --output` write through reports.write_text."""
        from veridor import reports  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "veridor-junit.xml"
            path.write_text("<stale/>", encoding="utf-8")
            stale = self.identity(path)
            reports.write_text(path, "<fresh/>")
            self.assertNotEqual(self.identity(path), stale)
            self.assertEqual(path.read_text(encoding="utf-8"), "<fresh/>")

    def test_control_an_in_place_rewrite_keeps_its_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.json"
            path.write_text('{"run_id": "stale"}', encoding="utf-8")
            stale = self.identity(path)
            path.write_text('{"run_id": "fresh"}', encoding="utf-8")
            self.assertEqual(self.identity(path), stale)

    def test_the_action_compares_identities_not_times(self) -> None:
        script = MAIN["run"]
        self.assertIn("st_ino", script)
        self.assertNotIn("st_mtime", script)


class FileCommandTest(unittest.TestCase):
    def test_both_syntaxes(self) -> None:
        text = "a=1\nb=x=y\nc<<EOF_1\nline 1\nline 2\nEOF_1\nd<<E\n\nE\n"
        self.assertEqual(parse_file_commands(text),
                         [("a", "1"), ("b", "x=y"), ("c", "line 1\nline 2"), ("d", "")])

    def test_an_unterminated_heredoc_raises(self) -> None:
        with self.assertRaises(HarnessError):
            parse_file_commands("c<<EOF\nnever closed\n")
        with self.assertRaises(HarnessError):
            parse_file_commands("no equals sign\n")


# ---------------------------------------------------------------------------
# Slow: the action executed step by step
# ---------------------------------------------------------------------------

_STUB_MAIN = r'''
import json, os, sys
log = os.environ.get("VERIDOR_STUB_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1:2] == ["report"]:
    args = sys.argv[1:]
    text = "stub markdown for " + args[args.index("--format") + 1] + "\n"
    if "--output" in args:
        open(args[args.index("--output") + 1], "w", encoding="utf-8").write(text)
    else:
        sys.stdout.write(text)
    raise SystemExit(0)
documents = json.loads(os.environ.get("VERIDOR_STUB_DOCUMENTS") or "{}")
for flag, body in documents.items():
    args = sys.argv[1:]
    if flag == "--report":
        # Every --report FORMAT=PATH, written the same way.
        for index, arg in enumerate(args[:-1]):
            if arg == "--report":
                target = args[index + 1].split("=", 1)[1]
                with open(target + ".stub-tmp", "w", encoding="utf-8") as handle:
                    handle.write(body)
                os.replace(target + ".stub-tmp", target)
        continue
    if flag in args:
        # Written the way core.write_json writes: a new file renamed over the
        # path, which is what action.yml's fresh() relies on.
        target = args[args.index(flag) + 1]
        with open(target + ".stub-tmp", "w", encoding="utf-8") as handle:
            handle.write(body if isinstance(body, str) else json.dumps(body))
        os.replace(target + ".stub-tmp", target)
raise SystemExit(int(os.environ.get("VERIDOR_STUB_EXIT", "0")))
'''


class _ActionCase(unittest.TestCase):
    """Shared setup: a workspace, a runner temp dir, and python3 on PATH."""

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("bash") is None:  # pragma: no cover - CI always has it
            raise unittest.SkipTest("bash is required to exercise the action")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-action-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.workspace = self.tmp / "workspace"
        self.workspace.mkdir()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        # What actions/setup-python provides: python3 on PATH, 3.11 or newer.
        (self.bin / "python3").symlink_to(sys.executable)
        self.path = [str(self.bin), "/usr/bin", "/bin"]
        self.summary = self.tmp / "step_summary.md"
        self.summary.write_text("line written by an earlier step\n", encoding="utf-8")

    def action_copy(self, text: str | None = None, *, src: Path | None = None) -> Path:
        """A directory holding action.yml (optionally mutated) and a src/."""
        directory = self.tmp / f"action-{len(list(self.tmp.glob('action-*')))}"
        directory.mkdir()
        (directory / "action.yml").write_text(text if text is not None else ACTION_TEXT,
                                              encoding="utf-8")
        (directory / "src").symlink_to(src or ROOT / "src", target_is_directory=True)
        return directory

    def run_action(self, inputs: dict[str, str], *, action_dir: Path | None = None,
                   path: list[str] | None = None, env: dict[str, str] | None = None):
        return run_action(action_dir or ROOT, inputs, workspace=self.workspace,
                          runner_temp=self.tmp / "runner-temp", path=path or self.path,
                          summary_file=self.summary, extra_env=env)


@slow("runs action.yml's steps under bash against a stub veridor package")
class ActionArgvTest(_ActionCase):
    """Inputs to argv, refusals, outputs and exit codes, with a stub Veridor."""

    def setUp(self) -> None:
        super().setUp()
        stub = self.tmp / "stub-src" / "veridor"
        stub.mkdir(parents=True)
        (stub / "__init__.py").write_text('__version__ = "0.0.0-stub"\n', encoding="utf-8")
        (stub / "__main__.py").write_text(_STUB_MAIN, encoding="utf-8")
        self.action = self.action_copy(src=stub.parent)
        self.argv_log = self.tmp / "argv.jsonl"

    def invoke(self, *, exit_code: int = 0, documents: dict | None = None,
               **inputs: str):
        env = {"VERIDOR_STUB_LOG": str(self.argv_log), "VERIDOR_STUB_EXIT": str(exit_code),
               "VERIDOR_STUB_DOCUMENTS": json.dumps(documents or {})}
        run = self.run_action(inputs, action_dir=self.action, env=env)
        calls = ([json.loads(line) for line in self.argv_log.read_text().splitlines()]
                 if self.argv_log.exists() else [])
        gate = [call for call in calls if call[:1] in (["run"], ["map"])]
        return run, (gate[0] if gate else None), calls

    def refused(self, message: str, **inputs: str):
        run, argv, _ = self.invoke(**inputs)
        self.assertEqual(run.returncode, 2, run.log)
        self.assertIsNone(argv, "veridor was invoked despite the refusal")
        self.assertIn(message, "\n".join(run.annotations()))
        self.assertEqual(run.outputs["exit-code"], "2")
        self.assertEqual(run.steps[-1].outcome, "skipped")
        return run

    def baseline_file(self) -> str:
        path = self.workspace / "matrix.json"
        path.write_text("{}", encoding="utf-8")
        return str(path)

    # -- run mode ------------------------------------------------------------

    def test_run_mode_builds_the_documented_command(self) -> None:
        run, argv, _ = self.invoke(config="veridor.json")
        self.assertEqual(run.returncode, 0, run.log)
        self.assertEqual(argv[:9], ["run", "--config", "veridor.json",
                                    "--output-dir", ".veridor",
                                    "--sarif", "veridor.sarif",
                                    "--fail-on", "new+confirmed"])
        self.assertEqual(argv[9], "--json")
        self.assertRegex(argv[10], r"/veridor-action\.[^/]+/run\.json$")
        self.assertEqual(argv[11:13], ["--report", argv[12]])
        self.assertRegex(argv[12], r"^junit=.*/veridor-action\.[^/]+/veridor-junit\.xml$")
        self.assertRegex(argv[14], r"^markdown=.*/veridor-action\.[^/]+/veridor\.md$")
        # --require-complete is ON by default here, so a probe the target
        # could not answer exits 3 rather than passing as a boundary that held.
        self.assertEqual(argv[15:], ["--require-complete"])

    def test_booleans_accept_true_and_false_in_any_case(self) -> None:
        for value, present in (("false", False), ("FALSE", False), ("False", False),
                               ("true", True), ("TRUE", True), ("True", True)):
            with self.subTest(value=value):
                self.argv_log.unlink(missing_ok=True)
                _, argv, _ = self.invoke(config="c.json", **{"require-complete": value,
                                                             "read-only": value})
                self.assertEqual("--require-complete" in argv, present, argv)
                self.assertEqual("--read-only" in argv, present, argv)

    def test_a_boolean_that_is_not_true_or_false_is_refused(self) -> None:
        """`read-only: yes` compared unequal to "true" and silently dropped
        --read-only, so a mutating configuration ran against the target."""
        for name in BOOLEAN_INPUTS:
            for value in ("yes", "1", "on", "", " true", "treu"):
                with self.subTest(input=name, value=value):
                    extra = {"openapi": "s.json"} if name == "allow-no-matches" else {}
                    run = self.refused(f"input {name} must be true or false",
                                       config="c.json", **{name: value}, **extra)
                    self.assertIn(f"got '{value}'", run.log)

    def test_optional_run_inputs_pass_through(self) -> None:
        _, argv, _ = self.invoke(config="c.json", baseline="b.json", json="r.json",
                                 sarif="out.sarif", junit="j.xml", markdown="m.md",
                                 openapi="s.json", coverage="cov.json", badge="b.svg",
                                 **{"fail-on": "any", "base-url": "http://127.0.0.1:1",
                                    "base-path": "/api", "allow-no-matches": "true",
                                    "require-clean-teardown": "true"})
        value = {flag: argv[argv.index(flag) + 1] for flag in
                 ("--baseline", "--json", "--sarif", "--fail-on", "--base-url",
                  "--openapi", "--coverage", "--badge", "--base-path")}
        self.assertEqual(value, {"--baseline": "b.json", "--json": "r.json",
                                 "--sarif": "out.sarif", "--fail-on": "any",
                                 "--base-url": "http://127.0.0.1:1",
                                 "--openapi": "s.json", "--coverage": "cov.json",
                                 "--badge": "b.svg", "--base-path": "/api"})
        self.assertIn("junit=j.xml", argv)
        self.assertIn("markdown=m.md", argv)
        self.assertIn("--allow-no-matches", argv)
        self.assertIn("--require-clean-teardown", argv)

    def test_wait_for_target_passes_a_whole_number_in_both_modes(self) -> None:
        baseline = self.baseline_file()
        for mode, extra in (("run", {}), ("drift", {"openapi": "s.json", "matrix-baseline": baseline})):
            for value, expected in (("30", "30"), ("007", "007"), ("0", None), ("000", None)):
                with self.subTest(mode=mode, value=value):
                    self.argv_log.unlink(missing_ok=True)
                    run, argv, _ = self.invoke(mode=mode, config="c.json",
                                               **{"wait-for-target": value}, **extra)
                    self.assertEqual(run.returncode, 0, run.log)
                    if expected is None:
                        self.assertNotIn("--wait-for-target", argv)
                    else:
                        # Passed as typed; veridor's parser reads "007" as 7
                        # (tests/test_wait_for_target.py).
                        self.assertEqual(argv[argv.index("--wait-for-target") + 1], expected)

    def test_wait_for_target_that_is_not_a_whole_number_is_refused(self) -> None:
        for value in ("-1", "1.5", "abc", "", " 5", "60s", "1e3"):
            with self.subTest(value=value):
                self.refused("input wait-for-target must be a whole number of seconds",
                             config="c.json", **{"wait-for-target": value})

    # -- drift mode ----------------------------------------------------------

    def test_drift_mode_builds_a_map_command(self) -> None:
        run, argv, _ = self.invoke(mode="drift", config="c.json", openapi="s.json",
                                   rate="1", **{"matrix-baseline": self.baseline_file(),
                                                "acknowledge-target": "I am authorized to test x",
                                                "max-requests": "900", "drift": "d.json",
                                                "matrix": "current.json"})
        self.assertEqual(run.returncode, 0, run.log)
        self.assertEqual(argv[0], "map")
        self.assertEqual(argv[argv.index("--fail-on-drift") + 1], "opened")
        for flag, expected in (("--acknowledge-target", "I am authorized to test x"),
                               ("--max-requests", "900"), ("--rate", "1"),
                               ("--drift", "d.json"), ("--matrix", "current.json"),
                               ("--openapi", "s.json")):
            self.assertEqual(argv[argv.index(flag) + 1], expected, flag)
        self.assertIn("--require-complete", argv)
        # The gate must never arrive as SARIF, JUnit or a run document.
        for flag in ("--sarif", "--fail-on", "--json", "--report"):
            self.assertNotIn(flag, argv)

    def test_a_missing_baseline_file_fails_rather_than_passing(self) -> None:
        """The worst outcome: a green gate that compared nothing."""
        self.refused("does not exist", mode="drift", config="c.json", openapi="s.json",
                     **{"matrix-baseline": "never-committed.json"})

    def test_a_directory_baseline_is_refused_because_it_ratchets(self) -> None:
        """This step always gates and writes a matrix into the directory a
        directory baseline resolves from, so the re-run of a failed build
        compares the regression against itself and passes."""
        self.refused("is a directory", mode="drift", config="c.json", openapi="s.json",
                     **{"matrix-baseline": "."})

    def test_drift_without_a_baseline_or_specification_is_refused(self) -> None:
        self.refused("requires matrix-baseline", mode="drift", config="c.json",
                     openapi="s.json")
        self.refused("requires the openapi input", mode="drift", config="c.json",
                     **{"matrix-baseline": self.baseline_file()})

    def test_run_only_inputs_are_refused_in_drift_mode(self) -> None:
        baseline = self.baseline_file()
        for name, value in (("baseline", "b.json"), ("json", "r.json"),
                            ("sarif", "veridor.sarif"), ("junit", "j.xml"),
                            ("fail-on", "new+confirmed")):
            with self.subTest(input=name):
                self.refused(f"input {name} is a run-mode input", mode="drift",
                             config="c.json", openapi="s.json",
                             **{"matrix-baseline": baseline, name: value})
        for name in ("read-only", "require-clean-teardown"):
            with self.subTest(input=name):
                self.refused("are run-mode inputs", mode="drift", config="c.json",
                             openapi="s.json", **{"matrix-baseline": baseline, name: "true"})

    def test_drift_inputs_are_refused_in_run_mode(self) -> None:
        """fail-on-drift used to be checked in neither mode's refusal, so a run
        step carrying it proceeded as if it gated something."""
        for name, value in (("matrix-baseline", "m.json"), ("drift", "d.json"),
                            ("matrix", "c.json"), ("max-requests", "900"),
                            ("rate", "1"), ("fail-on-drift", "opened"),
                            ("acknowledge-target", "I am authorized to test x")):
            with self.subTest(input=name):
                self.refused(f"input {name} requires mode: drift", config="c.json",
                             **{name: value})

    def test_coverage_inputs_without_openapi_are_refused(self) -> None:
        for name, value in (("coverage", "cov.json"), ("badge", "b.json"),
                            ("base-path", "/api"), ("allow-no-matches", "true")):
            with self.subTest(input=name):
                self.refused("require the openapi input", config="c.json", **{name: value})

    def test_an_unknown_mode_is_refused(self) -> None:
        self.refused("unknown mode", mode="both", config="c.json")

    def test_a_line_break_in_an_input_is_refused(self) -> None:
        """It could forge a second line in GITHUB_OUTPUT, such as exit-code=0."""
        self.refused("input json contains a line break", config="c.json",
                     json="run.json\nexit-code=0")

    # -- outputs and exit codes ------------------------------------------------

    def test_the_exit_code_fails_the_action_and_reaches_the_output(self) -> None:
        for code in (1, 2, 3, 70, 130, 143):
            with self.subTest(code=code):
                run, _, _ = self.invoke(exit_code=code, config="c.json")
                self.assertTrue(run.failed)
                self.assertEqual(run.returncode, code, run.log)
                self.assertEqual(run.outputs["exit-code"], str(code))
                self.assertEqual(run.steps[0].outcome, "success",
                                 "outputs must come from a step that completed")
        run, _, _ = self.invoke(exit_code=0, config="c.json")
        self.assertFalse(run.failed, run.log)
        self.assertEqual(run.outputs["exit-code"], "0")

    def test_70_and_143_say_what_they_are(self) -> None:
        run, _, _ = self.invoke(exit_code=70, config="c.json")
        self.assertTrue(any("exited 70" in a and "not a finding" in a for a in run.annotations()),
                        run.log)
        run, _, _ = self.invoke(exit_code=143, config="c.json")
        self.assertTrue(any("exited 143" in a and "SIGTERM" in a for a in run.annotations()),
                        run.log)

    def test_3_names_the_causes_of_the_mode_that_ran(self) -> None:
        """In drift mode, 3 is `map`'s: no cell measured in both runs (a
        baseline recorded while the target was down), a grid that measured
        nothing, or an unmeasured cell under require-complete. The annotation
        listed run mode's causes -- an unclean teardown, an unauthenticated
        identity -- which a drift step cannot have."""
        run, _, _ = self.invoke(exit_code=3, config="c.json")
        (run_text,) = [a for a in run.annotations() if "exited 3" in a]
        for cause in ("an unanswered probe", "nothing answered at all",
                      "an unauthenticated identity", "an unclean teardown"):
            self.assertIn(cause, run_text)
        self.assertNotIn("baseline", run_text)
        run, _, _ = self.invoke(exit_code=3, mode="drift", config="c.json", openapi="s.json",
                                **{"matrix-baseline": self.baseline_file()})
        self.assertEqual(run.returncode, 3, run.log)
        (drift_text,) = [a for a in run.annotations() if "exited 3" in a]
        for cause in ("no cell was measured in both this run and the baseline",
                      "recorded while the target was down",
                      "this run's matrix measured nothing", "require-complete"):
            self.assertIn(cause, drift_text)
        for cause in ("teardown", "unauthenticated identity"):
            self.assertNotIn(cause, drift_text)

    def test_3_in_drift_mode_does_not_say_nothing_changed(self) -> None:
        """REGRESSION. The annotation opened "no drift was found" while the
        same step's drift report listed 12 changes: a baseline recorded with
        the target down, compared with a live one, gains a measurement on every
        cell, and `map` exits 3 because no cell was measured in both. Exit 3
        also follows narrowing changes under `opened` with require-complete.
        What 3 does say is that the gate did not fire."""
        run, _, _ = self.invoke(exit_code=3, mode="drift", config="c.json", openapi="s.json",
                                **{"matrix-baseline": self.baseline_file()})
        (drift_text,) = [a for a in run.annotations() if "exited 3" in a]
        self.assertNotIn("no drift", drift_text.lower())
        self.assertIn("the drift gate did not fire", drift_text)
        self.assertIn("Changes may still be listed", drift_text)
        # Control: run mode's 3 is a different sentence and keeps its own claim.
        run, _, _ = self.invoke(exit_code=3, config="c.json")
        (run_text,) = [a for a in run.annotations() if "exited 3" in a]
        self.assertIn("the security gate passed", run_text)

    def test_the_documents_default_to_a_fresh_scratch_directory(self) -> None:
        run, _, _ = self.invoke(config="c.json", openapi="s.json", documents={
            "--json": {"run_id": "r", "findings": [], "summary": {}}, "--sarif": {"runs": []},
            "--coverage": {"coverage": 0.5, "status": "measured"}, "--report": "report\n"})
        scratch = Path(run.outputs["run-json"]).parent
        self.assertRegex(scratch.name, r"^veridor-action\.")
        self.assertEqual(Path(run.outputs["coverage-json"]).parent, scratch)
        self.assertEqual(Path(run.outputs["junit"]).parent, scratch)
        self.assertEqual(Path(run.outputs["markdown"]).parent, scratch)
        self.assertEqual(run.outputs["sarif"], "veridor.sarif")
        self.assertEqual(run.outputs["version"], "0.0.0-stub")

    def test_the_counts_and_gate_come_from_the_run_document(self) -> None:
        document = {
            "run_id": "20260803T000000Z-abc123",
            "findings": [{"a": 1}, {"b": 2}, {"c": 3}],
            "summary": {"new": 2, "vulnerable": 1, "inconclusive": 1},
            "gate": {"exit_code": 1, "reasons": [{"code": "findings", "exit_code": 1}]},
        }
        run, _, _ = self.invoke(exit_code=1, config="c.json", json="run.json",
                                documents={"--json": document})
        self.assertEqual(run.outputs["run-id"], "20260803T000000Z-abc123")
        self.assertEqual(run.outputs["findings"], "3")
        self.assertEqual(run.outputs["findings-new"], "2")
        self.assertEqual(run.outputs["findings-vulnerable"], "1")
        self.assertEqual(run.outputs["findings-inconclusive"], "1")
        self.assertEqual(run.outputs["gate-exit-code"], "1")
        self.assertEqual(json.loads(run.outputs["gate-reasons"]),
                         [{"code": "findings", "exit_code": 1}])

    def test_a_document_older_than_the_step_is_not_reported(self) -> None:
        """A caller's `json:` path can hold an EARLIER step's run. If this one
        is refused before writing, that file must not be read as its result."""
        stale = self.workspace / "run.json"
        stale.write_text(json.dumps({"run_id": "stale", "findings": [], "summary": {}}),
                         encoding="utf-8")
        old = time.time() - 60
        os.utime(stale, (old, old))
        run, _, _ = self.invoke(exit_code=2, config="c.json", json="run.json")
        self.assertNotIn("run-id", {k for k, v in run.outputs.items() if v})
        self.assertIn("exited 2 before it wrote a run document", run.summary)
        # Control: the same file written during the step IS read.
        run, _, _ = self.invoke(exit_code=0, config="c.json", json="run.json",
                                documents={"--json": {"run_id": "fresh", "findings": [],
                                                      "summary": {}}})
        self.assertEqual(run.outputs["run-id"], "fresh")

    def test_a_stale_document_is_not_reported_whatever_its_mtime(self) -> None:
        """fresh() compared mtimes: a document at or after the step's start
        counted as this step's. One an earlier step wrote in the same second,
        on a filesystem with one-second mtimes, or with a clock ahead of this
        one, passed. Simulated here with an mtime 30 s ahead."""
        stale = self.workspace / "run.json"

        def plant() -> None:
            stale.write_text(json.dumps({"run_id": "stale", "findings": [], "summary": {}}), encoding="utf-8")
            ahead = time.time() + 30
            os.utime(stale, (ahead, ahead))

        plant()
        run, _, _ = self.invoke(exit_code=2, config="c.json", json="run.json")
        self.assertNotIn("run-id", {k for k, v in run.outputs.items() if v}, run.log)
        self.assertIn("exited 2 before it wrote a run document", run.summary)
        # Control: a document written during the step over that same file IS
        # read, although the stale file's mtime is later than the new one's.
        plant()
        run, _, _ = self.invoke(exit_code=0, config="c.json", json="run.json",
                                documents={"--json": {"run_id": "fresh", "findings": [], "summary": {}}})
        self.assertEqual(run.outputs["run-id"], "fresh")

    def test_a_path_output_names_only_a_file_this_step_wrote(self) -> None:
        """A refusal (exit 2) writes nothing, and the step used to emit every
        path output anyway. A workflow that uploads `outputs.sarif` after a
        refusal then uploaded whatever an earlier step had left at that path,
        as this run's SARIF. Now a path output is set only when this step's
        Veridor wrote the file there."""
        paths = ("run-json", "sarif", "junit", "markdown", "coverage-json")
        (self.workspace / "veridor.sarif").write_text('{"stale": true}', encoding="utf-8")
        (self.workspace / "run.json").write_text('{"run_id": "stale"}', encoding="utf-8")
        run, _, _ = self.invoke(exit_code=2, config="c.json", openapi="s.json", json="run.json")
        self.assertEqual({name: run.outputs.get(name, "") for name in paths}, dict.fromkeys(paths, ""), run.log)
        # Control: the same step, with Veridor writing each file, emits each.
        run, _, _ = self.invoke(exit_code=0, config="c.json", openapi="s.json", json="run.json", documents={
            "--json": {"run_id": "r", "findings": [], "summary": {}}, "--sarif": {"runs": []},
            "--coverage": {"coverage": 0.5, "status": "measured"}, "--report": "written by this step\n"})
        self.assertEqual(run.outputs["sarif"], "veridor.sarif")
        self.assertEqual(run.outputs["run-json"], "run.json")
        for name in paths:
            with self.subTest(output=name):
                self.assertTrue(run.outputs[name] and Path(self.workspace, run.outputs[name]).is_file(), run.log)

    def test_a_drift_path_output_names_only_a_file_this_step_wrote(self) -> None:
        run, _, _ = self.invoke(exit_code=2, mode="drift", config="c.json", openapi="s.json",
                                **{"matrix-baseline": self.baseline_file()})
        self.assertEqual({name: run.outputs.get(name, "") for name in ("drift-json", "markdown", "coverage-json")},
                         {"drift-json": "", "markdown": "", "coverage-json": ""}, run.log)
        run, _, _ = self.invoke(mode="drift", config="c.json", openapi="s.json",
                                documents={"--drift": {"changes": [], "significant": 0, "blind_cells": 0},
                                           "--coverage": {"coverage": 0.5, "status": "measured"}},
                                **{"matrix-baseline": self.baseline_file()})
        for name in ("drift-json", "markdown", "coverage-json"):
            with self.subTest(output=name):
                self.assertTrue(run.outputs[name] and Path(run.outputs[name]).is_file(), run.log)

    def test_an_unreadable_document_fails_the_step(self) -> None:
        """Fail closed: the counts are read from the document, and one that
        does not parse is a defect, not a pass with blank outputs."""
        run, _, _ = self.invoke(exit_code=0, config="c.json",
                                documents={"--json": "{not json"})
        self.assertTrue(run.failed, run.log)
        self.assertNotEqual(run.outputs["exit-code"], "0")
        self.assertTrue(any("action's own script failed" in a for a in run.annotations()))

    def test_every_declared_output_is_emitted_by_some_run(self) -> None:
        run_doc = {"run_id": "r", "findings": [], "summary": {"new": 0, "vulnerable": 0,
                                                              "inconclusive": 0},
                   "gate": {"exit_code": 0, "reasons": []}}
        coverage = {"coverage": 0.5, "status": "measured"}
        drift = {"changes": [], "significant": 0, "blind_cells": 0}
        emitted = set()
        run, _, _ = self.invoke(config="c.json", openapi="s.json",
                                documents={"--json": run_doc, "--coverage": coverage, "--sarif": {"runs": []},
                                           "--report": "report\n"})
        emitted |= {name for name, value in run.outputs.items() if value != ""}
        run, _, _ = self.invoke(mode="drift", config="c.json", openapi="s.json",
                                documents={"--drift": drift, "--coverage": coverage},
                                **{"matrix-baseline": self.baseline_file()})
        emitted |= {name for name, value in run.outputs.items() if value != ""}
        self.assertEqual(set(OUTPUTS) - emitted, set())

    def test_the_summary_is_appended_and_never_replaced(self) -> None:
        run, _, calls = self.invoke(config="c.json", documents={"--json": {
            "run_id": "r", "findings": [], "summary": {}}})
        self.assertTrue(run.summary.startswith("line written by an earlier step\n"), run.summary)
        self.assertIn("stub markdown for markdown", run.summary)
        self.assertIn(["report", "--from-run"], [call[:2] for call in calls])

    def test_summary_false_writes_nothing(self) -> None:
        run, _, _ = self.invoke(config="c.json", summary="false", documents={"--json": {
            "run_id": "r", "findings": [], "summary": {}}})
        self.assertEqual(run.summary, "line written by an earlier step\n")

    def test_the_verdict_step_fails_closed_on_a_missing_code(self) -> None:
        """Run the real verdict step behind a first step that writes a given
        exit-code, including none at all."""
        verdict = "\n".join("        " + line for line in VERDICT["run"].splitlines())
        for written, expected in (("", 1), ("exit-code=\n", 1), ("exit-code=abc\n", 1),
                                  ("exit-code=0\n", 0), ("exit-code=3\n", 3)):
            with self.subTest(written=written):
                action = self.tmp / f"verdict-{expected}-{abs(hash(written))}"
                action.mkdir()
                (action / "action.yml").write_text(
                    "name: verdict\ndescription: verdict step alone\nruns:\n  using: composite\n"
                    "  steps:\n    - id: veridor\n      shell: bash\n      run: |\n"
                    f"        printf '{written.encode('unicode_escape').decode()}' >> \"$GITHUB_OUTPUT\"\n"
                    "    - shell: bash\n      env:\n"
                    "        VERIDOR_EXIT_CODE: ${{ steps.veridor.outputs.exit-code }}\n"
                    f"      run: |\n{verdict}\n",
                    encoding="utf-8")
                run = self.run_action({}, action_dir=action)
                self.assertEqual(run.returncode, expected, run.log)


class _DemoServers:
    """The vulnerable and fixed demo APIs, on ephemeral loopback ports."""

    def __init__(self) -> None:
        from scripts.demo_server import create_server  # noqa: PLC0415

        self.servers = {}
        for name, vulnerable in (("vulnerable", True), ("fixed", False)):
            server = create_server("127.0.0.1", 0, vulnerable=vulnerable)
            loopback.start(server)
            self.servers[name] = server

    def url(self, name: str) -> str:
        return f"http://127.0.0.1:{self.servers[name].server_address[1]}"

    def close(self) -> None:
        for server in self.servers.values():
            server.shutdown()
            server.server_close()


@slow("runs action.yml with the real package against loopback demo servers")
class ActionEndToEndTest(_ActionCase):
    """What a workflow sees from `uses: Veridor-authz/veridor@...`, end to end."""

    CONFIG = str(ROOT / "fixtures" / "veridor.demo.json")

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.demo = _DemoServers()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.demo.close()

    def gate(self, target: str, *, action_dir: Path | None = None, **inputs: str):
        url = self.demo.url(target) if target in ("vulnerable", "fixed") else target
        return self.run_action({"config": self.CONFIG, "base-url": url, **inputs},
                               action_dir=action_dir)

    def assert_vulnerable_run(self, run) -> None:
        """Everything a workflow relies on after a failing gate."""
        self.assertTrue(run.failed, run.log)
        self.assertEqual(run.returncode, 1, run.log)
        self.assertEqual(run.outputs["exit-code"], "1")
        self.assertEqual(run.outputs["findings-vulnerable"], "1")
        self.assertEqual(run.outputs["gate-exit-code"], "1")
        self.assertEqual([reason["code"] for reason in json.loads(run.outputs["gate-reasons"])],
                         ["findings"])
        self.assertTrue(run.summary.startswith("line written by an earlier step\n"))
        self.assertIn("**Gate failed (exit 1)", run.summary)

    def test_a_vulnerable_target_fails_the_step_with_exit_1(self) -> None:
        run = self.gate("vulnerable")
        self.assert_vulnerable_run(run)
        __version__ = re.search(r'__version__ = "([^"]+)"', (ROOT / "src" / "veridor" / "__init__.py").read_text(encoding="utf-8")).group(1)
        self.assertEqual(run.outputs["version"], __version__)
        self.assertIn(f"Veridor {__version__} from ", run.log)
        # The reports exist and parse.
        ElementTree.parse(run.outputs["junit"])
        self.assertIn("Gate failed (exit 1)",
                      Path(run.outputs["markdown"]).read_text(encoding="utf-8"))
        self.assertEqual(Path(run.outputs["run-json"]).is_file(), True)

    def test_the_sarif_is_valid_and_carries_the_automation_category(self) -> None:
        run = self.gate("vulnerable")
        sarif = json.loads((self.workspace / run.outputs["sarif"]).read_text(encoding="utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif", sarif["$schema"])
        (only,) = sarif["runs"]
        self.assertEqual(only["automationDetails"]["id"], f"veridor/{run.outputs['run-id']}")
        self.assertEqual(only["tool"]["driver"]["name"], "Veridor")
        self.assertEqual(len(only["results"]), 1)
        result = only["results"][0]
        self.assertIn("veridorFindingId/v1", result["partialFingerprints"])
        self.assertIn(result["ruleId"], {rule["id"] for rule in only["tool"]["driver"]["rules"]})

    def test_a_fixed_target_passes(self) -> None:
        run = self.gate("fixed")
        self.assertFalse(run.failed, run.log)
        self.assertEqual(run.outputs["exit-code"], "0")
        self.assertEqual(run.outputs["gate-exit-code"], "0")
        self.assertEqual(run.outputs["gate-reasons"], "[]")
        self.assertIn("Gate passed (exit 0)", run.summary)

    def test_an_unreachable_target_exits_3_not_0(self) -> None:
        # Not a port from bind(0): released, the kernel can hand that to another
        # process -- a parallel shard's server -- before the gate connects.
        run = self.gate(f"http://127.0.0.1:{loopback.unallocated_port()}")
        self.assertEqual(run.returncode, 3, run.log)
        self.assertEqual(run.outputs["exit-code"], "3")
        self.assertIn("nothing_answered",
                      [reason["code"] for reason in json.loads(run.outputs["gate-reasons"])])
        self.assertIn("Gate incomplete (exit 3)", run.summary)

    def test_a_bad_boolean_is_refused_before_veridor_runs(self) -> None:
        run = self.gate("vulnerable", **{"read-only": "yes"})
        self.assertEqual(run.returncode, 2, run.log)
        self.assertEqual(run.outputs["exit-code"], "2")
        self.assertIn("input read-only must be true or false", "\n".join(run.annotations()))
        self.assertEqual(run.outputs["run-id"], "")

    def test_python_older_than_3_11_is_refused_by_name(self) -> None:
        stubs = self.tmp / "py310"
        stubs.mkdir()
        for name in ("python3", "python"):
            stub = stubs / name
            stub.write_text("#!/bin/sh\necho 3.10.14\n", encoding="utf-8")
            stub.chmod(0o755)
        run = self.run_action({"config": self.CONFIG},
                              path=[str(stubs), "/usr/bin", "/bin"])
        self.assertEqual(run.returncode, 2, run.log)
        message = "\n".join(run.annotations())
        self.assertIn("needs Python 3.11 or newer", message)
        self.assertIn("python3 3.10.14", message)
        self.assertIn("actions/setup-python", message)

    def _plant_decoy(self) -> None:
        decoy = self.workspace / "veridor"
        decoy.mkdir()
        (decoy / "__init__.py").write_text('__version__ = "decoy"\n', encoding="utf-8")
        (decoy / "__main__.py").write_text("print('DECOY RAN')\nraise SystemExit(0)\n",
                                           encoding="utf-8")

    def test_a_veridor_directory_in_the_workspace_does_not_shadow_the_package(self) -> None:
        """This repository has its own veridor/ under src/, and a consumer's
        repository may have one at its root. The action runs with the
        workspace as its working directory, and `python -m` puts that first on
        sys.path unless -P says not to."""
        self._plant_decoy()
        run = self.gate("vulnerable")
        self.assert_vulnerable_run(run)
        self.assertNotIn("DECOY RAN", run.log)
        self.assertNotEqual(run.outputs["version"], "decoy")

    def test_control_without_minus_p_the_decoy_does_shadow(self) -> None:
        """The probe above could pass for a reason other than -P. It cannot:
        the same interpreter, PYTHONPATH and working directory run the decoy
        as soon as -P is dropped."""
        self._plant_decoy()
        env = {"PYTHONPATH": str(ROOT / "src"), "PATH": os.environ.get("PATH", "")}
        without = subprocess.run([sys.executable, "-m", "veridor", "--version"],
                                 cwd=self.workspace, env=env, capture_output=True, text=True)
        with_p = subprocess.run([sys.executable, "-P", "-m", "veridor", "--version"],
                                cwd=self.workspace, env=env, capture_output=True, text=True)
        self.assertIn("DECOY RAN", without.stdout)
        self.assertNotIn("DECOY RAN", with_p.stdout)
        self.assertIn("veridor", with_p.stdout)
        # And the action itself, with -P removed from every invocation, no
        # longer produces the result above.
        mutated = self.action_copy(ACTION_TEXT.replace(" -P ", " "))
        self.assertNotEqual(mutated.joinpath("action.yml").read_text(), ACTION_TEXT)
        run = self.gate("vulnerable", action_dir=mutated)
        with self.assertRaises(AssertionError):
            self.assert_vulnerable_run(run)
        self.assertEqual(run.outputs["exit-code"], "2")
        self.assertIn("did not load from this action's checkout", run.log)

    def test_control_an_action_that_swallows_the_exit_code_fails_this_suite(self) -> None:
        """Two ways to lose Veridor's verdict; each must turn the vulnerable
        scenario's assertion red."""
        swallowed_verdict = ACTION_TEXT.replace('exit "$code"\n', "exit 0\n")
        swallowed_status = ACTION_TEXT.replace("status=$?\n", "status=0\n")
        for label, text in (("verdict step exits 0", swallowed_verdict),
                            ("status forced to 0", swallowed_status)):
            with self.subTest(mutation=label):
                self.assertNotEqual(text, ACTION_TEXT, "the mutation did not apply")
                run = self.gate("vulnerable", action_dir=self.action_copy(text))
                with self.assertRaises(AssertionError):
                    self.assert_vulnerable_run(run)
                self.assertFalse(run.failed, "the mutant still failed the job")

    MAP_CONFIG = str(ROOT / "fixtures" / "veridor.map-demo.json")
    OPENAPI = str(ROOT / "fixtures" / "openapi.demo.json")

    def drift(self, *, src: Path | None = None):
        """Drift mode against the vulnerable server, from a baseline the real
        `veridor map` recorded against the fixed one."""
        baseline = self.workspace / "baseline.json"
        recorded = subprocess.run(
            [sys.executable, "-P", "-m", "veridor", "map", "--config", self.MAP_CONFIG, "--openapi", self.OPENAPI,
             "--base-url", self.demo.url("fixed"), "--matrix", str(baseline),
             "--output-dir", str(self.tmp / "baseline-run")],
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, capture_output=True, text=True)
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        return self.run_action({"mode": "drift", "config": self.MAP_CONFIG, "openapi": self.OPENAPI,
                                "base-url": self.demo.url("vulnerable"), "matrix-baseline": str(baseline)},
                               action_dir=self.action_copy(src=src))

    def assert_drift_outputs(self, run) -> None:
        """The drift-* outputs a workflow reads, from the document drift.py
        wrote. action.yml reads its keys with .get() and writes nothing for a
        missing one, so a key drift.py stops writing blanks the output while
        the exit code stays right."""
        self.assertEqual(run.returncode, 1, run.log)
        self.assertEqual(run.outputs["exit-code"], "1")
        for name in ("drift-changes", "drift-significant", "drift-blind-cells"):
            self.assertRegex(run.outputs.get(name, ""), r"^[0-9]+$",
                             f"{name} is empty: action.yml reads a key the drift document does not carry")
        document = json.loads(Path(run.outputs["drift-json"]).read_text(encoding="utf-8"))
        self.assertEqual(run.outputs["drift-changes"], str(len(document["changes"])))
        self.assertEqual(run.outputs["drift-significant"], str(document.get("significant")))
        self.assertEqual(run.outputs["drift-blind-cells"], str(document.get("blind_cells")))
        # The vulnerable target widens access, and the baseline leaves cells
        # unmeasured, so a constant 0 cannot pass for either.
        self.assertNotEqual(run.outputs["drift-significant"], "0")
        self.assertNotEqual(run.outputs["drift-blind-cells"], "0")

    def test_drift_mode_with_the_real_package_fills_every_drift_output(self) -> None:
        """Every other drift-mode test runs a stub that writes the JSON the
        test hands it, so nothing held action.yml's keys to drift.py's."""
        self.assert_drift_outputs(self.drift())

    def test_control_a_renamed_drift_key_blanks_its_output(self) -> None:
        """A rename made consistently inside the package, so test_drift and
        the package's own readers would follow it, passed every other test
        in this file while drift-blind-cells went empty."""
        mutant = self.tmp / "renamed-src"
        shutil.copytree(ROOT / "src", mutant)
        for relative in ("veridor/drift.py", "veridor/reports/markdown.py"):
            path = mutant / relative
            text = path.read_text(encoding="utf-8")
            renamed = re.sub(r"""(["'])blind_cells\1""", r"\1blind_cell_count\1", text)
            self.assertNotEqual(renamed, text, f"the mutation did not apply to {relative}")
            path.write_text(renamed, encoding="utf-8")
        run = self.drift(src=mutant)
        self.assertEqual(run.returncode, 1, run.log)
        self.assertEqual(run.outputs.get("drift-blind-cells", ""), "")
        with self.assertRaises(AssertionError):
            self.assert_drift_outputs(run)


@slow("runs shellcheck on every run: block of action.yml")
class ActionShellcheckTest(unittest.TestCase):
    """shellcheck every step script. Skips without shellcheck unless
    VERIDOR_REQUIRE_SHELLCHECK=1, which CI sets so the check cannot vanish."""

    def setUp(self) -> None:
        if shutil.which("shellcheck") is None:
            if os.environ.get("VERIDOR_REQUIRE_SHELLCHECK") == "1":
                self.fail("shellcheck is not on PATH and VERIDOR_REQUIRE_SHELLCHECK=1")
            self.skipTest("shellcheck is not on PATH (VERIDOR_REQUIRE_SHELLCHECK=1 makes this a failure)")

    def shellcheck(self, script: str) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
            handle.write(script)
        self.addCleanup(os.unlink, handle.name)
        return subprocess.run(["shellcheck", "--shell=bash", "--severity=style", handle.name],
                              capture_output=True, text=True, timeout=120)

    def test_every_run_block_is_clean(self) -> None:
        for step in STEPS:
            with self.subTest(step=step.get("name")):
                result = self.shellcheck(step["run"])
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_control_shellcheck_flags_a_known_bad_script(self) -> None:
        result = self.shellcheck('value=$1\nrm $value\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SC2086", result.stdout)


@slow("runs ruby to cross-check the harness YAML parser")
class YAMLParserAgreementTest(unittest.TestCase):
    """The harness parser against an independent YAML implementation.

    Ruby's Psych is on GitHub's ubuntu and macOS images; without ruby this
    skips, and says so -- it is a cross-check of the test tool, not a gate on
    the product."""

    RUBY = (
        "def norm(x); case x; when Hash then x.map{|k,v| [k.to_s, norm(v)]}.to_h; "
        "when Array then x.map{|v| norm(v)}; when nil then nil; else x.to_s; end; end; "
        "puts JSON.generate(norm(YAML.safe_load(STDIN.read)))"
    )

    def setUp(self) -> None:
        if shutil.which("ruby") is None:
            self.skipTest("ruby is not on PATH")

    def ruby(self, text: str):
        result = subprocess.run(["ruby", "-ryaml", "-rjson", "-e", self.RUBY], input=text,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_action_yml_parses_identically(self) -> None:
        self.assertEqual(load_yaml(ACTION_TEXT), self.ruby(ACTION_TEXT))

    def test_control_a_changed_document_compares_different(self) -> None:
        changed = ACTION_TEXT.replace("name: Run Veridor", "name: Run Veridor!", 1)
        self.assertNotEqual(changed, ACTION_TEXT)
        self.assertNotEqual(load_yaml(changed), self.ruby(ACTION_TEXT))


if __name__ == "__main__":
    unittest.main()
