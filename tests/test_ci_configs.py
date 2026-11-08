"""The CI configurations Veridor ships: the GitLab component and ci/*.

None of these has run on its own platform: there is no GitLab runner, Jenkins
controller, Azure agent or CodeBuild project attached to this repository.
What can rot without one is checked here, against the real code:

* templates/veridor.yml is rendered the way GitLab renders a component
  (tests/ci_validate.py): typed inputs, options, regexes, every input declared
  and used, the `extends` pairs that stand in for conditional keys.
* Every ``veridor`` command line in every shipped file -- the rendered
  component, the Jenkinsfile, the Azure pipeline, the buildspec -- is pulled
  out of the shell those files run and parsed by the CLI's own parser.
* The shell around the gate never swallows an exit code, names 70 and 143, and
  exits with Veridor's code; the report paths it writes are the ones the
  platform is told to collect.

Each assertion has a control beside it, run on a deliberately broken copy, so
a check that could not fail is noticed. What only a real platform can show
(GitLab rendering, Jenkins' Groovy, Azure's task.complete, CodeBuild's report
groups) is listed as UNTESTED in ci/README.md. scripts/e2e_gitlab_job.sh runs
the rendered GitLab job in docker; the slow tests here check its refusals.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

sys.path.insert(0, str(ROOT))
from scripts import release_check  # noqa: E402
import ci_validate as cv  # noqa: E402
import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import cli, core  # noqa: E402
from yaml_subset import load_yaml, load_yaml_documents  # noqa: E402

E2E_SCRIPT = ROOT / "scripts" / "e2e_gitlab_job.sh"
CI_README = ROOT / "ci" / "README.md"
README = ROOT / "README.md"

#: The exit codes every config must name: Veridor's full set.
EXIT_CODES = {0, 1, 2, 3, 70, 130, 143}
REQUIRE_SHELLCHECK_ENV = "VERIDOR_REQUIRE_SHELLCHECK"

#: Flags the component sets from its own inputs, which extra_args must not
#: override.
OWNED_FLAGS = ("--config", "--output-dir", "--json", "--fail-on", "--base-url", "--baseline", "--openapi",
               "--wait-for-target")


def component_text() -> str:
    return cv.COMPONENT.read_text(encoding="utf-8")


def rendered_job(text: str | None = None, given: dict[str, Any] | None = None) -> tuple[dict, dict, dict]:
    """(inputs, document, resolved gate job) of the component."""
    inputs, body = cv.render_component(component_text() if text is None else text, given)
    return inputs, body, cv.resolve_job(body, cv.gate_job_name(body))


def component_shell_and_variables(given: dict[str, Any] | None = None) -> tuple[str, dict[str, str]]:
    inputs, _, job = rendered_job(given=given)
    values = {name: (given or {}).get(name, definition.get("default")) for name, definition in inputs.items()}
    variables = {
        "out": values["output_dir"],
        # The worst case: every optional input present.
        "base_url": "https://staging.example.com",
        "baseline": "veridor-baseline.json",
        "openapi": "openapi.json",
        "wait_for_target": str(values["wait_for_target"]),
        "STAGING_URL": "https://staging.example.com",
    }
    return cv.job_shell(job), variables


def jenkins_shell() -> str:
    blocks = cv.jenkins_shell_blocks(cv.JENKINSFILE.read_text(encoding="utf-8"))
    if len(blocks) != 1:
        raise AssertionError(f"expected one ''' shell block in the Jenkinsfile, found {len(blocks)}")
    return blocks[0]


def azure_document() -> dict[str, Any]:
    return load_yaml(cv.AZURE)


def buildspec_document() -> dict[str, Any]:
    return load_yaml(cv.BUILDSPEC)


#: Sample values for the platform shells' variables. The gating ones,
#: VERIDOR_FAIL_ON and the allow-unmeasured switch, are NOT here: they come
#: from each shipped file (platform_gating_defaults). They used to be
#: supplied here, so a Jenkinsfile, Azure pipeline or buildspec that shipped
#: `none` left every test green (measured).
PLATFORM_VARIABLES = {
    "VERIDOR_CONFIG": "veridor.json",
    "VERIDOR_BASE_URL": "https://staging.example.com",
    "VERIDOR_BASELINE": "veridor-baseline.json",
    "VERIDOR_OUTPUT_DIR": "out/veridor",
    "out": "veridor-out",
}

#: What each platform template must ship: the gate fails on new or confirmed
#: findings, and exit 3 fails the build unless someone opts in. CodeBuild has
#: no warning state, so no switch.
SHIPPED_GATING = {
    "jenkins": {"fail_on": "new+confirmed", "allow_unmeasured": "false"},
    "azure": {"fail_on": "new+confirmed", "allow_unmeasured": "false"},
    "codebuild": {"fail_on": "new+confirmed", "allow_unmeasured": None},
}


def _single(pattern: str, text: str, what: str) -> str:
    found = re.findall(pattern, text, re.M)
    if len(found) != 1:
        raise AssertionError(f"expected exactly one {what}, found {found}")
    return found[0]


def platform_gating_defaults(jenkinsfile: str, azure: str, buildspec: str) -> dict[str, dict[str, str | None]]:
    """``{platform: {"fail_on", "allow_unmeasured"}}`` as each file ships them.

    Jenkins: the ``environment`` entries (an entry wins over a build
    parameter of the same name, measured). Azure: the gate step's ``env``
    value when it sets the name (so a hard-coded env value is read too), else
    the ``variables:`` block. CodeBuild: ``env.variables``. Booleans are
    lower-case text."""
    def text(value: Any) -> str:
        return ("true" if value else "false") if isinstance(value, bool) else str(value)

    azure_doc = load_yaml_documents(azure)[0]
    raw = azure_doc.get("variables") or {}
    variables = {v.get("name"): v.get("value") for v in raw} if isinstance(raw, list) else dict(raw)
    gate_step = next(s for s in cv.azure_steps(azure_doc) if "bash" in s and "veridor run" in s["bash"])

    def azure_env(name: str) -> str:
        env = gate_step.get("env") or {}
        return text(env[name] if name in env else variables[name])

    return {
        "jenkins": {
            "fail_on": _single(r"^\s*VERIDOR_FAIL_ON\s*=\s*'([^']*)'", jenkinsfile, "VERIDOR_FAIL_ON"),
            "allow_unmeasured": _single(r"^\s*VERIDOR_ALLOW_UNMEASURED\s*=\s*'([^']*)'",
                                        jenkinsfile, "VERIDOR_ALLOW_UNMEASURED environment entry"),
        },
        "azure": {"fail_on": azure_env("VERIDOR_FAIL_ON"), "allow_unmeasured": azure_env("VERIDOR_ALLOW_UNMEASURED")},
        "codebuild": {"fail_on": text(load_yaml_documents(buildspec)[0]["env"]["variables"]["VERIDOR_FAIL_ON"]),
                      "allow_unmeasured": None},
    }


def shipped_gating() -> dict[str, dict[str, str | None]]:
    return platform_gating_defaults(*(p.read_text(encoding="utf-8") for p in (cv.JENKINSFILE, cv.AZURE, cv.BUILDSPEC)))


def platform_variables(platform: str) -> dict[str, str]:
    """PLATFORM_VARIABLES plus the gating values the platform's file ships."""
    return dict(PLATFORM_VARIABLES, VERIDOR_FAIL_ON=str(shipped_gating()[platform]["fail_on"]))


def shipped_shells() -> dict[str, tuple[str, dict[str, str]]]:
    """Every shell that runs the gate, with sample values for its variables."""
    azure_variables = dict(platform_variables("azure"), out=PLATFORM_VARIABLES["VERIDOR_OUTPUT_DIR"])
    return {
        "gitlab (defaults)": component_shell_and_variables(),
        "gitlab (every input changed)": component_shell_and_variables(cv.NON_DEFAULT_INPUTS),
        "jenkins": (jenkins_shell(), platform_variables("jenkins")),
        "azure": (cv.azure_shell(azure_document()), azure_variables),
        "codebuild": (cv.codebuild_shell(buildspec_document()), platform_variables("codebuild")),
    }


def parse_argv(argv: list[str]) -> argparse.Namespace:
    """Parse with the real CLI parser; argparse's exit becomes an AssertionError."""
    if argv[:1] != ["veridor"]:
        raise AssertionError(f"not a veridor command: {argv}")
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            return cli._parser().parse_args(argv[1:])
    except SystemExit as exc:
        raise AssertionError(f"the CLI refuses {argv}: {stderr.getvalue().strip()}") from exc


def gate_invocations(shell: str, variables: dict[str, str]) -> list[argparse.Namespace]:
    return [parse_argv(argv) for argv in cv.veridor_commands(shell, variables)]


# ---------------------------------------------------------------------------
# The GitLab component, rendered
# ---------------------------------------------------------------------------


class ComponentRenderTest(unittest.TestCase):
    def test_defaults_render_the_gate_job(self) -> None:
        _, body, job = rendered_job()
        self.assertEqual(cv.gate_job_name(body), "veridor")
        self.assertEqual(job["stage"], "test")
        self.assertEqual(job["image"], {"name": "ghcr.io/veridor-authz/veridor:0.1.0", "entrypoint": [""]})
        self.assertIs(job["allow_failure"], False)
        self.assertEqual(job["retry"], 0)
        self.assertIs(job["interruptible"], True)
        self.assertEqual(job["rules"], [{"when": "on_success"}])
        self.assertEqual(job["artifacts"]["when"], "always")
        self.assertEqual(job["artifacts"]["reports"], {
            "sast": "veridor-out/gl-sast-report.json",
            "junit": "veridor-out/veridor-junit.xml",
            "codequality": "veridor-out/gl-code-quality-report.json",
        })
        self.assertEqual(job["before_script"], ["veridor --version"])

    def test_the_non_default_set_moves_every_input(self) -> None:
        """So the second render exercises every input, and a new one cannot be
        added without being rendered off its default here."""
        inputs, _, job = rendered_job(given=cv.NON_DEFAULT_INPUTS)
        self.assertEqual(set(cv.NON_DEFAULT_INPUTS), set(inputs))
        for name, value in cv.NON_DEFAULT_INPUTS.items():
            with self.subTest(input=name):
                self.assertNotEqual(value, inputs[name].get("default"))
        self.assertEqual(job["image"], "python:3.13-slim")
        self.assertEqual(job["before_script"], [
            'python3 -m pip install --quiet --disable-pip-version-check "dist/veridor-0.1.0-py3-none-any.whl"',
            "veridor --version",
        ])
        self.assertEqual(job["allow_failure"], {"exit_codes": [3]})
        self.assertEqual(job["stage"], "authz")
        self.assertEqual(job["artifacts"]["expire_in"], "1 week")
        self.assertEqual(job["rules"], cv.NON_DEFAULT_INPUTS["job_rules"])
        self.assertTrue(all(p.startswith("reports/veridor/") for p in job["artifacts"]["paths"]))

    def test_the_pip_image_is_the_release_image_s_pinned_base(self) -> None:
        """install: pip runs pip and then the gate, with every credential, in
        python_image. Its default was the tag python:3.12-slim, which the
        registry can move; now the digest the Dockerfile pins. Dependabot
        bumps the Dockerfile's digest (dependabot.yml, docker ecosystem) but
        never reads this YAML, so this test fails that bump until the
        component follows."""
        self.assertEqual(python_image_problems(component_text(), (ROOT / "Dockerfile").read_text(encoding="utf-8")),
                         [])

    def test_control_a_tag_or_a_different_digest_is_named(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        pinned = cv.split_component(component_text())[0]["inputs"]["python_image"]["default"]
        tag = component_text().replace(f'default: "{pinned}"', 'default: "python:3.12-alpine"')
        self.assertNotEqual(tag, component_text(), "the mutation did not apply")
        self.assertEqual(python_image_problems(tag, dockerfile),
                         ["python_image default 'python:3.12-alpine' is not pinned by digest",
                          "python_image default 'python:3.12-alpine' is not the Dockerfile's base "
                          f"{pinned!r}"])
        moved = dockerfile.replace(pinned.split("@sha256:")[1], "0" * 64)
        self.assertNotEqual(moved, dockerfile, "the mutation did not apply")
        self.assertEqual(len(python_image_problems(component_text(), moved)), 1)

    def test_every_option_pair_resolves(self) -> None:
        """Each extends target the inputs can name exists: a missing hidden job
        would be a pipeline GitLab refuses to create."""
        inputs, _, _ = rendered_job()
        for install in inputs["install"]["options"]:
            for allow in (False, True):
                with self.subTest(install=install, allow_unmeasured=allow):
                    _, _, job = rendered_job(given={"install": install, "allow_unmeasured": allow})
                    self.assertIn("image", job)
                    self.assertEqual(job["allow_failure"], {"exit_codes": [3]} if allow else False)

    def test_declared_and_used_inputs_agree(self) -> None:
        spec, body = cv.split_component(component_text())
        self.assertEqual(cv.used_inputs(body), set(cv.check_inputs(spec)))

    def test_the_renderer_refuses_what_gitlab_would(self) -> None:
        """The controls for everything above: each broken variant must fail."""
        text = component_text()
        cases = {
            "misspelt reference": text.replace("$[[ inputs.config ]]", "$[[ inputs.confg ]]", 1),
            "an interpolation function": text.replace("$[[ inputs.config ]]", "$[[ inputs.config | expand_vars ]]", 1),
            "declared, never used": text.replace('"$[[ inputs.artifacts_expire_in ]]"', '"30 days"'),
            "misspelt input key": text.replace("      default: veridor.json", "      defualt: veridor.json"),
            "default outside options": text.replace("      default: new+confirmed", "      default: new-and-confirmed"),
            "default of the wrong type": text.replace("      type: boolean\n      default: false", "      type: boolean\n      default: \"false\""),
            "unterminated block": text.replace("$[[ inputs.stage ]]", "$[[ inputs.stage ]", 1),
        }
        for label, mutated in cases.items():
            with self.subTest(control=label):
                self.assertFalse(mutated == text, "the mutation did not apply")
                with self.assertRaises(cv.ComponentError):
                    cv.render_component(mutated)
        bad_inputs = {
            "unknown input": {"confg": "x.json"},
            "fail_on outside options": {"fail_on": "all"},
            "boolean given as a string": {"require_complete": "yes"},
            "config with a double quote": {"config": 'a"b.json'},
            "base_url with a single quote": {"base_url": "https://x/'"},
            "absolute output_dir": {"output_dir": "/tmp/out"},
            "extra_args with a quote": {"extra_args": "--read-only '--x'"},
            "rules given as a string": {"job_rules": "always"},
        }
        for label, given in bad_inputs.items():
            with self.subTest(control=label), self.assertRaises(cv.ComponentError):
                cv.render_component(text, given)

    def test_allow_failure_is_never_true(self) -> None:
        """`allow_failure: true` would let a finding (exit 1) pass as a warning."""
        for allow in (False, True):
            _, body, _ = rendered_job(given={"allow_unmeasured": allow})
            with self.subTest(allow_unmeasured=allow):
                self.assertEqual(allow_failure_problems(body), [])
        mutated = component_text().replace("  allow_failure:\n    exit_codes: [3]", "  allow_failure: true")
        self.assertFalse(mutated == component_text(), "the mutation did not apply")
        _, body = cv.render_component(mutated, {"allow_unmeasured": True})
        self.assertTrue(allow_failure_problems(body), "control: allow_failure: true went unnoticed")

    def test_a_rule_that_sets_allow_failure_is_noticed(self) -> None:
        """job_rules reaches the job unchecked, and GitLab documents a rule's
        allow_failure as overriding the job's own (rules:allow_failure; not
        observed on GitLab). The check above read only job-level keys, so a
        rule carrying `allow_failure: true`, which would show a finding (exit
        1) as a warning, went unnoticed. The shipped renders carry none."""
        for label, given in (("defaults", None), ("every input changed", cv.NON_DEFAULT_INPUTS)):
            _, body, _ = rendered_job(given=given)
            with self.subTest(render=label):
                self.assertEqual(allow_failure_problems(body), [])
        _, body, _ = rendered_job(given={"job_rules": [{"if": "$CI_COMMIT_TAG", "when": "never"},
                                                       {"when": "on_success", "allow_failure": True}]})
        self.assertEqual(allow_failure_problems(body), ["veridor: rules[1] allow_failure: True"])

    def test_the_docs_name_the_rule_that_can_override_allow_failure(self) -> None:
        """The component cannot check the rules an includer passes, so the
        sentences that say no other exit code may fail must name the one
        place that can make one: a rule's allow_failure in job_rules."""
        self.assertEqual(rule_allow_failure_doc_problems(*shipped_rule_allow_failure_texts()), [])
        component, readme, ci_readme = shipped_rule_allow_failure_texts()
        # Exit 0 passes the job and 130/143 interrupt it; allow_failure decides
        # neither, so the comment names the codes it does reach.
        self.assertIn("every exit code that fails it\n# (1, 2, 3 and 70)", component)
        for label, broken in {
            "README": (component, readme.replace("`job_rules` can still set", "`rules` can still set"), ci_readme),
            "ci/README.md": (component, readme, ci_readme.replace("`job_rules` input", "rules input")),
            # The header line as it stood before it named the rule.
            "header comment": (re.sub(r"allowed to fail;\n(#     .*\n)+", "allowed to fail\n", component), readme, ci_readme),
            # The exit-code list as it stood before it said a rule's
            # allow_failure reaches every exit code, not only exit 3.
            "header comment, every exit code": (
                re.sub(r"\n# \S[^\n]*allow_failure[^\n]*(\n# \S[^\n]*)*?not only exit 3\.", "", component),
                readme, ci_readme),
        }.items():
            with self.subTest(control=label):
                self.assertNotEqual(broken, (component, readme, ci_readme), "the mutation did not apply")
                self.assertTrue(rule_allow_failure_doc_problems(*broken))

    def test_the_render_command_writes_the_job_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shell, job_json = Path(tmp) / "job.sh", Path(tmp) / "job.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = cv.main(["render", "--input", "allow_unmeasured=true", "--input", "base_url=http://t:1",
                                  "--shell", str(shell), "--job-json", str(job_json)])
            self.assertEqual(status, 0)
            self.assertIn('base_url="http://t:1"', shell.read_text())
            self.assertEqual(json.loads(job_json.read_text())["job"]["allow_failure"], {"exit_codes": [3]})
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                refused = cv.main(["render", "--input", "allow_unmeasured=yes",
                                   "--shell", str(shell), "--job-json", str(job_json)])
            self.assertEqual(refused, 2)
            self.assertIn("not true or false", stderr.getvalue())


def python_image_problems(component: str, dockerfile: str) -> list[str]:
    """The component's python_image default must be the digest-pinned base
    both stages of the Dockerfile use."""
    default = cv.split_component(component)[0]["inputs"]["python_image"]["default"]
    bases = set(re.findall(r"(?m)^FROM (\S+)", dockerfile))
    problems = []
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", default):
        problems.append(f"python_image default {default!r} is not pinned by digest")
    if len(bases) != 1:
        problems.append(f"the Dockerfile's stages use {sorted(bases)}, not one base")
    elif default not in bases:
        problems.append(f"python_image default {default!r} is not the Dockerfile's base {next(iter(bases))!r}")
    return problems


#: The default job_rules before this change: merge request pipelines and the
#: default branch.
OLD_DEFAULT_RULES = [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'},
                     {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}]

#: workflow:rules as GitLab ships or documents them. None: no workflow:rules.
WORKFLOWS: dict[str, Any] = {
    "no workflow:rules": None,
    # lib/gitlab/ci/templates/Workflows/Branch-Pipelines.gitlab-ci.yml
    "Branch-Pipelines template": [{"if": "$CI_COMMIT_TAG"}, {"if": "$CI_COMMIT_BRANCH"}],
    # lib/gitlab/ci/templates/Workflows/MergeRequest-Pipelines.gitlab-ci.yml
    "MergeRequest-Pipelines template": [{"if": "$CI_MERGE_REQUEST_IID"}, {"if": "$CI_COMMIT_TAG"},
                                        {"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}],
    # doc/ci/yaml/workflow.md, "Switch between branch pipelines and merge request pipelines"
    "switch between branch and merge request pipelines": [
        {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'},
        {"if": "$CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS", "when": "never"},
        {"if": "$CI_COMMIT_BRANCH"}],
}

#: What a push to a branch with an open merge request can create.
MERGE_REQUEST_PUSH = ("push to a branch with an open merge request", "merge request pipeline")


def gate_runs_for_a_merge_request_push(job_rules: Any, workflow: Any) -> list[str]:
    """The pipelines, among those a push to an open merge request's branch
    creates under ``workflow``, that contain the gate."""
    return [shape for shape in MERGE_REQUEST_PUSH
            if cv.rules_include(workflow, cv.PIPELINE_SHAPES[shape])
            and cv.rules_include(job_rules, cv.PIPELINE_SHAPES[shape])]


class JobRulesTest(unittest.TestCase):
    """Which pipelines the gate job is in, from its rendered rules, evaluated
    with GitLab's rules:if semantics against the variables each kind of
    pipeline has (ci_validate.PIPELINE_SHAPES; read in GitLab's source and
    docs, not observed on GitLab).

    The old default, merge request pipelines and the default branch, left
    the job out of pipelines that ran without it and without a trace: a
    branch pipeline for a merge request's branch (in a project using only
    branch pipelines, the gate never ran before merge), tags, and child and
    multi-project pipelines not on the default branch."""

    def test_the_default_is_in_every_pipeline(self) -> None:
        _, _, job = rendered_job()
        self.assertEqual(cv.pipelines_without(job["rules"]), [])
        self.assertLessEqual({"tag pipeline", "child of a merge request pipeline", "multi-project downstream on another branch",
                              "push to a branch with an open merge request"}, set(cv.PIPELINE_SHAPES))

    def test_control_the_old_default_is_seen_leaving_pipelines_out(self) -> None:
        missing = cv.pipelines_without(OLD_DEFAULT_RULES)
        for shape in ("push to a branch with an open merge request", "tag pipeline",
                      "child of a merge request pipeline", "multi-project downstream on another branch"):
            with self.subTest(left_out=shape):
                self.assertIn(shape, missing)
        for shape in ("merge request pipeline", "push to the default branch"):
            with self.subTest(kept=shape):
                self.assertNotIn(shape, missing)

    def test_the_gate_runs_before_merge_under_every_modelled_workflow(self) -> None:
        _, _, job = rendered_job()
        for name, workflow in WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertTrue(gate_runs_for_a_merge_request_push(job["rules"], workflow))
        self.assertEqual(gate_runs_for_a_merge_request_push(OLD_DEFAULT_RULES, WORKFLOWS["Branch-Pipelines template"]),
                         [], "control: the old default never ran before merge under Branch-Pipelines")

    def test_the_documented_trade_off(self) -> None:
        """What the README and the input description say it costs: two runs
        per push to an open merge request's branch without workflow:rules,
        one with GitLab's switch recipe."""
        _, _, job = rendered_job()
        self.assertEqual(len(gate_runs_for_a_merge_request_push(job["rules"], WORKFLOWS["no workflow:rules"])), 2)
        self.assertEqual(len(gate_runs_for_a_merge_request_push(
            job["rules"], WORKFLOWS["switch between branch and merge request pipelines"])), 1)
        self.assertEqual(cv.pipelines_without([{"if": "$CI_MERGE_REQUEST_ID"}, {"if": "$CI_COMMIT_BRANCH"}]),
                         ["tag pipeline", "child of a tag pipeline"], "the narrower default still omits tags")
        self.assertFalse(cv.rules_include(WORKFLOWS["switch between branch and merge request pipelines"],
                                          cv.PIPELINE_SHAPES["tag pipeline"]), "ci/.gitlab-ci.yml: the recipe stops tags")

    def test_the_example_shows_the_modelled_recipe(self) -> None:
        """The workflow:rules ci/.gitlab-ci.yml prints (commented out) are the
        ones modelled above."""
        example = cv.GITLAB_EXAMPLE.read_text(encoding="utf-8")
        block = re.search(r"(?m)^# workflow:\n((?:#  [^\n]*\n)+)", example)
        self.assertIsNotNone(block, "the recipe is gone from ci/.gitlab-ci.yml")
        text = "workflow:\n" + "".join(line[2:] + "\n" for line in block.group(1).splitlines())
        self.assertEqual(load_yaml_documents(text)[0]["workflow"]["rules"],
                         WORKFLOWS["switch between branch and merge request pipelines"])

    def test_the_evaluator_follows_gitlab(self) -> None:
        variables = {"SET": "x", "EMPTY": ""}
        for expression, expected in (('$SET == "x"', True), ('$SET != "x"', False), ("$UNSET == null", True),
                                     ("$UNSET == $ALSO_UNSET", True), ("$SET == $UNSET", False), ("$EMPTY", False),
                                     ("$UNSET", False), ("$SET && $UNSET", False), ("$UNSET || $SET", True),
                                     ("$EMPTY && $SET", True), ('($SET == "y") || $SET == "x"', True)):
            with self.subTest(expression=expression):
                self.assertIs(cv.rule_if(expression, variables), expected)
        self.assertFalse(cv.rules_include([{"if": "$SET", "when": "never"}, {"when": "on_success"}], variables))
        self.assertFalse(cv.rules_include([], variables), "no rule matched: not in the pipeline")
        for unsupported in ([{"if": "$SET =~ /x/"}], [{"changes": ["a"]}], [{"if": "$SET = 1"}]):
            with self.subTest(unsupported=unsupported), self.assertRaises(cv.ComponentError):
                cv.rules_include(unsupported, variables)


def allow_failure_problems(document: dict[str, Any]) -> list[str]:
    problems = []
    for name, job in document.items():
        if isinstance(job, dict) and "allow_failure" in job:
            value = job["allow_failure"]
            if value is True:
                problems.append(f"{name}: allow_failure: true")
            elif isinstance(value, dict) and value != {"exit_codes": [3]}:
                problems.append(f"{name}: allow_failure {value}")
        # A rule's allow_failure overrides the job's (GitLab's rules:allow_failure).
        rules = job.get("rules") if isinstance(job, dict) else None
        for index, rule in enumerate(rules if isinstance(rules, list) else []):
            if isinstance(rule, dict) and "allow_failure" in rule:
                problems.append(f"{name}: rules[{index}] allow_failure: {rule['allow_failure']}")
    return problems


def shipped_rule_allow_failure_texts() -> tuple[str, str, str]:
    return (component_text(), README.read_text(encoding="utf-8"), CI_README.read_text(encoding="utf-8"))


def header_exit_3_entry(component: str) -> str:
    """The exit-3 entry of the component's header comment, continuation lines
    included (they are indented deeper than the next entry, `#   70`)."""
    lines = component.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"#\s+3 gate passed", line)), None)
    if start is None:
        return ""
    entry = [lines[start]]
    for line in lines[start + 1:]:
        if not re.match(r"#\s{5,}\S", line):
            break
        entry.append(line)
    return " ".join(line.lstrip("#").strip() for line in entry)


def header_exit_codes_notes(component: str) -> str:
    """The lines of the header's exit-code list that belong to no single exit
    code: neither an entry (`#   3 ...`) nor its continuation (`#     ...`)."""
    lines = component.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("# Exit codes, as the job treats them")), None)
    if start is None:
        return ""
    notes = []
    for line in lines[start + 1:]:
        if line.strip() == "#" or not line.startswith("#"):
            break
        if not re.match(r"#\s+\d|#\s{5,}\S", line):
            notes.append(line)
    return " ".join(line.lstrip("#").strip() for line in notes)


def rule_allow_failure_doc_problems(component: str, readme: str, ci_readme: str) -> list[str]:
    """Each place that says only exit 3 may fail must also say that a rule in
    job_rules can set allow_failure, which the component cannot check, and
    the header's exit-code list must say that such a rule reaches every exit
    code, not only exit 3."""
    spec, _ = cv.split_component(component)
    flat = {
        "input allow_unmeasured": spec["inputs"]["allow_unmeasured"].get("description", ""),
        "input job_rules": spec["inputs"]["job_rules"].get("description", ""),
        "header comment, exit 3": header_exit_3_entry(component),
        "header comment, every exit code": " ".join(
            sentence for sentence in re.split(r"(?<=\.)\s+", header_exit_codes_notes(component))
            if "allow_failure" in sentence),
        "README": next((p for p in readme.split("\n\n") if "only exit 3, as a warning" in p), ""),
        "ci/README.md": next((p for p in ci_readme.split("\n\n") if "`allow_failure: true`" in p), ""),
    }
    problems = []
    for where, text in flat.items():
        text = " ".join(text.split())
        if not text:
            problems.append(f"{where}: the allow_failure sentence is gone")
        elif not re.search(r"job_rules\W.*allow_failure|allow_failure.*\Wjob_rules", text) and \
                not (where == "input job_rules" and "allow_failure" in text):
            problems.append(f"{where} does not say a rule in job_rules can set allow_failure")
        elif where == "header comment, every exit code" and not re.search(r"\bevery exit code\b", text):
            problems.append(f"{where} does not say the rule's allow_failure reaches every exit code")
    return problems


# ---------------------------------------------------------------------------
# Every veridor command line, through the real parser
# ---------------------------------------------------------------------------


class VeridorInvocationTest(unittest.TestCase):
    def test_every_command_parses_with_the_real_cli(self) -> None:
        for source, (shell, variables) in shipped_shells().items():
            with self.subTest(source=source):
                commands = gate_invocations(shell, variables)
                self.assertEqual(len(commands), 1, f"{source}: expected one veridor run, found {len(commands)}")
                args = commands[0]
                self.assertEqual(args.command, "run")
                self.assertIsNotNone(args.config)
                self.assertIsNotNone(args.json_path)
                formats = [fmt for fmt, _ in args.reports]
                self.assertIn("junit", formats)
                self.assertEqual(len(formats), len(set(formats)), formats)
                if source.startswith("gitlab"):
                    self.assertEqual(set(formats), {"gitlab-sast", "junit", "codequality", "markdown"})

    def test_the_gate_flags_carry_the_intended_values(self) -> None:
        args = gate_invocations(*component_shell_and_variables())[0]
        self.assertEqual(args.fail_on, "new+confirmed")
        self.assertTrue(args.require_complete)
        self.assertEqual(str(args.config), "veridor.json")
        self.assertEqual(args.base_url, "https://staging.example.com")
        changed = gate_invocations(*component_shell_and_variables(cv.NON_DEFAULT_INPUTS))[0]
        self.assertEqual(changed.fail_on, "any")
        self.assertFalse(changed.require_complete)
        self.assertTrue(changed.read_only)
        self.assertTrue(changed.require_clean_teardown)
        self.assertEqual(str(changed.openapi), "openapi.json")
        self.assertEqual(changed.wait_for_target, 45)
        for source in ("jenkins", "azure", "codebuild"):
            shell, variables = shipped_shells()[source]
            with self.subTest(source=source):
                args = gate_invocations(shell, variables)[0]
                self.assertTrue(args.require_complete)
                self.assertEqual(args.fail_on, "new+confirmed")

    def test_the_platform_templates_ship_the_gating_defaults(self) -> None:
        """Read from each file, not supplied by this test: the fail-on value
        that decides whether a finding fails the build, and the switch that
        turns exit 3 into a warning."""
        self.assertEqual(shipped_gating(), SHIPPED_GATING)

    def test_control_a_fail_open_platform_default_is_noticed(self) -> None:
        texts = {name: path.read_text(encoding="utf-8")
                 for name, path in (("jenkins", cv.JENKINSFILE), ("azure", cv.AZURE), ("codebuild", cv.BUILDSPEC))}
        mutations = {
            "jenkins fail-on none": ("jenkins", "VERIDOR_FAIL_ON = 'new+confirmed'", "VERIDOR_FAIL_ON = 'none'"),
            "jenkins allow-unmeasured on": ("jenkins", "VERIDOR_ALLOW_UNMEASURED = 'false'",
                                            "VERIDOR_ALLOW_UNMEASURED = 'true'"),
            "azure fail-on none": ("azure", "  VERIDOR_FAIL_ON: new+confirmed\n", "  VERIDOR_FAIL_ON: none\n"),
            "azure allow-unmeasured true": ("azure", '  VERIDOR_ALLOW_UNMEASURED: "false"\n',
                                            '  VERIDOR_ALLOW_UNMEASURED: "true"\n'),
            "azure env hard-coded none": ("azure", "              VERIDOR_OUTPUT_DIR:",
                                          "              VERIDOR_FAIL_ON: none\n              VERIDOR_OUTPUT_DIR:"),
            "buildspec fail-on none": ("codebuild", "    VERIDOR_FAIL_ON: new+confirmed", "    VERIDOR_FAIL_ON: none"),
        }
        for label, (platform, old, new) in mutations.items():
            with self.subTest(control=label):
                self.assertEqual(texts[platform].count(old), 1, "the mutation did not apply")
                mutated = dict(texts, **{platform: texts[platform].replace(old, new)})
                found = platform_gating_defaults(mutated["jenkins"], mutated["azure"], mutated["codebuild"])
                self.assertNotEqual(found, SHIPPED_GATING)

    def test_a_broken_command_is_refused(self) -> None:
        """The control: the parse above is not a formality."""
        shell, variables = component_shell_and_variables()
        for label, broken in {
            "misspelt flag": shell.replace('--fail-on "new+confirmed"', '--fail-om "new+confirmed"'),
            "bad fail-on value": shell.replace('--fail-on "new+confirmed"', '--fail-on "new-and-confirmed"'),
            "report format that does not exist": shell.replace('"junit=$out/', '"junitxml=$out/'),
            "map-only flag on run": shell.replace("--output-dir", "--acknowledge-target x --output-dir"),
        }.items():
            with self.subTest(control=label):
                self.assertFalse(broken == shell, "the mutation did not apply")
                with self.assertRaises(AssertionError):
                    gate_invocations(broken, variables)

    def test_an_unknown_variable_is_noticed(self) -> None:
        shell, variables = component_shell_and_variables()
        with self.assertRaises(KeyError):
            cv.veridor_commands(shell.replace('--config "veridor.json"', '--config "$RENAMED"'), variables)


# ---------------------------------------------------------------------------
# The shell around the gate
# ---------------------------------------------------------------------------


class GateShellTest(unittest.TestCase):
    def test_nothing_swallows_an_exit_code(self) -> None:
        for source, (shell, _) in shipped_shells().items():
            with self.subTest(source=source):
                self.assertEqual(cv.gate_problems(shell), [])
        for text in (cv.COMPONENT, cv.GITLAB_EXAMPLE, cv.AZURE, cv.BUILDSPEC):
            with self.subTest(file=text.name):
                self.assertNotRegex(text.read_text(encoding="utf-8"), r"allow_failure:\s*true")

    def test_the_problem_finder_finds_problems(self) -> None:
        shell, _ = component_shell_and_variables()
        for label, broken in {
            "|| true": shell.replace('"$@" || status=$?', '"$@" || true'),
            "set +e": shell.replace("status=0\n", "set +e\nstatus=0\n"),
        }.items():
            with self.subTest(control=label):
                self.assertFalse(broken == shell, "the mutation did not apply")
                self.assertTrue(cv.gate_problems(broken))

    def test_every_exit_code_has_its_own_branch(self) -> None:
        for source, (shell, _) in shipped_shells().items():
            if source == "jenkins":
                continue
            with self.subTest(source=source):
                self.assertLessEqual(EXIT_CODES, cv.exit_code_branches(shell))
        groovy = cv.JENKINSFILE.read_text(encoding="utf-8")
        self.assertLessEqual(EXIT_CODES, {int(n) for n in re.findall(r"^\s*case (\d+):", groovy, re.M)})
        shell, _ = component_shell_and_variables()
        broken = re.sub(r"(?m)^(\s*)143\) ", r"\g<1>144) ", shell)
        self.assertFalse(broken == shell, "the mutation did not apply")
        self.assertNotIn(143, cv.exit_code_branches(broken), "control: a missing 143 branch went unnoticed")

    def test_each_shell_exits_with_veridors_code(self) -> None:
        for source, (shell, _) in shipped_shells().items():
            with self.subTest(source=source):
                if source == "jenkins":
                    self.assertRegex(shell, r"\n\s*exec veridor run ")
                else:
                    last = [line.strip() for line in shell.strip().splitlines()][-1]
                    self.assertEqual(last, 'exit "$status"')
                    self.assertIn('"$@" || status=$?', shell)

    def test_exit_3_is_downgraded_only_on_request(self) -> None:
        """Azure: the one `exit 0` after the gate is inside the allowUnmeasured
        branch. It used to be the default for every exit 3."""
        shell = cv.azure_shell(azure_document())
        self.assertEqual(azure_unguarded_exit_zero(shell), [])
        a2_default = '3)\n  echo "##vso[task.complete result=SucceededWithIssues;]x"\n  exit 0\n  ;;\n'
        self.assertTrue(azure_unguarded_exit_zero(a2_default), "control: an unconditional exit 0 went unnoticed")
        codebuild = cv.codebuild_shell(buildspec_document())
        self.assertNotRegex(codebuild, r"(?m)^\s*exit 0\s*$")
        self.assertNotIn("VERIDOR_ON_EXIT_3", cv.BUILDSPEC.read_text(encoding="utf-8"))
        component = component_shell_and_variables()[0]
        self.assertNotRegex(component, r"(?m)^\s*exit 0\s*$")

    def test_codebuild_declares_bash(self) -> None:
        self.assertEqual(buildspec_document()["env"]["shell"], "bash")

    def test_the_buildspec_has_the_documented_shape(self) -> None:
        """SchemaStore publishes no buildspec schema; this is the stand-in."""
        self.assertEqual(cv.buildspec_problems(buildspec_document()), [])
        text = cv.BUILDSPEC.read_text(encoding="utf-8")
        for label, broken in {
            "misspelt phase": text.replace("  build:\n    commands:", "  biuld:\n    commands:"),
            "unknown shell": text.replace("  shell: bash", "  shell: zsh"),
            "unknown report format": text.replace("file-format: JUNITXML", "file-format: JUNIT"),
            "misspelt env key": text.replace("  variables:\n", "  varaibles:\n", 1),
            "runtime-versions outside install": text.replace("  build:\n    commands:", "  build:\n    runtime-versions:\n      python: 3.12\n    commands:"),
        }.items():
            with self.subTest(control=label):
                self.assertFalse(broken == text, "the mutation did not apply")
                self.assertTrue(cv.buildspec_problems(load_yaml_documents(broken)[0]))

    def test_jenkins_reports_cannot_change_the_result(self) -> None:
        groovy = cv.JENKINSFILE.read_text(encoding="utf-8")
        self.assertIn("skipMarkingBuildUnstable: true", groovy)
        self.assertIn("returnStatus: true", groovy)
        # The target is an environment entry ON PURPOSE: it wins over a build
        # parameter of the same name (measured), so nobody who can only start a
        # build can point the credentials elsewhere (QueueTimeSettingsTest).
        self.assertRegex(groovy, r"environment\s*\{[^}]*VERIDOR_BASE_URL\s*=")

    def test_azure_reports_cannot_change_the_result(self) -> None:
        steps = cv.azure_steps(azure_document())
        publish = [s for s in steps if s.get("task") == "PublishTestResults@2"]
        self.assertEqual(len(publish), 1)
        self.assertIs(publish[0]["inputs"]["failTaskOnFailedTests"], False)
        # The gate settings are YAML variables ON PURPOSE: Azure documents
        # that they cannot be overridden at queue time (QueueTimeSettingsTest).
        self.assertNotIn("parameters", azure_document())


# ---------------------------------------------------------------------------
# Who may set what decides where the credentials go and whether the gate fails
# ---------------------------------------------------------------------------

#: The settings a gate shell reads that decide where every bound credential is
#: sent (the base URL; the configuration names the target too) or whether the
#: gate can fail (the policy, the exit-3 switch, the baseline).
GATE_SETTINGS = ("VERIDOR_BASE_URL", "VERIDOR_CONFIG", "VERIDOR_FAIL_ON", "VERIDOR_ALLOW_UNMEASURED",
                 "VERIDOR_BASELINE")


def shell_reads(shell: str, names: tuple[str, ...] = GATE_SETTINGS) -> list[str]:
    return [name for name in names if re.search(r"\$\{?" + name + r"\b", shell)]


def jenkins_queue_time_settings(text: str) -> list[str]:
    """What a user who may start a build can set: every build parameter the
    Jenkinsfile declares, and every `params.X` it reads. Also every gate
    setting the shell reads that is not an `environment` entry, which a
    parameter of that name (added in the job's configuration) would fill."""
    found = []
    block = re.search(r"(?m)^\s*parameters\s*\{(.*?)^\s*\}", text, re.S)
    if block:
        found += [f"build parameter {name}" for name in re.findall(r"name:\s*'([^']+)'", block.group(1))]
    found += [f"params.{name}" for name in re.findall(r"\bparams\.(\w+)", text)]
    environment = re.search(r"(?m)^\s*environment\s*\{(.*?)^\s*\}", text, re.S)
    entries = set(re.findall(r"(?m)^\s*(\w+)\s*=", environment.group(1))) if environment else set()
    for name in shell_reads("\n".join(cv.jenkins_shell_blocks(text))):
        if name not in entries:
            found.append(f"{name} is not fixed in environment")
    return sorted(set(found))


def azure_queue_time_settings(text: str) -> list[str]:
    """Runtime parameters (Azure: settable when a run is queued), and every
    gate setting the gate step reads that is not a literal in the YAML's own
    `variables:` block. Azure documents that a YAML variable cannot be
    overridden at queue time and that it outranks a queue-time variable of the
    same name; a step `env:` entry that remaps the name, or a value built from
    a parameter or a macro, reopens it."""
    document = load_yaml_documents(text)[0]
    found = [f"runtime parameter {p.get('name')}" for p in document.get("parameters") or []]
    raw = document.get("variables") or {}
    variables = ({v.get("name"): v.get("value") for v in raw if isinstance(v, dict)} if isinstance(raw, list)
                 else dict(raw))
    gate = next(s for s in cv.azure_steps(document) if "veridor run" in s.get("bash", ""))
    for name in shell_reads(gate["bash"]):
        if name in (gate.get("env") or {}):
            found.append(f"{name} is remapped in the gate step's env: {gate['env'][name]!r}")
        elif name not in variables:
            found.append(f"{name} is not fixed in variables:, so a queue-time variable of that name reaches the step")
        elif re.search(r"\$\(|\$\{\{|\$\[", str(variables[name])):
            found.append(f"{name} is built from an expression: {variables[name]!r}")
    return sorted(set(found))


#: The Jenkinsfile and Azure pipeline as they were: the target and the
#: gate-weakening switches were set when a build was started.
_OLD_JENKINS_PARAMETERS = """  parameters {
    string(name: 'VERIDOR_BASE_URL', defaultValue: '',
           description: 'Overrides target.base_url. Empty uses the configuration\\'s own.')
    booleanParam(name: 'VERIDOR_ALLOW_UNMEASURED', defaultValue: false,
                 description: 'Mark exit 3 UNSTABLE instead of FAILURE.')
  }

"""
_OLD_AZURE_PARAMETERS = """parameters:
  - name: baseUrl
    displayName: Base URL override (empty uses the configuration's target.base_url)
    type: string
    default: ""

"""


class QueueTimeSettingsTest(unittest.TestCase):
    """Veridor sends every bound credential to the base URL. When a build
    parameter or queue-time value set it, anyone allowed to start a build
    could name their own host and collect the owner, other-tenant and admin
    tokens (measured: the Jenkins and Azure gate shells sent all three to a
    capture server when only that value changed), or pick `none`, or turn exit
    3 green. Those settings now live in the pipeline file, changed by a
    commit, not by whoever starts a build."""

    def test_no_template_takes_a_gate_setting_when_a_build_starts(self) -> None:
        self.assertEqual(jenkins_queue_time_settings(cv.JENKINSFILE.read_text(encoding="utf-8")), [])
        self.assertEqual(azure_queue_time_settings(cv.AZURE.read_text(encoding="utf-8")), [])

    def test_the_shells_still_read_every_gate_setting(self) -> None:
        """The check above looks at what each shell reads; this proves it reads
        something, so an empty answer is not a shell that was not found."""
        self.assertEqual(shell_reads(jenkins_shell()),
                         ["VERIDOR_BASE_URL", "VERIDOR_CONFIG", "VERIDOR_FAIL_ON", "VERIDOR_BASELINE"])
        self.assertEqual(shell_reads(cv.azure_shell(azure_document())),
                         ["VERIDOR_BASE_URL", "VERIDOR_CONFIG", "VERIDOR_FAIL_ON", "VERIDOR_ALLOW_UNMEASURED"])

    def test_control_parameters_and_unfixed_settings_are_named(self) -> None:
        jenkins = cv.JENKINSFILE.read_text(encoding="utf-8")
        self.assertIn("  options {", jenkins)
        with_parameters = jenkins.replace("  options {", _OLD_JENKINS_PARAMETERS + "  options {", 1)
        self.assertIn("build parameter VERIDOR_BASE_URL", jenkins_queue_time_settings(with_parameters))
        unfixed = re.sub(r"(?m)^\s*VERIDOR_BASE_URL\s*=.*\n", "", jenkins)
        self.assertFalse(unfixed == jenkins, "the mutation did not apply")
        self.assertEqual(jenkins_queue_time_settings(unfixed), ["VERIDOR_BASE_URL is not fixed in environment"])
        reads_params = jenkins.replace("env.VERIDOR_ALLOW_UNMEASURED", "params.VERIDOR_ALLOW_UNMEASURED")
        self.assertFalse(reads_params == jenkins, "the mutation did not apply")
        self.assertEqual(jenkins_queue_time_settings(reads_params), ["params.VERIDOR_ALLOW_UNMEASURED"])

        azure = cv.AZURE.read_text(encoding="utf-8")
        self.assertIn("\npool:", azure)
        self.assertEqual(azure_queue_time_settings(azure.replace("\npool:", "\n" + _OLD_AZURE_PARAMETERS + "pool:", 1)),
                         ["runtime parameter baseUrl"])
        for label, old, new in (
            ("remapped from a parameter", "VERIDOR_OUTPUT_DIR:",
             "VERIDOR_BASE_URL: ${{ parameters.baseUrl }}\n              VERIDOR_OUTPUT_DIR:"),
            ("dropped from variables", "  VERIDOR_FAIL_ON: new+confirmed\n", ""),
            ("built from a macro", "  VERIDOR_BASE_URL: \"\"\n", "  VERIDOR_BASE_URL: $(TargetUrl)\n"),
        ):
            with self.subTest(control=label):
                mutated = azure.replace(old, new, 1)
                self.assertFalse(mutated == azure, "the mutation did not apply")
                self.assertTrue(azure_queue_time_settings(mutated))

    def test_the_templates_and_guide_say_who_chooses_where_credentials_go(self) -> None:
        """CodeBuild cannot be fixed in the file: StartBuild overrides any
        environment variable and the buildspec itself. The file and the guide
        must say so and name the IAM condition keys that deny it. GitLab's
        base_url can name a variable, and a pipeline variable outranks every
        other kind."""
        buildspec = " ".join(cv.BUILDSPEC.read_text(encoding="utf-8").replace("#", " ").split())
        for phrase in ("StartBuild", "codebuild:source.buildspec", "codebuild:environment.environmentVariables.name"):
            self.assertIn(phrase, buildspec)
        guide = " ".join(CI_README.read_text(encoding="utf-8").split())
        for phrase in ("decides where every", "codebuild:source.buildspec", "Minimum role to use pipeline variables"):
            self.assertIn(phrase, guide)
        base_url = cv.split_component(component_text())[0]["inputs"]["base_url"]["description"]
        self.assertIn("pipeline variable", base_url)
        self.assertIn("Minimum role to use pipeline variables", base_url)


# ---------------------------------------------------------------------------
# Variables added when a build starts: proxies and package indexes
# ---------------------------------------------------------------------------

#: What each place that tells a platform's users who may redirect the
#: credentials must name. A literal base URL does not decide where they go on
#: its own: Veridor follows http_proxy / https_proxy (any case) for a target
#: that is not loopback, and whoever may add a variable when a pipeline or run
#: starts can set one. Measured before the component's
#: proxy_from_environment input: the GitLab job and the Azure gate step, each
#: with a literal http:// base URL, sent the owner, other-tenant and admin
#: tokens to a capture server named only by http_proxy / HTTP_PROXY. The same
#: person can set PIP_INDEX_URL and pick the code a pip install runs. Each
#: platform's own control is named too, because a list of variable names is
#: never complete (BASH_ENV runs code in a non-interactive bash).
PROXY_GUIDANCE = {
    "ci/README.md GitLab row": ("proxy_from_environment", "http_proxy", "PIP_INDEX_URL",
                                "Minimum role to use pipeline variables"),
    "ci/README.md Jenkins row": ("http_proxy", "PIP_INDEX_URL", "keepUndefinedParameters"),
    "ci/README.md Azure row": ("HTTP_PROXY", "PIP_INDEX_URL", "Limit variables that can be set at queue time"),
    "ci/README.md CodeBuild row": ("HTTP_PROXY", "PIP_INDEX_URL", "codebuild:environment.environmentVariables.name"),
    "templates/veridor.yml base_url": ("proxy_from_environment", "Minimum role to use pipeline variables"),
    "ci/.gitlab-ci.yml": ("proxy_from_environment", "PIP_INDEX_URL", "Minimum role to use pipeline variables"),
    "ci/Jenkinsfile WHO CHOOSES THE TARGET": ("http_proxy", "PIP_INDEX_URL", "keepUndefinedParameters"),
    "ci/azure-pipelines.yml WHO CHOOSES THE TARGET": ("HTTP_PROXY", "PIP_INDEX_URL",
                                                      "Limit variables that can be set at queue time"),
    "ci/buildspec.yml WHO CHOOSES THE TARGET": ("HTTP_PROXY", "PIP_INDEX_URL",
                                                "codebuild:environment.environmentVariables.name"),
    "README.md Other CI platforms": ("proxy_from_environment", "http_proxy"),
}


def _flat(text: str) -> str:
    """Comment markers dropped and whitespace collapsed, so a phrase wrapped
    across comment lines is still one phrase."""
    return " ".join(re.sub(r"(?m)^\s*(?://|#)", " ", text).split())


def _who_chooses(text: str) -> str:
    """The WHO CHOOSES THE TARGET paragraph of a platform file, or ''."""
    match = re.search(r"WHO CHOOSES THE TARGET\.(.*?)\n\s*(?://|#)\s*\n", text, re.S)
    return match.group(1) if match else ""


def proxy_guidance_texts(ci_readme: str, component: str, gitlab_example: str, jenkinsfile: str, azure: str,
                         buildspec: str, readme: str) -> dict[str, str]:
    """``{label: text}`` for every label in PROXY_GUIDANCE; '' when it is gone."""
    texts: dict[str, str] = {}
    table = ci_readme.split("**Whoever may set the base URL", 1)[-1].split("\n## ", 1)[0]
    for platform in ("GitLab", "Jenkins", "Azure", "CodeBuild"):
        row = re.search(rf"(?m)^\| {platform} \|.*$", table)
        texts[f"ci/README.md {platform} row"] = row.group(0) if row else ""
    texts["templates/veridor.yml base_url"] = cv.split_component(component)[0]["inputs"]["base_url"]["description"]
    texts["ci/.gitlab-ci.yml"] = gitlab_example
    texts["ci/Jenkinsfile WHO CHOOSES THE TARGET"] = _who_chooses(jenkinsfile)
    texts["ci/azure-pipelines.yml WHO CHOOSES THE TARGET"] = _who_chooses(azure)
    texts["ci/buildspec.yml WHO CHOOSES THE TARGET"] = _who_chooses(buildspec)
    section = readme.split("### Other CI platforms", 1)
    texts["README.md Other CI platforms"] = section[1].split("\n### ", 1)[0] if len(section) == 2 else ""
    return texts


def proxy_guidance_problems(texts: dict[str, str]) -> list[str]:
    return [f"{label} does not name {phrase}"
            for label, phrases in PROXY_GUIDANCE.items()
            for phrase in phrases if phrase not in _flat(texts.get(label, ""))]


def shipped_proxy_guidance_texts() -> dict[str, str]:
    return proxy_guidance_texts(*(p.read_text(encoding="utf-8") for p in (
        CI_README, cv.COMPONENT, cv.GITLAB_EXAMPLE, cv.JENKINSFILE, cv.AZURE, cv.BUILDSPEC, README)))


class ProxyVariablesTest(unittest.TestCase):
    def test_the_input_is_off_by_default_and_decides_before_veridor_runs(self) -> None:
        """The removal must happen before the one command that sends the
        credentials, in the default render and not in the opt-in one."""
        inputs, _, _ = rendered_job()
        definition = inputs.get("proxy_from_environment", {})
        self.assertEqual((definition.get("type"), definition.get("default")), ("boolean", False))
        for keep in (False, True):
            with self.subTest(proxy_from_environment=keep):
                lines = cv.job_shell(rendered_job(given={"proxy_from_environment": keep})[2]).splitlines()
                decision = [i for i, line in enumerate(lines) if line.strip() == f"if {str(keep).lower()}; then"
                            and "unset" in "\n".join(lines[i:i + 12])]
                removal = [i for i, line in enumerate(lines) if re.search(r'\bunset -v "\$name"', line)]
                run = [i for i, line in enumerate(lines) if line.strip().startswith("veridor run")]
                self.assertEqual(len(run), 1, lines)
                self.assertTrue(removal and max(removal) < run[0], lines)
                self.assertEqual(len(decision), 1, lines)

    def test_every_platform_says_who_may_add_a_proxy_or_a_package_index(self) -> None:
        self.assertEqual(proxy_guidance_problems(shipped_proxy_guidance_texts()), [])

    def test_control_a_missing_phrase_or_block_is_named(self) -> None:
        texts = shipped_proxy_guidance_texts()
        for label, phrases in PROXY_GUIDANCE.items():
            with self.subTest(label=label):
                removed = {**texts, label: _flat(texts[label]).replace(phrases[-1], "")}
                self.assertEqual(proxy_guidance_problems(removed), [f"{label} does not name {phrases[-1]}"])
        azure = cv.AZURE.read_text(encoding="utf-8").replace("WHO CHOOSES THE TARGET.", "WHO PICKS THE TARGET.")
        self.assertNotEqual(azure, cv.AZURE.read_text(encoding="utf-8"), "the mutation did not apply")
        self.assertEqual(_who_chooses(azure), "")


# ---------------------------------------------------------------------------
# What the exit-0 line claims
# ---------------------------------------------------------------------------

#: The one line each template prints on exit 0, exactly. It used to say
#: "Every declared expectation held", which is false whenever the policy does
#: not gate on a finding that is there: one in the baseline, anything under
#: `none`, a suspected finding under `confirmed`, and, in the GitLab
#: component with require_complete false, an unanswered probe (measured: exit
#: 0 and that sentence under a run that recorded 1 vulnerable).
EXIT_0_LINES = {
    "gitlab": ("veridor-gate: exit 0: PASS. Nothing that --fail-on $[[ inputs.fail_on ]] gates on was found. "
               "A finding it does not gate on, such as one in the baseline, also exits 0, and so does an "
               "unanswered probe when require_complete is false. The summary above and the reports list "
               "everything measured."),
    "jenkins": ("Veridor: exit 0: PASS. Nothing that --fail-on ${env.VERIDOR_FAIL_ON} gates on was found. "
                "A finding it does not gate on, such as one in the baseline, also exits 0. The log above, "
                "veridor-out/veridor-summary.md and the test results list everything measured."),
    "azure": ("veridor-gate: exit 0: PASS. Nothing that --fail-on $VERIDOR_FAIL_ON gates on was found. "
              "A finding it does not gate on also exits 0. The summary above, the Tests tab and the run "
              "summary list everything measured."),
    "codebuild": ("veridor-gate: exit 0: PASS. Nothing that --fail-on $VERIDOR_FAIL_ON gates on was found. "
                  "A finding it does not gate on, such as one in the baseline, also exits 0. The summary above "
                  "and the Reports tab list everything measured."),
}

#: What no CI file may say about an exit 0.
OVERCLAIMS = ("every declared expectation held", "every expectation held", "expectations held")


def exit_0_lines(component: str, jenkinsfile: str, azure: str, buildspec: str) -> dict[str, list[str]]:
    """The text each template prints on exit 0, read from its source."""
    shell_zero = re.compile(r'(?m)^\s*0\) echo "((?:[^"\\]|\\.)*)" ;;')
    groovy_zero = re.compile(r"case 0:\s*\n\s*echo\s+(?:\"((?:[^\"\\]|\\.)*)\"|'([^']*)')")
    _, body = cv.split_component(component)
    gate = next(job for name, job in body.items() if not name.startswith("."))
    return {
        "gitlab": shell_zero.findall("\n".join(gate["script"])),
        "jenkins": ["".join(match) for match in groovy_zero.findall(jenkinsfile)],
        "azure": shell_zero.findall(next(s["bash"] for s in cv.azure_steps(load_yaml_documents(azure)[0])
                                         if "veridor run" in s.get("bash", ""))),
        "codebuild": shell_zero.findall("\n".join(load_yaml_documents(buildspec)[0]["phases"]["build"]["commands"])),
    }


def overclaim_problems(texts: dict[str, str]) -> list[str]:
    return [f"{name} says {phrase!r}" for name, text in texts.items()
            for phrase in OVERCLAIMS if phrase in " ".join(text.lower().replace("//", " ").replace("#", " ").split())]


class ExitZeroLineTest(unittest.TestCase):
    def texts(self) -> dict[str, str]:
        return {path.name: path.read_text(encoding="utf-8")
                for path in (cv.COMPONENT, cv.JENKINSFILE, cv.AZURE, cv.BUILDSPEC, cv.GITLAB_EXAMPLE, CI_README)}

    def test_each_template_prints_exactly_the_scoped_line(self) -> None:
        texts = self.texts()
        found = exit_0_lines(texts["veridor.yml"], texts["Jenkinsfile"], texts["azure-pipelines.yml"],
                             texts["buildspec.yml"])
        self.assertEqual(found, {platform: [line] for platform, line in EXIT_0_LINES.items()})

    def test_no_ci_file_says_every_expectation_held(self) -> None:
        self.assertEqual(overclaim_problems(self.texts()), [])

    def test_control_the_old_line_is_named(self) -> None:
        old = ('0) echo "veridor-gate: exit 0: PASS. Every declared expectation held. That is agreement with '
               'your declaration, not proof that the boundary is enforced." ;;')
        self.assertEqual(overclaim_problems({"old": old}), ["old says 'every declared expectation held'"])
        header = "//   0   SUCCESS    every declared\n//                  expectation held"
        self.assertTrue(overclaim_problems({"header": header}), "a comment split over two lines went unnoticed")
        texts = self.texts()
        shell = texts["buildspec.yml"]
        broken = shell.replace(EXIT_0_LINES["codebuild"], "veridor-gate: exit 0: PASS. Every declared expectation held.")
        self.assertFalse(broken == shell, "the mutation did not apply")
        self.assertNotEqual(exit_0_lines(texts["veridor.yml"], texts["Jenkinsfile"], texts["azure-pipelines.yml"],
                                         broken)["codebuild"], [EXIT_0_LINES["codebuild"]])


def azure_unguarded_exit_zero(shell: str) -> list[int]:
    lines = shell.splitlines()
    bad = []
    for index, line in enumerate(lines):
        if re.fullmatch(r"\s*exit 0\s*", line):
            window = "\n".join(lines[max(0, index - 4):index])
            if "True | true)" not in window or "SucceededWithIssues" not in window:
                bad.append(index + 1)
    return bad


# ---------------------------------------------------------------------------
# The files Veridor writes are the files the platform collects
# ---------------------------------------------------------------------------


def component_written_files(given: dict[str, Any] | None = None) -> tuple[dict[str, str], dict[str, Any]]:
    shell, variables = component_shell_and_variables(given)
    args = gate_invocations(shell, variables)[0]
    written = {fmt: str(path) for fmt, path in args.reports}
    written["json"] = str(args.json_path)
    return written, rendered_job(given=given)[2]["artifacts"]


def artifact_problems(written: dict[str, str], artifacts: dict[str, Any]) -> list[str]:
    problems = []
    if set(artifacts["paths"]) != set(written.values()):
        problems.append(f"artifacts:paths {sorted(artifacts['paths'])} != written {sorted(written.values())}")
    expected = {"sast": written.get("gitlab-sast"), "junit": written.get("junit"),
                "codequality": written.get("codequality")}
    if artifacts["reports"] != expected:
        problems.append(f"artifacts:reports {artifacts['reports']} != written {expected}")
    return problems


class ReportPathsTest(unittest.TestCase):
    def test_gitlab_collects_what_veridor_writes(self) -> None:
        for given in ({}, cv.NON_DEFAULT_INPUTS):
            with self.subTest(inputs="defaults" if not given else "changed"):
                self.assertEqual(artifact_problems(*component_written_files(given)), [])

    def test_a_report_path_typo_is_noticed(self) -> None:
        mutated = component_text().replace(
            'junit: "$[[ inputs.output_dir ]]/veridor-junit.xml"', 'junit: "$[[ inputs.output_dir ]]/veridor-junit.xm"')
        self.assertFalse(mutated == component_text(), "the mutation did not apply")
        written, _ = component_written_files()
        _, body = cv.render_component(mutated)
        artifacts = cv.resolve_job(body, cv.gate_job_name(body))["artifacts"]
        self.assertTrue(artifact_problems(written, artifacts))

    def test_other_platforms_collect_what_veridor_writes(self) -> None:
        shells = shipped_shells()
        jenkins = {fmt: str(p) for fmt, p in gate_invocations(*shells["jenkins"])[0].reports}
        groovy = cv.JENKINSFILE.read_text(encoding="utf-8")
        self.assertIn(f"junit testResults: '{jenkins['junit']}'", groovy)
        self.assertIn(f"sarif(pattern: '{jenkins['sarif']}'", groovy)

        azure_doc = azure_document()
        gate_step = next(s for s in cv.azure_steps(azure_doc) if "bash" in s and "veridor run" in s["bash"])
        out = gate_step["env"]["VERIDOR_OUTPUT_DIR"]
        azure = {fmt: str(p) for fmt, p in gate_invocations(gate_step["bash"], dict(platform_variables("azure"), VERIDOR_OUTPUT_DIR=out, out=out))[0].reports}
        publish = next(s for s in cv.azure_steps(azure_doc) if s.get("task") == "PublishTestResults@2")
        self.assertEqual(publish["inputs"]["testResultsFiles"], azure["junit"])
        artifacts = next(s for s in cv.azure_steps(azure_doc) if s.get("task") == "PublishBuildArtifacts@1")
        self.assertEqual(artifacts["inputs"]["PathtoPublish"], out)
        self.assertEqual(artifacts["inputs"]["ArtifactName"], "CodeAnalysisLogs")

        buildspec = buildspec_document()
        codebuild = {fmt: str(p) for fmt, p in gate_invocations(*shells["codebuild"])[0].reports}
        group = buildspec["reports"]["veridor-authorization"]
        self.assertEqual(group["file-format"], "JUNITXML")
        self.assertEqual([f"{group['base-directory']}/{f}" for f in group["files"]], [codebuild["junit"]])
        self.assertEqual(buildspec["artifacts"]["files"], ["veridor-out/**/*"])


# ---------------------------------------------------------------------------
# Input text never becomes shell code
# ---------------------------------------------------------------------------

#: Values that run code, or read a variable as arithmetic, once GitLab has
#: pasted them into the job's shell. Each passed the old regexes; `$(...)`
#: executed in bash and dash, and `${HOME:X}` ran X's value as arithmetic in
#: bash 3.2 and 5.2 (measured with a marker file).
HOSTILE_INPUTS = ("$(touch pwned)", "a$(id)b", "$((1+1))", "${HOME:X}", "${X:-$(id)}", "${X/a/b}", "${#X}",
                  "${X[0]}", "${!X}", "$1", "$$", "$@", "$", "x$", "`id`", "ok\n")

#: What each input must keep accepting.
BENIGN_INPUTS = {
    "base_url": ("https://staging.example.com", "$REVIEW_APP_URL", "${REVIEW_APP_URL}", "https://x.example/${PREFIX}/api",
                 "http://host:8080/a-b_c.d~e"),
    "config": ("veridor.json", "ci/veridor.staging.json", "$VERIDOR_CONFIG", "configs/${CI_COMMIT_REF_SLUG}.json"),
    "pip_package": ("veridor==0.1.0", "dist/veridor-0.1.0-py3-none-any.whl", "veridor>=0.1,<0.2"),
    "baseline": ("", "ci/veridor-baseline.json", "$BASELINE"),
    "openapi": ("", "openapi.json", "${SPEC_DIR}/openapi.json"),
    "extra_args": ("", "--read-only --require-clean-teardown", "--max-requests $MAX", "--rate ${RATE}"),
}


def shell_inputs(text: str) -> set[str]:
    """Inputs whose text is interpolated into the gate job's before_script or script."""
    _, body = cv.split_component(text)
    lines = [line for job in body.values() if isinstance(job, dict)
             for key in ("before_script", "script") for line in job.get(key) or []]
    return {name for line in lines for name in cv._references(line)}


def input_injection_problems(text: str, only: str | None = None) -> list[str]:
    """Every hostile value some shell-interpolated string input would accept.

    ``only`` limits the check to that one input, and still only if the script
    interpolates it: each value renders the whole component, so a control
    about one input need not render every other string input for each one."""
    spec, _ = cv.split_component(text)
    inputs = cv.check_inputs(spec)
    names = shell_inputs(text)
    if only is not None:
        names &= {only}
    problems = []
    for name in sorted(names):
        if inputs[name].get("type", "string") != "string":
            continue  # typed: a boolean or number cannot carry shell text
        for value in HOSTILE_INPUTS:
            try:
                cv.render_component(text, {name: value})
            except cv.ComponentError:
                continue
            problems.append(f"{name} accepts {value!r}")
    return problems


class InputInjectionTest(unittest.TestCase):
    """GitLab pastes input text into the job's script before the shell reads
    it, so a regex is all that stands between an input and a command. The old
    ones excluded quotes and the backtick but let `$(...)` through, and a
    consumer that forwards a pipeline input (set from the Run pipeline form, a
    schedule or the trigger API) into base_url ran it in the job that holds
    the VERIDOR_* credentials (measured: a marker file was created)."""

    def test_no_shell_input_accepts_a_substitution(self) -> None:
        self.assertEqual(input_injection_problems(component_text()), [])

    def test_the_shell_inputs_are_the_ones_expected(self) -> None:
        """So a new input written into the script is covered above by
        construction, and a removed one is noticed."""
        self.assertEqual(shell_inputs(component_text()),
                         {"output_dir", "base_url", "baseline", "openapi", "wait_for_target", "extra_args",
                          "require_complete", "config", "fail_on", "allow_unmeasured", "pip_package",
                          "proxy_from_environment"})

    def test_variable_references_and_plain_values_still_render(self) -> None:
        for name, values in BENIGN_INPUTS.items():
            for value in values:
                with self.subTest(input=name, value=value):
                    cv.render_component(component_text(), {name: value})

    def test_control_the_old_regexes_are_caught(self) -> None:
        text = component_text()
        old = {
            "base_url": r"""'^[^"''\\\x60\s]*$'""",
            "config": r"""'^[^"\\\x60\n]+$'""",
            "extra_args": r"""'^[A-Za-z0-9 _./:=,+@%${}-]*$'""",
        }
        for name, regex in old.items():
            with self.subTest(input=name):
                current = re.search(rf"(?ms)^    {name}:\n.*?^      regex: ('[^\n]*')$", text)
                mutated = text[:current.start(1)] + regex + text[current.end(1):]
                self.assertFalse(mutated == text, "the mutation did not apply")
                self.assertTrue(any(p.startswith(f"{name} accepts")
                                    for p in input_injection_problems(mutated, only=name)))

    def test_the_regex_ends_where_gitlab_ends_it(self) -> None:
        """RE2's `$` is the end of the text; Python's also matches before a
        final newline. The renderer must refuse what GitLab refuses."""
        self.assertIsNone(cv.gitlab_regex(r"^[^\n]+$").search("veridor.json\n"))
        self.assertIsNotNone(re.search(r"^[^\n]+$", "veridor.json\n"), "control: Python's own $ accepts it")
        self.assertIsNotNone(cv.gitlab_regex(r"^[^$]+$").search("a"), "a $ inside a class stays literal")
        self.assertIsNone(cv.gitlab_regex(r"^[^$]+$").search("a$"))
        self.assertIsNotNone(cv.gitlab_regex(r"^\$x$").search("$x"), "an escaped $ stays literal")


# ---------------------------------------------------------------------------
# extra_args cannot replace a flag the component owns
# ---------------------------------------------------------------------------


def run_option_strings() -> list[str]:
    parser = cli._parser()
    subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return [s for s in subparsers.choices["run"]._option_string_actions if s.startswith("--")]


def accepted_spellings(option: str) -> list[str]:
    """Every spelling argparse resolves to ``option``: it and its unique prefixes."""
    options = run_option_strings()
    spellings = []
    for length in range(3, len(option) + 1):
        prefix = option[:length]
        matches = [o for o in options if o.startswith(prefix)]
        if prefix == option or matches == [option]:
            spellings.append(prefix)
    return spellings


def guard_patterns() -> list[str]:
    shell, _ = component_shell_and_variables()
    match = re.search(r"case \"\$arg\" in\n\s*([^\n]*)\)\n", shell)
    if match is None:
        raise AssertionError("the extra_args guard is gone from the component")
    return match.group(1).split("|")


class ExtraArgsGuardTest(unittest.TestCase):
    def test_argparse_really_takes_an_abbreviation_and_the_last_value(self) -> None:
        """Why the guard exists: without it, extra_args `--fail none` silently
        turns the gate off."""
        args = cli._parser().parse_args(["run", "--config", "c.json", "--fail-on", "any", "--fail", "none"])
        self.assertEqual(args.fail_on, "none")

    def test_every_spelling_of_an_owned_flag_is_refused(self) -> None:
        patterns = guard_patterns()
        for option in OWNED_FLAGS:
            for spelling in accepted_spellings(option):
                for form in (spelling, f"{spelling}=x"):
                    with self.subTest(argument=form):
                        self.assertTrue(any(fnmatch.fnmatchcase(form, p) for p in patterns), form)

    def test_help_is_refused(self) -> None:
        """`veridor run --help` exits 0 having run nothing: a green gate."""
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli._parser().parse_args(["run", "--he"])
        self.assertEqual(caught.exception.code, 0)
        patterns = guard_patterns()
        for spelling in ["-h", *accepted_spellings("--help")]:
            with self.subTest(argument=spelling):
                self.assertTrue(any(fnmatch.fnmatchcase(spelling, p) for p in patterns), spelling)

    def test_flags_the_component_does_not_own_pass(self) -> None:
        patterns = guard_patterns()
        for option in ("--read-only", "--require-clean-teardown", "--report", "--sarif",
                       "--no-prove-liveness", "--require-complete", "--coverage", "--badge"):
            with self.subTest(option=option):
                self.assertFalse(any(fnmatch.fnmatchcase(option, p) for p in patterns))

    def test_the_owned_flags_are_what_the_component_sets(self) -> None:
        shell, variables = component_shell_and_variables()
        argv = cv.veridor_commands(shell, variables)[0]
        set_by_component = {word for word in argv if word.startswith("--")} - {"--report", "--require-complete"}
        self.assertEqual(set_by_component, set(OWNED_FLAGS))


# ---------------------------------------------------------------------------
# The example configuration and the credentials each platform passes
# ---------------------------------------------------------------------------

_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ExampleConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.names = sorted(set(_REFERENCE.findall(cv.EXAMPLE_CONFIG.read_text(encoding="utf-8"))))

    def test_it_loads_with_its_variables_set(self) -> None:
        self.assertEqual(self.names, ["VERIDOR_ADMIN_TOKEN", "VERIDOR_OTHER_TENANT_TOKEN", "VERIDOR_OWNER_TOKEN"])
        env = {name: f"value-for-{name.lower()}" for name in self.names}
        with mock.patch.dict(os.environ, env):
            config = core.load_config(cv.EXAMPLE_CONFIG)
        self.assertEqual(len(config["checks"]), 2)

    def test_an_empty_credential_is_refused(self) -> None:
        env = {name: "x-value" for name in self.names}
        env["VERIDOR_OWNER_TOKEN"] = ""
        with mock.patch.dict(os.environ, env), self.assertRaises(core.ConfigError) as caught:
            core.load_config(cv.EXAMPLE_CONFIG)
        self.assertIn("VERIDOR_OWNER_TOKEN", str(caught.exception))

    def test_each_platform_passes_exactly_these_credentials(self) -> None:
        gate_step = next(s for s in cv.azure_steps(azure_document()) if "bash" in s and "veridor run" in s["bash"])
        azure = sorted(k for k, v in gate_step["env"].items() if v == f"$({k})")
        self.assertEqual(azure, self.names)
        groovy = cv.JENKINSFILE.read_text(encoding="utf-8")
        self.assertEqual(sorted(re.findall(r"variable: '([A-Z0-9_]+)'", groovy)), self.names)


# ---------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------


def readme_input_rows(text: str) -> dict[str, tuple[str, str]]:
    """``{input: (type, default)}`` from the GitLab section's inputs table."""
    section = text.split("### GitLab CI", 1)[1].split("\n### ", 1)[0]
    rows = {}
    for line in section.splitlines():
        match = re.match(r"\|\s*`([a-z_]+)`\s*\|\s*([a-z]+)\s*\|\s*(.*?)\s*\|", line)
        if match:
            rows[match.group(1)] = (match.group(2), match.group(3))
    return rows


#: Everywhere a reader can copy a pip requirement for the unregistered name.
PYPI_COPY_SOURCES = (cv.COMPONENT, cv.JENKINSFILE, cv.AZURE, cv.BUILDSPEC, README)
#: How far above the line its warning may sit: far enough for a template's note
#: to cover the install options under it, too short to cover a whole file.
PYPI_WARNING_WINDOW = 8


def unwarned_requirements(text: str) -> list[int]:
    """Line numbers naming veridor==VERSION with no "unclaimed" on or just above them."""
    lines = text.split("\n")
    return [number for number, line in enumerate(lines, 1)
            if "veridor==" in line and not any(
                "unclaimed" in nearby.lower() for nearby in lines[max(0, number - 1 - PYPI_WARNING_WINDOW):number])]


#: What the Azure and CodeBuild install steps hold until the first release.
WHEEL_PLACEHOLDER = "REPLACE_WITH_THE_PATH_OF_A_VERIDOR_WHEEL"

#: pip's refusal of that line as a wheel name, in the wording of pip 26
#: ("Invalid wheel filename (...): 'NAME'") and of pip 24, which a venv on a
#: runner's Python can still ship ("NAME.whl is not a valid wheel filename").
BAD_WHEEL_NAME = re.compile(
    rf"Invalid wheel filename \([^)]*\): '{WHEEL_PLACEHOLDER}'"
    rf"|{WHEEL_PLACEHOLDER}\.whl is not a valid wheel filename")


def active_requirements(text: str) -> list[str]:
    """Lines that would really install veridor==VERSION: everything but a comment."""
    return [line.strip() for line in text.split("\n")
            if "veridor==" in line and not line.lstrip().startswith("#")]


def files_naming_the_requirement() -> set[Path]:
    """Files a reader is sent to that hold the requirement. tests/ and the release tooling are not."""
    candidates = [path for top in ("ci", "templates", "deploy", "docs", ".github")
                  for path in (ROOT / top).rglob("*") if path.is_file()] + list(ROOT.glob("*.md"))
    return {path for path in candidates if "veridor==" in path.read_text(encoding="utf-8", errors="replace")}


def released() -> bool:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return re.search(r"^## \[\d[^\]]*\] - \d{4}-\d{2}-\d{2}", changelog, re.M) is not None


def readme_input_problems(text: str) -> list[str]:
    spec, _ = cv.split_component(component_text())
    inputs = cv.check_inputs(spec)
    rows = readme_input_rows(text)
    problems = []
    if list(rows) != list(inputs):
        problems.append(f"README inputs {list(rows)} != component inputs {list(inputs)}")
    for name, definition in inputs.items():
        if name not in rows:
            continue
        kind, default = rows[name]
        if kind != definition.get("type", "string"):
            problems.append(f"{name}: README type {kind} != {definition.get('type', 'string')}")
        want = definition.get("default")
        shown = default.strip("`") if default != "(empty)" else ""
        if isinstance(want, list):
            # An array default is shown as JSON, so it is compared, not skipped.
            try:
                same = json.loads(shown) == want
            except ValueError:
                same = False
            if not same:
                problems.append(f"{name}: README default {default!r} != {json.dumps(want)!r}")
            continue
        if isinstance(want, bool):
            want = "true" if want else "false"
        elif isinstance(want, (int, float)):
            want = str(want)
        if shown != want:
            problems.append(f"{name}: README default {default!r} != {want!r}")
    return problems


#: Predefined variables GitLab sets only in a job that declares an
#: environment (lib/gitlab/ci/variables/builder.rb appends them inside
#: `if environment.present?`; the predefined-variables page agrees).
ENVIRONMENT_ONLY_VARIABLES = frozenset({"CI_ENVIRONMENT_NAME", "CI_ENVIRONMENT_SLUG", "CI_ENVIRONMENT_URL",
                                        "CI_ENVIRONMENT_ACTION", "CI_ENVIRONMENT_TIER", "CI_ENVIRONMENT_ID"})


def unset_example_problems(component: str, example: str, readme: str) -> list[str]:
    """Places that offer, as a value for this job, a variable the job never has.

    The base_url description used to say "e.g. $CI_ENVIRONMENT_URL"; the
    rendered job declares no environment, so following it refused every
    pipeline with exit 2 (measured)."""
    _, _, job = rendered_job(component)
    if "environment" in job:
        return []
    spec, _ = cv.split_component(component)
    offered: list[tuple[str, str]] = []
    for name, definition in cv.check_inputs(spec).items():
        for variable in re.findall(r"(?:e\.g\.|for example|such as)\s+\$\{?([A-Z_][A-Z0-9_]*)",
                                   definition.get("description", "")):
            offered.append((f"input {name} description", variable))
    for where, document in gitlab_include_documents(example, readme):
        for item in (document or {}).get("include") or []:
            for name, value in (item.get("inputs") or {}).items():
                for variable in re.findall(r"\$\{?([A-Z_][A-Z0-9_]*)", str(value)):
                    offered.append((f"{where} include input {name}", variable))
    return [f"{where} offers ${variable}, which GitLab sets only in a job with an environment; this job has none"
            for where, variable in offered if variable in ENVIRONMENT_ONLY_VARIABLES]


def baseline_claim_problems(component: str) -> list[str]:
    """What the fail_on and baseline inputs must not claim, and must say.

    fail_on said new+confirmed "cannot be defeated by editing the baseline".
    That holds only for a confirmed finding: a suspected one (a 200 where 403
    was declared, no marker in the response) or an ungraded one (its check
    declares no marker) stops gating once its id is in the baseline, and the
    baseline file sits in the merge request's diff (reproduced: exit 1 became
    exit 0 through the rendered component)."""
    spec, _ = cv.split_component(component)
    problems = []
    for name, definition in spec["inputs"].items():
        text = " ".join(str(definition.get("description", "")).split())
        for phrase in ("cannot be defeated", "regardless of the baseline", "immune"):
            if phrase in text.lower():
                problems.append(f"input {name} claims the baseline {phrase!r}")
    for name, words in (("fail_on", ("confirmed", "suspected", "ungraded", "baseline", "merge request", "CODEOWNERS")),
                        ("baseline", ("confirmed", "merge request", "CODEOWNERS"))):
        text = " ".join(str(spec["inputs"][name].get("description", "")).split())
        problems += [f"input {name} does not name {word}" for word in words if word not in text]
    return problems


def stage_order_problems(component: str, example: str, readme: str) -> list[str]:
    """The gate probes whatever base_url serves when the job starts. Its
    default stage is `test`, which in GitLab's default stages runs before
    `deploy`, and the example aims it at staging: followed as written, it
    measures the deployment before this pipeline's. The stage input, the
    example and the README row must say to run it after the deploy."""
    spec, _ = cv.split_component(component)
    problems = []
    flat = {"input stage": " ".join(spec["inputs"]["stage"].get("description", "").split()),
            "ci/.gitlab-ci.yml": " ".join(example.replace("#", " ").split()),
            "README stage row": next((line for line in readme.splitlines() if line.startswith("| `stage` |")), "")}
    for where, text in flat.items():
        if not re.search(r"after the (?:job that deploys|deploy)", text):
            problems.append(f"{where} does not say to run after the deploy")
    if "needs" not in flat["input stage"] or "needs" not in flat["ci/.gitlab-ci.yml"]:
        problems.append("the stage input or the example does not mention needs")
    return problems


#: The form GitLab's CI schema gives include:integrity.
_INTEGRITY = re.compile(r"sha256-[A-Za-z0-9+/]{43}=")


def remote_include_problems(where: str, document: Any) -> list[str]:
    """A remote include that follows a movable ref, or has no integrity.

    The example used to include the component at the tag URL with no
    integrity, and the included job runs with the project's CI/CD variables:
    a moved tag would run changed code there, with no notice from GitLab."""
    problems = []
    for item in (document or {}).get("include") or []:
        if not isinstance(item, dict) or "remote" not in item:
            continue
        match = re.fullmatch(r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/([^/]+)/templates/veridor\.yml",
                             item["remote"])
        if match is None:
            problems.append(f"{where}: remote {item['remote']!r} is not this repository's raw file URL")
            continue
        ref = match.group(1)
        if not (re.fullmatch(r"[0-9a-f]{40}", ref) or ref == "COMMIT_SHA_OF_THE_RELEASE_TAG"):
            problems.append(f"{where}: remote include follows {ref!r}, which can move; pin a full commit SHA")
        if not _INTEGRITY.fullmatch(str(item.get("integrity", ""))):
            problems.append(f"{where}: remote include has no integrity in the form sha256-<base64>")
    return problems


def gitlab_include_documents(example: str, readme: str) -> list[tuple[str, Any]]:
    documents = [("ci/.gitlab-ci.yml", load_yaml_documents(example)[0])]
    section = readme.split("### GitLab CI", 1)[1].split("\n### ", 1)[0]
    for block in re.findall(r"```yaml\n(.*?)```", section, re.S):
        documents.append(("README GitLab section", load_yaml_documents(block)[0]))
    return documents


class DocumentationTest(unittest.TestCase):
    def test_the_remote_include_is_pinned_and_hashed(self) -> None:
        documents = gitlab_include_documents(cv.GITLAB_EXAMPLE.read_text(encoding="utf-8"),
                                             README.read_text(encoding="utf-8"))
        self.assertEqual(len([d for _, d in documents if (d or {}).get("include")]), 2)
        self.assertEqual([p for where, d in documents for p in remote_include_problems(where, d)], [])

    def test_control_the_tag_include_is_noticed(self) -> None:
        old = {"include": [{"remote": "https://raw.githubusercontent.com/Veridor-authz/veridor/v0.1.0/templates/veridor.yml",
                            "inputs": {"config": "veridor.json"}}]}
        self.assertEqual(remote_include_problems("old", old), [
            "old: remote include follows 'v0.1.0', which can move; pin a full commit SHA",
            "old: remote include has no integrity in the form sha256-<base64>"])
        pinned = {"include": [{"remote": f"https://raw.githubusercontent.com/Veridor-authz/veridor/{'a' * 40}/templates/veridor.yml",
                               "integrity": "sha256-" + "A" * 43 + "="}]}
        self.assertEqual(remote_include_problems("pinned", pinned), [])

    def test_no_example_offers_a_variable_this_job_never_has(self) -> None:
        self.assertEqual(unset_example_problems(component_text(), cv.GITLAB_EXAMPLE.read_text(encoding="utf-8"),
                                                README.read_text(encoding="utf-8")), [])

    def test_control_the_old_base_url_example_is_noticed(self) -> None:
        text = component_text()
        old = re.sub(r'(?m)^(      description: "Overrides target\.base_url)\.', r"\1, e.g. $CI_ENVIRONMENT_URL.", text)
        self.assertFalse(old == text, "the mutation did not apply")
        example = cv.GITLAB_EXAMPLE.read_text(encoding="utf-8")
        self.assertEqual(unset_example_problems(old, example, README.read_text(encoding="utf-8")),
                         ["input base_url description offers $CI_ENVIRONMENT_URL, which GitLab sets only in a job "
                          "with an environment; this job has none"])
        forwarded = example.replace('base_url: "https://staging.example.com"', "base_url: $CI_ENVIRONMENT_URL", 1)
        self.assertFalse(forwarded == example, "the mutation did not apply")
        self.assertTrue(unset_example_problems(text, forwarded, README.read_text(encoding="utf-8")))

    def test_no_dangling_portability_reference(self) -> None:
        for path in [README, CI_README, cv.COMPONENT, *sorted((ROOT / "ci").iterdir())]:
            if path.is_file():
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn("ci-portability.md", path.read_text(encoding="utf-8"))

    def test_the_platform_templates_say_they_are_untested(self) -> None:
        for path in (cv.JENKINSFILE, cv.AZURE, cv.BUILDSPEC):
            with self.subTest(file=path.name):
                self.assertIn("UNTESTED", path.read_text(encoding="utf-8")[:2000])

    def test_the_gitlab_end_to_end_count_lives_in_one_place(self) -> None:
        """The README said 145 checks and ci/README.md said 158, for one run on
        one date. The script's calls add up to 158, so 145 was the stale one, and
        a second copy of the number is how it went stale."""
        row = next(line for line in README.read_text(encoding="utf-8").splitlines()
                   if line.startswith("| [GitLab CI/CD component]"))
        self.assertNotRegex(row, r"\d+ checks")
        self.assertIn("ci/README.md#what-was-tested", row)
        self.assertRegex(CI_README.read_text(encoding="utf-8"), r"\d+ checks, 0 mismatches")

    def test_nothing_claims_a_release_exists(self) -> None:
        for path in (cv.COMPONENT, cv.GITLAB_EXAMPLE, cv.JENKINSFILE, cv.AZURE, cv.BUILDSPEC, CI_README):
            with self.subTest(file=path.name):
                self.assertRegex(path.read_text(encoding="utf-8"), r"(?i)not yet published|does not exist until|do not exist until")

    def test_every_pip_requirement_says_the_name_is_unclaimed(self) -> None:
        """Nobody has registered veridor on PyPI, so anyone can publish a 0.1.0,
        and these lines would run it with the job's credentials. "Not yet
        published" does not tell a reader that, so the warning has to be where
        the line gets copied from, and a new copy of the line has to bring it."""
        if released():
            self.skipTest("a release exists; the name is held")
        self.assertEqual(files_naming_the_requirement(), set(PYPI_COPY_SOURCES))
        for path in PYPI_COPY_SOURCES:
            with self.subTest(file=path.name):
                self.assertEqual(unwarned_requirements(path.read_text(encoding="utf-8")), [])

    def test_the_catalog_address_says_nothing_shows_who_holds_the_namespace(self) -> None:
        """The form is copyable, and the namespace is the same risk as the PyPI
        name: whoever holds it could publish a component at that address."""
        if released():
            self.skipTest("a release exists; the mirror does too")
        for path in (README, cv.GITLAB_EXAMPLE):
            with self.subTest(file=path.name):
                prose = " ".join(path.read_text(encoding="utf-8").replace("#", " ").split())
                self.assertRegex(prose, r"gitlab\.com/Veridor-authz.{0,400}check the holder")

    def test_no_template_installs_the_unclaimed_name_by_default(self) -> None:
        """A warning was the only control on these: copied as it stood, the Azure
        and CodeBuild templates ran `pip install veridor==0.1.0` with the job's
        credentials, and that starts working the day someone else registers the
        name. The GitLab remote include fails closed on its placeholders; these
        now do too. Mutant: the old line is named by the control below."""
        if released():
            self.skipTest("a release exists; the name is held")
        for path in (cv.AZURE, cv.BUILDSPEC):
            with self.subTest(file=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(active_requirements(text), [])
                self.assertIn(WHEEL_PLACEHOLDER, text)
                self.assertIn(WHEEL_PLACEHOLDER.lower(), release_check.pre_release_statements(text))

    def test_control_an_active_requirement_is_named(self) -> None:
        self.assertEqual(active_requirements('# pip install "veridor==0.1.0"\n'), [])
        self.assertEqual(active_requirements('- python3 -m pip install "veridor==0.1.0"\n'),
                         ['- python3 -m pip install "veridor==0.1.0"'])

    @slow("runs pip")
    def test_the_placeholder_stops_pip_without_asking_an_index(self) -> None:
        """The whole of this fix is that the line fails, so run it. --no-index and
        an empty --target keep it off the network and out of this interpreter."""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-index", "--target", directory,
                 "--quiet", "--disable-pip-version-check", f"./{WHEEL_PLACEHOLDER}.whl"],
                cwd=directory, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertRegex(result.stderr, BAD_WHEEL_NAME)
            self.assertEqual(os.listdir(directory), [])

    def test_control_the_pip_refusal_pattern(self) -> None:
        """Both wordings pip has used for a bad wheel name match; the refusals a
        name pip resolved instead would draw do not."""
        for stderr in ("ERROR: Invalid wheel filename (wrong number of parts): "
                       f"'{WHEEL_PLACEHOLDER}'",
                       f"ERROR: {WHEEL_PLACEHOLDER}.whl is not a valid wheel filename."):
            with self.subTest(stderr=stderr):
                self.assertRegex(stderr, BAD_WHEEL_NAME)
        for stderr in ("ERROR: Could not find a version that satisfies the requirement veridor",
                       f"ERROR: No matching distribution found for {WHEEL_PLACEHOLDER}",
                       "ERROR: Invalid wheel filename (wrong number of parts): 'other'"):
            with self.subTest(stderr=stderr):
                self.assertNotRegex(stderr, BAD_WHEEL_NAME)

    def test_control_a_requirement_without_the_warning_is_named(self) -> None:
        for path in PYPI_COPY_SOURCES:
            text = path.read_text(encoding="utf-8")
            stripped = "\n".join(line for line in text.split("\n") if "unclaimed" not in line.lower())
            with self.subTest(removed_from=path.name):
                self.assertTrue(unwarned_requirements(stripped))
        far = "the name is unclaimed\n" + "\n" * PYPI_WARNING_WINDOW + "pip install veridor==0.1.0\n"
        self.assertEqual(unwarned_requirements(far), [PYPI_WARNING_WINDOW + 2])
        near = "the name is unclaimed\n" + "\n" * (PYPI_WARNING_WINDOW - 1) + "pip install veridor==0.1.0\n"
        self.assertEqual(unwarned_requirements(near), [])
        self.assertEqual(unwarned_requirements("pip install veridor>=0.1 # veridor==0.1.0 unclaimed\n"), [])

    def test_the_readme_inputs_table_matches_the_component(self) -> None:
        self.assertEqual(readme_input_problems(README.read_text(encoding="utf-8")), [])

    def test_a_drifted_inputs_table_is_noticed(self) -> None:
        text = README.read_text(encoding="utf-8")
        for label, broken in {
            "default changed": text.replace("| `fail_on` | string | `new+confirmed` |", "| `fail_on` | string | `new` |"),
            "row removed": re.sub(r"\n\| `openapi` \|[^\n]*", "", text),
            "type changed": text.replace("| `allow_unmeasured` | boolean |", "| `allow_unmeasured` | string |"),
            "array default changed": text.replace('| `job_rules` | array | `[{"when": "on_success"}]` |',
                                                  "| `job_rules` | array | merge request pipelines and the default branch |"),
        }.items():
            with self.subTest(control=label):
                self.assertFalse(broken == text, "the mutation did not apply")
                self.assertTrue(readme_input_problems(broken))

    def test_other_ci_platforms_points_at_the_guide(self) -> None:
        section = README.read_text(encoding="utf-8").split("### Other CI platforms", 1)[1].split("\n### ", 1)[0]
        self.assertIn("ci/README.md", section)

    def test_no_input_says_the_baseline_cannot_defeat_the_gate(self) -> None:
        self.assertEqual(baseline_claim_problems(component_text()), [])

    def test_control_the_old_fail_on_sentence_is_noticed(self) -> None:
        text = component_text()
        sentence = ('"Findings that fail the gate (veridor run --fail-on). new+confirmed is '
                    "Veridor's default and cannot be defeated by editing the baseline.\"")
        old = re.sub(r'(?m)^(    fail_on:\n      description: )"[^\n]*"$', lambda m: m.group(1) + sentence, text)
        self.assertFalse(old == text, "the mutation did not apply")
        problems = baseline_claim_problems(old)
        self.assertIn("input fail_on claims the baseline 'cannot be defeated'", problems)
        self.assertIn("input fail_on does not name suspected", problems)

    def test_the_docs_say_where_the_gate_goes_relative_to_the_deploy(self) -> None:
        self.assertEqual(stage_order_problems(component_text(), cv.GITLAB_EXAMPLE.read_text(encoding="utf-8"),
                                              README.read_text(encoding="utf-8")), [])

    def test_control_the_old_stage_docs_are_named(self) -> None:
        text = component_text()
        old = re.sub(r'(?m)^(    stage:\n      description: )"[^\n]*"$',
                     lambda m: m.group(1) + "\"Pipeline stage the gate job runs in. It must exist in your "
                                            "pipeline's stages.\"", text)
        self.assertFalse(old == text, "the mutation did not apply")
        self.assertIn("input stage does not say to run after the deploy",
                      stage_order_problems(old, cv.GITLAB_EXAMPLE.read_text(encoding="utf-8"),
                                           README.read_text(encoding="utf-8")))

    def test_the_guide_says_what_was_executed(self) -> None:
        text = CI_README.read_text(encoding="utf-8")
        self.assertIn("scripts/e2e_gitlab_job.sh", text)
        self.assertIn("UNTESTED", text)
        for platform in ("GitLab", "Jenkins", "Azure", "CodeBuild"):
            self.assertIn(platform, text)


# ---------------------------------------------------------------------------
# The end-to-end script
# ---------------------------------------------------------------------------


class E2EScriptStaticTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = E2E_SCRIPT.read_text(encoding="utf-8")

    def test_strict_mode_and_cleanup(self) -> None:
        self.assertIn("set -Eeuo pipefail", self.text)
        self.assertIn("trap cleanup EXIT", self.text)
        self.assertIn('--filter "label=${LABEL}"', self.text)

    def test_it_runs_the_rendered_job_not_a_copy(self) -> None:
        """The job's shell comes from the template via the renderer. A script
        that typed its own `veridor run` would test itself, not the template."""
        self.assertIn("tests/ci_validate.py\" render", self.text)
        code = "\n".join(line for line in self.text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotRegex(code, r"veridor run\b")
        self.assertNotIn("--report ", code)

    def test_every_row_is_run(self) -> None:
        for row in ("vulnerable", "fixed", "unreachable", "unmeasured-allowed", "dash", "bash", "pip", "empty-credential",
                    "extra-args-override", "unset-base-url", "root-owned-workspace", "sigterm", "wait-for-target",
                    "nondefault-inputs", "proxy-variable", "proxy-variable-dash", "proxy-opt-in"):
            with self.subTest(row=row):
                self.assertIn(f'dir="$(row_dir {row})"', self.text)

    def test_every_row_runs_in_the_shell_the_runner_would_pick(self) -> None:
        """The rows used to run under a hard-coded bash. The Alpine image has
        none, so every row but the two sh ones found no shell and the script
        stopped before its table (measured). GitLab Runner's docker executor
        runs a job under the first bash it finds, else sh; each row asks for
        that, or for sh explicitly."""
        self.assertEqual(e2e_shell_problems(self.text), [])

    def test_control_a_row_with_a_hard_coded_bash_is_named(self) -> None:
        old = self.text.replace('run_job "$dir" runner 0000 1', 'run_job "$dir" bash 0000 1')
        self.assertFalse(old == self.text, "the mutation did not apply")
        self.assertEqual(e2e_shell_problems(old), ["a row runs under bash whatever its image holds: "
                                                   'run_job "$dir" bash 0000 1'])
        moved = self.text.replace("/usr/local/bin/bash /usr/bin/bash /bin/bash;", "/bin/bash;")
        self.assertFalse(moved == self.text, "the mutation did not apply")
        self.assertEqual(len(e2e_shell_problems(moved)), 1)

    def test_control_the_dash_rows_as_they_were_are_named(self) -> None:
        """Before: rendered with base_inputs, in the Alpine IMAGE, so "dash"
        was busybox sh -- the vulnerable row again."""
        old = self.text
        for row in ("dash", "proxy-variable-dash"):
            block = e2e_row_blocks(old)[row]
            old = old.replace(block, block.replace('"${debian_inputs[@]}"', '"${base_inputs[@]}"'), 1)
        self.assertEqual(e2e_shell_problems(old), [
            "row dash: not rendered with debian_inputs, so it runs no dash",
            "row proxy-variable-dash: not rendered with debian_inputs, so it runs no proxy-variable-dash"])
        bash = e2e_row_blocks(self.text)["bash"]
        self.assertEqual(e2e_shell_problems(self.text.replace(bash, bash.replace('"$dir" runner', '"$dir" sh'))),
                         ["row bash: not run under runner"])
        unchecked = self.text.replace(bash, bash.replace("check_shell ", "true "))
        self.assertEqual(e2e_shell_problems(unchecked), ["row bash: never checks the shell it ran under"])
        headless = self.text.replace('| cat - "$dir/job.sh" >', '| cat "$dir/job.sh" >')
        self.assertFalse(headless == self.text, "the mutation did not apply")
        self.assertEqual(e2e_shell_problems(headless), ["the job script does not start with GitLab Runner's header"])

    def test_every_input_that_reaches_the_shell_is_run_off_its_default(self) -> None:
        """The e2e used to leave wait_for_target, fail_on, require_complete,
        baseline and openapi at their defaults, so an image that rejected
        --wait-for-target passed all 77 checks (measured). An
        input no row moves must be one that cannot change the job's shell."""
        self.assertEqual(e2e_input_gaps(self.text), [])

    def test_control_an_unexercised_input_is_named(self) -> None:
        old = self.text.replace('"wait_for_target=5"', '"base_url=http://fixed-target:${DEMO_PORT}"')
        self.assertFalse(old == self.text, "the mutation did not apply")
        self.assertEqual(e2e_input_gaps(old), ["wait_for_target: no e2e row sets it, and it changes the job's shell"])

    def test_a_refusal_row_could_only_fall_through_to_the_counted_target(self) -> None:
        """Each "0 requests" row must be one where a job that stopped refusing
        would reach vulnerable-target. The unset-base-url row used to leave
        base_url to the example configuration's 127.0.0.1, inside the job
        container: with the refusal deleted it probed nothing counted and
        still read "0 requests ok" (measured)."""
        self.assertEqual(e2e_fall_through_problems(self.text), [])

    def test_control_the_old_unset_base_url_row_is_noticed(self) -> None:
        old = self.text.replace(" config=veridor-fallthrough.json\n", "\n")
        self.assertFalse(old == self.text, "the mutation did not apply")
        self.assertEqual(e2e_fall_through_problems(old),
                         ["unset-base-url: counts vulnerable-target, but a fall-through goes to the example "
                          "configuration's own target"])


#: Where GitLab Runner's shell detection looks for bash, in its order
#: (gitlab-runner shells/bash.go); then it falls back to sh.
RUNNER_BASH_PATHS = "/usr/local/bin/bash /usr/bin/bash /bin/bash"


def e2e_shell_problems(text: str) -> list[str]:
    """Every row of the e2e script runs the job in the shell GitLab Runner
    would pick for the image (``runner``) or in sh, never a bash the image
    may not have; both kinds are used, and the detection tries the runner's
    bash paths in the runner's order."""
    # A literal shell word; run_proxy_row's own `run_job "$dir" "$2"` passes its caller's.
    calls = re.findall(r'^\s*((?:run_job|run_proxy_row) "\$dir" ([a-z]+) .*)$', text, re.M)
    if not calls:
        return ["found no run_job or run_proxy_row row; the parser no longer matches the script"]
    problems = [f"a row runs under {shell} whatever its image holds: {line.strip()}"
                for line, shell in calls if shell not in ("runner", "sh")]
    used = {shell for _, shell in calls}
    for shell in ("runner", "sh"):
        if shell not in used:
            problems.append(f"no row runs under {shell}")
    if f"for b in {RUNNER_BASH_PATHS}; do" not in text:
        problems.append(f"runner_shell does not try {RUNNER_BASH_PATHS}, in that order")
    problems += e2e_debian_shell_problems(text)
    return problems


#: The rows named for a shell the Alpine images do not have, and how each is
#: run in the Debian image: dash is its /bin/sh, bash is what the runner picks.
E2E_DEBIAN_ROWS = {"dash": "sh", "bash": "runner", "proxy-variable-dash": "sh"}
#: What GitLab Runner writes at the top of every bash or sh job script.
RUNNER_HEADER = """case "$(set -o)" in *"pipefail"*) set -o pipefail;; esac; set -o errexit"""


def e2e_debian_shell_problems(text: str) -> list[str]:
    """Once IMAGE and the pip row's image were both Alpine, every row
    ran busybox sh: the "dash" rows re-ran the vulnerable and proxy-variable
    rows command for command, and no row ran bash or dash. Each row named for
    a shell runs in the Debian image, under that shell, and checks it."""
    problems = []
    if 'debian_inputs=("install=pip" "python_image=${E2E_DEBIAN_PYTHON_IMAGE}"' not in text:
        problems.append("no debian_inputs rendering the pip install in E2E_DEBIAN_PYTHON_IMAGE")
    blocks = e2e_row_blocks(text)
    for row, shell in E2E_DEBIAN_ROWS.items():
        block = blocks.get(row)
        if block is None:
            problems.append(f"row {row}: missing")
            continue
        if not re.search(r'^render "\$dir" "\$\{debian_inputs\[@\]\}" ', block, re.M):
            problems.append(f"row {row}: not rendered with debian_inputs, so it runs no {row}")
        if not re.search(rf'^(?:run_job|run_proxy_row) "\$dir" {shell} ', block, re.M):
            problems.append(f"row {row}: not run under {shell}")
        if not re.search(r"^check_shell ", block, re.M):
            problems.append(f"row {row}: never checks the shell it ran under")
    if f"readonly RUNNER_HEADER='{RUNNER_HEADER}" not in text or \
            'printf \'%s\\n\' "$RUNNER_HEADER" | cat - "$dir/job.sh" > "$dir/runner-job.sh"' not in text:
        problems.append("the job script does not start with GitLab Runner's header")
    return problems


def e2e_row_blocks(text: str) -> dict[str, str]:
    """``{row: its lines}`` for every ``log "row NAME"`` block of the e2e script."""
    parts = re.split(r'(?m)^log "row ([\w-]+)"\n', text.split("# --- the table", 1)[0])
    return dict(zip(parts[1::2], parts[2::2]))


def e2e_inputs_set(text: str) -> set[str]:
    """Component inputs some e2e row renders with an explicit value."""
    names: set[str] = set()
    base = re.search(r"(?m)^base_inputs=\((.*)\)$", text)
    logical = text.replace("\\\n", " ")
    lines = [line for line in logical.splitlines() if line.startswith("render ")]
    if base is not None:
        lines.append(base.group(1))
    for line in lines:
        names.update(re.findall(r"""(?:^|\s)["']?([a-z_]+)=""", line))
    return names


def e2e_input_gaps(text: str) -> list[str]:
    """Inputs no row moves, unless changing them leaves the job's shell as it is."""
    inputs, _, default_job = rendered_job()
    moved = e2e_inputs_set(text)
    gaps = []
    for name in inputs:
        if name in moved:
            continue
        _, _, changed = rendered_job(given={name: cv.NON_DEFAULT_INPUTS[name]})
        if cv.job_shell(changed) != cv.job_shell(default_job):
            gaps.append(f"{name}: no e2e row sets it, and it changes the job's shell")
    return gaps


def e2e_fall_through_problems(text: str) -> list[str]:
    """Rows that expect 0 requests to a target but whose job could not reach it."""
    counted = re.search(r'"\$WORK/project/veridor-fallthrough\.json" "http://vulnerable-target:\$\{DEMO_PORT\}"', text)
    problems = []
    for row, block in e2e_row_blocks(text).items():
        if not re.search(r'vulnerable-target 0 "\$before"', block):
            continue
        render = next(line for line in block.splitlines() if line.startswith("render "))
        if "base_url=http://vulnerable-target:" in render:
            continue
        if "config=veridor-fallthrough.json" in render and counted:
            continue
        problems.append(f"{row}: counts vulnerable-target, but a fall-through goes to the example "
                        "configuration's own target")
    return problems


@slow("runs each template's gate shell against a loopback demo target with the real CLI")
class GateShellRunTest(unittest.TestCase):
    """The shell each template runs, executed here with sh against the demo
    target. It exercises the shell and Veridor, not the platform: no GitLab,
    Jenkins, Azure or CodeBuild semantics are involved (ci/README.md)."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import demo_server  # noqa: PLC0415

        cls.servers = []
        cls.urls = {}
        # suspected: the other tenant gets 200 but no marker, so the finding
        # is graded suspected rather than confirmed.
        for name, vulnerable, leak in (("vulnerable", True, True), ("fixed", False, True),
                                       ("suspected", True, False)):
            server = demo_server.create_server("127.0.0.1", 0, vulnerable=vulnerable, leak_marker=leak)
            loopback.start(server)
            cls.servers.append(server)
            cls.urls[name] = f"http://127.0.0.1:{server.server_port}"
        cls.urls["unreachable"] = "http://127.0.0.1:9"

    @classmethod
    def tearDownClass(cls) -> None:
        for server in cls.servers:
            server.shutdown()
            server.server_close()

    def run_shell(self, shell: str, env: dict[str, str],
                  files: dict[str, Path] | None = None) -> tuple[int, str, Path]:
        project = Path(tempfile.mkdtemp(prefix="vg-ci-shell-"))
        self.addCleanup(shutil.rmtree, project, True)
        shutil.copy(cv.EXAMPLE_CONFIG, project / "veridor.json")
        for name, source in (files or {}).items():
            shutil.copy(source, project / name)
        bin_dir = project / ".bin"
        bin_dir.mkdir()
        shim = bin_dir / "veridor"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -B -m veridor "$@"\n', encoding="utf-8")
        shim.chmod(0o755)
        (project / "job.sh").write_text(shell, encoding="utf-8")
        full_env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(project),
            **source_path.child_env({}),
            "VERIDOR_OWNER_TOKEN": "owner-token",
            "VERIDOR_OTHER_TENANT_TOKEN": "outsider-token",
            "VERIDOR_ADMIN_TOKEN": "admin-token",
            **env,
        }
        result = subprocess.run(["sh", "-e", "job.sh"], cwd=project, env=full_env, capture_output=True,
                                text=True, timeout=120, check=False)
        return result.returncode, result.stdout + result.stderr, project

    def platform_shells(self) -> dict[str, str]:
        azure_gate = next(s["bash"] for s in cv.azure_steps(azure_document()) if "veridor run" in s.get("bash", ""))
        build = buildspec_document()["phases"]["build"]["commands"]
        return {"jenkins": jenkins_shell(), "azure": azure_gate, "codebuild": "\n".join(build) + "\n"}

    def platform_env(self, platform: str, url: str, allow_unmeasured: str | None = None) -> dict[str, str]:
        """The platform's own shipped fail-on and allow-unmeasured values,
        unless a test overrides the latter. Azure passes a boolean runtime
        parameter as text; its case there (True) is inferred, and the step
        accepts either case."""
        shipped = shipped_gating()[platform]
        if allow_unmeasured is None:
            allow_unmeasured = str(shipped["allow_unmeasured"] or "false").capitalize()
        return {"VERIDOR_CONFIG": "veridor.json", "VERIDOR_FAIL_ON": str(shipped["fail_on"]), "VERIDOR_BASE_URL": url,
                "VERIDOR_BASELINE": "", "VERIDOR_OUTPUT_DIR": "veridor-out",
                "VERIDOR_ALLOW_UNMEASURED": allow_unmeasured}

    def assert_reports(self, out: Path, names: list[str]) -> None:
        import xml.etree.ElementTree as ET  # noqa: PLC0415

        for name in names:
            path = out / name
            self.assertTrue(path.is_file(), f"{path} was not written")
            if name.endswith(".xml"):
                self.assertTrue(ET.parse(path).getroot().findall(".//testcase"))
            elif name.endswith(".json") or name.endswith(".sarif"):
                json.loads(path.read_text(encoding="utf-8"))

    def test_the_gitlab_job_exits_with_veridors_code_and_writes_every_report(self) -> None:
        for target, expected, line in (("vulnerable", 1, "exit 1: FAIL"), ("fixed", 0, "exit 0: PASS"),
                                       ("unreachable", 3, "exit 3: INCOMPLETE, failing the job")):
            with self.subTest(target=target):
                _, _, job = rendered_job(given={"base_url": self.urls[target]})
                status, output, project = self.run_shell(cv.job_shell(job), {})
                self.assertEqual(status, expected, output)
                self.assertIn(line, output)
                written = [Path(p).name for p in job["artifacts"]["paths"]]
                self.assert_reports(project / "veridor-out", written)

    def test_the_baseline_input_suppresses_only_what_fail_on_says(self) -> None:
        """The fail_on description, run through the rendered job at its default
        policy: a baseline that already holds a suspected finding turns exit 1
        into 0, and one that holds a confirmed finding does not. The
        description used to say the default "cannot be defeated by editing the
        baseline"."""
        for target, grade, expected in (("suspected", "suspected", 0), ("vulnerable", "confirmed", 1)):
            with self.subTest(target=target):
                _, _, seed_job = rendered_job(given={"base_url": self.urls[target]})
                status, output, seed = self.run_shell(cv.job_shell(seed_job), {})
                self.assertEqual(status, 1, output)  # without a baseline the finding gates
                seed_run = seed / "veridor-out" / "veridor-run.json"
                findings = json.loads(seed_run.read_text(encoding="utf-8"))["findings"]
                self.assertEqual({f.get("evidence_grade") for f in findings}, {grade})
                _, _, job = rendered_job(given={"base_url": self.urls[target], "baseline": "baseline.json"})
                status, output, _ = self.run_shell(cv.job_shell(job), {}, files={"baseline.json": seed_run})
                self.assertEqual(status, expected, output)
                self.assertIn("Suppressed by the baseline" if expected == 0 else "exit 1: FAIL", output)
                if expected == 0:
                    # The exit-0 line no longer says every expectation held.
                    self.assertIn("veridor-gate: exit 0: PASS. Nothing that --fail-on new+confirmed gates on "
                                  "was found. A finding it does not gate on, such as one in the baseline", output)
                    self.assertEqual(overclaim_problems({"log": output}), [])

    def test_every_platform_shell_exits_with_veridors_code(self) -> None:
        for platform, shell in self.platform_shells().items():
            for target, expected in (("vulnerable", 1), ("fixed", 0), ("unreachable", 3)):
                with self.subTest(platform=platform, target=target):
                    status, output, project = self.run_shell(shell, self.platform_env(platform, self.urls[target]))
                    self.assertEqual(status, expected, output)
                    self.assert_reports(project / "veridor-out",
                                        ["veridor-run.json", "veridor-junit.xml", "veridor.sarif", "veridor-summary.md"])

    def test_a_pass_that_leaves_a_finding_ungated_says_so(self) -> None:
        """Azure and CodeBuild with the policy at none, against the vulnerable
        target: exit 0 over a vulnerable finding. The line names the policy and
        no longer says every declared expectation held (it did, measured)."""
        for platform in ("azure", "codebuild"):
            with self.subTest(platform=platform):
                env = dict(self.platform_env(platform, self.urls["vulnerable"]), VERIDOR_FAIL_ON="none")
                status, output, _ = self.run_shell(self.platform_shells()[platform], env)
                self.assertEqual(status, 0, output)
                self.assertIn("1 vulnerable", output)
                self.assertIn("veridor-gate: exit 0: PASS. Nothing that --fail-on none gates on was found. "
                              "A finding it does not gate on", output)
                self.assertEqual(overclaim_problems({"log": output}), [])

    def test_azure_downgrades_exit_3_only_when_asked(self) -> None:
        shell = self.platform_shells()["azure"]
        status, output, _ = self.run_shell(shell, self.platform_env("azure", self.urls["unreachable"], "True"))
        self.assertEqual(status, 0, output)
        self.assertIn("##vso[task.complete result=SucceededWithIssues;]", output)
        status, output, _ = self.run_shell(shell, self.platform_env("azure", self.urls["unreachable"], "False"))
        self.assertEqual(status, 3, output)
        self.assertNotIn("task.complete", output)
        status, output, _ = self.run_shell(shell, self.platform_env("azure", self.urls["unreachable"], "yes"))
        self.assertEqual(status, 2, output)

    def test_a_base_url_variable_reaches_the_target_or_is_refused(self) -> None:
        """The documented review-app form, base_url: $REVIEW_APP_URL. Set, it
        is the target probed. Unset, the job refuses, and the advice says
        what an empty input would do instead: probe the configuration's own
        target. It used to say only "leave the input empty on purpose"."""
        _, _, job = rendered_job(given={"base_url": "$REVIEW_APP_URL"})
        status, output, _ = self.run_shell(cv.job_shell(job), {"REVIEW_APP_URL": self.urls["vulnerable"]})
        self.assertEqual(status, 1, output)
        status, output, project = self.run_shell(cv.job_shell(job), {})
        self.assertEqual(status, 2, output)
        self.assertIn("leave the input empty to probe the configuration's own target.base_url instead", output)
        self.assertFalse((project / "veridor-out" / "veridor-run.json").exists())
        for name, what in (("baseline", "run without a baseline"), ("openapi", "run without an OpenAPI document")):
            with self.subTest(input=name):
                _, _, other = rendered_job(given={"base_url": self.urls["fixed"], name: "$UNSET_INPUT"})
                status, output, _ = self.run_shell(cv.job_shell(other), {})
                self.assertEqual(status, 2, output)
                self.assertIn(f"leave the input empty to {what}", output)

    def test_the_gitlab_job_passes_wait_for_target_only_when_it_waits(self) -> None:
        """0 passes no flag (the stderr line never appears); a whole number
        passes it; anything else is refused before veridor runs."""
        for value, expected, waited in ((0, 0, False), (2, 0, True)):
            with self.subTest(wait_for_target=value):
                _, _, job = rendered_job(given={"base_url": self.urls["fixed"], "wait_for_target": value})
                status, output, _ = self.run_shell(cv.job_shell(job), {})
                self.assertEqual(status, expected, output)
                self.assertEqual("accepted a connection after" in output, waited, output)
        _, _, job = rendered_job(given={"base_url": self.urls["fixed"], "wait_for_target": 1.5})
        status, output, project = self.run_shell(cv.job_shell(job), {})
        self.assertEqual(status, 2, output)
        self.assertIn("Input wait_for_target is '1.5'", output)
        self.assertFalse((project / "veridor-out" / "veridor-run.json").exists())

    def test_a_variable_reference_is_expanded_not_executed(self) -> None:
        """What the input regexes still let through, $NAME, is safe: the shell
        expands a variable's value without reading it again as code. The
        control renders a template whose base_url regex admits anything and
        passes `$(touch ...)` as literal input text: the marker appears, so
        this run can see an execution when one happens."""
        marker = Path(tempfile.mkdtemp(prefix="vg-ci-marker-")) / "pwned"
        self.addCleanup(shutil.rmtree, marker.parent, True)
        hostile = f"$(touch {marker}){self.urls['fixed']}"
        _, _, job = rendered_job(given={"base_url": "$EVIL"})
        status, output, _ = self.run_shell(cv.job_shell(job), {"EVIL": hostile})
        self.assertFalse(marker.exists(), output)
        self.assertEqual(status, 2, output)  # veridor refuses the literal text as a base URL

        permissive = re.sub(r"(?m)^(    base_url:\n(?:      [^\n]*\n)*?      regex: )'[^\n]*'$", r"\1'^.*$'",
                            component_text())
        self.assertFalse(permissive == component_text(), "the mutation did not apply")
        _, _, job = rendered_job(permissive, {"base_url": hostile.replace(" ", "${IFS}")})
        self.run_shell(cv.job_shell(job), {})
        self.assertTrue(marker.exists(), "control: a $(...) pasted into the script did not run")

    def test_a_proxy_variable_reaches_veridor_only_when_the_input_says_so(self) -> None:
        """A pipeline variable named http_proxy, in any case, used to carry
        every credential to the proxy it named although base_url was a
        literal (measured: 9 requests, the owner, other-tenant and admin
        tokens). By default the job now removes every *_proxy variable before
        veridor runs, and says which; ALL_PROXY, which Veridor does not read,
        goes too. proxy_from_environment: true keeps them: the control, which
        shows this capture sees the requests when they come."""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: PLC0415

        seen: list[str] = []

        class Capture(BaseHTTPRequestHandler):
            def answer(self) -> None:
                seen.append(self.headers.get("Authorization", ""))
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_CONNECT = answer

            def log_message(self, *args: object) -> None:
                pass

        capture = ThreadingHTTPServer(("127.0.0.1", 0), Capture)
        loopback.start(capture)
        self.addCleanup(capture.server_close)
        self.addCleanup(capture.shutdown)
        proxy = f"http://127.0.0.1:{capture.server_port}"
        names = {"http_proxy", "HTTP_PROXY", "Http_Proxy", "HTTPS_PROXY", "ALL_PROXY"}
        # Not loopback, so Veridor would follow a proxy; .invalid never resolves.
        base = {"base_url": "http://staging.invalid:8080"}

        _, _, job = rendered_job(given=base)
        status, output, _ = self.run_shell(cv.job_shell(job), dict.fromkeys(names, proxy))
        self.assertEqual(seen, [], output)
        self.assertEqual(status, 3, output)  # the target itself is unreachable
        removed = re.search(r"veridor-gate: removed (.*) from veridor's environment", output)
        self.assertIsNotNone(removed, output)
        self.assertEqual(set(removed.group(1).split()), names, output)
        self.assertNotIn("go through the proxy", output)

        _, _, job = rendered_job(given=dict(base, proxy_from_environment=True))
        status, output, _ = self.run_shell(cv.job_shell(job), dict.fromkeys(names, proxy))
        self.assertIn("Bearer owner-token", seen, output)
        self.assertIn(f"go through the proxy 127.0.0.1:{capture.server_port}", output)
        self.assertIn("veridor-gate: proxy_from_environment is true", output)

        seen.clear()
        _, _, job = rendered_job(given=base)
        status, output, _ = self.run_shell(cv.job_shell(job), {})
        self.assertEqual(seen, [], output)
        self.assertIn("veridor-gate: no proxy variable is set", output)

    def test_an_image_without_the_proxy_tools_is_refused(self) -> None:
        """The proxy removal finds names with env and sed and checks each with
        printenv. With one of them missing from the job's image, its error was
        swallowed by the command substitution and the `if`, nothing was
        removed, and the log said "no proxy variable is set" while http_proxy
        and HTTPS_PROXY reached veridor (measured: exit 3 through the proxy).
        Each missing tool is now refused with exit 2 before anything is sent;
        the control, with all three present, removes both and runs."""
        proxy = "http://127.0.0.1:9"
        names = {"http_proxy", "HTTPS_PROXY"}
        _, _, job = rendered_job(given={"base_url": "http://staging.invalid:8080"})
        shell = cv.job_shell(job)
        for missing in ("env", "sed", "printenv", None):
            with self.subTest(missing=missing):
                bin_dir = Path(tempfile.mkdtemp(prefix="vg-ci-tools-"))
                self.addCleanup(shutil.rmtree, bin_dir, True)
                for tool in ("sh", "mkdir", "rm", "id", "env", "sed", "printenv"):
                    found = shutil.which(tool)
                    self.assertIsNotNone(found, f"{tool} is not on this host's PATH")
                    if tool != missing:
                        (bin_dir / tool).symlink_to(found)
                shim = bin_dir / "veridor"
                shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -B -m veridor "$@"\n', encoding="utf-8")
                shim.chmod(0o755)
                status, output, project = self.run_shell(shell, {"PATH": str(bin_dir), **dict.fromkeys(names, proxy)})
                if missing is None:
                    self.assertEqual(status, 3, output)  # the target itself is unreachable
                    removed = re.search(r"veridor-gate: removed (.*) from veridor's environment", output)
                    self.assertIsNotNone(removed, output)
                    self.assertEqual(set(removed.group(1).split()), names, output)
                    continue
                self.assertEqual(status, 2, output)
                self.assertIn(f"has no {missing}", output)
                self.assertNotIn("no proxy variable is set", output)
                self.assertFalse((project / "veridor-out" / "veridor-run.json").exists(), output)

    def test_azure_refuses_an_undefined_secret_mapping(self) -> None:
        shell = self.platform_shells()["azure"]
        env = dict(self.platform_env("azure", self.urls["vulnerable"]), VERIDOR_ADMIN_TOKEN="$(VERIDOR_ADMIN_TOKEN)")
        status, output, project = self.run_shell(shell, env)
        self.assertEqual(status, 2, output)
        self.assertIn("VERIDOR_ADMIN_TOKEN", output)
        self.assertFalse((project / "veridor-out" / "veridor-run.json").exists())


@slow("spawns bash to run the e2e script's refusals, and shellcheck when present")
class E2EScriptRefusalTest(unittest.TestCase):
    def run_script(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        base = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
        return subprocess.run(["bash", str(E2E_SCRIPT)], env={**base, **env}, capture_output=True,
                              text=True, timeout=60, check=False)

    def test_missing_image_is_refused(self) -> None:
        result = self.run_script({})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("IMAGE is not set", result.stderr)

    def test_missing_schema_is_refused(self) -> None:
        result = self.run_script({"IMAGE": "veridor:e2e"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("SAST_SCHEMA is not set", result.stderr)

    def test_an_unknown_control_is_refused(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json") as schema:
            result = self.run_script({"IMAGE": "veridor:e2e", "SAST_SCHEMA": schema.name, "E2E_CONTROL": "nope"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("is not a control this script knows", result.stderr)

    def test_shellcheck_is_clean(self) -> None:
        # CI sets VERIDOR_REQUIRE_SHELLCHECK=1; there a missing shellcheck is a
        # failure, not a skip that reads as a pass in a green job.
        if shutil.which("shellcheck") is None:
            if os.environ.get(REQUIRE_SHELLCHECK_ENV) == "1":
                self.fail(f"shellcheck is not on PATH and {REQUIRE_SHELLCHECK_ENV}=1 says this must run")
            self.skipTest(f"shellcheck is not on PATH (set {REQUIRE_SHELLCHECK_ENV}=1 to make this a failure)")
        with tempfile.TemporaryDirectory() as tmp:
            targets = [str(E2E_SCRIPT)]
            for source, (shell, _) in shipped_shells().items():
                path = Path(tmp) / (re.sub(r"\W+", "-", source) + ".sh")
                path.write_text(shell, encoding="utf-8")
                targets.append(str(path))
            for target in targets:
                with self.subTest(target=Path(target).name):
                    dialect = [] if target == str(E2E_SCRIPT) else ["-s", "sh"]
                    result = subprocess.run(["shellcheck", *dialect, target], capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            control = Path(tmp) / "control.sh"
            control.write_text("x=(a b)\necho $x\n", encoding="utf-8")
            result = subprocess.run(["shellcheck", "-s", "sh", str(control)], capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0, "control: shellcheck passed a broken script")


def e2e_shell_function(text: str, name: str) -> str:
    match = re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}\n", text)
    if match is None:
        raise AssertionError(f"{name}() is gone from the e2e script")
    return match.group(0)


def e2e_check_py(text: str) -> str:
    match = re.search(r"(?s)cat > \"\$WORK/check\.py\" <<'PYEOF'\n(.*?)\nPYEOF\n", text)
    if match is None:
        raise AssertionError("check.py is gone from the e2e script")
    return match.group(1)


@slow("runs the e2e script's request counter under bash with a stand-in docker, and its check.py")
class E2ERequestCountTest(unittest.TestCase):
    """What the e2e script reports when it cannot read a target's log.

    requests_seen used to turn a failed `docker logs` into 0, so after the
    counted target was removed four refusal rows read "0 requests ok" and the
    run exited 0 (measured). And under bash 3.2 with set -E its `grep -c`
    fired the ERR trap on a count of 0, printing "stopped before the table" on
    every passing run. Both are run here with the script's own functions."""

    FAKE_DOCKER = ('#!/bin/sh\ncase "$FAKE_DOCKER" in\n'
                   '  fail) echo "Error response from daemon: No such container: $2" >&2; exit 1 ;;\n'
                   '  zero) echo READY ;;\n'
                   "  two) printf 'READY\\nREQ GET /a\\nREQ GET /b\\n' ;;\n"
                   "esac\n")

    def count(self, text: str, mode: str) -> tuple[str, str]:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        tmp = Path(tempfile.mkdtemp(prefix="vg-e2e-count-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "bin").mkdir()
        docker = tmp / "bin" / "docker"
        docker.write_text(self.FAKE_DOCKER, encoding="utf-8")
        docker.chmod(0o755)
        harness = tmp / "harness.sh"
        harness.write_text(
            "set -Eeuo pipefail\nWORK=\"$1\"\nRUN_ID=t\n"
            + e2e_shell_function(text, "on_error")
            + "trap 'on_error \"$LINENO\" \"$BASH_COMMAND\"' ERR\n"
            + e2e_shell_function(text, "requests_seen")
            + 'count="$(requests_seen vulnerable-target)"\nprintf \'count=[%s]\\n\' "$count"\n',
            encoding="utf-8")
        result = subprocess.run([bash, str(harness), str(tmp)], capture_output=True, text=True, timeout=30,
                                check=False, env={"PATH": f"{tmp / 'bin'}{os.pathsep}/usr/bin:/bin",
                                                  "FAKE_DOCKER": mode})
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip(), result.stderr

    def test_an_unreadable_log_is_never_zero(self) -> None:
        stdout, stderr = self.count(E2E_SCRIPT.read_text(encoding="utf-8"), "fail")
        self.assertEqual(stdout, "count=[unreadable]")
        self.assertIn("cannot count the requests to vulnerable-target", stderr)

    def test_counts_are_counts_and_zero_is_quiet(self) -> None:
        """The positive controls: the stand-in docker's REQ lines are counted,
        and a real 0 is 0 with no ERR-trap line."""
        text = E2E_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(self.count(text, "two")[0], "count=[2]")
        stdout, stderr = self.count(text, "zero")
        self.assertEqual(stdout, "count=[0]")
        self.assertNotIn("stopped before the table", stderr)

    def test_check_py_makes_cannot_see_a_mismatch(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="vg-e2e-check-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        script = tmp / "check.py"
        script.write_text(e2e_check_py(E2E_SCRIPT.read_text(encoding="utf-8")), encoding="utf-8")
        row = tmp / "row"
        row.mkdir()
        (row / "log").write_text("veridor-gate: exit 2: REFUSED.\n", encoding="utf-8")

        def rows(before: str, after: str) -> list[list[str]]:
            result = subprocess.run([sys.executable, str(script), "unused-schema", str(row), "2", "2", "no",
                                     "exit 2: REFUSED", "vulnerable-target", "0", before, after],
                                    capture_output=True, text=True, timeout=30, check=True)
            return [line.split("\t") for line in result.stdout.splitlines()]

        unseen = rows("unreadable", "unreadable")[-1]
        self.assertEqual(unseen[1], "requests to vulnerable-target")
        self.assertTrue(unseen[3].startswith("cannot see"), unseen)
        self.assertEqual(unseen[4], "MISMATCH")
        self.assertEqual(rows("9", "9")[-1][3:], ["0", "ok"])
        self.assertEqual(rows("9", "12")[-1][3:], ["3", "MISMATCH"])


class ShellcheckRequirementTest(unittest.TestCase):
    """The control for E2EScriptRefusalTest.test_shellcheck_is_clean's skip:
    with PATH stripped of shellcheck it skips by default and FAILS under
    VERIDOR_REQUIRE_SHELLCHECK=1. It used to skip either way, so the variable
    CI sets to make the check unskippable protected nothing here. No
    subprocess runs: without shellcheck the test stops before spawning."""

    def outcome(self, env: dict[str, str]) -> unittest.TestResult:
        result = unittest.TestResult()
        empty = tempfile.mkdtemp(prefix="veridor-no-shellcheck-")
        self.addCleanup(shutil.rmtree, empty, True)
        with mock.patch.dict(os.environ, {"PATH": empty, **env}):
            if REQUIRE_SHELLCHECK_ENV not in env:
                os.environ.pop(REQUIRE_SHELLCHECK_ENV, None)
            self.assertIsNone(shutil.which("shellcheck"), "the PATH was not stripped")
            E2EScriptRefusalTest("test_shellcheck_is_clean").run(result)
        return result

    def test_missing_shellcheck_skips_by_default(self) -> None:
        result = self.outcome({})
        self.assertEqual((len(result.skipped), len(result.failures), len(result.errors)), (1, 0, 0))

    def test_missing_shellcheck_fails_when_required(self) -> None:
        result = self.outcome({REQUIRE_SHELLCHECK_ENV: "1"})
        self.assertEqual((len(result.skipped), len(result.failures), len(result.errors)), (0, 1, 0))
        self.assertIn(REQUIRE_SHELLCHECK_ENV, result.failures[0][1])


if __name__ == "__main__":
    unittest.main()
