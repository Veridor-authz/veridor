"""Run a composite GitHub Action the way the runner does, closely enough to test it.

``action.yml`` is the surface most users meet Veridor through, and it is a
shell program embedded in YAML and wired together with GitHub expressions. A
test that extracts one ``run:`` block and runs it under ``bash -c`` cannot see
the parts that decide whether the gate holds: the ``env:`` mapping from
``inputs``, the step that turns an output into the job's verdict, the
``outputs:`` block that reads ``steps.<id>.outputs``, or the shell flags the
runner adds. This module executes the whole ``runs.steps`` list in order:

* each ``run:`` is written to a file under ``RUNNER_TEMP`` and run as
  ``bash --noprofile --norc -eo pipefail FILE`` -- the command GitHub documents
  for ``shell: bash``;
* ``GITHUB_OUTPUT``, ``GITHUB_ENV``, ``GITHUB_PATH`` and ``GITHUB_STEP_SUMMARY``
  are real files, and the first three are parsed after each step with the
  runner's ``name=value`` and ``name<<DELIMITER`` syntax;
* ``${{ ... }}`` is evaluated for the subset of the expression language the
  Action uses: ``inputs.X`` (also ``inputs['x-y']``), ``github.action_path``,
  ``github.workspace``, ``steps.ID.outputs.K``, ``env.X`` and ``runner.temp``,
  plus the status functions a step ``if:`` can use;
* a step whose ``if:`` is absent runs only while nothing has failed, as on
  GitHub.

Anything outside that subset RAISES. A harness that substituted an empty string
for an expression it could not read would turn ``${{ inputs.read-onyl }}`` into
a silently disabled flag, which is the defect class this repository exists to
catch; so an unknown context, operator, function, input, step id or YAML
construct is an error in the test, never a blank.

YAML is parsed by tests/yaml_subset.py, the suite's one strict subset reader
(the suite is stdlib-only), in its untyped mode: every scalar stays the string
it was written as, the way the runner hands values to a step. It refuses
anchors, aliases, tags, flow mappings, multi-line plain scalars, document
markers, duplicate keys and tabs.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from yaml_subset import YAMLSubsetError, load_yaml_text  # noqa: E402

__all__ = [
    "ActionRun",
    "ExpressionError",
    "HarnessError",
    "StepRun",
    "YAMLSubsetError",
    "evaluate",
    "load_yaml",
    "parse_file_commands",
    "run_action",
]


def load_yaml(text: str) -> Any:
    """One document, every scalar a string (tests/yaml_subset.py, untyped)."""
    return load_yaml_text(text, typed=False)


class ExpressionError(ValueError):
    """A ``${{ }}`` expression outside the evaluated subset, or unresolvable."""


class HarnessError(RuntimeError):
    """The action uses a runner feature this harness does not model."""


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_IDENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_ACCESS = re.compile(rf"^({_IDENT})((?:\.{_IDENT}|\['[^']*'\])*)$")
_STATUS = {"always()", "success()", "failure()", "cancelled()", "!cancelled()"}


@dataclass
class Context:
    """Everything an expression may read."""

    inputs: dict[str, str]
    declared_inputs: set[str]
    action_path: str
    workspace: str
    runner_temp: str
    env: dict[str, str]
    step_ids: list[str]
    completed_steps: dict[str, dict[str, str]]
    failed: bool = False


def _path_parts(tail: str) -> list[str]:
    parts = []
    for match in re.finditer(rf"\.({_IDENT})|\['([^']*)'\]", tail):
        parts.append(match.group(1) if match.group(1) is not None else match.group(2))
    return parts


def _lookup(expression: str, context: Context) -> str:
    match = _ACCESS.match(expression)
    if not match:
        raise ExpressionError(f"cannot evaluate {expression!r}: only context property access is supported")
    root, parts = match.group(1), _path_parts(match.group(2))
    if root == "inputs" and len(parts) == 1:
        name = parts[0]
        if name not in context.declared_inputs:
            raise ExpressionError(f"inputs.{name} is not a declared input")
        return context.inputs[name]
    if root == "github" and parts == ["action_path"]:
        return context.action_path
    if root == "github" and parts == ["workspace"]:
        return context.workspace
    if root == "runner" and parts == ["temp"]:
        return context.runner_temp
    if root == "env" and len(parts) == 1:
        if parts[0] not in context.env:
            raise ExpressionError(f"env.{parts[0]} is not set")
        return context.env[parts[0]]
    if root == "steps" and len(parts) == 3 and parts[1] == "outputs":
        step, key = parts[0], parts[2]
        if step not in context.step_ids:
            raise ExpressionError(f"steps.{step}: no step has that id")
        if step not in context.completed_steps:
            raise ExpressionError(f"steps.{step} has not run yet")
        # GitHub: an output the step never wrote reads as an empty string.
        return context.completed_steps[step].get(key, "")
    raise ExpressionError(f"cannot evaluate {expression!r}: context not modelled by the harness")


def evaluate(value: str, context: Context) -> str:
    """Substitute every ``${{ }}`` in a string value."""
    if not isinstance(value, str):
        raise ExpressionError(f"expected a string, got {type(value).__name__}")

    def substitute(match: re.Match[str]) -> str:
        return _lookup(match.group(1).strip(), context)

    result = _EXPRESSION.sub(substitute, value)
    if "${{" in result:
        raise ExpressionError(f"unterminated expression in {value!r}")
    return result


def evaluate_condition(condition: Any, context: Context) -> bool:
    """A step's ``if:``. Absent means ``success()``."""
    if condition is None:
        return not context.failed
    if not isinstance(condition, str):
        raise ExpressionError(f"unsupported if: {condition!r}")
    text = condition.strip()
    whole = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.S)
    if whole:
        text = whole.group(1).strip()
    if text not in _STATUS:
        raise ExpressionError(f"cannot evaluate if: {condition!r}")
    return {
        "always()": True,
        "success()": not context.failed,
        "failure()": context.failed,
        "cancelled()": False,
        "!cancelled()": True,
    }[text]


# ---------------------------------------------------------------------------
# File commands
# ---------------------------------------------------------------------------


def parse_file_commands(text: str, source: str = "file command") -> list[tuple[str, str]]:
    """Parse GITHUB_OUTPUT / GITHUB_ENV contents: ``k=v`` and ``k<<DELIM``."""
    pairs: list[tuple[str, str]] = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "":
            index += 1
            continue
        heredoc = re.match(r"^([^=\s<]+)<<(.+)$", line)
        if heredoc and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = heredoc.groups()
            body: list[str] = []
            index += 1
            while index < len(lines) and lines[index] != delimiter:
                body.append(lines[index])
                index += 1
            if index >= len(lines):
                raise HarnessError(f"{source}: delimiter {delimiter!r} for {name!r} never closed")
            pairs.append((name, "\n".join(body)))
            index += 1
            continue
        if "=" not in line:
            raise HarnessError(f"{source}: malformed line {line!r}")
        name, value = line.split("=", 1)
        if not name:
            raise HarnessError(f"{source}: empty name in {line!r}")
        pairs.append((name, value))
        index += 1
    return pairs


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_STEP_KEYS = {"name", "id", "shell", "run", "env", "if", "working-directory"}


@dataclass
class StepRun:
    id: str | None
    name: str
    ran: bool
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    outputs: dict[str, str] = field(default_factory=dict)

    @property
    def outcome(self) -> str:
        if not self.ran:
            return "skipped"
        return "success" if self.returncode == 0 else "failure"


@dataclass
class ActionRun:
    steps: list[StepRun]
    outputs: dict[str, str]
    summary: str

    @property
    def failed(self) -> bool:
        return any(step.outcome == "failure" for step in self.steps)

    @property
    def returncode(self) -> int:
        """The exit code of the step that failed the action, else 0."""
        for step in self.steps:
            if step.outcome == "failure":
                return step.returncode  # type: ignore[return-value]
        return 0

    @property
    def log(self) -> str:
        return "".join(step.stdout + step.stderr for step in self.steps)

    def annotations(self, level: str = "error") -> list[str]:
        found = []
        for line in self.log.splitlines():
            match = re.match(rf"^::{level}(?: [^:]*)?::(.*)$", line)
            if match:
                found.append(match.group(1))
        return found


def load_action(action_dir: Path) -> dict:
    action = load_yaml((action_dir / "action.yml").read_text(encoding="utf-8"))
    if not isinstance(action, dict):
        raise HarnessError("action.yml is not a mapping")
    runs = action.get("runs") or {}
    if runs.get("using") != "composite":
        raise HarnessError(f"runs.using is {runs.get('using')!r}; the harness runs composite actions only")
    return action


def run_action(
    action_dir: Path,
    inputs: dict[str, str],
    *,
    workspace: Path,
    runner_temp: Path,
    path: list[str],
    summary_file: Path | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: float = 300,
) -> ActionRun:
    """Execute ``action_dir/action.yml`` with ``inputs``, as a workflow step would.

    ``path`` is the complete PATH, in order: nothing from the calling process
    leaks in, so a test states which interpreter the action can find.
    """
    action = load_action(action_dir)
    declared = dict(action.get("inputs") or {})
    unknown = set(inputs) - set(declared)
    if unknown:
        # GitHub warns "Unexpected input(s)" and carries on; a test passing an
        # undeclared input has a typo, and must not pass for the wrong reason.
        raise HarnessError(f"inputs not declared by the action: {sorted(unknown)}")
    resolved: dict[str, str] = {}
    for name, spec in declared.items():
        default = (spec or {}).get("default")
        if name in inputs:
            resolved[name] = inputs[name]
        elif default is None:
            resolved[name] = ""  # GitHub does not enforce `required:` for actions
        else:
            if "${{" in str(default):
                raise HarnessError(f"input {name}: expression defaults are not modelled")
            resolved[name] = str(default)

    steps = action["runs"].get("steps") or []
    step_ids = [step.get("id") for step in steps if isinstance(step, dict) and step.get("id")]
    runner_temp.mkdir(parents=True, exist_ok=True)
    commands_dir = runner_temp / "_runner_file_commands"
    commands_dir.mkdir(exist_ok=True)
    summary = summary_file or (runner_temp / "step_summary.md")
    summary.touch()

    job_env: dict[str, str] = {}
    extra_path: list[str] = []
    context = Context(
        inputs=resolved,
        declared_inputs=set(declared),
        action_path=str(action_dir),
        workspace=str(workspace),
        runner_temp=str(runner_temp),
        env={},
        step_ids=step_ids,
        completed_steps={},
    )
    runs: list[StepRun] = []
    for number, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise HarnessError(f"step {number} is not a mapping")
        unsupported = set(step) - _STEP_KEYS
        if unsupported:
            raise HarnessError(f"step {number}: keys the harness does not model: {sorted(unsupported)}")
        if "run" not in step:
            raise HarnessError(f"step {number} has no run:")
        name = str(step.get("name") or f"step {number}")
        base_env = {
            "PATH": os.pathsep.join(extra_path + path),
            "HOME": os.environ.get("HOME", str(runner_temp)),
            "LANG": "C.UTF-8",
            "TMPDIR": str(runner_temp),
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_ACTION_PATH": str(action_dir),
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_STEP_SUMMARY": str(summary),
        }
        base_env.update(extra_env or {})
        base_env.update(job_env)
        context.env = dict(base_env)
        if not evaluate_condition(step.get("if"), context):
            runs.append(StepRun(step.get("id"), name, ran=False, returncode=None))
            continue
        shell = step.get("shell")
        if shell != "bash":
            raise HarnessError(f"step {number}: shell {shell!r}; only `shell: bash` is modelled")
        step_env = {key: evaluate(str(value), context)
                    for key, value in (step.get("env") or {}).items()}
        env = dict(base_env)
        env.update(step_env)
        token = uuid.uuid4().hex
        files = {kind: commands_dir / f"{kind}_{token}" for kind in ("output", "env", "path")}
        for file in files.values():
            file.write_text("", encoding="utf-8")
        env["GITHUB_OUTPUT"] = str(files["output"])
        env["GITHUB_ENV"] = str(files["env"])
        env["GITHUB_PATH"] = str(files["path"])
        script = runner_temp / f"{token}.sh"
        script.write_text(evaluate(str(step["run"]), context), encoding="utf-8")
        cwd = workspace
        if step.get("working-directory"):
            cwd = workspace / evaluate(str(step["working-directory"]), context)
        completed = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
        )
        outputs = dict(parse_file_commands(files["output"].read_text(encoding="utf-8"),
                                           f"{name}: GITHUB_OUTPUT"))
        for key, value in parse_file_commands(files["env"].read_text(encoding="utf-8"),
                                              f"{name}: GITHUB_ENV"):
            job_env[key] = value
        for line in files["path"].read_text(encoding="utf-8").splitlines():
            if line.strip():
                extra_path.insert(0, line.strip())
        run = StepRun(step.get("id"), name, ran=True, returncode=completed.returncode,
                      stdout=completed.stdout, stderr=completed.stderr, outputs=outputs)
        runs.append(run)
        if run.id:
            context.completed_steps[run.id] = outputs
        if run.outcome == "failure":
            context.failed = True
    for run in runs:
        if run.id and run.id not in context.completed_steps:
            context.completed_steps[run.id] = {}  # a skipped step's outputs read as ''
    action_outputs = {}
    for name, spec in (action.get("outputs") or {}).items():
        action_outputs[name] = evaluate(str((spec or {}).get("value", "")), context)
    return ActionRun(runs, action_outputs, summary.read_text(encoding="utf-8"))
