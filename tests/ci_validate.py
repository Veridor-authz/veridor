"""Read, render and check the CI configurations Veridor ships.

Three users:

* ``tests/test_ci_configs.py`` imports the pure functions (standard library
  only): the GitLab component interpolator, ``extends`` resolution, and the
  extraction of every ``veridor`` command line from the shell the configs run.
* ``scripts/e2e_gitlab_job.sh`` runs ``render`` to turn templates/veridor.yml
  into the exact shell a GitLab job would run, so the end-to-end test executes
  the template's own lines rather than a re-typed copy.
* ``python3 tests/ci_validate.py schemas ...`` validates every shipped CI file
  against the platform's published JSON schema. That needs PyYAML and
  jsonschema, which the repository does not depend on, so it is a command and
  not a test: ci/README.md records what it printed.

Not collected by unittest (the file name does not start with ``test``).

The interpolator implements the part of GitLab's ``spec:inputs`` that
templates/veridor.yml uses: ``$[[ inputs.NAME ]]`` with the four input types,
``options``, ``regex`` and ``default``. It refuses everything else -- an
interpolation function, an undeclared input, an input that is declared but
never used, a value of the wrong type -- because a renderer that guessed would
let the template drift from what GitLab accepts while this test stayed green.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from yaml_subset import load_yaml_documents  # noqa: E402

COMPONENT = ROOT / "templates" / "veridor.yml"
GITLAB_EXAMPLE = ROOT / "ci" / ".gitlab-ci.yml"
JENKINSFILE = ROOT / "ci" / "Jenkinsfile"
AZURE = ROOT / "ci" / "azure-pipelines.yml"
BUILDSPEC = ROOT / "ci" / "buildspec.yml"
EXAMPLE_CONFIG = ROOT / "ci" / "veridor.example.json"

#: Keys GitLab accepts under ``spec:inputs:<name>``. The published CI schema
#: does not close this object, so a misspelt ``defualt:`` would pass it.
INPUT_KEYS = frozenset({"type", "description", "options", "regex", "default", "rules"})
SPEC_KEYS = frozenset({"inputs", "include", "component", "description"})
INPUT_TYPES = ("string", "boolean", "number", "array")

_BLOCK = re.compile(r"\$\[\[(.*?)\]\]", re.S)
_REFERENCE = re.compile(r"inputs\.([A-Za-z0-9_-]+)")


class ComponentError(ValueError):
    """The component, or the inputs given to it, would not render on GitLab."""


# ---------------------------------------------------------------------------
# GitLab component: spec, interpolation, extends
# ---------------------------------------------------------------------------


def split_component(text: str) -> tuple[dict[str, Any], Any]:
    """(spec, body) of a component file: a ``spec:`` header, ``---``, the body."""
    documents = load_yaml_documents(text)
    if len(documents) != 2:
        raise ComponentError(f"a component is a spec header and a body; found {len(documents)} documents")
    header, body = documents
    if not isinstance(header, dict) or set(header) != {"spec"}:
        raise ComponentError("the first document must hold `spec:` and nothing else")
    spec = header["spec"]
    if not isinstance(spec, dict):
        raise ComponentError("spec must be a mapping")
    unknown = set(spec) - SPEC_KEYS
    if unknown:
        raise ComponentError(f"spec has unknown keys {sorted(unknown)}")
    if not isinstance(body, dict):
        raise ComponentError("the component body must be a mapping of jobs")
    return spec, body


def _type_ok(kind: str, value: Any) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, list)


def gitlab_regex(pattern: str) -> re.Pattern[str]:
    """``pattern`` compiled to behave as GitLab applies an input's ``regex``.

    GitLab (lib/ci/inputs/string_input.rb) checks it with
    ``Gitlab::UntrustedRegexp#match?``: RE2, an unanchored search, no
    multi-line flag. In RE2 ``$`` matches only at the end of the text; in
    Python it also matches before a final newline, so ``^[^\\n]+$`` would
    accept ``"x\\n"`` here and not on GitLab. Each ``$`` outside a character
    class therefore becomes ``\\Z``. Everything else the templates use means
    the same in both engines."""
    out: list[str] = []
    index, in_class = 0, False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            out.append(pattern[index:index + 2])
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
            out.append(char)
            index += 1
            for literal in ("^", "]"):  # `[^]` and `[]` open with a literal
                if pattern.startswith(literal, index):
                    out.append(literal)
                    index += 1
            continue
        elif char == "$":
            char = r"\Z"
        out.append(char)
        index += 1
    return re.compile("".join(out))


def check_value(name: str, definition: dict[str, Any], value: Any, *, what: str = "value") -> None:
    kind = definition.get("type", "string")
    if not _type_ok(kind, value):
        raise ComponentError(f"input {name}: {what} {value!r} is not a {kind}")
    options = definition.get("options")
    if options is not None and value not in options:
        raise ComponentError(f"input {name}: {what} {value!r} is not one of {options}")
    regex = definition.get("regex")
    if regex is not None and gitlab_regex(regex).search(value) is None:
        raise ComponentError(f"input {name}: {what} {value!r} does not match {regex}")


def check_inputs(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Structural checks GitLab's schema leaves open; returns the inputs."""
    inputs = spec.get("inputs") or {}
    if not isinstance(inputs, dict):
        raise ComponentError("spec:inputs must be a mapping")
    for name, definition in inputs.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ComponentError(f"input name {name!r} is not one interpolation can reference")
        if definition is None:
            definition = inputs[name] = {}
        if not isinstance(definition, dict):
            raise ComponentError(f"input {name}: definition must be a mapping")
        unknown = set(definition) - INPUT_KEYS
        if unknown:
            raise ComponentError(f"input {name}: unknown keys {sorted(unknown)}")
        kind = definition.get("type", "string")
        if kind not in INPUT_TYPES:
            raise ComponentError(f"input {name}: type {kind!r} is not one of {INPUT_TYPES}")
        if "rules" in definition:
            raise ComponentError(f"input {name}: spec:inputs rules are not supported by this renderer")
        if "options" in definition and kind not in ("string", "number"):
            raise ComponentError(f"input {name}: options need type string or number, not {kind}")
        if "regex" in definition and kind != "string":
            raise ComponentError(f"input {name}: regex needs type string, not {kind}")
        if "regex" in definition:
            try:
                re.compile(definition["regex"])
            except re.error as exc:
                raise ComponentError(f"input {name}: regex does not compile: {exc}") from None
        description = definition.get("description")
        if description is not None and (not isinstance(description, str) or len(description) > 1024):
            raise ComponentError(f"input {name}: description must be a string of at most 1024 characters")
        if "default" in definition:
            check_value(name, definition, definition["default"], what="default")
    return inputs


def _references(text: str) -> list[str]:
    names = []
    for block in _BLOCK.findall(text):
        expression = block.strip()
        match = _REFERENCE.fullmatch(expression)
        if match is None:
            raise ComponentError(
                f"$[[{block}]] is not a plain `inputs.NAME` reference; functions and "
                "other contexts are not supported by this renderer"
            )
        names.append(match.group(1))
    if "$[[" in _BLOCK.sub("", text):
        raise ComponentError(f"unterminated $[[ in {text!r}")
    return names


def _walk_strings(node: Any) -> Iterable[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_strings(item)


def used_inputs(body: Any) -> set[str]:
    return {name for text in _walk_strings(body) for name in _references(text)}


def _as_text(name: str, value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    raise ComponentError(f"input {name} is an array and cannot be interpolated into a string")


def _interpolate(node: Any, values: dict[str, Any]) -> Any:
    if isinstance(node, str):
        whole = _BLOCK.fullmatch(node)
        if whole is not None:
            return copy.deepcopy(values[_references(node)[0]])
        _references(node)  # validates every block
        return _BLOCK.sub(lambda m: _as_text(m.group(1).strip()[7:], values[m.group(1).strip()[7:]]), node)
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            rendered_key = _interpolate(key, values)
            if not isinstance(rendered_key, str):
                raise ComponentError(f"key {key!r} rendered to a non-string")
            if rendered_key in out:
                raise ComponentError(f"two keys render to {rendered_key!r}")
            out[rendered_key] = _interpolate(value, values)
        return out
    if isinstance(node, list):
        return [_interpolate(item, values) for item in node]
    return node


def render_component(text: str, given: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """(inputs, rendered body) for ``text`` with the ``given`` inputs."""
    spec, body = split_component(text)
    inputs = check_inputs(spec)
    given = dict(given or {})
    unknown = set(given) - set(inputs)
    if unknown:
        raise ComponentError(f"unknown input(s) {sorted(unknown)}; the component declares {sorted(inputs)}")
    used = used_inputs(body)
    undeclared = used - set(inputs)
    if undeclared:
        raise ComponentError(f"the body references undeclared input(s) {sorted(undeclared)}")
    unused = set(inputs) - used
    if unused:
        raise ComponentError(f"input(s) {sorted(unused)} are declared but never used")
    values: dict[str, Any] = {}
    for name, definition in inputs.items():
        if name in given:
            check_value(name, definition, given[name])
            values[name] = given[name]
        elif "default" in definition:
            values[name] = definition["default"]
        else:
            raise ComponentError(f"input {name} is required and was not given")
    return inputs, _interpolate(body, values)


def coerce_inputs(inputs: dict[str, dict[str, Any]], pairs: list[str]) -> dict[str, Any]:
    """``NAME=VALUE`` strings from a command line, typed as the spec declares."""
    given: dict[str, Any] = {}
    for pair in pairs:
        name, sep, raw = pair.partition("=")
        if not sep:
            raise ComponentError(f"--input {pair!r} is not NAME=VALUE")
        if name not in inputs:
            raise ComponentError(f"unknown input {name!r}")
        kind = inputs[name].get("type", "string")
        if kind == "boolean":
            if raw not in ("true", "false"):
                raise ComponentError(f"input {name} is boolean; {raw!r} is not true or false")
            given[name] = raw == "true"
        elif kind == "number":
            given[name] = float(raw) if "." in raw else int(raw)
        elif kind == "array":
            given[name] = json.loads(raw)
        else:
            given[name] = raw
    return given


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """GitLab's `extends` merge: mappings deep-merge, everything else is replaced."""
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def resolve_job(document: dict[str, Any], name: str, _depth: int = 0) -> dict[str, Any]:
    """The job ``name`` with its ``extends`` chain applied, as GitLab merges it."""
    if _depth > 11:
        raise ComponentError(f"{name}: extends nests deeper than GitLab's limit of 11")
    if name not in document:
        raise ComponentError(f"extends names {name!r}, which is not in the document")
    job = document[name]
    parents = job.get("extends", [])
    parents = [parents] if isinstance(parents, str) else parents
    merged: dict[str, Any] = {}
    for parent in parents:
        merged = _merge(merged, resolve_job(document, parent, _depth + 1))
    own = {key: value for key, value in job.items() if key != "extends"}
    return _merge(merged, own)


def gate_job_name(body: dict[str, Any]) -> str:
    visible = [key for key in body if not key.startswith(".")]
    if len(visible) != 1:
        raise ComponentError(f"expected exactly one visible job, found {visible}")
    return visible[0]


def job_shell(job: dict[str, Any]) -> str:
    """before_script and script, in order: GitLab runs them in one shell."""
    lines = list(job.get("before_script") or []) + list(job.get("script") or [])
    if not all(isinstance(line, str) for line in lines):
        raise ComponentError("before_script/script must be lists of strings")
    return "\n".join(line.rstrip("\n") for line in lines) + "\n"


# ---------------------------------------------------------------------------
# Shell extraction: every veridor command line, as argv
# ---------------------------------------------------------------------------

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _expand(word: str, variables: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3)
        if name in variables:
            return variables[name]
        if match.group(2) is not None:
            return match.group(2)
        raise KeyError(f"${name} has no sample value; add one to the variables given to veridor_commands")

    return _VARIABLE.sub(replace, word)


def _logical_lines(shell: str) -> list[str]:
    return shell.replace("\\\n", " ").splitlines()


def veridor_commands(shell: str, variables: dict[str, str]) -> list[list[str]]:
    """argv of every ``veridor`` command in ``shell``, conditional flags included.

    Each ``set -- ...`` line resets or extends the positional parameters, and a
    ``"$@"`` in a veridor command stands for all of them -- the worst case, in
    which every conditional flag is present, except one guarded by a literal
    ``if false`` (a boolean component input rendered off). ``$VAR`` references take their
    values from ``variables``; an unknown one raises, so a renamed variable is
    noticed. ``veridor --version`` is not a command worth parsing and is skipped.
    """
    positional: list[str] = []
    commands: list[list[str]] = []
    for line in _logical_lines(shell):
        words_text = line.strip()
        condition = re.match(r"if (.*); then (set -- .*); fi$", words_text)
        if condition:
            if condition.group(1).strip() == "false":
                continue  # a boolean input rendered off: the flag is never passed
            words_text = condition.group(2)
        if words_text.startswith("set -- "):
            words = shlex.split(words_text[len("set -- "):], posix=True)
            if words[:1] == ["$@"]:
                positional += [_expand(w, variables) for w in words[1:]]
            else:
                positional = [_expand(w, variables) for w in words]
            continue
        if words_text == "set --":
            positional = []
            continue
        text = re.sub(r"\s*\|\|\s*status=\$\?\s*$", "", words_text)
        text = re.sub(r"^exec\s+", "", text)
        if not re.match(r"veridor\s", text):
            continue
        words = shlex.split(text, posix=True)
        if words[1:] == ["--version"]:
            continue
        argv: list[str] = []
        for word in words:
            if word == "$@":
                argv.extend(positional)
            else:
                argv.append(_expand(word, variables))
        commands.append(argv)
    return commands


def exit_code_branches(shell: str) -> set[int]:
    """Exit codes a ``case "$status" in`` statement names as its own branch."""
    codes: set[int] = set()
    for match in re.finditer(r"^\s*((?:[0-9]+\|)*[0-9]+)\)", shell, re.M):
        codes.update(int(code) for code in match.group(1).split("|"))
    return codes


def gate_problems(shell: str) -> list[str]:
    """What must never be in the shell around a gate, as a list of problems."""
    problems = []
    for number, line in enumerate(_logical_lines(shell), 1):
        stripped = line.split("#", 1)[0] if not line.lstrip().startswith("echo") else line
        if re.search(r"\|\|\s*true\b", stripped) or re.search(r"\|\|\s*:\s*$", stripped):
            problems.append(f"line {number}: `|| true` swallows an exit code: {line.strip()}")
        if re.search(r"\bset\s+\+e\b", stripped):
            problems.append(f"line {number}: `set +e` lets a failing command continue: {line.strip()}")
    return problems


# ---------------------------------------------------------------------------
# GitLab job rules: which pipelines the job is in
# ---------------------------------------------------------------------------

#: The predefined variables that decide ``rules:if`` in each kind of
#: pipeline, modelled on GitLab's variable builder
#: (lib/gitlab/ci/variables/builder/pipeline.rb: CI_COMMIT_BRANCH only when
#: the pipeline is for a branch, never for a tag or a merge request;
#: CI_OPEN_MERGE_REQUESTS on a branch pipeline whose branch has one), the
#: CI_PIPELINE_SOURCE table in doc/ci/jobs/job_rules.md, and
#: doc/ci/pipelines/downstream_pipelines.md (a child pipeline's source is
#: always parent_pipeline, and a merge request parent passes its
#: CI_MERGE_REQUEST_* variables down). Read in GitLab's source and docs, not
#: observed on a GitLab instance. The default branch is `main`, the other
#: branch `feature`.
_MR = {"CI_MERGE_REQUEST_ID": "101", "CI_MERGE_REQUEST_IID": "1", "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature",
       "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"}
PIPELINE_SHAPES: dict[str, dict[str, str]] = {
    "push to the default branch": {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "main"},
    "push to another branch": {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "feature"},
    "push to a branch with an open merge request": {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "feature",
                                                    "CI_OPEN_MERGE_REQUESTS": "group/project!1"},
    "tag pipeline": {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_TAG": "v1.2.3"},
    "merge request pipeline": {"CI_PIPELINE_SOURCE": "merge_request_event", **_MR,
                               "CI_MERGE_REQUEST_EVENT_TYPE": "detached"},
    "merged results pipeline": {"CI_PIPELINE_SOURCE": "merge_request_event", **_MR,
                                "CI_MERGE_REQUEST_EVENT_TYPE": "merged_result"},
    "merge train pipeline": {"CI_PIPELINE_SOURCE": "merge_request_event", **_MR,
                             "CI_MERGE_REQUEST_EVENT_TYPE": "merge_train"},
    "scheduled pipeline": {"CI_PIPELINE_SOURCE": "schedule", "CI_COMMIT_BRANCH": "main"},
    "run from the UI on another branch": {"CI_PIPELINE_SOURCE": "web", "CI_COMMIT_BRANCH": "feature"},
    "pipelines API on another branch": {"CI_PIPELINE_SOURCE": "api", "CI_COMMIT_BRANCH": "feature"},
    "trigger token on another branch": {"CI_PIPELINE_SOURCE": "trigger", "CI_COMMIT_BRANCH": "feature"},
    "Web IDE on another branch": {"CI_PIPELINE_SOURCE": "webide", "CI_COMMIT_BRANCH": "feature"},
    "ChatOps": {"CI_PIPELINE_SOURCE": "chat", "CI_COMMIT_BRANCH": "main"},
    "child of a merge request pipeline": {"CI_PIPELINE_SOURCE": "parent_pipeline", **_MR},
    "child of a default-branch pipeline": {"CI_PIPELINE_SOURCE": "parent_pipeline", "CI_COMMIT_BRANCH": "main"},
    "child of another branch's pipeline": {"CI_PIPELINE_SOURCE": "parent_pipeline", "CI_COMMIT_BRANCH": "feature"},
    "child of a tag pipeline": {"CI_PIPELINE_SOURCE": "parent_pipeline", "CI_COMMIT_TAG": "v1.2.3"},
    "multi-project downstream on the default branch": {"CI_PIPELINE_SOURCE": "pipeline", "CI_COMMIT_BRANCH": "main"},
    "multi-project downstream on another branch": {"CI_PIPELINE_SOURCE": "pipeline", "CI_COMMIT_BRANCH": "feature"},
    "external pull request": {"CI_PIPELINE_SOURCE": "external_pull_request_event", "CI_COMMIT_BRANCH": "feature"},
    "external CI service": {"CI_PIPELINE_SOURCE": "external", "CI_COMMIT_BRANCH": "feature"},
    "scan execution policy": {"CI_PIPELINE_SOURCE": "security_orchestration_policy", "CI_COMMIT_BRANCH": "main"},
    "DAST on-demand scan": {"CI_PIPELINE_SOURCE": "ondemand_dast_scan", "CI_COMMIT_BRANCH": "main"},
    "DAST on-demand validation": {"CI_PIPELINE_SOURCE": "ondemand_dast_validation", "CI_COMMIT_BRANCH": "main"},
}
for _shape in PIPELINE_SHAPES.values():
    _shape.setdefault("CI_DEFAULT_BRANCH", "main")

_RULE_TOKEN = re.compile(r"""\s*(?:(?P<op>==|!=|=~|!~|&&|\|\||\(|\))|\$(?P<var>\w+)|"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<null>null)\b)""")
#: Keys of a rule this evaluator understands. `changes` and `exists` depend
#: on the commit, not the pipeline, so a rule using them is refused rather
#: than guessed.
_RULE_KEYS = frozenset({"if", "when", "allow_failure", "variables", "needs", "interruptible", "start_in"})


def _rule_tokens(expression: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    index = 0
    while index < len(expression):
        if expression[index:].strip() == "":
            break
        match = _RULE_TOKEN.match(expression, index)
        if match is None:
            raise ComponentError(f"rules:if {expression!r}: cannot read {expression[index:]!r}")
        if match.group("op") in ("=~", "!~"):
            raise ComponentError(f"rules:if {expression!r}: regular-expression matches are not evaluated here")
        if match.group("op"):
            tokens.append(("op", match.group("op")))
        elif match.group("var") is not None:
            tokens.append(("var", match.group("var")))
        elif match.group("null"):
            tokens.append(("value", None))
        else:
            tokens.append(("value", match.group("dq") if match.group("dq") is not None else match.group("sq")))
        index = match.end()
    return tokens


def rule_if(expression: str, variables: dict[str, str]) -> bool:
    """A ``rules:if`` expression, with GitLab's semantics
    (lib/gitlab/ci/pipeline/expression): an undefined variable is null,
    ``==`` compares values, ``&&``/``||`` bind looser than ``==`` and use
    Ruby truthiness, and the whole statement is true when its value is
    ``present?`` (not null, not empty or blank)."""
    tokens = _rule_tokens(expression)
    position = 0

    def peek() -> tuple[str, Any] | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> tuple[str, Any]:
        nonlocal position
        if position >= len(tokens):
            raise ComponentError(f"rules:if {expression!r} ends early")
        position += 1
        return tokens[position - 1]

    def operand() -> Any:
        kind, value = take()
        if (kind, value) == ("op", "("):
            inner = disjunction()
            if take() != ("op", ")"):
                raise ComponentError(f"rules:if {expression!r}: unbalanced parentheses")
            return inner
        if kind == "var":
            return variables.get(value)
        if kind == "value":
            return value
        raise ComponentError(f"rules:if {expression!r}: unexpected {value!r}")

    def comparison() -> Any:
        left = operand()
        while peek() in (("op", "=="), ("op", "!=")):
            operator = take()[1]
            right = operand()
            left = (left == right) if operator == "==" else (left != right)
        return left

    def truthy(value: Any) -> bool:  # Ruby: only nil and false are false
        return value is not None and value is not False

    def conjunction() -> Any:
        left = comparison()
        while peek() == ("op", "&&"):
            take()
            right = comparison()
            left = right if truthy(left) else left
        return left

    def disjunction() -> Any:
        left = conjunction()
        while peek() == ("op", "||"):
            take()
            right = conjunction()
            left = left if truthy(left) else right
        return left

    result = disjunction()
    if position != len(tokens):
        raise ComponentError(f"rules:if {expression!r}: trailing {tokens[position:]!r}")
    if isinstance(result, str):
        return result.strip() != ""
    return truthy(result)


def rules_include(rules: Any, variables: dict[str, str]) -> bool:
    """Whether a job with these ``rules`` is in a pipeline with these
    variables: the first rule that matches decides, ``when: never`` leaves
    the job out, and no match leaves it out. No rules at all puts it in."""
    if rules is None:
        return True
    if not isinstance(rules, list):
        raise ComponentError(f"rules must be a list, not {rules!r}")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - _RULE_KEYS:
            raise ComponentError(f"rule {rule!r} is not one this evaluator reads")
        if "if" not in rule or rule_if(rule["if"], variables):
            return rule.get("when", "on_success") != "never"
    return False


def pipelines_without(rules: Any) -> list[str]:
    """The PIPELINE_SHAPES a job with these rules is left out of."""
    return [name for name, variables in PIPELINE_SHAPES.items() if not rules_include(rules, variables)]


# ---------------------------------------------------------------------------
# Other platforms: where their shell lives
# ---------------------------------------------------------------------------


def jenkins_shell_blocks(text: str) -> list[str]:
    """Every ``'''...'''`` shell body in a Jenkinsfile (Groovy does not
    interpolate triple-single-quoted strings, so the text is the shell)."""
    return re.findall(r"'''(.*?)'''", text, re.S)


def azure_steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("steps"), list):
                steps.extend(step for step in node["steps"] if isinstance(step, dict))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    return steps


def azure_shell(document: dict[str, Any]) -> str:
    return "\n".join(
        step.get("bash") or step.get("script") or ""
        for step in azure_steps(document)
        if "bash" in step or "script" in step
    )


#: The buildspec keys AWS documents (CodeBuild User Guide, "Build
#: specification reference", buildspec version 0.2). SchemaStore has no
#: buildspec schema, so this is the check that stands in for one.
BUILDSPEC_KEYS = {
    "": {"version", "run-as", "env", "proxy", "batch", "phases", "reports", "artifacts", "cache"},
    "env": {"shell", "variables", "parameter-store", "exported-variables", "secrets-manager", "git-credential-helper"},
    "phase": {"run-as", "on-failure", "runtime-versions", "commands", "finally"},
    "report": {"files", "base-directory", "discard-paths", "file-format"},
    "artifacts": {"files", "name", "discard-paths", "base-directory", "exclude-paths", "enable-symlinks",
                  "s3-prefix", "secondary-artifacts"},
}
BUILDSPEC_PHASES = ("install", "pre_build", "build", "post_build")
BUILDSPEC_SHELLS = ("bash", "/bin/sh")
BUILDSPEC_REPORT_FORMATS = ("CUCUMBERJSON", "JUNITXML", "NUNITXML", "NUNIT3XML", "TESTNGXML", "VISUALSTUDIOTRX",
                            "CLOVERXML", "COBERTURAXML", "JACOCOXML", "SIMPLECOV")


def buildspec_problems(document: Any) -> list[str]:
    """Keys and values outside the documented buildspec 0.2 shape."""
    if not isinstance(document, dict):
        return ["a buildspec is a mapping"]
    problems = [f"unknown top-level key {k!r}" for k in document if k not in BUILDSPEC_KEYS[""]]
    if str(document.get("version")) != "0.2":
        problems.append(f"version {document.get('version')!r} is not 0.2")
    env = document.get("env") or {}
    problems += [f"unknown env key {k!r}" for k in env if k not in BUILDSPEC_KEYS["env"]]
    if "shell" in env and env["shell"] not in BUILDSPEC_SHELLS:
        problems.append(f"env.shell {env['shell']!r} is not one of {BUILDSPEC_SHELLS}")
    for name, value in (env.get("variables") or {}).items():
        if not isinstance(value, str):
            problems.append(f"env.variables.{name} is not a string")
    phases = document.get("phases")
    if not isinstance(phases, dict) or not phases:
        problems.append("phases is required")
        phases = {}
    for name, phase in phases.items():
        if name not in BUILDSPEC_PHASES:
            problems.append(f"unknown phase {name!r}")
            continue
        problems += [f"phases.{name}: unknown key {k!r}" for k in phase if k not in BUILDSPEC_KEYS["phase"]]
        if "runtime-versions" in phase and name != "install":
            problems.append(f"phases.{name}: runtime-versions belongs to install")
        commands = phase.get("commands")
        if not isinstance(commands, list) or not commands or not all(isinstance(c, str) for c in commands):
            problems.append(f"phases.{name}.commands must be a non-empty list of strings")
    for group, report in (document.get("reports") or {}).items():
        problems += [f"reports.{group}: unknown key {k!r}" for k in report if k not in BUILDSPEC_KEYS["report"]]
        if report.get("file-format", "JUNITXML") not in BUILDSPEC_REPORT_FORMATS:
            problems.append(f"reports.{group}.file-format {report.get('file-format')!r} is not a report format")
        if not isinstance(report.get("files"), list) or not report["files"]:
            problems.append(f"reports.{group}.files must be a non-empty list")
    artifacts = document.get("artifacts") or {}
    problems += [f"artifacts: unknown key {k!r}" for k in artifacts if k not in BUILDSPEC_KEYS["artifacts"]]
    return problems


def codebuild_shell(document: dict[str, Any]) -> str:
    """Every phase's commands in order: buildspec 0.2 runs them in one shell."""
    lines: list[str] = []
    for phase in ("install", "pre_build", "build", "post_build"):
        block = (document.get("phases") or {}).get(phase) or {}
        for key in ("commands", "finally"):
            lines.extend(block.get(key) or [])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Schemas (needs PyYAML and jsonschema; a command, not a test)
# ---------------------------------------------------------------------------

#: Non-default inputs for the second render: every input moved off its default.
NON_DEFAULT_INPUTS: dict[str, Any] = {
    "stage": "authz",
    "job_name": "veridor-staging",
    "install": "pip",
    "image": "registry.example.com/mirror/veridor@sha256:" + "0" * 64,
    "python_image": "python:3.13-slim",
    "pip_package": "dist/veridor-0.1.0-py3-none-any.whl",
    "config": "ci/veridor.staging.json",
    "base_url": "$STAGING_URL",
    "proxy_from_environment": True,
    "wait_for_target": 45,
    "fail_on": "any",
    "require_complete": False,
    "allow_unmeasured": True,
    "baseline": "ci/veridor-baseline.json",
    "openapi": "openapi.json",
    "output_dir": "reports/veridor",
    "extra_args": "--read-only --require-clean-teardown",
    "artifacts_expire_in": "1 week",
    "job_rules": [{"if": '$CI_PIPELINE_SOURCE == "schedule"'}, {"when": "manual"}],
}


def _schema_command(args: argparse.Namespace) -> int:
    import jsonschema  # noqa: PLC0415 - optional, command only
    import yaml  # noqa: PLC0415 - optional, command only

    rows: list[tuple[str, str, str]] = []

    def record(name: str, expect_valid: bool, errors: list[str]) -> None:
        valid = not errors
        verdict = "ok" if valid == expect_valid else "MISMATCH"
        detail = "valid" if valid else f"{len(errors)} error(s): {errors[0][:110]}"
        rows.append((name, ("valid" if expect_valid else "invalid") + " expected", f"{detail} [{verdict}]"))

    def errors_for(schema: dict[str, Any], instance: Any) -> list[str]:
        validator = jsonschema.Draft7Validator(schema)
        return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in validator.iter_errors(instance)]

    def same_parse(path_or_text: Any, name: str) -> None:
        text = path_or_text.read_text(encoding="utf-8") if isinstance(path_or_text, Path) else path_or_text
        ours = load_yaml_documents(text)
        theirs = [doc for doc in yaml.safe_load_all(text) if doc is not None]
        rows.append((f"{name}: subset reader == PyYAML", "equal", "equal [ok]" if ours == theirs else "DIFFERENT [MISMATCH]"))

    gitlab = json.loads(Path(args.gitlab_schema).read_text(encoding="utf-8"))
    text = COMPONENT.read_text(encoding="utf-8")
    same_parse(COMPONENT, "templates/veridor.yml")
    spec, _ = split_component(text)
    record("templates/veridor.yml spec header", True, errors_for(gitlab, {"spec": spec}))
    _, default_body = render_component(text)
    record("component rendered with defaults", True, errors_for(gitlab, default_body))
    _, other_body = render_component(text, NON_DEFAULT_INPUTS)
    record("component rendered with every input changed", True, errors_for(gitlab, other_body))
    same_parse(GITLAB_EXAMPLE, "ci/.gitlab-ci.yml")
    example = yaml.safe_load(GITLAB_EXAMPLE.read_text(encoding="utf-8"))
    record("ci/.gitlab-ci.yml", True, errors_for(gitlab, example))
    readme = (ROOT / "README.md").read_text(encoding="utf-8").split("### GitLab CI", 1)[1].split("\n### ", 1)[0]
    for number, block in enumerate(re.findall(r"```yaml\n(.*?)```", readme, re.S), 1):
        record(f"README.md GitLab section, YAML block {number}", True, errors_for(gitlab, yaml.safe_load(block)))
    remote = next(item for item in example["include"] if "remote" in item)
    for label, change in (
        ("control: include integrity as a hex digest", lambda item: item.__setitem__("integrity", "sha256-" + "0" * 64)),
        ("control: include key `integrty`", lambda item: item.__setitem__("integrty", item.pop("integrity"))),
    ):
        bad = copy.deepcopy(example)
        change(next(item for item in bad["include"] if item.get("remote") == remote["remote"]))
        record(label, False, errors_for(gitlab, bad))

    # Controls: each must be rejected, or a pass above means nothing.
    job = gate_job_name(default_body)
    bad = copy.deepcopy(default_body)
    bad[job]["artifact"] = {"paths": ["x"]}
    record("control: unknown job key `artifact`", False, errors_for(gitlab, bad))
    bad = copy.deepcopy(default_body)
    bad[job]["artifacts"]["reports"]["sast"] = 5
    record("control: artifacts.reports.sast: 5", False, errors_for(gitlab, bad))
    bad = copy.deepcopy(default_body)
    bad[job]["allow_failure"] = {"exit_codes": []}
    record("control: allow_failure exit_codes []", False, errors_for(gitlab, bad))
    bad_spec = copy.deepcopy(spec)
    bad_spec["inputs"]["fail_on"]["type"] = "enum"
    record("control: spec input type enum", False, errors_for(gitlab, {"spec": bad_spec}))
    for label, mutated in (
        ("control: misspelt $[[ inputs.confg ]]", text.replace("$[[ inputs.config ]]", "$[[ inputs.confg ]]", 1)),
        ("control: $[[ inputs.config | expand_vars ]]", text.replace("$[[ inputs.config ]]", "$[[ inputs.config | expand_vars ]]", 1)),
        ("control: declared input never used", text.replace('"$[[ inputs.artifacts_expire_in ]]"', '"30 days"')),
        ("control: default outside options", text.replace("default: new+confirmed", "default: new-and-confirmed")),
    ):
        try:
            render_component(mutated)
            outcome: list[str] = []
        except ComponentError as exc:
            outcome = [str(exc)]
        record(label, False, outcome)
    try:
        render_component(text, {"fail_on": "all"})
        outcome = []
    except ComponentError as exc:
        outcome = [str(exc)]
    record("control: input fail_on=all", False, outcome)

    if args.azure_schema:
        # Azure's parser keeps every YAML scalar a string, and its published
        # schema is written that way: `cancelTimeoutInMinutes: 2` must be a
        # string, while a task input declared boolean must read true or false.
        # So the file is loaded with PyYAML's BaseLoader (all scalars strings)
        # and boolean / integer / number accept the strings Azure accepts.
        import re as _re  # noqa: PLC0415
        from jsonschema import validators  # noqa: PLC0415

        checker = (jsonschema.Draft7Validator.TYPE_CHECKER
                   .redefine("boolean", lambda _c, x: isinstance(x, bool) or (isinstance(x, str) and x.lower() in ("true", "false")))
                   .redefine("integer", lambda _c, x: (isinstance(x, int) and not isinstance(x, bool)) or (isinstance(x, str) and _re.fullmatch(r"-?[0-9]+", x) is not None))
                   .redefine("number", lambda _c, x: (isinstance(x, (int, float)) and not isinstance(x, bool)) or (isinstance(x, str) and _re.fullmatch(r"-?[0-9]+(\.[0-9]+)?", x) is not None)))
        azure_validator = validators.extend(jsonschema.Draft7Validator, type_checker=checker)
        azure_schema = json.loads(Path(args.azure_schema).read_text(encoding="utf-8"))

        def azure_errors(instance: Any) -> list[str]:
            return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in azure_validator(azure_schema).iter_errors(instance)]

        same_parse(AZURE, "ci/azure-pipelines.yml")
        azure_doc = yaml.load(AZURE.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        record("ci/azure-pipelines.yml", True, azure_errors(azure_doc))
        job = ("stages", 0, "jobs", 0)

        def mutate(change: Any) -> Any:
            bad = copy.deepcopy(azure_doc)
            target = bad
            for key in job:
                target = target[key]
            change(target)
            return bad

        record("control: azure job key `stepz`", False, azure_errors(mutate(lambda j: j.__setitem__("stepz", j.pop("steps")))))
        record("control: azure continueOnError: sometimes", False,
               azure_errors(mutate(lambda j: j["steps"][2].__setitem__("continueOnError", "sometimes"))))
        record("control: PublishTestResults failTaskOnFailedTests: maybe", False,
               azure_errors(mutate(lambda j: next(s for s in j["steps"] if s.get("task") == "PublishTestResults@2")["inputs"].__setitem__("failTaskOnFailedTests", "maybe"))))
        record("control: PublishTestResults testResultsFormat: JUnit5", False,
               azure_errors(mutate(lambda j: next(s for s in j["steps"] if s.get("task") == "PublishTestResults@2")["inputs"].__setitem__("testResultsFormat", "JUnit5"))))

    same_parse(BUILDSPEC, "ci/buildspec.yml")
    width = max(len(row[0]) for row in rows)
    for name, expected, observed in rows:
        print(f"{name:<{width}}  {expected:<16}  {observed}")
    mismatches = [row for row in rows if "MISMATCH" in row[2]]
    print(f"{len(rows)} rows, {len(mismatches)} mismatch(es)")
    return 1 if mismatches else 0


def _render_command(args: argparse.Namespace) -> int:
    text = Path(args.template).read_text(encoding="utf-8")
    spec, _ = split_component(text)
    inputs = check_inputs(spec)
    given = coerce_inputs(inputs, args.input)
    _, body = render_component(text, given)
    name = gate_job_name(body)
    job = resolve_job(body, name)
    Path(args.shell).write_text(job_shell(job), encoding="utf-8")
    Path(args.job_json).write_text(json.dumps({"name": name, "job": job, "document": body}, indent=2), encoding="utf-8")
    print(f"rendered {name}: {len(job.get('before_script') or [])} before_script and {len(job.get('script') or [])} script entries")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    render = sub.add_parser("render", help="render the component and write the gate job's shell and JSON")
    render.add_argument("--template", default=str(COMPONENT))
    render.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    render.add_argument("--shell", required=True, help="write before_script + script here")
    render.add_argument("--job-json", required=True, help="write the resolved job (and the document) here")
    schemas = sub.add_parser("schemas", help="validate the shipped CI files against published schemas")
    schemas.add_argument("--gitlab-schema", required=True)
    schemas.add_argument("--azure-schema")
    args = parser.parse_args(argv)
    try:
        if args.command == "render":
            return _render_command(args)
        return _schema_command(args)
    except ComponentError as exc:
        print(f"ci_validate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
