"""What ships: the licence files, the package metadata, and which code the suite tested.

A wheel is only worth testing if the tests import the wheel. ``VERIDOR_TEST_AGAINST``
(see ``tests/source_path.py``) makes that a switch rather than a hope, and the
first test here states which one this process is running against, so a CI job
that thinks it tested the installed package and actually tested ``src/`` fails
instead of passing.
"""

from __future__ import annotations

import ast
import functools
import gc
import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import sysconfig
import tempfile
import time
import tomllib
import unittest
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402

import veridor  # noqa: E402
from scripts import build_zipapp, image_bytecode_check  # noqa: E402
from dockerignore_model import ignored, read_patterns  # noqa: E402
import loopback  # noqa: E402
from tiers import slow  # noqa: E402

PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

#: sha256 of https://www.apache.org/licenses/LICENSE-2.0.txt, byte for byte.
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


#: Every way of putting src/ on the import path the guard below must refuse.
#: Each is planted by test_control_every_spelling_is_caught.
SRC_PATH_SPELLINGS: tuple[str, ...] = (
    'sys.path.insert(0, str(ROOT / "src"))',
    "sys.path.insert(0, str(ROOT / 'src'))",
    'SRC = ROOT / "src"\nsys.path.insert(0, str(SRC))',
    'LIB = ROOT / "src"\nsys.path.insert(0, str(LIB))',
    'sys.path.append(str(ROOT / "src"))',
    'sys.path.extend([str(ROOT / "src")])',
    'sys.path[:0] = [str(ROOT / "src")]',
    'sys.path += [str(ROOT / "src")]',
    'from sys import path\npath.insert(0, "src")',
    'import os\nsys.path.insert(0, os.path.join(str(ROOT), "src"))',
    'sys.path.insert(0, f"{ROOT}/src")',
    'import site\nsite.addsitedir(str(ROOT / "src"))',
    'import os\nos.environ["PYTHONPATH"] = str(ROOT / "src")',
    'import os\nos.environ.setdefault("PYTHONPATH", str(ROOT / "src"))',
    'import os\nos.putenv("PYTHONPATH", str(ROOT / "src"))',
    'import os\nos.environ.update(PYTHONPATH=str(ROOT / "src"))',
    'env = {"PYTHONPATH": str(ROOT / "src")}',
    'env = dict(PYTHONPATH=str(ROOT / "src"))',
    'SRC = ROOT / "src"\nenv = {}\nenv["PYTHONPATH"] = str(SRC)',
)

#: (file, offence) pairs that are deliberate, each with the reason. Keep empty
#: unless the code NEEDS the checkout rather than the package under test.
SRC_PATH_ALLOWED: frozenset[tuple[str, str]] = frozenset({
    # test_control_without_minus_p_the_decoy_does_shadow: a control that runs
    # `python -m veridor` with and without -P to show a veridor/ directory in
    # the workspace shadows the package unless -P is given. It is about import
    # precedence, not about which Veridor is under test; it could use
    # source_path.child_env() instead (owned outside this change).
    ("tests/test_action.py", "PYTHONPATH in a dict literal"),
})

_SRC = re.compile(r"src", re.IGNORECASE)


def _all_nodes(tree: ast.AST) -> list[ast.AST]:
    """Every node of ``tree``: the nodes ``ast.walk`` yields, in its order.

    About twice as fast as ``list(ast.walk(tree))``, which goes through two
    generators per node. The guard below walks every module the suite runs.
    ``test_all_nodes_is_ast_walk`` holds the two equal.
    """
    nodes = [tree]
    append = nodes.append
    for node in nodes:  # grows while it is read: breadth first, as ast.walk is
        for field in node._fields:
            value = getattr(node, field, None)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        append(item)
            elif isinstance(value, ast.AST):
                append(value)
    return nodes


def _by_type(nodes: list[ast.AST]) -> dict[type, list[ast.AST]]:
    """``nodes`` grouped by exact class, in order. ``ast.parse`` builds only
    the node classes themselves, never subclasses, so a lookup here selects
    what ``isinstance`` would."""
    grouped: dict[type, list[ast.AST]] = {}
    for node in nodes:
        grouped.setdefault(type(node), []).append(node)
    return grouped


def _src_path_offences(text: str, tree: ast.AST | None = None,
                       grouped: dict[type, list[ast.AST]] | None = None) -> list[tuple[int, str]]:
    """Every place ``text`` puts a path mentioning src on sys.path or PYTHONPATH.

    "Mentioning" is read off the source of the expression, following names
    back through their assignments, so ``SRC = ROOT / "src"`` then
    ``insert(0, str(SRC))`` counts as much as the literal does.
    """
    if grouped is None:
        grouped = _by_type(_all_nodes(tree if tree is not None else ast.parse(text)))

    def of(*kinds: type) -> list[ast.AST]:
        """The nodes of these kinds. Their order does not matter: the first
        pass only collects, and the second's findings are sorted."""
        return [node for kind in kinds for node in grouped.get(kind, [])]

    assigned: dict[str, list[ast.AST]] = {}
    path_aliases = set()
    for node in of(ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.ImportFrom):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        assigned.setdefault(name.id, []).append(node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            if isinstance(node.target, ast.Name) and node.value is not None:
                assigned.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            path_aliases |= {a.asname or a.name for a in node.names if a.name == "path"}

    def mentions_src(node: ast.AST, depth: int = 0, seen: frozenset[str] = frozenset()) -> bool:
        if _SRC.search(ast.get_source_segment(text, node) or ""):
            return True
        if depth >= 4:
            return False
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} - seen
        return any(mentions_src(value, depth + 1, seen | names)
                   for name in names for value in assigned.get(name, ()))

    def is_sys_path(node: ast.AST) -> bool:
        return (isinstance(node, ast.Attribute) and node.attr == "path"
                and isinstance(node.value, ast.Name) and node.value.id == "sys") or (
                isinstance(node, ast.Name) and node.id in path_aliases)

    def is_pythonpath(node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and node.value == "PYTHONPATH"

    found: list[tuple[int, str]] = []
    for node in of(ast.Call, ast.Assign, ast.AugAssign, ast.Dict):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr in {"insert", "append", "extend"}
                    and is_sys_path(func.value) and any(map(mentions_src, node.args))):
                found.append((node.lineno, f"sys.path.{func.attr}"))
            if (isinstance(func, ast.Attribute) and func.attr == "addsitedir"
                    and any(map(mentions_src, node.args))):
                found.append((node.lineno, "site.addsitedir"))
            if (isinstance(func, ast.Attribute) and func.attr in {"setdefault", "putenv"}
                    and len(node.args) > 1 and is_pythonpath(node.args[0])
                    and mentions_src(node.args[1])):
                found.append((node.lineno, f"PYTHONPATH through {func.attr}"))
            for keyword in node.keywords:
                if keyword.arg == "PYTHONPATH" and mentions_src(keyword.value):
                    found.append((node.lineno, "PYTHONPATH= keyword"))
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                base = target.value if isinstance(target, ast.Subscript) else target
                if is_sys_path(base) and mentions_src(node.value):
                    found.append((node.lineno, "sys.path assignment"))
                if (isinstance(target, ast.Subscript) and is_pythonpath(target.slice)
                        and mentions_src(node.value)):
                    found.append((node.lineno, "PYTHONPATH item assignment"))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if is_pythonpath(key) and mentions_src(value):
                    found.append((node.lineno, "PYTHONPATH in a dict literal"))
    return sorted(found)


def _scripts_used_by(tree: ast.AST, scripts: set[str],
                     grouped: dict[type, list[ast.AST]] | None = None) -> set[str]:
    """scripts/*.py a module imports (``scripts.x``, or ``x`` once scripts/ is
    on the path) or names as a file to run (``.../x.py``)."""
    used: set[str] = set()
    if grouped is None:
        grouped = _by_type(_all_nodes(tree))
    for node in (grouped.get(ast.ImportFrom, []) + grouped.get(ast.Import, [])
                 + grouped.get(ast.Constant, [])):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "scripts":
                used |= {alias.name for alias in node.names}
            else:
                used.add(node.module.removeprefix("scripts.").split(".")[0])
        elif isinstance(node, ast.Import):
            used |= {alias.name.removeprefix("scripts.").split(".")[0] for alias in node.names}
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = re.search(r"(?:^|/)(\w+)\.py$", node.value)
            if match:
                used.add(match.group(1))
    return used & scripts


@functools.lru_cache(maxsize=1)
def _modules_the_suite_runs() -> tuple[tuple[Path, tuple[tuple[int, str], ...]], ...]:
    """Every test module but source_path.py, scripts/run_tests.py, and every
    script reachable from them through imports or run-this-file references,
    each as ``(path, its src-path offences)``. Parsed and walked once per
    process, and scanned in the same pass.

    Only the offences are kept, never the trees. This cache used to hold every
    module's text, tree and node grouping: about 475,000 objects that lived to
    the end of the run, so each full garbage collection after this module
    cost about 0.1 s idle and 0.4 s under load instead of about 0.005 s
    (measured), charged to whichever later test triggered it -- in the fast
    tier, the Markdown size-limit test and ``--list``.
    """
    scripts = {path.stem for path in (ROOT / "scripts").glob("*.py")}
    pending = [ROOT / "scripts" / "run_tests.py"] + [
        path for path in sorted((ROOT / "tests").glob("*.py")) if path.name != "source_path.py"
    ]
    seen: dict[Path, tuple[tuple[int, str], ...]] = {}
    # A module's nodes live until its scan below is done, so a cyclic
    # collection while parsing only walks a heap that is still growing: it
    # cost a quarter to a third of the parse here, and it frees nothing.
    # Nothing a tree holds is cyclic, so each is freed by reference counting
    # as soon as the next module replaces it.
    collecting = gc.isenabled()
    gc.disable()
    try:
        while pending:
            path = pending.pop(0)
            if path in seen:
                continue
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
            grouped = _by_type(_all_nodes(tree))
            seen[path] = tuple(_src_path_offences(text, tree, grouped))
            pending += [ROOT / "scripts" / f"{name}.py"
                        for name in sorted(_scripts_used_by(tree, scripts, grouped))]
            del tree, grouped
    finally:
        if collecting:
            gc.enable()
    return tuple((path, seen[path]) for path in sorted(seen))


#: Why the two tests that read _modules_the_suite_runs() are slow-tier. It
#: parses every test module and every script they reach (58 files, 2.2 MB of
#: Python), and ast.parse alone is 0.13 s of it: 0.29 s at load ~2, 0.54-0.94 s
#: at load ~6-25 (measured), far above what the fast tier's tests spend. Both CI jobs
#: run the slow tier, the installed-package one included, which is the run
#: VERIDOR_TEST_AGAINST=installed exists for.
_WHOLE_SUITE_SCAN = ("parses every test module and every script they reach, 2.2 MB of "
                     "Python; 0.29 s idle, costlier than any test left in the fast tier")


class CodeUnderTestTest(unittest.TestCase):
    """The switch decides where `import veridor` resolves, in both directions."""

    def test_veridor_is_imported_from_where_the_switch_says(self) -> None:
        location = Path(veridor.__file__).resolve().parent
        if source_path.MODE == "source":
            self.assertEqual(location, (ROOT / "src" / "veridor").resolve())
        else:
            self.assertFalse(location.is_relative_to(ROOT.resolve()),
                             f"VERIDOR_TEST_AGAINST=installed but veridor came from {location}")
            installed = {Path(sysconfig.get_paths()[key]).resolve() for key in ("purelib", "platlib")}
            self.assertIn(location.parent, installed,
                          f"{location} is not in this interpreter's site-packages {installed}")

    def test_child_processes_get_the_same_choice(self) -> None:
        env = source_path.child_env({"PYTHONPATH": "/elsewhere", "KEEP": "1"}, EXTRA="2")
        self.assertEqual(env["KEEP"], "1")
        self.assertEqual(env["EXTRA"], "2")
        if source_path.MODE == "source":
            self.assertEqual(env["PYTHONPATH"], str(ROOT / "src"))
        else:
            self.assertNotIn("PYTHONPATH", env)

    @slow(_WHOLE_SUITE_SCAN)
    def test_no_test_module_or_script_it_runs_puts_src_on_the_path(self) -> None:
        """One place decides. Anything else that put src/ on sys.path or
        PYTHONPATH would quietly undo VERIDOR_TEST_AGAINST=installed.

        This used to grep tests/*.py for one exact spelling, double quotes and
        all. Measured: a single-quoted insert, an ``SRC`` variable, an append
        and every script a test imports passed it, and tests/test_e2e.py
        imports scripts/e2e_validation.py, which inserted src/ at import time
        -- so ``VERIDOR_TEST_AGAINST=installed python -m unittest
        tests.test_e2e`` tested the checkout, not the installed wheel. Now
        every test module, scripts/run_tests.py, and every script a test
        imports or runs (followed transitively) is parsed, and every spelling
        in :data:`SRC_PATH_SPELLINGS` is refused.
        """
        found = [
            (path.relative_to(ROOT).as_posix(), line, what)
            for path, offences in _modules_the_suite_runs()
            for line, what in offences
        ]
        offenders = [f"{path}:{line}: {what}" for path, line, what in found
                     if (path, what) not in SRC_PATH_ALLOWED]
        self.assertEqual(offenders, [])
        # Control: every allowance is still found, so the scan read the real
        # modules rather than nothing, and the allowlist names nothing stale.
        self.assertEqual({(path, what) for path, _, what in found}, set(SRC_PATH_ALLOWED))
        runner = (ROOT / "scripts" / "run_tests.py").read_text(encoding="utf-8")
        self.assertIn("import source_path", runner)

    def test_all_nodes_is_ast_walk(self) -> None:
        """The faster walk the guard uses yields what ast.walk yields, node for
        node and in order, and grouping by class selects what isinstance does.
        Checked on this module and on one holding every planted spelling."""
        planted = "import sys\n" + "\n".join(SRC_PATH_SPELLINGS) + "\n"
        for label, text in (("tests/test_packaging.py", Path(__file__).read_text(encoding="utf-8")),
                            ("the planted spellings", planted)):
            with self.subTest(module=label):
                tree = ast.parse(text)
                nodes = _all_nodes(tree)
                walked = list(ast.walk(tree))
                self.assertEqual(len(nodes), len(walked))
                self.assertTrue(all(a is b for a, b in zip(nodes, walked)))
                grouped = _by_type(nodes)
                for kind in (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr,
                             ast.ImportFrom, ast.Import, ast.Constant, ast.Call, ast.Dict):
                    self.assertEqual(grouped.get(kind, []),
                                     [node for node in walked if isinstance(node, kind)])

    @slow(_WHOLE_SUITE_SCAN)
    def test_the_scan_reaches_the_scripts_tests_use(self) -> None:
        """Control: a scan that never opened scripts/ would find nothing there."""
        scanned = {path.relative_to(ROOT).as_posix() for path, _ in _modules_the_suite_runs()}
        for script in ("scripts/e2e_validation.py",
                       "scripts/blind_config_study.py", "scripts/run_tests.py",
                       "scripts/demo_server.py"):
            self.assertIn(script, scanned)
        self.assertNotIn("tests/source_path.py", scanned)

    def test_control_every_spelling_is_caught(self) -> None:
        """Each spelling planted in an otherwise clean module must be refused."""
        clean = "import sys\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
        self.assertEqual(_src_path_offences(clean + "sys.path.insert(0, str(ROOT))\n"), [])
        for spelling in SRC_PATH_SPELLINGS:
            with self.subTest(spelling=spelling):
                self.assertTrue(_src_path_offences(clean + spelling + "\n"), spelling)


class LicenceFilesTest(unittest.TestCase):
    def test_licence_is_the_full_apache_2_0_text(self) -> None:
        """The file used to be the 17-line notice, which is not the licence
        Apache-2.0 section 4(a) says recipients must be given."""
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual(digest, APACHE_2_0_SHA256)

    def test_notice_carries_the_copyright_line(self) -> None:
        """The holder was "Veridor Contributors", a group with no members that
        cannot hold anything. GOVERNANCE.md says there is one maintainer, so
        NOTICE and the package metadata name that person and nobody invented."""
        holder = "Santosh Kumar Puppala"
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertTrue(notice.startswith(f"Copyright 2026 {holder}\n"), notice[:80])
        self.assertEqual(PYPROJECT["project"]["authors"], [{"name": holder}])
        self.assertEqual(PYPROJECT["project"]["maintainers"], [{"name": holder}])
        self.assertIn("Licensed under the Apache License, Version 2.0", notice)

    def test_metadata_uses_a_pep_639_expression_and_ships_both_files(self) -> None:
        project = PYPROJECT["project"]
        self.assertEqual(project["license"], "Apache-2.0")
        self.assertEqual(project["license-files"], ["LICENSE", "NOTICE"])
        self.assertFalse([c for c in project["classifiers"] if c.startswith("License ::")],
                         "PEP 639 forbids a License classifier next to a license expression")
        self.assertIn("setuptools>=77", PYPROJECT["build-system"]["requires"])



def dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """``(KEYWORD, arguments)`` per instruction, as BuildKit reads them:
    continuation lines joined, comment lines dropped."""
    instructions, pending = [], ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not (stripped or pending):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        joined, pending = (pending + stripped).strip(), ""
        if joined:
            keyword, _, arguments = joined.partition(" ")
            instructions.append((keyword.upper(), arguments.strip()))
    return instructions


#: The runtime stage's one RUN: the wheel read from the build stage through a
#: read-only mount, installed offline, then pip removed and the CLI's imports
#: compiled, all in the layer that ran pip.
WHEEL_MOUNT = "type=bind,from=build,source=/dist,target=/tmp/wheels"
WHEEL_INSTALL = "python -m pip install --no-cache-dir --no-index --no-deps /tmp/wheels/*.whl"
PIP_REMOVAL = ("python -m pip uninstall --yes --no-cache-dir pip",
               "rm -rf /usr/local/lib/python3.12/ensurepip /usr/local/bin/pip*")
#: What the install RUN runs to compile what the CLI's verbs import: the CLI,
#: the modules its verbs import lazily, the codecs a run looks up by name, and
#: `serve`'s page reads (by calling them: which modules importlib.resources
#: imports to read a file differs from 3.11 to 3.13, measured). No quote
#: inside, so the CI step can quote it whole. WarmStepCoversEveryVerbTest runs
#: every verb and holds this to what they import.
WARM_CODE = ("import veridor.cli, veridor.capsule, veridor.mutation, veridor.sequence, veridor.web, "
             "encodings.idna, encodings.utf_16_be, encodings.utf_16_le, importlib.resources; "
             "[f.read_bytes() for f in importlib.resources.files(veridor.web).iterdir() if f.is_file()]")
WARM_STEP = f'env -u PYTHONDONTWRITEBYTECODE python -c "{WARM_CODE}"'
#: The warm step as it was: what `import veridor.cli` imports, and no more.
CLI_ONLY_WARM_STEP = 'env -u PYTHONDONTWRITEBYTECODE python -c "import veridor.cli"'


def _runtime_install(dockerfile: str) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """The runtime stage's instructions, the install RUN's mounts, and its
    ``&&``-separated commands (both empty when there is not exactly one)."""
    instructions = dockerfile_instructions(dockerfile)
    last_from = max(i for i, (keyword, _) in enumerate(instructions) if keyword == "FROM")
    runtime = instructions[last_from + 1:]
    installs = [arguments for keyword, arguments in runtime if keyword == "RUN" and "pip install" in arguments]
    if len(installs) != 1:
        return runtime, [], []
    mounts = re.findall(r"--mount=(\S+)\s+", installs[0])
    body = re.sub(r"^(?:--mount=\S+\s+)+", "", installs[0])
    return runtime, mounts, [command.strip() for command in body.split("&&")]


def wheel_install_problems(dockerfile: str) -> list[str]:
    """Only the wheel reaches the image, installed with no index: nothing is
    COPYed into a runtime layer, and pip reads the wheel from a read-only mount
    of the build stage's /dist."""
    runtime, mounts, commands = _runtime_install(dockerfile)
    problems = [f"the runtime stage writes files into a layer: {keyword} {arguments}"
                for keyword, arguments in runtime if keyword in ("COPY", "ADD")]
    if not commands:
        return problems + ["the runtime stage has no single RUN that installs the wheel"]
    if mounts != [WHEEL_MOUNT]:
        problems.append(f"the install RUN mounts {mounts}, not only the build stage's /dist, read-only")
    if commands[0] != WHEEL_INSTALL:
        problems.append(f"the install RUN starts with {commands[0]!r}, not the offline install from the mount")
    return problems


def pip_removal_problems(dockerfile: str) -> list[str]:
    """pip and ensurepip leave in the same RUN that used them, so neither they
    nor the bytecode pip wrote for its own imports is committed."""
    _, _, commands = _runtime_install(dockerfile)
    return [f"the install RUN does not run {step!r}" for step in PIP_REMOVAL if step not in commands]


def warm_step_problems(dockerfile: str) -> list[str]:
    """The install RUN ends by compiling what the CLI imports, with bytecode
    writing on whatever the environment says."""
    _, _, commands = _runtime_install(dockerfile)
    if not commands or commands[-1] != WARM_STEP:
        return [f"the install RUN does not end with {WARM_STEP!r}; it ends with "
                f"{commands[-1] if commands else None!r}"]
    return []


class ReleaseImageTest(unittest.TestCase):
    """The release Dockerfile, read as text. The CI `image` job builds and runs it."""

    DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    IGNORE = read_patterns(ROOT / ".dockerignore")

    def test_both_stages_use_one_base_pinned_by_digest(self) -> None:
        bases = re.findall(r"^FROM (\S+)", self.DOCKERFILE, re.M)
        self.assertEqual(len(bases), 2, bases)
        for base in bases:
            self.assertRegex(base, r"^python:3\.12-alpine@sha256:[0-9a-f]{64}$")
        self.assertEqual(len(set(bases)), 1)

    def test_it_runs_as_10001_with_veridor_as_the_entrypoint(self) -> None:
        self.assertIn("\nUSER 10001:10001\n", self.DOCKERFILE)
        self.assertIn('\nENTRYPOINT ["veridor"]\nCMD ["--help"]\n', self.DOCKERFILE)
        self.assertIn("\nWORKDIR /work\n", self.DOCKERFILE)
        # busybox: the group is created with gid 10001, the user with uid
        # 10001 in that group (the CI image job reads `id -u` back).
        self.assertRegex(self.DOCKERFILE, r"\baddgroup -S -g 10001 veridor\b")
        self.assertRegex(self.DOCKERFILE, r"\badduser (?:-\w \S+ |-\w )*-u 10001 -G veridor\b")

    def test_the_runtime_installs_only_the_wheel_offline(self) -> None:
        """This asserted `COPY --from=build /dist/ /tmp/wheels/`. That COPY was
        a 454 KB layer holding the wheel, which the next RUN deleted and every
        pull still downloaded (measured). The wheel is now read through a
        mount, so the intent is pinned in the new form: no runtime layer is
        written by COPY or ADD, and pip installs from the mount with no index."""
        self.assertEqual(wheel_install_problems(self.DOCKERFILE), [])

    def test_pip_leaves_in_the_layer_that_ran_it(self) -> None:
        """The old install layer held pip's own bytecode: 310 files, 3.9 MB
        before compression (measured). Removed in a later RUN, it would still
        be in this layer, and downloaded."""
        self.assertEqual(pip_removal_problems(self.DOCKERFILE), [])

    def test_the_install_layer_compiles_what_the_cli_imports(self) -> None:
        """uid 10001 cannot write bytecode, so anything this step does not
        compile is compiled on every start. scripts/image_bytecode_check.py
        checks the built image in CI; this keeps the step where it runs."""
        self.assertEqual(warm_step_problems(self.DOCKERFILE), [])

    def test_control_the_old_install_and_broken_layers_are_named(self) -> None:
        old = self.DOCKERFILE.replace(
            f"RUN --mount={WHEEL_MOUNT} \\\n    {WHEEL_INSTALL} \\\n",
            f"COPY --from=build /dist/ /tmp/wheels/\nRUN {WHEEL_INSTALL} \\\n && rm -rf /tmp/wheels \\\n")
        self.assertNotEqual(old, self.DOCKERFILE, "the mutation did not apply")
        self.assertEqual(wheel_install_problems(old), [
            "the runtime stage writes files into a layer: COPY --from=build /dist/ /tmp/wheels/",
            "the install RUN mounts [], not only the build stage's /dist, read-only"])
        writable = self.DOCKERFILE.replace(WHEEL_MOUNT, WHEEL_MOUNT + ",rw")
        self.assertEqual(len(wheel_install_problems(writable)), 1)
        online = self.DOCKERFILE.replace(" --no-index --no-deps /tmp/wheels", " --no-deps /tmp/wheels")
        self.assertEqual(len(wheel_install_problems(online)), 1)
        # pip removed in a later RUN: its bytecode is already committed.
        split = self.DOCKERFILE.replace(f" \\\n && {PIP_REMOVAL[0]} \\\n", f"\nRUN {PIP_REMOVAL[0]} \\\n")
        self.assertNotEqual(split, self.DOCKERFILE, "the mutation did not apply")
        self.assertEqual(pip_removal_problems(split), [f"the install RUN does not run {step!r}" for step in PIP_REMOVAL])
        cold = self.DOCKERFILE.replace(f" \\\n && {WARM_STEP}\n", "\n")
        self.assertNotEqual(cold, self.DOCKERFILE, "the mutation did not apply")
        self.assertEqual(len(warm_step_problems(cold)), 1)
        # The step runs with PYTHONDONTWRITEBYTECODE unset. With it set above
        # this RUN, even clearing sys.dont_write_bytecode inside the command
        # left the modules Python imports at start (encodings) compiled from
        # source on every start (measured: 3).
        plain = self.DOCKERFILE.replace(WARM_STEP, WARM_STEP.removeprefix("env -u PYTHONDONTWRITEBYTECODE "))
        self.assertNotEqual(plain, self.DOCKERFILE, "the mutation did not apply")
        self.assertEqual(len(warm_step_problems(plain)), 1)
        # The step as it was: every verb that sends a request compiled two
        # codecs from source on every start (WarmStepCoversEveryVerbTest).
        self.assertEqual(len(warm_step_problems(self.DOCKERFILE.replace(WARM_STEP, CLI_ONLY_WARM_STEP))), 1)

    def test_the_oci_labels_are_set_from_build_args(self) -> None:
        for label, value in (("source", "https://github.com/Veridor-authz/veridor"),
                             ("licenses", "Apache-2.0"), ("version", "${VERSION}"),
                             ("revision", "${REVISION}"), ("created", "${CREATED}")):
            with self.subTest(label=label):
                self.assertIn(f'org.opencontainers.image.{label}="{value}"', self.DOCKERFILE)

    def test_the_context_excludes_private_and_non_shipping_trees(self) -> None:
        """A checkout's local files must not reach a builder. This asked for
        these literal lines, which an allowlist does not have, so it now asks
        what the rules do to a file in each tree."""
        for path in (".private/x", ".git/config", ".veridor/x", "tests/x.py", "docs/x.md",
                     "src/veridor/__pycache__/x.pyc"):
            with self.subTest(path=path):
                self.assertTrue(ignored(path, self.IGNORE))
        # Control: the rules are not simply excluding everything.
        for path in ("pyproject.toml", "src/veridor/cli.py"):
            with self.subTest(path=path):
                self.assertFalse(ignored(path, self.IGNORE))


class ImageBytecodeCheckTest(unittest.TestCase):
    """scripts/image_bytecode_check.py's reading of a PYTHONVERBOSE=1 log.

    The lines are CPython 3.12's own, copied from `veridor --version` in the
    images: the release image, one built without the warm step, and one whose
    sources were touched after it (every .pyc present, all of them stale)."""

    CLI = ("# /usr/local/lib/python3.12/site-packages/veridor/__pycache__/cli.cpython-312.pyc matches "
           "/usr/local/lib/python3.12/site-packages/veridor/cli.py\n"
           "# code object from '/usr/local/lib/python3.12/site-packages/veridor/__pycache__/cli.cpython-312.pyc'\n")
    WARM = ("# /usr/local/lib/python3.12/__pycache__/heapq.cpython-312.pyc matches /usr/local/lib/python3.12/heapq.py\n"
            "# code object from '/usr/local/lib/python3.12/__pycache__/heapq.cpython-312.pyc'\n")
    MISSING = "# code object from /usr/local/lib/python3.12/difflib.py\n"
    STALE = "# bytecode is stale for 'difflib'\n# code object from /usr/local/lib/python3.12/difflib.py\n"

    def test_a_start_that_loads_only_bytecode_passes(self) -> None:
        self.assertEqual(image_bytecode_check.problems(self.WARM + self.CLI + "veridor 0.1.0\n"), [])

    def test_a_missing_or_stale_pyc_is_named(self) -> None:
        for label, line in (("missing", self.MISSING), ("stale", self.STALE)):
            with self.subTest(label):
                self.assertEqual(image_bytecode_check.problems(self.WARM + line + self.CLI),
                                 ["compiled from source on every start: /usr/local/lib/python3.12/difflib.py"])

    def test_control_a_log_that_is_not_the_verbose_cli_import_fails(self) -> None:
        """No verbose lines at all (PYTHONVERBOSE not reaching the
        interpreter) would otherwise read as 0 compiled from source."""
        for label, log in (("not verbose", "veridor 0.1.0\n"), ("another program", self.WARM),
                           ("cli from source", self.WARM + self.MISSING.replace(
                               "python3.12/difflib.py", "python3.12/site-packages/veridor/cli.py"))):
            with self.subTest(label):
                found = image_bytecode_check.problems(log)
                self.assertTrue(found)
                self.assertIn("never shows veridor.cli loaded from bytecode", found[-1])

    #: What a `veridor run` loads that `--version` does not, from the release
    #: image's own log; and what it compiled from source before the warm step
    #: covered it (both measured).
    RUN_ONLY = "# code object from '/usr/local/lib/python3.12/site-packages/veridor/__pycache__/sequence.cpython-312.pyc'\n"
    CODEC_FROM_SOURCE = "# code object from /usr/local/lib/python3.12/encodings/utf_16_le.py\n"

    def test_a_start_and_a_run_that_load_only_bytecode_pass(self) -> None:
        version = self.WARM + self.CLI
        self.assertEqual(image_bytecode_check.verdict(version, version + self.RUN_ONLY), [])

    def test_a_run_that_compiles_what_version_did_not_is_named(self) -> None:
        """--version alone passed while every run compiled two codecs."""
        version = self.WARM + self.CLI
        self.assertEqual(image_bytecode_check.verdict(version, version + self.RUN_ONLY + self.CODEC_FROM_SOURCE),
                         ["run: compiled from source on every run: /usr/local/lib/python3.12/encodings/utf_16_le.py"])
        self.assertEqual(image_bytecode_check.problems(version), [], "control: --version itself is clean")

    def test_control_a_run_log_that_is_only_a_start_is_not_a_run(self) -> None:
        version = self.WARM + self.CLI
        found = image_bytecode_check.verdict(version, version)
        self.assertEqual(len(found), 1)
        self.assertIn("not the import log of a run", found[0])
        self.assertEqual(image_bytecode_check.verdict("veridor 0.1.0\n", version + self.RUN_ONLY)[0],
                         "--version: the log never shows veridor.cli loaded from bytecode, so it is not the "
                         "verbose import log of the CLI and shows nothing either way")


#: One verb in a fresh interpreter: import veridor.cli, note sys.modules, run
#: the verb (``serve`` on a thread, until a page and each static file are
#: fetched), then print the pure-Python modules it imported beyond them.
_VERB_CHILD = r"""
import contextlib, io, json, os, sys, threading, time, urllib.request
import veridor.cli as cli
before = set(sys.modules)
args = json.loads(os.environ["VERB_ARGS"])
out = io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
    if args[0] == "serve":
        port = int(args[args.index("--port") + 1])
        threading.Thread(target=cli.main, args=(args,), daemon=True).start()
        fetched = []
        for page in ("/", "/app.js", "/styles.css", "/theme.js", "/favicon.svg", "/api/runs"):
            for _ in range(200):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}{page}", timeout=5) as reply:
                        fetched.append(reply.status)
                    break
                except OSError:
                    time.sleep(0.02)
        code = fetched
    elif args[0] == "import":
        exec(args[1])
        code = 0
    else:
        try:
            code = cli.main(args)
        except SystemExit as exc:
            code = exc.code
new = sorted(name for name in set(sys.modules) - before
             if str(getattr(getattr(sys.modules[name], "__spec__", None), "origin", "")).endswith(".py"))
sys.__stdout__.write(json.dumps({"code": code, "new": new}) + "\n")
sys.__stdout__.flush()
os._exit(0)
"""


@slow("runs every verb, each in its own interpreter, against a loopback demo API")
class WarmStepCoversEveryVerbTest(unittest.TestCase):
    """F1. The image's user cannot write bytecode, so a module a verb imports
    that the build's warm step did not compile is compiled from source every
    time. The step compiled what ``import veridor.cli`` imports, and
    scripts/image_bytecode_check.py ran only ``--version``: it passed while
    ``run``, ``map``, ``mutate`` and ``verify`` each compiled
    encodings.utf_16_le and utf_16_be from source in the image (measured).
    Here each verb runs on this interpreter, and every module it imports
    beyond ``veridor.cli`` must be one the Dockerfile's warm step imports."""

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.demo_server import create_server  # noqa: PLC0415

        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        work = Path(directory.name)
        server = create_server("127.0.0.1", 0, vulnerable=True)
        loopback.start(server)
        cls.addClassCleanup(server.server_close)
        cls.addClassCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        fixtures = ROOT / "fixtures"
        # The demo config with its tokens moved to the environment, so a
        # capsule can be written from it.
        config = json.loads((fixtures / "veridor.demo.json").read_text(encoding="utf-8"))
        for identity, token in (("invoice_owner", "OWNER"), ("other_tenant", "OTHER_TENANT"),
                                ("administrator", "ADMIN")):
            config["identities"][identity]["headers"]["Authorization"] = f"Bearer ${{VERIDOR_{token}_TOKEN}}"
        (work / "demo.json").write_text(json.dumps(config), encoding="utf-8")
        reports = [f"{kind}={work / name}" for kind, name in (
            ("sarif", "r.sarif"), ("junit", "r.xml"), ("gitlab-sast", "gl.json"), ("codequality", "cq.json"),
            ("markdown", "r.md"))]
        cls.scenarios: dict[str, list[str]] = {
            "--version": ["--version"],
            "run": ["run", "--config", str(work / "demo.json"), "--base-url", base, "--require-complete",
                    "--output-dir", str(work / "run"), "--json", str(work / "run.json"),
                    *[flag for report in reports for flag in ("--report", report)]],
            "map": ["map", "--config", str(fixtures / "veridor.map-demo.json"), "--openapi",
                    str(fixtures / "openapi.demo.json"), "--base-url", base, "--output-dir", str(work / "map"),
                    "--rate", "10"],
            "mutate": ["mutate", "--config", str(fixtures / "veridor.mutation-demo.json"), "--base-url", base,
                       "--output-dir", str(work / "mutate")],
            "report": ["report", "--from-run", str(work / "run.json"), "--format", "markdown", "--output",
                       str(work / "report.md")],
            "capsule": ["capsule", "--config", str(work / "demo.json"), "--check", "invoice-tenant-isolation",
                        "--from-run", str(work / "run.json"), "--output", str(work / "capsule.json")],
            "verify": ["verify", str(work / "capsule.json"), "--base-url", base],
            "init": ["init", "--openapi", str(fixtures / "openapi.demo.json"), "--output", str(work / "init.json")],
            "coverage": ["coverage", "--config", str(fixtures / "veridor.demo.json"), "--openapi",
                         str(fixtures / "openapi.demo.json"), "--allow-no-matches"],
            "new-marker": ["new-marker"],
            "serve": ["serve", "--output-dir", str(work / "run"), "--port", str(loopback.unallocated_port())],
        }
        env = source_path.child_env(VERIDOR_OWNER_TOKEN="owner-token", VERIDOR_OTHER_TENANT_TOKEN="outsider-token",
                                    VERIDOR_ADMIN_TOKEN="admin-token")
        cls.results: dict[str, dict] = {}
        # In order: report, capsule and verify read what run and capsule wrote.
        for verb, args in cls.scenarios.items():
            cls.results[verb] = cls.child(args, env, work)
        cls.warm = set(cls.child(["import", WARM_CODE], env, work)["new"])
        cls.cli_only = set(cls.child(["import", "import veridor.cli"], env, work)["new"])

    @staticmethod
    def child(args: list[str], env: dict[str, str], work: Path) -> dict:
        done = subprocess.run([sys.executable, "-c", _VERB_CHILD], env={**env, "VERB_ARGS": json.dumps(args)},
                              cwd=work, capture_output=True, text=True, timeout=300, check=False)
        lines = [line for line in done.stdout.splitlines() if line.startswith("{")]
        if not lines:
            raise AssertionError(f"{args[0]}: the child printed no result (exit {done.returncode}): "
                                 f"{done.stderr[-2000:]}")
        return json.loads(lines[-1])

    def test_the_dockerfile_warm_step_is_the_one_measured_here(self) -> None:
        self.assertEqual(warm_step_problems((ROOT / "Dockerfile").read_text(encoding="utf-8")), [])

    def test_each_verb_reached_its_path(self) -> None:
        """Not vacuous: each ran to its expected end, so its imports are the path's."""
        codes = {verb: result["code"] for verb, result in self.results.items()}
        self.assertEqual({verb: codes[verb] for verb in ("--version", "run", "map", "report", "capsule", "verify",
                                                          "init", "coverage", "new-marker")},
                         {"--version": 0, "run": 1, "map": 0, "report": 0, "capsule": 0, "verify": 1, "init": 0,
                          "coverage": 0, "new-marker": 0})
        self.assertIn(codes["mutate"], (0, 1, 2))
        self.assertEqual(codes["serve"], [200] * 6)
        self.assertIn("encodings.utf_16_le", self.results["run"]["new"])

    def test_every_verb_imports_only_what_the_warm_step_compiled(self) -> None:
        missing = {verb: sorted(set(result["new"]) - self.warm) for verb, result in self.results.items()
                   if set(result["new"]) - self.warm}
        self.assertEqual(missing, {}, "a verb imports a module the Dockerfile's warm step does not: in the image "
                         "it is compiled from source on every start. Add it to the step (and WARM_CODE).")

    def test_control_the_warm_step_as_it_was_misses_the_codecs(self) -> None:
        self.assertEqual(self.cli_only, set(), "`import veridor.cli` itself is the baseline")
        for verb in ("run", "map", "mutate", "verify"):
            with self.subTest(verb=verb):
                self.assertTrue({"encodings.utf_16_be", "encodings.utf_16_le"} <= set(self.results[verb]["new"]))


class ZipappContentsTest(unittest.TestCase):
    """scripts/build_zipapp.py: deterministic, and nothing but the package."""

    def test_two_builds_are_byte_identical(self) -> None:
        self.assertEqual(hashlib.sha256(build_zipapp.build()).hexdigest(),
                         hashlib.sha256(build_zipapp.build()).hexdigest())

    def test_it_holds_the_package_the_licence_and_a_main_only(self) -> None:
        data = build_zipapp.build()
        self.assertTrue(data.startswith(b"#!/usr/bin/env python3\n"))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
        names = [info.filename for info in infos]
        self.assertEqual(names, sorted(names))
        package = ROOT / "src"
        expected = {path.relative_to(package).as_posix()
                    for path in (package / "veridor").rglob("*")
                    if path.is_file() and "__pycache__" not in path.parts}
        self.assertEqual(set(names), expected | {"__main__.py", "LICENSE", "NOTICE"})
        self.assertIn("veridor/web/styles.css", names)
        for info in infos:
            self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0), info.filename)
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED, info.filename)

    def test_the_file_is_named_for_the_package_version(self) -> None:
        self.assertEqual(build_zipapp.version(), veridor.__version__)


@slow("builds the zipapp and runs it in subprocesses against loopback servers")
class ZipappRunsTest(unittest.TestCase):
    """The zipapp as a user runs it: --version, a gate run, and the viewer's
    package data served from inside the zip."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="veridor-pyz-"))
        cls.pyz = cls.tmp / f"veridor-{build_zipapp.version()}.pyz"
        cls.pyz.write_bytes(build_zipapp.build())

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil  # noqa: PLC0415

        shutil.rmtree(cls.tmp, True)

    def run_pyz(self, *args: str, **kwargs) -> subprocess.CompletedProcess[str]:
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        return subprocess.run([sys.executable, "-I", str(self.pyz), *args], capture_output=True,
                              text=True, env=env, timeout=120, cwd=self.tmp, **kwargs)

    def test_version(self) -> None:
        result = self.run_pyz("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"veridor {build_zipapp.version()}")

    def test_a_gate_run_against_the_vulnerable_demo_exits_1(self) -> None:
        from scripts.demo_server import create_server  # noqa: PLC0415

        server = create_server("127.0.0.1", 0, vulnerable=True)
        loopback.start(server)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        result = self.run_pyz("run", "--config", str(ROOT / "fixtures" / "veridor.demo.json"),
                              "--base-url", f"http://127.0.0.1:{server.server_address[1]}",
                              "--output-dir", str(self.tmp / "out"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_serve_reads_its_assets_from_inside_the_zip(self) -> None:
        # Outside the ephemeral range: a port from bind(0), released here, could be
        # handed to another process before serve binds it, and the loop below
        # would then read that process's answers.
        port = loopback.unallocated_port()
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        process = subprocess.Popen([sys.executable, "-I", str(self.pyz), "serve", "--output-dir",
                                    str(self.tmp / "serve"), "--port", str(port)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
                                   cwd=self.tmp)
        self.addCleanup(process.stderr.close)  # cleanups run last-added first:
        self.addCleanup(process.wait, 10)       # terminate, wait, then close
        self.addCleanup(process.terminate)
        deadline = time.monotonic() + 20
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline or process.poll() is not None:
                    self.fail(f"serve did not start: {process.stderr.read().decode() if process.poll() is not None else 'timeout'}")
                time.sleep(0.1)
        for asset in ("styles.css", "app.js"):
            with self.subTest(asset=asset):
                request = urllib.request.Request(f"http://127.0.0.1:{port}/{asset}",
                                                 headers={"Host": "127.0.0.1"})
                with urllib.request.urlopen(request, timeout=10) as response:
                    body = response.read()
                self.assertEqual(body, (ROOT / "src" / "veridor" / "web" / asset).read_bytes())


if __name__ == "__main__":
    unittest.main()
