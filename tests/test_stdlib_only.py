"""The runtime imports nothing but the Python standard library.

Stdlib-only is a product claim, not a preference: it is why a built wheel
installs with no package index at all (``pip install --no-index --no-deps``),
why ``pip install`` pulls in nothing but Veridor itself, and why the release
image has no dependency layer. It does not make a source install work
offline: building from source needs the build backend (setuptools), which comes
from a package index unless it is already installed. SECURITY.md says Veridor
connects to nothing but the target it was given, or a proxy the environment
names for it; this module checks only the import half of that, never a
connection (tests/test_proxy.py checks where requests go). SECURITY.md,
CONTRIBUTING.md and deploy/kind/Dockerfile all say stdlib-only is checked.

It was checked by an AST scan in ``release.yml`` until that step was removed.
After that nothing did: the only import assertions left in the suite
cover ``openapi.py``, ``coverage.py`` and ``sequence.py``, so an ``import yaml``
planted in ``gate.py`` inside a ``try`` block, and a ``from requests import
adapters`` planted in ``reports/markdown.py``, passed the whole fast tier
(measured). This module is the check those three documents now name.

The scan reads the package that is being tested -- ``src/veridor`` by default,
the installed package under ``VERIDOR_TEST_AGAINST=installed`` -- and walks
every node, so an import inside a function, a class, a ``try`` or an
``if TYPE_CHECKING`` block counts the same as one at the top of a file.
"""

from __future__ import annotations

import ast
import functools
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import veridor  # noqa: E402

PACKAGE = Path(veridor.__file__).resolve().parent

#: What a runtime import may name at the top level: a module this interpreter
#: ships, or Veridor itself. ``sys.stdlib_module_names`` is per-version, so a
#: module removed from the standard library (PEP 594) fails on the interpreter
#: that no longer has it -- which is exactly where it would break at runtime.
ALLOWED_TOP_LEVEL = frozenset(sys.stdlib_module_names) | {"veridor"}

#: Functions that import a module named by a value rather than a statement, as
#: (module, name); ``None`` is a builtin.
_DYNAMIC = {
    ("importlib", "import_module"), ("importlib", "__import__"),
    ("builtins", "__import__"), ("runpy", "run_module"), (None, "__import__"),
}


def _importers(tree: ast.AST) -> tuple[dict[str, str], dict[str, tuple[str | None, str]]]:
    """What names in this file reach a function in :data:`_DYNAMIC`: modules
    bound by ``import importlib [as il]``, and the functions themselves bound
    by ``from importlib import import_module [as load]``. Collected over the
    whole file, whatever the scope: a name bound anywhere counts everywhere,
    which can only list more."""
    modules = {module: module for module, _ in _DYNAMIC if module}
    functions: dict[str, tuple[str | None, str]] = {"__import__": (None, "__import__")}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in modules:
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for alias in node.names:
                if (node.module, alias.name) in _DYNAMIC:
                    functions[alias.asname or alias.name] = (node.module, alias.name)
    return modules, functions


def _dynamic_import(node: ast.AST, modules: dict[str, str],
                    functions: dict[str, tuple[str | None, str]]) -> bool:
    """Is ``node`` a reference to an importing function, called or not?"""
    if isinstance(node, ast.Name):
        return node.id in functions
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
        return (modules[node.value.id], node.attr) in _DYNAMIC
    return False


def imports_in(path: Path) -> list[tuple[int, str]]:
    """``[(line, top-level module)]`` for every absolute import in ``path``.

    Relative imports (``from . import x``) are Veridor importing itself and are
    not listed. A dynamic import whose argument is a string literal is listed
    by that literal; one whose argument is anything else is listed as
    ``<dynamic>``, because what it imports cannot be read from the source. A
    dynamic import is any call to a function in :data:`_DYNAMIC`, however the
    file named it (:func:`_importers`), and a reference to one that is not
    called is ``<dynamic>`` too.
    """
    text = path.read_text(encoding="utf-8")
    try:
        return list(_imports_in_text(text))
    except SyntaxError:
        ast.parse(text, filename=str(path))  # raise it again, naming the file
        raise


@functools.lru_cache(maxsize=None)
def _imports_in_text(text: str) -> tuple[tuple[int, str], ...]:
    """:func:`imports_in` for one file's text, parsed once per process.

    Five tests scan the package or a temporary copy of it, and each parse of
    the package cost about 0.12 s. The file is still read every time and the
    key is its whole text, so a copy with an import planted in it is a
    different key and is parsed; only identical text is answered from the
    cache, whatever its path. A SyntaxError is not cached.
    """
    tree = ast.parse(text)
    modules, functions = _importers(tree)
    found: list[tuple[int, str]] = []
    called: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, alias.name.split(".")[0]) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                found.append((node.lineno, (node.module or "").split(".")[0]))
        elif isinstance(node, ast.Call) and _dynamic_import(node.func, modules, functions):
            called.add(id(node.func))
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.append((node.lineno, first.value.split(".")[0]))
            else:
                found.append((node.lineno, "<dynamic>"))
        elif id(node) not in called and _dynamic_import(node, modules, functions):
            # The importer itself, not called here: bound to another name or
            # passed along, so what it imports cannot be read from the source.
            found.append((node.lineno, "<dynamic>"))
    return tuple(found)


def third_party_imports(package: Path) -> list[str]:
    """``path:line: module`` for every import in ``package`` that is neither
    the standard library nor Veridor."""
    return [
        f"{path.relative_to(package.parent).as_posix()}:{line}: {module}"
        for path in sorted(package.rglob("*.py"))
        for line, module in imports_in(path)
        if module not in ALLOWED_TOP_LEVEL
    ]


class StdlibOnlyTest(unittest.TestCase):
    def test_every_runtime_import_is_stdlib_or_veridor(self) -> None:
        self.assertEqual(third_party_imports(PACKAGE), [])

    def test_the_scan_read_the_whole_package(self) -> None:
        """A guard on the guard: a scan of the wrong directory, or of nothing,
        finds no third-party import too."""
        files = {path.relative_to(PACKAGE).as_posix() for path in PACKAGE.rglob("*.py")}
        for expected in ("__init__.py", "cli.py", "core.py", "gate.py",
                         "reports/markdown.py", "reports/gitlab_sast.py"):
            self.assertIn(expected, files)
        if source_path.MODE == "source":
            self.assertEqual(PACKAGE, (ROOT / "src" / "veridor").resolve())
        modules = {module for path in PACKAGE.rglob("*.py") for _, module in imports_in(path)}
        self.assertTrue({"json", "urllib", "veridor", "__future__"} <= modules, modules)

    def test_the_package_declares_no_runtime_dependency(self) -> None:
        """``pip install veridor`` must pull in nothing else, which is the half
        of the claim an import scan cannot see."""
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project.get("dependencies", []), [])
        self.assertNotIn("dependencies", project.get("dynamic", []))

    def test_the_documents_that_claim_the_check_name_this_module(self) -> None:
        """Each said "an AST scan in the test suite" while none existed. Naming
        the file makes the claim checkable, and this makes the name stay true."""
        name = "tests/test_stdlib_only.py"
        self.assertTrue((ROOT / name).is_file())
        for document in ("SECURITY.md", "CONTRIBUTING.md", "deploy/kind/Dockerfile"):
            with self.subTest(document=document):
                self.assertIn(name, (ROOT / document).read_text(encoding="utf-8"))


class StdlibOnlyControlTest(unittest.TestCase):
    """The scan fails on a planted third-party import, wherever it hides."""

    PLANTS = {
        "top level": ("import yaml\n", ["yaml"]),
        "dotted": ("import google.protobuf\n", ["google"]),
        "from-import": ("from requests import adapters\n", ["requests"]),
        "inside a function, in a try": (
            "def f():\n    try:\n        import httpx\n    except ImportError:\n        pass\n",
            ["httpx"],
        ),
        "in a class body": ("class C:\n    import attrs\n", ["attrs"]),
        "under TYPE_CHECKING": (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import pydantic\n",
            ["pydantic"],
        ),
        "importlib literal": ("import importlib\nimportlib.import_module('jwt')\n", ["jwt"]),
        "__import__ of a value": ("name = 'x'\n__import__(name)\n", ["<dynamic>"]),
        # REGRESSION: each of these passed the scan, which matched only the
        # two literal spellings above (measured).
        "import_module, from-imported": (
            "from importlib import import_module\nimport_module('jwt')\n", ["jwt"]),
        "import_module, renamed": (
            "from importlib import import_module as load\nload('yaml')\n", ["yaml"]),
        "importlib, aliased": ("import importlib as il\nil.import_module('toml')\n", ["toml"]),
        "builtins.__import__": ("import builtins\nbuiltins.__import__('httpx')\n", ["httpx"]),
        "runpy.run_module": ("import runpy\nrunpy.run_module('pip')\n", ["pip"]),
        "the importer as a value": (
            "import importlib\nload = importlib.import_module\nload('attrs')\n", ["<dynamic>"]),
    }

    def copy(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="veridor-stdlib-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(PACKAGE, root / "veridor",
                        ignore=shutil.ignore_patterns("__pycache__"))
        return root / "veridor"

    def test_the_unmodified_copy_is_clean(self) -> None:
        self.assertEqual(third_party_imports(self.copy()), [])

    def test_a_planted_import_is_named_with_its_file_and_line(self) -> None:
        # Each shape is appended to a different module of ONE copy, and the
        # copy is scanned once: a copy and a scan per shape took 2.2 s, over
        # the fast tier's per-test budget.
        package = self.copy()
        modules_in_copy = sorted(package.rglob("*.py"))
        self.assertGreaterEqual(len(modules_in_copy), len(self.PLANTS))
        planted = []
        for target, (where, (source, modules)) in zip(modules_in_copy, self.PLANTS.items()):
            text = target.read_text(encoding="utf-8")
            text += "" if text.endswith("\n") else "\n"
            target.write_text(text + source, encoding="utf-8")
            planted.append((where, target.relative_to(package.parent).as_posix(),
                            modules, text.count("\n")))
        found: dict[str, list[tuple[int, str]]] = {}
        for entry in third_party_imports(package):
            location, module = entry.rsplit(": ", 1)
            path, line = location.rsplit(":", 1)
            found.setdefault(path, []).append((int(line), module))
        self.assertEqual(set(found), {path for _, path, _, _ in planted})
        for where, path, modules, lines_before in planted:
            with self.subTest(where=where, path=path):
                self.assertEqual([module for _, module in found[path]], modules)
                self.assertTrue(all(line > lines_before for line, _ in found[path]))

    def test_relative_imports_and_stdlib_are_not_flagged(self) -> None:
        package = self.copy()
        (package / "planted.py").write_text(
            "from . import core\nfrom .reports import markdown\nimport json, urllib.request\n"
            "import importlib\nimportlib.import_module('xml.etree.ElementTree')\n",
            encoding="utf-8")
        self.assertEqual(third_party_imports(package), [])


if __name__ == "__main__":
    unittest.main()
