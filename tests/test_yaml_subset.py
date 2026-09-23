"""tests/yaml_subset.py: the one YAML reader, in its two modes.

There were two readers. tests/action_harness.py's kept every scalar a string
and refused Kubernetes keys (``app.kubernetes.io/name``) and ``{}``; the one
here typed scalars but kept a trailing `` # comment`` as part of the value
(measured on the README's Action example: ``security-events`` read as
``'write   # for the SARIF upload step only'``) and refused every workflow,
because ``branches: [main]`` is not JSON. Each was cross-checked against a
different parser on the files it happened to read. Now one parser serves both,
and these tests hold the difference between the modes to what it should be.

Fast tier: strings in, values out.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import action_harness  # noqa: E402
import yaml_subset  # noqa: E402
from yaml_subset import YAMLSubsetError, load_yaml_documents, load_yaml_text  # noqa: E402

#: YAML in the repository the subset refuses, and why. Everything else must
#: parse, so a new file is either readable by the tests or named here.
REFUSED = {
    "deploy/kind/veridor.yaml": "flow mappings that are not JSON (`{ name: Host, ... }`)",
    "deploy/helm/veridor-gate/README.md#yaml0": "a flow mapping that is not JSON",
    "deploy/helm/veridor-gate/README.md#yaml1": "a flow mapping that is not JSON",
    "deploy/kustomize/veridor-gate/README.md#yaml0": "a flow mapping that is not JSON",
}
_MARKDOWN = ("README.md", "CONTRIBUTING.md", "ci/README.md", "deploy/argocd/README.md",
             "deploy/argo-rollouts/README.md", "deploy/helm/veridor-gate/README.md",
             "deploy/kustomize/veridor-gate/README.md", "deploy/kind/README.md")


def repository_yaml() -> dict[str, str]:
    """Every YAML file (Helm's Go templates excepted) and every ```yaml block."""
    found = {}
    skip = {"build", "dist", "node_modules", "__pycache__"}
    for directory, dirnames, filenames in os.walk(ROOT):
        rel_dir = Path(directory).relative_to(ROOT).as_posix()
        dirnames[:] = sorted(d for d in dirnames if d not in skip and (not d.startswith(".") or d == ".github"))
        if rel_dir == "deploy/helm/veridor-gate/templates":
            continue
        for filename in sorted(filenames):
            if filename.endswith((".yml", ".yaml")):
                rel = filename if rel_dir == "." else f"{rel_dir}/{filename}"
                found[rel] = (ROOT / rel).read_text(encoding="utf-8")
    for name in _MARKDOWN:
        text = (ROOT / name).read_text(encoding="utf-8")
        for index, match in enumerate(re.finditer(r"^```ya?ml\n(.*?)^```", text, re.M | re.S)):
            found[f"{name}#yaml{index}"] = textwrap.dedent(match.group(1))
    return found


class OneReaderTest(unittest.TestCase):
    def test_the_harness_reads_yaml_with_this_module(self) -> None:
        self.assertIs(action_harness.YAMLSubsetError, YAMLSubsetError)
        self.assertEqual(action_harness.load_yaml("a: 1\n"), {"a": "1"})
        # No other test module carries a YAML parser of its own.
        parsers = [path.name for path in sorted((ROOT / "tests").glob("*.py"))
                   if re.search(r"^(class _Lines|def _parse_mapping|class _Reader)\b",
                                path.read_text(encoding="utf-8"), re.M)]
        self.assertEqual(parsers, ["yaml_subset.py"])

    def test_every_yaml_file_in_the_repository_parses_or_is_named(self) -> None:
        inputs = repository_yaml()
        self.assertGreater(len(inputs), 25, "the walk found almost no YAML")
        self.assertIn(".github/workflows/veridor.yml", inputs)
        refused = {}
        for name, text in inputs.items():
            try:
                load_yaml_documents(text)
            except YAMLSubsetError as error:
                refused[name] = str(error)
        self.assertEqual(set(refused), set(REFUSED), refused)


class ModesTest(unittest.TestCase):
    DOCUMENT = (
        "on:\n  push:\n    branches: [main]\n"
        "count: 3\nratio: 0.5\nflag: true\nnothing: null\nempty:\n"
        "quoted: \"3\"\n"
        "permissions:\n  security-events: write   # for the SARIF upload only\n"
    )

    def test_typed_resolves_scalars_the_way_pyyaml_does(self) -> None:
        self.assertEqual(load_yaml_text(self.DOCUMENT, typed=True), {
            "on": {"push": {"branches": ["main"]}}, "count": 3, "ratio": 0.5, "flag": True,
            "nothing": None, "empty": None, "quoted": "3",
            "permissions": {"security-events": "write"}})

    def test_untyped_keeps_every_scalar_as_written(self) -> None:
        self.assertEqual(load_yaml_text(self.DOCUMENT), {
            "on": {"push": {"branches": ["main"]}}, "count": "3", "ratio": "0.5", "flag": "true",
            "nothing": "null", "empty": None, "quoted": "3",
            "permissions": {"security-events": "write"}})

    def test_kubernetes_keys_and_json_flow_collections(self) -> None:
        text = ('metadata:\n  labels:\n    app.kubernetes.io/name: veridor\n'
                'spec:\n  config: {}\n  drop: ["ALL"]\n  env: [{"name": "A", "value": "1"}]\n')
        self.assertEqual(load_yaml_documents(text), [{
            "metadata": {"labels": {"app.kubernetes.io/name": "veridor"}},
            "spec": {"config": {}, "drop": ["ALL"], "env": [{"name": "A", "value": "1"}]}}])
        # Untyped reads keep refusing flow mappings, as the harness always did.
        with self.assertRaises(YAMLSubsetError):
            load_yaml_text(text)
        self.assertEqual(load_yaml_text("labels:\n  app.kubernetes.io/name: veridor\n"),
                         {"labels": {"app.kubernetes.io/name": "veridor"}})

    def test_a_yaml_1_1_boolean_is_refused_when_typed(self) -> None:
        """PyYAML, Helm and kubectl read `on` as true; a YAML 1.2 reader reads a string."""
        for word in ("yes", "No", "ON", "off"):
            with self.subTest(word=word):
                with self.assertRaises(YAMLSubsetError) as caught:
                    load_yaml_documents(f"enabled: {word}\n")
                self.assertIn("quote it or write true/false", str(caught.exception))
                self.assertEqual(load_yaml_documents(f'enabled: "{word}"\n'), [{"enabled": word}])
                self.assertEqual(load_yaml_text(f"enabled: {word}\n"), {"enabled": word})

    def test_it_refuses_what_it_does_not_implement_in_both_modes(self) -> None:
        for text in ("a: &anchor x\n", "a: *alias\n", "a: !!str x\n", "a: {b: c}\n", "a: x\na: y\n",
                     "a: b: c\n", "a:\n\tb: c\n", "a: 'unterminated\n", "a: >+\n  x\n", "a: |2\n  x\n",
                     "a: [b,\n  c]\n", "a:\n    b: 1\n  c: 2\n", '- run: gh pr comment --body "Veridor: 1"\n',
                     'a: "x" y\n', 'a: "\\x41"\n'):
            for typed in (True, False):
                with self.subTest(text=text, typed=typed), self.assertRaises(YAMLSubsetError):
                    load_yaml_text(text, typed=typed)

    def test_documents_split_on_markers_and_a_single_read_refuses_them(self) -> None:
        self.assertEqual(load_yaml_documents("---\na: 1\n---\n# only a comment\n---\nb: 2\n"),
                         [{"a": 1}, {"b": 2}])
        with self.assertRaises(YAMLSubsetError):
            load_yaml_text("---\na: b\n")
        with self.assertRaises(YAMLSubsetError):
            yaml_subset.load_yaml(ROOT / "deploy" / "argo-rollouts" / "rollout-example.yaml")


if __name__ == "__main__":
    unittest.main()
