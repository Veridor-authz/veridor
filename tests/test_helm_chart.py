"""The Kubernetes surface: the veridor-gate chart, the Argo Rollouts template,
the Argo CD example and the kind end-to-end script.

A deployment gate fails in one direction only: silently open. A Job with a
retry turns a finding into a pass on the second attempt; a hook annotation for
the wrong tool makes the Job run beside the release instead of gating it; a
credential rendered into a ConfigMap is readable by anyone who can read
ConfigMaps. None of that shows up as a crash. So these tests read what the
chart actually renders, with the real `helm`, and parse the Job's arguments
with Veridor's real CLI parser.

Two tiers. The fast tests read the repository's files only. The slow tests
spawn `helm` (and bash, for the e2e script's refusals); when `helm` is not on
PATH they skip -- unless VERIDOR_REQUIRE_HELM=1, which turns the skip into a
failure so a CI job that is meant to run them cannot pass by not having helm.

The live cluster behaviour (Argo CD failing the sync, Rollouts aborting the
canary, Pod Security admission) is measured by scripts/e2e_kubernetes.sh, not
here.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import functools
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

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from scripts import release_check  # noqa: E402 -- ROOT is on sys.path above

CHART = ROOT / "deploy" / "helm" / "veridor-gate"
ANALYSIS_TEMPLATE = ROOT / "deploy" / "argo-rollouts" / "veridor-analysistemplate.yaml"
ROLLOUT_EXAMPLE = ROOT / "deploy" / "argo-rollouts" / "rollout-example.yaml"
APPLICATION_EXAMPLE = ROOT / "deploy" / "argocd" / "application-example.yaml"
E2E_SCRIPT = ROOT / "scripts" / "e2e_kubernetes.sh"
REQUIRE_HELM_ENV = "VERIDOR_REQUIRE_HELM"
REQUIRE_KUBECTL_ENV = "VERIDOR_REQUIRE_KUBECTL"
REQUIRE_SHELLCHECK_ENV = "VERIDOR_REQUIRE_SHELLCHECK"


# The YAML subset reader lives in tests/yaml_subset.py, shared with the CI
# configuration tests. YamlSubsetTest below still pins its output.
from yaml_subset import flatten, load_yaml, load_yaml_documents  # noqa: E402,F401


# ---------------------------------------------------------------------------
# Fast tier: the files, read and parsed. No helm, no subprocess.
# ---------------------------------------------------------------------------


class YamlSubsetTest(unittest.TestCase):
    """The control for every structural assertion below: if the reader
    mis-parsed, the tests built on it would be testing its bugs."""

    def test_a_known_document_parses_to_the_known_value(self) -> None:
        text = (
            "---\n# Source: x\n"
            "apiVersion: batch/v1\n"
            "metadata:\n"
            "  annotations:\n"
            '    argocd.argoproj.io/hook: "PostSync"\n'
            "    url: http://a.b:8080/x\n"
            "spec:\n"
            "  backoffLimit: 0\n"
            "  list:\n"
            "  - a\n"
            "  - name: n\n"
            "    value: '1'\n"
            "  items:\n"
            "    - --config\n"
            '    - "sleep 8; exec veridor \\"$@\\""\n'
            "  drop: [\"ALL\"]\n"
            "  empty: {}\n"
            "  data: |\n"
            "    {\n"
            '      "k": 1\n'
            "    }\n"
            "  folded: >-\n"
            "    one\n"
            "    two\n"
            "  after: true\n"
            "---\n"
            "# only a comment\n"
        )
        self.assertEqual(
            load_yaml_documents(text),
            [{
                "apiVersion": "batch/v1",
                "metadata": {"annotations": {"argocd.argoproj.io/hook": "PostSync",
                                             "url": "http://a.b:8080/x"}},
                "spec": {
                    "backoffLimit": 0,
                    "list": ["a", {"name": "n", "value": "1"}],
                    "items": ["--config", 'sleep 8; exec veridor "$@"'],
                    "drop": ["ALL"],
                    "empty": {},
                    "data": '{\n  "k": 1\n}\n',
                    "folded": "one two",
                    "after": True,
                },
            }],
        )

    def test_it_refuses_what_it_does_not_understand(self) -> None:
        for text in ("a: &anchor 1\n", "a:\n    b: 1\n  c: 2\n", "a: !!str x\n", "a: |2\n  x\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                load_yaml_documents(text)


class ChartMetadataTest(unittest.TestCase):
    def test_chart_identity(self) -> None:
        chart = load_yaml(CHART / "Chart.yaml")
        self.assertEqual(chart["apiVersion"], "v2")
        self.assertEqual(chart["name"], "veridor-gate")
        self.assertEqual(chart["version"], "0.1.0")

    def test_app_version_is_the_package_version(self) -> None:
        """The image tag defaults to appVersion, so a drift here deploys a
        different Veridor than the chart documents.

        appVersion is SemVer (it is an image tag) and ``__version__`` is PEP
        440, so a pre-release is ``1.2.0-rc.1`` in one and ``1.2.0rc1`` in the
        other. Compared as raw strings, this failed on every tree that
        ``release_check.py bump 1.2.0-rc.1 --write`` produced. The comparison
        goes through the mapping ``bump`` writes with and ``versions`` checks.
        """
        from veridor import __version__  # noqa: PLC0415

        self.assertEqual(str(load_yaml(CHART / "Chart.yaml")["appVersion"]),
                         release_check.pep440_to_semver(__version__))

    def test_defaults_that_decide_whether_the_gate_gates(self) -> None:
        values = load_yaml(CHART / "values.yaml")
        # No default hook mode: the render refuses until one is chosen.
        self.assertEqual(values["hook"]["mode"], "")
        self.assertEqual(values["hook"]["argocd"]["phase"], "PostSync")
        self.assertEqual(values["hook"]["argocd"]["deletePolicy"], "BeforeHookCreation")
        self.assertEqual(values["hook"]["helm"]["events"], "post-install,post-upgrade")
        self.assertEqual(values["hook"]["helm"]["deletePolicy"], "before-hook-creation")
        self.assertEqual(values["image"]["repository"], "ghcr.io/veridor-authz/veridor")
        self.assertEqual(values["image"]["tag"], "")
        self.assertEqual(values["image"]["command"], ["veridor"])
        self.assertIs(values["gate"]["requireComplete"], True)
        self.assertEqual(values["gate"]["failOn"], "new+confirmed")
        # The PostSync race: a hook Job can start before the Service routes to
        # the pod that just turned Ready. On by default, well under the deadline.
        self.assertEqual(values["gate"]["waitForTargetSeconds"], 60)
        self.assertLess(values["gate"]["waitForTargetSeconds"], values["job"]["activeDeadlineSeconds"])
        self.assertEqual(values["podSecurityContext"]["runAsUser"], 10001)
        self.assertEqual(values["podSecurityContext"]["runAsGroup"], 10001)
        self.assertEqual(values["config"], {})
        self.assertEqual(values["secretEnv"], [])

    def test_every_value_is_documented_in_the_readme(self) -> None:
        readme = (CHART / "README.md").read_text(encoding="utf-8")
        values = load_yaml(CHART / "values.yaml")
        paths = flatten(values)
        self.assertGreater(len(paths), 40, paths)
        missing = [path for path in paths if f"`{path}`" not in readme]
        self.assertEqual(missing, [], "values.yaml keys with no `key` entry in the chart README")

    def test_the_schema_covers_exactly_the_values(self) -> None:
        schema = json.loads((CHART / "values.schema.json").read_text(encoding="utf-8"))
        values = load_yaml(CHART / "values.yaml")
        self.assertIs(schema.get("additionalProperties"), False)
        declared = set(schema["properties"]) - {"global"}
        self.assertEqual(declared, set(values))

        def walk(node_schema: dict[str, Any], node: Any, path: str) -> None:
            if not isinstance(node, dict) or node_schema.get("type") != "object":
                return
            props = node_schema.get("properties")
            if props is None:
                return
            for key, item in node.items():
                with self.subTest(path=f"{path}.{key}"):
                    self.assertIn(key, props, f"{path}.{key} is in values.yaml but not the schema")
                    walk(props[key], item, f"{path}.{key}")

        walk(schema, values, "values")


class AnalysisTemplateTest(unittest.TestCase):
    """The Rollouts template is a hand-written copy of the Job the chart
    renders, so it is held to the same fields here."""

    def setUp(self) -> None:
        self.template = load_yaml(ANALYSIS_TEMPLATE)
        self.metric = self.template["spec"]["metrics"][0]
        self.job = self.metric["provider"]["job"]["spec"]
        self.pod = self.job["template"]["spec"]
        self.container = self.pod["containers"][0]

    def test_one_failed_measurement_aborts(self) -> None:
        self.assertEqual(self.template["kind"], "AnalysisTemplate")
        self.assertEqual(self.template["metadata"]["name"], "veridor-gate")
        self.assertEqual(self.metric["failureLimit"], 0)
        self.assertEqual(self.metric["count"], 1)
        self.assertEqual(self.job["backoffLimit"], 0)
        self.assertEqual(self.pod["restartPolicy"], "Never")

    def test_restricted_pod_security(self) -> None:
        assert_restricted(self, self.pod, self.container)

    def test_base_url_has_no_default_and_every_arg_is_used(self) -> None:
        declared = {arg["name"]: arg.get("value") for arg in self.template["spec"]["args"]}
        self.assertIn("base-url", declared)
        self.assertIsNone(declared["base-url"], "a default base-url could gate the stable Service")
        text = ANALYSIS_TEMPLATE.read_text(encoding="utf-8")
        used = set(re.findall(r"\{\{args\.([a-z0-9-]+)\}\}", text))
        self.assertEqual(used, set(declared))

    def test_the_job_runs_veridor_with_the_gate_flags(self) -> None:
        self.assertEqual(self.container["command"], ["veridor"])
        args = self.container["args"]
        self.assertEqual(args[0], "run")
        self.assertIn("--require-complete", args)
        self.assertNotIn("|| true", ANALYSIS_TEMPLATE.read_text(encoding="utf-8"))

    def test_the_job_arguments_parse_with_the_real_cli(self) -> None:
        from veridor import cli  # noqa: PLC0415

        declared = {arg["name"]: arg.get("value") for arg in self.template["spec"]["args"]}
        self.assertEqual(declared["wait-for-target"], "60")
        parsed = cli._parser().parse_args(analysis_template_args(self.template))
        self.assertEqual(parsed.command, "run")
        self.assertTrue(parsed.require_complete)
        self.assertEqual(parsed.base_url, "http://invoices-api-canary:8080")
        self.assertEqual(parsed.wait_for_target, 60)
        # The DECLARED default, not a value this test supplies: with
        # `fail-on: none` every canary analysis passed whatever it found, and
        # both test tiers stayed green (measured).
        self.assertEqual(parsed.fail_on, "new+confirmed")

    def test_default_fail_on_is_one_the_cli_accepts(self) -> None:
        from veridor import cli  # noqa: PLC0415

        declared = {arg["name"]: arg.get("value") for arg in self.template["spec"]["args"]}
        cli._parser().parse_args(["run", "--config", "c.json", "--fail-on", declared["fail-on"]])
        # Accepted is not correct: `none` parses too.
        self.assertEqual(declared["fail-on"], "new+confirmed")

    def test_the_fail_on_pin_can_fail(self) -> None:
        """Mutation control: the template with `fail-on: none` fails the pin
        above, so its pass is a result."""
        from veridor import cli  # noqa: PLC0415

        mutant = json.loads(json.dumps(self.template))
        for arg in mutant["spec"]["args"]:
            if arg["name"] == "fail-on":
                arg["value"] = "none"
        self.assertEqual(cli._parser().parse_args(analysis_template_args(mutant)).fail_on, "none")

    def test_credentials_come_from_a_secret_only(self) -> None:
        for entry in self.container.get("env") or []:
            self.assertTrue(entry["name"].startswith("PYTHON"), entry)
        self.assertEqual(
            self.container["envFrom"],
            [{"secretRef": {"name": "{{args.secret}}", "optional": True}}],
        )


def analysis_template_args(template: dict[str, Any]) -> list[str]:
    """The AnalysisTemplate Job's arguments with every {{args.NAME}} replaced
    by its DECLARED default, and a canary URL for base-url, which has none."""
    declared = {arg["name"]: arg.get("value") for arg in template["spec"]["args"]}
    declared["base-url"] = "http://invoices-api-canary:8080"
    container = template["spec"]["metrics"][0]["provider"]["job"]["spec"]["template"]["spec"]["containers"][0]
    return [re.sub(r"\{\{args\.([a-z0-9-]+)\}\}", lambda m: declared[m.group(1)], arg)
            for arg in container["args"]]


class RolloutExampleTest(unittest.TestCase):
    def setUp(self) -> None:
        documents = load_yaml_documents(ROLLOUT_EXAMPLE.read_text(encoding="utf-8"))
        self.services = {d["metadata"]["name"]: d for d in documents if d["kind"] == "Service"}
        self.rollout = next(d for d in documents if d["kind"] == "Rollout")
        self.canary = self.rollout["spec"]["strategy"]["canary"]

    def test_the_canary_and_stable_services_exist(self) -> None:
        self.assertIn(self.canary["canaryService"], self.services)
        self.assertIn(self.canary["stableService"], self.services)
        self.assertNotEqual(self.canary["canaryService"], self.canary["stableService"])

    def test_steps_weight_then_analysis_then_promotion(self) -> None:
        steps = self.canary["steps"]
        self.assertEqual([next(iter(step)) for step in steps], ["setWeight", "analysis", "setWeight"])
        self.assertLess(steps[0]["setWeight"], 100)
        self.assertEqual(steps[2]["setWeight"], 100)

    def test_the_analysis_probes_the_canary_service(self) -> None:
        analysis = next(step["analysis"] for step in self.canary["steps"] if "analysis" in step)
        self.assertEqual(analysis["templates"], [{"templateName": "veridor-gate"}])
        args = {arg["name"]: arg["value"] for arg in analysis["args"]}
        template_args = {arg["name"] for arg in load_yaml(ANALYSIS_TEMPLATE)["spec"]["args"]}
        self.assertLessEqual(set(args), template_args)
        canary = self.services[self.canary["canaryService"]]
        port = canary["spec"]["ports"][0]["port"]
        self.assertEqual(args["base-url"], f"http://{self.canary['canaryService']}:{port}")


class HelmModeInvocationDocumentTest(unittest.TestCase):
    """REGRESSION (R3-2 and R3-8, measured on kind with Helm 4.2.2): the
    README said `helm install` / `helm upgrade` exits non-zero when the gate
    fails and never said how to run it. Under Helm's default flags the hook
    probed a RollingUpdate Deployment's previous pods and passed a vulnerable
    upgrade (2 of 2); `--wait` and `--rollback-on-failure` against the app's
    own Service still let the replaced pod answer. The documented invocation
    is the one measured correct, and the e2e runs it."""

    def section(self) -> str:
        text = (CHART / "README.md").read_text(encoding="utf-8")
        start = text.index("## hook.mode helm: what the gate probes")
        return text[start:text.index("\n## ", start + 1)]

    def test_the_readme_documents_the_measured_invocation(self) -> None:
        section = self.section()
        self.assertIn("helm upgrade --install shop ./shop --namespace shop --rollback-on-failure", section)
        self.assertIn("example.com/release-revision: {{ .Release.Revision | quote }}", section)
        self.assertIn("baseUrl: http://invoices-api-this-revision.shop.svc.cluster.local:8080", section)
        self.assertIn("a dependency of your app's chart", section)
        table = " ".join((CHART / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("Under Helm's default flags the hook probes the version being replaced", table)

    def test_recreate_is_not_called_safe_under_helm_s_default_flags(self) -> None:
        """REGRESSION: NOTES and this section blamed the default-flags hazard
        on RollingUpdate alone, and step 2 called Recreate "measured correct"
        without saying it was measured with --rollback-on-failure. Measured
        on kind: with Recreate and Helm's default flags, 2 of 2 vulnerable
        upgrades passed, every gate request answered by the replaced pod,
        still terminating when the hook started."""
        section = " ".join(self.section().split())
        self.assertIn("| none (the defaults) | `Recreate` (5 s) | the app's Service | **2 of 2** |", section)
        self.assertIn("Under Helm's default flags `Recreate` does not", section)
        self.assertIn("Without step 3 Recreate passed the vulnerable version", section)
        self.assertNotIn("Only a Service of this revision's pods and `Recreate` keep the replaced pod", section)
        notes = " ".join((CHART / "templates" / "NOTES.txt").read_text(encoding="utf-8").split())
        self.assertNotIn("while a RollingUpdate Deployment's previous pods still served", notes)
        self.assertIn("under Recreate the old pod was still terminating and answering", notes)

    def test_the_e2e_runs_the_documented_invocation(self) -> None:
        script = E2E_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('rollback="--rollback-on-failure"', script)
        self.assertIn("shop_leg vuln yes vulnerable-2 shop-this-revision \"$rollback\"", script)
        self.assertIn("shop_leg default-flags yes vulnerable-5 shop\n", script)
        self.assertIn('vg-e2e/release-revision: {{ .Release.Revision | quote }}', script)


#: The chart README's Argo CD subsection, and the snippets the two recipes
#: are written in: a ```yaml block whose files start with a comment line
#: "# your chart, templates/<file>".
ARGO_SECTION_TITLE = "### Under Argo CD and `helm template`"


def readme_recipe(marker: str) -> dict[str, str]:
    """{file name: text} of the chart README's yaml block containing
    ``marker``, split at its "# your chart, templates/<file>" lines."""
    text = (CHART / "README.md").read_text(encoding="utf-8")
    blocks = [block for block in re.findall(r"```yaml\n(.*?)```", text, flags=re.S)
              if marker in block and "# your chart, templates/" in block]
    if len(blocks) != 1:
        raise AssertionError(f"{len(blocks)} README yaml blocks hold {marker!r}")
    lines = blocks[0].splitlines()
    indent = min(len(line) - len(line.lstrip()) for line in lines if line.strip())
    files: dict[str, list[str]] = {}
    current = None
    for line in lines:
        line = line[indent:]
        found = re.match(r"# your chart, templates/(\S+)", line)
        if found:
            current = files.setdefault(found.group(1), [])
        elif current is not None and line.strip() != "---":
            current.append(line)
    return {name: "\n".join(body).strip("\n") + "\n" for name, body in files.items()}


class ArgoCdTargetDocumentTest(unittest.TestCase):
    """REGRESSION (R4-5, R4-8): values.yaml (hook.argocd), the main README and
    the chart README sent Argo CD PostSync users to the Service on a
    `.Release.Revision` label, and CHANGELOG said the Argo CD docs gave "the
    invocation measured correct". Argo CD renders with `helm template`, where
    the revision is always 1 (measured through Argo CD by the e2e's argocd
    scenario), so that Service listed the replaced pod as well. Each Argo CD
    pointer must now lead to the pod-template recipe, and the revision recipe
    must say it is for the Helm CLI."""

    def normalised(self, path: Path) -> str:
        return " ".join(re.sub(r"(?m)^\s*#", "", path.read_text(encoding="utf-8")).split())

    def test_the_revision_recipe_says_it_is_for_the_helm_cli_only(self) -> None:
        section = " ".join(HelmModeInvocationDocumentTest().section().split())
        self.assertIn("This recipe is for the Helm CLI only", section)
        self.assertIn("`helm template` renders it as `1` every time", section)
        self.assertIn("Installed with `helm upgrade`, no pod of an earlier revision carries the label", section)
        self.assertIn(ARGO_SECTION_TITLE, section)

    def test_every_argo_cd_pointer_names_the_pod_template_label(self) -> None:
        values = load_yaml(CHART / "values.yaml")
        self.assertEqual(values["hook"]["argocd"]["phase"], "PostSync")
        text = (CHART / "values.yaml").read_text(encoding="utf-8")
        argocd_block = text[text.index("  argocd:\n"):text.index("    phase: PostSync")]
        pointers = {
            "values.yaml hook.argocd": " ".join(re.sub(r"(?m)^\s*#", "", argocd_block).split()),
            "README.md": self.normalised(ROOT / "README.md"),
            "deploy/argocd/README.md": self.normalised(ROOT / "deploy" / "argocd" / "README.md"),
        }
        for name, body in pointers.items():
            with self.subTest(pointer=name):
                self.assertRegex(body, r"(?:hash(?:ed)? (?:of|from) the (?:rendered )?pod (?:template|spec))")
                self.assertRegex(body, r"`?\.Release\.Revision`?[^.]*(?:always|is) (?:`)?1")
                self.assertIn("Argo Rollouts", body)
        # The control: the hook.argocd comment as it was passes none of this.
        before = ("PostSync runs after every Sync-phase resource is Healthy. The gate probes whatever "
                  "target.baseUrl routes to then, and a pod being replaced can still answer: aim it at a "
                  "Service of the new pods only (README, \"hook.mode helm: what the gate probes\").")
        self.assertNotRegex(before, r"(?:hash(?:ed)? (?:of|from) the (?:rendered )?pod (?:template|spec))")

    def test_the_changelog_no_longer_says_the_argo_cd_docs_were_measured(self) -> None:
        text = " ".join((ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split())
        self.assertNotIn("the Argo CD and Kustomize docs now give the invocation measured correct", text)
        self.assertIn("now give the invocation measured correct with the Helm CLI", text)

    def test_the_argo_section_reports_what_the_e2e_measured(self) -> None:
        text = (CHART / "README.md").read_text(encoding="utf-8")
        section = text[text.index(ARGO_SECTION_TITLE):text.index("\n## ", text.index(ARGO_SECTION_TITLE))]
        self.assertNotIn("MEASURE", section)
        self.assertIn("e2e's `argocd` scenario", section)
        script = E2E_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('scenario_argocd_rolling "$prefix"', script)
        for row in ('record "argocd: .Release.Revision label on the replaced / the new pod" "1 / 1"',
                    'record "argocd: demo-this-revision lists the replaced pod after the sync" "yes"',
                    'record "argocd: demo-this-pod-template lists the replaced pod after the sync" "no"',
                    'record "argocd: pod-template label: gate requests the replaced pod answered" "0"',
                    'record "argocd: pod-template label: vulnerable sync: gate exit" "1"',
                    'record "argocd: pod-template label: vulnerable sync: sync" "Failed"',
                    'record "argocd: Recreate app, fixed -> vulnerable: gate exit" "1"',
                    'record "argocd: Recreate app, fixed -> vulnerable: sync" "Failed"'):
            with self.subTest(row=row):
                self.assertIn(row, script)
        # The e2e's pod-template label is the README's: a sha256 of the
        # rendered pod template, cut to 16 characters.
        self.assertIn("sha256sum | trunc 16 | quote", script)
        self.assertIn("sha256sum | trunc 16 | quote", section)


#: What a reader of the repository follows: the READMEs, the changelog, the
#: docs, the shipped manifests and chart, and the CI templates.
DOC_READERS = ("README.md", "CHANGELOG.md", "docs", "deploy", "ci", "action.yml", "templates")

#: Wording that says a failed gate fails the Argo CD sync.
#: Wording that says a failed gate fails the Argo CD sync, or that the
#: operation's phase is what to alert on.
SYNC_CLAIM = re.compile(r"(?i)fails? (?:the|that|this|that sync's) (?:Argo CD )?(?:sync|operation)"
                        r"|sync(?: operation)? fails|fail(?:s|ed)? the (?:Argo CD )?sync"
                        r"|failing the sync|the sync operation fails"
                        r"|alert on `?(?:status\.operationState\.phase|the operation)")

#: Wording that says whose Job the sync is read from.
PER_SYNC_JOB = re.compile(r"(?i)generateName|Job of its own|own (?:gate )?Job|each sync's (?:gate )?Job")


def flat_documents(root: Path) -> dict[str, str]:
    """Every readable text file under DOC_READERS, comment markers dropped and
    whitespace collapsed, by its path relative to root."""
    found = {}
    for name in DOC_READERS:
        top = root / name
        if not top.exists():
            continue
        for path in [top] if top.is_file() else sorted(p for p in top.rglob("*") if p.is_file()):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            found[path.relative_to(root).as_posix()] = " ".join(re.sub(r"(?m)^\s*#", "", text).split())
    return found


def bare_sync_claims(root: Path, window: int = 400) -> tuple[int, list[tuple[str, str]]]:
    """(claims seen, the claims with no per-sync pointer within `window`
    characters either side)."""
    seen, bare = 0, []
    for name, text in flat_documents(root).items():
        for match in SYNC_CLAIM.finditer(text):
            seen += 1
            if not PER_SYNC_JOB.search(text[max(0, match.start() - window):match.end() + window]):
                bare.append((name, text[max(0, match.start() - 60):match.end() + 40]))
    return seen, bare


class ArgoCdSyncClaimTest(unittest.TestCase):
    """REGRESSION: the docs caveated "a failed gate fails
    the sync" in three files and left it bare in NOTES, Chart.yaml, the main
    README, the _helpers.tpl refusal, the Kustomize overlay and the Argo CD
    guide itself, while Argo CD v3.5.3 reported syncs from the previous
    sync's Job. The claim is now true because each sync has a Job of its own,
    and every file that makes it, anywhere a reader looks, must say so next
    to it."""

    def test_every_claim_that_a_failed_gate_fails_the_sync_says_whose_job(self) -> None:
        seen, bare = bare_sync_claims(ROOT)
        self.assertEqual(bare, [])
        self.assertGreaterEqual(seen, 7, "the scan no longer sees the claims; re-point it")

    def test_control_a_bare_claim_is_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deploy").mkdir()
            (root / "deploy" / "NOTES.txt").write_text("When the Job fails, a failed Job fails the sync operation.\n",
                                                      encoding="utf-8")
            (root / "deploy" / "app.yaml").write_text("# A PostSync hook cannot undo it. Alert on\n"
                                                      "# the operation phase.\n", encoding="utf-8")
            (root / "README.md").write_text("A vulnerable target fails the sync, each sync from its own Job.\n",
                                            encoding="utf-8")
            seen, bare = bare_sync_claims(root)
        self.assertEqual(seen, 3)
        self.assertEqual([name for name, _ in bare], ["deploy/NOTES.txt", "deploy/app.yaml"])

    def test_no_doc_reads_the_argo_cd_gate_job_by_a_fixed_name(self) -> None:
        """REGRESSION: the guide said `kubectl -n shop logs
        job/invoices-api-gate-veridor-gate`, a name no argocd-mode Job has."""
        for name, text in flat_documents(ROOT).items():
            with self.subTest(document=name):
                self.assertNotRegex(text, r"invoices-api-gate-veridor-gate(?![-\w<])")
                self.assertNotRegex(text, r"<(?:helm\.)?releaseName>-veridor-gate(?![-\w])")
        guide = (ROOT / "deploy" / "argocd" / "README.md").read_text(encoding="utf-8")
        self.assertIn("\n## Each sync reads its own Job\n", guide)
        self.assertIn('.status.operationState.syncResult.resources[?(@.hookType=="PostSync")].name', guide)
        self.assertIn('kubectl -n shop logs "job/$job"', guide)
        # The control: the guide as it was.
        self.assertRegex("kubectl -n shop logs job/invoices-api-gate-veridor-gate ```",
                         r"invoices-api-gate-veridor-gate(?![-\w<])")

    def test_no_doc_says_the_job_stays_until_the_next_sync(self) -> None:
        """REGRESSION: BeforeHookCreation was said to keep the last Job "until
        the next sync". Each sync's Job has a name of its own now, so the next
        sync deletes nothing (measured: one Job per sync until the TTL)."""
        found = [name for name, text in flat_documents(ROOT).items()
                 if re.search(r"until the next sync", text) and name != "CHANGELOG.md"]
        self.assertEqual(found, [])
        self.assertIn("\"until the next sync\"", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
                      "the changelog's quote of the old wording is what the exception is for")

    def test_the_pod_template_runs_are_not_overclaimed(self) -> None:
        """REGRESSION: three places said the gate failed on the
        vulnerable version in 5 of 5 runs of the pod-template recipe; in the
        fifth the gate had not finished when it was read ("gate exit none").
        4 of 4 was measured."""
        chart = " ".join((CHART / "README.md").read_text(encoding="utf-8").split())
        guide = " ".join((ROOT / "deploy" / "argocd" / "README.md").read_text(encoding="utf-8").split())
        changelog = " ".join((ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split())
        self.assertNotIn("| failed, 5 of 5 (exit 1 in the 4 runs whose exit code was read) |", chart)
        self.assertNotIn("the gate failed each time", changelog)
        self.assertNotIn("5 runs: the replaced pod was not listed, answered 0 of 20 gate requests, and the gate "
                         "failed on the vulnerable version", guide)
        self.assertIn("and the gate failed in the 4 whose exit code was read", changelog)

    def test_the_e2e_releases_hook_finalizers_before_deleting_its_namespaces(self) -> None:
        body = E2E_SCRIPT.read_text(encoding="utf-8")
        cleanup = body[body.index("delete_own_objects() {"):body.index("\n}\n", body.index("delete_own_objects() {"))]
        self.assertIn('"path": "/metadata/finalizers"', cleanup)
        self.assertLess(cleanup.index("delete application"), cleanup.index("/metadata/finalizers"))
        self.assertLess(cleanup.index("/metadata/finalizers"), cleanup.index('k delete namespace "$ns"'))


#: Wording that says every sync runs the gate, or has a gate Job.
EVERY_SYNC_GATES = re.compile(r"(?i)every sync(?: of the app)? runs|each sync runs|one per sync"
                              r"|a Job of its own (?:per|each) sync|gives each sync a Job"
                              r"|(?:runs|run) after every sync(?![-\w])")

#: Wording that names the syncs Argo CD runs no hook for.
UNGATED_SYNC = re.compile(r"(?i)selective|apply only|--strategy apply|runs? no hooks?|that (?:runs?|ran) hooks")


def bare_every_sync_claims(root: Path, window: int = 600) -> tuple[int, list[tuple[str, str]]]:
    """(claims seen, the claims with no ungated-sync pointer within `window`
    characters either side)."""
    seen, bare = 0, []
    for name, text in flat_documents(root).items():
        for match in EVERY_SYNC_GATES.finditer(text):
            seen += 1
            if not UNGATED_SYNC.search(text[max(0, match.start() - window):match.end() + window]):
                bare.append((name, text[max(0, match.start() - 60):match.end() + 40]))
    return seen, bare


class UngatedSyncClaimTest(unittest.TestCase):
    """REGRESSION (CL-2): the Argo CD guide, the chart README, NOTES,
    values.yaml and the chart's own messages said every sync runs the gate
    with a Job of its own, and told readers to alert on a Failed operation.
    Argo CD v3.5.3 runs no hook for a sync that names resources or uses the
    apply strategy (controller/sync.go passes skipHooks for either): such an
    operation ends Succeeded with no PostSync entry and no gate Job, whatever
    it applied (measured live on kind-veridor-demo). Every claim that each
    sync runs the gate must name those syncs next to it."""

    def test_every_claim_that_each_sync_runs_the_gate_names_the_syncs_that_do_not(self) -> None:
        seen, bare = bare_every_sync_claims(ROOT)
        self.assertEqual(bare, [])
        self.assertGreaterEqual(seen, 5, "the scan no longer sees the claims; re-point it")

    def test_control_a_bare_claim_is_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deploy").mkdir()
            (root / "deploy" / "README.md").write_text(
                "chart with `hook.mode: argocd`. Every sync of the app runs `veridor run` once the "
                "sync's resources are Healthy.\n", encoding="utf-8")
            (root / "deploy" / "NOTES.txt").write_text(
                "Argo CD creates one per sync. A selective sync or an Apply Only sync runs no hooks.\n",
                encoding="utf-8")
            (root / "README.md").write_text("PostSync runs after every Sync-phase resource is Healthy.\n",
                                            encoding="utf-8")
            seen, bare = bare_every_sync_claims(root)
        self.assertEqual(seen, 2)
        self.assertEqual([name for name, _ in bare], ["deploy/README.md"])

    def test_the_argo_cd_guide_says_what_an_ungated_sync_reports(self) -> None:
        text = (ROOT / "deploy" / "argocd" / "README.md").read_text(encoding="utf-8")
        self.assertIn("\n## Syncs that run no gate\n", text)
        section = " ".join(text[text.index("## Syncs that run no gate"):].split("\n## ")[0].split())
        for needle in ("`argocd app sync <app> --resource", "--strategy apply`", "*Apply Only*",
                       "self-heal", "`successfully synced (all tasks run)`",
                       "no `PostSync` entry in `status.operationState.syncResult.resources`",
                       "treat a `Succeeded` operation with no `PostSync` entry as ungated"):
            with self.subTest(needle=needle):
                self.assertIn(needle, section)
        reading = text[text.index("## Reading the result"):]
        self.assertIn("empty after the operation has finished: this sync ran no gate", reading)
        # What the guide says is what the e2e measures.
        body = shell_function("scenario_argocd")
        for row in ('record "argocd: ${ungated} sync, vulnerable version: phase, PostSync entry, new gate Job"',
                    '"Succeeded, no-PostSync-hook, none"'):
            with self.subTest(row=row):
                self.assertIn(row, body)
        self.assertIn('"resources":[{"group":"apps","kind":"Deployment","name":"demo"}]', body)
        self.assertIn('"syncStrategy":{"apply":{}}', body)
        # "none" is read only from a listing that saw the earlier Jobs.
        self.assertIn('if [[ -z "${jobs_before// /}" ]]; then echo "cannot see"', body)


class CompleteJobClaimTest(unittest.TestCase):
    """REGRESSION: the chart README said a Complete Job meant "the target
    matched the declared expectations for the requests that were sent". Exit
    0 means nothing the selected gate selects was present; the same README
    measured a vulnerable target exiting 0 under gate.failOn none."""

    def test_the_readme_says_what_exit_0_means(self) -> None:
        text = " ".join((CHART / "README.md").read_text(encoding="utf-8").split())
        self.assertNotIn("matched the declared expectations", text)
        self.assertIn("A Complete Job means Veridor exited 0: nothing the selected gate "
                      "(`gate.failOn`, `gate.requireComplete`, `gate.requireCleanTeardown`) "
                      "selects was present.", text)


class ApplicationExampleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = load_yaml(APPLICATION_EXAMPLE)
        self.gate = next(s for s in self.app["spec"]["sources"] if s.get("chart") == "veridor-gate")
        self.values = self.gate["helm"]["valuesObject"]

    def test_the_gate_is_a_post_sync_hook(self) -> None:
        self.assertEqual(self.app["kind"], "Application")
        self.assertEqual(self.values["hook"]["mode"], "argocd")
        self.assertEqual(self.values["hook"]["argocd"]["phase"], "PostSync")
        # BeforeHookCreation deletes nothing with a Job named per sync; the
        # example no longer sets it as if it did.
        self.assertNotIn("deletePolicy", self.values["hook"]["argocd"])

    def test_no_sync_retry(self) -> None:
        """A retried sync re-runs the gate until the luckiest attempt passes."""
        self.assertNotIn("retry", self.app["spec"].get("syncPolicy") or {})

    def test_credentials_are_references(self) -> None:
        provided = {entry["name"] for entry in self.values["secretEnv"]}
        referenced = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", json.dumps(self.values["config"])))
        self.assertTrue(referenced)
        self.assertEqual(referenced, provided)


#: Lines of scripts/e2e_kubernetes.sh that name kubectl or helm followed by
#: an argument and reach no cluster: the tool and scenario lists, the helm
#: scenario's table text, the kubeconfig read that finds the context, and
#: local chart packaging. Matched whole; each must still be in the script.
CONTEXT_FREE_LINES = (
    "for tool in kubectl helm kind docker python3; do",
    'E2E_SCENARIOS="${E2E_SCENARIOS:-plain helm argocd rollouts psa kustomize wait}"',
    "plain | helm | argocd | rollouts | psa | kustomize | wait) ;;",
    '*) refuse "E2E_SCENARIOS names \'${scenario}\'; choose from: plain helm argocd rollouts psa kustomize wait." ;;',
    'elif ! kubectl config get-contexts -o name | grep -qx "$KUBE_CONTEXT"; then',
    'helm package "$CHART_DIR" --version "$CHART_VERSION" -d "${WORK}/repo" >/dev/null',
    'helm package "${WORK}/charts/vg-e2e-demo-target" --version "$CHART_VERSION" -d "${WORK}/repo" >/dev/null',
    'helm repo index "${WORK}/repo" --url "$REPO_URL"',
    'gate_values "${WORK}/helm-${leg}.json" helm \\',
    'gate_values "${WORK}/shop-gate.json" helm "http://${service}.${NS_HELM}.svc.cluster.local:${DEMO_PORT}" "$vulnerable"',
    'record "helm: install vs vulnerable target" "helm exit!=0, failed, gate exit 1" \\',
    'record "helm: install vs fixed target" "helm exit=0, deployed, gate exit 0" \\',
    '"helm exit$([[ $rc -ne 0 ]] && echo \'!=0\' || echo \'=0\'), ${release_status}, gate exit ${code}"',
)

#: The word kubectl or helm, as a word (not part of a name such as vg-e2e-helm
#: or a path segment such as deploy/helm/), followed -- after any closing
#: quote, parenthesis or brace -- by an argument that is not --context or
#: --kube-context. Anywhere on the line, not only in command position: the
#: shell has too many command positions (if, !, VAR=x, xargs, timeout, ...)
#: to list, and missing one is how a context-less call passed this test.
_BARE_CLUSTER_CALL = re.compile(r"(?<![\w.-])(kubectl|helm)[\"')}]*\s+(?!--(kube-)?context\b)\S")


def bare_cluster_calls(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every non-comment line of a shell script that
    names kubectl or helm without the context, outside CONTEXT_FREE_LINES."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped in CONTEXT_FREE_LINES:
            continue
        if _BARE_CLUSTER_CALL.search(stripped):
            found.append((number, stripped))
    return found


class E2EScriptStaticTest(unittest.TestCase):
    TEXT = E2E_SCRIPT.read_text(encoding="utf-8")

    def test_strict_mode_and_pins(self) -> None:
        self.assertTrue(self.TEXT.startswith("#!/usr/bin/env bash\n"))
        self.assertRegex(self.TEXT, r"\nset -E?euo pipefail\n")
        self.assertRegex(self.TEXT, r'ARGOCD_VERSION="v3\.5\.3"')
        self.assertRegex(self.TEXT, r'ROLLOUTS_VERSION="v1\.10\.0"')
        self.assertRegex(self.TEXT, r'ARGOCD_SHA256="[0-9a-f]{64}"')
        self.assertRegex(self.TEXT, r'ROLLOUTS_SHA256="[0-9a-f]{64}"')

    def test_it_never_uses_the_current_context(self) -> None:
        """Every kubectl and helm call goes through the wrappers that pin
        --context / --kube-context; a bare call would act on whatever cluster
        the user last switched to."""
        self.assertEqual(bare_cluster_calls(self.TEXT), [])
        lines = {line.strip() for line in self.TEXT.splitlines()}
        for allowed in CONTEXT_FREE_LINES:
            with self.subTest(allowed=allowed):
                self.assertIn(allowed, lines, "an allowed line is gone; remove it from CONTEXT_FREE_LINES")
        self.assertNotIn("use-context", self.TEXT)
        self.assertNotIn("current-context", self.TEXT.replace("current context", ""))

    def test_the_scan_sees_every_shell_form(self) -> None:
        """Controls, one per shell form. REGRESSION: the scan looked for a
        call at the start of a line or after ; & | ( only, so `if kubectl`,
        `! kubectl`, `X=1 kubectl`, `xargs kubectl` and `timeout 5 kubectl`
        passed it, and so did the whole suite (measured: a context-less
        `if kubectl delete namespace ...` in the cleanup stayed green)."""
        lines = self.TEXT.splitlines()
        anchor = lines.index('h() { "${HELM[@]}" "$@"; }') + 1
        forms = (
            "kubectl delete namespace vg-e2e-plain",
            "if kubectl get crd rollouts.argoproj.io >/dev/null; then :; fi",
            "elif kubectl get ns x; then :",
            "while kubectl get ns x; do sleep 1; done",
            "until helm status r; do sleep 1; done",
            "! kubectl get ns x",
            "KUBECONFIG_X=1 kubectl delete namespace vg-e2e-plain",
            "echo vg-e2e-plain | xargs kubectl delete namespace",
            "timeout 5 kubectl get ns",
            "time kubectl get ns",
            "command kubectl get ns",
            "exec helm upgrade --install r c",
            "retry 3 kubectl apply -f x.yaml",
            'x="$(kubectl get ns)"',
            "x=`kubectl get ns`",
            "true && helm upgrade --install r c",
            "false || kubectl delete ns x",
            "{ kubectl get ns; }",
            "( helm list )",
            "then kubectl get ns",
            "do helm list",
            "/usr/local/bin/kubectl get ns",
            '"kubectl" get ns',
            '"$(command -v kubectl)" get ns',
            "kubectl -n vg-e2e-plain get pods",
            "helm --namespace vg-e2e-helm list",
        )
        for form in forms:
            with self.subTest(form=form):
                mutated = "\n".join([*lines[:anchor], "  " + form, *lines[anchor:]])
                self.assertEqual([line for _, line in bare_cluster_calls(mutated)], [form])
        # And a call that carries its context is not flagged.
        mutated = "\n".join([*lines[:anchor], '  kubectl --context "$KUBE_CONTEXT" get ns', *lines[anchor:]])
        self.assertEqual(bare_cluster_calls(mutated), [])


# ---------------------------------------------------------------------------
# Slow tier: `helm template` / `helm lint`, and the e2e script's refusals.
# ---------------------------------------------------------------------------

#: The demo configuration with every credential a ${NAME} reference.
DEMO_CONFIG: dict[str, Any] = {
    "version": 1,
    "target": {"base_url": "http://127.0.0.1:8765", "timeout_seconds": 3},
    "identities": {
        "invoice_owner": {
            "headers": {"Authorization": "Bearer ${VERIDOR_OWNER_TOKEN}"},
            "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
        },
        "other_tenant": {
            "headers": {"Authorization": "Bearer ${VERIDOR_OUTSIDER_TOKEN}"},
            "marker": "vdr-Bq3Wm8Ke5Tz1Yx7Rn2Hd4Vs6",
            "marker_probe": {"method": "GET", "path": "/api/invoices/inv-200"},
        },
        "anonymous": {"headers": {}},
    },
    "checks": [
        {
            "id": "invoice-tenant-isolation",
            "request": {"method": "GET", "path": "/api/invoices/inv-100"},
            "expect": {
                "invoice_owner": {"status": [200], "contains_marker": "invoice_owner"},
                "other_tenant": {"status": [404], "excludes_marker": "invoice_owner"},
                "anonymous": {"status": [401]},
            },
        }
    ],
}

SECRET_ENV = [
    {"name": "VERIDOR_OWNER_TOKEN", "secretName": "gate-credentials", "key": "owner"},
    {"name": "VERIDOR_OUTSIDER_TOKEN", "secretName": "gate-credentials", "key": "outsider"},
]


def base_values(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "hook": {"mode": "argocd"},
        "target": {"baseUrl": "http://invoices-api.shop.svc.cluster.local:8080"},
        "secretEnv": json.loads(json.dumps(SECRET_ENV)),
        "config": json.loads(json.dumps(DEMO_CONFIG)),
    }
    values.update(overrides)
    return values


def without_cluster(values: dict[str, Any]) -> dict[str, Any]:
    """``values`` as the Helm CLI renders hook.mode helm with no cluster.

    A helm-mode render that reaches no cluster is refused unless
    hook.helm.allowRenderWithoutCluster is true: Argo CD renders that way
    (HookModeTest.test_helm_mode_is_refused_on_a_render_that_reaches_no_cluster).
    These tests render helm mode with `helm template` or a client-side dry
    run on the Helm CLI's behalf, so they open it -- unless the values name
    it themselves, which is how the refusal's own tests keep it closed.
    """
    hook = values.get("hook")
    if not isinstance(hook, dict) or hook.get("mode") != "helm":
        return values
    if "allowRenderWithoutCluster" in (hook.get("helm") or {}):
        return values
    opened = json.loads(json.dumps(values))
    opened["hook"]["helm"] = {**(opened["hook"].get("helm") or {}), "allowRenderWithoutCluster": True}
    return opened


def assert_restricted(case: unittest.TestCase, pod: dict[str, Any], container: dict[str, Any]) -> None:
    """The Pod Security "restricted" fields, plus the ones this gate adds."""
    pod_ctx = pod["securityContext"]
    case.assertIs(pod_ctx["runAsNonRoot"], True)
    case.assertEqual(pod_ctx["runAsUser"], 10001)
    case.assertEqual(pod_ctx["runAsGroup"], 10001)
    case.assertEqual(pod_ctx["seccompProfile"], {"type": "RuntimeDefault"})
    case.assertIs(pod["automountServiceAccountToken"], False)
    ctx = container["securityContext"]
    case.assertIs(ctx["allowPrivilegeEscalation"], False)
    case.assertIs(ctx["readOnlyRootFilesystem"], True)
    case.assertIs(ctx["runAsNonRoot"], True)
    case.assertEqual(ctx["runAsUser"], 10001)
    case.assertEqual(ctx["runAsGroup"], 10001)
    case.assertEqual(ctx["capabilities"], {"drop": ["ALL"]})
    case.assertEqual(ctx["seccompProfile"], {"type": "RuntimeDefault"})
    for volume in pod["volumes"]:
        case.assertTrue(
            {"configMap", "emptyDir", "persistentVolumeClaim", "secret"} & set(volume),
            f"volume type outside the restricted profile: {volume}",
        )
    mounts = {mount["mountPath"]: mount for mount in container["volumeMounts"]}
    case.assertEqual(set(mounts), {"/config", "/work", "/tmp"})
    case.assertIs(mounts["/config"]["readOnly"], True)


@functools.lru_cache(maxsize=1)
def owned_flags() -> dict[str, str]:
    """The flags the chart refuses in extraArgs (veridor-gate.refuseOwnedArgs),
    read from _helpers.tpl: flag -> the value to set instead."""
    helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
    found = re.findall(r'\{\{- \$owned := dict ((?:"[^"]*" ?)+)-\}\}', helpers)
    if len(found) != 1:
        raise AssertionError(f"$owned is defined {len(found)} times in _helpers.tpl, expected 1")
    words = re.findall(r'"([^"]*)"', found[0])
    return dict(zip(words[::2], words[1::2]))


@functools.lru_cache(maxsize=1)
def run_options() -> tuple[str, ...]:
    from veridor import cli  # noqa: PLC0415

    subparsers = next(a for a in cli._parser()._actions if isinstance(a, argparse._SubParsersAction))
    return tuple(o for action in subparsers.choices["run"]._actions for o in action.option_strings)


def argparse_reads(spelling: str) -> str | None:
    """The `veridor run` option argparse reads ``spelling`` (before any "=")
    as: an exact option, else the one option it is a prefix of; None when it
    is ambiguous or matches nothing (argparse then exits 2)."""
    options = run_options()
    if spelling in options:
        return spelling
    matches = [o for o in options if o.startswith(spelling)] if spelling.startswith("--") else []
    return matches[0] if len(matches) == 1 else None


def chart_refuses(argument: str) -> bool:
    """veridor-gate.refuseOwnedArgs, modelled: the rule the slow test below
    holds the template to on a sample of spellings."""
    flag = argument.split("=", 1)[0]
    if re.match(r"^-[^-]", flag) and "h" in flag:
        return True
    return bool(re.match(r"^--[^-=]", flag)) and any(name.startswith(flag) for name in owned_flags())


class ExtraArgsRuleTest(unittest.TestCase):
    """REGRESSION: extraArgs is rendered after the chart's own arguments, and
    `--base-url` there (or `--base-u`, an abbreviation argparse accepts)
    replaced target.baseUrl without its credential check: the Job carried a
    literal ;token= and Veridor probed that URL (measured). The chart now
    refuses every spelling of a flag it owns. These fast tests hold the rule
    to the real parser; ExtraArgsRenderTest holds the template to the rule."""

    def test_the_owned_flags_are_the_flags_the_chart_passes(self) -> None:
        helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        args = helpers[helpers.index('{{- define "veridor-gate.args" -}}'):]
        passed = set(re.findall(r"^- (--[a-z-]+)$", args, re.M))
        self.assertEqual(set(owned_flags()) - {"--help"}, passed)
        self.assertLessEqual(set(owned_flags()), set(run_options()))

    def test_every_spelling_that_reaches_an_owned_flag_is_refused(self) -> None:
        owned = set(owned_flags())
        checked = 0
        for option in run_options():
            for length in range(3, len(option) + 1):
                for form in (option[:length], option[:length] + "=x"):
                    reads = argparse_reads(form.split("=", 1)[0])
                    with self.subTest(argument=form, reads=reads):
                        if reads in owned:
                            self.assertTrue(chart_refuses(form))
                            checked += 1
                        elif reads is not None:
                            self.assertFalse(chart_refuses(form), "a flag the chart does not own is refused")
        self.assertGreater(checked, 100)
        self.assertTrue(chart_refuses("-h"))

    def test_every_single_dash_token_the_parser_reads_as_help_is_refused(self) -> None:
        """REGRESSION: only an exact `-h` was refused. argparse reads a
        single-dash cluster that starts with -h as -h (measured: `veridor run
        --config c.json -hx` exits 0 having run nothing, and so do -hq, -hv,
        -h1 and -hh), so extraArgs ["-hx"] rendered a Job that completed as a
        pass. Every token below is fed to the real `run` parser; each one it
        answers with its usage and exit 0 must be refused by the rule."""
        from veridor import cli  # noqa: PLC0415

        parser = cli._parser()
        letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789="
        tokens = ["-h", "-h=x", *("-h" + c for c in letters), *("-" + c + "h" for c in letters),
                  *("-" + c for c in letters)]
        helped = []
        for token in tokens:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    parser.parse_args(["run", "--config", "c.json", token])
                    status = None
                except SystemExit as stop:
                    status = stop.code
            if status == 0:
                helped.append(token)
                with self.subTest(token=token):
                    self.assertTrue(chart_refuses(token))
        # The premise: the parser really does read these as --help.
        self.assertLessEqual({"-h", "-hx", "-hq", "-hh", "-h1"}, set(helped))
        self.assertFalse(chart_refuses("-x"), "a single-dash token without h is Veridor's own exit 2")

    def test_argparse_really_reads_an_abbreviation_and_keeps_the_last_value(self) -> None:
        """Why the rule exists, and the control for the model above."""
        from veridor import cli  # noqa: PLC0415

        parsed = cli._parser().parse_args(["run", "--config", "c.json", "--base-url", "http://a/first",
                                           "--base-u", "http://a/second"])
        self.assertEqual(parsed.base_url, "http://a/second")
        self.assertEqual(argparse_reads("--base-u"), "--base-url")
        self.assertIsNone(argparse_reads("--base"))
        self.assertEqual(argparse_reads("--basel"), "--baseline")


class _HelmCase(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("helm") is None:
            if os.environ.get(REQUIRE_HELM_ENV) == "1":
                self.fail(f"helm is not on PATH and {REQUIRE_HELM_ENV}=1 says these tests must run")
            self.skipTest(f"helm is not on PATH (set {REQUIRE_HELM_ENV}=1 to make this a failure)")
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-helm-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def helm(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["helm", *args], capture_output=True, text=True, timeout=60, check=False)

    def template(self, values: dict[str, Any], *extra: str) -> subprocess.CompletedProcess[str]:
        path = self.tmp / f"values-{len(list(self.tmp.iterdir()))}.json"
        path.write_text(json.dumps(without_cluster(values)), encoding="utf-8")
        return self.helm("template", "gate", str(CHART), "--namespace", "shop", "-f", str(path), *extra)

    def render(self, values: dict[str, Any]) -> dict[str, dict[str, Any]]:
        result = self.template(values)
        self.assertEqual(result.returncode, 0, result.stderr)
        documents = load_yaml_documents(result.stdout)
        return {document["kind"]: document for document in documents}

    def refused(self, values: dict[str, Any]) -> str:
        result = self.template(values)
        self.assertNotEqual(result.returncode, 0, "the render was expected to be refused")
        self.assertIn("veridor-gate:", result.stderr)
        return result.stderr

    def job_parts(self, values: dict[str, Any]) -> tuple[dict, dict, dict]:
        job = self.render(values)["Job"]
        pod = job["spec"]["template"]["spec"]
        return job, pod, pod["containers"][0]


@slow("spawns helm")
class HelmLintTest(_HelmCase):
    def test_lint_passes_with_the_ci_values(self) -> None:
        result = self.helm("lint", str(CHART), "-f", str(CHART / "ci" / "argocd-values.yaml"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 chart(s) failed", result.stdout)

    def test_lint_can_fail(self) -> None:
        """The control for the test above: a template that does not parse
        fails lint, so a passing lint is a result rather than a no-op."""
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        job = broken / "templates" / "job.yaml"
        job.write_text(job.read_text(encoding="utf-8") + "\n{{ .Values.hook.mode\n", encoding="utf-8")
        result = self.helm("lint", str(broken), "-f", str(CHART / "ci" / "argocd-values.yaml"))
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_the_render_refusals_are_enforced_by_template_not_lint(self) -> None:
        """Measured with helm 4.2: lint runs templates in lint mode, where
        `fail` only logs, so lint passes a chart whose render is refused. The
        refusals are therefore gated with `helm template`, which fails. CI must
        render with `helm template`, not rely on `helm lint`, to catch them."""
        result = self.helm("template", "gate", str(CHART))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("hook.mode", result.stderr)


@slow("spawns helm")
class ReadmeRecipeRenderTest(_HelmCase):
    """The chart README's two recipes for aiming the gate at the new pods,
    extracted from the README and rendered as a chart: the snippets are
    complete (the Service's `targetPort: http` names a container port the
    Deployment declares; the first version showed only the pod labels), the
    Service selects exactly the pod template's label, and what `helm
    template` -- Argo CD's renderer -- makes of each label."""

    def chart(self, marker: str) -> Path:
        chart = self.tmp / marker.strip("{}. ").replace(" ", "-").replace('"', "")
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: shop\nversion: 0.1.0\n", encoding="utf-8")
        (chart / "values.yaml").write_text("image: registry.example/invoices-api:1.0.0\n", encoding="utf-8")
        for name, body in readme_recipe(marker).items():
            (chart / "templates" / name).write_text(body, encoding="utf-8")
        return chart

    def rendered(self, chart: Path, *args: str) -> tuple[dict[str, Any], dict[str, Any]]:
        result = self.helm("template", "shop", str(chart), "--namespace", "shop", *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        documents = {d["kind"]: d for d in load_yaml_documents(result.stdout)}
        return documents["Deployment"], documents["Service"]

    def assert_complete(self, deployment: dict[str, Any], service: dict[str, Any]) -> str:
        pod = deployment["spec"]["template"]
        labels = pod["metadata"]["labels"]
        for key, value in service["spec"]["selector"].items():
            self.assertEqual(labels.get(key), value, key)
        self.assertEqual(deployment["spec"]["selector"]["matchLabels"], {"app": "invoices-api"})
        ports = {port["name"] for c in pod["spec"]["containers"] for port in c.get("ports", []) if "name" in port}
        self.assertIn(service["spec"]["ports"][0]["targetPort"], ports)
        return next(value for key, value in labels.items() if key.startswith("example.com/"))

    def test_the_revision_recipe_is_always_1_under_helm_template(self) -> None:
        chart = self.chart("{{ .Release.Revision | quote }}")
        for args in ((), ("--is-upgrade",), ("--set", "image=registry.example/invoices-api:2.0.0")):
            with self.subTest(args=args):
                self.assertEqual(self.assert_complete(*self.rendered(chart, *args)), "1")

    def test_the_pod_template_recipe_changes_with_the_pod_template_only(self) -> None:
        chart = self.chart('{{ include "invoices-api.version" . }}')
        one = self.assert_complete(*self.rendered(chart))
        again = self.assert_complete(*self.rendered(chart, "--is-upgrade"))
        two = self.assert_complete(*self.rendered(chart, "--set", "image=registry.example/invoices-api:2.0.0"))
        self.assertRegex(one, r"^[0-9a-f]{16}$")
        self.assertEqual(one, again, "the same pod template must keep its label")
        self.assertNotEqual(one, two, "a new pod template must get a new label")


@slow("spawns helm")
class HookModeTest(_HelmCase):
    ARGO = ("argocd.argoproj.io/hook", "argocd.argoproj.io/hook-delete-policy")
    HELM = ("helm.sh/hook", "helm.sh/hook-delete-policy", "helm.sh/hook-weight")

    def test_argocd_post_sync(self) -> None:
        job, _, _ = self.job_parts(base_values())
        annotations = job["metadata"]["annotations"]
        self.assertEqual(annotations["argocd.argoproj.io/hook"], "PostSync")
        self.assertEqual(annotations["argocd.argoproj.io/hook-delete-policy"], "BeforeHookCreation")
        self.assertFalse(set(self.HELM) & set(annotations))

    def test_argocd_names_each_sync_s_job_itself(self) -> None:
        """REGRESSION: the argocd-mode Job had one fixed name, and with
        BeforeHookCreation Argo CD v3.5.3 reported syncs from the previous
        sync's Job, in both directions (measured on kind with this chart: 4 of
        16 passing syncs reported Failed; the e2e saw vulnerable syncs reported
        Succeeded with the gate at exit 1). With generateName Argo CD names
        each sync's Job <prefix><revision>-postsync-<start> and every sync was
        reported from its own Job. helm and none keep their names."""
        job, _, _ = self.job_parts(base_values())
        self.assertNotIn("name", job["metadata"])
        self.assertEqual(job["metadata"]["generateName"], "gate-veridor-gate-")
        for mode, name in (("helm", "gate-veridor-gate"), ("none", "gate-veridor-gate-r1")):
            with self.subTest(mode=mode):
                job, _, _ = self.job_parts(base_values(hook={"mode": mode}))
                self.assertEqual(job["metadata"]["name"], name)
                self.assertNotIn("generateName", job["metadata"])

    def test_the_argocd_prefix_leaves_room_for_argo_cd_s_suffix(self) -> None:
        """A Job name is its pods' job-name label, at most 63 characters
        (measured: a 64-character Job name is refused by the API server), and
        Argo CD appends up to 27: 7 of the revision, "-postsync-", 10
        digits. A 52-character fullname, the chart's limit, would make every
        sync's Job invalid."""
        for release in ("gate", "a" * 40, "invoices-api-gate-for-the-shop-namespace-in-prod"):
            with self.subTest(release=release):
                result = self.helm("template", release, str(CHART), "-f", str(self._values(base_values())))
                self.assertEqual(result.returncode, 0, result.stderr)
                job = next(d for d in load_yaml_documents(result.stdout) if d["kind"] == "Job")
                prefix = job["metadata"]["generateName"]
                self.assertTrue(prefix.endswith("-") and not prefix.endswith("--"), prefix)
                self.assertLessEqual(len(prefix + "0.1.0-e" + "-postsync-" + "1790302471"), 63, prefix)
        # The control: the fullname alone can be longer than that.
        result = self.helm("template", "a" * 40, str(CHART), "-f", str(self._values(base_values(hook={"mode": "helm"}))))
        job = next(d for d in load_yaml_documents(result.stdout) if d["kind"] == "Job")
        self.assertGreater(len(job["metadata"]["name"] + "-0.1.0-e-postsync-1790302471"), 63)

    def _values(self, values: dict[str, Any]) -> Path:
        path = self.tmp / f"values-{len(list(self.tmp.iterdir()))}.json"
        path.write_text(json.dumps(without_cluster(values)), encoding="utf-8")
        return path

    def test_argocd_mode_needs_something_that_deletes_old_jobs(self) -> None:
        """Each sync's Job has a name of its own, so BeforeHookCreation never
        finds an earlier one (measured: 16 Jobs in the namespace after 16
        syncs). Without a TTL, and without both HookSucceeded and HookFailed,
        nothing would ever delete them."""
        for policy in ("BeforeHookCreation", "HookSucceeded", "HookFailed,BeforeHookCreation"):
            with self.subTest(policy=policy):
                stderr = self.refused(base_values(hook={"mode": "argocd", "argocd": {"deletePolicy": policy}},
                                                  job={"ttlSecondsAfterFinished": None}))
                self.assertIn("job.ttlSecondsAfterFinished is null with hook.mode argocd", stderr)
        # The controls: a TTL, or Argo CD deleting every Job; and other modes.
        self.render(base_values(hook={"mode": "argocd", "argocd": {"deletePolicy": "HookSucceeded,HookFailed"}},
                                job={"ttlSecondsAfterFinished": None}))
        job, _, _ = self.job_parts(base_values(job={"ttlSecondsAfterFinished": 60}))
        self.assertEqual(job["spec"]["ttlSecondsAfterFinished"], 60)
        for mode in ("helm", "none"):
            with self.subTest(mode=mode):
                self.render(base_values(hook={"mode": mode}, job={"ttlSecondsAfterFinished": None}))

    def test_the_helm_cli_refusal_is_argocd_mode_only_and_needs_a_cluster(self) -> None:
        """`helm install` of the argocd-mode chart is refused at render: the
        Helm CLI does not run Argo CD hooks, and before the refusal
        `--server-side=false` installed the unnamed Job with the release
        deployed (measured with Helm 4.2.2; the e2e's argocd scenario has
        the row). The refusal keys on lookup, which answers only when a
        cluster is reached, so Argo CD's `helm template` and a client dry run
        still render. It cannot be run without a cluster; this pins its
        condition."""
        helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        self.assertIn('{{- if and (eq $mode "argocd") (lookup "v1" "ConfigMap" .Release.Namespace "") -}}', helpers)
        self.assertIn("veridor-gate: hook.mode is argocd, and this render reached a cluster", helpers)
        self.render(base_values())
        self.assertIn("NOTES:", subprocess.run(
            ["helm", "install", "gate", str(CHART), "--dry-run=client", "-f", str(self._values(base_values()))],
            capture_output=True, text=True, timeout=60, check=False, env={**os.environ, "KUBECONFIG": os.devnull},
        ).stdout)

    def test_helm_mode_is_refused_on_a_render_that_reaches_no_cluster(self) -> None:
        """REGRESSION (K8S-LATE-1): Argo CD renders with `helm template` and
        maps `helm.sh/hook: post-install,post-upgrade` to PostSync and
        `before-hook-creation` to BeforeHookCreation (gitops-engine v3.5.3,
        pkg/sync/hook/helm), so hook.mode helm under Argo CD was a PostSync
        hook with ONE fixed name: the shape argocd mode left because Argo CD
        reported syncs from the previous sync's Job. Measured in a gate-only
        Application, target alternating: 1, 3, 4 and 6 of 20 syncs misreported
        in helm mode, none in argocd mode. The mirror of the argocd-mode
        refusal: a helm-mode render that reaches no cluster is refused unless
        the Helm CLI user opens hook.helm.allowRenderWithoutCluster."""
        # The reproduction, as run: the Argo CD example's values with helm mode
        # rendered `helm template` exit 0, a Job named
        # invoices-api-gate-veridor-gate with the post-install,post-upgrade hook.
        repro = self.helm("template", "invoices-api-gate", str(CHART), "-f", str(CHART / "ci" / "argocd-values.yaml"),
                          "--set", "hook.mode=helm")
        self.assertNotEqual(repro.returncode, 0, repro.stdout[-400:])
        self.assertIn("this render reached no cluster", repro.stderr)
        closed = base_values(hook={"mode": "helm", "helm": {"allowRenderWithoutCluster": False}})
        stderr = " ".join(self.refused(closed).split())
        self.assertIn("veridor-gate: hook.mode is helm, and this render reached no cluster", stderr)
        self.assertIn("Under Argo CD use hook.mode argocd", stderr)
        self.assertIn("hook.helm.allowRenderWithoutCluster", stderr)
        # A client-side dry run, with no kubeconfig at all, is refused too.
        dry = subprocess.run(
            ["helm", "install", "gate", str(CHART), "--dry-run=client", "-f", str(self._values(closed))],
            capture_output=True, text=True, timeout=60, check=False, env={**os.environ, "KUBECONFIG": os.devnull},
        )
        self.assertNotEqual(dry.returncode, 0, dry.stdout[-400:])
        self.assertIn("this render reached no cluster", dry.stderr)
        # The default is closed: values.yaml's false, not an absent key.
        self.assertIs(load_yaml(CHART / "values.yaml")["hook"]["helm"]["allowRenderWithoutCluster"], False)
        # Controls. Opened, helm mode renders exactly the hook it did.
        job, _, _ = self.job_parts(base_values(hook={"mode": "helm", "helm": {"allowRenderWithoutCluster": True}}))
        self.assertEqual(job["metadata"]["name"], "gate-veridor-gate")
        self.assertEqual(job["metadata"]["annotations"]["helm.sh/hook"], "post-install,post-upgrade")
        # The other modes never read it, closed or open.
        for mode in ("argocd", "none"):
            for allow in (False, True):
                with self.subTest(mode=mode, allow=allow):
                    self.render(base_values(hook={"mode": mode, "helm": {"allowRenderWithoutCluster": allow}}))

    def test_only_a_boolean_true_opens_the_render_without_a_cluster(self) -> None:
        """A string "true" is not an opt-in: the schema refuses it, and with
        the schema skipped the template reads it as closed."""
        for value in ("true", "yes", 1):
            with self.subTest(value=value):
                self.assert_refused_twice({"mode": "helm", "helm": {"allowRenderWithoutCluster": value}},
                                          "/hook/helm/allowRenderWithoutCluster",
                                          "this render reached no cluster")

    def test_the_helm_mode_refusal_keys_on_lookup_after_the_opt_in(self) -> None:
        """It cannot be run against a cluster here (the e2e's helm scenario
        installs helm mode with `helm install`, which does reach one); this
        pins its condition. The opt-in is read first, so an opened render
        never calls lookup."""
        helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        self.assertIn('{{- if and (eq $mode "helm") (not $renderWithoutCluster) '
                      '(not (lookup "v1" "ConfigMap" .Release.Namespace "")) -}}', helpers)

    def test_argocd_sync_wave(self) -> None:
        job, _, _ = self.job_parts(base_values(hook={"mode": "argocd", "argocd": {"syncWave": "5"}}))
        self.assertEqual(job["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"], "5")

    def test_helm_post_install_post_upgrade(self) -> None:
        job, _, _ = self.job_parts(base_values(hook={"mode": "helm"}))
        annotations = job["metadata"]["annotations"]
        self.assertEqual(annotations["helm.sh/hook"], "post-install,post-upgrade")
        self.assertEqual(annotations["helm.sh/hook-delete-policy"], "before-hook-creation")
        self.assertFalse(set(self.ARGO) & set(annotations))

    def test_none_is_a_plain_job_named_per_revision(self) -> None:
        job, _, _ = self.job_parts(base_values(hook={"mode": "none"}))
        annotations = job["metadata"].get("annotations") or {}
        self.assertFalse((set(self.ARGO) | set(self.HELM)) & set(annotations), annotations)
        self.assertEqual(job["metadata"]["name"], "gate-veridor-gate-r1")

    PRE_PHASES = (
        {"mode": "helm", "helm": {"events": "pre-install"}},
        {"mode": "helm", "helm": {"events": "pre-install,pre-upgrade"}},
        {"mode": "helm", "helm": {"events": "pre-upgrade"}},
        {"mode": "helm", "helm": {"events": "post-install,pre-upgrade"}},
        {"mode": "helm", "helm": {"events": "pre-rollback"}},
        {"mode": "argocd", "argocd": {"phase": "PreSync"}},
        # REGRESSION: Helm lower-cases and trims each event, Argo CD trims
        # each phase; the refusal compared the raw text, so with the schema
        # skipped these rendered (measured: post-install,PRE-UPGRADE ran as a
        # pre-upgrade hook that read the previous revision's configuration).
        {"mode": "helm", "helm": {"events": "Pre-Install"}},
        {"mode": "helm", "helm": {"events": "post-install,PRE-UPGRADE"}},
        {"mode": "helm", "helm": {"events": "post-install,post-upgrade, Pre-Rollback "}},
        {"mode": "argocd", "argocd": {"phase": " PreSync"}},
        {"mode": "argocd", "argocd": {"phase": "PreSync,PostSync"}},
    )

    def test_a_pre_phase_hook_is_refused(self) -> None:
        """REGRESSION: a pre-phase hook runs before this release's ConfigMap
        is created or updated. Measured on kind: with pre-install the Job
        never mounted its configuration (FailedMount until the deadline, and
        `helm install` failed); with pre-upgrade `helm upgrade` exited 0 and
        the hook read the PREVIOUS revision's configuration. The schema
        refuses these phases; the template refuses them too when the schema
        is skipped."""
        for hook in self.PRE_PHASES:
            with self.subTest(hook=hook):
                result = self.template(base_values(hook=hook))
                self.assertNotEqual(result.returncode, 0, result.stdout[-400:])
                self.assertIn("/hook/", result.stderr)
                result = self.template(base_values(hook=hook), "--skip-schema-validation")
                self.assertNotEqual(result.returncode, 0, result.stdout[-400:])
                self.assertIn("veridor-gate: a pre-phase hook", result.stderr)

    def test_post_phase_hooks_render(self) -> None:
        """The control: the phases that run after the ConfigMap is applied."""
        for hook in ({"mode": "helm", "helm": {"events": "post-install,post-upgrade"}},
                     {"mode": "helm", "helm": {"events": "post-install,post-upgrade,post-rollback,test"}},
                     {"mode": "helm", "helm": {"events": "test,post-upgrade,post-install"}},
                     {"mode": "argocd", "argocd": {"phase": "PostSync"}}):
            with self.subTest(hook=hook):
                self.render(base_values(hook=hook))
                result = self.template(base_values(hook=hook), "--skip-schema-validation")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_hook_values_render_as_the_tool_reads_them(self) -> None:
        """With the schema skipped, a value Helm or Argo CD reads the same way
        as the canonical one is accepted, and rendered in that canonical form,
        so what was checked is what the tool sees."""
        for hook, key, rendered in (
                ({"mode": "helm", "helm": {"events": "Post-Install, POST-UPGRADE"}}, "helm.sh/hook",
                 "post-install,post-upgrade"),
                ({"mode": "helm", "helm": {"deletePolicy": " Before-Hook-Creation ,hook-failed"}},
                 "helm.sh/hook-delete-policy", "before-hook-creation,hook-failed"),
                ({"mode": "argocd", "argocd": {"phase": " PostSync "}}, "argocd.argoproj.io/hook", "PostSync"),
                ({"mode": "argocd", "argocd": {"deletePolicy": "BeforeHookCreation, HookFailed"}},
                 "argocd.argoproj.io/hook-delete-policy", "BeforeHookCreation,HookFailed")):
            with self.subTest(hook=hook):
                result = self.template(base_values(hook=hook), "--skip-schema-validation")
                self.assertEqual(result.returncode, 0, result.stderr)
                job = next(d for d in load_yaml_documents(result.stdout) if d["kind"] == "Job")
                self.assertEqual(job["metadata"]["annotations"][key], rendered)

    def assert_refused_twice(self, hook: dict[str, Any], schema_path: str, message: str) -> None:
        """Refused by the schema, and by the template when the schema is
        skipped (helm --skip-schema-validation, Argo CD's
        spec.source.helm.skipSchemaValidation)."""
        result = self.template(base_values(hook=hook))
        self.assertNotEqual(result.returncode, 0, result.stdout[-400:])
        self.assertIn(schema_path, result.stderr)
        result = self.template(base_values(hook=hook), "--skip-schema-validation")
        self.assertNotEqual(result.returncode, 0, result.stdout[-400:])
        self.assertIn(message, result.stderr)

    def test_hook_annotations_in_job_annotations_are_refused(self) -> None:
        """REGRESSION: job.annotations are rendered after the hook annotations
        the chart checks, as duplicate keys, and Helm keeps the last one.
        Measured with helm template: `helm.sh/hook: test` there made
        --skip-tests drop the Job (install and upgrade would run no gate);
        `helm.sh/hook: pre-install` made a hook.mode none Job a pre-install
        hook past the pre-phase refusal; `argocd.argoproj.io/hook: Sync`
        rendered past the Sync refusal. Every mode refuses every such key."""
        keys = {"helm.sh/hook": "test", "helm.sh/hook-delete-policy": "hook-failed",
                "helm.sh/hook-weight": "-5", "argocd.argoproj.io/hook": "Sync",
                "argocd.argoproj.io/hook-delete-policy": "HookFailed", "argocd.argoproj.io/sync-wave": "1"}
        for mode in ("argocd", "helm", "none"):
            for key, value in keys.items():
                with self.subTest(mode=mode, key=key):
                    stderr = self.refused(base_values(hook={"mode": mode}, job={"annotations": {key: value}}))
                    self.assertIn(f"job.annotations sets {key}", stderr)
        # The premise, on a copy of the chart without the refusal: the key
        # really does override the checked annotation.
        broken = self.tmp / "veridor-gate"
        shutil.copytree(CHART, broken)
        helpers = broken / "templates" / "_helpers.tpl"
        text = helpers.read_text(encoding="utf-8")
        refusal = '{{- include "veridor-gate.refuseHookAnnotations" .Values.job.annotations -}}'
        self.assertEqual(text.count(refusal), 1, "the mutation no longer applies")
        helpers.write_text(text.replace(refusal, ""), encoding="utf-8")
        values = self.tmp / "override.json"
        values.write_text(json.dumps(without_cluster(base_values(hook={"mode": "helm"},
                                                                 job={"annotations": {"helm.sh/hook": "test"}}))),
                          encoding="utf-8")
        result = self.helm("template", "gate", str(broken), "-f", str(values), "--skip-tests")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("kind: Job", result.stdout)

    def test_lifecycle_annotations_in_job_annotations_are_refused(self) -> None:
        """REGRESSION: only the hook keys were refused, and the control below
        rendered `helm.sh/resource-policy: keep` as an ordinary annotation.
        It is not one. Measured on kind with hook.mode none: `helm uninstall`
        kept the Complete Job gate-veridor-gate-r1, the target was switched to
        vulnerable, and `helm install` with the same values adopted that Job
        (same uid, still Complete), ran no gate, and the NOTES wait exited 0.
        Without the annotation the same sequence ran a new Job, which Failed
        (exit 1). Every key under helm.sh/ and argocd.argoproj.io/ decides when
        the Job is created, kept or deleted, and the chart sets its own."""
        keys = {"helm.sh/resource-policy": "keep", "argocd.argoproj.io/sync-options": "Delete=false", "argocd.argoproj.io/compare-options": "IgnoreExtraneous",
                "argocd.argoproj.io/tracking-id": "other:batch/Job:shop/gate"}
        for mode in ("argocd", "helm", "none"):
            for key, value in keys.items():
                with self.subTest(mode=mode, key=key):
                    stderr = self.refused(base_values(hook={"mode": mode}, job={"annotations": {key: value}}))
                    self.assertIn(f"job.annotations sets {key}", stderr)
                    self.assertIn("helm.sh/ or argocd.argoproj.io/", stderr)

    def test_other_job_annotations_and_hook_keys_in_pod_annotations_render(self) -> None:
        """The control: an ordinary annotation still renders, including one
        whose domain only ends in a refused one (Argo CD's own
        link.argocd.argoproj.io/ external links, notifications), and a hook
        key on the POD template is not read by Helm or Argo CD (measured:
        with `helm.sh/hook: test` there, --skip-tests still renders the Job),
        so it is left alone."""
        annotations = {"example.com/owner": "shop", "link.argocd.argoproj.io/external-link": "https://example.test",
                       "notifications.argoproj.io/subscribe.on-sync-failed.slack": "gates"}
        job, _, _ = self.job_parts(base_values(hook={"mode": "helm"}, job={
            "annotations": annotations, "podAnnotations": {"helm.sh/hook": "test", "helm.sh/resource-policy": "keep"}}))
        for key, value in annotations.items():
            self.assertEqual(job["metadata"]["annotations"][key], value)
        self.assertEqual(job["metadata"]["annotations"]["helm.sh/hook"], "post-install,post-upgrade")

    def test_the_argocd_sync_phase_is_refused(self) -> None:
        """REGRESSION: Sync was accepted. Argo CD runs a Sync hook with the
        apply of the application's manifests, not once they are Healthy (its
        resource-hook documentation), so the gate probes whatever the Service
        still routes to, the version being replaced. Not run through Argo CD
        here: the render is what this refuses."""
        for phase in ("Sync", " Sync", "PostSync,Sync"):
            with self.subTest(phase=phase):
                self.assert_refused_twice({"mode": "argocd", "argocd": {"phase": phase}},
                                          "/hook/argocd/phase", "veridor-gate: hook.argocd.phase Sync is not supported")

    def test_an_argocd_phase_that_is_not_exactly_post_sync_is_refused(self) -> None:
        """Argo CD matches the phase case-sensitively: `postsync` is a hook it
        never runs, and SyncFail / Skip / PostDelete do not run after a sync."""
        for phase in ("postsync", "POSTSYNC", "presync", "SyncFail", "Skip", "PostDelete", "", "PostSync,PostSync"):
            with self.subTest(phase=phase):
                self.assert_refused_twice({"mode": "argocd", "argocd": {"phase": phase}},
                                          "/hook/argocd/phase", "veridor-gate: hook.argocd.phase is")

    def test_events_that_leave_install_or_upgrade_ungated_are_refused(self) -> None:
        """REGRESSION: test or post-rollback alone was accepted, and then
        `helm install` and `helm upgrade` created no Job and exited 0 with
        the release deployed while NOTES said the gate had run (measured on
        kind with a gate that always failed)."""
        for events in ("test", "post-rollback", "post-install", "post-upgrade", "post-install,test",
                       "test,post-rollback", "post-upgrade,post-rollback"):
            with self.subTest(events=events):
                self.assert_refused_twice({"mode": "helm", "helm": {"events": events}}, "/hook/helm/events",
                                          "veridor-gate: hook.helm.events is")
        for events in ("post-instal,post-upgrade", "post-install,post-upgrade,post-delete"):
            with self.subTest(events=events):
                self.assert_refused_twice({"mode": "helm", "helm": {"events": events}}, "/hook/helm/events",
                                          "veridor-gate: hook.helm.events names")

    def test_delete_policies_that_keep_an_earlier_job_are_refused(self) -> None:
        """REGRESSION: hook-failed was accepted. The Job keeps one name, so the
        Job a passing install left behind was what the next `helm upgrade`
        found: it exited 0 with the release deployed and the gate not run
        (measured on kind: the same Job uid across install and upgrade)."""
        for policy in ("hook-failed", "hook-succeeded", "hook-succeeded,hook-failed"):
            with self.subTest(policy=policy):
                self.assert_refused_twice({"mode": "helm", "helm": {"deletePolicy": policy}},
                                          "/hook/helm/deletePolicy", "which does not include before-hook-creation")
        # Argo CD matches the policy case-sensitively and does not act on an
        # unknown one.
        for policy in ("beforehookcreation", "Never", "HookSucceeded,never", ""):
            with self.subTest(policy=policy):
                self.assert_refused_twice({"mode": "argocd", "argocd": {"deletePolicy": policy}},
                                          "/hook/argocd/deletePolicy", "veridor-gate: hook.argocd.deletePolicy names")
        # An empty or unknown policy is one Helm does not act on, so it keeps
        # the Job just the same.
        for policy, named in (("before-hook-creation,never", "never"), ("", "")):
            with self.subTest(policy=policy):
                self.assert_refused_twice({"mode": "helm", "helm": {"deletePolicy": policy}},
                                          "/hook/helm/deletePolicy", f'hook.helm.deletePolicy names "{named}"')

    def test_delete_policies_that_include_before_hook_creation_render(self) -> None:
        """The control for the test above. An argocd-mode Job has a name of
        its own every sync, so no Job an earlier sync left can stand in for
        it and BeforeHookCreation is not required there: HookSucceeded or
        HookFailed alone render (measured through Argo CD with HookSucceeded:
        every sync reported from its own Job)."""
        for hook in ({"mode": "helm", "helm": {"deletePolicy": "before-hook-creation,hook-failed"}},
                     {"mode": "helm", "helm": {"deletePolicy": "hook-succeeded,before-hook-creation"}},
                     {"mode": "argocd", "argocd": {"deletePolicy": "BeforeHookCreation,HookFailed"}},
                     {"mode": "argocd", "argocd": {"deletePolicy": "HookSucceeded,BeforeHookCreation"}},
                     {"mode": "argocd", "argocd": {"deletePolicy": "HookSucceeded"}},
                     {"mode": "argocd", "argocd": {"deletePolicy": "HookFailed"}},
                     {"mode": "argocd", "argocd": {"deletePolicy": "HookSucceeded,HookFailed"}}):
            with self.subTest(hook=hook):
                self.render(base_values(hook=hook))
                result = self.template(base_values(hook=hook), "--skip-schema-validation")
                self.assertEqual(result.returncode, 0, result.stderr)

    def notes(self, values: dict[str, Any]) -> str:
        """NOTES.txt as `helm install` prints it; a client-side dry run with
        no kubeconfig, so no cluster is reached."""
        path = self.tmp / f"notes-{len(list(self.tmp.iterdir()))}.json"
        path.write_text(json.dumps(without_cluster(values)), encoding="utf-8")
        result = subprocess.run(["helm", "install", "gate", str(CHART), "--namespace", "shop", "--dry-run=client",
                                 "-f", str(path)], capture_output=True, text=True, timeout=60, check=False,
                                env={**os.environ, "KUBECONFIG": os.devnull})
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout[result.stdout.index("NOTES:"):]

    def test_notes_say_which_hook_ran_and_what_helm_test_means(self) -> None:
        notes = self.notes(base_values(hook={"mode": "helm"}))
        self.assertIn("Ran as this install's Helm post-install hook (hook.helm.events post-install,post-upgrade)", notes)
        self.assertNotIn("helm test", notes)
        notes = self.notes(base_values(hook={"mode": "helm", "helm": {"events": "post-install,post-upgrade,test"}}))
        self.assertIn("`helm test gate -n shop` runs it again", notes)
        self.assertIn("a failed test leaves the release\n`deployed`", notes)
        notes = self.notes(base_values(hook={"mode": "argocd", "argocd": {"phase": "PostSync"}}))
        self.assertIn("an Argo CD PostSync hook", notes)

    def test_helm_notes_say_which_version_the_gate_probed(self) -> None:
        """REGRESSION (R3-2, measured on kind with Helm 4.2.2): under Helm's
        default flags the post-upgrade hook ran as soon as the manifests were
        applied, probed the RollingUpdate Deployment's previous pods, and
        passed a vulnerable upgrade (2 of 2), while NOTES said a successful
        release meant the gate had passed. NOTES now say what it probed and
        which invocation makes it the new version."""
        notes = " ".join(self.notes(base_values(hook={"mode": "helm"})).split())
        self.assertIn("it may have probed the version being replaced", notes)
        self.assertIn("--rollback-on-failure", notes)
        self.assertIn("hook.mode helm: what the gate probes", notes)

    def test_argocd_notes_do_not_promise_a_failed_sync_to_the_helm_cli(self) -> None:
        """REGRESSION: in hook.mode argocd NOTES said "When the Job fails, the
        sync operation fails". NOTES are printed only by the Helm CLI, which
        does not read Argo CD annotations: measured on kind, `helm install`
        of this chart in argocd mode against a vulnerable target exited 0 at
        once with the release deployed. That install is now refused at
        render, so these NOTES come only from a dry run, and they say so."""
        notes = " ".join(self.notes(base_values(hook={"mode": "argocd"})).split())
        self.assertNotIn("When the Job fails, the sync operation fails", notes)
        self.assertIn("Only Argo CD renders this mode. `helm install` and `helm upgrade` refuse it", notes)
        self.assertIn("These notes come from a dry run", notes)

    def test_argocd_notes_name_the_job_the_way_argo_cd_does(self) -> None:
        """REGRESSION: NOTES printed one fixed Job name and `kubectl logs
        job/<that name>`; Argo CD names each sync's Job itself. They now give
        the prefix, and read the name from the sync's syncResult."""
        notes = " ".join(self.notes(base_values(hook={"mode": "argocd"})).split())
        self.assertIn("Job: gate-veridor-gate-<named by Argo CD, one per sync that runs hooks>", notes)
        self.assertIn("A selective sync or an Apply Only sync runs no hooks: it creates no gate Job and still "
                      "ends Succeeded, with no PostSync entry in its syncResult.", notes)
        self.assertIn("gate-veridor-gate-<revision>-postsync-<the sync's start, Unix seconds> (<revision>: its first "
                      "7 characters; empty for an Application with several sources)", notes)
        self.assertIn('.status.operationState.syncResult.resources[?(@.hookType=="PostSync")].name', notes)
        self.assertNotIn("logs job/gate-veridor-gate\n", notes + "\n")
        self.assertIn("Each sync's Job and its log stay for job.ttlSecondsAfterFinished (3600 s)", notes)
        notes = " ".join(self.notes(base_values(hook={"mode": "argocd", "argocd": {"deletePolicy": "HookSucceeded,HookFailed"}},
                                                job={"ttlSecondsAfterFinished": None})).split())
        self.assertIn("Argo CD deletes each sync's Job, and its log, as soon as it has read the result", notes)

    def test_notes_say_what_a_complete_job_means_under_the_policy(self) -> None:
        """REGRESSION: NOTES said a Complete Job meant "the target matched
        the declared expectations for the requests sent", and listed "1
        (findings)" among the exits that fail the Job, whatever gate.failOn
        was. Exit 0 means only that nothing the selected gate selects was
        present: under gate.failOn none a vulnerable target completes the
        Job (measured), and a finding the policy does not select leaves it
        Complete too."""
        notes = " ".join(self.notes(base_values(gate={"failOn": "none", "requireComplete": False})).split())
        self.assertNotIn("matched the declared expectations", notes)
        self.assertNotIn("1 (findings)", notes)
        self.assertIn("gate.failOn is none: findings never fail this Job", notes)
        notes = " ".join(self.notes(base_values()).split())
        self.assertNotIn("matched the declared expectations", notes)
        self.assertIn("1 (a finding gate.failOn new+confirmed selects)", notes)
        self.assertIn("A Complete Job means Veridor exited 0: nothing the selected gate "
                      "(gate.failOn new+confirmed, --require-complete) selects was present", notes)

    def test_no_mode_is_refused(self) -> None:
        values = base_values()
        values["hook"] = {"mode": ""}
        stderr = self.refused(values)
        for word in ("hook.mode", "argocd", "helm", "none"):
            self.assertIn(word, stderr)

    def test_an_unknown_mode_is_refused_by_the_schema(self) -> None:
        result = self.template(base_values(hook={"mode": "flux"}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/hook/mode", result.stderr)


@slow("spawns helm")
class JobShapeTest(_HelmCase):
    def test_never_retried_and_bounded(self) -> None:
        job, pod, _ = self.job_parts(base_values())
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 600)
        self.assertEqual(job["spec"]["ttlSecondsAfterFinished"], 3600)
        self.assertEqual(pod["restartPolicy"], "Never")

    def test_restricted_pod_security(self) -> None:
        _, pod, container = self.job_parts(base_values())
        assert_restricted(self, pod, container)
        self.assertIs(pod["enableServiceLinks"], False)
        work = next(v for v in pod["volumes"] if v["name"] == "work")
        self.assertIn("emptyDir", work)

    def test_the_analysis_template_matches_the_chart(self) -> None:
        """Two hand-maintained copies of one Job: they must not drift apart."""
        _, pod, container = self.job_parts(base_values())
        template = load_yaml(ANALYSIS_TEMPLATE)
        t_pod = template["spec"]["metrics"][0]["provider"]["job"]["spec"]["template"]["spec"]
        t_container = t_pod["containers"][0]
        self.assertEqual(t_pod["securityContext"], pod["securityContext"])
        self.assertEqual(t_container["securityContext"], container["securityContext"])
        self.assertEqual(t_container["resources"], container["resources"])
        self.assertEqual(t_container["command"], container["command"])
        # The gate flags too, parsed rather than compared as text: the
        # template's declared defaults against the chart's default render.
        from veridor import cli  # noqa: PLC0415

        ours = cli._parser().parse_args(container["args"])
        theirs = cli._parser().parse_args(analysis_template_args(template))
        for flag in ("command", "fail_on", "require_complete", "wait_for_target", "prove_liveness",
                     "read_only", "require_clean_teardown", "output_dir", "config"):
            with self.subTest(flag=flag):
                self.assertEqual(getattr(theirs, flag), getattr(ours, flag))

    def test_image_tag_defaults_to_app_version_and_takes_a_digest(self) -> None:
        from veridor import __version__  # noqa: PLC0415

        # The tag is appVersion, SemVer; see test_app_version_is_the_package_version.
        _, _, container = self.job_parts(base_values())
        self.assertEqual(container["image"],
                         f"ghcr.io/veridor-authz/veridor:{release_check.pep440_to_semver(__version__)}")
        digest = "sha256:" + "a" * 64
        # A digest with a tag other than appVersion needs digestTag naming
        # that tag (ImageDigestTest has why).
        _, _, container = self.job_parts(base_values(image={"repository": "r.example/v", "tag": "1.2.3",
                                                            "digest": digest, "digestTag": "1.2.3"}))
        self.assertEqual(container["image"], f"r.example/v:1.2.3@{digest}")

    def test_command_is_explicit(self) -> None:
        _, _, container = self.job_parts(base_values())
        self.assertEqual(container["command"], ["veridor"])

    def test_default_arguments(self) -> None:
        _, _, container = self.job_parts(base_values())
        self.assertEqual(container["args"], [
            "run", "--config", "/config/veridor.json", "--output-dir", "/work/.veridor",
            "--fail-on", "new+confirmed",
            "--base-url", "http://invoices-api.shop.svc.cluster.local:8080",
            "--require-complete",
            "--wait-for-target", "60",
        ])

    def test_every_gate_value_maps_to_a_real_flag(self) -> None:
        from veridor import cli  # noqa: PLC0415

        values = base_values(
            gate={"failOn": "confirmed", "requireComplete": False, "requireCleanTeardown": True,
                  "readOnly": True, "proveLiveness": False, "sarif": True,
                  "waitForTargetSeconds": 15},
            extraArgs=["--baseline", "/work/baseline.json"],
        )
        _, _, container = self.job_parts(values)
        parsed = cli._parser().parse_args(container["args"])
        self.assertEqual(parsed.command, "run")
        self.assertEqual(parsed.fail_on, "confirmed")
        self.assertFalse(parsed.require_complete)
        self.assertTrue(parsed.require_clean_teardown)
        self.assertTrue(parsed.read_only)
        self.assertFalse(parsed.prove_liveness)
        self.assertEqual(str(parsed.sarif), "/work/.veridor/veridor.sarif")
        self.assertEqual(str(parsed.baseline), "/work/baseline.json")
        self.assertEqual(str(parsed.config), "/config/veridor.json")
        self.assertEqual(parsed.wait_for_target, 15)

    def test_a_zero_wait_renders_no_flag_and_the_schema_refuses_a_bad_one(self) -> None:
        _, _, container = self.job_parts(base_values(gate={"waitForTargetSeconds": 0}))
        self.assertNotIn("--wait-for-target", container["args"])
        for bad in (-1, 1.5, "60"):
            with self.subTest(value=bad):
                result = self.template(base_values(gate={"waitForTargetSeconds": bad}))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("waitForTargetSeconds", result.stderr)

    def test_default_arguments_parse_with_the_real_cli(self) -> None:
        from veridor import cli  # noqa: PLC0415

        _, _, container = self.job_parts(base_values())
        parsed = cli._parser().parse_args(container["args"])
        self.assertTrue(parsed.require_complete)
        self.assertTrue(parsed.prove_liveness)

    def test_output_dir_outside_work_is_refused(self) -> None:
        result = self.template(base_values(output={"dir": "/data"}))
        self.assertNotEqual(result.returncode, 0)

    def test_existing_claim_replaces_the_emptydir(self) -> None:
        _, pod, _ = self.job_parts(base_values(output={"existingClaim": "gate-history"}))
        work = next(v for v in pod["volumes"] if v["name"] == "work")
        self.assertEqual(work, {"name": "work", "persistentVolumeClaim": {"claimName": "gate-history"}})

    def test_service_account(self) -> None:
        _, pod, _ = self.job_parts(base_values())
        self.assertEqual(pod["serviceAccountName"], "default")
        docs = self.render(base_values(serviceAccount={"create": True}))
        self.assertEqual(docs["ServiceAccount"]["metadata"]["name"], "gate-veridor-gate")
        self.assertIs(docs["ServiceAccount"]["automountServiceAccountToken"], False)
        self.assertEqual(docs["Job"]["spec"]["template"]["spec"]["serviceAccountName"], "gate-veridor-gate")


@slow("spawns helm")
class ImageDigestTest(_HelmCase):
    """REGRESSION: the release workflow packages the chart with image.digest
    set to its image, and `--set image.tag=0.1.1` on that chart rendered
    ghcr.io/veridor-authz/veridor:0.1.1@<the 0.1.0 digest>. The kubelet pulls the
    digest and ignores the tag (measured on kind: a nonexistent tag with a
    real digest ran that digest's image), so the gate kept running the old
    image while the manifest named the new one. A digest now goes only with
    the tag it belongs to: image.digestTag, appVersion when empty."""

    DIGEST = "sha256:" + "a" * 64
    OTHER = "sha256:" + "b" * 64

    def published(self) -> Path:
        """The chart as release.yml packages it: its values.yaml edit, which
        sets the one `  digest: ""` line, then `helm package`."""
        work = self.tmp / "published" / "veridor-gate"
        shutil.copytree(CHART, work)
        values = work / "values.yaml"
        text = values.read_text(encoding="utf-8")
        old = '\n  digest: ""\n'
        self.assertEqual(text.count(old), 1, "the release workflow's edit no longer applies")
        values.write_text(text.replace(old, f'\n  digest: "{self.DIGEST}"\n'), encoding="utf-8")
        result = self.helm("package", str(work), "--destination", str(self.tmp / "published"))
        self.assertEqual(result.returncode, 0, result.stderr)
        return next((self.tmp / "published").glob("veridor-gate-*.tgz"))

    def image(self, chart: Path, *sets: str) -> subprocess.CompletedProcess[str]:
        path = self.tmp / f"values-{len(list(self.tmp.iterdir()))}.json"
        path.write_text(json.dumps(base_values()), encoding="utf-8")
        return self.helm("template", "gate", str(chart), "-f", str(path), *[a for s in sets for a in ("--set", s)])

    def rendered_image(self, result: subprocess.CompletedProcess[str]) -> str:
        self.assertEqual(result.returncode, 0, result.stderr)
        job = next(d for d in load_yaml_documents(result.stdout) if d["kind"] == "Job")
        return job["spec"]["template"]["spec"]["containers"][0]["image"]

    def test_a_tag_alone_on_the_published_chart_is_refused(self) -> None:
        from veridor import __version__  # noqa: PLC0415

        chart = self.published()
        version = release_check.pep440_to_semver(__version__)
        for sets in (("image.tag=0.1.1",), ("image.repository=registry.example.com/veridor", "image.tag=0.1.1"),
                     ("image.tag=0.1.1", f"image.digestTag={version}")):
            with self.subTest(sets=sets):
                result = self.image(chart, *sets)
                self.assertNotEqual(result.returncode, 0, result.stdout[-300:])
                self.assertIn('veridor-gate: image.tag is "0.1.1", but image.digest is the digest of tag', result.stderr)

    def test_the_ways_to_change_the_tag_render_what_they_say(self) -> None:
        """The control: each render names exactly the image it pulls."""
        from veridor import __version__  # noqa: PLC0415

        chart = self.published()
        version = release_check.pep440_to_semver(__version__)
        repo = "ghcr.io/veridor-authz/veridor"
        for sets, image in (
                ((), f"{repo}:{version}@{self.DIGEST}"),
                ((f"image.tag={version}",), f"{repo}:{version}@{self.DIGEST}"),
                (("image.tag=0.1.1", "image.digest="), f"{repo}:0.1.1"),
                (("image.tag=0.1.1", f"image.digest={self.OTHER}", "image.digestTag=0.1.1"),
                 f"{repo}:0.1.1@{self.OTHER}"),
                (("image.repository=mirror.example/veridor",), f"mirror.example/veridor:{version}@{self.DIGEST}")):
            with self.subTest(sets=sets):
                self.assertEqual(self.rendered_image(self.image(chart, *sets)), image)

    def test_the_unpublished_chart_takes_a_tag(self) -> None:
        self.assertEqual(self.rendered_image(self.image(CHART, "image.tag=0.1.1")), "ghcr.io/veridor-authz/veridor:0.1.1")


@slow("spawns helm")
class ExtraArgsRenderTest(_HelmCase):
    def test_owned_flags_in_extra_args_are_refused_without_printing_the_value(self) -> None:
        literal = "hunter2-literal-7f3a"
        for option in owned_flags():
            shortest = next(option[:n] for n in range(3, len(option) + 1)
                            if argparse_reads(option[:n]) == option)
            for extra in ([option, f"http://api/v1;token={literal}"], [f"{option}=http://api/v1;token={literal}"],
                          [shortest, literal], [f"{shortest}={literal}"]):
                with self.subTest(extraArgs=extra):
                    self.assertTrue(chart_refuses(extra[0]))
                    stderr = self.refused(base_values(extraArgs=["--baseline", "/work/b.json", *extra]))
                    self.assertIn("veridor-gate: extraArgs[", stderr)
                    self.assertNotIn(literal, stderr)
        stderr = self.refused(base_values(extraArgs=["-h"]))
        self.assertIn("which Veridor reads as --help", stderr)
        stderr = self.refused(base_values(extraArgs=["--he"]))
        self.assertIn("extraArgs[0] is --he, which Veridor reads as --help", stderr)
        for token in ("-hx", "-h=x", "-qh"):
            with self.subTest(extraArgs=[token]):
                stderr = self.refused(base_values(extraArgs=["--baseline", "/work/b.json", token]))
                self.assertIn(f"extraArgs[2] is {token.split('=')[0]}, a single-dash token with an h in it", stderr)

    def test_other_arguments_render(self) -> None:
        """The control: flags the chart does not own, in full and abbreviated,
        and non-flag values."""
        for extra in (["--baseline", "/work/b.json"], ["--basel=/work/b.json"], ["--base-path", "/v1"],
                      ["--rep", "junit=/work/j.xml"], ["--allow-no-matches"], [5], ["---config"]):
            with self.subTest(extraArgs=extra):
                self.assertFalse(chart_refuses(str(extra[0])))
                self.render(base_values(extraArgs=extra))


@slow("spawns helm")
class CredentialTest(_HelmCase):
    """The chart never renders a literal credential. The refusals are the
    enforcing half; the positive controls prove the rule is not simply
    refusing everything."""

    SECRET = "s3cr3t-literal-value-9f2c"

    def test_credentials_are_secret_key_refs_only(self) -> None:
        _, _, container = self.job_parts(base_values())
        by_name = {entry["name"]: entry for entry in container["env"]}
        for entry in SECRET_ENV:
            ref = by_name[entry["name"]]["valueFrom"]["secretKeyRef"]
            self.assertEqual(ref, {"name": entry["secretName"], "key": entry["key"], "optional": True})
        literal = [e["name"] for e in container["env"] if "value" in e]
        self.assertEqual(sorted(literal), ["PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"])

    def test_a_scheme_and_a_reference_renders(self) -> None:
        self.render(base_values())

    def _with_header(self, name: str, value: str, **overrides: Any) -> dict[str, Any]:
        values = base_values(**overrides)
        values["config"]["identities"]["invoice_owner"]["headers"][name] = value
        return values

    def test_a_literal_authorization_header_is_refused_without_echoing_it(self) -> None:
        stderr = self.refused(self._with_header("Authorization", f"Bearer {self.SECRET}"))
        self.assertIn("config.identities.invoice_owner.headers.Authorization", stderr)
        self.assertIn("secretEnv", stderr)
        self.assertNotIn(self.SECRET, stderr)

    def test_a_literal_mixed_with_a_reference_is_refused(self) -> None:
        stderr = self.refused(self._with_header("Authorization", "Bearer abc${VERIDOR_OWNER_TOKEN}"))
        self.assertIn("headers.Authorization", stderr)

    def test_a_literal_cookie_is_refused(self) -> None:
        self.refused(self._with_header("Cookie", f"session={self.SECRET}"))

    def test_a_literal_header_in_a_check_request_is_refused(self) -> None:
        values = base_values()
        values["config"]["checks"][0]["request"]["headers"] = {"X-Api-Key": self.SECRET}
        stderr = self.refused(values)
        self.assertIn("config.checks[0].request.headers.X-Api-Key", stderr)
        self.assertNotIn(self.SECRET, stderr)

    def test_a_credential_named_body_field_is_refused(self) -> None:
        for value in (self.SECRET, 123456):
            with self.subTest(value=value):
                values = base_values()
                values["config"]["identities"]["invoice_owner"]["session"] = {
                    "login": [{"method": "POST", "path": "/login",
                               "json": {"username": "alice", "password": value}}],
                    "establishes": {"cookie": "sid"},
                }
                stderr = self.refused(values)
                self.assertIn("session.login[0].json.password", stderr)
                self.assertNotIn(str(value), stderr)

    def test_a_referenced_body_field_renders(self) -> None:
        values = base_values()
        values["config"]["identities"]["invoice_owner"]["session"] = {
            "login": [{"method": "POST", "path": "/login",
                       "json": {"username": "alice", "password": "${VERIDOR_OWNER_TOKEN}"}}],
            "establishes": {"cookie": "sid"},
        }
        self.render(values)

    def test_a_literal_session_inject_is_refused(self) -> None:
        values = base_values()
        values["config"]["identities"]["invoice_owner"]["session"] = {
            "login": [{"method": "POST", "path": "/login"}],
            "establishes": {"cookie": "sid"},
            "inject": [{"header": "X-CSRF-Token", "value": self.SECRET}],
        }
        stderr = self.refused(values)
        self.assertIn("inject[0].value", stderr)
        self.assertNotIn(self.SECRET, stderr)
        values["config"]["identities"]["invoice_owner"]["session"]["inject"][0]["value"] = "${capture.csrf}"
        self.render(values)

    def test_a_non_credential_header_needs_listing(self) -> None:
        self.refused(self._with_header("X-Tenant-Id", "acme"))
        self.render(self._with_header("X-Tenant-Id", "acme", allowLiteralHeaders=["x-tenant-id"]))

    def test_a_credential_header_cannot_be_listed(self) -> None:
        for name in ("Authorization", "Cookie", "X-Api-Key", "X-Auth-Token"):
            with self.subTest(name=name):
                stderr = self.refused(self._with_header(name, "x", allowLiteralHeaders=[name]))
                self.assertIn("allowLiteralHeaders", stderr)

    def test_userinfo_in_a_url_is_refused(self) -> None:
        stderr = self.refused(base_values(target={"baseUrl": f"http://gate:{self.SECRET}@api:8080"}))
        self.assertIn("target.baseUrl", stderr)
        self.assertNotIn(self.SECRET, stderr)
        values = base_values()
        values["config"]["target"]["base_url"] = f"https://u:{self.SECRET}@api"
        self.assertIn("config.target.base_url", self.refused(values))

    def test_target_base_url_is_held_to_the_string_rules(self) -> None:
        """REGRESSION: target.baseUrl was checked for user:password@ only, so
        `;token=<literal>` and `?api_key=<literal>` rendered into the Job's
        arguments (measured: in the pod spec on kind), and Veridor sends a
        matrix parameter on every probe. The same text in
        config.target.base_url was refused."""
        # ;jsessionid= and ?key= are the parameter-only names (a servlet
        # session, a Google API key): they rendered here too (measured).
        for url in (f"http://api:8080/v1;token={self.SECRET}", f"http://api:8080/v1?api_key={self.SECRET}",
                    f"http://api:8080/v1;accessToken={self.SECRET}", f"http://api:8080/v1;jsessionid={self.SECRET}",
                    f"http://api:8080/v1?key={self.SECRET}"):
            with self.subTest(url=url):
                stderr = self.refused(base_values(target={"baseUrl": url}))
                self.assertIn("target.baseUrl", stderr)
                self.assertNotIn(self.SECRET, stderr)
        # A reference is refused too: --base-url is applied after Veridor
        # expands the configuration, so ${NAME} would be sent as written.
        from veridor.core import load_config  # noqa: PLC0415

        path = self.tmp / "veridor.json"
        path.write_text(json.dumps(DEMO_CONFIG), encoding="utf-8")
        reference = "http://api:8080/v1;token=${VERIDOR_OWNER_TOKEN}"
        with mock.patch.dict(os.environ, {"VERIDOR_OWNER_TOKEN": "owner-token",
                                          "VERIDOR_OUTSIDER_TOKEN": "outsider-token"}):
            self.assertEqual(load_config(path, base_url=reference)["target"]["base_url"], reference)
        stderr = self.refused(base_values(target={"baseUrl": reference}))
        self.assertIn("does not expand", stderr)
        # Controls: a URL without a credential still renders. (This list held
        # ";jsessionid=abc" as a URL without a credential; a jsessionid is a
        # session, which the product's own scrubbing treats as a secret.)
        for url in ("http://api:8080", "http://api:8080/v1;v=2", "http://api:8080/v1?page=2",
                    "http://api:8080/v1?keyword=x&codec=h264"):
            with self.subTest(url=url):
                self.render(base_values(target={"baseUrl": url}))

    def test_every_reference_needs_a_secret_env_entry(self) -> None:
        values = base_values()
        values["secretEnv"] = values["secretEnv"][:1]
        stderr = self.refused(values)
        self.assertIn("VERIDOR_OUTSIDER_TOKEN", stderr)

    def test_sequence_capture_references_are_not_environment(self) -> None:
        values = base_values()
        values["config"]["version"] = 2
        values["config"]["sequences"] = [{"id": "s", "steps": [
            {"as": "invoice_owner", "method": "GET", "path": "/api/invoices/${invoice_id}"}]}]
        self.render(values)

    def test_the_rendered_output_carries_no_value_from_a_secret(self) -> None:
        """No path through the values puts a Secret's content in a manifest:
        the chart only ever names the Secret and the key."""
        result = self.template(base_values())
        self.assertEqual(result.returncode, 0, result.stderr)
        for entry in SECRET_ENV:
            self.assertIn(f'name: "{entry["secretName"]}"', result.stdout)
        self.assertNotRegex(result.stdout, r"(?i)bearer [A-Za-z0-9]")


@slow("spawns helm")
class ConfigMapTest(_HelmCase):
    def test_the_config_map_is_the_config_and_veridor_loads_it(self) -> None:
        from veridor.core import ConfigError, load_config  # noqa: PLC0415

        docs = self.render(base_values())
        text = docs["ConfigMap"]["data"]["veridor.json"]
        self.assertEqual(json.loads(text), DEMO_CONFIG)
        path = self.tmp / "veridor.json"
        path.write_text(text, encoding="utf-8")
        env = {"VERIDOR_OWNER_TOKEN": "owner-token", "VERIDOR_OUTSIDER_TOKEN": "outsider-token"}
        with mock.patch.dict(os.environ, env):
            config = load_config(path)
        self.assertEqual(
            config["identities"]["invoice_owner"]["headers"]["Authorization"], "Bearer owner-token"
        )
        # The control: the same file without the variables is refused, so the
        # load above really did expand them rather than pass text through.
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(ConfigError):
            load_config(path)

    def test_the_job_mounts_the_rendered_config_map(self) -> None:
        docs = self.render(base_values())
        volume = next(v for v in docs["Job"]["spec"]["template"]["spec"]["volumes"] if v["name"] == "config")
        self.assertEqual(volume["configMap"]["name"], docs["ConfigMap"]["metadata"]["name"])
        self.assertEqual(volume["configMap"]["items"], [{"key": "veridor.json", "path": "veridor.json"}])

    def test_existing_config_map(self) -> None:
        values = base_values(existingConfigMap={"name": "my-config", "key": "gate.json"})
        values["config"] = {}
        docs = self.render(values)
        self.assertNotIn("ConfigMap", docs)
        volume = next(v for v in docs["Job"]["spec"]["template"]["spec"]["volumes"] if v["name"] == "config")
        self.assertEqual(volume["configMap"], {"name": "my-config", "items": [{"key": "gate.json", "path": "veridor.json"}]})

    def test_both_or_neither_is_refused(self) -> None:
        self.assertIn("both", self.refused(base_values(existingConfigMap={"name": "my-config"})))
        values = base_values()
        values["config"] = {}
        self.assertIn("no Veridor configuration", self.refused(values))

    def test_no_target_is_refused(self) -> None:
        values = base_values(target={"baseUrl": ""})
        del values["config"]["target"]
        self.assertIn("no target", self.refused(values))

    def test_target_base_url_still_needs_a_target_object(self) -> None:
        """REGRESSION: with target.baseUrl set and no config.target the chart
        rendered a configuration Veridor refuses whatever --base-url says
        ("target must be an object", exit 2; measured in a Job on kind), so
        every run failed. The chart now refuses it at render."""
        from veridor.core import ConfigError, load_config  # noqa: PLC0415

        env = {"VERIDOR_OWNER_TOKEN": "owner-token", "VERIDOR_OUTSIDER_TOKEN": "outsider-token"}
        values = base_values()
        del values["config"]["target"]
        # The premise, from Veridor's own loader: no target object is refused
        # even with a base URL.
        path = self.tmp / "no-target.json"
        path.write_text(json.dumps(values["config"]), encoding="utf-8")
        with mock.patch.dict(os.environ, env), self.assertRaisesRegex(ConfigError, "target must be an object"):
            load_config(path, base_url="http://invoices-api.shop.svc.cluster.local:8080")
        self.assertIn("no target object", self.refused(values))
        values["config"]["target"] = "http://invoices-api.shop.svc.cluster.local:8080"
        self.assertIn("no target object", self.refused(values))
        # The control: `target: {}` renders, and Veridor loads it with the URL.
        values["config"]["target"] = {}
        text = self.render(values)["ConfigMap"]["data"]["veridor.json"]
        path.write_text(text, encoding="utf-8")
        with mock.patch.dict(os.environ, env):
            config = load_config(path, base_url="http://invoices-api.shop.svc.cluster.local:8080")
        self.assertEqual(config["target"]["base_url"], "http://invoices-api.shop.svc.cluster.local:8080")

    def test_the_argocd_example_values_render(self) -> None:
        app = load_yaml(APPLICATION_EXAMPLE)
        gate = next(s for s in app["spec"]["sources"] if s.get("chart") == "veridor-gate")
        job = self.render(gate["helm"]["valuesObject"])["Job"]
        self.assertEqual(job["metadata"]["generateName"], "gate-veridor-gate-")
        self.assertEqual(job["spec"]["ttlSecondsAfterFinished"], 3600)

    def test_the_ci_values_render(self) -> None:
        result = self.helm("template", "gate", str(CHART), "-f", str(CHART / "ci" / "argocd-values.yaml"))
        self.assertEqual(result.returncode, 0, result.stderr)


@slow("spawns helm, stands up the demo API on loopback and runs Veridor against it")
class DocumentedConfigTest(_HelmCase):
    """The configurations a reader copies, run the way the chart runs them.

    REGRESSION (measured on the host with the chart's argv, and on kind): the
    chart README quick start and deploy/argocd/application-example.yaml gave
    ``other_tenant`` a denial and no ``marker_probe``. The demo API answers an
    unknown token with the same 404, so the denial was unproven, and with
    ``gate.requireComplete: true`` a FIXED target exited 3
    (``liveness_unproven``): the release or the sync failed for every adopter
    who followed the page. The tests rendered the example and never ran it,
    and the e2e replaced its configuration with its own.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.demo_server import create_server  # noqa: PLC0415

        cls.servers = {}
        for vulnerable in (False, True):
            server = create_server("127.0.0.1", 0, vulnerable=vulnerable)
            loopback.start(server)
            cls.servers[vulnerable] = server

    @classmethod
    def tearDownClass(cls) -> None:
        for server in cls.servers.values():
            server.shutdown()
            server.server_close()

    def documented(self) -> dict[str, Path]:
        readme = self.tmp / "readme-values.yaml"
        readme.write_text(readme_block(CHART / "README.md", "# values.yaml"), encoding="utf-8")
        app = load_yaml(APPLICATION_EXAMPLE)
        gate = next(s for s in app["spec"]["sources"] if s.get("chart") == "veridor-gate")
        example = self.tmp / "example-values.json"
        example.write_text(json.dumps(gate["helm"]["valuesObject"]), encoding="utf-8")
        return {"chart README quick start": readme, "deploy/argocd/application-example.yaml": example}

    def rendered(self, values: Path) -> tuple[dict[str, Any], list[str]]:
        result = self.helm("template", "gate", str(CHART), "--namespace", "shop", "-f", str(values))
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = {doc["kind"]: doc for doc in load_yaml_documents(result.stdout)}
        container = docs["Job"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["command"], ["veridor"])
        return json.loads(docs["ConfigMap"]["data"]["veridor.json"]), list(container["args"])

    def run_as_the_job(self, config: dict[str, Any], args: list[str], vulnerable: bool) -> tuple[int, list[str]]:
        """The Job's own argv with its three paths pointed at this host."""
        from veridor import cli  # noqa: PLC0415

        work = Path(tempfile.mkdtemp(dir=self.tmp))
        (work / "veridor.json").write_text(json.dumps(config), encoding="utf-8")
        argv = list(args)
        for flag, value in (("--config", str(work / "veridor.json")), ("--output-dir", str(work / "out")),
                            ("--base-url", f"http://127.0.0.1:{self.servers[vulnerable].server_port}")):
            argv[argv.index(flag) + 1] = value
        env = {"VERIDOR_OWNER_TOKEN": "owner-token", "VERIDOR_OUTSIDER_TOKEN": "outsider-token"}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(argv)
        latest = json.loads((work / "out" / "latest.json").read_text(encoding="utf-8"))
        return code, [reason["code"] for reason in latest["gate"]["reasons"]]

    def test_the_documented_configurations_pass_fixed_and_fail_vulnerable(self) -> None:
        for name, values in self.documented().items():
            config, args = self.rendered(values)
            self.assertIn("--require-complete", args)
            for vulnerable, expected in ((False, (0, [])), (True, (1, ["findings"]))):
                with self.subTest(document=name, vulnerable=vulnerable):
                    self.assertEqual(self.run_as_the_job(config, args, vulnerable), expected)

    def test_control_without_the_marker_probe_a_fixed_target_exits_3(self) -> None:
        """The defect, reproduced: the same configuration with other_tenant's
        marker and marker_probe taken out, as both documents had them."""
        config, args = self.rendered(self.documented()["chart README quick start"])
        other = config["identities"]["other_tenant"]
        self.assertIn("marker_probe", other)
        del other["marker_probe"], other["marker"]
        self.assertEqual(self.run_as_the_job(config, args, False), (3, ["liveness_unproven"]))
        self.assertEqual(self.run_as_the_job(config, args, True), (1, ["findings"]))

    def test_the_two_documents_carry_the_same_configuration(self) -> None:
        """The e2e's argocd scenario runs the example's configuration on kind;
        this keeps the quick start's identities and checks the same."""
        rendered = {name: self.rendered(values)[0] for name, values in self.documented().items()}
        readme, example = rendered.values()
        self.assertEqual(readme["identities"], example["identities"])
        self.assertEqual([dict(c, name=None) for c in readme["checks"]],
                         [dict(c, name=None) for c in example["checks"]])


@slow("spawns helm")
class NetworkPolicyTest(_HelmCase):
    PEERS = [{"podSelector": {"matchLabels": {"app": "invoices-api"}}}]
    PORTS = [{"port": 8080, "protocol": "TCP"}]

    def test_off_by_default(self) -> None:
        self.assertNotIn("NetworkPolicy", self.render(base_values()))

    def test_egress_to_the_target_and_dns_only(self) -> None:
        docs = self.render(base_values(networkPolicy={
            "enabled": True, "targetPeers": self.PEERS, "targetPorts": self.PORTS}))
        policy = docs["NetworkPolicy"]["spec"]
        self.assertEqual(policy["policyTypes"], ["Ingress", "Egress"])
        self.assertEqual(policy["ingress"], [])
        self.assertEqual(policy["egress"][0], {"to": self.PEERS, "ports": self.PORTS})
        self.assertEqual({p["port"] for p in policy["egress"][1]["ports"]}, {53})
        self.assertEqual(len(policy["egress"]), 2)
        pod_labels = docs["Job"]["spec"]["template"]["metadata"]["labels"]
        for key, value in policy["podSelector"]["matchLabels"].items():
            self.assertEqual(pod_labels[key], value)

    def test_enabled_without_a_target_is_refused(self) -> None:
        self.assertIn("targetPeers", self.refused(base_values(networkPolicy={"enabled": True})))

    def test_pod_labels_cannot_detach_the_pod_from_the_policy(self) -> None:
        """REGRESSION: job.podLabels was rendered after the selector labels
        with no check, so app.kubernetes.io/component (or name, or instance)
        replaced the pod's label and the policy's podSelector matched no pod.
        Measured on kind: 0 pods selected, and the gate reached a target the
        policy excluded (Job Complete instead of exit 3)."""
        enabled = {"enabled": True, "targetPeers": self.PEERS, "targetPorts": self.PORTS}
        docs = self.render(base_values(networkPolicy=enabled, job={"podLabels": {"team": "payments"}}))
        selector = docs["NetworkPolicy"]["spec"]["podSelector"]["matchLabels"]
        pod_labels = docs["Job"]["spec"]["template"]["metadata"]["labels"]
        self.assertEqual(pod_labels["team"], "payments")  # the control: other labels still render
        self.assertLessEqual(selector.items(), pod_labels.items())
        self.assertEqual(set(selector), {"app.kubernetes.io/name", "app.kubernetes.io/instance",
                                         "app.kubernetes.io/component"})
        for key in selector:
            for policy in (enabled, {"enabled": False}):
                with self.subTest(key=key, policy=policy["enabled"]):
                    stderr = self.refused(base_values(networkPolicy=policy, job={"podLabels": {key: "custom"}}))
                    self.assertIn(f"job.podLabels sets {key}", stderr)

    def test_a_dns_rule_or_a_port_that_opens_everything_is_refused(self) -> None:
        """REGRESSION: dns.peers [] or null rendered a DNS rule with no `to`,
        which allows port 53 to every destination (measured on kind: a pod
        that is not DNS answered the gate's pod on 53/tcp), and targetPorts
        [{}] allowed every TCP port of the target (measured: port 8080 of a
        target peer answered, with no entry naming it)."""
        cases = {
            "dns.peers []": {"dns": {"peers": []}},
            "dns.peers null": {"dns": {"peers": None}},
            "dns.ports []": {"dns": {"ports": []}},
            "dns.ports without a port": {"dns": {"ports": [{"protocol": "UDP"}]}},
            "targetPorts [{}]": {"targetPorts": [{}]},
            "targetPorts without a port": {"targetPorts": [{"protocol": "TCP"}]},
            "targetPorts with a null port": {"targetPorts": [{"port": None, "protocol": "TCP"}]},
        }
        for name, override in cases.items():
            with self.subTest(case=name):
                policy = {"enabled": True, "targetPeers": self.PEERS, "targetPorts": self.PORTS, **override}
                stderr = self.refused(base_values(networkPolicy=policy))
                self.assertIn("networkPolicy.", stderr)
                self.assertRegex(stderr, r"every (destination|port)")
        # Controls: DNS turned off with no peers renders one rule, a named port renders.
        docs = self.render(base_values(networkPolicy={
            "enabled": True, "targetPeers": self.PEERS, "targetPorts": [{"port": "http"}],
            "dns": {"enabled": False, "peers": []}}))
        self.assertEqual(docs["NetworkPolicy"]["spec"]["egress"],
                         [{"to": self.PEERS, "ports": [{"port": "http"}]}])


class NoneModeDocumentTest(unittest.TestCase):
    """hook.mode none's wait, as the README and NOTES print it. REGRESSION:
    NOTES printed `kubectl wait --for=condition=Complete`, which reports a
    failed gate only when its timeout runs out, and nothing said that a Job
    rendered with `helm template` is always -r1: re-applied unchanged it runs
    nothing, and the wait read the previous run (measured on kind)."""

    def test_the_readme_deletes_the_rendered_job_and_waits_for_either_outcome(self) -> None:
        block = readme_block(CHART / "README.md", "helm template gate")
        lines = [line.strip() for line in block.splitlines()]
        delete = next(i for i, line in enumerate(lines) if "delete job gate-veridor-gate-r1" in line)
        apply = next(i for i, line in enumerate(lines) if " apply -f gate.yaml" in line)
        self.assertLess(delete, apply)
        self.assertIn("--ignore-not-found", lines[delete])
        self.assertNotIn("kubectl wait", block)
        self.assertIn('*" Complete "* | *" Failed "*) break', block)
        self.assertEqual(lines[-1], 'case " $outcome " in *" Complete "*) true ;; *) false ;; esac')

    def test_every_step_before_the_wait_is_checked(self) -> None:
        """REGRESSION: run without `set -e` (the README allowed it), a
        refused delete fell through to `apply` ("unchanged") and the wait
        read the previous run's Complete (measured on kind as an identity
        without delete on Jobs). Each step now stops the block itself."""
        lines = [line.strip() for line in readme_block(CHART / "README.md", "helm template gate").splitlines()]
        wait = next(i for i, line in enumerate(lines) if line.startswith("while "))
        for line in lines[1:wait]:
            if not line.startswith("if "):
                with self.subTest(line=line):
                    self.assertTrue(line.endswith(" || exit 1"), line)
        self.assertNotIn("set -e", "\n".join(lines))

    def test_notes_wait_for_either_outcome(self) -> None:
        notes = (CHART / "templates" / "NOTES.txt").read_text(encoding="utf-8")
        self.assertNotIn("wait --for=condition=Complete", notes)
        self.assertIn('*" Complete "* | *" Failed "*) break', notes)
        self.assertIn('case " $outcome " in *" Complete "*) true ;; *) false ;; esac', notes)
        self.assertIn("helm template` always", notes)


@slow("runs the README's hook.mode none flow under sh against a stub kubectl")
class NoneModeFlowTest(unittest.TestCase):
    JOB = "gate-veridor-gate-r1"

    def block(self) -> str:
        return readme_block(CHART / "README.md", "helm template gate")

    def test_a_previous_passing_job_is_not_read_as_this_run(self) -> None:
        status, calls, jobs = run_documented_flow(self, self.block(), self.JOB, "Failed", existing="Complete")
        self.assertEqual(status, 1, calls)
        self.assertEqual(jobs[self.JOB]["uid"], 2, "the flow read the previous run's Job")
        self.assertLess(next(i for i, c in enumerate(calls) if " delete job " in f" {c} "),
                        next(i for i, c in enumerate(calls) if " apply " in f" {c} "))

    def test_this_run_s_outcome_decides(self) -> None:
        for outcome, existing, expected in (("Complete", None, 0), ("Complete", "Failed", 0),
                                            ("Failed", None, 1), ("Vanishes", None, 1)):
            with self.subTest(outcome=outcome, existing=existing):
                status, calls, _ = run_documented_flow(self, self.block(), self.JOB, outcome, existing=existing)
                self.assertEqual(status, expected, calls)

    def test_a_step_that_fails_stops_the_flow_and_its_control_passes_stale(self) -> None:
        """REGRESSION (measured on kind, as an identity that may create but
        not delete Jobs, the block under plain `sh`): the delete was refused,
        `apply` printed "unchanged", and the block exited 0 on the previous
        run's Complete against a target that had turned vulnerable. The same
        with `helm template` refusing the values. Each mode: the block exits
        1 and leaves the previous Job; the control, the same block without
        its step checks and uid binding (the block as it read before), exits
        0 on that previous Job, so the stub reproduces the defect."""
        modes = ({"delete": "forbidden"}, {"delete": "noop"}, {"delete": "forbidden", "apply": "immutable"},
                 {"helm": "fail", "delete": "forbidden"}, {"replace": "1"})
        for mode in modes:
            with self.subTest(mode=mode):
                status, calls, jobs = run_documented_flow(self, self.block(), self.JOB, "Failed",
                                                          existing="Complete", **mode)
                self.assertEqual(status, 1, calls)
                if "replace" not in mode:
                    self.assertEqual(jobs[self.JOB]["uid"], 1, calls)
                status, calls, _ = run_documented_flow(self, unchecked(self.block()), self.JOB, "Failed",
                                                       existing="Complete", **mode)
                self.assertEqual(status, 0, f"the control no longer reproduces the defect: {calls}")

    def test_a_refused_render_runs_no_kubectl(self) -> None:
        status, calls, _ = run_documented_flow(self, self.block(), self.JOB, "Complete", helm="fail")
        self.assertEqual((status, calls), (1, []))

    def test_the_unchecked_control_is_the_previous_block(self) -> None:
        """What the control above runs is exactly the block this README
        printed before (and what the e2e's live control runs)."""
        self.assertEqual(unchecked(self.block()), PREVIOUS_CHART_BLOCK)

    def test_control_the_old_wait_reads_the_previous_job(self) -> None:
        """The stub reproduces the defect: apply then `kubectl wait
        --for=condition=Complete`, with a passing Job from an earlier run
        present and this run failing, exits 0."""
        old = ("ns=shop\nkubectl -n \"$ns\" apply -f gate.yaml\n"
               "kubectl -n \"$ns\" wait --for=condition=Complete --timeout=600s job/gate-veridor-gate-r1\n")
        status, calls, jobs = run_documented_flow(self, old, self.JOB, "Failed", existing="Complete")
        self.assertEqual(status, 0, calls)
        self.assertEqual(jobs[self.JOB]["uid"], 1)


#: The chart README's hook.mode none block before it checked its steps.
PREVIOUS_CHART_BLOCK = """ns=shop
helm template gate ./veridor-gate --namespace "$ns" -f values.yaml > gate.yaml
kubectl -n "$ns" delete job gate-veridor-gate-r1 --ignore-not-found --wait=true
kubectl -n "$ns" apply -f gate.yaml
while outcome="$(kubectl -n "$ns" get job gate-veridor-gate-r1 -o jsonpath='{.status.conditions[?(@.status=="True")].type}')"; do
  case " $outcome " in *" Complete "* | *" Failed "*) break ;; esac
  sleep 5
done
kubectl -n "$ns" logs job/gate-veridor-gate-r1
case " $outcome " in *" Complete "*) true ;; *) false ;; esac
"""


@slow("runs the e2e script under bash; it refuses before touching any cluster")
class E2EScriptRefusalTest(unittest.TestCase):
    def run_script(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        clean = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
        clean.update(env)
        return subprocess.run(["bash", str(E2E_SCRIPT)], capture_output=True, text=True,
                              env=clean, timeout=60, check=False)

    def test_no_context_is_refused(self) -> None:
        result = self.run_script({})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("KUBE_CONTEXT is not set", result.stderr)

    def test_a_non_kind_context_is_refused(self) -> None:
        result = self.run_script({"KUBE_CONTEXT": "prod-eu-west-1"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("does not start with 'kind-'", result.stderr)

    def test_an_unknown_scenario_is_refused(self) -> None:
        # The script checks its tools before its arguments. helm and kubectl
        # have a VERIDOR_REQUIRE_* variable, and under it a missing one is a
        # failure; kind and docker have none, so without them this skips.
        for tool, env in (("helm", REQUIRE_HELM_ENV), ("kubectl", REQUIRE_KUBECTL_ENV)):
            if shutil.which(tool) is None and os.environ.get(env) == "1":
                self.fail(f"{tool} is not on PATH and {env}=1 says this must run")
        if not all(shutil.which(tool) for tool in ("kubectl", "helm", "kind", "docker", "python3")):
            self.skipTest("the scenario check runs after the tool check")
        result = self.run_script({"KUBE_CONTEXT": "kind-x", "E2E_SCENARIOS": "plain chaos"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("'chaos'", result.stderr)

    def test_shellcheck_clean(self) -> None:
        # CI sets VERIDOR_REQUIRE_SHELLCHECK=1; there a missing shellcheck is a
        # failure, not a skip that reads as a pass in a green job.
        if shutil.which("shellcheck") is None:
            if os.environ.get(REQUIRE_SHELLCHECK_ENV) == "1":
                self.fail(f"shellcheck is not on PATH and {REQUIRE_SHELLCHECK_ENV}=1 says this must run")
            self.skipTest(f"shellcheck is not on PATH (set {REQUIRE_SHELLCHECK_ENV}=1 to make this a failure)")
        result = subprocess.run(["shellcheck", str(E2E_SCRIPT)], capture_output=True, text=True,
                                timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)


class ShellcheckRequirementTest(unittest.TestCase):
    """The control for test_shellcheck_clean's skip: with PATH stripped of
    shellcheck it skips by default and FAILS under VERIDOR_REQUIRE_SHELLCHECK=1.
    It used to skip either way, so CI setting the variable protected nothing.
    No subprocess runs: without shellcheck the test stops before spawning."""

    def outcome(self, env: dict[str, str]) -> unittest.TestResult:
        result = unittest.TestResult()
        empty = tempfile.mkdtemp(prefix="veridor-no-shellcheck-")
        self.addCleanup(shutil.rmtree, empty, True)
        with mock.patch.dict(os.environ, {"PATH": empty, **env}):
            if REQUIRE_SHELLCHECK_ENV not in env:
                os.environ.pop(REQUIRE_SHELLCHECK_ENV, None)
            self.assertIsNone(shutil.which("shellcheck"), "the PATH was not stripped")
            E2EScriptRefusalTest("test_shellcheck_clean").run(result)
        return result

    def test_missing_shellcheck_skips_by_default(self) -> None:
        result = self.outcome({})
        self.assertEqual((len(result.skipped), len(result.failures), len(result.errors)), (1, 0, 0))

    def test_missing_shellcheck_fails_when_required(self) -> None:
        result = self.outcome({REQUIRE_SHELLCHECK_ENV: "1"})
        self.assertEqual((len(result.skipped), len(result.failures), len(result.errors)), (0, 1, 0))
        self.assertIn(REQUIRE_SHELLCHECK_ENV, result.failures[0][1])


class ScenarioToolRequirementTest(unittest.TestCase):
    """The control for test_an_unknown_scenario_is_refused's skip. The script
    checks its tools before its arguments, so the test needs kubectl, helm,
    kind and docker. It skipped when any was missing, including under
    VERIDOR_REQUIRE_HELM=1 and VERIDOR_REQUIRE_KUBECTL=1 (measured with both
    stripped from PATH). Now a required tool that is missing is a failure;
    kind and docker have no such variable and still skip. No subprocess runs:
    with PATH stripped the test stops before spawning."""

    def outcome(self, env: dict[str, str]) -> unittest.TestResult:
        result = unittest.TestResult()
        empty = tempfile.mkdtemp(prefix="veridor-no-tools-")
        self.addCleanup(shutil.rmtree, empty, True)
        with mock.patch.dict(os.environ, {"PATH": empty, **env}):
            for name in (REQUIRE_HELM_ENV, REQUIRE_KUBECTL_ENV):
                if name not in env:
                    os.environ.pop(name, None)
            self.assertIsNone(shutil.which("helm"), "the PATH was not stripped")
            self.assertIsNone(shutil.which("kubectl"), "the PATH was not stripped")
            E2EScriptRefusalTest("test_an_unknown_scenario_is_refused").run(result)
        return result

    def test_missing_tools_skip_by_default(self) -> None:
        result = self.outcome({})
        self.assertEqual((len(result.skipped), len(result.failures), len(result.errors)), (1, 0, 0))

    def test_a_missing_required_tool_fails(self) -> None:
        for env in (REQUIRE_HELM_ENV, REQUIRE_KUBECTL_ENV):
            with self.subTest(env=env):
                result = self.outcome({env: "1"})
                self.assertEqual((len(result.skipped), len(result.failures), len(result.errors)),
                                 (0, 1, 0))
                self.assertIn(env, result.failures[0][1])


#: The stubbed e2e runs' `sleep`: every wait costs at most one second. With
#: E2E_TIMEOUT=1 each `deadline=$((SECONDS + E2E_TIMEOUT))` loop runs its body
#: once, sleeps, and stops only when SECONDS has passed the deadline -- which a
#: full second of real sleep guarantees whatever length was asked for, so every
#: loop runs its body exactly as often as under the real `sleep` (the kubectl
#: and helm call logs of all four scenario groups are the same either way). A
#: no-op `sleep`, as run_documented_flow uses, would not do here: the SECONDS
#: loops would spin the kubectl stub for up to a second per wait, and
#: run_readme_flow's one-second poll would kill the flow it is waiting on.
#: Measured: the 12 stubbed-e2e tests took 153.0 s with the real `sleep` and
#: 103.5 s with this one (medians of 3, interleaved, 2026-09-27).
#: STUB_SLEEP_LOG, when set, records each request.
_SLEEP_STUB = """#!/bin/sh
if [ -n "$STUB_SLEEP_LOG" ]; then echo "$*" >> "$STUB_SLEEP_LOG"; fi
case "$1" in
  0|0.*) exec {sleep} "$1" ;;
esac
exec {sleep} 1
"""


def install_sleep_stub(stubs: Path, real: str | None = None, text: str = _SLEEP_STUB) -> Path:
    """Put the capped `sleep` in ``stubs``, calling the real one by absolute path."""
    real = real or shutil.which("sleep")
    assert real, "no sleep on PATH to cap"
    path = stubs / "sleep"
    path.write_text(text.replace("{sleep}", real), encoding="utf-8")
    path.chmod(0o755)
    return path


@slow("runs the stubbed e2e runs' sleep under sh")
class SleepStubTest(unittest.TestCase):
    """The cap is what makes the stubbed e2e runs cheap, and nothing else in
    them would notice it gone: a full-length `sleep` only makes them slower."""

    REQUESTS = ("5", "2", "1", "0.2", "30")

    def passed_on(self, text: str = _SLEEP_STUB) -> list[str]:
        """What the stub asks of the real `sleep`, which here only records it."""
        stubs = Path(tempfile.mkdtemp(prefix="veridor-sleep-stub-"))
        self.addCleanup(shutil.rmtree, stubs, True)
        record = stubs / "real-sleep"
        record.write_text(f'#!/bin/sh\necho "$*" >> "{stubs}/asked"\n', encoding="utf-8")
        record.chmod(0o755)
        stub = install_sleep_stub(stubs, real=str(record), text=text)
        for seconds in self.REQUESTS:
            subprocess.run(["sh", str(stub), seconds], check=True, timeout=10,
                           env={"PATH": "/usr/bin:/bin", "STUB_SLEEP_LOG": str(stubs / "requested")})
        self.assertEqual((stubs / "requested").read_text(encoding="utf-8").split(), list(self.REQUESTS))
        return (stubs / "asked").read_text(encoding="utf-8").split()

    def test_every_wait_is_capped_at_one_second_and_shorter_ones_pass_through(self) -> None:
        self.assertEqual(self.passed_on(), ["1", "1", "1", "0.2", "1"])

    def test_control_without_the_cap_the_full_waits_reach_the_real_sleep(self) -> None:
        uncapped = _SLEEP_STUB.replace('exec {sleep} 1\n', 'exec {sleep} "$1"\n')
        self.assertEqual(_SLEEP_STUB.count('exec {sleep} 1\n'), 1, "the mutation no longer applies")
        self.assertEqual(self.passed_on(uncapped), list(self.REQUESTS))


@slow("runs the e2e script under bash against stub kubectl/helm/kind/docker")
class E2EScriptExitCodeTest(unittest.TestCase):
    """Exit 1 means "a row mismatched", so a run that dies in setup must not
    exit 1. It did: on a new kind cluster the Argo Rollouts apply hit
    "etcdserver: request timed out" and the script exited 1. Here the cluster
    tools are stubs that succeed, except the one step each test breaks."""

    STUB = "#!/bin/sh\n{body}\n"

    def run_with_stubs(self, *, kind_load_fails: bool) -> subprocess.CompletedProcess[str]:
        stubs = Path(tempfile.mkdtemp(prefix="veridor-e2e-stubs-"))
        self.addCleanup(shutil.rmtree, stubs, True)
        bodies = {
            # `create -f -` is the lock namespace: read the manifest, succeed.
            "kubectl": 'case "$*" in *"get-contexts -o name"*) echo kind-stub ;; '
                       '*"create -f -"*) cat >/dev/null ;; esac; exit 0',
            "kind": 'case "$1" in get) echo stub ;; load) exit {load} ;; esac; exit 0'.format(
                load=1 if kind_load_fails else 0),
            "helm": "exit 0",
            "docker": "exit 0",
        }
        for name, body in bodies.items():
            path = stubs / name
            path.write_text(self.STUB.format(body=body), encoding="utf-8")
            path.chmod(0o755)
        (stubs / "python3").symlink_to(sys.executable)
        install_sleep_stub(stubs)
        self.sleep_log = stubs / "sleep.log"
        env = {
            "PATH": f"{stubs}:/usr/bin:/bin",
            "HOME": str(stubs),
            "KUBE_CONTEXT": "kind-stub",
            "E2E_BUILD_IMAGE": "0",
            "E2E_SCENARIOS": "plain",
            "E2E_TIMEOUT": "1",
            "E2E_WORKDIR": str(stubs / "work"),
            "STUB_SLEEP_LOG": str(self.sleep_log),
        }
        return subprocess.run(["bash", str(E2E_SCRIPT)], capture_output=True, text=True,
                              env=env, timeout=120, check=False)

    def test_a_setup_failure_exits_3_and_names_the_step(self) -> None:
        result = self.run_with_stubs(kind_load_fails=True)
        self.assertEqual(result.returncode, 3, result.stderr[-2000:])
        self.assertIn("stopped before the result table", result.stderr)
        self.assertIn("kind load docker-image", result.stderr)
        self.assertIn("Nothing was concluded", result.stderr)

    def test_a_mismatch_still_exits_1(self) -> None:
        """The control: with setup passing, the stubbed cluster never
        completes a Job, every row is a Timeout mismatch, and the exit is 1."""
        result = self.run_with_stubs(kind_load_fails=False)
        self.assertEqual(result.returncode, 1, result.stderr[-2000:])
        self.assertIn("MISMATCH", result.stdout + result.stderr)
        self.assertNotIn("stopped before the result table", result.stderr)
        # The script's waits went through the capped `sleep`, not /bin/sleep:
        # every row timed out, so each of its wait loops asked for one.
        requested = self.sleep_log.read_text(encoding="utf-8").split()
        self.assertTrue(any(float(seconds) > 1 for seconds in requested), requested)


_LOCK_STUB = r"""#!{python}
# A kubectl that keeps one namespace, vg-e2e-lock, in $STUB_STATE/lock.json,
# answers everything else with success, and logs every call.
import datetime, json, os, sys

args = sys.argv[1:]
state = os.environ["STUB_STATE"]
with open(os.path.join(state, "calls.log"), "a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\n")
rest, index = [], 0
while index < len(args):
    if args[index] in ("--context", "--kubeconfig"):
        index += 2
        continue
    rest.append(args[index])
    index += 1
lock = os.path.join(state, "lock.json")
if rest[:2] == ["config", "get-contexts"]:
    print("kind-stub")
elif rest == ["create", "-f", "-"]:
    document = json.load(sys.stdin)
    if os.path.exists(lock):
        sys.stderr.write('Error from server (AlreadyExists): namespaces "vg-e2e-lock" already exists\n')
        sys.exit(1)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    document["metadata"]["creationTimestamp"] = now
    for path in (lock, os.path.join(state, "lock-created.json")):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
elif rest[:3] == ["get", "namespace", "vg-e2e-lock"]:
    if not os.path.exists(lock):
        sys.stderr.write('Error from server (NotFound): namespaces "vg-e2e-lock" not found\n')
        sys.exit(1)
    with open(lock, encoding="utf-8") as handle:
        document = json.load(handle)
    output = rest[rest.index("-o") + 1]
    if output == "json":
        print(json.dumps(document))
    else:
        run_id = document["metadata"]["annotations"].get("vg-e2e/run-id", "")
        sys.stdout.write(os.environ.get("STUB_FOREIGN_RUN_ID") or run_id)
elif rest[:3] == ["delete", "namespace", "vg-e2e-lock"]:
    if os.path.exists(lock):
        os.remove(lock)
elif rest[:2] == ["get", "crd"] and os.environ.get("STUB_NO_ARGO"):
    sys.exit(1)
"""


def readme_block(path: Path, needle: str) -> str:
    """The one fenced code block of a README that contains ``needle`` -- the
    same extraction scripts/e2e_kubernetes.sh uses to run a README's flow."""
    text = path.read_text(encoding="utf-8")
    blocks = [block for block in re.findall(r"^```[a-z]*\n(.*?)^```$", text, re.S | re.M) if needle in block]
    if len(blocks) != 1:
        raise AssertionError(f"{path}: {len(blocks)} fenced blocks contain {needle!r}, expected 1")
    return blocks[0]


#: A kubectl that keeps Jobs the way the API server treats them in the plain
#: flow: `apply` of a Job that exists prints "unchanged" and changes nothing,
#: `delete` removes it, and a new Job runs one poll and then ends as
#: $STUB_OUTCOME (Complete, Failed, or Vanishes: deleted before it is read).
#: `get -o jsonpath=...` renders the two expressions the flows read, the uid
#: and the True conditions; `--ignore-not-found` turns NotFound into nothing.
#: Failure modes, each measured on kind or a way the flow can be misused:
#:   STUB_DELETE=forbidden  delete refused (an identity without delete on
#:                          Jobs), the Job kept
#:   STUB_DELETE=noop       delete exits 0 and deletes nothing
#:   STUB_APPLY=immutable   apply refused ("field is immutable"), Job kept
#:   STUB_REPLACE=1         while the flow waits, another run replaces the
#:                          Job under the same name; the new one completes
#: `apply -f FILE` of an empty FILE fails as kubectl does.
_FLOW_STUB = r"""#!{python}
import json, os, sys

state_dir = os.environ["STUB_STATE"]
with open(os.path.join(state_dir, "calls.log"), "a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
rest, index, output, apply_file = [], 1, "", None
ignore_missing = False
while index < len(sys.argv):
    arg = sys.argv[index]
    if arg in ("-n", "--namespace", "--context", "--kubeconfig"):
        index += 2
        continue
    if arg == "-o":
        output = sys.argv[index + 1]
        index += 2
        continue
    if arg == "-f":
        apply_file = sys.argv[index + 1]
        index += 2
        continue
    if arg == "--ignore-not-found":
        ignore_missing = True
    elif not arg.startswith("--as="):
        rest.append(arg)
    index += 1
path = os.path.join(state_dir, "jobs.json")
state = json.load(open(path)) if os.path.exists(path) else {"uid": 0, "jobs": {}}
jobs, name, verb = state["jobs"], os.environ["STUB_JOB"], rest[0]
status = 0
CONDITIONS = '{.status.conditions[?(@.status=="True")].type}'
if verb == "delete":
    if os.environ.get("STUB_DELETE") == "forbidden":
        sys.stderr.write('Error from server (Forbidden): jobs.batch "%s" is forbidden: User "ci" cannot delete '
                         'resource "jobs" in API group "batch"\n' % name)
        status = 1
    elif os.environ.get("STUB_DELETE") == "noop":
        pass
    elif jobs.pop(name, None):
        print('job.batch "%s" deleted' % name)
elif verb == "apply":
    if apply_file is not None and not open(apply_file, encoding="utf-8").read().strip():
        sys.stderr.write("error: no objects passed to apply\n")
        status = 1
    elif os.environ.get("STUB_APPLY") == "immutable":
        sys.stderr.write('The Job "%s" is invalid: spec.template: Invalid value: field is immutable\n' % name)
        status = 1
    elif name in jobs:
        print("job.batch/%s unchanged" % name)
    else:
        state["uid"] += 1
        jobs[name] = {"uid": state["uid"], "polls": 1, "outcome": os.environ["STUB_OUTCOME"]}
        print("job.batch/%s created" % name)
elif verb in ("get", "wait", "logs"):
    job = jobs.get(name)
    if job and job["polls"] == 0 and job["outcome"] == "Vanishes":
        del jobs[name]
        job = None
    if job is None:
        if not (verb == "get" and ignore_missing):
            sys.stderr.write('Error from server (NotFound): jobs.batch "%s" not found\n' % name)
            status = 1
    elif verb == "get":
        if not output.startswith("jsonpath="):
            sys.exit("stub: get without -o jsonpath=")
        template = output[len("jsonpath="):]
        if CONDITIONS in template:
            if os.environ.get("STUB_REPLACE") and not state.get("replaced"):
                state["uid"] += 1
                state["replaced"] = True
                job = jobs[name] = {"uid": state["uid"], "polls": 0, "outcome": "Complete"}
            if job["polls"]:
                job["polls"] -= 1
                conditions = ""
            else:
                conditions = {"Complete": "SuccessCriteriaMet Complete", "Failed": "FailureTarget Failed"}[job["outcome"]]
            template = template.replace(CONDITIONS, conditions)
        rendered = template.replace("{.metadata.uid}", str(job["uid"]))
        if "{" in rendered:
            sys.exit("stub: jsonpath it does not render: " + rendered)
        sys.stdout.write(rendered)
    elif verb == "wait":
        if job["polls"] == 0 and job["outcome"] == "Complete":
            print("job.batch/%s condition met" % name)
        else:
            sys.stderr.write("error: timed out waiting for the condition on jobs/%s\n" % name)
            status = 1
    else:
        print("log of job %s, uid %d" % (name, job["uid"]))
json.dump(state, open(path, "w"))
sys.exit(status)
"""


def unchecked(block: str) -> str:
    """A README flow with its step checks and uid binding taken out: the
    block as it read before it had them (scripts/e2e_kubernetes.sh
    unchecked_block does the same, for its live control)."""
    kept = [line for line in block.splitlines()
            if not line.startswith(("old=", "uid=", 'if [ -z "$uid" ]')) and 'in "$uid "*)' not in line]
    assert len(kept) == len(block.splitlines()) - 4, "not the checked block"
    text = "\n".join(kept) + "\n"
    assert text.count(" || exit 1") >= 2, "not the checked block"
    return text.replace(" || exit 1", "").replace("{.metadata.uid} {.status", "{.status")


def run_documented_flow(case: unittest.TestCase, block: str, job: str, outcome: str,
                        existing: str | None = None, **modes: str) -> tuple[int, list[str], dict[str, Any]]:
    """Run a README's flow under `sh` (no -e) against _FLOW_STUB (and a helm
    that prints a manifest, or with STUB_HELM=fail prints nothing and fails).
    ``existing`` seeds a finished Job from an earlier run (Complete or
    Failed). ``modes`` are the stub's STUB_* failure modes. Returns the exit
    status, the kubectl calls, and the Jobs left behind."""
    stubs = Path(tempfile.mkdtemp(prefix="veridor-flow-"))
    case.addCleanup(shutil.rmtree, stubs, True)
    state = stubs / "state"
    state.mkdir()
    (state / "calls.log").write_text("", encoding="utf-8")
    if existing:
        (state / "jobs.json").write_text(json.dumps(
            {"uid": 1, "jobs": {job: {"uid": 1, "polls": 0, "outcome": existing}}}), encoding="utf-8")
    (stubs / "kubectl").write_text(_FLOW_STUB.replace("{python}", sys.executable), encoding="utf-8")
    (stubs / "helm").write_text('#!/bin/sh\n[ "$STUB_HELM" = fail ] && { echo "Error: values refused" >&2; exit 1; }\n'
                                "echo 'kind: Job'\n", encoding="utf-8")
    (stubs / "sleep").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for name in ("kubectl", "helm", "sleep"):
        (stubs / name).chmod(0o755)
    (stubs / "flow.sh").write_text(block, encoding="utf-8")
    env = {"PATH": f"{stubs}:/usr/bin:/bin", "HOME": str(stubs), "STUB_STATE": str(state),
           "STUB_JOB": job, "STUB_OUTCOME": outcome, "STUB_HELM": "",
           **{f"STUB_{key.upper()}": value for key, value in modes.items()}}
    result = subprocess.run(["sh", str(stubs / "flow.sh")], capture_output=True, text=True, env=env,
                            cwd=stubs, timeout=60, check=False)
    case.assertNotIn("stub:", result.stderr, "the stub was asked for something it does not model")
    calls = (state / "calls.log").read_text(encoding="utf-8").splitlines()
    jobs_path = state / "jobs.json"
    jobs = json.loads(jobs_path.read_text(encoding="utf-8"))["jobs"] if jobs_path.exists() else {}
    return result.returncode, calls, jobs


class _StubbedE2E(unittest.TestCase):
    """The e2e script against stub kubectl/helm/kind/docker; see _LOCK_STUB."""

    def setUp(self) -> None:
        self.stubs = Path(tempfile.mkdtemp(prefix="veridor-e2e-lock-"))
        self.addCleanup(shutil.rmtree, self.stubs, True)
        self.state = self.stubs / "state"
        self.state.mkdir()
        (self.stubs / "kubectl").write_text(_LOCK_STUB.replace("{python}", sys.executable), encoding="utf-8")
        for name, body in {"kind": 'case "$1" in get) echo stub ;; load) exit "${STUB_KIND_LOAD:-1}" ;; esac; exit 0',
                           "helm": 'echo "$*" >> "$STUB_STATE/helm.log"; exit 0', "docker": "exit 0"}.items():
            (self.stubs / name).write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        for name in ("kubectl", "kind", "helm", "docker"):
            (self.stubs / name).chmod(0o755)
        (self.stubs / "python3").symlink_to(sys.executable)
        install_sleep_stub(self.stubs)

    def seed_lock(self, age_seconds: int, run_id: str = "someone-else-1") -> dict[str, Any]:
        created = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=age_seconds)
        document = {"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": "vg-e2e-lock", "creationTimestamp": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "annotations": {"vg-e2e/holder": "alice@build-7", "vg-e2e/host": "build-7",
                            "vg-e2e/pid": "4242", "vg-e2e/started-at": "2026-09-24T01:02:03Z",
                            "vg-e2e/run-id": run_id}}}
        (self.state / "lock.json").write_text(json.dumps(document), encoding="utf-8")
        return document

    def run_script(self, script: Path = E2E_SCRIPT, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {"PATH": f"{self.stubs}:/usr/bin:/bin", "HOME": str(self.stubs), "KUBE_CONTEXT": "kind-stub",
               "E2E_BUILD_IMAGE": "0", "E2E_SCENARIOS": "plain", "E2E_TIMEOUT": "1",
               "E2E_WORKDIR": str(self.stubs / "work"), "STUB_STATE": str(self.state), **extra}
        return subprocess.run(["bash", str(script)], capture_output=True, text=True,
                              env=env, timeout=120, check=False)

    def calls(self) -> list[str]:
        path = self.state / "calls.log"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def deletes(self) -> list[str]:
        return [call for call in self.calls() if " delete " in f" {call} "]

    def helm_calls(self) -> list[str]:
        path = self.state / "helm.log"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


@slow("runs the e2e script under bash against stub kubectl/helm/kind/docker")
class E2EContextPinTest(_StubbedE2E):
    """The behavioural half of test_it_never_uses_the_current_context: the
    stubs log the arguments of every kubectl and helm call the script makes,
    so a context-less call is caught however it is spelled, on every path the
    stubbed run reaches. The static scan covers the paths it does not."""

    #: Calls that read only local files: the kubeconfig, chart packaging, and
    #: the chart README's hook.mode none block rendering with `helm template`
    #: (no --validate, so no cluster), which the plain scenario runs verbatim.
    LOCAL_KUBECTL = ("config get-contexts -o name",)
    LOCAL_HELM = ("package ", "repo index ", "template gate ./veridor-gate ")

    def unpinned(self) -> tuple[list[str], list[str]]:
        kubectl = [call for call in self.calls()
                   if "--context" not in call.split() and call not in self.LOCAL_KUBECTL]
        helm = [call for call in self.helm_calls()
                if "--kube-context" not in call.split() and not call.startswith(self.LOCAL_HELM)]
        return kubectl, helm

    def test_every_cluster_call_names_the_context(self) -> None:
        # The scenarios that reach the result table under the stubs, then the
        # ones that stop part-way (a stub cannot answer their waits) -- each
        # still makes its setup calls and the cleanup's. kustomize stopped
        # part-way while it served an Argo CD overlay from Git; it has none.
        runs = (("plain helm rollouts psa", 1), ("kustomize", 1), ("argocd", 3), ("wait", 3))
        for scenarios, status in runs:
            with self.subTest(scenarios=scenarios):
                for log in ("calls.log", "helm.log", "lock.json"):
                    (self.state / log).unlink(missing_ok=True)
                result = self.run_script(E2E_SCENARIOS=scenarios, STUB_KIND_LOAD="0")
                self.assertEqual(result.returncode, status, result.stderr[-1500:])
                self.assertGreater(len(self.calls()), 40, "the stubbed run made few kubectl calls")
                self.assertTrue(self.helm_calls(), "the stubbed run made no helm calls")
                self.assertEqual(self.unpinned(), ([], []))

    def test_an_unpinned_call_is_caught(self) -> None:
        """The control: the cleanup's namespace delete without its wrapper,
        written in a form the old static scan missed, is caught here."""
        text = E2E_SCRIPT.read_text(encoding="utf-8")
        line = '    k delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true\n'
        self.assertEqual(text.count(line), 1, "the mutation no longer applies")
        tree = self.stubs / "tree"
        (tree / "scripts").mkdir(parents=True)
        (tree / "deploy").symlink_to(ROOT / "deploy", target_is_directory=True)
        (tree / "scripts" / "demo_server.py").symlink_to(ROOT / "scripts" / "demo_server.py")
        copy = tree / "scripts" / "e2e_kubernetes.sh"
        copy.write_text(text.replace(line, line.replace("    k delete", "    if kubectl delete").replace(
            " || true\n", "; then :; fi\n")), encoding="utf-8")
        self.run_script(copy, STUB_KIND_LOAD="0")
        kubectl, _ = self.unpinned()
        self.assertIn("delete namespace vg-e2e-plain --ignore-not-found --wait=false", kubectl)


def shell_function(name: str, text: str | None = None) -> str:
    """The body of one function of scripts/e2e_kubernetes.sh, `name() {`
    through the first line that is exactly `}`."""
    text = E2E_SCRIPT.read_text(encoding="utf-8") if text is None else text
    start = text.index(f"\n{name}() {{\n") + 1
    return text[start:text.index("\n}\n", start) + 3]


class E2EArgoCdJobStaticTest(unittest.TestCase):
    """REGRESSION: the argocd scenario read the gate Job by one name fixed in
    advance (<release>-veridor-gate), and job_exit took the uid it found under
    that name at read time: nothing tied the Job to the sync just started.
    With a fixed name Argo CD itself reported syncs from the previous sync's
    Job; the chart now has none (generateName), so every read goes through
    sync_job, which takes the name this sync's syncResult records and checks
    the Job was created after the operation started."""

    TEXT = E2E_SCRIPT.read_text(encoding="utf-8")

    def test_no_argo_cd_gate_job_is_read_by_a_name_fixed_in_advance(self) -> None:
        body = shell_function("scenario_argocd", self.TEXT) + shell_function("argocd_rolling_leg", self.TEXT)
        self.assertNotIn("-veridor-gate\"", body)
        self.assertEqual(body.count('sync_job "$NS_ARGOCD"\n  job="$SYNC_JOB"\n'), 4)
        for line in body.splitlines():
            if "wait_job" in line or "job_exit" in line or "show_job_log" in line:
                with self.subTest(line=line.strip()):
                    self.assertIn('"$job"', line)
        # Control: the scenario as it was reads a name built from releaseName.
        self.assertIn('-veridor-gate"', 'job="$(k create --dry-run=client -o jsonpath=... -f example)-veridor-gate"')

    def test_the_scenario_renders_helm_mode_through_argo_cd(self) -> None:
        """K8S-LATE-1: Argo CD must fail to render the helm-mode chart, and
        the row reads the chart's own refusal, not any ComparisonError: the
        literal-credential row just before leaves one standing, so the wait
        is for this text. Its control is the same Application opted in."""
        body = shell_function("scenario_argocd", self.TEXT)
        helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
        refusal = "veridor-gate: hook.mode is helm, and this render reached no cluster"
        self.assertIn(refusal, helpers)
        self.assertIn('error="$(comparison_error "hook.mode is helm, and this render reached no cluster")"', body)
        self.assertIn(f'*"{refusal}"*', body)
        self.assertIn('record "argocd: helm-mode gate chart" "ComparisonError, refusal named"', body)
        self.assertIn('record "argocd: control, helm-mode chart with allowRenderWithoutCluster" "rendered"', body)
        self.assertIn('{"allowRenderWithoutCluster": True}', body)
        # No sync is started on either: a helm-mode Job under Argo CD is the
        # fixed-name hook the refusal exists to prevent.
        section = body[body.index("app-helm-mode"):body.index("comparison_clears")]
        self.assertNotIn("sync_application", section)
        comparison = shell_function("comparison_error", self.TEXT)
        self.assertIn('[[ -z "$needle" || "$message" == *"$needle"* ]]', comparison)

    def test_the_rows_that_pin_the_mechanism(self) -> None:
        for row in ('record "argocd: PostSync hook in syncResult (vulnerable)" "this sync\'s Job, ${prefix}*, Failed"',
                    'record "argocd: PostSync hook in syncResult (fixed)" "this sync\'s Job, ${prefix}*, Succeeded"',
                    'record "argocd: each sync\'s gate Job, by name" "7 syncs, 7 Jobs, all ${prefix}*"',
                    'record "argocd: Helm CLI install of the argocd-mode chart" "refused at render, no Job, no release"',
                    'record "argocd: sync vs vulnerable target" "Failed" "$phase"',
                    'record "argocd: sync vs fixed target" "Succeeded" "$phase"',
                    'record "argocd: Recreate app, fixed -> vulnerable: sync" "Failed" "$phase"',
                    'record "argocd: RollingUpdate, .Release.Revision label: fixed sync" "Succeeded" "$ROLL_PHASE"',
                    'record "argocd: RollingUpdate, pod-template label: fixed sync" "Succeeded" "$ROLL_PHASE"',
                    'record "argocd: pod-template label: vulnerable sync: sync" "Failed" "$ROLL_PHASE"'):
            with self.subTest(row=row):
                self.assertIn(row, self.TEXT)
        # 3 syncs in scenario_argocd and 4 rolling legs: the count the row states.
        self.assertEqual(shell_function("scenario_argocd", self.TEXT).count("phase=\"$(sync_application)\""), 3)
        self.assertEqual(shell_function("scenario_argocd_rolling", self.TEXT).count("argocd_rolling_leg "), 4)


class E2EWorkflowGroupsTest(unittest.TestCase):
    """The CI job runs the script's scenarios in groups, one kind cluster per
    group: the whole script ran longer than the job's timeout allowed for
    (measured). A scenario left out of every group would read as tested and
    run nowhere, and one in two groups would run twice."""

    def groups(self, workflow: dict[str, Any]) -> list[list[str]]:
        job = workflow["jobs"]["kubernetes-e2e"]
        step = job["steps"][-1]
        self.assertEqual(step["env"]["E2E_SCENARIOS"], "${{ matrix.scenarios }}")
        return [group.split() for group in job["strategy"]["matrix"]["scenarios"]]

    def scenarios(self) -> list[str]:
        match = re.search(r'E2E_SCENARIOS="\$\{E2E_SCENARIOS:-([a-z ]+)\}"', E2E_SCRIPT.read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        return match.group(1).split()

    def problems(self, groups: list[list[str]]) -> list[str]:
        flat = [name for group in groups for name in group]
        found = [f"{name}: in no group" for name in self.scenarios() if name not in flat]
        found += [f"{name}: in {flat.count(name)} groups" for name in sorted(set(flat)) if flat.count(name) > 1]
        found += [f"{name}: not a scenario" for name in sorted(set(flat) - set(self.scenarios()))]
        return found

    def test_every_scenario_runs_in_exactly_one_group(self) -> None:
        workflow = load_yaml(ROOT / ".github" / "workflows" / "veridor.yml")
        groups = self.groups(workflow)
        self.assertEqual(self.problems(groups), [])
        self.assertIs(workflow["jobs"]["kubernetes-e2e"]["strategy"].get("fail-fast"), False)

    def test_control_a_dropped_or_doubled_scenario_is_named(self) -> None:
        groups = self.groups(load_yaml(ROOT / ".github" / "workflows" / "veridor.yml"))
        dropped = [[name for name in group if name != "argocd"] for group in groups]
        self.assertEqual(self.problems(dropped), ["argocd: in no group"])
        self.assertEqual(self.problems(groups + [["kustomize"]]), ["kustomize: in 2 groups"])


@slow("spawns helm")
class E2EHelmSettleTest(_HelmCase):
    """REGRESSION: the helm scenario's settle loop, after each `helm upgrade`
    of the app chart with the gate as a dependency, waited for exactly one pod
    labelled app.kubernetes.io/instance=shop. The gate's pod carries that
    label too and stays until the next upgrade, so the loop never saw one pod
    and ran to E2E_TIMEOUT on every leg (measured on kind: the legs' gates ran
    304 to 318 s apart, about 20 of the scenario's 21 minutes, which put the
    whole script past the CI job's 30)."""

    def test_the_gate_pod_carries_the_release_label(self) -> None:
        """The premise, rendered: under release `shop` the gate's pod has
        instance=shop, and not the demo app's name label the loop now adds."""
        values = self.tmp / "shop.json"
        values.write_text(json.dumps(without_cluster(base_values(hook={"mode": "helm"}))), encoding="utf-8")
        result = self.helm("template", "shop", str(CHART), "-f", str(values))
        self.assertEqual(result.returncode, 0, result.stderr)
        job = next(d for d in load_yaml_documents(result.stdout) if d["kind"] == "Job")
        labels = job["spec"]["template"]["metadata"]["labels"]
        self.assertEqual(labels["app.kubernetes.io/instance"], "shop")
        self.assertNotEqual(labels.get("app.kubernetes.io/name"), "vg-e2e-demo-target")

    def test_the_settle_loop_selects_the_app_s_pods_only(self) -> None:
        body = shell_function("shop_leg")
        self.assertIn("get pods -l app.kubernetes.io/instance=shop,app.kubernetes.io/name=vg-e2e-demo-target", body)
        self.assertNotIn("get pods -l app.kubernetes.io/instance=shop -o json", body)
        # The demo chart labels its pods with that name.
        self.assertIn("app.kubernetes.io/name: vg-e2e-demo-target", shell_function("write_demo_chart"))


@slow("runs the e2e script's sync_job under bash against a stub kubectl")
class E2ESyncJobTest(unittest.TestCase):
    """sync_job, extracted from the script and run against a stub `k`: it
    must return the Job this sync's syncResult names only when that Job was
    created at or after the operation's startedAt."""

    STARTED = "2026-09-25T02:14:31Z"

    def pick(self, function: str, hooks: list[str], created: dict[str, str]) -> str:
        app = {"status": {"operationState": {"startedAt": self.STARTED, "syncResult": {"resources": [
            {"kind": "Job", "name": name, "hookType": "PostSync", "hookPhase": "Failed"} for name in hooks] + [
            {"kind": "ConfigMap", "name": "gate-veridor-gate-config"}]}}}}
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.json").write_text(json.dumps(app), encoding="utf-8")
            (Path(tmp) / "created.json").write_text(json.dumps(created), encoding="utf-8")
            script = (
                "set -Eeuo pipefail\n"
                "log() { printf '==> %s\\n' \"$*\" >&2; }\n"
                f"k() {{\n  case \"$*\" in\n    *'get application'*) cat {tmp}/app.json ;;\n"
                f"    *'get job '*) python3 -c 'import json, sys; c = json.load(open(sys.argv[1])); n = sys.argv[2];"
                f" print(c[n]) if n in c else sys.exit(1)' {tmp}/created.json \"$5\" ;;\n"
                "    *) exit 9 ;;\n  esac\n}\n"
                "ARGO_APP=vg-e2e-gate\nARGO_SYNC_JOBS=()\nSYNC_JOB=none\n"
                + function +
                'sync_job vg-e2e-argocd\nsync_job vg-e2e-argocd\necho "$SYNC_JOB ${ARGO_SYNC_JOBS[*]}"\n')
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, check=False,
                                    env={**os.environ, "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"})
        self.assertEqual(result.returncode, 0, result.stderr)
        job, *recorded = result.stdout.split()
        self.assertEqual(recorded, [job, job], "each call must be recorded in ARGO_SYNC_JOBS")
        return job

    def cases(self, function: str) -> dict[str, str]:
        name = "gate-veridor-gate-0.1.0-e-postsync-1790302471"
        return {
            "created after the sync started": self.pick(function, [name], {name: "2026-09-25T02:14:33Z"}),
            "created in the second it started": self.pick(function, [name], {name: self.STARTED}),
            "left by an earlier sync": self.pick(function, [name], {name: "2026-09-25T02:13:58Z"}),
            "gone": self.pick(function, [name], {}),
            "two PostSync Jobs": self.pick(function, [name, name + "x"], {name: "2026-09-25T02:14:33Z"}),
            "no PostSync Job": self.pick(function, [], {}),
        }

    def test_only_a_job_created_by_this_sync_is_taken(self) -> None:
        name = "gate-veridor-gate-0.1.0-e-postsync-1790302471"
        self.assertEqual(self.cases(shell_function("sync_job")), {
            "created after the sync started": name, "created in the second it started": name,
            "left by an earlier sync": "none", "gone": "none", "two PostSync Jobs": "none", "no PostSync Job": "none"})

    def test_control_without_the_time_check_an_earlier_job_is_taken(self) -> None:
        """The mutation control: the same function with the creationTimestamp
        comparison removed takes the Job an earlier sync left, which is the
        read the fixed name made possible."""
        function = shell_function("sync_job")
        check = ' && -n "$created" && ! "$created" < "$started" ]]'
        self.assertEqual(function.count(check), 1, "the mutation no longer applies")
        mutated = function.replace(check, ' && -n "$created" ]]')
        self.assertEqual(self.cases(mutated)["left by an earlier sync"], "gate-veridor-gate-0.1.0-e-postsync-1790302471")


@slow("runs the e2e script under bash against a stub kubectl that keeps the lock namespace")
class E2ELockTest(_StubbedE2E):
    """Two runs against one cluster deleted each other's vg-e2e-* namespaces
    (measured with two concurrent runs on kind-veridor-demo). The script now takes an
    in-cluster lock -- creating the vg-e2e-lock namespace, which the API server
    does atomically -- before it touches anything, and a second run exits 2
    naming the holder without deleting anything."""

    def test_a_run_takes_the_lock_first_and_releases_it_last(self) -> None:
        result = self.run_script()
        # kind load fails in the stub: a setup failure, after the lock.
        self.assertEqual(result.returncode, 3, result.stderr[-1500:])
        calls = self.calls()
        created = next(i for i, call in enumerate(calls) if call.endswith("create -f -"))
        first_delete = next(i for i, call in enumerate(calls) if " delete " in f" {call} ")
        self.assertLess(created, first_delete, "something was deleted before the lock was taken")
        lock = json.loads((self.state / "lock-created.json").read_text(encoding="utf-8"))
        notes = lock["metadata"]["annotations"]
        self.assertEqual(lock["metadata"]["name"], "vg-e2e-lock")
        for key in ("holder", "host", "pid", "started-at", "run-id"):
            self.assertTrue(notes.get(f"vg-e2e/{key}"), key)
        self.assertRegex(notes["vg-e2e/started-at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        released = [i for i, call in enumerate(calls) if "delete namespace vg-e2e-lock" in call]
        cleanup = [i for i, call in enumerate(calls) if "delete namespace vg-e2e-" in call
                   and "vg-e2e-lock" not in call]
        self.assertEqual(len(released), 1, calls)
        self.assertGreater(released[0], max(cleanup), "the lock was released before the cleanup")
        self.assertFalse((self.state / "lock.json").exists())
        self.assertIn("lock: released vg-e2e-lock", result.stderr)

    def test_a_second_run_exits_2_naming_the_holder_and_deletes_nothing(self) -> None:
        before = self.seed_lock(age_seconds=30)
        result = self.run_script()
        self.assertEqual(result.returncode, 2, result.stderr[-1500:])
        for fragment in ("another run holds the lock namespace vg-e2e-lock", "alice@build-7",
                         "pid 4242", "started-at 2026-09-24T01:02:03Z", "someone-else-1",
                         "E2E_BREAK_LOCK=1"):
            self.assertIn(fragment, result.stderr)
        self.assertEqual(self.deletes(), [], "a refused run deleted something")
        self.assertEqual(json.loads((self.state / "lock.json").read_text(encoding="utf-8")), before)
        self.assertNotIn("stopped before the result table", result.stderr)

    def test_a_stale_lock_is_broken_only_with_e2e_break_lock(self) -> None:
        self.seed_lock(age_seconds=7200)
        result = self.run_script()
        self.assertEqual(result.returncode, 2, result.stderr[-1500:])
        self.assertEqual(self.deletes(), [])
        broken = self.run_script(E2E_BREAK_LOCK="1")
        self.assertIn("lock: breaking vg-e2e-lock", broken.stderr)
        self.assertEqual(broken.returncode, 3, broken.stderr[-1500:])  # on to the stubbed setup failure
        calls = self.calls()
        self.assertIn("delete namespace vg-e2e-lock", calls[next(
            i for i, call in enumerate(calls) if " delete " in f" {call} ")])
        self.assertFalse((self.state / "lock.json").exists(), "the new lock was not released")

    def test_a_young_lock_is_not_broken_even_on_request(self) -> None:
        self.seed_lock(age_seconds=60)
        result = self.run_script(E2E_BREAK_LOCK="1")
        self.assertEqual(result.returncode, 2, result.stderr[-1500:])
        self.assertIn("E2E_BREAK_LOCK=1 does not break it", result.stderr)
        self.assertEqual(self.deletes(), [])

    def test_a_lock_that_is_no_longer_this_run_s_is_left_alone(self) -> None:
        result = self.run_script(STUB_FOREIGN_RUN_ID="a-run-that-broke-ours")
        self.assertEqual(result.returncode, 3, result.stderr[-1500:])
        self.assertIn("is no longer this run's", result.stderr)
        self.assertNotIn("delete namespace vg-e2e-lock", "\n".join(self.calls()))
        self.assertTrue((self.state / "lock.json").exists())


@slow("runs the e2e script under bash against stub kubectl/helm/kind/docker")
class E2EExitTrapTest(_StubbedE2E):
    """Only the result table is a result. Measured on macOS bash 3.2: the
    script was edited while a run was in progress, bash hit a syntax error
    part-way through the file, the exit trap saw status 0, and the run exited 0
    with no table (bash 5.2 exits 2 on the same file, which read as a refusal)."""

    def corrupted_copy(self) -> Path:
        tree = self.stubs / "tree"
        (tree / "scripts").mkdir(parents=True)
        (tree / "deploy").symlink_to(ROOT / "deploy", target_is_directory=True)
        (tree / "scripts" / "demo_server.py").symlink_to(ROOT / "scripts" / "demo_server.py")
        text = E2E_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(text.count("\nprint_table\n"), 1, "the corruption no longer applies")
        copy = tree / "scripts" / "e2e_kubernetes.sh"
        copy.write_text(text.replace("\nprint_table\n", '\necho "unterminated\n'), encoding="utf-8")
        return copy

    def test_a_run_that_never_prints_the_table_does_not_exit_0(self) -> None:
        result = self.run_script(self.corrupted_copy(), STUB_KIND_LOAD="0")
        self.assertIn("unexpected EOF", result.stderr)
        self.assertEqual(result.returncode, 3, result.stderr[-1500:])
        self.assertIn("stopped before the result table", result.stderr)
        self.assertNotIn("row(s),", result.stdout)

    def test_the_control_the_same_run_uncorrupted_prints_the_table(self) -> None:
        result = self.run_script(STUB_KIND_LOAD="0")
        self.assertEqual(result.returncode, 1, result.stderr[-1500:])  # stub Jobs never finish
        self.assertIn("row(s),", result.stdout)

    def test_a_pinned_manifest_mismatch_is_still_a_refusal(self) -> None:
        manifests = self.stubs / "manifests"
        manifests.mkdir()
        (manifests / "argocd-core-install-v3.5.3.yaml").write_text("not the pinned file\n", encoding="utf-8")
        result = self.run_script(STUB_NO_ARGO="1", E2E_ARGO_MANIFEST_DIR=str(manifests))
        self.assertEqual(result.returncode, 2, result.stderr[-1500:])
        self.assertIn("Not applying it", result.stderr)
        self.assertNotIn("stopped before the result table", result.stderr)


if __name__ == "__main__":
    unittest.main()
