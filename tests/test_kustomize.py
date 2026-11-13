"""The Kustomize packaging of the gate: deploy/kustomize/veridor-gate.

It is a second, hand-written copy of the Job the Helm chart renders, and two
hand-maintained copies of a security-relevant manifest drift apart silently: a
Job that retries, runs as root or mounts a token still runs and still "gates".
So the slow tests render both -- `kubectl kustomize` and `helm template` -- and
compare the Job specs field by field, with a mutation control showing that the
comparison notices a changed uid, retry count or privilege setting.

Two tiers. The fast tests read the files with the YAML subset reader from
tests/test_helm_chart.py. The slow tests spawn kubectl (and helm); without
kubectl they skip, unless VERIDOR_REQUIRE_KUBECTL=1, which turns the skip into
a failure so a CI job meant to run them cannot pass by not having kubectl.
VERIDOR_REQUIRE_HELM=1 does the same for helm.

The live behaviour -- a Job against a vulnerable and a fixed target -- is
measured by the `kustomize` scenario of scripts/e2e_kubernetes.sh, not here.
There is no Argo CD overlay: Kustomize refuses the generateName an Argo CD
hook Job needs (NoArgoCdOverlayTest).
"""

from __future__ import annotations

import copy
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

from test_helm_chart import (  # noqa: E402
    assert_restricted, load_yaml, load_yaml_documents, readme_block, run_documented_flow, unchecked,
)
from tiers import slow  # noqa: E402

KUSTOMIZE = ROOT / "deploy" / "kustomize" / "veridor-gate"
BASE = KUSTOMIZE / "base"
OVERLAYS = {"plain": KUSTOMIZE / "overlays" / "plain"}
COMPONENT = KUSTOMIZE / "components" / "service-account"
CHART = ROOT / "deploy" / "helm" / "veridor-gate"
#: Removed: a fixed-name PostSync Job, which Argo CD v3.5.3 reported syncs from.
REMOVED = (KUSTOMIZE / "overlays" / "argocd", ROOT / "deploy" / "argocd" / "application-kustomize-example.yaml")
E2E_SCRIPT = ROOT / "scripts" / "e2e_kubernetes.sh"
REQUIRE_KUBECTL_ENV = "VERIDOR_REQUIRE_KUBECTL"
REQUIRE_HELM_ENV = "VERIDOR_REQUIRE_HELM"

_MISSING = object()


def differences(left: Any, right: Any, path: str = "") -> list[str]:
    """Every path at which two parsed documents differ."""
    if isinstance(left, dict) and isinstance(right, dict):
        found: list[str] = []
        for key in sorted(set(left) | set(right)):
            found += differences(left.get(key, _MISSING), right.get(key, _MISSING), f"{path}.{key}")
        return found
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        found = []
        for index, (a, b) in enumerate(zip(left, right)):
            found += differences(a, b, f"{path}[{index}]")
        return found
    return [] if left == right else [path or "."]


def comparable_job_spec(job: dict[str, Any]) -> dict[str, Any]:
    """The Job spec with what legitimately differs between the two renders
    removed: pod-template metadata (Helm labels and a config checksum
    annotation; Kustomize labels) and the ConfigMap's name (Helm's
    <release>-veridor-gate-config, Kustomize's hash-suffixed one)."""
    spec = copy.deepcopy(job["spec"])
    spec["template"].pop("metadata", None)
    for volume in spec["template"]["spec"]["volumes"]:
        if "configMap" in volume:
            volume["configMap"]["name"] = "<the configuration ConfigMap>"
    return spec


def base_job() -> dict[str, Any]:
    return load_yaml(BASE / "job.yaml")


def base_config() -> dict[str, Any]:
    return json.loads((BASE / "veridor.json").read_text(encoding="utf-8"))


def chart_values_for_the_base(mode: str) -> dict[str, Any]:
    """Helm values describing the same gate the Kustomize base describes: its
    configuration, and its Secret-backed env entries as secretEnv."""
    container = base_job()["spec"]["template"]["spec"]["containers"][0]
    secret_env = [
        {"name": entry["name"], "secretName": entry["valueFrom"]["secretKeyRef"]["name"],
         "key": entry["valueFrom"]["secretKeyRef"]["key"]}
        for entry in container["env"]
        if "valueFrom" in entry
    ]
    return {"hook": {"mode": mode}, "config": base_config(), "secretEnv": secret_env}


# ---------------------------------------------------------------------------
# Fast tier: the files, read and parsed. No kubectl, no helm, no subprocess.
# ---------------------------------------------------------------------------


class KustomizeFilesTest(unittest.TestCase):
    def test_every_referenced_file_exists(self) -> None:
        for directory in (BASE, *OVERLAYS.values(), COMPONENT):
            kustomization = load_yaml(directory / "kustomization.yaml")
            referenced = list(kustomization.get("resources") or [])
            referenced += list(kustomization.get("components") or [])
            for generator in kustomization.get("configMapGenerator") or []:
                referenced += generator.get("files") or []
            self.assertTrue(referenced, directory)
            for name in referenced:
                with self.subTest(kustomization=str(directory.relative_to(ROOT)), ref=name):
                    self.assertTrue((directory / name).exists())

    def test_the_base_waits_for_the_target_like_the_chart_default(self) -> None:
        """The race of a Job started as soon as a rollout completes (measured
        with a PostSync hook that started before the Service routed to the new
        pod) applies to the plain Job as to the chart, and the chart parity
        test compares the rendered args."""
        args = base_job()["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertEqual(args[args.index("--wait-for-target") + 1], "60")
        # The e2e control patches args/5 and args/6 (--fail-on and its value);
        # the wait was appended after them so those indexes still hold.
        self.assertEqual(args[5:7], ["--fail-on", "new+confirmed"])

    def test_the_base_job_is_never_retried_and_bounded(self) -> None:
        spec = base_job()["spec"]
        self.assertEqual(spec["backoffLimit"], 0)
        self.assertEqual(spec["activeDeadlineSeconds"], 600)
        self.assertEqual(spec["ttlSecondsAfterFinished"], 3600)
        self.assertEqual(spec["template"]["spec"]["restartPolicy"], "Never")

    def test_the_base_pod_is_restricted(self) -> None:
        pod = base_job()["spec"]["template"]["spec"]
        assert_restricted(self, pod, pod["containers"][0])
        self.assertIs(pod["enableServiceLinks"], False)
        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertIn("emptyDir", volumes["work"])
        self.assertIn("emptyDir", volumes["tmp"])

    def test_credentials_come_only_from_secrets(self) -> None:
        container = base_job()["spec"]["template"]["spec"]["containers"][0]
        literal = {entry["name"] for entry in container["env"] if "value" in entry}
        self.assertEqual(literal, {"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"})
        for entry in container["env"]:
            if "valueFrom" in entry:
                self.assertEqual(set(entry["valueFrom"]), {"secretKeyRef"}, entry["name"])
                self.assertIs(entry["valueFrom"]["secretKeyRef"]["optional"], True)

    def test_every_reference_in_the_example_configuration_has_an_env_entry(self) -> None:
        """The chart refuses to render when a ${NAME} has no secretEnv entry;
        Kustomize cannot refuse, so the shipped example is held to it here."""
        container = base_job()["spec"]["template"]["spec"]["containers"][0]
        provided = {entry["name"] for entry in container["env"]}
        referenced = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
                                    (BASE / "veridor.json").read_text(encoding="utf-8")))
        self.assertTrue(referenced)
        self.assertEqual(referenced - provided, set())

    def test_the_example_configuration_loads_and_carries_no_literal_credential(self) -> None:
        from veridor import capsule, core  # noqa: PLC0415

        self.assertEqual(capsule.literal_credentials(base_config()), [])
        env = {name: f"value-{name.lower()}" for name in
               ("VERIDOR_OWNER_TOKEN", "VERIDOR_OUTSIDER_TOKEN", "VERIDOR_ADMIN_TOKEN")}
        with mock.patch.dict(os.environ, env):
            loaded = core.load_config(BASE / "veridor.json")
        self.assertEqual(len(loaded["checks"]), 2)

    def test_the_plain_overlay_adds_nothing(self) -> None:
        plain = load_yaml(OVERLAYS["plain"] / "kustomization.yaml")
        self.assertEqual(plain, {"apiVersion": "kustomize.config.k8s.io/v1beta1",
                                 "kind": "Kustomization", "resources": ["../../base"]})

    def test_the_image_is_labelled_the_release_s(self) -> None:
        """Until the first tag no image was published, and the base and the
        README said so. From the tag on, the base names the image a release
        publishes, and both say how to run another."""
        job = (BASE / "job.yaml").read_text(encoding="utf-8")
        self.assertIn("The image each release publishes", job)
        self.assertNotIn("placeholder", job.lower())
        readme = " ".join((KUSTOMIZE / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("Each release tag publishes the `ghcr.io/veridor-authz/veridor` image the base names", readme)
        self.assertNotRegex(readme, r"(?i)not published|placeholder")


class NoArgoCdOverlayDocumentTest(unittest.TestCase):
    """REGRESSION: overlays/argocd rendered the gate as a PostSync hook with
    one fixed name and BeforeHookCreation, and Argo CD v3.5.3 reported syncs
    from the previous sync's Job (measured with the chart's Job named the same
    way: passing syncs reported Failed; this overlay's e2e leg reported a
    passing sync Failed). Argo CD's remedy, generateName, is one Kustomize
    refuses (KustomizeRenderTest), so the overlay and the Application example
    built on it are gone, and nothing may point a reader at them."""

    def test_the_overlay_and_its_example_are_gone(self) -> None:
        for path in REMOVED:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertFalse(path.exists())

    def test_nothing_a_reader_follows_points_at_them(self) -> None:
        # The Kustomize README names the overlay to say why there is none.
        self.assertEqual(pointers_to_the_removed_overlay(ROOT),
                         [("deploy/kustomize/veridor-gate/README.md", "overlays/argocd")])
        raw = (KUSTOMIZE / "README.md").read_text(encoding="utf-8")
        self.assertIn("\n## No Argo CD overlay\n", raw)
        readme = " ".join(raw.split())
        self.assertIn("missing metadata.name", readme)
        self.assertIn("take the gate from the Helm chart", readme)

    def test_control_the_scan_finds_a_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deploy" / "argocd").mkdir(parents=True)
            (root / "deploy" / "argocd" / "README.md").write_text(
                "Without Helm, application-kustomize-example.yaml is the same Application.\n", encoding="utf-8")
            (root / "README.md").write_text("resources:\n  - ../veridor-gate/overlays/argocd\n", encoding="utf-8")
            self.assertEqual(pointers_to_the_removed_overlay(root),
                             [("README.md", "overlays/argocd"),
                              ("deploy/argocd/README.md", "application-kustomize-example")])


#: What a reader of the repository follows: the READMEs, the docs, the
#: shipped manifests and the CI templates.
READERS = ("README.md", "docs", "deploy", "ci", "action.yml", "templates")


def pointers_to_the_removed_overlay(root: Path) -> list[tuple[str, str]]:
    found = []
    for name in READERS:
        top = root / name
        if not top.exists():
            continue
        for path in [top] if top.is_file() else sorted(p for p in top.rglob("*") if p.is_file()):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for needle in ("overlays/argocd", "application-kustomize-example"):
                if needle in text:
                    found.append((path.relative_to(root).as_posix(), needle))
    return found


class E2EKustomizeScenarioStaticTest(unittest.TestCase):
    TEXT = E2E_SCRIPT.read_text(encoding="utf-8")

    def test_the_scenario_is_known_and_on_by_default(self) -> None:
        self.assertRegex(self.TEXT, r'E2E_SCENARIOS="\$\{E2E_SCENARIOS:-[a-z ]*\bkustomize\b[a-z ]*\}"')
        self.assertRegex(self.TEXT, r"plain \| helm \| argocd \| rollouts \| psa \| kustomize( \| [a-z]+)*\)")
        self.assertIn("scenario_kustomize()", self.TEXT)

    def test_it_renders_the_shipped_overlay_and_no_argo_cd_one(self) -> None:
        self.assertIn("deploy/kustomize/veridor-gate", self.TEXT)
        self.assertIn("veridor-gate/overlays/plain", self.TEXT)
        self.assertNotIn("overlays/argocd", self.TEXT)
        self.assertNotIn("application-kustomize-example", self.TEXT)


class PlainFlowDocumentTest(unittest.TestCase):
    """The plain overlay's flow as documented. REGRESSION: the README and the
    overlay said `kubectl apply -k` then `kubectl wait
    --for=condition=Complete`. A Job runs once; re-applied unchanged it
    prints "unchanged", and the wait read the previous run's Complete: on
    kind a gate that had passed passed again after the target was redeployed
    vulnerable, without running."""

    README = KUSTOMIZE / "README.md"

    def block(self) -> str:
        return readme_block(self.README, "apply -k my-overlay/")

    def test_the_readme_deletes_the_previous_job_first(self) -> None:
        lines = [line.strip() for line in self.block().splitlines()]
        self.assertEqual(lines[0], "old=\"$(kubectl get job veridor-gate --ignore-not-found "
                                   "-o jsonpath='{.metadata.uid}')\" || exit 1")
        self.assertEqual(lines[1], "kubectl delete job veridor-gate --ignore-not-found --wait=true || exit 1")
        self.assertEqual(lines[2], "kubectl apply -k my-overlay/ || exit 1")

    def test_every_step_before_the_wait_is_checked(self) -> None:
        """REGRESSION: the README let this block run without `set -e`, and
        there a refused delete fell through to `apply` ("unchanged") and the
        wait read the previous run's Complete (measured on kind, as an
        identity without delete on Jobs, under plain `sh`). Every step now
        stops the block itself, and the wait is bound to the new Job's uid."""
        lines = [line.strip() for line in self.block().splitlines()]
        wait = next(i for i, line in enumerate(lines) if line.startswith("while "))
        for line in lines[:wait]:
            if not line.startswith("if "):
                with self.subTest(line=line):
                    self.assertTrue(line.endswith(" || exit 1"), line)
        self.assertIn('if [ -z "$uid" ] || [ "$uid" = "$old" ]; then', self.block())
        self.assertIn('{.metadata.uid} {.status.conditions', lines[wait])
        self.assertIn('case "$outcome " in "$uid "*) ;; *) outcome=""; break ;; esac', lines)
        self.assertNotIn("set -e", self.block())

    def test_it_waits_for_this_run_s_complete_or_failed(self) -> None:
        block = self.block()
        self.assertNotIn("kubectl wait", block)
        self.assertIn("kubectl get job veridor-gate", block)
        self.assertIn('*" Complete "* | *" Failed "*) break', block)
        self.assertEqual(block.strip().splitlines()[-1].strip(),
                         'case " $outcome " in *" Complete "*) true ;; *) false ;; esac')

    def test_the_overlay_comment_carries_the_same_flow(self) -> None:
        comment = [line[4:] for line in (OVERLAYS["plain"] / "kustomization.yaml").read_text(
            encoding="utf-8").splitlines() if line.startswith("#   ")]
        self.assertEqual(comment, self.block().strip().splitlines())

    def test_the_e2e_runs_this_block(self) -> None:
        text = E2E_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('readme_block "${ROOT}/deploy/kustomize/veridor-gate/README.md" "apply -k my-overlay/"', text)
        self.assertIn('run_readme_flow "$flow" "${WORK}/readme-plain-flow.sh"', text)
        self.assertIn('exec sh "$script"', text)
        # As an identity that cannot delete Jobs, with the unchecked block as
        # its control; and the chart README's block in the plain scenario.
        self.assertIn('run_readme_flow "$flow" "${WORK}/readme-plain-flow.sh" "${WORK}/flow.log" '
                      '"${WORK}/readme-kubectl-nodelete"', text)
        self.assertIn('run_readme_flow "$flow" "${WORK}/readme-plain-flow-previous.sh" "${WORK}/flow.log" '
                      '"${WORK}/readme-kubectl-nodelete"', text)
        self.assertIn('unchecked_block "${WORK}/readme-plain-flow.sh" "${WORK}/readme-plain-flow-previous.sh"', text)
        self.assertIn('readme_block "${CHART_DIR}/README.md" "delete job gate-veridor-gate-r1" "${WORK}/chart-flow.sh"', text)
        self.assertIn('run_readme_flow "$flow" "${WORK}/chart-flow.sh" "${WORK}/chart-flow.log" '
                      '"${WORK}/chart-kubectl-nodelete"', text)


@slow("runs the README's plain-overlay flow under sh against a stub kubectl")
class PlainFlowTest(unittest.TestCase):
    def block(self) -> str:
        return readme_block(KUSTOMIZE / "README.md", "apply -k my-overlay/")

    def test_a_previous_passing_job_is_not_read_as_this_run(self) -> None:
        status, calls, jobs = run_documented_flow(self, self.block(), "veridor-gate", "Failed", existing="Complete")
        self.assertEqual(status, 1, calls)
        self.assertEqual(jobs["veridor-gate"]["uid"], 2, "the flow read the previous run's Job")

    def test_this_run_s_outcome_decides(self) -> None:
        for outcome, existing, expected in (("Complete", None, 0), ("Complete", "Failed", 0),
                                            ("Complete", "Complete", 0), ("Failed", None, 1),
                                            ("Vanishes", None, 1)):
            with self.subTest(outcome=outcome, existing=existing):
                status, calls, _ = run_documented_flow(self, self.block(), "veridor-gate", outcome,
                                                       existing=existing)
                self.assertEqual(status, expected, calls)

    def test_control_the_old_flow_reads_the_previous_job(self) -> None:
        """The stub reproduces the measured defect with the flow the README
        documented before: apply, then wait for Complete, exits 0 on a run
        that failed, because the Job it reads is the earlier one."""
        old = ("kubectl apply -k my-overlay/\n"
               "kubectl wait --for=condition=Complete job/veridor-gate --timeout=10m\n")
        status, calls, jobs = run_documented_flow(self, old, "veridor-gate", "Failed", existing="Complete")
        self.assertEqual(status, 0, calls)
        self.assertIn("apply -k my-overlay/", calls)
        self.assertEqual(jobs["veridor-gate"]["uid"], 1)

    def test_a_step_that_fails_stops_the_flow_and_its_control_passes_stale(self) -> None:
        """REGRESSION (measured on kind, as an identity that may create and
        patch Jobs but not delete them, the block under plain `sh`): the
        delete was refused, `apply` printed "unchanged" (or, after a config
        change, "field is immutable"), and the block exited 0 on the previous
        run's Complete against a vulnerable target. Each mode: exit 1, the
        previous Job left alone. The control, the block without its step
        checks and uid binding (as it read before), exits 0 on that Job."""
        for mode in ({"delete": "forbidden"}, {"delete": "noop"},
                     {"delete": "forbidden", "apply": "immutable"}, {"replace": "1"}):
            with self.subTest(mode=mode):
                status, calls, jobs = run_documented_flow(self, self.block(), "veridor-gate", "Failed",
                                                          existing="Complete", **mode)
                self.assertEqual(status, 1, calls)
                if "replace" not in mode:
                    self.assertEqual(jobs["veridor-gate"]["uid"], 1, calls)
                status, calls, _ = run_documented_flow(self, unchecked(self.block()), "veridor-gate", "Failed",
                                                       existing="Complete", **mode)
                self.assertEqual(status, 0, f"the control no longer reproduces the defect: {calls}")

    def test_the_unchecked_control_is_the_previous_block(self) -> None:
        self.assertEqual(unchecked(self.block()), PREVIOUS_BLOCK)


#: The README's plain-overlay block before it checked its steps.
PREVIOUS_BLOCK = """kubectl delete job veridor-gate --ignore-not-found --wait=true
kubectl apply -k my-overlay/
while outcome="$(kubectl get job veridor-gate -o jsonpath='{.status.conditions[?(@.status=="True")].type}')"; do
  case " $outcome " in *" Complete "* | *" Failed "*) break ;; esac
  sleep 5
done
kubectl logs job/veridor-gate
case " $outcome " in *" Complete "*) true ;; *) false ;; esac
"""


# ---------------------------------------------------------------------------
# Slow tier: `kubectl kustomize`, compared with `helm template`.
# ---------------------------------------------------------------------------


class _RenderCase(unittest.TestCase):
    def require(self, tool: str, env: str) -> None:
        if shutil.which(tool) is None:
            if os.environ.get(env) == "1":
                self.fail(f"{tool} is not on PATH and {env}=1 says these tests must run")
            self.skipTest(f"{tool} is not on PATH (set {env}=1 to make this a failure)")

    def setUp(self) -> None:
        self.require("kubectl", REQUIRE_KUBECTL_ENV)
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-kustomize-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def kustomize(self, directory: Path) -> dict[str, dict[str, Any]]:
        result = subprocess.run(["kubectl", "kustomize", str(directory)],
                                capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {document["kind"]: document for document in load_yaml_documents(result.stdout)}

    def helm(self, values: dict[str, Any]) -> dict[str, dict[str, Any]]:
        self.require("helm", REQUIRE_HELM_ENV)
        path = self.tmp / f"values-{len(list(self.tmp.glob('values-*')))}.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        result = subprocess.run(["helm", "template", "gate", str(CHART), "-f", str(path)],
                                capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {document["kind"]: document for document in load_yaml_documents(result.stdout)}

    def copy_tree(self) -> Path:
        destination = self.tmp / "veridor-gate"
        shutil.copytree(KUSTOMIZE, destination)
        return destination

    def drift(self, overlay: Path, mode: str) -> list[str]:
        """Where the rendered Kustomize Job differs from the chart's."""
        chart_job = self.helm(chart_values_for_the_base(mode))["Job"]
        kustomize_job = self.kustomize(overlay)["Job"]
        return differences(comparable_job_spec(chart_job), comparable_job_spec(kustomize_job))


@slow("spawns kubectl kustomize and helm")
class KustomizeRenderTest(_RenderCase):
    def test_each_overlay_renders_a_job_and_its_configuration(self) -> None:
        for name, overlay in OVERLAYS.items():
            with self.subTest(overlay=name):
                documents = self.kustomize(overlay)
                self.assertEqual(set(documents), {"Job", "ConfigMap"})
                config_map = documents["ConfigMap"]["metadata"]["name"]
                self.assertRegex(config_map, r"^veridor-gate-config-[a-z0-9]{10}$")
                volumes = documents["Job"]["spec"]["template"]["spec"]["volumes"]
                self.assertIn(config_map, [v.get("configMap", {}).get("name") for v in volumes])
                self.assertEqual(json.loads(documents["ConfigMap"]["data"]["veridor.json"]),
                                 base_config())

    def test_the_plain_overlay_is_no_hook(self) -> None:
        plain = self.kustomize(OVERLAYS["plain"])["Job"]["metadata"]
        self.assertNotIn("annotations", plain)
        self.assertEqual(plain["name"], "veridor-gate")

    def test_kustomize_refuses_the_generate_name_an_argo_cd_hook_needs(self) -> None:
        """Why there is no Argo CD overlay. Measured with kubectl's Kustomize
        v5.7.1 and the one bundled in Argo CD v3.5.3 (v5.8.1): a Job with only
        generateName is refused, in a base or after a patch that removes the
        name. If this starts passing, an overlay with generateName can be
        measured through Argo CD again."""
        tree = self.copy_tree()
        base_job = tree / "base" / "job.yaml"
        text = base_job.read_text(encoding="utf-8")
        self.assertEqual(text.count("  name: veridor-gate\n"), 1, "the mutation no longer applies")
        base_job.write_text(text.replace("  name: veridor-gate\n", "  generateName: veridor-gate-\n"), encoding="utf-8")
        result = subprocess.run(["kubectl", "kustomize", str(tree / "overlays" / "plain")],
                                capture_output=True, text=True, timeout=60, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout[:400])
        self.assertIn("missing metadata.name", result.stderr)
        # A patch that removes the name, on the shipped base: refused as well.
        patched = self.tmp / "patched"
        shutil.copytree(KUSTOMIZE, patched)
        (patched / "mine").mkdir()
        (patched / "mine" / "kustomization.yaml").write_text(
            "resources:\n  - ../overlays/plain\n"
            "patches:\n  - target: {kind: Job, name: veridor-gate}\n    patch: |-\n"
            "      - op: remove\n        path: /metadata/name\n"
            "      - op: add\n        path: /metadata/generateName\n        value: veridor-gate-\n",
            encoding="utf-8")
        result = subprocess.run(["kubectl", "kustomize", str(patched / "mine")],
                                capture_output=True, text=True, timeout=60, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout[:400])
        self.assertIn("missing metadata.name", result.stderr)
        # The control: the same tree with the name renders.
        self.assertEqual(self.kustomize(KUSTOMIZE / "overlays" / "plain")["Job"]["metadata"]["name"], "veridor-gate")

    def test_the_arguments_parse_with_the_real_cli(self) -> None:
        from veridor import cli  # noqa: PLC0415

        container = self.kustomize(OVERLAYS["plain"])["Job"]["spec"]["template"]["spec"]["containers"][0]
        parsed = cli._parser().parse_args(container["args"])
        self.assertEqual(parsed.command, "run")
        self.assertEqual(str(parsed.config), "/config/veridor.json")
        self.assertEqual(parsed.fail_on, "new+confirmed")
        self.assertTrue(parsed.require_complete)
        self.assertTrue(parsed.prove_liveness)
        self.assertEqual(parsed.wait_for_target, 60)

    def test_a_user_overlay_replaces_the_configuration(self) -> None:
        tree = self.copy_tree()
        overlay = tree / "mine"
        overlay.mkdir()
        mine = dict(base_config(), target={"base_url": "http://orders.shop.svc:8080"})
        (overlay / "veridor.json").write_text(json.dumps(mine, indent=2) + "\n", encoding="utf-8")
        (overlay / "kustomization.yaml").write_text(
            "resources:\n  - ../overlays/plain\n"
            "images:\n  - name: ghcr.io/veridor-authz/veridor\n    newName: registry.example/veridor\n    newTag: 9.9.9\n"
            "configMapGenerator:\n  - name: veridor-gate-config\n    behavior: replace\n"
            "    files:\n      - veridor.json\n",
            encoding="utf-8",
        )
        documents = self.kustomize(overlay)
        self.assertEqual(json.loads(documents["ConfigMap"]["data"]["veridor.json"]), mine)
        pod = documents["Job"]["spec"]["template"]["spec"]
        self.assertEqual(pod["containers"][0]["image"], "registry.example/veridor:9.9.9")
        config_volume = next(v for v in pod["volumes"] if v["name"] == "config")
        self.assertEqual(config_volume["configMap"]["name"], documents["ConfigMap"]["metadata"]["name"])

    def test_the_service_account_component(self) -> None:
        tree = self.copy_tree()
        overlay = tree / "mine"
        overlay.mkdir()
        (overlay / "kustomization.yaml").write_text(
            "resources:\n  - ../overlays/plain\n"
            "components:\n  - ../components/service-account\n"
            "nameSuffix: -orders\n",
            encoding="utf-8",
        )
        documents = self.kustomize(overlay)
        account = documents["ServiceAccount"]
        self.assertEqual(account["metadata"]["name"], "veridor-gate-orders")
        self.assertIs(account["automountServiceAccountToken"], False)
        pod = documents["Job"]["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "veridor-gate-orders")
        self.assertIs(pod["automountServiceAccountToken"], False)


@slow("spawns kubectl kustomize")
class ReadmeOverlayTest(_RenderCase):
    """REGRESSION: the README's "Use it" overlay repointed VERIDOR_OWNER_TOKEN
    to its own Secret and nothing else. Measured with kubectl's Kustomize
    v5.7.1: the env entries merge by name, so VERIDOR_OUTSIDER_TOKEN and
    VERIDOR_ADMIN_TOKEN still read veridor-gate-credentials, and an adopter
    who created only the Secret the example names got exit 2 (measured on the
    host: "environment variable 'VERIDOR_OUTSIDER_TOKEN' is not set"). The
    block is built here, as written."""

    def env(self, overlay: str) -> list[dict[str, Any]]:
        """The README block beside a copy of the tree, as its comment says
        (`../veridor-gate/overlays/plain`)."""
        root = self.tmp / overlay
        shutil.copytree(KUSTOMIZE, root / "veridor-gate")
        mine = root / "my-overlay"
        mine.mkdir()
        block = readme_block(KUSTOMIZE / "README.md", "# kustomization.yaml")
        self.assertIn(f"../veridor-gate/overlays/{overlay}", block)
        (mine / "kustomization.yaml").write_text(block, encoding="utf-8")
        shutil.copy(BASE / "veridor.json", mine / "veridor.json")
        return self.kustomize(mine)["Job"]["spec"]["template"]["spec"]["containers"][0]["env"]

    def test_the_readme_overlay_keeps_every_variable_and_repoints_them_together(self) -> None:
        base_env = base_job()["spec"]["template"]["spec"]["containers"][0]["env"]
        for overlay in ("plain",):
            with self.subTest(overlay=overlay):
                env = self.env(overlay)
                self.assertEqual(sorted(e["name"] for e in env), sorted(e["name"] for e in base_env))
                secrets = {e["valueFrom"]["secretKeyRef"]["name"] for e in env if "valueFrom" in e}
                self.assertEqual(secrets, {"invoices-gate-credentials"})
                referenced = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", json.dumps(base_config())))
                self.assertLessEqual(referenced, {e["name"] for e in env if "valueFrom" in e})


@slow("spawns kubectl kustomize and helm")
class ChartParityTest(_RenderCase):
    """The Kustomize Job and the chart's Job are the same Job."""

    def test_the_plain_overlay_is_the_chart_in_none_mode(self) -> None:
        self.assertEqual(self.drift(OVERLAYS["plain"], "none"), [])

    def test_the_named_fields_agree(self) -> None:
        """Asserted by name as well, so a failure says which one moved."""
        chart = self.helm(chart_values_for_the_base("none"))["Job"]
        mine = self.kustomize(OVERLAYS["plain"])["Job"]
        chart_pod, pod = chart["spec"]["template"]["spec"], mine["spec"]["template"]["spec"]
        self.assertEqual(pod["securityContext"], chart_pod["securityContext"])
        self.assertEqual(pod["containers"][0]["securityContext"],
                         chart_pod["containers"][0]["securityContext"])
        self.assertEqual(mine["spec"]["backoffLimit"], chart["spec"]["backoffLimit"])

    def test_the_comparison_notices_drift(self) -> None:
        """The mutation control. Each edit to a copy of the Kustomize base is
        one a reviewer could miss; the comparison must name the field."""
        mutations = {
            "pod runs as root": (
                "        runAsUser: 10001\n        runAsGroup: 10001\n        fsGroup: 10001\n",
                "        runAsUser: 0\n        runAsGroup: 10001\n        fsGroup: 10001\n",
                ".template.spec.securityContext.runAsUser",
            ),
            "the Job retries": ("  backoffLimit: 0\n", "  backoffLimit: 2\n", ".backoffLimit"),
            "privilege escalation allowed": (
                "            allowPrivilegeEscalation: false\n",
                "            allowPrivilegeEscalation: true\n",
                ".template.spec.containers[0].securityContext.allowPrivilegeEscalation",
            ),
            "token mounted": (
                "      automountServiceAccountToken: false\n",
                "      automountServiceAccountToken: true\n",
                ".template.spec.automountServiceAccountToken",
            ),
        }
        for name, (before, after, field) in mutations.items():
            with self.subTest(mutation=name):
                tree = self.copy_tree()
                job = tree / "base" / "job.yaml"
                text = job.read_text(encoding="utf-8")
                self.assertEqual(text.count(before), 1, "the mutation no longer applies")
                job.write_text(text.replace(before, after), encoding="utf-8")
                self.assertIn(field, self.drift(tree / "overlays" / "plain", "none"))
                shutil.rmtree(tree)


if __name__ == "__main__":
    unittest.main()
