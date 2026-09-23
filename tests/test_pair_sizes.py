"""scripts/pair_sizes.py: what the pairs download, read from the registry.

Every test answers the script's registry requests from FakeRegistry, an
opener that serves manifests from a table and records each request, so
nothing here reaches a network (the fast tier's guard would fail it if it
did). The script was run against the real registries once; `buildx imagetools
inspect` agreed with it on the one image compared.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import itertools
import json
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

SCRIPT = ROOT / "scripts" / "pair_sizes.py"
_LOADS = itertools.count()
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
TOKEN = "fake-anonymous-token-9d1c"


def load_script():
    spec = importlib.util.spec_from_file_location(f"pair_sizes_under_test_{next(_LOADS)}", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def layer(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


class FakeRegistry:
    """urlopen for the script: token URLs answer TOKEN, manifest URLs answer
    from `manifests` ((host, repository, digest) -> bytes), anything else 404."""

    def __init__(self) -> None:
        self.manifests: dict[tuple[str, str, str], bytes] = {}
        self.releases: dict[tuple[str, str], list[dict]] = {}
        self.requests: list = []

    def release(self, name: str, version: str, files: dict[str, int]) -> dict[str, str]:
        """PyPI's JSON for one release: {filename: size}; returns each file's sha256."""
        hashes = {filename: hashlib.sha256(f"{name}/{filename}".encode()).hexdigest() for filename in files}
        self.releases[(name, version)] = [{"filename": filename, "size": size, "digests": {"sha256": hashes[filename]}}
                                          for filename, size in files.items()]
        return hashes

    def add(self, host: str, repository: str, document: dict) -> str:
        body = json.dumps(document).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        self.manifests[(host, repository, digest)] = body
        return digest

    def image(self, host: str, repository: str, platforms: dict[str, list[tuple[str, int]]]) -> str:
        """An index over one manifest per platform, plus an attestation entry
        (unknown/unknown), the way buildkit publishes; its digest."""
        entries = []
        for platform, layers in platforms.items():
            os_, arch, *variant = platform.split("/")
            manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST,
                        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                   "digest": layer(f"config-{repository}-{platform}"), "size": 900},
                        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                                    "digest": digest, "size": size} for digest, size in layers]}
            entries.append({"mediaType": OCI_MANIFEST, "digest": self.add(host, repository, manifest), "size": 500,
                            "platform": {"os": os_, "architecture": arch, **({"variant": variant[0]} if variant else {})}})
        attestation = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "layers": [{"digest": layer("att"), "size": 1}]}
        entries.append({"mediaType": OCI_MANIFEST, "digest": self.add(host, repository, attestation), "size": 400,
                        "platform": {"os": "unknown", "architecture": "unknown"}})
        return self.add(host, repository, {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries})

    def __call__(self, request) -> bytes:
        self.requests.append(request)
        url = urllib.parse.urlsplit(request.full_url)
        if url.path.endswith("/token"):
            return json.dumps({"token": TOKEN}).encode()
        if url.hostname == "pypi.org":
            _, _, name, version, _ = url.path.split("/")
            if (name, version) not in self.releases:
                raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)
            return json.dumps({"urls": self.releases[(name, version)]}).encode()
        repository, _, digest = url.path.removeprefix("/v2/").rpartition("/manifests/")
        body = self.manifests.get((url.hostname, repository, digest))
        if body is None:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)
        return body

    def hosts(self) -> set[str]:
        return {urllib.parse.urlsplit(request.full_url).hostname for request in self.requests}


def pair(name: str, image: str, vulnerable: str, patched: str) -> dict:
    return {"name": name, "image": image, "vulnerable": "1.0", "patched": "1.1",
            "vulnerable_digest": vulnerable, "patched_digest": patched}


class UnionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.script = load_script()

    def registry(self, base: tuple[str, str]) -> tuple[FakeRegistry, list[dict]]:
        """Two repositories, two builds each. `base` names the layer each
        repository's first build starts from."""
        fake = FakeRegistry()
        hub = "registry-1.docker.io"
        a1 = fake.image(hub, "acme/app", {"linux/amd64": [(layer(base[0]), 100), (layer("a1"), 10)]})
        a2 = fake.image(hub, "acme/app", {"linux/amd64": [(layer(base[0]), 100), (layer("a2"), 20)]})
        b1 = fake.image("ghcr.io", "acme/other", {"linux/amd64": [(layer(base[1]), 100), (layer("b1"), 5)]})
        b2 = fake.image("ghcr.io", "acme/other", {"linux/amd64": [(layer("b2"), 7)]})
        # Three pairs over two images, the way the three Gitea pairs share one.
        pairs = [pair("app-one", "acme/app", a1, a2), pair("other", "ghcr.io/acme/other", b1, b2),
                 pair("app-two", "acme/app", a1, a2)]
        return fake, pairs

    def test_a_layer_shared_by_two_builds_or_two_images_is_counted_once(self) -> None:
        fake, pairs = self.registry(("base", "base"))
        result = self.script.measure(pairs, "linux/amd64", fake)
        totals = {entry["name"]: entry["bytes"] for entry in result["pairs"]}
        # Each pair: its two builds share `base`, counted once.
        self.assertEqual(totals, {"app-one": 130, "other": 112, "app-two": 130})
        self.assertEqual([side["bytes"] for side in result["pairs"][0]["sides"]], [110, 120])
        # The union: `base` once across both repositories, and app's two
        # images once though two pairs name them.
        self.assertEqual(result["union"], {"bytes": 142, "layers": 5, "images_measured": 4, "images": 4,
                                           "complete": True})
        text = self.script.render(result)
        self.assertIn("every pair together: 142 bytes (0.00 GB), 4 images, 5 distinct layers", text)
        self.assertIn("sum of the pair totals: 372 bytes", text)
        self.assertNotIn("PARTIAL", text)
        # An image two pairs name is read once: one index and one platform
        # manifest per image, one token per repository.
        manifests = [r.full_url for r in fake.requests if "/manifests/" in r.full_url]
        self.assertEqual(len(manifests), 8)
        self.assertEqual(len(manifests), len(set(manifests)))
        self.assertEqual(sum("/token" in r.full_url for r in fake.requests), 2)

    def test_control_without_a_shared_layer_the_union_is_the_plain_sum(self) -> None:
        """The same registry with the two repositories' first builds on
        different bases: the union gains exactly the 100 bytes they shared, so
        the 142 above came from counting that layer once across repositories.
        No pair total moves, because no pair holds both repositories."""
        fake, pairs = self.registry(("base-a", "base-b"))
        result = self.script.measure(pairs, "linux/amd64", fake)
        self.assertEqual(result["union"]["bytes"], 242)
        self.assertEqual(result["union"]["layers"], 6)
        self.assertEqual({entry["name"]: entry["bytes"] for entry in result["pairs"]},
                         {"app-one": 130, "other": 112, "app-two": 130})


class PlatformTest(unittest.TestCase):
    def setUp(self) -> None:
        self.script = load_script()
        self.fake = FakeRegistry()
        layers = {"linux/amd64": [(layer("x86"), 1000)], "linux/arm64": [(layer("arm64"), 2000)],
                  "linux/arm/v6": [(layer("v6"), 6)], "linux/arm/v7": [(layer("v7"), 7)]}
        index = self.fake.image("registry-1.docker.io", "vikunja/vikunja", layers)
        self.pairs = [pair("p", "vikunja/vikunja", index, index)]

    def measure(self, platform: str) -> dict:
        return self.script.measure(self.pairs, platform, self.fake)

    def test_the_platform_asked_for_is_the_one_measured(self) -> None:
        for platform, size in (("linux/amd64", 1000), ("linux/arm64", 2000), ("linux/arm/v7", 7), ("linux/arm/v6", 6)):
            with self.subTest(platform):
                self.assertEqual(self.measure(platform)["union"]["bytes"], size)

    def test_a_platform_the_index_lacks_or_cannot_decide_is_reported_not_guessed(self) -> None:
        missing = self.measure("linux/s390x")
        self.assertFalse(missing["union"]["complete"])
        self.assertIsNone(missing["pairs"][0]["bytes"])
        # The attestation entry is neither picked nor offered.
        self.assertEqual(missing["pairs"][0]["sides"][0]["error"], "no linux/s390x manifest in the index; it offers "
                         "linux/amd64, linux/arm64, linux/arm/v6, linux/arm/v7")
        ambiguous = self.measure("linux/arm")["pairs"][0]["sides"][0]["error"]
        self.assertTrue(ambiguous.startswith("2 linux/arm manifests in the index"), ambiguous)
        self.assertIn("name the variant", ambiguous)
        with self.assertRaises(ValueError):
            self.script.parse_platform("amd64")

    def test_linux_amd64_is_the_default_and_a_bad_platform_exits_2(self) -> None:
        """Through main(), on a fixture directory holding one pair whose
        digests the fake registry serves."""
        tmp = Path(tempfile.mkdtemp(prefix="veridor-pair-sizes-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        base = json.loads((ROOT / "fixtures" / "pairs" / "vikunja-task-comment-idor.json").read_text(encoding="utf-8"))
        second = self.fake.image("registry-1.docker.io", "vikunja/vikunja", {"linux/amd64": [(layer("x86"), 1000),
                                                                                             (layer("new"), 1)]})
        (tmp / "p.json").write_text(json.dumps({**base, "vulnerable_digest": self.pairs[0]["vulnerable_digest"],
                                                "patched_digest": second}), encoding="utf-8")

        def run(*argv: str) -> tuple[int, str, str]:
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(self.script.patched_pairs, "PAIRS_DIR", tmp), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = self.script.main(list(argv), opener=self.fake)
            return code, out.getvalue(), err.getvalue()

        code, out, err = run("--json")
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual((document["platform"], document["union"]["bytes"]), ("linux/amd64", 1001))
        code, out, _ = run("--platform", "linux/arm64")
        self.assertEqual(code, 1, "the second build has no arm64 manifest")
        self.assertIn("PARTIAL: only 1 of 2 images could be measured", out)
        self.assertNotIn("every pair together", out)
        code, out, err = run("--platform", "amd64")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("is not os/architecture[/variant]", err)


class RegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.script = load_script()

    def test_only_docker_hub_and_ghcr_are_read(self) -> None:
        split = self.script.split_image
        self.assertEqual(split("gitea/gitea"), ("docker.io", "gitea/gitea"))
        self.assertEqual(split("python"), ("docker.io", "library/python"))
        self.assertEqual(split("docker.io/library/python"), ("docker.io", "library/python"))
        self.assertEqual(split("index.docker.io/gitea/gitea"), ("docker.io", "gitea/gitea"))
        self.assertEqual(split("ghcr.io/hargata/lubelogger"), ("ghcr.io", "hargata/lubelogger"))
        for image in ("quay.io/org/app", "localhost:5000/app", "registry.gitlab.com/g/p", "localhost/app"):
            with self.subTest(image), self.assertRaises(self.script.SizeError) as refused:
                split(image)
            self.assertIn("is not one this reads (docker.io, ghcr.io); its token endpoint is not guessed",
                          str(refused.exception))
        # Every fixture the harness runs is one it can measure.
        for fixture in self.script.patched_pairs.load_pairs(None):
            with self.subTest(fixture["name"]):
                self.assertIn(split(fixture["image"])[0], self.script.REGISTRIES)

    def test_a_refused_registry_is_reported_and_never_asked(self) -> None:
        fake = FakeRegistry()
        good = fake.image("ghcr.io", "acme/app", {"linux/amd64": [(layer("g"), 3)]})
        pairs = [pair("elsewhere", "quay.io/acme/app", "sha256:" + "1" * 64, "sha256:" + "2" * 64),
                 pair("here", "ghcr.io/acme/app", good, good)]
        result = self.script.measure(pairs, "linux/amd64", fake)
        self.assertIn("registry quay.io is not one this reads", result["pairs"][0]["sides"][0]["error"])
        self.assertEqual(fake.hosts(), {"ghcr.io"}, "nothing may be sent to a registry that is refused")
        self.assertEqual(result["union"]["images_measured"], 1)
        self.assertFalse(result["union"]["complete"])
        self.assertIn("PARTIAL", self.script.render(result))

    def test_bytes_that_do_not_hash_to_the_digest_are_reported(self) -> None:
        fake = FakeRegistry()
        index = fake.image("registry-1.docker.io", "acme/app", {"linux/amd64": [(layer("l"), 50)]})
        pairs = [pair("p", "acme/app", index, index)]
        # Control: served as published, it measures.
        self.assertEqual(self.script.measure(pairs, "linux/amd64", fake)["union"]["bytes"], 50)
        # The index answered with other bytes for the pinned digest.
        key = ("registry-1.docker.io", "acme/app", index)
        published = fake.manifests[key]
        fake.manifests[key] = published.replace(b'"schemaVersion": 2', b'"schemaVersion":  2')
        result = self.script.measure(pairs, "linux/amd64", fake)
        error = result["pairs"][0]["sides"][0]["error"]
        found = "sha256:" + hashlib.sha256(fake.manifests[key]).hexdigest()
        self.assertEqual(error, f"docker.io/acme/app@{index}: the registry's bytes hash to {found}, "
                                "not the digest asked for")
        self.assertFalse(result["union"]["complete"])
        # The same for the platform manifest the index points at.
        fake.manifests[key] = published
        platform_digest = json.loads(published)["manifests"][0]["digest"]
        platform_key = ("registry-1.docker.io", "acme/app", platform_digest)
        fake.manifests[platform_key] = fake.manifests[platform_key] + b" "
        error = self.script.measure(pairs, "linux/amd64", fake)["pairs"][0]["sides"][0]["error"]
        self.assertTrue(error.startswith(f"docker.io/acme/app@{platform_digest}: the registry's bytes hash to"), error)

    def test_an_http_error_is_reported_and_the_token_goes_nowhere_else(self) -> None:
        fake = FakeRegistry()
        index = fake.image("ghcr.io", "acme/app", {"linux/amd64": [(layer("l"), 50)]})
        pairs = [pair("p", "ghcr.io/acme/app", index, "sha256:" + "9" * 64)]
        result = self.script.measure(pairs, "linux/amd64", fake)
        self.assertEqual(result["pairs"][0]["sides"][1]["error"],
                         f"GET https://ghcr.io/v2/acme/app/manifests/sha256:{'9' * 64} answered HTTP 404")
        self.assertNotIn(TOKEN, json.dumps(result) + self.script.render(result))
        manifest_requests = [r for r in fake.requests if "/manifests/" in r.full_url]
        self.assertTrue(manifest_requests)
        for request in manifest_requests:
            # Sent, but not carried across a redirect to another host.
            self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")
            self.assertNotIn("Authorization", request.headers)
            self.assertIn(OCI_INDEX, request.get_header("Accept"))

    def test_a_single_manifest_pin_is_refused(self) -> None:
        """A digest that names one platform's manifest cannot say which
        platform it is without its config blob; the fixtures pin indexes."""
        fake = FakeRegistry()
        index = fake.image("ghcr.io", "acme/app", {"linux/amd64": [(layer("l"), 50)]})
        single = json.loads(fake.manifests[("ghcr.io", "acme/app", index)])["manifests"][0]["digest"]
        result = self.script.measure([pair("p", "ghcr.io/acme/app", single, index)], "linux/amd64", fake)
        self.assertIn("is a single manifest (application/vnd.oci.image.manifest.v1+json), not an index",
                      result["pairs"][0]["sides"][0]["error"])
        self.assertNotIn("error", result["pairs"][0]["sides"][1])



class BuiltPairTest(unittest.TestCase):
    """A built pair downloads its base image and the files its recipe pins.

    The fake serves the base from Docker Hub and the files from PyPI. One
    dependency ships a wheel per architecture and its line pins both, the way
    the datasette recipe's markupsafe and pyyaml lines do."""

    def setUp(self) -> None:
        self.script = load_script()
        self.fake = FakeRegistry()
        self.base = self.fake.image("registry-1.docker.io", "library/python",
                                    {"linux/amd64": [(layer("py-x86"), 1000)], "linux/arm64": [(layer("py-arm"), 2000)]})
        self.app = self.fake.release("app", "1.0", {"app-1.0-py3-none-any.whl": 30})
        self.app.update(self.fake.release("app", "1.1", {"app-1.1-py3-none-any.whl": 31}))
        self.pure = self.fake.release("pure", "2.0", {"pure-2.0-py3-none-any.whl": 7, "pure-2.0.tar.gz": 9})
        self.native = self.fake.release("native", "3.0", {
            "native-3.0-cp312-cp312-manylinux_2_17_x86_64.whl": 100,
            "native-3.0-cp312-cp312-manylinux_2_17_aarch64.whl": 200,
            "native-3.0-cp312-cp312-win_amd64.whl": 300})
        self.tmp = Path(tempfile.mkdtemp(prefix="veridor-sizes-built-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "recipes" / "app").mkdir(parents=True)
        (self.tmp / "recipes" / "app" / "Dockerfile").write_text("ARG BASE\nFROM ${BASE}\n", encoding="utf-8")
        self.requirements(
            f"pure==2.0 --hash=sha256:{self.pure['pure-2.0-py3-none-any.whl']}",
            "native==3.0 --hash=sha256:{} --hash=sha256:{}".format(
                self.native["native-3.0-cp312-cp312-manylinux_2_17_x86_64.whl"],
                self.native["native-3.0-cp312-cp312-manylinux_2_17_aarch64.whl"]))
        self.pair = {"name": "built", "image": "veridor-pair-build/app", "vulnerable": "1.0", "patched": "1.1",
                     "build": {"recipe": "app", "base": f"python@{self.base}", "package": "app"},
                     "vulnerable_sha256": self.app["app-1.0-py3-none-any.whl"],
                     "patched_sha256": self.app["app-1.1-py3-none-any.whl"], "_dir": str(self.tmp)}

    def requirements(self, *lines: str) -> None:
        (self.tmp / "recipes" / "app" / "requirements.txt").write_text(
            "# pinned\n" + "\n".join(lines) + "\n", encoding="utf-8")

    def test_the_base_the_package_and_every_pinned_file_are_counted_and_shared_ones_once(self) -> None:
        result = self.script.measure([self.pair], "linux/amd64", self.fake)
        vulnerable, patched = result["pairs"][0]["sides"]
        # 1000 base + 30 package + 7 pure + 100 native (the x86_64 wheel).
        self.assertEqual((vulnerable["bytes"], vulnerable["layers"]), (1137, 4))
        self.assertEqual(patched["bytes"], 1138)
        self.assertEqual((vulnerable["built_on"], vulnerable["file_sha256"]),
                         (f"python@{self.base}", self.pair["vulnerable_sha256"]))
        self.assertNotIn("digest", vulnerable)
        # The base and both dependencies once; the two package files each.
        self.assertEqual(result["pairs"][0]["bytes"], 1168)
        self.assertTrue(result["union"]["complete"])
        # Control: on arm64 the other base and the other wheel of `native`.
        result = self.script.measure([self.pair], "linux/arm64", self.fake)
        self.assertEqual(result["pairs"][0]["sides"][0]["bytes"], 2000 + 30 + 7 + 200)

    def test_a_hash_that_names_no_file_of_the_release_is_reported_not_sized(self) -> None:
        cases = {
            "the package": ({**self.pair, "vulnerable_sha256": "e" * 64}, None,
                            "app 1.0: PyPI publishes 0 files matching the pinned hash for linux/amd64, not one"),
            "a dependency": (self.pair, ("pure==2.0 --hash=sha256:" + "e" * 64,),
                             "pure 2.0: PyPI publishes 0 files matching the pinned hash"),
            "an architecture no line pins": (self.pair, (
                "native==3.0 --hash=sha256:{} --hash=sha256:{}".format(
                    self.native["native-3.0-cp312-cp312-manylinux_2_17_x86_64.whl"],
                    self.native["native-3.0-cp312-cp312-win_amd64.whl"]),), None),
            "a release PyPI does not have": (self.pair, (f"pure==9.9 --hash=sha256:{'a' * 64}",),
                                             "GET https://pypi.org/pypi/pure/9.9/json answered HTTP 404"),
            "an unpinned line": (self.pair, ("pure==2.0",), "requirements.txt: 'pure==2.0' is not pinned"),
        }
        for label, (built, lines, message) in cases.items():
            with self.subTest(label):
                if lines:
                    self.requirements(*lines)
                platform = "linux/arm64" if label == "an architecture no line pins" else "linux/amd64"
                result = self.script.measure([built], platform, self.fake)
                side = result["pairs"][0]["sides"][0]
                self.assertIn(message or "native 3.0: PyPI publishes 0 files matching the pinned hashes for "
                              "linux/arm64, not one", side["error"])
                self.assertIsNone(result["pairs"][0]["bytes"])
                self.assertFalse(result["union"]["complete"])
                self.assertIn("PARTIAL", self.script.render(result))
        # Control: the pins as set up measure completely.
        self.setUp()
        self.assertTrue(self.script.measure([self.pair], "linux/amd64", self.fake)["union"]["complete"])


if __name__ == "__main__":
    unittest.main()
