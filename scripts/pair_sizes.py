#!/usr/bin/env python3.12
"""What the published-advisory pairs download, read from each image's registry.

    python3.12 scripts/pair_sizes.py                          # every pair, linux/amd64
    python3.12 scripts/pair_sizes.py --pair bugsink-…         # one
    python3.12 scripts/pair_sizes.py --platform linux/arm64   # another platform
    python3.12 scripts/pair_sizes.py --json                   # machine readable

For each side of each fixture in fixtures/pairs/, it asks the image's registry
for the manifest at the pinned digest, checks that the bytes it got hash to
that digest, picks the platform's manifest out of the index (linux/amd64 by
default, what a GitHub-hosted runner pulls), checks that one's digest too, and
adds up its layers' compressed sizes. A pair's total counts a layer its two
builds share once. The union counts a layer shared by any two images once:
that is what a runner pulling every pair downloads, give or take the config
blobs (a few kB each, not counted).

**From the registry, never from local disk.** The README and CI once said the
pairs' images were "about 7 GB". That was the disk usage `docker image ls`
reported on one arm64 laptop: the compressed layers plus their unpacked copy,
for another architecture, and not a download at all. A registry manifest
answers the question for a platform this machine may not even run, so this
never asks Docker.

A built pair (one whose sides are built from published package files, not
pulled) downloads its base image and the files its recipe installs. The base
is read from its registry the same way; each file's size is read from PyPI's
JSON for its release, found by the exact sha256 the recipe pins, so a hash
that names no file of that release is reported rather than sized from another.
A line pinning one file per architecture is sized by the platform's wheel.

Anonymous pull tokens from Docker Hub and ghcr.io; any other registry is
refused by name rather than guessed at. Exit 0 when every side was measured;
1 when any side was not, and the union is then printed as partial, never as a
total; 2 for a selection or platform that cannot be read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import patched_pairs  # noqa: E402 -- the same fixtures, checks and --pair as the harness

#: registry host -> (API base, anonymous pull-token URL for one repository).
REGISTRIES = {
    "docker.io": ("https://registry-1.docker.io",
                  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"),
    "ghcr.io": ("https://ghcr.io", "https://ghcr.io/token?service=ghcr.io&scope=repository:{repository}:pull"),
}
#: Docker Hub's other spellings.
DOCKER_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io"}
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json"}
ACCEPT = ", ".join(sorted(INDEX_TYPES | MANIFEST_TYPES))
TIMEOUT_SECONDS = 30
#: Every file PyPI publishes for one release, each with its sha256 and size.
PYPI_RELEASE = "https://pypi.org/pypi/{name}/{version}/json"
#: One hash-pinned line of a recipe's requirements: name==version, then the
#: sha256 of every file pip may install for it.
PINNED_LINE = re.compile(r"([A-Za-z0-9._-]+)==(\S+)((?: --hash=sha256:[0-9a-f]{64})+)")
#: A platform's architecture as a wheel's filename spells it.
WHEEL_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}
GB = 10 ** 9

#: GET one request, return the body; raise urllib.error.HTTPError or OSError
#: the way urlopen does. The tests pass their own, so nothing reaches a network.
Opener = Callable[[urllib.request.Request], bytes]


class SizeError(RuntimeError):
    """One side could not be measured. Carries no credential."""


def _urlopen(request: urllib.request.Request) -> bytes:
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read()


def split_image(image: str) -> tuple[str, str]:
    """(registry host, repository) for a fixture's `image`, the way Docker reads it."""
    first, _, rest = image.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first, rest
    else:
        registry, repository = "docker.io", image
    if registry in DOCKER_HUB:
        registry = "docker.io"
        if "/" not in repository:
            repository = f"library/{repository}"
    if registry not in REGISTRIES:
        raise SizeError(f"{image}: registry {registry} is not one this reads ({', '.join(sorted(REGISTRIES))}); "
                        "its token endpoint is not guessed")
    return registry, repository


def parse_platform(platform: str) -> tuple[str, str, str | None]:
    parts = platform.split("/")
    if len(parts) not in (2, 3) or not all(parts):
        raise ValueError(f"--platform {platform!r} is not os/architecture[/variant], such as linux/amd64")
    return parts[0], parts[1], parts[2] if len(parts) == 3 else None


def pick_platform(index: dict[str, Any], platform: str) -> dict[str, Any]:
    """The one entry of an image index that is `platform`.

    Entries whose platform is unknown/unknown are attestations (provenance,
    SBOM), not images, and are neither picked nor offered. Without a variant
    in `platform`, any variant matches, and more than one match is refused
    rather than chosen between."""
    want_os, want_arch, want_variant = parse_platform(platform)
    offered, found = [], []
    for entry in index.get("manifests") or []:
        spec = entry.get("platform") or {}
        if (spec.get("os"), spec.get("architecture")) == ("unknown", "unknown"):
            continue
        offered.append("/".join(str(part) for part in (spec.get("os"), spec.get("architecture"), spec.get("variant"))
                                if part))
        if (spec.get("os"), spec.get("architecture")) == (want_os, want_arch) and (
                want_variant is None or spec.get("variant") == want_variant):
            found.append(entry)
    if not found:
        raise SizeError(f"no {platform} manifest in the index; it offers {', '.join(offered) or 'nothing'}")
    if len(found) > 1:
        raise SizeError(f"{len(found)} {platform} manifests in the index ({', '.join(offered)}); "
                        "name the variant, such as linux/arm/v7")
    return found[0]


class Registry:
    """Manifests by digest, each checked against the digest it was asked for."""

    def __init__(self, opener: Opener | None = None) -> None:
        self.open = opener or _urlopen
        self.tokens: dict[tuple[str, str], str] = {}

    def _get(self, url: str, headers: dict[str, str]) -> bytes:
        request = urllib.request.Request(url)
        for name, value in headers.items():
            # Unredirected: a redirect to another host does not carry the token.
            request.add_unredirected_header(name, value)
        try:
            return self.open(request)
        except urllib.error.HTTPError as error:
            raise SizeError(f"GET {url} answered HTTP {error.code}") from None
        except OSError as error:  # URLError, a timeout, a refused connection
            raise SizeError(f"GET {url} failed: {getattr(error, 'reason', error)}") from None

    def _token(self, registry: str, repository: str) -> str:
        key = (registry, repository)
        if key not in self.tokens:
            body = self._get(REGISTRIES[registry][1].format(repository=repository), {})
            try:
                answer = json.loads(body)
            except ValueError:
                answer = None
            token = (answer.get("token") or answer.get("access_token")) if isinstance(answer, dict) else None
            if not isinstance(token, str) or not token:
                raise SizeError(f"{registry} gave no anonymous pull token for {repository}")
            self.tokens[key] = token
        return self.tokens[key]

    def manifest(self, registry: str, repository: str, digest: str) -> dict[str, Any]:
        base = REGISTRIES[registry][0]
        body = self._get(f"{base}/v2/{repository}/manifests/{digest}",
                         {"Accept": ACCEPT, "Authorization": f"Bearer {self._token(registry, repository)}"})
        found = "sha256:" + hashlib.sha256(body).hexdigest()
        if found != digest:
            raise SizeError(f"{registry}/{repository}@{digest}: the registry's bytes hash to {found}, "
                            "not the digest asked for")
        try:
            document = json.loads(body)
        except ValueError:
            raise SizeError(f"{registry}/{repository}@{digest}: the manifest is not JSON") from None
        if not isinstance(document, dict):
            raise SizeError(f"{registry}/{repository}@{digest}: the manifest is not a JSON object")
        return document

    def package_file(self, name: str, version: str, hashes: list[str], platform: str) -> tuple[str, int]:
        """(sha256, bytes) of the file pip installs for name==version on
        `platform`, read from PyPI and found by one of the pinned hashes."""
        body = self._get(PYPI_RELEASE.format(name=name, version=version), {})
        try:
            document = json.loads(body)
        except ValueError:
            document = None
        entries = document.get("urls") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise SizeError(f"PyPI's answer for {name} {version} lists no files")
        pinned = [(entry["digests"]["sha256"], entry["size"], str(entry.get("filename")))
                  for entry in entries
                  if isinstance(entry, dict) and isinstance(entry.get("size"), int)
                  and (entry.get("digests") or {}).get("sha256") in hashes]
        if len(hashes) > 1:
            arch = WHEEL_ARCH.get(parse_platform(platform)[1])
            pinned = [found for found in pinned if arch and arch in found[2]]
        if len(pinned) != 1:
            raise SizeError(f"{name} {version}: PyPI publishes {len(pinned)} files matching the pinned "
                            f"{'hashes' if len(hashes) > 1 else 'hash'} for {platform}, not one")
        return pinned[0][0], pinned[0][1]

    def built_side(self, pair: dict[str, Any], side: str, platform: str) -> tuple[str, dict[str, int]]:
        """What building one side of a built pair downloads: the base image's
        layers, the package's own file, and every file its recipe pins. Files
        are keyed by their sha256, so one both sides install counts once."""
        base_image, _, base_digest = pair["build"]["base"].partition("@")
        platform_digest, sizes = self.layers(base_image, base_digest, platform)
        wanted = [(pair["build"]["package"], pair[side], [pair[side + "_sha256"]])]
        for name, version, hashes in recipe_requirements(pair):
            wanted.append((name, version, hashes))
        for name, version, hashes in wanted:
            sha256, size = self.package_file(name, version, hashes, platform)
            sizes[f"file:sha256:{sha256}"] = size
        return platform_digest, sizes

    def layers(self, image: str, digest: str, platform: str) -> tuple[str, dict[str, int]]:
        """(the platform manifest's digest, {layer digest: compressed bytes})."""
        registry, repository = split_image(image)
        index = self.manifest(registry, repository, digest)
        if not (index.get("mediaType") in INDEX_TYPES or (index.get("mediaType") is None and "manifests" in index)):
            raise SizeError(f"{image}@{digest} is a single manifest ({index.get('mediaType')}), not an index, so "
                            "which platform it is cannot be read from it; pin the index digest")
        digest = str(pick_platform(index, platform).get("digest"))
        document = self.manifest(registry, repository, digest)
        media = document.get("mediaType")
        if media not in MANIFEST_TYPES and not (media is None and "layers" in document):
            raise SizeError(f"{image}@{digest}: {media!r} is not an image manifest")
        sizes = {}
        for layer in document.get("layers") or []:
            if not (isinstance(layer.get("digest"), str) and isinstance(layer.get("size"), int)):
                raise SizeError(f"{image}@{digest}: a layer without a digest and a size")
            sizes[layer["digest"]] = layer["size"]
        return digest, sizes


def recipe_requirements(pair: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    """(name, version, [sha256, ...]) for every pinned line of the recipe's
    requirement files. A line that is not pinned is refused: pip would refuse
    it too, under --require-hashes."""
    found = []
    for path in sorted(patched_pairs.recipe_dir(pair).glob("*.txt")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            match = PINNED_LINE.fullmatch(line.strip())
            if not match:
                raise SizeError(f"{path.name}: {line.split()[0]!r} is not pinned as name==version --hash=sha256:...")
            found.append((match[1], match[2], re.findall(r"[0-9a-f]{64}", match[3])))
    return found


def measure(pairs: list[dict[str, Any]], platform: str, opener: Opener | None = None) -> dict[str, Any]:
    """Every side of every pair, each pair's total, and the union; any side
    that could not be measured carries its reason and makes the union partial."""
    registry = Registry(opener)
    union: dict[str, int] = {}
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    report = []
    for pair in pairs:
        sides, pair_layers, complete = [], {}, True
        built = patched_pairs.is_built(pair)
        for side, _ in patched_pairs.SIDES:
            pin = patched_pairs.pin_of(pair, side)
            key = (pair["image"], pin)
            if key not in seen:
                entry: dict[str, Any] = {"image": pair["image"], "tag": pair[side]}
                entry.update({"built_on": pair["build"]["base"], "file_sha256": pin} if built else {"digest": pin})
                try:
                    entry["platform_digest"], entry["_layers"] = (
                        registry.built_side(pair, side, platform) if built
                        else registry.layers(pair["image"], pin, platform))
                except SizeError as error:
                    entry["error"] = str(error)
                seen[key] = entry
            entry = seen[key]
            if "error" in entry:
                complete = False
            else:
                pair_layers.update(entry["_layers"])
            sides.append({"side": side, **{k: v for k, v in entry.items() if k != "_layers"},
                          **({"bytes": sum(entry["_layers"].values()), "layers": len(entry["_layers"])}
                             if "_layers" in entry else {})})
        union.update(pair_layers)
        report.append({"name": pair["name"], "sides": sides,
                       "bytes": sum(pair_layers.values()) if complete else None})
    measured = [entry for entry in seen.values() if "error" not in entry]
    return {
        "platform": platform,
        "pairs": report,
        "union": {"bytes": sum(union.values()), "layers": len(union), "images_measured": len(measured),
                  "images": len(seen), "complete": len(measured) == len(seen)},
    }


def render(result: dict[str, Any]) -> str:
    lines = [f"{result['platform']}, compressed layer bytes read from each image's registry (GB = 10^9 bytes)", "",
             f"{'vulnerable':>14} {'patched':>14} {'pair':>14}  (a layer both builds share counted once)"]
    for pair in result["pairs"]:
        cells = [f"{side['bytes']:>14,}" if "bytes" in side else f"{'?':>14}" for side in pair["sides"]]
        total = f"{pair['bytes']:>14,}" if pair["bytes"] is not None else f"{'?':>14}"
        vulnerable, patched = pair["sides"]
        lines.append(f"{cells[0]} {cells[1]} {total}  {pair['name']} "
                     f"({vulnerable['image']} {vulnerable['tag']} -> {patched['tag']})")
        for side in pair["sides"]:
            if "error" in side:
                lines.append(f"{'':>44}cannot measure {side['side']} {side['image']}:{side['tag']}: {side['error']}")
    union = result["union"]
    lines.append("")
    if union["complete"]:
        summed = sum(pair["bytes"] for pair in result["pairs"])
        lines.append(f"sum of the pair totals: {summed:,} bytes ({summed / GB:.2f} GB), which counts an image two "
                     "pairs share twice")
        lines.append(f"every pair together: {union['bytes']:,} bytes ({union['bytes'] / GB:.2f} GB), "
                     f"{union['images']} images, {union['layers']} distinct layers, each counted once")
    else:
        lines.append(f"PARTIAL: only {union['images_measured']} of {union['images']} images could be measured; their "
                     f"{union['layers']} distinct layers are {union['bytes']:,} bytes. This is not the total.")
    return "\n".join(lines)


def main(argv: list[str] | None = None, opener: Opener | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", help="only this pair (name or filename stem)")
    parser.add_argument("--platform", default="linux/amd64", help="os/architecture[/variant] (default linux/amd64)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)
    try:
        parse_platform(args.platform)
        pairs, _ = patched_pairs.select_pairs(patched_pairs.load_pairs(None), only=args.pair)
    except (ValueError, patched_pairs.PairError) as error:
        print(str(error), file=sys.stderr)
        return 2
    result = measure(pairs, args.platform, opener)
    print(json.dumps(result, indent=1) if args.json else render(result))
    return 0 if result["union"]["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
