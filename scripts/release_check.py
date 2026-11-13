#!/usr/bin/env python3
"""Checks .github/workflows/release.yml runs before anything is published.

    python3 scripts/release_check.py versions [--tag vX.Y.Z] [--list]
    python3 scripts/release_check.py bump X.Y.Z [--write]
    python3 scripts/release_check.py notes vX.Y.Z > notes.md
    python3 scripts/release_check.py dist dist/ [--tag vX.Y.Z] [--require-zipapp]
    python3 scripts/release_check.py identity
    python3 scripts/release_check.py owner --repository OWNER/REPO --image IMAGE --chart-repository oci://...

``versions``
    One version, stated in many places, must agree. ``pyproject.toml`` is the
    source; every other place Veridor's own version is written into a shipped
    file is listed in ``REGISTRY`` below (the package, the Helm chart, the
    GitLab component defaults, the Jenkins, Azure and CodeBuild templates, the
    Kustomize base, the Argo Rollouts AnalysisTemplate, and the READMEs and
    comments that name it). With ``--tag`` the git tag must name it too. A
    pre-release is written the PEP 440 way where pip reads it (``X.Y.ZrcN``:
    pyproject, ``__version__``, ``veridor==``, the zipapp name) and the SemVer
    way where a tag, an image or Helm reads it (``vX.Y.Z-rc.N``,
    ``X.Y.Z-rc.N``); the two are compared after conversion.

    It also scans every shipped text file (tests/ and CHANGELOG.md excepted;
    what .gitignore or the checkout's info/exclude ignores is skipped, unless git
    tracks it; a tracked file that is not UTF-8, a SHA-256 repository and a
    missing index beside a commit are refused) for a
    version-shaped string that is either the current version or sits on a line
    that names Veridor, and fails on any that no registry entry and no
    ``NOT_RELEASE_VERSIONS`` entry accounts for. A new hard-coded version therefore cannot be missed by
    ``bump``: it fails here first. Prints ``version=``, ``semver=`` and
    ``prerelease=`` lines (GITHUB_OUTPUT format); ``--list`` also prints every
    registered occurrence, to stderr.

``bump``
    Rewrite every registered occurrence to a new version. Without ``--write``
    it prints a unified diff and changes nothing. It refuses when the tree has
    an unregistered occurrence (it would be left behind) or when a registry
    pattern matches nothing (the file moved on without the registry), and it
    re-runs the ``versions`` check on the result before writing anything.

``notes``
    Print the CHANGELOG section for the tag's version -- everything under its
    ``## [VERSION]`` heading up to the next ``## [``. A missing or empty
    section is an error: release notes that say nothing are not written. So
    is a section that says it is not released (the placeholder an untagged
    version carries, or the [Unreleased] preamble carried along by the
    fold), and so is a non-empty ``## [Unreleased]``: its entries describe
    changes in the tagged tree, and notes that leave them out describe less
    than the release ships. It also refuses any shipped file that still holds
    one of the phrases in ``_PRE_RELEASE_STATEMENT`` (no release exists, not
    published, does not exist yet or until the first release, the PyPI name is
    unclaimed, a wheel placeholder), because this is
    the first thing a tag runs. It reads phrases, not meaning: a sentence worded
    some other way passes, so CONTRIBUTING.md's step 3 still names the sections
    to read. tests/, CHANGELOG.md, CONTRIBUTING.md and this script are not read.

``dist``
    Check the built artifacts: exactly one wheel and one sdist for the
    version, License-Expression and License-File metadata, LICENSE and NOTICE
    inside both, and (when present) the zipapp's name and contents. The wheel
    may hold only the ``veridor/`` package and its dist-info, with no bytecode.
    The sdist must hold what rebuilds the wheel -- every file the wheel
    installs, under ``src/``, with ``pyproject.toml``, ``README.md`` and the readme
    ``pyproject.toml`` names -- and
    nothing outside that package, the top-level packaging files and the
    egg-info setuptools writes. Every link in the wheel's and the sdist's
    description, the PyPI page, must be an absolute http(s) or mailto URL:
    PyPI renders it with no base URL and no heading ids, so a
    repository-relative path or a bare ``#anchor`` goes nowhere there, and an
    uploaded version's page cannot be replaced. With ``--tag``, the
    description must also exist and must not say that no release exists.

``identity``
    List every occurrence of the project's organisation, registry and domain
    names (github.com/Veridor-authz, Veridor-authz/veridor, ghcr.io/veridor-authz,
    raw.githubusercontent.com/Veridor-authz, gitlab.com/Veridor-authz, veridor.org) with
    file:line, so renaming them is a known list. It rewrites nothing.
    It skips this script and its test, which define the names, so the list
    is short of what a rename must change: REGISTRY's patterns and the test's
    release literals name the owner too, and ``versions`` fails on a tree they
    no longer match. It fails on any occurrence of a name in
    ``IDENTITY_RETIRED``, the namespaces this project does not hold, in the
    spellings that list covers. The project holds veridor.org, which serves the
    product page, and docs.veridor.org, which serves the docs, so those two
    hosts pass. Any other host under the domain still fails, because nothing
    commits to serving it, and so does any address at it, because the domain
    publishes no mail exchanger and a report sent there reaches nobody.

``owner``
    Compare the tree with the repository a release is running in, before
    anything is published. IMAGE and CHART_REPOSITORY must sit under
    ``ghcr.io/<owner>/``, lowercase, because a registry reference cannot hold
    the capitals a GitHub owner can. The chart's default image must be IMAGE,
    and pyproject's Repository must be this repository. Under another owner
    these would otherwise fail at the image job, after the PyPI upload that
    cannot be undone. The signing identity SECURITY.md tells users to verify
    must name this repository exactly, in its own case, because the certificate
    is compared exactly.

Exit codes: 0 consistent, 1 a check failed (every problem is listed), 2 bad
usage.
"""

from __future__ import annotations

import argparse
import difflib
import email.parser
import fnmatch
import os
import re
import struct
import sys
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_FINAL = r"(\d+)\.(\d+)\.(\d+)"
_PEP440 = re.compile(rf"^{_FINAL}(?:(a|b|rc)(\d+))?$")
_SEMVER = re.compile(rf"^{_FINAL}(?:-(alpha|beta|rc)\.(\d+))?$")
_TO_SEMVER = {"a": "alpha", "b": "beta", "rc": "rc"}
_TO_PEP440 = {value: key for key, value in _TO_SEMVER.items()}

#: What follows a version's first number, in either spelling.
_VERSION_TAIL = r"\.\d+\.\d+(?:(?:a|b|rc)\d+|-(?:alpha|beta|rc)\.\d+)?"

#: A version in either spelling, as a named group. Registry patterns write
#: ``{V}`` where it sits.
_VERSION_GROUP = rf"(?P<v>\d+{_VERSION_TAIL})"

#: Any version-shaped token, for the scan: not the tail of a longer number
#: (10.1.0, 1.0.1.0) and not followed by one. The "not preceded by a digit or
#: a dot" test is made after the first digit, as a two-character lookbehind,
#: rather than before it: it matches the same tokens, and a pattern that begins
#: with a digit lets the regex engine skip to the next digit instead of trying
#: a lookbehind at every character, which was most of the scan's time.
_TOKEN = re.compile(rf"(?P<v>\d(?<![\d.]\d)\d*{_VERSION_TAIL})(?!\d|\.\d)")


class CheckFailed(Exception):
    """One or more checks failed; the message lists each."""


@dataclass(frozen=True)
class Occurrence:
    """One place Veridor's own version is written into a shipped file."""

    path: str
    pattern: str  #: regex; ``{V}`` marks the version
    form: str  #: "pep440" (pip reads it) or "semver" (a tag, image or chart reads it)
    what: str

    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern.replace("{V}", _VERSION_GROUP), re.MULTILINE)


def _occ(path: str, pattern: str, form: str, what: str) -> Occurrence:
    return Occurrence(path, pattern, form, what)


#: Every place Veridor's version is hard-coded in a shipped file. ``bump``
#: rewrites exactly these; ``versions`` checks each matches at least once and
#: agrees with pyproject.toml. The scan (``unregistered``) fails on any
#: occurrence outside this list, so adding one means adding it here.
REGISTRY: tuple[Occurrence, ...] = (
    # The package itself.
    _occ("pyproject.toml", r'^version = "{V}"$', "pep440", "the package version (the source)"),
    _occ("src/veridor/__init__.py", r'^__version__ = "{V}"$', "pep440", "veridor.__version__"),
    # Helm: the chart version and appVersion, which is the image tag default.
    _occ("deploy/helm/veridor-gate/Chart.yaml", r"^version: {V}$", "semver", "chart version"),
    _occ("deploy/helm/veridor-gate/Chart.yaml", r'^appVersion: "{V}"$', "semver",
         "chart appVersion (the default image tag)"),
    _occ("deploy/helm/veridor-gate/README.md", r"not implemented in chart {V}\.", "semver", "chart README"),
    # Kustomize and Argo.
    _occ("deploy/kustomize/veridor-gate/base/job.yaml", r"image: ghcr\.io/veridor-authz/veridor:{V}$", "semver",
         "Kustomize base image"),
    _occ("deploy/kustomize/veridor-gate/README.md", r"^\s*newTag: {V}$", "semver", "Kustomize README images: example"),
    _occ("deploy/argocd/application-example.yaml", r"^\s*targetRevision: {V}$", "semver",
         "Argo CD Helm example chart version"),
    _occ("deploy/argo-rollouts/veridor-analysistemplate.yaml", r"value: ghcr\.io/veridor-authz/veridor:{V}$", "semver",
         "AnalysisTemplate image default"),
    _occ("deploy/argo-rollouts/README.md", r"`ghcr\.io/veridor-authz/veridor:{V}`", "semver", "Rollouts README"),
    # The GitLab component and its consumer example.
    _occ("templates/veridor.yml", r'default: "ghcr\.io/veridor-authz/veridor:{V}"', "semver", "component image default"),
    _occ("templates/veridor.yml", r'default: "veridor=={V}"', "pep440", "component pip_package default"),
    _occ("ci/.gitlab-ci.yml", r"name the first release \({V}\)", "semver", "comment"),
    _occ("ci/.gitlab-ci.yml", r"raw\.githubusercontent\.com/Veridor-authz/veridor/v{V}/templates", "semver",
         "include: remote tag"),
    _occ("ci/.gitlab-ci.yml", r"gitlab\.com/Veridor-authz/veridor/veridor@{V}", "semver", "include: component version"),
    # Jenkins, Azure Pipelines, CodeBuild.
    _occ("ci/Jenkinsfile", r"first release \({V}\)", "semver", "comment"),
    _occ("ci/Jenkinsfile", r"'veridor=={V}'", "pep440", "pip comment"),
    _occ("ci/Jenkinsfile", r"veridor-{V}\.pyz", "pep440", "zipapp name"),
    _occ("ci/Jenkinsfile", r"image 'ghcr\.io/veridor-authz/veridor:{V}'", "semver", "agent image"),
    _occ("ci/azure-pipelines.yml", r"first release \({V}\)", "semver", "comment"),
    _occ("ci/azure-pipelines.yml", r"veridor=={V}", "pep440", "pip install"),
    _occ("ci/azure-pipelines.yml", r"ghcr\.io/veridor-authz/veridor:{V}$", "semver", "docker run comment"),
    _occ("ci/azure-pipelines.yml", r"veridor-{V}\.pyz", "pep440", "zipapp name"),
    _occ("ci/buildspec.yml", r"first release \({V}\)", "semver", "comment"),
    _occ("ci/buildspec.yml", r"veridor=={V}", "pep440", "pip install"),
    _occ("ci/buildspec.yml", r"veridor-{V}\.pyz", "pep440", "zipapp name"),
    _occ("ci/README.md", r"names the first release \({V}\)", "semver", "ci README"),
    _occ("ci/README.md", r"veridor-{V}\.pyz", "pep440", "ci README zipapp name"),
    # The top-level README and the files that show `veridor --version`.
    _occ("README.md", r"^veridor {V}$", "pep440", "`veridor --version` output"),
    _occ("README.md", r"raw\.githubusercontent\.com/Veridor-authz/veridor/v{V}/templates", "semver", "GitLab include"),
    _occ("README.md", r"gitlab\.com/Veridor-authz/veridor/veridor@{V}", "semver", "GitLab component"),
    _occ("README.md", r"The `v{V}` tag", "semver", "GitLab section"),
    _occ("README.md", r"ghcr\.io/veridor-authz/veridor:{V}", "semver", "GitLab section image"),
    _occ("README.md", r"`veridor=={V}`", "pep440", "GitLab input table"),
    _occ(".github/ISSUE_TEMPLATE/bug_report.yml", r"placeholder: veridor {V}$", "pep440",
         "`veridor --version` placeholder"),
    _occ("scripts/build_zipapp.py", r"dist/veridor-{V}\.pyz", "pep440", "docstring zipapp name"),
    _occ("Dockerfile", r"^ARG VERSION={V}$", "pep440", "the image's version label default"),
    # Tests that pin a shipped default. They belong to other files' owners, so
    # bump keeps them in step rather than leaving the suite red after a bump.
    _occ("tests/test_ci_configs.py", r'"ghcr\.io/veridor-authz/veridor:{V}"', "semver", "pins the component default"),
    _occ("tests/test_helm_chart.py", r'chart\["version"\], "{V}"', "semver", "pins the chart version"),
)

#: Version-shaped strings the scan finds that are NOT Veridor's release
#: version, each with the reason. A literal pattern, so the entry keeps
#: matching after a bump; ``versions`` fails when one no longer matches
#: anything, so the list cannot rot.
NOT_RELEASE_VERSIONS: tuple[tuple[str, str, str], ...] = (
    ("scripts/e2e_kubernetes.sh", r'CHART_VERSION="0\.1\.0-e2e\.',
     "the e2e's per-run chart version for its in-cluster Helm repository"),
    ("scripts/e2e_kubernetes.sh", r"^version: 0\.1\.0$",
     "the e2e's throwaway demo-target chart"),
    ("src/veridor/core.py", r'It said "0\.1\.0" as a literal',
     "history: the literal semanticVersion that __version__ replaced"),
    ("src/veridor/core.py", r"SARIF 2\.1\.0", "the SARIF specification's version"),
    ("README.md", r"OpenAPI 3\.0\.3", "the demo specification's OpenAPI version"),
    ("ci/README.md", r"security-report-schemas 15\.2\.5", "GitLab's report schema version"),
    ("README.md", r"Argo CD v3\.5\.3", "the Argo CD version the kind e2e installs"),
    ("deploy/helm/veridor-gate/templates/_helpers.tpl", r"Argo CD v3\.5\.3",
     "the Argo CD version the helm-mode refusal's measurement ran on"),
    ("CONTRIBUTING.md", r"`## \[0\.1\.0\]` already", "history: the first CHANGELOG section, which was never tagged"),
    ("CONTRIBUTING.md", r"so a 0\.1\.0 release folds", "history: the first CHANGELOG section, which was never tagged"),
)

#: Not scanned for versions: history and tests (which hold versions as data;
#: the two that pin a shipped default are registered above).
_SCAN_EXCLUDED_PREFIXES = ("tests/",)
_SCAN_EXCLUDED_FILES = frozenset({"CHANGELOG.md", "LICENSE", "NOTICE"})

#: The organisation, registry and domain names a rename would have to touch.
#: Longest first: ghcr.io/veridor-authz/veridor is one ghcr.io/veridor-authz occurrence,
#: not also a bare Veridor-authz/veridor.
IDENTITY_NAMES: tuple[tuple[str, str], ...] = (
    ("raw.githubusercontent.com/Veridor-authz", r"raw\.githubusercontent\.com/Veridor-authz\b"),
    ("github.com/Veridor-authz", r"(?<![\w.])github\.com/Veridor-authz\b"),
    ("gitlab.com/Veridor-authz", r"gitlab\.com/Veridor-authz\b"),
    ("ghcr.io/veridor-authz", r"ghcr\.io/veridor-authz\b"),
    ("veridor.org", r"(?<![\w-])(?:[\w-]+\.|[\w.+-]+@)?veridor\.org\b"),
    ("Veridor-authz/veridor", r"(?<![\w./-])Veridor-authz/veridor(?![\w-])"),
)
#: The two files that define the list above; they are not uses of the names.
_IDENTITY_SELF = frozenset({"scripts/release_check.py", "tests/test_release_check.py"})
_IDENTITY = re.compile("|".join(f"(?P<n{index}>{pattern})"
                                for index, (_, pattern) in enumerate(IDENTITY_NAMES)), re.IGNORECASE)
#: Every name above contains one of these (lowercased), so identity() skips a
#: line without any -- 98% of the tree's lines -- instead of trying all six
#: alternatives at every position of it (0.56 s of regex work on the tree
#: became 0.03 s, measured).
_IDENTITY_LITERALS = ("veridor", "veridor-authz")

#: The addresses at veridor.org that take mail (MX to Zoho since 2026-11-13;
#: delivery to both checked by the maintainer that day). SECURITY.md and
#: CODE_OF_CONDUCT.md name them; any other address at the domain is refused below.
HELD_ADDRESSES: tuple[str, ...] = ("opensource@veridor.org", "security@veridor.org")

#: Names this project does not hold, so nothing may send a reader to them: the
#: ``veridor`` owner on the code hosts and registries, any veridor.org host but
#: the two that serve (veridor.org and docs.veridor.org), any address at the
#: domain but opensource@ and security@, and the maintainer's own account as a home for the project
#: (github.com/<handle> alone is allowed: GOVERNANCE.md links to the person).
#: identity() lists only the names in use, so one of these would otherwise just
#: not appear. Matched in any case, and with the escapes a regex source adds.
#: Beyond that, a spelling not written here passes: this is a list, not a proof.
IDENTITY_RETIRED: tuple[tuple[str, str], ...] = (
    ("raw.githubusercontent.com/veridor", r"raw\\*\.githubusercontent\\*\.com\\*/veridor(?![\w-])"),
    ("github.com/veridor", r"(?<![\w-])github\\*\.com(?:\\*/|:)veridor(?![\w-])"),
    ("gitlab.com/veridor", r"(?<![\w-])gitlab\\*\.com(?:\\*/|:)veridor(?![\w-])"),
    ("veridor.github.io", r"(?<![\w-])veridor\\*\.github\\*\.io(?![\w-])"),
    ("hub.docker.com/veridor", r"hub\\*\.docker\\*\.com\\*/(?:[ru]\\*/)?veridor(?![\w-])"),
    ("shields.io/veridor/veridor", r"shields\\*\.io\S*/veridor\\*/veridor(?![\w-])"),
    ("codecov.io/veridor/veridor", r"codecov\\*\.io\S*/veridor\\*/veridor(?![\w-])"),
    ("uses: veridor/", r"\buses:\s*[\"']?veridor/"),
    ("veridor%2Fveridor", r"veridor%2Fveridor(?![\w-])"),
    ("ghcr.io/veridor", r"(?<![\w-])ghcr\\*\.io\\*/veridor(?![\w-])"),
    ("docker.io/veridor", r"(?<![\w-])docker\\*\.io\\*/veridor(?![\w-])"),
    ("quay.io/veridor", r"(?<![\w-])quay\\*\.io\\*/veridor(?![\w-])"),
    ("repos/veridor/veridor", r"(?<![\w-])repos/veridor\\*/veridor(?![\w-])"),
    ("veridor/veridor", r"(?<![\w./\\-])veridor\\*/veridor(?![\w-])"),
    ("Santoshkumarpuppala/veridor", r"(?<![\w-])santoshkumarpuppala\\*/veridor(?![\w-])"),
    ("ghcr.io/santoshkumarpuppala", r"(?<![\w-])ghcr\\*\.io\\*/santoshkumarpuppala(?![\w-])"),
    ("gitlab.com/santoshkumarpuppala", r"(?<![\w-])gitlab\\*\.com(?:\\*/|:)santoshkumarpuppala(?![\w-])"),
    # The domain takes mail for two announced addresses only (MX to Zoho since
    # 2026-11-13): opensource@ and security@. Any other address at it, or at a
    # host under it, is a report sent to a mailbox nobody reads. The lookbehind
    # keeps a match from starting inside a longer local part, so
    # xsecurity@veridor.org is still refused.
    ("@veridor.org", r"(?<![\w.+-])(?!(?:" + "|".join(a.split("@")[0] for a in HELD_ADDRESSES)
                     + r")@veridor\\*\.org(?![\w-]|\\*\.[\w-]))"
                     r"[\w.+-]*@(?:[\w-]+\\*\.)*veridor\\*\.org(?![\w-])"),
    # Every host under the domain but docs. The bare domain passes because at
    # least one label must come before it. A match may start after a dot: the
    # search tries the leftmost start first, so a.docs.veridor.org is matched
    # from "a" and never reaches docs. The lookbehind once refused a dot too,
    # and "see...www.veridor.org" passed, with no label start left to match.
    ("host.veridor.org", r"(?<![\w-])(?!docs\\*\.veridor\\*\.org(?![\w-]))(?:[\w-]+\\*\.)+veridor\\*\.org(?![\w-])"),
)
#: The retired names tests/ may hold: they plant them as controls. Taken from
#: the list, so this script names the retired spellings in that list alone.
_IDENTITY_DOMAIN_RETIRED = frozenset(name for name, _ in IDENTITY_RETIRED if name.endswith("veridor.org"))
_IDENTITY_RETIRED_RE = [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in IDENTITY_RETIRED]
#: Every retired name contains one of these (lowercased), so identity_leftovers()
#: skips a line without any. "veridor" alone was the filter once, and the two
#: retired santoshkumarpuppala hosts never fired on a line that did not also say
#: veridor (a ``helm pull`` of a chart under that owner's ghcr namespace).
_IDENTITY_RETIRED_LITERALS = ("veridor", "santoshkumarpuppala")


def _unfilterable_identity_names(names: tuple[tuple[str, str], ...]) -> list[str]:
    """Names the line filter in identity() would skip everywhere.

    A name added without one of ``_IDENTITY_LITERALS``, or whose pattern does not
    match the name itself, would silently count zero occurrences, and `identity`
    would print an inventory that looks complete. So it is refused at import.
    What this cannot see: a pattern that also matches some OTHER text lacking
    the literal (an alternation such as ``(?:veridor|vrdr)``); that text would
    be skipped.
    """
    return [name for name, pattern in names
            if not any(literal in name.lower() and literal in pattern.lower()
                       for literal in _IDENTITY_LITERALS)
            or not re.fullmatch(pattern, name)]


if _unfilterable_identity_names(IDENTITY_NAMES):
    raise RuntimeError(
        f"release_check.IDENTITY_NAMES: {_unfilterable_identity_names(IDENTITY_NAMES)} "
        f"must contain one of {_IDENTITY_LITERALS!r} and be matched by their own pattern; "
        "identity() skips every line without one")


def _unfilterable_retired_names(names: tuple[tuple[str, str], ...]) -> list[str]:
    """Retired names the line filter in identity_leftovers() would skip everywhere.

    The same refusal as _unfilterable_identity_names, for IDENTITY_RETIRED and
    ``_IDENTITY_RETIRED_LITERALS``: a retired name without one of the literals,
    or that its own pattern (in any case) does not match, would never fire, and
    identity would pass a tree that still sends readers to it.
    """
    return [name for name, pattern in names
            if not any(literal in name.lower() and literal in pattern.lower()
                       for literal in _IDENTITY_RETIRED_LITERALS)
            or not re.fullmatch(pattern, name, re.IGNORECASE)]


if _unfilterable_retired_names(IDENTITY_RETIRED):
    raise RuntimeError(
        f"release_check.IDENTITY_RETIRED: {_unfilterable_retired_names(IDENTITY_RETIRED)} "
        f"must contain one of {_IDENTITY_RETIRED_LITERALS!r} and be matched by their own pattern; "
        "identity_leftovers() skips every line without one")


def pep440_to_semver(version: str) -> str:
    match = _PEP440.match(version)
    if not match:
        raise CheckFailed(
            f"{version!r} is not X.Y.Z or X.Y.Z(a|b|rc)N; this release workflow "
            "publishes nothing else"
        )
    major, minor, patch, label, number = match.groups()
    base = f"{major}.{minor}.{patch}"
    return base if label is None else f"{base}-{_TO_SEMVER[label]}.{number}"


def semver_to_pep440(version: str) -> str:
    match = _SEMVER.match(version)
    if not match:
        raise CheckFailed(
            f"{version!r} is not X.Y.Z or X.Y.Z-(alpha|beta|rc).N; this release "
            "workflow publishes nothing else"
        )
    major, minor, patch, label, number = match.groups()
    base = f"{major}.{minor}.{patch}"
    return base if label is None else f"{base}{_TO_PEP440[label]}{number}"


def both_forms(version: str) -> dict[str, str]:
    """{"pep440": ..., "semver": ...} for a version given in either spelling."""
    if _PEP440.match(version):
        return {"pep440": version, "semver": pep440_to_semver(version)}
    if _SEMVER.match(version):
        return {"pep440": semver_to_pep440(version), "semver": version}
    raise CheckFailed(f"{version!r} is neither X.Y.Z, X.Y.Z(a|b|rc)N nor X.Y.Z-(alpha|beta|rc).N")


# ---------------------------------------------------------------------------
# The shipped tree
# ---------------------------------------------------------------------------

def _git_dirs(root: Path) -> tuple[Path, Path] | None:
    """(this checkout's git directory, the common one), or None without a .git.

    A source archive has no .git. A linked worktree's .git is a file naming its
    private directory, which holds its index, and git keeps the one exclude file
    in the common directory that one points back to. Read without spawning git,
    which a source archive may not have either."""
    dot_git = root / ".git"
    if dot_git.is_file():
        pointer = dot_git.read_text(encoding="utf-8").strip()
        if not pointer.startswith("gitdir:"):
            return None
        git_dir = root / pointer.removeprefix("gitdir:").strip()
        common = git_dir / "commondir"
        if common.is_file():
            return git_dir, git_dir / common.read_text(encoding="utf-8").strip()
        return git_dir, git_dir
    return (dot_git, dot_git) if dot_git.is_dir() else None


def _local_exclude(root: Path) -> Path | None:
    """This checkout's info/exclude, where local files are listed without
    publishing their names.

    A global core.excludesFile is not read: a file ignored only there is scanned,
    which fails loudly rather than skipping something that ships."""
    dirs = _git_dirs(root)
    exclude = dirs[1] / "info" / "exclude" if dirs else None
    return exclude if exclude is not None and exclude.is_file() else None


def _index_paths(data: bytes) -> set[str]:
    """The paths in a git index, versions 2 to 4 (git's gitformat-index).

    A split index or a sparse one does not list every tracked path, so it is
    refused rather than read as a shorter list."""
    try:
        if data[:4] != b"DIRC":
            raise ValueError("no DIRC signature")
        version, count = struct.unpack(">II", data[4:12])
        if version not in (2, 3, 4):
            raise ValueError(f"version {version}")
        offset, previous, paths = 12, b"", set()
        for _ in range(count):
            start = offset
            flags = struct.unpack(">H", data[offset + 60:offset + 62])[0]
            offset += 64 if flags & 0x4000 else 62
            if version == 4:
                byte = data[offset]
                offset += 1
                strip = byte & 0x7f
                while byte & 0x80:
                    byte = data[offset]
                    offset += 1
                    strip = ((strip + 1) << 7) | (byte & 0x7f)
                end = data.index(b"\0", offset)
                name = previous[:len(previous) - strip] + data[offset:end]
                offset = end + 1
            else:
                end = data.index(b"\0", offset)
                name = data[offset:end]
                offset = start + (end - start + 8) // 8 * 8
            paths.add(name.decode("utf-8", "surrogateescape"))
            previous = name
        while offset < len(data) - 20:
            size = struct.unpack(">I", data[offset + 4:offset + 8])[0]
            if data[offset:offset + 4] in (b"link", b"sdir"):
                raise ValueError(f"{data[offset:offset + 4].decode()} extension")
            offset += 8 + size
    except (struct.error, ValueError, IndexError) as error:
        raise CheckFailed(f"this checkout's git index is outside what release_check.py models: {error}") from None
    return paths


def _has_commits(git_dir: Path, common: Path) -> bool:
    """Whether HEAD names a commit: detached, or a branch that exists loose or packed."""
    head = git_dir / "HEAD"
    if not head.is_file():
        return False
    target = head.read_text(encoding="utf-8", errors="replace").strip()
    if not target.startswith("ref:"):
        return bool(target)
    ref = target.removeprefix("ref:").strip()
    if (common / ref).is_file() or (git_dir / ref).is_file():
        return True
    packed = common / "packed-refs"
    return packed.is_file() and any(line.split(" ", 1)[-1] == ref for line in
                                    packed.read_text(encoding="utf-8", errors="replace").splitlines())


#: The repository's object format, from [extensions] in its config.
_OBJECT_FORMAT = re.compile(r"^\s*objectformat\s*=\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def _tracked_paths(root: Path) -> set[str]:
    """What git tracks here, from the index. Empty without a .git, or in a
    repository with no commit and no index (a fresh `git init`).

    A missing index in a repository that has commits is refused: read as
    "nothing tracked", every info/exclude line applied to files that ship. So is
    a SHA-256 repository, whose index entries hold 32-byte ids that the parser,
    which steps over 20, read as garbage names (measured)."""
    dirs = _git_dirs(root)
    if not dirs:
        return set()
    git_dir, common = dirs
    config = common / "config"
    if config.is_file():
        formats = _OBJECT_FORMAT.findall(config.read_text(encoding="utf-8", errors="replace"))
        if any(found.lower() != "sha1" for found in formats):
            raise CheckFailed(f"this checkout's object format is {formats[-1]}; release_check.py "
                              "reads only a SHA-1 repository's git index")
    index = git_dir / "index"
    if index.is_file():
        return _index_paths(index.read_bytes())
    if _has_commits(git_dir, common):
        raise CheckFailed(f"this checkout has commits but no git index at {index}; "
                          "nothing would count as tracked, so it is refused")
    return set()


def _ignore_patterns(root: Path) -> list[str]:
    patterns = []
    for name, path in ((".gitignore", root / ".gitignore"), ("info/exclude", _local_exclude(root))):
        if path is None or not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!") or "**" in line:
                # A matcher that silently mis-read a pattern would scan files git
                # does not ship, or skip files it does. Refuse instead.
                raise CheckFailed(f"{name} pattern {line!r} is outside what release_check.py models")
            patterns.append(line)
    return patterns


def _ignored(rel: str, is_dir: bool, patterns: list[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    for pattern in patterns:
        if pattern.endswith("/") and not is_dir:
            continue
        body = pattern.rstrip("/")
        if "/" in body:
            if fnmatch.fnmatchcase(rel, body.lstrip("/")):
                return True
        elif fnmatch.fnmatchcase(name, body):
            return True
    return False


def text_files(root: Path) -> list[str]:
    """Every text file under root that git would not ignore, as posix paths.

    An ignore rule does not apply to a tracked file, in git or here. A local
    info/exclude line naming README.md used to take it out of these checks while
    it still shipped, and `identity` exited 0 on a leftover in it (measured)."""
    patterns = _ignore_patterns(root)
    tracked = _tracked_paths(root)
    tracked_dirs = {parent.as_posix() for path in tracked for parent in Path(path).parents}
    found, undecodable = [], []
    for directory, dirnames, filenames in os.walk(root):
        base = Path(directory).relative_to(root).as_posix()
        prefix = "" if base == "." else base + "/"
        dirnames[:] = sorted(d for d in dirnames if d != ".git" and (
            prefix + d in tracked_dirs or not _ignored(prefix + d, True, patterns)))
        for filename in sorted(filenames):
            rel = prefix + filename
            if filename == ".git" or (rel not in tracked and _ignored(rel, False, patterns)):
                continue
            try:
                (root / rel).read_text(encoding="utf-8")
            except UnicodeDecodeError:
                if rel in tracked:
                    undecodable.append(rel)  # it ships, so skipping it would pass unread text
                continue
            except OSError:
                continue
            found.append(rel)
    if undecodable:
        raise CheckFailed("tracked file(s) that are not UTF-8, which these checks cannot read: "
                          + ", ".join(undecodable))
    return found


def _read_texts(root: Path, paths) -> dict[str, str]:
    texts = {}
    for path in paths:
        file = root / path
        if file.is_file():
            texts[path] = file.read_text(encoding="utf-8")
    return texts


def registered_matches(texts: dict[str, str]) -> tuple[list[tuple[Occurrence, int, str]], list[str]]:
    """([(entry, line, value)], problems) for every registry entry."""
    found, problems = [], []
    for entry in REGISTRY:
        if entry.path not in texts:
            problems.append(f"{entry.path} is missing (registered: {entry.what})")
            continue
        text = texts[entry.path]
        matches = list(entry.regex().finditer(text))
        if not matches:
            problems.append(f"{entry.path}: the registered pattern for {entry.what} matches nothing "
                            f"({entry.pattern}); update REGISTRY in scripts/release_check.py")
        for match in matches:
            found.append((entry, text.count("\n", 0, match.start("v")) + 1, match.group("v")))
    return found, problems


def unregistered(root: Path, version: str) -> list[str]:
    """Version-shaped strings no registry or NOT_RELEASE_VERSIONS entry covers.

    Found either because the string IS the current version (in either
    spelling), or because it sits on a line that names Veridor.
    """
    forms = set(both_forms(version).values())
    paths = [p for p in text_files(root)
             if not p.startswith(_SCAN_EXCLUDED_PREFIXES) and p not in _SCAN_EXCLUDED_FILES]
    texts = _read_texts(root, paths)
    covered: dict[str, set[tuple[int, int]]] = {}
    for entry in REGISTRY:
        if entry.path in texts:
            for match in entry.regex().finditer(texts[entry.path]):
                covered.setdefault(entry.path, set()).add(match.span("v"))
    allowed: dict[str, list[tuple[int, int]]] = {}
    for path, pattern, _ in NOT_RELEASE_VERSIONS:
        if path in texts:
            for match in re.finditer(pattern, texts[path], re.MULTILINE):
                allowed.setdefault(path, []).append(match.span())
    problems = []
    for path, text in texts.items():
        # One pass over the whole text, not one per line: a token cannot
        # contain a newline, and a newline is neither a digit nor a dot, so
        # _TOKEN's lookarounds read it exactly as they read the end of a line.
        # The matches, their spans and their order are the line-by-line ones.
        for match in _TOKEN.finditer(text):
            value = match.group("v")
            span = match.span("v")
            start = text.rfind("\n", 0, span[0]) + 1
            end = text.find("\n", span[1])
            line = text[start:] if end < 0 else text[start:end]
            if value not in forms and "veridor" not in line.lower():
                continue
            if span in covered.get(path, set()):
                continue
            if any(first <= span[0] and span[1] <= last for first, last in allowed.get(path, [])):
                continue
            number = text.count("\n", 0, span[0]) + 1
            problems.append(f"{path}:{number}: {value!r} is not in release_check.py's REGISTRY "
                            f"(or NOT_RELEASE_VERSIONS): {line.strip()[:100]}")
    return problems


def stale_allowances(root: Path) -> list[str]:
    problems = []
    for path, pattern, reason in NOT_RELEASE_VERSIONS:
        file = root / path
        if not file.is_file() or not re.search(pattern, file.read_text(encoding="utf-8"), re.MULTILINE):
            problems.append(f"NOT_RELEASE_VERSIONS entry for {path} ({reason}) matches nothing; remove it")
    return problems


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _check_texts(texts: dict[str, str], version: str) -> list[str]:
    forms = both_forms(version)
    found, problems = registered_matches(texts)
    for entry, line, value in found:
        if value != forms[entry.form]:
            problems.append(f"{entry.path}:{line}: {entry.what} says {value}; it must be "
                            f"{forms[entry.form]} (pyproject.toml {forms['pep440']})")
    return problems


def check_versions(root: Path, tag: str | None, *, scan: bool = True) -> dict[str, str]:
    """Return {version, semver, prerelease} or raise CheckFailed listing every mismatch."""
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(pyproject["project"]["version"])
    try:
        semver = pep440_to_semver(version)
    except CheckFailed as error:
        raise CheckFailed(f"pyproject.toml version: {error}") from None
    texts = _read_texts(root, {entry.path for entry in REGISTRY})
    problems = _check_texts(texts, version)
    if scan:
        problems += unregistered(root, version)
        problems += stale_allowances(root)
    if tag is not None:
        if not tag.startswith("v"):
            problems.append(f"tag {tag!r} does not start with 'v'")
        elif tag[1:] != semver:
            problems.append(f"tag {tag} names {tag[1:]}, but the tree is {version} ({semver})")
    if problems:
        raise CheckFailed("\n".join(problems))
    prerelease = "-" in semver
    return {"version": version, "semver": semver,
            "prerelease": "true" if prerelease else "false"}


def bump(root: Path, new: str) -> dict[str, tuple[str, str]]:
    """{path: (old text, new text)} for every file the bump changes.

    Refuses (CheckFailed) when an occurrence is unregistered or a pattern
    matches nothing, and checks the result before returning it.
    """
    forms = both_forms(new)
    current = str(tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
    problems = unregistered(root, current) + stale_allowances(root)
    texts = _read_texts(root, {entry.path for entry in REGISTRY})
    _, missing = registered_matches(texts)
    problems += missing
    if problems:
        raise CheckFailed("refusing to bump:\n" + "\n".join(problems))
    changed = dict(texts)
    for entry in REGISTRY:
        replacement = forms[entry.form]

        def swap(match: re.Match[str], replacement: str = replacement) -> str:
            start, end = match.span("v")
            whole_start = match.start()
            text = match.group(0)
            return text[: start - whole_start] + replacement + text[end - whole_start:]

        changed[entry.path] = entry.regex().sub(swap, changed[entry.path])
    after = _check_texts(changed, forms["pep440"])
    if after:
        raise CheckFailed("the bumped tree would not be consistent:\n" + "\n".join(after))
    return {path: (texts[path], changed[path]) for path in sorted(texts) if texts[path] != changed[path]}


def identity(root: Path) -> list[tuple[str, int, str, str]]:
    """[(path, line, name, line text)] for every organisation/registry/domain name."""
    names = [name for name, _ in IDENTITY_NAMES]
    found = []
    for path in text_files(root):
        if path in _IDENTITY_SELF:
            continue
        text = (root / path).read_text(encoding="utf-8")
        for number, line in enumerate(text.split("\n"), 1):
            lowered = line.lower()
            if not any(literal in lowered for literal in _IDENTITY_LITERALS):
                continue  # no name can match here; see _unfilterable_identity_names
            for match in _IDENTITY.finditer(line):
                index = int(next(key for key, value in match.groupdict().items() if value)[1:])
                found.append((path, number, names[index], line.strip()))
    return found


def _identity_keeps(path: str, name: str) -> bool:
    return name in _IDENTITY_DOMAIN_RETIRED and path.startswith("tests/")


def identity_leftovers(root: Path) -> list[tuple[str, int, str, str]]:
    """[(path, line, retired name, line text)] for each name this project does not hold."""
    found = []
    for path in text_files(root):
        if path in _IDENTITY_SELF:
            continue
        text = (root / path).read_text(encoding="utf-8")
        for number, line in enumerate(text.split("\n"), 1):
            lowered = line.lower()
            if not any(literal in lowered for literal in _IDENTITY_RETIRED_LITERALS):
                continue  # no retired name can match here; see _unfilterable_retired_names
            for name, pattern in _IDENTITY_RETIRED_RE:
                if pattern.search(line) and not _identity_keeps(path, name):
                    found.append((path, number, name, line.strip()))
                    break
    return found


#: A section that says it is not released: the placeholder a version carries
#: before it is tagged ("Not released. There is no tag ..."), and the
#: [Unreleased] preamble a fold can carry along. Matched at the start of a
#: line, so notes that mention a release in passing are not refused.
_NOT_RELEASED = re.compile(r"^(?:Not (?:yet )?released\.|Nothing here has been released\b)", re.M)


#: What the tree says before there is a release. The readme pyproject.toml
#: names (README.pypi.md) is the PyPI description, and an uploaded version's page cannot be replaced, so one of these
#: would tell that page's readers the page does not exist. Every development build
#: carries them, so only what runs for a tag reads them.
_PRE_RELEASE_STATEMENT = re.compile(
    r"\bno release (?:exists|has been tagged)\b|\bnot on PyPI\b|\b(?:until|before) the first release\b"
    r"|\bunclaimed\b|\bnot (?:yet )?published\b|\b(?:neither|nothing) is published\b|\bno image is published\b"
    r"|\bReleases\.\*\* None yet\b|\bREPLACE_WITH_THE_PATH_OF_A_VERIDOR_WHEEL\b"
    # "which": src/veridor/cli.py says paths "that do not exist yet", which is no release statement.
    r"|\bwhich (?:does|do) not exist yet\b|\b(?:does|do) not exist until (?:Veridor's |the )?first release\b",
    re.IGNORECASE)

#: Not read for those phrases: tests hold them as data, the changelog's preamble
#: has its own rule, and the other two describe the rule and so quote it. Every
#: other shipped file is read, because a list of files is one more place a new
#: "not published" sentence can be missing from.
_RELEASE_STATEMENT_EXCLUDED_PREFIXES = ("tests/",)
_RELEASE_STATEMENT_EXCLUDED_FILES = frozenset({"CHANGELOG.md", "CONTRIBUTING.md", "scripts/release_check.py"})


def pre_release_statements(text: str) -> list[str]:
    """Each distinct pre-release statement in ``text``, across line breaks."""
    return sorted({found.group(0).lower() for found in _PRE_RELEASE_STATEMENT.finditer(" ".join(text.split()))})


def tree_release_statements(root: Path) -> list[str]:
    """One problem per file a tag must not leave saying no release exists."""
    problems = []
    for name in text_files(root):
        if name.startswith(_RELEASE_STATEMENT_EXCLUDED_PREFIXES) or name in _RELEASE_STATEMENT_EXCLUDED_FILES:
            continue
        found = pre_release_statements((root / name).read_text(encoding="utf-8"))
        if found:
            problems.append(f"{name} still says {found}; rewrite it before tagging "
                            "(CONTRIBUTING.md, \"Releasing\")")
    return problems


def _section(lines: list[str], names: set[str]) -> tuple[int, int] | None:
    """(first body line, end) of the first ``## [NAME]`` section, or None."""
    for index, line in enumerate(lines):
        match = re.match(r"^## \[([^\]]+)\]", line)
        if match and match.group(1) in names:
            end = next((i for i in range(index + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
            return index + 1, end
    return None


def release_notes(changelog: str, tag: str) -> str:
    """The CHANGELOG section for the tag: present and not empty.

    A reader: tests/test_release_files.py uses it on every tree to check the
    current version has a section. What `notes`, and so release.yml, prints
    goes through publishable_notes(), which also refuses what a development
    tree legitimately has (a placeholder section, entries in [Unreleased])."""
    semver = tag.removeprefix("v")
    candidates = {semver, semver_to_pep440(semver)}
    lines = changelog.splitlines()
    found = _section(lines, candidates)
    if found is None:
        raise CheckFailed(f"CHANGELOG.md has no '## [{semver}]' section; write the release "
                          "notes there before tagging")
    body = "\n".join(lines[found[0]:found[1]]).strip()
    if not body:
        raise CheckFailed(f"CHANGELOG.md's '## [{semver}]' section is empty")
    return body + "\n"


def publishable_notes(changelog: str, tag: str) -> str:
    """release_notes(), refused unless it can be posted as the tag's release.

    It used to be release_notes() alone: on a tree whose section still said
    "Not released. There is no tag ..." `notes` exited 0 and printed that,
    and the [Unreleased] entries were left out of the notes."""
    body = release_notes(changelog, tag)
    semver = tag.removeprefix("v")
    placeholder = _NOT_RELEASED.search(body)
    if placeholder:
        raise CheckFailed(f"CHANGELOG.md's '## [{semver}]' section says it is not released "
                          f"({placeholder.group(0)!r}); replace that with the release notes, "
                          "folding [Unreleased] into it, before tagging")
    lines = changelog.splitlines()
    unreleased = _section(lines, {"Unreleased"})
    if unreleased and "\n".join(lines[unreleased[0]:unreleased[1]]).strip():
        raise CheckFailed(f"CHANGELOG.md's '## [Unreleased]' is not empty: its entries are changes "
                          f"in the tagged tree, and the notes for {semver} would leave them out. "
                          f"Move them under '## [{semver}]' and leave '## [Unreleased]' empty")
    return body


def check_dist(directory: Path, version: str, *, require_zipapp: bool = False,
               tagged: bool = False) -> list[str]:
    """Every problem with the built artifacts, or [].

    ``tagged`` is a build about to be published, which also has to carry a
    description that can stand on PyPI."""
    problems: list[str] = []
    if require_zipapp and not (directory / f"veridor-{version}.pyz").is_file():
        problems.append(f"veridor-{version}.pyz is missing (scripts/build_zipapp.py builds it)")
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    expected_wheel = f"veridor-{version}-py3-none-any.whl"
    expected_sdist = f"veridor-{version}.tar.gz"
    if [w.name for w in wheels] != [expected_wheel]:
        problems.append(f"expected exactly {expected_wheel}, found {[w.name for w in wheels]}")
    if [s.name for s in sdists] != [expected_sdist]:
        problems.append(f"expected exactly {expected_sdist}, found {[s.name for s in sdists]}")
    if not problems:
        with zipfile.ZipFile(wheels[0]) as wheel:
            wheel_names = set(wheel.namelist())
            info = f"veridor-{version}.dist-info"
            metadata = email.parser.Parser().parsestr(
                wheel.read(f"{info}/METADATA").decode("utf-8"), headersonly=True)
            if tagged:
                problems += _description_problems(expected_wheel, metadata)
            problems += _description_link_problems(expected_wheel, metadata)
            for name in ("LICENSE", "NOTICE"):
                if f"{info}/licenses/{name}" not in wheel_names:
                    problems.append(f"{expected_wheel} does not contain {info}/licenses/{name}")
            problems += _wheel_content_problems(expected_wheel, info, wheel_names)
        problems += _metadata_problems(expected_wheel, metadata, version)
        with tarfile.open(sdists[0]) as sdist:
            members = set(sdist.getnames())
            base = f"veridor-{version}"
            for name in ("LICENSE", "NOTICE", "PKG-INFO"):
                if f"{base}/{name}" not in members:
                    problems.append(f"{expected_sdist} does not contain {base}/{name}")
            if f"{base}/PKG-INFO" in members:
                handle = sdist.extractfile(f"{base}/PKG-INFO")
                pkg_info = email.parser.Parser().parsestr(
                    handle.read().decode("utf-8"), headersonly=True)  # type: ignore[union-attr]
                if tagged:
                    problems += _description_problems(expected_sdist, pkg_info)
                problems += _description_link_problems(expected_sdist, pkg_info)
                problems += _metadata_problems(expected_sdist, pkg_info, version)
            problems += _sdist_content_problems(expected_sdist, base, members, wheel_names,
                                                _sdist_readme(sdist, base, members))
    for pyz in sorted(directory.glob("*.pyz")):
        if pyz.name != f"veridor-{version}.pyz":
            problems.append(f"zipapp is named {pyz.name}, expected veridor-{version}.pyz")
        with zipfile.ZipFile(pyz) as archive:
            names = set(archive.namelist())
        for name in ("__main__.py", "LICENSE", "NOTICE", "veridor/__init__.py", "veridor/cli.py"):
            if name not in names:
                problems.append(f"{pyz.name} does not contain {name}")
        stray = sorted(n for n in names if "__pycache__" in n or not n.startswith("veridor/")
                       and n not in ("__main__.py", "LICENSE", "NOTICE"))
        if stray:
            problems.append(f"{pyz.name} contains files it must not ship: {stray[:5]}")
    return problems


def _wheel_content_problems(wheel: str, info: str, names: set[str]) -> list[str]:
    """Only the package and its dist-info, as an allowlist: a list of what to
    refuse passed a wheel holding tests/ or a local directory, and PyPI cannot take
    a version back."""
    stray = sorted(name for name in names
                   if not name.startswith(("veridor/", f"{info}/"))
                   or "__pycache__" in name or name.endswith(".pyc"))
    return [f"{wheel} contains files it must not ship: {stray[:5]}"] if stray else []


#: The top-level files an sdist holds beside src/, and what setuptools adds.
_SDIST_TOP_LEVEL = frozenset({"LICENSE", "NOTICE", "MANIFEST.in", "PKG-INFO", "README.md",
                              "pyproject.toml", "setup.cfg"})


def _sdist_readme(sdist: tarfile.TarFile, base: str, members: set[str]) -> str | None:
    """The readme the sdist's own pyproject.toml names, which a rebuild reads."""
    if f"{base}/pyproject.toml" not in members:
        return None
    handle = sdist.extractfile(f"{base}/pyproject.toml")
    try:
        readme = tomllib.loads(handle.read().decode("utf-8")).get("project", {}).get("readme")  # type: ignore[union-attr]
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None
    if isinstance(readme, dict):
        readme = readme.get("file")
    return readme if isinstance(readme, str) and "/" not in readme else None


def _sdist_content_problems(sdist: str, base: str, members: set[str],
                            wheel_names: set[str], readme: str | None = None) -> list[str]:
    """What the sdist must hold, and must not.

    It is what a downstream builder turns into the wheel, so every file the
    wheel installs has to be in it: a MANIFEST.in rule that pruned too much
    would publish an sdist that builds a different Veridor. It is not a way to
    run the suite: setuptools used to add tests/test_*.py without the helpers
    they import, so 0 of the 51 it shipped could be imported (measured).
    ``readme`` is the file its pyproject.toml names, which a rebuild reads.
    """
    problems = []
    readmes = {"README.md"} | ({readme} if readme else set())
    top_level = _SDIST_TOP_LEVEL | readmes
    needed = {f"{base}/pyproject.toml"} | {f"{base}/{name}" for name in readmes} | {
        f"{base}/src/{name}" for name in wheel_names
        if name.startswith("veridor/") and not name.endswith("/")}
    missing = sorted(needed - members)
    if missing:
        problems.append(f"{sdist} cannot rebuild the wheel; it does not contain {missing[:5]}")
    allowed = {base, f"{base}/src", f"{base}/src/veridor", f"{base}/src/veridor.egg-info"} | {
        f"{base}/{name}" for name in top_level}
    stray = sorted(
        name for name in members
        if not (name in allowed or name.startswith((f"{base}/src/veridor/", f"{base}/src/veridor.egg-info/")))
        or "__pycache__" in name or name.endswith(".pyc"))
    if stray:
        problems.append(f"{sdist} contains files it must not ship: {stray[:5]}")
    return problems


def owner_problems(root: Path, repository: str, image: str, chart_repository: str) -> list[str]:
    """Each place the tree names a repository or registry that is not this one's."""
    owner, _, name = repository.partition("/")
    if not owner or not name:
        return [f"--repository {repository!r} is not OWNER/REPO"]
    prefix = f"ghcr.io/{owner.lower()}/"
    problems = []
    if not chart_repository.startswith("oci://"):
        problems.append(f"CHART_REPOSITORY {chart_repository!r} does not start with oci://")
    for what, reference in (("IMAGE", image), ("CHART_REPOSITORY", chart_repository.removeprefix("oci://"))):
        if not reference.startswith(prefix):
            problems.append(f"{what} {reference!r} is not under {prefix}, where this repository's "
                            "GITHUB_TOKEN can push: rename it before tagging")
        elif reference != reference.lower():
            problems.append(f"{what} {reference!r} has capitals, which a registry reference cannot hold")
    values = (root / "deploy/helm/veridor-gate/values.yaml").read_text(encoding="utf-8")
    default = re.search(r"^image:\n(?:[ \t]+#.*\n)*[ \t]+repository:[ \t]*(\S+)", values, re.M)
    if default is None:
        problems.append("deploy/helm/veridor-gate/values.yaml has no image.repository to compare with IMAGE")
    elif default.group(1).strip("\"'") != image:
        problems.append(f"deploy/helm/veridor-gate/values.yaml's image.repository is {default.group(1)}, "
                        f"not IMAGE {image}: the chart job would refuse it after the PyPI upload")
    urls = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["urls"]
    if urls.get("Repository", "").casefold() != f"https://github.com/{repository}".casefold():
        problems.append(f"pyproject.toml's Repository is {urls.get('Repository')!r}, not this repository, "
                        f"{repository}: PyPI's page cannot be changed once it is uploaded")
    return problems + _signing_identity_problems(root, repository)


def _signing_identity_problems(root: Path, repository: str) -> list[str]:
    """SECURITY.md's `gh attestation verify` commands name the signer, and the
    comparison is exact. GitHub's own spelling of the repository is the one in the
    certificate, and this is the one place that has it. A difference only in case
    passed every other check here, and would have made genuine signatures fail on
    a page that is hard to change once a release is out."""
    path = root / "SECURITY.md"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    # A regexp identity escapes its dots (github\.com); reading only the plain
    # spelling skipped one naming another repository, and the check passed.
    named = re.findall(r"github\\?\.com/([^/\s]+/[^/\s]+)/\\?\.github/workflows/release", text)
    if not named:
        return ["SECURITY.md names no release.yml signing identity to compare with this repository"]
    problems = [f"SECURITY.md's signing identity names {name}, not {repository}: "
                "the certificate is compared exactly, so genuine signatures would be refused"
                for name in sorted(set(named)) if name != repository]
    # `gh attestation verify --repo` names the repository the attestation must
    # come from; one naming another repository refuses every genuine file.
    # Compared case blind: GitHub resolves a repository name in any case, and
    # whether gh then compares it exactly is not measured here.
    repos = re.findall(r"(?<![\w-])(?:--repo|-R)(?:=|[ \t]+|[ \t]*\\\n[ \t]*)['\"]?([^\s'\"\\]+)", text)
    owners = re.findall(r"(?<![\w-])--owner(?:=|[ \t]+|[ \t]*\\\n[ \t]*)['\"]?([^\s'\"\\]+)", text)
    problems += [f"SECURITY.md's gh attestation --owner names {name}, not {repository.split('/')[0]}: "
                 "genuine attestations would be refused"
                 for name in sorted(set(owners)) if name.casefold() != repository.split("/")[0].casefold()]
    return problems + [f"SECURITY.md's gh attestation --repo names {name}, not {repository}: "
                       "genuine attestations would be refused"
                       for name in sorted(set(repos)) if name.casefold() != repository.casefold()]


#: A link target that works on a page with no base URL.
_ABSOLUTE_TARGET = re.compile(r"^(?:https?://|mailto:)", re.IGNORECASE)
_FENCED_BLOCK = re.compile(r"^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1[ \t]*$", re.M | re.S)
_CODE_SPAN = re.compile(r"(`+)(?!`).+?(?<!`)\1", re.S)
_LINK_TARGETS = (
    re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^\s)>]*)"),          # [text](target), ![alt](src)
    re.compile(r"^ {0,3}\[[^\]]+\]:[ \t]*<?([^\s>]+)", re.M),                   # [label]: target
    re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*)>"),                      # <scheme:...>
    re.compile(r"\b(?:href|src)\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE),        # raw HTML
)


def description_link_problems(description: str) -> list[str]:
    """Each link target in a markdown description that is not an absolute
    http(s) or mailto URL, once, in order. Code is not read: a link written
    inside a code span or block is text on PyPI too.

    The README was the description. Its 24 repository-relative links and 30
    ``#anchor`` links all resolve on GitHub and none of them on pypi.org,
    which has no repository to resolve a path against and gives headings no
    ids. The only rule against that was a sentence in CONTRIBUTING.md."""
    text = _CODE_SPAN.sub("code", _FENCED_BLOCK.sub("", description))
    found: list[str] = []
    for pattern in _LINK_TARGETS:
        for match in pattern.finditer(text):
            target = match.group(1)
            if not _ABSOLUTE_TARGET.match(target) and target not in found:
                found.append(target)
    return found


def _description_link_problems(artifact: str, metadata) -> list[str]:
    description = metadata.get_payload()
    targets = description_link_problems(description) if isinstance(description, str) else []
    if not targets:
        return []
    return [f"{artifact}: its description, the PyPI page, has {len(targets)} link(s) that are not "
            f"absolute URLs, which go nowhere on PyPI: {targets[:8]}; make every link in the readme "
            "pyproject.toml names absolute (CONTRIBUTING.md, \"Releasing\")"]


def _description_problems(artifact: str, metadata) -> list[str]:
    """An empty description is a problem too: this rule would read nothing."""
    description = metadata.get_payload()
    if not isinstance(description, str) or not description.strip():
        return [f"{artifact}: has no long description"]
    found = pre_release_statements(description)
    if found:
        return [f"{artifact}: its description, the PyPI page, still says {found}; "
                "rewrite the readme pyproject.toml names before tagging (CONTRIBUTING.md, \"Releasing\")"]
    return []


def _metadata_problems(artifact: str, metadata, version: str) -> list[str]:
    problems = []
    if metadata.get("Version") != version:
        problems.append(f"{artifact}: Version is {metadata.get('Version')!r}, expected {version}")
    if metadata.get("License-Expression") != "Apache-2.0":
        problems.append(f"{artifact}: License-Expression is {metadata.get('License-Expression')!r}")
    files = metadata.get_all("License-File") or []
    if sorted(files) != ["LICENSE", "NOTICE"]:
        problems.append(f"{artifact}: License-File is {files}, expected LICENSE and NOTICE")
    if any(value.startswith("License ::") for value in metadata.get_all("Classifier") or []):
        problems.append(f"{artifact}: carries a License classifier next to License-Expression")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    versions = commands.add_parser("versions", help="check every registered version string agrees")
    versions.add_argument("--tag", help="the git tag being released, e.g. vX.Y.Z")
    versions.add_argument("--list", action="store_true",
                          help="also print every registered occurrence (to stderr)")
    bumper = commands.add_parser("bump", help="rewrite every registered version string")
    bumper.add_argument("version", help="the new version, X.Y.Z, X.Y.ZrcN or X.Y.Z-rc.N")
    bumper.add_argument("--write", action="store_true",
                        help="apply the change (default: print the diff and change nothing)")
    notes = commands.add_parser("notes", help="print the CHANGELOG section for a tag")
    notes.add_argument("tag")
    dist = commands.add_parser("dist", help="check the built artifacts")
    dist.add_argument("directory", type=Path)
    dist.add_argument("--tag", help="the git tag; defaults to the tree's version")
    dist.add_argument("--require-zipapp", action="store_true",
                      help="fail when veridor-<version>.pyz is not in the directory")
    commands.add_parser("identity", help="list every organisation/registry/domain name occurrence")
    owner = commands.add_parser("owner", help="compare the tree with the repository a release runs in")
    owner.add_argument("--repository", required=True, help="OWNER/REPO, $GITHUB_REPOSITORY")
    owner.add_argument("--image", required=True, help="release.yml's IMAGE")
    owner.add_argument("--chart-repository", required=True, help="release.yml's CHART_REPOSITORY")
    args = parser.parse_args(argv)
    try:
        if args.command == "versions":
            result = check_versions(args.root, args.tag)
            for key, value in result.items():
                print(f"{key}={value}")
            if args.list:
                found, _ = registered_matches(_read_texts(args.root, {e.path for e in REGISTRY}))
                for entry, line, value in found:
                    print(f"{entry.path}:{line}: {value} ({entry.form}; {entry.what})", file=sys.stderr)
                print(f"{len(found)} registered occurrence(s) in "
                      f"{len({entry.path for entry, _, _ in found})} file(s)", file=sys.stderr)
        elif args.command == "bump":
            changes = bump(args.root, args.version)
            for path, (old, new) in changes.items():
                sys.stdout.writelines(difflib.unified_diff(
                    old.splitlines(keepends=True), new.splitlines(keepends=True),
                    fromfile=f"a/{path}", tofile=f"b/{path}"))
            if args.write:
                for path, (_, new) in changes.items():
                    (args.root / path).write_text(new, encoding="utf-8")
                print(f"bumped {len(changes)} file(s) to {args.version}", file=sys.stderr)
            else:
                print(f"dry run: {len(changes)} file(s) would change; pass --write to apply",
                      file=sys.stderr)
        elif args.command == "notes":
            body = publishable_notes((args.root / "CHANGELOG.md").read_text(encoding="utf-8"), args.tag)
            stale = tree_release_statements(args.root)
            if stale:
                raise CheckFailed("\n".join(stale))
            sys.stdout.write(body)
        elif args.command == "owner":
            problems = owner_problems(args.root, args.repository, args.image, args.chart_repository)
            if problems:
                raise CheckFailed("\n".join(problems))
            print(f"{args.image} and {args.chart_repository} are under {args.repository}'s owner, "
                  "and the chart and the package metadata agree")
        elif args.command == "identity":
            found = identity(args.root)
            for path, line, name, text in found:
                print(f"{path}:{line}: {name}: {text[:140]}")
            counts: dict[str, int] = {}
            for _, _, name, _ in found:
                counts[name] = counts.get(name, 0) + 1
            summary = ", ".join(f"{name} {counts.get(name, 0)}" for name, _ in IDENTITY_NAMES)
            print(f"{len(found)} occurrence(s) on {len({(p, n) for p, n, _, _ in found})} line(s) "
                  f"in {len({p for p, _, _, _ in found})} file(s): {summary} "
                  f"(not counted: {', '.join(sorted(_IDENTITY_SELF))}, which define the list; "
                  "a rename must also change their REGISTRY patterns and release literals)")
            leftovers = identity_leftovers(args.root)
            if leftovers:
                raise CheckFailed("\n".join(
                    f"{path}:{line}: {name} is a name this project does not hold: {text[:140]}"
                    for path, line, name, text in leftovers))
        else:
            version = check_versions(args.root, args.tag)["version"]
            problems = check_dist(args.directory, version, require_zipapp=args.require_zipapp,
                                  tagged=args.tag is not None)
            if problems:
                raise CheckFailed("\n".join(problems))
            print(f"dist/ checks passed for {version}: "
                  f"{sorted(p.name for p in args.directory.iterdir())}")
    except CheckFailed as error:
        for line in str(error).splitlines():
            print(f"::error title=release check::{line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
