"""The files a stranger reads before they trust the tool.

None of these change what Veridor does, which is exactly why they rot: nothing
fails when SECURITY.md points at a repository that was renamed, or when the
Action example in the README pins a tag that does not exist. A reader who
follows a broken instruction concludes the project is unmaintained, and they are
not being unreasonable.

So the checks here are about CONSISTENCY between files rather than about
content. A policy nobody can act on is worse than no policy, because it looks
like one.
"""

from __future__ import annotations

import ast
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import tomllib
import unittest
import json
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from dockerignore_model import ignored, read_patterns  # noqa: E402
from scripts import sync_doc_counts  # noqa: E402
from tiers import slow  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

#: The GitHub `owner/repo` every published link has to agree on, taken from the
#: packaging metadata rather than restated here.
REPOSITORY = PYPROJECT["project"]["urls"]["Repository"].removeprefix(
    "https://github.com/"
)


def repository_this_runs_in(environ: dict[str, str] | os._Environ[str] = os.environ) -> str:
    """The `owner/repo` the tree has to name: GitHub's own GITHUB_REPOSITORY on
    Actions, and pyproject's offline, where nothing else knows.

    A fork's own Actions run keeps pyproject's: the tree there rightly still
    names the upstream repository. A pull request from a fork runs as the
    upstream repository, so it is compared. An event file that cannot be read
    says nothing about a fork, so the comparison stands."""
    running = environ.get("GITHUB_REPOSITORY")
    if not running:
        return REPOSITORY
    try:
        event = json.loads(Path(environ.get("GITHUB_EVENT_PATH", "")).read_text(encoding="utf-8"))
        fork = (event.get("repository") or {}).get("fork") is True
    except (OSError, ValueError, AttributeError):
        fork = False
    return REPOSITORY if fork else running


def links_to_another_repository(expected: str) -> list[tuple[str, str]]:
    """(file, owner/repo) for each published GitHub link not to ``expected``,
    with pyproject's own Repository first. GitHub treats owner names without
    regard to case."""
    wrong = [("pyproject.toml", REPOSITORY)] if REPOSITORY.casefold() != expected.casefold() else []
    for name in ("SECURITY.md", "README.md", ".github/PULL_REQUEST_TEMPLATE.md",
                 ".github/ISSUE_TEMPLATE/config.yml",
                 ".github/ISSUE_TEMPLATE/bug_report.yml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        wrong += [(name, link) for link in re.findall(r"https://github\.com/([\w.-]+/[\w.-]+)", text)
                  if link.casefold() != expected.casefold()]
    return wrong


class PresenceTest(unittest.TestCase):
    def test_the_files_a_public_repository_is_expected_to_have(self) -> None:
        for name in ("LICENSE", "README.md", "SECURITY.md", "CONTRIBUTING.md",
                     "CHANGELOG.md", ".github/PULL_REQUEST_TEMPLATE.md",
                     ".github/ISSUE_TEMPLATE/config.yml"):
            with self.subTest(file=name):
                path = ROOT / name
                self.assertTrue(path.is_file(), f"{name} is missing")
                self.assertGreater(len(path.read_text(encoding="utf-8")), 200, name)

    def test_packaging_metadata_carries_the_links(self) -> None:
        """A PyPI page with no source, issues or security link asks the reader
        to trust a security tool on nothing."""
        urls = PYPROJECT["project"]["urls"]
        for key in ("Homepage", "Repository", "Issues", "Security policy"):
            self.assertIn(key, urls)
            self.assertTrue(urls[key].startswith("https://"), key)

    #: The two hosts the project holds, and the pages they serve: the product
    #: page and the docs. This test said every link had to be on the
    #: repository, because no domain served anything then; Homepage and
    #: Documentation pointed at the repository root and a blob/main README.
    HELD = {"Homepage": "https://veridor.org/", "Documentation": "https://docs.veridor.org/"}

    @classmethod
    def links_off_what_the_project_holds(cls, urls: dict[str, str]) -> dict[str, str]:
        return {key: url for key, url in urls.items()
                if url != cls.HELD.get(key) and not url.startswith(f"https://github.com/{REPOSITORY}/")
                and url != f"https://github.com/{REPOSITORY}"}

    def test_every_metadata_link_is_on_the_repository_or_a_held_host(self) -> None:
        """Metadata is fixed once a release is uploaded, so each link names the
        repository or one of the two hosts the project holds, and Homepage and
        Documentation name those hosts."""
        urls = PYPROJECT["project"]["urls"]
        self.assertEqual({key: urls.get(key) for key in self.HELD}, self.HELD)
        self.assertEqual(self.links_off_what_the_project_holds(urls), {})

    def test_control_a_link_off_the_held_hosts_is_named(self) -> None:
        for key, url in (("Documentation", "https://www.veridor.org/"),
                         ("Homepage", "https://docs.veridor.org/"),
                         ("Changelog", "https://veridor.org/changelog"),
                         ("Issues", f"https://github.com/{REPOSITORY}x/issues")):
            with self.subTest(url=url):
                self.assertEqual(self.links_off_what_the_project_holds({key: url}), {key: url})

    def test_the_metadata_describes_what_the_readme_describes(self) -> None:
        """It opened with "Deterministic", which identical `mutate` runs on a
        noisy target are not, and which the README does not claim of the tool."""
        description = PYPROJECT["project"]["description"]
        self.assertIn("authorization regression runner", description)
        self.assertIn("authorization regression runner", " ".join(README.split()).replace("**", ""))
        self.assertNotIn("Deterministic", description)

    def test_the_classifier_comment_does_not_say_ci_has_run(self) -> None:
        """The comment names what CI is set up to test, which a passing run
        does not widen. SUPPORT.md says the same."""
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("was RUN", text)
        self.assertIn("is configured to run the fast tier and a wheel", " ".join(text.replace("#", "").split()))

    def test_the_licence_matches_the_one_the_metadata_declares(self) -> None:
        """The metadata names Apache-2.0 as a PEP 639 expression; LICENSE is the
        licence text itself (tests/test_packaging.py checks it byte for byte)."""
        self.assertEqual(PYPROJECT["project"]["license"], "Apache-2.0")
        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", licence)
        self.assertIn("Version 2.0", licence)
        self.assertIn("END OF TERMS AND CONDITIONS", licence)
        self.assertIn("Apache License 2.0",
                      (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"))


class PythonSupportTest(unittest.TestCase):
    """Three places state which interpreters Veridor runs on. They must agree.

    `requires-python` is the one pip ENFORCES: a floor of 3.11 means somebody
    on 3.11 is allowed to install, and if nothing ever ran there they find out
    it was a guess at the worst moment. The classifiers are what a reader sees
    on PyPI. The CI matrix is the only one of the three that is evidence.

    So the rule is: every version claimed is a version tested, and the floor is
    the lowest one tested. Nothing here checks that the versions are *right* --
    only that no list can quietly drift from the others, which is how this went
    out of sync in the first place (floor 3.11, CI 3.12-only, classifier 3.11).
    """

    WORKFLOW = (ROOT / ".github" / "workflows" / "veridor.yml").read_text(
        encoding="utf-8"
    )

    @staticmethod
    def _versions(values) -> list[tuple[int, ...]]:
        return sorted(tuple(int(part) for part in value.split("."))
                      for value in values)

    def _classifier_versions(self) -> set[str]:
        return {
            line.rsplit(" :: ", 1)[-1]
            for line in PYPROJECT["project"]["classifiers"]
            if line.startswith("Programming Language :: Python :: ")
            and line.rsplit(" :: ", 1)[-1] != "3"
        }

    def _matrix_versions(self) -> set[str]:
        block = re.search(r"python-version: \[(.*?)\]", self.WORKFLOW)
        self.assertIsNotNone(block, "the fast tier no longer runs a version matrix")
        return set(re.findall(r'"([\d.]+)"', block.group(1)))

    def test_every_classified_version_is_tested_in_ci(self) -> None:
        untested = self._classifier_versions() - self._matrix_versions()
        self.assertFalse(
            untested,
            f"pyproject claims Python {sorted(untested)} and CI never runs it. "
            "Add it to the matrix in .github/workflows/veridor.yml, or drop the "
            "classifier.",
        )

    def test_every_tested_version_is_classified(self) -> None:
        unclaimed = self._matrix_versions() - self._classifier_versions()
        self.assertFalse(
            unclaimed,
            f"CI runs Python {sorted(unclaimed)} and pyproject does not say so.",
        )

    def test_requires_python_matches_the_lowest_tested_version(self) -> None:
        floor = PYPROJECT["project"]["requires-python"]
        self.assertTrue(floor.startswith(">="), floor)
        declared = tuple(int(part) for part in floor.removeprefix(">=").split("."))
        lowest = self._versions(self._matrix_versions())[0]
        self.assertEqual(
            declared, lowest,
            f"requires-python is {floor} but the lowest version CI runs is "
            f"{'.'.join(str(part) for part in lowest)}. pip enforces the floor, "
            "so an untested one is a promise to somebody who cannot check it.",
        )

    def test_ci_installs_the_wheel_on_every_version(self) -> None:
        """Running from a checkout on 3.11 says nothing about installing there,
        and installing is what a user does. The installed-package job builds
        the wheel, installs it into a fresh venv and runs the suite against it
        on every classified version."""
        job = self.WORKFLOW[self.WORKFLOW.index("\n  installed-package:"):
                            self.WORKFLOW.index("\n  action-e2e:")]
        block = re.search(r"python-version: \[(.*?)\]", job)
        self.assertIsNotNone(block, "the installed-package job runs no version matrix")
        self.assertEqual(set(re.findall(r'"([\d.]+)"', block.group(1))),
                         self._classifier_versions())
        self.assertIn("python -m build --no-isolation --outdir dist .", job)
        self.assertIn('-m pip install --no-index --no-deps dist/*.whl', job)
        self.assertEqual(job.count("VERIDOR_TEST_AGAINST: installed"), 2)

    def test_the_readme_install_section_states_the_same_floor(self) -> None:
        floor = PYPROJECT["project"]["requires-python"].removeprefix(">=")
        self.assertIn(f"Python {floor} or newer", README)


class ConfigSchemaTest(unittest.TestCase):
    """The JSON Schema in this tree must match the loader.

    A schema is a promise an editor shows people while they type. If it drifts
    from `core`'s validation the editor green-lights a config the tool refuses,
    which is worse than having no schema: the reader trusts the wrong one.

    Checked structurally against the code's OWN key sets rather than with a
    validator library -- the runtime is stdlib-only and a docs artifact is not
    a reason to break that.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "schema" / "veridor-config-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )

    def _resolve(self, node: dict) -> dict:
        """Follow a local ``$ref``; the schema factors shared shapes into $defs."""
        while "$ref" in node:
            target = self.schema
            for part in node["$ref"].lstrip("#").split("/")[1:]:
                target = target[part]
            node = target
        return node

    def test_identity_keys_match_the_loader(self) -> None:
        from veridor.core import _IDENTITY_KEYS

        declared = set(
            self._resolve(
                self.schema["properties"]["identities"]["additionalProperties"]
            )["properties"]
        )
        self.assertEqual(declared, set(_IDENTITY_KEYS))

    def test_request_keys_match_the_loader(self) -> None:
        from veridor.core import _REQUEST_KEYS

        declared = set(self.schema["$defs"]["request"]["properties"])
        self.assertEqual(declared, set(_REQUEST_KEYS))

    def test_expectation_keys_match_the_loader(self) -> None:
        from veridor.core import _MARKER_EXPECT_KEYS

        expect = self.schema["properties"]["checks"]["items"]["properties"]["expect"]
        # One form only: the loader refuses the "allow"/"deny" strings the
        # schema used to offer as an alternative.
        obj = self._resolve(expect["additionalProperties"])
        self.assertEqual(obj.get("type"), "object")
        self.assertEqual(set(obj["properties"]), set(_MARKER_EXPECT_KEYS))

    def test_safe_methods_are_named_as_safe(self) -> None:
        """The schema says which verbs are safe; `core` decides. One source."""
        from veridor.core import SAFE_METHODS

        described = self.schema["$defs"]["request"]["properties"]["method"][
            "description"
        ]
        for method in sorted(SAFE_METHODS):
            self.assertIn(method, described)

    def test_the_id_pattern_matches_the_loader(self) -> None:
        from veridor.core import _SAFE_NAME

        for path in (
            self.schema["properties"]["identities"]["propertyNames"]["pattern"],
            self.schema["properties"]["checks"]["items"]["properties"]["id"]["pattern"],
        ):
            self.assertEqual(path, _SAFE_NAME.pattern)

    def test_every_shipped_fixture_satisfies_the_required_keys(self) -> None:
        required = set(self.schema["required"])
        for fixture in sorted((ROOT / "fixtures").glob("veridor*.json")):
            with self.subTest(fixture=fixture.name):
                config = json.loads(fixture.read_text(encoding="utf-8"))
                self.assertEqual(required - set(config), set())

    def test_the_schema_id_is_an_identifier_and_says_so(self) -> None:
        """A $id names a schema; it need not resolve. The docs site serves a
        copy at this one, and the description says so, but nothing in the
        schema may depend on fetching it: every $ref stays inside the file."""
        self.assertEqual(
            self.schema["$id"],
            "https://docs.veridor.org/schema/veridor-config-v1.schema.json",
        )
        self.assertIn("the docs site serves a copy of this file at that address", self.schema["description"])
        self.assertNotIn("nothing is served", self.schema["description"])
        references = re.findall(r'"\$ref": "([^"]+)"', json.dumps(self.schema))
        self.assertTrue(references, "the schema no longer factors anything into $defs")
        self.assertEqual([ref for ref in references if not ref.startswith("#")], [])


class ConsistencyTest(unittest.TestCase):
    """Every published file has to name the same repository and the same tag."""

    def test_every_github_link_points_at_this_repository(self) -> None:
        """On Actions this compares the tree with the repository it runs in.
        Offline it can only compare the links with pyproject: both used to come
        from the tree, so an owner nobody controls passed on every run."""
        self.assertEqual(links_to_another_repository(repository_this_runs_in()), [])

    def test_a_wrong_owner_fails_where_github_says_which_repository_this_is(self) -> None:
        event = Path(tempfile.mkdtemp()) / "event.json"
        self.addCleanup(shutil.rmtree, event.parent, True)
        elsewhere = {"GITHUB_REPOSITORY": "someone-else/veridor", "GITHUB_EVENT_PATH": str(event)}
        event.write_text('{"repository": {"fork": false}}', encoding="utf-8")
        self.assertEqual(repository_this_runs_in(elsewhere), "someone-else/veridor")
        wrong = links_to_another_repository(repository_this_runs_in(elsewhere))
        self.assertIn(("pyproject.toml", REPOSITORY), wrong)
        self.assertIn(("SECURITY.md", REPOSITORY), wrong)
        # An unreadable event file does not excuse it.
        self.assertEqual(repository_this_runs_in({"GITHUB_REPOSITORY": "someone-else/veridor"}), "someone-else/veridor")

    def test_control_offline_a_fork_and_another_case_compare_with_the_tree(self) -> None:
        self.assertEqual(repository_this_runs_in({}), REPOSITORY)
        event = Path(tempfile.mkdtemp()) / "event.json"
        self.addCleanup(shutil.rmtree, event.parent, True)
        event.write_text('{"repository": {"fork": true}}', encoding="utf-8")
        self.assertEqual(repository_this_runs_in({"GITHUB_REPOSITORY": "someone-else/veridor",
                                                  "GITHUB_EVENT_PATH": str(event)}), REPOSITORY)
        self.assertEqual(links_to_another_repository(REPOSITORY), [])
        self.assertEqual(links_to_another_repository(REPOSITORY.upper()), [])

    def test_the_action_examples_pin_a_commit_never_a_tag(self) -> None:
        """`uses: ./` only resolves inside this repository, a floating ref means
        a push here changes what runs in somebody's pipeline with their
        credentials in the environment, and the `@v0.1.0` the README used to
        show named a tag that did not exist. So this repository's Action is
        shown pinned to a commit: the `<full-commit-sha>` placeholder with a
        `# vX.Y.Z` comment, which the README says stands for the commit a
        release tag points to (the text is committed before the tag exists, so
        it cannot name that SHA), or a real 40-hex SHA with a `# vX.Y.Z`
        comment after. Every other action shown is pinned the same way this
        repository pins its own."""
        uses = re.findall(r"^\s*(?:- )?uses: (\S+)(.*)$", README, re.MULTILINE)
        ours = [(ref, rest) for ref, rest in uses if ref.startswith(REPOSITORY + "@")]
        self.assertTrue(ours, "the README no longer shows how to use the Action")
        for reference, rest in uses:
            with self.subTest(uses=reference):
                self.assertNotEqual(reference, "./", "the README tells users `uses: ./`")
                repository, _, ref = reference.partition("@")
                if repository == REPOSITORY and ref == "<full-commit-sha>":
                    self.assertIn("stands for the full 40-character commit SHA a release tag points to",
                                  " ".join(README.split()))
                    self.assertRegex(rest, r"^\s+#\s+vX\.Y\.Z$", "say it is a release's SHA, and nothing else")
                    continue
                self.assertRegex(ref, r"^[0-9a-f]{40}$", "pin a full commit SHA, not a tag or branch")
                self.assertRegex(rest, r"^\s+#\s+v\d", "say which version the SHA is")

    def test_the_changelog_names_the_current_version(self) -> None:
        """Read with release_check's own reader, the one release.yml runs.

        It takes a pre-release heading in either spelling, and its error asks
        for the SemVer one (``## [1.2.0-rc.1]``). This looked for the PEP 440
        one (``[1.2.0rc1]``) only, so a pre-release whose CHANGELOG followed
        the tool failed the suite on the tagged commit.
        """
        from scripts import release_check  # noqa: PLC0415 -- ROOT is on sys.path

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        semver = release_check.pep440_to_semver(PYPROJECT["project"]["version"])
        try:
            notes = release_check.release_notes(changelog, f"v{semver}")
        except release_check.CheckFailed as missing:
            self.fail(str(missing))
        self.assertTrue(notes.strip())

    def test_the_security_policy_names_the_form_and_a_fallback(self) -> None:
        """This holds the text, not the route. The form exists only while
        private vulnerability reporting is on, which is a repository setting
        no test can read (CONTRIBUTING.md, "Repository settings"). So the policy
        also says what to do when the form is unavailable, through an issue form
        that does exist in the tree."""
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn(f"https://github.com/{REPOSITORY}/security/advisories/new",
                      security)
        flat = " ".join(security.split())
        self.assertIn("private vulnerability reporting form", flat)
        self.assertIn('If the form is unavailable, open a public issue with the "Question" '
                      "issue form asking for a contact, and leave out every detail of the problem.", flat)
        form = (ROOT / ".github" / "ISSUE_TEMPLATE" / "question.yml").read_text(encoding="utf-8")
        self.assertTrue(form.startswith("name: Question\n"), form[:40])
        # An invented email address would be a dead letter box on a document
        # whose whole job is to be actionable.
        self.assertNotIn("@example.com", security)
        self.assertNotIn("security@", security)


class DockerBuildContextTest(unittest.TestCase):
    """Every path a Dockerfile COPYs must survive its build context's ignore file.

    The kind demo's Dockerfile copies ``fixtures/`` and ``scripts/demo_server.py``.
    A root ``.dockerignore`` excluding both arrived with the release image, and
    from then on ``docker build -f deploy/kind/Dockerfile .`` failed -- with no
    test or CI job to notice, because nothing builds the demo image. BuildKit
    reads ``<Dockerfile>.dockerignore`` beside a Dockerfile in preference to the
    root file, so that is the file checked when it exists.
    """

    DOCKERFILES = ("Dockerfile", "deploy/kind/Dockerfile")

    @staticmethod
    def _ignore_file(dockerfile: Path) -> Path:
        specific = dockerfile.with_name(dockerfile.name + ".dockerignore")
        return specific if specific.is_file() else ROOT / ".dockerignore"

    #: What a checkout can hold that no Dockerfile copies, whether or not it
    #: exists today: a new top-level file or directory must not reach a builder.
    NEVER_COPIED = (".env", ".private/notes.md", ".veridor/runs.json", ".venv/lib/x.py", "dist/veridor.whl",
                    "build/lib/x.py", "docs/note.md", "tests/test_x.py", ".git/config", "a-new-file.md",
                    "a-new-directory/file.txt")
    #: What a COPY of src/ or fixtures/ would otherwise carry along.
    NEVER_INSIDE_A_COPY = ("src/veridor/__pycache__/cli.cpython-312.pyc", "src/veridor.egg-info/PKG-INFO")

    @staticmethod
    def _patterns(path: Path) -> list[str]:
        return read_patterns(path)

    @staticmethod
    def _ignored(source: str, patterns: list[str]) -> bool:
        return ignored(source, patterns)

    @staticmethod
    def _files(top: Path) -> list[str]:
        """Every file under top, relative to ROOT, leaving out .git and bytecode."""
        found = []
        for directory, dirnames, filenames in os.walk(top):
            dirnames[:] = [name for name in dirnames if name not in (".git", "__pycache__")]
            found.extend((Path(directory) / name).relative_to(ROOT).as_posix() for name in filenames)
        return found

    @staticmethod
    def _strays(sources: list[str], patterns: list[str], paths: list[str]) -> list[str]:
        """Paths the context keeps although no COPY reads them."""
        kept = [source.removeprefix("./").rstrip("/") for source in sources]
        return [path for path in paths
                if not any(path == source or path.startswith(source + "/") for source in kept)
                and not ignored(path, patterns)]

    def test_control_the_model_reads_the_rules_docker_documents(self) -> None:
        for patterns, path, expected in (
            (["*"], "a", True),
            (["*"], "a/b/c", True),
            (["*", "!src/"], "src/x.py", False),
            (["*", "!src/"], "srcfoo/x.py", True),
            (["*", "!a/b.py"], "a/b.py", False),
            (["*", "!a/b.py"], "a/c.py", True),
            (["**/__pycache__/"], "__pycache__/x", True),
            (["**/__pycache__/"], "a/b/__pycache__/x", True),
            (["**/__pycache__/"], "a/__pycache__x", False),
            (["*.md"], "a.md", True),
            (["*.md"], "a/b.md", False),
            (["*.md", "!README.md"], "README.md", False),
            (["!README.md", "*.md"], "README.md", True),
            (["*", "!a/", "a/b/"], "a/b/c", True),
            (["*", "!a/", "a/b/"], "a/d", False),
            (["*", "!a/", "**/__pycache__/"], "a/b/__pycache__/x", True),
            ([], "a", False),
        ):
            with self.subTest(patterns=patterns, path=path):
                self.assertEqual(ignored(path, patterns), expected)
        for unsupported in ("a[bc]", "a**", r"a\*"):
            with self.subTest(unsupported=unsupported), self.assertRaises(AssertionError):
                ignored("a", [unsupported])

    @staticmethod
    def _context_sources(text: str) -> list[str]:
        """What COPY reads from the context, and what a RUN's bind mount does:
        the release image reads its wheel through `RUN --mount=type=bind`, a
        way in this parser used not to see. A mount with from= reads a build
        stage; one without reads the context (source defaults to its root)."""
        sources = []
        for line in text.splitlines():
            words = line.split()
            if not words or words[0] not in ("COPY", "RUN"):
                continue
            args = words[1:]
            if words[0] == "RUN":
                for flag in args:
                    if not flag.startswith("--mount="):
                        break
                    options = dict(o.partition("=")[::2] for o in flag.removeprefix("--mount=").split(","))
                    if options.get("type", "bind") == "bind" and "from" not in options:
                        sources.append(options.get("source") or options.get("src") or ".")
                continue
            if any(a.startswith("--from=") for a in args):
                continue  # copied from another build stage, not the context
            args = [a for a in args if not a.startswith("--")]
            sources.extend(args[:-1])
        return sources

    @classmethod
    def _copy_sources(cls, dockerfile: Path) -> list[str]:
        return cls._context_sources(dockerfile.read_text(encoding="utf-8"))

    def test_control_a_bind_mount_of_the_context_is_read_and_one_of_a_stage_is_not(self) -> None:
        text = ("RUN --mount=type=bind,source=tests,target=/t --mount=type=cache,target=/c \\\n    true\n"
                "RUN --mount=type=bind,from=build,source=/dist,target=/tmp/wheels true\n"
                "RUN --mount=type=bind,target=/ctx true\n")
        self.assertEqual(self._context_sources(text), ["tests", "."])
        self.assertTrue(self._ignored("tests", self._patterns(ROOT / ".dockerignore")))

    def test_every_dockerfile_copies_the_licence_files_its_wheel_ships(self) -> None:
        """REGRESSION. The kind image built its wheel from pyproject.toml without
        the files `license-files` names: setuptools warned that this becomes an
        error by 2027-Feb-18, and the wheel held no licence (measured). The
        context has to let them through too, which the next test reads."""
        files = PYPROJECT["project"]["license-files"]
        self.assertEqual(files, ["LICENSE", "NOTICE"])
        for name in self.DOCKERFILES:
            sources = self._copy_sources(ROOT / name)
            for file in files:
                with self.subTest(dockerfile=name, file=file):
                    self.assertIn(file, sources)

    def test_no_dockerfile_copies_a_path_its_context_excludes(self) -> None:
        for name in self.DOCKERFILES:
            dockerfile = ROOT / name
            patterns = self._patterns(self._ignore_file(dockerfile))
            sources = self._copy_sources(dockerfile)
            self.assertTrue(sources, f"{name}: no COPY found -- the parser saw nothing")
            for source in sources:
                with self.subTest(dockerfile=name, source=source):
                    self.assertTrue((ROOT / source).exists(), f"{name} copies missing {source}")
                    self.assertFalse(
                        self._ignored(source, patterns),
                        f"{name} copies {source}, which {self._ignore_file(dockerfile).name} excludes",
                    )
                    # A later pattern can take a copied directory's contents
                    # back out while the directory itself survives.
                    self.assertEqual(
                        [path for path in self._files(ROOT / source)
                         if self._ignored(path, patterns) and ".egg-info/" not in path], [])

    def test_a_context_holds_only_what_its_dockerfile_copies(self) -> None:
        """The root file's comment said everything else stays out of the context,
        over a list of exclusions: any file nobody had listed, such as a .env or
        a new top-level directory, went to the builder (remote builders
        included), and the kind file had no such limit at all."""
        for name in self.DOCKERFILES:
            dockerfile = ROOT / name
            with self.subTest(dockerfile=name):
                sources = self._copy_sources(dockerfile)
                patterns = self._patterns(self._ignore_file(dockerfile))
                self.assertEqual(
                    self._strays(sources, patterns, [*self._files(ROOT), *self.NEVER_COPIED]), [])
                for path in self.NEVER_INSIDE_A_COPY:
                    self.assertTrue(self._ignored(path, patterns), path)
                self.assertEqual(
                    {pattern[1:].rstrip("/") for pattern in patterns if pattern.startswith("!")},
                    {source.removeprefix("./").rstrip("/") for source in sources},
                    "the file re-admits something other than what the Dockerfile copies",
                )

    def test_control_a_list_of_exclusions_is_reported(self) -> None:
        strays = self._strays(["src/"], [".git/", "tests/", "docs/"], ["src/x.py", "tests/y.py", ".env", "new/z"])
        self.assertEqual(strays, [".env", "new/z"])


class KindDemoInvocationTest(unittest.TestCase):
    """Every ``veridor`` command the kind demo ships must still be one the CLI accepts.

    The demo broke twice without a test noticing: its image could not be built
    once a root ``.dockerignore`` arrived, and its viewer exited 2 on every start
    once ``serve`` began refusing a non-loopback bind without an acknowledgement.
    Each time the CLI moved and the demo's own command lines did not. So they are
    parsed here by the real parser, and the viewer's through the real guard.
    """

    KIND = ROOT / "deploy" / "kind"

    @classmethod
    def _manifest_argv(cls) -> list[str]:
        lines = (cls.KIND / "veridor.yaml").read_text(encoding="utf-8").splitlines()
        start = next(i for i, line in enumerate(lines) if line.strip() == "args:")
        argv = []
        for line in lines[start + 1:]:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if not stripped.startswith("- "):
                break
            argv.append(stripped[2:].strip())
        return argv

    @classmethod
    def _dockerfile_argv(cls) -> list[str]:
        for line in (cls.KIND / "Dockerfile").read_text(encoding="utf-8").splitlines():
            if line.startswith("CMD "):
                return json.loads(line[4:])
        raise AssertionError("deploy/kind/Dockerfile has no CMD")

    @classmethod
    def _seed_invocations(cls) -> list[list[str]]:
        text = (cls.KIND / "seed.sh").read_text(encoding="utf-8").replace("\\\n", " ")
        calls = []
        for line in text.splitlines():
            words = line.strip().split()
            if words[:1] == ["veridor"]:
                calls.append([w.strip('"') for w in words if w not in ("||", "true")])
        return calls

    def _parse(self, argv: list[str]):
        from veridor import cli  # noqa: PLC0415

        self.assertEqual(argv[0], "veridor", argv)
        return cli._parser().parse_args(argv[1:])

    def test_the_viewer_command_passes_the_exposure_guard(self) -> None:
        from veridor import cli  # noqa: PLC0415

        for source, argv in (("veridor.yaml", self._manifest_argv()),
                             ("Dockerfile CMD", self._dockerfile_argv())):
            with self.subTest(source=source):
                args = self._parse(argv)
                self.assertEqual(args.command, "serve")
                cli._refuse_unauthenticated_exposure(args)  # raises if refused

    def test_the_guard_refuses_the_same_bind_without_the_acknowledgement(self) -> None:
        """The control: the check above could not pass if the guard were a no-op."""
        from veridor import cli  # noqa: PLC0415
        from veridor.core import ConfigError  # noqa: PLC0415

        argv = [a for a in self._manifest_argv() if a != "--i-understand-this-is-unauthenticated"]
        with self.assertRaises(ConfigError):
            cli._refuse_unauthenticated_exposure(self._parse(argv))

    def test_the_probes_send_a_host_the_viewer_answers(self) -> None:
        """The viewer refuses unexpected Host names with 421 (DNS rebinding), and a
        kubelet probe addresses the pod IP -- so without a Host header the pod is
        killed by its own liveness probe."""
        text = (self.KIND / "veridor.yaml").read_text(encoding="utf-8")
        for probe in ("readinessProbe:", "livenessProbe:"):
            with self.subTest(probe=probe):
                self.assertIn(probe, text)
                block = text.split(probe, 1)[1].split("Seconds", 1)[0]
                self.assertRegex(block, r'httpHeaders:\s*\[\{\s*name:\s*Host,\s*value:\s*"(127\.0\.0\.1|localhost)"')

    def test_every_seed_command_parses(self) -> None:
        calls = self._seed_invocations()
        self.assertGreaterEqual(len(calls), 4, calls)
        for argv in calls:
            with self.subTest(verb=argv[1]):
                self._parse(argv)

    @slow("runs seed.sh under sh with the real demo server on a loopback port")
    def test_the_seed_stops_when_its_target_does_not_come_up(self) -> None:
        """seed.sh says a target that fails to come up must not be carried
        past, and it used to be: the readiness loop broke on whatever answered
        the port and otherwise fell through after 10 s, and every verb is
        `|| true`, so the init container exited 0 and the viewer started
        without the finding the README says was measured (measured: a
        foreign process on the port took the run, "0 vulnerable"; a target
        that never started gave inconclusive runs). Both now stop the seed
        non-zero before any verb runs. The control, with the port free, seeds
        all four calls. veridor here is a recorder, not the CLI: what is under
        test is whether the seed reaches it."""
        import os  # noqa: PLC0415
        import shutil  # noqa: PLC0415
        import socket  # noqa: PLC0415
        import subprocess  # noqa: PLC0415
        import tempfile  # noqa: PLC0415
        import time  # noqa: PLC0415

        seed = (self.KIND / "seed.sh").read_text(encoding="utf-8")

        def run(port: int, demo: str) -> tuple[int, str, list[str]]:
            work = Path(tempfile.mkdtemp(prefix="vg-kind-seed-"))
            self.addCleanup(shutil.rmtree, work, True)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            (bin_dir / "python").symlink_to(sys.executable)
            calls = work / "calls"
            recorder = bin_dir / "veridor"
            recorder.write_text(f'#!/bin/sh\necho "$1" >> "{calls}"\n', encoding="utf-8")
            recorder.chmod(0o755)
            # seed.sh names /app unquoted, as it may inside the image. A link
            # inside the temporary directory stands in for /app, so a checkout
            # path with a space in it (or any shell metacharacter) is never
            # pasted into the script and split by the shell.
            app = work / "app"
            app.symlink_to(ROOT, target_is_directory=True)
            script = seed
            for old, new in (("/app/scripts/demo_server.py", demo), ("/app/", f"{app}/"),
                             ("OUT=/data/.veridor", f"OUT={work}/.veridor"), ("PORT=8765", f"PORT={port}")):
                self.assertIn(old, script, "seed.sh changed; this copy no longer matches it")
                script = script.replace(old, new)
            (work / "seed.sh").write_text(script, encoding="utf-8")
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}", "HOME": str(work)}
            result = subprocess.run(["sh", str(work / "seed.sh")], cwd=work, env=env, capture_output=True,
                                    text=True, timeout=120, check=False)
            verbs = calls.read_text(encoding="utf-8").split() if calls.exists() else []
            return result.returncode, result.stdout + result.stderr, verbs

        def free_port() -> int:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                return probe.getsockname()[1]

        demo = "/app/scripts/demo_server.py"
        status, output, verbs = run(free_port(), demo)
        self.assertEqual((status, verbs), (0, ["run", "map", "mutate", "run"]), output)

        with socket.socket() as foreign:
            foreign.bind(("127.0.0.1", 0))
            foreign.listen()
            status, output, verbs = run(foreign.getsockname()[1], demo)
        self.assertNotEqual(status, 0, output)
        self.assertEqual(verbs, [], output)
        self.assertIn("already answers", output)

        # A target that has already exited must stop the seed at once, through
        # the `kill -0` check, not by waiting out the 10 s readiness loop: with
        # that check removed this case still failed, but only after the
        # timeout, so nothing pinned it. The case alone, as timed below, took
        # 11.2-11.6 s without the check and 0.3 s with it (measured).
        started = time.monotonic()
        status, output, verbs = run(free_port(), "/app/scripts/no_such_demo_server.py")
        elapsed = time.monotonic() - started
        self.assertNotEqual(status, 0, output)
        self.assertEqual(verbs, [], output)
        self.assertIn("did not answer", output)
        self.assertLess(elapsed, 5.0, f"the seed waited out its timeout for a target that had exited\n{output}")


#: What a reader cannot see in a source file: format characters, the bidi
#: controls among them, and the line and paragraph separators. Written as
#: escapes, which is the point of the rule. These are the Basic Multilingual
#: Plane's characters of category Cf, Zl and Zp.
INVISIBLE = re.compile(
    "[\\u00ad\\u0600-\\u0605\\u061c\\u06dd\\u070f\\u0890\\u0891\\u08e2\\u180e\\u200b-\\u200f\\u2028-\\u202e"
    "\\u2060-\\u2064\\u2066-\\u206f\\ufeff\\ufff9-\\ufffb]"
)


def invisible_characters(text: str) -> list[tuple[int, str]]:
    """(line, U+XXXX) for every character INVISIBLE finds in ``text``."""
    return [(text.count("\n", 0, found.start()) + 1, f"U+{ord(found.group()):04X}")
            for found in INVISIBLE.finditer(text)]


class InvisibleUnicodeTest(unittest.TestCase):
    """Source has to read as what it does. `text.lstrip("<U+FEFF>")` shows as
    `text.lstrip("")` in a browser, a no-op in a security tool's parser, and a
    literal U+202E earns the bidi warning on a project whose SECURITY.md names
    that character as an attack it refuses. Python's escapes make the same
    strings."""

    def test_no_shipped_or_test_source_carries_one_literally(self) -> None:
        roots = ("src", "scripts", "tests", "templates", "ci", "deploy", ".github", "schema")
        suffixes = {".py", ".sh", ".yml", ".yaml", ".md", ".js", ".html", ".css", ".tpl", ".json"}
        scanned = [path for top in roots for path in (ROOT / top).rglob("*")
                   if path.suffix in suffixes and path.is_file()
                   and "__pycache__" not in path.parts]
        scanned += [ROOT / name for name in ("action.yml", "Dockerfile", "README.md",
                                             "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md")]
        self.assertGreater(len(scanned), 150, "the scan is not reading the tree")
        found = {str(path.relative_to(ROOT)): hits for path in scanned
                 if (hits := invisible_characters(path.read_text(encoding="utf-8")))}
        self.assertEqual(found, {})

    def test_control_each_kind_is_seen_and_its_escape_is_not(self) -> None:
        for character in ("\ufeff", "\u202e", "\u2066", "\u200f", "\u061c", "\u2028", "\u00ad"):
            with self.subTest(code_point=f"{ord(character):04X}"):
                self.assertEqual(invisible_characters(f"a\nb{character}"),
                                 [(2, f"U+{ord(character):04X}")])
        self.assertEqual(invisible_characters('text.lstrip("\\ufeff")'), [])
        self.assertEqual(invisible_characters("an em dash \u2014 and a \u00a0 stay"), [])


class SdistManifestTest(unittest.TestCase):
    """The sdist leaves out the test suite, and nothing else, on purpose.

    setuptools' default file set put tests/test_*.py in the sdist but none of
    the helpers they import, nor fixtures/ or scripts/: 0 of the 51 modules it
    shipped could be imported from an unpacked sdist, and they were half its
    bytes (measured). ``scripts/release_check.py dist`` checks the built sdist
    in CI and in the release build -- no tests/, and every file the wheel
    installs (tests/test_release_check.py, DistTest) -- and this pins the rule
    that produces it, so widening it is a decision somebody makes here rather
    than a line nobody reads.
    """

    def test_the_manifest_prunes_the_tests_and_nothing_else(self) -> None:
        text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        directives = [line.split() for line in text.splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(directives, [["prune", "tests"]])


class InternalDocumentTest(unittest.TestCase):
    """Working notes stay out of the published tree.

    A reader who came for the tool would take anything under docs/ as
    documentation of it, so only what is written for that reader goes there.
    """

    #: Everything under docs/ that IS published. Anything else there is a
    #: working note and stays local.
    PUBLISHED = {"report-formats.md"}

    @slow("shells out to git ls-files")
    def test_no_working_note_is_tracked(self) -> None:
        import subprocess  # noqa: PLC0415

        tracked = subprocess.run(
            ["git", "ls-files", "docs/"], cwd=ROOT, capture_output=True, text=True
        )
        if tracked.returncode != 0:  # pragma: no cover - not a git checkout
            self.skipTest("not a git working copy")
        names = {Path(line).name for line in tracked.stdout.split() if line}
        self.assertEqual(
            names, self.PUBLISHED,
            "docs/ tracks something outside the published set; keep it local "
            "(.git/info/exclude), or add it to PUBLISHED if it is genuinely for users",
        )

    #: What the README's commands write into the directory they run in, anchored
    #: to the root. A contributor who ran the quickstart in a clone had an
    #: untracked veridor.sarif carrying the version, and the fast tier's versions
    #: check then failed (measured).
    README_WRITES = frozenset({
        "/veridor.json", "/veridor/", "/baseline.json", "/current.json", "/coverage.json",
        "/candidates.json", "/proof.json", "/veridor.sarif", "/veridor-junit.xml", "/summary.md",
        "/gl-sast-report.json"})

    def test_what_the_readme_writes_is_ignored(self) -> None:
        """Every output path a README command names at the root is ignored.

        Read from the README's flags, so a new example that writes a new name
        fails here until .gitignore covers it."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        written = set()
        for match in re.finditer(
                r"--(?:sarif|output|matrix|coverage|promote|json|baseline)[ =]([\w./-]+)"
                r"|--report [a-z-]+=([\w./-]+)", readme):
            path = match.group(1) or match.group(2)
            if path.startswith(("fixtures/", ".veridor/", "-")) or path.isupper():
                continue  # inputs that ship, the ignored run history, stdout, a placeholder
            written.add("/" + path.split("/")[0] + ("/" if "/" in path else ""))
        self.assertTrue({"/veridor.sarif", "/proof.json", "/veridor/"} <= written, written)  # control
        self.assertEqual(written - self.README_WRITES, set())

    def test_the_tracked_gitignore_is_patterns_for_what_the_tools_produce(self) -> None:
        """A tracked ignore file is published with the tree, so it is no place to
        list or describe local files: .git/info/exclude keeps those names local,
        and release_check reads it too."""
        lines = [line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(
            {line for line in lines if line and not line.startswith("#")},
            {".veridor/", ".venv/", "__pycache__/", "*.py[cod]", "*.egg-info/", "build/", "dist/", ".private/",
             *self.README_WRITES},
        )
        self.assertLessEqual(sum(line.startswith("#") for line in lines), 1)

    #: A repository path as prose or code names it: docs/x.md, scripts/x.py.
    _POINTER = re.compile(r"(?<![\w./-])((?:docs|scripts)/[\w.-]*\w\.(?:md|py|sh))")

    def _dangling(self, text: str) -> list[str]:
        return [path for path in self._POINTER.findall(text) if not (ROOT / path).is_file()]

    def test_what_the_published_text_points_at_exists(self) -> None:
        """A reader follows these. The docs/ set above stays exact, so removing
        a file from it without removing the links to it is the failure here."""
        sources = [
            *ROOT.glob("*.md"),
            *(ROOT / "docs").glob("*.md"),
            *(ROOT / "deploy").rglob("*.md"),
            *(ROOT / "ci").glob("*.md"),
            *(ROOT / "src" / "veridor").glob("*.py"),
            *(ROOT / "scripts").glob("*.py"),
            *(ROOT / ".github" / "workflows").glob("*.yml"),
        ]
        self.assertGreater(len(sources), 10)
        for source in sources:
            with self.subTest(source=source.relative_to(ROOT).as_posix()):
                self.assertEqual(self._dangling(source.read_text(encoding="utf-8")), [])

    def test_control_a_path_that_is_not_there_is_reported(self) -> None:
        self.assertEqual(
            self._dangling("See docs/report-formats.md and docs/not-a-file.md, or run "
                           "`python scripts/run_tests.py` and scripts/not-a-script.sh."),
            ["docs/not-a-file.md", "scripts/not-a-script.sh"],
        )

    #: `ROOT / ...` paths in tests and scripts that are absent from a fresh clone
    #: on purpose, each with the reason.
    ABSENT_ON_PURPOSE = {
        "dist",  # scripts/build_zipapp.py writes it
        ".veridor/e2e",  # scripts/e2e_validation.py writes it
        "deploy/argocd/application-kustomize-example.yaml",  # test_kustomize: must stay removed
        "scripts/no_such_demo_server.py",  # test_release_files: a control
    }

    @staticmethod
    def _root_paths(text: str) -> list[str]:
        """Every path written as ROOT / "a" / "b", the way this suite spells a
        file in the repository."""
        tree = ast.parse(text)
        joins = [node for node in ast.walk(tree) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)]
        inner = {id(node.left) for node in joins}
        found = []
        for node in joins:
            if id(node) in inner:
                continue  # ROOT / "docs" inside ROOT / "docs" / "x"
            parts: list[str] = []
            while (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                   and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
                parts.insert(0, node.right.value)
                node = node.left
            if parts and isinstance(node, ast.Name) and node.id == "ROOT":
                found.append("/".join(parts))
        return found

    def _absent(self, text: str) -> list[str]:
        return sorted({path for path in self._root_paths(text)
                       if not (ROOT / path).exists() and path not in self.ABSENT_ON_PURPOSE})

    @slow("parses every test and script twice, 3.5 MB of Python: 0.85 s idle, the costliest "
          "test the fast tier had by a factor of three")
    def test_the_suite_does_not_depend_on_an_untracked_document(self) -> None:
        """A fresh clone must pass, so a test or script may not reach for a file
        the clone does not have, whether unconditionally (the first thing a new
        contributor runs fails) or behind an exists() check (it tests something
        only one checkout can see). CI runs this on a fresh clone."""
        sources = [*(ROOT / "tests").glob("*.py"), *(ROOT / "scripts").glob("*.py")]
        self.assertGreater(len(sources), 10)
        seen = 0
        for source in sources:
            text = source.read_text(encoding="utf-8")
            seen += len(self._root_paths(text))
            with self.subTest(source=source.relative_to(ROOT).as_posix()):
                self.assertEqual(self._absent(text), [])
        self.assertGreater(seen, 100, "the reader found almost no ROOT paths: it has stopped seeing them")

    def test_control_a_guarded_read_of_a_local_file_is_reported(self) -> None:
        text = ('note = ROOT / "docs" / "local-note.md"\n'
                'if note.exists():\n    note.read_text()\n'
                'readme = ROOT / "README.md"\n')
        self.assertEqual(self._root_paths(text), ["docs/local-note.md", "README.md"])
        self.assertEqual(self._absent(text), ["docs/local-note.md"])

    def test_the_main_guard_is_the_last_statement_of_this_file(self) -> None:
        """`python3.12 tests/test_release_files.py` collects the tests defined
        when unittest.main() runs and exits. RemediationFlagTest sat below the
        guard, so running this file as a script skipped it silently."""
        body = ast.parse(Path(__file__).read_text(encoding="utf-8")).body
        guards = [index for index, node in enumerate(body)
                  if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)]
        self.assertEqual(guards, [len(body) - 1],
                         "something follows the unittest.main() guard; running the file as a script skips it")


class SyncDocCountsTest(unittest.TestCase):
    """scripts/sync_doc_counts.py, with the counts supplied and README in a temp dir."""

    STALE = "| `fast` | 1 |\n| `slow` | 2 |\n| both | 3 |\n"
    FRESH = "| `fast` | 7 |\n| `slow` | 3 |\n| both | 10 |\n"

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.readme = self.root / "README.md"
        self.readme.write_text(self.STALE, encoding="utf-8")
        self.extra = self.root / "extra.md"
        self.extra.write_text(self.STALE, encoding="utf-8")

    def run_it(self, *argv: str) -> tuple[int, str]:
        output = io.StringIO()
        with (mock.patch.object(sync_doc_counts, "ROOT", self.root),
              mock.patch.object(sync_doc_counts, "counts", return_value={"fast": 7, "slow": 3, "all": 10}),
              contextlib.redirect_stdout(output), contextlib.redirect_stderr(output)):
            return sync_doc_counts.main(list(argv)), output.getvalue()

    def test_a_named_document_is_found_from_the_current_directory(self) -> None:
        """The usage says so, and a path a shell completed means that. Mutant:
        resolving it under ROOT syncs the file of that name at the top instead."""
        elsewhere = self.root / "sub"
        elsewhere.mkdir()
        named = elsewhere / "extra.md"
        named.write_text(self.STALE, encoding="utf-8")
        before = os.getcwd()
        self.addCleanup(os.chdir, before)
        os.chdir(elsewhere)
        self.assertEqual(self.run_it("extra.md")[0], 0)
        self.assertEqual(named.read_text(encoding="utf-8"), self.FRESH)
        self.assertEqual(self.extra.read_text(encoding="utf-8"), self.STALE)

    def test_with_no_arguments_it_writes_the_readme_and_nothing_else(self) -> None:
        self.assertEqual(self.run_it()[0], 0)
        self.assertEqual(self.readme.read_text(encoding="utf-8"), self.FRESH)
        self.assertEqual(self.extra.read_text(encoding="utf-8"), self.STALE)

    def test_a_named_document_is_synced_as_well(self) -> None:
        self.assertEqual(self.run_it(str(self.extra))[0], 0)
        self.assertEqual(self.readme.read_text(encoding="utf-8"), self.FRESH)
        self.assertEqual(self.extra.read_text(encoding="utf-8"), self.FRESH)

    def test_check_reports_a_stale_named_document_and_writes_nothing(self) -> None:
        self.readme.write_text(self.FRESH, encoding="utf-8")
        code, output = self.run_it("--check", str(self.extra))
        self.assertEqual(code, 1)
        self.assertIn(f"STALE: {self.extra}", output)
        self.assertEqual(self.extra.read_text(encoding="utf-8"), self.STALE)
        # Control: without the named document nothing is stale.
        self.assertEqual(self.run_it("--check")[0], 0)

    def test_a_named_document_that_is_missing_stops_it_before_any_write(self) -> None:
        """Skipping it would report success for a sync that never ran."""
        code, output = self.run_it(str(self.root / "not-there.md"))
        self.assertEqual(code, 2)
        self.assertIn("not-there.md", output)
        self.assertEqual(self.readme.read_text(encoding="utf-8"), self.STALE)

    def test_a_document_with_no_table_is_refused_not_called_current(self) -> None:
        """With no row to change it read as already correct, which is the
        message a document that does carry the real counts gets."""
        self.extra.write_text("no tier table here\n", encoding="utf-8")
        code, output = self.run_it(str(self.extra))
        self.assertEqual(code, 2)
        self.assertIn("extra.md", output)
        self.assertEqual(self.readme.read_text(encoding="utf-8"), self.STALE)

    def test_the_real_readme_carries_the_table_it_syncs(self) -> None:
        self.assertTrue(any(re.search(pattern, README) for pattern, _ in sync_doc_counts.PATTERNS))


class RemediationFlagTest(unittest.TestCase):
    """Every `--flag` a message tells you to type must actually exist.

    This class of defect has appeared twice. The matrix budget refusal said
    "raise the budget explicitly with max_requests=800" -- the keyword this
    module takes, not the flag the operator is holding a command line for. The
    specimen advice emitted a `matrix.specimens` key with the method glued on,
    which the matrix then refuses. A remediation you cannot paste is the same
    defect as no remediation; it just charges you an attempt first.

    So this scans the runtime for flags named in message text and holds each one
    against the real parser. It cannot check semantics -- only that the string
    is a flag Veridor accepts, which is exactly where both bugs were.
    """

    #: Flags that appear in runtime strings and are deliberately NOT Veridor's.
    #: Enumerated rather than pattern-matched away, so a new one has to be
    #: justified by a person instead of slipping through a loosened rule.
    FOREIGN = {
        # An example of the OPERATOR's own hook script's arguments, in the
        # tier-2 documentation: ["./scripts/mutate.sh", "--guard", "..."].
        "--guard",
        # Named in a docstring precisely to say it does not exist: the rate
        # limiter has no escape hatch.
        "--no-throttle",
        # Docker's flag, not Veridor's: the write-preflight refusal tells a
        # container user to run as the owner of the mounted directory with
        # `docker run --user "$(id -u):$(id -g)"`.
        "--user",
    }

    @staticmethod
    def _known_flags() -> set[str]:
        from veridor.cli import _parser  # noqa: PLC0415

        parser = _parser()
        flags = set()

        def collect(target) -> None:
            for action in target._actions:  # noqa: SLF001 - argparse has no API
                flags.update(action.option_strings)
            subparsers = getattr(target, "_subparsers", None)
            if subparsers is None:
                return
            for group in subparsers._group_actions:  # noqa: SLF001
                for sub in getattr(group, "choices", {}).values():
                    collect(sub)

        collect(parser)
        return flags

    def test_the_foreign_list_stays_honest(self) -> None:
        """An entry that becomes a real flag must leave this list, or the guard
        silently stops covering it."""
        known = self._known_flags()
        self.assertEqual(
            self.FOREIGN & known, set(),
            "these are now real Veridor flags and must be removed from FOREIGN",
        )

    def test_every_flag_named_in_a_message_is_a_real_flag(self) -> None:
        known = self._known_flags()
        source_root = ROOT / "src" / "veridor"
        offenders: list[str] = []
        for path in sorted(source_root.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r'"[^"]*?(--[a-z][a-z0-9-]{2,})', text):
                flag = match.group(1)
                if flag not in known and flag not in self.FOREIGN:
                    offenders.append(f"{path.name}: {flag}")
        self.assertEqual(
            offenders, [],
            "these messages name flags the CLI does not accept:\n  "
            + "\n  ".join(sorted(set(offenders))),
        )


if __name__ == "__main__":
    unittest.main()
