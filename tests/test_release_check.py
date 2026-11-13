"""scripts/release_check.py: one version everywhere, a bump that reaches all of it.

`versions` used to compare four strings (pyproject, __init__, the chart's
version and appVersion) while the same version was hard-coded in sixteen more
shipped files -- the GitLab component's image and pip defaults, the Jenkins,
Azure and CodeBuild templates, the Kustomize base, the Rollouts
AnalysisTemplate, the READMEs. Measured before this change: a copy of the tree
whose component default said ``ghcr.io/veridor-authz/veridor:0.0.9`` passed
`versions` with exit 0, so a release would have shipped a component pointing
at an image of a different version. These tests run the real registry against
copies of the real files, plant the defects, and check each one is named.

Fast tier: files are copied and read; nothing is spawned, except by the one test
marked slow that asks git about a checkout's layout.
"""

from __future__ import annotations

import contextlib
import io
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

sys.path.insert(0, str(ROOT))
from scripts import release_check  # noqa: E402
from tiers import slow  # noqa: E402

CURRENT = release_check.check_versions(ROOT, None, scan=False)
_MAJOR, _MINOR, _ = (int(part) for part in re.match(r"(\d+)\.(\d+)\.(\d+)", CURRENT["version"]).groups())
#: Versions guaranteed to differ from the tree's, so these tests still hold
#: after `bump` has moved it: the next minor, a pre-release of it, and one
#: older than any release (the planted disagreement).
NEXT = f"{_MAJOR}.{_MINOR + 1}.0"
NEXT_RC_PEP440, NEXT_RC_SEMVER = f"{NEXT}rc1", f"{NEXT}-rc.1"
OTHER = "0.0.8"


class _Tree(unittest.TestCase):
    """A temporary copy of every registered file, .gitignore, and the scan's
    exceptions -- enough of the real tree for every command to run on."""

    def tree(self) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        paths = {entry.path for entry in release_check.REGISTRY}
        paths |= {path for path, _, _ in release_check.NOT_RELEASE_VERSIONS}
        paths.add(".gitignore")
        for path in paths:
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, root / path)
        return root

    @staticmethod
    def edit(root: Path, path: str, old: str, new: str) -> None:
        file = root / path
        text = file.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise AssertionError(f"{path}: {old!r} occurs {text.count(old)} times, expected 1")
        file.write_text(text.replace(old, new), encoding="utf-8")

    @staticmethod
    def write_bump(root: Path, version: str) -> None:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = release_check.main(["--root", str(root), "bump", version, "--write"])
        if code != 0:
            raise AssertionError(f"bump {version} exited {code}")

    def failure(self, root: Path, tag: str | None = None) -> str:
        with self.assertRaises(release_check.CheckFailed) as caught:
            release_check.check_versions(root, tag)
        return str(caught.exception)


class VersionsTest(_Tree):
    def test_the_real_tree_agrees_with_its_own_tag(self) -> None:
        result = release_check.check_versions(ROOT, None)
        self.assertEqual(result, CURRENT)
        tag = "v" + result["semver"]
        self.assertEqual(release_check.check_versions(ROOT, tag)["version"], result["version"])

    def test_every_registered_pattern_matches_the_real_tree(self) -> None:
        texts = release_check._read_texts(ROOT, {entry.path for entry in release_check.REGISTRY})
        found, problems = release_check.registered_matches(texts)
        self.assertEqual(problems, [])
        matched = {entry for entry, _, _ in found}
        self.assertEqual(matched, set(release_check.REGISTRY), "an entry matched nothing")
        # The files that must stay registered, so the registry cannot quietly shrink.
        for path in ("templates/veridor.yml", "ci/.gitlab-ci.yml", "ci/Jenkinsfile",
                     "ci/azure-pipelines.yml", "ci/buildspec.yml",
                     "deploy/kustomize/veridor-gate/base/job.yaml",
                     "deploy/argo-rollouts/veridor-analysistemplate.yaml",
                     "deploy/helm/veridor-gate/Chart.yaml", "README.md"):
            with self.subTest(path=path):
                self.assertIn(path, {entry.path for entry in matched})

    def test_the_real_tree_has_no_unregistered_version(self) -> None:
        self.assertEqual(release_check.unregistered(ROOT, CURRENT["version"]), [])
        self.assertEqual(release_check.stale_allowances(ROOT), [])

    def test_every_disagreement_is_named(self) -> None:
        # Each file is edited in the spelling the registry holds it in: PEP 440
        # where pip reads it, SemVer where a chart or an image tag does. With
        # the PEP 440 spelling everywhere, every chart and image case failed to
        # find its text on a pre-release tree (`bump 1.2.0-rc.1`), where the
        # two differ.
        pep440, semver = CURRENT["version"], CURRENT["semver"]
        # The line the message must name, read from the file: a comment added
        # above the agent image used to break this case, not the check.
        jenkins_line = next(number for number, line in enumerate(
            (ROOT / "ci" / "Jenkinsfile").read_text(encoding="utf-8").splitlines(), 1)
            if f"image 'ghcr.io/veridor-authz/veridor:{semver}'" in line)
        cases = {
            f"veridor.__version__ says {OTHER}": ("src/veridor/__init__.py", f'"{pep440}"', f'"{OTHER}"'),
            f"chart version says {OTHER}": ("deploy/helm/veridor-gate/Chart.yaml",
                                           f"\nversion: {semver}\n", f"\nversion: {OTHER}\n"),
            f"chart appVersion (the default image tag) says {OTHER}": (
                "deploy/helm/veridor-gate/Chart.yaml", f'appVersion: "{semver}"', f'appVersion: "{OTHER}"'),
            # Before the registry, this one passed `versions` with exit 0.
            "templates/veridor.yml:19: component image default says 0.0.9": (
                "templates/veridor.yml", f"ghcr.io/veridor-authz/veridor:{semver}", "ghcr.io/veridor-authz/veridor:0.0.9"),
            "component pip_package default says 0.0.9": (
                "templates/veridor.yml", f'"veridor=={pep440}"', '"veridor==0.0.9"'),
            "Kustomize base image says 0.0.9": (
                "deploy/kustomize/veridor-gate/base/job.yaml", f"veridor:{semver}", "veridor:0.0.9"),
            "AnalysisTemplate image default says 0.0.9": (
                "deploy/argo-rollouts/veridor-analysistemplate.yaml", f"veridor:{semver}", "veridor:0.0.9"),
            f"ci/Jenkinsfile:{jenkins_line}: agent image says 0.0.9": (
                "ci/Jenkinsfile", f"image 'ghcr.io/veridor-authz/veridor:{semver}'", "image 'ghcr.io/veridor-authz/veridor:0.0.9'"),
        }
        # One copy, each edit undone before the next: a copy and two full
        # checks per case cost 0.18 s idle and up to 0.45 s under load. The
        # restore is checked byte for byte, so every case still starts from
        # the tree the first check below passed, and the last check shows the
        # copy is clean again.
        root = self.tree()
        self.assertEqual(release_check.check_versions(root, None), CURRENT)
        for message, (path, old, new) in cases.items():
            with self.subTest(case=message):
                original = (root / path).read_bytes()
                try:
                    self.edit(root, path, old, new)
                    self.assertIn(message, self.failure(root))
                finally:
                    (root / path).write_bytes(original)
                self.assertEqual((root / path).read_bytes(), original)
        self.assertEqual(release_check.check_versions(root, None), CURRENT)

    def test_the_tag_must_name_the_tree(self) -> None:
        root = self.tree()
        self.assertIn(f"tag v{OTHER} names {OTHER}, but the tree is {CURRENT['version']}",
                      self.failure(root, f"v{OTHER}"))
        self.assertIn("does not start with 'v'", self.failure(root, CURRENT["semver"]))

    def test_a_prerelease_is_compared_across_the_two_spellings(self) -> None:
        root = self.tree()
        self.write_bump(root, NEXT_RC_PEP440)
        self.assertEqual(release_check.check_versions(root, f"v{NEXT_RC_SEMVER}"),
                         {"version": NEXT_RC_PEP440, "semver": NEXT_RC_SEMVER, "prerelease": "true"})
        # A final version is not a pre-release. Bumped to one rather than read
        # from the tree, which between an rc tag and the final is itself a
        # pre-release: this said "false" of `v` + the tree's own version, and
        # failed on every tree `bump 1.2.0-rc.1` produced.
        final = self.tree()
        self.write_bump(final, NEXT)
        self.assertEqual(release_check.check_versions(final, f"v{NEXT}")["prerelease"], "false")
        root = self.tree()
        self.edit(root, "pyproject.toml", f'version = "{CURRENT["version"]}"', 'version = "1.2.0.post1"')
        self.assertIn("pyproject.toml version", self.failure(root))

    def test_a_registered_pattern_that_matches_nothing_fails(self) -> None:
        """A reworded file must not silently drop out of the bump."""
        root = self.tree()
        self.edit(root, "ci/.gitlab-ci.yml", f"name the first release ({CURRENT['semver']})",
                  "name the first release")
        self.assertIn("ci/.gitlab-ci.yml: the registered pattern for comment matches nothing",
                      self.failure(root))
        root = self.tree()
        (root / "ci" / "Jenkinsfile").unlink()
        self.assertIn("ci/Jenkinsfile is missing", self.failure(root))

    def test_stdout_is_exactly_the_github_output_lines(self) -> None:
        """release.yml tees stdout into GITHUB_OUTPUT; --list goes to stderr."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release_check.main(["--root", str(self.tree()), "versions", "--list"])
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(out.getvalue().splitlines(),
                         [f"{key}={value}" for key, value in CURRENT.items()])
        self.assertIn("templates/veridor.yml:19:", err.getvalue())
        self.assertIn("registered occurrence(s)", err.getvalue())


class ScanTest(_Tree):
    """The scan is what makes the registry complete; each rule can fail."""

    def problems(self, root: Path) -> list[str]:
        return release_check.unregistered(root, CURRENT["version"])

    def test_control_a_new_occurrence_of_the_current_version_is_found(self) -> None:
        root = self.tree()
        self.assertEqual(self.problems(root), [])
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs" / "install.md").write_text(
            f"# Install\n\n    pip install veridor=={CURRENT['version']}\n", encoding="utf-8")
        problems = self.problems(root)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("docs/install.md:3: "), problems)
        self.assertIn("docs/install.md:3", self.failure(root))

    def test_control_the_current_version_is_found_even_on_a_line_without_veridor(self) -> None:
        root = self.tree()
        (root / "deploy" / "extra.yaml").write_text(f"targetRevision: {CURRENT['semver']}\n", encoding="utf-8")
        self.assertEqual(len(self.problems(root)), 1)

    def test_control_a_stale_version_on_a_line_naming_veridor_is_found(self) -> None:
        root = self.tree()
        (root / "deploy" / "extra.yaml").write_text("image: ghcr.io/veridor-authz/veridor:0.0.7\n", encoding="utf-8")
        problems = self.problems(root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("'0.0.7'", problems[0])

    def test_what_git_ignores_and_tests_are_not_scanned(self) -> None:
        root = self.tree()
        line = f"pip install veridor=={CURRENT['version']}\n"
        gitignore = root / ".gitignore"
        with_note = gitignore.read_text(encoding="utf-8") + "docs/ignored-note.md\n"
        gitignore.write_text(with_note, encoding="utf-8")
        for path in ("build/notes.md", "docs/ignored-note.md", "src/veridor.egg-info/PKG-INFO",
                     "tests/test_new.py", "CHANGELOG.md"):
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(line, encoding="utf-8")
        self.assertEqual(self.problems(root), [])
        # Control: the same file once .gitignore stops ignoring it.
        gitignore.write_text(with_note.replace("\ndocs/ignored-note.md\n", "\n"), encoding="utf-8")
        self.assertEqual([p.split(":")[0] for p in self.problems(root)], ["docs/ignored-note.md"])

    def test_a_gitignore_pattern_it_cannot_model_is_refused(self) -> None:
        root = self.tree()
        with (root / ".gitignore").open("a", encoding="utf-8") as handle:
            handle.write("!keep-me.md\n")
        with self.assertRaises(release_check.CheckFailed):
            self.problems(root)

    def _plant_note(self, root: Path) -> None:
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs" / "excluded-note.md").write_text(f"veridor {OTHER}\n", encoding="utf-8")

    def test_what_the_checkouts_exclude_file_ignores_is_not_scanned(self) -> None:
        """A local note listed in .git/info/exclude is not shipped, and git says
        so. Reading only .gitignore, this failed `versions` on such a note
        (measured: exit 1), so a tracked .gitignore had to name every local
        file for the check to pass."""
        root = self.tree()
        self._plant_note(root)
        exclude = root / ".git" / "info" / "exclude"
        exclude.parent.mkdir(parents=True)
        exclude.write_text("# local\ndocs/excluded-note.md\n", encoding="utf-8")
        self.assertEqual(self.problems(root), [])
        # Control: the same note, and a tree with an exclude file that does not name it.
        exclude.write_text("# local\n", encoding="utf-8")
        self.assertEqual([p.split(":")[0] for p in self.problems(root)], ["docs/excluded-note.md"])

    def test_a_linked_worktree_reads_the_exclude_file_of_its_main_checkout(self) -> None:
        """git keeps one info/exclude per repository, in the common directory,
        and a linked worktree's .git is a file pointing at its private directory."""
        root = self.tree()
        self._plant_note(root)
        common = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, common, True)
        private = common / "worktrees" / "wt"
        private.mkdir(parents=True)
        (private / "commondir").write_text("../..\n", encoding="utf-8")
        (root / ".git").write_text(f"gitdir: {private}\n", encoding="utf-8")
        # Control: the note is reported until the common directory excludes it.
        self.assertEqual([p.split(":")[0] for p in self.problems(root)], ["docs/excluded-note.md"])
        (common / "info").mkdir()
        (common / "info" / "exclude").write_text("docs/excluded-note.md\n", encoding="utf-8")
        self.assertEqual(self.problems(root), [])

    def test_an_exclude_pattern_it_cannot_model_is_refused_by_name(self) -> None:
        root = self.tree()
        exclude = root / ".git" / "info" / "exclude"
        exclude.parent.mkdir(parents=True)
        exclude.write_text("!keep-me.md\n", encoding="utf-8")
        with self.assertRaisesRegex(release_check.CheckFailed, "exclude"):
            self.problems(root)

    @slow("shells out to git")
    def test_git_agrees_about_both_checkout_layouts(self) -> None:
        """The two tests above build the layout by hand. This builds it with git
        and asks git, so they cannot be pinning a layout git does not produce."""
        root = self.tree()
        self._plant_note(root)
        identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.hooksPath=/dev/null"]

        def git(*args: str, cwd: Path = root) -> subprocess.CompletedProcess[str]:
            return subprocess.run(["git", *identity, *args], cwd=cwd, capture_output=True, text=True)

        self.assertEqual(git("init", "-q").returncode, 0)
        # Control: nothing excludes the note yet, for git or for the scan.
        self.assertEqual(git("check-ignore", "-q", "docs/excluded-note.md").returncode, 1)
        self.assertEqual([p.split(":")[0] for p in self.problems(root)], ["docs/excluded-note.md"])
        with (root / ".git" / "info" / "exclude").open("a", encoding="utf-8") as handle:
            handle.write("docs/excluded-note.md\n")
        self.assertEqual(git("check-ignore", "-q", "docs/excluded-note.md").returncode, 0)
        self.assertEqual(self.problems(root), [])

        self.assertEqual(git("add", "-A").returncode, 0)
        self.assertEqual(git("commit", "-qm", "tree").returncode, 0)
        linked = Path(tempfile.mkdtemp()) / "linked"
        self.addCleanup(shutil.rmtree, linked.parent, True)
        added = git("worktree", "add", "-q", str(linked))
        self.assertEqual(added.returncode, 0, added.stderr)
        self._plant_note(linked)
        self.assertTrue((linked / ".git").is_file())
        self.assertEqual(git("check-ignore", "-q", "docs/excluded-note.md", cwd=linked).returncode, 0)
        self.assertEqual(self.problems(linked), [])

    def test_numbers_that_merely_contain_a_version_are_not_versions(self) -> None:
        root = self.tree()
        text = f"veridor ran on kind 10.{CURRENT['version']} and 1.{CURRENT['version']}.4\n"
        self.assertEqual(release_check._TOKEN.findall(text), [])
        # Control: the same line with the version standing alone is found.
        self.assertEqual(release_check._TOKEN.findall(text + f"veridor {CURRENT['version']}"),
                         [CURRENT["version"]])

    #: The scan's token as it was written before it was made digit-first.
    TOKEN_LOOKBEHIND_FIRST = re.compile(r"(?<![\d.])" + release_check._VERSION_GROUP
                                        + r"(?!\d|\.\d)")

    @classmethod
    def problems_line_by_line(cls, root: Path, version: str) -> list[str]:
        """unregistered() as it was written before it scanned each file in one
        pass: split into lines, and the lookbehind-first token run over each
        line on its own."""
        forms = set(release_check.both_forms(version).values())
        paths = [p for p in release_check.text_files(root)
                 if not p.startswith(release_check._SCAN_EXCLUDED_PREFIXES)
                 and p not in release_check._SCAN_EXCLUDED_FILES]
        texts = release_check._read_texts(root, paths)
        covered: dict[str, set[tuple[int, int]]] = {}
        for entry in release_check.REGISTRY:
            if entry.path in texts:
                for match in entry.regex().finditer(texts[entry.path]):
                    covered.setdefault(entry.path, set()).add(match.span("v"))
        allowed: dict[str, list[tuple[int, int]]] = {}
        for path, pattern, _ in release_check.NOT_RELEASE_VERSIONS:
            if path in texts:
                for match in re.finditer(pattern, texts[path], re.MULTILINE):
                    allowed.setdefault(path, []).append(match.span())
        problems = []
        for path, text in texts.items():
            offset = 0
            for number, line in enumerate(text.split("\n"), 1):
                names_veridor = "veridor" in line.lower()
                for match in cls.TOKEN_LOOKBEHIND_FIRST.finditer(line):
                    value = match.group("v")
                    if value not in forms and not names_veridor:
                        continue
                    span = (offset + match.start("v"), offset + match.end("v"))
                    if span in covered.get(path, set()):
                        continue
                    if any(start <= span[0] and span[1] <= end
                           for start, end in allowed.get(path, [])):
                        continue
                    problems.append(f"{path}:{number}: {value!r} is not in release_check.py's "
                                    f"REGISTRY (or NOT_RELEASE_VERSIONS): {line.strip()[:100]}")
                offset += len(line) + 1
        return problems

    def test_one_pass_per_file_finds_what_a_scan_per_line_found(self) -> None:
        """unregistered() runs a digit-first _TOKEN over each file once, where
        it ran a lookbehind-first one over each line; on the registered files
        that took it from about 16 ms to about 6 (VersionsTest runs it twice
        per case). Held equal, problem for problem and in order, to the scan
        it replaced: on the registered files, and on tokens that touch line
        ends, digits and dots across a newline, CRLF, and the first and last
        byte of a file."""
        version, semver = CURRENT["version"], CURRENT["semver"]
        edges = (f"{version}\nveridor 1.\n2.3.4 veridor 1.2.3\n.4 veridor\n"
                 f"VERIDOR 10.1.0 1.0.1.0 x1.2.3\nveridor {semver}\r\nplain {version}\r\n\n"
                 f"9.8.7rc1 veridor 9.8.7-rc.1\nveridor 5.6.7-rc.1.2 {version}.\n"
                 f".{version} veridor 0.0.1")
        root = self.tree()
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs" / "edges.md").write_text(edges, encoding="utf-8")
        for scanned_as in (version, OTHER):
            with self.subTest(version=scanned_as):
                expected = self.problems_line_by_line(root, scanned_as)
                # Control: the tokens either side of a newline are candidates,
                # so the comparison reaches the boundary it is about.
                for token in ("docs/edges.md:3: '2.3.4'", "docs/edges.md:3: '1.2.3'",
                              "docs/edges.md:11: '0.0.1'"):
                    self.assertTrue(any(line.startswith(token) for line in expected), token)
                self.assertEqual(release_check.unregistered(root, scanned_as), expected)
        # The two tokens agree on the edge text itself, spans included.
        self.assertEqual([m.span() for m in release_check._TOKEN.finditer(edges)],
                         [m.span() for m in self.TOKEN_LOOKBEHIND_FIRST.finditer(edges)])

    def test_a_stale_not_release_entry_is_reported(self) -> None:
        root = self.tree()
        path, pattern, _ = release_check.NOT_RELEASE_VERSIONS[0]
        self.assertEqual(release_check.stale_allowances(root), [])
        (root / path).write_text("nothing here\n", encoding="utf-8")
        stale = release_check.stale_allowances(root)
        entries = [entry for entry in release_check.NOT_RELEASE_VERSIONS if entry[0] == path]
        self.assertEqual(len(stale), len(entries), stale)
        self.assertTrue(all(path in line for line in stale), stale)


class BumpTest(_Tree):
    def snapshot(self, root: Path) -> dict[str, bytes]:
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}

    def test_the_dry_run_changes_nothing_and_prints_the_diff(self) -> None:
        root = self.tree()
        before = self.snapshot(root)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release_check.main(["--root", str(root), "bump", NEXT])
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(self.snapshot(root), before)
        self.assertIn(f'+version = "{NEXT}"', out.getvalue())
        self.assertIn(f'+      default: "ghcr.io/veridor-authz/veridor:{NEXT}"', out.getvalue())
        self.assertIn("pass --write to apply", err.getvalue())

    def test_write_reaches_every_registered_occurrence_and_round_trips(self) -> None:
        root = self.tree()
        before = self.snapshot(root)
        changes = release_check.bump(root, NEXT)
        self.assertEqual(set(changes), {entry.path for entry in release_check.REGISTRY})
        self.write_bump(root, NEXT)
        self.assertEqual(release_check.check_versions(root, f"v{NEXT}")["version"], NEXT)
        texts = release_check._read_texts(root, {entry.path for entry in release_check.REGISTRY})
        found, problems = release_check.registered_matches(texts)
        self.assertEqual(problems, [])
        self.assertEqual({value for _, _, value in found}, {NEXT})
        self.write_bump(root, CURRENT["version"])
        self.assertEqual(self.snapshot(root), before, "bumping back did not restore the tree")

    def test_a_prerelease_uses_each_files_own_spelling(self) -> None:
        root = self.tree()
        release_check.bump(root, NEXT_RC_SEMVER)  # either spelling is accepted
        self.write_bump(root, NEXT_RC_SEMVER)
        component = (root / "templates" / "veridor.yml").read_text(encoding="utf-8")
        self.assertIn(f'default: "ghcr.io/veridor-authz/veridor:{NEXT_RC_SEMVER}"', component)
        self.assertIn(f'default: "veridor=={NEXT_RC_PEP440}"', component)
        self.assertIn(f"veridor-{NEXT_RC_PEP440}.pyz", (root / "ci" / "buildspec.yml").read_text(encoding="utf-8"))
        self.assertIn(f'appVersion: "{NEXT_RC_SEMVER}"',
                      (root / "deploy/helm/veridor-gate/Chart.yaml").read_text(encoding="utf-8"))
        self.assertIn(f'__version__ = "{NEXT_RC_PEP440}"',
                      (root / "src/veridor/__init__.py").read_text(encoding="utf-8"))

    def test_control_it_refuses_to_leave_an_unregistered_occurrence_behind(self) -> None:
        root = self.tree()
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs" / "install.md").write_text(f"veridor=={CURRENT['version']}\n", encoding="utf-8")
        before = self.snapshot(root)
        with self.assertRaises(release_check.CheckFailed) as caught:
            release_check.bump(root, NEXT)
        self.assertIn("refusing to bump", str(caught.exception))
        self.assertIn("docs/install.md:1", str(caught.exception))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_check.main(["--root", str(root), "bump", NEXT, "--write"]), 1)
        self.assertEqual(self.snapshot(root), before)

    def test_it_refuses_a_version_the_release_workflow_cannot_publish(self) -> None:
        root = self.tree()
        for bad in ("0.2", "0.2.0.post1", "v0.2.0", "0.2.0-beta1"):
            with self.subTest(version=bad), self.assertRaises(release_check.CheckFailed):
                release_check.bump(root, bad)


class IdentityTest(_Tree):
    def test_the_inventory_names_file_line_and_name(self) -> None:
        found = release_check.identity(ROOT)
        names = {name for _, _, name, _ in found}
        self.assertEqual(names, {name for name, _ in release_check.IDENTITY_NAMES})
        lines: dict[str, list[str]] = {}
        for path, line, name, text in found:
            if path not in lines:
                lines[path] = (ROOT / path).read_text(encoding="utf-8").split("\n")
            self.assertEqual(lines[path][line - 1].strip(), text)
        self.assertIn(("pyproject.toml", "github.com/Veridor-authz"),
                      {(path, name) for path, _, name, _ in found})

    def test_control_each_name_is_counted_once_and_lookalikes_are_not(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "a.md").write_text(
            "https://github.com/Veridor-authz/veridor/issues\n"
            "raw.githubusercontent.com/Veridor-authz/veridor/v1/templates/veridor.yml\n"
            "image: ghcr.io/veridor-authz/veridor:1\n"
            "gitlab.com/Veridor-authz/veridor/veridor@1\n"
            "https://docs.veridor.org/schema and someone@veridor.org\n"
            "uses: Veridor-authz/veridor@0123\n"
            "src/Veridor-authz/veridor-gate github.com/Veridor-authzx example.veridor.orgs\n",
            encoding="utf-8")
        found = release_check.identity(root)
        self.assertEqual(
            [(line, name) for _, line, name, _ in found],
            [(1, "github.com/Veridor-authz"), (2, "raw.githubusercontent.com/Veridor-authz"), (3, "ghcr.io/veridor-authz"),
             (4, "gitlab.com/Veridor-authz"), (5, "veridor.org"), (5, "veridor.org"), (6, "Veridor-authz/veridor")])

    def test_a_name_the_line_filter_would_skip_is_refused(self) -> None:
        """identity() skips lines without "veridor"; a name that lacks it, or
        that its own pattern does not match, would count zero everywhere."""
        self.assertEqual(release_check._unfilterable_identity_names(release_check.IDENTITY_NAMES), [])
        planted = release_check.IDENTITY_NAMES + (
            ("acme.io", r"acme\.io"), ("veridor.dev", r"veridor\.org"), ("x/veridor", r"x/veridor"))
        self.assertEqual(release_check._unfilterable_identity_names(planted), ["acme.io", "veridor.dev"])

    def test_a_retired_name_the_line_filter_would_skip_is_refused(self) -> None:
        """identity_leftovers() skips lines without any of
        _IDENTITY_RETIRED_LITERALS; a retired name that lacks them, or that its
        own pattern does not match, would never fire."""
        self.assertEqual(release_check._unfilterable_retired_names(release_check.IDENTITY_RETIRED), [])
        planted = release_check.IDENTITY_RETIRED + (
            ("ghcr.io/acme", r"ghcr\.io/acme"), ("ghcr.io/santoshkumarpuppala-x", r"ghcr\.io/veridor"),
            ("quay.io/santoshkumarpuppala", r"quay\.io/santoshkumarpuppala"))
        self.assertEqual(release_check._unfilterable_retired_names(planted),
                         ["ghcr.io/acme", "ghcr.io/santoshkumarpuppala-x"])

    def test_it_writes_nothing(self) -> None:
        root = self.tree()
        before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(release_check.main(["--root", str(root), "identity"]), 0)
        self.assertEqual({p: p.read_bytes() for p in root.rglob("*") if p.is_file()}, before)
        self.assertRegex(out.getvalue().splitlines()[-1], r"^\d+ occurrence\(s\) on \d+ line\(s\) in \d+ file\(s\)")

    def test_a_retired_name_left_behind_fails_identity(self) -> None:
        """identity lists the current names only, so without this a reference
        to the old owner would just stop appearing and the command would pass."""
        for leftover in ("https://github.com/veridor/veridor/issues",
                         "raw.githubusercontent.com/veridor/veridor/v1/templates/veridor.yml",
                         "component: gitlab.com/veridor/veridor/veridor@1",
                         "image: ghcr.io/veridor/veridor:1",
                         "CHART_REPOSITORY: oci://ghcr.io/veridor/charts",
                         "uses: veridor/veridor@0123",
                         r"image: ghcr\.io/veridor/veridor:{V}$",
                         r"https://github\.com/veridor/veridor/",
                         r"gitlab\.com/veridor/veridor",
                         r"raw\.githubusercontent\.com/veridor/veridor/",
                         r"\"ghcr\\.io\\/veridor\/veridor\"",
                         r"veridor\/veridor",
                         "Report to someone@veridor.org.",
                         "security@docs.veridor.org",
                         r"someone@veridor\.org",
                         "https://www.veridor.org/",
                         "https://example.veridor.org/guide",
                         "https://a.docs.veridor.org/",
                         r"https://www\.veridor\.org/",
                         # A dot before the first label is not part of the host.
                         "see...www.veridor.org",
                         "the host is .www.veridor.org",
                         "docker.io/veridor/veridor:1",
                         "gh api repos/veridor/veridor",
                         "HTTPS://GitHub.com/Veridor/veridor",
                         "quay.io/veridor/veridor:1",
                         "git clone git@github.com:veridor/other.git",
                         "git@gitlab.com:veridor/other.git",
                         "https://veridor.github.io/x",
                         "https://hub.docker.com/r/veridor/veridor",
                         "https://img.shields.io/github/stars/veridor/veridor",
                         "https://codecov.io/gh/veridor/veridor",
                         "- uses: veridor/action@v1",
                         "https://example.test/?repo=github.com%2Fveridor%2Fveridor",
                         r"ghcr\.io/veridor",
                         # No "veridor" on these lines: the line filter skipped them once.
                         "helm pull oci://ghcr.io/santoshkumarpuppala/charts/x",
                         "git clone https://gitlab.com/santoshkumarpuppala/other.git",
                         "git@gitlab.com:santoshkumarpuppala/other.git",
                         "https://github.com/Santoshkumarpuppala/veridor"):
            with self.subTest(leftover=leftover):
                root = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, root, True)
                (root / "a.md").write_text(leftover + "\n", encoding="utf-8")
                self.assertEqual([path for path, *_ in release_check.identity_leftovers(root)], ["a.md"])
                # The walk reaches where these live: dot directories and deep paths.
                (root / ".github" / "workflows").mkdir(parents=True)
                (root / ".github" / "workflows" / "b.yml").write_text(leftover + "\n", encoding="utf-8")
                self.assertEqual({path for path, *_ in release_check.identity_leftovers(root)},
                                 {"a.md", ".github/workflows/b.yml"})
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(release_check.main(["--root", str(root), "identity"]), 1)

    def test_control_lookalikes_of_a_retired_name_pass(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "a.md").write_text(
            "https://github.com/veridor-dev/veridor/issues\n"
            "ghcr.io/veridor-dev/veridor:1\n"
            "src/veridor/veridor-gate github.com/veridorx\n"
            "gitlab.com/acme/veridor/veridor@1\n"
            "veridor/baseline-matrix.json https://pypi.org/p/veridor\n"
            "- uses: Veridor-authz/veridor@0123\n"
            "git@github.com:veridor-dev/veridor.git https://veridor-dev.github.io/x\n"
            "https://hub.docker.com/r/veridorx/veridor https://img.shields.io/badge/veridor-1-blue\n"
            "https://veridor.org/ https://docs.veridor.org/guide veridor.org's mark\n"
            "r\"https://docs\\.veridor\\.org/\" veridor.organic example.veridor.orgs\n"
            "see...veridor.org and ...docs.veridor.org\n",
            encoding="utf-8")
        self.assertEqual(release_check.identity_leftovers(root), [])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_check.main(["--root", str(root), "identity"]), 0)

    def test_any_case_of_a_name_in_use_is_listed(self) -> None:
        """The inventory is what a rename works from, and a lowercase GitHub link
        resolves. It matched one case, so that link counted zero and would be left
        behind. Mutant: without re.IGNORECASE on _IDENTITY, these are not listed."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "a.md").write_text("https://github.com/veridor-authz/veridor\n"
                                   "ghcr.io/Veridor-authz/veridor\n", encoding="utf-8")
        self.assertEqual([(line, name) for _, line, name, _ in release_check.identity(root)],
                         [(1, "github.com/Veridor-authz"), (2, "ghcr.io/veridor-authz")])

    def test_a_name_this_project_does_not_hold_is_a_leftover_under_tests_too(self) -> None:
        """tests/ may plant the domain as a control, and only the domain. Mutant:
        _identity_keeps returning True for every path under tests/ fails this."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "tests").mkdir()
        (root / "tests" / "test_x.py").write_text('IMAGE = "ghcr.io/veridor/veridor:1"\n', encoding="utf-8")
        self.assertEqual([(path, name) for path, _, name, _ in release_check.identity_leftovers(root)],
                         [("tests/test_x.py", "ghcr.io/veridor")])

    def test_the_project_holds_veridor_org_and_docs_veridor_org(self) -> None:
        """The project holds the domain now: veridor.org serves the product page
        and docs.veridor.org the docs. This test kept the domain out of every
        file but the two identifiers, because it served nothing then; the
        viewer's comments naming veridor.org failed identity for that reason.
        The held hosts pass in any shipped file; the rest of the domain does not."""
        held = ('  "$comment": "see https://docs.veridor.org/schema",\n'
                "/* veridor.org's mark: a shield and a tick. */\n"
                'Homepage = "https://veridor.org/"\n'
                # The two addresses the domain takes mail for (MX to Zoho since
                # 2026-11-13), at a sentence end and in bold too.
                "write to security@veridor.org. Or **opensource@veridor.org**\n")
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for path in ("schema/other.json", "src/veridor/web/styles.css", "pyproject.toml"):
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(held, encoding="utf-8")
        self.assertEqual(release_check.identity_leftovers(root), [])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_check.main(["--root", str(root), "identity"]), 0)
        # Control: the same files fail on a host or an address the project does not hold.
        with (root / "src/veridor/web/styles.css").open("a", encoding="utf-8") as styles:
            styles.write("/* see https://www.veridor.org/ */\n/* or write to someone@veridor.org */\n"
                         "/* not ours: xsecurity@veridor.org */\n/* nor security@docs.veridor.org */\n")
        self.assertEqual([(path, line, name) for path, line, name, _ in release_check.identity_leftovers(root)],
                         [("src/veridor/web/styles.css", 5, "host.veridor.org"),
                          ("src/veridor/web/styles.css", 6, "@veridor.org"),
                          ("src/veridor/web/styles.css", 7, "@veridor.org"),
                          ("src/veridor/web/styles.css", 8, "@veridor.org")])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(release_check.main(["--root", str(root), "identity"]), 1)

    def test_only_tests_may_plant_an_unheld_veridor_org_name(self) -> None:
        """tests/ plants an address or another host as a control; outside
        tests/ the same line is a leftover."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        planted = "someone@veridor.org https://www.veridor.org/\n"
        (root / "tests").mkdir()
        (root / "tests" / "test_x.py").write_text(planted, encoding="utf-8")
        self.assertEqual(release_check.identity_leftovers(root), [])
        (root / "SECURITY.md").write_text(planted, encoding="utf-8")
        self.assertEqual([(path, name) for path, _, name, _ in release_check.identity_leftovers(root)],
                         [("SECURITY.md", "@veridor.org")])

    def test_the_tree_carries_no_retired_name(self) -> None:
        self.assertEqual(release_check.identity_leftovers(ROOT), [])

    def test_this_script_names_the_retired_owner_only_in_its_retired_list(self) -> None:
        """identity skips the two files that define the names, so REGISTRY's
        patterns are checked here. A retired host in a regex source is the
        spelling a plain grep for ghcr.io/veridor walks past."""
        source = (ROOT / "scripts" / "release_check.py").read_text(encoding="utf-8")
        start = source.index("IDENTITY_RETIRED: tuple")
        block = source[start:source.index("\n)\n", start)]
        rest = source.replace(block, "")
        self.assertNotIn("ghcr", block.split("\n", 1)[0], "the block's start moved")

        def leftovers(text: str) -> list[str]:
            return [name for name, pattern in release_check._IDENTITY_RETIRED_RE if pattern.search(text)]

        self.assertEqual(leftovers(rest), [])
        # Control: the same check, on the block it removed, finds every name.
        self.assertEqual(len(leftovers(block)), len(release_check.IDENTITY_RETIRED))

    def test_the_finding_id_namespace_did_not_move(self) -> None:
        """Every finding ID derives from it; the rename must not renumber them."""
        from veridor.reports._common import FINDING_ID_NAMESPACE  # noqa: PLC0415
        self.assertEqual(str(FINDING_ID_NAMESPACE), "5ec096cf-02ff-5d16-a95c-17c40bf2257a")


def git_index(*paths: str) -> bytes:
    """A version 2 git index holding ``paths``, as gitformat-index lays it out."""
    entries = b""
    for path in sorted(paths):
        name = path.encode()
        fixed = b"\0" * 40 + b"\0" * 20 + struct.pack(">H", min(len(name), 0xfff))
        entry = fixed + name
        entries += entry + b"\0" * (8 - len(entry) % 8)
    return b"DIRC" + struct.pack(">II", 2, len(paths)) + entries + b"\0" * 20


class LocalExcludeTest(unittest.TestCase):
    """info/exclude keeps local files out of these checks. It must not take out a
    file that ships, and a tracked file does, whatever an ignore rule says."""

    LEFTOVER = "ghcr.io/veridor/veridor:1\n"

    def tree(self) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".git" / "info").mkdir(parents=True)
        (root / ".git" / "info" / "exclude").write_text("README.md\nnotes/\n", encoding="utf-8")
        (root / "README.md").write_text(self.LEFTOVER, encoding="utf-8")
        (root / "notes").mkdir()
        (root / "notes" / "a.md").write_text(self.LEFTOVER, encoding="utf-8")
        return root

    def leftovers(self, root: Path) -> list[str]:
        return [path for path, *_ in release_check.identity_leftovers(root)]

    def test_control_an_untracked_file_is_still_skipped(self) -> None:
        self.assertEqual(self.leftovers(self.tree()), [])

    def test_a_tracked_file_an_exclude_line_matches_is_still_read(self) -> None:
        """Mutant: drop `rel not in tracked` from text_files and this finds nothing."""
        root = self.tree()
        (root / ".git" / "index").write_bytes(git_index("README.md"))
        self.assertEqual(self.leftovers(root), ["README.md"])

    def test_a_tracked_file_under_an_excluded_directory_is_still_read(self) -> None:
        root = self.tree()
        (root / ".git" / "index").write_bytes(git_index("notes/a.md"))
        self.assertEqual(self.leftovers(root), ["notes/a.md"])

    def test_an_index_it_cannot_read_is_refused_not_read_as_empty(self) -> None:
        root = self.tree()
        for label, data in (("not an index", b"nonsense"),
                            ("cut short", git_index("README.md")[:30]),
                            ("a split index", git_index("README.md")[:-20] + b"link" + struct.pack(">I", 0) + b"\0" * 20)):
            with self.subTest(index=label):
                (root / ".git" / "index").write_bytes(data)
                with self.assertRaises(release_check.CheckFailed) as caught:
                    release_check.text_files(root)
                self.assertIn("git index", str(caught.exception))

    def test_a_dot_git_file_that_is_no_pointer_is_not_followed(self) -> None:
        """Mutant: dropping the gitdir: test reads elsewhere/info/exclude and
        skips README.md here."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "elsewhere" / "info").mkdir(parents=True)
        (root / "elsewhere" / "info" / "exclude").write_text("README.md\n", encoding="utf-8")
        (root / ".git").write_text("elsewhere\n", encoding="utf-8")
        (root / "README.md").write_text(self.LEFTOVER, encoding="utf-8")
        self.assertEqual(self.leftovers(root), ["README.md"])
        (root / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
        self.assertEqual(self.leftovers(root), [], "control: a real pointer is followed")

    def test_a_tracked_file_that_is_not_utf8_is_a_failure(self) -> None:
        """text_files skipped it, so a leftover in a tracked Latin-1 file was
        never read and identity passed. Mutant: `continue` for every
        UnicodeDecodeError and this returns ["README.md"]."""
        root = self.tree()
        (root / "notes.md").write_bytes(b"caf\xe9 " + self.LEFTOVER.encode())
        # Control: untracked, it is skipped, as a binary scratch file should be.
        (root / ".git" / "index").write_bytes(git_index("README.md"))
        self.assertEqual(self.leftovers(root), ["README.md"])
        (root / ".git" / "index").write_bytes(git_index("README.md", "notes.md"))
        with self.assertRaisesRegex(release_check.CheckFailed, "not UTF-8.*notes.md"):
            self.leftovers(root)

    def test_a_sha256_repository_is_refused(self) -> None:
        """Its index entries hold 32-byte ids; read as 20 they gave garbage
        names and no refusal. Mutant: skip the objectformat read."""
        root = self.tree()
        (root / ".git" / "index").write_bytes(git_index("README.md"))
        (root / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 1\n"
                                               "[extensions]\n\tobjectFormat = sha1\n", encoding="utf-8")
        self.assertEqual(self.leftovers(root), ["README.md"])  # control: sha1 is read
        (root / ".git" / "config").write_text("[extensions]\n\tobjectformat = sha256\n", encoding="utf-8")
        with self.assertRaisesRegex(release_check.CheckFailed, "object format is sha256"):
            self.leftovers(root)

    def test_a_missing_index_beside_a_commit_is_refused(self) -> None:
        """Read as nothing tracked, the exclude line took README.md out of the
        scan while it shipped (identity exited 0, measured). With no commit, as
        after `git init`, nothing is tracked and that reading is right."""
        root = self.tree()
        (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        self.assertEqual(self.leftovers(root), [])  # control: a fresh repository
        for label, plant in (("loose", lambda: (root / ".git" / "refs" / "heads").mkdir(parents=True)
                              or (root / ".git" / "refs" / "heads" / "main").write_text("a" * 40 + "\n")),
                             ("packed", lambda: (root / ".git" / "packed-refs").write_text(
                                 "# pack-refs with: peeled\n" + "a" * 40 + " refs/heads/main\n")),
                             ("detached", lambda: (root / ".git" / "HEAD").write_text("a" * 40 + "\n"))):
            with self.subTest(head=label):
                shutil.rmtree(root / ".git" / "refs", ignore_errors=True)
                (root / ".git" / "packed-refs").unlink(missing_ok=True)
                (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
                plant()
                with self.assertRaisesRegex(release_check.CheckFailed, "no git index"):
                    self.leftovers(root)

    @slow("runs git")
    def test_git_agrees_about_the_index_refusals(self) -> None:
        """The three tests above build the layout by hand; this has git build it."""
        def git(root: Path, *argv: str) -> None:
            done = subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.test",
                                   "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *argv],
                                  capture_output=True, text=True, check=False)
            if done.returncode != 0:
                self.skipTest(f"git {argv[0]} failed: {done.stderr.strip()[:200]}")

        sha256 = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, sha256, True)
        git(sha256, "init", "-q", "--object-format=sha256", ".")
        (sha256 / "a.md").write_text("text\n", encoding="utf-8")
        git(sha256, "add", "a.md")
        with self.assertRaisesRegex(release_check.CheckFailed, "sha256"):
            release_check.text_files(sha256)

        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        git(root, "init", "-q", ".")
        (root / "README.md").write_text(self.LEFTOVER, encoding="utf-8")
        self.assertEqual(release_check.text_files(root), ["README.md"])  # control: no commit, no index
        git(root, "add", "README.md")
        git(root, "commit", "-q", "-m", "x")
        (root / ".git" / "index").unlink()
        with self.assertRaisesRegex(release_check.CheckFailed, "no git index"):
            release_check.text_files(root)

    @slow("runs git")
    def test_the_parser_lists_what_git_lists_at_every_index_version(self) -> None:
        """The test above hands it an index written here, which can only show it
        reads what this file writes. This asks git, at each version, including 4's
        prefix compression, the long names that pad differently, and an entry with
        the extended flag, which 3 and 4 add for intent-to-add."""
        def git(*argv: str) -> str:
            done = subprocess.run(["git", "-C", str(root), *argv], capture_output=True, text=True, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout

        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        git("init", "-q", ".")
        names = ["README.md", "a/b.txt", "a/bb.txt", "a/b/c/deep.txt", "x" * 8 + ".md", "x" * 9 + ".md",
                 "long/" + "y" * 200 + ".md"]
        for name in names:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text("text\n", encoding="utf-8")
        git("add", *names)

        def same_as_git(versions: tuple[int, ...]) -> None:
            for version in versions:
                with self.subTest(version=version, entries=len(git("ls-files").split())):
                    git("update-index", "--index-version", str(version))
                    on_disk = struct.unpack(">I", (root / ".git" / "index").read_bytes()[4:8])[0]
                    self.assertEqual(on_disk, version, "git did not write the version under test")
                    self.assertEqual(release_check._tracked_paths(root), set(git("ls-files").split("\n")) - {""})

        same_as_git((2, 4))  # git writes 3 only for an entry that needs the flag
        (root / "later.md").write_text("text\n", encoding="utf-8")
        git("add", "--intent-to-add", "later.md")
        same_as_git((3, 4))
        # A linked worktree keeps its own index in its private directory.
        git("-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "x")
        linked = root / "linked"
        git("worktree", "add", "-q", str(linked))
        self.assertIn("README.md", release_check._tracked_paths(linked))


class NotesTest(unittest.TestCase):
    def test_release_notes_are_the_version_s_section(self) -> None:
        changelog = ("# Changelog\n\n## [Unreleased]\n\n- later\n\n## [0.2.0] - 2026-10-01\n\n"
                     "### Added\n\n- a thing\n\n## [0.1.0]\n\nFirst.\n")
        self.assertEqual(release_check.release_notes(changelog, "v0.2.0"),
                         "### Added\n\n- a thing\n")
        self.assertEqual(release_check.release_notes(changelog, "v0.1.0"), "First.\n")
        with self.assertRaises(release_check.CheckFailed):
            release_check.release_notes(changelog, "v0.3.0")
        with self.assertRaises(release_check.CheckFailed):
            release_check.release_notes("## [0.4.0]\n\n\n## [0.3.0]\nx\n", "v0.4.0")

    #: The placeholder CHANGELOG.md carried for 0.1.0, and the [Unreleased]
    #: preamble, as a tag pushed before the fold would have published them.
    #: Measured on the tree before this check: `notes v0.1.0` exited 0 and
    #: printed "Not released. There is no `v0.1.0` tag, ...", while none of
    #: the ~640 lines under [Unreleased] reached the notes.
    PLACEHOLDER = ("Not released. There is no `v0.1.0` tag, and no package, image or chart for\n"
                   "0.1.0. If the first release is 0.1.0, fold [Unreleased] into\nthis section before tagging it.\n")
    PREAMBLE = ("Nothing here has been released: there is no tag, and no package, image or\n"
                "chart (see [0.1.0]).\n\n### Security\n\n- a fix\n")

    #: The repository `notes` links to when pyproject.toml names it.
    PYPROJECT = '[project]\nname = "x"\n\n[project.urls]\nRepository = "https://github.com/Example-org/example"\n'

    @staticmethod
    def link(version: str, anchor: str) -> str:
        return (f"The full release notes are the [{version}] section of CHANGELOG.md:\n"
                f"https://github.com/Example-org/example/blob/v{version}/CHANGELOG.md#{anchor}\n")

    def notes_cli(self, changelog: str, tag: str) -> tuple[int, str, str]:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        (root / "pyproject.toml").write_text(self.PYPROJECT, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release_check.main(["--root", str(root), "notes", tag])
        return code, out.getvalue(), err.getvalue()

    def test_a_section_that_says_it_is_not_released_is_refused(self) -> None:
        for label, body in (("the 0.1.0 placeholder", self.PLACEHOLDER),
                            ("a fold that kept the [Unreleased] preamble", self.PREAMBLE)):
            with self.subTest(label):
                changelog = f"# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-10-01\n\n{body}"
                with self.assertRaises(release_check.CheckFailed) as caught:
                    release_check.publishable_notes(changelog, "v0.1.0")
                self.assertIn("says it is not released", str(caught.exception))
                # The reader alone still finds it: the development-tree check
                # in tests/test_release_files.py relies on that.
                self.assertEqual(release_check.release_notes(changelog, "v0.1.0"), body)
                code, out, err = self.notes_cli(changelog, "v0.1.0")
                self.assertEqual((code, out), (1, ""))
                self.assertIn("::error title=release check::", err)

    def test_notes_refuses_a_tree_that_still_says_no_release_exists(self) -> None:
        """`notes` is the tag's first job, so this stops before anything builds.
        SECURITY.md ships in no artifact, and only this reads it."""
        changelog = "## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n- a thing\n"
        for name, text in (("README.md", "As of 2026-11-04 no release\nexists.\n"),
                           ("SECURITY.md", "**As of 2026-11-04 no release exists**, so\n")):
            with self.subTest(name):
                root = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, root, True)
                (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
                (root / "pyproject.toml").write_text(self.PYPROJECT, encoding="utf-8")
                (root / name).write_text(text, encoding="utf-8")
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = release_check.main(["--root", str(root), "notes", "v0.2.0"])
                self.assertEqual((code, out.getvalue()), (1, ""))
                self.assertIn(f"{name} still says", err.getvalue())
                # Control: the same tree once the sentence is rewritten.
                (root / name).write_text("Only the latest release is supported.\n", encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = release_check.main(["--root", str(root), "notes", "v0.2.0"])
                self.assertEqual((code, out.getvalue()),
                                 (0, "- a thing\n\n" + self.link("0.2.0", "020---2026-10-01")))

    def test_the_real_preamble_is_one_the_fold_check_reads(self) -> None:
        """A fold that kept the paragraph would post it as release notes, and
        rewording it past _NOT_RELEASED would let that through."""
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        preamble = changelog.split("## [Unreleased]\n", 1)[1].split("###", 1)[0].split("## [", 1)[0].strip()
        if preamble:  # empty once a release has folded it
            self.assertRegex(preamble, release_check._NOT_RELEASED)
            self.assertIn("before the first public version", " ".join(preamble.split()))

    def test_control_notes_that_merely_mention_releases_are_accepted(self) -> None:
        body = ("### Fixed\n\n- The `--x` flag, which was never released, is gone.\n"
                "- Not released builds no longer print a version.\n")
        changelog = f"## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n{body}\n## [0.1.0]\n\nFirst.\n"
        self.assertEqual(release_check.publishable_notes(changelog, "v0.2.0"), body)
        # The section opens with a heading, so the notes are the link alone.
        self.assertEqual(self.notes_cli(changelog, "v0.2.0"), (0, self.link("0.2.0", "020---2026-10-01"), ""))

    def test_unreleased_entries_left_behind_are_refused(self) -> None:
        """Every entry under [Unreleased] describes a change in the tagged tree;
        notes that leave them out describe less than the release ships."""
        changelog = "## [Unreleased]\n\n- pending\n\n## [0.2.0] - 2026-10-01\n\n- a thing\n"
        with self.assertRaises(release_check.CheckFailed) as caught:
            release_check.publishable_notes(changelog, "v0.2.0")
        self.assertIn("'## [Unreleased]' is not empty", str(caught.exception))
        code, out, err = self.notes_cli(changelog, "v0.2.0")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("[Unreleased]", err)
        # Control: the same file with [Unreleased] emptied, as CONTRIBUTING says.
        self.assertEqual(self.notes_cli(changelog.replace("- pending\n\n", ""), "v0.2.0"),
                         (0, "- a thing\n\n" + self.link("0.2.0", "020---2026-10-01"), ""))

    def test_the_unreleased_section_is_never_release_notes(self) -> None:
        """Tagging without renaming [Unreleased] must fail, not publish it."""
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]", changelog)
        with self.assertRaises(release_check.CheckFailed):
            release_check.release_notes(changelog, "v99.0.0")


def first_release_changelog() -> str:
    """CHANGELOG.md as it stood at v0.1.0: an empty [Unreleased] and the
    0.1.0 section, which no later change rewrites."""
    section = release_check.release_notes((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), "v0.1.0")
    return f"# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-13\n\n{section}"


#: Read from github.com/Veridor-authz/veridor/blob/v0.1.0/CHANGELOG.md on
#: 2026-11-13: the rendered heading carries id="user-content-010---2026-11-13".
FIRST_RELEASE_ANCHOR = "010---2026-11-13"


class ReleaseBodyTest(unittest.TestCase):
    """GitHub refused v0.1.0's release (HTTP 422, "body is too long (maximum
    is 125000 characters)") because its notes were the whole 0.1.0 section,
    about 223,000 characters, and nothing before the last job counted them."""

    def test_the_anchor_is_the_id_github_gave_the_first_release_heading(self) -> None:
        changelog = first_release_changelog()
        line = changelog.splitlines().index("## [0.1.0] - 2026-11-13")
        self.assertEqual(release_check.heading_anchor(changelog, line), FIRST_RELEASE_ANCHOR)
        self.assertEqual(release_check.heading_anchor(changelog, 0), "changelog")
        self.assertEqual(release_check.github_slug("[0.2.0-rc.1] - 2026-12-01"), "020-rc1---2026-12-01")
        self.assertEqual(release_check.github_slug("Uses [a link](https://x.test/y) and `code`"),
                         "uses-a-link-and-code")

    def test_a_repeated_heading_takes_a_suffix_and_fenced_lines_are_not_headings(self) -> None:
        text = "## Added\n\n```\n## Added\n```\n\n## Added\n\n~~~~\n# x\n~~~\n~~~~\n## Added\n"
        lines = text.splitlines()
        self.assertEqual([release_check.heading_anchor(text, i) for i in (0, 6, 12)],
                         ["added", "added-1", "added-2"])
        self.assertEqual([lines[i] for i in (0, 3, 6, 12)], ["## Added"] * 4)
        # Control: a line inside a fence is refused as a heading, not counted.
        with self.assertRaises(release_check.CheckFailed):
            release_check.heading_anchor(text, 3)

    def test_the_first_release_section_passed_whole_is_refused(self) -> None:
        section = release_check.release_notes(first_release_changelog(), "v0.1.0")
        self.assertGreater(len(section), 200_000)  # 222,989 measured
        (problem,) = release_check.release_body_problems(section)
        self.assertIn(f"{len(section):,} characters", problem)
        self.assertIn("125,000", problem)

    def test_the_short_notes_for_the_first_release_pass_and_link_the_section(self) -> None:
        changelog = first_release_changelog()
        notes = release_check.release_notes_summary(changelog, "v0.1.0", "Veridor-authz/veridor")
        self.assertEqual(release_check.release_body_problems(notes), [])
        self.assertLess(len(notes), 2_000)
        opening, link = notes.split("\n\n")
        self.assertTrue(opening.startswith("First public release. It contains `map`, `run` and `mutate`"))
        self.assertNotIn("### ", notes)
        self.assertEqual(link, "The full release notes are the [0.1.0] section of CHANGELOG.md:\n"
                         "https://github.com/Veridor-authz/veridor/blob/v0.1.0/CHANGELOG.md#"
                         f"{FIRST_RELEASE_ANCHOR}\n")

    def test_every_paragraph_before_the_first_subheading_is_in_the_notes(self) -> None:
        """The notes kept only the first paragraph of that text, so an upgrade
        note written as the second paragraph never reached the release page."""
        changelog = ("# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n"
                     "Second release.\n\nUpgrading: re-run `veridor map` first.\n\n"
                     "#7 in the tracker is not a heading.\n\n### Added\n\n- a thing\n")
        notes = release_check.release_notes_summary(changelog, "v0.2.0", "Veridor-authz/veridor")
        opening, _, link = notes.rpartition("\n\n")
        self.assertEqual(opening, "Second release.\n\nUpgrading: re-run `veridor map` first.\n\n"
                         "#7 in the tracker is not a heading.")
        self.assertTrue(link.startswith("The full release notes are the [0.2.0] section"), link)
        self.assertNotIn("- a thing", notes)
        # With no subheading at all, the whole section is the text before one.
        bare = changelog.replace("### Added\n\n- a thing\n", "")
        self.assertIn("is not a heading.\n\nThe full release notes",
                      release_check.release_notes_summary(bare, "v0.2.0", "Veridor-authz/veridor"))

    def test_the_limit_counts_characters_not_bytes(self) -> None:
        self.assertEqual(release_check.release_body_problems("é" * release_check.RELEASE_BODY_LIMIT), [])
        self.assertTrue(release_check.release_body_problems("e" * (release_check.RELEASE_BODY_LIMIT + 1)))
        self.assertTrue(release_check.release_body_problems(" \n"))

    def test_notes_over_the_limit_are_refused_by_notes_itself(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "pyproject.toml").write_text(NotesTest.PYPROJECT, encoding="utf-8")
        long = "word " * 30_000
        for label, opening, code in (("over", long, 1), ("control, under", "Short.", 0)):
            with self.subTest(label):
                (root / "CHANGELOG.md").write_text(
                    f"## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n{opening}\n\n### Added\n\n- x\n",
                    encoding="utf-8")
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(release_check.main(["--root", str(root), "notes", "v0.2.0"]), code)
                self.assertEqual("too long" in err.getvalue(), code == 1, err.getvalue())

    def test_the_release_step_is_read_from_release_yml(self) -> None:
        workflow = (ROOT / release_check.RELEASE_WORKFLOW).read_text(encoding="utf-8")
        script = release_check.release_step_script(workflow)
        self.assertIn('python3 scripts/release_check.py notes "$GITHUB_REF_NAME" > "$RUNNER_TEMP/notes.md"', script)
        self.assertIn('gh release create "$GITHUB_REF_NAME" dist/* "${flags[@]}"', script)
        self.assertFalse(script.startswith(" "))
        self.assertNotIn("- name:", script)
        # Controls: a second step of that name, or none, is refused rather than guessed at.
        step = "      - name: Create the release\n"
        twice = workflow.replace(step, step + "        run: |\n          true\n" + step)
        for label, text in (("twice", twice), ("missing", workflow.replace(step, "      - name: Other\n"))):
            with self.subTest(label), self.assertRaisesRegex(release_check.CheckFailed, "steps, expected 1"):
                release_check.release_step_script(text)


@slow("runs release.yml's release step under bash, with gh stubbed")
class ReleaseBodyStepTest(unittest.TestCase):
    """`release-body` against a copy of the files the step reads."""

    ARGS = ["--repository", "Veridor-authz/veridor", "--image", "ghcr.io/veridor-authz/veridor",
            "--chart-repository", "oci://ghcr.io/veridor-authz/charts"]

    def tree(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="veridor-release-body-"))
        self.addCleanup(shutil.rmtree, root, True)
        for name in ("pyproject.toml", release_check.RELEASE_WORKFLOW, "scripts/release_check.py"):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, root / name)
        (root / "CHANGELOG.md").write_text(first_release_changelog(), encoding="utf-8")
        return root

    def body(self, root: Path) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release_check.main(["--root", str(root), "release-body", "v0.1.0", *self.ARGS])
        return code, out.getvalue(), err.getvalue()

    def test_the_body_the_step_would_post_for_the_first_release_fits(self) -> None:
        root = self.tree()
        code, body, err = self.body(root)
        self.assertEqual(code, 0, err)
        notes = release_check.release_notes_summary(first_release_changelog(), "v0.1.0", "Veridor-authz/veridor")
        self.assertTrue(body.startswith(notes), body[:300])
        self.assertIn(f"#{FIRST_RELEASE_ANCHOR}\n", body)
        self.assertIn(f"ghcr.io/veridor-authz/veridor@{release_check.PLACEHOLDER_DIGEST}", body)
        self.assertIn("release.yml@refs/tags/v0.1.0`.", body)
        self.assertIn("The SBOM and SHA256SUMS carry no provenance.", body)
        self.assertLessEqual(len(body), release_check.RELEASE_BODY_LIMIT)
        self.assertIn(f"{len(body):,} of 125,000 characters", err)

    def test_control_the_notes_as_they_were_are_refused(self) -> None:
        """The step as it stood when v0.1.0 was tagged: `notes` printed the
        whole section. Stood in for by a script that prints it."""
        root = self.tree()
        section = release_check.release_notes(first_release_changelog(), "v0.1.0")
        (root / "section.md").write_text(section, encoding="utf-8")
        (root / "scripts" / "release_check.py").write_text(
            "import sys\nsys.stdout.write(open('section.md', encoding='utf-8').read())\n", encoding="utf-8")
        code, out, err = self.body(root)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("characters, and GitHub refuses more than 125,000", err)
        posted = int(re.search(r"release body is ([\d,]+) characters", err).group(1).replace(",", ""))
        self.assertGreater(posted, len(section))  # the verification lines were appended to it

    def test_control_a_step_that_posts_no_notes_file_is_named(self) -> None:
        root = self.tree()
        workflow = root / release_check.RELEASE_WORKFLOW
        text = workflow.read_text(encoding="utf-8")
        self.assertEqual(text.count('--notes-file "$RUNNER_TEMP/notes.md"'), 1)
        workflow.write_text(text.replace('--notes-file "$RUNNER_TEMP/notes.md"', "--generate-notes"),
                            encoding="utf-8")
        code, out, err = self.body(root)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("with no --notes-file", err)

    def test_control_a_failing_notes_command_stops_it(self) -> None:
        root = self.tree()
        (root / "CHANGELOG.md").write_text("## [Unreleased]\n\n- pending\n\n" +
                                           first_release_changelog().split("## [Unreleased]\n\n", 1)[1],
                                           encoding="utf-8")
        code, out, err = self.body(root)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("'## [Unreleased]' is not empty", err)


#: What the wheel installs in these fakes, and so what the sdist must carry under src/.
PACKAGE = ("veridor/__init__.py", "veridor/cli.py", "veridor/web/index.html")


class DistTest(unittest.TestCase):
    #: What CONTRIBUTING's step 3 sends a reader to, and more. Each must say so
    #: until a version has a dated CHANGELOG section.
    SAY_NOTHING_IS_RELEASED = (
        "README.md", "SECURITY.md", "SUPPORT.md", "ci/README.md", "ci/.gitlab-ci.yml", "ci/Jenkinsfile",
        "ci/azure-pipelines.yml", "ci/buildspec.yml", "templates/veridor.yml", "deploy/helm/veridor-gate/README.md",
        "deploy/helm/veridor-gate/values.yaml", "deploy/kustomize/veridor-gate/README.md",
        "deploy/kustomize/veridor-gate/base/job.yaml", "deploy/argocd/README.md",
        "deploy/argocd/application-example.yaml", "deploy/argo-rollouts/README.md",
        "deploy/argo-rollouts/veridor-analysistemplate.yaml",
    )

    def _dist(self, *, notice: bool = True, expression: str = "Apache-2.0",
              drop: tuple[str, ...] = (), extra: tuple[str, ...] = (),
              description: str = "", pyproject: str = "[project]") -> Path:
        """A wheel and an sdist as setuptools builds them; ``drop`` leaves
        sdist members out and ``extra`` adds some."""
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        metadata = (f"Metadata-Version: 2.4\nName: veridor\nVersion: 0.1.0\n"
                    f"License-Expression: {expression}\nLicense-File: LICENSE\n"
                    + ("License-File: NOTICE\n" if notice else "") + "\n" + description)
        info = "veridor-0.1.0.dist-info"
        with zipfile.ZipFile(directory / "veridor-0.1.0-py3-none-any.whl", "w") as wheel:
            for name in PACKAGE:
                wheel.writestr(name, "code")
            wheel.writestr(f"{info}/METADATA", metadata)
            wheel.writestr(f"{info}/licenses/LICENSE", "licence")
            if notice:
                wheel.writestr(f"{info}/licenses/NOTICE", "notice")
        with tarfile.open(directory / "veridor-0.1.0.tar.gz", "w:gz") as sdist:
            members = {"PKG-INFO": metadata, "LICENSE": "licence", "pyproject.toml": pyproject,
                       "README.md": "readme", **{f"src/{name}": "code" for name in PACKAGE},
                       **{name: "extra" for name in extra}}
            if notice:
                members["NOTICE"] = "notice"
            for name in drop:
                del members[name]
            for name, body in members.items():
                data = body.encode()
                member = tarfile.TarInfo(f"veridor-0.1.0/{name}")
                member.size = len(data)
                sdist.addfile(member, io.BytesIO(data))
        return directory

    def test_dist_accepts_a_complete_build(self) -> None:
        self.assertEqual(release_check.check_dist(self._dist(), "0.1.0"), [])

    def test_control_dist_names_what_is_missing(self) -> None:
        problems = release_check.check_dist(self._dist(notice=False), "0.1.0")
        self.assertTrue(any("licenses/NOTICE" in p for p in problems), problems)
        self.assertTrue(any("License-File" in p for p in problems), problems)
        problems = release_check.check_dist(self._dist(expression="MIT"), "0.1.0")
        self.assertTrue(any("License-Expression" in p for p in problems), problems)
        self.assertTrue(any("veridor-0.2.0-py3-none-any.whl" in p
                            for p in release_check.check_dist(self._dist(), "0.2.0")))
        self.assertTrue(release_check.check_dist(self._dist(), "0.1.0", require_zipapp=True))

    def test_a_tagged_build_cannot_publish_a_page_saying_no_release_exists(self) -> None:
        """The readme pyproject.toml names is the PyPI description and a
        version's page cannot be replaced. A wheel and sdist built from this tree passed `dist --tag` with
        "No release exists yet. Veridor is not on PyPI" in their metadata."""
        for statement in ("**As of 2026-11-04 no release exists.**", "Veridor is not on\nPyPI, and",
                          "As of 2026-11-04, no release\nhas been tagged.",
                          "Until the first release, install from source"):
            with self.subTest(statement=statement):
                built = self._dist(description=f"# Veridor\n\n{statement}\n")
                problems = release_check.check_dist(built, "0.1.0", tagged=True)
                self.assertEqual(len(problems), 2, problems)  # the wheel and the sdist
                self.assertTrue(all("the PyPI page, still says" in p for p in problems), problems)
                # Control: every build on a branch carries this text and has to pass.
                self.assertEqual(release_check.check_dist(built, "0.1.0"), [])

    def test_control_a_tagged_build_with_a_released_description_passes(self) -> None:
        built = self._dist(description="# Veridor\n\nInstall with `pip install veridor==0.1.0`.\n")
        self.assertEqual(release_check.check_dist(built, "0.1.0", tagged=True), [])

    def test_a_description_with_a_link_pypi_cannot_follow_is_refused(self) -> None:
        """PyPI renders the description with no base URL and no heading ids.
        The README was the description, with 43 distinct relative and #anchor
        targets in it, and every check here passed it. Not only for a tag: a
        branch build fails too, so the README cannot drift back first."""
        for link in ("[the changelog](CHANGELOG.md)", "[non-goals](#non-goals)",
                     "[tested](ci/README.md#what-was-tested)", "![logo](docs/logo.png)",
                     "see\n[x]: SECURITY.md", '<a href="#install">install</a>'):
            with self.subTest(link=link):
                built = self._dist(description=f"# Veridor\n\nRead {link}.\n")
                for tagged in (False, True):
                    problems = release_check.check_dist(built, "0.1.0", tagged=tagged)
                    self.assertEqual(len(problems), 2, problems)  # the wheel and the sdist
                    self.assertTrue(all("not absolute URLs, which go nowhere on PyPI" in p for p in problems),
                                    problems)

    def test_control_absolute_links_and_links_in_code_pass(self) -> None:
        description = ("# Veridor\n\n[non-goals](https://github.com/o/r#non-goals), <https://docs.example/>, "
                       "[mail](mailto:a@example.org), `[not a link](x.md)`\n\n```\n[nor](y.md)\n```\n")
        self.assertEqual(release_check.check_dist(self._dist(description=description), "0.1.0", tagged=True), [])

    def test_an_sdist_must_carry_the_readme_its_pyproject_names(self) -> None:
        """Building the wheel from the sdist reads it; setuptools fails without it."""
        pyproject = '[project]\nreadme = "README.pypi.md"\n'
        self.assertEqual(release_check.check_dist(
            self._dist(pyproject=pyproject, extra=("README.pypi.md",)), "0.1.0"), [])
        problems = release_check.check_dist(self._dist(pyproject=pyproject), "0.1.0")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("cannot rebuild the wheel", problems[0])
        self.assertIn("veridor-0.1.0/README.pypi.md", problems[0])
        # Control: a readme pyproject does not name is still a stray file.
        problems = release_check.check_dist(self._dist(extra=("README.pypi.md",)), "0.1.0")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("must not ship", problems[0])

    def test_a_tagged_build_with_no_description_is_refused(self) -> None:
        """The rule above would read nothing and pass."""
        problems = release_check.check_dist(self._dist(), "0.1.0", tagged=True)
        self.assertEqual(len(problems), 2, problems)
        self.assertTrue(all("has no long description" in p for p in problems), problems)

    def test_the_release_build_passes_the_tag_and_the_ci_build_does_not(self) -> None:
        """--tag is what turns the description rule on. Without it in release.yml
        the rule is silent, and with it in veridor.yml every push fails."""
        tagged = r"release_check\.py dist dist --tag \"\$GITHUB_REF_NAME\""
        workflows = ROOT / ".github" / "workflows"
        self.assertRegex((workflows / "release.yml").read_text(encoding="utf-8"), tagged)
        ci = (workflows / "veridor.yml").read_text(encoding="utf-8")
        self.assertRegex(ci, r"release_check\.py dist dist --require-zipapp")
        self.assertNotRegex(ci, tagged)

    def test_the_command_line_with_a_tag_reads_the_description(self) -> None:
        """--tag is the only thing that sets ``tagged``. Mutant: main() passing
        tagged=False exits 0 here, and the two tests above still pass, because they
        call check_dist directly and read release.yml's text."""
        built = self._dist(description="# Veridor\n\nNo release exists yet. Veridor is not on PyPI.\n")
        tree = {"version": "0.1.0", "semver": "0.1.0", "prerelease": "false"}
        for argv, code, said in ((["dist", str(built), "--tag", "v0.1.0"], 1, "its description, the PyPI page"),
                                 (["dist", str(built)], 0, "")):
            with self.subTest(argv=argv[2:]):
                err = io.StringIO()
                with mock.patch.object(release_check, "check_versions", return_value=tree), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    self.assertEqual(release_check.main(argv), code, err.getvalue())
                self.assertIn(said, err.getvalue())

    def test_a_tag_refuses_a_template_still_warning_of_an_unclaimed_name(self) -> None:
        """The warning beside each pip line is false once the release holds the
        name, and nothing else would make anyone take it out."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ci").mkdir()
        (root / "ci" / "buildspec.yml").write_text("# The name is held.\n", encoding="utf-8")
        self.assertEqual(release_check.tree_release_statements(root), [])
        (root / "ci" / "buildspec.yml").write_text("# The PyPI name is\n# unclaimed.\n", encoding="utf-8")
        problems = release_check.tree_release_statements(root)
        self.assertEqual(len(problems), 1)
        self.assertIn("ci/buildspec.yml still says ['unclaimed']", problems[0])

    def test_the_rule_still_reads_what_the_tree_says(self) -> None:
        """Rewording the sentence past the rule would silence it. Until a version
        has a dated CHANGELOG section, every file it reads must say so in words
        it reads."""
        self._skip_once_released()
        problems = release_check.tree_release_statements(ROOT)
        said = {problem.split(" still says ")[0] for problem in problems}
        self.assertEqual(set(self.SAY_NOTHING_IS_RELEASED) - said, set(), problems)

    def _skip_once_released(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        if re.search(r"^## \[\d[^\]]*\] - \d{4}-\d{2}-\d{2}", changelog, re.M):
            self.skipTest("a release exists; tree_release_statements holds the files to that")

    def test_every_sentence_the_tree_uses_is_one_the_rule_reads(self) -> None:
        """The rule had four phrases, and the tree's own banner was not one of
        them: a fold that replaced only those four, only in the seven files it
        listed, passed `notes` with all of these still in the tree (measured)."""
        for sentence in ("# NOT YET PUBLISHED as of 2026-11-04. No release tag",
                         "**Not yet published, as of 2026-11-04.**",
                         "**Not published as of 2026-11-04.** At chart version",
                         "**Neither is published as of 2026-11-04.**",
                         "Nothing is published, so the image",
                         "A placeholder: no image is published yet.",
                         "The chart is not published to a public chart\n#   repository",
                         "- **Releases.** None yet. After",
                         "Before the first release | After the first release",
                         'pip install "./REPLACE_WITH_THE_PATH_OF_A_VERIDOR_WHEEL.whl"',
                         # ci/Jenkinsfile, ci/azure-pipelines.yml, ci/buildspec.yml
                         "// below do not exist until Veridor's first release (0.1.0).",
                         "# do not exist until Veridor's first release (0.1.0).",
                         # templates/veridor.yml, ci/.gitlab-ci.yml, README.md
                         "The default names the first release, which does not exist yet.",
                         "# which does not exist yet, under a namespace nothing here shows this project",
                         "the PyPI package and a Catalog entry do not exist\nuntil the first release."):
            with self.subTest(sentence=sentence):
                self.assertTrue(release_check.pre_release_statements(sentence))
        self.assertEqual(release_check.pre_release_statements(
            "The image is signed. A published version cannot be replaced. After the first release, "
            "only the latest release gets fixes. The nearest ancestor that exists, and the names "
            "below it that do not exist yet."), [])

    def test_a_file_on_no_list_is_still_read(self) -> None:
        """Files were a list, which left out ci/.gitlab-ci.yml and the Helm and
        Kustomize READMEs while CONTRIBUTING told the reader they were covered."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "deploy" / "new").mkdir(parents=True)
        (root / "deploy" / "new" / "README.md").write_text("**Not published as of 2026-11-04.**\n", encoding="utf-8")
        for exempt in ("CHANGELOG.md", "CONTRIBUTING.md"):
            (root / exempt).write_text("The rule refuses a sentence saying not published.\n", encoding="utf-8")
        (root / "tests").mkdir()
        (root / "tests" / "test_x.py").write_text("# not published\n", encoding="utf-8")
        problems = release_check.tree_release_statements(root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("deploy/new/README.md still says ['not published']", problems[0])

    def test_every_path_to_the_default_image_says_it_is_not_published(self) -> None:
        """The Argo CD path said the chart was unpublished and never mentioned the
        image, so a reader who served the chart as told got a PostSync Job that
        could not pull. The two copyable defaults had no note beside them."""
        self._skip_once_released()
        for name in ("deploy/argocd/README.md", "deploy/argocd/application-example.yaml",
                     "deploy/argo-rollouts/veridor-analysistemplate.yaml", "deploy/helm/veridor-gate/values.yaml"):
            with self.subTest(file=name):
                prose = " ".join((ROOT / name).read_text(encoding="utf-8").replace("#", " ").split())
                self.assertRegex(prose, r"(?i)\bimage\b.{0,80}\bnot published\b")

    def test_an_sdist_carrying_the_test_suite_is_refused(self) -> None:
        """MANIFEST.in prunes tests/; this is what notices if it stops. Control:
        the same build without the extra member passes (test above)."""
        for extra in ("tests/test_core.py", "docs/index.md", "src/veridor/__pycache__/cli.cpython-312.pyc"):
            with self.subTest(member=extra):
                problems = release_check.check_dist(self._dist(extra=(extra,)), "0.1.0")
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("must not ship", problems[0])
                self.assertIn(f"veridor-0.1.0/{extra}", problems[0])

    def test_an_sdist_carrying_anything_outside_the_package_is_refused(self) -> None:
        """An allowlist: the denylist named tests/ and docs/, so an ignored local
        directory, fixtures/ and scripts/ passed (measured)."""
        for extra in (".private/x.json", "fixtures/veridor.demo.json", "scripts/demo_server.py",
                      "src/other/thing.py", "WORKING-NOTES.md"):
            with self.subTest(member=extra):
                problems = release_check.check_dist(self._dist(extra=(extra,)), "0.1.0")
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("must not ship", problems[0])
                self.assertIn(f"veridor-0.1.0/{extra}", problems[0])

    def test_control_what_setuptools_writes_into_an_sdist_is_accepted(self) -> None:
        built = self._dist(extra=("setup.cfg", "MANIFEST.in", "src/veridor.egg-info/PKG-INFO"))
        self.assertEqual(release_check.check_dist(built, "0.1.0"), [])

    def test_a_wheel_carrying_anything_outside_the_package_is_refused(self) -> None:
        """REGRESSION. The wheel's contents were never read: tests/, an ignored
        local directory and docs/ in it all exited 0, and the wheel is what PyPI
        serves."""
        for extra in ("tests/test_core.py", ".private/x.json", "docs/notes.md", "fixtures/x.json",
                      "veridor/__pycache__/cli.cpython-312.pyc", "veridor-0.1.0.data/data/x"):
            with self.subTest(member=extra):
                directory = self._dist()
                with zipfile.ZipFile(directory / "veridor-0.1.0-py3-none-any.whl", "a") as wheel:
                    wheel.writestr(extra, "stray")
                problems = release_check.check_dist(directory, "0.1.0")
                self.assertTrue(any("must not ship" in problem and extra in problem for problem in problems), problems)

    def test_a_zipapp_carrying_anything_outside_the_package_is_refused(self) -> None:
        directory = self._dist()
        with zipfile.ZipFile(directory / "veridor-0.1.0.pyz", "w") as pyz:
            for name in ("__main__.py", "LICENSE", "NOTICE", "veridor/__init__.py", "veridor/cli.py"):
                pyz.writestr(name, "x")
        self.assertEqual(release_check.check_dist(directory, "0.1.0"), [])
        for stray in (".private/x.json", "veridor/__pycache__/cli.cpython-312.pyc"):
            with self.subTest(stray=stray):
                with zipfile.ZipFile(directory / "veridor-0.1.0.pyz", "a") as pyz:
                    pyz.writestr(stray, "stray")
                problems = release_check.check_dist(directory, "0.1.0")
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("must not ship", problems[0])
                self.assertIn(stray, problems[0])

    def test_an_sdist_that_cannot_rebuild_the_wheel_is_refused(self) -> None:
        """A prune that took too much would publish an sdist that builds a
        different Veridor: every file the wheel installs must be under src/."""
        for dropped in ("src/veridor/cli.py", "src/veridor/web/index.html", "pyproject.toml", "README.md"):
            with self.subTest(dropped=dropped):
                problems = release_check.check_dist(self._dist(drop=(dropped,)), "0.1.0")
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("cannot rebuild the wheel", problems[0])
                self.assertIn(f"veridor-0.1.0/{dropped}", problems[0])


class OwnerTest(unittest.TestCase):
    """A release under another owner failed at the image job, after PyPI.

    REGRESSION. IMAGE and CHART_REPOSITORY were literals nothing compared with
    the repository, so a rename that missed them, or kept a mixed-case owner
    in a registry path, burned the version first (a plain rename passed the
    suite and helm lint and rendered ghcr.io/Acme-Sec/veridor, measured)."""

    REPOSITORY = "Acme-Sec/veridor"
    IMAGE = "ghcr.io/acme-sec/veridor"
    CHART = "oci://ghcr.io/acme-sec/charts"

    def tree(self, *, chart_image: str = IMAGE, url: str = "https://github.com/Acme-Sec/veridor",
             signer: str = REPOSITORY) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "deploy/helm/veridor-gate").mkdir(parents=True)
        (root / "deploy/helm/veridor-gate/values.yaml").write_text(
            f"image:\n  # where\n  repository: {chart_image}\n  tag: \"\"\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(f'[project.urls]\nRepository = "{url}"\n', encoding="utf-8")
        (root / "SECURITY.md").write_text(
            f"gh attestation verify x.whl --repo {signer} \\\n"
            f"--cert-identity https://github.com/{signer}/.github/workflows/release.yml@refs/tags/vX.Y.Z\n"
            f"--certificate-identity-regexp '^https://github.com/{signer}/\\.github/workflows/release\\.yml@'\n",
            encoding="utf-8")
        return root

    def problems(self, root: Path | None = None, **given: str) -> list[str]:
        return release_check.owner_problems(root or self.tree(), given.get("repository", self.REPOSITORY),
                                            given.get("image", self.IMAGE), given.get("chart", self.CHART))

    def test_the_signing_identity_must_match_the_repository_in_its_own_case(self) -> None:
        """The certificate is compared exactly and everything else here is case
        blind, so a repository spelled differently passed with SECURITY.md's
        commands refusing every genuine signature. Mutant: `name != repository`
        compared with casefold fails the first of these."""
        problems = self.problems(repository="ACME-SEC/VERIDOR")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("SECURITY.md's signing identity names Acme-Sec/veridor, not ACME-SEC/VERIDOR", problems[0])
        root = self.tree()
        security = root / "SECURITY.md"
        security.write_text("\n".join(security.read_text(encoding="utf-8").split("\n")[:2]) + "\n"
                            "--certificate-identity-regexp '^https://github.com/acme-sec/veridor/\\.github/workflows/release'\n",
                            encoding="utf-8")
        problems = self.problems(root)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("names acme-sec/veridor", problems[0])

    def test_an_escaped_regexp_identity_naming_another_repository_is_refused(self) -> None:
        """A regexp identity may escape every dot, github\\.com included; the
        rule read only the plain spelling and passed one naming someone else.
        Mutant: drop the optional backslash before `.com` and this passes."""
        root = self.tree()
        security = root / "SECURITY.md"
        security.write_text(security.read_text(encoding="utf-8")
                            + "--certificate-identity-regexp '^https://github\\.com/Other/veridor/"
                            "\\.github/workflows/release\\.yml@refs/tags/v'\n", encoding="utf-8")
        self.assertEqual(self.problems(root), [
            f"SECURITY.md's signing identity names Other/veridor, not {self.REPOSITORY}: "
            "the certificate is compared exactly, so genuine signatures would be refused"])

    def test_a_gh_attestation_repo_naming_another_repository_is_refused(self) -> None:
        """`--repo` was not compared at all. Mutant: return `problems` alone."""
        for spelling in ("--repo Other/veridor \\", "--repo=Other/veridor", "--repo 'Other/veridor'",
                         "-R Other/veridor", "--repo  Other/veridor", "--repo \\\n  Other/veridor"):
            with self.subTest(spelling=spelling):
                root = self.tree()
                security = root / "SECURITY.md"
                security.write_text(security.read_text(encoding="utf-8")
                                    + f"gh attestation verify x.whl {spelling}\n", encoding="utf-8")
                self.assertEqual(self.problems(root), [
                    f"SECURITY.md's gh attestation --repo names Other/veridor, not {self.REPOSITORY}: "
                    "genuine attestations would be refused"])

    def test_a_gh_attestation_owner_naming_another_owner_is_refused(self) -> None:
        """`--owner` selects the attestations as `--repo` does. Mutant: drop `owners`."""
        root = self.tree()
        security = root / "SECURITY.md"
        security.write_text(security.read_text(encoding="utf-8")
                            + "gh attestation verify x.whl --owner Other\n", encoding="utf-8")
        self.assertEqual(self.problems(root), [
            f"SECURITY.md's gh attestation --owner names Other, not {self.REPOSITORY.split('/')[0]}: "
            "genuine attestations would be refused"])

    def test_a_security_policy_with_no_signing_identity_is_refused(self) -> None:
        """The rule above would read nothing and pass."""
        root = self.tree()
        (root / "SECURITY.md").write_text("Report through the form.\n", encoding="utf-8")
        self.assertEqual(self.problems(root), [
            "SECURITY.md names no release.yml signing identity to compare with this repository"])

    def test_the_real_security_policy_names_the_real_repository(self) -> None:
        """Both commands read: a test on a planted file cannot see the real one."""
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        repository = re.search(r'^Repository = "https://github\.com/([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(release_check._signing_identity_problems(ROOT, repository), [])
        named = re.findall(r"github\.com/([^/\s]+/[^/\s]+)/\\?\.github/workflows/release",
                           (ROOT / "SECURITY.md").read_text(encoding="utf-8"))
        self.assertEqual(len(named), 2)
        self.assertEqual(re.findall(r"--repo ([^\s\\]+)", (ROOT / "SECURITY.md").read_text(encoding="utf-8")),
                         [repository])

    def test_values_with_no_image_repository_is_named(self) -> None:
        """Mutant: without the None test this raises AttributeError, not a problem."""
        root = self.tree()
        (root / "deploy/helm/veridor-gate/values.yaml").write_text("image:\n  tag: \"\"\n", encoding="utf-8")
        self.assertEqual(self.problems(root), [
            "deploy/helm/veridor-gate/values.yaml has no image.repository to compare with IMAGE"])

    def test_a_tree_under_this_repositorys_owner_passes_with_a_mixed_case_owner(self) -> None:
        self.assertEqual(self.problems(), [])

    def test_a_github_owner_in_another_case_still_matches(self) -> None:
        """Except the signing identity, which is compared exactly: the test above.
        Spelling that the way the repository is spelled leaves the rest case blind."""
        self.assertEqual(self.problems(self.tree(signer="acme-sec/VERIDOR"), repository="acme-sec/VERIDOR"), [])

    def test_every_way_of_naming_someone_else_is_refused(self) -> None:
        cases = {
            "image": ({"image": "ghcr.io/other-owner/veridor"}, "IMAGE 'ghcr.io/other-owner/veridor' is not under ghcr.io/acme-sec/"),
            "chart": ({"chart": "oci://ghcr.io/other-owner/charts"}, "CHART_REPOSITORY 'ghcr.io/other-owner/charts' is not under"),
            "chart scheme": ({"chart": "ghcr.io/acme-sec/charts"}, "does not start with oci://"),
            "capitals": ({"image": "ghcr.io/acme-sec/Veridor"}, "has capitals"),
            "not a repository": ({"repository": "veridor"}, "is not OWNER/REPO"),
        }
        for label, (given, message) in cases.items():
            with self.subTest(case=label):
                problems = self.problems(**given)
                self.assertTrue(any(message in problem for problem in problems), problems)

    def test_a_mixed_case_owner_copied_into_the_registry_path_is_refused(self) -> None:
        problems = self.problems(image="ghcr.io/Acme-Sec/veridor", chart="oci://ghcr.io/Acme-Sec/charts",
                                 root=self.tree(chart_image="ghcr.io/Acme-Sec/veridor"))
        self.assertEqual(len(problems), 2, problems)
        self.assertIn("is not under ghcr.io/acme-sec/", problems[0])

    def test_a_chart_or_a_package_left_behind_is_refused(self) -> None:
        self.assertIn("image.repository is ghcr.io/other-owner/veridor",
                      self.problems(self.tree(chart_image="ghcr.io/other-owner/veridor"))[0])
        self.assertIn("pyproject.toml's Repository",
                      self.problems(self.tree(url="https://github.com/other-owner/veridor"))[0])

    def test_the_command_exits_1_and_names_it(self) -> None:
        arguments = ["--root", str(self.tree()), "owner", "--repository", self.REPOSITORY,
                     "--image", "ghcr.io/other-owner/veridor", "--chart-repository", self.CHART]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_check.main(arguments), 1)
        self.assertIn("::error title=release check::IMAGE", err.getvalue())
        arguments[arguments.index("--image") + 1] = self.IMAGE
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_check.main(arguments), 0)


if __name__ == "__main__":
    unittest.main()
