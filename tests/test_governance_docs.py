"""The files a contributor or an adopter reads first, held to what they point at.

The README's CI/CD integrations table is the one place a reader decides which
integration to trust, so every row must point at a file or heading that
exists, and every row must say what has not been done yet. The governance
files link to each other by heading; a renamed heading breaks those links
silently. Each check below has a control that makes it fail on a known-bad
sample.

Fast tier: files are read, nothing is spawned.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from yaml_subset import load_yaml  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")
MAINTAINER = "@Santoshkumarpuppala"
_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)\)")
_FENCE = re.compile(r"^```.*?^```", re.M | re.S)


def anchors(markdown: str) -> set[str]:
    """GitHub's heading anchors, plus explicit <a id> / <a name> ones."""
    found: set[str] = set()
    seen: dict[str, int] = {}
    for match in re.finditer(r"^#{1,6} (.+?)\s*$", _FENCE.sub("", markdown), re.M):
        slug = re.sub(r"[^\w\- ]", "", match.group(1).strip().lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    found |= set(re.findall(r"<a (?:id|name)=\"([^\"]+)\"", markdown))
    return found


def link_problems(markdown: str, source: Path) -> list[str]:
    """Every relative link or anchor in markdown that does not resolve."""
    problems = []
    for target in _LINK.findall(_FENCE.sub("", markdown)):
        if re.match(r"^[a-z]+:", target):
            continue  # an absolute URL; not checked here
        path, _, anchor = target.partition("#")
        file = (source.parent / path).resolve() if path else source
        if not file.exists():
            problems.append(f"{target}: {file.relative_to(ROOT) if ROOT in file.parents else file} does not exist")
            continue
        if anchor:
            if file.is_dir() or file.suffix != ".md":
                problems.append(f"{target}: an anchor into something that is not a markdown file")
            elif anchor not in anchors(file.read_text(encoding="utf-8")):
                problems.append(f"{target}: no heading or anchor #{anchor} in {file.name}")
    return problems


def integration_rows(readme: str) -> list[list[str]]:
    match = re.search(r"^## CI/CD integrations$(.*?)(?=^## )", readme, re.M | re.S)
    if match is None:
        raise AssertionError("README has no '## CI/CD integrations' section")
    rows = [line for line in match.group(1).splitlines() if line.startswith("|")]
    return [[cell.strip() for cell in row.strip("|").split(" | ")] for row in rows[2:]]


class IntegrationsTableTest(unittest.TestCase):
    NAMES = ("GitHub Action", "GitLab CI/CD component", "Argo CD PostSync gate, Helm",
             "Argo CD PostSync gate, Kustomize", "Argo Rollouts analysis", "Jenkins",
             "Azure Pipelines", "AWS CodeBuild", "Any CI, container image", "Any CI, zipapp")

    def test_every_integration_has_a_row(self) -> None:
        rows = integration_rows(README)
        names = [re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", row[0]) for row in rows]
        self.assertEqual(names, list(self.NAMES))
        for row in rows:
            with self.subTest(row=row[0]):
                self.assertEqual(len(row), 4, row)
                self.assertTrue(row[2] and row[3], "say what was executed and what was not")

    def test_every_row_points_at_something_that_exists(self) -> None:
        rows = integration_rows(README)
        for row in rows:
            with self.subTest(row=row[0]):
                cells = " | ".join(row)
                self.assertTrue(_LINK.findall(cells), "a row with no link to its files")
                self.assertEqual(link_problems(cells, ROOT / "README.md"), [])

    def test_control_a_broken_file_or_anchor_fails(self) -> None:
        row = "| [GitHub Action](#github-action) | [action.yml](action.yml) | x | y |"
        self.assertEqual(link_problems(row, ROOT / "README.md"), [])
        self.assertEqual(link_problems(row.replace("(action.yml)", "(action.yaml)"), ROOT / "README.md"),
                         ["action.yaml: action.yaml does not exist"])
        self.assertEqual(link_problems(row.replace("#github-action", "#github-actions"), ROOT / "README.md"),
                         ["#github-actions: no heading or anchor #github-actions in README.md"])
        self.assertEqual(len(link_problems("[x](ci/README.md#what-was-testedd)", ROOT / "README.md")), 1)
        broken = README.replace("(deploy/argo-rollouts/README.md)", "(deploy/argo-rollout/README.md)")
        rows = integration_rows(broken)
        self.assertTrue(any(link_problems(" | ".join(row), ROOT / "README.md") for row in rows))

    def test_the_table_claims_nothing_exists_that_does_not(self) -> None:
        section = re.search(r"^## CI/CD integrations$(.*?)(?=^## )", README, re.M | re.S).group(1)
        self.assertIn("every other row ran outside its platform", section)
        # Until the first tag this read "Nothing is published"; the files
        # name what each release tag publishes, and the table claims only
        # what was executed.
        self.assertIn("are the ones each release tag publishes", " ".join(section.split()))
        for claim in self.EXISTENCE_CLAIMS:
            with self.subTest(claim=claim):
                self.assertIsNone(re.search(claim, section))
        # Control: each pattern fires on the sentence it exists to stop.
        for claim, sentence in zip(self.EXISTENCE_CLAIMS, (
                "Veridor is available on PyPI.", "The image is published to ghcr.io.",
                "The Action ran on GitHub.", "It runs on GitHub today.",
                "It is listed in the CI/CD Catalog.", "Supported on Jenkins.")):
            with self.subTest(control=sentence):
                self.assertIsNotNone(re.search(claim, sentence))

    EXISTENCE_CLAIMS = (r"available on PyPI", r"(?<![Nn]othing )(?<!not )\bis published",
                        r"\bran on GitHub", r"\bruns on GitHub", r"\bin the CI/CD Catalog",
                        r"(?i)\bsupported on\b")


class DocumentLinksTest(unittest.TestCase):
    DOCUMENTS = ("README.md", "CONTRIBUTING.md", "SECURITY.md", "GOVERNANCE.md", "SUPPORT.md",
                 "CHANGELOG.md", ".github/PULL_REQUEST_TEMPLATE.md", "ci/README.md")

    def test_every_relative_link_resolves(self) -> None:
        for name in self.DOCUMENTS:
            with self.subTest(document=name):
                path = ROOT / name
                self.assertEqual(link_problems(path.read_text(encoding="utf-8"), path), [])

    def test_anchors_follow_githubs_rules(self) -> None:
        text = "# A: b / `c`?\n## Same\n## Same\n```\n# not a heading\n```\n<a id=\"x-y\"></a>\n"
        self.assertEqual(anchors(text), {"a-b--c", "same", "same-1", "x-y"})


class GovernanceTest(unittest.TestCase):
    def test_codeowners_covers_what_ships_and_names_the_maintainer(self) -> None:
        text = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        rules = [line.split() for line in text.splitlines() if line.strip() and not line.startswith("#")]
        self.assertTrue(rules)
        for pattern, *owners in rules:
            with self.subTest(pattern=pattern):
                self.assertEqual(owners, [MAINTAINER])
                if pattern != "*":
                    self.assertTrue((ROOT / pattern.strip("/")).exists(), f"{pattern} matches nothing")
        patterns = {rule[0] for rule in rules}
        for required in ("*", "/action.yml", "/.github/", "/scripts/release_check.py", "/deploy/",
                         "/templates/"):
            self.assertIn(required, patterns)
        self.assertIn(MAINTAINER, (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8"))

    def test_issue_forms_are_well_formed(self) -> None:
        directory = ROOT / ".github" / "ISSUE_TEMPLATE"
        forms = sorted(p for p in directory.glob("*.yml") if p.name != "config.yml")
        self.assertEqual([p.name for p in forms],
                         ["bug_report.yml", "feature_request.yml", "overclaim.yml", "question.yml"])
        for path in forms:
            with self.subTest(form=path.name):
                self.assertEqual(self.form_problems(load_yaml(path)), [])
        config = load_yaml(directory / "config.yml")
        self.assertIs(config["blank_issues_enabled"], False)
        security = config["contact_links"][0]
        self.assertTrue(security["url"].endswith("/blob/main/SECURITY.md"), security)
        self.assertIn("SECURITY.md", security["about"])

    #: The labels GitHub gives a new repository. Issue forms do not create a
    #: label: GitHub leaves out one the repository does not have, silently. That
    #: is GitHub's documented behaviour, and the tree cannot show which labels
    #: the repository really has.
    NEW_REPOSITORY_LABELS = frozenset({"bug", "documentation", "duplicate", "enhancement", "good first issue",
                                       "help wanted", "invalid", "question", "wontfix"})

    @classmethod
    def label_problems(cls, form: dict) -> list[str]:
        """A form must carry a label that exists before anyone sets anything up."""
        labels = form.get("labels") or []
        if cls.NEW_REPOSITORY_LABELS.isdisjoint(labels):
            return [f"{form.get('name')}: no label a new repository has, in {labels}"]
        return []

    def test_a_report_from_any_form_is_labelled_on_a_new_repository(self) -> None:
        directory = ROOT / ".github" / "ISSUE_TEMPLATE"
        for path in sorted(directory.glob("*.yml")):
            if path.name != "config.yml":
                with self.subTest(form=path.name):
                    self.assertEqual(self.label_problems(load_yaml(path)), [])

    def test_control_a_form_with_only_an_uncreated_label_is_named(self) -> None:
        self.assertEqual(self.label_problems({"name": "x", "labels": ["claim-discipline"]}),
                         ["x: no label a new repository has, in ['claim-discipline']"])
        self.assertEqual(self.label_problems({"name": "x"}), ["x: no label a new repository has, in []"])
        self.assertEqual(self.label_problems({"name": "x", "labels": ["bug", "claim-discipline"]}), [])

    @staticmethod
    def dead_contact_links(config: dict) -> list[str]:
        """Discussions is off on this repository, so a link to it is a dead page."""
        return [link["url"] for link in config.get("contact_links") or [] if "/discussions" in link["url"]]

    def test_a_question_has_a_route_that_works_with_discussions_off(self) -> None:
        directory = ROOT / ".github" / "ISSUE_TEMPLATE"
        self.assertEqual(self.dead_contact_links(load_yaml(directory / "config.yml")), [])
        name = load_yaml(directory / "question.yml")["name"]
        support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
        self.assertIn(f'The "{name}" issue template', support)
        self.assertNotRegex(support, r"(?i)questions link|discussion")

    def test_control_a_discussions_link_is_named(self) -> None:
        url = "https://github.com/o/r/discussions"
        self.assertEqual(self.dead_contact_links({"contact_links": [{"url": url}]}), [url])

    @staticmethod
    def form_problems(form: dict) -> list[str]:
        problems = [f"missing {key}" for key in ("name", "description", "body") if not form.get(key)]
        ids = []
        for item in form.get("body") or []:
            kind = item.get("type")
            if kind not in {"markdown", "textarea", "input", "dropdown", "checkboxes"}:
                problems.append(f"unknown body type {kind!r}")
            elif kind != "markdown":
                ids.append(item.get("id"))
                if not (item.get("attributes") or {}).get("label"):
                    problems.append(f"{item.get('id')}: no label")
        if len(ids) != len(set(ids)) or None in ids:
            problems.append(f"ids must be present and unique: {ids}")
        return problems

    def test_control_a_broken_form_is_named(self) -> None:
        form = {"name": "x", "description": "y", "body": [
            {"type": "textbox", "id": "a", "attributes": {"label": "A"}},
            {"type": "input", "id": "b", "attributes": {}},
            {"type": "input", "id": "b", "attributes": {"label": "B"}}]}
        self.assertEqual(self.form_problems(form),
                         ["unknown body type 'textbox'", "b: no label", "ids must be present and unique: ['b', 'b']"])


class ConductReportingTest(unittest.TestCase):
    """CODE_OF_CONDUCT.md sends a report to the private form SECURITY.md links,
    with an address as the fallback. A reporter must never be sent to an address
    nobody has shown receives mail, or be left with no confidential route at
    all: an earlier edit replaced an address with "not set", which did the
    second. Until 2026-11-13 the domain took no mail and the document named no
    address; it may now name only one release_check.HELD_ADDRESSES lists."""

    TEXT = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    FLAT = " ".join(TEXT.split())
    EMAIL = re.compile(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)+")

    def test_every_address_it_names_takes_mail(self) -> None:
        sys.path.insert(0, str(ROOT))
        from scripts import release_check  # noqa: PLC0415

        found = self.EMAIL.findall(self.TEXT)
        self.assertEqual(found, ["opensource@veridor.org"])
        self.assertTrue(set(found) <= set(release_check.HELD_ADDRESSES), found)
        self.assertNotIn("conduct@", (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"))

    def test_control_the_address_pattern_finds_an_address(self) -> None:
        self.assertEqual(self.EMAIL.findall("Report to **conduct@example.org**. Reports"),
                         ["conduct@example.org"])

    def test_the_document_gives_the_identity_inventory_nothing_to_rename(self) -> None:
        # The real `identity` over a root holding only the real document: the
        # whole tree costs 0.4 s, near the fast tier's per-test budget, and
        # IdentityTest already covers the whole-tree walk. The form's address
        # stays in SECURITY.md alone, so a rename has one place to change. The
        # one name the document carries is the held fallback address, which the
        # inventory lists and the retired-name check passes.
        sys.path.insert(0, str(ROOT))
        from scripts import release_check  # noqa: PLC0415

        root = Path(tempfile.mkdtemp(prefix="veridor-conduct-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copyfile(ROOT / "CODE_OF_CONDUCT.md", root / "CODE_OF_CONDUCT.md")
        self.assertEqual([(path, name) for path, _, name, _ in release_check.identity(root)],
                         [("CODE_OF_CONDUCT.md", "veridor.org")])
        self.assertEqual(release_check.identity_leftovers(root), [])
        # Control: an address the domain does not take mail for is a leftover.
        with (root / "CODE_OF_CONDUCT.md").open("a", encoding="utf-8") as document:
            document.write("Report to someone@veridor.org.\n")
        self.assertEqual([(path, name) for path, _, name, _ in release_check.identity_leftovers(root)],
                         [("CODE_OF_CONDUCT.md", "@veridor.org")])

    def test_the_route_is_the_private_form_with_the_same_fallback_as_security(self) -> None:
        """The text only. Whether the form is on is a repository setting."""
        enforcement = re.search(r"^## Enforcement$(.*?)(?=^## )", self.TEXT, re.M | re.S).group(1)
        flat = " ".join(enforcement.split())
        self.assertIn("private vulnerability reporting form linked from [SECURITY.md](SECURITY.md)", flat)
        self.assertIn("say it is a conduct report", flat)
        self.assertIn("If the form is unavailable, write to opensource@veridor.org and say it is a "
                      "conduct report.", flat)
        self.assertIn('If that fails too, open a public issue with the "Question" issue form '
                      "asking for a contact, and leave out every detail of the report.", flat)
        self.assertIn(MAINTAINER, flat)

    def test_the_scope_names_no_space_that_does_not_exist(self) -> None:
        self.assertNotIn("discussions", self.TEXT.lower())

    def test_the_covenants_licence_is_indicated(self) -> None:
        """CC BY 4.0 asks an adaptation to name the licence and say it changed
        the text. The document linked the Covenant and named neither."""
        self.assertIn("[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)", self.FLAT)
        self.assertIn("version 2.1", self.FLAT)
        self.assertIn("shortened and changed", self.FLAT)

    def test_it_does_not_promise_a_second_maintainer(self) -> None:
        """"It will be handled by someone else" -- there is one maintainer."""
        self.assertNotIn("handled by someone else", self.TEXT)


class RepositorySettingsTest(unittest.TestCase):
    """The reporting route, the branch rules and the secret scanning live in
    GitHub's settings, where no test can read them. The only settings list in
    the tree covered releases and was timed for the first release, so nothing
    told the maintainer to turn on what SECURITY.md depends on from the first
    push. This holds the list, not the settings."""

    ITEMS = ("Private vulnerability reporting", "Branch protection on `main`", "Secret scanning",
             "push protection", "`claim-discipline`", "Discussions", "About panel")

    @staticmethod
    def section(contributing: str) -> str:
        found = re.search(r"^## Repository settings$(.*?)(?=^## )", contributing, re.M | re.S)
        return found.group(1) if found else ""

    def test_contributing_lists_each_setting(self) -> None:
        section = self.section((ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"))
        for item in self.ITEMS:
            with self.subTest(item=item):
                self.assertIn(item, section)

    def test_control_a_mention_outside_the_section_does_not_count(self) -> None:
        text = "## Other\n\nDiscussions\n\n## Repository settings\n\nSecret scanning\n\n## Next\n"
        self.assertNotIn("Discussions", self.section(text))
        self.assertIn("Secret scanning", self.section(text))


class ResponseTimeTest(unittest.TestCase):
    """One maintainer cannot keep a clock. SECURITY.md promised an
    acknowledgement within a week while SUPPORT.md said there was no
    response-time commitment, and GOVERNANCE.md sent a reader to SUPPORT.md for
    what to expect on a security report, which it did not cover. A reporter
    holds a project to the strictest thing it says."""

    DOCUMENTS = ("SECURITY.md", "SUPPORT.md", "GOVERNANCE.md", "CODE_OF_CONDUCT.md")
    PROMISE = re.compile(r"(?i)\bwithin (?:a|an|one|two|three|\d+) (?:\w+ )?(?:hour|day|week|month)s?\b")

    @staticmethod
    def flat(name: str) -> str:
        return " ".join((ROOT / name).read_text(encoding="utf-8").split())

    def test_no_document_promises_a_time(self) -> None:
        for name in self.DOCUMENTS:
            with self.subTest(document=name):
                self.assertEqual(self.PROMISE.findall(self.flat(name)), [])

    def test_control_the_old_promises_are_found(self) -> None:
        for sentence in ("Expect an acknowledgement within a week.",
                         "If you hear nothing back within a week, use the form.",
                         "We reply within 3 working days."):
            with self.subTest(sentence=sentence):
                self.assertIsNotNone(self.PROMISE.search(sentence))

    def test_the_three_documents_say_the_same_thing(self) -> None:
        self.assertIn("no response-time commitment, for security reports or anything else",
                      self.flat("SUPPORT.md"))
        self.assertIn("no response-time commitment ([SUPPORT.md](SUPPORT.md))", self.flat("SECURITY.md"))
        governance = self.flat("GOVERNANCE.md")
        self.assertIn("waits until that person is available", governance)
        self.assertIn("[SECURITY.md](SECURITY.md) says how to report one", governance)
        self.assertIn("[SUPPORT.md](SUPPORT.md) says there is no response-time commitment", governance)


class CommercialLanguageTest(unittest.TestCase):
    """Veridor is a one-person open source project (GOVERNANCE.md), so nothing
    public should read as a sales document. Names of other people's products
    (GitHub Marketplace, GitLab Premium) are not this."""

    DOCUMENTS = ("README.md", "SECURITY.md", "SUPPORT.md", "GOVERNANCE.md", "CONTRIBUTING.md",
                 "CODE_OF_CONDUCT.md", "pyproject.toml", "tests/tiers.py", "tests/test_tiers.py")
    WORDS = re.compile(r"(?i)\b(?:invest(?:ors?|ment)|buyers?|pitch|pricing|marketing|commercial|customers?"
                       r"|paid support|go-to-market|monetiz\w+)\b")

    def test_public_documents_use_none_of_it(self) -> None:
        for name in self.DOCUMENTS:
            with self.subTest(document=name):
                self.assertEqual(self.WORDS.findall((ROOT / name).read_text(encoding="utf-8")), [])

    def test_control_each_kind_of_word_is_found(self) -> None:
        for sentence in ("Ask about paid support.", "An investment case.", "Our customers say so."):
            with self.subTest(sentence=sentence):
                self.assertIsNotNone(self.WORDS.search(sentence))


class ChangelogTest(unittest.TestCase):
    KINDS = ("Security", "Added", "Changed", "Deprecated", "Removed", "Fixed")
    TEXT = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    @classmethod
    def problems(cls, text: str) -> list[str]:
        problems = []
        sections = re.split(r"^## ", text, flags=re.M)[1:]
        if [s.split("\n", 1)[0] for s in sections].count("[Unreleased]") != 1:
            problems.append("exactly one [Unreleased] section")
        for section in sections:
            title = section.split("\n", 1)[0]
            kinds = re.findall(r"^### (.+)$", section, re.M)
            for kind in kinds:
                if kind not in cls.KINDS:
                    problems.append(f"{title}: '### {kind}' is not a Keep a Changelog heading")
            if len(kinds) != len(set(kinds)):
                problems.append(f"{title}: a '###' heading appears twice")
        return problems

    def test_each_section_has_each_kind_once(self) -> None:
        self.assertEqual(self.problems(self.TEXT), [])

    def test_control_a_second_added_heading_is_caught(self) -> None:
        # Planted before the first '### Fixed', and expected under whichever
        # section holds it. After a release renames [Unreleased] and opens an
        # empty one above it (CONTRIBUTING, "Releasing"), that is the release's
        # section; naming [Unreleased] here failed on every release tree.
        # The planted heading is a second '### Fixed', which that section
        # holds by construction: a planted '### Added' was a duplicate only
        # while the section also had one, and an [Unreleased] holding only
        # Fixed entries made the control pass with nothing doubled.
        at = self.TEXT.index("### Fixed\n")
        title = re.findall(r"^## (.+)$", self.TEXT[:at], re.M)[-1]
        doubled = self.TEXT[:at] + "### Fixed\n\n- x\n\n" + self.TEXT[at:]
        self.assertEqual(self.problems(doubled), [f"{title}: a '###' heading appears twice"])

    def test_the_released_version_is_dated_and_says_so(self) -> None:
        """0.1.0 was once called "First tagged release" while no tag existed,
        and until the tag this asserted its section said "Not released". The
        release commit dates the heading and replaces that paragraph, and
        opens [Unreleased] above it (CONTRIBUTING, "Releasing").

        This asserted [Unreleased] was empty, which held only until the first
        change after the release recorded itself there, as CONTRIBUTING says
        changes do. That it is empty when a tag is pushed is release_check's
        `notes` rule (NotesTest in tests/test_release_check.py). What is held
        here is that the fold left nothing of the pre-release preamble in it."""
        section = re.search(r"^## \[0\.1\.0\] - \d{4}-\d{2}-\d{2}$(.*?)(?=^## |\Z)", self.TEXT, re.M | re.S)
        self.assertIsNotNone(section, "0.1.0 has no dated heading")
        self.assertNotRegex(section.group(1), r"(?m)^(?:Not (?:yet )?released\.|Nothing here has been released)")
        self.assertIn("First public release.", section.group(1))
        self.assertEqual(self.unreleased_problems(self.TEXT), [])

    @staticmethod
    def unreleased_problems(text: str) -> list[str]:
        unreleased = re.search(r"^## \[Unreleased\]$(.*?)(?=^## |\Z)", text, re.M | re.S)
        if unreleased is None or text.index("## [Unreleased]") > text.index("## [0.1.0]"):
            return ["no [Unreleased] section above 0.1.0"]
        if re.search(r"(?m)^(?:Not (?:yet )?released\.|Nothing here has been released)", unreleased.group(1)):
            return ["[Unreleased] still carries the pre-release preamble"]
        return []

    def test_control_the_pre_release_preamble_in_unreleased_is_named(self) -> None:
        planted = self.TEXT.replace("## [Unreleased]\n", "## [Unreleased]\n\nNothing here has been released: "
                                    "there is no tag, and no package, image or\nchart (see [0.1.0]).\n", 1)
        self.assertEqual(self.unreleased_problems(planted), ["[Unreleased] still carries the pre-release preamble"])
        moved = self.TEXT.replace("## [Unreleased]\n", "", 1) + "\n## [Unreleased]\n"
        self.assertEqual(self.unreleased_problems(moved), ["no [Unreleased] section above 0.1.0"])


class MajorTagPolicyTest(unittest.TestCase):
    """Three places state the tag policy; the release workflow is the one that acts."""

    def test_no_moving_major_tag_everywhere_it_is_stated(self) -> None:
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("NO moving major tag", release)
        self.assertNotIn("git push", release)
        prose = {name: re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))
                 for name in ("README.md", "CONTRIBUTING.md")}
        self.assertIn("There is no moving major tag (`v0`, `v1`) while the version is `0.x`",
                      prose["README.md"])
        self.assertIn("There is no moving major tag (`v0`, `v1`) while the version is `0.x`",
                      prose["CONTRIBUTING.md"])
        for name, text in prose.items():
            with self.subTest(document=name):
                self.assertNotRegex(text, r"@v[01]\b(?! ?tag)")


if __name__ == "__main__":
    unittest.main()
