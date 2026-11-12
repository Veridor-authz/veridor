"""The local dashboard is an emitted artifact and is held to the same contract.

core.py states the invariant in its own words: the ``DECLARATION_SCOPE``
sentence "must accompany every count of findings Veridor prints and every
report it emits." The CLI prints it, SARIF carries it in the driver
description, the rule descriptions, and ``runs[0].properties.interpretation``.
``veridor serve`` was the one artifact channel where it was dropped entirely --
a reader who opened the dashboard on an over-strict declaration saw a red
Vulnerable count and a "Fix:" line telling them to change their server, with
nothing saying the declaration is the untested half.

Almost nothing here executes JavaScript. These are source-level contracts: the
strings the UI ships must not drift from the strings core.py defines, and the
fields the runner computes must actually be read by the renderer. The exception
is DriftPanelCoverageTest, which runs renderDrift under node, because a source
check cannot tell a right percentage from a wrong one.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402

WEB = ROOT / "src" / "veridor" / "web"
APP_JS = (WEB / "app.js").read_text(encoding="utf-8")
INDEX_HTML = (WEB / "index.html").read_text(encoding="utf-8")
STYLES = (WEB / "styles.css").read_text(encoding="utf-8")


def _js_constant(name: str) -> str:
    """Read a `const NAME = "a" + "b";` literal out of app.js.

    The UI has no build step and cannot import from Python, so the scope
    sentences exist there as literals. This test is what stops them drifting.
    """
    match = re.search(rf"^const {name} =\n?(.*?);$", APP_JS, re.MULTILINE | re.DOTALL)
    if match is None:  # pragma: no cover - failure path
        raise AssertionError(f"{name} not found in app.js")
    parts = re.findall(r'"(?:[^"\\]|\\.)*"', match.group(1))
    return "".join(json.loads(part) for part in parts)


class ScopeRenderingTest(unittest.TestCase):
    def test_the_ui_renders_the_run_s_own_interpretation(self) -> None:
        """The server already ships `interpretation`; the UI must read it."""
        self.assertIn("run.interpretation", APP_JS)
        self.assertIn("interpretation.summary", APP_JS)
        self.assertIn("interpretation.pass_means", APP_JS)

    def test_the_scope_block_is_not_conditional(self) -> None:
        """It qualifies the counts, so it renders on passed and failed alike."""
        self.assertIn('data-field="scope"', INDEX_HTML)
        self.assertIn('data-field="scope-finding"', INDEX_HTML)
        self.assertIn('data-field="scope-pass"', INDEX_HTML)
        self.assertIn("renderScope(fragment, run)", APP_JS)
        # renderScope is called unconditionally from renderDetail, not from a
        # branch that a passing run could skip.
        detail = APP_JS.split("function renderDetail()", 1)[1]
        for line in detail.splitlines():
            if "renderScope(" in line:
                self.assertEqual(line.strip(), "renderScope(fragment, run);")
                break
        else:  # pragma: no cover - failure path
            self.fail("renderScope is never called from renderDetail")

    def test_the_ui_fallback_strings_match_core_exactly(self) -> None:
        """A v1 run carries no interpretation; the fallback must be the real text."""
        self.assertEqual(_js_constant("DECLARATION_SCOPE"), core.DECLARATION_SCOPE)
        self.assertEqual(_js_constant("PASS_SCOPE"), core.PASS_SCOPE)

    def test_the_ui_does_not_paint_a_refusal_as_vulnerable(self) -> None:
        """`unexpected_denial` is its own metric, not folded into Vulnerable."""
        self.assertIn("summary.unexpected_denial", APP_JS)
        self.assertIn('metric("Unexpected denial"', APP_JS)

    def test_the_ui_does_not_call_a_matched_probe_safe(self) -> None:
        """`safe` is a security claim; coverage.BANNED_CLAIM_WORDS rules it out."""
        self.assertIn('metric("Matched", summary.safe', APP_JS)
        self.assertNotIn('metric("Safe"', APP_JS)


class EscalationVisibilityTest(unittest.TestCase):
    """`summary.escalated` is computed and printed but had no viewer at all."""

    def test_escalation_has_a_metric(self) -> None:
        self.assertIn('metric(\n      "Escalated",', APP_JS)
        self.assertIn("summary.escalated", APP_JS)

    def test_escalation_has_a_regression_tab(self) -> None:
        self.assertIn('data-tab="escalated"', INDEX_HTML)

    def test_a_v1_run_without_the_key_still_renders(self) -> None:
        """v1 documents predate `escalated` and must not throw in the viewer."""
        self.assertIn("run.regression[tab] || []", APP_JS)
        self.assertIn("run.regression[state.activeDiff] || []", APP_JS)


class GateRenderingTest(unittest.TestCase):
    """A run CI failed is never painted as one CI passed.

    `status` is computed from findings alone, so a run the gate failed with
    exit 3 for unproven liveness, an unclean teardown or a non-asserting
    expectation stays `passed`. The viewer coloured its badge and its list dot
    from `status` alone and never read the `gate` object, so that run showed
    the same green PASSED badge as a run that exited 0 -- the mirror image of
    the red FAILED badge over a green build fixed before.
    """

    def _function(self, name: str) -> str:
        self.assertIn(f"function {name}(", APP_JS)
        return APP_JS.split(f"function {name}(", 1)[1].split("\nfunction ", 1)[0]

    def test_the_badge_tone_reads_the_gate(self) -> None:
        detail = self._function("renderDetail")
        self.assertIn("run.gate", detail)
        self.assertNotIn("STATUS_TONE[run.status]", detail)
        self.assertIn("runTone(run.status", detail)
        tone = self._function("runTone")
        # Green only when the gate did not fail the run.
        self.assertIn('"safe"', tone)
        self.assertIn("!== 0", tone)

    def test_the_gate_s_reasons_are_said_on_the_run(self) -> None:
        detail = self._function("renderDetail")
        self.assertIn("gate.reasons", detail)
        self.assertIn("is not a finding", detail)

    def test_the_list_dot_reads_the_gate_too(self) -> None:
        self.assertNotIn("STATUS_TONE[entry.status]", APP_JS)
        self.assertIn("runTone(entry.status, entry.gate_exit_code)", APP_JS)


class PassDisclosureRenderingTest(unittest.TestCase):
    """A passing check emits no finding, so its caveats need their own channel."""

    def test_both_disclosure_blocks_are_rendered(self) -> None:
        self.assertIn("non_asserting_expectations", APP_JS)
        self.assertIn("oracle_disclosures", APP_JS)
        self.assertIn('data-field="disclosures"', INDEX_HTML)

    def test_the_injection_disclosures_are_rendered_by_their_label(self) -> None:
        """``injection_disclosures`` is the third pass disclosure. It reached the
        console only, though its own docstring said the UI showed it. Read from
        the renderer's group list, not anywhere in the file, and labelled by
        ``where``: a sequence step, teardown or marker-probe entry has no
        ``check_id``, so labelling it by one would print 'undefined'."""
        body = APP_JS.split("function disclosureList(run)", 1)[1].split("\nfunction ", 1)[0]
        groups = body.split("const groups = [", 1)[1].split("];", 1)[0]
        self.assertIn('"injection_disclosures"', groups)
        self.assertIn("entry.where", body)

    def test_the_disclosure_block_has_styling_so_it_is_not_invisible(self) -> None:
        self.assertIn(".disclosure-list", STYLES)
        self.assertIn(".scope p", STYLES)


class UiVocabularyTest(unittest.TestCase):
    def test_no_ui_string_asserts_a_boundary_was_crossed(self) -> None:
        overclaims = (
            "crossed the boundary",
            "is vulnerable",
            "unauthorized access",
            "disclosed",
            "proven secure",
        )
        blob = f"{APP_JS}\n{INDEX_HTML}".lower()
        for phrase in overclaims:
            self.assertNotIn(phrase, blob, phrase)


class PresentationContractTest(unittest.TestCase):
    """Properties that make this a product surface rather than a debug view.

    None of these are cosmetic preferences. A viewer that only works in dark
    mode, cannot be operated from the keyboard, or leaves a first-time user
    staring at an empty pane is one people stop opening -- and this project's
    whole thesis is that adoption is gated on friction, not capability.
    """

    def test_the_stylesheet_defines_both_themes(self) -> None:
        self.assertIn("prefers-color-scheme: dark", STYLES)
        self.assertIn(':root[data-theme="light"]', STYLES)
        self.assertIn(':root[data-theme="dark"]', STYLES)
        self.assertIn("color-scheme: light dark", STYLES)

    def test_the_theme_survives_a_reload_without_a_flash(self) -> None:
        """The anti-flash snippet cannot be inline: the CSP forbids that.

        It therefore has to be its own same-origin file, loaded synchronously
        in <head> BEFORE the deferred application script. If it ever became
        deferred, every reload would repaint.
        """
        self.assertIn('<script src="/theme.js"></script>', INDEX_HTML)
        theme_js = (WEB / "theme.js").read_text(encoding="utf-8")
        self.assertIn("veridor-theme", theme_js)
        self.assertIn("localStorage", APP_JS)
        head = INDEX_HTML.split("</head>", 1)[0]
        self.assertIn("theme.js", head)
        self.assertNotIn('src="/theme.js" defer', INDEX_HTML)

    def test_the_viewer_is_operable_from_the_keyboard(self) -> None:
        self.assertIn(":focus-visible", STYLES)
        self.assertIn("skip-link", STYLES)
        self.assertIn('class="skip-link"', INDEX_HTML)

    def test_motion_is_optional(self) -> None:
        self.assertIn("prefers-reduced-motion: reduce", STYLES)

    def test_every_asset_is_same_origin(self) -> None:
        """A CDN reference would simply fail under `default-src 'self'`.

        Checked here rather than discovered in a browser: the failure mode is a
        page that loads with no styling at all, and the CSP that causes it is
        the same one that makes the viewer safe to point at local artifacts.
        """
        blob = f"{APP_JS}\n{INDEX_HTML}\n{STYLES}"
        for scheme in ("http://", "https://", "//cdn", "@import url("):
            with self.subTest(scheme=scheme):
                self.assertNotIn(scheme, blob)

    def test_an_empty_state_names_the_command_that_fills_it(self) -> None:
        """"Select a run" helps nobody who has no runs."""
        for verb in ("veridor map --config", "veridor run --config", "veridor mutate --config"):
            with self.subTest(verb=verb):
                self.assertIn(verb, APP_JS)
        self.assertIn("placeholder-hint", STYLES)

    def test_the_error_state_says_where_the_viewer_was_looking(self) -> None:
        self.assertIn("veridor serve --output-dir", APP_JS)

    def test_the_footer_states_the_posture_on_every_view(self) -> None:
        """Local, read-only, and scoped to YOUR declaration -- said once, always.

        The README says it, but a viewer that a colleague was shown over a
        shoulder has no README attached to it.
        """
        footer = INDEX_HTML.split('class="app-footer"', 1)[1].split("</footer>", 1)[0]
        self.assertIn("never writes", footer)
        self.assertIn("issues no request", footer)
        self.assertIn("your", footer.lower())

    def test_the_layout_survives_a_narrow_viewport(self) -> None:
        self.assertIn("@media (max-width: 900px)", STYLES)
        self.assertIn("width=device-width", INDEX_HTML)

    def test_numbers_do_not_reflow_their_cards(self) -> None:
        """Tabular figures: a metric that changes width as it counts looks broken."""
        self.assertIn("font-variant-numeric: tabular-nums", STYLES)

    def test_every_served_asset_is_actually_packaged(self) -> None:
        """A glob in pyproject that misses a file is a 404 in a wheel.

        Adding ``favicon.svg`` to the server without adding ``web/*.svg`` to
        package-data produced exactly that: the repo checkout worked, the
        installed package did not. The failure only shows up in a container or
        after `pip install .`, which is the worst place to find it, so the
        server's own asset table is checked against the manifest here.
        """
        import fnmatch  # noqa: PLC0415 - local, only this test globs

        from veridor import server  # noqa: PLC0415 - local, reads its table

        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        section = pyproject.split("[tool.setuptools.package-data]", 1)[1]
        patterns = re.findall(r'"(web/[^"]+)"', section)
        self.assertTrue(patterns, "no package-data patterns found")

        for filename, _ in server._ASSETS.values():
            with self.subTest(asset=filename):
                self.assertTrue(
                    (WEB / filename).is_file(), f"{filename} is served but absent"
                )
                self.assertTrue(
                    any(fnmatch.fnmatch(f"web/{filename}", p) for p in patterns),
                    f"web/{filename} is served but no package-data glob ships it",
                )

    def test_the_verb_bar_is_centred_with_equal_segments(self) -> None:
        """Three peers means three equal tracks on the header's true centre.

        As a flex row the bar sat against the wordmark and drifted further left
        the wider the window got, and the segments took their width from how
        long each question happened to be -- which made them look ranked.
        """
        header = STYLES.split("header {", 1)[1].split("}", 1)[0]
        self.assertIn("grid-template-columns: 1fr auto 1fr", header)
        verbs = STYLES.split(".verbs {", 1)[1].split("}", 1)[0]
        self.assertIn("repeat(3, minmax(0, 1fr))", verbs)

    def test_only_the_history_list_scrolls(self) -> None:
        """A filter box that scrolls away is useless when the list is long."""
        self.assertIn('class="sidebar-scroll"', INDEX_HTML)
        aside = STYLES.split("\naside {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow: hidden", aside)
        scroll = STYLES.split(".sidebar-scroll {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow-y: auto", scroll)
        self.assertIn("min-height: 0", scroll)
        # The filter and heading must sit OUTSIDE the scrolling region.
        head, _, tail = INDEX_HTML.partition('<div class="sidebar-scroll">')
        self.assertIn('id="filter"', head)
        self.assertIn('id="list-heading"', head)
        self.assertIn('id="runs"', tail)

    def test_the_content_column_is_centred_in_its_track(self) -> None:
        """Capped and left-anchored it read as content that had run out."""
        detail = STYLES.split("#run-detail {", 1)[1].split("}", 1)[0]
        self.assertIn("margin-inline: auto", detail)
        self.assertIn("max-width:", detail)

    def test_the_verdict_sits_beside_the_thing_it_judges(self) -> None:
        """Pinned right of a 1100px column it was half a screen from its subject."""
        self.assertIn('class="title-row"', INDEX_HTML)
        for field in ('data-field="run-status"', 'data-field="map-status"'):
            with self.subTest(field=field):
                row = INDEX_HTML.split('<div class="title-row">')
                self.assertTrue(
                    any(field in chunk.split("</div>", 1)[0] for chunk in row[1:]),
                    f"{field} is not inside a title-row",
                )

    def test_the_history_can_be_filtered(self) -> None:
        """Fine at two entries, unusable at two hundred -- which is a week of CI."""
        self.assertIn('id="filter"', INDEX_HTML)
        self.assertIn("matchesFilter", APP_JS)
        # An empty history and an over-narrow filter are different problems
        # with different fixes, so they must not share a message.
        self.assertIn('id="no-matches"', INDEX_HTML)
        self.assertIn("Nothing matches that filter", INDEX_HTML)
        # Switching verbs clears it: a filter typed against runs means nothing
        # against maps, and carrying it over would look like an empty history.
        self.assertIn('filterElement.value = ""', APP_JS)

    def test_a_headline_number_is_not_a_chip(self) -> None:
        """The mutation score is what the whole view exists to report."""
        self.assertIn("hero-value", APP_JS)
        self.assertIn(".hero-value", STYLES)
        self.assertIn("mutation score", APP_JS)

    def test_a_proportion_is_drawn_as_well_as_stated(self) -> None:
        """Reach is a proportion and was available only as prose.

        The unmeasured slice is drawn in its own tone deliberately: a short
        reached bar must not read as "this identity reaches little" when most
        cells were never probed.
        """
        self.assertIn("proportionBar", APP_JS)
        # The class names are built as `bar-${kind}`, so assert on the kinds the
        # renderer actually iterates rather than on a literal that never appears.
        body = APP_JS.split("function proportionBar(", 1)[1].split("\n}\n", 1)[0]
        for kind in ("reached", "refused", "unmeasured"):
            with self.subTest(kind=kind):
                self.assertIn(f'"{kind}"', body)
        self.assertIn(".bar-unmeasured", STYLES)
        # Three colours with no key are decoration.
        self.assertIn("key-reached", STYLES)
        self.assertIn("aria-label", APP_JS)

    def test_the_claim_text_is_never_rewritten_to_fit_the_layout(self) -> None:
        """splitLead may only cut on a sentence boundary, never edit.

        The claim paragraphs are the product's credibility. A viewer that
        trimmed, summarised or reordered them to look tidier would be lying, so
        the split is a slice and the two halves must reconstitute the original.
        """
        body = APP_JS.split("function splitLead(", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("slice(", body)
        for mutating in (".replace(", ".substring(0", "truncat", "…", "..."):
            with self.subTest(call=mutating):
                self.assertNotIn(mutating, body)

    def test_every_view_links_to_the_document_it_rendered(self) -> None:
        """A security tool that hides its own JSON is asking for unearned trust."""
        self.assertIn("rawLink(", APP_JS)
        self.assertIn("/api/runs/", APP_JS)
        self.assertIn("/api/maps/", APP_JS)
        self.assertIn("/api/mutations/", APP_JS)
        self.assertIn('rel = "noopener"', APP_JS)

    def test_prose_has_a_readable_measure(self) -> None:
        """The claim paragraphs are the most important text in the product.

        Set full-bleed across a wide column they were accurate and unread,
        which is its own kind of failure for text whose entire job is to stop a
        reader overclaiming.
        """
        self.assertIn("--measure:", STYLES)
        self.assertIn("max-width: var(--measure)", STYLES)


class VerbShapeTest(unittest.TestCase):
    """The viewer shows three verbs, because the product is three verbs.

    ``map`` and ``mutate`` were wired to the CLI and then had no viewer at all,
    so the only way to read a blast radius or a surviving mutant was to open the
    JSON by hand. Each verb keeps its own view because each makes a DIFFERENT
    claim, and a shared one would invite a reader to carry a hypothesis across
    into a finding.
    """

    def test_all_three_verbs_are_reachable(self) -> None:
        for verb in ("map", "run", "mutate"):
            with self.subTest(verb=verb):
                self.assertIn(f'data-verb="{verb}"', INDEX_HTML)
        self.assertIn("#map-template", APP_JS)
        self.assertIn("#mutate-template", APP_JS)

    def test_each_verb_has_its_own_endpoint(self) -> None:
        """A run endpoint must never be able to return a map."""
        self.assertIn("/api/maps", APP_JS)
        self.assertIn("/api/mutations", APP_JS)
        self.assertIn("/api/runs", APP_JS)


class MapClaimTest(unittest.TestCase):
    """`map` observes and proposes. It never concludes."""

    def test_candidates_are_labelled_hypotheses_not_findings(self) -> None:
        self.assertIn("HYPOTHESES, NOT FINDINGS", INDEX_HTML)
        self.assertIn("hypothes", APP_JS)

    def test_the_document_s_own_discipline_sentence_is_rendered(self) -> None:
        """`discipline` is a STRING in the document, not an object.

        Reading it as ``discipline.statement`` silently yielded undefined and
        fell through to the UI's paraphrase, so the canonical sentence sat
        unused in the JSON while the viewer showed something else. That is the
        drift the fallbacks exist to prevent, so the key name is pinned.
        """
        self.assertIn("candidates.discipline || CANDIDATE_DISCIPLINE", APP_JS)
        self.assertNotIn("candidates.discipline.statement", APP_JS)

    def test_the_blast_radius_headline_is_rendered_verbatim(self) -> None:
        """The document says "at least N of M"; a paraphrase would drop it."""
        self.assertIn("entry.headline", APP_JS)

    def test_the_operation_level_limitation_is_shown(self) -> None:
        """Blast radius counts operations reached, never objects."""
        self.assertIn("operations, not objects", INDEX_HTML)
        self.assertIn('data-field="map-limitation"', INDEX_HTML)
        self.assertIn("blast.limitation", APP_JS)

    def test_an_empty_candidate_list_is_not_a_clean_bill_of_health(self) -> None:
        self.assertIn("Consistency is not authorization", APP_JS)

    def test_an_incomplete_map_says_so_above_its_counts(self) -> None:
        """A quorum rule that never ran produces zero candidates either way."""
        self.assertIn("safety.aborted", APP_JS)
        self.assertIn("INCOMPLETE", APP_JS)
        self.assertIn(".warn-note", STYLES)

    def test_a_missing_document_is_distinguished_from_an_empty_one(self) -> None:
        self.assertIn("map.missing", APP_JS)
        self.assertIn("An absent document is not the same as an empty one", APP_JS)

    def test_the_rules_declared_failure_modes_are_shown(self) -> None:
        """How an operator decides whether to believe a candidate at all."""
        self.assertIn("false_positive_modes", APP_JS)
        self.assertIn(".fp-modes", STYLES)


class DriftClaimTest(unittest.TestCase):
    """Drift is a difference between two RUNS. It is not a verdict on either.

    It sits inside the map view rather than in a tab of its own, because a
    fourth tab would sell it as a fourth verb when it is what a map MEANS read
    against an earlier one. That makes the claim separation load-bearing: the
    reader meets it directly under the candidate list, and the two say
    different things about different evidence.
    """

    def test_drift_lives_inside_the_map_view(self) -> None:
        map_template = INDEX_HTML.split('id="map-template"', 1)[1].split(
            "</template>", 1
        )[0]
        self.assertIn('data-field="drift-panel"', map_template)
        self.assertNotIn('data-tab="drift"', INDEX_HTML)

    def test_the_heading_says_it_is_not_a_verdict(self) -> None:
        self.assertIn("A DIFFERENCE BETWEEN TWO RUNS, NOT A VERDICT", INDEX_HTML)

    def test_the_panel_is_hidden_when_no_baseline_was_given(self) -> None:
        """Rendering "0 changes" with no baseline answers a question nobody
        asked, and reads as a measurement that was never taken."""
        self.assertIn("if (!drift) return;", APP_JS)
        self.assertIn('data-field="drift-panel" hidden', INDEX_HTML)

    def test_an_empty_diff_is_not_a_clean_bill_of_health(self) -> None:
        self.assertIn("not a clean bill of health", APP_JS)

    def test_the_blindness_is_rendered_beside_the_changes(self) -> None:
        """A diff can only speak about what changed, and the panel has to say
        so where the reader is looking rather than in a document elsewhere."""
        self.assertIn("claim.blind_to", APP_JS)
        self.assertIn("DRIFT_BLINDNESS", APP_JS)
        self.assertIn('data-field="drift-blindness"', INDEX_HTML)

    def test_the_documents_own_claim_wins_over_the_fallback(self) -> None:
        """Same failure as `candidates.discipline`: reading the wrong key
        silently showed the viewer's paraphrase while the canonical sentence
        sat unused in the JSON."""
        self.assertIn("claim.does_not_measure", APP_JS)
        self.assertIn("DRIFT_DISCIPLINE", APP_JS)

    def test_a_diff_across_two_targets_is_called_out(self) -> None:
        """It compares deployments, not changes -- the most misleading thing
        this panel could render silently."""
        self.assertIn("DIFFERENT targets", APP_JS)
        self.assertIn("compares deployments, not changes", APP_JS)

    def test_a_significant_change_is_amber_and_never_red(self) -> None:
        """Amber is this viewer's word for "you cannot conclude anything yet".
        Red is reserved for a measured departure from a DECLARATION, and drift
        has no declaration to depart from."""
        self.assertIn(".finding.drift-significant", STYLES)
        block = STYLES.split(".finding.drift-significant", 1)[1].split("}", 1)[0]
        self.assertIn("var(--warn)", block)
        self.assertNotIn("var(--alert)", block)

    def test_the_list_distinguishes_not_compared_from_no_change(self) -> None:
        self.assertIn("entry.drift", APP_JS)
        # Built as `change${n === 1 ? "" : "s"} vs baseline`, so the suffix is
        # what to pin -- the full phrase never appears as a literal.
        self.assertIn("vs baseline", APP_JS)
        self.assertIn("more access", APP_JS)

    def _render_drift(self) -> str:
        return APP_JS.split("function renderDrift(", 1)[1].split("\nfunction ", 1)[0]

    def test_a_void_comparison_is_not_called_nothing_moved(self) -> None:
        """drift.render withholds "Nothing moved" when no cell was compared or
        none was measured in both runs, and says "Nothing to compare" instead;
        a gate over that exits 3. The viewer chose its sentence from an empty
        `changes` list alone, so re-seeded specimens hiding a 200 with the
        victim's marker rendered exactly like a quiet run (measured 2026-10-14
        by running renderDrift in node on both documents)."""
        body = self._render_drift()
        for field in ("comparable_cells", "incomparable_cells", "measured_in_both_cells"):
            with self.subTest(field=field):
                self.assertIn(field, body)
        self.assertIn("Nothing to compare", body)
        # The withheld branch is tested first, so "Nothing moved" is its else.
        self.assertLess(body.index("Nothing to compare"), body.index("Nothing moved"))

    def test_the_baseline_s_blindness_is_said_above_the_counts(self) -> None:
        """README: a drift report against a blind baseline "says so above its
        own counts, in those words". The viewer never read blind_cells or
        redirect_cells, so it did not."""
        body = self._render_drift()
        for field in ("blind_cells", "blind_cells_not_probed", "redirect_cells"):
            with self.subTest(field=field):
                self.assertIn(field, body)
        self.assertIn("THE BASELINE NEVER MEASURED", body)
        self.assertIn("NOT ONE CELL WAS MEASURED IN BOTH RUNS", body)
        # Above the changes: the warnings go into drift-targets, which the
        # template places before drift-changes.
        self.assertLess(INDEX_HTML.index('data-field="drift-targets"'),
                        INDEX_HTML.index('data-field="drift-changes"'))
        self.assertLess(body.index("THE BASELINE NEVER MEASURED"),
                        body.index('[data-field="drift-changes"]'))

    def test_drift_never_uses_finding_vocabulary(self) -> None:
        drift_code = APP_JS.split("function renderDrift(", 1)[1].split(
            "\nfunction ", 1
        )[0]
        for word in ("vulnerab", "exploit", "insecure", "proven", "breach"):
            with self.subTest(word=word):
                self.assertNotIn(word, drift_code.lower())


#: Runs app.js's element() and renderDrift() under node on a stub DOM, once per
#: drift document in argv[2], and prints what landed in drift-targets (the
#: warnings above the changes) and in drift-changes.
_DRIFT_PANEL_HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const src = fs.readFileSync(process.argv[1], "utf8");
const grab = (name) => {
  const start = src.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`app.js has no function ${name}`);
  const end = src.indexOf("\nfunction ", start + 1);
  return src.slice(start, end < 0 ? undefined : end);
};
const code = grab("element") + "\n" + grab("renderDrift");
const text = (n) => [n.textContent, ...n.children.map(text)].filter(Boolean).join(" ");
const out = JSON.parse(process.argv[2]).map((doc) => {
  const node = () => ({ children: [], textContent: "", hidden: true, className: "",
                        append(...c) { this.children.push(...c); } });
  const fields = {};
  const fragment = { querySelector(selector) {
    const name = /data-field="([^"]+)"/.exec(selector)[1];
    return (fields[name] ||= node());
  } };
  const context = { document: { createElement: node }, DRIFT_DISCIPLINE: "",
                    DRIFT_BLINDNESS: "", driftCard: node, fragment, doc };
  vm.createContext(context);
  vm.runInContext(code + "\nrenderDrift(fragment, doc);", context);
  return { targets: (fields["drift-targets"] || node()).children.map(text),
           changes: text(fields["drift-changes"] || node()) };
});
console.log(JSON.stringify(out));
"""


@slow("runs app.js under node in a subprocess")
class DriftPanelCoverageTest(unittest.TestCase):
    """The drift panel says how much of the grid it saw, as drift.render does.

    This class does execute JavaScript, unlike the rest of this file: the
    claim is about what renderDrift shows for a document, and the source-text
    checks above pass on a renderer whose arithmetic is wrong. It needs node,
    so it is in the slow tier, and is skipped without node except under CI,
    where it fails instead.

    renderDrift printed neither drift.render's partial-coverage line ("drift
    saw N% of the grid ... A quiet report below is quiet about the rest") nor
    its could-not-be-measured warning. On {changes: [], comparable_cells: 6,
    measured_in_both_cells: 3, unmeasured_cells: 3} the panel had no warning
    and said "Nothing moved. Every comparable cell reads the same as the
    baseline", while drift.render said it saw 50% and that 3 of 6 cells could
    not be measured (measured 2026-10-14 in node on a stub DOM).
    """

    @staticmethod
    def _document(comparable: int, **counts: int) -> dict:
        return {
            "changes": [], "significant": 0, "counts": {},
            "comparable_cells": comparable,
            "baseline": {"cells": comparable, "target": "https://t.example"},
            "current": {"cells": comparable, "target": "https://t.example"},
            **counts,
        }

    def _panels(self, documents: list[dict]) -> list[dict]:
        node = shutil.which("node")
        if node is None:
            if os.environ.get("CI"):
                self.fail("node is not installed; this check cannot run")
            self.skipTest("node is not installed")
        result = subprocess.run(
            [node, "-e", _DRIFT_PANEL_HARNESS, str(WEB / "app.js"), json.dumps(documents)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_the_panel_states_the_coverage_drift_render_states(self) -> None:
        from veridor import drift

        documents = [
            # Half the grid lost.
            self._document(6, measured_in_both_cells=3, unmeasured_cells=3),
            # An older report with no measured_in_both_cells; 4 in 1,000 lost
            # is 99%, never a rounded-up 100.
            self._document(1000, unmeasured_cells=4),
            # Some lost, some never probed by the plan's rules.
            self._document(10, measured_in_both_cells=6, unmeasured_cells=4,
                           unmeasured_cells_not_probed=3),
            # Redirects are unseen but are not "could not be measured".
            self._document(8, measured_in_both_cells=6, redirect_cells=2),
            # Control: every cell measured in both; no coverage line at all.
            self._document(6, measured_in_both_cells=6),
        ]
        lines = {
            "share": (r"drift saw (\d+)% of the grid: (\d+) of (\d+) comparable",
                      "drift saw {}% of the grid: {} of {} comparable"),
            "lost": (r"!! (\d+) of (\d+) comparable cell\(s\) could not be measured",
                     "{} of {} comparable cell(s) could not be measured"),
            "further": (r"!! (\d+) further comparable cell\(s\) were never probed",
                        "{} further comparable cell(s) were never probed"),
        }
        printed = {name: 0 for name in lines}
        for document, panel in zip(documents, self._panels(documents)):
            rendered = drift.render(document)
            notes = " ".join(panel["targets"])
            for name, (pattern, phrase) in lines.items():
                with self.subTest(document=document, line=name):
                    match = re.search(pattern, rendered)
                    if match:
                        printed[name] += 1
                        self.assertIn(phrase.format(*match.groups()), notes)
                    else:
                        self.assertNotRegex(notes, pattern.replace("!! ", ""))
            with self.subTest(document=document, line="nothing moved"):
                self.assertEqual("Nothing moved" in panel["changes"],
                                 "Nothing moved" in rendered)
        # Control: each line fired on some document, so no assertion above
        # passed for want of a line to compare.
        self.assertTrue(all(printed.values()), printed)


class MutateClaimTest(unittest.TestCase):
    """The score is a property of the DECLARATION, never of the target."""

    def test_the_report_s_own_statement_is_rendered(self) -> None:
        """The mutation report names this key `statement`, not `summary`.

        Run documents use ``summary``; assuming the two matched meant the
        report's own wording was never rendered and the UI's fallback stood in
        for it silently.
        """
        self.assertIn("interpretation.statement || MUTANT_DISCIPLINE", APP_JS)
        self.assertNotIn("interpretation.summary || MUTANT_DISCIPLINE", APP_JS)

    def test_the_relationship_between_the_two_scores_is_rendered(self) -> None:
        """Coverage and mutation score are different claims; both are shown."""
        self.assertIn("interpretation.relationship", APP_JS)
        self.assertIn('data-field="mutate-relationship"', INDEX_HTML)

    def test_a_survivor_is_framed_as_possible_vacuity(self) -> None:
        self.assertIn("CHECKS THAT MAY BE VACUOUS", INDEX_HTML)
        self.assertIn("MAY BE VACUOUS", APP_JS)
        self.assertIn("survivor.diagnosis", APP_JS)

    def test_a_perfect_score_is_not_reported_as_enforcement(self) -> None:
        self.assertIn("not about", APP_JS)
        self.assertIn("whether the boundary is enforced", APP_JS)

    def _function(self, name: str) -> str:
        self.assertIn(f"function {name}(", APP_JS)
        return APP_JS.split(f"function {name}(", 1)[1].split("\nfunction ", 1)[0]

    def test_green_and_the_all_clear_mean_mutation_exit_0(self) -> None:
        """mutation.exit_code is 0 only when mutants were generated and every one
        was killed: none survived, none aberrant, none errored. The hero and the
        list dot keyed on `survived` alone and the all-clear on an empty
        survivor list, so a report that generated nothing (exit 2, score null)
        and one whose only unkilled mutants errored (exit 2) both got a green
        hero and "Every mutant was killed" -- the second directly above its own
        panel of errored mutants (measured 2026-10-14 in node)."""
        tone = self._function("mutationTone")
        for field in ("generated", "survived", "aberrant", "errored"):
            with self.subTest(field=field):
                self.assertIn(f"summary.{field}", tone)
        detail = self._function("renderMutateDetail")
        self.assertNotIn('summary.survived ? "warn" : "safe"', detail)
        self.assertNotIn('entry.survived ? "warn" : "safe"', APP_JS)
        self.assertIn("mutationTone(summary)", detail)
        self.assertIn("mutationTone(entry)", APP_JS)
        # The all-clear sits behind the same exit-0 test as the green hero.
        guard = detail.index("allKilled")
        self.assertLess(guard, detail.index("Every mutant was killed"))
        self.assertIn('const allKilled = mutationTone(summary) === "safe"', detail)

    def test_an_empty_mutant_set_says_nothing_was_measured(self) -> None:
        detail = self._function("renderMutateDetail")
        self.assertIn("No mutant was generated", detail)

    def test_no_survivor_string_calls_the_target_defective(self) -> None:
        """Mirrors mutation.BANNED_DIAGNOSIS_WORDS at the viewer.

        Scoped to the text a reader actually sees in the mutate view: the
        string literals in its two render functions, plus the mutate template's
        markup with comments stripped. Scanning the whole file instead swept in
        the *run* template -- which legitimately says "vulnerable", because a
        run verdict is allowed to -- and the map tab's "what would a compromise
        reach?". A ban that fires on a neighbouring view's correct vocabulary
        teaches people to delete the ban.
        """
        from veridor import mutation  # noqa: PLC0415 - local, mirrors the module

        visible: list[str] = []
        for name in ("renderMutateDetail", "survivorCard"):
            body = APP_JS.split(f"function {name}(", 1)[1].split("\n}\n", 1)[0]
            code = re.sub(r"//[^\n]*", "", body)
            visible.extend(json.loads(part) for part in re.findall(r'"(?:[^"\\]|\\.)*"', code))
        template = INDEX_HTML.split('<template id="mutate-template">', 1)[1].split(
            "</template>", 1
        )[0]
        visible.append(re.sub(r"<!--.*?-->", "", template, flags=re.DOTALL))

        blob = " ".join(visible).lower()
        self.assertIn("vacuous", blob, "the mutate view lost its own framing")
        for word in mutation.BANNED_DIAGNOSIS_WORDS:
            with self.subTest(word=word):
                self.assertNotIn(word.lower(), blob)

    def test_a_survivor_is_not_painted_as_a_measured_difference(self) -> None:
        """Amber, not red: "cannot conclude" is not the same as "differed"."""
        self.assertIn(".finding.survivor", STYLES)
        self.assertIn(".finding.candidate", STYLES)
        self.assertIn("--warn", STYLES)

    def test_no_survivor_is_listed_twice(self) -> None:
        """``unresolved`` is survivors PLUS errored, so it cannot be dumped raw.

        The viewer listed `survivors` in one panel and `unresolved` in the next,
        which re-printed every survivor verbatim -- on the demo report that
        showed two vacuous checks as four entries. A reader counting problems
        would have counted double, which is the overclaiming this product is
        built to avoid, arriving through arithmetic instead of vocabulary.
        """
        self.assertIn("survivorIds", APP_JS)
        self.assertIn("!survivorIds.has(item.id)", APP_JS)
        # The remainder is errored mutants, and the panel must say so rather
        # than calling them survivors -- nothing about them was measured.
        self.assertIn("Errored mutants", INDEX_HTML)
        self.assertIn("NOTHING WAS MEASURED", INDEX_HTML)

    def test_the_relationship_is_not_printed_twice(self) -> None:
        """``interpretation.statement`` already ends with the relationship.

        Rendering both put the coverage-versus-mutation-score paragraph on the
        page twice in a row. The paragraph exists to keep two claims distinct;
        printing it twice makes the whole block read as generated rather than
        written, which costs the reader's trust in exactly the text that most
        needs it.
        """
        self.assertIn("statement.includes(relationship)", APP_JS)


class MutationReportShapeTest(unittest.TestCase):
    """The viewer's assumptions about the report, checked against the engine.

    These are the assumptions that produced two live defects: that `unresolved`
    and `survivors` were disjoint, and that `interpretation` used the same key
    names as a run document. Both were wrong, and neither was visible without
    rendering a real report -- so they are pinned here against the module that
    actually builds it.
    """

    @staticmethod
    def _mutation_source() -> str:
        from veridor import mutation  # noqa: PLC0415 - local, mirrors the module

        return Path(mutation.__file__).read_text(encoding="utf-8")

    def test_unresolved_is_a_superset_of_survivors(self) -> None:
        """If this ever became disjoint, the viewer's filter would be wrong."""
        self.assertIn('"unresolved": survivors', self._mutation_source())

    def test_the_interpretation_block_uses_statement_not_summary(self) -> None:
        """Run documents say `summary`; this one says `statement`.

        Assuming they matched meant the report's own wording never rendered and
        the viewer's fallback stood in for it silently. The keys are read out of
        the dict literal the engine actually builds, so renaming one breaks this
        rather than the page.
        """
        import ast  # noqa: PLC0415 - local, only this test parses source

        tree = ast.parse(self._mutation_source())
        keys: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "interpretation"
                    and isinstance(value, ast.Dict)
                ):
                    keys = {
                        inner.value
                        for inner in value.keys
                        if isinstance(inner, ast.Constant)
                    }
        self.assertTrue(keys, "no interpretation dict literal found")
        self.assertIn("statement", keys)
        self.assertIn("relationship", keys)
        self.assertNotIn("summary", keys)


# A harness for the functions below that do run under node. It lifts named
# functions out of app.js verbatim (sync or async), so the code under test is
# the shipped code, and stubs only the DOM and the network.
_APP_HARNESS_PRELUDE = r"""
const fs = require("fs"), vm = require("vm");
const src = fs.readFileSync(process.argv[1], "utf8");
const grab = (name) => {
  let start = src.indexOf(`\nasync function ${name}(`);
  if (start < 0) start = src.indexOf(`\nfunction ${name}(`);
  if (start < 0) throw new Error(`app.js has no function ${name}`);
  const end = src.indexOf("\n}\n", start);
  return src.slice(start, end + 3);
};
const grabConst = (name) => {
  const m = new RegExp(`\nconst ${name} = [^;]+;`).exec(src);
  if (!m) throw new Error(`app.js has no const ${name}`);
  return m[0];
};
const node = () => {
  const n = { children: [], textContent: "", className: "", hidden: true, title: "",
    attrs: {}, style: { setProperty() {} },
    classList: { add(c) { n.className += ` ${c}`; } },
    setAttribute(k, v) { n.attrs[k] = v; },
    append(...c) { for (const x of c) n.children.push(typeof x === "string" ? { textContent: x, children: [] } : x); } };
  return n;
};
const text = (n) => [n.textContent, ...(n.children || []).map(text)].filter(Boolean).join(" ");
"""

_ROUTE_HARNESS = _APP_HARNESS_PRELUDE + r"""
const code = ["routeFromHash", "writeHash", "applyRoute", "loadRuns", "selectRun",
              "selectMap", "selectMutation", "switchVerb", "boot"].map(grab).join("\n");
const lists = { runs: [{ run_id: "R-new" }, { run_id: "R-old" }],
                maps: [{ map_id: "M-new" }, { map_id: "M-old" }],
                mutations: [{ stem: "U-new" }] };
(async () => {
  const out = [];
  for (const hash of JSON.parse(process.argv[2])) {
    const location = { hash };
    const tabs = ["run", "map", "mutate"].map((verb) => ({ dataset: { verb }, attrs: {},
      setAttribute(k, v) { this.attrs[k] = v; } }));
    const heading = { textContent: "Run history" };
    const context = {
      headingElement: heading, noMatchesElement: {}, emptyElement: {}, detailElement: { replaceChildren() {} },
      placeholder: () => ({}),
      VERB_LABELS: { run: { heading: "Run history", empty: "" }, map: { heading: "Map history", empty: "" },
                     mutate: { heading: "Mutation history", empty: "" } },
      location, loadedAt: 0, Date, CSS: { escape: (x) => x },
      history: { replaceState(_s, _t, path) { location.hash = path; } },
      document: { querySelector: () => null, querySelectorAll: () => tabs },
      filterElement: { value: "" },
      state: { verb: "run", runs: [], maps: [], mutations: [], selected: null,
               activeDiff: "new", filter: "", pendingRoute: null },
      showSkeleton() {}, renderRuns() {}, renderDetail() {}, renderMapDetail() {},
      renderMutateDetail() {}, renderFreshness() {}, setConnection() {}, showError() {},
      async request(path) {
        const [, kind, id] = /^\/api\/(runs|maps|mutations)\/?(.*)$/.exec(path);
        if (!id) return { [kind]: lists[kind] };
        const key = { runs: "run_id", maps: "map_id", mutations: "stem" }[kind];
        const hit = lists[kind].find((e) => e[key] === decodeURIComponent(id));
        if (!hit) throw new Error("404 Not Found");
        return { ...hit };
      },
    };
    vm.createContext(context);
    vm.runInContext(code, context);
    await vm.runInContext("boot()", context);
    const sel = context.state.selected || {};
    const selectedTab = tabs.find((t) => t.attrs["aria-selected"] === "true");
    out.push({ shown: sel.run_id || sel.map_id || sel.stem || null, hash: location.hash,
               tab: selectedTab ? selectedTab.dataset.verb : "run", heading: heading.textContent });
  }
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
"""

_GATE_HARNESS = _APP_HARNESS_PRELUDE + r"""
const code = grabConst("STATUS_TONE") + grab("runTone") + grabConst("CAPSULE_EXIT") +
  grabConst("CAPSULE_TONE") + grab("capsuleStatus") + grab("element") + grab("gateBanner");
const context = { document: { createElement: node } };
vm.createContext(context);
vm.runInContext(code, context);
const out = JSON.parse(process.argv[2]).map((run) => {
  context.run = run;
  const b = vm.runInContext("gateBanner(run)", context);
  return b ? { tone: b.className.replace("gate-banner", "").trim(), text: text(b) } : null;
});
console.log(JSON.stringify(out));
"""

# The run list as renderRuns() builds it, with the server's /api/runs entries
# as input: each row's status dot (class and words) and its summary line, and
# the rows a filter keeps.
_RUN_LIST_HARNESS = _APP_HARNESS_PRELUDE + r"""
const code = grabConst("STATUS_TONE") + grab("runTone") + grabConst("CAPSULE_EXIT") +
  grabConst("CAPSULE_TONE") + grab("capsuleStatus") + grab("element") +
  ["listButton", "matchesFilter", "renderRuns", "formatDate", "targetLabel"].map(grab).join("\n");
const { entries, filter } = JSON.parse(process.argv[2])[0];
const runs = node();
runs.replaceChildren = () => { runs.children = []; };
const context = {
  document: { createElement: () => Object.assign(node(), { dataset: {}, addEventListener() {} }) },
  runsElement: runs, emptyElement: {}, noMatchesElement: {},
  state: { verb: "run", runs: entries, maps: [], mutations: [], selected: null, filter },
  selectRun() {}, Date, Intl,
};
const dots = (n, acc = []) => {
  if (/\bdot\b/.test(n.className || "")) acc.push({ cls: n.className.replace("dot", "").trim(), text: n.textContent });
  for (const c of n.children || []) dots(c, acc);
  return acc;
};
const summaries = (n, acc = []) => {
  if (/\brun-summary\b/.test(n.className || "")) acc.push(n.textContent);
  for (const c of n.children || []) summaries(c, acc);
  return acc;
};
vm.createContext(context);
vm.runInContext(code, context);
vm.runInContext("renderRuns()", context);
console.log(JSON.stringify([{ dots: dots(runs), summaries: summaries(runs) }]));
"""

_MATRIX_HARNESS = _APP_HARNESS_PRELUDE + r"""
const code = grab("element") + grab("accessMatrix");
const context = { document: { createElement: node, createTextNode: (t) => ({ textContent: t, children: [] }) } };
vm.createContext(context);
vm.runInContext(code, context);
const cellsOf = (n, acc = []) => {
  if (/\bmatrix-cell\b/.test(n.className || "")) acc.push({ cls: n.className, label: n.attrs["aria-label"], text: text(n) });
  for (const c of n.children || []) cellsOf(c, acc);
  return acc;
};
const legendOf = (n) => /matrix-legend/.test(n.className || "") ? text(n) : (n.children || []).map(legendOf).find(Boolean) || "";
const out = JSON.parse(process.argv[2]).map((matrix) => {
  context.matrix = matrix;
  const grid = vm.runInContext("accessMatrix(matrix)", context);
  return grid ? { cells: cellsOf(grid), legend: legendOf(grid) } : null;
});
console.log(JSON.stringify(out));
"""


def _run_node(harness: str, payload: list) -> list:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            raise AssertionError("node is not installed; this check cannot run")
        raise unittest.SkipTest("node is not installed")
    result = subprocess.run(
        [node, "-e", harness, str(WEB / "app.js"), json.dumps(payload)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


@slow("runs app.js under node in a subprocess")
class LinkOnLoadTest(unittest.TestCase):
    """A link to an older run, map or report opens that one, not the newest.

    Loading a list auto-selected its newest entry and selecting rewrote the
    hash, both before applyRoute() read it, so every shared link to anything
    but the newest run opened the newest instead (measured 2026-11-12 in the
    browser: #/run/<older passed run> showed the newest failed run, on the
    viewer as shipped and after its redesign).
    """

    def test_the_linked_entry_is_the_one_shown(self) -> None:
        shown = _run_node(_ROUTE_HARNESS, [
            "#/run/R-old", "#/map/M-old", "", "#/run/R-missing",
        ])
        run_view = {"tab": "run", "heading": "Run history"}
        self.assertEqual(shown[0], {"shown": "R-old", "hash": "#/run/R-old", **run_view})
        # A map link shows the map under the map tab and heading, not under
        # "run" (the state flipped while the screen did not).
        self.assertEqual(shown[1], {"shown": "M-old", "hash": "#/map/M-old",
                                    "tab": "map", "heading": "Map history"})
        # Control: no link still opens the newest run.
        self.assertEqual(shown[2], {"shown": "R-new", "hash": "#/run/R-new", **run_view})
        # A link to an entry that is not there falls back to the newest, and
        # the hash then names what is shown rather than what was asked for.
        self.assertEqual(shown[3], {"shown": "R-new", "hash": "#/run/R-new", **run_view})


@slow("runs app.js under node in a subprocess")
class GateBannerTest(unittest.TestCase):
    """The run view's banner says what the gate did, and only that."""

    @staticmethod
    def _run(status: str, exit_code, *, baseline=None, **summary) -> dict:
        base = {"probes": 6, "safe": 6, "vulnerable": 0, "confirmed": 0, "new": 0, "resolved": 0}
        base.update(summary)
        gate = {} if exit_code is None else {"exit_code": exit_code, "fail_on": "new+confirmed",
                                              "reasons": summary.pop("reasons", [])}
        return {"status": status, "gate": gate, "summary": base,
                "regression": {"baseline_run_id": baseline}}

    def test_the_banner_reads_the_gate_and_names_a_baseline_only_when_there_is_one(self) -> None:
        runs = [
            self._run("failed", 1, safe=5, vulnerable=1, confirmed=1, new=1),
            self._run("failed", 1, baseline="B", safe=5, vulnerable=1, confirmed=1, new=1),
            self._run("passed", 0, baseline="B", resolved=1),
            self._run("passed", 2),
            self._run("passed", None),
        ]
        runs[3]["gate"]["reasons"] = [{"code": "liveness_unproven"}]
        out = _run_node(_GATE_HARNESS, runs)
        no_baseline, with_baseline, fixed, gate_only, old_schema = out

        self.assertEqual(no_baseline["tone"], "danger")
        self.assertIn("Gate fails", no_baseline["text"])
        self.assertIn("exit 1", no_baseline["text"])
        self.assertIn("1 confirmed by marker", no_baseline["text"])
        # Without a baseline every finding is "new"; saying "since the
        # baseline" would claim a comparison that never ran.
        self.assertNotIn("baseline", no_baseline["text"])
        self.assertIn("1 new since the baseline", with_baseline["text"])

        self.assertEqual(fixed["tone"], "safe")
        self.assertIn("Gate passes", fixed["text"])
        self.assertIn("1 resolved since the baseline", fixed["text"])

        # A run with no finding that the gate still failed is amber, never green.
        self.assertEqual(gate_only["tone"], "warn")
        self.assertIn("Gate fails", gate_only["text"])
        self.assertIn("failed for: liveness_unproven", gate_only["text"])

        # A document without a gate gets no banner, not a guessed one.
        self.assertIsNone(old_schema)


@slow("runs app.js under node in a subprocess")
class CapsuleVerificationViewTest(unittest.TestCase):
    """A capsule verification is shown as one, with its verdict.

    `veridor verify` exits with the capsule's verdict -- 1 CONFIRMED, 0
    NOT_REPRODUCED, 2 INCONCLUSIVE -- and its run was listed as an ordinary run
    whose status is computed from findings: an INCONCLUSIVE verification (a
    probe that drew a 500) read FAILED in red, and its banner said "Gate
    fails" with no word of the capsule. A run document without `capsule`
    renders as before.
    """

    @staticmethod
    def _run(status: str, verdict, exit_code: int, reason: str = "the reason") -> dict:
        run = {"status": status, "summary": {"probes": 3, "safe": 2, "vulnerable": 0},
               "regression": {"baseline_run_id": None},
               "gate": {"exit_code": exit_code, "fail_on": None, "reasons": []}}
        if verdict is not None:
            run["capsule"] = {"verdict": verdict, "exit_code": exit_code, "reason": reason,
                              "check_id": "invoice-tenant-isolation"}
        return run

    def test_the_banner_is_headed_by_the_verdict(self) -> None:
        runs = [
            self._run("inconclusive", "INCONCLUSIVE", 2, "Identity 'x' received HTTP 500."),
            self._run("failed", "CONFIRMED", 1),
            self._run("passed", "NOT_REPRODUCED", 0,
                      "the declared expectation held on this target. That is not proof"),
            # Hand-edited: a verdict whose exit code is not the gate's.
            self._run("passed", "NOT_REPRODUCED", 2),
            self._run("passed", "LOOKS_FINE", 0),
            # Control: an ordinary run that failed, no capsule.
            self._run("failed", None, 1),
        ]
        runs[-1]["gate"]["fail_on"] = "new+confirmed"
        inconclusive, confirmed, not_reproduced, disagreeing, unknown, ordinary = (
            _run_node(_GATE_HARNESS, runs))

        self.assertEqual(inconclusive["tone"], "warn")
        self.assertIn("Capsule INCONCLUSIVE", inconclusive["text"])
        self.assertIn("exit 2", inconclusive["text"])
        self.assertIn("HTTP 500", inconclusive["text"])
        self.assertIn("invoice-tenant-isolation", inconclusive["text"])
        self.assertNotIn("Gate", inconclusive["text"])

        self.assertEqual(confirmed["tone"], "danger")
        self.assertIn("Capsule CONFIRMED", confirmed["text"])

        self.assertEqual(not_reproduced["tone"], "safe")
        self.assertIn("Capsule NOT REPRODUCED", not_reproduced["text"])
        self.assertIn("not proof", not_reproduced["text"])
        for word in ("passes", "safe", "secure", "verified"):
            self.assertNotIn(word, not_reproduced["text"].lower())

        # Never green unless the verdict is known and its exit code agrees.
        self.assertEqual(disagreeing["tone"], "warn")
        self.assertEqual(unknown["tone"], "warn")

        self.assertEqual(ordinary["tone"], "danger")
        self.assertIn("Gate fails", ordinary["text"])
        self.assertIn("fail-on new+confirmed", ordinary["text"])
        self.assertNotIn("Capsule", ordinary["text"])
        self.assertNotIn("fail-on null", inconclusive["text"])

    def _list(self, entries: list, filter_text: str = "") -> dict:
        return _run_node(_RUN_LIST_HARNESS, [{"entries": entries, "filter": filter_text}])[0]

    @staticmethod
    def _entry(run_id: str, status: str, exit_code: int, verdict=None) -> dict:
        entry = {"run_id": run_id, "status": status, "gate_exit_code": exit_code,
                 "started_at": None, "target": "http://127.0.0.1:1",
                 "summary": {"probes": 3, "new": 1}, "capsule": None}
        if verdict is not None:
            entry["capsule"] = {"verdict": verdict, "check_id": "invoice-tenant-isolation"}
        return entry

    def test_the_run_list_names_a_capsule_verification_by_its_verdict(self) -> None:
        listed = self._list([
            self._entry("V-inc", "inconclusive", 2, "INCONCLUSIVE"),
            self._entry("V-fail", "failed", 2, "INCONCLUSIVE"),
            self._entry("V-conf", "failed", 1, "CONFIRMED"),
            self._entry("V-not", "passed", 0, "NOT_REPRODUCED"),
            self._entry("R-run", "failed", 1),
            # An entry from a server that predates the field.
            {key: value for key, value in self._entry("R-old", "passed", 0).items()
             if key != "capsule"},
        ])
        self.assertEqual(listed["dots"], [
            {"cls": "warn", "text": "capsule · INCONCLUSIVE"},
            # The status computed from findings said FAILED here, in red.
            {"cls": "warn", "text": "capsule · INCONCLUSIVE"},
            {"cls": "danger", "text": "capsule · CONFIRMED"},
            {"cls": "safe", "text": "capsule · NOT REPRODUCED"},
            {"cls": "danger", "text": "failed"},
            {"cls": "safe", "text": "passed"},
        ])
        self.assertTrue(listed["summaries"][0].startswith("check invoice-tenant-isolation"))
        self.assertEqual(listed["summaries"][4], "3 probes · 1 new")

    def test_the_detail_badge_reads_the_capsule_verdict(self) -> None:
        detail = APP_JS.split("function renderDetail(", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("capsuleStatus(run.capsule, gate.exit_code)", detail)
        self.assertIn("capsule.label", detail)
        self.assertIn("capsule.tone", detail)

    def test_the_filter_finds_what_the_row_says(self) -> None:
        entries = [self._entry("V-inc", "inconclusive", 2, "INCONCLUSIVE"),
                   self._entry("R-run", "failed", 1)]
        self.assertEqual([d["text"] for d in self._list(entries, "capsule")["dots"]],
                         ["capsule · INCONCLUSIVE"])
        self.assertEqual(len(self._list(entries, "invoice-tenant")["dots"]), 1)
        self.assertEqual(len(self._list(entries, "")["dots"]), 2)


@slow("runs app.js under node in a subprocess")
class AccessMatrixTest(unittest.TestCase):
    """The map's grid draws measured cells and never upgrades a candidate."""

    def test_a_crossed_marker_is_a_candidate_and_an_unprobed_cell_says_so(self) -> None:
        cell = lambda identity, reach, status, marker=None, reason=None: {
            "operation": "GET /api/invoices/{id}", "specimen": None, "identity": identity,
            "reach": reach, "status": status, "marker_scan": marker,
            "marker_owner": "owner" if marker else None, "unknown_reason": reason,
        }
        matrix = {
            "identities": ["owner", "other", "writer"],
            "rows": [{"operation": "GET /api/invoices/{id}", "specimen": None}],
            "cells": [
                cell("owner", "reached", 200, "present"),
                cell("other", "reached", 200, "present"),
                cell("writer", "unknown", None, None, "skipped_mutating"),
            ],
        }
        empty = {"identities": [], "rows": [], "cells": []}
        grid, nothing = _run_node(_MATRIX_HARNESS, [matrix, empty])

        owner, other, writer = grid["cells"]
        self.assertNotIn("crossed", owner["cls"])
        self.assertIn("carries its own marker", owner["label"])
        self.assertIn("crossed", other["cls"])
        self.assertIn("carries owner's marker", other["label"])
        self.assertIn("unknown", writer["cls"])
        self.assertIn("skipped_mutating", writer["label"])
        self.assertIn("·", writer["text"])
        # In a map a crossed marker is a hypothesis; the legend must say so.
        self.assertIn("not a finding", grid["legend"])
        self.assertIsNone(nothing)


if __name__ == "__main__":
    unittest.main()
