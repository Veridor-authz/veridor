"""Discovery proposes; declaration disposes. These tests keep that true.

Every test here exists because one of these gets it wrong exactly once:

* A candidate that reaches the findings list, a SARIF result, or an exit code
  turns Veridor into the noisy scanner it exists to replace. The separation is
  structural, and it is asserted structurally.
* A rule that reads an ``unknown`` cell as a denial fabricates a disagreement
  out of an absence. Every rule is tested with its subject cell unknown, and
  must stay silent.
* A rule whose stated false-positive mode is untested is not done. Each rule has
  BOTH a true case and its own documented failure case here: a public health
  endpoint, a genuinely shared resource, a collection-versus-item difference,
  an owned object, a tenant-scoped 404.
* A candidate described in language that asserts more than an observed
  inconsistency is worse than no candidate at all.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import inspect
import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from veridor import blastradius as br  # noqa: E402
from veridor import coverage  # noqa: E402
from veridor.matrix import (  # noqa: E402
    OUTCOME_OBSERVED,
    OUTCOME_UNKNOWN,
    REACH_UNKNOWN,
    AccessMatrix,
    Cell,
    classify_reach,
    load_matrix,
)

FIXTURES = ROOT / "tests" / "fixtures"

#: Every shipped ``(matrix, config)`` pair, so the vocabulary police and the
#: "every rule fires somewhere" check cover all of them rather than a subset
#: that happens to be old enough to be listed.
CORPUS: tuple[tuple[str, str], ...] = (
    ("matrix.observed.json", "matrix.demo.json"),
    ("matrix.sibling.json", "blastradius.sibling.json"),
    ("matrix.shared.json", "blastradius.shared.json"),
    ("matrix.benign.json", "blastradius.benign.json"),
    ("matrix.idor.json", "blastradius.idor.json"),
)


# ---------------------------------------------------------------------------
# synthetic matrices: the rules are pure, so the fixtures can be tiny
# ---------------------------------------------------------------------------


def _concrete(operation: str) -> str:
    _, _, template = operation.partition(" ")
    return re.sub(r"\{[^}]*\}", "concrete-1", template)


def _cell(operation: str, identity: str, specimen: str | None, value: Any) -> Cell:
    if isinstance(value, str) and value.startswith("unknown:"):
        return Cell(
            operation=operation,
            identity=identity,
            specimen=specimen,
            url_path=_concrete(operation),
            outcome=OUTCOME_UNKNOWN,
            reach=REACH_UNKNOWN,
            unknown_reason=value.split(":", 1)[1],
        )
    spec: dict[str, Any] = dict(value) if isinstance(value, Mapping) else {"status": value}
    status = int(spec["status"])
    reach, refusal, reason = classify_reach(status)
    measured = reason is None
    return Cell(
        operation=operation,
        identity=identity,
        specimen=specimen,
        url_path=_concrete(operation),
        outcome=OUTCOME_OBSERVED if measured else OUTCOME_UNKNOWN,
        reach=reach,
        status=status,
        refusal_kind=refusal,
        body_bytes=spec.get("body_bytes", 11),
        body_empty=spec.get("body_empty", False),
        body_digest=spec.get("digest", "digest-generic"),
        marker_scan=spec.get("marker"),
        marker_owner=spec.get("marker_owner") if spec.get("marker") else None,
        unknown_reason=reason,
    )


def make_matrix(
    grid: Sequence[tuple[str, str | None, Mapping[str, Any]]],
    *,
    identities: Sequence[str] | None = None,
    not_shared: Sequence[tuple[str, str | None]] = (),
    marker_owner: str | None = None,
    aborted: bool = False,
    abort_reason: str | None = None,
    issued: int | None = None,
    planned: int | None = None,
    ignored: Sequence[str] = (),
    max_specimens: int = 1,
) -> AccessMatrix:
    """Build a dense AccessMatrix from ``(operation, specimen, {identity: value})``.

    ``value`` is a status code, ``"unknown:<reason>"``, or a mapping carrying
    ``status`` plus any of ``marker``, ``marker_owner``, ``digest``,
    ``body_empty``.
    """
    names = tuple(identities) if identities else tuple(dict.fromkeys(
        identity for _, _, row in grid for identity in row
    ))
    rows = tuple((operation, specimen) for operation, specimen, _ in grid)
    cells: list[Cell] = []
    for operation, specimen, row in grid:
        for identity in names:
            cells.append(
                _cell(operation, identity, specimen, row.get(identity, "unknown:not_probed"))
            )
    shared = tuple(row for row in rows if row not in set(not_shared))
    return AccessMatrix(
        base_url="http://127.0.0.1:8765",
        host="127.0.0.1:8765",
        target_class="loopback",
        operations=tuple(dict.fromkeys(operation for operation, _, _ in grid)),
        identities=names,
        rows=rows,
        cells=tuple(cells),
        planned=planned if planned is not None else len(cells),
        issued=issued if issued is not None else len(cells),
        aborted=aborted,
        abort_reason=abort_reason,
        shared_specimen_rows=shared,
        ignored=tuple(ignored),
        marker_owner=marker_owner,
        max_specimens=max_specimens,
    )


def grouping(
    matrix: AccessMatrix,
    *,
    peer_groups: Mapping[str, list[str]] | None = None,
    privilege_order: list[str] | None = None,
    unauthenticated: str | None = None,
    unanimous: bool | None = None,
    headers: Mapping[str, Mapping[str, Any]] | None = None,
) -> br.PeerGrouping:
    section: dict[str, Any] = {}
    if peer_groups is not None:
        section["peer_groups"] = dict(peer_groups)
    if privilege_order is not None:
        section["privilege_order"] = list(privilege_order)
    if unauthenticated is not None:
        section["unauthenticated"] = unauthenticated
    if unanimous is not None:
        section["peer_divergence_unanimous"] = unanimous
    identities = dict(headers) if headers else {
        name: {"headers": {"Authorization": "Bearer x"}} for name in matrix.identities
    }
    return br.peer_groups({"identities": identities, "matrix": section}, matrix)


def rules_fired(candidates: Sequence[br.Candidate]) -> set[str]:
    return {candidate.rule for candidate in candidates}


def operations_for(candidates: Sequence[br.Candidate], rule: str) -> list[str]:
    return [item.operation for item in candidates if item.rule == rule]


def family_grid(
    refused_members: Sequence[str],
    reached_members: Sequence[str],
    identity: str,
    *,
    prefix: str = "/api/reports",
    others: Mapping[str, int] | None = None,
) -> list[tuple[str, str | None, dict[str, Any]]]:
    other_rows = dict(others or {"owner": 200})
    grid: list[tuple[str, str | None, dict[str, Any]]] = []
    for name in refused_members:
        grid.append((f"GET {prefix}/{name}", None, {identity: 403, **other_rows}))
    for name in reached_members:
        grid.append((f"GET {prefix}/{name}", None, {identity: 200, **other_rows}))
    return grid


# ---------------------------------------------------------------------------
# blast radius
# ---------------------------------------------------------------------------


class BlastRadiusTest(unittest.TestCase):
    def matrix(self) -> AccessMatrix:
        return make_matrix(
            [
                ("GET /a", None, {"p": 200, "q": 403}),
                ("GET /b", None, {"p": 204, "q": 404}),
                ("GET /c", None, {"p": 302, "q": 401}),
                ("GET /d", None, {"p": "unknown:skipped_mutating", "q": 200}),
                ("GET /e", None, {"p": 503, "q": 429}),
            ]
        )

    def test_unknown_is_never_counted_as_refused(self) -> None:
        radius = br.compute_blast_radius(self.matrix(), "p")
        self.assertEqual(len(radius.reached), 2)
        self.assertEqual(len(radius.refused), 0)
        self.assertEqual(len(radius.indeterminate), 1)
        self.assertEqual(len(radius.unmeasured), 2)
        self.assertEqual(
            dict(radius.unknown_reasons), {"skipped_mutating": 1, "server_error": 1}
        )

    def test_skipped_and_errored_cells_stay_out_of_the_reach_fraction(self) -> None:
        radius = br.compute_blast_radius(self.matrix(), "p")
        # observed = reached + refused + indeterminate. Neither numerator nor
        # denominator may contain a cell nobody measured.
        self.assertEqual(radius.observed, 3)
        self.assertEqual(radius.inventory, 5)

    def test_no_percentage_is_rendered_over_an_incomplete_denominator(self) -> None:
        self.assertIsNone(br.compute_blast_radius(self.matrix(), "p").share)
        report = br.blast_radius_report(self.matrix())
        text = br.render_blast_radius(report)
        self.assertIn("no share is rendered", text)

    def test_a_share_is_rendered_once_everything_is_measured(self) -> None:
        matrix = make_matrix(
            [("GET /a", None, {"p": 200}), ("GET /b", None, {"p": 403})]
        )
        self.assertEqual(br.compute_blast_radius(matrix, "p").share, "50.0%")

    def test_the_headline_is_always_a_lower_bound(self) -> None:
        radius = br.compute_blast_radius(self.matrix(), "p")
        self.assertIn("lower bound", radius.headline)
        self.assertIn("at least 2 of 5", radius.headline)

    def test_the_share_ceils_where_coverage_floors(self) -> None:
        # Understating reach is this module's dangerous direction, so the two
        # saturating cases are named rather than rounded into.
        self.assertEqual(br._format_share_ceiling(1, 100000), "0.1%")
        self.assertNotEqual(br._format_share_ceiling(1, 100000), "0.0%")
        self.assertEqual(br._format_share_ceiling(99999, 100000), ">99.9%")
        self.assertEqual(br._format_share_ceiling(3, 3), "100.0%")
        self.assertEqual(br._format_share_ceiling(1, 3), "33.4%")
        self.assertEqual(br._format_share_ceiling(0, 0), "n/a")

    def test_a_redirect_is_reported_on_its_own_line_and_folded_nowhere(self) -> None:
        text = br.render_blast_radius(br.blast_radius_report(self.matrix()))
        self.assertIn("unresolved (redirect, not followed)", text)

    def test_a_rejected_input_is_not_called_a_redirect(self) -> None:
        # REGRESSION. Every indeterminate cell was rendered "redirect, not
        # followed" with advice to "declare the post-redirect status" -- a
        # setting the matrix does not have. classify_reach also files 400,
        # 409, 418 and 422 there: the handler answered, nothing was returned,
        # and no redirect was involved.
        matrix = make_matrix([
            ("GET /a", None, {"p": 400}),
            ("GET /b", None, {"p": 422}),
            ("GET /c", None, {"p": 302}),
            ("GET /d", None, {"p": 200}),
        ])
        text = br.render_blast_radius(br.blast_radius_report(matrix))
        self.assertIn("1 unresolved (redirect, not followed)", text)
        self.assertIn("2 unresolved (a status that is neither reach nor refusal", text)
        self.assertNotIn("post-redirect", text)
        self.assertEqual(br.banned_words_in(text), ())

    def test_the_stale_credential_line_does_not_count_a_407(self) -> None:
        # REGRESSION. The render and the diagnostic said "every measured cell
        # ... is a 401/407", but a 407 is never a measured cell: it is the
        # proxy's answer, recorded as unmeasured. A row of 401s and 407s is
        # suppressed because the 407s are not counted, not because they are
        # rejected credentials.
        matrix = make_matrix([
            ("GET /a", None, {"owner": 200, "stale": 401}),
            ("GET /b", None, {"owner": 200, "stale": 407}),
        ])
        config = {
            "identities": {
                "owner": {"headers": {"Authorization": "Bearer o"}},
                "stale": {"headers": {"Authorization": "Bearer s"}},
            },
            "matrix": {},
        }
        report = br.blast_radius_report(
            matrix, br.credential_bearing_identities(config, matrix.identities)
        )
        notes = [
            note["message"] for note in br.peer_groups(config, matrix).diagnostics
            if note["code"] == "row_uniformly_unauthenticated"
        ]
        self.assertEqual(len(notes), 1)
        for text in (br.render_blast_radius(report), notes[0]):
            self.assertIn("is a 401", text)
            self.assertNotIn("401/407", text)
            self.assertIn("407", text)

    def test_an_empty_body_is_still_reach_and_is_stated(self) -> None:
        matrix = make_matrix(
            [
                ("GET /a", None, {"p": {"status": 200, "body_empty": True}}),
                ("GET /b", None, {"p": 200}),
            ]
        )
        radius = br.compute_blast_radius(matrix, "p")
        self.assertEqual(len(radius.reached), 2)
        self.assertEqual(radius.empty_bodied, 1)
        text = br.render_blast_radius(br.blast_radius_report(matrix))
        self.assertIn("zero-byte body", text)
        self.assertIn("cannot tell an empty collection from a full one", text)

    def test_the_operation_level_limitation_is_on_every_rendering(self) -> None:
        text = br.render_blast_radius(br.blast_radius_report(self.matrix()))
        self.assertIn("measured at OPERATION level", text)
        self.assertIn("never enumerated identifiers", text)

    def test_an_aborted_run_stamps_every_rendering_incomplete(self) -> None:
        matrix = make_matrix(
            [("GET /a", None, {"p": 200}), ("GET /b", None, {"p": "unknown:aborted"})],
            aborted=True,
            abort_reason="rate_limited",
            issued=1,
            planned=2,
        )
        text = br.render_blast_radius(br.blast_radius_report(matrix))
        self.assertIn("INCOMPLETE", text)
        self.assertIn("aborted after 1 of 2 requests (rate_limited)", text)
        document = br.candidates_document(matrix, [])
        self.assertIn("INCOMPLETE", br.render_candidates(document))

    def test_an_unknown_identity_is_refused_rather_than_silently_empty(self) -> None:
        with self.assertRaises(br.BlastRadiusError):
            br.compute_blast_radius(self.matrix(), "nobody")

    def test_a_proxy_s_407_is_not_the_credential_being_refused(self) -> None:
        """A 407 is the proxy's answer; the target never saw the credential."""
        matrix = make_matrix(
            [("GET /a", None, {"p": 407}), ("GET /b", None, {"p": 407})]
        )
        self.assertEqual(br.uniformly_unauthenticated_identities(matrix), ())

    def test_a_uniformly_unauthenticated_row_is_named_as_a_config_problem(self) -> None:
        matrix = make_matrix(
            [("GET /a", None, {"p": 401}), ("GET /b", None, {"p": 401})]
        )
        radius = br.compute_blast_radius(matrix, "p")
        self.assertTrue(radius.uniformly_unauthenticated)
        self.assertEqual(br.uniformly_unauthenticated_identities(matrix), ("p",))
        self.assertIn(
            "never accepted this credential",
            "".join(
                note["message"] for note in grouping(matrix).diagnostics
            ),
        )


# ---------------------------------------------------------------------------
# peer groups: declared membership, observed evidence
# ---------------------------------------------------------------------------


class PeerGroupTest(unittest.TestCase):
    def matrix(self) -> AccessMatrix:
        return make_matrix(
            [("GET /a", None, {"alice": 200, "bob": 403, "carol": 403})]
        )

    def test_overlapping_membership_is_refused(self) -> None:
        with self.assertRaises(br.BlastRadiusError) as raised:
            grouping(
                self.matrix(),
                peer_groups={"one": ["alice", "bob"], "two": ["bob", "carol"]},
            )
        self.assertIn("at most one peer group", str(raised.exception))

    def test_a_group_member_must_be_a_probed_identity(self) -> None:
        with self.assertRaises(br.BlastRadiusError):
            grouping(self.matrix(), peer_groups={"one": ["alice", "mallory"]})

    def test_privilege_order_must_name_probed_identities_and_not_repeat(self) -> None:
        with self.assertRaises(br.BlastRadiusError):
            grouping(self.matrix(), privilege_order=["alice", "nobody"])
        with self.assertRaises(br.BlastRadiusError):
            grouping(self.matrix(), privilege_order=["alice", "alice"])

    def test_a_singleton_group_emits_a_diagnostic_and_no_candidate(self) -> None:
        matrix = self.matrix()
        group = grouping(matrix, peer_groups={"solo": ["alice"]})
        codes = [note["code"] for note in group.diagnostics]
        self.assertIn("peer_group_singleton", codes)
        candidates = br.find_candidates(matrix, group)
        self.assertNotIn("peer_divergence", rules_fired(candidates))

    def test_a_single_identity_config_fabricates_nothing(self) -> None:
        matrix = make_matrix([("GET /a", None, {"solo": 200})])
        group = grouping(matrix, peer_groups={"only": ["solo"]})
        self.assertEqual(br.find_candidates(matrix, group), [])

    def test_an_identity_in_no_group_produces_no_peer_candidate(self) -> None:
        matrix = self.matrix()
        group = grouping(matrix, peer_groups={"pair": ["bob", "carol"]})
        codes = [note["code"] for note in group.diagnostics]
        self.assertIn("identity_in_no_peer_group", codes)
        candidates = br.find_candidates(matrix, group)
        self.assertEqual(operations_for(candidates, "peer_divergence"), [])

    def test_the_unauthenticated_identity_can_be_inferred_and_says_so(self) -> None:
        matrix = self.matrix()
        group = grouping(
            matrix,
            headers={
                "alice": {"headers": {"Authorization": "Bearer a"}},
                "bob": {"headers": {"Authorization": "Bearer b"}},
                "carol": {"headers": {}},
            },
        )
        self.assertEqual(group.unauthenticated, "carol")
        self.assertEqual(group.unauthenticated_source, "inferred_empty_headers")
        self.assertIn(
            "unauthenticated_identity_inferred",
            [note["code"] for note in group.diagnostics],
        )

    def test_two_credential_free_identities_are_ambiguous_rather_than_guessed(self) -> None:
        group = grouping(
            self.matrix(),
            headers={
                "alice": {"headers": {}},
                "bob": {"headers": {}},
                "carol": {"headers": {"Authorization": "Bearer c"}},
            },
        )
        self.assertIsNone(group.unauthenticated)
        self.assertIn(
            "unauthenticated_identity_ambiguous",
            [note["code"] for note in group.diagnostics],
        )

    def test_a_declared_unauthenticated_identity_wins(self) -> None:
        group = grouping(self.matrix(), unauthenticated="bob")
        self.assertEqual((group.unauthenticated, group.unauthenticated_source), ("bob", "declared"))

    def test_a_session_identity_is_never_inferred_as_unauthenticated(self) -> None:
        """The empty-headers heuristic named the AUTHENTICATED identity.

        An identity that logs in carries its credential in a cookie jar, not in
        ``headers``, so ``not identities[name]["headers"]`` was true of exactly
        the identity that is most authenticated. ``unauthenticated_reach`` then
        ran against it. ``matrix.plan_matrix`` refuses such a configuration
        before a socket opens; this is the second, independent guard, because
        this module is a library and takes a matrix from any prober.
        """
        group = grouping(
            self.matrix(),
            headers={
                "alice": {"headers": {"Authorization": "Bearer a"}},
                "bob": {"headers": {"Authorization": "Bearer b"}},
                "carol": {"session": {"establishes": {"cookie": "sessionid"}}},
            },
        )
        self.assertIsNone(group.unauthenticated)
        self.assertEqual(group.unauthenticated_source, "none")
        note = next(
            item
            for item in group.diagnostics
            if item["code"] == "unauthenticated_identity_session_backed"
        )
        self.assertEqual(note["identities"], ["carol"])
        self.assertIn("carol", note["message"])

    def test_a_declared_unauthenticated_identity_still_wins_over_the_guard(self) -> None:
        """An explicit declaration is the operator's, and outranks a heuristic."""
        group = grouping(
            self.matrix(),
            unauthenticated="bob",
            headers={
                "alice": {"headers": {"Authorization": "Bearer a"}},
                "bob": {"headers": {}},
                "carol": {"session": {"establishes": {"cookie": "sessionid"}}},
            },
        )
        self.assertEqual(group.unauthenticated, "bob")

    def test_declaring_the_session_identity_itself_is_refused(self) -> None:
        """Deference has a floor, and this is below it.

        The guard above ran only on the inferred path, so an operator who
        *named* the session-backed identity as the unauthenticated one was
        obeyed silently -- and ``unauthenticated_reach`` then measured a
        credentialed identity's reach as anonymous, reporting a SMALLER blast
        radius than reality. A declaration outranks a heuristic, but it cannot
        make a logged-in identity anonymous, so this one is a contradiction
        rather than a preference and is refused.
        """
        with self.assertRaises(br.BlastRadiusError) as caught:
            grouping(
                self.matrix(),
                unauthenticated="carol",
                headers={
                    "alice": {"headers": {"Authorization": "Bearer a"}},
                    "bob": {"headers": {"Authorization": "Bearer b"}},
                    "carol": {"session": {"establishes": {"cookie": "sessionid"}}},
                },
            )
        message = str(caught.exception)
        self.assertIn("carol", message)
        self.assertIn("session", message)
        # The message must say what to do instead, both ways out.
        self.assertIn("no credential", message)
        self.assertIn("omit matrix.unauthenticated", message)


# ---------------------------------------------------------------------------
# Rule F -- marker_reach
# ---------------------------------------------------------------------------


class MarkerReachTest(unittest.TestCase):
    def test_true_case_a_marker_crossed_a_boundary(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "owner_invoice",
                    {
                        "owner": {"status": 200, "marker": "present", "marker_owner": "owner"},
                        "outsider": {
                            "status": 200,
                            "marker": "present",
                            "marker_owner": "owner",
                            "digest": "digest-outsider",
                        },
                    },
                )
            ],
            marker_owner="owner",
        )
        candidates = br.find_candidates(matrix, grouping(matrix))
        marker = [item for item in candidates if item.rule == "marker_reach"]
        self.assertEqual([item.identity for item in marker], ["outsider"])
        self.assertEqual(marker[0].evidence_tier, br.TIER_MARKER_BACKED)
        self.assertEqual(marker[0].control_identity, "owner")

    def test_a_reader_declared_above_the_marker_owner_is_not_a_candidate(self) -> None:
        # REGRESSION. marker_reach is the only rule at tier 0, so
        # whatever it emits occupies the top of the list. It used to ignore
        # privilege_order entirely -- the one rule that reads it is
        # inverted_guard -- so an administrator the operator DECLARED to be
        # strictly above the marker's owner, reading that owner's record,
        # ranked first. The declaration already says that should happen.
        grid = [
            (
                "GET /api/admin/audit",
                None,
                {
                    "owner": {"status": 200, "marker": "present", "marker_owner": "owner"},
                    "administrator": {
                        "status": 200,
                        "marker": "present",
                        "marker_owner": "owner",
                        "digest": "digest-admin",
                    },
                    "outsider": {
                        "status": 200,
                        "marker": "present",
                        "marker_owner": "owner",
                        "digest": "digest-outsider",
                    },
                },
            )
        ]
        matrix = make_matrix(grid, marker_owner="owner")
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(
            matrix,
            grouping(matrix, privilege_order=["outsider", "owner", "administrator"]),
            suppressions=suppressions,
        )
        marker = [item for item in candidates if item.rule == "marker_reach"]
        self.assertEqual([item.identity for item in marker], ["outsider"])
        self.assertEqual(
            suppressions.get("marker_reach_reader_declared_higher_privilege"), 1
        )

        # ... and with nothing declared, nothing is assumed: the administrator
        # is reported like anybody else. Silence must come from a declaration,
        # never from a guess about what a name means.
        undeclared = br.find_candidates(matrix, grouping(matrix))
        self.assertEqual(
            sorted(item.identity for item in undeclared if item.rule == "marker_reach"),
            ["administrator", "outsider"],
        )

    def test_the_marker_owner_seeing_its_own_marker_is_not_a_candidate(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "owner_invoice",
                    {"owner": {"status": 200, "marker": "present", "marker_owner": "owner"}},
                )
            ],
            marker_owner="owner",
        )
        self.assertEqual(br.find_candidates(matrix, grouping(matrix)), [])

    def test_false_positive_case_a_genuinely_shared_resource_is_tagged_and_ranked_down(
        self,
    ) -> None:
        # A shared audit feed hands every caller the same bytes. That is the
        # documented failure mode, so the identical digest ranks it down and
        # names the mode -- it never silently disappears.
        shared = {
            "status": 200,
            "marker": "present",
            "marker_owner": "owner",
            "digest": "digest-shared",
        }
        private = {
            "status": 200,
            "marker": "present",
            "marker_owner": "owner",
            "digest": "digest-private",
        }
        matrix = make_matrix(
            [
                ("GET /api/audit/feed", None, {"owner": dict(shared), "outsider": dict(shared)}),
                (
                    "GET /api/invoices/{id}",
                    "owner_invoice",
                    {
                        "owner": {**private, "digest": "digest-owner"},
                        "outsider": dict(private),
                    },
                ),
            ],
            marker_owner="owner",
        )
        candidates = br.find_candidates(matrix, grouping(matrix))
        by_operation = {item.operation: item for item in candidates}
        self.assertIn(
            br.TAG_IDENTICAL_BODY, by_operation["GET /api/audit/feed"].tags
        )
        self.assertNotIn(
            br.TAG_IDENTICAL_BODY, by_operation["GET /api/invoices/{id}"].tags
        )
        # tagged sinks below untagged inside the same tier
        self.assertLess(
            candidates.index(by_operation["GET /api/invoices/{id}"]),
            candidates.index(by_operation["GET /api/audit/feed"]),
        )
        self.assertTrue(
            any(
                "shared resource" in mode
                for mode in by_operation["GET /api/audit/feed"].false_positive_modes
            )
        )

    def test_false_positive_case_a_group_wide_feed_is_excluded_and_counted(self) -> None:
        # The rule's own first stated failure mode: a tenant-wide activity feed
        # legitimately carries every member's records, so the owner's marker
        # turns up in her peers' responses. It was one of the four surviving
        # candidates on the zero-bug fixture. A COLLECTION that every active
        # member of the owner's DECLARED peer group reached is now excluded.
        seen = {"status": 200, "marker": "present", "marker_owner": "alice"}
        matrix = make_matrix(
            [
                (
                    "GET /api/activity",
                    None,
                    {
                        "alice": dict(seen),
                        "bob": {**seen, "digest": "digest-bob"},
                        "carol": {**seen, "digest": "digest-carol"},
                    },
                )
            ],
            marker_owner="alice",
        )
        suppressions: dict[str, int] = {}
        group = grouping(matrix, peer_groups={"tenant": ["alice", "bob", "carol"]})
        self.assertEqual(
            br.find_candidates(matrix, group, suppressions=suppressions), []
        )
        self.assertEqual(suppressions.get("marker_reach_group_wide_collection"), 2)
        # and the operator is told, by reason and count
        note = next(
            item
            for item in br.discovery_notes(matrix, group, suppressions=suppressions)
            if item["code"] == "rule_suppressions"
        )
        self.assertIn("marker_reach_group_wide_collection", note["message"])

    def test_one_refused_peer_means_the_feed_has_a_guard_and_the_row_stands(self) -> None:
        # The exclusion above is not "collections are boring". A declared peer
        # refused on the same row is the target demonstrating a boundary there,
        # so the marker crossing it is exactly the shape the rule is for.
        seen = {"status": 200, "marker": "present", "marker_owner": "alice"}
        matrix = make_matrix(
            [
                (
                    "GET /api/activity",
                    None,
                    {
                        "alice": dict(seen),
                        "bob": {**seen, "digest": "digest-bob"},
                        "carol": 403,
                    },
                )
            ],
            marker_owner="alice",
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, peer_groups={"tenant": ["alice", "bob", "carol"]})
        )
        self.assertEqual(
            [item.identity for item in candidates if item.rule == "marker_reach"],
            ["bob"],
        )

    def test_an_identified_object_is_never_excluded_as_a_shared_feed(self) -> None:
        # An item row names ONE object and one object has one owner, so the
        # "several identities' records legitimately live here" reading is not
        # available -- even when the whole declared group reached it.
        seen = {"status": 200, "marker": "present", "marker_owner": "alice"}
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "owner_invoice",
                    {
                        "alice": dict(seen),
                        "bob": {**seen, "digest": "digest-bob"},
                        "carol": {**seen, "digest": "digest-carol"},
                    },
                )
            ],
            marker_owner="alice",
        )
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(
            matrix,
            grouping(matrix, peer_groups={"tenant": ["alice", "bob", "carol"]}),
            suppressions=suppressions,
        )
        self.assertEqual(
            sorted(item.identity for item in candidates if item.rule == "marker_reach"),
            ["bob", "carol"],
        )
        self.assertNotIn("marker_reach_group_wide_collection", suppressions)

    def test_a_reader_outside_the_group_is_not_excused_by_the_group(self) -> None:
        # The feed belonging to a declared group says nothing about a reader who
        # is not in it.
        seen = {"status": 200, "marker": "present", "marker_owner": "alice"}
        matrix = make_matrix(
            [
                (
                    "GET /api/activity",
                    None,
                    {
                        "alice": dict(seen),
                        "bob": {**seen, "digest": "digest-bob"},
                        "carol": {**seen, "digest": "digest-carol"},
                        "stranger": {**seen, "digest": "digest-stranger"},
                    },
                )
            ],
            marker_owner="alice",
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, peer_groups={"tenant": ["alice", "bob", "carol"]})
        )
        self.assertEqual(
            sorted(item.identity for item in candidates if item.rule == "marker_reach"),
            ["stranger"],
        )

    def test_a_two_identity_group_is_never_excused_as_a_shared_feed(self) -> None:
        # REGRESSION. The exclusion's justification is "where even one declared
        # peer was refused, the row has a guard and the candidate stands". In a
        # two-member group the members ARE the marker's owner and the subject:
        # the owner planted the marker that was read, and the subject reached
        # the row by the rule's own precondition, so no third peer is left who
        # could have been refused and the test fires unconditionally. Two
        # identities is the minimum meaningful grouping and what
        # fixtures/veridor.map-demo.json declares, so declaring the peer group
        # CORRECTLY used to delete the ordinary cross-tenant collection read
        # while leaving peer_groups empty surfaced it.
        seen = {"status": 200, "marker": "present", "marker_owner": "alice"}
        matrix = make_matrix(
            [
                (
                    "GET /api/activity",
                    None,
                    {"alice": dict(seen), "bob": {**seen, "digest": "digest-bob"}},
                )
            ],
            marker_owner="alice",
        )
        suppressions: dict[str, int] = {}
        declared = br.find_candidates(
            matrix,
            grouping(matrix, peer_groups={"tenant": ["alice", "bob"]}),
            suppressions=suppressions,
        )
        self.assertEqual(
            [item.identity for item in declared if item.rule == "marker_reach"],
            ["bob"],
        )
        self.assertNotIn("marker_reach_group_wide_collection", suppressions)
        # and declaring the group is never worse than not declaring it
        undeclared = br.find_candidates(matrix, grouping(matrix))
        self.assertEqual(
            [item.identity for item in undeclared if item.rule == "marker_reach"],
            [item.identity for item in declared if item.rule == "marker_reach"],
        )

    def test_without_a_declared_group_nothing_is_excluded(self) -> None:
        # Silence must come from a declaration. With no peer group around the
        # marker owner there is nothing that says "these callers share a feed",
        # so the row is reported.
        seen = {"status": 200, "marker": "present", "marker_owner": "alice"}
        matrix = make_matrix(
            [
                (
                    "GET /api/activity",
                    None,
                    {"alice": dict(seen), "bob": {**seen, "digest": "digest-bob"}},
                )
            ],
            marker_owner="alice",
        )
        candidates = br.find_candidates(matrix, grouping(matrix))
        self.assertEqual([item.identity for item in candidates], ["bob"])

    def test_it_does_not_fire_on_an_unknown_cell(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "owner_invoice",
                    {"owner": 200, "outsider": "unknown:server_error"},
                )
            ],
            marker_owner="owner",
        )
        self.assertEqual(br.find_candidates(matrix, grouping(matrix)), [])

    def test_the_promotion_stub_is_mechanical_for_this_rule(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "owner_invoice",
                    {
                        "owner": {"status": 200, "marker": "present", "marker_owner": "owner"},
                        "outsider": {"status": 200, "marker": "present", "marker_owner": "owner"},
                    },
                )
            ],
            marker_owner="owner",
        )
        candidate = br.find_candidates(matrix, grouping(matrix))[0]
        stub = br.promotion_stub(candidate)
        self.assertEqual(stub["expect"]["owner"]["contains_marker"], "owner")
        self.assertEqual(stub["expect"]["outsider"]["excludes_marker"], "owner")
        self.assertEqual(stub["expect"]["outsider"]["status"], [403, 404])
        self.assertTrue(stub["name"].startswith("TODO"))


# ---------------------------------------------------------------------------
# Rule D -- unauthenticated_reach
# ---------------------------------------------------------------------------


class UnauthenticatedReachTest(unittest.TestCase):
    def test_true_case_an_unauthenticated_caller_reached_a_business_operation(self) -> None:
        matrix = make_matrix(
            [
                ("GET /api/invoices", None, {"anonymous": 200, "owner": 200}),
                ("GET /api/reports", None, {"anonymous": 401, "owner": 200}),
                ("GET /api/ledgers", None, {"anonymous": 401, "owner": 200}),
            ]
        )
        candidates = br.find_candidates(matrix, grouping(matrix, unauthenticated="anonymous"))
        unauthenticated = [item for item in candidates if item.rule == "unauthenticated_reach"]
        self.assertEqual(
            [item.operation for item in unauthenticated], ["GET /api/invoices"]
        )
        self.assertEqual(unauthenticated[0].tags, ())

    def test_a_plain_public_health_endpoint_is_suppressed_and_counted(self) -> None:
        # REGRESSION (precision). /health, /version and /auth/* answering an
        # unauthenticated caller is those endpoints working. Tagging them put
        # four guaranteed-false candidates in every run against every target.
        matrix = make_matrix(
            [
                ("GET /health", None, {"anonymous": 200, "owner": 200}),
                ("GET /api/invoices", None, {"anonymous": 200, "owner": 200}),
                ("GET /api/reports", None, {"anonymous": 401, "owner": 200}),
                ("GET /api/ledgers", None, {"anonymous": 401, "owner": 200}),
            ]
        )
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(
            matrix,
            grouping(matrix, unauthenticated="anonymous"),
            suppressions=suppressions,
        )
        by_operation = {
            item.operation: item
            for item in candidates
            if item.rule == "unauthenticated_reach"
        }
        self.assertNotIn("GET /health", by_operation)
        self.assertEqual(by_operation["GET /api/invoices"].tags, ())
        self.assertEqual(
            suppressions.get("unauthenticated_reach_conventionally_public"), 1
        )

    def test_a_public_endpoint_carrying_a_marker_is_still_raised(self) -> None:
        # REGRESSION (recall). The suppression above must not become the
        # denylist the module refuses to have: a /health that really does hand
        # back a named identity's data carries the planted marker, and the
        # marker keeps the candidate.
        matrix = make_matrix(
            [
                (
                    "GET /health",
                    None,
                    {
                        "anonymous": {
                            "status": 200,
                            "marker": "present",
                            "marker_owner": "owner",
                        },
                        "owner": 200,
                    },
                ),
                ("GET /api/reports", None, {"anonymous": 401, "owner": 200}),
                ("GET /api/ledgers", None, {"anonymous": 401, "owner": 200}),
            ],
            marker_owner="owner",
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, unauthenticated="anonymous")
        )
        unauthenticated = [
            item for item in candidates if item.rule == "unauthenticated_reach"
        ]
        self.assertEqual([item.operation for item in unauthenticated], ["GET /health"])
        self.assertIn(br.TAG_CONVENTIONALLY_PUBLIC, unauthenticated[0].tags)

    def test_conventionally_public_patterns_are_matched_on_the_final_segment(self) -> None:
        self.assertTrue(br._is_conventionally_public("GET /api/v1/health"))
        self.assertTrue(br._is_conventionally_public("GET /.well-known/jwks.json"))
        self.assertFalse(br._is_conventionally_public("GET /api/invoices/{id}"))

    def test_a_substantially_public_target_collapses_to_one_note(self) -> None:
        grid = [(f"GET /public/{index}", None, {"anonymous": 200, "owner": 200}) for index in range(9)]
        grid.append(("GET /api/secrets", None, {"anonymous": 401, "owner": 200}))
        matrix = make_matrix(grid)
        group = grouping(matrix, unauthenticated="anonymous")
        candidates = br.find_candidates(matrix, group)
        self.assertEqual(operations_for(candidates, "unauthenticated_reach"), [])
        codes = {note["code"] for note in br.discovery_notes(matrix, group)}
        self.assertIn("unauthenticated_saturated", codes)
        text = br.render_candidates(br.candidates_document(matrix, candidates, grouping=group))
        self.assertIn("substantially public", text)

    def test_it_does_not_fire_on_an_unknown_cell(self) -> None:
        matrix = make_matrix(
            [
                ("GET /api/invoices", None, {"anonymous": "unknown:rate_limited", "owner": 200}),
                ("GET /api/reports", None, {"anonymous": 401, "owner": 200}),
            ]
        )
        candidates = br.find_candidates(matrix, grouping(matrix, unauthenticated="anonymous"))
        self.assertEqual(operations_for(candidates, "unauthenticated_reach"), [])

    def test_without_an_unauthenticated_identity_the_rule_does_not_run(self) -> None:
        matrix = make_matrix([("GET /api/invoices", None, {"owner": 200, "peer": 200})])
        candidates = br.find_candidates(matrix, grouping(matrix))
        self.assertEqual(operations_for(candidates, "unauthenticated_reach"), [])


# ---------------------------------------------------------------------------
# Rule E -- inverted_guard
# ---------------------------------------------------------------------------


class InvertedGuardTest(unittest.TestCase):
    def test_true_case_a_lower_identity_reached_what_a_higher_one_did_not(self) -> None:
        matrix = make_matrix(
            [("GET /api/reports/quarterly", None, {"tenant_user": 200, "platform_admin": 403})]
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, privilege_order=["tenant_user", "platform_admin"])
        )
        inverted = [item for item in candidates if item.rule == "inverted_guard"]
        self.assertEqual([item.identity for item in inverted], ["tenant_user"])
        self.assertEqual(inverted[0].tags, ())

    def test_a_tenant_scoped_404_from_every_higher_identity_is_suppressed(self) -> None:
        # REGRESSION (precision). A platform administrator has no tenant and is
        # correctly 404'd on tenant-scoped objects a tenant user reaches
        # legitimately. Tagging it produced one candidate per tenant-scoped row:
        # 21 of 30 on a benign 43-operation fixture, growing to 161 at 183 rows,
        # every one of them carrying the tag and every one of them correct.
        matrix = make_matrix(
            [
                ("GET /api/reports/quarterly", None, {"tenant_user": 200, "platform_admin": 403}),
                ("GET /api/tenants/{tid}/profile", "own_tenant", {"tenant_user": 200, "platform_admin": 404}),
            ]
        )
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(
            matrix,
            grouping(matrix, privilege_order=["tenant_user", "platform_admin"]),
            suppressions=suppressions,
        )
        inverted = [item for item in candidates if item.rule == "inverted_guard"]
        self.assertEqual(
            [item.operation for item in inverted], ["GET /api/reports/quarterly"]
        )
        self.assertEqual(inverted[0].tags, ())
        self.assertEqual(
            suppressions.get("inverted_guard_higher_identity_absent"), 1
        )

    def test_it_grows_with_anomalies_not_with_the_size_of_the_api(self) -> None:
        # REGRESSION (precision). The suppressed shape used to be emitted once
        # per tenant-scoped row, so the candidate count tracked API size rather
        # than anything anomalous.
        def rows(count: int) -> list[Any]:
            return [
                (
                    f"GET /api/tenants/{{tid}}/thing{index}",
                    "own_tenant",
                    {"tenant_user": 200, "platform_admin": 404},
                )
                for index in range(count)
            ]

        counts = []
        for width in (5, 20, 80):
            matrix = make_matrix(rows(width))
            counts.append(
                len(
                    br.find_candidates(
                        matrix,
                        grouping(
                            matrix,
                            privilege_order=["tenant_user", "platform_admin"],
                        ),
                    )
                )
            )
        self.assertEqual(counts, [0, 0, 0])

    def test_a_mixed_refusal_survives_and_is_tagged(self) -> None:
        # One higher identity answered 403, which IS an authorization signal, so
        # the row is kept. The 404 alongside it is still named.
        matrix = make_matrix(
            [
                (
                    "GET /api/tenants/{tid}/profile",
                    "own_tenant",
                    {"tenant_user": 200, "billing_admin": 403, "platform_admin": 404},
                )
            ]
        )
        candidates = br.find_candidates(
            matrix,
            grouping(
                matrix,
                privilege_order=["tenant_user", "billing_admin", "platform_admin"],
            ),
        )
        inverted = [item for item in candidates if item.rule == "inverted_guard"]
        self.assertEqual([item.identity for item in inverted], ["tenant_user"])
        self.assertIn(br.TAG_HIGHER_IDENTITY_ABSENT, inverted[0].tags)
        self.assertTrue(
            any("not a total order" in mode for mode in inverted[0].false_positive_modes)
        )

    def test_it_does_not_run_without_a_declared_privilege_order(self) -> None:
        matrix = make_matrix(
            [("GET /api/reports/quarterly", None, {"tenant_user": 200, "platform_admin": 403})]
        )
        group = grouping(matrix)
        self.assertEqual(operations_for(br.find_candidates(matrix, group), "inverted_guard"), [])
        self.assertIn("privilege_order_absent", [note["code"] for note in group.diagnostics])

    def test_it_does_not_fire_on_an_unknown_cell(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/reports/quarterly",
                    None,
                    {"tenant_user": 200, "platform_admin": "unknown:server_error"},
                )
            ]
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, privilege_order=["tenant_user", "platform_admin"])
        )
        self.assertEqual(operations_for(candidates, "inverted_guard"), [])

    def test_a_per_identity_specimen_disables_the_comparison(self) -> None:
        matrix = make_matrix(
            [("GET /api/tenants/{tid}/profile", "own", {"tenant_user": 200, "platform_admin": 403})],
            not_shared=[("GET /api/tenants/{tid}/profile", "own")],
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, privilege_order=["tenant_user", "platform_admin"])
        )
        self.assertEqual(operations_for(candidates, "inverted_guard"), [])

    def test_405_from_the_higher_identity_is_not_read_as_a_guard(self) -> None:
        matrix = make_matrix(
            [("GET /api/reports/quarterly", None, {"tenant_user": 200, "platform_admin": 405})]
        )
        candidates = br.find_candidates(
            matrix, grouping(matrix, privilege_order=["tenant_user", "platform_admin"])
        )
        self.assertEqual(operations_for(candidates, "inverted_guard"), [])


# ---------------------------------------------------------------------------
# Rule B -- peer_divergence
# ---------------------------------------------------------------------------


class PeerDivergenceTest(unittest.TestCase):
    def three_member_matrix(self, **overrides: Any) -> AccessMatrix:
        row: dict[str, Any] = {"alice": 200, "bob": 403, "carol": 403}
        row.update(overrides)
        return make_matrix([("GET /api/reports/{id}", "shared_report", row)])

    def test_a_single_reacher_on_a_shared_object_is_its_owner_and_raises_nothing(
        self,
    ) -> None:
        # REGRESSION (precision, and the rule's orientation). One object, one
        # owner: exactly one member reaching and the rest refused is the guard
        # WORKING. The rule used to report precisely this, on every correctly
        # authorized object in the target, and only this.
        for size in (2, 3, 5):
            with self.subTest(group_size=size):
                members = [f"peer{index}" for index in range(size)]
                row = {member: 403 for member in members}
                row[members[0]] = 200
                matrix = make_matrix([("GET /api/reports/{id}", "shared_report", row)])
                group = grouping(matrix, peer_groups={"tenant_users": members})
                suppressions: dict[str, int] = {}
                candidates = [
                    item
                    for item in br.find_candidates(
                        matrix, group, suppressions=suppressions
                    )
                    if item.rule == "peer_divergence"
                ]
                self.assertEqual(candidates, [])
                self.assertEqual(
                    suppressions.get(
                        "peer_divergence_single_reacher_is_the_owner"
                    ),
                    1,
                )

    def test_true_case_two_reachers_on_one_shared_object_is_the_candidate(self) -> None:
        # REGRESSION (recall). Owner plus attacker on one shared object is the
        # classic IDOR this rule names in its own shape line, and it was
        # structurally invisible at every group size: the majority guard and the
        # `len(reached) != 1` unanimity clause each excluded it on their own.
        for size in (3, 4, 5):
            with self.subTest(group_size=size):
                members = ["owner", "attacker"] + [
                    f"peer{index}" for index in range(size - 2)
                ]
                row = {member: 403 for member in members}
                row["owner"] = 200
                row["attacker"] = 200
                matrix = make_matrix([("GET /api/reports/{id}", "shared_report", row)])
                group = grouping(matrix, peer_groups={"tenant_users": members})
                candidates = [
                    item
                    for item in br.find_candidates(matrix, group)
                    if item.rule == "peer_divergence"
                ]
                self.assertEqual(
                    sorted(item.identity for item in candidates),
                    ["attacker", "owner"],
                )
                for candidate in candidates:
                    self.assertIn(br.TAG_OWNER_UNIDENTIFIED, candidate.tags)
                    self.assertIn("at most one of", candidate.explanation)

    def test_a_marker_naming_the_owner_leaves_only_the_other_reacher(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "alice_invoice",
                    {
                        "alice": {"status": 200, "marker": "present", "marker_owner": "alice"},
                        "bob": 200,
                        "carol": 403,
                    },
                )
            ],
            marker_owner="alice",
        )
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        candidates = [
            item
            for item in br.find_candidates(matrix, group)
            if item.rule == "peer_divergence"
        ]
        self.assertEqual([item.identity for item in candidates], ["bob"])
        self.assertNotIn(br.TAG_OWNER_UNIDENTIFIED, candidates[0].tags)
        self.assertIn(("marker_identified_owner", "alice"), candidates[0].evidence)

    def test_refusals_that_are_all_404_need_a_marker_to_arbitrate(self) -> None:
        # 404 is "absent or denied" and indistinguishable from routing: a
        # tenant-shared object that simply does not exist for another tenant
        # produces exactly this shape, and it is benign. With a marker naming
        # the owner the crossing is physical, so that case survives.
        row = {"alice": 200, "bob": 200, "carol": 404}
        matrix = make_matrix([("GET /api/announcements/{id}", "shared", row)])
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        suppressions: dict[str, int] = {}
        self.assertEqual(
            [
                item
                for item in br.find_candidates(matrix, group, suppressions=suppressions)
                if item.rule == "peer_divergence"
            ],
            [],
        )
        self.assertEqual(
            suppressions.get("peer_divergence_refusals_are_all_absent_or_denied"), 1
        )

        marked = make_matrix(
            [
                (
                    "GET /api/announcements/{id}",
                    "shared",
                    {
                        "alice": {"status": 200, "marker": "present", "marker_owner": "alice"},
                        "bob": 200,
                        "carol": 404,
                    },
                )
            ],
            marker_owner="alice",
        )
        group = grouping(marked, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        candidates = [
            item
            for item in br.find_candidates(marked, group)
            if item.rule == "peer_divergence"
        ]
        self.assertEqual([item.identity for item in candidates], ["bob"])

    def test_false_positive_case_a_genuinely_shared_resource_produces_nothing(self) -> None:
        # Every member of the group reaches the team changelog, because it is
        # shared by design. There is no inconsistency, so there is no candidate.
        matrix = make_matrix(
            [
                ("GET /api/team/changelog", None, {"alice": 200, "bob": 200, "carol": 200}),
                ("GET /api/notes/{id}", "team_note", {"alice": 200, "bob": 200, "carol": 200}),
            ]
        )
        group = grouping(matrix, peer_groups={"team": ["alice", "bob", "carol"]})
        self.assertEqual(br.find_candidates(matrix, group), [])

    def test_false_positive_case_an_owned_object_produces_nothing_at_all(self) -> None:
        # REGRESSION (precision). The specimen is an object alice owns: her
        # reaching it and her peers being refused are both correct. This used to
        # be reported and merely tagged; ownership is now handled by the rule's
        # arithmetic, so there is nothing to rank down.
        matrix = make_matrix(
            [
                (
                    "GET /api/invoices/{id}",
                    "alice_invoice",
                    {
                        "alice": {"status": 200, "marker": "present", "marker_owner": "alice"},
                        "bob": 404,
                        "carol": 404,
                    },
                ),
                ("GET /api/reports/{id}", "shared_report", {"alice": 200, "bob": 403, "carol": 403}),
            ],
            marker_owner="alice",
        )
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        candidates = [
            item for item in br.find_candidates(matrix, group) if item.rule == "peer_divergence"
        ]
        self.assertEqual(candidates, [])
        self.assertTrue(
            any(
                "Ownership is handled" in mode
                for mode in br.RULES["peer_divergence"].false_positive_modes
            )
        )

    def test_a_per_identity_specimen_disables_the_rule_for_that_operation(self) -> None:
        matrix = make_matrix(
            [("GET /api/tenants/{tid}/users/{uid}", "own_user", {"alice": 200, "bob": 404, "carol": 404})],
            not_shared=[("GET /api/tenants/{tid}/users/{uid}", "own_user")],
        )
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        self.assertEqual(br.find_candidates(matrix, group), [])
        notes = {note["code"] for note in br.discovery_notes(matrix, group)}
        self.assertIn("not_comparable_per_identity_specimen", notes)

    def test_it_does_not_fire_when_any_peer_cell_is_unknown(self) -> None:
        matrix = self.three_member_matrix(carol="unknown:skipped_no_specimen")
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        self.assertEqual(br.find_candidates(matrix, group), [])

    def test_unanimous_now_means_every_member_has_a_verdict(self) -> None:
        # REGRESSION. `peer_divergence_unanimous` used to additionally require
        # exactly one reacher, which is what made the two-reacher bug shape
        # unreachable at the default. It now means only what its name says:
        # every active member must have a definite reached/refused verdict.
        members = {"tenant_users": ["alice", "bob", "carol", "dave", "erin"]}
        complete = make_matrix(
            [
                (
                    "GET /api/reports/{id}",
                    "shared_report",
                    {"alice": 200, "bob": 200, "carol": 403, "dave": 403, "erin": 403},
                )
            ]
        )
        candidates = br.find_candidates(
            complete, grouping(complete, peer_groups=members)
        )
        self.assertEqual(sorted(item.identity for item in candidates), ["alice", "bob"])
        for candidate in candidates:
            self.assertNotIn(br.TAG_NON_UNANIMOUS, candidate.tags)
            self.assertEqual(candidate.consensus, (3, 4))

        partial = make_matrix(
            [
                (
                    "GET /api/reports/{id}",
                    "shared_report",
                    {
                        "alice": 200,
                        "bob": 200,
                        "carol": 403,
                        "dave": 403,
                        "erin": 302,
                    },
                )
            ]
        )
        suppressions: dict[str, int] = {}
        strict = grouping(partial, peer_groups=members)
        self.assertEqual(
            br.find_candidates(partial, strict, suppressions=suppressions), []
        )
        self.assertEqual(
            suppressions.get("peer_divergence_group_not_unanimous"), 1
        )
        relaxed = grouping(partial, peer_groups=members, unanimous=False)
        relaxed_candidates = br.find_candidates(partial, relaxed)
        self.assertEqual(
            sorted(item.identity for item in relaxed_candidates), ["alice", "bob"]
        )
        for candidate in relaxed_candidates:
            self.assertIn(br.TAG_NON_UNANIMOUS, candidate.tags)

    def test_a_suppressed_peer_never_stands_in_as_a_denial(self) -> None:
        # bob's whole row is 401: the target never accepted his credential. If
        # that counted as a refusal, alice would be reported as diverging from
        # a peer that was never authenticated at all.
        matrix = make_matrix(
            [
                ("GET /api/reports/{id}", "shared_report", {"alice": 200, "bob": 401, "carol": 200}),
                ("GET /api/reports/daily", None, {"alice": 200, "bob": 401, "carol": 200}),
            ]
        )
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        self.assertEqual(group.suppressed, ("bob",))
        self.assertEqual(br.find_candidates(matrix, group), [])

    def test_a_peer_that_presents_no_credential_is_the_denial(self) -> None:
        # The same 401 row, and the opposite meaning. `anonymous` is declared
        # the way the README asks -- `"headers": {}` -- so its 401 everywhere
        # is the boundary working, not a credential the target rejected.
        # Suppressing it deleted the only refusal on the row, and with it the
        # one thing peer_divergence exists to notice: two tenants reading the
        # same specimen while a peer is refused. No marker is declared here on
        # purpose. With one, marker_reach still fires and the row is merely
        # under-reported; without one, suppression makes the row silent.
        matrix = make_matrix(
            [
                ("GET /api/invoices/{id}", "shared_invoice",
                 {"owner": 200, "other_tenant": 200, "anonymous": 401}),
                ("GET /api/profile", None,
                 {"owner": 200, "other_tenant": 200, "anonymous": 401}),
            ]
        )
        group = grouping(
            matrix,
            peer_groups={"tenants": ["owner", "other_tenant", "anonymous"]},
            headers={
                "owner": {"headers": {"Authorization": "Bearer owner"}},
                "other_tenant": {"headers": {"Authorization": "Bearer other"}},
                "anonymous": {"headers": {}},
            },
        )
        self.assertEqual(group.suppressed, ())
        candidates = br.find_candidates(matrix, group)
        self.assertIn("peer_divergence", rules_fired(candidates))
        self.assertIn(
            "GET /api/invoices/{id}", operations_for(candidates, "peer_divergence")
        )

    def test_a_benign_header_is_not_a_credential(self) -> None:
        """The M1 regression survived its own fix for most anonymous identities.

        Many targets 406 without an `Accept` header, so a real anonymous
        identity carries one. Counting ANY header as a credential meant that
        identity was still suppressed from every rule -- and told "the target
        never accepted this credential" about a credential it does not send.
        """
        matrix = make_matrix([
            ("GET /api/invoices/{id}", "shared_invoice",
             {"alice": 200, "bob": 200, "anon": 401}),
            ("GET /api/profile", None, {"alice": 200, "bob": 200, "anon": 401}),
        ])
        for headers in ({}, {"Accept": "application/json"},
                        {"User-Agent": "veridor", "Accept": "*/*"}):
            with self.subTest(headers=headers):
                group = grouping(
                    matrix,
                    peer_groups={"tenants": ["alice", "bob", "anon"]},
                    headers={
                        "alice": {"headers": {"Authorization": "Bearer a"}},
                        "bob": {"headers": {"Authorization": "Bearer b"}},
                        "anon": {"headers": headers},
                    },
                )
                self.assertEqual(group.suppressed, ())
                self.assertIn(
                    "peer_divergence", rules_fired(br.find_candidates(matrix, group))
                )

    def test_the_declared_unauthenticated_identity_is_never_a_credential(self) -> None:
        """The operator's declaration settles the question the headers cannot."""
        config = {
            "identities": {
                "alice": {"headers": {"Authorization": "Bearer a"}},
                # A custom auth header WOULD read as a credential -- but the
                # operator has said this identity is the unauthenticated one.
                "anon": {"headers": {"X-Api-Key": ""}},
            },
            "matrix": {"unauthenticated": "anon"},
        }
        self.assertEqual(
            br.credential_bearing_identities(config, ("alice", "anon")),
            frozenset({"alice"}),
        )

    def test_one_unmeasured_member_does_not_delete_the_row(self) -> None:
        """A failed probe for one peer erased a cross-tenant read for the others.

        `peer_divergence` vetoed the whole row if ANY active member's cell was
        unmeasured. Un-suppressing the no-credential identity moved it into
        `active`, so a single missed probe for `anon` deleted candidates the
        previous code emitted -- with no counter, so nothing was printed.
        """
        matrix = make_matrix([
            ("GET /api/invoices/{id}", "shared_invoice",
             {"owner": 200, "other_tenant": 200, "third": 403,
              "anon": "unknown:transport_error"}),
            ("GET /api/profile", None,
             {"owner": 200, "other_tenant": 200, "third": 403, "anon": 401}),
        ])
        group = grouping(
            matrix,
            peer_groups={"tenants": ["owner", "other_tenant", "third", "anon"]},
            headers={
                "owner": {"headers": {"Authorization": "Bearer o"}},
                "other_tenant": {"headers": {"Authorization": "Bearer t"}},
                "third": {"headers": {"Authorization": "Bearer h"}},
                "anon": {"headers": {}},
            },
        )
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(matrix, group, suppressions=suppressions)
        invoice = [
            item for item in candidates
            if item.rule == "peer_divergence" and "invoices" in item.operation
        ]
        self.assertTrue(invoice, "the cross-tenant read was deleted by an absent probe")
        # Counted, not silent: the operator is told a member was dropped.
        self.assertEqual(suppressions.get("peer_divergence_member_unmeasured"), 1)

    def test_a_rejected_credential_is_still_suppressed(self) -> None:
        # The negative half. An identity that DOES present something and is
        # refused everywhere is a stale token, and the suppression it earns is
        # the one the rule was built for. Without this test the guard above can
        # be widened later until nothing is ever suppressed.
        matrix = make_matrix(
            [
                ("GET /api/invoices/{id}", "shared_invoice",
                 {"owner": 200, "other_tenant": 200, "stale": 401}),
                ("GET /api/profile", None,
                 {"owner": 200, "other_tenant": 200, "stale": 401}),
            ]
        )
        group = grouping(
            matrix,
            peer_groups={"tenants": ["owner", "other_tenant", "stale"]},
            headers={
                "owner": {"headers": {"Authorization": "Bearer owner"}},
                "other_tenant": {"headers": {"Authorization": "Bearer other"}},
                "stale": {"headers": {"Authorization": "Bearer stale-token"}},
            },
        )
        self.assertEqual(group.suppressed, ("stale",))
        self.assertEqual(br.find_candidates(matrix, group), [])

    def test_a_custom_credential_header_is_still_a_credential(self) -> None:
        # REGRESSION. Only six header names counted as a credential, so a
        # stale GitLab `PRIVATE-TOKEN` read as "presents nothing": not
        # suppressed, no stale-credential warning, and -- as the only identity
        # outside the list -- inferred to BE the unauthenticated identity with
        # a note saying its headers map was empty. Its zero reach then read as
        # posture. A header this module does not recognise is the conservative
        # case: it counts.
        matrix = make_matrix([
            ("GET /api/invoices/{id}", "shared_invoice", {"admin": 200, "svc": 401}),
            ("GET /api/profile", None, {"admin": 200, "svc": 401}),
        ])
        for name in ("PRIVATE-TOKEN", "X-Access-Token", "X-Api-Key"):
            with self.subTest(header=name):
                config = {
                    "identities": {
                        "admin": {"headers": {"Authorization": "Bearer a"}},
                        "svc": {"headers": {name: "stale"}},
                    },
                    "matrix": {"peer_groups": {"all": ["admin", "svc"]}},
                }
                group = br.peer_groups(config, matrix)
                self.assertEqual(group.suppressed, ("svc",))
                self.assertIsNone(group.unauthenticated)
                self.assertNotIn(
                    "unauthenticated_identity_inferred",
                    [note["code"] for note in group.diagnostics],
                )
                report = br.blast_radius_report(
                    matrix, br.credential_bearing_identities(config, matrix.identities)
                )
                svc = [e for e in report["identities"] if e["identity"] == "svc"][0]
                self.assertTrue(svc["row_uniformly_unauthenticated"])

    #: Headers an anonymous browser or SPA client sends on every request. None
    #: of them is a credential.
    SPA_HEADERS: tuple[str, ...] = (
        "Origin", "Referer", "X-Requested-With", "DNT", "If-None-Match",
        "If-Modified-Since", "Range", "Sec-Fetch-Mode", "Sec-Fetch-Site",
        "Sec-CH-UA", "Traceparent", "Tracestate", "X-Request-Id",
        "X-Correlation-Id", "Upgrade-Insecure-Requests", "Accept-Language",
        "Content-Length", "Sec-CH-UA-Platform", "Sec-GPC", "Sec-Purpose",
    )

    def test_a_standard_request_header_is_not_a_credential(self) -> None:
        # REGRESSION. The benign list stopped at eight content-negotiation
        # names, so an anonymous SPA identity sending `Origin`, `Referer` or
        # `X-Requested-With` was counted as presenting a credential: with 401
        # everywhere it was suppressed from every rule and told the target
        # never accepted a credential it does not send, and with
        # matrix.unauthenticated undeclared it was no longer inferred as the
        # unauthenticated identity, so unauthenticated_reach lost its candidate.
        refused = make_matrix([
            ("GET /api/profile", None, {"admin": 200, "anon": 401}),
            ("GET /api/public", None, {"admin": 200, "anon": 401}),
        ])
        reached = make_matrix([
            ("GET /api/invoices", None, {"admin": 200, "anon": 200}),
            ("GET /api/profile", None, {"admin": 200, "anon": 401}),
        ])
        for name in self.SPA_HEADERS:
            with self.subTest(header=name):
                config = {
                    "identities": {
                        "admin": {"headers": {"Authorization": "Bearer a"}},
                        "anon": {"headers": {name: "x", "Accept": "*/*"}},
                    },
                    "matrix": {},
                }
                group = br.peer_groups(config, refused)
                self.assertEqual(group.suppressed, ())
                self.assertEqual(group.unauthenticated, "anon")
                group = br.peer_groups(config, reached)
                self.assertEqual(
                    operations_for(
                        br.find_candidates(reached, group), "unauthenticated_reach"
                    ),
                    ["GET /api/invoices"],
                )

    def test_a_benign_prefix_does_not_cover_a_lookalike_credential_header(self) -> None:
        # The broadened benign set matches `Accept-*`, `If-*`, `Sec-Fetch-*`
        # and `Sec-CH-*` by prefix. The prefix stops at the hyphen, so a
        # credential whose name merely starts with the same letters still
        # counts. REGRESSION: the prefix was `Sec-*`, which also covered
        # `Sec-WebSocket-Protocol` -- the Kubernetes API server accepts a
        # bearer token in it as `base64url.bearer.authorization.k8s.io.<token>`.
        # An identity whose only credential was there read as sending none,
        # so a stale one was not suppressed and it was inferred as the
        # unauthenticated identity.
        matrix = make_matrix([("GET /api/profile", None, {"admin": 200, "svc": 401})])
        for name in ("Secret-Token", "Accepted-Token", "Iframe-Session",
                     "X-Origin-Token", "X-CSRF-Token", "X-Forwarded-For",
                     "Sec-WebSocket-Protocol", "sec-websocket-protocol"):
            with self.subTest(header=name):
                config = {
                    "identities": {
                        "admin": {"headers": {"Authorization": "Bearer a"}},
                        "svc": {"headers": {name: "stale"}},
                    },
                    "matrix": {},
                }
                self.assertEqual(br.peer_groups(config, matrix).suppressed, ("svc",))

    def test_the_ambiguous_note_does_not_claim_an_empty_headers_map(self) -> None:
        # The inferred note was corrected first; its sibling still said
        # the candidates "have an empty headers map", false for an identity
        # that sends only Accept or Origin.
        group = grouping(
            make_matrix([("GET /api/profile", None, {"a": 200, "b": 401, "c": 401})]),
            headers={
                "a": {"headers": {"Authorization": "Bearer a"}},
                "b": {"headers": {"Accept": "*/*"}},
                "c": {"headers": {"Origin": "https://app.example"}},
            },
        )
        notes = [n for n in group.diagnostics
                 if n["code"] == "unauthenticated_identity_ambiguous"]
        self.assertEqual(len(notes), 1)
        self.assertNotIn("empty headers map", notes[0]["message"])
        self.assertIn("no credential header", notes[0]["message"])

    def test_the_session_backed_note_does_not_name_an_empty_headers_heuristic(self) -> None:
        # The first fix stopped inferring the unauthenticated identity from an
        # empty headers map; it now looks for an identity that sends no
        # credential header. The ambiguous note was corrected next,
        # but this sibling still blamed "the empty-headers heuristic".
        group = grouping(
            make_matrix([("GET /api/profile", None, {"a": 200, "s": 200})]),
            headers={
                "a": {"headers": {"Authorization": "Bearer a"}},
                "s": {"session": {"establishes": {"cookie": "sessionid"}}},
            },
        )
        notes = [n for n in group.diagnostics
                 if n["code"] == "unauthenticated_identity_session_backed"]
        self.assertEqual(len(notes), 1)
        self.assertNotIn("empty-headers", notes[0]["message"])
        self.assertNotIn("empty headers", notes[0]["message"])
        self.assertIn("no credential header", notes[0]["message"])

    def test_no_credential_no_rejected_credential_claim(self) -> None:
        # The report and the render line said "the target never accepted this
        # credential" about an identity that sent none. The vocabulary police
        # never sees these two strings -- no shipped fixture triggers the
        # suppression -- so they are asserted here directly.
        matrix = make_matrix(
            [("GET /api/profile", None, {"owner": 200, "anonymous": 401})]
        )
        config = {
            "identities": {
                "owner": {"headers": {"Authorization": "Bearer owner"}},
                "anonymous": {"headers": {}},
            },
            "matrix": {},
        }
        credentialed = br.credential_bearing_identities(config, matrix.identities)
        self.assertEqual(credentialed, frozenset({"owner"}))
        report = br.blast_radius_report(matrix, credentialed)
        anonymous = [
            entry for entry in report["identities"] if entry["identity"] == "anonymous"
        ][0]
        self.assertFalse(anonymous["row_uniformly_unauthenticated"])
        text = br.render_blast_radius(report)
        self.assertNotIn("never accepted this credential", text)
        self.assertEqual(
            [note["code"] for note in br.peer_groups(config, matrix).diagnostics
             if note["code"] == "row_uniformly_unauthenticated"],
            [],
        )


# ---------------------------------------------------------------------------
# Rule A -- sibling_asymmetry
# ---------------------------------------------------------------------------


class SiblingAsymmetryTest(unittest.TestCase):
    def test_true_case_eleven_of_twelve_siblings_refused(self) -> None:
        grid = family_grid(
            [f"r{index}" for index in range(11)], ["quarterly"], "outsider"
        )
        matrix = make_matrix(grid)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual([item.operation for item in candidates], ["GET /api/reports/quarterly"])
        self.assertEqual(candidates[0].consensus, (11, 12))
        self.assertEqual(candidates[0].tags, ())
        self.assertIn("11 of 12 sibling operations under /api/reports", candidates[0].explanation)

    def test_the_advertised_minimum_family_size_can_actually_fire(self) -> None:
        # REGRESSION. min_family_size advertised 5, but the archetype
        # the rule exists to find -- refused on all but one sibling -- has
        # consensus (n-1)/n, so the old family_consensus of 0.85 meant families
        # of 5 (0.800) and 6 (0.833) passed the size gate and were then always
        # discarded. The advertised sensitivity did not exist, and most real
        # APIs have 2-5 siblings under a parent path.
        for width in (5, 6, 7, 8):
            with self.subTest(family_size=width):
                names = [f"r{index}" for index in range(width - 1)]
                grid = family_grid(names, ["odd"], "outsider")
                matrix = make_matrix(grid)
                candidates = [
                    item
                    for item in br.find_candidates(matrix, grouping(matrix))
                    if item.rule == "sibling_asymmetry"
                ]
                self.assertEqual(
                    [item.operation for item in candidates],
                    ["GET /api/reports/odd"],
                    f"a family of {width} with one anomalous reach must fire",
                )
                self.assertEqual(candidates[0].consensus, (width - 1, width))

    def test_the_options_refuse_a_combination_that_can_never_fire(self) -> None:
        # The two defaults are now checked against each other rather than
        # silently disagreeing.
        with self.assertRaises(br.BlastRadiusError) as raised:
            br.CandidateOptions(min_family_size=4, min_refused_siblings=4)
        self.assertIn("can never produce a candidate", str(raised.exception))

    def test_more_anomalous_reaches_do_not_make_the_rule_quieter(self) -> None:
        # REGRESSION. The old gate was a fraction of the whole
        # family, so every extra operation the identity reached LOWERED it: a
        # 7-member family fired on one anomalous reach (6/7 = 0.857) and went
        # silent on two (5/7 = 0.714). Detection fell as the problem got worse,
        # and planting a real second reach deleted the candidate the first one
        # had produced.
        for reaches in (1, 2):
            with self.subTest(anomalous_reaches=reaches):
                refused = [f"r{index}" for index in range(7 - reaches)]
                reached = [f"open{index}" for index in range(reaches)]
                matrix = make_matrix(family_grid(refused, reached, "outsider"))
                candidates = [
                    item
                    for item in br.find_candidates(matrix, grouping(matrix))
                    if item.rule == "sibling_asymmetry"
                ]
                self.assertEqual(
                    sorted(item.operation for item in candidates),
                    sorted(f"GET /api/reports/{name}" for name in reached),
                )

    def test_a_family_the_identity_mostly_reaches_is_not_a_consensus(self) -> None:
        # The other side of the same knob, and the rule's own declared failure
        # mode: a semantically mixed prefix (4 refused beside 3 reached) is not
        # a consensus and must stay silent, or every /api/config/* in the world
        # becomes three candidates.
        matrix = make_matrix(
            family_grid(["secrets", "integrations", "webhooks", "keys"],
                        ["public", "flags", "locales"], "outsider")
        )
        suppressions: dict[str, int] = {}
        self.assertEqual(
            operations_for(
                br.find_candidates(matrix, grouping(matrix), suppressions=suppressions),
                "sibling_asymmetry",
            ),
            [],
        )
        self.assertIn(
            "sibling_asymmetry_reaches_are_not_the_exception", suppressions
        )

    def test_a_family_below_the_minimum_size_stays_silent(self) -> None:
        grid = family_grid(["a", "b", "c"], ["d"], "outsider")
        matrix = make_matrix(grid)
        self.assertEqual(
            operations_for(br.find_candidates(matrix, grouping(matrix)), "sibling_asymmetry"),
            [],
        )

    def test_false_positive_case_a_capability_probe_open_to_everyone_is_excluded(
        self,
    ) -> None:
        # The rule's second stated failure mode, and three of the four survivors
        # on the zero-bug fixture: /api/admin/whoami answers every caller so a
        # single-page app can decide whether to draw the admin nav. Each of the
        # three tenant identities is refused across the rest of /api/admin/ and
        # reaches that one, so the rule fired once PER IDENTITY -- the list grew
        # with the number of identities probed rather than with anything
        # anomalous.
        closed = ("users", "settings", "audit", "billing", "jobs")
        grid: list[tuple[str, str | None, dict[str, Any]]] = [
            (f"GET /api/admin/{name}", None,
             {"alice": 403, "bob": 403, "carol": 403, "admin": 200})
            for name in closed
        ]
        grid.append(("GET /api/admin/whoami", None,
                     {"alice": 200, "bob": 200, "carol": 200, "admin": 200}))
        matrix = make_matrix(grid)
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(
            matrix, grouping(matrix), suppressions=suppressions
        )
        self.assertEqual(operations_for(candidates, "sibling_asymmetry"), [])
        self.assertEqual(
            suppressions.get("sibling_asymmetry_reached_by_several_locked_out_identities"),
            3,
        )

    def test_a_sibling_open_to_exactly_one_locked_out_identity_still_fires(self) -> None:
        # The exclusion above must not be "wide families are boring". The same
        # family, with a second open sibling that only ONE locked-out identity
        # reaches, still surfaces that one -- and only that one.
        closed = ("users", "settings", "audit", "billing", "jobs")
        grid: list[tuple[str, str | None, dict[str, Any]]] = [
            (f"GET /api/admin/{name}", None,
             {"alice": 403, "bob": 403, "carol": 403, "admin": 200})
            for name in closed
        ]
        grid.append(("GET /api/admin/whoami", None,
                     {"alice": 200, "bob": 200, "carol": 200, "admin": 200}))
        grid.append(("GET /api/admin/keys", None,
                     {"alice": 403, "bob": 403, "carol": 200, "admin": 200}))
        matrix = make_matrix(grid)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual(
            [(item.identity, item.operation) for item in candidates],
            [("carol", "GET /api/admin/keys")],
        )

    def test_the_exclusion_is_per_sibling_not_per_family(self) -> None:
        # Two identities reaching DIFFERENT siblings is two independent
        # exceptions, not one open route, and both stand.
        closed = ("users", "settings", "audit", "billing", "jobs", "jobs2")
        grid: list[tuple[str, str | None, dict[str, Any]]] = [
            (f"GET /api/admin/{name}", None, {"alice": 403, "bob": 403, "admin": 200})
            for name in closed
        ]
        grid.append(("GET /api/admin/keys", None,
                     {"alice": 200, "bob": 403, "admin": 200}))
        grid.append(("GET /api/admin/tokens", None,
                     {"alice": 403, "bob": 200, "admin": 200}))
        matrix = make_matrix(grid)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual(
            sorted((item.identity, item.operation) for item in candidates),
            [
                ("alice", "GET /api/admin/keys"),
                ("bob", "GET /api/admin/tokens"),
            ],
        )

    def test_false_positive_case_a_collection_in_an_item_family_is_tagged_last(self) -> None:
        # /api/orders/summary is a COLLECTION; its siblings are ITEMs carrying
        # somebody else's identifier and are correctly refused. The rule fires,
        # so the failure mode is named on the candidate and it ranks last.
        grid: list[tuple[str, str | None, dict[str, Any]]] = [
            ("GET /api/orders/{id}", f"item_{index}", {"outsider": 404, "owner": 200})
            for index in range(3)
        ]
        grid += [
            ("GET /api/orders/{code}", f"code_{index}", {"outsider": 404, "owner": 200})
            for index in range(3)
        ]
        grid.append(("GET /api/orders/summary", None, {"outsider": 200, "owner": 200}))
        matrix = make_matrix(grid, max_specimens=3)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual([item.operation for item in candidates], ["GET /api/orders/summary"])
        self.assertIn(br.TAG_COLLECTION_VS_ITEM, candidates[0].tags)
        self.assertTrue(
            any(
                "Collection-versus-item" in mode
                for mode in candidates[0].false_positive_modes
            )
        )

    def test_an_item_reached_in_an_item_family_carries_no_collection_tag(self) -> None:
        grid: list[tuple[str, str | None, dict[str, Any]]] = [
            ("GET /api/orders/{id}", f"item_{index}", {"outsider": 404, "owner": 200})
            for index in range(3)
        ]
        grid += [
            ("GET /api/orders/{code}", f"code_{index}", {"outsider": 404, "owner": 200})
            for index in range(3)
        ]
        grid.append(("GET /api/orders/{ref}", "ref_0", {"outsider": 200, "owner": 200}))
        matrix = make_matrix(grid, max_specimens=3)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].tags, ())

    def test_one_unknown_member_is_dropped_and_counted(self) -> None:
        # REWRITTEN. This test was `..._silences_the_whole_family` and pinned
        # the defect: one unmeasured sibling vetoed the family for that
        # identity with a bare `continue`, counted nowhere, so the output was
        # indistinguishable from a family with no asymmetry. What it protects
        # still holds -- the unknown is not read as a refusal: it is dropped,
        # the consensus is over the ten measured refusals, and the drop is
        # counted. Same policy as peer_divergence_member_unmeasured.
        grid = family_grid([f"r{index}" for index in range(11)], ["quarterly"], "outsider")
        grid[0] = (grid[0][0], None, {"outsider": "unknown:server_error", "owner": 200})
        matrix = make_matrix(grid)
        suppressions: dict[str, int] = {}
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix), suppressions=suppressions)
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual([item.operation for item in candidates], ["GET /api/reports/quarterly"])
        self.assertEqual(candidates[0].consensus, (10, 11))
        self.assertEqual(suppressions.get("sibling_asymmetry_member_unmeasured"), 1)

    def test_an_unknown_subject_raises_nothing(self) -> None:
        # The other half: the reach itself unmeasured is no reach at all.
        grid = family_grid([f"r{index}" for index in range(11)], ["quarterly"], "outsider")
        grid[-1] = (grid[-1][0], None, {"outsider": "unknown:server_error", "owner": 200})
        matrix = make_matrix(grid)
        self.assertEqual(
            operations_for(br.find_candidates(matrix, grouping(matrix)), "sibling_asymmetry"),
            [],
        )

    def test_a_sibling_with_no_specimen_does_not_switch_the_family_off(self) -> None:
        # REGRESSION. A templated sibling with no specimen (or an ignored one)
        # is a row that is unknown for every identity, and it turned the rule
        # off for the whole family -- for every identity, with suppressions {}.
        grid = family_grid([f"r{index}" for index in range(5)], ["odd"], "mallory")
        grid.append((
            "GET /api/reports/{id}", None,
            {"mallory": "unknown:skipped_no_specimen", "owner": "unknown:skipped_no_specimen"},
        ))
        matrix = make_matrix(grid)
        suppressions: dict[str, int] = {}
        candidates = br.find_candidates(matrix, grouping(matrix), suppressions=suppressions)
        self.assertEqual(
            operations_for(candidates, "sibling_asymmetry"), ["GET /api/reports/odd"]
        )
        # Counted once per identity the row was dropped for: mallory and owner.
        self.assertEqual(suppressions.get("sibling_asymmetry_member_unmeasured"), 2)

    def test_405_members_are_excluded_from_the_consensus(self) -> None:
        grid = family_grid([f"r{index}" for index in range(11)], ["quarterly"], "outsider")
        grid[0] = (grid[0][0], None, {"outsider": 405, "owner": 200})
        matrix = make_matrix(grid)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        # 10 refused of 11 considered; the 405 is neither a refusal nor a member.
        self.assertEqual(candidates[0].consensus, (10, 11))

    def test_ranking_prefers_the_larger_disagreement(self) -> None:
        grid = family_grid([f"r{index}" for index in range(11)], ["quarterly"], "outsider")
        grid += family_grid(
            [f"l{index}" for index in range(7)],
            ["summary"],
            "outsider",
            prefix="/api/ledgers",
        )
        matrix = make_matrix(grid)
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "sibling_asymmetry"
        ]
        self.assertEqual(
            [item.consensus for item in candidates], [(11, 12), (7, 8)]
        )

    def test_the_family_key_ignores_only_the_final_segment(self) -> None:
        self.assertEqual(
            br._family_key("GET /api/reports/daily"), ("GET", ("api", "reports"))
        )
        self.assertEqual(
            br._family_key("GET /api/tenants/{tid}/users/{uid}"),
            ("GET", ("api", "tenants", "{}", "users")),
        )
        self.assertNotEqual(
            br._family_key("GET /api/invoices"), br._family_key("GET /api/invoices/{id}")
        )


# ---------------------------------------------------------------------------
# Rule C -- method_asymmetry, and the coverage gap that is NOT a candidate
# ---------------------------------------------------------------------------


class MethodAsymmetryTest(unittest.TestCase):
    def test_true_case_two_probed_verbs_disagree(self) -> None:
        matrix = make_matrix(
            [
                ("GET /api/widgets/{id}", "widget", {"outsider": 403}),
                ("PUT /api/widgets/{id}", "widget", {"outsider": 200}),
            ]
        )
        candidates = [
            item
            for item in br.find_candidates(matrix, grouping(matrix))
            if item.rule == "method_asymmetry"
        ]
        self.assertEqual([item.operation for item in candidates], ["PUT /api/widgets/{id}"])
        self.assertIn("GET /api/widgets/{id}", candidates[0].explanation)

    def test_false_positive_case_head_versus_get_is_excluded_by_default(self) -> None:
        # Frameworks synthesise HEAD from GET and route it differently often
        # enough that the pair is noise.
        matrix = make_matrix(
            [
                ("GET /api/widgets/{id}", "widget", {"outsider": 403}),
                ("HEAD /api/widgets/{id}", "widget", {"outsider": 200}),
            ]
        )
        self.assertEqual(
            operations_for(br.find_candidates(matrix, grouping(matrix)), "method_asymmetry"),
            [],
        )
        options = br.CandidateOptions(compare_head_with_get=True)
        self.assertEqual(
            operations_for(
                br.find_candidates(matrix, grouping(matrix), options=options),
                "method_asymmetry",
            ),
            ["HEAD /api/widgets/{id}"],
        )

    def test_405_is_never_read_as_a_guard(self) -> None:
        matrix = make_matrix(
            [
                ("GET /api/widgets/{id}", "widget", {"outsider": 200}),
                ("DELETE /api/widgets/{id}", "widget", {"outsider": 405}),
            ]
        )
        self.assertEqual(
            operations_for(br.find_candidates(matrix, grouping(matrix)), "method_asymmetry"),
            [],
        )

    def test_it_does_not_fire_on_an_unknown_cell(self) -> None:
        matrix = make_matrix(
            [
                ("GET /api/widgets/{id}", "widget", {"outsider": 403}),
                ("PUT /api/widgets/{id}", "widget", {"outsider": "unknown:skipped_mutating"}),
            ]
        )
        self.assertEqual(br.find_candidates(matrix, grouping(matrix)), [])

    def test_an_unprobed_sibling_is_a_coverage_gap_and_never_a_candidate(self) -> None:
        matrix = make_matrix(
            [
                ("GET /api/widgets/{id}", "widget", {"outsider": 403}),
                ("DELETE /api/widgets/{id}", "widget", {"outsider": "unknown:skipped_mutating"}),
            ]
        )
        gaps = br.unprobed_siblings(matrix)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["kind"], "coverage_gap")
        self.assertFalse(gaps[0]["is_finding"])
        self.assertNotIn("candidate_id", gaps[0])
        self.assertIn("no observation for DELETE /api/widgets/{id}", gaps[0]["message"])
        self.assertIn("Read-only mode did not probe it.", gaps[0]["message"])
        document = br.candidates_document(matrix, br.find_candidates(matrix, grouping(matrix)))
        self.assertEqual(document["counts"]["candidates"], 0)
        self.assertEqual(len(document["unprobed_siblings"]), 1)


# ---------------------------------------------------------------------------
# the firewall between candidates and findings
# ---------------------------------------------------------------------------


class DisciplineTest(unittest.TestCase):
    def candidate(self) -> br.Candidate:
        matrix = make_matrix(
            [
                (
                    "GET /api/reports/{id}",
                    "shared_report",
                    {"alice": 200, "bob": 200, "carol": 403},
                )
            ]
        )
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        return br.find_candidates(matrix, group)[0]

    def test_a_candidate_dict_has_no_finding_identity_keys(self) -> None:
        entry = self.candidate().to_dict()
        for forbidden in ("id", "verdict", "evidence_grade", "rule_id", "level", "message", "location", "check_id"):
            self.assertNotIn(forbidden, entry, forbidden)
        self.assertIs(entry["is_finding"], False)
        self.assertEqual(entry["status"], "candidate")
        self.assertIn("candidate_id", entry)
        self.assertIn("rule", entry)

    def test_a_candidate_spliced_into_findings_crashes_rather_than_emitting(self) -> None:
        # The structural firewall: core keys findings on finding["id"], which a
        # candidate does not have. A consumer that merges the two lists fails
        # loudly instead of quietly producing a SARIF result.
        from veridor import core

        with self.assertRaises(KeyError):
            core._compare_findings([self.candidate().to_dict()], None)

    def test_a_candidate_would_fail_run_finding_validation(self) -> None:
        entry = self.candidate().to_dict()
        required = {"id", "rule_id", "level", "message", "location", "check_id", "verdict"}
        self.assertEqual(required & set(entry), set())

    def test_the_module_imports_neither_core_nor_sarif(self) -> None:
        tree = ast.parse((ROOT / "src/veridor/blastradius.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                if node.module in {"veridor", ""}:
                    imported.update(f"veridor.{alias.name}" for alias in node.names)
        self.assertNotIn("veridor.core", imported)
        self.assertFalse({name for name in imported if "sarif" in name.lower()})

    def test_the_candidate_id_is_stable_and_in_its_own_namespace(self) -> None:
        first, second = self.candidate(), self.candidate()
        self.assertEqual(first.candidate_id, second.candidate_id)
        self.assertEqual(len(first.candidate_id), 20)
        self.assertTrue(
            br.promotion_stub(first)["id"].startswith("candidate-peer-divergence-")
        )

    def test_ranking_is_byte_stable_across_repeated_runs(self) -> None:
        matrix = load_matrix(FIXTURES / "matrix.observed.json")
        config = json.loads((FIXTURES / "matrix.demo.json").read_text(encoding="utf-8"))
        renders = []
        for _ in range(3):
            group = br.peer_groups(config, matrix)
            candidates = br.find_candidates(matrix, group)
            document = br.candidates_document(matrix, candidates, grouping=group)
            renders.append(json.dumps(document, indent=2, sort_keys=True))
            renders.append(br.render_candidates(document))
        self.assertEqual(len(set(renders[0::2])), 1)
        self.assertEqual(len(set(renders[1::2])), 1)

    def test_the_shipped_demo_pair_echoes_what_its_config_ignored(self) -> None:
        # matrix.demo.json ignores /health. Until the canned matrix recorded
        # that, every shipped pair had ignored == [] and the echo was driven
        # only by synthetic matrices.
        matrix = load_matrix(FIXTURES / "matrix.observed.json")
        config = json.loads((FIXTURES / "matrix.demo.json").read_text(encoding="utf-8"))
        group = br.peer_groups(config, matrix)
        notes = br.discovery_notes(matrix, group)
        note = next(item for item in notes if item["code"] == "ignored_operations")
        self.assertEqual(note["operations"], ["GET /health"])
        document = br.candidates_document(
            matrix, br.find_candidates(matrix, group), grouping=group
        )
        self.assertEqual(document["ignored"], ["GET /health"])
        self.assertNotIn(
            "GET /health",
            {item.operation for item in br.find_candidates(matrix, group)},
        )

    def test_an_all_unknown_row_yields_no_candidate_in_either_direction(self) -> None:
        matrix = make_matrix(
            [
                (
                    "GET /api/reports/{id}",
                    "shared_report",
                    {
                        "alice": "unknown:not_probed",
                        "bob": "unknown:skipped_budget",
                        "carol": "unknown:transport_error",
                    },
                )
            ]
        )
        group = grouping(
            matrix,
            peer_groups={"tenant_users": ["alice", "bob", "carol"]},
            privilege_order=["carol", "bob", "alice"],
            unauthenticated="carol",
        )
        self.assertEqual(br.find_candidates(matrix, group), [])
        radius = br.compute_blast_radius(matrix, "alice")
        self.assertEqual((len(radius.reached), len(radius.refused)), (0, 0))
        self.assertEqual(len(radius.unmeasured), 1)

    def test_an_aborted_matrix_tags_every_surviving_candidate(self) -> None:
        matrix = make_matrix(
            [("GET /api/reports/{id}", "shared_report", {"alice": 200, "bob": 403, "carol": 403})],
            aborted=True,
            abort_reason="hostile_rate",
            issued=3,
            planned=9,
        )
        group = grouping(matrix, peer_groups={"tenant_users": ["alice", "bob", "carol"]})
        candidates = br.find_candidates(matrix, group)
        self.assertTrue(all(br.TAG_PARTIAL_MATRIX in item.tags for item in candidates))

    def test_every_rule_states_its_false_positive_modes(self) -> None:
        for name, rule in br.RULES.items():
            self.assertTrue(rule.false_positive_modes, name)
        with self.assertRaises(br.BlastRadiusError):
            br.Rule(name="nameless", tier=9, shape="x", false_positive_modes=())

    def test_the_rule_tier_order_is_the_documented_one(self) -> None:
        ordered = [rule.name for rule in sorted(br.RULES.values(), key=lambda item: item.tier)]
        self.assertEqual(
            ordered,
            [
                "marker_reach",
                "unauthenticated_reach",
                "inverted_guard",
                "peer_divergence",
                "sibling_asymmetry",
                "method_asymmetry",
            ],
        )


# ---------------------------------------------------------------------------
# vocabulary and artifact hygiene
# ---------------------------------------------------------------------------


class VocabularyTest(unittest.TestCase):
    #: JSON field NAMES fixed by the schema that contain a policed word. The
    #: key `safety` names the run's own request envelope (rate, budget,
    #: methods) -- a fact about how Veridor limited its traffic, not a claim
    #: about the target -- and renaming it is a schema change. Only the key
    #: name is spared: every value beneath it is still checked.
    SCHEMA_KEYS: frozenset[str] = frozenset({"safety"})

    def json_text(self, document: Any) -> str:
        """``json.dumps(document)`` with only the :attr:`SCHEMA_KEYS` names blanked."""
        def strip(node: Any) -> Any:
            if isinstance(node, Mapping):
                return {
                    ("<schema-key>" if key in self.SCHEMA_KEYS else key): strip(value)
                    for key, value in node.items()
                }
            if isinstance(node, list):
                return [strip(item) for item in node]
            return node
        return json.dumps(strip(document))

    def test_the_schema_key_exception_spares_only_the_key(self) -> None:
        # The exception must still be needed (the key is policed and present)
        # and must not hide a policed word in a value under it.
        for key in self.SCHEMA_KEYS:
            self.assertTrue(br.banned_words_in(key), key)
        matrix = load_matrix(FIXTURES / "matrix.observed.json")
        document = br.candidates_document(matrix, [])
        self.assertIn("safety", document)
        self.assertEqual(br.banned_words_in(self.json_text(document)), ())
        document["safety"] = {"posture": "the target is secure"}
        self.assertEqual(br.banned_words_in(self.json_text(document)), ("secure",))
        self.assertEqual(
            br.banned_words_in(self.json_text({"note": "a safety claim"})), ("safety",)
        )

    def rendered(self) -> list[str]:
        texts: list[str] = []
        for name, config_name in CORPUS:
            matrix = load_matrix(FIXTURES / name)
            config = json.loads((FIXTURES / config_name).read_text(encoding="utf-8"))
            group = br.peer_groups(config, matrix)
            suppressions: dict[str, int] = {}
            candidates = br.find_candidates(matrix, group, suppressions=suppressions)
            document = br.candidates_document(
                matrix, candidates, grouping=group, suppressions=suppressions
            )
            texts.append(br.render_candidates(document))
            texts.append(self.json_text(document))
            texts.append(br.render_blast_radius(br.blast_radius_report(matrix)))
        # the zero-candidate rendering too
        empty = make_matrix([("GET /a", None, {"p": 200})])
        texts.append(br.render_candidates(br.candidates_document(empty, [])))
        return texts

    def test_every_rule_fires_somewhere_in_the_corpus(self) -> None:
        fired: set[str] = set()
        for name, config_name in CORPUS:
            matrix = load_matrix(FIXTURES / name)
            config = json.loads((FIXTURES / config_name).read_text(encoding="utf-8"))
            fired |= rules_fired(br.find_candidates(matrix, br.peer_groups(config, matrix)))
        self.assertLessEqual(
            {"marker_reach", "unauthenticated_reach", "inverted_guard", "peer_divergence", "sibling_asymmetry"},
            fired,
        )

    def test_no_rendered_string_asserts_more_than_an_observation(self) -> None:
        for text in self.rendered():
            self.assertEqual(br.banned_words_in(text), (), text[:400])

    def test_no_module_constant_asserts_more_than_an_observation(self) -> None:
        for name, value in vars(br).items():
            if name.startswith("__") or not isinstance(value, str):
                continue
            self.assertEqual(br.banned_words_in(value), (), name)
        for rule in br.RULES.values():
            for mode in rule.false_positive_modes + (rule.shape,):
                self.assertEqual(br.banned_words_in(mode), (), rule.name)

    def test_the_policed_vocabulary_does_not_flag_the_product_name(self) -> None:
        # "Veridor" contains "idor"; a substring check would fail every heading.
        self.assertEqual(br.banned_words_in("Veridor considers the boundary"), ())
        self.assertEqual(br.banned_words_in("this is a vulnerability"), ("vulnerability",))

    def test_the_policed_vocabulary_matches_stem_changing_forms(self) -> None:
        # REGRESSION. Suffixes were appended to the whole base word, so every
        # form that changes the stem walked past the vocabulary tests above:
        # "vulnerabilities", "leakage", "exploitation", "severities",
        # "unauthorised". Those tests read as enforcing the vocabulary and
        # could not fail on any of them.
        for text, word in (
            ("these are vulnerabilities", "vulnerabilities"),
            ("a data leakage", "leakage"),
            ("an exploitation path", "exploitation"),
            ("two severities", "severities"),
            ("an unauthorised read", "unauthorised"),
            ("an insecurity", "insecurity"),
            ("compromising", "compromising"),
        ):
            with self.subTest(text=text):
                self.assertEqual(br.banned_words_in(text), (word,))
        # Control: the forms that always matched still do, and whole-word
        # matching still spares the product name.
        for text, word in (("two leaks", "leaks"), ("leaked", "leaked"),
                           ("unauthorized", "unauthorized"), ("criticality", "criticality")):
            with self.subTest(text=text):
                self.assertEqual(br.banned_words_in(text), (word,))
        self.assertEqual(br.banned_words_in("Veridor's idors"), ("idors",))

    #: Every policed word, with the base and present forms of its stem that
    #: must match, plus the derived forms `br._STEM_FORMS` and
    #: `br._LITERAL_FORMS` list. Those are common derived forms, not every
    #: derived form English has; a derived form absent here is not policed.
    #: `broken` is policed as itself only: its stem is "break", which a report
    #: legitimately uses ("a line break").
    POLICED_FAMILIES: dict[str, tuple[str, ...]] = {
        "vulnerability": ("vulnerability", "vulnerabilities"),
        "vulnerable": ("vulnerable", "vulnerably"),
        "exploit": ("exploit", "exploits", "exploited", "exploiting", "exploitation",
                    "exploiter", "exploiters", "exploitative"),
        "exploitable": ("exploitable", "exploitability", "exploitably"),
        "breach": ("breach", "breaches", "breached", "breaching", "breachable"),
        "leak": ("leak", "leaks", "leaked", "leaking", "leakage", "leaky", "leakier",
                 "leakiest"),
        "insecure": ("insecure", "insecurely", "insecurity"),
        "misconfiguration": ("misconfiguration", "misconfigurations", "misconfigure",
                             "misconfigures", "misconfigured", "misconfiguring"),
        "flaw": ("flaw", "flaws", "flawed"),
        "bug": ("bug", "bugs", "buggy", "bugged"),
        "idor": ("idor", "idors"),
        "bola": ("bola", "bolas"),
        "broken": ("broken",),
        "unauthorized": ("unauthorized", "unauthorised"),
        "attack": ("attack", "attacks", "attacked", "attacking", "attackable"),
        "attacker": ("attacker", "attackers"),
        "compromise": ("compromise", "compromises", "compromised", "compromising",
                       "compromisable"),
        "critical": ("critical", "critically", "criticality"),
        "severity": ("severity", "severities", "severe", "severely", "severer",
                     "severest"),
        "secure": ("secure", "secures", "secured", "securing", "securely", "security"),
        "protected": ("protect", "protects", "protected", "protecting", "protection",
                      "protections", "protective", "protector", "protectors"),
        "safe": ("safe", "safely", "safer", "safest", "safety"),
        "compliant": ("compliant", "comply", "complies", "complied", "complying",
                      "compliance"),
        "verified": ("verify", "verifies", "verified", "verifying", "verification",
                     "verifiable", "verifiability", "verifiably"),
        "guaranteed": ("guarantee", "guarantees", "guaranteed", "guaranteeing",
                       "guarantor", "guarantors"),
    }

    def test_every_policed_stem_matches_its_base_and_present_forms(self) -> None:
        # REGRESSION. The first fix added stem-changing suffixes but still
        # derived every form from the policed word itself, so a word policed
        # as a past participle missed its own base and present forms:
        # "guaranteed" matched, "guarantees" did not, nor "verifies",
        # "protects" or "protection"; "vulnerably" and "safety" also passed.
        # Every policed word must have a family here, so a word added to the
        # vocabulary without one fails this test instead of being half-policed.
        self.assertEqual(
            set(self.POLICED_FAMILIES),
            set(br.BANNED_CANDIDATE_WORDS) | set(coverage.BANNED_CLAIM_WORDS),
        )
        for word, forms in self.POLICED_FAMILIES.items():
            for form in forms:
                with self.subTest(word=word, form=form):
                    self.assertEqual(br.banned_words_in(f"it {form} here"), (form,))
                    self.assertEqual(
                        br.banned_words_in(form.capitalize()), (form,)
                    )
        # Control: whole-word matching still spares near neighbours.
        for text in ("Veridor", "a line break", "it breaks", "protocol", "verbose",
                     "guard", "safeguard"):
            with self.subTest(control=text):
                self.assertEqual(br.banned_words_in(text), ())

    def test_sever_meaning_cut_is_not_policed_as_severe(self) -> None:
        # REGRESSION. "severe" was inflected like every other form, so the
        # suffix rules reached "severed" and "severing" -- ordinary English
        # for "cut", as in core's "a severed socket" -- and policed them.
        # "severe" and its own forms are now policed as themselves only.
        for text in ("a severed socket", "severing the connection", "it severs",
                     "Severed"):
            with self.subTest(text=text):
                self.assertEqual(br.banned_words_in(text), ())
        # Control: the forms that mean "serious" are still policed.
        for text, word in (("a severe gap", "severe"), ("severely", "severely"),
                           ("Severity", "severity"), ("two severities", "severities")):
            with self.subTest(control=text):
                self.assertEqual(br.banned_words_in(text), (word,))

    def test_every_candidate_block_says_candidate_and_denies_being_a_finding(self) -> None:
        matrix = load_matrix(FIXTURES / "matrix.observed.json")
        config = json.loads((FIXTURES / "matrix.demo.json").read_text(encoding="utf-8"))
        group = br.peer_groups(config, matrix)
        candidates = br.find_candidates(matrix, group)
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertIn("not a finding", candidate.explanation)
            self.assertNotIn("is a finding.", candidate.explanation)
        text = br.render_candidates(
            br.candidates_document(matrix, candidates, grouping=group)
        )
        for block in text.split("\n\n"):
            if block.lstrip().startswith("["):
                self.assertIn("candidate", block)
                self.assertIn("Worth declaring an expectation for", block)

    def test_the_zero_candidate_footer_refuses_a_clean_bill_of_health(self) -> None:
        matrix = make_matrix([("GET /a", None, {"p": 200})])
        document = br.candidates_document(matrix, [])
        text = br.render_candidates(document)
        self.assertEqual(document["footer"], br.ZERO_CANDIDATE_FOOTER)
        self.assertIn("Consistency is not authorization.", text)
        self.assertIn("only that they are mutually consistent", text)
        self.assertNotIn("Veridor has not tested", text)

    def test_the_candidate_footer_is_mandatory_when_there_are_candidates(self) -> None:
        matrix = load_matrix(FIXTURES / "matrix.sibling.json")
        config = json.loads((FIXTURES / "blastradius.sibling.json").read_text(encoding="utf-8"))
        group = br.peer_groups(config, matrix)
        document = br.candidates_document(
            matrix, br.find_candidates(matrix, group), grouping=group
        )
        text = br.render_candidates(document)
        self.assertEqual(document["footer"], br.CANDIDATE_FOOTER)
        self.assertIn("established nothing about them", text)
        self.assertIn("uphold the expectation", text)


class ArtifactHygieneTest(unittest.TestCase):
    def documents(self) -> list[str]:
        out: list[str] = []
        for name, config_name in (
            ("matrix.observed.json", "matrix.demo.json"),
            ("matrix.sibling.json", "blastradius.sibling.json"),
            ("matrix.shared.json", "blastradius.shared.json"),
        ):
            matrix = load_matrix(FIXTURES / name)
            config = json.loads((FIXTURES / config_name).read_text(encoding="utf-8"))
            group = br.peer_groups(config, matrix)
            candidates = br.find_candidates(matrix, group)
            out.append(
                json.dumps(br.candidates_document(matrix, candidates, grouping=group))
            )
            out.append(json.dumps(br.blast_radius_report(matrix)))
            out.append(br.render_candidates(br.candidates_document(matrix, candidates, grouping=group)))
            out.append(br.render_blast_radius(br.blast_radius_report(matrix)))
        return out

    def test_no_artifact_carries_a_credential_a_cookie_or_a_body(self) -> None:
        forbidden = (
            "Authorization",
            "Bearer",
            "Set-Cookie",
            "session=",
            "owner-token",
            "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
            "body_sha256",
            "?",
        )
        for text in self.documents():
            for needle in forbidden:
                self.assertNotIn(needle, text, needle)

    def test_the_promotion_stub_carries_only_a_redacted_path(self) -> None:
        matrix = load_matrix(FIXTURES / "matrix.observed.json")
        config = json.loads((FIXTURES / "matrix.demo.json").read_text(encoding="utf-8"))
        group = br.peer_groups(config, matrix)
        for candidate in br.find_candidates(matrix, group):
            stub = br.promotion_stub(candidate)
            self.assertTrue(stub["request"]["path"].startswith("/"))
            self.assertNotIn("?", stub["request"]["path"])
            self.assertNotIn("http", stub["request"]["path"])


# ---------------------------------------------------------------------------
# the shipped fixtures, exercised offline
# ---------------------------------------------------------------------------


class FixtureTest(unittest.TestCase):
    def load(self, matrix_name: str, config_name: str) -> tuple[Any, br.PeerGrouping, list[br.Candidate]]:
        matrix = load_matrix(FIXTURES / matrix_name)
        config = json.loads((FIXTURES / config_name).read_text(encoding="utf-8"))
        group = br.peer_groups(config, matrix)
        return matrix, group, br.find_candidates(matrix, group)

    def test_the_sibling_fixture_surfaces_both_asymmetries_in_order(self) -> None:
        matrix, _, candidates = self.load("matrix.sibling.json", "blastradius.sibling.json")
        self.assertFalse(matrix.aborted)
        self.assertEqual(
            [(item.rule, item.identity, item.operation, item.consensus) for item in candidates],
            [
                ("sibling_asymmetry", "other_tenant", "GET /api/reports/quarterly", (12, 13)),
                ("sibling_asymmetry", "other_tenant", "GET /api/ledgers/summary", (7, 8)),
            ],
        )

    def test_the_sibling_fixture_reports_reach_as_a_lower_bound(self) -> None:
        matrix, _, _ = self.load("matrix.sibling.json", "blastradius.sibling.json")
        radius = br.compute_blast_radius(matrix, "other_tenant")
        self.assertEqual(len(radius.reached), 2)
        self.assertEqual(radius.inventory, 21)
        self.assertIn("lower bound", radius.headline)

    def test_the_shared_fixture_never_surfaces_the_shared_resource(self) -> None:
        matrix, group, candidates = self.load("matrix.shared.json", "blastradius.shared.json")
        self.assertEqual(
            [item.operation for item in candidates if "changelog" in item.operation], []
        )
        self.assertEqual(
            [item.operation for item in candidates if item.operation.startswith("GET /api/notes")],
            [],
        )
        # the whole team reaches it, which is exactly why there is nothing to say
        for identity in ("alice", "bob", "carol"):
            cell = matrix.cell("GET /api/team/changelog", identity, None)
            self.assertEqual(cell.status, 200)
        # and its one remaining entry was anonymous on /health, which is that
        # endpoint working. A benign target now produces a benign list.
        self.assertEqual(candidates, [])
        suppressions: dict[str, int] = {}
        br.find_candidates(matrix, group, suppressions=suppressions)
        self.assertEqual(
            suppressions.get("unauthenticated_reach_conventionally_public"), 1
        )
        codes = {
            note["code"]
            for note in br.discovery_notes(matrix, group, suppressions=suppressions)
        }
        self.assertIn("rule_suppressions", codes)

    def test_the_observed_fixture_exercises_the_declared_rules(self) -> None:
        matrix, group, candidates = self.load("matrix.observed.json", "matrix.demo.json")
        fired = rules_fired(candidates)
        self.assertIn("marker_reach", fired)
        self.assertIn("inverted_guard", fired)
        self.assertIn("sibling_asymmetry", fired)
        # the 503 cell is recorded and never becomes a candidate
        self.assertEqual(
            matrix.cell("GET /api/admin/audit", "peer_tenant", None).reach, REACH_UNKNOWN
        )
        self.assertNotIn(
            "GET /api/admin/audit",
            [item.operation for item in candidates if item.identity == "peer_tenant"],
        )
        # the per-identity specimen row is never compared across identities
        notes = {note["code"] for note in br.discovery_notes(matrix, group)}
        self.assertIn("not_comparable_per_identity_specimen", notes)
        self.assertEqual(
            [
                item.operation
                for item in candidates
                if item.rule in {"peer_divergence", "inverted_guard"}
                and "tenants" in item.operation
            ],
            [],
        )

    def test_marker_backed_candidates_rank_above_every_comparative_rule(self) -> None:
        _, _, candidates = self.load("matrix.observed.json", "matrix.demo.json")
        tiers = [candidate.evidence_tier for candidate in candidates]
        self.assertEqual(tiers, sorted(tiers, key=lambda tier: br._TIER_ORDER[tier]))
        self.assertEqual(candidates[0].evidence_tier, br.TIER_MARKER_BACKED)


# ---------------------------------------------------------------------------
# the false-candidate rate, measured
# ---------------------------------------------------------------------------


class PrecisionTest(unittest.TestCase):
    """A benign target of realistic width must produce a benign list.

    There was no test of this shape, and that is how a 43-operation API in
    which every single access is correct came to produce 30 candidates, all
    false, growing linearly with the API (183 rows -> 170). An operator who
    reads thirty tagged hypotheses and finds nothing in any of them stops
    reading the list, and then the rules detect nothing at all -- which is the
    alert fatigue this product exists to replace.

    The ceiling is now ZERO. A clean target that produces four bogus
    candidates is the first thing a new user sees, and it loses them
    permanently; there is no count of false candidates that is acceptable on a
    fixture in which every cell is correct by construction. Recall is measured
    on the same shape by the tests below, so a rule cannot buy this number by
    going silent.
    """

    #: What a fully-correct 44-row, 5-identity multi-tenant API may cost the
    #: operator. Zero, and each of the two shapes that used to survive here has
    #: its own exclusion and its own test in this file:
    #: MarkerReachTest.test_false_positive_case_a_group_wide_feed_is_excluded_and_counted
    #: and
    #: SiblingAsymmetryTest.test_false_positive_case_a_capability_probe_open_to_everyone_is_excluded
    MAX_FALSE_CANDIDATES = 0

    def load(self, name: str) -> tuple[Any, br.PeerGrouping, list[br.Candidate], dict[str, int]]:
        matrix = load_matrix(FIXTURES / f"matrix.{name}.json")
        config = json.loads(
            (FIXTURES / f"blastradius.{name}.json").read_text(encoding="utf-8")
        )
        group = br.peer_groups(config, matrix)
        suppressions: dict[str, int] = {}
        return (
            matrix,
            group,
            br.find_candidates(matrix, group, suppressions=suppressions),
            suppressions,
        )

    def test_a_wholly_correct_api_produces_nothing_at_all(self) -> None:
        matrix, _, candidates, _ = self.load("benign")
        self.assertGreaterEqual(len(matrix.rows), 40, "the fixture must stay wide")
        self.assertGreaterEqual(len(matrix.identities), 5)
        self.assertLessEqual(
            len(candidates),
            self.MAX_FALSE_CANDIDATES,
            "every candidate here is false by construction: "
            + "; ".join(f"{item.rule}/{item.identity}/{item.operation}" for item in candidates),
        )

    def test_the_zero_candidate_footer_still_refuses_a_clean_bill_of_health(self) -> None:
        # Zero candidates on a benign target is the goal, and it is also the
        # moment the product is most tempted to congratulate itself. It must
        # not: consistency is not authorization.
        matrix, group, candidates, suppressions = self.load("benign")
        self.assertEqual(candidates, [])
        text = br.render_candidates(
            br.candidates_document(
                matrix, candidates, grouping=group, suppressions=suppressions
            )
        )
        self.assertIn("0 candidates.", text)
        self.assertIn("Consistency is not authorization", text)
        self.assertNotIn(br.CANDIDATE_FOOTER.split(".")[0], text)

    def test_the_count_tracks_anomalies_not_the_size_of_the_api(self) -> None:
        # The old failure was one candidate per tenant-scoped row, so the list
        # grew with the spec. Widening the benign API with more of exactly the
        # same correct behaviour must not add anything.
        matrix, group, candidates, _ = self.load("benign")
        rows = list(matrix.rows)
        cells = list(matrix.cells)
        extra_rows: list[tuple[str, str | None]] = []
        extra_cells: list[Cell] = []
        for index in range(60):
            operation = f"GET /api/widgets/set{index}"
            extra_rows.append((operation, None))
            for identity in matrix.identities:
                status = {"alice": 200, "bob": 200, "carol": 200}.get(
                    identity, 404 if identity == "admin" else 401
                )
                extra_cells.append(_cell(operation, identity, None, status))
        fields = {
            field.name: getattr(matrix, field.name)
            for field in dataclasses.fields(matrix)
        }
        wider = AccessMatrix(
            **{
                **fields,
                "rows": tuple(rows + extra_rows),
                "cells": tuple(cells + extra_cells),
                "operations": matrix.operations
                + tuple(operation for operation, _ in extra_rows),
                "shared_specimen_rows": matrix.shared_specimen_rows
                + tuple(extra_rows),
            }
        )
        widened = br.find_candidates(wider, group)
        self.assertEqual(
            len(widened),
            len(candidates),
            "60 more correctly-authorized operations added candidates",
        )

    def test_the_real_bugs_in_the_same_target_are_still_surfaced(self) -> None:
        # Precision is only worth having with recall beside it, measured on the
        # same fixture: four genuine bugs planted in the benign API.
        _, _, benign, _ = self.load("benign")
        _, _, planted, _ = self.load("idor")
        surfaced = {(item.identity, item.operation) for item in planted}
        for identity, operation, description in (
            ("bob", "GET /api/invoices/{id}", "classic IDOR on another user's invoice"),
            ("carol", "GET /api/admin/keys", "privilege escalation to platform keys"),
            ("anon", "GET /api/billing/history", "unauthenticated read of billing"),
        ):
            with self.subTest(bug=description):
                self.assertIn((identity, operation), surfaced)
        self.assertGreater(len(planted), len(benign), "a real bug must move the list")
        # Every candidate on the planted fixture is one of the planted bugs.
        # Recall without precision is a list nobody reads; precision without
        # recall is a rule that went silent. Both are asserted on one target.
        self.assertEqual(
            sorted(
                {(item.identity, item.operation) for item in planted}
                - {
                    ("bob", "GET /api/invoices/{id}"),
                    ("carol", "GET /api/admin/keys"),
                    ("anon", "GET /api/billing/history"),
                }
            ),
            [],
        )

    def test_the_marker_crossing_survives_the_shared_feed_exclusion(self) -> None:
        # marker_reach now excludes a group-wide collection. The bug it must
        # still see is the identified object: bob's response to
        # GET /api/invoices/{id} carries alice's planted marker, because it IS
        # her invoice. If the exclusion ever widened to items, this goes quiet.
        _, _, planted, suppressions = self.load("idor")
        self.assertIn(
            ("marker_reach", "bob", "GET /api/invoices/{id}"),
            {(item.rule, item.identity, item.operation) for item in planted},
        )
        # ... while the tenant-wide activity feed on the same target is excluded
        self.assertEqual(suppressions.get("marker_reach_group_wide_collection"), 1)

    def test_the_bug_no_rule_can_honestly_see_is_not_claimed(self) -> None:
        # B1: carol (tenant B) reads tenant A's announcement. alice AND bob both
        # legitimately read that object, so no peer refusal contradicts carol's
        # read and no marker names an owner. A rule that raised it here would be
        # guessing. The gap is a coverage statement, not a silent miss.
        _, _, planted, _ = self.load("idor")
        self.assertNotIn(
            ("carol", "GET /api/announcements/{id}"),
            {(item.identity, item.operation) for item in planted},
        )

    def test_the_classic_idor_is_found_by_the_rule_that_is_about_it(self) -> None:
        # It used to be found only incidentally, by inverted_guard, because the
        # platform admin happened to 404 on that row -- so dropping
        # privilege_order made it invisible. peer_divergence owns this shape.
        _, _, planted, _ = self.load("idor")
        rules = {
            item.rule
            for item in planted
            if item.identity == "bob" and item.operation == "GET /api/invoices/{id}"
        }
        self.assertIn("peer_divergence", rules)

        matrix = load_matrix(FIXTURES / "matrix.idor.json")
        config = json.loads(
            (FIXTURES / "blastradius.idor.json").read_text(encoding="utf-8")
        )
        del config["matrix"]["privilege_order"]
        without = br.find_candidates(matrix, br.peer_groups(config, matrix))
        self.assertIn(
            ("bob", "GET /api/invoices/{id}"),
            {(item.identity, item.operation) for item in without},
            "the IDOR must survive an absent privilege_order",
        )

    def _with_order(self, name: str, order: list[str] | None) -> tuple[Any, br.PeerGrouping, list[br.Candidate], dict[str, int]]:
        matrix = load_matrix(FIXTURES / f"matrix.{name}.json")
        config = json.loads(
            (FIXTURES / f"blastradius.{name}.json").read_text(encoding="utf-8")
        )
        if order is None:
            del config["matrix"]["privilege_order"]
        else:
            config["matrix"]["privilege_order"] = order
        group = br.peer_groups(config, matrix)
        suppressions: dict[str, int] = {}
        return (
            matrix,
            group,
            br.find_candidates(matrix, group, suppressions=suppressions),
            suppressions,
        )

    def test_precision_and_the_marker_backed_recall_do_not_rest_on_the_peer_ranking(self) -> None:
        # The fixture ranks alice above bob. Precision and the marker-backed
        # recall must not depend on that: leaving privilege_order out, leaving
        # the marker owner out of it, or ranking no peer at all leaves the
        # benign list empty and the marker_reach crossing raised. Only a
        # declaration the API contradicts may move them (below). The rest of
        # the candidate list does move with these orders; see
        # test_the_inverted_guard_candidates_do_follow_the_peer_ranking.
        crossing = ("marker_reach", "bob", "GET /api/invoices/{id}")
        for order in (
            ["anon", "carol", "bob", "alice", "admin"],
            None,
            ["anon", "carol", "bob", "admin"],
            ["anon", "carol", "admin"],
            ["anon", "admin"],
        ):
            with self.subTest(privilege_order=order):
                _, _, benign, _ = self._with_order("benign", order)
                self.assertEqual(
                    [(item.rule, item.identity, item.operation) for item in benign], []
                )
                _, _, planted, _ = self._with_order("idor", order)
                self.assertIn(
                    crossing,
                    {(item.rule, item.identity, item.operation) for item in planted},
                )

    def test_the_inverted_guard_candidates_do_follow_the_peer_ranking(self) -> None:
        # carol reaches GET /api/admin/keys where alice and bob get 403.
        # inverted_guard raises that only while carol is ranked below alice or
        # bob; with privilege_order left out, carol unranked, or carol ranked
        # above both, it is not raised. Recall at the (identity, operation)
        # level does not rest on that, because sibling_asymmetry raises the
        # same pair under every order. The generator's comment on
        # privilege_order says so, and this keeps it from drifting back to
        # "the results are the same".
        held = ("inverted_guard", "carol", "GET /api/admin/keys")
        sibling = ("sibling_asymmetry", "carol", "GET /api/admin/keys")
        for order, raised in (
            (["anon", "carol", "bob", "alice", "admin"], True),
            (["anon", "carol", "alice", "admin"], True),
            (["anon", "alice", "carol", "bob", "admin"], True),
            (None, False),
            (["anon", "admin"], False),
            (["anon", "carol", "admin"], False),
            (["anon", "alice", "carol", "admin"], False),
            (["anon", "bob", "alice", "carol", "admin"], False),
        ):
            with self.subTest(privilege_order=order):
                _, _, planted, _ = self._with_order("idor", order)
                found = {(item.rule, item.identity, item.operation) for item in planted}
                self.assertIs(held in found, raised)
                self.assertIn(sibling, found)

    def test_ranking_a_peer_above_the_marker_owner_is_counted_not_silent(self) -> None:
        # bob declared above alice is a declaration the benign API refutes (it
        # refuses bob her invoice). Both rules name a wrong privilege_order as
        # their failure mode. What must not happen is a silent change: the lost
        # marker evidence is a counted, reported suppression, the IDOR is still
        # raised by peer_divergence, and the benign side shows its one false
        # inverted_guard rather than hiding it.
        swapped = ["anon", "carol", "alice", "bob", "admin"]
        matrix, group, planted, suppressions = self._with_order("idor", swapped)
        raised = {(item.rule, item.identity, item.operation) for item in planted}
        self.assertNotIn(("marker_reach", "bob", "GET /api/invoices/{id}"), raised)
        self.assertIn(("peer_divergence", "bob", "GET /api/invoices/{id}"), raised)
        self.assertEqual(
            suppressions.get("marker_reach_reader_declared_higher_privilege"), 2
        )
        note = next(
            item
            for item in br.discovery_notes(matrix, group, suppressions=suppressions)
            if item["code"] == "rule_suppressions"
        )
        self.assertIn("marker_reach_reader_declared_higher_privilege", note["message"])
        _, _, benign, _ = self._with_order("benign", swapped)
        self.assertEqual(
            [(item.rule, item.identity, item.operation) for item in benign],
            [("inverted_guard", "alice", "GET /api/invoices/{id}")],
        )

    def test_every_suppression_is_reported_to_the_operator(self) -> None:
        # The rules are tighter than the observations alone permit. A
        # suppression nobody is told about is indistinguishable from a rule
        # that stopped working.
        matrix, group, _, suppressions = self.load("benign")
        self.assertTrue(suppressions)
        notes = br.discovery_notes(matrix, group, suppressions=suppressions)
        note = next(item for item in notes if item["code"] == "rule_suppressions")
        self.assertEqual(note["reasons"], dict(sorted(suppressions.items())))
        for reason in suppressions:
            self.assertIn(reason, note["message"])
        text = br.render_candidates(
            br.candidates_document(
                matrix, [], grouping=group, suppressions=suppressions
            )
        )
        self.assertIn("rule_suppressions", text)


def _precision_generator() -> Any:
    """tests/fixtures/blastradius_precision_fixture.py, imported without running it.

    The generator puts src/ at the front of sys.path, which would undo
    VERIDOR_TEST_AGAINST=installed for anything imported later, so the path is
    restored once it has loaded.
    """
    saved = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location(
            "blastradius_precision_fixture_under_test",
            FIXTURES / "blastradius_precision_fixture.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved
    return module


class PrecisionFixtureProvenanceTest(unittest.TestCase):
    """The committed precision fixtures are what their generator writes.

    PrecisionTest measures the committed JSON; the generator is the record of
    what that JSON is meant to contain. Without this, a change to either the
    generator or matrix_document drifts away from the committed files and
    nothing says so -- the committed matrices once lacked two safety keys the
    generator had started to emit, and the docstring counted 43 operations
    while both described 44.
    """

    def test_the_committed_files_are_byte_identical_to_the_generator_output(self) -> None:
        generator = _precision_generator()
        for name, planted in (("benign", False), ("idor", True)):
            with self.subTest(fixture=name):
                self.assertEqual(
                    (FIXTURES / f"matrix.{name}.json").read_text(encoding="utf-8"),
                    json.dumps(
                        generator.matrix_document(generator.build(planted=planted)),
                        indent=1,
                    )
                    + "\n",
                    f"matrix.{name}.json is stale; rerun the generator",
                )
                self.assertEqual(
                    (FIXTURES / f"blastradius.{name}.json").read_text(encoding="utf-8"),
                    json.dumps(generator.config(), indent=1) + "\n",
                    f"blastradius.{name}.json is stale; rerun the generator",
                )

    def test_the_docstring_counts_the_operations_the_generator_builds(self) -> None:
        generator = _precision_generator()
        for planted in (False, True):
            operations = len(generator.build(planted=planted).operations)
            self.assertIn(
                f"API of {operations} operations x {len(generator.IDENTITIES)} identities",
                " ".join(generator.__doc__.split()),
            )

    def test_the_ranking_comment_says_what_the_peer_ranking_moves_and_what_it_does_not(self) -> None:
        # The comment on privilege_order once ranked alice above bob "because
        # the benign API refuses bob her invoice". That refusal refutes bob
        # above alice; it does not establish alice above bob. Its replacement
        # then said the results are the same with no peer ranked or with
        # privilege_order left out, and that only bob above alice moves them.
        # Measured, that is false: inverted_guard raises carol on
        # GET /api/admin/keys only while carol is ranked below alice or bob, so
        # leaving privilege_order out drops it. What holds is narrower:
        # precision and the marker-backed recall do not depend on the peers'
        # order. The comment must say that, say what the order does move, and
        # name the tests that show each, so both claims can be checked.
        lines = inspect.getsource(_precision_generator().config).splitlines()
        at = next(
            index for index, line in enumerate(lines) if '"privilege_order":' in line
        )
        comment = []
        for line in reversed(lines[:at]):
            if not line.strip().startswith("#"):
                break
            comment.insert(0, line.strip().lstrip("#").strip())
        comment = " ".join(comment)
        # control: the comment block above privilege_order is found at all
        self.assertIn("privilege_order", comment)
        self.assertNotRegex(comment, r"alice above bob because")
        self.assertNotRegex(comment, r"results are (the same|unchanged)")
        self.assertNotRegex(comment, r"[Ww]hat moves them is")
        self.assertIn("precision and the marker-backed recall", comment)
        for named in ("inverted_guard", "carol", "GET /api/admin/keys", "sibling_asymmetry"):
            self.assertIn(named, comment)
        for name in (
            "test_precision_and_the_marker_backed_recall_do_not_rest_on_the_peer_ranking",
            "test_the_inverted_guard_candidates_do_follow_the_peer_ranking",
            "test_ranking_a_peer_above_the_marker_owner_is_counted_not_silent",
        ):
            self.assertTrue(hasattr(PrecisionTest, name), name)
            self.assertIn(name, comment)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
