"""Builds the two fixtures the candidate-precision tests measure against.

Run from the repository root::

    PYTHONPATH=src python3.12 tests/fixtures/blastradius_precision_fixture.py

It writes, deterministically:

``matrix.benign.json`` / ``blastradius.benign.json``
    A realistic multi-tenant SaaS API of 44 operations x 5 identities in which
    EVERY cell is correct authorization behaviour. Nothing in it is a bug, so
    every candidate the rules raise against it is false by construction. It
    exists because there was no fixture of realistic width that measured the
    false-candidate rate: the shipped benign fixture is 9 rows x 4 identities
    with no privilege order, no wide families and no shared feed, and the
    shipped observed fixture is 13 rows -- neither one can show a rule that
    emits one entry per tenant-scoped row.

``matrix.idor.json`` / ``blastradius.idor.json``
    The same target with four genuine authorization bugs planted, so recall is
    measured on the same shape precision is measured on.

The API modelled is the ordinary one, not a convenient one. It has the shapes
that make honest rules noisy: public health and version routes, a tenant-wide
activity feed that legitimately carries another user's records, an
``/api/admin/whoami`` capability probe that answers everyone so a single-page
app can decide whether to draw the admin nav, a per-identity specimen row, an
empty-list-instead-of-403 collection, and a platform administrator with no
tenant membership -- the Stripe/Auth0 shape, in which tenant routes 404 for the
most privileged identity in the config.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from veridor.matrix import (  # noqa: E402
    OUTCOME_OBSERVED,
    AccessMatrix,
    Cell,
    classify_reach,
    matrix_document,
)

IDENTITIES = ("alice", "bob", "carol", "admin", "anon")
MARKER_OWNER = "alice"
BASE_URL = "http://127.0.0.1:8765"

#: ``(operation, specimen, shared, {identity: status | (status, marker) | (status, marker, body)})``
Row = tuple[str, "str | None", bool, dict[str, Any]]


def _rows(*, planted: bool) -> list[Row]:
    """The grid. ``planted`` swaps four cells for four genuine bugs.

    Each bug is a different real shape, so a rule cannot pass by catching one
    kind of thing:

    B1  carol (tenant B) reads tenant A's private announcement -- cross-tenant.
    B2  bob reads alice's invoice -- the classic IDOR. His response carries her
        planted marker, because it IS her invoice: the crossing is physical, not
        inferred, which is what makes it the one bug marker_reach can see.
    B3  carol reads the platform API keys -- privilege escalation.
    B4  an unauthenticated caller reads billing history -- authentication bypass.

    B1 is deliberately left invisible to every rule. Tenant A's announcement is
    legitimately read by alice AND bob, so an observation-only rule has nothing
    to compare carol's read against, and no marker names the object's owner. A
    fixture whose every bug is catchable measures a rule set nobody has, so this
    one keeps a bug the rules honestly cannot reach.
    """
    rows: list[Row] = []

    def row(operation: str, specimen: str | None, shared: bool, **cells: Any) -> None:
        rows.append((operation, specimen, shared, dict(cells)))

    # public infrastructure: correct, documented, open
    for operation in (
        "GET /health",
        "GET /version",
        "GET /openapi.json",
        "GET /auth/providers",
    ):
        row(operation, None, True, alice=200, bob=200, carol=200, admin=200, anon=200)
    # metrics is closed to tenant users and open to the platform admin: correct
    row("GET /metrics", None, True, alice=403, bob=403, carol=403, admin=200, anon=401)

    # alice's invoice: the owner reads it, her peer and the other tenant do not,
    # and the platform admin has no tenant so it 404s.
    row(
        "GET /api/invoices/{id}",
        "owner_invoice",
        True,
        alice=(200, "present"),
        bob=(200, "present") if planted else 403,  # B2
        carol=404,
        admin=404,
        anon=401,
    )
    # tenant-scoped collections: every tenant user sees THEIR OWN. Correct.
    for operation in (
        "GET /api/invoices/summary",
        "GET /api/invoices/overdue",
        "GET /api/invoices/drafts",
        "GET /api/invoices/export",
        "GET /api/invoices/recent",
    ):
        row(operation, None, True, alice=200, bob=200, carol=200, admin=404, anon=401)

    # /api/admin/*: closed to tenant users, except the capability probe.
    # /api/admin/whoami answering {"is_admin": false} to everybody is how a
    # single-page app decides whether to render the admin nav. Correct, common.
    for operation in (
        "GET /api/admin/users",
        "GET /api/admin/settings",
        "GET /api/admin/audit",
        "GET /api/admin/billing",
        "GET /api/admin/jobs",
    ):
        row(operation, None, True, alice=403, bob=403, carol=403, admin=200, anon=401)
    row(
        "GET /api/admin/keys",
        None,
        True,
        alice=403,
        bob=403,
        carol=200 if planted else 403,  # B3
        admin=200,
        anon=401,
    )
    row("GET /api/admin/whoami", None, True,
        alice=200, bob=200, carol=200, admin=200, anon=401)

    # /api/config/*: a semantically mixed prefix, which is the sibling rule's
    # own declared failure mode. Four closed, three open, all correct.
    row("GET /api/config/{key}", "smtp_host", True,
        alice=403, bob=403, carol=403, admin=200, anon=401)
    for operation in (
        "GET /api/config/secrets",
        "GET /api/config/integrations",
        "GET /api/config/webhooks",
    ):
        row(operation, None, True, alice=403, bob=403, carol=403, admin=200, anon=401)
    for operation in (
        "GET /api/config/public",
        "GET /api/config/flags",
        "GET /api/config/locales",
    ):
        row(operation, None, True, alice=200, bob=200, carol=200, admin=200, anon=401)

    # tenant A shared objects: both tenant A users read them, tenant B 404s.
    row("GET /api/announcements", None, True,
        alice=200, bob=200, carol=200, admin=404, anon=401)
    row(
        "GET /api/announcements/{id}",
        "tenant_a_announcement",
        True,
        alice=200,
        bob=200,
        carol=200 if planted else 404,  # B1
        admin=404,
        anon=401,
    )
    row("GET /api/reports/{id}", "tenant_a_report", True,
        alice=200, bob=200, carol=404, admin=404, anon=401)
    for operation in (
        "GET /api/reports/scheduled",
        "GET /api/reports/templates",
        "GET /api/reports/exports",
        "GET /api/reports/archive",
        "GET /api/reports/shared",
    ):
        row(operation, None, True, alice=200, bob=200, carol=200, admin=404, anon=401)

    # the tenant-wide activity feed legitimately carries other members' records,
    # so alice's planted marker turns up in bob's response. Correct behaviour,
    # and the hardest honest case in the fixture.
    row("GET /api/activity", None, True,
        alice=(200, "present"), bob=(200, "present"), carol=200,
        admin=404, anon=401)

    # a collection that answers 200 with an empty list rather than 403
    row("GET /api/teams/{tid}/members", "tenant_a_team", True,
        alice=200, bob=200, carol=(200, None, "empty"), admin=404, anon=401)

    # a per-identity specimen: the identities requested DIFFERENT objects, so
    # cross-identity comparison is not meaningful and must not happen.
    row("GET /api/users/{uid}/profile", "own_profile", False,
        alice=200, bob=200, carol=200, admin=404, anon=401)

    # billing
    row(
        "GET /api/billing/history",
        None,
        True,
        alice=200,
        bob=200,
        carol=200,
        admin=404,
        anon=200 if planted else 401,  # B4
    )
    for operation in (
        "GET /api/billing/plan",
        "GET /api/billing/usage",
        "GET /api/billing/methods",
        "GET /api/billing/contacts",
    ):
        row(operation, None, True, alice=200, bob=200, carol=200, admin=404, anon=401)

    row("GET /api/notifications", None, True,
        alice=200, bob=200, carol=200, admin=404, anon=401)
    row("GET /api/search", None, True,
        alice=200, bob=200, carol=200, admin=404, anon=401)
    row("GET /api/webhooks/deliveries", None, True,
        alice=403, bob=403, carol=403, admin=200, anon=401)
    return rows


def _cell(operation: str, identity: str, specimen: str | None, spec: Any) -> Cell:
    if isinstance(spec, int):
        status, marker, body = spec, None, "data"
    elif len(spec) == 2:
        (status, marker), body = spec, "data"
    else:
        status, marker, body = spec
    reach, refusal, unknown = classify_reach(status)
    path = operation.split(" ", 1)[1]
    digest = hashlib.sha256(f"{operation}|{identity}|{body}".encode()).hexdigest()[:16]
    return Cell(
        operation=operation,
        identity=identity,
        specimen=specimen,
        url_path=path,
        outcome=OUTCOME_OBSERVED,
        reach=reach,
        status=status,
        status_class=None,
        refusal_kind=refusal,
        duration_ms=12.0,
        body_bytes=0 if body == "empty" else 400,
        body_empty=body == "empty",
        body_digest=digest if reach == "reached" else None,
        marker_scan=marker,
        marker_owner=MARKER_OWNER if marker else None,
        unknown_reason=unknown,
    )


def build(*, planted: bool) -> AccessMatrix:
    rows = _rows(planted=planted)
    cells = [
        _cell(operation, identity, specimen, per_identity[identity])
        for operation, specimen, _, per_identity in rows
        for identity in IDENTITIES
    ]
    grid = tuple((operation, specimen) for operation, specimen, _, _ in rows)
    return AccessMatrix(
        base_url=BASE_URL,
        host="127.0.0.1:8765",
        target_class="loopback",
        operations=tuple(dict.fromkeys(operation for operation, _, _, _ in rows)),
        identities=IDENTITIES,
        rows=grid,
        cells=tuple(cells),
        planned=len(cells),
        issued=len(cells),
        aborted=False,
        abort_reason=None,
        read_only=True,
        permitted_methods=("GET", "HEAD"),
        requests_per_second=2.0,
        max_specimens=1,
        shared_specimen_rows=tuple(
            (operation, specimen)
            for operation, specimen, shared, _ in rows
            if shared
        ),
        ignored=(),
        marker_owner=MARKER_OWNER,
    )


def config() -> dict[str, Any]:
    specimens = {
        template: [{"label": label, "values": {name: f"{name}-1" for name in names}}]
        for template, label, names in (
            ("/api/invoices/{id}", "owner_invoice", ("id",)),
            ("/api/config/{key}", "smtp_host", ("key",)),
            ("/api/announcements/{id}", "tenant_a_announcement", ("id",)),
            ("/api/reports/{id}", "tenant_a_report", ("id",)),
            ("/api/teams/{tid}/members", "tenant_a_team", ("tid",)),
        )
    }
    # each identity requested its OWN profile, so the specimen is per_identity,
    # matching shared_specimen=false on this row in the matrix
    specimens["/api/users/{uid}/profile"] = [
        {
            "label": "own_profile",
            "per_identity": {
                identity: {"uid": f"u-{identity}"}
                for identity in IDENTITIES
            },
        }
    ]
    return {
        "version": 1,
        "target": {"base_url": BASE_URL, "timeout_seconds": 3},
        "identities": {
            "alice": {"headers": {"Authorization": "Bearer alice-token"},
                      "marker": "veridor-marker-alice"},
            "bob": {"headers": {"Authorization": "Bearer bob-token"}},
            "carol": {"headers": {"Authorization": "Bearer carol-token"}},
            "admin": {"headers": {"Authorization": "Bearer admin-token"}},
            "anon": {"headers": {}},
        },
        "checks": [
            {
                "id": "invoice-owner-reads-own-invoice",
                "name": "The invoice owner can read her own invoice",
                "request": {"method": "GET", "path": "/api/invoices/id-1"},
                "expect": {"alice": {"status": [200]}, "carol": {"status": [404]}},
            }
        ],
        "matrix": {
            "specimens": specimens,
            "marker_owner": MARKER_OWNER,
            "peer_groups": {"tenant_users": ["alice", "bob", "carol"]},
            # precision and the marker-backed recall do not depend on how this
            # privilege_order ranks the same-tenant peers: the benign list stays
            # empty and the marker_reach crossing stays raised with alice
            # unranked, with no peer ranked, or with privilege_order left out
            # (PrecisionTest.test_precision_and_the_marker_backed_recall_do_not_rest_on_the_peer_ranking).
            # The inverted_guard candidate set does depend on it. carol
            # reaches GET /api/admin/keys where alice and bob get 403, and
            # inverted_guard raises that only while carol is ranked below
            # alice or bob; sibling_asymmetry raises the same pair under every
            # order
            # (PrecisionTest.test_the_inverted_guard_candidates_do_follow_the_peer_ranking).
            # Ranking bob above alice, the marker owner, is a declaration the
            # benign API refutes by refusing bob her invoice; it costs a
            # counted marker_reach suppression and a benign inverted_guard
            # (PrecisionTest.test_ranking_a_peer_above_the_marker_owner_is_counted_not_silent).
            "privilege_order": ["anon", "carol", "bob", "alice", "admin"],
            "unauthenticated": "anon",
        },
    }


def main() -> None:
    here = Path(__file__).resolve().parent
    for name, planted in (("benign", False), ("idor", True)):
        (here / f"matrix.{name}.json").write_text(
            json.dumps(matrix_document(build(planted=planted)), indent=1) + "\n",
            encoding="utf-8",
        )
        (here / f"blastradius.{name}.json").write_text(
            json.dumps(config(), indent=1) + "\n", encoding="utf-8"
        )
        print(f"wrote matrix.{name}.json and blastradius.{name}.json")


if __name__ == "__main__":
    main()
