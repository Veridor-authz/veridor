"""Projections over an access matrix: observed reach, and inconsistencies in it.

WHAT THIS MODULE IS
===================

Everything here is a *pure projection* over an :class:`veridor.matrix.AccessMatrix`.
Nothing in this file opens a socket, reads a file, issues a request, or observes
a response body. The matrix does the dangerous part; this module only counts
what it already recorded.

Two projections:

* **Blast radius** -- for each named identity, which operations it was OBSERVED
  to reach. Always a lower bound, always printed with its unmeasured count, and
  never rendered as a percentage over an incomplete denominator.
* **Anomaly candidates** -- inconsistencies between observations. If an identity
  is refused on 47 of 48 sibling operations and reaches the 48th, that 48th is
  worth declaring an expectation for. Nobody had to declare a policy first: the
  inconsistency is visible in the observations alone.

THE DISCIPLINE: DISCOVERY PROPOSES, DECLARATION DISPOSES
========================================================

A candidate is a HYPOTHESIS, never a finding. Veridor's credibility rests on
findings being proof-backed and on the configuration being the policy. A
candidate is something an operator promotes into a declared expectation, which
then either holds or fails on the normal ``veridor run`` path.

That discipline is enforced structurally, not by convention:

* :meth:`Candidate.to_dict` emits ``candidate_id`` and ``rule`` -- never ``id``,
  ``verdict``, ``evidence_grade``, ``rule_id``, ``level``, ``message``,
  ``location`` or ``check_id``. A consumer that splices a candidate into
  ``findings`` raises ``KeyError`` inside ``core._compare_findings`` (which keys
  on ``finding["id"]``) instead of silently emitting a SARIF result.
* ``is_finding`` is a literal ``False`` on every candidate, and ``status`` is
  the literal ``"candidate"``.
* This module imports neither ``veridor.core`` nor any SARIF machinery, so it
  cannot produce a SARIF result or an exit code even by accident. The exit-code
  contract for the follow-on CLI wiring: **0** on a completed run regardless of
  candidate count, **2** on a safety refusal or configuration error, **3** on an
  abort, and never **1** -- that code belongs to the run path and means a
  declared expectation was violated. A candidate must never turn CI red.
* Vocabulary is policed: :data:`BANNED_CANDIDATE_WORDS` extends
  ``coverage.BANNED_CLAIM_WORDS``, and a test renders every rule and asserts no
  banned word survives into any string this module can produce.

A CANDIDATE NOBODY READS IS WORTH LESS THAN NO CANDIDATE
=========================================================

The discipline above keeps candidates from becoming findings. It does nothing
about volume, and volume is the other way this fails. A 43-operation API in
which every single access was correct once produced 30 candidates -- 21 of them
one rule emitting its own measured dominant failure mode, one per tenant-scoped
row, so the list grew with the size of the spec rather than with anything
anomalous. An operator who reads thirty tagged hypotheses and finds nothing in
any of them stops reading the list, and a rule nobody reads detects nothing.

So a rule that has measured its own dominant false-positive shape SUPPRESSES it
rather than tagging it. Tagging is for a shape that is ambiguous; suppression is
for one the rule itself can show is almost always correct behaviour from the
evidence on the row in front of it. The distinction matters: a suppression based
on a guess about what a path MEANS is a denylist and is refused (see
:data:`CONVENTIONALLY_PUBLIC_PATTERNS`), while one based on the rule's own
arithmetic is the rule working.

Every suppression is counted and reported. :func:`find_candidates` fills a
``suppressions`` dict, :func:`discovery_notes` renders it by reason and count,
and each rule names the recall it gave up in its ``false_positive_modes``.
A quiet target and a broken rule must never look the same.

WHAT A RULE MAY READ
====================

Only cells where ``Cell.measured`` is true -- ``outcome == "observed"`` and
``reach != "unknown"``. An unprobed, skipped, throttled, errored or crashed cell
says nothing about the boundary in EITHER direction, and reading one as a denial
would fabricate a disagreement out of an absence. This precondition is applied
once, in :meth:`_Context.measured`, rather than being re-derived per rule.

DEPENDENCY DIRECTION
====================

``blastradius -> matrix -> openapi`` and ``blastradius -> coverage``. ``matrix``
imports ``core`` lazily, inside ``default_prober`` only, so importing this module
never pulls in the request machinery.

:class:`BlastRadiusError` subclasses ``ValueError`` for the same reason
``matrix.MatrixError`` does: subclassing ``core.ConfigError`` would require
importing ``core`` at module scope. ``core.ConfigError`` is itself a
``ValueError``, so ``except ValueError`` catches either, and a caller that wants
to distinguish them should catch ``(ConfigError, MatrixError, BlastRadiusError)``
explicitly and map all three to exit 2.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, replace
from fractions import Fraction
from typing import Any, Collection, Iterable, Mapping, Sequence

from veridor.credentials import (  # noqa: F401 -- re-exported
    BENIGN_HEADER_NAMES,
    BENIGN_HEADER_PREFIXES,
    is_benign_header,
    presents_credential,
)
from veridor.coverage import (
    BANNED_CLAIM_WORDS,
    DEFAULT_DENIAL_STATUSES,
    REPORT_WIDTH,
    wrap_paragraph,
)
from veridor.matrix import (
    CLAIM,
    OPERATION_LEVEL_LIMITATION,
    REACH_INDETERMINATE,
    REACH_REACHED,
    REACH_REFUSED,
    REFUSAL_METHOD_NOT_SUPPORTED,
    REFUSAL_UNAUTHENTICATED,
    SAFETY_POSTURE,
    AccessMatrix,
    Cell,
)
from veridor.openapi import TEMPLATE_TOKEN, split_segments
from veridor.terminal import quoted, terminal_names, terminal_text

__all__ = [
    "BANNED_CANDIDATE_WORDS",
    "BLAST_RADIUS_KIND",
    "CANDIDATES_KIND",
    "CANDIDATE_FOOTER",
    "CLAIM",
    "CONVENTIONALLY_PUBLIC_PATTERNS",
    "SCHEMA_VERSION",
    "ZERO_CANDIDATE_FOOTER",
    "BlastRadius",
    "BlastRadiusError",
    "Candidate",
    "CandidateOptions",
    "PeerGrouping",
    "RULES",
    "Rule",
    "banned_words_in",
    "blast_radius_report",
    "candidates_document",
    "compute_blast_radius",
    "credential_bearing_identities",
    "discovery_notes",
    "find_candidates",
    "peer_groups",
    "promotion_stub",
    "rank_candidates",
    "render_blast_radius",
    "render_candidates",
    "unprobed_siblings",
]


class BlastRadiusError(ValueError):
    """Raised when a peer grouping cannot be built from a configuration.

    Not a subclass of ``core.ConfigError``; see the module docstring. Both are
    ``ValueError`` subclasses.
    """


SCHEMA_VERSION: int = 1
BLAST_RADIUS_KIND: str = "veridor.blast_radius"
CANDIDATES_KIND: str = "veridor.candidates"

_MAX_LISTED: int = 50

#: Vocabulary that must never describe a candidate. A candidate is an
#: inconsistency between observations; asserting more than that is the exact
#: behaviour of the noisy scanner this product exists to replace.
BANNED_CANDIDATE_WORDS: tuple[str, ...] = (
    "vulnerability",
    "vulnerable",
    "exploit",
    "exploitable",
    "breach",
    "leak",
    "insecure",
    "misconfiguration",
    "flaw",
    "bug",
    "idor",
    "bola",
    "broken",
    "unauthorized",
    "attack",
    "attacker",
    "compromise",
    "critical",
    "severity",
)

#: The full policed vocabulary: this module's list plus ``coverage``'s.
_POLICED_WORDS: tuple[str, ...] = tuple(
    dict.fromkeys(BANNED_CANDIDATE_WORDS + BANNED_CLAIM_WORDS)
)

#: The base and present forms of a policed stem that no suffix rule reaches
#: from the policed word itself, plus the common derived forms listed here. A
#: word policed as a participle or an adjective ("guaranteed", "protected",
#: "safe") reached only that form: the suffixes appended to "guaranteed" never
#: produce "guarantees", and nothing produced "protection" or "safety". Each
#: form here is inflected in turn, so "protection" also polices "protections".
#: This is not every derived form English has -- a derived form that is not
#: listed here or in :data:`_LITERAL_FORMS` is not policed.
#: `broken` has no entry on purpose: its stem is "break", which a report
#: legitimately uses ("a line break").
_STEM_FORMS: dict[str, tuple[str, ...]] = {
    "vulnerable": ("vulnerably",),
    "exploit": ("exploiter", "exploitative"),
    "exploitable": ("exploitability", "exploitably"),
    "breach": ("breachable",),
    "leak": ("leaky",),
    "misconfiguration": ("misconfigure",),
    "bug": ("buggy", "bugged", "bugging"),
    "attack": ("attackable",),
    "compromise": ("compromisable",),
    "protected": ("protect", "protection", "protective", "protector"),
    "safe": ("safer", "safest", "safety"),
    "compliant": ("comply", "compliance"),
    "verified": ("verify", "verification", "verifiable", "verifiability", "verifiably"),
    "guaranteed": ("guarantee", "guaranteeing", "guarantor"),
}

#: Forms policed exactly as written, never inflected. "severe" inflected like
#: the others reached "severed" and "severing", which are ordinary English for
#: "cut" ("a severed socket"), so its forms are spelled out here instead.
_LITERAL_FORMS: dict[str, tuple[str, ...]] = {
    "leak": ("leakier", "leakiest"),
    "severity": ("severe", "severely", "severer", "severest"),
}


def _inflected(word: str) -> str:
    """One policed word and the forms that change its stem, as a regex.

    Suffixes appended to the whole word missed every form that does not keep
    it intact -- "vulnerabilities", "severities", "insecurity", "compromising"
    -- plus "leakage", "exploitation" and the British "unauthorised". The
    vocabulary tests then read as enforcing and could not fail on any of them.
    Forms of the stem that no suffix reaches come from :data:`_STEM_FORMS`,
    and forms that must not be inflected from :data:`_LITERAL_FORMS`.
    """
    stem = re.escape(word).replace("iz", "i[sz]")
    forms = [stem + r"(?:s|es|d|ed|ing|ity|ities|ly|age|ation|ations)?"]
    if word.endswith("y"):
        forms.append(stem[:-1] + r"(?:ies|ied)")
    if word.endswith("e"):
        forms.append(stem[:-1] + r"(?:ing|ity|ities|ation|ations)")
    return "|".join(forms)


def _policed_family(word: str) -> str:
    inflected = [_inflected(form) for form in (word, *_STEM_FORMS.get(word, ()))]
    literal = [re.escape(form) for form in _LITERAL_FORMS.get(word, ())]
    return "|".join(inflected + literal)


#: Whole words only, with the ordinary English inflections. Substring matching
#: is wrong here for a concrete reason: "Veridor" contains "idor", so a naive
#: ``word in text`` check would flag the product's own name in every heading.
_POLICED_PATTERN = re.compile(
    r"\b(?:" + "|".join(_policed_family(word) for word in _POLICED_WORDS) + r")\b",
    re.IGNORECASE,
)


def banned_words_in(text: str) -> tuple[str, ...]:
    """Every policed word occurring in ``text``, lower-cased and de-duplicated."""
    return tuple(dict.fromkeys(match.lower() for match in _POLICED_PATTERN.findall(text)))


_NOT_A_FINDING: str = (
    "This is an inconsistency in the observations, not a finding. Declare the "
    "expectation to test it."
)

CANDIDATE_FOOTER: str = (
    "Candidates are hypotheses derived from observation. Veridor has not tested any "
    "of them and has established nothing about them. Promote a candidate into a "
    "declared expectation in your configuration and run `veridor run`; that run will "
    "either uphold the expectation or produce a proof-backed finding."
)

ZERO_CANDIDATE_FOOTER: str = (
    "No inconsistencies were computed from this matrix. This does not mean the "
    "observed accesses are correct -- only that they are mutually consistent. "
    "Consistency is not authorization."
)

_INCOMPLETE_STAMP: str = (
    "INCOMPLETE -- this run aborted after {issued} of {planned} requests ({reason}). "
    "The reach numbers below are a floor over a partial matrix."
)

_CLAIM_PARAGRAPH: str = (
    "  Reach is an OBSERVATION, not a verdict: an operation an identity reached\n"
    "  may be exactly what policy intends. Blast radius is a lower bound on\n"
    "  observed reach, not a measure of exposure. Anomaly candidates are\n"
    "  inconsistencies in the observations; they are hypotheses to declare and\n"
    "  test, never findings."
)

#: Tags. Every tag lowers a candidate's rank and is printed; none of them
#: silently drops a candidate. A denylist that hides results is how a real
#: problem on a ``/health`` endpoint goes unreported.
TAG_CONVENTIONALLY_PUBLIC: str = "conventionally_public"
TAG_COLLECTION_VS_ITEM: str = "collection_vs_item"
#: Several peers reached one shared object and no marker says which of them owns
#: it, so one of the candidates on that row is presumably the owner's own
#: correct access. Ranks the row below one where a marker settled the question.
TAG_OWNER_UNIDENTIFIED: str = "owner_not_identified"
TAG_PARTIAL_MATRIX: str = "partial_matrix"
TAG_NON_UNANIMOUS: str = "non_unanimous_majority"
#: Applied when SOME, not all, of the declared-higher identities were refused
#: with 404. The all-404 case is suppressed by ``inverted_guard`` outright; see
#: that rule for why that one is not a tag.
TAG_HIGHER_IDENTITY_ABSENT: str = "higher_identity_absent_or_denied"
TAG_IDENTICAL_BODY: str = "identical_body_bytes"

TIER_MARKER_BACKED: str = "marker_backed"
TIER_OBSERVED_ONLY: str = "observed_only"
_TIER_ORDER: dict[str, int] = {TIER_MARKER_BACKED: 0, TIER_OBSERVED_ONLY: 1}

#: Templates conventionally open to an unauthenticated caller. Matching one is a
#: TAG that ranks a candidate last -- never a suppression. A ``/health``
#: endpoint that really does return another identity's data is exactly the thing
#: a denylist would hide. Permanent suppression is the operator's decision, made
#: in ``matrix.ignore``, which is echoed in every document.
CONVENTIONALLY_PUBLIC_PATTERNS: tuple[str, ...] = (
    "/health",
    "/healthz",
    "/livez",
    "/readyz",
    "/ping",
    "/status",
    "/version",
    "/metrics",
    "/.well-known/*",
    "/openapi*",
    "/swagger*",
    "/login",
    "/logout",
    "/auth/*",
    "/register",
    "/robots.txt",
    "/favicon.ico",
)


# ---------------------------------------------------------------------------
# the rule table
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """One anomaly rule, its rank tier, and its stated failure modes.

    ``false_positive_modes`` is mandatory. A rule whose failure modes are not
    written down cannot be registered, because a candidate the operator cannot
    dismiss on sight is a candidate they learn to ignore wholesale.
    """

    name: str
    tier: int
    shape: str
    false_positive_modes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.false_positive_modes:
            raise BlastRadiusError(
                f"rule {quoted(self.name)} declares no false_positive_modes; a rule whose "
                "failure modes are not stated cannot be registered"
            )


def _rule(name: str, tier: int, shape: str, *modes: str) -> Rule:
    return Rule(name=name, tier=tier, shape=shape, false_positive_modes=tuple(modes))


#: Ordered by how FEW assumptions the rule makes, lowest tier first.
#: ``marker_reach`` assumes nothing -- a planted marker physically moved between
#: identities. ``sibling_asymmetry`` rests on an INFERRED path family and is the
#: most assumption-heavy, so it ranks below every rule resting on declared
#: configuration.
RULES: dict[str, Rule] = {
    rule.name: rule
    for rule in (
        _rule(
            "marker_reach",
            0,
            "one identity's planted marker was observed in another identity's response",
            "A genuinely shared resource that is meant to carry several identities' "
            "records: a shared audit feed, a group changelog, a tenant-wide search "
            "index. Where that resource is a COLLECTION and every active member of "
            "the marker owner's declared peer group reached it, the row is excluded "
            "outright: a feed the whole declared group reads is the feed working, "
            "and the marker in it is an aggregated record rather than a crossing.",
            "Excluding it means a collection the whole declared peer group can reach "
            "but should not is not raised by this rule. An identified object is never "
            "excluded this way -- a specimen or a templated final segment names ONE "
            "object, one object has one owner, and the exclusion does not apply.",
            "A marker value that also occurs naturally in the data.",
            "Reflection is impossible by construction: core refuses a configuration "
            "that would send a marker it later matches.",
            "A reader the operator declared strictly ABOVE the marker's owner in "
            "privilege_order is excluded, so an incomplete or wrong privilege_order "
            "can hide a real crossing here.",
        ),
        _rule(
            "unauthenticated_reach",
            1,
            "the identity designated unauthenticated returned a success status",
            "Public or read-only APIs, and documented open endpoints.",
            "Static assets and CDN-fronted routes.",
            "Conventionally-public templates (/health, /version, /auth/*) are "
            "excluded unless the row carried a planted marker, so another "
            "identity's data reaching an unauthenticated caller from one of those "
            "paths without carrying the marker is not raised.",
        ),
        _rule(
            "inverted_guard",
            2,
            "a lower-privilege identity reached what a declared higher one did not",
            "Privilege is very often not a total order. A platform administrator "
            "has no tenant and is correctly 404'd on tenant-scoped objects that a "
            "tenant user reaches legitimately; a billing administrator is not "
            "'above' a tenant user for tenant data. That shape -- every higher "
            "identity refused with 404 -- was the single most common one here and "
            "almost always correct, so it is now excluded outright; a row where at "
            "least one higher identity was refused with 403 or 401 survives.",
            "Excluding it means a real inverted guard whose higher identities all "
            "happen to answer 404 is not raised by this rule.",
            "The declared privilege_order is wrong or incomplete.",
        ),
        _rule(
            "peer_divergence",
            3,
            "several members of a declared peer group reached one shared object",
            "Ownership is handled rather than merely declared: a single reacher is "
            "taken to be the object's owner and raises nothing. Where two or more "
            "reached and no marker names the owner, one of the candidates on that "
            "row IS the owner's own correct access, and is tagged as such.",
            "A specimen declared shared that is not really one object -- an alias, "
            "a redirect to 'my' record, or an identifier the target reinterprets "
            "per caller.",
            "The declared peer group is wrong -- one 'peer' is also a group owner "
            "or a billing administrator.",
        ),
        _rule(
            "sibling_asymmetry",
            4,
            "an identity refused on nearly every member of a path family reached one",
            "Collection-versus-item semantics, the dominant failure mode: "
            "/api/invoices returns YOUR invoices and is correctly reachable, while "
            "its siblings /api/invoices/{id} carrying somebody else's identifier "
            "are correctly refused.",
            "Semantically mixed prefixes, such as /api/config/public sitting under "
            "an otherwise closed /api/config/, or the /api/admin/whoami capability "
            "probe that answers every caller so a single-page app can decide "
            "whether to draw the admin nav. Where the SAME sibling is the exception "
            "for two or more independently locked-out identities, it is excluded "
            "outright: a route that is open to everyone the family shuts out is an "
            "open route, not one identity's hole in a guard.",
            "Excluding it means a sibling wrongly open to two or more identities at "
            "once is not raised by this rule; only a sibling open to exactly one is.",
            "The family must contain at least min_refused_siblings refusals and the "
            "reaches must be outnumbered by them, so a prefix an identity reaches "
            "wholesale is not raised here at all -- read that from blast radius.",
            "Flat or RPC-shaped APIs, where every operation lands in one family and "
            "the family loses meaning.",
        ),
        _rule(
            "method_asymmetry",
            5,
            "two verbs on the same template disagreed for the same identity",
            "Method-override middleware makes the verbs non-independent.",
            "CORS preflight handling.",
            "APIs where PUT is an upsert with different authorization semantics by "
            "design: create-if-absent is genuinely allowed where update is not.",
        ),
    )
}


# ---------------------------------------------------------------------------
# blast radius
# ---------------------------------------------------------------------------

Row = tuple[str, "str | None"]


@dataclass(frozen=True)
class BlastRadius:
    """One identity's observed reach over one matrix. Always a lower bound."""

    identity: str
    reached: tuple[Row, ...]
    refused: tuple[Row, ...]
    indeterminate: tuple[Row, ...]
    unmeasured: tuple[tuple[str, str | None, str], ...]
    inventory: int
    empty_bodied: int = 0
    refusal_kinds: tuple[tuple[str, int], ...] = ()
    unknown_reasons: tuple[tuple[str, int], ...] = ()
    uniformly_unauthenticated: bool = False

    @property
    def observed(self) -> int:
        return len(self.reached) + len(self.refused) + len(self.indeterminate)

    @property
    def share(self) -> str | None:
        """The reached share, or ``None`` when any cell went unmeasured.

        A percentage over an incomplete denominator invites the reader to treat
        it as the answer, so it is not rendered at all while anything is
        unmeasured.
        """
        if self.unmeasured or self.observed <= 0:
            return None
        return _format_share_ceiling(len(self.reached), self.observed)

    @property
    def headline(self) -> str:
        text = (
            f'Observed reach (lower bound), identity "{terminal_text(self.identity)}": '
            f"{len(self.reached)} of {self.inventory} probed operations returned a "
            "success status."
        )
        if self.unmeasured:
            text = (
                f'Observed reach (lower bound), identity "{terminal_text(self.identity)}": at least '
                f"{len(self.reached)} of {self.inventory} probed operations returned a "
                "success status."
            )
        return text


def _format_share_ceiling(reached: int, observed: int) -> str:
    """Mirror of ``coverage.format_percent``, rounded the other way.

    ``coverage`` floors, because overstating coverage is its dangerous
    direction. Blast radius ceils, because UNDERstating reach is this module's
    dangerous direction: a number that reads low is a number nobody acts on.
    Both saturating cases are named rather than rounded into.
    """
    if observed <= 0:
        return "n/a"
    if reached >= observed:
        return "100.0%"
    ceiled = math.ceil(reached * 1000 / observed) / 10
    if reached > 0 and ceiled <= 0.0:
        return "<0.1%"
    if ceiled >= 100.0:
        return ">99.9%"
    return f"{ceiled:.1f}%"


def compute_blast_radius(matrix: AccessMatrix, identity: str) -> BlastRadius:
    """Project one identity's row onto reached / refused / indeterminate / unmeasured.

    ``unknown`` cells land in ``unmeasured`` and are counted separately on every
    rendering. They are never folded into ``refused``: reading "we did not
    measure this" as "the target refused this" understates reach, which is the
    dangerous direction.
    """
    if identity not in matrix.identities:
        raise BlastRadiusError(
            f"identity {quoted(identity)} is not in this matrix "
            f"({terminal_names(matrix.identities) or 'none'})"
        )
    reached: list[Row] = []
    refused: list[Row] = []
    indeterminate: list[Row] = []
    unmeasured: list[tuple[str, str | None, str]] = []
    refusal_kinds: dict[str, int] = {}
    unknown_reasons: dict[str, int] = {}
    empty_bodied = 0
    unauthenticated = 0

    for operation, specimen in matrix.rows:
        cell = matrix.cell(operation, identity, specimen)
        if cell is None:
            unmeasured.append((operation, specimen, "not_probed"))
            unknown_reasons["not_probed"] = unknown_reasons.get("not_probed", 0) + 1
            continue
        if not cell.measured:
            reason = cell.unknown_reason or "not_probed"
            unmeasured.append((operation, specimen, reason))
            unknown_reasons[reason] = unknown_reasons.get(reason, 0) + 1
            continue
        if cell.reach == REACH_REACHED:
            reached.append((operation, specimen))
            if cell.body_empty:
                empty_bodied += 1
        elif cell.reach == REACH_REFUSED:
            refused.append((operation, specimen))
            kind = cell.refusal_kind or "unclassified"
            refusal_kinds[kind] = refusal_kinds.get(kind, 0) + 1
            if cell.refusal_kind == REFUSAL_UNAUTHENTICATED:
                unauthenticated += 1
        elif cell.reach == REACH_INDETERMINATE:
            indeterminate.append((operation, specimen))

    measured_total = len(reached) + len(refused) + len(indeterminate)
    return BlastRadius(
        identity=identity,
        reached=tuple(reached),
        refused=tuple(refused),
        indeterminate=tuple(indeterminate),
        unmeasured=tuple(unmeasured),
        inventory=len(matrix.rows),
        empty_bodied=empty_bodied,
        refusal_kinds=tuple(sorted(refusal_kinds.items())),
        unknown_reasons=tuple(sorted(unknown_reasons.items())),
        uniformly_unauthenticated=measured_total > 0 and unauthenticated == measured_total,
    )


#: The closed list of standard request headers that never carry a credential,
#: and the classifier built on it, live in :mod:`veridor.credentials` so that
#: ``core`` -- which must not import this module -- reads the same list: the
#: liveness rule and the sham planner used to answer "does this identity
#: present a credential" from six names and a regex, and disagreed with this
#: module about an anonymous identity that sends only ``Accept``.
_presents_a_credential = presents_credential


def credential_bearing_identities(
    config: Mapping[str, Any], known: Sequence[str]
) -> frozenset[str]:
    """The identities that present something a target could accept or reject.

    The one fact an :class:`AccessMatrix` cannot hold. It records identity
    NAMES and cells; whether a name arrived carrying a token lives only in the
    config, and without it a row of 401s has two opposite readings that no
    amount of looking at the matrix can separate.
    """
    identities = config.get("identities")
    if not isinstance(identities, Mapping):
        return frozenset(known)
    # The operator's declaration settles it. `matrix.unauthenticated` names the
    # identity that is SUPPOSED to present nothing, so reading its headers to
    # decide the same question -- and reaching the opposite answer -- was the
    # M1 defect surviving its own fix: an anonymous identity carrying `Accept`
    # was suppressed from every rule, and told "the target never accepted this
    # credential" about a credential the config says it does not send.
    section = config.get("matrix")
    declared = section.get("unauthenticated") if isinstance(section, Mapping) else None
    return frozenset(
        name
        for name in known
        if name != declared and _presents_a_credential(identities.get(name))
    )


def uniformly_unauthenticated_identities(
    matrix: AccessMatrix, credentialed: Collection[str] | None = None
) -> tuple[str, ...]:
    """Identities that PRESENT a credential and whose every measured cell is a 401.

    A 407 is not one: it is a proxy's answer, recorded as unmeasured
    (``matrix.classify_reach``), because the target never saw the credential.

    That is a credential the target never accepted -- a configuration problem,
    not a posture -- so the identity is suppressed from every rule. Comparing
    against a row that was never authenticated manufactures disagreement out of
    a stale token.

    ``credentialed`` is the whole guard. An identity that presents NOTHING --
    the ``{"headers": {}}`` the README asks for, the identity
    ``matrix.unauthenticated`` names -- draws a 401 on every operation when the
    boundary is doing its job, and reading that as a rejected credential
    inverted the plainest row the matrix can carry. Suppressing it also deleted
    the refusals other rules read: on an operation two tenants both reached,
    the anonymous 401 is the refusal that makes peer_divergence a candidate at
    all, so declaring the identity deleted the finding. ``None`` treats every
    identity as credentialed, which is what a caller holding only a matrix can
    honestly assume.
    """
    return tuple(
        identity
        for identity in matrix.identities
        if (credentialed is None or identity in credentialed)
        and compute_blast_radius(matrix, identity).uniformly_unauthenticated
    )


def blast_radius_report(
    matrix: AccessMatrix, credentialed: Collection[str] | None = None
) -> dict[str, Any]:
    """The ``veridor.blast_radius`` artifact: every identity's observed reach.

    ``credentialed`` has the meaning it has in
    :func:`uniformly_unauthenticated_identities`, and is threaded here so the
    ``row_uniformly_unauthenticated`` field means what the suppression means.
    Without it the report named a rejected credential for an identity that
    presents none while the rules -- correctly -- left that identity active,
    and one artifact said two different things.
    """
    identities: list[dict[str, Any]] = []
    for name in matrix.identities:
        radius = compute_blast_radius(matrix, name)
        if credentialed is not None and name not in credentialed:
            radius = replace(radius, uniformly_unauthenticated=False)
        identities.append(
            {
                "identity": name,
                "headline": radius.headline,
                "counts": {
                    "reached": len(radius.reached),
                    "refused": len(radius.refused),
                    "indeterminate": len(radius.indeterminate),
                    "unmeasured": len(radius.unmeasured),
                    "observed": radius.observed,
                    "inventory": radius.inventory,
                    "empty_bodied": radius.empty_bodied,
                },
                "share": radius.share,
                "reached_operations": [
                    _row_entry(matrix, name, row) for row in radius.reached
                ],
                "refused_operations": [
                    _row_entry(matrix, name, row) for row in radius.refused
                ],
                "indeterminate_operations": [
                    _row_entry(matrix, name, row) for row in radius.indeterminate
                ],
                "unmeasured_operations": [
                    {"operation": operation, "specimen": specimen, "reason": reason}
                    for operation, specimen, reason in radius.unmeasured
                ],
                "refusal_kinds": dict(radius.refusal_kinds),
                "unknown_reasons": dict(radius.unknown_reasons),
                "row_uniformly_unauthenticated": radius.uniformly_unauthenticated,
            }
        )
    return {
        "kind": BLAST_RADIUS_KIND,
        "schema_version": SCHEMA_VERSION,
        "claim": dict(CLAIM),
        "limitation": OPERATION_LEVEL_LIMITATION.format(specimens=matrix.max_specimens),
        "object_level": False,
        "safety": _safety_block(matrix),
        "target": {
            "base_url": matrix.base_url,
            "host": matrix.host,
            "target_class": matrix.target_class,
        },
        "inventory": {
            "rows": len(matrix.rows),
            "operations": len(matrix.operations),
            "identities": len(matrix.identities),
            "max_specimens": matrix.max_specimens,
        },
        "ignored": list(matrix.ignored),
        "identities": identities,
    }


def _row_entry(matrix: AccessMatrix, identity: str, row: Row) -> dict[str, Any]:
    operation, specimen = row
    cell = matrix.cell(operation, identity, specimen)
    return {
        "operation": operation,
        "specimen": specimen,
        "url_path": cell.url_path if cell else "",
        "status": cell.status if cell else None,
        "refusal_kind": cell.refusal_kind if cell else None,
        "body_empty": cell.body_empty if cell else None,
    }


def _safety_block(matrix: AccessMatrix) -> dict[str, Any]:
    return {
        "posture": SAFETY_POSTURE,
        "read_only": matrix.read_only,
        "permitted_methods": list(matrix.permitted_methods),
        "requests_per_second": matrix.requests_per_second,
        "concurrency": "sequential",
        "follows_redirects": False,
        "planned": matrix.planned,
        "issued": matrix.issued,
        "aborted": matrix.aborted,
        "abort_reason": matrix.abort_reason,
    }


def _incomplete_stamp(safety: Mapping[str, Any]) -> str | None:
    if not safety.get("aborted"):
        return None
    return _INCOMPLETE_STAMP.format(
        issued=safety.get("issued", 0),
        planned=safety.get("planned", 0),
        reason=safety.get("abort_reason") or "unknown",
    )


def render_blast_radius(report: Mapping[str, Any]) -> str:
    """Render the human blast-radius report.

    The claim paragraph and the operation-level limitation are printed under the
    headline, always, and are not suppressible by any flag -- the same treatment
    ``coverage.render_text`` gives its own claim block.
    """
    inventory = report["inventory"]
    lines = [
        "Veridor blast radius -- observed reach per identity",
        f"  target:    {report['target']['host']} ({report['target']['target_class']})",
        f"  matrix:    {inventory['rows']} operation-specimen rows x "
        f"{inventory['identities']} identities",
        f"  requests:  {report['safety']['issued']} of {report['safety']['planned']} "
        "issued",
    ]
    stamp = _incomplete_stamp(report["safety"])
    if stamp:
        lines.append("")
        lines.append(stamp)
    lines.append("")
    lines.append(_CLAIM_PARAGRAPH)
    lines.append("")
    lines.append(_wrap(report["limitation"], "  "))
    if report["ignored"]:
        lines.append("")
        lines.append(
            "  Suppressed by matrix.ignore (echoed so suppression is always visible): "
            # Every entry, each bounded: a list cut short would hide one.
            + ", ".join(terminal_text(entry) for entry in report["ignored"])
        )
    lines.append("")

    for entry in report["identities"]:
        counts = entry["counts"]
        lines.append(entry["headline"])
        if counts["indeterminate"]:
            # Two different things share the bucket: a 3xx (core never follows
            # a redirect) and any other status that is neither reach nor
            # refusal -- a 400, 409, 422. Calling the second a redirect, and
            # advising a "post-redirect status" no matrix setting accepts, was
            # wrong for both.
            redirects = sum(
                1 for item in entry.get("indeterminate_operations", ())
                if isinstance(item.get("status"), int) and 300 <= item["status"] <= 399
            )
            other = counts["indeterminate"] - redirects
            if redirects:
                lines.append(
                    f"  {redirects} unresolved (redirect, not followed). "
                    "Veridor does not follow redirects, so their reach is unresolved."
                )
            if other:
                lines.append(
                    f"  {other} unresolved (a status that is neither reach nor "
                    "refusal, such as 400 or 422). The handler answered without "
                    "returning a success or refusing the caller, so their reach is "
                    "unresolved."
                )
        lines.append(
            f"  reached {counts['reached']}   refused {counts['refused']}   "
            f"unresolved {counts['indeterminate']}   unmeasured {counts['unmeasured']}"
            f"   of {counts['inventory']}"
        )
        if entry["share"] is not None:
            lines.append(f"  share of observed operations reached: {entry['share']}")
        else:
            lines.append(
                "  no share is rendered: "
                f"{counts['unmeasured']} operation(s) were not measured, and a "
                "percentage over an incomplete denominator reads as the answer."
            )
        if entry["row_uniformly_unauthenticated"]:
            lines.append(
                "  every measured cell for this identity is a 401 (a 407 is the "
                "proxy's answer and is counted as unmeasured), and it "
                "presents a credential. That is a credential the target never "
                "accepted, not a posture; this identity is suppressed from every "
                "rule. An identity that presents no credential is never suppressed "
                "for this: a 401 everywhere is not evidence of a credential the "
                "target rejected."
            )
        if counts["empty_bodied"]:
            lines.append(
                f"  {counts['empty_bodied']} of the {counts['reached']} reached "
                "operations returned a zero-byte body. Veridor does not parse bodies "
                "and cannot tell an empty collection from a full one."
            )
        for row in entry["reached_operations"][:_MAX_LISTED]:
            lines.append(f"    reached  {_row_label(row)}  [{row['status']}]")
        if len(entry["reached_operations"]) > _MAX_LISTED:
            lines.append(
                f"    ... and {len(entry['reached_operations']) - _MAX_LISTED} more "
                "(see the JSON report)"
            )
        if entry["unmeasured_operations"]:
            reasons = ", ".join(
                f"{reason} x{count}"
                for reason, count in sorted(entry["unknown_reasons"].items())
            )
            lines.append(f"    unmeasured: {reasons}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _row_label(row: Mapping[str, Any]) -> str:
    if row.get("specimen"):
        return f"{terminal_text(row['operation'])} [specimen {terminal_text(row['specimen'])}]"
    return terminal_text(row["operation"])


def _wrap(text: str, indent: str, width: int = REPORT_WIDTH) -> str:
    """Wrap a paragraph and join it. One implementation, in ``coverage``.

    This hand-rolled copy broke one character early. It accumulated
    ``word + " "`` into ``current`` and then tested
    ``len(current) + len(word) + 1``, counting the trailing space it had
    already stored a second time. At width 77 a line of exactly 77 characters
    came back as two lines.

    So this changes ``map``'s printed output. Measured over the report prose
    Veridor actually emits rather than a randomised corpus, the two hand-rolled
    copies disagreed on 26% of inputs -- the randomised figure of ~12% was
    optimistic, because generated text has fewer long words landing on the
    boundary than real sentences do. Those paragraphs now use the full width
    they were always entitled to. Long tokens are still never split, which both
    copies already got right and which the stdlib defaults get wrong.
    """
    return "\n".join(wrap_paragraph(text, indent, width))


# ---------------------------------------------------------------------------
# peer groups
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PeerGrouping:
    """Declared group membership. Observation never invents a group.

    Clustering identities by observed row similarity would be circular: the
    outlier we want to surface is precisely the row that would either be
    excluded from its own cluster or pull the cluster toward itself and hide the
    deviation. A wrong grouping does not produce fewer candidates, it produces
    confidently wrong ones. Observation may rank and tag; it may never create
    the group it is measured against.
    """

    groups: tuple[tuple[str, tuple[str, ...]], ...] = ()
    privilege_order: tuple[str, ...] = ()
    unauthenticated: str | None = None
    unauthenticated_source: str = "none"
    unanimous: bool = True
    suppressed: tuple[str, ...] = ()
    diagnostics: tuple[dict[str, Any], ...] = ()

    def group_of(self, identity: str) -> tuple[str, tuple[str, ...]] | None:
        for name, members in self.groups:
            if identity in members:
                return (name, members)
        return None

    def rank_of(self, identity: str) -> int | None:
        if identity in self.privilege_order:
            return self.privilege_order.index(identity)
        return None


def peer_groups(config: Mapping[str, Any], matrix: AccessMatrix) -> PeerGrouping:
    """Read declared groups, privilege order and the unauthenticated identity.

    Every membership decision here comes from the configuration. The matrix is
    consulted only to check that a declared name was actually probed and to work
    out which identities are suppressed for having no accepted credential.
    """
    if not isinstance(config, Mapping):
        raise BlastRadiusError("configuration must be a mapping")
    section = config.get("matrix", {})
    if not isinstance(section, Mapping):
        raise BlastRadiusError("matrix must be an object")

    known = tuple(matrix.identities) or tuple(
        str(name) for name in (config.get("identities") or {})
    )
    diagnostics: list[dict[str, Any]] = []

    groups = _parse_peer_groups(section.get("peer_groups", {}), known)
    for name, members in groups:
        if len(members) == 1:
            diagnostics.append(
                _note(
                    "peer_group_singleton",
                    f"peer group {quoted(name)} has one member; peer divergence needs at "
                    "least two observations to compare and none were computed.",
                    group=name,
                )
            )
    grouped = {member for _, members in groups for member in members}
    ungrouped = [name for name in known if name not in grouped]
    if ungrouped:
        diagnostics.append(
            _note(
                "identity_in_no_peer_group",
                f"{len(ungrouped)} identity(ies) are in no declared peer group, so "
                "they produce no peer-based candidates: "
                + terminal_names(ungrouped),
                identities=list(ungrouped),
            )
        )

    privilege_order = _parse_privilege_order(section.get("privilege_order", ()), known)
    if not privilege_order:
        diagnostics.append(
            _note(
                "privilege_order_absent",
                "no matrix.privilege_order is declared, so the inverted_guard rule "
                "did not run. Privilege is never inferred from observed reach: the "
                "inversion the rule hunts for is exactly what would corrupt the "
                "inference.",
            )
        )

    unauthenticated, source = _resolve_unauthenticated(
        section, config, known, diagnostics
    )

    unanimous = section.get("peer_divergence_unanimous", True)
    if not isinstance(unanimous, bool):
        raise BlastRadiusError("matrix.peer_divergence_unanimous must be true or false")

    suppressed = uniformly_unauthenticated_identities(
        matrix, credential_bearing_identities(config, known)
    )
    for identity in suppressed:
        diagnostics.append(
            _note(
                "row_uniformly_unauthenticated",
                f"{quoted(identity)} presents a credential, and every measured cell for "
                "it is a 401 (a 407 is the proxy's answer and is counted as "
                "unmeasured): the target never accepted this credential. That "
                "is a configuration problem, not a posture; the identity is "
                "suppressed from every rule. An identity that presents no "
                "credential is never suppressed for this: a 401 everywhere is not "
                "evidence of a credential the target rejected.",
                identity=identity,
            )
        )
    if matrix.aborted:
        diagnostics.append(
            _note(
                "partial_matrix",
                f"the matrix run aborted after {matrix.issued} of {matrix.planned} "
                f"requests ({matrix.abort_reason}). Rules that need a family or group "
                "quorum simply failed to reach it; candidates that survived are "
                "tagged partial_matrix and ranked down.",
                issued=matrix.issued,
                planned=matrix.planned,
                reason=matrix.abort_reason,
            )
        )
    return PeerGrouping(
        groups=groups,
        privilege_order=privilege_order,
        unauthenticated=unauthenticated,
        unauthenticated_source=source,
        unanimous=unanimous,
        suppressed=suppressed,
        diagnostics=tuple(diagnostics),
    )


def _note(code: str, message: str, **fields: Any) -> dict[str, Any]:
    return {"code": code, "message": message, **fields}


def _parse_peer_groups(
    raw: Any, known: Sequence[str]
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(raw, Mapping):
        raise BlastRadiusError("matrix.peer_groups must be an object of name -> members")
    groups: list[tuple[str, tuple[str, ...]]] = []
    seen: dict[str, str] = {}
    for name, members in raw.items():
        if not isinstance(name, str) or not name.strip():
            raise BlastRadiusError("matrix.peer_groups keys must be non-empty strings")
        if not isinstance(members, list) or not members:
            raise BlastRadiusError(
                f"matrix.peer_groups[{quoted(name)}] must be a non-empty list of identity names"
            )
        parsed: list[str] = []
        for member in members:
            if not isinstance(member, str) or member not in known:
                raise BlastRadiusError(
                    f"matrix.peer_groups[{quoted(name)}] names {quoted(member)}, which is not one "
                    f"of the probed identities ({terminal_names(known) or 'none'})"
                )
            if member in parsed:
                raise BlastRadiusError(
                    f"matrix.peer_groups[{quoted(name)}] lists {quoted(member)} twice"
                )
            if member in seen:
                raise BlastRadiusError(
                    f"{quoted(member)} is in peer groups {quoted(seen[member])} and {quoted(name)}. An "
                    "identity belongs to at most one peer group: with overlapping "
                    "groups, 'the group disagrees' has no single referent."
                )
            seen[member] = name
            parsed.append(member)
        groups.append((name, tuple(parsed)))
    return tuple(groups)


def _parse_privilege_order(raw: Any, known: Sequence[str]) -> tuple[str, ...]:
    if raw in (None, ()):
        return ()
    if not isinstance(raw, list):
        raise BlastRadiusError(
            "matrix.privilege_order must be a list of identity names, lowest first"
        )
    order: list[str] = []
    for name in raw:
        if not isinstance(name, str) or name not in known:
            raise BlastRadiusError(
                f"matrix.privilege_order names {quoted(name)}, which is not one of the "
                f"probed identities ({terminal_names(known) or 'none'})"
            )
        if name in order:
            raise BlastRadiusError(f"matrix.privilege_order lists {quoted(name)} twice")
        order.append(name)
    return tuple(order)


def _resolve_unauthenticated(
    section: Mapping[str, Any],
    config: Mapping[str, Any],
    known: Sequence[str],
    diagnostics: list[dict[str, Any]],
) -> tuple[str | None, str]:
    declared = section.get("unauthenticated")
    identities = config.get("identities")
    session_backed = (
        sorted(
            name
            for name in known
            if isinstance(identities.get(name), Mapping)
            and "session" in identities[name]
        )
        if isinstance(identities, Mapping)
        else []
    )
    # One predicate for "presents a credential", shared with the suppression in
    # ``peer_groups``. If these two ever disagree, the identity map calls
    # unauthenticated and the identity the suppression spares stop being the
    # same identity -- and the disagreement would be silent.
    if declared is not None:
        if not isinstance(declared, str) or declared not in known:
            raise BlastRadiusError(
                f"matrix.unauthenticated {quoted(declared)} must name one of the probed "
                f"identities ({terminal_names(known) or 'none'})"
            )
        # Checked BEFORE deferring to the declaration, not after. An explicit
        # declaration normally wins -- the operator knows their target and this
        # module does not -- but naming a session-backed identity as the
        # UNAUTHENTICATED one is not a preference, it is a contradiction: that
        # identity authenticates by logging in. Honouring it would run
        # unauthenticated_reach against a credentialed identity and report a
        # SMALLER reach than reality, which is the false-SAFE direction and the
        # worst failure this product has. Refusing keeps the second guard
        # genuinely independent of the first, rather than independent only for
        # the inputs the first one happens to reject.
        if declared in session_backed:
            raise BlastRadiusError(
                f"matrix.unauthenticated names {quoted(declared)}, which authenticates "
                "through a 'session' block. An identity that logs in is not the "
                "unauthenticated identity, and treating it as one would measure "
                "its reach as anonymous and understate it. Name an identity with "
                "no credential, or omit matrix.unauthenticated to leave the "
                "unauthenticated_reach rule switched off."
            )
        return declared, "declared"
    if not isinstance(identities, Mapping):
        return None, "none"
    if session_backed:
        # ``matrix.plan_matrix`` refuses these before a socket opens, so this is
        # the second of two independent guards -- this module is a library and
        # a caller can hand it a matrix built by any prober. An identity that
        # logs in sends no static credential header, so the inference below,
        # which picks the one identity that sends no credential header, would
        # nominate the AUTHENTICATED identity as the unauthenticated one and
        # run unauthenticated_reach against it. That is the false-SAFE
        # direction, so the rule declines to run rather than guess. (The
        # source value "inferred_empty_headers" is a schema value kept for
        # compatibility; it names that inference, not an empty headers map.)
        diagnostics.append(
            _note(
                "unauthenticated_identity_session_backed",
                f"{len(session_backed)} identity(ies) authenticate through a "
                f"'session' block ({terminal_names(session_backed)}). An identity that "
                "logs in sends no credential header of its own, so inferring the "
                "unauthenticated identity from the credential headers could have "
                "named one of them. The "
                "unauthenticated_reach rule did not run. Declare "
                "matrix.unauthenticated.",
                identities=list(session_backed),
            )
        )
        return None, "none"
    credentialed = credential_bearing_identities(config, known)
    candidates = [name for name in known if name not in credentialed]
    if len(candidates) == 1:
        diagnostics.append(
            _note(
                "unauthenticated_identity_inferred",
                f"matrix.unauthenticated is not declared. {quoted(candidates[0])} was "
                "treated as the unauthenticated identity because it sends no "
                "credential header. Declare matrix.unauthenticated to make this "
                "explicit.",
                identity=candidates[0],
            )
        )
        return candidates[0], "inferred_empty_headers"
    if len(candidates) > 1:
        diagnostics.append(
            _note(
                "unauthenticated_identity_ambiguous",
                f"{len(candidates)} identities send no credential header "
                f"({terminal_names(candidates)}), so none was treated as the "
                "unauthenticated identity and the unauthenticated_reach rule did not "
                "run. Declare matrix.unauthenticated.",
                identities=list(candidates),
            )
        )
        return None, "none"
    diagnostics.append(
        _note(
            "unauthenticated_identity_absent",
            "no identity is declared or inferable as unauthenticated, so the "
            "unauthenticated_reach rule did not run.",
        )
    )
    return None, "none"


# ---------------------------------------------------------------------------
# candidates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateOptions:
    """Thresholds for the comparative rules. Every default is conservative."""

    min_family_size: int = 5
    #: Counted, not a fraction of the family.
    #:
    #: This replaces a ``family_consensus = 0.85`` share, which was incoherent
    #: with ``min_family_size = 5`` in both directions. Upwards: the archetype
    #: the rule exists to find is "refused on all but one sibling", whose share
    #: is ``(n-1)/n``, so 0.85 needed ``n >= 7`` and families of 5 (0.800) and 6
    #: (0.833) passed the size gate and were then always discarded -- the
    #: advertised minimum of 5 could not fire. Downwards: because the
    #: denominator was the whole family, every additional operation the identity
    #: could reach LOWERED the share, so a 7-member family reported one
    #: anomalous reach (6/7) and went silent on two (5/7) and three (4/7).
    #: Detection fell as the problem got worse, which is backwards for a rule
    #: whose purpose is to surface a compromised identity's reach.
    #:
    #: A count of refused siblings plus "refused must outnumber reached" has
    #: neither property: it is monotone in severity and it means what it says.
    min_refused_siblings: int = 4
    #: How far the refusals must outnumber the reaches within the family. At 2,
    #: a semantically mixed prefix -- the rule's own declared failure mode, e.g.
    #: /api/config/{secrets,integrations,webhooks} refused beside
    #: /api/config/{public,flags,locales} reached, 4 against 3 -- is not a
    #: consensus and stays silent, while 5 against 2 is.
    min_refused_per_reached: int = 2
    unauthenticated_saturation: float = 0.60
    #: HEAD-versus-GET disagreement is excluded by default: frameworks
    #: synthesise HEAD from GET and route it differently often enough that the
    #: pair is noise rather than signal.
    compare_head_with_get: bool = False

    def __post_init__(self) -> None:
        if self.min_family_size < 2:
            raise BlastRadiusError("min_family_size must be at least 2")
        if self.min_refused_siblings < 2:
            raise BlastRadiusError("min_refused_siblings must be at least 2")
        if self.min_refused_per_reached < 1:
            raise BlastRadiusError("min_refused_per_reached must be at least 1")
        if self.min_family_size <= self.min_refused_siblings:
            # Otherwise the advertised minimum family width is unreachable: the
            # family needs room for the refused siblings AND the reached one.
            raise BlastRadiusError(
                f"min_family_size ({self.min_family_size}) must exceed "
                f"min_refused_siblings ({self.min_refused_siblings}); a family with "
                "no room for a reached sibling can never produce a candidate"
            )
        if not 0.0 < self.unauthenticated_saturation <= 1.0:
            raise BlastRadiusError("unauthenticated_saturation must be in (0, 1]")


@dataclass(frozen=True)
class Candidate:
    """One inconsistency between observations. A hypothesis, never a finding.

    Structurally not a finding: :meth:`to_dict` emits ``candidate_id`` and
    ``rule``, and never the keys ``core`` requires of a finding. See the module
    docstring.
    """

    rule: str
    identity: str
    operation: str
    specimen: str | None
    url_path: str
    explanation: str
    evidence: tuple[tuple[str, Any], ...] = ()
    tags: tuple[str, ...] = ()
    disagreement: int = 0
    consensus: tuple[int, int] = (0, 0)
    evidence_tier: str = TIER_OBSERVED_ONLY
    control_identity: str | None = None
    control_status: int | None = None
    marker_owner: str | None = None

    def __post_init__(self) -> None:
        if self.rule not in RULES:
            raise BlastRadiusError(f"unknown rule {quoted(self.rule)}")
        if self.evidence_tier not in _TIER_ORDER:
            raise BlastRadiusError(f"unknown evidence tier {quoted(self.evidence_tier)}")
        object.__setattr__(self, "tags", tuple(sorted(dict.fromkeys(self.tags))))

    @property
    def method(self) -> str:
        return _split_operation(self.operation)[0]

    @property
    def path_template(self) -> str:
        return _split_operation(self.operation)[1]

    @property
    def definition(self) -> Rule:
        return RULES[self.rule]

    @property
    def false_positive_modes(self) -> tuple[str, ...]:
        return self.definition.false_positive_modes

    @property
    def consensus_label(self) -> str:
        numerator, denominator = self.consensus
        return f"{numerator}/{denominator}" if denominator else "n/a"

    @property
    def candidate_id(self) -> str:
        """Stable across identical runs, and in a different namespace from a finding.

        Deliberately NOT ``core._finding_id``: a candidate identifier must never
        collide with, or be mistakable for, the identifier of something Veridor
        proved.
        """
        signature = ";".join(
            f"{key}={_signature_value(value)}" for key, value in self.evidence
        )
        material = "|".join(
            [self.rule, self.identity, self.operation, self.specimen or "", signature]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

    def with_tags(self, *tags: str) -> "Candidate":
        return Candidate(**{**self.__dict__, "tags": self.tags + tuple(tags)})

    def ranking_key(self) -> tuple[Any, ...]:
        numerator, denominator = self.consensus
        share = Fraction(numerator, denominator) if denominator else Fraction(0)
        return (
            _TIER_ORDER[self.evidence_tier],
            self.definition.tier,
            -self.disagreement,
            -share,
            len(self.tags),
            self.operation,
            self.identity,
            self.specimen or "",
        )

    def ranking(self) -> dict[str, Any]:
        return {
            "evidence_tier": self.evidence_tier,
            "rule_tier": self.definition.tier,
            "disagreement": self.disagreement,
            "consensus": self.consensus_label,
            "tags": len(self.tags),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "rule": self.rule,
            "is_finding": False,
            "status": "candidate",
            "identity": self.identity,
            "operation": self.operation,
            "specimen": self.specimen,
            "evidence": {key: _json_value(value) for key, value in self.evidence},
            "tags": list(self.tags),
            "false_positive_modes": list(self.false_positive_modes),
            "explanation": self.explanation,
            "evidence_tier": self.evidence_tier,
            "ranking": self.ranking(),
            "promotion": promotion_stub(self),
        }


def _signature_value(value: Any) -> str:
    if isinstance(value, (tuple, list)):
        return ",".join(str(item) for item in value)
    return str(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    return value


def _split_operation(operation: str) -> tuple[str, str]:
    method, _, template = operation.partition(" ")
    return method, template


def promotion_stub(candidate: Candidate) -> dict[str, Any]:
    """A paste-ready declared check, deliberately incomplete.

    ``name`` is a TODO and an allowed identity is carried alongside the denial,
    because ``coverage`` already flags a denial with no corroborating success as
    weak coverage. What the boundary IS remains the operator's decision: that
    decision is the declaration, and it is not Veridor's to make.
    """
    denial = sorted(DEFAULT_DENIAL_STATUSES)
    expect: dict[str, Any] = {}
    control = candidate.control_identity
    subject: dict[str, Any] = {"status": denial}
    if candidate.rule == "marker_reach" and candidate.marker_owner:
        control = candidate.marker_owner
        expect[control] = {
            "status": [candidate.control_status or 200],
            "contains_marker": candidate.marker_owner,
        }
        subject["excludes_marker"] = candidate.marker_owner
    elif control:
        expect[control] = {"status": [candidate.control_status or 200]}
    else:
        expect["TODO_identity_that_should_be_allowed"] = {"status": [200]}
    expect[candidate.identity] = subject
    return {
        "id": f"candidate-{candidate.rule.replace('_', '-')}-{candidate.candidate_id[:8]}",
        "name": "TODO: describe the boundary you are asserting",
        "request": {"method": candidate.method, "path": candidate.url_path},
        "expect": expect,
    }


# ---------------------------------------------------------------------------
# rule evaluation
# ---------------------------------------------------------------------------


class _Context:
    """Shared read-only view of a matrix, plus the one precondition guard."""

    def __init__(
        self,
        matrix: AccessMatrix,
        grouping: PeerGrouping,
        options: CandidateOptions,
    ) -> None:
        self.matrix = matrix
        self.grouping = grouping
        self.options = options
        self.rows: tuple[Row, ...] = tuple(matrix.rows)
        self.identities: tuple[str, ...] = tuple(matrix.identities)
        self.suppressed = frozenset(grouping.suppressed)
        #: Counted reasons a rule declined to emit. A suppression that nobody
        #: can see is indistinguishable from a rule that does not work, so every
        #: one of these is surfaced by :func:`discovery_notes`.
        self.suppressions: dict[str, int] = {}

    def suppress(self, reason: str) -> None:
        self.suppressions[reason] = self.suppressions.get(reason, 0) + 1

    def measured(self, row: Row, identity: str) -> Cell | None:
        """The cell, but only when a rule is allowed to read it.

        Precondition 5.0.1 lives here and nowhere else. An unknown cell yields
        ``None`` in BOTH directions: it can neither raise a candidate nor stand
        in as a denial that corroborates one.
        """
        cell = self.matrix.cell(row[0], identity, row[1])
        if cell is None or not cell.measured:
            return None
        return cell

    def active(self, identity: str) -> bool:
        return identity not in self.suppressed

    def comparable(self, row: Row) -> bool:
        """Whether identities on this row requested the SAME object."""
        return self.matrix.is_shared_specimen(row[0], row[1])


def find_candidates(
    matrix: AccessMatrix,
    grouping: PeerGrouping,
    *,
    options: CandidateOptions = CandidateOptions(),
    suppressions: dict[str, int] | None = None,
) -> list[Candidate]:
    """Run every rule and return the ranked candidate list.

    Candidates are returned in their own structure and are never merged into
    findings. Nothing here produces a SARIF result or influences an exit code.

    ``suppressions``, when supplied, is filled with the counted reasons rules
    declined to emit. Pass the same dict to :func:`discovery_notes` so the
    operator sees them: a suppression nobody is told about is how a tightened
    rule turns into a rule that quietly does nothing.
    """
    context = _Context(matrix, grouping, options)
    found: list[Candidate] = []
    found.extend(_rule_marker_reach(context))
    found.extend(_rule_unauthenticated_reach(context))
    found.extend(_rule_inverted_guard(context))
    found.extend(_rule_peer_divergence(context))
    found.extend(_rule_sibling_asymmetry(context))
    found.extend(_rule_method_asymmetry(context))

    deduplicated: dict[tuple[str, str, str, str | None], Candidate] = {}
    for candidate in found:
        key = (
            candidate.rule,
            candidate.identity,
            candidate.operation,
            candidate.specimen,
        )
        deduplicated.setdefault(key, candidate)
    result = list(deduplicated.values())
    if matrix.aborted:
        result = [candidate.with_tags(TAG_PARTIAL_MATRIX) for candidate in result]
    if suppressions is not None:
        for reason, count in context.suppressions.items():
            suppressions[reason] = suppressions.get(reason, 0) + count
    return rank_candidates(result)


def rank_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Order candidates by counted observations only.

    There is no score, no percentage and no confidence number. A fabricated
    0.86 invites the reader to treat it as "86% likely to be real", which is a
    claim nothing here can support and which would make candidates behave
    exactly like findings. Every component of the key is a count, and every
    component is printed next to the candidate it ordered.
    """
    return sorted(candidates, key=lambda candidate: candidate.ranking_key())


# --- Rule F: marker_reach --------------------------------------------------


def _rule_marker_reach(context: _Context) -> list[Candidate]:
    """One identity's planted marker observed in another identity's response.

    The only rule whose evidence is physical rather than comparative, which is
    why it ranks above every comparative rule. It is still a candidate: nobody
    declared that boundary, and a shared audit feed legitimately carries several
    identities' records.

    It is also the only rule at ``rule_tier`` 0, so whatever it emits occupies
    the top of the list. That is why it now consults ``privilege_order``, which
    it previously ignored: an identity the operator DECLARED to be strictly
    above the marker's owner reading that owner's data is what the declaration
    says should happen. Ranking it first made the highest-signal position in the
    output a description of correct behaviour -- on the project's own fixture,
    the #1 entry was "administrator reached GET /api/admin/audit and the
    response carried invoice_owner's marker".
    """
    out: list[Candidate] = []
    for row in context.rows:
        digests = _reached_digests(context, row)
        for identity in context.identities:
            if not context.active(identity):
                continue
            cell = context.measured(row, identity)
            if cell is None or cell.reach != REACH_REACHED:
                continue
            owner = cell.marker_owner
            if cell.marker_scan != "present" or not owner or owner == identity:
                continue
            subject_rank = context.grouping.rank_of(identity)
            owner_rank = context.grouping.rank_of(owner)
            if (
                subject_rank is not None
                and owner_rank is not None
                and subject_rank > owner_rank
            ):
                # The operator declared this identity strictly above the
                # marker's owner. Reaching the owner's data is then definitional,
                # not anomalous, and the config already carries the fact. Counted
                # and reported in the notes, never silently dropped.
                context.suppress("marker_reach_reader_declared_higher_privilege")
                continue
            if _group_wide_collection(context, row, identity, owner):
                # A collection every active member of the owner's declared peer
                # group reached. That is the rule's own dominant false-positive
                # shape -- the shared feed -- established from the declared
                # grouping and the observations on this row, not from a guess
                # about what the path means. Counted, reported, never silent.
                context.suppress("marker_reach_group_wide_collection")
                continue
            tags: list[str] = []
            if len(digests) > 1 and len(set(digests.values())) == 1:
                # Every identity that reached this row got the same bytes. That
                # is the signature of a shared feed rather than one identity's
                # record. Used only to rank down -- never to raise a candidate,
                # and never to drop one.
                tags.append(TAG_IDENTICAL_BODY)
            owner_cell = context.measured(row, owner)
            out.append(
                Candidate(
                    rule="marker_reach",
                    identity=identity,
                    operation=row[0],
                    specimen=row[1],
                    url_path=cell.url_path,
                    explanation=(
                        f"{terminal_text(identity)} reached {terminal_text(row[0])} and the "
                        f"response carried {terminal_text(owner)}'s planted marker. Data "
                        "belonging to another named identity was observed in "
                        f"{terminal_text(identity)}'s response. "
                        + _NOT_A_FINDING
                    ),
                    evidence=(
                        ("marker_owner", owner),
                        ("marker_scan", "present"),
                        ("observed_status", cell.status),
                        ("identities_reaching_row", len(digests)),
                        (
                            "identical_body_for_all_reachers",
                            len(digests) > 1 and len(set(digests.values())) == 1,
                        ),
                    ),
                    tags=tuple(tags),
                    disagreement=1,
                    consensus=(1, 1),
                    evidence_tier=TIER_MARKER_BACKED,
                    control_identity=owner,
                    control_status=owner_cell.status if owner_cell else None,
                    marker_owner=owner,
                )
            )
    return out


def _group_wide_collection(
    context: _Context, row: Row, identity: str, owner: str
) -> bool:
    """Whether this row is a COLLECTION the owner's whole declared group reached.

    Both halves are load-bearing, and neither is a guess about semantics.

    *Collection.* A row with a specimen, or whose final template segment is a
    parameter, names ONE object, and one object has one owner -- there is no
    honest reading of "several identities' records legitimately live here". Only
    an unspecimened, literal-tailed row can be the feed the rule's first stated
    failure mode describes.

    *Group-wide.* Every active member of the peer group the OPERATOR declared
    around the marker's owner reached this row. The target is handing the row to
    the whole declared group, so the marker in it is one member's record inside a
    group resource. Where even one declared peer was refused, the row has a
    guard, the guard let this identity past, and the candidate stands.

    That last sentence is the whole justification, and it is only true when
    there is a peer left who COULD have been refused. The group here always
    contains the marker's owner and the subject: the owner planted the marker
    the subject read, and the subject reached the row by the caller's own
    precondition. So for a two-member group the "every member reached it" test
    is not a measurement -- it is those two facts restated, and it fires
    unconditionally. Two identities is the minimum meaningful grouping and what
    ``fixtures/veridor.map-demo.json`` declares, so the effect was that
    declaring the peer group CORRECTLY deleted the ordinary cross-tenant
    collection read, while leaving ``peer_groups`` empty surfaced it. A
    suppression that punishes correct configuration is worse than no
    suppression. Three active members is therefore the floor: only then is
    there a third identity whose refusal would have kept the candidate, which
    is what makes the reach of the other two evidence of anything.
    """
    if row[1] is not None or _is_item(row[0]):
        return False
    group = context.grouping.group_of(owner)
    if group is None or identity not in group[1]:
        return False
    members = [member for member in group[1] if context.active(member)]
    if len(members) < 3:
        return False
    return all(
        (cell := context.measured(row, member)) is not None
        and cell.reach == REACH_REACHED
        for member in members
    )


def _reached_digests(context: _Context, row: Row) -> dict[str, str]:
    digests: dict[str, str] = {}
    for identity in context.identities:
        cell = context.measured(row, identity)
        if cell is not None and cell.reach == REACH_REACHED and cell.body_digest:
            digests[identity] = cell.body_digest
    return digests


# --- Rule D: unauthenticated_reach -----------------------------------------


def _rule_unauthenticated_reach(context: _Context) -> list[Candidate]:
    """The identity designated unauthenticated returned a success status.

    The highest signal per unit of assumption in the set: it assumes only that
    an unauthenticated caller should not reach things, and needs neither a group
    nor a privilege order.

    A conventionally-public template is suppressed rather than tagged UNLESS the
    row carried a planted marker, which is physical evidence that a named
    identity's data came back.
    ``/health``, ``/version``, ``/openapi.json`` and ``/auth/*`` being reachable
    without credentials is the definition of those endpoints working, and on a
    benign fixture they were four of the surviving candidates. The module's
    standing argument against a denylist -- that a ``/health`` endpoint really
    returning another identity's data is exactly what a denylist would hide --
    is preserved by the exception, not overridden: that case carries the planted
    marker, and the marker keeps the candidate.

    A differing body digest is deliberately NOT a second signal. Timestamps,
    request identifiers and uptime counters make a genuinely public body differ
    on every call, so it would suppress nothing.
    """
    identity = context.grouping.unauthenticated
    if identity is None or not context.active(identity):
        return []
    radius = compute_blast_radius(context.matrix, identity)
    if radius.observed and (
        len(radius.reached) / radius.observed > context.options.unauthenticated_saturation
    ):
        # Drowning the operator in 84 candidates is the same failure as being
        # wrong. The note is emitted by discovery_notes; the candidates are not.
        return []
    out: list[Candidate] = []
    for row in radius.reached:
        cell = context.measured(row, identity)
        if cell is None:
            continue  # pragma: no cover - reached implies measured
        tags: list[str] = []
        if _is_conventionally_public(row[0]):
            if cell.marker_scan != "present":
                context.suppress("unauthenticated_reach_conventionally_public")
                continue
            # A planted marker in the body of a conventionally-public route is
            # the case where a conventionally-public route really did return a
            # named identity's data. It is the only signal used
            # here: a differing body digest is not one, because timestamps and
            # request identifiers make a genuinely public body differ per call.
            tags.append(TAG_CONVENTIONALLY_PUBLIC)
        control, control_status = _other_reacher(context, row, identity)
        out.append(
            Candidate(
                rule="unauthenticated_reach",
                identity=identity,
                operation=row[0],
                specimen=row[1],
                url_path=cell.url_path,
                explanation=(
                    f"{terminal_text(identity)}, the identity declared as "
                    f"unauthenticated, reached {terminal_text(row[0])} with status "
                    f"{cell.status}. " + _NOT_A_FINDING
                ),
                evidence=(
                    ("observed_status", cell.status),
                    ("unauthenticated_source", context.grouping.unauthenticated_source),
                    ("reached_of_observed", f"{len(radius.reached)}/{radius.observed}"),
                    ("conventionally_public", TAG_CONVENTIONALLY_PUBLIC in tags),
                ),
                tags=tuple(tags),
                disagreement=1,
                consensus=(1, 1),
                control_identity=control,
                control_status=control_status,
            )
        )
    return out


def _is_conventionally_public(operation: str) -> bool:
    """Whether a template matches a documented conventionally-public pattern.

    Matching only ever adds a tag that ranks the candidate last, with the
    failure mode named inline. The final-segment match is deliberately broad
    (``/api/v1/health`` matches ``/health``) precisely because the consequence
    is a lower rank rather than a disappearance.
    """
    _, template = _split_operation(operation)
    template = template.rstrip("/") or "/"
    segments = split_segments(template, decode=False)
    tail = "/" + segments[-1] if segments else "/"
    for pattern in CONVENTIONALLY_PUBLIC_PATTERNS:
        if pattern.endswith("*"):
            if template.startswith(pattern[:-1]):
                return True
        elif template == pattern or tail == pattern:
            return True
    return False


def _other_reacher(
    context: _Context, row: Row, exclude: str
) -> tuple[str | None, int | None]:
    """An identity that also reached this row, for the promotion stub's control."""
    for identity in context.identities:
        if identity == exclude or not context.active(identity):
            continue
        cell = context.measured(row, identity)
        if cell is not None and cell.reach == REACH_REACHED:
            return identity, cell.status
    return None, None


# --- Rule E: inverted_guard ------------------------------------------------


def _rule_inverted_guard(context: _Context) -> list[Candidate]:
    """A lower-privilege identity reached what a declared higher one did not.

    The most seductive rule in the set and the heaviest in false positives, so
    its dominant failure mode is stated on every candidate it emits.

    That dominant mode -- EVERY declared-higher identity refused with 404 -- is
    now suppressed rather than tagged. Tagging it was measured at 21 of 30
    candidates on a benign 43-operation fixture, all 21 carrying the tag, all 21
    correct behaviour, one per tenant-scoped row and therefore growing linearly
    with the API (161 at 183 rows). The module's argument for tagging over
    suppression is about the conventionally-public PATH list, which is a guess
    about semantics that could hide a real problem on ``/health``. It does not
    transfer: this is the rule's own dominant failure mode, measured from its
    own evidence on the row in front of it, and a 404 from an identity with no
    tenant membership carries no information about the lower identity's access
    at all. A mixed refusal -- at least one 403 or 401 alongside a 404 -- is
    still emitted, tagged, and ranked below a clean 403.
    """
    order = context.grouping.privilege_order
    if len(order) < 2:
        return []
    out: list[Candidate] = []
    for row in context.rows:
        if not context.comparable(row):
            continue
        for index, lower in enumerate(order):
            if not context.active(lower):
                continue
            low_cell = context.measured(row, lower)
            if low_cell is None or low_cell.reach != REACH_REACHED:
                continue
            higher_refused: list[tuple[str, int | None, str | None]] = []
            higher_observed = 0
            for higher in order[index + 1 :]:
                if not context.active(higher):
                    continue
                high_cell = context.measured(row, higher)
                if high_cell is None:
                    continue
                higher_observed += 1
                if (
                    high_cell.reach == REACH_REFUSED
                    and high_cell.refusal_kind != REFUSAL_METHOD_NOT_SUPPORTED
                ):
                    higher_refused.append(
                        (higher, high_cell.status, high_cell.refusal_kind)
                    )
            if not higher_refused:
                continue
            if all(status == 404 for _, status, _ in higher_refused):
                context.suppress("inverted_guard_higher_identity_absent")
                continue
            statuses = sorted({str(status) for _, status, _ in higher_refused})
            tags: list[str] = []
            if any(status == 404 for _, status, _ in higher_refused):
                # Mixed: at least one higher identity was refused with something
                # that IS an authorization signal, so the row survives, but a
                # 404 in the set still means part of the evidence is a
                # tenant-scoping artefact. Tagged, and ranked below a clean 403.
                tags.append(TAG_HIGHER_IDENTITY_ABSENT)
            names = terminal_names(name for name, _, _ in higher_refused)
            control, control_status = _other_reacher(context, row, lower)
            out.append(
                Candidate(
                    rule="inverted_guard",
                    identity=lower,
                    operation=row[0],
                    specimen=row[1],
                    url_path=low_cell.url_path,
                    explanation=(
                        f"{terminal_text(lower)} reached {terminal_text(row[0])} where "
                        f"{names}, declared strictly "
                        f"higher in privilege_order, was refused "
                        f"({', '.join(statuses)}). " + _NOT_A_FINDING
                    ),
                    evidence=(
                        ("observed_status", low_cell.status),
                        (
                            "higher_identities_refused",
                            tuple(name for name, _, _ in higher_refused),
                        ),
                        ("higher_refusal_statuses", tuple(statuses)),
                        (
                            "higher_refusal_kinds",
                            tuple(
                                sorted({kind or "" for _, _, kind in higher_refused})
                            ),
                        ),
                        ("higher_identities_observed", higher_observed),
                        ("privilege_order", tuple(order)),
                    ),
                    tags=tuple(tags),
                    disagreement=len(higher_refused),
                    consensus=(len(higher_refused), higher_observed),
                    control_identity=control,
                    control_status=control_status,
                )
            )
    return out


# --- Rule B: peer_divergence -----------------------------------------------


def _rule_peer_divergence(context: _Context) -> list[Candidate]:
    """Several members of a declared peer group reached ONE shared object.

    The rule only runs on a shared specimen, which means every member requested
    the same object, and an object has one owner. That fixes the arithmetic:

    * exactly one member reaches and the rest are refused -- that member is the
      owner. This is CORRECT behaviour and produces nothing.
    * two or more members reach while at least one peer is refused -- at most
      one of the reachers can be the owner, so the others reached an object that
      is not theirs. That is the inconsistency, and it is what the rule reports.

    The previous orientation had these exactly backwards. Two guards did it: a
    majority filter (``len(reached) >= len(refused)``) and, under the default
    ``peer_divergence_unanimous``, a ``len(reached) != 1`` test that admitted
    ONLY the single-reacher case. Together they reported correct ownership every
    time and made the two-reacher case -- owner plus attacker, the classic IDOR
    this rule names in its own shape line -- structurally invisible at every
    group size. Measured: N=3/4/5 with an attacker also reaching produced zero
    candidates, while N=3/5 with everything correct produced one each.

    Where a marker identifies the owner among the reachers, that reacher is
    excluded and only the others are reported. Where nothing identifies the
    owner, every reacher is reported and the explanation says plainly that one
    of them is presumably the owner -- an honest N-way hypothesis beats a
    confident silence.
    """
    out: list[Candidate] = []
    for row in context.rows:
        if not context.comparable(row):
            # Per-identity specimens mean the identities requested DIFFERENT
            # objects. Comparing them is not a weak signal, it is a wrong one.
            continue
        for name, members in context.grouping.groups:
            active = [member for member in members if context.active(member)]
            if len(active) < 2:
                continue
            cells = {member: context.measured(row, member) for member in active}
            unmeasured = [member for member in active if cells[member] is None]
            if unmeasured:
                # Dropped, not vetoed. Vetoing the row let one member's failed
                # probe delete a cross-tenant read the other members measured
                # perfectly well -- silently, because a `continue` here counts
                # nothing. Measured: owner 200, other_tenant 200, third 403,
                # anonymous's request never landed, and the two candidates
                # vanished. Dropping over-reports, which is the direction this
                # module chooses everywhere it has the choice.
                context.suppress("peer_divergence_member_unmeasured")
                active = [member for member in active if cells[member] is not None]
                if len(active) < 2:
                    continue
            reached = [
                member
                for member in active
                if cells[member].reach == REACH_REACHED  # type: ignore[union-attr]
            ]
            refused = [
                member
                for member in active
                if cells[member].reach == REACH_REFUSED  # type: ignore[union-attr]
                and cells[member].refusal_kind  # type: ignore[union-attr]
                != REFUSAL_METHOD_NOT_SUPPORTED
            ]
            if not reached or not refused:
                continue
            if len(reached) < 2:
                # One reacher on a shared object is its owner, and the peers
                # being refused is the guard working. Reporting it was the
                # rule's guaranteed false positive on every correctly
                # authorized object in the target.
                context.suppress("peer_divergence_single_reacher_is_the_owner")
                continue
            unanimous = len(reached) + len(refused) == len(active) and not [
                member
                for member in active
                if cells[member].reach  # type: ignore[union-attr]
                not in (REACH_REACHED, REACH_REFUSED)
            ]
            if context.grouping.unanimous and not unanimous:
                # ``peer_divergence_unanimous`` now means what its name says:
                # every active member must have a definite reached/refused
                # verdict. It used to additionally require exactly one reacher,
                # which is what made the bug shape unreachable at the default.
                context.suppress("peer_divergence_group_not_unanimous")
                continue
            owners = [
                member
                for member in reached
                if cells[member].marker_scan == "present"  # type: ignore[union-attr]
                and cells[member].marker_owner == member  # type: ignore[union-attr]
            ]
            # Only when the marker names exactly one owner is the ambiguity
            # resolved; two self-markers on one shared specimen means the
            # marker configuration cannot arbitrate, so nobody is excluded.
            owner = owners[0] if len(owners) == 1 else None
            if owner is None and all(
                cells[member].status == 404  # type: ignore[union-attr]
                for member in refused
            ):
                # Every refusal is a 404, which is "absent or denied" and
                # indistinguishable from routing: a tenant-scoped object that
                # simply does not exist for the other tenant produces exactly
                # this, and it is the same signature inverted_guard excludes.
                # With a marker naming the owner the crossing is physical and
                # the ambiguity does not matter, so that case is kept.
                context.suppress("peer_divergence_refusals_are_all_absent_or_denied")
                continue
            subjects = [member for member in reached if member != owner]
            if not subjects:  # pragma: no cover - owner is one of >=2 reachers
                continue
            statuses = sorted(
                {
                    str(cells[member].status)  # type: ignore[union-attr]
                    for member in refused
                }
            )
            for subject in subjects:
                cell = cells[subject]
                if cell is None:  # pragma: no cover - measured above
                    continue
                tags: list[str] = []
                if owner is None:
                    # Nothing distinguishes the owner among the reachers, so one
                    # of these candidates is presumed to be the owner's own
                    # correct access. Named, and ranked below the case where a
                    # marker settled it.
                    tags.append(TAG_OWNER_UNIDENTIFIED)
                if not unanimous:
                    tags.append(TAG_NON_UNANIMOUS)
                if owner is not None:
                    explanation = (
                        f"{terminal_text(subject)} reached {terminal_text(row[0])}, the "
                        f"same object {terminal_text(owner)} reached carrying "
                        f"{terminal_text(owner)}'s own marker, while {len(refused)} of "
                        f"{len(active) - 1} declared peers were refused "
                        f"({', '.join(statuses)}). The specimen is shared, so every "
                        f"peer requested that one object. " + _NOT_A_FINDING
                    )
                else:
                    explanation = (
                        f"{len(reached)} members of peer group {terminal_text(name)} "
                        f"reached {terminal_text(row[0])} while {len(refused)} were "
                        f"refused ({', '.join(statuses)}). The specimen is shared, so "
                        f"this is one object with one owner: at most one of "
                        f"{terminal_names(reached)} can be reading its own data. "
                        + _NOT_A_FINDING
                    )
                control, control_status = _other_reacher(context, row, subject)
                out.append(
                    Candidate(
                        rule="peer_divergence",
                        identity=subject,
                        operation=row[0],
                        specimen=row[1],
                        url_path=cell.url_path,
                        explanation=explanation,
                        evidence=(
                            ("peer_group", name),
                            ("observed_status", cell.status),
                            ("peers_refused", tuple(refused)),
                            ("peers_reached", tuple(reached)),
                            ("peer_refusal_statuses", tuple(statuses)),
                            ("group_size", len(active)),
                            ("unanimous", unanimous),
                            ("marker_identified_owner", owner),
                            ("shared_specimen", True),
                        ),
                        tags=tuple(tags),
                        disagreement=len(refused),
                        consensus=(len(refused), len(active) - 1),
                        control_identity=control,
                        control_status=control_status,
                    )
                )
    return out


# --- Rule A: sibling_asymmetry ---------------------------------------------


def _rule_sibling_asymmetry(context: _Context) -> list[Candidate]:
    """Refused on nearly every member of a path family, and reached one.

    This automates by observation the read-scoped / write-unscoped sibling diff
    that has been done by hand. Nobody declares anything: the inconsistency is
    visible in the observations alone.

    One sibling may only be the exception for ONE identity. The rule's claim is
    that a particular identity's reach here is exceptional against the rest of
    the family; two identities that the family independently shuts out both
    reaching the same sibling refute that claim from the rule's own evidence --
    the sibling is simply open to callers the neighbourhood closes. That shape
    was measured as three of the four surviving candidates on a zero-bug
    fixture (``/api/admin/whoami``, the capability probe that answers everybody
    so a single-page app can decide whether to draw the admin nav), one per
    tenant identity, so it grew with the number of identities probed.
    """
    families: dict[tuple[str, tuple[str, ...]], list[Row]] = {}
    for row in context.rows:
        families.setdefault(_family_key(row[0]), []).append(row)

    out: list[Candidate] = []
    for (method, parent), members in sorted(families.items()):
        if len(members) < context.options.min_family_size:
            continue
        family_label = "/" + "/".join(parent) if parent else "/"
        item_members = sum(1 for row in members if _is_item(row[0]))
        item_dominated = item_members * 2 > len(members)
        #: Candidates this family produced, by the row they single out. A row
        #: singled out by more than one identity is drained below.
        by_row: dict[Row, list[Candidate]] = {}
        for identity in context.identities:
            if not context.active(identity):
                continue
            cells: dict[Row, Cell] = {}
            unmeasured = False
            for row in members:
                cell = context.measured(row, identity)
                if cell is None:
                    # Dropped, not vetoed. Vetoing the family let one sibling
                    # with no specimen, one matrix.ignore entry or one failed
                    # probe switch the rule off for every identity -- silently,
                    # because a `continue` counted nothing. The unknown is not
                    # a refusal either: it simply leaves the consensus, the way
                    # a 405 does below and peer_divergence's absent member does.
                    unmeasured = True
                    continue
                if cell.refusal_kind == REFUSAL_METHOD_NOT_SUPPORTED:
                    # 405/501 is "this verb is not implemented here", not a
                    # guard. Counting it as a refusal would invent consensus.
                    continue
                cells[row] = cell
            if unmeasured:
                context.suppress("sibling_asymmetry_member_unmeasured")
            if len(cells) < context.options.min_family_size:
                continue
            refused = [row for row, cell in cells.items() if cell.reach == REACH_REFUSED]
            reached = [row for row, cell in cells.items() if cell.reach == REACH_REACHED]
            if not reached or not refused:
                continue
            if len(refused) < context.options.min_refused_siblings:
                context.suppress("sibling_asymmetry_too_few_refused_siblings")
                continue
            if len(refused) < context.options.min_refused_per_reached * len(reached):
                # The refusals must be the pattern and the reaches the
                # exception. Counted against each other rather than against the
                # family width, so that a second anomalous reach cannot make the
                # rule quieter than a first one did: at the default of 2, a
                # 7-member family fires on one anomalous reach (6 v 1) and on
                # two (5 v 2), where the old share gate fired only on one.
                context.suppress("sibling_asymmetry_reaches_are_not_the_exception")
                continue
            statuses = sorted({str(cells[row].status) for row in refused})
            for row in reached:
                cell = cells[row]
                tags: list[str] = []
                if item_dominated and not _is_item(row[0]):
                    # A collection sitting in an item-dominated family:
                    # /api/invoices returning YOUR invoices while
                    # /api/invoices/{id} with somebody else's identifier is
                    # correctly refused. Tagged and ranked last, never dropped.
                    tags.append(TAG_COLLECTION_VS_ITEM)
                control, control_status = _other_reacher(context, row, identity)
                by_row.setdefault(row, []).append(
                    Candidate(
                        rule="sibling_asymmetry",
                        identity=identity,
                        operation=row[0],
                        specimen=row[1],
                        url_path=cell.url_path,
                        explanation=(
                            f"{len(refused)} of {len(cells)} sibling operations under "
                            f"{terminal_text(family_label)} were refused "
                            f"({', '.join(statuses)}) for {terminal_text(identity)}, "
                            "which reached this one with status "
                            f"{cell.status}. " + _NOT_A_FINDING
                        ),
                        evidence=(
                            ("family", f"{method} {family_label}"),
                            ("family_size", len(cells)),
                            ("siblings_refused", len(refused)),
                            ("siblings_reached", len(reached)),
                            ("sibling_refusal_statuses", tuple(statuses)),
                            ("observed_status", cell.status),
                            ("member_kind", "item" if _is_item(row[0]) else "collection"),
                            ("family_is_item_dominated", item_dominated),
                        ),
                        tags=tuple(tags),
                        disagreement=len(refused),
                        consensus=(len(refused), len(cells)),
                        control_identity=control,
                        control_status=control_status,
                    )
                )
        for row, raised in sorted(by_row.items()):
            if len(raised) > 1:
                # The same sibling is the exception for several identities the
                # family independently shuts out. "This identity's reach here is
                # exceptional" is refuted by the rule's own evidence: the route
                # is open to callers the neighbourhood closes.
                for _ in raised:
                    context.suppress(
                        "sibling_asymmetry_reached_by_several_locked_out_identities"
                    )
                continue
            out.extend(raised)
    return out


def _family_key(operation: str) -> tuple[str, tuple[str, ...]]:
    """``(method, parent template with every {param} segment normalized)``.

    Siblings are operations whose templates differ only in their final segment.
    Cross-method comparison is ``method_asymmetry``'s job, so the method is part
    of the key.
    """
    method, template = _split_operation(operation)
    segments = split_segments(template, decode=False)
    parent = tuple(
        "{}" if TEMPLATE_TOKEN.search(segment) else segment for segment in segments[:-1]
    )
    return (method, parent)


def _is_item(operation: str) -> bool:
    """Whether the final segment is a parameter (ITEM) or a literal (COLLECTION)."""
    _, template = _split_operation(operation)
    segments = split_segments(template, decode=False)
    return bool(segments) and bool(TEMPLATE_TOKEN.search(segments[-1]))


# --- Rule C1: method_asymmetry ---------------------------------------------


def _rule_method_asymmetry(context: _Context) -> list[Candidate]:
    """Two verbs on the same template disagreed for the same identity.

    Requires both verbs to have been genuinely probed. Under the read-only
    default that is rare, which is honest: the interesting direction is usually
    unobserved, and the unobserved half is reported as a coverage gap by
    :func:`unprobed_siblings`, never as a candidate.
    """
    by_template: dict[tuple[str, str | None], list[Row]] = {}
    for row in context.rows:
        by_template.setdefault((_split_operation(row[0])[1], row[1]), []).append(row)

    out: list[Candidate] = []
    for (template, specimen), rows in sorted(by_template.items()):
        if len(rows) < 2:
            continue
        for identity in context.identities:
            if not context.active(identity):
                continue
            observed: dict[Row, Cell] = {}
            for row in rows:
                cell = context.measured(row, identity)
                if cell is None:
                    continue
                if cell.refusal_kind == REFUSAL_METHOD_NOT_SUPPORTED:
                    # A route that does not implement PUT is not a guarded one.
                    continue
                observed[row] = cell
            reached = [row for row, cell in observed.items() if cell.reach == REACH_REACHED]
            refused = [row for row, cell in observed.items() if cell.reach == REACH_REFUSED]
            if not reached or not refused:
                continue
            for row in reached:
                counterparts = [
                    other
                    for other in refused
                    if context.options.compare_head_with_get
                    or {_split_operation(row[0])[0], _split_operation(other[0])[0]}
                    != {"GET", "HEAD"}
                ]
                if not counterparts:
                    continue
                cell = observed[row]
                names = terminal_names(sorted(other[0] for other in counterparts))
                statuses = sorted(
                    {str(observed[other].status) for other in counterparts}
                )
                control, control_status = _other_reacher(context, row, identity)
                out.append(
                    Candidate(
                        rule="method_asymmetry",
                        identity=identity,
                        operation=row[0],
                        specimen=specimen,
                        url_path=cell.url_path,
                        explanation=(
                            f"{terminal_text(identity)} reached {terminal_text(row[0])} on "
                            f"{terminal_text(template)} where "
                            f"{names} was refused ({', '.join(statuses)}) for the same "
                            "identity and the same specimen. " + _NOT_A_FINDING
                        ),
                        evidence=(
                            ("template", template),
                            ("observed_status", cell.status),
                            ("counterpart_operations", tuple(sorted(
                                other[0] for other in counterparts
                            ))),
                            ("counterpart_statuses", tuple(statuses)),
                        ),
                        disagreement=len(counterparts),
                        consensus=(len(counterparts), len(observed)),
                        control_identity=control,
                        control_status=control_status,
                    )
                )
    return out


# --- Rule C2: unprobed siblings, which are NOT candidates ------------------


def unprobed_siblings(matrix: AccessMatrix) -> tuple[dict[str, Any], ...]:
    """Operations a refused identity has a sibling verb for, but no observation of.

    Derived from ZERO observation, so it cannot be a candidate and is never
    shaped like one. ``GET /x`` refused while ``DELETE /x`` was never probed is
    a coverage gap: Veridor has no observation for ``DELETE /x``, and dressing
    that up as a result is exactly what a scanner would do here.
    """
    by_template: dict[tuple[str, str | None], list[Row]] = {}
    for row in matrix.rows:
        by_template.setdefault((_split_operation(row[0])[1], row[1]), []).append(row)

    gaps: dict[str, dict[str, Any]] = {}
    for (_, _specimen), rows in sorted(by_template.items()):
        if len(rows) < 2:
            continue
        for row in rows:
            unknown_reasons: set[str] = set()
            unmeasured = True
            for identity in matrix.identities:
                cell = matrix.cell(row[0], identity, row[1])
                if cell is not None and cell.measured:
                    unmeasured = False
                    break
                if cell is not None and cell.unknown_reason:
                    unknown_reasons.add(cell.unknown_reason)
            if not unmeasured:
                continue
            refused_by: set[str] = set()
            siblings: set[str] = set()
            for other in rows:
                if other == row:
                    continue
                for identity in matrix.identities:
                    cell = matrix.cell(other[0], identity, other[1])
                    if (
                        cell is not None
                        and cell.measured
                        and cell.reach == REACH_REFUSED
                        and cell.refusal_kind != REFUSAL_METHOD_NOT_SUPPORTED
                    ):
                        refused_by.add(identity)
                        siblings.add(other[0])
            if not refused_by:
                continue
            reason = sorted(unknown_reasons)[0] if unknown_reasons else "not_probed"
            message = (
                f"Veridor has no observation for {row[0]}. Read-only mode did not "
                "probe it."
                if reason == "skipped_mutating"
                else f"Veridor has no observation for {row[0]} ({reason})."
            )
            gaps[f"{row[0]}|{row[1] or ''}"] = {
                "kind": "coverage_gap",
                "is_finding": False,
                "operation": row[0],
                "specimen": row[1],
                "unknown_reason": reason,
                "identities_refused_on_a_sibling": sorted(refused_by),
                "observed_sibling_operations": sorted(siblings),
                "message": message,
            }
    return tuple(gaps[key] for key in sorted(gaps))


# ---------------------------------------------------------------------------
# notes and documents
# ---------------------------------------------------------------------------


def discovery_notes(
    matrix: AccessMatrix,
    grouping: PeerGrouping,
    *,
    options: CandidateOptions = CandidateOptions(),
    suppressions: Mapping[str, int] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Everything the operator must see that is not a candidate.

    Suppressions, non-comparable rows, singleton groups and the anti-drowning
    collapse all live here, so that "no candidate" is never silently the same
    thing as "nothing was computable".

    ``suppressions`` is the dict :func:`find_candidates` fills. Every rule that
    declined to emit is reported by reason and count: the rules are deliberately
    tighter than the observations alone would permit, and an operator has to be
    able to tell a quiet target from a rule that stopped working.
    """
    notes: list[dict[str, Any]] = list(grouping.diagnostics)
    if suppressions:
        notes.append(
            _note(
                "rule_suppressions",
                "rules declined to raise a candidate "
                f"{sum(suppressions.values())} time(s), by reason: "
                + ", ".join(
                    f"{reason} x{count}" for reason, count in sorted(suppressions.items())
                )
                + ". Each is a shape measured to be correct behaviour far more often "
                "than not; the matrix still records every observation behind them.",
                reasons=dict(sorted(suppressions.items())),
            )
        )
    not_comparable = [
        {"operation": operation, "specimen": specimen}
        for operation, specimen in matrix.rows
        if not matrix.is_shared_specimen(operation, specimen)
    ]
    if not_comparable:
        notes.append(
            _note(
                "not_comparable_per_identity_specimen",
                f"{len(not_comparable)} row(s) used a per-identity specimen, so the "
                "identities requested different objects. Cross-identity comparison is "
                "not meaningful for them and peer_divergence and inverted_guard did "
                "not run on them.",
                rows=not_comparable,
            )
        )
    identity = grouping.unauthenticated
    if identity is not None and identity in matrix.identities:
        radius = compute_blast_radius(matrix, identity)
        if radius.observed and (
            len(radius.reached) / radius.observed > options.unauthenticated_saturation
        ):
            notes.append(
                _note(
                    "unauthenticated_saturated",
                    f"this target responded successfully to an unauthenticated caller "
                    f"on {len(radius.reached)} of {radius.observed} probed operations; "
                    "it appears to be substantially public. Per-operation candidates "
                    "are suppressed; see the matrix.",
                    identity=identity,
                    reached=len(radius.reached),
                    observed=radius.observed,
                )
            )
    if matrix.ignored:
        notes.append(
            _note(
                "ignored_operations",
                "operations suppressed by matrix.ignore, echoed so suppression is "
                # Every entry, each bounded: a list cut short would hide one.
                "always visible: "
                + ", ".join(terminal_text(entry) for entry in matrix.ignored),
                operations=list(matrix.ignored),
            )
        )
    return tuple(notes)


def candidates_document(
    matrix: AccessMatrix,
    candidates: Sequence[Candidate],
    *,
    grouping: PeerGrouping | None = None,
    options: CandidateOptions = CandidateOptions(),
    suppressions: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """The ``veridor.candidates`` artifact.

    Written under ``output_dir/candidates/``. Never into ``latest.json``, never
    merged into a run document, and never fed to the SARIF writer: a candidate
    is not a result.
    """
    grouping = grouping if grouping is not None else PeerGrouping()
    ranked = rank_candidates(candidates)
    return {
        "kind": CANDIDATES_KIND,
        "schema_version": SCHEMA_VERSION,
        "claim": dict(CLAIM),
        "limitation": OPERATION_LEVEL_LIMITATION.format(specimens=matrix.max_specimens),
        "discipline": (
            "Discovery proposes; declaration disposes. Every entry below is a "
            "candidate: an inconsistency between observations, and a hypothesis to "
            "declare and test. None of them is a finding, none produces a SARIF "
            "result, and none affects an exit code."
        ),
        "safety": _safety_block(matrix),
        "target": {
            "base_url": matrix.base_url,
            "host": matrix.host,
            "target_class": matrix.target_class,
        },
        "peer_groups": [
            {"name": name, "members": list(members)} for name, members in grouping.groups
        ],
        "privilege_order": list(grouping.privilege_order),
        "unauthenticated": {
            "identity": grouping.unauthenticated,
            "source": grouping.unauthenticated_source,
        },
        "suppressed_identities": list(grouping.suppressed),
        "ignored": list(matrix.ignored),
        "rules": [
            {
                "rule": rule.name,
                "tier": rule.tier,
                "shape": rule.shape,
                "false_positive_modes": list(rule.false_positive_modes),
            }
            for rule in sorted(RULES.values(), key=lambda item: item.tier)
        ],
        "counts": {
            "candidates": len(ranked),
            "by_rule": {
                name: sum(1 for candidate in ranked if candidate.rule == name)
                for name in sorted(RULES)
            },
        },
        "candidates": [candidate.to_dict() for candidate in ranked],
        "unprobed_siblings": [dict(entry) for entry in unprobed_siblings(matrix)],
        "notes": [
            dict(note)
            for note in discovery_notes(
                matrix, grouping, options=options, suppressions=suppressions
            )
        ],
        "footer": CANDIDATE_FOOTER if ranked else ZERO_CANDIDATE_FOOTER,
    }


def render_candidates(document: Mapping[str, Any]) -> str:
    """Render the human candidate list, footer and all."""
    candidates = document["candidates"]
    lines = [
        "Veridor anomaly candidates -- inconsistencies in the observed access matrix",
        f"  target:    {document['target']['host']} "
        f"({document['target']['target_class']})",
        f"  requests:  {document['safety']['issued']} of "
        f"{document['safety']['planned']} issued",
    ]
    stamp = _incomplete_stamp(document["safety"])
    if stamp:
        lines.append("")
        lines.append(stamp)
    lines.append("")
    lines.append(_CLAIM_PARAGRAPH)
    lines.append("")
    lines.append(_wrap(document["limitation"], "  "))
    lines.append("")
    lines.append(_wrap(document["discipline"], "  "))
    lines.append("")

    if candidates:
        lines.append(
            f"{len(candidates)} candidate(s), ordered by counted observations only "
            "(no score, no confidence number):"
        )
    else:
        # "0 candidates" must never stand alone: the notes below carry the
        # anti-drowning collapse, the suppressed identities and the
        # non-comparable rows, any of which is the real reason the list is
        # empty.
        lines.append("0 candidates.")
    lines.append("")
    for entry in candidates[:_MAX_LISTED]:
        ranking = entry["ranking"]
        label = (
            f"{terminal_text(entry['operation'])} [specimen {terminal_text(entry['specimen'])}]"
            if entry["specimen"]
            else terminal_text(entry["operation"])
        )
        lines.append(
            f"[{entry['rule']}] candidate -- {terminal_text(entry['identity'])} on {label}"
        )
        lines.append(_wrap(entry["explanation"], "    "))
        lines.append(
            f"    Ranked by: evidence {ranking['evidence_tier']}, rule tier "
            f"{ranking['rule_tier']}, disagreement {ranking['disagreement']}, "
            f"consensus {ranking['consensus']}.  Tags: "
            + (", ".join(entry["tags"]) if entry["tags"] else "none")
            + "."
        )
        lines.append(
            "    Worth declaring an expectation for: paste promotion["
            f"{entry['promotion']['id']}] from the JSON document into your config."
        )
        for mode in entry["false_positive_modes"]:
            lines.append(_wrap("When this rule is wrong: " + mode, "      "))
        lines.append("")
    if len(candidates) > _MAX_LISTED:
        lines.append(
            f"... and {len(candidates) - _MAX_LISTED} more (see the JSON document)"
        )
        lines.append("")

    if document["unprobed_siblings"]:
        lines.append(
            f"Coverage gaps, which are NOT candidates ({len(document['unprobed_siblings'])}):"
        )
        for entry in document["unprobed_siblings"][:_MAX_LISTED]:
            lines.append(f"  {entry['message']}")
        lines.append("")

    if document["notes"]:
        lines.append(f"Notes ({len(document['notes'])}):")
        for note in document["notes"][:_MAX_LISTED]:
            lines.append(_wrap(f"[{note['code']}] {note['message']}", "  "))
        lines.append("")

    lines.append(_wrap(document["footer"], "  "))
    return "\n".join(lines).rstrip("\n") + "\n"
