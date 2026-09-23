"""Mutation testing for authorization declarations.

Boundary coverage says a cross-identity denial is ASSERTED for a boundary. It
does not say the assertion would catch anything. An authorization check passes vacuously all the time, and the
passing looks identical to a real pass:

* the attacker gets 403 because their TOKEN IS INVALID, not because
  authorization works;
* the attacker gets 404 because the RESOURCE DOES NOT EXIST;
* both identities get 401 because NEITHER is authenticated;
* the expectation is so wide (``[200, 403, 404]``) that no observation could
  ever fail it;
* the marker never appears anywhere, so ``excludes_marker`` passes trivially.

In every one of those the suite reports green and the operator believes a
boundary is guarded. That is the most dangerous failure a security tool can
have: it does not miss a bug, it ASSERTS SAFETY.

This module answers the question coverage cannot: **would this check catch
anything?** It perturbs the DECLARATION, re-grades the same observations, and
requires the verdict to change. A mutant that does not change the verdict is a
SURVIVING MUTANT, and a surviving mutant means the check has no discriminating
power on this target -- its green result may be worthless.

Tier 1 -- assertion mutation
----------------------------

Default, and the whole product feature. It mutates the CONFIGURATION ONLY. The
target is observed and never altered. Four of the five operators issue no
request at all: they re-grade the observations the baseline already collected,
through :func:`veridor.core._grade_check`, which is the same grader
``veridor run`` uses. Only ``M4`` reaches the network, once per applicable
identity.

======  ==============================================================
``M1``  INVERT-DENIAL. An identity declared to be DENIED is re-declared
        to receive the success status the owner actually got. A check
        with discriminating power must now report a finding. Survives
        when the identity was itself served that success status and the
        declaration accepted it anyway -- the expectation cannot tell
        allowed from denied.
``M2``  INVERT-ALLOW. An identity declared to SUCCEED is re-declared to
        be denied. Survives when the identity is in fact being denied
        and the declaration tolerated it -- nobody would notice the
        owner losing access.
``M3``  DROP-MARKER. Applies to ``excludes_marker`` only -- the one
        marker assertion that can pass vacuously. It is inverted to
        ``contains_marker``, so the check demands the very data flow it
        forbids, AND the kill additionally requires that the marker
        owner's data was observed to be surfaceable AT THE PATH UNDER
        TEST. Survives when it is not: the oracle could never have
        fired, so the check's evidence reduces to the status code.
``M4``  STRIP-CREDENTIAL. The identity's own request is re-issued with
        its credentials removed. Survives when the target answers the
        identity exactly as it answers a caller with no credential at
        all AND that answer is an AUTHENTICATION refusal, or when no
        identity in the check is answered differently. It SENDS A REAL
        UNAUTHENTICATED REQUEST -- see the budget rules below.
``M5``  POSITIVE-CONTROL. The whole check is re-declared as "every
        identity is refused", and the identity whose data the denial
        protects must have been SERVED. The 2xx is then corroborated
        by a NEGATIVE CONTROL: the same request for a resource id that
        cannot exist. Survives when no protected identity was served,
        or when the route answers 2xx for the fabricated id too -- a
        soft-404 envelope, where the 2xx establishes nothing.
``M6``  SHAM-CREDENTIAL. The identity's request is re-issued with a
        fabricated credential that belongs to nobody. Survives when
        the target answers the identity exactly as it answers that
        nobody: nothing observed establishes that this identity is a
        principal the boundary under test even applies to. It SENDS A
        REAL REQUEST WITH A FABRICATED CREDENTIAL.
======  ==============================================================

Why ``M3`` inverts rather than deletes. Deleting an ``excludes_marker`` from a
correctly behaving target changes nothing -- the assertion passed before and
its absence passes after -- so a literal deletion is unkillable by construction
and would report every marker in the suite as inert. Inversion is the mutation
that has the property the operator wants: it demands the very data flow the
check exists to forbid.

Why the inversion alone is not enough, and why ``M3`` skips ``contains_marker``.
A PASSING ``excludes_marker`` means the marker was not observed, so inverting it
to ``contains_marker`` always produces a finding -- an ``inconclusive`` "the
oracle could no longer be satisfied" if nothing else. Banking that as a kill
would make ``M3`` a guaranteed ``+1`` per marker assertion that can never report
the inertness it advertises. The kill therefore also requires evidence that this
path CAN surface the owner's marker, taken from ``core._resolve_control`` so the
grader and this module cannot disagree about what counts as same-path evidence.
``contains_marker`` gets no mutant at all: it is falsifiable by construction --
it fails the moment the marker is absent -- so a passing one has already
demonstrated the oracle fires, and mutating it could only manufacture another
guaranteed kill.

Why ``M4`` and ``M6`` are both needed. ``M4`` asks whether the credential is
read; ``M6`` asks whether the credential names a principal this boundary applies
to. A target that answers ``401`` to a missing header and ``403`` to an
unrecognised one -- an extremely common split -- kills ``M4`` for an identity
whose token is expired, typo'd, or scoped away by a coarser gate that fires
before the boundary under test is ever reached. ``M6`` compares against a
credential that certainly belongs to nobody instead of against no credential at
all, which is the comparison that separates "denied because of who you are" from
"denied because we do not know who you are".

Expected direction, and why it is encoded
-----------------------------------------

A mutant that changes the verdict the WRONG way is not a kill. Lumping the two
together would hide a real defect in the check, so each operator declares the
direction its kill must take and :data:`ABERRANT` is a distinct outcome:

* ``M1`` must produce ``unexpected_denial`` -- the target refused, exactly as
  declared, and the mutant demanded success. A ``vulnerable`` verdict instead
  means the accepted status was not a refusal at all (a redirect, say), which
  the operator declared as though it were one.
* ``M2`` must produce ``vulnerable`` -- the identity was served and the mutant
  demanded refusal.
* ``M3`` must produce a finding for the identity whose marker assertion was
  mutated. A finding that lands only on some OTHER identity means the mutation
  perturbed a control rather than the assertion.
* ``M4`` must produce a status that is not MORE permissive. Credentialed 403
  becoming anonymous 200 is a status change, but calling it a kill would
  celebrate an endpoint that serves unauthenticated callers.
* ``M5`` must be killed by an observed 2xx that belongs to the protected
  identity and that a fabricated resource id does not also receive. A 500 also
  differs from a refusal and is not a positive control.
* ``M6`` must produce a status that is not MORE permissive, for the same reason
  as ``M4``: a fabricated credential outscoring a real one is not a kill.

Those verdict names are internal. They are compared against, never printed: see
:data:`_VERDICT` for why a mutation report must not put the word ``vulnerable``
in the console output of a suite that is working perfectly.

Scoring, and why it is unweighted
---------------------------------

``score = killed / generated``, where ``generated`` counts only the mutants that
were actually evaluated -- ``killed``, ``survived``, ``aberrant``, ``errored``.
``not_applicable`` and ``skipped`` produced no mutant, so counting them would let
a suite improve its score by being unmutatable.

Every operator counts once. Weighting them was considered and rejected: a weight
is a claim about which vacuity matters most, that claim is target-specific, and
no evidence in this tool could falsify it. A fabricated weight would also make
the single number look more authoritative than it is, which is the opposite of
what a tool that exists to deflate a green result should do. The honest
alternative to weighting is decomposition, so the report carries a per-operator
breakdown (``summary["by_operator"]``): an operator can see that a 0.80 came
from four status kills and one ``M4`` survivor, which is a different suite from
one with five even results, without the engine pretending to know which is
worse.

The score is triage. The SURVIVORS are the deliverable -- the score alone is a
vanity number, so every survivor carries a plain-English diagnosis and the text
report prints them before the number is ever mentioned again.

What the denominator does NOT contain
-------------------------------------

A mutant that cannot be killed is not a measurement, and a survivor an operator
cannot act on teaches them to skip the survivor list. Three kinds of thing are
therefore kept out of the score and reported as facts instead.

**Limits on the evidence**, printed under ``LIMITS ON THE EVIDENCE`` and carried
as ``check["evidence_notes"]``. These are ``not_applicable`` outcomes that mean
"this target cannot show us", as distinct from "there was nothing here to
mutate": an ``M4`` or ``M6`` comparison on an operation that hides existence
uniformly, a public read, an ``M6`` on a check where nobody succeeds. They are
printed beside the score precisely BECAUSE they leave a 1.00 with an empty
survivor list, which reads as a perfect result rather than as an unanswered
question.

**Properties of a check**, which no mutation could ever perturb:

* **A check with no marker assertion at all.** There is nothing to mutate, so a
  literal "the mutation was a no-op" record is unkillable by construction, is
  byte-identical for every such check, and on a DELETE returning 204 asks for a
  marker the operator cannot supply. It is now
  ``check["marker_evidence"] == "status_only"`` and one line in the report.
* **A ``sequences`` block.** :func:`analyze` mutates ``checks`` and nothing else.
  A version-2 configuration's sequences are counted in
  ``summary["unmutated_sequences"]`` and named in the report header, because a
  score published over part of a suite while the rest is silently unmeasured is
  exactly the claim ``SCORING["undefined"]`` refuses to make.

Reporting
---------

Three artifacts, one report document:

* :func:`render_text` -- ASCII, survivors first, the disclaimer above the
  number. It renders ``report["unresolved"]``, which is the survivors PLUS the
  errored mutants: an errored mutant is not a survivor and is never called one,
  but it is unmeasured, the per-unit table already counts it in its "N to read
  above", and the all-clear sentence is false while one exists. A tier-2 hook
  whose restore did not verify prints above everything else, header included.
* the report dict itself -- the machine JSON, written by :func:`write_reports`.
* :func:`render_badge` -- shields.io endpoint JSON, the same shape and the same
  discipline as ``veridor.coverage.render_badge``: the label carries its own
  claim boundary because a badge is the artifact that travels furthest from its
  context, and a measurement that is not defined never renders a green badge.
  Nor does one with a SURVIVOR: downgrading for the outcomes the engine cannot
  explain while ignoring the one it can was exactly backwards.

:data:`RELATIONSHIP` states, in the report header, how the two numbers relate --
coverage says a denial is ASSERTED, the mutation score says the assertion would
CATCH A REGRESSION, and neither says the boundary is ENFORCED -- so a reader who sees
both can never conflate them.

Rules this module does not bend
-------------------------------

1. **Mutation runs never produce findings.** A mutant's failure is EXPECTED and
   is the evidence the suite works. Nothing here enters the findings list, the
   SARIF document, or the exit code of ``veridor run``. :func:`exit_code` is
   the mutation report's own, separate exit code.
2. **Tier 1 never mutates the target.** The configuration is deep-copied before
   every perturbation; the loaded config is never written to.
3. **Three operators reach the network.** ``M4`` sends a real UNAUTHENTICATED
   request, ``M6`` a real request carrying a FABRICATED credential, and ``M5``
   one request for a FABRICATED resource id. All three are refused outright for
   any method outside :data:`veridor.core.SAFE_METHODS`, all three are counted
   in ``request_budget``, and ``min_interval_seconds`` throttles all three. The
   fabricated credential is generated per run from
   :func:`veridor.core.generate_marker` and authenticates to nothing.
4. **No credential, cookie, token or body reaches an artifact.** The report
   carries statuses, identity NAMES, and ``_safe_url`` paths. It never carries a
   header, a header value, a body, or a marker literal.
5. **Honest wording.** A surviving mutant means "this check may be vacuous", not
   "you have a vulnerability" -- the same register as the coverage report, which
   says denials are ASSERTED and never ENFORCED.

Tier 2 -- target mutation
-------------------------

Opt-in, and deliberately not a per-language mutation engine. The operator
supplies a command that produces a build with a guard removed and a command
that restores it; :func:`run_target_mutations` runs the real suite in between
and applies the same kill/survive logic. Highest fidelity, entirely the
operator's build system::

    hook = TargetMutationHook(
        name="drop-tenant-filter",
        removes="the tenant predicate in InvoiceRepository.find_by_id",
        apply_command=("./scripts/mutate.sh", "drop-tenant-filter"),
        restore_command=("git", "checkout", "--", "src/invoices.py"),
    )
    report = run_target_mutations(config, [hook], output_dir=tmp)

A hook is KILLED when the suite reports an identity served what its declaration
refuses -- a ``vulnerable`` finding -- while the guard is removed, and SURVIVED
when the suite stays green -- meaning the suite would not have noticed the guard
going away. A mutated run whose only findings about the target are
``unexpected_denial`` is ABERRANT, naming each identity refused and what it
drew: removing a guard grants access, so a build that refuses an identity it
should serve broke in some other way, and one that refuses an identity it
should refuse with a different status (401 declared, 302 drawn) granted
nothing. One whose findings are all ``inconclusive`` is errored. Each of
these needs a suite that is green without the mutation, so the suite runs once
against the unmutated target first; when that run is red every hook is
``not_applicable``, and when it could not grade everything every hook is
``errored``. No hook is applied in either case.

The hook contract, in full, is :data:`TIER2_CONTRACT`, which is printed in the
tier-2 report header and enforced by :func:`_validate_hooks` before any command
runs -- down to the TYPE of every argv element, because ``subprocess.run``
raises ``TypeError`` for a non-string argument, that exception is caught by
neither ``OSError`` nor ``SubprocessError``, and on the restore command it would
otherwise propagate out of the ``finally`` that puts the target back. Its load-bearing clause is the restore command: tier 2 leaves a target
altered, so a hook without a documented way to put it back is refused outright
rather than run and reported. The restore command runs on EVERY path -- the
apply command failing, the suite raising, the suite passing, the suite going
red -- and a hook whose restore does not exit ``0`` is reported ``errored`` with
``restore_verified`` false, which is the loudest thing this module says. Every
later hook in the same run is then skipped, because applying a second mutation
to a target already in an unknown state is not a measurement.

``fixtures/tier2_guard_toggle.py`` is the shipped worked example: a mutate and a
restore command over the mutation fixture's guard seam, in the exact argv shape
a real ``./scripts/mutate.sh`` would take.
"""

from __future__ import annotations

import copy
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from os import PathLike
from pathlib import Path
from typing import Any, Sequence

from veridor import capsule, core, redaction
from veridor.core import ConfigError
from veridor.coverage import (
    AUTHN_STATUSES,
    DEFAULT_DENIAL_STATUSES,
    REPORT_WIDTH,
    format_percent,
    status_class,
    wrap_paragraph,
)
from veridor.terminal import quoted

__all__ = [
    "ABERRANT",
    "BADGE_LABEL",
    "BANNED_DIAGNOSIS_WORDS",
    "ERRORED",
    "KILLED",
    "MUTATION_SCHEMA_VERSION",
    "NOT_APPLICABLE",
    "OPERATORS",
    "OUTCOMES",
    "RELATIONSHIP",
    "SCORING",
    "SKIPPED",
    "SURVIVED",
    "TIER1_HEADER",
    "TIER2_BADGE_LABEL",
    "TIER2_CONTRACT",
    "TARGET_OPERATOR",
    "TargetMutationHook",
    "UNMUTATED_PASSED",
    "analyze",
    "evidence_component",
    "exit_code",
    "mutation_summary",
    "preflight_banner",
    "render_badge",
    "render_text",
    "run_target_mutations",
    "score",
    "summarize",
    "write_reports",
]

MUTATION_SCHEMA_VERSION: int = 1


#: A mutant was generated and the verdict changed in the direction the operator
#: requires. The check has discriminating power along that axis.
KILLED: str = "killed"
#: A mutant was generated and the verdict did NOT change. The check may be
#: vacuous along that axis. Survivors are the entire point of the report.
SURVIVED: str = "survived"
#: The verdict changed, but not in the direction the operator requires. A
#: distinct outcome on purpose: folding it into ``killed`` would hide a real
#: defect in the check.
ABERRANT: str = "aberrant"
#: The mutant could not be evaluated -- the request failed, typically. Counted
#: in the denominator, because an unevaluable mutant is not a kill.
ERRORED: str = "errored"
#: No mutant was generated: the baseline already reports a finding here, so
#: there is no passing verdict whose discriminating power could be measured.
NOT_APPLICABLE: str = "not_applicable"
#: No mutant was generated by policy. See :data:`SKIP_REASONS` for the closed
#: set of causes.
SKIPPED: str = "skipped"

#: Why a mutant was not generated. Closed set, and PRINTED with its count: the
#: console published `skipped N` and put the reason only in the JSON, so the one
#: number a reader could not act on was the one with no explanation attached.
SKIP_REASONS: dict[str, str] = {
    "mutating_verb": (
        "the request method is not one of GET, HEAD or OPTIONS, so no "
        "unauthenticated copy (M4), no fabricated-credential copy (M6) and no "
        "fabricated-resource-id copy (M5) of it is ever issued"
    ),
    "no_resource_id": (
        "the request path carries no resource id to fabricate, so the positive "
        "control (M5) cannot be checked against a negative one"
    ),
    # Two keys rather than one, because the two operators test different
    # predicates. M4 asks what this REQUEST sends -- identity headers plus any
    # credential header declared on the check. M6 asks what the IDENTITY
    # declares. An identity with empty headers and an Authorization on the check
    # skips M6 and kills M4, so one shared sentence would print "nothing to
    # strip" directly above a mutant that stripped something.
    "no_credential_to_strip": (
        "the request carries no credential to remove, so an unauthenticated "
        "copy (M4) would be the same request"
    ),
    "no_credential_header": (
        "the identity declares no credential header, so a fabricated one (M6) "
        "would leave it already indistinguishable from a caller the target does "
        "not know"
    ),
    "already_served": (
        "the identity was already served 2xx here, so there is no denial whose "
        "meaning is in question"
    ),
    "budget_exhausted": "the mutation request budget is exhausted",
    "target_state_unknown": (
        "an earlier tier-2 hook could not be restored, so nothing further was "
        "applied to the target"
    ),
}

OUTCOMES: tuple[str, ...] = (
    KILLED,
    SURVIVED,
    ABERRANT,
    ERRORED,
    NOT_APPLICABLE,
    SKIPPED,
)

#: Outcomes that count toward the mutation score. ``not_applicable`` and
#: ``skipped`` are recorded and printed but never generated a mutant, so
#: including them would let a suite improve its score by being unmutatable.
_SCORED: frozenset[str] = frozenset({KILLED, SURVIVED, ABERRANT, ERRORED})

#: How this number relates to the other number Veridor publishes. Printed in the
#: report header, carried in the JSON, and deliberately phrased so the two can
#: never be read as the same claim. ASCII only.
RELATIONSHIP: str = (
    "Boundary coverage says a cross-identity denial is ASSERTED for a boundary: "
    "some check declares one. This score says that assertion WOULD CATCH A "
    "REGRESSION: perturbing the declaration changes the verdict. Neither says "
    "the boundary is ENFORCED. The two multiply rather than add -- full "
    "coverage made of checks that cannot fail is worth nothing, and a perfect "
    "score over one operation says nothing about the operations coverage "
    "reports as unasserted."
)

#: ASCII only. This is printed on every mutation run, including on consoles
#: whose encoding cannot represent typographic punctuation.
TIER1_HEADER: tuple[str, ...] = (
    "Tier 1 mutates the CONFIGURATION only. The target is observed, never "
    "altered.",
    "Nothing in this report is a finding. A mutant that fails is EXPECTED to "
    "fail; that failure is the evidence your check works. No mutant enters the "
    "findings list, the SARIF document, or the exit code of `veridor run`.",
    "A surviving mutant means this check MAY BE VACUOUS -- it may pass whatever "
    "the target does. It is not a report of a vulnerability, and a mutation "
    "score of 1.0 does not mean the boundary is enforced.",
    RELATIONSHIP,
)

#: The scoring rule, published in the report so the number is reproducible from
#: its own document and the weighting decision travels with it.
SCORING: dict[str, str] = {
    "formula": "killed / generated",
    "generated": (
        "mutants that were actually evaluated: killed, survived, aberrant, "
        "errored"
    ),
    "excluded": (
        "not_applicable and skipped, which generated no mutant -- counting them "
        "would let a suite raise its score by being unmutatable"
    ),
    "weighting": "none: every operator counts once",
    "why_unweighted": (
        "a weight is a claim about which vacuity matters most; that claim is "
        "target-specific and nothing in this tool could falsify it, and a "
        "fabricated weight would make one number look more authoritative than "
        "it is. The report decomposes the score by operator instead, which "
        "gives the operator the same information without the invented claim."
    ),
    "kills": (
        "only a verdict change in the operator's declared direction; a change "
        "the wrong way is aberrant and is not a kill"
    ),
    "undefined": (
        "a suite that generated no mutants scores null, not 0.0 and not 1.0 -- "
        "both would be a claim about checks that were never measured"
    ),
}

#: Vocabulary that must never appear in a diagnosis. A surviving mutant means
#: "this check may be vacuous"; it is not a report of a defect in the target,
#: and the register has to match the coverage output, which says denials are
#: ASSERTED and never ENFORCED. Mirrors ``coverage.BANNED_CLAIM_WORDS`` in intent:
#: that list stops a measurement overclaiming safety, this one stops a
#: measurement overclaiming danger.
BANNED_DIAGNOSIS_WORDS: tuple[str, ...] = (
    "vulnerab",
    "insecure",
    "exploit",
    "breach",
    "unprotected",
    "compromis",
    "proven",
    "guaranteed",
)

#: shields.io label. Three words that carry their own claim boundary, because
#: the badge is pasted into READMEs where no caveat can follow it. It says
#: "mutation score", not "authorization tested": the number is a property of the
#: CHECKS, not of the target.
BADGE_LABEL: str = "authz mutation score"

#: Tier 2 gets its own label. The two badges measure different things -- one
#: scores declarations, the other scores the suite against a real build -- and
#: two badges in one README under the same three words would be read as one
#: number that moved.
TIER2_BADGE_LABEL: str = "authz guard mutation"

OPERATORS: dict[str, dict[str, str]] = {
    "M1": {
        "label": "invert-denial",
        "mutates": (
            "an identity declared to be denied is re-declared to receive the "
            "success status observed on this request"
        ),
        "kill_direction": (
            "the mutated expectation must now fail because the target REFUSED "
            "this identity"
        ),
        "catches": (
            "an expectation that accepts both access and denial, and an "
            "attacker who is in fact being served"
        ),
        "requests": "0",
    },
    "M2": {
        "label": "invert-allow",
        "mutates": "an identity declared to succeed is re-declared to be denied",
        "kill_direction": (
            "the mutated expectation must now fail because the target SERVED "
            "this identity"
        ),
        "catches": (
            "an allow expectation that also tolerates denial, so the owner "
            "losing access would go unnoticed"
        ),
        "requests": "0",
    },
    "M3": {
        "label": "drop-marker",
        "mutates": (
            "an excludes_marker assertion is inverted, so the check demands the "
            "data flow it exists to forbid"
        ),
        "kill_direction": (
            "the identity whose exclusion was mutated must report a finding AND "
            "the owner's marker must have been observed to be surfaceable at "
            "this path"
        ),
        "catches": (
            "an exclusion whose marker oracle could never fire, because nothing "
            "observed shows this path can surface the owner's marker at all"
        ),
        "requests": "0",
    },
    "M4": {
        "label": "strip-credential",
        "mutates": "the identity's request is re-issued with its credentials removed",
        "kill_direction": (
            "the observed status must change, and must not become more permissive"
        ),
        "catches": (
            "a credential the target never reads -- an unauthenticated pair, a "
            "stale token the target answers exactly as it answers no token, a "
            "route with no authorization at all"
        ),
        "requests": "1 per applicable identity",
    },
    "M5": {
        "label": "positive-control",
        "mutates": "every identity in the check is re-declared as refused",
        "kill_direction": (
            "the identity whose data this denial protects must have been served "
            "a 2xx that a fabricated resource id does not also receive"
        ),
        "catches": (
            "a check on a route that refuses everyone, where the attacker's 404 "
            "proves nothing, and a soft-404 envelope where the owner's 2xx does "
            "not establish that the resource exists"
        ),
        "requests": "1 per check with a positive control",
    },
    "M6": {
        "label": "sham-credential",
        "mutates": (
            "the identity's request is re-issued with a fabricated credential "
            "that belongs to nobody"
        ),
        "kill_direction": (
            "the observed status must differ from what the fabricated "
            "credential receives, and must not become more permissive"
        ),
        "catches": (
            "an 'attacker' the boundary under test never applies to -- an "
            "expired or typo'd token, or a principal a coarser gate refuses "
            "before the ownership predicate ever runs"
        ),
        "requests": "1 per credential shape in a check that declares a denial",
    },
}

#: Every status that means the target REFUSED. Sourced from core so the grader
#: and this module can never disagree about what a denial is.
_REFUSAL: frozenset[int] = core.REFUSAL_STATUSES
_DENIAL_CLASSES: frozenset[str] = frozenset({"authz_denial", "authn_denial"})

#: The status list an ``M5`` mutant declares for every identity in the check.
_ALL_REFUSED: tuple[int, ...] = tuple(sorted(_REFUSAL))

#: The success status ``M1`` falls back to when no identity in the check was
#: served anything. Named so the report can say where the number came from.
_ASSUMED_SUCCESS: int = 200

#: Prefix for every fabricated value this module puts on the wire -- the ``M6``
#: sham credential and the ``M5`` absent resource id. It is recognisable in a
#: target's access log, so an operator reading one can tell a Veridor probe from
#: a real caller, and it is generated per run so it can never collide with a
#: real credential or a real resource id.
_SHAM_PREFIX: str = "veridor-sham"

#: The only refusal an ABSENT route also returns. ``M5``'s survivor claim -- "a
#: denial here is equally well explained by an absent route" -- is available for
#: this status and for no other, because a 401 or a 403 is the route answering.
_NOT_FOUND: int = 404

#: Why a re-grading fired, in mutation vocabulary. Veridor's own rule ids are
#: deliberately NOT reproduced here. A rule id is the identifier of a FINDING,
#: and CI greps log output: a mutation report echoing ``VERIDOR-AUTHZ-001``
#: eight times for a healthy suite is exactly the false alarm rule 1 exists to
#: prevent. Unknown ids degrade to a neutral phrase rather than to the id.
#: The one rule id that means "nothing was measured" rather than "the check
#: disagreed with the target". Tier 2 has to tell the two apart: see
#: :func:`_run_suite_against_mutated_build`.
_EXECUTION_RULE_ID: str = "VERIDOR-EXEC-001"

_WHY: dict[str, str] = {
    "VERIDOR-AUTHZ-001": "the observed status no longer matched the declaration",
    "VERIDOR-LEAK-001": "the marker oracle rejected the observed response",
    "VERIDOR-ORACLE-001": "the marker oracle could no longer be satisfied",
    "VERIDOR-EXEC-001": "the probe did not complete",
}


def _why(finding: dict[str, Any]) -> str:
    return _WHY.get(finding["rule_id"], "the re-graded check no longer matched")


#: What a re-grading's VERDICT means, in mutation vocabulary. Kept out of the
#: report for the same reason as the rule ids above, and it is the sharper case
#: of the two: core's verdict for "the identity was served what it should have
#: been refused" is the literal word ``vulnerable``, and a healthy suite's
#: mutation report is full of those verdicts BY DESIGN -- they are the evidence
#: the checks work. Printing the word would put "vulnerable" in a green run's
#: console output eight times over, which is precisely the false alarm rule 1
#: exists to prevent. The direction is what the reader needs; the identifier is
#: not.
_VERDICT: dict[str, str] = {
    "vulnerable": "failed because the target SERVED this identity",
    "unexpected_denial": "failed because the target REFUSED this identity",
    "inconclusive": "could not be evaluated",
}


def _verdict(name: str) -> str:
    return _VERDICT.get(name, "failed")


# ---------------------------------------------------------------------------
# Tier 1
# ---------------------------------------------------------------------------


@dataclass
class _Observation:
    """One check, its probes, and the baseline grading of them."""

    check: dict[str, Any]
    probes: dict[str, dict[str, Any]]
    findings: dict[str, dict[str, Any]]


@dataclass
class _Context:
    """Everything the operators share for one tier-1 run.

    The fabricated credential and the fabricated resource id are generated ONCE
    per run and held here: an operator that minted its own per call would put a
    different unrecognisable string in the target's access log on every probe,
    and an operator reading that log could not tell one Veridor run from a
    credential-stuffing attempt.
    """

    config: dict[str, Any]
    config_path: Path
    marker_controls: dict[str, dict[str, Any]]
    budget: _Budget
    sham_token: str

    @property
    def base_url(self) -> str:
        return str(self.config["target"]["base_url"])

    @property
    def timeout(self) -> float:
        return float(self.config["target"].get("timeout_seconds", 10))

    def send(
        self, request: dict[str, Any], *, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Issue one mutation request against the budget and the rate limit.

        ``headers`` is the identity surface to send it under -- empty for an
        anonymous probe, the identity's own headers for a negative control that
        has to be issued as that identity, a fabricated set for ``M6``.
        """
        self.budget.take()
        return core._perform_request(
            self.base_url, self.timeout, request, {"headers": dict(headers or {})}
        )


def analyze(
    config_path: Path,
    *,
    base_url: str | None = None,
    request_budget: int | None = None,
    min_interval_seconds: float = 0.0,
    read_only: bool = False,
) -> dict[str, Any]:
    """Run tier-1 assertion mutation over every check and return the report.

    ``request_budget`` caps the number of ADDITIONAL target requests the run may
    issue -- that is, ``M4`` strip-credential requests. The baseline probes are
    the requests ``veridor run`` issues anyway and are reported separately.
    ``min_interval_seconds`` throttles EVERY request, baseline included: the
    baseline is the bulk of the traffic and bounding only the additional half
    bounds almost nothing.

    ``read_only`` is the same hard refusal ``veridor run --read-only`` applies,
    enforced here as well as in the CLI so neither layer is anyone's only line
    of defence. ``mutate`` re-issues every declared request, ``DELETE``
    included; an operator who will not let ``run`` write to a target must have
    the same escape hatch here, on the same configuration.

    The library defaults are permissive because a caller passing neither
    argument has asked for neither. The CLI is the surface an operator actually
    points at a target, and it supplies ``cli.MUTATE_DEFAULT_MIN_INTERVAL`` and
    ``cli.MUTATE_DEFAULT_REQUEST_BUDGET`` in their place.

    The returned document is the mutation report and nothing else. It contains
    no findings, produces no SARIF, and has its own exit code
    (:func:`exit_code`).
    """
    if min_interval_seconds < 0:
        raise ConfigError("min_interval_seconds must not be negative")
    if request_budget is not None and request_budget < 0:
        raise ConfigError("request_budget must not be negative")

    # `mutate` re-issues the declared requests, so it needs concrete paths
    # for the same reason `run` does.
    config = core.load_config(
        config_path, base_url, read_only=read_only, require_concrete_paths=True
    )
    _refuse_session_identities(config)
    started_at = datetime.now(UTC)

    budget = _Budget(request_budget, min_interval_seconds)
    observations, marker_controls, baseline_requests, transport = _observe(
        config, config_path, budget
    )
    context = _Context(
        config=config,
        config_path=config_path,
        marker_controls=marker_controls,
        budget=budget,
        sham_token=f"{_SHAM_PREFIX}-{core.generate_marker()}",
    )

    checks: list[dict[str, Any]] = []
    mutants: list[dict[str, Any]] = []
    for observation in observations:
        produced = _mutate_check(context, observation)
        mutants.extend(produced)
        evidence = _marker_evidence(observation)
        checks.append(
            {
                "check_id": observation.check["id"],
                "name": observation.check.get("name", observation.check["id"]),
                **evidence,
                "evidence_notes": _evidence_notes(evidence, produced),
                **_tally(produced),
                "mutants": produced,
            }
        )

    unmutated = _unmutated_declarations(config)
    summary = summarize(
        mutants,
        checks=len(observations),
        baseline_requests=baseline_requests,
        mutation_requests=context.budget.spent,
        unmutated_sequences=len(unmutated),
    )
    survivors = [
        mutant for mutant in mutants if mutant["outcome"] in {SURVIVED, ABERRANT}
    ]
    return {
        "schema_version": MUTATION_SCHEMA_VERSION,
        "tier": 1,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "target": core._safe_url(config["target"]["base_url"]),
        "config": str(config_path),
        "interpretation": {
            "measures": (
                "whether each declared expectation has the power to fail when "
                "the target's behaviour changes"
            ),
            "does_not_measure": (
                "whether authorization is enforced, and whether the declaration "
                "itself is correct"
            ),
            "not_measured": _not_measured(unmutated),
            "relationship": RELATIONSHIP,
            "statement": " ".join(TIER1_HEADER),
        },
        "scoring": dict(SCORING),
        "operators": copy.deepcopy(OPERATORS),
        # What the wire did, before any mutation arithmetic. A report whose
        # baseline never reached the target is not a measurement, and the
        # reader must not have to infer that from a null score.
        "baseline_transport": transport,
        "summary": summary,
        # Survivors first and duplicated on purpose: the score alone is a vanity
        # number, and the survivors are the entire point of running this.
        "survivors": survivors,
        # Errored mutants are unresolved too. They are NOT survivors -- nothing
        # about them was measured -- but they must reach the human artifact, so
        # the renderer reads this list rather than re-deriving one.
        "unresolved": survivors
        + [mutant for mutant in mutants if mutant["outcome"] == ERRORED],
        "unmutated_declarations": unmutated,
        "checks": checks,
    }


def _unmutated_declarations(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Name every declared assertion this analysis did not mutate.

    Today that is ``sequences`` and only ``sequences``. :func:`analyze` iterates
    ``config["checks"]``; a version-2 configuration may also declare multi-step
    sequences, which ``core.execute_run`` executes and which nothing here
    perturbs. Publishing a score and an exit code over the checks alone, with
    the sequences silently absent, is exactly the claim ``SCORING["undefined"]``
    refuses to make about checks that were never measured -- so the omission is
    counted, named, and printed in the header instead.
    """
    sequences = config.get("sequences")
    if not isinstance(sequences, list):
        return []
    named: list[dict[str, Any]] = []
    for index, sequence in enumerate(sequences):
        identifier = (
            sequence.get("id") if isinstance(sequence, dict) else None
        ) or f"sequence[{index}]"
        named.append({"kind": "sequence", "id": str(identifier)})
    return named


def _not_measured(unmutated: Sequence[dict[str, Any]]) -> str:
    if not unmutated:
        return (
            "nothing: every declared assertion in this configuration is a check, "
            "and every check was mutated"
        )
    return (
        f"{len(unmutated)} declared sequence(s): "
        + ", ".join(quoted(entry["id"]) for entry in unmutated)
        + ". Mutation perturbs check expectations only, so this score and this "
        "exit code say nothing about them."
    )


def _is_evidence_limit(mutant: dict[str, Any]) -> bool:
    """One predicate for what LIMITS ON THE EVIDENCE prints and ``limited`` counts.

    They used to be two rules. ``limited`` counted every not_applicable, so the
    structural M3 record every owner ``contains_marker`` produces was counted as
    a mutant the target could not answer while printing nowhere, and
    ``--require-evaluable`` exited 3 on the suite's own perfect config.

    A ``not_applicable`` either means "this target cannot show us" -- a LIMIT ON
    THE EVIDENCE, which belongs in the report -- or "there was nothing here to
    mutate", which is bookkeeping. The operator cannot tell them apart: ``M4``
    and ``M6`` produce both, a public read or uniform existence hiding beside an
    already-failing baseline. So the record says which, as ``evidence_limit``,
    where the outcome is decided. It used to be the operator set ``{"M6"}``,
    which left M4's public-read and existence-hiding results out of the report
    the module docstring promised them to, and put M6's already-failing ones in.
    """
    return bool(
        mutant["outcome"] == NOT_APPLICABLE
        and mutant.get("evidence_limit")
        and mutant.get("diagnosis")
    )


def _evidence_notes(
    evidence: dict[str, Any], mutants: Sequence[dict[str, Any]]
) -> list[str]:
    """Per-check limits on what this run could measure at all.

    Not survivors and not in the score -- nothing here was measured, so neither
    would be honest -- but they must be visible. A check whose attacker the
    target answers exactly as it answers a nobody scores 1.00 with no survivors,
    and an operator reading only the number would take that for a perfect
    result rather than for an unanswered question.
    """
    notes: list[str] = []
    if evidence.get("marker_note"):
        notes.append(evidence["marker_note"])
    for mutant in mutants:
        if _is_evidence_limit(mutant):
            notes.append(f"{mutant['identity']}: {mutant['diagnosis']}.")
    return notes


def _marker_evidence(observation: _Observation) -> dict[str, Any]:
    """Report a check's data-flow evidence as a PROPERTY, not as a mutant.

    A check with no marker assertion has nothing for ``M3`` to mutate. The old
    ``absent`` mutant recorded that as a survivor, which put an unkillable
    entry in the denominator, repeated one verbatim paragraph per marker-less
    check in the survivor list, and -- on a ``DELETE`` answering 204 with no
    body -- printed a remediation the operator cannot carry out. It is a
    property of the check, so it is reported once as one.
    """
    asserted = sorted(
        identity
        for identity, expectation in observation.check["expect"].items()
        if expectation.get("contains_marker") or expectation.get("excludes_marker")
    )
    if asserted:
        return {"marker_evidence": "declared", "marker_assertions": asserted}
    served = [
        probe["response"]
        for probe in observation.probes.values()
        if isinstance(probe["response"]["status"], int)
        and 200 <= probe["response"]["status"] < 300
    ]
    bodiless = bool(served) and all(
        response["body_bytes"] == 0 for response in served
    )
    note = (
        "this check's only evidence is the status code. A status matches "
        "whether or not the response body carried another identity's data."
    )
    note += (
        " Every served response on this operation had an empty body, so there "
        "is nothing here to mark; the data-flow evidence has to come from an "
        "operation that returns one."
        if bodiless
        else " Add contains_marker on the owner and excludes_marker on the "
        "other identities to get data-flow evidence."
    )
    return {
        "marker_evidence": "status_only",
        "marker_assertions": [],
        "marker_note": note,
    }


def _baseline_requests(config: dict[str, Any]) -> int:
    """One request per identity each check's ``expect`` names, plus marker probes.

    Shared by the pre-flight banner and the ceiling below so the number the
    operator is shown and the number they are refused over can never diverge.
    """
    checks = config.get("checks") or ()
    return sum(len(check.get("expect") or {}) for check in checks) + sum(
        1
        for identity in (config.get("identities") or {}).values()
        if isinstance(identity, dict) and isinstance(identity.get("marker_probe"), dict)
    )


def _liveness_requests(config: dict[str, Any], prove_liveness: bool) -> int:
    """The liveness controls one ``core.execute_run`` adds to the baseline.

    Tier 2 runs the suite through ``execute_run``, which sends one fabricated-
    credential request per distinct denial-only request on every run. They
    were left out of the ceiling and the banner: a plan of 60 was accepted and
    90 went on the wire. Counted from core's own planner, so the two cannot
    disagree about what a liveness control is.
    """
    return len(core.plan_liveness_controls(config)) if prove_liveness else 0


def planned_requests(
    config: dict[str, Any],
    *,
    request_budget: int | None,
    suite_runs: int = 1,
    prove_liveness: bool = False,
) -> int:
    """The requests ``--max-requests`` is held against, derived offline: the
    baseline, the liveness controls at tier 2, and the mutation budget. Session
    logins and ``sequences`` steps are not counted at tier 2.

    ``prove_liveness`` is true at tier 2, where each suite run is a full
    ``execute_run`` and sends its liveness controls as well.
    """
    per_run = _baseline_requests(config) + _liveness_requests(config, prove_liveness)
    return per_run * max(suite_runs, 1) + (request_budget or 0)


def refuse_if_over_total(
    config: dict[str, Any],
    *,
    max_requests: int,
    request_budget: int | None,
    min_interval_seconds: float,
    suite_runs: int = 1,
    prove_liveness: bool = False,
) -> None:
    """Refuse an oversized plan before the first socket opens.

    ``map`` has always refused a plan it considers too large; ``mutate`` only
    ever narrated one. The rate limit bounds how *fast* the target is hit, not
    how much: at the default 0.5s interval a 5,000-check configuration runs for
    roughly 85 minutes rather than being turned away. Disclosure is not a
    control if the only way to act on it is Ctrl-C, so the ceiling is a refusal.

    The budget is charged against the baseline as well as the additional
    probes, because the baseline is what the volume complaint is about --
    ``--request-budget`` deliberately governs only the additional probes. At
    tier 2 it counts each suite run's baseline and liveness controls; session
    logins and ``sequences`` steps are not counted at tier 2, so for a
    configuration with either, more goes on the wire than the plan it checked.
    """
    planned = planned_requests(
        config,
        request_budget=request_budget,
        suite_runs=suite_runs,
        prove_liveness=prove_liveness,
    )
    if planned <= max_requests:
        return
    estimate = (
        f" At {1 / min_interval_seconds:.4g} req/s this would take "
        f"{_format_plan_duration(planned * min_interval_seconds)}."
        if min_interval_seconds
        else ""
    )
    raise ConfigError(
        f"the mutation plan is {planned:,} requests to be issued against the "
        f"target, over the budget of {max_requests:,}. Nothing has been sent."
        f"{estimate} Narrow the configuration, lower --request-budget, or raise "
        f"the ceiling explicitly with --max-requests {planned}."
    )


def _format_plan_duration(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def preflight_banner(
    config: dict[str, Any],
    *,
    min_interval_seconds: float,
    request_budget: int | None,
    read_only: bool = False,
    suite_runs: int = 1,
    prove_liveness: bool = False,
) -> str:
    """The number, the rate and the write posture, before anything is sent.

    ``map`` shows the operator the request count and the safety posture before
    it opens a socket; ``run`` discloses that a configuration writes. ``mutate``
    did neither, while issuing everything ``run`` issues plus its own probes on
    top -- including ``DELETE``, at whatever rate the network allowed.

    Every number here is derived offline from the loaded configuration, so this
    is printed before the first request rather than reported after the last.
    The baseline count is exact: one request per identity named in each check's
    ``expect``, plus one per identity that declares a ``marker_probe``.

    ``suite_runs`` is how many times that baseline goes on the wire -- once at
    tier 1, once per hook plus once unmutated at tier 2. ``request_budget`` of ``None`` means the
    caller issues no additional probes at all (tier 2), not "unlimited";
    ``prove_liveness`` names the liveness controls each tier-2 suite run sends.
    """
    baseline = _baseline_requests(config)
    liveness = _liveness_requests(config, prove_liveness)
    host = core._safe_url(config["target"]["base_url"])
    lines = [
        f"Veridor mutation -- this will re-issue your {baseline:,} declared "
        f"request(s) to {host}"
        + (f", {suite_runs} time(s)." if suite_runs != 1 else ",")
    ]
    if request_budget is None and liveness:
        lines.append(
            f"  plus {liveness:,} liveness control(s) per run, each carrying a "
            "credential Veridor fabricated; no mutation probes of its own."
        )
    elif request_budget is None:
        lines.append("  plus no additional probes of its own.")
    else:
        lines.append(f"  plus up to {request_budget:,} additional probe(s) of its own.")
    rate = (
        "no limit"
        if not min_interval_seconds
        else f"{1 / min_interval_seconds:.4g} req/s ({min_interval_seconds:g}s apart)"
    )
    lines.append(f"  rate:      {rate}, sequential")
    lines.append(
        "  measures:  your declaration. Nothing here is a finding about the target."
    )
    # The same surface `run`'s write disclosure counts, from the same function,
    # so the two can never disagree about what a write is.
    mutating = core._mutating_disclosure_surface(config)
    if mutating:
        verbs = ", ".join(sorted({verb for verb, _, _, _ in mutating}))
        lines.append(
            f"!! This configuration issues {verbs}. Running it WRITES to the target,\n"
            f"!! once per baseline probe and again for every mutation probe of the\n"
            f"!! same request. Pass --read-only to refuse it before anything is sent."
        )
    elif read_only:
        lines.append("  read-only: verified -- no request outside GET/HEAD/OPTIONS.")
    return "\n".join(lines)


def _refuse_session_identities(config: dict[str, Any]) -> None:
    """Fail closed on identities this module cannot faithfully impersonate.

    A session-authenticated identity is authenticated by a cookie jar the
    mutation engine does not establish. Probing it anyway would send every
    request unauthenticated, and the resulting "the credential is not being
    used" survivor would be manufactured by this module rather than observed. A
    false claim of vacuity is as bad as a false claim of safety, so the analysis
    refuses to start instead.
    """
    named = sorted(
        name
        for name, identity in config["identities"].items()
        if isinstance(identity, dict) and "session" in identity
    )
    if named:
        raise ConfigError(
            "mutation analysis does not model session-authenticated identities "
            f"({', '.join(named)}); it would probe them unauthenticated and "
            "report a vacuity it manufactured itself"
        )


def _observe(
    config: dict[str, Any], config_path: Path, budget: _Budget
) -> tuple[list[_Observation], dict[str, dict[str, Any]], int, dict[str, Any]]:
    """Issue the baseline probes and grade them with core's own grader.

    Every request here goes through ``budget.wait()`` first. These are the
    requests ``veridor run`` issues anyway, so the ALLOWANCE does not charge for
    them -- but they are the bulk of what ``mutate`` puts on the wire, and a
    rate limit that skipped them was a rate limit in name only.

    The fourth return value is the baseline TRANSPORT tally: how many of those
    requests never got a status, and the distinct reasons why. Without it a
    mutate run against a target that is not listening produces a report whose
    only symptom is ``not applicable`` counts and a null score, and the reader
    is left to guess. That is how the documented ``mutate`` example read to a
    new user who had not started the fixture server it needs.
    """
    base_url = config["target"]["base_url"]
    timeout = float(config["target"].get("timeout_seconds", 10))
    marker_controls = core._execute_marker_controls(config, pace=budget.wait)
    requests = len(marker_controls)
    observations: list[_Observation] = []
    results: list[dict[str, Any]] = list(marker_controls.values())
    for check in config["checks"]:
        probes: dict[str, dict[str, Any]] = {}
        for identity_name, expectation in check["expect"].items():
            budget.wait()
            probes[identity_name] = core._execute_probe(
                base_url,
                timeout,
                check,
                identity_name,
                config["identities"][identity_name],
                marker=core._probe_marker(config, check, identity_name, expectation),
            )
            requests += 1
        results.extend(probes.values())
        observations.append(
            _Observation(
                check=check,
                probes=probes,
                findings=_grade(check, probes, config_path, marker_controls),
            )
        )
    return observations, marker_controls, requests, _transport(results)


def _transport(results: list[dict[str, Any]]) -> dict[str, Any]:
    """How many baseline requests never got a status, and why.

    ``reasons`` is deduplicated and order-preserving because a target that is
    not listening produces the same message once per request, and printing it
    five times says nothing the count does not.
    """
    failed = [
        result
        for result in results
        if result["response"]["status"] is None and result.get("error")
    ]
    reasons: list[str] = []
    for result in failed:
        if result["error"] not in reasons:
            reasons.append(result["error"])
    return {
        "requests": len(results),
        "failed": len(failed),
        "reasons": reasons,
    }


def _grade(
    check: dict[str, Any],
    probes: dict[str, dict[str, Any]],
    config_path: Path,
    marker_controls: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Grade one check with core's grader and key the findings by identity.

    ``core._grade_check`` emits at most one finding per probe, so the mapping is
    total and lossless. Nothing this function returns is ever persisted as a
    finding: the caller reads ``rule_id`` and ``verdict`` and discards the rest.
    """
    findings = core._grade_check(
        check,
        probes,
        config_path,
        marker_controls=marker_controls,
        disclosures=[],
    )
    return {finding["identity"]: finding for finding in findings}


def _regrade(
    context: _Context, variant: dict[str, Any], observation: _Observation
) -> dict[str, dict[str, Any]]:
    """Re-grade a mutated check against the observations already collected."""
    return _grade(
        variant, observation.probes, context.config_path, context.marker_controls
    )


class _Budget:
    """The rate limit for EVERY request, and the allowance for the extra ones.

    Two jobs, deliberately in one object, because they are two halves of one
    envelope and splitting them is how they came to disagree.

    The ALLOWANCE counts only the additional ``M4`` probes -- the requests
    mutation invents. The baseline probes are the ones ``veridor run`` issues
    anyway and are budgeted by nothing, exactly as they are under ``run``.

    The RATE LIMIT covers both. It has to: a config of 60 ``DELETE`` checks and
    two identities is 120 baseline requests and zero additional ones, and
    throttling only the additional half would have left that measured 3,900
    req/s of ``DELETE`` traffic completely unchanged. Total load on the target
    is what needs bounding, which is the same reasoning ``matrix`` states for
    its own global limiter.
    """

    def __init__(self, allowance: int | None, min_interval_seconds: float) -> None:
        self._allowance = allowance
        self._interval = min_interval_seconds
        self._last: float | None = None
        self.spent = 0

    @property
    def exhausted(self) -> bool:
        return self._allowance is not None and self.spent >= self._allowance

    def wait(self) -> None:
        """Wait out the rate limit. Charges nothing to the allowance."""
        if self._interval and self._last is not None:
            elapsed = time.monotonic() - self._last
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
        self._last = time.monotonic()

    def take(self) -> None:
        """Account for one additional request and wait out the rate limit."""
        self.wait()
        self.spent += 1


def score(killed: int, generated: int) -> float | None:
    """``killed / generated``, or ``None`` when nothing was generated.

    ``None`` rather than ``0.0`` or ``1.0``. A suite that generated no mutants
    has no measured discriminating power at all, and either number would be a
    claim about checks that were never tested -- ``1.0`` the dangerous
    direction. Every consumer renders it as ``n/a``, and the badge renders it as
    ``unknown`` in grey. This is the only division in the module, so it is also
    the only place a zero-check suite could divide by zero; it does not.
    """
    if generated <= 0:
        return None
    return killed / generated


def _tally(mutants: Sequence[dict[str, Any]]) -> dict[str, Any]:
    counts = {outcome: 0 for outcome in OUTCOMES}
    for mutant in mutants:
        counts[mutant["outcome"]] += 1
    generated = sum(counts[outcome] for outcome in _SCORED)
    # A caveat that cannot move a number cannot gate a build. `limited` counts
    # the mutants this target could not answer -- the ones reported under
    # LIMITS ON THE EVIDENCE and deliberately kept out of `score`, on the sound
    # argument that an unanswerable mutant is not a measurement. The unsound
    # part was leaving the headline at 1.00 with nothing beside it: a suite
    # whose ONLY cross-tenant assertion sits in that section scores 1.00 (6/6)
    # and exits 0, and scores BETTER than the working config it was derived
    # from. So the same arithmetic is now also reported against the wider
    # denominator, which is a fact and not a re-weighting. Only those: a
    # structural not_applicable (an already-failing baseline, M3's
    # self-falsifying contains_marker) is not something this target withheld.
    limited = sum(1 for mutant in mutants if _is_evidence_limit(mutant))
    evaluable = generated + limited
    return {
        "generated": generated,
        **counts,
        "score": score(counts[KILLED], generated),
        "limited": limited,
        "score_of_evaluable": score(counts[KILLED], evaluable),
        "evaluable": evaluable,
    }


def _by_operator(
    mutants: Sequence[dict[str, Any]], operators: Sequence[str]
) -> dict[str, dict[str, Any]]:
    """The score decomposed by operator -- the honest alternative to weighting.

    Every declared operator appears even when it generated nothing, so a reader
    can tell "M4 killed everything" from "M4 never ran", which are opposite
    facts about a suite and would otherwise both render as an absent row.
    """
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in operators}
    for mutant in mutants:
        grouped.setdefault(mutant["operator"], []).append(mutant)
    return {name: _tally(group) for name, group in grouped.items()}


def summarize(
    mutants: Sequence[dict[str, Any]],
    *,
    checks: int,
    baseline_requests: int = 0,
    mutation_requests: int = 0,
    unmutated_sequences: int = 0,
    operators: Sequence[str] = tuple(OPERATORS),
) -> dict[str, Any]:
    """The summary block: overall tally, score, and the per-operator breakdown.

    Total by construction -- ``summarize([], checks=0)`` is a valid summary with
    a null score, so a configuration with nothing to mutate still renders text,
    JSON and a badge rather than raising.

    ``unmutated_sequences`` rides in the summary rather than only in the prose
    because the summary is what a CI script reads. A gate that sees ``score:
    1.0`` and nothing else would conclude the suite has discriminating power
    while three quarters of its declared assertions were never touched.
    """
    return {
        "checks": checks,
        "baseline_requests": baseline_requests,
        "mutation_requests": mutation_requests,
        "unmutated_sequences": unmutated_sequences,
        **_tally(mutants),
        "survivors": sum(
            1 for mutant in mutants if mutant["outcome"] in {SURVIVED, ABERRANT}
        ),
        # A partition of `skipped`, and a test asserts it sums to it. A future
        # skip site that forgets its tag would otherwise add to the number and
        # to none of the reasons -- silently reintroducing the count nobody
        # could act on that this block exists to remove.
        "skipped_reasons": {
            reason: sum(
                1
                for mutant in mutants
                if mutant["outcome"] == SKIPPED
                and mutant.get("skip_reason") == reason
            )
            for reason in SKIP_REASONS
        },
        "by_operator": _by_operator(mutants, operators),
    }


def exit_code(report: dict[str, Any]) -> int:
    """The mutation report's OWN exit code. It is never a run's exit code.

    ``0`` every generated mutant was killed; ``1`` at least one mutant survived,
    so at least one check may be vacuous; ``2`` at least one mutant was aberrant
    or could not be evaluated, which is the fail-closed direction -- the engine
    does not know whether those checks discriminate.

    A run that generated NOTHING also exits ``2``, not ``0``. ``0`` claims every
    generated mutant was killed, which is vacuously true of an empty set, and a
    CI gate reading that ``0`` would conclude the checks are sound when nothing
    was measured -- the exact vacuous pass this module exists to eliminate. It
    reuses ``2`` rather than inventing a code, because ``2`` already means "the
    engine does not know whether these checks discriminate", and that is
    precisely the situation.
    """
    summary = report["summary"]
    if summary[ABERRANT] or summary[ERRORED] or not summary["generated"]:
        return 2
    if summary[SURVIVED]:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Mutant generation
# ---------------------------------------------------------------------------


def _mutate_check(
    context: _Context, observation: _Observation
) -> list[dict[str, Any]]:
    mutants: list[dict[str, Any]] = []
    for build in (_m1, _m2, _m3, _m4, _m5, _m6):
        mutants.extend(build(context, observation))
    return mutants


#: Outcomes the reader is expected to act on. Each one must carry a diagnosis.
_DIAGNOSIS_REQUIRED: frozenset[str] = frozenset({SURVIVED, ABERRANT, ERRORED})


def _default_diagnosis(operator: str, outcome: str) -> str:
    """The diagnosis of last resort, so no actionable outcome ships bare.

    Written from the operator catalogue rather than hard-coded per operator, so
    an operator added later inherits a truthful sentence instead of a blank
    field. It is deliberately weaker than the hand-written diagnoses: it names
    the axis and stops, because a generic sentence that guessed at the cause
    would be worse than one that admits it does not know.
    """
    meta = OPERATORS.get(operator) or TARGET_OPERATOR.get(operator)
    axis = f" ({meta['mutates']})" if meta else ""
    if outcome == SURVIVED:
        return (
            f"the {operator} mutation{axis} did not change this check's verdict, "
            "so the check may be vacuous along that axis: it may pass whatever "
            "the target does here."
        )
    if outcome == ABERRANT:
        required = meta["kill_direction"] if meta else "the required direction"
        return (
            f"the {operator} mutation{axis} changed the verdict, but not as a "
            f"kill requires ({required}), so whether this check discriminates "
            "along that axis is unknown."
        )
    return (
        f"the {operator} mutation{axis} could not be evaluated, so whether this "
        "check discriminates along that axis is unknown."
    )


def _record(
    operator: str,
    observation: _Observation,
    identity: str | None,
    *,
    variant: str,
    mutation: str,
    outcome: str,
    observed: str,
    diagnosis: str | None = None,
    requests: int = 0,
    **extra: Any,
) -> dict[str, Any]:
    """One mutant record. Every field here is a status, a name, or prose.

    Nothing that reaches this function is a header, a header value, a body, a
    cookie, or a marker literal, and nothing downstream adds one.

    Every outcome the report publishes as a survivor leaves here with a
    non-empty diagnosis, filled from :func:`_default_diagnosis` if the caller
    supplied none. A survivor without a diagnosis is a number nobody can act on,
    so the guarantee is structural rather than a convention each operator has to
    remember.
    """
    check_id = observation.check["id"]
    if outcome in _DIAGNOSIS_REQUIRED and not (diagnosis or "").strip():
        diagnosis = _default_diagnosis(operator, outcome)
    return {
        "id": f"{check_id}::{identity or '*'}::{operator}",
        "operator": operator,
        "operator_label": OPERATORS[operator]["label"],
        "check_id": check_id,
        "identity": identity,
        "variant": variant,
        "mutation": mutation,
        "expected_direction": OPERATORS[operator]["kill_direction"],
        "outcome": outcome,
        "observed": observed,
        "diagnosis": diagnosis,
        "requests_issued": requests,
        **extra,
    }


def _variant(observation: _Observation) -> dict[str, Any]:
    """A deep copy of the check, so no mutation can reach the loaded config."""
    return copy.deepcopy(observation.check)


def _statuses(expectation: dict[str, Any]) -> list[int]:
    return [status for status in expectation["status"] if isinstance(status, int)]


def _classes(expectation: dict[str, Any]) -> set[str]:
    return {status_class(status) for status in _statuses(expectation)}


def _baseline_blocked(
    observation: _Observation, identity: str
) -> tuple[str, str] | None:
    """Say why ``identity`` cannot be mutated, or ``None`` when it can.

    See :func:`_blocked_outcome` for why the CAUSE matters as much as the fact.
    """
    probe = observation.probes[identity]
    if probe["error"]:
        return (
            "the baseline probe for this identity did not complete",
            "mutation measures the discriminating power of a PASSING check; "
            "this one did not run",
        )
    finding = observation.findings.get(identity)
    if finding is not None:
        if finding.get("verdict") == "inconclusive":
            # NOT "already failing". The probe went unanswered -- a rate limit,
            # a 5xx, a timeout -- so nothing is known about this check's
            # discriminating power either way. Saying it is already failing
            # would be a claim about the operator's declaration drawn from a
            # 429.
            return (
                "the baseline probe for this identity was never answered "
                f"({_why(finding)})",
                "mutation measures the discriminating power of a PASSING "
                "check; this one was not measured",
            )
        return (
            f"the baseline already reports a finding for this identity ("
            f"{_why(finding)})",
            "mutation measures the discriminating power of a PASSING check; "
            "this one is already failing",
        )
    return None


def _blocked_outcome(observation: _Observation, identity: str) -> str:
    """``NOT_APPLICABLE`` for a structural block, ``ERRORED`` for a transient.

    The two look identical in a summary and are opposites in meaning.

    ``not_applicable`` is a permanent fact about the shape of a check -- this
    operator has nothing to rewrite here -- and it recurs identically on every
    run, so removing it from the denominator is correct. A baseline probe that
    went UNANSWERED is neither permanent nor structural: the mutant would have
    been evaluated on a quieter afternoon, and dropping it silently shrinks the
    population the score is computed over while the score itself reads the same.

    Measured against a noisy target, this took a mutation run from 15 generated
    mutants to 11 and still reported 1.00 and exit 0. ``errored`` is the outcome
    that already means "the engine does not know", and it is the one that makes
    ``exit_code`` return 2.
    """
    probe = observation.probes[identity]
    finding = observation.findings.get(identity)
    unanswered = bool(probe["error"]) or (
        finding is not None and finding.get("verdict") == "inconclusive"
    )
    return ERRORED if unanswered else NOT_APPLICABLE


def _observed_success(observation: _Observation) -> tuple[str, int] | None:
    """The identity in this check that was actually served, and its status.

    Preference goes to an identity whose declaration is allow-only -- that is
    the check's own nomination of the owner -- and falls back to whoever the
    target served, in declaration order.
    """
    served = [
        (name, probe["response"]["status"])
        for name, probe in observation.probes.items()
        if isinstance(probe["response"]["status"], int)
        and 200 <= probe["response"]["status"] < 300
    ]
    if not served:
        return None
    for name, status in served:
        if _classes(observation.check["expect"][name]) == {"allow"}:
            return name, status
    return served[0]


def _directional(
    operator: str,
    observation: _Observation,
    identity: str,
    mutated: dict[str, dict[str, Any]],
    *,
    expected_verdict: str | None,
) -> tuple[str, str]:
    """Compare a re-grading against the baseline and return ``(outcome, why)``.

    The focus identity is the one whose declaration was mutated. A finding that
    lands only somewhere else is ``aberrant``: the mutation perturbed a control
    rather than the assertion it named, and the operator needs to know that
    rather than bank a kill.
    """
    finding = mutated.get(identity)
    if finding is not None:
        verdict = finding["verdict"]
        if expected_verdict is not None and verdict != expected_verdict:
            return (
                ABERRANT,
                f"the mutant {_verdict(verdict)}, where a kill requires that it "
                f"{_verdict(expected_verdict)}: {_why(finding)}",
            )
        return (KILLED, f"the mutant {_verdict(verdict)}: {_why(finding)}")
    strays = sorted(set(mutated) - set(observation.findings) - {identity})
    if strays:
        return (
            ABERRANT,
            "the mutated expectation still passed, but the mutation changed the "
            f"verdict of {', '.join(quoted(name) for name in strays)} instead",
        )
    return SURVIVED, "the mutated expectation still passed"


def _m1(context: _Context, observation: _Observation) -> list[dict[str, Any]]:
    """INVERT-DENIAL: a denied identity is re-declared to be served."""
    mutants: list[dict[str, Any]] = []
    success = _observed_success(observation)
    for identity, expectation in observation.check["expect"].items():
        if not (_classes(expectation) & _DENIAL_CLASSES):
            continue
        declared = _statuses(expectation)
        blocked = _baseline_blocked(observation, identity)
        owner, status = success or (None, _ASSUMED_SUCCESS)
        source = (
            f"the status {quoted(owner)} received on this request"
            if owner
            else "HTTP 200, because no identity in this check was served"
        )
        mutation = (
            f"declare {quoted(identity)} receives {[status]} instead of {declared} "
            f"({source})"
        )
        if blocked is not None:
            mutants.append(
                _record(
                    "M1",
                    observation,
                    identity,
                    variant="denial_to_success",
                    mutation=mutation,
                    outcome=_blocked_outcome(observation, identity),
                    observed=blocked[0],
                    diagnosis=blocked[1],
                    declared_statuses=declared,
                    mutant_statuses=[status],
                )
            )
            continue
        variant = _variant(observation)
        variant["expect"][identity]["status"] = [status]
        mutated = _regrade(context, variant, observation)
        outcome, why = _directional(
            "M1",
            observation,
            identity,
            mutated,
            expected_verdict="unexpected_denial",
        )
        observed_status = observation.probes[identity]["response"]["status"]
        diagnosis = None
        if outcome == SURVIVED:
            diagnosis = (
                f"{quoted(identity)} was served HTTP {observed_status} on this request "
                f"and the declaration {declared} accepted it. The expectation "
                "cannot tell allowed from denied, so its pass may be vacuous: "
                "narrow it to the denial statuses you actually require."
            )
        elif outcome == ABERRANT:
            diagnosis = (
                f"{quoted(identity)} was served HTTP {observed_status}, which the "
                f"declaration {declared} accepts but which is not a refusal. "
                "The check reads as a denial assertion and is not one."
            )
        mutants.append(
            _record(
                "M1",
                observation,
                identity,
                variant="denial_to_success",
                mutation=mutation,
                outcome=outcome,
                observed=why,
                diagnosis=diagnosis,
                declared_statuses=declared,
                mutant_statuses=[status],
                observed_status=observed_status,
            )
        )
    return mutants


def _m2(context: _Context, observation: _Observation) -> list[dict[str, Any]]:
    """INVERT-ALLOW: an identity declared to succeed is re-declared denied."""
    mutants: list[dict[str, Any]] = []
    for identity, expectation in observation.check["expect"].items():
        if "allow" not in _classes(expectation):
            continue
        declared = _statuses(expectation)
        denial = _denial_for(observation, identity, declared)
        mutation = (
            f"declare {quoted(identity)} is denied with {[denial]} instead of {declared}"
        )
        blocked = _baseline_blocked(observation, identity)
        if blocked is not None:
            mutants.append(
                _record(
                    "M2",
                    observation,
                    identity,
                    variant="allow_to_denial",
                    mutation=mutation,
                    outcome=_blocked_outcome(observation, identity),
                    observed=blocked[0],
                    diagnosis=blocked[1],
                    declared_statuses=declared,
                    mutant_statuses=[denial],
                )
            )
            continue
        variant = _variant(observation)
        variant["expect"][identity]["status"] = [denial]
        mutated = _regrade(context, variant, observation)
        outcome, why = _directional(
            "M2", observation, identity, mutated, expected_verdict="vulnerable"
        )
        observed_status = observation.probes[identity]["response"]["status"]
        diagnosis = None
        if outcome == SURVIVED:
            diagnosis = (
                f"{quoted(identity)} is declared to succeed but was refused with HTTP "
                f"{observed_status}, and the declaration {declared} accepted "
                "that too. Nothing in this check would notice this identity "
                "losing access."
            )
        elif outcome == ABERRANT:
            diagnosis = (
                f"{quoted(identity)} received HTTP {observed_status}, which the mutant "
                "graded as a refusal rather than as access."
            )
        mutants.append(
            _record(
                "M2",
                observation,
                identity,
                variant="allow_to_denial",
                mutation=mutation,
                outcome=outcome,
                observed=why,
                diagnosis=diagnosis,
                declared_statuses=declared,
                mutant_statuses=[denial],
                observed_status=observed_status,
            )
        )
    return mutants


def _denial_for(
    observation: _Observation, identity: str, declared: Sequence[int]
) -> int:
    """The denial status an ``M2`` mutant declares.

    A denial already inside the identity's OWN declared list comes first,
    because that is the case worth catching: an expectation that accepts both
    200 and 403 asserts nothing, and choosing any other denial would hide it
    behind a kill. Then a denial this check declares for some other identity,
    so the mutant speaks the suite's own vocabulary. Then 403.
    """
    for status in declared:
        if status in _REFUSAL:
            return status
    for name, expectation in observation.check["expect"].items():
        if name == identity:
            continue
        for status in _statuses(expectation):
            if status in DEFAULT_DENIAL_STATUSES:
                return status
    for name, expectation in observation.check["expect"].items():
        if name == identity:
            continue
        for status in _statuses(expectation):
            if status in AUTHN_STATUSES:
                return status
    return 403


def _m3(context: _Context, observation: _Observation) -> list[dict[str, Any]]:
    """DROP-MARKER: could this exclusion's marker oracle ever have fired?

    Only ``excludes_marker`` is mutated. A ``contains_marker`` cannot pass
    vacuously -- it fails the instant the marker is absent -- so a passing one
    has already proved its oracle fires, and inverting it would only bank a
    kill that was guaranteed before the mutation was generated.

    The kill takes TWO conditions, not one. The inversion must make the grader
    report a finding for this identity, AND the owner's marker must have been
    observed to be surfaceable at the path under test. The second condition is
    what makes the operator informative: a passing exclusion means the marker
    was not seen, so the inversion produces a finding unconditionally -- an
    ``inconclusive`` "the oracle could no longer be satisfied" at worst -- and
    accepting that alone would make every marker assertion in every suite a
    free ``+1`` that could never report the inertness this operator exists to
    report. Same-path observability comes from ``core._resolve_control`` so
    that the grader and this module cannot disagree about what licenses an
    exclusion.
    """
    check = observation.check
    mutants: list[dict[str, Any]] = []
    for identity, expectation in check["expect"].items():
        contains = expectation.get("contains_marker")
        excludes = expectation.get("excludes_marker")
        if not (contains or excludes):
            continue
        if contains:
            mutants.append(
                _record(
                    "M3",
                    observation,
                    identity,
                    variant="contains_is_self_falsifying",
                    mutation=(
                        f"none: contains_marker {quoted(contains)} on {quoted(identity)} is "
                        "not mutated"
                    ),
                    outcome=NOT_APPLICABLE,
                    observed=(
                        "a contains_marker assertion fails whenever the marker "
                        "is absent, so a passing one has already shown its "
                        "oracle can fail"
                    ),
                    diagnosis=(
                        "there is no vacuity here to measure: this assertion is "
                        "falsifiable by construction"
                    ),
                    marker_owner=contains,
                )
            )
            continue
        owner = excludes
        mutation = (
            f"replace excludes_marker {quoted(owner)} on {quoted(identity)} with "
            f"contains_marker, so the check demands the data flow it forbids"
        )
        blocked = _baseline_blocked(observation, identity)
        if blocked is not None:
            mutants.append(
                _record(
                    "M3",
                    observation,
                    identity,
                    variant="invert_exclusion",
                    mutation=mutation,
                    outcome=_blocked_outcome(observation, identity),
                    observed=blocked[0],
                    diagnosis=blocked[1],
                    marker_owner=owner,
                )
            )
            continue
        variant = _variant(observation)
        target = variant["expect"][identity]
        target.pop("excludes_marker", None)
        target["contains_marker"] = owner
        mutated = _regrade(context, variant, observation)
        outcome, why = _directional(
            "M3", observation, identity, mutated, expected_verdict=None
        )
        source, observable, reason = _marker_surfaceable(context, observation, owner)
        diagnosis = None
        if outcome == KILLED and not observable:
            # The inversion did produce a finding, but a passing exclusion
            # guarantees one, so the finding on its own is not evidence. Nothing
            # observed shows this path can surface the owner's marker, which is
            # what the exclusion would have to detect.
            outcome = SURVIVED
            why = (
                "the inverted assertion did report, but nothing observed shows "
                f"this path can surface {quoted(owner)}'s marker"
            )
        elif outcome == KILLED:
            # Never report a kill in the grader's own words here. A passing
            # exclusion inverts to "the oracle could no longer be satisfied",
            # and printing that sentence as the evidence of discriminating
            # power is exactly the inconclusive-sold-as-a-kill the second
            # condition exists to stop. The kill rests on the observation.
            why = (
                f"{quoted(owner)}'s marker was observed to be surfaceable at this "
                f"path, so an exclusion on {quoted(identity)} has something it could "
                "reject; inverting it reported"
            )
        if outcome == SURVIVED:
            diagnosis = (
                f"the excludes_marker on {quoted(identity)} could not have fired: "
                f"{reason} An exclusion that no observation could falsify adds "
                "nothing to the status code it sits beside. Probe "
                f"{quoted(owner)} against this same request and assert "
                f"contains_marker {quoted(owner)} on it, so the run establishes that "
                "this path surfaces the marker at all."
            )
        elif outcome == ABERRANT:
            diagnosis = (
                f"inverting the marker assertion on {quoted(identity)} left that "
                "expectation passing and moved the verdict elsewhere; the "
                "assertion is licensed by a control rather than by evidence at "
                "this path."
            )
        mutants.append(
            _record(
                "M3",
                observation,
                identity,
                variant="invert_exclusion",
                mutation=mutation,
                outcome=outcome,
                observed=why,
                diagnosis=diagnosis,
                marker_owner=owner,
                marker_observable_at_path=observable,
                marker_control_source=source,
            )
        )
    return mutants


def _marker_surfaceable(
    context: _Context, observation: _Observation, owner: str
) -> tuple[str, bool, str]:
    """Was ``owner``'s marker observed to be surfaceable AT THIS PATH?

    Delegates to ``core._resolve_control``, whose ``check`` and
    ``check_observed`` sources are exactly "the marker owner was probed at this
    very request and the answer settles whether this path can carry their
    marker". An ``identity_probe`` licence proves the marker is live SOMEWHERE
    and says nothing about here, which is precisely the inert case.
    """
    source, state, reason = core._resolve_control(
        observation.check, owner, observation.probes, context.marker_controls
    )
    observable = source in {"check", "check_observed"} and state == "present"
    if observable:
        return source, True, ""
    if source == "identity_probe":
        detail = (
            f"the only evidence that {quoted(owner)}'s marker is live comes from that "
            "identity's own marker_probe of a DIFFERENT path, so nothing "
            "establishes that the request under test can surface it"
        )
    elif source in {"check", "check_observed"}:
        detail = reason or (
            f"{quoted(owner)} was probed on this request and its own marker was not "
            "observed in the response"
        )
    else:
        detail = reason or f"no control established that {quoted(owner)}'s marker is live"
    return source, False, detail.rstrip(". ") + "."


def _m4(context: _Context, observation: _Observation) -> list[dict[str, Any]]:
    """STRIP-CREDENTIAL: is the credential read on this request at all?

    One real, unauthenticated request per applicable identity. Refused outright
    for a mutating verb, because an unauthenticated DELETE is not a diagnostic,
    it is an incident.

    Equality of the two statuses is NOT on its own a vacuity. Two very common
    and entirely correct designs produce it:

    * **Uniform existence-hiding.** A route that answers 200 to the owner and
      404 to everybody else -- credentialed or not -- is the more conservative
      design, and its 404 to the other tenant equals its 404 to an anonymous
      caller. The credential is plainly read at that path: the owner got a 200.
      Calling that check vacuous penalises the safer target, and the evidence
      that refutes the claim is sitting in the same ``_Observation``.
    * **A public read.** If the identity is served the same 2xx with and
      without its credential the operation is public; there is no cross-identity
      denial on it to be vacuous about, and no configuration knob exists here to
      waive a survivor, so the entry would reappear on every CI run forever.

    What equality DOES prove, on its own and against any other evidence, is the
    AUTHENTICATION case: a 401 or 407 is the target stating that this caller is
    not authenticated, which is exactly what it states to a caller with no
    credential. That is the invalid-token vacuity, and it stays a survivor.
    """
    check = observation.check
    method = check["request"].get("method", "GET").upper()
    mutants: list[dict[str, Any]] = []
    for identity in check["expect"]:
        credentials = _credential_surface(context.config["identities"][identity], check)
        mutation = (
            f"re-issue this request as {quoted(identity)} with "
            f"{credentials['description']} removed"
        )
        skip = skip_reason = None
        if method not in core.SAFE_METHODS:
            skip = (
                f"the request method is {method}; an unauthenticated {method} is "
                "never issued"
            )
            skip_reason = "mutating_verb"
        elif not credentials["strips"]:
            skip = (
                f"{quoted(identity)} sends no credential on this request, so there is "
                "nothing to strip"
            )
            skip_reason = "no_credential_to_strip"
        elif context.budget.exhausted:
            skip = "the mutation request budget is exhausted"
            skip_reason = "budget_exhausted"
        if skip is not None:
            mutants.append(
                _record(
                    "M4",
                    observation,
                    identity,
                    variant="no_credentials",
                    mutation=mutation,
                    outcome=SKIPPED,
                    observed=skip,
                    diagnosis=None,
                    skip_reason=skip_reason,
                )
            )
            continue
        blocked = _baseline_blocked(observation, identity)
        if blocked is not None:
            mutants.append(
                _record(
                    "M4",
                    observation,
                    identity,
                    variant="no_credentials",
                    mutation=mutation,
                    outcome=_blocked_outcome(observation, identity),
                    observed=blocked[0],
                    diagnosis=blocked[1],
                )
            )
            continue

        stripped = context.send(credentials["request"])
        credentialed = observation.probes[identity]["response"]["status"]
        anonymous = stripped["response"]["status"]
        if stripped["error"]:
            mutants.append(
                _record(
                    "M4",
                    observation,
                    identity,
                    variant="no_credentials",
                    mutation=mutation,
                    outcome=ERRORED,
                    observed="the uncredentialed request did not complete",
                    diagnosis=(
                        "the credential could not be tested, so whether this "
                        "check can distinguish identities is unknown"
                    ),
                    requests=1,
                    observed_status=credentialed,
                )
            )
            continue
        if _more_permissive(credentialed, anonymous):
            outcome = ABERRANT
            observed = (
                f"HTTP {credentialed} with credentials, HTTP {anonymous} without"
            )
            diagnosis = (
                f"removing the credential {quoted(identity)} sends made the response "
                f"MORE permissive (HTTP {credentialed} -> HTTP {anonymous}). The "
                "status did change, but not in the direction a kill requires: "
                "this path serves unauthenticated callers."
            )
        elif anonymous == credentialed:
            outcome, observed, diagnosis = _m4_unchanged(
                observation, identity, anonymous
            )
        else:
            outcome = KILLED
            observed = (
                f"HTTP {credentialed} with credentials, HTTP {anonymous} without"
            )
            diagnosis = None
        mutants.append(
            _record(
                "M4",
                observation,
                identity,
                variant="no_credentials",
                mutation=mutation,
                outcome=outcome,
                observed=observed,
                diagnosis=diagnosis,
                requests=1,
                observed_status=credentialed,
                uncredentialed_status=anonymous,
                # Every not_applicable reaching here came from _m4_unchanged: a
                # public read or uniform existence hiding, both "this target
                # cannot show us".
                evidence_limit=outcome == NOT_APPLICABLE,
            )
        )
    return mutants


def _more_permissive(before: Any, after: Any) -> bool:
    """Did removing or faking the credential make the target MORE generous?"""
    return (
        isinstance(after, int)
        and 200 <= after < 300
        and not (isinstance(before, int) and 200 <= before < 300)
    )


def _m4_unchanged(
    observation: _Observation, identity: str, status: Any
) -> tuple[str, str, str | None]:
    """Decide what "the same status either way" is worth for this identity.

    Three cases, and only the first is a vacuity the operator can act on. See
    :func:`_m4` for why the other two are not: they are the shapes of a target
    that hides existence uniformly and of an operation that is simply public,
    and reporting either as a possible vacuity would make the survivor list --
    the module's whole deliverable -- something a reader learns to skip.
    """
    observed = f"HTTP {status} with and without credentials"
    if isinstance(status, int) and status_class(status) == "authn_denial":
        return (
            SURVIVED,
            observed,
            (
                f"the target told {quoted(identity)} it is not authenticated (HTTP "
                f"{status}) and told a caller with no credential at all exactly "
                "the same thing. The credential is not being accepted, so this "
                "check cannot distinguish identities and its pass may be "
                "vacuous. Confirm this identity's credential is live before "
                "reading anything into its denial."
            ),
        )
    if isinstance(status, int) and 200 <= status < 300:
        return (
            NOT_APPLICABLE,
            observed,
            (
                "this operation serves a caller with no credential the same 2xx, "
                "so it is a public read; there is no identity distinction here "
                "for a strip-credential probe to measure"
            ),
        )
    others = sorted(
        f"{name} (HTTP {probe['response']['status']})"
        for name, probe in observation.probes.items()
        if name != identity and probe["response"]["status"] != status
    )
    if others:
        return (
            NOT_APPLICABLE,
            observed
            + f", while this request answers {', '.join(others)} differently",
            (
                "the credential IS read on this request -- "
                f"{', '.join(others)} -- so the identical answer to "
                f"{quoted(identity)} and to an anonymous caller is this operation "
                "hiding existence uniformly, not a credential the target "
                "ignores. Stripping the credential cannot measure this identity "
                "here; M6 is the operator that can."
            ),
        )
    return (
        SURVIVED,
        observed,
        (
            f"the credential {quoted(identity)} sends makes no difference to this "
            f"request: the target answered HTTP {status} either way, and no "
            "identity in this check was answered differently. The observed "
            "status is what this path returns to anyone, so this check cannot "
            "distinguish identities and its pass may be vacuous."
        ),
    )


def _credential_surface(
    identity: dict[str, Any], check: dict[str, Any]
) -> dict[str, Any]:
    """The request with this identity's credentials removed, and what went.

    Two sources are stripped: every header the IDENTITY declares, because those
    headers ARE what distinguishes it from another identity, and any credential
    header declared on the check request itself. The returned description names
    header NAMES only -- never a value, and never a count that could leak one.

    "Credential header" is capsule's definition, the one that refuses a literal
    value in such a header. It used to be core's three names only, so a check
    sending X-Api-Key kept it on the copy this operator calls unauthenticated.
    """
    identity_headers = sorted(identity.get("headers", {}) or {})
    request = dict(check["request"])
    request_headers = dict(request.get("headers", {}) or {})
    dropped_from_request = sorted(
        name for name in request_headers if capsule._credential_header(name)
    )
    request["headers"] = {
        name: value
        for name, value in request_headers.items()
        if name not in dropped_from_request
    }
    strips = identity_headers + dropped_from_request
    description = (
        ", ".join(f"the {name} header" for name in strips)
        if strips
        else "no header"
    )
    return {"request": request, "strips": strips, "description": description}


def _m5(context: _Context, observation: _Observation) -> list[dict[str, Any]]:
    """POSITIVE-CONTROL: does anything here prove the RESOURCE serves its owner?

    "Somebody got a 2xx" is not that proof, and the two ways it falls short are
    the two things this operator now checks.

    *Whose* 2xx. The mandate is "the OWNER actually succeeds on the same
    resource". A 2xx from an admin, or from a health-style caller declared in
    the same check, says nothing about whether the resource the attacker was
    denied exists for the identity whose data the denial protects. The positive
    control must be that identity: the one an ``excludes_marker`` names, and
    failing that an allow-only identity.

    *Worth what*. A 2xx is not the same as a resource. ``200 {"data": null}``,
    ``200 []`` and ``200 {"error": "not found"}`` are how a great many REST APIs
    report a missing record, and an envelope that echoes the caller satisfies a
    ``contains_marker`` on the caller's own marker while there is nothing behind
    the route at all. So the 2xx is corroborated by a NEGATIVE CONTROL: the same
    request, as the same identity, for a resource id that cannot exist. If that
    is served a 2xx as well, then a 2xx at this path does not establish that
    anything is there, and the positive control is worth nothing.
    """
    check = observation.check
    mutation = (
        f"declare every identity in {quoted(check['id'])} is refused with "
        f"{list(_ALL_REFUSED)}"
    )
    if observation.findings:
        already = sorted(observation.findings)
        return [
            _record(
                "M5",
                observation,
                None,
                variant="all_refused",
                mutation=mutation,
                outcome=NOT_APPLICABLE,
                observed=(
                    "the baseline already reports findings for "
                    f"{', '.join(quoted(name) for name in already)}"
                ),
                diagnosis=(
                    "mutation measures the discriminating power of a PASSING "
                    "check; this one is already failing"
                ),
            )
        ]
    variant = _variant(observation)
    for expectation in variant["expect"].values():
        expectation["status"] = list(_ALL_REFUSED)
    mutated = _regrade(context, variant, observation)
    served = _positive_control(observation)
    if served is not None and served[0] in mutated:
        return [_m5_corroborate(context, observation, mutation, *served)]
    if mutated:
        strays = sorted(mutated)
        elsewhere = _observed_success(observation)
        if elsewhere is not None:
            return [
                _record(
                    "M5",
                    observation,
                    None,
                    variant="all_refused",
                    mutation=mutation,
                    outcome=SURVIVED,
                    observed=(
                        f"the only 2xx in this check went to {quoted(elsewhere[0])} "
                        "(HTTP "
                        f"{elsewhere[1]}), which is not the identity whose data "
                        "the denial protects"
                    ),
                    diagnosis=(
                        f"{quoted(elsewhere[0])} being served says nothing about "
                        "whether the resource the other identities were refused "
                        "exists for its owner -- a 2xx to an administrator or to "
                        "a health-style caller is not a positive control. "
                        "Declare the identity whose data this denial protects, "
                        "and require it to succeed on this same resource."
                    ),
                    positive_control=None,
                )
            ]
        return [
            _record(
                "M5",
                observation,
                None,
                variant="all_refused",
                mutation=mutation,
                outcome=ABERRANT,
                observed=(
                    "the mutant reported a finding for "
                    f"{', '.join(quoted(name) for name in strays)}, but no identity "
                    "in this check was served a 2xx"
                ),
                diagnosis=(
                    "the only thing distinguishing this check from a universal "
                    "refusal is a status that is neither a refusal nor a success "
                    "-- a redirect or a server error. That is not a positive "
                    "control: nothing here shows the route serves anyone."
                ),
            )
        ]
    return [_m5_everyone_refused(observation, mutation)]


def _m5_everyone_refused(
    observation: _Observation, mutation: str
) -> dict[str, Any]:
    """Nobody was served. Whether that is a vacuity depends on HOW they were refused.

    The survivor's whole claim is that the denial is equally well explained by
    an absent route, an unshipped feature or a wrong resource id -- and that
    claim is only available when the refusal is indistinguishable from absence.
    A 401 or a 403 is not: the route answered, and it answered by refusing. On
    the same targets these runs observe, an absent route returns 404. Making the
    claim over an observed 403 states something the engine can see is false, and
    it fires on a perfectly ordinary check -- "no tenant identity may read the
    admin audit log" -- whose remediation ("declare an identity that must
    succeed here") does not exist, because no identity may succeed there.
    """
    statuses = [
        probe["response"]["status"] for probe in observation.probes.values()
    ]
    # 404 is the one refusal that an absent route also returns, so it is the one
    # refusal that leaves the missing-resource explanation open.
    ambiguous = any(status == _NOT_FOUND for status in statuses)
    explicit = sorted({status for status in statuses if status != _NOT_FOUND})
    if not ambiguous:
        return _record(
            "M5",
            observation,
            None,
            variant="all_refused",
            mutation=mutation,
            outcome=NOT_APPLICABLE,
            observed=(
                "no identity in this check was served, and every observed "
                f"status ({', '.join(f'HTTP {status}' for status in explicit)}) "
                "is an explicit refusal rather than a not-found"
            ),
            diagnosis=(
                "there is no positive control here and none is available: the "
                "route answered every identity by refusing it, which shows the "
                "route exists, so the missing-resource explanation a positive "
                "control exists to rule out is already ruled out. A check where "
                "no identity may succeed cannot be given one."
            ),
            positive_control=None,
        )
    return _record(
        "M5",
        observation,
        None,
        variant="all_refused",
        mutation=mutation,
        outcome=SURVIVED,
        observed="every identity in this check was refused",
        diagnosis=(
            "no identity in this check received a successful response, and the "
            "refusal observed is a 404, which is what an absent route returns. "
            "A denial observed here is equally well explained by an absent "
            "route, an unshipped feature, or a wrong resource id -- it is not "
            "evidence about authorization. Declare an identity that must "
            "succeed on this same resource."
        ),
        positive_control=None,
    )


def _m5_corroborate(
    context: _Context,
    observation: _Observation,
    mutation: str,
    owner: str,
    status: int,
) -> dict[str, Any]:
    """Is the owner's 2xx about the RESOURCE, or about the route answering at all?

    One request: the same method, the same identity, the last path segment
    replaced by an id that was generated this run and cannot name anything. A
    2xx to that is a route that answers 2xx for any id, so the owner's 2xx at
    the real id establishes nothing and the positive control is worthless.
    """
    method = observation.check["request"].get("method", "GET").upper()
    observed = (
        f"{quoted(owner)} was served HTTP {status} on this request, so the mutant "
        "reported a finding"
    )
    probe = _absent_resource_request(context, observation.check)
    # Without the negative control the soft-404 explanation is exactly as open
    # as it was before, so an unsent or failed one is SKIPPED or ERRORED, as it
    # is for M4 and M6 -- never a kill on the status alone. It used to be a
    # kill, and a request budget running out turned this operator's survivor
    # into a 1.00 with exit 0.
    reason = skip_reason = None
    if method not in core.SAFE_METHODS:
        reason = f"the request method is {method}, so no extra request was issued"
        skip_reason = "mutating_verb"
    elif probe is None:
        reason = "this request's path carries no resource id to fabricate"
        skip_reason = "no_resource_id"
    elif context.budget.exhausted:
        reason = "the mutation request budget is exhausted"
        skip_reason = "budget_exhausted"
    if reason is not None:
        return _record(
            "M5",
            observation,
            None,
            variant="all_refused",
            mutation=mutation,
            outcome=SKIPPED,
            observed=f"{observed}; it was not corroborated because {reason}",
            diagnosis=None,
            skip_reason=skip_reason,
            positive_control=owner,
            positive_control_evidence="status_only",
        )
    request, safe_path = probe
    absent = context.send(
        request, headers=context.config["identities"][owner].get("headers", {})
    )
    absent_status = absent["response"]["status"]
    if absent["error"]:
        return _record(
            "M5",
            observation,
            None,
            variant="all_refused",
            mutation=mutation,
            outcome=ERRORED,
            observed=(
                f"{observed}; the negative control for {safe_path} did not "
                "complete, so the 2xx is uncorroborated"
            ),
            diagnosis=(
                "the fabricated-id request did not complete, so whether this "
                "route answers a 2xx for anything at all is unknown and the "
                "owner's 2xx is not yet a positive control"
            ),
            requests=1,
            positive_control=owner,
            positive_control_evidence="status_only",
        )
    if isinstance(absent_status, int) and 200 <= absent_status < 300:
        return _record(
            "M5",
            observation,
            None,
            variant="all_refused",
            mutation=mutation,
            outcome=SURVIVED,
            observed=(
                f"{quoted(owner)} was served HTTP {status} here and HTTP "
                f"{absent_status} for a resource id fabricated this run"
            ),
            diagnosis=(
                f"the 2xx {quoted(owner)} received is not evidence that this resource "
                "exists: the same route answers a 2xx for an id that was "
                "generated moments ago and cannot name anything, which is what a "
                "soft 404 inside a success envelope looks like. Nothing here is "
                "a positive control, so the other identities' denials are "
                "equally well explained by there being nothing to serve. Assert "
                "something about the RESOURCE in the owner's response -- a "
                "marker planted in the record itself, not one the envelope "
                "echoes back from the caller."
            ),
            requests=1,
            positive_control=owner,
            positive_control_evidence="refuted_by_negative_control",
            absent_resource_status=absent_status,
        )
    return _record(
        "M5",
        observation,
        None,
        variant="all_refused",
        mutation=mutation,
        outcome=KILLED,
        observed=(
            f"{observed}, and a fabricated resource id on the same route was "
            f"answered HTTP {absent_status}"
        ),
        diagnosis=None,
        requests=1,
        positive_control=owner,
        positive_control_evidence="negative_control",
        absent_resource_status=absent_status,
    )


def _absent_resource_request(
    context: _Context, check: dict[str, Any]
) -> tuple[dict[str, Any], str] | None:
    """The check's own request with its last path segment made unresolvable."""
    request = dict(check["request"])
    path = str(request.get("path", ""))
    base, separator, query = path.partition("?")
    segments = base.split("/")
    for index in range(len(segments) - 1, -1, -1):
        if segments[index]:
            segments[index] = f"{_SHAM_PREFIX}-absent-{context.sham_token[-12:]}"
            fabricated = "/".join(segments) + (separator + query if query else "")
            request["path"] = fabricated
            return request, "/".join(segments)
    return None


def _positive_control(observation: _Observation) -> tuple[str, int] | None:
    """The identity whose 2xx would be a positive control, and its status.

    An ``excludes_marker`` names the owner of the data the denial protects, and
    where the check names one it is the ONLY identity whose 2xx is a positive
    control -- an allow-only bystander in the same check being served says
    nothing about the resource that owner's data lives in. Where no owner is
    named, an allow-only identity is the check's own nomination. Never "the
    first 2xx we saw", which is how an administrator's success became proof
    that the resource exists for somebody else.
    """
    check = observation.check
    protected: list[str] = []
    for expectation in check["expect"].values():
        owner = expectation.get("excludes_marker")
        if owner and owner in check["expect"] and owner not in protected:
            protected.append(owner)
    candidates = protected or [
        name
        for name, expectation in check["expect"].items()
        if _classes(expectation) == {"allow"}
    ]
    for name in candidates:
        status = observation.probes[name]["response"]["status"]
        if isinstance(status, int) and 200 <= status < 300:
            return name, status
    return None


def _m6(context: _Context, observation: _Observation) -> list[dict[str, Any]]:
    """SHAM-CREDENTIAL: is this identity a principal the boundary applies to?

    ``M4`` compares the identity against NO credential. That comparison cannot
    separate two very different sentences a target might be saying:

    * "I do not know who you are" -- an expired token, a typo'd token, a
      credential for an account that no longer exists;
    * "I know who you are and you may not have this" -- the only sentence a
      cross-identity authorization check is entitled to read into a denial.

    A target that answers 401 to a missing header and 403 to an unrecognised one
    -- an extremely common split -- makes ``M4`` a KILL for an identity that is
    not a principal at all, and the check then scores a perfect 1.00 while being
    completely unable to notice the guard it names being removed. The same
    happens to a real principal that a coarser gate refuses before the ownership
    predicate ever runs: it too is denied for a reason that has nothing to do
    with the boundary under test.

    So this operator compares against a credential that certainly belongs to
    nobody: same header names, fabricated values, generated this run. If the
    target answers the identity exactly as it answers that nobody, then nothing
    observed distinguishes the identity from a non-principal, and the check's
    pass is not evidence about the boundary it names.

    Deliberately narrow, because a survivor nobody can act on makes the whole
    survivor list something a reader learns to skip. It runs only where all of
    these hold:

    * the check declares this identity must be DENIED -- an allow expectation
      is not a boundary claim;
    * the identity WAS refused -- an identity the target served has already
      shown the target knows it;
    * the identity actually sends a credential -- one that sends none IS the
      nobody;
    * and SOME identity in the check was served. Without that, the check says
      "nobody may read this", which is a perfectly ordinary and correct thing to
      assert; a fabricated credential being refused as well is the declaration
      coming true, not evidence against it. The question this operator asks --
      is this identity's denial about this identity? -- only exists where the
      check claims somebody else may.

    One request per credential shape per check, safe methods only, charged to
    the budget.
    """
    check = observation.check
    method = check["request"].get("method", "GET").upper()
    mutants: list[dict[str, Any]] = []
    cache: dict[tuple[str, ...], dict[str, Any]] = {}
    contrast = _observed_success(observation)
    for identity, expectation in check["expect"].items():
        if not (_classes(expectation) & _DENIAL_CLASSES):
            continue
        headers = sorted(context.config["identities"][identity].get("headers", {}) or {})
        mutation = (
            f"re-issue this request as {quoted(identity)} with "
            + (", ".join(f"the {name} header" for name in headers) or "no header")
            + " carrying a credential fabricated this run"
        )
        status = observation.probes[identity]["response"]["status"]
        skip = skip_reason = None
        if method not in core.SAFE_METHODS:
            skip = (
                f"the request method is {method}; a fabricated credential is "
                f"never sent on a {method}"
            )
            skip_reason = "mutating_verb"
        elif not headers:
            skip = (
                f"{quoted(identity)} sends no credential on this request, so it is "
                "already indistinguishable from a caller the target does not know"
            )
            skip_reason = "no_credential_header"
        elif isinstance(status, int) and 200 <= status < 300:
            skip = (
                f"{quoted(identity)} was served HTTP {status} on this request, so the "
                "target does recognise it; there is no denial here whose meaning "
                "is in question"
            )
            skip_reason = "already_served"
        elif context.budget.exhausted:
            skip = "the mutation request budget is exhausted"
            skip_reason = "budget_exhausted"
        if skip is not None:
            mutants.append(
                _record(
                    "M6",
                    observation,
                    identity,
                    variant="sham_credential",
                    mutation=mutation,
                    outcome=SKIPPED,
                    observed=skip,
                    diagnosis=None,
                    skip_reason=skip_reason,
                )
            )
            continue
        blocked = _baseline_blocked(observation, identity)
        # An already-failing baseline is bookkeeping; nobody being served is a
        # limit on what this target can show.
        limit = blocked is None and contrast is None
        if limit:
            # Ordered after the mutating-verb refusal on purpose: the safety
            # rule is the one the reader must see reported, whatever else is
            # true of the check.
            blocked = (
                "no identity in this check was served",
                "this check asserts that nobody may have this resource, so a "
                "credential belonging to nobody being refused too is the "
                "declaration holding rather than evidence about this identity",
            )
        if blocked is not None:
            mutants.append(
                _record(
                    "M6",
                    observation,
                    identity,
                    variant="sham_credential",
                    mutation=mutation,
                    outcome=_blocked_outcome(observation, identity),
                    observed=blocked[0],
                    diagnosis=blocked[1],
                    evidence_limit=limit,
                )
            )
            continue
        key = tuple(headers)
        issued = 0
        if key not in cache:
            cache[key] = context.send(
                dict(check["request"]), headers=_sham_headers(context, headers)
            )
            issued = 1
        sham = cache[key]
        sham_status = sham["response"]["status"]
        if sham["error"]:
            mutants.append(
                _record(
                    "M6",
                    observation,
                    identity,
                    variant="sham_credential",
                    mutation=mutation,
                    outcome=ERRORED,
                    observed="the request carrying a fabricated credential did not complete",
                    diagnosis=(
                        "whether this identity is a principal this boundary "
                        "applies to could not be tested, so whether this check "
                        "discriminates along that axis is unknown"
                    ),
                    requests=issued,
                    observed_status=status,
                )
            )
            continue
        observed = f"HTTP {status} as {quoted(identity)}, HTTP {sham_status} with a fabricated credential"
        if _more_permissive(status, sham_status):
            outcome = ABERRANT
            diagnosis = (
                f"a credential fabricated this run was served HTTP {sham_status} "
                f"where {quoted(identity)} was refused with HTTP {status}. The answer "
                "did change, but not in the direction a kill requires: this path "
                "serves a caller it cannot have recognised."
            )
        elif sham_status == status:
            observed = (
                f"HTTP {status} both for {quoted(identity)} and for a credential "
                "fabricated this run"
            )
            outcome, diagnosis = _m6_indistinguishable(identity, status)
        else:
            outcome = KILLED
            diagnosis = None
        mutants.append(
            _record(
                "M6",
                observation,
                identity,
                variant="sham_credential",
                mutation=mutation,
                outcome=outcome,
                observed=observed,
                diagnosis=diagnosis,
                requests=issued,
                observed_status=status,
                sham_status=sham_status,
                # Every not_applicable reaching here came from
                # _m6_indistinguishable.
                evidence_limit=outcome == NOT_APPLICABLE,
            )
        )
    return mutants


def _m6_indistinguishable(identity: str, status: Any) -> tuple[str, str]:
    """The target answered the identity and a nobody alike. Is that a vacuity?

    Only for an explicit ``403``. That status is the target making a statement
    ABOUT THE CALLER -- "I know what you are asking for and you may not have
    it" -- and making the identical statement to a credential that certainly
    belongs to nobody puts the declared attacker in the same bucket as that
    nobody. Nothing observed then distinguishes "denied because of who you are"
    from "denied because we do not know who you are", which is the whole of the
    critical defect this operator exists for.

    The other refusals are recorded as unmeasurable rather than as vacuities:

    * ``404`` is the target declining to say anything at all, including whether
      it recognises the caller. A route that hides existence uniformly returns
      it to everybody by construction, so equality carries no information in
      either direction and there is nothing the operator could change. Calling
      that a possible vacuity penalises the more conservative design and would
      reappear on every CI run forever.
    * ``401``/``407`` is an authentication failure, which ``M4`` already reports
      against the far stronger evidence of a request carrying no credential at
      all. Two survivors for one fact is one survivor too many.
    """
    if status == _NOT_FOUND:
        return (
            NOT_APPLICABLE,
            (
                "this operation answers HTTP 404 both to this identity and to a "
                "credential it could not have recognised, which is what hiding "
                "existence uniformly looks like. That answer says nothing about "
                "who the caller is, in either direction, so whether this "
                "identity is a principal the boundary applies to cannot be "
                "measured from outside this target"
            ),
        )
    if isinstance(status, int) and status_class(status) == "authn_denial":
        return (
            NOT_APPLICABLE,
            (
                f"the target does not accept {quoted(identity)}'s credential at all "
                f"(HTTP {status}); M4 already reports that against a request "
                "carrying no credential, which is the stronger evidence"
            ),
        )
    if not isinstance(status, int) or status_class(status) != "authz_denial":
        return (
            NOT_APPLICABLE,
            (
                f"HTTP {status} is neither an authorization refusal nor a "
                "success, so what the target meant by answering this identity "
                "and a fabricated credential alike cannot be read"
            ),
        )
    return (
        SURVIVED,
        (
            f"the target answers {quoted(identity)} exactly as it answers a credential "
            f"that belongs to nobody (HTTP {status} either way) -- an explicit "
            "refusal, given identically to a caller it cannot have recognised. "
            f"Nothing observed here establishes that {quoted(identity)} is a principal "
            "this boundary applies to: its denial is equally well explained by a "
            "stale or mistyped credential, or by a coarser gate refusing it "
            "before the boundary under test is reached, so this check's pass may "
            "be vacuous. Confirm this identity's credential is live, and that it "
            "reaches the predicate this check is about, before reading a "
            "boundary into its denial."
        ),
    )


def _sham_headers(context: _Context, names: Sequence[str]) -> dict[str, str]:
    """Fabricated values for the headers an identity uses to identify itself.

    The real values are never read. ``Authorization`` gets a bearer token so the
    scheme parses; anything else gets the bare fabricated string. The value is
    generated once per run, is recognisable in an access log, and authenticates
    to nothing -- so this probe can never accidentally BE a credential.
    """
    sham: dict[str, str] = {}
    for name in names:
        sham[name] = (
            f"Bearer {context.sham_token}"
            if name.lower() == "authorization"
            else context.sham_token
        )
    return sham


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


#: What each tier calls the thing it mutated, so one renderer serves both.
_TIER_TITLE: dict[int, str] = {
    1: "tier 1, assertion mutation",
    2: "tier 2, target mutation",
}
_TIER_UNIT: dict[int, str] = {1: "check", 2: "hook"}


def render_text(report: dict[str, Any]) -> str:
    """Render one mutation report. ASCII only, survivors first.

    The order is load-bearing. The disclaimer comes before the number, because a
    reader who sees a score first has already formed a belief about it; the
    survivors come before the per-unit table, because they are the deliverable
    and the score is triage. Serves tier 1 and tier 2 from the same shape.
    """
    tier = report.get("tier", 1)
    unit = _TIER_UNIT.get(tier, "check")
    summary = report["summary"]
    lines: list[str] = []
    lines.append(
        f"Veridor mutation analysis -- {_TIER_TITLE.get(tier, f'tier {tier}')}"
    )
    lines.append(f"  target: {report.get('target') or '(as configured)'}")
    lines.append(f"  config: {report['config']}")
    lines.append("")
    lines.extend(_render_transport(report))
    lines.extend(_render_unrestored(report))
    for sentence in _header_sentences(report):
        lines.extend(_wrap(sentence, "  "))
    unmeasured = report.get("interpretation", {}).get("not_measured")
    if summary.get("unmutated_sequences"):
        lines.extend(_wrap(f"NOT MEASURED: {unmeasured}", "  "))
    lines.append("")
    lines.append(
        f"Mutation score: {_format_score(summary['score'])}  "
        f"({summary[KILLED]} killed / {summary['generated']} generated)"
    )
    lines.append(
        f"  survived {summary[SURVIVED]}  aberrant {summary[ABERRANT]}  "
        f"errored {summary[ERRORED]}  not applicable {summary[NOT_APPLICABLE]}  "
        f"skipped {summary[SKIPPED]}"
    )
    # Both denominators, side by side. The first is the honest score of what
    # could be evaluated; the second says how much that was.
    if summary.get("limited"):
        lines.append(
            f"  {_format_score(summary['score_of_evaluable'])} of "
            f"{summary['evaluable']} generated + limited "
            f"({summary['limited']} could not be evaluated). A mutation score "
            "is only as wide as the mutants it could evaluate."
        )
    # `skipped N` published a number whose reasons lived only in the JSON. The
    # LIMITS block covers `not_applicable`; this was the count with nothing
    # attached to it, so the reader could not tell "the budget ran out" from
    # "there was nothing here to strip".
    skipped_reasons = {
        reason: count
        for reason, count in (summary.get("skipped_reasons") or {}).items()
        if count
    }
    if skipped_reasons:
        lines.append(
            "  skipped, by reason -- no mutant was generated by POLICY, not by "
            "measurement:"
        )
        for reason, count in sorted(skipped_reasons.items()):
            lines.extend(
                _wrap(f"{count} x {SKIP_REASONS.get(reason, reason)}", "      ")
            )
    if summary["generated"] == 0:
        lines.extend(
            _wrap(
                "No mutant was generated, so there is no score. That is not a "
                f"pass: nothing here measured whether any {unit} can fail.",
                "  ",
            )
        )
    if tier == 1:
        lines.append(
            f"  requests: {summary['baseline_requests']} baseline, "
            f"{summary['mutation_requests']} issued by mutation (M4, M5, M6)"
        )
        if summary.get("unmutated_sequences"):
            lines.append(
                f"  unmutated: {summary['unmutated_sequences']} declared "
                "sequence(s), which this score does not cover"
            )
    lines.append("")
    lines.extend(_render_survivors(report, unit))
    lines.append("")
    lines.extend(_render_status_only(report))
    lines.extend(_render_scores(report, unit))
    lines.append("Operators:")
    for name, meta in report["operators"].items():
        lines.append(f"  {name} {meta['label']}: catches {meta['catches']}")
    return "\n".join(lines) + "\n"


def _header_sentences(report: dict[str, Any]) -> tuple[str, ...]:
    if report.get("tier") == 2:
        return (report["interpretation"]["statement"], *TIER2_CONTRACT, RELATIONSHIP)
    return TIER1_HEADER


def _render_transport(report: dict[str, Any]) -> list[str]:
    """Say it plainly when the baseline never reached the target.

    A mutate run against a host that is not listening produced a report with a
    null score, a wall of ``not applicable``, and -- three lines below the
    ``n/a`` -- the all-clear paragraph. Nothing anywhere named the host or the
    connection error. The reader's own conclusion was that ``mutate`` is
    broken.
    """
    transport = report.get("baseline_transport") or {}
    failed = transport.get("failed", 0)
    if not failed:
        return []
    total = transport.get("requests", failed)
    lines = ["!! THE BASELINE DID NOT REACH THE TARGET !!"]
    lines.extend(
        _wrap(
            f"{failed} of {total} baseline request(s) to "
            f"{report.get('target') or 'the target'} got no response. Mutation "
            "grades the target's OBSERVED behaviour against a mutated "
            "declaration, so with no observation there is nothing to grade and "
            "nothing below is a measurement of your checks.",
            "  ",
        )
    )
    for reason in transport.get("reasons") or ():
        lines.extend(_wrap(f"reason: {reason}", "  "))
    lines.append("")
    return lines


def _render_unrestored(report: dict[str, Any]) -> list[str]:
    """The loudest thing this module says, at the top of the page it is on.

    A tier-2 hook whose restore command did not exit 0 leaves the operator's
    target with a guard removed. That fact reached the JSON and the exit code
    but not the rendered text -- the artifact a human actually reads out of a CI
    log -- so the person whose environment was sitting there mutated was shown
    an all-clear. It goes first, before the header, before the score.
    """
    stranded = [
        record
        for record in report.get("checks") or []
        if record.get("restore_verified") is False
    ]
    if not stranded:
        return []
    lines = ["!! THE TARGET MAY STILL BE MUTATED !!"]
    for record in stranded:
        lines.extend(
            _wrap(
                f"hook {quoted(record['check_id'])}: {record.get('observed', '')}. It "
                f"was applied to remove {record['mutation'][len('remove '):]} "
                "and the restore command did not confirm it was put back. "
                "Restore this target by hand before pointing anything else at "
                "this environment.",
                "  ",
            )
        )
    lines.append("")
    return lines


def _render_survivors(report: dict[str, Any], unit: str) -> list[str]:
    """The real deliverable: who, which operator, what was seen, what it means.

    Errored mutants are printed here too. They are not survivors and the report
    never calls them that, but they are UNRESOLVED -- nothing about them was
    measured -- and the per-unit table already counts them in its "N to read
    above". Leaving them out made that count point at nothing and, when the
    errored mutants were the only unresolved ones, printed the all-clear over
    them.
    """
    unresolved = report.get("unresolved")
    if unresolved is None:
        unresolved = report["survivors"]
    if not unresolved:
        if not report.get("summary", {}).get("generated"):
            # "Every generated mutant changed the verdict" is vacuously true of
            # an empty set, and printing it three lines under `score: n/a` put
            # a green-sounding sentence over a null measurement. The n/a line
            # above already says what happened; saying nothing more is the only
            # honest option here.
            return []
        return _wrap(
            "No surviving mutants. Every generated mutant changed the verdict in "
            "the required direction, so every mutated declaration would have "
            "caught the change. That is a statement about these declarations, "
            "not about the target.",
            "",
        )
    survived = sum(1 for mutant in unresolved if mutant["outcome"] != ERRORED)
    errored = len(unresolved) - survived
    headline = (
        f"SURVIVING MUTANTS ({survived}) -- these {unit}s may be vacuous"
        if survived
        else f"UNRESOLVED MUTANTS ({errored}) -- nothing here was measured"
    )
    lines = [headline]
    if survived and errored:
        lines[0] += f", plus {errored} that could not be evaluated"
    lines.extend(
        _wrap(
            "Each entry below is a mutation that did NOT change the verdict, "
            "changed it the wrong way, or could not be evaluated at all. None of "
            "them is a finding about your target; each is a statement about what "
            "its declaration can detect.",
            "  ",
        )
    )
    for mutant in unresolved:
        lines.append("")
        who = mutant["identity"] or "(whole check)"
        lines.append(
            f"  [{mutant['outcome'].upper()}] {mutant['operator']} "
            f"{mutant['operator_label']} -- {unit} {quoted(mutant['check_id'])}, "
            f"identity {who}"
        )
        lines.extend(_wrap(f"mutation: {mutant['mutation']}", "      "))
        lines.extend(_wrap(f"expected: {mutant['expected_direction']}", "      "))
        lines.extend(_wrap(f"observed: {mutant['observed']}", "      "))
        if mutant["diagnosis"]:
            lines.extend(_wrap(f"means:    {mutant['diagnosis']}", "      "))
    return lines


def _render_status_only(report: dict[str, Any]) -> list[str]:
    """What this run could not measure, reported once per check.

    Neither a mutant nor a survivor. A status-only check has nothing to mutate,
    and an identity a target answers exactly as it answers a nobody has nothing
    the engine can read -- but a score of 1.00 with an empty survivor list is
    read as a perfect result, so the unanswered questions have to be printed
    next to it or the number travels alone.
    """
    weak = [
        check
        for check in report.get("checks") or []
        if check.get("evidence_notes")
    ]
    if not weak:
        return []
    total = sum(len(check["evidence_notes"]) for check in weak)
    lines = [
        f"LIMITS ON THE EVIDENCE ({total}) -- not scored, and not survivors: "
        "nothing here was measured either way"
    ]
    for check in weak:
        lines.append(f"  {check['check_id']}")
        for note in check["evidence_notes"]:
            lines.extend(_wrap(note, "      "))
    lines.append("")
    return lines


def _render_scores(report: dict[str, Any], unit: str) -> list[str]:
    """The score, decomposed two ways. Neither decomposition is weighted."""
    lines = [f"Per {unit}:"]
    for check in report["checks"]:
        # Never truncated: two ids that differ past a column would render
        # identical, and the reader would be looking for the wrong check.
        lines.append(
            f"  {check['check_id']:<40}  {_format_score(check['score'])}  "
            f"({check[KILLED]}/{check['generated']}){_survivor_note(check)}"
        )
    by_operator = report["summary"].get("by_operator") or {}
    if by_operator:
        lines.append("")
        lines.append("Per operator (unweighted -- every operator counts once):")
        for name, tally in by_operator.items():
            label = report["operators"].get(name, {}).get("label", "")
            lines.append(
                f"  {f'{name} {label}':<40}  {_format_score(tally['score'])}  "
                f"({tally[KILLED]}/{tally['generated']}){_survivor_note(tally)}"
            )
    lines.append("")
    return lines


def _survivor_note(tally: dict[str, Any]) -> str:
    unresolved = tally[SURVIVED] + tally[ABERRANT] + tally[ERRORED]
    if not unresolved:
        return ""
    return f"  {unresolved} to read above"


def _format_score(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


# ---------------------------------------------------------------------------
# Machine artifacts
# ---------------------------------------------------------------------------


def _badge_color(percent: float, *, unresolved: int) -> str:
    """The coverage badge's thresholds, with one extra rule.

    The badge never renders green while any mutant is unresolved, and a SURVIVOR
    counts as unresolved along with an aberrant and an errored one. Downgrading
    for the two the engine cannot explain while ignoring the one it CAN was
    exactly backwards: a survivor is a KNOWN possible vacuity, the module calls
    it the deliverable, and the badge is the artifact that travels furthest from
    the survivor list that would have explained it. Five checks the report
    itself describes as possibly vacuous must not render brightgreen while one
    unexplained aberrant renders yellow.

    The thresholds themselves mirror ``coverage._badge_color`` so two badges in
    the same README are read on the same scale.
    """
    if percent >= 95:
        color = "brightgreen"
    elif percent >= 90:
        color = "green"
    elif percent >= 75:
        color = "yellow"
    elif percent >= 50:
        color = "orange"
    else:
        color = "red"
    if unresolved and color in {"green", "brightgreen"}:
        return "yellow"
    return color


def render_badge(
    report: dict[str, Any],
    *,
    label: str | None = None,
    cache_seconds: int = 300,
) -> dict[str, Any]:
    """shields.io endpoint JSON, in the shape ``coverage.render_badge`` uses.

    The message says ``killed``, not ``passed``: what the number counts is
    mutants this suite detected, and a reader who mistakes it for a pass rate
    would read a green badge as a statement about the target. The percentage is
    floored by ``coverage.format_percent``, so one survivor in two thousand can
    never round up to ``100.0%``.

    A measurement that is not defined never renders a green badge -- a suite
    that generated no mutants is ``unknown`` in grey with ``isError``, exactly as
    an unmeasurable coverage report is.

    The label defaults by tier, so a README carrying both badges never shows two
    different measurements under the same words.
    """
    if label is None:
        label = TIER2_BADGE_LABEL if report.get("tier") == 2 else BADGE_LABEL
    summary = report.get("summary") or {}
    generated = summary.get("generated")
    killed = summary.get(KILLED)
    if (
        not isinstance(generated, int)
        or not isinstance(killed, int)
        or generated <= 0
    ):
        return {
            "schemaVersion": 1,
            "label": label,
            "message": "unknown",
            "color": "lightgrey",
            "isError": True,
            "cacheSeconds": cache_seconds,
        }
    unresolved = sum(summary.get(key) or 0 for key in (SURVIVED, ABERRANT, ERRORED))
    return {
        "schemaVersion": 1,
        "label": label,
        "message": f"{format_percent(killed, generated)} killed",
        "color": _badge_color(killed * 100 / generated, unresolved=unresolved),
        "cacheSeconds": cache_seconds,
    }


def mutation_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Compact block for embedding beside a coverage summary.

    Carries :data:`RELATIONSHIP` with it. The two numbers are only ever
    dangerous together, and an embedded block is exactly where they end up
    together with no header above them to say how they differ.
    """
    summary = report.get("summary") or {}
    return {
        "tier": report.get("tier"),
        "score": summary.get("score"),
        "generated": summary.get("generated"),
        "killed": summary.get(KILLED),
        "survived": summary.get(SURVIVED),
        "aberrant": summary.get(ABERRANT),
        "errored": summary.get(ERRORED),
        "survivors": len(report.get("survivors") or []),
        "unmutated_sequences": summary.get("unmutated_sequences") or 0,
        "measures": report.get("interpretation", {}).get("measures"),
        "not_measured": report.get("interpretation", {}).get("not_measured"),
        "does_not_measure": report.get("interpretation", {}).get("does_not_measure"),
        "relationship": RELATIONSHIP,
    }


def write_reports(
    report: dict[str, Any], output_dir: Path, *, stem: str = "mutation"
) -> dict[str, Path]:
    """Write the human text, the machine JSON and the badge JSON. No SARIF.

    Deliberately no SARIF, and deliberately not into the run's output document:
    SARIF is the findings format, a mutation result is not a finding, and a
    killed mutant that reached a code-scanning UI would be the exact false alarm
    rule 1 exists to prevent.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": output_dir / f"{stem}.json",
        "text": output_dir / f"{stem}.txt",
        "badge": output_dir / f"{stem}-badge.json",
    }
    core.write_json(paths["json"], report)
    # The renderer's own prose is ASCII; the file is UTF-8 because a check id or
    # an identity NAME comes from the operator's configuration, and refusing to
    # write the report over an accented identity name would be a silly failure.
    paths["text"].write_text(
        redaction.scrub_text(render_text(report)), encoding="utf-8", errors="strict"
    )
    core.write_json(paths["badge"], render_badge(report))
    return paths


def _wrap(text: str, indent: str, width: int = REPORT_WIDTH) -> list[str]:
    """Wrap a paragraph. One implementation, in ``coverage``.

    This used to hand-roll it "without importing textwrap", and the copy in
    ``blastradius`` hand-rolled it differently: over Veridor's own report prose
    the two disagreed on 26% of inputs.

    Delegating changes one thing here, and it is a fix. The old body began
    ``text.split()``, which collapses every run of whitespace, so the aligned
    gutter three lines below -- ``means:    `` padded to the same ten columns
    as ``mutation: ``, ``expected: `` and ``observed: `` -- was flattened to
    ``means: `` and the column the author had lined up did not survive to the
    terminal. ``textwrap`` preserves it. Measured over the report strings this
    module really emits, that is the only difference: 14 of 88, every one of
    them a ``means:`` line getting its alignment back.
    """
    return wrap_paragraph(text, indent, width)


# ---------------------------------------------------------------------------
# Tier 2
# ---------------------------------------------------------------------------


#: The hook contract, printed in every tier-2 report and enforced by
#: :func:`_validate_hooks` before any command runs. ASCII only.
TIER2_CONTRACT: tuple[str, ...] = (
    "apply_command: your argv, run without a shell, that produces a build with "
    "exactly ONE named guard removed. Exit 0 on success. Veridor does not parse "
    "your source, does not know your language, and does not generate the "
    "mutation -- you do.",
    "restore_command: your argv that puts the target back. Exit 0 on success. "
    "It is MANDATORY: tier 2 leaves your target altered, so a hook with no "
    "documented way back is refused before anything runs.",
    "restore_command runs on EVERY path -- the apply command failing, the suite "
    "raising, the suite passing, the suite going red. If it does not exit 0 the "
    "hook is reported errored with restore_verified false, and every later hook "
    "in the run is skipped rather than applied to a target in an unknown state.",
    "removes: one phrase naming the guard, in your words. The survivor "
    "diagnosis is written from it, so 'the tenant predicate in "
    "InvoiceRepository.find_by_id' is useful and 'mutation 3' is not.",
    "Neither command's stdout or stderr is captured. A build log is exactly the "
    "kind of artifact that carries a token; only the exit status is read.",
    "The suite runs once against the unmutated target before any hook is "
    "applied. If it already reports a finding there, every hook is not "
    "applicable; if it cannot grade every check there, every hook is errored. "
    "No hook is applied in either case: a suite that is red before a guard is "
    "removed cannot show that removing it turned the suite red.",
    "Nothing tier 2 reports is a finding either. A suite that goes red against a "
    "mutated build is working as intended -- that red is the evidence, and it "
    "never becomes a finding, a SARIF result, or a `veridor run` exit code.",
)


@dataclass(frozen=True)
class TargetMutationHook:
    """One operator-supplied target mutation. See :data:`TIER2_CONTRACT`.

    ``apply_command`` must produce a build with exactly one guard removed;
    ``restore_command`` must put it back. Both are argv sequences run without a
    shell. Their stdout and stderr are never captured into the report -- a build
    log is exactly the kind of artifact that carries a token.

    ``restore_command`` has no default on purpose. A default -- even a no-op --
    would make "I forgot the restore command" and "this target needs no restore"
    indistinguishable, and the first of those must not run.
    """

    name: str
    removes: str
    apply_command: Sequence[str]
    restore_command: Sequence[str]
    cwd: str | None = None
    timeout_seconds: float = 300.0


#: The tier-2 operator, in the shape ``render_text`` reads for tier 1.
TARGET_OPERATOR: dict[str, dict[str, str]] = {
    "T1": {
        "label": "target-mutation",
        "mutates": "a guard is removed from the target's own build",
        "kill_direction": (
            "the suite, green against the unmutated target, must report an "
            "identity served what its declaration refuses"
        ),
        "catches": (
            "a guard no check in this configuration covers, whose removal the "
            "suite would not notice"
        ),
        "requests": "one full suite execution per hook",
    }
}


def _validate_hooks(hooks: Sequence[TargetMutationHook]) -> None:
    """Refuse the whole run before a single command executes.

    Every check here is a refusal to start, not a per-hook error, because the
    first thing a tier-2 run does is alter the operator's target. Discovering
    hook 3 has no restore command after hooks 1 and 2 have already been applied
    is not a diagnostic, it is a mess left in someone's environment.
    """
    seen: set[str] = set()
    for hook in hooks:
        if not isinstance(hook.name, str) or not hook.name.strip():
            raise ConfigError("every target mutation hook must be named")
        if hook.name in seen:
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} is declared twice; names "
                "identify a hook in the report and must be unique"
            )
        seen.add(hook.name)
        if not _argv(hook.apply_command):
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} supplies no apply command"
            )
        if not _argv(hook.restore_command):
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} supplies no restore "
                "command; tier 2 modifies your target and will not run without "
                "a command that puts it back"
            )
        _validate_argv(hook.name, "apply_command", hook.apply_command)
        _validate_argv(hook.name, "restore_command", hook.restore_command)
        if not isinstance(hook.removes, str) or not hook.removes.strip():
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} must say which guard it "
                "removes; the survivor diagnosis is written from it"
            )
        if not isinstance(hook.timeout_seconds, (int, float)) or isinstance(
            hook.timeout_seconds, bool
        ):
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} declares a non-numeric "
                "timeout"
            )
        if hook.timeout_seconds <= 0:
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} declares a non-positive "
                "timeout; a command that is never allowed to finish cannot be "
                "restored from"
            )
        if hook.cwd is not None and not isinstance(hook.cwd, (str, bytes, PathLike)):
            raise ConfigError(
                f"target mutation hook {quoted(hook.name)} declares a cwd that is not "
                "a path"
            )


#: Everything a hook name may contribute to a directory name. Deliberately an
#: allow-list: an operator's hook name is prose ("drop the tenant filter"), and
#: enumerating the characters that are dangerous on three filesystems is a game
#: nobody wins. Anything outside this collapses to a single ``-``.
_UNSAFE_IN_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")

#: Two or more dots in a row, wherever they land.
_DOT_RUN = re.compile(r"\.{2,}")

#: Long enough to stay readable, short enough that ``NN-`` plus this plus the
#: run-document filenames underneath stays inside the shortest ``PATH_MAX``
#: this project claims to support.
_MAX_COMPONENT = 60

#: What an unnameable hook is called. A name of ``"..."``, ``"///"`` or a string
#: of emoji sanitises to nothing, and an empty component would silently write
#: the evidence into ``NN-``'s parent -- the same containment break by a
#: different route. The index prefix keeps these unique.
_UNNAMEABLE_COMPONENT = "hook"


#: ``report["unmutated_run"]["outcome"]`` when the suite was green against the
#: unmutated target and the hooks were applied. Otherwise the outcome is the one
#: every hook was given instead: ``not_applicable`` or ``errored``.
UNMUTATED_PASSED = "passed"


def evidence_component(index: int, name: str) -> str:
    """The ONE directory component a hook's evidence may be written to.

    A hook name is operator prose that reaches the filesystem, and it was the
    single input in the hooks file that received no validation at all. A name
    containing ``..`` -- or any separator, since ``f"{index:02d}-{name}"``
    prefixes only the FIRST component -- put the tier-2 run documents outside
    ``--output-dir`` while the console still announced the containing path.
    Those are the documents the CLI says "Do not publish them" about.

    Rejecting a literal ``".."`` is not enough and is not what this does:
    ``a/../../x`` contains no standalone ``..`` segment until it is split, and
    ``.`` and a bare separator escape by other routes. Everything outside the
    allow-list collapses, the result is stripped of leading dots so no name can
    produce ``..`` or a hidden directory, and an empty result falls back to a
    usable name rather than to the parent directory.

    This is containment, not privilege separation -- tier 2 already runs argv
    the operator supplied. It keeps the artifacts where the operator was told
    they would be.
    """
    collapsed = _UNSAFE_IN_COMPONENT.sub("-", name)
    # A run of dots collapses to one. Not because ".." is dangerous once the
    # separators are gone -- it is inert inside a component -- but because a
    # directory named "00-a-..-..-vd-ESCAPED" reads like a traversal that
    # worked, and an artifact-containment guarantee nobody believes is worth
    # very little. Leading and trailing dots go too: "." and ".." must be
    # unreachable, and Windows drops a trailing dot so two names would collide.
    safe = _DOT_RUN.sub(".", collapsed).strip(".-")[:_MAX_COMPONENT].strip(".-")
    return f"{index:02d}-{safe or _UNNAMEABLE_COMPONENT}"


def _argv(command: Any) -> tuple[Any, ...]:
    """``command`` as a tuple, or empty when it is not a sequence of arguments."""
    if command is None or isinstance(command, (str, bytes)):
        # A bare string is argv-shaped only to the eye: tuple("git") is four
        # one-character arguments, which is not what anyone meant.
        return ()
    try:
        return tuple(command)
    except TypeError:
        return ()


def _validate_argv(name: str, field: str, command: Any) -> None:
    """Refuse an argv element ``subprocess.run`` cannot accept.

    ``subprocess.run`` raises ``TypeError`` -- not ``OSError``, not
    ``SubprocessError`` -- for an argv element that is not ``str``, ``bytes`` or
    ``PathLike``. On the restore command that exception used to propagate out of
    the ``finally`` in :func:`_run_hook` and out of the whole run: no report,
    ``restore_verified`` never set, no "THE TARGET MAY STILL BE MUTATED", later
    hooks never marked abandoned -- and the guard the apply command had already
    deleted still deleted. A JSON- or YAML-driven hook definition produces ints
    for numeric arguments as a matter of course (``["./mutate.sh", "--port",
    8080]``), so this is an ordinary input, and it is refused here, before
    anything has been applied to the operator's target.
    """
    for index, element in enumerate(_argv(command)):
        if not isinstance(element, (str, bytes, PathLike)):
            raise ConfigError(
                f"target mutation hook {quoted(name)} declares {field}[{index}] as "
                f"{type(element).__name__}; every argument must be a string, "
                "bytes or a path. Tier 2 removes a guard from your target and "
                "the restore command is the only way back, so a command that "
                "cannot be executed is refused before anything runs."
            )


def run_target_mutations(
    config_path: Path,
    hooks: Sequence[TargetMutationHook],
    *,
    output_dir: Path,
    base_url: str | None = None,
    read_only: bool = False,
) -> dict[str, Any]:
    """Run each hook, execute the real suite against the mutated build, restore.

    A hook is KILLED when the suite reports an identity served what its
    declaration refuses while the guard is removed, ABERRANT when the only
    findings about the target are refusals, and SURVIVED when the suite stays
    green -- which means the suite would not have noticed that guard going
    away. The suite runs once against the unmutated target first, and no hook
    is applied unless that run is green: see :func:`_unmutated_run`.

    ``output_dir`` receives the run documents each suite execution writes. They
    are mutation EVIDENCE, not findings: this function returns counts and never
    the findings themselves, emits no SARIF, and its exit code
    (:func:`exit_code`) is separate from any run's.

    ``read_only`` reaches every suite execution, so ``mutate --read-only`` means
    the same thing at tier 2 as at tier 1 and as under ``run``. It says nothing
    about the hooks: tier 2 runs commands the operator supplied and this flag is
    about the wire, exactly as it is on ``run``.

    Raises :class:`ConfigError` -- before running anything at all -- for any hook
    that violates :data:`TIER2_CONTRACT`, most importantly one with no restore
    command.
    """
    _validate_hooks(hooks)
    started_at = datetime.now(UTC)
    results: list[dict[str, Any]] = []
    unrestored: str | None = None
    # Before any hook touches the target. A kill means the suite went red
    # BECAUSE the guard was removed, and that is only true of a suite that is
    # green without the removal: a suite already red scored every hook killed,
    # a hook whose commands do nothing included, with score 1.00 and exit 0.
    unmeasurable = _unmutated_run(config_path, output_dir, base_url, read_only)
    for index, hook in enumerate(hooks):
        if unmeasurable is not None:
            results.append(_unmeasurable_hook(hook, *unmeasurable))
            continue
        if unrestored is not None:
            # The target is in an unknown state. Applying another mutation on top
            # of it would measure nothing and would deepen the mess.
            results.append(_abandoned_hook(hook, unrestored))
            continue
        # Sanitised, never interpolated: the hook name is operator prose and
        # this is the only place it reaches the filesystem. See
        # :func:`evidence_component`.
        result = _run_hook(
            hook,
            config_path,
            output_dir / evidence_component(index, hook.name),
            base_url,
            read_only,
        )
        results.append(result)
        if result["restore_verified"] is False:
            unrestored = hook.name
    summary = summarize(
        results, checks=len(hooks), operators=tuple(TARGET_OPERATOR)
    )
    return {
        "schema_version": MUTATION_SCHEMA_VERSION,
        "tier": 2,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "target": core._safe_url(base_url) if base_url else None,
        "config": str(config_path),
        "interpretation": {
            "measures": (
                "whether the suite reports a finding when a named guard is "
                "removed from the target's own build"
            ),
            "does_not_measure": "whether any other guard is present or correct",
            "relationship": RELATIONSHIP,
            "statement": (
                "Tier 2 modifies the target through commands YOU supplied. "
                "Nothing it reports is a finding; a suite that goes red here is "
                "working as intended. Confirm the restore command ran before you "
                "point anything else at this environment."
            ),
            "contract": list(TIER2_CONTRACT),
        },
        "scoring": dict(SCORING),
        "operators": copy.deepcopy(TARGET_OPERATOR),
        "summary": summary,
        "survivors": [
            result for result in results if result["outcome"] in {SURVIVED, ABERRANT}
        ],
        # An errored hook is the one whose restore may not have run. It is not a
        # survivor and is never called one, but it must reach the rendered text.
        "unresolved": [
            result
            for result in results
            if result["outcome"] in {SURVIVED, ABERRANT, ERRORED}
        ],
        "unmutated_declarations": [],
        # What the suite did against the target as it is, before any hook. The
        # CLI's closing line describes unmutated/ from this, so it cannot call
        # that run a pass when it was the reason no hook was applied.
        "unmutated_run": (
            {"outcome": UNMUTATED_PASSED}
            if unmeasurable is None
            else {"outcome": unmeasurable[0], "observed": unmeasurable[1]}
        ),
        "checks": results,
    }


def _blank_hook_record(hook: TargetMutationHook) -> dict[str, Any]:
    return {
        "id": f"target::{hook.name}",
        "operator": "T1",
        "operator_label": TARGET_OPERATOR["T1"]["label"],
        "check_id": hook.name,
        "identity": None,
        "variant": "guard_removed",
        "mutation": f"remove {hook.removes}",
        "expected_direction": TARGET_OPERATOR["T1"]["kill_direction"],
        "requests_issued": 0,
        "diagnosis": None,
        # True when the restore command exited 0, False when it did not, and
        # None when this hook never applied anything so there was nothing to
        # restore. False is the only value that means "somebody must go look".
        "restore_verified": None,
        # Counts only. The findings themselves stay in the run document; letting
        # them into this report is how a mutation result becomes a false alarm.
        "findings_while_mutated": 0,
    }


def _run_hook(
    hook: TargetMutationHook,
    config_path: Path,
    output_dir: Path,
    base_url: str | None,
    read_only: bool = False,
) -> dict[str, Any]:
    """Apply, run the suite, restore. The restore is in a ``finally``.

    Every failure mode between the apply and the restore -- a non-zero apply, an
    exception from the suite, a red suite, a green suite -- lands in the same
    ``finally``, because the one outcome this function must never produce is a
    mutated target left behind with the process exiting normally.
    """
    record = _blank_hook_record(hook)
    try:
        applied = _invoke(hook, hook.apply_command)
        if applied != 0:
            record.update(
                outcome=ERRORED,
                observed=f"the apply command exited {applied}",
                diagnosis=(
                    "the mutated build was not produced, so nothing was tested. "
                    "The restore command was run anyway, in case the apply "
                    "command failed part-way through."
                ),
            )
        else:
            _run_suite_against_mutated_build(
                hook, record, config_path, output_dir, base_url, read_only
            )
    finally:
        restored = _invoke(hook, hook.restore_command)
        record["restore_verified"] = restored == 0
        if restored != 0:
            record.update(
                outcome=ERRORED,
                observed=f"the restore command exited {restored}",
                diagnosis=(
                    "THE TARGET MAY STILL BE MUTATED. Restore it before pointing "
                    "anything else at this environment. No later hook in this "
                    "run was applied."
                ),
            )
    return _finish_hook(record)


def _run_suite_against_mutated_build(
    hook: TargetMutationHook,
    record: dict[str, Any],
    config_path: Path,
    output_dir: Path,
    base_url: str | None,
    read_only: bool = False,
) -> None:
    try:
        mutated = core.execute_run(
            config_path,
            output_dir=output_dir / "mutated",
            base_url=base_url,
            read_only=read_only,
        )
        findings = mutated["findings"]
        record["findings_while_mutated"] = len(findings)
    except Exception as exc:  # noqa: BLE001 - reported, never re-raised as a finding
        record.update(
            outcome=ERRORED,
            observed=(
                "the suite could not run against the mutated build: "
                f"{core._safe_error(exc)}"
            ),
            diagnosis="whether the suite would catch this guard's removal is unknown",
        )
        return
    # A kill requires the suite to have GRADED something. An execution failure
    # is reported by core as a finding too, so counting findings alone lets an
    # unreachable target -- a build that never came up, a port that moved, the
    # apply command breaking the service outright -- score as "your suite caught
    # the guard removal". That is the tier-1 vacuity this module exists to
    # prevent, one level up: the highest-fidelity tier would be the one
    # asserting safety on no evidence at all.
    #
    # Graded means a verdict about the TARGET. Excluding only the execution
    # rule let an inconclusive ORACLE-001 or CACHE-001 through as a kill: a
    # hook that merely stripped the owner's marker from a 200, or 503'd the
    # owner so the outsider's excludes_marker lost its control, scored killed
    # with exit 0. Tier 1 treats every inconclusive verdict as unmeasured.
    graded = _target_findings(findings)
    if findings and not graded:
        unrun = all(
            finding.get("rule_id") == _EXECUTION_RULE_ID for finding in findings
        )
        record.update(
            outcome=ERRORED,
            observed=(
                f"the suite did not complete against the mutated build: all "
                f"{len(findings)} result(s) report that the probe did not run"
                if unrun
                else "the suite could not grade the mutated build: all "
                f"{len(findings)} result(s) are inconclusive"
            ),
            diagnosis=(
                "whether the suite would catch this guard's removal is unknown. "
                "Nothing was graded, so this is NOT a kill -- check that the "
                "apply command left the target reachable"
                + ("." if unrun else " and serving what the suite asserts.")
            ),
        )
        return
    record["findings_while_mutated"] = len(graded)
    # A kill needs the suite to have seen access GRANTED, because that is what
    # removing a guard does. A refusal of an identity the build should serve
    # is the build breaking -- a rebuild that reset the store, a rotated
    # signing key -- and it usually takes the outsider's excludes_marker
    # control down with it. Counting it scored such a hook killed, 1.00, exit 0, while the
    # check that guards the boundary measured nothing.
    served = [
        finding for finding in graded if finding.get("verdict") == "vulnerable"
    ]
    if served:
        record.update(
            outcome=KILLED,
            observed=(
                f"the suite reported {len(served)} finding(s) of an identity "
                "served what its declaration refuses while the guard was removed"
            ),
        )
    elif graded:
        observed, diagnosis = _refusals(graded)
        record.update(
            outcome=ABERRANT,
            observed=(
                f"the mutated build {observed}, and the suite saw no "
                "identity served what its declaration refuses"
            ),
            diagnosis=diagnosis,
        )
    else:
        record.update(
            outcome=SURVIVED,
            observed="the suite stayed green while the guard was removed",
            diagnosis=(
                f"removing {hook.removes} changed nothing the suite asserts. "
                "No check in this configuration covers that guard, so its "
                "green result says nothing about it."
            ),
        )


def _refusals(findings: Sequence[dict[str, Any]]) -> tuple[str, str]:
    """What the mutated build did to each refused identity, and why that is
    not a kill: ``(observed, diagnosis)``, each identity named once.

    Two different things reach here as a refusal. An identity the declaration
    expects to SERVE that was refused is the build breaking (a reset store, a
    rotated key). An identity it expects REFUSED that drew a different refusal
    (anonymous declared [401] got 302; an attacker declared [403] got 404) was
    still refused, and a guard removal that turns 403 into 404 lands here. The
    reason used to call both "an identity it should serve", which is false for
    the second and sent its reader to check data and credentials.
    """
    observed: list[str] = []
    served: list[str] = []
    changed: list[str] = []
    unknown: list[str] = []
    for finding in findings:
        identity = finding.get("identity")
        who = (
            f"identity {quoted(identity)}"
            if identity
            else "an identity the finding does not name"
        )
        check = finding.get("check_id")
        where = f" on check {quoted(check)}" if check else ""
        evidence = finding.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        declared = evidence.get("expected_statuses")
        got = evidence.get("actual_status")
        status = f" with HTTP {got}" if isinstance(got, int) else ""
        if not isinstance(declared, list) or not declared or not all(
            isinstance(item, int) for item in declared
        ):
            clause, bucket = f"refused {who}{where}{status}", unknown
        elif any(core._target_served(item) for item in declared):
            clause, bucket = f"refused {who}{where}{status}", served
        else:
            clause, bucket = (
                f"answered {who}{where}{status}, a refusal other than the "
                f"declared one of {sorted(declared)}",
                changed,
            )
        if clause not in observed:
            observed.append(clause)
        if who not in bucket:
            bucket.append(who)

    def names(group: list[str]) -> str:
        return group[0] if len(group) == 1 else ", ".join(group[:-1]) + " and " + group[-1]

    reasons = []
    if served:
        expects = (
            "which its declaration expects it to serve"
            if len(served) == 1
            else "which their declarations expect them to serve"
        )
        reasons.append(
            f"the build refused {names(served)}, {expects}: removing a guard "
            "grants access, it does not refuse it, so check that the apply "
            "command left the target's data and credentials as the suite "
            "expects them"
        )
    if unknown:
        reasons.append(
            f"the build refused {names(unknown)} where the declaration expects "
            "otherwise: removing a guard grants access, it does not refuse it"
        )
    if changed:
        reasons.append(
            # What was seen, not why. A guard removal that turns 403 into 404
            # lands here (see the docstring), and so does a build that broke
            # some other way; this said the first "is not a guard's removal",
            # which Veridor cannot know.
            f"the build still refused {names(changed)}, only with a different "
            "status than declared, so the suite saw no access granted; "
            "Veridor cannot tell whether the guard's removal caused it, so "
            "check that the apply command removes the guard it names and that "
            "the declared statuses match how the target refuses"
        )
    diagnosis = (
        "; ".join(reasons)
        + ". This is NOT a kill: a kill needs the suite to see an identity "
        "served what its declaration refuses, and it saw only refusals."
    )
    return "; ".join(observed), diagnosis


def _target_findings(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings that state something about the target, from core's own set.

    ``inconclusive`` -- an unrun probe, an oracle that lost its control, a
    cacheable response -- says the suite could not tell, which is not the suite
    noticing anything.
    """
    return [
        finding
        for finding in findings
        if finding.get("verdict") in core._TARGET_VERDICTS
    ]


def _unmutated_run(
    config_path: Path,
    output_dir: Path,
    base_url: str | None,
    read_only: bool,
) -> tuple[str, str, str] | None:
    """Run the suite once against the target as it is. ``None`` when it is green.

    Otherwise the outcome, observation and diagnosis every hook in the run is
    given instead of being applied. A red suite is ``not_applicable``, as a
    tier-1 check whose baseline already reports a finding is; a suite that could
    not grade everything is ``errored``, because a finding that appears once a
    guard is removed may be the check that went unmeasured here.
    """
    try:
        unmutated = core.execute_run(
            config_path,
            output_dir=output_dir / "unmutated",
            base_url=base_url,
            read_only=read_only,
        )
        findings = unmutated["findings"]
    except Exception as exc:  # noqa: BLE001 - reported, never re-raised as a finding
        return (
            ERRORED,
            "the suite could not run against the unmutated target: "
            f"{core._safe_error(exc)}",
            "no hook was applied, so whether the suite would catch any guard's "
            "removal is unknown",
        )
    graded = _target_findings(findings)
    if graded:
        return (
            NOT_APPLICABLE,
            f"the suite already reports {len(graded)} finding(s) against the "
            "unmutated target, so no hook was applied",
            "a suite that is red before any guard is removed would be red "
            "after, so its red says nothing about this guard. Make the suite "
            "pass against the real target first.",
        )
    if findings:
        return (
            ERRORED,
            f"the suite could not grade {len(findings)} result(s) against the "
            "unmutated target, so no hook was applied",
            "a kill needs a suite that passes without the mutation, and this one "
            "was not measured. Whether it would catch any guard's removal is "
            "unknown.",
        )
    return None


def _unmeasurable_hook(
    hook: TargetMutationHook, outcome: str, observed: str, diagnosis: str
) -> dict[str, Any]:
    """A hook never applied, because the unmutated suite run was not green."""
    record = _blank_hook_record(hook)
    record.update(outcome=outcome, observed=observed, diagnosis=diagnosis)
    if outcome == NOT_APPLICABLE:
        # Not a survivor and not unresolved, so without this the console would
        # print `not applicable 1` and an n/a score with no reason anywhere.
        record["evidence_notes"] = [f"{observed}: {diagnosis}"]
    return _finish_hook(record)


def _abandoned_hook(hook: TargetMutationHook, unrestored: str) -> dict[str, Any]:
    """A hook that was never applied because an earlier restore did not verify."""
    record = _blank_hook_record(hook)
    record.update(
        outcome=SKIPPED,
        observed=(
            f"hook {quoted(unrestored)} could not be restored, so the target's state is "
            "unknown and nothing further was applied to it"
        ),
        diagnosis=(
            "this hook was not tested. Restore the target by hand, confirm it, "
            "and run tier 2 again."
        ),
        skip_reason="target_state_unknown",
    )
    return _finish_hook(record)


def _finish_hook(record: dict[str, Any]) -> dict[str, Any]:
    """Give one hook result the same tally shape a tier-1 check has."""
    outcome = record["outcome"]
    for name in OUTCOMES:
        record[name] = 0
    record[outcome] = 1
    # A skipped hook applied nothing and measured nothing, so it stays out of the
    # denominator for the same reason a skipped M4 does.
    record["generated"] = 1 if outcome in _SCORED else 0
    record["score"] = score(record[KILLED], record["generated"])
    if outcome in _DIAGNOSIS_REQUIRED and not (record["diagnosis"] or "").strip():
        record["diagnosis"] = _default_diagnosis("T1", outcome)
    record["mutants"] = [dict(record)]
    return record


def _invoke(hook: TargetMutationHook, command: Sequence[str]) -> int:
    """Run one operator-supplied command and return its exit status only.

    ``stdout`` and ``stderr`` are discarded rather than captured: a build log is
    exactly the kind of artifact that carries a token, and nothing in this
    report needs it.
    """
    argv = _argv(command)
    if not argv:
        raise ConfigError(f"target mutation hook {quoted(hook.name)} declares an empty command")
    try:
        completed = subprocess.run(  # noqa: S603 - argv from the operator, no shell
            list(argv),
            cwd=hook.cwd,
            timeout=hook.timeout_seconds,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    # TypeError and ValueError are caught alongside the two obvious families
    # because _validate_hooks is not the only caller's only line of defence: a
    # restore command that raises out of the finally in _run_hook abandons the
    # target mid-mutation with no report and no warning, so nothing this
    # function does may propagate. A command that could not be run reads as a
    # non-zero exit, which is the fail-closed direction -- for the restore
    # command it triggers the loudest diagnosis in the module.
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return -1
    return completed.returncode
