"""The exit-code policy of ``veridor run``, in one place.

Before this module the policy lived in seven helpers in ``cli.py``, chained by
``or`` inside ``_run``, each printing its own stderr line as a side effect. The
exit code was the only artifact of the decision: the run document said nothing
about it (``status`` is a different, flag-independent fact), and every report
format a CI system reads -- JUnit, GitLab SAST, Code Quality, a Markdown job
summary -- had to guess why a job was red or amber from the findings alone. They
guessed wrong in the cases that matter most: a run that answered nothing, an
identity that never logged in, an unclean teardown. None of those is a finding,
so a converter that reads ``findings`` renders them as a pass.

:func:`evaluate` is now the single computation. It returns the exit code, the
machine-readable reasons behind it, the conditions that were present but that
this policy does not gate on, and the exact stderr lines the CLI has always
printed. The CLI exits with ``decision.exit_code`` and writes
``decision.to_document()`` into the run document as ``gate``, so the number a
pipeline reads and the number every report renders are one number.

Precedence is unchanged, byte for byte: a finding the policy selects (1) beats
an undefined coverage measurement (2), which beats a run that established
nothing or an identity that never authenticated (3), which beats an unclean
teardown or an incomplete measurement (3), which beats unproven liveness (3).
``--fail-on none`` keeps its documented shape: only the two opt-in cleanup and
completeness flags can move the code.

Pure: nothing here prints, reads a file, or looks at the clock.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from veridor.core import CAPSULE_EXIT_CODES, CONFIGURATION_UNSENT_ERRORS, probe_answered
from veridor.terminal import quoted

#: The ``--fail-on`` choices, in the order ``--help`` lists them.
FAIL_ON_CHOICES: tuple[str, ...] = ("new+confirmed", "new", "any", "confirmed", "none")
DEFAULT_FAIL_ON: str = "new+confirmed"

# ---------------------------------------------------------------------------
# Reason codes. Stable strings: they are written into run documents and read by
# CI scripts. Add new ones; never rename one.
# ---------------------------------------------------------------------------

#: A finding about the target that the ``--fail-on`` policy selects. Exit 1.
FINDINGS = "findings"
#: ``--openapi`` was given and boundary coverage could not be measured. Exit 2.
COVERAGE_NOT_MEASURED = "coverage_not_measured"
#: Not one probe was answered and nothing about the target was found. Exit 3.
NOTHING_ANSWERED = "nothing_answered"
#: A session identity failed to log in, deterministically. Exit 3.
IDENTITY_UNAUTHENTICATED = "identity_unauthenticated"
#: A sequence teardown failed, was incomplete or aborted. Exit 3 with
#: ``--require-clean-teardown``.
TEARDOWN_UNCLEAN = "teardown_unclean"
#: An expectation accepts both access and denial. Exit 3 with
#: ``--require-complete``.
EXPECTATIONS_NON_ASSERTING = "expectations_non_asserting"
#: A finding with verdict ``inconclusive``: a probe or step that established
#: nothing. Exit 3 with ``--require-complete``.
INCONCLUSIVE = "inconclusive"
#: A denial-only expectation, held by an identity that presents a credential,
#: did not establish who was denied: Veridor's fabricated credential received
#: the same denial, or none was sent to compare with (a write, or no header to
#: shape one on) and the identity was not proven live elsewhere (a 2xx on a
#: request where something without its credential was refused, or its
#: marker_probe; for a session, either one only under the same login and
#: session cookie value). Exit 3 with ``--require-complete``.
LIVENESS_UNPROVEN = "liveness_unproven"

#: Every reason code, in precedence order. The first ENFORCED reason in this
#: order decides the exit code.
REASON_CODES: tuple[str, ...] = (
    FINDINGS,
    COVERAGE_NOT_MEASURED,
    NOTHING_ANSWERED,
    IDENTITY_UNAUTHENTICATED,
    TEARDOWN_UNCLEAN,
    EXPECTATIONS_NON_ASSERTING,
    INCONCLUSIVE,
    LIVENESS_UNPROVEN,
)

# ---------------------------------------------------------------------------
# Capsule verification. `veridor verify` exits with the capsule's verdict, not
# with this policy, so its two failing verdicts are reasons of their own. Kept
# out of REASON_CODES, which is the precedence order of `veridor run` and
# which evaluate() never produces these from.
# ---------------------------------------------------------------------------

#: A capsule's claim reproduced on the target. Exit 1. About the target.
CAPSULE_CONFIRMED = "capsule_confirmed"
#: A capsule's claim was neither reproduced nor ruled out. Exit 2.
CAPSULE_INCONCLUSIVE = "capsule_inconclusive"

#: What each capsule reason means. The adjudication's own sentence follows it.
#: Held to ``coverage.BANNED_CLAIM_WORDS`` like REASON_TEXT.
CAPSULE_REASON_TEXT: dict[str, str] = {
    CAPSULE_CONFIRMED: "the capsule's claim reproduced on this target (CONFIRMED)",
    CAPSULE_INCONCLUSIVE: (
        "the capsule's claim was neither reproduced nor ruled out on this target "
        "(INCONCLUSIVE)"
    ),
}

#: The reason codes that are about the TARGET. Every other code says something
#: went unmeasured, and a report must never render one of those as a pass.
FINDING_REASON_CODES: frozenset[str] = frozenset({FINDINGS, CAPSULE_CONFIRMED})

#: What each reason means, in words a report can print after a colon, for a
#: reason that carries no ``count`` (``coverage_not_measured`` never does; a
#: hand-written or older document may omit one). Deliberately free of
#: ``coverage.BANNED_CLAIM_WORDS`` -- a test holds every string here to it.
REASON_TEXT: dict[str, str] = {
    FINDINGS: "at least one finding about the target",
    COVERAGE_NOT_MEASURED: (
        "boundary coverage was requested with --openapi and could not be measured"
    ),
    NOTHING_ANSWERED: (
        "not one probe was answered, so the run established nothing about the target"
    ),
    IDENTITY_UNAUTHENTICATED: (
        "at least one identity never authenticated, so no boundary involving it "
        "was tested"
    ),
    TEARDOWN_UNCLEAN: (
        "at least one sequence teardown did not complete cleanly; the target may "
        "hold fixtures this run created"
    ),
    EXPECTATIONS_NON_ASSERTING: (
        "at least one expectation accepts both access and denial, so it asserts "
        "nothing about the boundary"
    ),
    INCONCLUSIVE: (
        "at least one probe or step came back inconclusive, so that boundary was "
        "not measured"
    ),
    LIVENESS_UNPROVEN: (
        "at least one denial expectation held only against a denial that a "
        "fabricated credential received too, or that no fabricated credential "
        "was sent to compare with or whose fabricated credential's request "
        "failed or drew neither a refusal nor a success, so it did not "
        "establish who was denied"
    ),
}

#: The same meanings with the reason's ``count`` in them: ``(one, many)``,
#: each a ``str.format`` template over ``count``. The count used to be glued in
#: front of the REASON_TEXT sentence, and every report format printed "6 not
#: one probe was answered, so the run established nothing about the target".
#: ``findings`` is worded without "selected": a not-enforced ``findings``
#: reason lists the findings the policy did NOT select, and read "selected by
#: the --fail-on policy" beside "--fail-on any would gate on it".
REASON_COUNTED: dict[str, tuple[str, str]] = {
    FINDINGS: (
        "{count} finding about the target",
        "{count} findings about the target",
    ),
    NOTHING_ANSWERED: (
        "not one probe was answered, so the run established nothing about the "
        "target ({count} unanswered)",
    ) * 2,
    IDENTITY_UNAUTHENTICATED: (
        "{count} identity never authenticated, so no boundary involving it was tested",
        "{count} identities never authenticated, so no boundary involving them "
        "was tested",
    ),
    TEARDOWN_UNCLEAN: (
        "{count} sequence teardown did not complete cleanly; the target may hold "
        "fixtures this run created",
        "{count} sequence teardowns did not complete cleanly; the target may hold "
        "fixtures this run created",
    ),
    EXPECTATIONS_NON_ASSERTING: (
        "{count} expectation accepts both access and denial, so it asserts nothing "
        "about the boundary",
        "{count} expectations accept both access and denial, so they assert "
        "nothing about the boundary",
    ),
    INCONCLUSIVE: (
        "{count} probe or step came back inconclusive, so that boundary was not "
        "measured",
        "{count} probes or steps came back inconclusive, so those boundaries were "
        "not measured",
    ),
    LIVENESS_UNPROVEN: (
        "{count} denial expectation held only against a denial that a fabricated "
        "credential received too, or that no fabricated credential was sent to "
        "compare with or whose fabricated credential's request failed or drew "
        "neither a refusal nor a success, so it did not establish who was denied",
        "{count} denial expectations held only against a denial that a fabricated "
        "credential received too, or that no fabricated credential was sent to "
        "compare with or whose fabricated credential's request failed or drew "
        "neither a refusal nor a success, so they did not establish who was "
        "denied",
    ),
}


def describe(reason: Mapping[str, Any]) -> str:
    """One clause for a reason, lower-case, to follow a colon in a report.

    A code this Veridor does not know -- a document from a newer one -- is
    named as it is, with its count beside it rather than in front of it.
    """
    code = str(reason.get("code"))
    count = reason.get("count")
    if code in CAPSULE_REASON_TEXT:
        detail = reason.get("detail")
        if isinstance(detail, str) and detail.strip(" ."):
            return f"{CAPSULE_REASON_TEXT[code]}: {detail.strip().rstrip('.')}"
        return CAPSULE_REASON_TEXT[code]
    if code == NOTHING_ANSWERED and reason.get("nothing_graded") is True:
        # Setup steps only: the target may have answered every one, and "not
        # one probe was answered (0 unanswered)" said the opposite.
        return ("the configuration declares nothing to grade (no check, and no "
                "sequence with an assert step), so the run established nothing "
                "about the target")
    counted = isinstance(count, int) and not isinstance(count, bool)
    if counted and code in REASON_COUNTED:
        one, many = REASON_COUNTED[code]
        return (one if count == 1 else many).format(count=count)
    text = REASON_TEXT.get(code, f"reason {code}")
    return f"{text} (count {count})" if counted else text


#: What would make a not-enforced reason move the exit code.
_ENFORCED_BY_FAIL_ON = "--fail-on with any policy other than none"

#: Verdicts that say something about the TARGET. `inconclusive` does not: it
#: says Veridor could not do its job on that probe.
_TARGET_VERDICTS = frozenset({"vulnerable", "unexpected_denial"})

_UNCLEAN_TEARDOWN = frozenset({"failed", "incomplete", "aborted"})


# ---------------------------------------------------------------------------
# The conditions. Each is pure and takes the options as any object carrying
# ``fail_on`` / ``require_complete`` / ``require_clean_teardown`` attributes, so
# an ``argparse.Namespace`` and :class:`Options` both work. The names are the
# ones ``cli.py`` has always used; ``cli`` imports them from here.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Options:
    """The flags the policy reads. Defaults are the CLI's defaults."""

    fail_on: str = DEFAULT_FAIL_ON
    require_complete: bool = False
    require_clean_teardown: bool = False


def _security_findings(findings: Iterable[Mapping[str, Any]]) -> list[Any]:
    """The findings the security gate is entitled to fire on.

    DELIBERATE CHANGE to what `new` and `any` used to do, made with the
    compatibility note above open. They fired on `inconclusive` too, so a rate
    limit or a 5xx failed the build -- measured at 70% of runs against a target
    whose boundary never moved. A gate that fires when nothing was measured is
    not strict, it is wrong, and it is the reason gates get switched off.

    Coverage still cannot fail silently: `--require-complete` turns an
    inconclusive probe into exit 3, the same shape `--require-clean-teardown`
    already uses, and a real finding always wins over it.
    """
    return [
        finding for finding in findings
        if finding.get("verdict") in _TARGET_VERDICTS
    ]


def _confirmed_findings(findings: Iterable[Mapping[str, Any]]) -> list[Any]:
    """Findings about the target whose response actually carried a marker."""
    return [
        finding
        for finding in _security_findings(findings)
        if finding.get("evidence_grade") == "confirmed"
    ]


def _new_findings(result: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    return (result.get("regression") or {}).get("new") or ()


def _policy_findings(policy: str, result: Mapping[str, Any]) -> list[Any]:
    """The findings ``policy`` gates on, each once, in document order.

    ``new``, ``any``, and ``none`` keep their meaning for every finding that is
    about the target. ``confirmed`` gates on proof rather than on novelty: it
    fires only when a response actually carried another identity's marker,
    whether that finding is new, unchanged, or escalated from a weaker grade in
    the baseline.

    ``new+confirmed`` is the union, and the default. ``new`` alone is a set
    difference over finding ids against a file the guide asks you to COMMIT,
    and nothing about that file is verifiable: ids are deterministic and stable
    across runs, so adding twenty characters to `baseline.json` in a pull
    request moves a live `confirmed` cross-tenant leak from `new` to
    `unchanged` and the build goes green. Measured on the demo target: exit 1
    becomes exit 0, with the console still printing "1 vulnerable" above it.

    There is no way to tell that edit from a legitimate triage decision by
    inspecting the baseline -- both are the same bytes -- so the fix cannot live
    in baseline validation. It lives here: a gate whose verdict depends on a
    file inside the diff it is gating is not a gate, and proof of data flow does
    not become acceptable by being old.
    """
    findings = result.get("findings") or ()
    if policy == "none":
        return []
    if policy == "any":
        return _security_findings(findings)
    if policy == "confirmed":
        return _confirmed_findings(findings)
    new = _security_findings(_new_findings(result))
    if policy != "new+confirmed":
        # `new`, and -- as before the move -- anything unrecognised.
        return new
    # new+confirmed: the union, deduplicated on the finding id (the regression
    # diff holds copies of the same findings, keyed by id).
    selected: list[Any] = []
    seen: set[Any] = set()
    for finding in list(new) + _confirmed_findings(findings):
        key = finding.get("id") or id(finding)
        if key in seen:
            continue
        seen.add(key)
        selected.append(finding)
    return selected


def _gate_exit_code(policy: str, result: Mapping[str, Any]) -> int:
    """1 when ``policy`` selects any finding, else 0. See :func:`_policy_findings`."""
    return 1 if _policy_findings(policy, result) else 0


def _answered_probes(result: Mapping[str, Any]) -> int:
    """How many probes the TARGET answered.

    Delegates to :func:`core.probe_answered` rather than restating it. The
    docstring here used to claim the definition had been unified with the one
    the verdict uses; it had not. This module counted any arriving status as an
    answer, so a `500` was an answer for the exit code and not an answer for
    the grade, and a uniformly-5xx target exited `0` while every finding on it
    said the probe established nothing. Importing the predicate is the only
    version of "unified" that stays true.
    """
    return sum(
        1 for probe in result.get("probes") or () if probe_answered(probe)
    )


def _sequence_steps(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every sequence step record in the run, executed or skipped."""
    return [
        step
        for record in result.get("sequences") or ()
        for step in record.get("steps") or ()
    ]


def _assert_steps(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The sequence steps that grade a declaration: role ``assert``.

    A ``setup`` step provisions the state an assert reads. Its answer is a
    precondition, not a measurement of any boundary, so it is never an answer
    for the vacuity rule.
    """
    return [step for step in _sequence_steps(result) if step.get("role") == "assert"]


def _declares_checks(result: Mapping[str, Any]) -> bool:
    """Whether the run declared any check, whether or not a probe was sent.

    ``summary.checks`` is the declaration count. The probe list is not: an
    identity whose session never established has its probes skipped, so a
    checks-only run whose every login drew a 503 has declared checks and an
    empty probe list.
    """
    return bool(result.get("probes")) or bool((result.get("summary") or {}).get("checks"))


def _nothing_graded(result: Mapping[str, Any]) -> bool:
    """No check and no assert step declared: every request was a setup.

    Such a run is vacuous however the target answered, since a setup grades no
    declaration. It said "not one of 1 probe(s) was answered ... check that
    the target is up" about a setup the target had served 200; it now says the
    configuration declares nothing to grade.
    """
    return (
        not _declares_checks(result)
        and bool(_sequence_steps(result))
        and not _assert_steps(result)
    )


def _is_vacuous(result: Mapping[str, Any]) -> bool:
    """True when the run answered nothing, so it established nothing.

    ``result["probes"]`` holds CHECK probes only. A config may declare
    ``checks: []`` beside its sequences, and then this read an empty list and
    could never be true: a sequences-only run against a target that was down,
    or answered 503 to every step, exited 0 with an empty gate. With no checks
    declared the sequence steps are the run's requests, so they decide. A step
    record carries the same ``response``/``error`` shape as a probe; a skipped
    step has no response and is not an answer.

    A check probe that was never sent is not an answer. Asking "were there
    probes" instead of "were there checks" let a checks-only run whose every
    session failed transiently -- logins answered 503, so no probe was
    appended -- find nothing to judge and exit 0 having sent nothing but
    logins, while the same outage written as a sequence exited 3.

    Check probes and sequence steps are judged TOGETHER. The fix above first
    let declared checks decide alone, so a run whose check sessions all drew
    a 503 while a sequence on other identities was answered 200 and 401 exited
    3 and said it "established nothing", though the sequence had measured a
    boundary. Vacuous means nothing was answered anywhere: not one check probe
    and not one sequence step. Unanswered probes beside an answered sequence
    stay inconclusive, disclosed and gated by ``--require-complete``.

    Only ASSERT steps are answers. A setup step grades no declaration, and
    counting any answered step let a run whose check probes all went
    unanswered -- or that had no checks -- and whose sequence's only answered
    request was its setup (the assert drew a 503) exit 0 with an empty gate,
    though not one boundary had been measured.
    """
    if not (_declares_checks(result) or _sequence_steps(result)):
        return False
    return _answered_probes(result) == 0 and not any(
        probe_answered(step) for step in _assert_steps(result)
    )


def _established_nothing(result: Mapping[str, Any]) -> bool:
    """Vacuous AND carrying no finding about the target.

    The second half is not optional. ``result["probes"]`` holds CHECK probes
    only -- sequence findings are appended from a separate engine -- so a config
    whose checks all time out while a sequence step serves another tenant's
    order is vacuous by the first test and has a confirmed cross-tenant read by
    the second. Gating the console sentence on the first half alone printed
    "every entry above is a probe that did not run, not a finding about your
    target" two lines above exactly such a finding, while the exit code -- which
    always tested both halves -- correctly deferred to it. Extracting one
    definition and then using half of it at one of its two call sites is the
    failure this helper exists to make impossible.
    """
    return _is_vacuous(result) and not _security_findings(result.get("findings") or ())


def _unanswered_count(result: Mapping[str, Any]) -> int:
    """The count the "not one probe was answered" sentence has always printed.

    0 when the run declares nothing to grade: no gradable request existed to
    go unanswered, and counting the answered setups said they had not been.
    """
    if _nothing_graded(result):
        return 0
    findings = result.get("findings") or ()
    unanswered = [f for f in findings if f.get("verdict") == "inconclusive"]
    return len(unanswered or (result.get("probes") or _sequence_steps(result)))


def _vacuous_exit_code(options: Any, result: Mapping[str, Any]) -> int:
    """Exit 3 when NOT ONE probe was answered. No flag, by design.

    Taking `inconclusive` out of the security gate opened a hole big enough to
    drive a wrong base URL through: every probe fails, no finding is about the
    target, and the run exits 0 with "0 probes matched" -- a green build that
    measured nothing. That is a stronger overclaim than any false positive this
    session removed, so it does not wait to be opted into.

    Ranked below a real finding and below a coverage error -- exit 2 already
    means "Veridor could not do its job because of your inputs", and a spec that
    will not parse is that. `--fail-on none` still never fails, because
    report-only means report-only.

    Answered means the target RESPONDED, not that the probe matched its
    declaration. Testing `summary.safe` instead made this fire on a run where
    every probe came back 200 -- the checks were inconclusive because a HEAD
    request has no body for the marker oracle, and the message told the
    operator to go and check whether their target was up.
    """
    if not _established_nothing(result):
        return 0
    return 0 if getattr(options, "fail_on", DEFAULT_FAIL_ON) == "none" else 3


def _unauthenticated_identities(result: Mapping[str, Any]) -> list[str]:
    """Identities whose session failed DETERMINISTICALLY, sorted.

    `sequence.is_transient_session_failure` draws the line and records it on
    the finding as ``evidence.session.transient``; a 429 or a 5xx on login
    stays on the transient side and never gates. A missing flag reads as
    transient, which is the direction that does not invent a failure.
    """
    return sorted({
        finding["identity"]
        for finding in result.get("findings") or ()
        if (finding.get("evidence") or {}).get("session", {}).get("state") == "failed"
        and not (finding["evidence"]["session"] or {}).get("transient", True)
    })


def _unauthenticated_identity_exit_code(options: Any, result: Mapping[str, Any]) -> int:
    """Exit 3 when an identity was never authenticated. No flag, by design.

    A mistyped password meant one identity's session never established, every
    probe as that identity reported inconclusive, and the run exited 0 under
    the default policy. The identity that matters most in an authorization
    suite is usually the attacker, and its boundary had not been tested at all.

    The vacuous guard does not catch it: the OTHER identity answered fine, so
    "not one probe was answered" is false. What makes this gateable, where a
    rate limit is not, is that it is DETERMINISTIC -- the target read the
    credential and refused it, and it will refuse identically on the next run.
    The finding's ``evidence.session["transient"]`` flag, set by
    `sequence.is_transient_session_failure`, draws that line.
    """
    blocked = _unauthenticated_identities(result)
    if not blocked or getattr(options, "fail_on", DEFAULT_FAIL_ON) == "none":
        return 0
    return 3


def _unclean_teardowns(result: Mapping[str, Any]) -> list[str]:
    return [
        record["sequence_id"]
        for record in result.get("sequences") or ()
        if record.get("teardown_state") in _UNCLEAN_TEARDOWN
    ]


def _teardown_exit_code(options: Any, result: Mapping[str, Any]) -> int:
    """Exit 3 for unclean cleanup, and only when the operator asked for it.

    Without ``--require-clean-teardown`` a cleanup problem is visible on
    stderr, in the CI annotations, and in the run document, but it does not
    fail the build: a broken cleanup endpoint is an operational problem and
    must not block a security gate.
    """
    if not getattr(options, "require_clean_teardown", False):
        return 0
    return 3 if _unclean_teardowns(result) else 0


def _non_asserting(result: Mapping[str, Any]) -> list[Any]:
    return list(result.get("non_asserting_expectations") or ())


def _inconclusive(result: Mapping[str, Any]) -> list[Any]:
    return [
        finding for finding in result.get("findings") or ()
        if finding.get("verdict") == "inconclusive"
    ]


def _incomplete_exit_code(options: Any, result: Mapping[str, Any]) -> int:
    """Exit 3 when a probe was never answered, and only when asked.

    The counterpart to taking `inconclusive` out of the security gate. A rate
    limit must not fail the build as a security finding -- but a run where
    probes went unanswered has not established that those boundaries hold, and
    a CI job reads an exit code rather than a summary line. A non-asserting
    expectation belongs here for the same reason: neither established that the
    boundary holds.
    """
    if not getattr(options, "require_complete", False):
        return 0
    return 3 if (_non_asserting(result) or _inconclusive(result)) else 0


def _unproven_liveness(result: Mapping[str, Any]) -> list[Any]:
    return list((result.get("liveness") or {}).get("unproven") or ())


def _liveness_exit_code(options: Any, result: Mapping[str, Any]) -> int:
    """Exit 3 for an unverified boundary, and only when asked.

    Gated on ``--require-complete`` rather than fired unconditionally: an
    identity asserted only to be denied and never served anywhere is the
    ORDINARY shape of an authorization suite, so an unconditional exit fired
    on the majority of correct configurations. The fact is disclosed on every
    run regardless; this flag decides only whether it moves the exit code.
    """
    if getattr(options, "fail_on", DEFAULT_FAIL_ON) == "none" or not getattr(
        options, "require_complete", False
    ):
        return 0
    return 3 if _unproven_liveness(result) else 0


# ---------------------------------------------------------------------------
# The stderr lines. Byte-identical to what cli.py printed before the move.
# ---------------------------------------------------------------------------


def _teardown_message(unclean: Sequence[str]) -> str:
    return (
        "veridor: teardown did not complete cleanly for "
        f"{', '.join(unclean)}; the target may hold fixtures this run created"
    )


def _non_asserting_message(count: int) -> str:
    return (
        f"veridor: {count} expectation(s) accept both access and "
        "denial, so they assert nothing about the boundary and their pass "
        "is not evidence. Narrow them to the statuses you require."
    )


def _unanswered_message(count: int) -> str:
    return (
        f"veridor: {count} probe(s) were never answered, so those "
        "boundaries are unverified rather than verified. Re-run when the target "
        "is healthy."
    )


def _withheld_by_configuration(result: Mapping[str, Any]) -> tuple[Counter, int]:
    """(configuration-caused unsent reasons, unanswered requests) of the run.

    Read from the records that decide vacuity -- the check probes when checks
    were declared, the sequence steps otherwise -- so the two counts describe
    the same requests. A sequence step refused for a reflected marker carries
    its own message, so its sequence's abort reason names it.

    A step skipped because an earlier step of its sequence was withheld by the
    configuration counts with that step's reason: it was never sent for the
    same configuration cause. It counted as unanswered and not withheld, so a
    sequences-only run whose first step was withheld got the network advice.
    """
    def configured(entry: Mapping[str, Any], abort_reason: Any) -> str | None:
        reason = CONFIGURATION_UNSENT_ERRORS.get(str(entry.get("error")))
        if reason is None and abort_reason in CONFIGURATION_UNSENT_ERRORS.values():
            reason = abort_reason
        return reason

    records: list[tuple[Mapping[str, Any], str | None]] = []
    if _declares_checks(result):
        records = [(probe, configured(probe, None)) for probe in result.get("probes") or ()]
    else:
        for record in result.get("sequences") or ():
            aborted_at = record.get("aborted_at_step")
            steps = list(record.get("steps") or ())
            # The configuration cause of the abort, if the aborting step was
            # withheld by the configuration; None for a network failure.
            cause = next(
                (
                    configured(step, record.get("abort_reason"))
                    for step in steps
                    if aborted_at is not None and step.get("index") == aborted_at
                    and not probe_answered(step)
                ),
                None,
            )
            for step in steps:
                if aborted_at is not None and step.get("index") == aborted_at:
                    records.append((step, configured(step, record.get("abort_reason"))))
                elif (
                    step.get("state") == "skipped"
                    and isinstance(aborted_at, int)
                    and isinstance(step.get("index"), int)
                    and step["index"] > aborted_at
                ):
                    records.append((step, cause))
                else:
                    records.append((step, configured(step, None)))
    reasons: Counter = Counter()
    unanswered = 0
    for entry, reason in records:
        if probe_answered(entry):
            continue
        unanswered += 1
        if reason:
            reasons[reason] += 1
    return reasons, unanswered


def _skipped_behind_an_answered_step(result: Mapping[str, Any]) -> int:
    """Steps skipped because an earlier step of their sequence was answered
    but did not match its declaration (a setup that drew 200 for a declared
    201, a capture that found nothing).

    Read from the same records as :func:`_withheld_by_configuration`, so with
    checks declared it is 0. These steps were unanswered because the target
    DID answer the step before them; they counted toward the network advice.
    """
    if _declares_checks(result):
        return 0
    skipped = 0
    for record in result.get("sequences") or ():
        aborted_at = record.get("aborted_at_step")
        steps = list(record.get("steps") or ())
        if not isinstance(aborted_at, int) or not any(
            step.get("index") == aborted_at and probe_answered(step) for step in steps
        ):
            continue
        skipped += sum(
            1 for step in steps
            if step.get("state") == "skipped"
            and isinstance(step.get("index"), int) and step["index"] > aborted_at
        )
    return skipped


def _vacuous_message(count: int, result: Mapping[str, Any] | None = None) -> str:
    """"Not one probe was answered" -- and, when the configuration withheld
    them, that this is not a network problem.

    It always ended "Check the target URL, the credentials, and that the
    target is up", including when every probe was withheld before the socket
    for a reason the configuration causes (injection_not_applicable,
    marker_reflection_blocked, credential_slot_interpolation,
    unresolved_reference): nothing was sent and the target was healthy.

    Nor is it a network problem when the target answered and nothing was
    graded: a run of setup steps only, or one whose asserts were skipped
    because the setup before them drew an undeclared status. Both got the
    network advice. A sequences-only run counts its assert steps, as the
    stdout summary does.
    """
    if result is not None and _nothing_graded(result):
        setups = _sequence_steps(result)
        answered = sum(1 for step in setups if probe_answered(step))
        return (
            "veridor: this run declares nothing to grade -- no check, and no "
            "sequence with an assert step -- so it established nothing. It is "
            f"not a pass. The target answered {answered} of {len(setups)} setup "
            "step(s); a setup step provisions state and grades no declaration. "
            "Add an assert step to the sequence, or a check."
            # A setup that went unanswered is still a network question.
            + (" Check the target URL, the credentials, and that the target is up."
               if answered < len(setups) else "")
        )
    unit = "probe(s)"
    if result is not None and not _declares_checks(result):
        unit, count = "assert step(s)", len(_assert_steps(result))
    head = (
        f"veridor: not one of {count} {unit} was answered, so this run "
        "established nothing. It is not a pass."
    )
    network = " Check the target URL, the credentials, and that the target is up."
    reasons, unanswered = (
        _withheld_by_configuration(result) if result is not None else (Counter(), 0)
    )
    stalled = _skipped_behind_an_answered_step(result) if result is not None else 0
    withheld = sum(reasons.values())
    if not withheld and not stalled:
        return head + network
    named = ", ".join(f"{reason} ({n})" for reason, n in sorted(reasons.items()))
    if withheld and withheld == unanswered:
        return (
            head + f" Nothing was sent: the configuration withheld all "
            f"{unanswered} request(s) ({named}). This is not a network problem: "
            "fix the configuration -- each finding's remediation says how."
        )
    text = head + (network if unanswered - withheld - stalled > 0 else "")
    if withheld:
        text += (
            f" {withheld} of the {unanswered} unanswered request(s) were not sent "
            f"because the configuration withheld them ({named}); each finding's "
            "remediation says how to fix that."
        )
    if stalled:
        text += (
            f" {stalled} step(s) were skipped because an earlier step of their "
            "sequence was answered but did not match its declaration, so the "
            "state they depend on was never established; the target did "
            "answer, and each sequence finding names that step and what it drew."
        )
    return text


def _unauthenticated_message(blocked: Sequence[str]) -> str:
    names = ", ".join(quoted(name) for name in blocked)
    return (
        f"veridor: identit{'y' if len(blocked) == 1 else 'ies'} {names} "
        "never authenticated, so no boundary involving "
        f"{'it' if len(blocked) == 1 else 'them'} was tested. This failure is "
        "deterministic: a re-run will fail identically. Check the credentials."
    )


def _liveness_message(unproven: Sequence[Mapping[str, Any]]) -> str:
    names = ", ".join(sorted({quoted(entry["identity"]) for entry in unproven}))
    # Some denials had no sham to compare with -- a write, or no header to
    # shape one on -- and for those "the sham received it too" would be false.
    cause = "a credential Veridor fabricated received too" + (
        ", or that no fabricated credential was sent to compare with"
        if any(str(entry.get("control") or "").startswith("withheld_")
               for entry in unproven)
        else ""
    ) + (
        # Sent, and its own request failed: there was nothing to compare.
        ", or where the fabricated credential's own request failed"
        if any(entry.get("control") == "control_errored" for entry in unproven)
        else ""
    ) + (
        # Answered, but by a parser, a proxy, a limiter or a crash: a 400,
        # 406, 407, 429 or 5xx tells no credential apart.
        ", or where the fabricated credential's answer was neither a refusal "
        "nor a success"
        if any(entry.get("control") == "control_uninformative" for entry in unproven)
        else ""
    )
    # A failed request, or a limiter's or a crash's answer, is the one cause a
    # re-run can change.
    errored = any(entry.get("control") in ("control_errored", "control_uninformative")
                  for entry in unproven)
    # A marker_probe is the remedy only for an identity that does not already
    # have one counting against it. One that logs in again per check, or whose
    # session cookie the target replaced after it was proven, has the
    # marker_probe and needs something else; telling it to add one sent the
    # reader after a fix already in place.
    def scoped(scope: str) -> str:
        return ", ".join(sorted({quoted(entry["identity"]) for entry in unproven
                                 if entry.get("proof_scope") == scope}))

    special = [
        text
        for text in (
            f"for {scoped('login')}, whose session logs in again before every "
            'check and sequence ("reestablish": "check"), a marker_probe proves '
            'only the first login: set "reestablish": "run", or show it served '
            "in the same sequence where an identity with no credential is refused"
            if scoped("login") else "",
            f"for {scoped('cookie_value')}, whose session cookie the target gave "
            "a new value after its login or proof of life, a 2xx sent after the change, "
            "where an identity with no credential or the fabricated credential is "
            "refused, proves it"
            if scoped("cookie_value") else "",
        )
        if text
    ]
    if any(not entry.get("proof_scope") for entry in unproven):
        advice = "Give the identity a marker_probe naming something it should be served"
        if special:
            advice += " (" + "; ".join(special) + ")"
    else:
        advice = "; ".join(special)
        advice = advice[0].upper() + advice[1:]
    return (
        f"veridor: {len(unproven)} expectation(s) were satisfied by a denial that "
        f"{cause} ({names}). Those boundaries "
        "are unverified rather than verified"
        + (
            "; a fabricated-credential request that failed or drew neither a "
            "refusal nor a success may be answered differently on a re-run. "
            if errored
            else ", and this is deterministic -- a re-run reports identically. "
        )
        + advice
        + ", or accept that a target which hides "
        "existence uniformly cannot be measured from outside."
    )


# ---------------------------------------------------------------------------
# The decision.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateDecision:
    """What the gate decided, why, and what it saw but did not gate on."""

    fail_on: str
    require_complete: bool
    require_clean_teardown: bool
    exit_code: int
    #: Conditions that moved, or would have moved, the exit code under these
    #: flags, in precedence order. Empty exactly when ``exit_code`` is 0.
    reasons: tuple[dict[str, Any], ...]
    #: Conditions present in the run that these flags do not gate on. Each
    #: names the flag that would. Reported so a green exit is never silent
    #: about what it did not require.
    not_enforced: tuple[dict[str, Any], ...]
    #: The stderr lines the CLI prints, in order.
    messages: tuple[str, ...]

    def to_document(self) -> dict[str, Any]:
        """The ``gate`` object written into the run document."""
        return {
            "fail_on": self.fail_on,
            "require_complete": self.require_complete,
            "require_clean_teardown": self.require_clean_teardown,
            "exit_code": self.exit_code,
            "reasons": [dict(reason) for reason in self.reasons],
            "not_enforced": [dict(reason) for reason in self.not_enforced],
        }


def _grade_counts(findings: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(str(f.get("evidence_grade", "ungraded")) for f in findings)
    return dict(sorted(counts.items()))


def _reason(code: str, exit_code: int, **detail: Any) -> dict[str, Any]:
    return {"code": code, "exit_code": exit_code, **detail}


def evaluate(
    result: Mapping[str, Any],
    *,
    fail_on: str = DEFAULT_FAIL_ON,
    require_complete: bool = False,
    require_clean_teardown: bool = False,
    coverage_status: int = 0,
) -> GateDecision:
    """Decide the exit code of ``veridor run`` for ``result``.

    ``coverage_status`` is what boundary coverage returned when ``--openapi``
    was given: 0 when it was measured, 2 when it was not. It is an input rather
    than something computed here because coverage reads a specification file.
    """
    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(f"unknown --fail-on policy {quoted(fail_on)}")
    options = Options(fail_on, bool(require_complete), bool(require_clean_teardown))
    reporting_only = fail_on == "none"

    # -- the stderr lines, with the short-circuits _run always had ----------
    # Which lines print is part of the contract, byte for byte: an unclean
    # teardown suppresses the incompleteness lines (the `or` it used to sit
    # in), and a run that established nothing suppresses the identity line.
    # "Not one probe was answered" prints whichever code wins -- it was
    # computed outside the `or` chain precisely so a coverage error could not
    # swallow it -- and the liveness line prints only when nothing ranked
    # above it decided the code.
    messages: list[str] = []
    unclean = _unclean_teardowns(result)
    non_asserting = _non_asserting(result)
    inconclusive = _inconclusive(result)
    teardown_status = _teardown_exit_code(options, result)
    if teardown_status:
        messages.append(_teardown_message(unclean))
    else:
        teardown_status = _incomplete_exit_code(options, result)
        if options.require_complete:
            if non_asserting:
                messages.append(_non_asserting_message(len(non_asserting)))
            if inconclusive:
                messages.append(_unanswered_message(len(inconclusive)))

    nothing = _established_nothing(result)
    if nothing:
        messages.append(_vacuous_message(_unanswered_count(result), result))
    blocked = _unauthenticated_identities(result)
    vacuous_status = _vacuous_exit_code(options, result)
    if not vacuous_status:
        vacuous_status = _unauthenticated_identity_exit_code(options, result)
        if vacuous_status:
            messages.append(_unauthenticated_message(blocked))

    unproven = _unproven_liveness(result)
    if reporting_only:
        # 'none never fails' is the documented contract for the security
        # policy, and a report-only pipeline that also passes --openapi must not
        # start failing the build the moment the spec drifts. The two opt-in
        # flags report operational facts, not security verdicts, so 'none'
        # does not cover them.
        exit_code = teardown_status
    else:
        exit_code = (
            _gate_exit_code(fail_on, result)
            or coverage_status
            or vacuous_status
            or teardown_status
        )
        if not exit_code:
            exit_code = _liveness_exit_code(options, result)
            if exit_code:
                messages.append(_liveness_message(unproven))

    # -- the reasons, every condition, enforced or not ----------------------
    reasons: list[dict[str, Any]] = []
    not_enforced: list[dict[str, Any]] = []

    security = _security_findings(result.get("findings") or ())
    selected = _policy_findings(fail_on, result)
    if selected:
        reasons.append(_reason(
            FINDINGS, 1,
            count=len(selected),
            by_grade=_grade_counts(selected),
            finding_ids=[str(f.get("id")) for f in selected],
        ))
    selected_ids = {f.get("id") for f in selected}
    unselected = [f for f in security if f.get("id") not in selected_ids]
    if unselected:
        not_enforced.append(_reason(
            FINDINGS, 0,
            count=len(unselected),
            by_grade=_grade_counts(unselected),
            finding_ids=[str(f.get("id")) for f in unselected],
            enforced_by=(
                _ENFORCED_BY_FAIL_ON if reporting_only else "--fail-on any"
            ),
        ))

    if coverage_status:
        entry = _reason(COVERAGE_NOT_MEASURED, coverage_status)
        if reporting_only:
            not_enforced.append({**entry, "exit_code": 0,
                                 "enforced_by": _ENFORCED_BY_FAIL_ON})
        else:
            reasons.append(entry)

    if nothing:
        # nothing_graded: the configuration declares no check and no assert
        # step, so the reports say that instead of "not one was answered".
        entry = _reason(NOTHING_ANSWERED, 3, count=_unanswered_count(result),
                        **({"nothing_graded": True} if _nothing_graded(result) else {}))
        if reporting_only:
            not_enforced.append({**entry, "exit_code": 0,
                                 "enforced_by": _ENFORCED_BY_FAIL_ON})
        else:
            reasons.append(entry)

    if blocked:
        entry = _reason(IDENTITY_UNAUTHENTICATED, 3, count=len(blocked),
                        identities=list(blocked))
        if reporting_only:
            not_enforced.append({**entry, "exit_code": 0,
                                 "enforced_by": _ENFORCED_BY_FAIL_ON})
        else:
            reasons.append(entry)

    for code, present, count, detail, flag, enforced in (
        (TEARDOWN_UNCLEAN, bool(unclean), len(unclean),
         {"sequences": list(unclean)}, "--require-clean-teardown",
         options.require_clean_teardown),
        (EXPECTATIONS_NON_ASSERTING, bool(non_asserting), len(non_asserting),
         {}, "--require-complete", options.require_complete),
        (INCONCLUSIVE, bool(inconclusive), len(inconclusive),
         {}, "--require-complete", options.require_complete),
    ):
        if not present:
            continue
        if enforced:
            reasons.append(_reason(code, 3, count=count, **detail))
        else:
            not_enforced.append(_reason(code, 0, count=count, enforced_by=flag,
                                        **detail))

    if unproven:
        identities = sorted({str(entry.get("identity")) for entry in unproven})
        if options.require_complete and not reporting_only:
            reasons.append(_reason(LIVENESS_UNPROVEN, 3, count=len(unproven),
                                   identities=identities))
        else:
            not_enforced.append(_reason(
                LIVENESS_UNPROVEN, 0, count=len(unproven), identities=identities,
                enforced_by=(
                    "--require-complete, with --fail-on other than none"
                    if reporting_only else "--require-complete"
                ),
            ))

    return GateDecision(
        fail_on=fail_on,
        require_complete=options.require_complete,
        require_clean_teardown=options.require_clean_teardown,
        exit_code=exit_code,
        reasons=tuple(reasons),
        not_enforced=tuple(not_enforced),
        messages=tuple(messages),
    )


def capsule_gate(
    verdict: str, reason: str, finding_ids: Sequence[str] = ()
) -> dict[str, Any]:
    """The ``gate`` object ``veridor verify`` writes beside its ``capsule``.

    ``verify`` used to persist the run of the capsule with no gate at all, so
    every report re-derived one with the ``veridor run`` defaults: an
    INCONCLUSIVE verification -- exit 2 -- rendered "Gate passed (exit 0)".
    The exit code here is the one ``verify`` exits with, and the one reason
    names the verdict; NOT_REPRODUCED is exit 0 with no reason, and the
    reports word it from the capsule, never as a pass of the target.
    ``fail_on`` is null: ``verify`` applies no ``--fail-on`` policy.
    """
    exit_code = CAPSULE_EXIT_CODES[verdict]
    reasons: list[dict[str, Any]] = []
    if verdict == "CONFIRMED":
        reasons.append(_reason(CAPSULE_CONFIRMED, exit_code, detail=reason,
                               finding_ids=[str(i) for i in finding_ids]))
    elif verdict == "INCONCLUSIVE":
        reasons.append(_reason(CAPSULE_INCONCLUSIVE, exit_code, detail=reason))
    return {
        "fail_on": None,
        "require_complete": False,
        "require_clean_teardown": False,
        "exit_code": exit_code,
        "reasons": reasons,
        "not_enforced": [],
    }


def non_finding_reasons(gate: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The enforced reasons in a ``gate`` object that are not findings."""
    return [
        reason for reason in gate.get("reasons") or ()
        if reason.get("code") not in FINDING_REASON_CODES
    ]
