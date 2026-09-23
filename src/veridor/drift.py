"""Diff two access matrices: authorization regression with nothing declared.

`run` answers "does the boundary hold where you said it should". That is the
stronger claim and it costs the operator a declaration for every check. This
module answers a weaker question that costs nothing: **did anything move?**

    run 1   veridor map ...                      records the matrix. Finds nothing.
    run 2   veridor map ... --baseline veridor/baseline-matrix.json
                                              reports what changed.

Nobody writes a policy. The tool records reality, and a human reviews a diff --
the same bargain snapshot testing makes, and the reason snapshot tests were
adopted at a scale hand-written assertions never reached. The declaration still
exists; it just moves from "write it before" to "accept it after", and accepting
is one command rather than a config file.

WHAT A CHANGE IS, AND IS NOT
----------------------------
A change is an OBSERVATION. Reach that opened may be a feature that shipped this
week; reach that closed may be a broken deploy rather than a fix. Veridor
reports what moved between two runs and does not know which of those it is
looking at. Nothing here is a finding, none of it produces SARIF, and `map`
still exits 0 unless the operator explicitly asks drift to gate.

WHAT IT CANNOT DO
-----------------
Drift is blind to anything that was already true at the first run. An endpoint
that should be admin-only and has been open to everyone since launch never
moves, so it never appears here. That needs a declared expectation or a human
reading the matrix; no amount of diffing substitutes for knowing the intent.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any, Mapping

from veridor import redaction
from veridor.core import ConfigError
from veridor.terminal import quoted

#: The reach value `matrix.py` records when a cell could not be measured. Taken
#: as a literal rather than imported: `matrix` imports nothing from here and the
#: dependency should stay that way, and a test pins the two to the same string.
REACH_UNKNOWN = "unknown"

#: What `map` stamps on the document this module diffs. Guessed wrong once --
#: it is `veridor.matrix`, not `veridor.access_matrix` -- so it is read from the
#: producing module rather than restated here.
MATRIX_KIND = "veridor.matrix"

DRIFT_KIND = "veridor.matrix_drift"
DRIFT_SCHEMA_VERSION = 1

#: What moved. `significant` marks the changes that mean MORE access than
#: before -- the only ones worth failing a build over. Everything else is
#: recorded because a diff that hides half of what moved is not a diff.
REACH_OPENED = "reach_opened"
REACH_CLOSED = "reach_closed"
REACH_APPEARED = "reach_appeared"
MARKER_APPEARED = "marker_appeared"
MARKER_CLEARED = "marker_cleared"
STATUS_CHANGED = "status_changed"
#: One of the two runs could not measure this cell at all -- a 429, a 5xx, a
#: timeout, a transport error. Named separately because the alternative was
#: reporting it as reach that CLOSED, which says the boundary moved when the
#: truth is that nobody looked.
MEASUREMENT_LOST = "measurement_lost"
MEASUREMENT_GAINED = "measurement_gained"
OPERATION_ADDED = "operation_added"
OPERATION_REMOVED = "operation_removed"
IDENTITY_ADDED = "identity_added"
IDENTITY_REMOVED = "identity_removed"

#: More access than the baseline had. These are what `--fail-on-drift opened`
#: gates on.
SIGNIFICANT = frozenset({REACH_OPENED, MARKER_APPEARED})

#: Reported, never gated on -- by ANY policy. These say one of the two runs did
#: not measure a cell, which is a fact about the probe rather than about the
#: target, and `--fail-on-drift any` that fires on a rate limit is a gate
#: somebody switches off. They are surfaced as a COMPARISON QUALITY number
#: instead: a report that saw less than the whole matrix has to say so, or its
#: silence gets read as coverage it does not have.
UNMEASURED = frozenset({MEASUREMENT_LOST, MEASUREMENT_GAINED})

#: `unknown_reason` values that mean the PLAN never probed the cell, as opposed
#: to the target failing to answer it. The distinction decides what a reader is
#: told to do: a rate limit is noise and re-running helps, a mutating method the
#: plan declined to send recurs identically on every run forever, and telling
#: somebody to "re-record against a quiet target" for the second one is advice
#: that cannot work. Literals for the same reason `REACH_UNKNOWN` is one --
#: `matrix` imports nothing from here -- and a test pins these strings to
#: `matrix.UNKNOWN_REASONS`. Enumerated POSITIVELY so that a reason added there
#: later defaults to the loud transient wording rather than being silently
#: called structural.
NOT_PROBED_REASONS: frozenset[str] = frozenset({
    "not_probed",
    "skipped_mutating",
    "skipped_budget",
    "skipped_no_specimen",
    "skipped_ignored",
})

#: How many distinct reasons a warning names before it summarises the rest. The
#: census is unbounded -- five reasons at 20 characters each runs a terminal
#: line past 120 -- and `cli` already caps this way (`_SPECIMEN_ADVICE_LIMIT`).
REASON_DETAIL_LIMIT: int = 4


def _reason_detail(census: dict[str, int], keep: frozenset[str] | None = None) -> str:
    """Render a reason census, largest first, capped and wrapped.

    Wrapped as well as capped: five reasons at twenty characters each is one
    line of 120 even after the cap, and a warning that runs off the terminal is
    a warning nobody finishes reading.
    """
    items = sorted(
        ((reason, count) for reason, count in census.items()
         if keep is None or reason in keep),
        key=lambda item: (-item[1], item[0]),
    )
    shown = items[:REASON_DETAIL_LIMIT]
    text = ", ".join(f"{reason} x{count}" for reason, count in shown)
    if len(items) > len(shown):
        text += f", +{len(items) - len(shown)} more"
    return textwrap.fill(
        f"({text})", width=78, initial_indent="     ", subsequent_indent="      "
    )


def _census_minus(whole: dict[str, int], part: dict[str, int]) -> dict[str, int]:
    """The reasons in `whole` that `part` has not already accounted for.

    Every unmeasured cell contributes exactly one label to the whole census and
    the same label to the blind census when the baseline is the unknown run, so
    subtracting labels leaves precisely the cells the blind warning did not
    name. Without it the second warning re-listed reasons already reported one
    line up, against a count that did not include them.
    """
    return {
        reason: count - part.get(reason, 0)
        for reason, count in whole.items()
        if count - part.get(reason, 0) > 0
    }

CLAIM: dict[str, str] = {
    "measures": "differences between two recorded access matrices for the same target",
    "does_not_measure": (
        "whether any difference is a defect. Reach that opened may be a feature "
        "you shipped, and reach that closed may be a broken deploy rather than a fix"
    ),
    "blind_to": (
        "anything that did not change. An endpoint open to everyone since the "
        "first run never moves, so it never appears here"
    ),
}


class DriftError(ConfigError):
    """A drift comparison could not be made.

    A ConfigError so the CLI reports it as `veridor: ...` and exit 2 like every
    other operator mistake, rather than as a traceback.
    """


def _is_redirect(cell: dict[str, Any]) -> bool:
    status = cell.get("status")
    return (
        isinstance(status, int) and not isinstance(status, bool)
        and 300 <= status <= 399
    )


def observed(cell: dict[str, Any]) -> bool:
    """Whether a matrix cell observed the target at all.

    Two kinds of cell did not, and `matrix.classify_reach` says so for both:
    an ``unknown`` one (a timeout, a 429, a 5xx, or a request the plan never
    sent), and a 3xx. Veridor never follows a redirect, so what is behind one
    is "genuinely unobserved"; the matrix records it as ``indeterminate``.
    Every other ``indeterminate`` cell -- a 400, a 409, a 422 -- reached the
    handler and was answered, and stays observed.

    The exit-3 rules count with this: drift's cells measured in both runs and
    each side's ``measured_cells``, and `map`'s "records nothing" guard. They
    counted every cell that was not ``unknown``, so a 3xx counted. Measured
    against a listener that answered everything with 302, a baseline recorded
    there exited 0 and `--fail-on-drift opened` with it then exited 0 against
    a target serving another tenant's invoice, on a comparison in which no
    request had reached the application in the baseline run.

    It does not change what drift REPORTS: a redirect cell is still compared
    and its changes still listed, and a marker in the current response still
    fires. It changes only whether the cell counts toward "this comparison
    measured something".
    """
    return cell.get("reach") != REACH_UNKNOWN and not _is_redirect(cell)


def _key(cell: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(cell.get("operation")),
        str(cell.get("identity")),
        str(cell.get("specimen") or ""),
    )


def _index(matrix: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    cells = matrix.get("cells")
    if not isinstance(cells, list):
        raise DriftError("matrix document has no 'cells' list; is it a Veridor matrix?")
    for index, cell in enumerate(cells):
        # Checked here rather than left to `_key`'s .get: an AttributeError is
        # not in `main`'s handler list, so a hand-edited baseline exited 1 --
        # "the gate failed" -- with a traceback, when it is an input error.
        if not isinstance(cell, dict):
            raise DriftError(
                f"matrix cell {index} is {type(cell).__name__}, not an object; "
                "is it a Veridor matrix?"
            )
    return {_key(cell): cell for cell in cells}


def _change(kind: str, key: tuple[str, str, str], before: Any, after: Any, note: str) -> dict[str, Any]:
    operation, identity, specimen = key
    entry = {
        "kind": kind,
        "significant": kind in SIGNIFICANT,
        "operation": operation,
        "identity": identity,
        "before": before,
        "after": after,
        "note": note,
    }
    if specimen:
        entry["specimen"] = specimen
    return entry


def compare(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Diff two matrix documents, oldest first.

    Both are scrubbed first (:func:`veridor.redaction.scrub`), so the join
    compares like with like. A baseline read from disk went through
    `core.write_json`, which writes every expanded ``${NAME}`` value back as
    its reference -- keys and join fields included -- while the current matrix
    arrives from memory with the value still in it. A specimen label, an
    identity name or a base URL containing such a value then read differently
    on the two sides: measured with `veridor map`, a label naming an invoice
    whose id came from ``${VERIDOR_INV}`` made 16 cells "exist in only one
    run" and `--fail-on-drift opened` exited 0 against a cross-tenant read.
    Scrubbing only the current side would break the other direction, a
    baseline that still holds the raw value (written before the value moved
    into ``${NAME}``); scrubbing a scrubbed document changes nothing.
    """
    baseline, current = redaction.scrub(baseline), redaction.scrub(current)
    for name, matrix in (("baseline", baseline), ("current", current)):
        if matrix.get("kind") not in (None, MATRIX_KIND):
            raise DriftError(f"{name} is {quoted(matrix.get('kind'))}, not a Veridor access matrix")

    before, after = _index(baseline), _index(current)
    changes: list[dict[str, Any]] = []
    #: Cells at least one run could not measure. Counted whether or not that
    #: produced a change, because the question it answers is how much of the
    #: grid this comparison could speak about at all.
    uncomparable = 0
    #: Cells the BASELINE could not measure. A subset of `uncomparable`, kept
    #: apart because it is the direction that hides regressions rather than
    #: inventing them.
    blind = 0
    #: The structural halves of the two counts above: cells no run was ever
    #: going to measure. Kept separately rather than subtracted at render time
    #: because the two get opposite advice, and one of them gets none.
    uncomparable_not_probed = 0
    blind_not_probed = 0
    #: Cells both runs answered where at least one answer was a redirect. Not
    #: unmeasured -- the rules below still compare them, and a marker in the
    #: current response still fires -- but not measured either: nothing behind
    #: an unfollowed redirect was seen. They never count toward
    #: `measured_in_both_cells`. See :func:`observed`.
    redirected = 0
    #: Cells the BASELINE answered with a redirect that this run SERVES. Not
    #: `reach_opened`, so `--fail-on-drift opened` does not count them: a 3xx
    #: is unobserved, and counting it would fail the gate on every
    #: trailing-slash or http->https fix. But an anonymous 302 to /login that
    #: became a 200 may be an authentication bypass in a session app, and it
    #: exited 0 under `opened` with "0 that mean more access" and nothing else
    #: to say why. Counted so every report that renders it says so.
    redirect_served = 0
    #: One entry per cell, so the census sums to the count it explains. Two,
    #: because the blind block and the unmeasured block describe different
    #: cells and a shared census names reasons in a warning they belong to.
    unmeasured_reasons: dict[str, int] = {}
    blind_reasons: dict[str, int] = {}

    base_ops = {key[0] for key in before}
    now_ops = {key[0] for key in after}
    for operation in sorted(now_ops - base_ops):
        changes.append(_change(OPERATION_ADDED, (operation, "", ""), None, "present",
                               "this operation was not in the baseline inventory"))
    for operation in sorted(base_ops - now_ops):
        changes.append(_change(OPERATION_REMOVED, (operation, "", ""), "present", None,
                               "this operation is no longer in the inventory; it may "
                               "have been removed, renamed, or simply not probed"))

    base_ids = {key[1] for key in before}
    now_ids = {key[1] for key in after}
    for identity in sorted(now_ids - base_ids):
        changes.append(_change(IDENTITY_ADDED, ("", identity, ""), None, "present",
                               "this identity was not probed for the baseline, so "
                               "none of its cells are comparable"))
    for identity in sorted(base_ids - now_ids):
        changes.append(_change(IDENTITY_REMOVED, ("", identity, ""), "present", None,
                               "this identity was not probed this time"))

    for key in sorted(before.keys() & after.keys()):
        was, now = before[key], after[key]
        was_reach, now_reach = was.get("reach"), now.get("reach")

        # A cell nobody could measure is not a cell whose access changed, and
        # the two must not share a vocabulary. Measured against a target with a
        # FIXED boundary and realistic transients, treating `unknown` as a
        # state produced reach_closed on every rate limit -- "this identity was
        # served here and is not now. That may be a fix, or a feature that
        # broke" -- about a 429. Everything below this branch compares two
        # observations; this branch is for when there is only one.
        if REACH_UNKNOWN in (was_reach, now_reach):
            uncomparable += 1
            # ONE label per cell, not one per run. A cell unknown in both runs
            # for two different reasons is still one cell that could not be
            # compared, and a census summing to more than the count it explains
            # is the same misattribution this partition exists to end. The
            # baseline's reason wins: if the baseline never measured the cell,
            # a quiet current run does not make it comparable.
            reason = str(
                (was if was_reach == REACH_UNKNOWN else now).get("unknown_reason") or ""
            )
            label = reason or "unrecorded"
            unmeasured_reasons[label] = unmeasured_reasons.get(label, 0) + 1
            # An empty reason -- an older matrix, or one built by hand -- stays
            # on the transient side, which is the wording this always printed.
            if reason in NOT_PROBED_REASONS:
                uncomparable_not_probed += 1
            if was_reach == REACH_UNKNOWN:
                blind_reasons[label] = blind_reasons.get(label, 0) + 1
                if reason in NOT_PROBED_REASONS:
                    blind_not_probed += 1
                # The BASELINE never measured this cell, which is worse than
                # noise: every later comparison here is unknown -> something,
                # so a real regression can only ever be reported as
                # `measurement_gained` and never as more access. Measured
                # against a noisy target, a baseline recorded during one bad
                # minute missed a genuine boundary opening on 8 runs out of 8
                # while reporting nothing significant. Silent under-detection
                # is the one failure a gate must never have, so the count is
                # carried out and rendered above everything else.
                blind += 1
            if was_reach == now_reach:
                # NEITHER run measured it. There is no difference to report --
                # a 429 in one run and a timeout in the other is two absences,
                # not a change. Left unguarded this reached the status
                # comparison below and reported "the status code changed
                # without changing whether the identity was served", about two
                # requests that were never answered.
                continue
            lost = now_reach == REACH_UNKNOWN
            changes.append(_change(
                MEASUREMENT_LOST if lost else MEASUREMENT_GAINED,
                key, was_reach, now_reach,
                ("this run could not measure this cell -- a rate limit, a server "
                 "error, a timeout, or a proxy that answered 407 before the target "
                 "saw the request. Nothing follows about access: the boundary "
                 "may be exactly where it was")
                if lost else
                ("the baseline could not measure this cell, so there is nothing "
                 "to compare this run against")))
            continue

        if _is_redirect(was) or _is_redirect(now):
            redirected += 1

        if was_reach != now_reach:
            if now_reach == "reached" and was_reach == "refused":
                changes.append(_change(
                    REACH_OPENED, key, was_reach, now_reach,
                    "this identity was refused here and is now served. That is more "
                    "access than the baseline recorded; whether it is intended is "
                    "not something Veridor can tell you"))
            elif now_reach == "reached" and _is_redirect(was):
                redirect_served += 1
                changes.append(_change(
                    REACH_APPEARED, key, was_reach, now_reach,
                    f"the baseline was answered with a redirect ({was.get('status')}) "
                    "and this identity is now served here. Veridor does not follow "
                    "redirects, so whether the redirect was a denial -- a login "
                    "wall -- is unknown. --fail-on-drift opened does not count "
                    "this; --fail-on-drift any does"))
            elif now_reach == "reached":
                changes.append(_change(
                    REACH_APPEARED, key, was_reach, now_reach,
                    "this identity is now served here, but the baseline never "
                    "measured it, so nothing is known about what changed"))
            elif was_reach == "reached":
                changes.append(_change(
                    REACH_CLOSED, key, was_reach, now_reach,
                    "this identity was served here and is not now. That may be a "
                    "fix, or a feature that broke"))
            else:
                changes.append(_change(
                    STATUS_CHANGED, key, was_reach, now_reach,
                    "the measurement changed between two states that are neither "
                    "reached nor refused"))

        was_marker, now_marker = was.get("marker_scan"), now.get("marker_scan")
        owner = now.get("marker_owner") or was.get("marker_owner")
        # The marker in its OWN owner's response is the owner reading their own
        # data. It can never be evidence that anything crossed a boundary, so
        # its coming and going is ordering noise -- on a collection whose sort
        # is "recently updated", whether page one still holds the marked record
        # has nothing to do with authorization. `blastradius.marker_reach`
        # already skips `owner == identity`; this rule re-derived the signal
        # and did not carry the guard over, which measured out as a false
        # `marker_appeared` -- a SIGNIFICANT change, so a failed build -- on up
        # to 75% of runs against a target whose boundary never moved.
        if owner and owner == key[1]:
            was_marker = now_marker = None

        if was_marker != now_marker and now_marker == "present":
            changes.append(_change(
                MARKER_APPEARED, key, was_marker, now_marker,
                f"this response now carries {quoted(owner)}'s planted marker and did not "
                "before. That is a measured fact about data flow, and it is the "
                "strongest signal in this report"))
        elif was_marker == "present" and now_marker != "present":
            changes.append(_change(
                MARKER_CLEARED, key, was_marker, now_marker,
                "this response no longer carries another identity's marker"))

        if was_reach == now_reach and was.get("status") != now.get("status"):
            changes.append(_change(
                STATUS_CHANGED, key, was.get("status"), now.get("status"),
                "the status code changed without changing whether the identity "
                "was served"))

    counts: dict[str, int] = {}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1

    comparable = len(before.keys() & after.keys())
    # Cells that exist in ONE matrix only. Whole operations and whole identities
    # are diffed above, but a cell keyed by a specimen that was re-seeded --
    # `seed-a` becomes `seed-b` -- matches neither, so it was dropped with no
    # change, no census, and "Nothing moved" printed over it. Measured: a
    # baseline refusal at 403 and a current 200 carrying the victim's marker
    # produced changes=[], comparable=0, exit 0 under every policy. The
    # denominator is the UNION, because a report that speaks about 49 of 100
    # baseline cells has not seen 98% of the grid.
    incomparable = len(before.keys() ^ after.keys())
    return {
        "kind": DRIFT_KIND,
        "schema_version": DRIFT_SCHEMA_VERSION,
        "claim": CLAIM,
        "baseline": {
            "target": (baseline.get("target") or {}).get("base_url"),
            "cells": len(before),
            "measured_cells": _measured(before),
        },
        "current": {
            "target": (current.get("target") or {}).get("base_url"),
            "cells": len(after),
            "measured_cells": _measured(after),
        },
        "comparable_cells": comparable,
        # The cells this comparison could actually speak about: in both runs
        # and measured in both. Zero means no policy could have fired -- every
        # comparison was `unknown -> something`, a redirect nobody followed,
        # or nothing lined up -- so a gate over it has not passed. See
        # :func:`exit_code` and :func:`observed`.
        "measured_in_both_cells": comparable - uncomparable - redirected,
        # Answered in both runs, and a redirect in at least one of them.
        "redirect_cells": redirected,
        # A redirect in the baseline, served now. Reported, not gated by
        # `opened`; see `redirect_served` above.
        "redirect_now_served_cells": redirect_served,
        # How much of the grid this comparison could actually speak about. A
        # drift report is only as strong as the cells both runs measured, and
        # without this a run that lost half its matrix to rate limiting reads
        # exactly like a quiet one.
        "incomparable_cells": incomparable,
        "unmeasured_cells": uncomparable,
        "unmeasured_cells_not_probed": uncomparable_not_probed,
        "unmeasured_reasons": dict(sorted(unmeasured_reasons.items())),
        "blind_cells": blind,
        "blind_cells_not_probed": blind_not_probed,
        "blind_reasons": dict(sorted(blind_reasons.items())),
        "counts": counts,
        "significant": sum(1 for change in changes if change["significant"]),
        "changes": changes,
    }


def _measured(index: dict[tuple[str, str, str], dict[str, Any]]) -> int:
    """How many of one run's cells observed the target at all."""
    return sum(1 for cell in index.values() if observed(cell))


def measured_in_both(drift: dict[str, Any]) -> int:
    """Cells present in both runs and measured in both.

    Read from the document when it carries the count, and derived from the two
    counts every drift document has carried otherwise, so an older report
    answers the same way.
    """
    recorded = drift.get("measured_in_both_cells")
    if isinstance(recorded, int) and not isinstance(recorded, bool):
        return recorded
    return (
        int(drift.get("comparable_cells") or 0)
        - int(drift.get("unmeasured_cells") or 0)
        - int(drift.get("redirect_cells") or 0)
    )


def load_matrix(path: Path) -> dict[str, Any]:
    """Read a matrix. A directory resolves to its most recent one.

    Pointing at the directory is the ergonomic form -- `map` writes one matrix
    per run into `.veridor/matrix/`, and a CI job should not have to know the
    id of last week's.

    NOTE for callers: resolve this BEFORE the current run writes its own matrix
    into the same directory, or the newest file is this run and the comparison
    is a run against itself -- which reports no drift and looks like good news.
    """
    if path.is_dir():
        # By modification time, with the name only as a tie-break. Matrix files
        # are named `<timestamp>-<hex>.json`, and the timestamp has one-second
        # resolution -- so two runs inside the same second sort by a random hex
        # suffix, and "the most recent" becomes a coin flip. Rare in CI, routine
        # in a test harness, and silently wrong in both.
        candidates = sorted(path.glob("*.json"), key=lambda p: (p.stat().st_mtime, p.name))
        if not candidates:
            raise DriftError(
                f"no matrix JSON in {path}. Run `map` once without --baseline "
                "to record one."
            )
        path = candidates[-1]
    try:
        matrix = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DriftError(f"cannot read matrix {path}: {error}") from error
    if not isinstance(matrix, dict):
        raise DriftError(f"matrix {path} must contain an object")
    return matrix


def redirect_served_message(count: int) -> str:
    """The sentence every channel prints for :data:`redirect_now_served_cells`."""
    return (
        f"{count} cell(s) answered with a redirect in the baseline are SERVED "
        "now. --fail-on-drift opened does not count them: Veridor does not "
        "follow redirects, so it never saw whether the redirect was a denial. A "
        "login redirect that became a success may be an authentication bypass. "
        "--fail-on-drift any gates on them."
    )


def headline_served(drift: Mapping[str, Any], *, code: bool = False) -> str:
    """The headline's clause for :data:`redirect_now_served_cells`, or "".

    Said in the headline itself, beside "N that mean more access", because the
    redirect cells are not in that count: "1 change(s), 0 that mean more
    access" headed a report whose only change was a login redirect that became
    a 200, with the line saying so further down."""
    served = drift.get("redirect_now_served_cells") or 0
    if not served:
        return ""
    flag = "`--fail-on-drift opened`" if code else "--fail-on-drift opened"
    return f", {served} baseline redirect(s) now served ({flag} does not count them)"


def render(drift: dict[str, Any]) -> str:
    counts = drift["counts"]
    lines = [
        f"Access-matrix drift — {len(drift['changes'])} change(s), "
        f"{drift['significant']} that mean more access{headline_served(drift)}",
        f"  baseline {drift['baseline']['cells']} cells · "
        f"current {drift['current']['cells']} cells · "
        f"{drift['comparable_cells']} comparable",
    ]
    comparable = drift["comparable_cells"] or 1
    unmeasured = drift.get("unmeasured_cells", 0)
    redirected = drift.get("redirect_cells", 0)
    #: Cells in both runs that were NOT measured in both: unknown in one, or a
    #: redirect in one. The share line counts from this, not from `unmeasured`
    #: alone, or it printed "drift saw 100%" under "NOT ONE CELL WAS MEASURED".
    unseen = drift["comparable_cells"] - max(measured_in_both(drift), 0)
    not_probed = drift.get("unmeasured_cells_not_probed", 0)
    incomparable = drift.get("incomparable_cells", 0)
    nothing_measured = drift["comparable_cells"] and measured_in_both(drift) <= 0
    if nothing_measured:
        # First of all. Every other warning below describes part of the grid;
        # this one says there was no grid, and a gate over it cannot fail.
        baseline_measured = drift["baseline"].get("measured_cells")
        current_measured = drift["current"].get("measured_cells")
        sides = (
            f"\n     The baseline measured {baseline_measured} of its "
            f"{drift['baseline']['cells']} cell(s); this run measured "
            f"{current_measured} of {drift['current']['cells']}."
            if baseline_measured is not None and current_measured is not None
            else ""
        )
        lines.append(
            f"  !! NOT ONE CELL WAS MEASURED IN BOTH RUNS ({drift['comparable_cells']} "
            "appear in both).\n     No policy can fire on this comparison: "
            "under --fail-on-drift it exits 3,\n     not 0. It is not a pass."
            f"{sides}"
        )
    if incomparable:
        lines.append(
            f"  !! {incomparable} cell(s) EXIST IN ONLY ONE OF THE TWO RUNS and were "
            "not compared\n     at all. A specimen that was re-seeded changes the "
            "cell's identity, so the old\n     cell and the new one are different "
            "cells and neither is a change. Re-record\n     the baseline against the "
            "specimens this run uses, or drift is silent there."
        )
    if unseen:
        # Said once, in the header, rather than inside whichever warning fires.
        # Attached to a warning it read as that warning's share: one rate-limited
        # cell beside eight the plan never sent rendered "1 of 9 could not be
        # measured ... drift saw 0% of the grid", which blames the rate limit for
        # a loss it did not cause.
        # Floored, and never 100 while anything went unmeasured. `round` sent
        # 4 unmeasured cells in 1,000 to "drift saw 100% of the grid", one line
        # above a warning saying four cells could not be measured. Understating
        # coverage is the safe direction; overstating it is the direction this
        # module exists to prevent.
        seen = min(99, 100 * (comparable - unseen) // comparable)
        lines.append(
            f"  drift saw {seen}% of the grid: "
            f"{comparable - unseen} of {comparable} comparable cell(s)\n"
            "     were measured in BOTH runs. A quiet report below is quiet about "
            "the rest\n     of it, not evidence about it."
        )
    if redirected:
        lines.append(
            f"  !! {redirected} of {comparable} comparable cell(s) were answered with a "
            "redirect in at least\n     one run. Veridor does not follow redirects, so "
            "nothing behind them was\n     observed: their changes are listed below, but "
            "they do not count as\n     measured. A target that redirects every request "
            "is usually behind a\n     login wall, an SSO proxy or a maintenance page, or "
            "was given http://\n     for an https-only host."
        )
    served = drift.get("redirect_now_served_cells", 0)
    if served:
        lines.append(f"  !! {redirect_served_message(served)}")
    blind = drift.get("blind_cells", 0)
    blind_not_probed = drift.get("blind_cells_not_probed", 0)
    if blind - blind_not_probed:
        # First, above everything, and phrased as under-detection rather than
        # as a data-quality note. This is the state in which the gate reports
        # nothing significant BECAUSE IT COULD NOT LOOK, and a reader who takes
        # that for "all clear" has been misled by a green build.
        lines.append(
            f"  !! THE BASELINE NEVER MEASURED {blind - blind_not_probed} of "
            f"{comparable} cell(s). Drift is\n     BLIND there: a regression on "
            "those cells cannot be reported as more\n     access, only as "
            "'measurement_gained'. Re-record the baseline against\n     a quiet "
            "target before trusting a clean report."
        )
    if blind_not_probed:
        # The same blindness, and the opposite advice. These cells were not
        # lost, they were never sent: re-recording produces byte-identical
        # output forever, so the only move is to widen the plan or to read that
        # part of the matrix as out of scope. The census is keyed on the
        # BASELINE cell, because naming a reason drawn from the current run in
        # a warning about the baseline is the misattribution one line up.
        detail = _reason_detail(drift.get("blind_reasons") or {}, NOT_PROBED_REASONS)
        lines.append(
            f"  !! {blind_not_probed} of {comparable} cell(s) WERE NEVER PROBED, by "
            "this plan's own rules\n"
            f"{detail}\n"
            "     Drift is blind there and will stay blind: re-running changes "
            "nothing,\n     because nothing failed. Widen the plan -- a specimen, an\n"
            "     --allow-mutating-method, a dropped matrix.ignore -- or read that\n"
            "     half of the matrix as out of scope for drift."
        )
    if unmeasured - not_probed:
        # Above the changes, not below them. This number decides how much the
        # rest of the report is worth: a run that lost a third of its grid to
        # rate limiting and reports nothing significant has not established
        # that nothing significant happened.
        lines.append(
            f"  !! {unmeasured - not_probed} of {comparable} comparable cell(s) "
            "could not be measured in\n     one of the two runs — a rate limit, a "
            "server error, a timeout,\n     or a proxy that answered 407 before the "
            "target saw the request."
        )
    if not_probed - blind_not_probed:
        detail = _reason_detail(
            _census_minus(
                drift.get("unmeasured_reasons") or {}, drift.get("blind_reasons") or {}
            ),
            NOT_PROBED_REASONS,
        )
        lines.append(
            f"  !! {not_probed - blind_not_probed} further comparable cell(s) were "
            f"never probed\n{detail}\n     That is structural, not noise: "
            "the same cells every run, and no\n     target behaviour will change it."
        )
    if drift["baseline"]["target"] != drift["current"]["target"]:
        lines.append(
            f"  !! different targets: baseline {drift['baseline']['target']} vs "
            f"current {drift['current']['target']}. A diff across two targets "
            "compares deployments, not changes."
        )
    lines.append("")

    if not drift["changes"] and (
        drift.get("incomparable_cells") or not drift["comparable_cells"]
        or nothing_measured
    ):
        # The reassuring sentence, withheld. With every cell re-keyed by a new
        # specimen there are zero changes AND zero comparable cells, and
        # "Nothing moved" over that is the strongest false statement this tool
        # can make: it reads as a clean run when nothing was compared at all.
        why = (
            "  This is not 'nothing moved'. A cell neither run measured cannot "
            "change, so a grid\n  nobody measured produces no changes for the same "
            "reason an empty run does."
            if nothing_measured and not drift.get("incomparable_cells") else
            "  This is not 'nothing moved'. Two matrices whose cells do not line "
            "up produce\n  no changes for the same reason an empty run does. Check "
            "that both runs used\n  the same specimens, identities and "
            "specification."
        )
        lines += [
            f"  Nothing to compare. {drift['comparable_cells']} cell(s) appear in "
            f"both runs, {max(measured_in_both(drift), 0)} measured in both.",
            "",
            why,
            "",
        ]
    elif not drift["changes"]:
        lines += [
            "  Nothing moved. Every comparable cell reads the same as the baseline.",
            "",
            "  That is not a clean bill of health: drift is blind to anything that "
            "did not change,",
            "  including an endpoint that has been open to everyone since the first run.",
        ]
        return "\n".join(lines)

    significant = [c for c in drift["changes"] if c["significant"]]
    other = [c for c in drift["changes"] if not c["significant"]]
    for heading, group in (("MORE ACCESS THAN THE BASELINE", significant),
                           ("OTHER CHANGES", other)):
        if not group:
            continue
        lines.append(f"  {heading}")
        for change in group:
            where = " ".join(part for part in (change["operation"], change["identity"]) if part)
            if change.get("specimen"):
                # Without this, drift on one object reads as drift on the whole
                # operation -- and the two are not the same claim.
                where += f" [specimen {change['specimen']}]"
            lines.append(f"    [{change['kind']}] {where}")
            lines.append(f"        {change['before']} -> {change['after']}")
            lines += textwrap.wrap(change["note"], width=76,
                                   initial_indent="        ",
                                   subsequent_indent="        ")
        lines.append("")

    lines += [
        "  A change is an observation, not a verdict. Reach that opened may be a "
        "feature you shipped;",
        "  reach that closed may be a broken deploy rather than a fix. Veridor "
        "reports what moved.",
        "",
        f"  Accept these as the new baseline by keeping this run's matrix: "
        f"{', '.join(f'{k}={v}' for k, v in sorted(counts.items()))}",
    ]
    return "\n".join(lines)


#: The exit code of a gate that compared nothing it could measure. The same
#: code `run` uses when not one probe was answered, and `map` when its own grid
#: measured nothing: the gate did not fail, and it did not pass either.
EXIT_NOTHING_COMPARED = 3


def exit_code(drift: dict[str, Any], policy: str) -> int:
    """Drift never fails a build unless the operator asked it to.

    No policy gates on :data:`UNMEASURED`. Against a target with a fixed
    boundary and realistic transients, those alone made ``any`` fire on 100% of
    runs -- a gate nobody keeps. They are a coverage signal, not a difference:
    the cell was not measured, so there is nothing to differ.

    Which is exactly why a gating policy over a comparison with NO cell
    measured in both runs is :data:`EXIT_NOTHING_COMPARED` and not 0. Every
    comparison it made was ``unknown -> something``, so neither policy could
    have fired whatever the target did. Measured: a baseline recorded while the
    target was down, compared with a target serving another tenant's invoice,
    exited 0 under ``opened`` and ``any``. A difference (1) still outranks it.
    A comparison where some cells were measured in both runs and others were
    not is partial blindness, which is reported and not gated.
    """
    if policy == "none":
        return 0
    if policy == "opened":
        moved = bool(drift["significant"])
    elif policy == "any":
        moved = any(change["kind"] not in UNMEASURED for change in drift["changes"])
    else:
        raise DriftError(f"unknown drift policy {quoted(policy)}")
    if moved:
        return 1
    return EXIT_NOTHING_COMPARED if measured_in_both(drift) <= 0 else 0
