"""Markdown: a GitHub job summary (``$GITHUB_STEP_SUMMARY``) or a merge request note.

The verdict line is the gate's exit code, taken from the same ``gate`` object
the CLI exits with -- never recomputed from the findings, which cannot see a
run that answered nothing. It is followed by the counts, every gate reason
(and every condition present but not gated, with the flag that would gate it),
the two scope sentences exactly as the console prints them, every pass
disclosure the console prints (what the matched probes do not establish), and
the findings.

Two rules no edit may break, and a test holds both:

* nothing written here uses ``coverage.BANNED_CLAIM_WORDS``. A green gate is
  "Gate passed (exit 0)" and the ``Pass:`` sentence under it says what that
  does not establish;
* the output stays under :data:`MAX_BYTES` (GitHub's 1 MiB step-summary
  limit). Findings past the limit are cut at a row boundary with a visible
  note naming how many were left out -- never silently.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Mapping, Sequence

from veridor import gate as gate_policy
from veridor.drift import headline_served, measured_in_both
from veridor.reports._common import (
    TARGET_VERDICTS,
    display_path,
    finding_line,
    findings,
    gate_of,
    pass_disclosures,
    reason_sentence,
    scope_sentences,
)

#: GitHub rejects a step summary over 1 MiB.
MAX_BYTES: int = 1024 * 1024

#: Longest message a findings-table cell carries before it is cut.
CELL_LIMIT: int = 600

#: Entries listed per pass-disclosure group before the rest are counted.
MAX_LISTED_DISCLOSURES: int = 20

_FLAG_NOTE = (
    "{remaining} more {noun} not shown: this summary stops at {limit} bytes, "
    "under GitHub's 1 MiB step-summary limit. {where}"
)


def cell(value: Any, limit: int = CELL_LIMIT) -> str:
    """Text safe inside a table cell: no HTML, no markup, no row breaks."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    text = html.escape(text, quote=False)
    text = text.replace("\\", "\\\\")
    for char in "`*_[]|#~":
        text = text.replace(char, "\\" + char)
    return text.replace("\n", "<br>")


def _code(value: Any) -> str:
    text = str(value)
    if "`" in text or "\n" in text or "|" in text:
        return cell(text)
    return f"`{text}`"


def _size(lines: Sequence[str]) -> int:
    return len(("\n".join(lines) + "\n").encode("utf-8"))


def _fit(
    head: list[str], rows: list[str], *, noun: str, where: str, max_bytes: int
) -> str:
    """``head`` then as many ``rows`` as fit under ``max_bytes``, then a note."""
    if max_bytes < 4096:
        raise ValueError("a Markdown report needs at least 4096 bytes")
    out = list(head)
    budget = max_bytes - 512  # the truncation note and its line breaks
    used = _size(out)
    shown = 0
    for row in rows:
        cost = len((row + "\n").encode("utf-8"))
        if used + cost > budget:
            break
        out.append(row)
        used += cost
        shown += 1
    remaining = len(rows) - shown
    if remaining:
        out += ["", "_" + _FLAG_NOTE.format(
            remaining=remaining, noun=noun, limit=max_bytes, where=where) + "_"]
    if _size(out) <= max_bytes:
        return "\n".join(out) + "\n"
    # The head alone is over budget (a pathological reason list). Cut whole
    # lines, keep a visible marker, never exceed the limit.
    marker = ["", f"_Truncated: this summary stops at {max_bytes} bytes._"]
    while out and _size(out + marker) > max_bytes:
        out.pop()
    return "\n".join(out + marker) + "\n"


def _capsule_verdict(gate: Mapping[str, Any], capsule: Mapping[str, Any]) -> str:
    """The verdict line of a capsule verification (``veridor verify``).

    It used to be the ``veridor run`` verdict re-derived from the findings, so
    an INCONCLUSIVE verification read "Gate passed (exit 0)" over a command
    that had exited 2. The capsule answers whether one claim reproduced, so it
    is said in those words, and NOT_REPRODUCED is never worded as a pass: the
    adjudication's own sentence, which says what it does not establish,
    follows it.
    """
    verdict = capsule.get("verdict")
    code = gate.get("exit_code")
    reason = cell(str(capsule.get("reason") or "").strip().rstrip("."))
    if verdict == "CONFIRMED":
        return (f"**Capsule CONFIRMED (exit {code}):** the claim reproduced on this "
                f"target: {reason}.")
    if verdict == "NOT_REPRODUCED":
        return (f"**Capsule NOT\\_REPRODUCED (exit {code}):** the claim did not "
                f"reproduce here: {reason}.")
    return (f"**Capsule INCONCLUSIVE (exit {code}):** the claim was neither "
            f"reproduced nor ruled out: {reason}. This is not a pass.")


def _verdict(gate: Mapping[str, Any]) -> str:
    code = gate.get("exit_code")
    capsule = gate.get("capsule")
    if isinstance(capsule, Mapping):
        return _capsule_verdict(gate, capsule)
    reasons = list(gate.get("reasons") or ())
    lead = cell(reason_sentence(reasons[0])) if reasons else ""
    quiet = list(gate.get("not_enforced") or ())
    if code == 0 and any(r.get("code") == gate_policy.NOTHING_ANSWERED for r in quiet):
        # Exit 0 only because the policy is report-only. Saying "passed" over a
        # run that measured nothing is the overclaim this tool exists to refuse.
        return (
            "**Gate exit 0, and nothing was measured.** Not one probe was "
            "answered, so this run established nothing about the target; the "
            "policy below does not gate on that. This is not a pass."
        )
    if code == 0 and quiet:
        listed = (
            "1 condition it does not gate on is" if len(quiet) == 1
            else f"{len(quiet)} conditions it does not gate on are"
        )
        return (
            "**Gate passed (exit 0).** Nothing this policy gates on was present; "
            f"{listed} listed below."
        )
    if code == 0:
        return "**Gate passed (exit 0).** Nothing this policy gates on was present."
    if code == 1:
        return f"**Gate failed (exit 1):** {lead}."
    if code == 2:
        return f"**Gate failed (exit 2):** {lead}."
    if code == 3:
        return (
            "**Gate incomplete (exit 3):** no finding failed the gate, but "
            f"something it requires went unmeasured: {lead}. This is not a pass."
        )
    return f"**Gate exit {code}.**"


def _policy(gate: Mapping[str, Any]) -> str:
    capsule = gate.get("capsule")
    if isinstance(capsule, Mapping):
        # `verify` takes no --fail-on; naming one would describe a policy
        # that was never applied.
        return (
            f"Capsule verification of check {_code(capsule.get('check_id'))}: "
            f"{_code('veridor verify')} exits 1 for CONFIRMED, 0 for "
            "NOT\\_REPRODUCED and 2 for INCONCLUSIVE."
        )
    flags = [f"--fail-on {gate.get('fail_on')}"]
    if gate.get("require_complete"):
        flags.append("--require-complete")
    if gate.get("require_clean_teardown"):
        flags.append("--require-clean-teardown")
    return "Policy: " + " ".join(_code(flag) for flag in flags) + "."


def _counts(document: Mapping[str, Any]) -> list[str]:
    summary = document.get("summary") or {}
    every = findings(document)

    def value(key: str, fallback: int) -> Any:
        found = summary.get(key)
        return found if isinstance(found, int) else fallback

    probes = value("probes", len(document.get("probes") or ()))
    row = [
        probes,
        value("safe", max(0, probes - len(every))),
        value("vulnerable", sum(f.get("verdict") == "vulnerable" for f in every)),
        value("unexpected_denial",
              sum(f.get("verdict") == "unexpected_denial" for f in every)),
        value("inconclusive", sum(f.get("verdict") == "inconclusive" for f in every)),
        value("new", len((document.get("regression") or {}).get("new") or ())),
        value("unchanged", len((document.get("regression") or {}).get("unchanged") or ())),
        value("resolved", len((document.get("regression") or {}).get("resolved") or ())),
    ]
    lines = [
        "| Probes | Matched their declaration | Vulnerable | Unexpected denial "
        "| Inconclusive | New | Unchanged | Resolved |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        "| " + " | ".join(str(item) for item in row) + " |",
        "",
        f"Evidence: {value('confirmed', 0)} confirmed, {value('suspected', 0)} "
        f"suspected, {value('ungraded', 0)} ungraded.",
    ]
    if "sequences" in summary:
        lines.append(
            f"Sequences: {summary.get('sequences', 0)} executed, "
            f"{summary.get('sequence_steps_matched', 0)}/"
            f"{summary.get('sequence_steps', 0)} steps matched their declaration, "
            f"{summary.get('sequences_aborted', 0)} aborted, "
            f"{summary.get('teardown_failures', 0)} teardown failure(s)."
        )
    return lines


def _reasons(gate: Mapping[str, Any]) -> list[str]:
    lines = ["#### Gate reasons", ""]
    reasons = list(gate.get("reasons") or ())
    quiet = list(gate.get("not_enforced") or ())
    for reason in reasons:
        lines.append(
            f"- {_code(reason.get('code'))} (exit {reason.get('exit_code')}): "
            f"{cell(reason_sentence(reason))}."
        )
    if quiet:
        if reasons:
            lines.append("")
        lines.append("Present, and not gated under this policy:")
        lines.append("")
        for reason in quiet:
            lines.append(
                f"- {_code(reason.get('code'))}: {cell(reason_sentence(reason))}. "
                f"{cell(reason.get('enforced_by'))} would gate on it."
            )
    if not reasons and not quiet:
        lines.append("None: nothing the gate reads was present in this run.")
    return lines


def _pass_disclosures(document: Mapping[str, Any]) -> list[str]:
    """What the matched probes do not establish, grouped and worded as the
    console prints it. The summary said "Gate passed" over a probe that went
    out without its declared CSRF field, or an exclusion a marker_probe
    licensed elsewhere, with nothing to qualify it."""
    groups = pass_disclosures(document)
    if not groups:
        return []
    lines = ["#### What the matched probes do not establish", ""]
    for _group, where, heading, entries in groups:
        lines += [cell(heading.format(count=len(entries))) + ":", ""]
        for entry in entries[:MAX_LISTED_DISCLOSURES]:
            place = entry.get(where) if entry.get(where) is not None else entry.get("check_id")
            lines.append(
                f"- {_code(place)} / {_code(entry.get('identity'))}: "
                f"{cell(entry.get('statement'), limit=2000)}"
            )
        remaining = len(entries) - MAX_LISTED_DISCLOSURES
        if remaining > 0:
            lines.append(
                f"- _{remaining} more not shown; every one is in the run JSON "
                "and the JUnit, Code Quality and GitLab SAST reports._"
            )
        lines.append("")
    return lines


def render(
    document: Mapping[str, Any],
    *,
    root: Path | None = None,
    max_bytes: int = MAX_BYTES,
) -> str:
    gate = gate_of(document)
    declaration_scope, pass_scope = scope_sentences()
    target = document.get("target")
    if isinstance(target, Mapping):
        target = target.get("base_url")
    head = [
        f"## Veridor run {_code(document.get('run_id'))}",
        "",
        _verdict(gate),
        _policy(gate),
    ]
    if not gate.get("recorded"):
        head += [
            "",
            "> This run document records no gate decision, so the verdict above "
            "was re-derived with the CLI defaults "
            f"({_code('--fail-on ' + gate_policy.DEFAULT_FAIL_ON)}). The job may "
            "have used other flags; its own exit code decides.",
        ]
    head += [
        "",
        f"Target: {_code(target)}. Config: "
        f"{_code(display_path(document.get('config'), root))}.",
        "",
    ]
    head += _counts(document)
    head += [""] + _reasons(gate)
    head += [
        "",
        f"> Scope: {declaration_scope}",
        ">",
        f"> Pass: {pass_scope}",
        "",
    ]
    head += _pass_disclosures(document)

    every = findings(document)
    gating = {
        str(identifier)
        for reason in gate.get("reasons") or ()
        for identifier in reason.get("finding_ids") or ()
    }
    ordered = sorted(
        every,
        key=lambda f: (
            f.get("verdict") not in TARGET_VERDICTS,
            str(f.get("id")) not in gating,
        ),
    )
    head.append(f"#### Findings ({len(every)})")
    head.append("")
    if not every:
        head.append("No findings.")
        return _fit(head, [], noun="finding(s)", where="", max_bytes=max_bytes)
    head += [
        "| Verdict | Grade | Gates | Check | Identity | Rule | Where | Message |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    rows = []
    for finding in ordered:
        where = f"{display_path(finding.get('location') or document.get('config'), root)}:{finding_line(finding)}"
        check = str(finding.get("check_id"))
        if isinstance(finding.get("step_index"), int):
            check += f" step {finding['step_index']}"
        rows.append("| " + " | ".join((
            cell(finding.get("verdict")),
            cell(finding.get("evidence_grade", "")),
            "yes" if str(finding.get("id")) in gating else "",
            cell(check),
            cell(finding.get("identity")),
            cell(finding.get("rule_id")),
            cell(where),
            cell(finding.get("message")),
        )) + " |")
    return _fit(
        head, rows, noun="finding(s)",
        where="Every finding is in the run JSON and in the SARIF and JUnit reports.",
        max_bytes=max_bytes,
    )


def _number(value: Any) -> Any:
    """A count as the drift report prints it: the integer, or, for anything
    else, its text escaped like a table cell. ``load_drift`` refuses a count
    that is not an integer; this is for a caller that renders without it. A
    string in ``redirect_now_served_cells`` went into the bold headline as
    raw HTML and a link."""
    return value if isinstance(value, int) and not isinstance(value, bool) else cell(value)


def render_drift(document: Mapping[str, Any], *, max_bytes: int = MAX_BYTES) -> str:
    """A drift report as Markdown. Drift is never a finding, and this says so."""
    claim = document.get("claim") or {}
    changes = [c for c in document.get("changes") or () if isinstance(c, Mapping)]
    significant = [c for c in changes if c.get("significant")]
    other = [c for c in changes if not c.get("significant")]
    baseline = document.get("baseline") or {}
    current = document.get("current") or {}
    comparable = _number(document.get("comparable_cells", 0))
    served = _number(document.get("redirect_now_served_cells"))
    head = [
        "## Veridor access-matrix drift",
        "",
        f"**{len(changes)} change(s), {len(significant)} that mean more access "
        f"than the baseline"
        f"{headline_served({'redirect_now_served_cells': served}, code=True)}.** "
        "A change is an observation, not a finding: reach "
        "that opened may be a feature you shipped, and reach that closed may be "
        "a deploy that went wrong rather than a fix.",
        "",
        "This document does not record the `--fail-on-drift` policy or the exit "
        "code; the job's exit code is the gate.",
        "",
        "| Baseline cells | Current cells | Comparable | In one run only "
        "| Unmeasured in either run | Never measured by the baseline |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {_number(baseline.get('cells', 0))} | {_number(current.get('cells', 0))} "
        f"| {comparable} | {_number(document.get('incomparable_cells', 0))} "
        f"| {_number(document.get('unmeasured_cells', 0))} "
        f"| {_number(document.get('blind_cells', 0))} |",
        "",
    ]
    nothing_measured = bool(comparable) and measured_in_both(dict(document)) <= 0
    if nothing_measured:
        head += [
            f"**Not one cell was measured in both runs** ({comparable} appear in "
            "both). No drift policy can fire on this comparison, so under "
            "`--fail-on-drift` Veridor exits 3 rather than 0. It is not a pass.",
            "",
        ]
    if not changes and (document.get("incomparable_cells") or not comparable):
        head += [
            "Nothing to compare: the two matrices share "
            f"{comparable} cell(s). This is not \"nothing moved\"; check that both "
            "runs used the same specimens, identities and specification.",
            "",
        ]
    elif not changes and nothing_measured:
        head += [
            "Nothing to compare: neither run measured a cell the other did. This "
            "is not \"nothing moved\".",
            "",
        ]
    elif not changes:
        head += [
            "Nothing moved among the comparable cells. Drift cannot see anything "
            "that did not change, including an endpoint open to everyone since "
            "the first run.",
            "",
        ]
    if document.get("blind_cells"):
        head += [
            f"The baseline never measured {_number(document['blind_cells'])} cell(s); drift "
            "cannot report more access there.",
            "",
        ]
    if document.get("redirect_cells"):
        head += [
            f"{_number(document['redirect_cells'])} cell(s) were answered with a redirect in "
            "at least one run. Veridor does not follow redirects, so nothing behind "
            "them was observed and they do not count as measured.",
            "",
        ]
    if served:
        head += [
            f"{served} cell(s) answered with a "
            "redirect in the baseline are served now. `--fail-on-drift opened` "
            "does not count them: Veridor does not follow redirects, so it never "
            "saw whether the redirect was a denial. A login redirect that became "
            "a success may be an authentication bypass. `--fail-on-drift any` "
            "gates on them.",
            "",
        ]
    if baseline.get("target") != current.get("target"):
        head += [
            f"Different targets: baseline {_code(baseline.get('target'))}, current "
            f"{_code(current.get('target'))}. This compares two deployments.",
            "",
        ]
    # `does_not_measure` is said in the bold line above, in words held to
    # blastradius.BANNED_CANDIDATE_WORDS; the document's own sentence is not.
    for key, label in (("measures", "Measures"), ("blind_to", "Blind to")):
        if claim.get(key):
            head.append(f"> {label}: {cell(claim[key], limit=2000)}")
            head.append(">")
    if head[-1] == ">":
        head[-1] = ""
    counts = document.get("counts") or {}
    if counts:
        head.append(
            "Counts: " + ", ".join(
                f"{_code(kind)} {_number(count)}" for kind, count in sorted(counts.items())
            ) + "."
        )
        head.append("")

    rows: list[str] = []
    table = [
        "| Change | Operation | Identity | Specimen | Before | After | Note |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, group in (("More access than the baseline", significant),
                         ("Other changes", other)):
        if not group:
            continue
        rows += ["", f"#### {label} ({len(group)})", ""] + table
        for change in group:
            rows.append("| " + " | ".join((
                cell(change.get("kind")),
                cell(change.get("operation")),
                cell(change.get("identity")),
                cell(change.get("specimen", "")),
                cell(change.get("before")),
                cell(change.get("after")),
                cell(change.get("note")),
            )) + " |")
    return _fit(
        head, rows, noun="line(s) of the change table",
        where="Every change is in the drift JSON.",
        max_bytes=max_bytes,
    )
