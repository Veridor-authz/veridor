"""JUnit XML: the one format GitLab, Jenkins, Azure DevOps and CodeBuild all read.

One test case per thing Veridor measured, so a green report shows the
denominator it actually covered:

* one per check probe (a check x an identity), named ``<check> as <identity>``;
* one per sequence step, named ``<sequence> step <n> (<role>) as <identity>``;
* one named ``veridor.gate`` for the gate decision itself.

A case fails, errors, or passes like this:

``<failure>``
    A finding about the target -- ``vulnerable`` or ``unexpected_denial`` --
    with its message and remediation. A sequence finding lands on its step
    (the old converter filed a proven cross-tenant write as an ``<error>`` on
    a case it made up, because steps were never test cases).
``<error>``
    ``inconclusive``, a step that was never executed, or any other outcome
    that measured nothing. NOT ``<skipped>``: every one of these UIs reads a
    skip as "deliberately not run, all fine", and not-measured is the state
    this tool refuses to launder into a pass.
``veridor.gate``
    Fails whenever the gate's exit code is non-zero, listing every reason. This
    is what carries a non-finding exit -- nothing answered, an identity that
    never logged in, an unclean teardown, an unproven denial -- which no probe
    case can express. It passes only on exit 0.

A finding that matches no probe or step is never dropped: it gets its own case,
``... (no probe record)``, failed or errored by its verdict. Counts on the
``testsuite`` and ``testsuites`` elements are computed from the cases written.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping, Sequence

from veridor.reports._common import (
    PASS_DISCLOSURE_LABELS,
    TARGET_VERDICTS,
    VERDICT_QUALIFIER,
    disclosure_text,
    duration_seconds,
    findings,
    gate_of,
    is_int,
    parse_time,
    pass_disclosures,
    reason_sentence,
    scope_sentences,
    xml_text,
)
from veridor.terminal import quoted

_GATE_CASE = "veridor.gate"


def _case(parent: ET.Element, classname: str, name: str, seconds: float = 0.0) -> ET.Element:
    return ET.SubElement(
        parent,
        "testcase",
        {"classname": xml_text(classname), "name": xml_text(name),
         "time": f"{max(0.0, seconds):.3f}"},
    )


def _body(entries: Sequence[Mapping[str, Any]]) -> str:
    parts = []
    for finding in entries:
        verdict = str(finding.get("verdict"))
        grade = finding.get("evidence_grade")
        head = f"[{verdict}{'' if grade in (None, 'n/a', 'ungraded') else f', {grade}'}] "
        head += f"{finding.get('rule_id')} {finding.get('id')}"
        lines = [head, str(finding.get("message") or "")]
        qualifier = VERDICT_QUALIFIER.get(verdict)
        if qualifier:
            lines.append(qualifier)
        if finding.get("remediation"):
            lines.append(str(finding["remediation"]))
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def _attach(case: ET.Element, entries: Sequence[Mapping[str, Any]]) -> str:
    """Put ONE outcome element on ``case``. Returns failure, error or pass."""
    if not entries:
        return "pass"
    target = [f for f in entries if f.get("verdict") in TARGET_VERDICTS]
    lead = target[0] if target else entries[0]
    tag = "failure" if target else "error"
    ET.SubElement(
        case,
        tag,
        {
            "type": xml_text(lead.get("rule_id") or "VERIDOR"),
            "message": xml_text(lead.get("title") or lead.get("message") or lead.get("verdict")),
        },
    ).text = xml_text(_body(entries))
    return tag


def _probe_seconds(probe: Mapping[str, Any]) -> float:
    duration = (probe.get("response") or {}).get("duration_ms")
    return duration / 1000.0 if isinstance(duration, (int, float)) and not isinstance(duration, bool) else 0.0


def _disclosures(
    document: Mapping[str, Any],
) -> tuple[dict[tuple[str, str], list[str]], dict[tuple[str, int], list[str]], list[str]]:
    """The facts that qualify a PASS: per (check, identity) probe case, per
    (sequence, step index) step case, and the rest, which go on the
    ``veridor.gate`` case.

    Every pass disclosure the console prints is here (``pass_disclosures``),
    with the denials liveness left unproven. One that names no case written
    -- a teardown or marker-probe request, a served fabricated credential, an
    entry whose probe has no record -- is put on the gate case rather than
    dropped: JUnit had read only non-asserting expectations and unproven
    denials, so a probe that went out without its declared CSRF field passed
    here unqualified while the console said otherwise.
    """
    probes = {
        (str(probe.get("check_id")), str(probe.get("identity")))
        for probe in document.get("probes") or ()
    }
    steps: dict[tuple[str, str], tuple[str, int]] = {}
    for record in document.get("sequences") or ():
        sequence_id = str(record.get("sequence_id"))
        for step in record.get("steps") or ():
            if isinstance(step, Mapping) and is_int(step.get("index")):
                # The label core._injection_disclosures writes in `where`.
                label = f"sequence {quoted(sequence_id)} step {step.get('index')}"
                steps[(label, str(step.get("as")))] = (sequence_id, step.get("index"))
    on_probe: dict[tuple[str, str], list[str]] = {}
    on_step: dict[tuple[str, int], list[str]] = {}
    rest: list[str] = []

    def place(key: tuple[str, str], note: str, line: str) -> None:
        if key in probes:
            on_probe.setdefault(key, []).append(note)
        else:
            rest.append(line)

    for group, where, _heading, entries in pass_disclosures(document):
        label = PASS_DISCLOSURE_LABELS[group]
        for entry in entries:
            note = f"{label}: {entry.get('statement')}"
            line = disclosure_text(group, where, entry)
            if group == "injection_disclosures" and entry.get("source") != "check":
                step = steps.get((str(entry.get("where")), str(entry.get("identity"))))
                if entry.get("source") == "sequence_step" and step is not None:
                    on_step.setdefault(step, []).append(note)
                else:
                    rest.append(line)
                continue
            place((str(entry.get("check_id")), str(entry.get("identity"))), note, line)
    for entry in (document.get("liveness") or {}).get("unproven") or ():
        if not isinstance(entry, Mapping):
            continue
        note = f"Unproven denial: {entry.get('statement')}"
        # A sequence step's entry carries its sequence id in check_id; keyed
        # like a check's it matched no case, or a check sharing that id.
        if "sequence_id" in entry and is_int(entry.get("step_index")):
            on_step.setdefault(
                (str(entry.get("sequence_id")), entry["step_index"]), []
            ).append(note)
            continue
        check, identity = str(entry.get("check_id")), str(entry.get("identity"))
        place((check, identity), note,
              f"Unproven denial ({check} / {identity}): {entry.get('statement')}")
    return on_probe, on_step, rest


def render(document: Mapping[str, Any], *, root: Path | None = None) -> str:
    del root
    gate = gate_of(document)
    declaration_scope, pass_scope = scope_sentences()

    by_probe: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    by_step: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    order: list[Mapping[str, Any]] = findings(document)
    for finding in order:
        if is_int(finding.get("step_index")):
            by_step.setdefault(
                (str(finding.get("check_id")), finding["step_index"]), []
            ).append(finding)
        else:
            by_probe.setdefault(
                (str(finding.get("check_id")), str(finding.get("identity"))), []
            ).append(finding)

    suite = ET.Element("testsuite")
    outcomes: list[str] = []
    placed: set[int] = set()
    notes, step_notes, unplaced = _disclosures(document)

    for probe in document.get("probes") or ():
        key = (str(probe.get("check_id")), str(probe.get("identity")))
        case = _case(suite, f"veridor.{key[0]}", f"{key[0]} as {key[1]}", _probe_seconds(probe))
        entries = [f for f in by_probe.get(key, ()) if id(f) not in placed]
        placed.update(id(f) for f in entries)
        outcomes.append(_attach(case, entries))
        if key in notes:
            ET.SubElement(case, "system-out").text = xml_text("\n".join(notes[key]))

    for record in document.get("sequences") or ():
        sequence_id = str(record.get("sequence_id"))
        aborted_at = record.get("aborted_at_step")
        for step in record.get("steps") or ():
            if not isinstance(step, Mapping):
                continue
            index = step.get("index")
            case = _case(
                suite,
                f"veridor.{sequence_id}",
                f"{sequence_id} step {index} ({step.get('role')}) as {step.get('as')}",
            )
            entries = [
                f for f in by_step.get((sequence_id, index), ()) if id(f) not in placed
            ] if is_int(index) else []
            placed.update(id(f) for f in entries)
            state = str(step.get("state"))
            if entries:
                outcomes.append(_attach(case, entries))
            elif state == "matched":
                outcomes.append("pass")
            else:
                detail = (
                    f"Not executed: the sequence was aborted at step {aborted_at}, so "
                    "this step measured nothing."
                    if state.startswith("skipped")
                    else f"Step state {quoted(state)}: this step measured nothing."
                )
                ET.SubElement(
                    case, "error",
                    {"type": xml_text(f"step_{state}"), "message": xml_text(detail)},
                ).text = xml_text(detail)
                outcomes.append("error")
            # After the outcome element, as on a probe case: the JUnit schema
            # puts system-out last.
            if is_int(index) and (sequence_id, index) in step_notes:
                ET.SubElement(case, "system-out").text = xml_text(
                    "\n".join(step_notes[(sequence_id, index)]))

    # Never drop a finding: anything not placed on a probe or a step gets a case.
    for finding in order:
        if id(finding) in placed:
            continue
        placed.add(id(finding))
        check_id, identity = str(finding.get("check_id")), str(finding.get("identity"))
        step = finding.get("step_index")
        name = f"{check_id} as {identity}" + (f" step {step}" if is_int(step) else "")
        case = _case(suite, f"veridor.{check_id}", f"{name} (no probe record)")
        outcomes.append(_attach(case, [finding]))

    # The gate itself.
    case = _case(suite, _GATE_CASE, _GATE_CASE)
    exit_code = gate.get("exit_code")
    reasons = list(gate.get("reasons") or ())
    lines = [
        f"Veridor gate exit {exit_code} under --fail-on {gate.get('fail_on')}"
        + (" --require-complete" if gate.get("require_complete") else "")
        + (" --require-clean-teardown" if gate.get("require_clean_teardown") else "")
        + "."
    ]
    if not gate.get("recorded"):
        lines.append(
            "This run document records no gate decision; this one was re-derived "
            "with the CLI defaults, and the job may have run with other flags."
        )
    lines += [f"Gated: {reason_sentence(reason)}" for reason in reasons]
    lines += [
        f"Not gated ({reason.get('enforced_by')} would gate on it): {reason_sentence(reason)}"
        for reason in gate.get("not_enforced") or ()
    ]
    lines += unplaced
    if exit_code:
        ET.SubElement(
            case,
            "failure",
            {
                "type": xml_text(f"exit-{exit_code}"),
                "message": xml_text(
                    f"Veridor gate exit {exit_code}: "
                    + "; ".join(reason_sentence(reason) for reason in reasons)
                ),
            },
        ).text = xml_text("\n".join(lines))
        outcomes.append("failure")
    else:
        ET.SubElement(case, "system-out").text = xml_text("\n".join(lines + [pass_scope]))
        outcomes.append("pass")

    tests = len(outcomes)
    failures = outcomes.count("failure")
    errors = outcomes.count("error")
    seconds = f"{duration_seconds(document):.3f}"
    started = parse_time(document.get("started_at"))
    suite.attrib.update({
        "name": "veridor",
        "tests": str(tests),
        "failures": str(failures),
        "errors": str(errors),
        "skipped": "0",
        "time": seconds,
    })
    if started is not None:
        suite.set("timestamp", started.strftime("%Y-%m-%dT%H:%M:%S"))
    target = document.get("target")
    if isinstance(target, Mapping):
        target = target.get("base_url")
    properties = ET.Element("properties")
    for name, value in (
        ("veridor.run_id", document.get("run_id")),
        ("veridor.schema_version", document.get("schema_version", 1)),
        ("veridor.status", document.get("status")),
        ("veridor.target", target),
        ("veridor.gate.exit_code", exit_code),
        ("veridor.gate.fail_on", gate.get("fail_on")),
        ("veridor.gate.recorded", "true" if gate.get("recorded") else "false"),
        ("veridor.gate.reasons", ",".join(str(r.get("code")) for r in reasons)),
        ("veridor.scope", declaration_scope),
        ("veridor.pass_scope", pass_scope),
    ):
        ET.SubElement(properties, "property", {"name": name, "value": xml_text(value)})
    suite.insert(0, properties)

    root_element = ET.Element(
        "testsuites",
        {"name": "veridor", "tests": str(tests), "failures": str(failures),
         "errors": str(errors), "skipped": "0", "time": seconds},
    )
    root_element.append(suite)
    ET.indent(root_element, space="  ")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        + ET.tostring(root_element, encoding="unicode")
        + "\n"
    )
