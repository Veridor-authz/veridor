"""GitLab Code Quality (``artifacts:reports:codequality``): a JSON array of issues.

The subset of the CodeClimate issue format GitLab reads: ``description``,
``check_name``, ``fingerprint``, ``severity`` (``info``, ``minor``, ``major``,
``critical`` or ``blocker``) and ``location.path`` + ``location.lines.begin``.
``type`` and ``categories`` come from the CodeClimate format and are extra to
those five.

Each issue sits on the configuration line the finding graded, which is where
a reviewer would change the declaration.

========================================  ==========
``vulnerable``, evidence ``confirmed``     critical
``vulnerable``, any other grade            major
``unexpected_denial``                      minor
``inconclusive`` (measured nothing)        info
non-asserting expectation                  info
any other pass disclosure                  info
``veridor.gate``, exit for a non-finding   major
========================================  ==========

A pass disclosure -- a non-asserting expectation, an exclusion licensed by a
marker_probe, a fabricated credential the target served, a request that went
out without a declared form_field or json_field -- is an ``info`` issue each,
because nothing else in this format qualifies a pass; the console prints the
same list (``_common.pass_disclosures``).

The ``veridor.gate`` issue exists because Code Quality has no other way to
say the gate is red or amber for a reason that is not a finding. Fingerprints
are derived from Veridor's own finding fingerprint (or, for the gate, the
reason codes), so an unchanged finding is the same issue across pipelines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from veridor.reports._common import (
    VERDICT_QUALIFIER,
    disclosure_text,
    display_path,
    finding_line,
    findings,
    gate_of,
    non_finding_reasons,
    pass_disclosures,
    reason_sentence,
    stable_digest,
    unique,
)

SEVERITIES: tuple[str, ...] = ("info", "minor", "major", "critical", "blocker")

#: The ``check_name`` of the ``info`` issue each pass disclosure becomes.
DISCLOSURE_CHECK_NAMES: dict[str, str] = {
    "non_asserting_expectations": "VERIDOR-VACUOUS-001",
    "oracle_disclosures": "veridor.unproven_oracle",
    "fabricated_credential_served": "veridor.fabricated_credential_served",
    "injection_disclosures": "veridor.injection_not_applied",
}


def _severity(finding: Mapping[str, Any]) -> str:
    verdict = finding.get("verdict")
    if verdict == "vulnerable":
        return "critical" if finding.get("evidence_grade") == "confirmed" else "major"
    if verdict == "unexpected_denial":
        return "minor"
    return "info"


def build(document: Mapping[str, Any], *, root: Path | None = None) -> list[dict[str, Any]]:
    gate = gate_of(document)
    config = document.get("config")
    config_path = display_path(config, root)
    issues: list[dict[str, Any]] = []
    keys: list[str] = []

    for finding in findings(document):
        verdict = str(finding.get("verdict"))
        text = f"{finding.get('title') or finding.get('rule_id')}: {finding.get('message')}"
        if verdict == "inconclusive":
            text = f"{text} {VERDICT_QUALIFIER['inconclusive']}"
        issues.append({
            "type": "issue",
            "check_name": str(finding.get("rule_id")),
            "description": text,
            "categories": ["Security"],
            "severity": _severity(finding),
            "location": {
                "path": display_path(finding.get("location") or config, root),
                "lines": {"begin": finding_line(finding)},
            },
        })
        keys.append(stable_digest("veridor-codequality/v1", "finding", str(finding.get("id"))))

    for group, where, _heading, entries in pass_disclosures(document):
        for entry in entries:
            if group == "non_asserting_expectations":
                description = f"Expectation asserts nothing: {entry.get('statement')}"
                # Keyed like core._vacuous_fingerprint (check, identity, not
                # the statuses), read defensively: a report must not crash on
                # a key.
                key = ("vacuous", str(entry.get("check_id")), str(entry.get("identity")))
            else:
                description = disclosure_text(group, where, entry)
                key = (group, str(entry.get("source")), str(entry.get(where)),
                       str(entry.get("check_id")), str(entry.get("identity")))
            issues.append({
                "type": "issue",
                "check_name": DISCLOSURE_CHECK_NAMES[group],
                "description": description,
                "categories": ["Bug Risk"],
                "severity": "info",
                "location": {"path": config_path, "lines": {"begin": 1}},
            })
            keys.append(stable_digest("veridor-codequality/v1", *key))

    gating = non_finding_reasons(gate)
    unmeasured = [
        reason for reason in gate.get("not_enforced") or ()
        if reason.get("code") == "nothing_answered"
    ]
    if gating or unmeasured:
        listed = gating or unmeasured
        issues.append({
            "type": "issue",
            "check_name": "veridor.gate",
            "description": (
                f"Veridor gate exit {gate.get('exit_code')}: "
                + "; ".join(reason_sentence(reason) for reason in listed)
                + "."
            ),
            "categories": ["Bug Risk"],
            "severity": "major" if gating else "info",
            "location": {"path": config_path, "lines": {"begin": 1}},
        })
        keys.append(stable_digest(
            "veridor-codequality/v1", "gate",
            *sorted(str(reason.get("code")) for reason in listed),
        ))

    for issue, fingerprint in zip(issues, unique(key[:32] for key in keys)):
        issue["fingerprint"] = fingerprint
    return issues


def render(document: Mapping[str, Any], *, root: Path | None = None) -> str:
    return json.dumps(build(document, root=root), indent=2, ensure_ascii=False) + "\n"
