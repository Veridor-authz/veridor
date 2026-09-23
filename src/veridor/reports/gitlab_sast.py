"""GitLab security report (``artifacts:reports:sast``), schema 15.2.5.

Written against GitLab's published ``sast-report-format.json`` whose
``self.version`` is ``15.2.5`` (gitlab-org/security-products/
security-report-schemas). The repository's tests check the structure with the
standard library only, because the runtime and the suite take no third-party
dependency; validation against the schema itself was done with ``jsonschema``
when this module was written and is not re-run on every commit.

What becomes a GitLab vulnerability, and what does not:

* ``vulnerable`` -> severity ``High``. ``unexpected_denial`` -> ``Info``: the
  target refused something the declaration said it would serve, which is a
  disagreement between the two, not a data flow. Nothing is ``Critical``, for
  the reason SARIF caps ``security-severity`` below 9.0: every finding is
  graded against a declaration Veridor cannot audit.
* ``inconclusive`` findings are NOT vulnerabilities. A probe that measured
  nothing entered the Vulnerability Report as severity ``Unknown`` under the
  old converter, where it could trip an approval policy on a rate limit.
  They are counted in ``scan.messages`` instead.
* When the gate is non-zero for a reason that is not a finding -- nothing
  answered, an identity that never logged in, an unclean teardown, an
  incomplete measurement -- ``scan.status`` is ``failure`` and every reason is
  a ``scan.messages`` entry. A run that answered nothing is ``failure`` under
  any policy, because the scan did not happen.

* A pass disclosure -- a non-asserting expectation, an exclusion licensed by
  a marker_probe, a fabricated credential the target served, a request that
  went out without a declared form_field or json_field -- is an ``info``
  ``scan.messages`` entry each, the list the console prints. It is not a
  vulnerability and does not change ``scan.status``.

Vulnerability ids are UUIDs derived from Veridor's finding fingerprint alone,
so the same finding keeps the same id across pipelines.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from veridor import gate as gate_policy
from veridor.reports._common import (
    VERDICT_QUALIFIER,
    disclosure_text,
    display_path,
    finding_line,
    gate_of,
    is_int,
    non_finding_reasons,
    parse_time,
    pass_disclosures,
    reason_sentence,
    rules_by_id,
    scope_sentences,
    stable_uuid,
    target_findings,
    unique,
    version,
)

#: The schema version this report conforms to. ``self.version`` of the schema.
SCHEMA_VERSION = "15.2.5"

SEVERITY: dict[str, str] = {"vulnerable": "High", "unexpected_denial": "Info"}

_NAME_MAX = 255
_DESCRIPTION_MAX = 1_048_576
_SOLUTION_MAX = 7000


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = " [truncated]"
    return text[: limit - len(marker)] + marker


def _gitlab_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _details(finding: Mapping[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") or {}
    request = evidence.get("request") or {}
    fields: list[tuple[str, str, Any]] = [
        ("verdict", "Verdict", finding.get("verdict")),
        ("evidence_grade", "Evidence grade", finding.get("evidence_grade")),
        ("identity", "Identity", finding.get("identity")),
        ("check", "Check", finding.get("check_id")),
        ("finding_id", "Veridor finding id", finding.get("id")),
        ("expected_statuses", "Declared statuses", evidence.get("expected_statuses")),
        ("actual_status", "Observed status", evidence.get("actual_status")),
        ("request", "Request",
         " ".join(str(part) for part in (request.get("method"), request.get("url")) if part)
         or None),
    ]
    if is_int(finding.get("step_index")):
        fields.append(("step_index", "Sequence step", finding["step_index"]))
    return {
        key: {"name": name, "type": "text",
              "value": value if isinstance(value, str) else json.dumps(value)}
        for key, name, value in fields
        if value not in (None, "", [])
    }


def build(document: Mapping[str, Any], *, root: Path | None = None,
          now: datetime | None = None) -> dict[str, Any]:
    """The report as a dict. :func:`render` serialises it."""
    gate = gate_of(document)
    rules = rules_by_id(document)
    declaration_scope, _ = scope_sentences()
    config = document.get("config")
    selected = target_findings(document)
    ids = unique(stable_uuid(str(f.get("id"))) for f in selected)

    vulnerabilities = []
    for vulnerability_id, finding in zip(ids, selected):
        rule_id = str(finding.get("rule_id"))
        rule = rules.get(rule_id) or {}
        name = (rule.get("shortDescription") or {}).get("text") or rule_id
        check = f"{finding.get('check_id')}/{finding.get('identity')}"
        if is_int(finding.get("step_index")):
            check += f"/step-{finding['step_index']}"
        line = finding_line(finding)
        description = "\n\n".join(
            part for part in (
                str(finding.get("title") or ""),
                str(finding.get("message") or ""),
                VERDICT_QUALIFIER.get(str(finding.get("verdict")), ""),
                declaration_scope,
            ) if part
        )
        vulnerabilities.append({
            "id": vulnerability_id,
            "name": _clip(str(name), _NAME_MAX),
            "description": _clip(description, _DESCRIPTION_MAX),
            "severity": SEVERITY[str(finding.get("verdict"))],
            "solution": _clip(str(finding.get("remediation") or ""), _SOLUTION_MAX),
            "identifiers": [
                {"type": "veridor_rule_id", "name": rule_id, "value": rule_id},
                {
                    "type": "veridor_check",
                    "name": str(finding.get("check_name") or finding.get("check_id")),
                    "value": check,
                },
                {
                    "type": "veridor_finding_id",
                    "name": f"Veridor finding {finding.get('id')}",
                    "value": str(finding.get("id")),
                },
            ],
            "location": {
                "file": display_path(finding.get("location") or config, root),
                "start_line": line,
                "end_line": line,
            },
            "details": _details(finding),
        })

    exit_code = gate.get("exit_code")
    messages: list[dict[str, str]] = []
    if not gate.get("recorded"):
        messages.append({"level": "info", "value": (
            "This run document records no gate decision; the one below was "
            "re-derived with the CLI defaults (--fail-on "
            f"{gate_policy.DEFAULT_FAIL_ON}), and the job may have used other flags."
        )})
    for reason in gate.get("reasons") or ():
        level = "info" if reason.get("code") in gate_policy.FINDING_REASON_CODES else "warn"
        messages.append({"level": level, "value": (
            f"Veridor gate exit {exit_code}: {reason_sentence(reason)}."
        )})
    for reason in gate.get("not_enforced") or ():
        messages.append({"level": "info", "value": (
            f"Not gated ({reason.get('enforced_by')} would gate on it): "
            f"{reason_sentence(reason)}."
        )})
    # What a pass does not establish, as the console prints it. Not a
    # vulnerability -- nothing here is a finding -- and not a reason for
    # scan.status: failure, which is the gate's to decide.
    for group, where, _heading, entries in pass_disclosures(document):
        for entry in entries:
            messages.append({"level": "info", "value": disclosure_text(group, where, entry)})
    messages.append({"level": "info", "value": declaration_scope})

    unmeasured = any(
        reason.get("code") == gate_policy.NOTHING_ANSWERED
        for reason in list(gate.get("reasons") or ()) + list(gate.get("not_enforced") or ())
    )
    status = "failure" if non_finding_reasons(gate) or unmeasured else "success"

    started = parse_time(document.get("started_at"))
    ended = parse_time(document.get("completed_at"))
    if started is None or ended is None:
        messages.append({"level": "warn", "value": (
            "The run document carries no usable started_at/completed_at, so the "
            "scan times below are the time this report was rendered."
        )})
        fallback = now or datetime.now(UTC)
        started = started or fallback
        ended = ended or fallback

    tool = {
        "id": "veridor",
        "name": "Veridor",
        "version": version(),
        "vendor": {"name": "Veridor"},
    }
    return {
        "version": SCHEMA_VERSION,
        "scan": {
            "analyzer": dict(tool),
            "scanner": dict(tool),
            "type": "sast",
            "start_time": _gitlab_time(started),
            "end_time": _gitlab_time(ended),
            "status": status,
            "messages": messages,
        },
        "vulnerabilities": vulnerabilities,
    }


def render(document: Mapping[str, Any], *, root: Path | None = None) -> str:
    return json.dumps(build(document, root=root), indent=2, ensure_ascii=False) + "\n"
