"""What every report format shares: the gate, locations, ids, and text hygiene."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from veridor import core
from veridor import gate as gate_policy

#: Verdicts that are findings about the TARGET.
TARGET_VERDICTS: frozenset[str] = frozenset({"vulnerable", "unexpected_denial"})

#: A fixed namespace for the UUIDs GitLab asks vulnerability ids to be. Derived
#: once from a constant, so the id of a finding depends on its Veridor
#: fingerprint and nothing else -- not the run, not the clock, not the host.
#: The URL names the namespace and nothing is served there. Do not rewrite it
#: with a domain rename: that changes every GitLab vulnerability id, and GitLab
#: reports the same findings as new. tests/test_reports.py pins the value.
FINDING_ID_NAMESPACE: uuid.UUID = uuid.uuid5(uuid.NAMESPACE_URL, "https://veridor.org/finding-id/v1")

_SURROGATE = re.compile(r"[\ud800-\udfff]")
#: Characters XML 1.0 cannot carry at all, even escaped.
_XML_ILLEGAL = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]"
)


def scrub(value: Any) -> Any:
    """Replace lone surrogates with U+FFFD, at any depth.

    A lone surrogate is legal in a Python str and in ``json.loads`` output, and
    illegal in UTF-8. Replaced rather than dropped, so a reader can see that
    something was there.
    """
    if isinstance(value, str):
        return _SURROGATE.sub("�", value)
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, dict):
        return {scrub(key) if isinstance(key, str) else key: scrub(item)
                for key, item in value.items()}
    return value


def xml_text(value: Any) -> str:
    """Text an XML 1.0 parser will accept: illegal characters become U+FFFD."""
    return _XML_ILLEGAL.sub("�", "" if value is None else str(value))


def gate_of(document: Mapping[str, Any]) -> dict[str, Any]:
    """The gate decision for this run, and whether it was recorded or derived.

    ``veridor run`` writes the decision it exited with into the document. A
    document without one -- written by an older Veridor, or by ``execute_run``
    directly -- gets the decision the CLI DEFAULTS would have made, marked
    ``recorded: False`` so every format can say it was re-derived rather than
    read. The real job may have run with other flags.

    A capsule verification (``veridor verify``) carries ``capsule`` beside its
    gate, and the gate's exit code is the capsule's verdict, not a ``--fail-on``
    decision; ``capsule`` is passed through so every format can say so.
    ``core.validate_run`` has already refused a capsule document whose verdict,
    exit code and gate disagree, or that has no gate to re-derive from.
    """
    recorded = document.get("gate")
    if isinstance(recorded, Mapping):
        return {
            "fail_on": recorded.get("fail_on"),
            "require_complete": bool(recorded.get("require_complete")),
            "require_clean_teardown": bool(recorded.get("require_clean_teardown")),
            "exit_code": recorded.get("exit_code"),
            "reasons": list(recorded.get("reasons") or ()),
            "not_enforced": list(recorded.get("not_enforced") or ()),
            "recorded": True,
            "capsule": document.get("capsule") if isinstance(
                document.get("capsule"), Mapping) else None,
        }
    return {**gate_policy.evaluate(document).to_document(), "recorded": False}


def non_finding_reasons(gate: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return gate_policy.non_finding_reasons(gate)


def reason_sentence(reason: Mapping[str, Any]) -> str:
    """One clause for a reason -- its count, its meaning, and any names it
    carries -- worded by :func:`veridor.gate.describe`. Every format prints it
    after a colon, so it starts lower-case."""
    sentence = gate_policy.describe(reason)
    names = reason.get("identities") or reason.get("sequences")
    if names:
        sentence += f" ({', '.join(str(name) for name in names)})"
    return sentence


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def finding_line(finding: Mapping[str, Any]) -> int:
    line = finding.get("location_line")
    return line if is_int(line) and line > 0 else 1


def display_path(location: Any, root: Path | None) -> str:
    """The config path a report should cite: relative to ``root`` when under it.

    The run document keeps ``--config`` exactly as typed, which on a CI runner
    is often an absolute path that links to nothing in a merge request. A path
    outside ``root`` is kept as written rather than guessed at.
    """
    text = str(location or "veridor.json")
    if root is not None and os.path.isabs(text):
        try:
            text = Path(text).relative_to(root).as_posix()
        except ValueError:
            return text
    if text.startswith("./"):
        text = str(PurePosixPath(text))
    return text


def stable_uuid(fingerprint: str) -> str:
    """A UUID-shaped id that is a pure function of a Veridor fingerprint."""
    return str(uuid.uuid5(FINDING_ID_NAMESPACE, fingerprint))


def stable_digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def unique(keys: Iterable[str]) -> list[str]:
    """Make each key unique by suffixing repeats, deterministically."""
    seen: dict[str, int] = {}
    out: list[str] = []
    for key in keys:
        count = seen.get(key, 0)
        seen[key] = count + 1
        out.append(key if count == 0 else f"{key}-{count}")
    return out


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def duration_seconds(document: Mapping[str, Any]) -> float:
    start = parse_time(document.get("started_at"))
    end = parse_time(document.get("completed_at"))
    if start is None or end is None:
        return 0.0
    return max(0.0, (end - start).total_seconds())


def rules_by_id(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """The SARIF rule table for this run: one source for every rule's name."""
    driver = core.to_sarif(dict(document))["runs"][0]["tool"]["driver"]
    return {rule["id"]: rule for rule in driver["rules"]}


def version() -> str:
    """The running Veridor's version, read at call time."""
    import veridor  # noqa: PLC0415

    return veridor.__version__


#: What each verdict means, said once. Free of coverage.BANNED_CLAIM_WORDS.
VERDICT_QUALIFIER: dict[str, str] = {
    "vulnerable": (
        "Veridor issued this request as this identity and observed behaviour "
        "outside the declared expectation."
    ),
    "unexpected_denial": (
        "The target refused a request the declaration said this identity would "
        "be served. That is a disagreement between the declaration and the "
        "deployment, not evidence of a data flow."
    ),
    "inconclusive": (
        "NOT MEASURED. This probe or step established nothing about the target, "
        "in either direction. It is neither a pass nor a finding."
    ),
}


def findings(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [f for f in document.get("findings") or () if isinstance(f, Mapping)]


def target_findings(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [f for f in findings(document) if f.get("verdict") in TARGET_VERDICTS]


def scope_sentences() -> tuple[str, str]:
    return core.DECLARATION_SCOPE, core.PASS_SCOPE


#: The pass disclosures a run document carries, as ``veridor run`` prints them:
#: (group, the field that says where, heading). Each describes an outcome that
#: emits no finding and that a pass does not establish. ``oracle_disclosures``
#: holds two kinds, split by ``control_source``: printing a served fabricated
#: credential under the marker_probe heading would call a target that accepts
#: a forged credential "a marker live elsewhere".
PASS_DISCLOSURE_GROUPS: tuple[tuple[str, str, str], ...] = (
    (
        "non_asserting_expectations",
        "check_id",
        "Non-asserting: {count} expectation(s) accept both access and denial, "
        "so they assert nothing about the boundary",
    ),
    (
        "oracle_disclosures",
        "check_id",
        "Unproven oracle: {count} exclusion(s) were licensed by an identity "
        "marker_probe, which proves the marker is live elsewhere, not that "
        "the path under test can surface it",
    ),
    (
        "fabricated_credential_served",
        "check_id",
        "Fabricated credential served: {count} check request(s) answered a "
        "credential Veridor fabricated with a 2xx, so the target accepted a "
        "credential nobody issued",
    ),
    (
        # Not only check probes: a sequence step, a teardown entry and a
        # marker probe each say which one it was in 'where'.
        "injection_disclosures",
        "where",
        "Injection not applied: {count} request(s) went out without a "
        "declared form_field or json_field their body could not carry, so a "
        "matched denial over one may be the target refusing the missing field "
        "rather than the identity",
    ),
)

#: The short label each format puts in front of one entry's statement.
PASS_DISCLOSURE_LABELS: dict[str, str] = {
    "non_asserting_expectations": "Non-asserting",
    "oracle_disclosures": "Unproven oracle",
    "fabricated_credential_served": "Fabricated credential served",
    "injection_disclosures": "Injection not applied",
}


def _disclosure_entries(value: Any) -> list[Mapping[str, Any]]:
    """The entries of one disclosure list, never dropped for their shape.

    ``validate_run`` checks the shape of ``non_asserting_expectations`` and
    ``injection_disclosures`` but not ``oracle_disclosures``; an entry that is
    not an object is kept as its text rather than skipped, so a report can
    never be quieter than the document it renders."""
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [entry if isinstance(entry, Mapping) else {"statement": str(entry)} for entry in value]


def pass_disclosures(document: Mapping[str, Any]) -> list[tuple[str, str, str, list[Mapping[str, Any]]]]:
    """Every pass disclosure in ``document``, grouped as the console prints
    them: (group, where field, heading, entries), groups with no entry left
    out. The console, and every report format but SARIF (which carries the
    raw lists as run properties), read this one function, so a disclosure
    the console prints cannot be missing from a CI report."""
    oracle = _disclosure_entries(document.get("oracle_disclosures"))
    entries = {
        "non_asserting_expectations": _disclosure_entries(document.get("non_asserting_expectations")),
        "oracle_disclosures": [
            entry for entry in oracle if entry.get("control_source") != "fabricated_credential"
        ],
        "fabricated_credential_served": [
            entry for entry in oracle if entry.get("control_source") == "fabricated_credential"
        ],
        "injection_disclosures": _disclosure_entries(document.get("injection_disclosures")),
    }
    return [
        (group, where, heading, entries[group])
        for group, where, heading in PASS_DISCLOSURE_GROUPS
        if entries[group]
    ]


def disclosure_text(group: str, where: str, entry: Mapping[str, Any]) -> str:
    """One entry as one line: its label, where it was and as whom, and the
    run's own statement of what it does not establish."""
    place = entry.get(where) if entry.get(where) is not None else entry.get("check_id")
    subject = " / ".join(str(part) for part in (place, entry.get("identity")) if part is not None)
    label = PASS_DISCLOSURE_LABELS[group]
    return f"{label} ({subject}): {entry.get('statement')}" if subject else f"{label}: {entry.get('statement')}"
