"""Authorization boundary coverage: which operations have a denial asserted.

This module answers one question and refuses to imply a second. It measures
whether a cross-identity denial is ASSERTED for each operation in a route
inventory. It never measures whether authorization is ENFORCED -- only
``veridor run`` does that, by issuing the requests and reading the findings.

Stdlib only, and offline by construction. Nothing here opens a socket, issues a
request, or observes a response body: it is a static comparison of two files,
so it runs in an air-gapped CI job and against a spec for an environment the
runner cannot reach.

Dependency direction is strictly ``core -> coverage -> openapi``. This module
imports ``veridor.openapi`` and never ``veridor.core``; it takes an
already-loaded configuration dict, which keeps the graph acyclic.
"""

from __future__ import annotations

import difflib
import math
import textwrap
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from veridor.terminal import _BLANK_RUN, quoted, terminal_names, terminal_text
from veridor.openapi import (
    DEFAULT_METHODS,
    TEMPLATE_TOKEN as _TEMPLATE_TOKEN,
    Operation,
    RouteInventory,
    SpecError,
    match_path,
    nearest_template,
    normalize_path,
    undecodable_segments,
)

__all__ = [
    "AUTHN_STATUSES",
    "BADGE_LABEL",
    "BANNED_CLAIM_WORDS",
    "BasePathResolution",
    "CLAIM",
    "Classification",
    "CoverageError",
    "DEFAULT_DENIAL_STATUSES",
    "SpecError",
    "classify_expectation",
    "compute_coverage",
    "coverage_summary",
    "format_percent",
    "not_measured_report",
    "operation_for_check",
    "render_badge",
    "render_text",
    "resolve_base_path",
    "status_class",
]


class CoverageError(ValueError):
    """Raised when boundary coverage cannot be computed or is undefined.

    Instances carry a ``report`` attribute holding the full report that was
    built before the measurement was declared undefined, so a caller can still
    persist JSON and a badge while exiting non-zero.
    """

    report: dict[str, Any] | None = None
    #: Why the measurement is undefined, as a token a caller can branch on
    #: without parsing prose. "no_declaration" is the documented starting state
    #: of the drift path and is not a problem with anything; "no_matches" is a
    #: stale configuration. Only one of them should read like a failure.
    reason: str | None = None


DEFAULT_DENIAL_STATUSES: frozenset[int] = frozenset({403, 404})
AUTHN_STATUSES: frozenset[int] = frozenset({401, 407})
BADGE_LABEL: str = "authz denial asserted"
CLAIM: dict[str, str] = {
    "measures": "presence of an asserted cross-identity authorization denial per operation",
    "does_not_measure": "whether authorization is enforced at runtime",
    "statement": (
        "Boundary coverage counts operations that have at least one configured check "
        "asserting a denial-only outcome for at least one identity. A covered "
        "operation is tested, not proven secure. Enforcement is determined only by "
        "executing the run and reading its findings."
    ),
}

#: Vocabulary that must never describe a covered operation, in code or docs.
BANNED_CLAIM_WORDS: tuple[str, ...] = (
    "secure",
    "protected",
    "safe",
    "compliant",
    "verified",
    "guaranteed",
)

_CLAIM_PARAGRAPH = (
    "  Coverage measures whether a cross-identity denial is ASSERTED for each\n"
    "  operation. It does not measure whether authorization is ENFORCED.\n"
    "  Run `veridor run` to test enforcement.\n"
    "\n"
    "  Every figure here is a fact about your CONFIGURATION, not about any\n"
    "  run. It is a property of what you wrote down; nothing here observed a\n"
    "  target."
)

_CORROBORATED_NOTE = (
    "  A positive control is declared in the same check -- one identity asserted\n"
    "  to be served alongside one asserted to be refused -- so the denial cannot\n"
    "  pass merely because the route is absent."
)

_PERFECT_NOTE = (
    "All inventoried operations have a denial asserted. This does not mean all "
    "are correctly enforced."
)

#: The key ``veridor init`` writes into the configuration it generates. Its
#: presence means nobody has removed it, which is the only signal available
#: that the declarations below it are still the tool's guesses.
GENERATED_BY_KEY = "_generated_by"

_UNREVIEWED_NOTE = (
    "THIS NUMBER IS NOT YOURS YET. This configuration still carries "
    f"{GENERATED_BY_KEY!r}, so it is `veridor init` output: it declares "
    "'owner allowed, other_tenant denied' on every operation it found, "
    "including ones no owner is entitled to. Every operation therefore has a "
    "denial-only expectation and the score is a restatement of the scaffold, "
    "not a measurement of anything you decided. Read the checks, delete the "
    f"operations with no authorization boundary, then delete {GENERATED_BY_KEY} "
    "to claim the number. The badge stays 'unreviewed' until you do."
)

#: Badge message for a scaffold nobody has read. Never green, and never a
#: percentage: the percentage is the thing that must not travel.
UNREVIEWED_BADGE_MESSAGE = "unreviewed"

# "allow_only" | "denial_only" | "authn_only" | "permissive"
#            | "redirect" | "server_error" | "ambiguous"
Classification = str

_UNUSABLE = ("permissive", "redirect", "server_error", "ambiguous")

_DIAGNOSTIC_ADVICE = {
    "permissive": (
        "accepts both access and denial, so it asserts nothing about the boundary; "
        "not counted"
    ),
    "redirect": (
        "is a redirect, which is ambiguous between a login wall and a successful "
        "resource redirect; assert the post-redirect status or a denial status instead"
    ),
    "server_error": (
        "asserts that the server breaks, which is not an authorization outcome; "
        "not counted"
    ),
    "ambiguous": (
        "contains a status that is neither an authorization denial nor an "
        "authentication denial, so the set is not denial-only; not counted"
    ),
}

_MAX_LISTED = 50


@dataclass(frozen=True)
class BasePathResolution:
    """The single global base path decision, with the evidence behind it."""

    value: str
    source: str
    candidates: tuple[dict[str, Any], ...]


# ---------------------------------------------------------------------------
# expectation classification
# ---------------------------------------------------------------------------


def status_class(
    status: int,
    *,
    denial_statuses: frozenset[int] = DEFAULT_DENIAL_STATUSES,
    authn_statuses: frozenset[int] = AUTHN_STATUSES,
) -> str:
    """Classify one HTTP status. Anything unlisted is ``ambiguous``."""
    if status in denial_statuses:
        return "authz_denial"
    if status in authn_statuses:
        return "authn_denial"
    if 200 <= status <= 299:
        return "allow"
    if 300 <= status <= 399:
        return "redirect"
    if 500 <= status <= 599:
        return "server_error"
    return "ambiguous"


def classify_expectation(
    statuses: Sequence[int],
    *,
    denial_statuses: frozenset[int] = DEFAULT_DENIAL_STATUSES,
    authn_statuses: frozenset[int] = AUTHN_STATUSES,
) -> Classification:
    """Classify one identity's expected status list on one check.

    ``denial_only`` -- the only classification that counts toward coverage --
    requires every acceptable outcome to be a refusal and at least one of them
    to be an *authorization* refusal. A set mixing a 2xx with a denial accepts
    both access and refusal, asserts nothing, and is ``permissive``.
    """
    values = [
        status
        for status in statuses
        if isinstance(status, int) and not isinstance(status, bool)
    ]
    if not values:
        return "ambiguous"
    classes = [
        status_class(
            status, denial_statuses=denial_statuses, authn_statuses=authn_statuses
        )
        for status in values
    ]
    if all(item == "allow" for item in classes):
        return "allow_only"
    if all(item in {"authz_denial", "authn_denial"} for item in classes):
        return "denial_only" if "authz_denial" in classes else "authn_only"
    if "allow" in classes and (
        "authz_denial" in classes or "authn_denial" in classes
    ):
        return "permissive"
    for item in classes:
        if item in {"redirect", "server_error", "ambiguous"}:
            return item
    return "ambiguous"


#: The keys a top-level ``coverage`` block holds, besides ``_`` annotations.
COVERAGE_KEYS: frozenset[str] = frozenset({"denial_statuses"})


def _normalized_key(key: str) -> str:
    return "".join(char for char in key.lower() if char.isascii() and char.isalnum())


def _nearest_key(key: str, known: frozenset[str]) -> str | None:
    """The real key ``key`` is a slip of, or None.

    The loader's rule (``core._nearest_key``), restated because this module
    never imports core; tests/test_coverage.py holds the two equal. The same
    key once case and separators are dropped, a difflib match at 0.85, or the
    same letters in another order.
    """
    normalized = _normalized_key(key)
    if not normalized:
        return None
    by_normal = {_normalized_key(item): item for item in known}
    if normalized in by_normal:
        return by_normal[normalized]
    close = difflib.get_close_matches(normalized, sorted(by_normal), n=1, cutoff=0.85)
    if close:
        return by_normal[close[0]]
    by_letters = {"".join(sorted(item)): real for item, real in by_normal.items()}
    return by_letters.get("".join(sorted(normalized)))


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "a list"
    return type(value).__name__


def _refuse_unreadable_section(config: Mapping[str, Any]) -> None:
    """Refuse a ``coverage`` block this module would not read as written.

    Only ``denial_statuses`` was ever read, through ``section.get``, so a
    misspelt ``Denial_Statuses`` or ``denail_statuses``, any other key, and a
    ``coverage`` that was a list, a string or null all loaded and the figure
    was computed against the default 403 and 404 without a word -- 20% on the
    demo with ``[403]`` declared, 40% with the same block misspelt. The root
    guard refused a misspelt ``Coverage`` and nothing looked inside it.
    """
    if "coverage" not in config:
        return
    section = config["coverage"]
    if not isinstance(section, dict):
        raise CoverageError(
            f"coverage must be an object holding denial_statuses, not "
            f"{_json_type(section)}, so the statuses it was meant to declare "
            "would never be read. Fix it, or remove it to use the default 403 "
            "and 404."
        )
    unknown = sorted(
        str(key) for key in section
        if not str(key).startswith("_") and key not in COVERAGE_KEYS
    )
    if not unknown:
        return
    nearest = {key: _nearest_key(key, COVERAGE_KEYS) for key in unknown}
    hints = [
        f"did you mean {quoted(nearest[key])} for {quoted(key)}?"
        if nearest[key]
        else f"an annotation starts with '_': write '_{terminal_text(key)}'"
        for key in unknown
    ]
    it = "it" if len(unknown) == 1 else "each"
    raise CoverageError(
        f"coverage has unsupported keys: {terminal_names(unknown)} "
        f"({'; '.join(hints)}) Veridor reads {', '.join(sorted(COVERAGE_KEYS))} "
        "here and nothing else, so the figure would be computed as though the "
        f"key were absent. Rename {it}, or start {it} with '_' if it is an "
        "annotation."
    )


def _denial_statuses(
    config: Mapping[str, Any], denial_statuses: frozenset[int]
) -> frozenset[int]:
    _refuse_unreadable_section(config)
    if denial_statuses is not DEFAULT_DENIAL_STATUSES:
        declared: Any = sorted(denial_statuses)
    else:
        section = config.get("coverage")
        # Present and null is refused below with every other non-list: the
        # schema says `"type": "array"`, and reading null as absent measured
        # against the defaults while the author had written the key.
        if not isinstance(section, dict) or "denial_statuses" not in section:
            return DEFAULT_DENIAL_STATUSES
        declared = section["denial_statuses"]
    # A declared denial status is classified BEFORE the authentication and
    # 2xx rules in status_class, so it must be a 4xx refusal that is not an
    # authentication one. Accepting 401 here turned an anonymous 401-only
    # expectation into 100% asserted coverage, and 200 did the same for an
    # allow-only one, while the policy block still said a 401 never counts.
    if (
        not isinstance(declared, list)
        or not declared
        or not all(
            isinstance(status, int)
            and not isinstance(status, bool)
            and 400 <= status <= 499
            and status not in AUTHN_STATUSES
            for status in declared
        )
    ):
        raise CoverageError(
            "coverage.denial_statuses must be a non-empty list of 4xx "
            "authorization refusal statuses; 401 and 407 are authentication "
            "and never count as an authorization denial"
        )
    return frozenset(declared)


# ---------------------------------------------------------------------------
# base path resolution
# ---------------------------------------------------------------------------


def target_base_path(config: Mapping[str, Any]) -> str:
    """Return the path component of ``target.base_url``, normalized.

    ``core._execute_probe`` builds each URL as ``urljoin(base_url + '/',
    path)``, so this prefix is part of every request Veridor issues and is
    therefore part of every check's effective path.
    """
    target = config.get("target")
    if not isinstance(target, dict) or not isinstance(target.get("base_url"), str):
        return ""
    path = normalize_path(urlsplit(target["base_url"]).path)
    return "" if path in {"", "/"} else path.rstrip("/")


def _redacted_raw_path(raw: str) -> str:
    """Drop the query from a raw config path before it is persisted.

    Every other path in the report goes through ``normalize_path``, which
    strips the query; this one is kept raw so undecodable percent-escapes
    survive, which is exactly why its query values must not.
    """
    head, separator, _ = raw.partition("?")
    return f"{head}?[REDACTED]" if separator else head


def _check_requests(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    checks = config.get("checks")
    if not isinstance(checks, list):
        raise CoverageError("configuration has no checks list")
    prefix = target_base_path(config)
    requests: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        request = check.get("request")
        if not isinstance(request, dict) or not isinstance(request.get("path"), str):
            continue
        method = request.get("method", "GET")
        raw_path = request["path"]
        effective = normalize_path(raw_path)
        if prefix:
            # Check paths are written relative to target.base_url, so the
            # coverage side must apply the same prefix the probe does. Feeding
            # the target prefix to the SPEC instead leaves a valid config
            # unmeasurable by any --base-path value.
            effective = normalize_path(prefix + effective)
        requests.append(
            {
                "check": check,
                "check_id": str(check.get("id", "")),
                "method": str(method).upper(),
                "raw_path": raw_path,
                "display_path": _redacted_raw_path(raw_path),
                "path": effective,
                "templated": bool(_TEMPLATE_TOKEN.search(normalize_path(raw_path))),
            }
        )
    return requests


def _operation_absolutes(
    operation: Operation, base_path: str, *, override: bool
) -> tuple[str, ...]:
    """Return every absolute path this operation is declared to be served at.

    ``servers`` is a LIST, and a path item may override the document's. Folding
    all of that into one global prefix relabels an operation under a prefix the
    spec does not place it at, which both credits a check that hits a different
    route and invents routes that were never declared. ``override`` is set when
    the user stated ``--base-path``, which is the documented way to force one
    prefix onto a spec whose ``servers`` do not describe the environment.
    """
    if override or not any(operation.base_paths):
        return (operation.absolute_path(base_path),)
    return tuple(
        dict.fromkeys(operation.absolute_path(item) for item in operation.base_paths)
    )


def _absolute_index(
    inventory: RouteInventory, base_path: str, *, override: bool = False
) -> tuple[list[str], dict[str, frozenset[str]], dict[tuple[str, str], Operation]]:
    templates: dict[str, None] = {}
    methods: dict[str, set[str]] = {}
    operations: dict[tuple[str, str], Operation] = {}
    for operation in inventory.operations:
        for absolute in _operation_absolutes(operation, base_path, override=override):
            templates.setdefault(absolute, None)
            methods.setdefault(absolute, set()).add(operation.method)
            operations.setdefault((absolute, operation.method), operation)
    return (
        list(templates),
        {key: frozenset(value) for key, value in methods.items()},
        operations,
    )


def _score_candidate(
    inventory: RouteInventory, candidate: str, paths: Sequence[str]
) -> int:
    # ``override=True``: the scoreboard answers "how many checks match if this
    # one prefix is forced onto every operation?", which is the question the
    # candidate is competing on. Scoring with per-operation prefixes instead
    # would give every candidate the same total and make the board meaningless.
    templates, _, _ = _absolute_index(inventory, candidate, override=True)
    if not templates:
        return 0
    return sum(1 for path in paths if match_path(path, templates) is not None)


def resolve_base_path(
    config: Mapping[str, Any],
    inventory: RouteInventory,
    *,
    explicit: str | None = None,
) -> BasePathResolution:
    """Choose one base path for the whole run, by evidence, and show the work.

    Spec paths are relative to ``servers[].url``; config paths are absolute from
    ``target.base_url``. Getting this wrong is the single biggest cause of a
    catastrophically wrong number, so every candidate is scored by how many
    distinct config check paths it makes match, and the full scoreboard travels
    into both the JSON report and the text header.
    """
    seen: dict[str, None] = {}
    for candidate in inventory.base_paths:
        seen.setdefault(candidate, None)
    target = config.get("target")
    if isinstance(target, dict) and isinstance(target.get("base_url"), str):
        target_path = normalize_path(urlsplit(target["base_url"]).path)
        seen.setdefault("" if target_path in {"", "/"} else target_path, None)
    seen.setdefault("", None)

    paths = sorted({request["path"] for request in _check_requests(config)})

    if explicit is not None:
        value = normalize_path(explicit)
        value = "" if value in {"", "/"} else value
        matched = _score_candidate(inventory, value, paths)
        candidates = ({"value": value, "matched_checks": matched},)
        if matched == 0 and paths and inventory.operations:
            raise CoverageError(
                f"--base-path {explicit!r} matched none of the {len(paths)} configured "
                "check paths. Veridor does not silently fall back to auto-detection "
                "when a base path was stated explicitly. Drop the flag to auto-detect, "
                "or pass --base-path '' to force no prefix."
            )
        return BasePathResolution(value=value, source="flag", candidates=candidates)

    scored = [
        {"value": candidate, "matched_checks": _score_candidate(inventory, candidate, paths)}
        for candidate in seen
    ]
    scored.sort(
        key=lambda entry: (
            -entry["matched_checks"],
            -len(entry["value"]),
            entry["value"],
        )
    )
    best = scored[0]["value"] if scored else ""
    return BasePathResolution(
        value=best,
        source="none" if best == "" else "auto",
        candidates=tuple(scored),
    )


# ---------------------------------------------------------------------------
# coverage computation
# ---------------------------------------------------------------------------


def _diagnostic(code: str, severity: str, message: str, **fields: Any) -> dict[str, Any]:
    """One diagnostic. ``message`` is printed by ``render_text``, which escapes
    it but does not cut it, so every value it quotes from the config or the
    spec is bounded where it is built: :func:`quoted` for ``{value!r}``,
    :func:`terminal_text` for a bare value. Collapsing blank runs is not
    enough on its own -- a printable blank such as U+2800 still pads a forged
    row. The raw values are kept whole in the fields beside the message."""
    entry: dict[str, Any] = {"code": code, "severity": severity}
    entry.update(fields)
    entry["message"] = message
    return entry


def _uncovered_reason(classifications: Sequence[str]) -> str:
    if not classifications:
        return "no_check"
    if "authn_only" in classifications:
        return "authentication_only"
    if "permissive" in classifications:
        return "permissive_only"
    if "allow_only" in classifications:
        return "allow_only"
    return "unclassified_expectations"


def _identity_role(classifications: Sequence[str]) -> str:
    has_allow = "allow_only" in classifications
    has_denial = "denial_only" in classifications
    if has_allow and has_denial:
        return "contextual"
    if has_denial:
        return "challenger"
    if has_allow:
        return "principal-owner"
    if classifications and all(item == "authn_only" for item in classifications):
        return "authenticator"
    return "unclassified"


def compute_coverage(
    config: Mapping[str, Any],
    inventory: RouteInventory,
    *,
    config_path: Path | str | None = None,
    spec_path: Path | str | None = None,
    base_path: str | None = None,
    denial_statuses: frozenset[int] = DEFAULT_DENIAL_STATUSES,
    require_corroboration: bool = False,
    allow_no_matches: bool = False,
    methods: frozenset[str] = DEFAULT_METHODS,
    exclude_deprecated: bool = False,
) -> dict[str, Any]:
    """Compute the full boundary coverage report.

    Never raises for a low score. Raises ``CoverageError`` only when the
    measurement is undefined -- an empty inventory, or an inventory and a
    configuration that share no route at all -- because reporting 0/0 or a
    silent 0% would be worse than refusing to answer. The exception carries the
    report on ``.report`` so callers can still write JSON and a badge.
    """
    denials = _denial_statuses(config, denial_statuses)
    requests = _check_requests(config)
    resolution = resolve_base_path(config, inventory, explicit=base_path)
    override = resolution.source == "flag"
    templates, template_methods, operation_index = _absolute_index(
        inventory, resolution.value, override=override
    )
    lowered: dict[str, str] = {}
    for template in templates:
        lowered.setdefault(template.lower(), template)

    diagnostics: list[dict[str, Any]] = []
    credited: dict[tuple[str, str], list[dict[str, Any]]] = {}
    match_cache: dict[tuple[str, str], Any] = {}
    unmatched = 0

    for request in requests:
        check_id = request["check_id"]
        concrete = request["path"]
        method = request["method"]
        for segment in undecodable_segments(request["display_path"]):
            diagnostics.append(
                _diagnostic(
                    "undecodable_segment",
                    "warning",
                    f"check {quoted(check_id)} path segment {quoted(segment)} is not a "
                    "valid UTF-8 percent-escape; the raw segment was kept for matching",
                    check_id=check_id,
                    method=method,
                    path=request["display_path"],
                )
            )
        if request["templated"]:
            # A check path that still carries {id} matches the very template it
            # was generated from, so `veridor init` output would score 100%
            # untouched. An unsubstituted placeholder is not a request anyone
            # can issue, so it credits nothing.
            unmatched += 1
            diagnostics.append(
                _diagnostic(
                    "templated_check_path",
                    "error",
                    f"check {quoted(check_id)} path {quoted(request['display_path'])} "
                    "still contains an unsubstituted path placeholder, so it does not name "
                    "a concrete resource; replace it with a real id. It credits no operation",
                    check_id=check_id,
                    method=method,
                    path=request["display_path"],
                )
            )
            continue
        cache_key = (concrete, method)
        if cache_key not in match_cache:
            match_cache[cache_key] = match_path(
                concrete,
                templates,
                prefer_methods=template_methods,
                method=method,
            )
        match = match_cache[cache_key]
        if match is None:
            unmatched += 1
            insensitive = match_path(concrete.lower(), list(lowered))
            if insensitive is not None:
                diagnostics.append(
                    _diagnostic(
                        "case_mismatch",
                        "warning",
                        f"check {quoted(check_id)} path {quoted(concrete)} matches no "
                        f"operation; paths are compared case-sensitively and "
                        f"{quoted(lowered[insensitive.template])} differs only in case",
                        check_id=check_id,
                        method=method,
                        path=concrete,
                        nearest=lowered[insensitive.template],
                    )
                )
            suggestion = nearest_template(concrete, templates)
            diagnostics.append(
                _diagnostic(
                    "unmatched_check",
                    "warning",
                    f"check {quoted(check_id)} {terminal_text(method)} {terminal_text(concrete)} matched "
                    "no operation"
                    + (f"; nearest: {terminal_text(suggestion)}" if suggestion else ""),
                    check_id=check_id,
                    method=method,
                    path=concrete,
                    nearest=suggestion,
                )
            )
            continue

        available = sorted(template_methods.get(match.template, frozenset()))
        if method not in template_methods.get(match.template, frozenset()):
            diagnostics.append(
                _diagnostic(
                    "method_not_in_spec",
                    "warning",
                    f"check {quoted(check_id)} {terminal_text(method)} {terminal_text(concrete)} matched "
                    f"{terminal_text(match.template)}, for which the spec defines "
                    f"{', '.join(available) or '(no in-scope method)'}",
                    check_id=check_id,
                    method=method,
                    path=concrete,
                    template=match.template,
                    spec_methods=available,
                )
            )
            continue

        expect = request["check"].get("expect")
        classifications: dict[str, str] = {}
        if isinstance(expect, dict):
            for identity, expectation in expect.items():
                statuses = expectation.get("status") if isinstance(expectation, dict) else None
                if isinstance(statuses, int) and not isinstance(statuses, bool):
                    statuses = [statuses]
                if not isinstance(statuses, list):
                    statuses = []
                classification = classify_expectation(
                    statuses, denial_statuses=denials, authn_statuses=AUTHN_STATUSES
                )
                classifications[str(identity)] = classification
                if classification in _UNUSABLE:
                    diagnostics.append(
                        _diagnostic(
                            f"{classification}_expect",
                            "warning",
                            f"expectation {quoted(list(statuses))} for identity "
                            f"{quoted(str(identity))} on check {quoted(check_id)} "
                            f"{_DIAGNOSTIC_ADVICE[classification]}",
                            check_id=check_id,
                            identity=str(identity),
                            method=method,
                            path=concrete,
                            statuses=list(statuses),
                        )
                    )
        credited.setdefault((match.template, method), []).append(
            {
                "check_id": check_id,
                "concrete_path": concrete,
                "ambiguous_with": list(match.ambiguous_with),
                "identities": classifications,
            }
        )

    operations: list[dict[str, Any]] = []
    for operation in inventory.operations:
        absolutes = _operation_absolutes(
            operation, resolution.value, override=override
        )
        checks = [
            record
            for absolute in absolutes
            for record in credited.get((absolute, operation.method), [])
        ]
        # Report the prefix a check actually hit; otherwise the first one the
        # spec declares, so the printed route never contradicts the document.
        absolute = next(
            (
                candidate
                for candidate in absolutes
                if credited.get((candidate, operation.method))
            ),
            absolutes[0],
        )
        denial = any(
            "denial_only" in record["identities"].values() for record in checks
        )
        corroborated = any(
            "denial_only" in record["identities"].values()
            and "allow_only" in record["identities"].values()
            for record in checks
        )
        headline = corroborated if require_corroboration else denial
        if headline:
            reason = "denial_asserted"
        elif require_corroboration and denial:
            reason = "not_corroborated"
        else:
            observed = [
                value for record in checks for value in record["identities"].values()
            ]
            reason = _uncovered_reason(observed)
        operations.append(
            {
                "method": operation.method,
                "path_template": operation.path_template,
                "absolute_path": absolute,
                "operation_id": operation.operation_id,
                "deprecated": operation.deprecated,
                "covered": headline,
                "corroborated": corroborated,
                "denial_asserted": denial,
                "reason": reason,
                "checks": checks,
            }
        )

    diagnostics.sort(
        key=lambda entry: (
            entry.get("code", ""),
            str(entry.get("check_id", "")),
            str(entry.get("path", "")),
            str(entry.get("method", "")),
            str(entry.get("identity", "")),
            entry.get("message", ""),
        )
    )

    total = len(operations)
    covered = sum(1 for entry in operations if entry["covered"])
    corroborated_count = sum(1 for entry in operations if entry["corroborated"])
    weak = sum(
        1 for entry in operations if entry["denial_asserted"] and not entry["corroborated"]
    )
    authentication_only = sum(
        1 for entry in operations if entry["reason"] == "authentication_only"
    )
    paths: dict[str, bool] = {}
    for entry in operations:
        paths[entry["absolute_path"]] = paths.get(entry["absolute_path"], False) or entry[
            "covered"
        ]
    path_total = len(paths)
    paths_covered = sum(1 for value in paths.values() if value)

    if total == 0:
        status = "empty_inventory"
    elif not credited:
        status = "no_matches"
    else:
        status = "measured"
    # 6 decimal places, not 4: at the supported ceiling of 20,000 operations
    # round(19999/20000, 4) is exactly 1.0, so a JSON consumer would read a
    # perfect score for an inventory with an untested authorization boundary.
    ratio = round(covered / total, 6) if status == "measured" and total else None
    path_ratio = (
        round(paths_covered / path_total, 6)
        if status == "measured" and path_total
        else None
    )

    identity_classifications: dict[str, list[str]] = {}
    for request in requests:
        expect = request["check"].get("expect")
        if not isinstance(expect, dict):
            continue
        for identity, expectation in expect.items():
            statuses = expectation.get("status") if isinstance(expectation, dict) else None
            if isinstance(statuses, int) and not isinstance(statuses, bool):
                statuses = [statuses]
            if not isinstance(statuses, list):
                statuses = []
            identity_classifications.setdefault(str(identity), []).append(
                classify_expectation(
                    statuses, denial_statuses=denials, authn_statuses=AUTHN_STATUSES
                )
            )

    matched_for_base = next(
        (
            entry["matched_checks"]
            for entry in resolution.candidates
            if entry["value"] == resolution.value
        ),
        0,
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "veridor.coverage",
        "generated_at": datetime.now(UTC).isoformat(),
        "spec": {
            "path": str(spec_path) if spec_path is not None else None,
            "version": inventory.spec_version,
            "title": inventory.title,
            "paths": inventory.path_count,
            "operations_total": total + len(inventory.excluded),
        },
        "config": {
            "path": str(config_path) if config_path is not None else None,
            "checks": len(requests),
            # True while the configuration still declares itself to be `veridor
            # init` output. See _UNREVIEWED_NOTE.
            "unreviewed_scaffold": bool(config.get(GENERATED_BY_KEY)),
        },
        "base_path": {
            "value": resolution.value,
            "source": resolution.source,
            "candidates": [dict(entry) for entry in resolution.candidates],
            "matched_checks": matched_for_base,
            "check_paths": len({request["path"] for request in requests}),
        },
        "claim": dict(CLAIM),
        "policy": {
            "unit": "operation",
            "methods": sorted(method.upper() for method in methods),
            "denial_statuses": sorted(denials),
            "authn_statuses": sorted(AUTHN_STATUSES),
            "authn_counts_as_coverage": False,
            "require_corroboration": require_corroboration,
            "exclude_deprecated": bool(exclude_deprecated)
            or any(entry["reason"] == "deprecated" for entry in inventory.excluded),
        },
        "status": status,
        "coverage": ratio,
        "summary": {
            "operations": total,
            "covered": covered,
            "uncovered": total - covered,
            "corroborated": corroborated_count,
            "weak": weak,
            "authentication_only": authentication_only,
            "excluded": len(inventory.excluded),
            "unmatched_checks": unmatched,
            "diagnostics": len(diagnostics),
            "path_coverage": path_ratio,
            "paths": path_total,
            "paths_covered": paths_covered,
        },
        "operations": operations,
        "uncovered": [
            {
                "method": entry["method"],
                "path_template": entry["path_template"],
                "absolute_path": entry["absolute_path"],
                "reason": entry["reason"],
            }
            for entry in operations
            if not entry["covered"]
        ],
        "weak_coverage": [
            {
                "method": entry["method"],
                "path_template": entry["path_template"],
                "absolute_path": entry["absolute_path"],
                "checks": [record["check_id"] for record in entry["checks"]],
            }
            for entry in operations
            if entry["denial_asserted"] and not entry["corroborated"]
        ],
        "excluded": [dict(entry) for entry in inventory.excluded],
        "diagnostics": diagnostics,
        "spec_warnings": list(inventory.warnings),
        "identity_roles": {
            identity: _identity_role(values)
            for identity, values in sorted(identity_classifications.items())
        },
    }

    if status == "empty_inventory":
        error = CoverageError(
            f"the specification declares no in-scope operations, so boundary coverage "
            f"is undefined (0/0). Nothing is reported as 0% or 100%. "
            f"Check that 'paths' is populated in {spec_path or 'the spec'} and that at "
            f"least one of {sorted(method.upper() for method in methods)} is declared."
        )
        error.report = report
        raise error
    if status == "no_matches" and not allow_no_matches:
        error = CoverageError(_no_matches_message(report, templates, requests, spec_path))
        error.report = report
        error.reason = (
            "no_declaration" if not report["base_path"]["check_paths"] else "no_matches"
        )
        raise error
    return report


def _no_matches_message(
    report: Mapping[str, Any],
    templates: Sequence[str],
    requests: Sequence[Mapping[str, Any]],
    spec_path: Path | str | None,
) -> str:
    if not report["base_path"]["check_paths"]:
        # The generic message below diagnoses a prefix mismatch, which is the
        # right guess when checks exist and none matched. With no checks at all
        # it is simply wrong, and it lands at the top of `map`'s output on the
        # path where the user declared nothing on purpose. Say the real cause.
        return (
            f"this configuration declares no checks, so there is nothing to "
            f"measure against the {report['summary']['operations']} operations "
            f"in {spec_path or 'the spec'}. That is expected while you are still "
            "discovering: `map` and drift need no checks, and boundary coverage "
            "starts existing once you declare your first expectation.\n\n"
            "  Boundary coverage is undefined here, not 0%: a percentage would "
            "read as a\n  measurement of your API when it is a fact about an "
            "empty declaration."
        )
    scoreboard = "\n".join(
        f"    {terminal_text(entry['value'] or '(none)'):<24} {entry['matched_checks']} of "
        f"{report['base_path']['check_paths']} check paths"
        for entry in report["base_path"]["candidates"]
    )
    example_checks = "\n".join(
        f"    {terminal_text(request['method'])} {terminal_text(request['path'])}"
        for request in requests[:3]
    )
    # Routes, config paths and candidates come from the spec and the config:
    # each is shown, not obeyed, and bounded, as every quoted value is.
    example_routes = "\n".join(f"    {terminal_text(template)}" for template in templates[:3])
    return (
        f"none of the {report['base_path']['check_paths']} configured check paths "
        f"matched any of the {report['summary']['operations']} operations in "
        f"{spec_path or 'the spec'}. Boundary coverage is undefined and is not "
        "reported as 0%.\n\n"
        "  base-path candidates scored (no candidate produced any match):\n"
        f"{scoreboard}\n\n"
        "  example config paths:\n"
        f"{example_checks}\n\n"
        "  example spec routes:\n"
        f"{example_routes}\n\n"
        "  Suggestion: the config and the spec probably describe different prefixes. "
        "Pass\n  --base-path <prefix> to state the spec's prefix explicitly, or confirm "
        "the spec\n  covers the environment under test. Use --allow-no-matches to accept "
        "this."
    )


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _spec_label(report: Mapping[str, Any]) -> str:
    spec = report["spec"]
    version = str(spec.get("version") or "")
    family = "Swagger" if version.startswith("2") else "OpenAPI"
    name = Path(str(spec["path"])).name if spec.get("path") else "(spec)"
    title = spec.get("title")
    suffix = f", {title!r}" if isinstance(title, str) and title else ""
    return f"{name} ({family} {version}{suffix})"


def _excluded_label(report: Mapping[str, Any]) -> str:
    counts: dict[str, int] = {}
    for entry in report["excluded"]:
        key = (
            str(entry.get("method"))
            if entry.get("reason") == "method_not_in_scope"
            else str(entry.get("reason"))
        )
        counts[key] = counts.get(key, 0) + 1
    breakdown = ", ".join(
        f"{count} {label}"
        for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    )
    total = len(report["excluded"])
    return f"{total} operations ({breakdown})" if breakdown else "0 operations"


def _base_path_line(report: Mapping[str, Any]) -> str:
    block = report["base_path"]
    value = terminal_text(block["value"]) if block["value"] else "(none)"
    source = {
        "flag": "from --base-path",
        "auto": "auto-detected",
        "none": "no prefix",
    }.get(block["source"], block["source"])
    return (
        f"  base path: {value}  ({source}; {block['matched_checks']} of "
        f"{block['check_paths']} check paths matched)"
    )


#: The width every plain-text report in this package wraps to.
REPORT_WIDTH = 78


def wrap_paragraph(
    text: str, indent: str = "  ", width: int = REPORT_WIDTH
) -> list[str]:
    """Wrap one paragraph to the width every report in this package uses.

    The single implementation. ``blastradius`` and ``mutation`` each carried a
    hand-rolled copy of this and had already drifted apart -- 12-15% of inputs
    wrapped differently -- which is the same defect class this project fixed
    once before, when a divergent copy of "was this probe answered" was unified
    into ``core.probe_answered``.

    Two flags are load-bearing and are why the stdlib defaults are not used.
    ``break_long_words`` and ``break_on_hyphens`` are both off, so a token
    longer than the width overflows its line rather than being split. Veridor's
    output is evidence somebody copies into a ticket or a shell, and it is full
    of tokens that mean nothing in halves: URLs, ``/api/v1/invoices/{id}``,
    ``VERIDOR-AUTHZ-001``, marker values, fingerprints. With the defaults, a
    103-character finding URL came back as ``...tenants/acme-`` on one line and
    ``corp/invoices/...`` on the next.

    Both hand-rolled versions already refused to split tokens, so this
    preserves what ``mutate`` and ``map`` printed. It changes ``coverage``,
    which had been on the stdlib defaults and was splitting them.
    """
    return textwrap.wrap(
        text,
        width=width,
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def _wrap_note(text: str, indent: str = "  ") -> list[str]:
    """Backwards-compatible alias for this module's own call site."""
    return wrap_paragraph(text, indent)


def render_text(report: Mapping[str, Any]) -> str:
    """Render the human-readable report.

    The claim boundary is printed immediately under the headline, always, and is
    not suppressible by any flag.
    """
    summary = report["summary"]
    lines = [
        "Veridor boundary coverage",
        f"  spec:      {_spec_label(report)}",
        f"  config:    {Path(str(report['config']['path'])).name if report['config']['path'] else '(config)'}",
        _base_path_line(report),
    ]
    if report["excluded"]:
        lines.append(f"  excluded:  {_excluded_label(report)}")
    lines.append("")

    if report["status"] != "measured" or report["coverage"] is None:
        lines.append(
            f"Authorization boundary coverage: not measured ({report['status']})"
        )
        lines.append("")
        lines.append(_CLAIM_PARAGRAPH)
        lines.append("")
        if report["status"] == "empty_inventory":
            lines.append(
                "  The specification declares no in-scope operations, so the ratio is "
                "0/0\n  and is undefined. It is never rendered as 0% or 100%."
            )
        else:
            lines.append(
                f"  0 of {report['base_path']['check_paths']} configured check paths "
                f"matched any of the\n  {summary['operations']} inventoried operations, "
                "so the ratio is undefined. It is never\n  rendered as 0%. Check the "
                "base path candidates above and the spec prefix."
            )
        return "\n".join(lines) + "\n"

    lines.append(
        f"Authorization boundary coverage: {summary['covered']}/"
        f"{summary['operations']} operations "
        f"({format_percent(summary['covered'], summary['operations'])})"
    )
    lines.append("")
    lines.append(_CLAIM_PARAGRAPH)
    lines.append("")
    lines.append(f"Corroborated: {summary['corroborated']}/{summary['operations']} operations")
    lines.append("")
    lines.append(_CORROBORATED_NOTE)
    lines.append("")

    if report.get("config", {}).get("unreviewed_scaffold"):
        lines.extend(_wrap_note(_UNREVIEWED_NOTE))
        lines.append("")

    if summary["covered"] == summary["operations"]:
        lines.append(_PERFECT_NOTE)
        lines.append("")

    uncovered = report["uncovered"]
    if uncovered:
        lines.append(
            f"{len(uncovered)} operations have no cross-identity denial asserted:"
        )
        for entry in uncovered[:_MAX_LISTED]:
            tag = (
                f"    [{entry['reason']}]"
                if entry["reason"] not in {"no_check"}
                else ""
            )
            # Spec-derived, so shown and not obeyed: a path key carrying an
            # escape sequence or a bidi override reached the terminal raw here
            # while the no-matches refusal escaped the same value.
            lines.append(
                f"  {entry['method']:<6} {terminal_text(entry['absolute_path'])}{tag}"
            )
        if len(uncovered) > _MAX_LISTED:
            lines.append(
                f"  ... and {len(uncovered) - _MAX_LISTED} more (see the JSON report)"
            )
        if summary["authentication_only"]:
            lines.append(
                f"  {summary['authentication_only']} of these are asserted only against "
                "an unauthenticated identity. A 401\n  for an anonymous caller is an "
                "authentication boundary, not an authorization one."
            )
        lines.append("")

    weak = report["weak_coverage"]
    if weak:
        lines.append(
            "Weak coverage -- denial asserted, but no identity is expected to succeed "
            f"({len(weak)}):"
        )
        for entry in weak[:_MAX_LISTED]:
            checks = ", ".join(f"`{terminal_text(item)}`" for item in entry["checks"])
            lines.append(
                f"  {entry['method']:<6} {terminal_text(entry['absolute_path'])}"
                f"    check {checks}"
            )
        lines.append(
            "  A check where every identity is denied cannot distinguish \"denied\" from "
            "\"this\n  route does not exist\". Add a 2xx expectation for an owning identity."
        )
        lines.append("")

    diagnostics = report["diagnostics"]
    if diagnostics:
        lines.append(f"Diagnostics ({len(diagnostics)}):")
        shown = diagnostics[:_MAX_LISTED]
        # Width from the data, never a constant. `templated_check_path` is
        # exactly 20 characters, so a hard-coded `:<20` padded it to nothing
        # and printed `templated_check_pathcheck 'get-org' path ...` -- 102
        # times in one run, for the docs-only trial that found it. Widening
        # the constant to 22 would only move the boundary to the next
        # 22-character code.
        width = max(len(str(entry["code"])) for entry in shown) + 2
        for entry in shown:
            # Escaped, not cut, so Veridor's own advice is never cut short:
            # each value the message quotes was cut to ECHO_LIMIT where it
            # was built (_diagnostic). Blank runs are collapsed here too.
            message = _BLANK_RUN.sub(" ", str(entry["message"]))
            lines.append(f"  {entry['code']:<{width}}{terminal_text(message, limit=None)}")
        if len(diagnostics) > _MAX_LISTED:
            lines.append(
                f"  ... and {len(diagnostics) - _MAX_LISTED} more (see the JSON report)"
            )
        lines.append("")

    if summary["unmatched_checks"] and report["config"]["checks"]:
        if summary["unmatched_checks"] * 2 > report["config"]["checks"]:
            # Name the cause this function can actually SEE. The diagnostics
            # printed a few lines above already say which checks carry an
            # unsubstituted placeholder; telling that same reader their base
            # path or spec is "probably stale" sends them to check two things
            # that are correct. One docs-only trial had 102 of 124 checks in
            # exactly this state and both suggested causes were wrong.
            templated = sum(
                1 for entry in diagnostics
                if entry["code"] == "templated_check_path"
            )
            if templated * 2 > summary["unmatched_checks"]:
                cause = (
                    f"{templated} of them still contain an unsubstituted path "
                    "placeholder such as {id},\n  so they name no concrete "
                    "resource; replace each one with a real id."
                )
                # And do NOT rule out the base path unless it really did
                # resolve every check. Asserting "the base path matched, so it
                # is not the cause" on a mixed run would be the same defect
                # this branch exists to fix, in the opposite direction.
                matched = report["base_path"].get("matched_checks")
                if matched is not None and matched == report["base_path"]["check_paths"]:
                    cause += (
                        "\n  The base path above resolved every check, so it is "
                        "not the cause."
                    )
            else:
                cause = (
                    "The denominator is still valid, but the base path or the "
                    "spec is probably stale."
                )
            lines.append(
                f"WARNING: {summary['unmatched_checks']} of "
                f"{report['config']['checks']} checks matched no operation.\n  "
                + cause
            )
            lines.append("")

    if report["policy"]["denial_statuses"] != sorted(DEFAULT_DENIAL_STATUSES):
        lines.append(
            f"Denial statuses in use (declared by config): "
            f"{report['policy']['denial_statuses']}"
        )
        lines.append("")

    if summary["path_coverage"] is not None:
        lines.append(
            f"Path-level coverage (secondary): {summary['paths_covered']}/"
            f"{summary['paths']} paths "
            f"({format_percent(summary['paths_covered'], summary['paths'])})"
        )
    return "\n".join(lines).rstrip("\n") + "\n"


def format_percent(covered: int, total: int) -> str:
    """Render ``covered/total`` as a percentage that never rounds past a bound.

    One uncovered operation in 1,819 is 99.945%, which ``.1f`` rounds to
    ``100.0%`` -- a green badge over a known-untested authorization boundary.
    The value is floored instead of rounded, so the number never overstates
    coverage, and the two saturating cases are named rather than rounded into.
    """
    if total <= 0:
        return "n/a"
    if covered >= total:
        return "100.0%"
    # Flooring can never reach 100.0 while covered < total, so the upper bound
    # needs no special case; the lower one does, because a real fraction can
    # floor to 0.0 and "0.0% asserted" reads as "nothing is asserted".
    floored = math.floor(covered * 1000 / total) / 10
    if covered > 0 and floored <= 0.0:
        return "<0.1%"
    return f"{floored:.1f}%"


def _badge_color(percent: float) -> str:
    if percent >= 95:
        return "brightgreen"
    if percent >= 90:
        return "green"
    if percent >= 75:
        return "yellow"
    if percent >= 50:
        return "orange"
    return "red"


def not_measured_report(reason: str) -> dict[str, Any]:
    """The document written to ``--coverage`` when the measurement was refused
    before any report existed: a status that is not ``measured``, no figure,
    and why. Without it the file was left as it was, so a step that read it
    after the refusal found the last run's ``measured`` figure."""
    return {
        "schema_version": 1,
        "kind": "veridor.coverage",
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "not_measured",
        "coverage": None,
        "reason": reason,
        "claim": dict(CLAIM),
    }


def render_badge(
    report: Mapping[str, Any],
    *,
    label: str = BADGE_LABEL,
    cache_seconds: int = 300,
) -> dict[str, Any]:
    """shields.io endpoint JSON.

    The label carries the claim boundary inside its own three words, because the
    badge is the artifact that travels furthest from its context: it gets pasted
    into a README where none of the caveats around it can follow.

    It says ``asserted``, not ``tested``. ``tested`` is the enforcement claim
    this module disclaims in ``CLAIM['does_not_measure']`` -- and it would be
    false on its face, because ``veridor coverage`` is offline by construction
    and issues no request, so it can score a target that was never contacted.
    ``asserted`` is exactly ``CLAIM['measures']``.

    A measurement that is not defined never renders a green badge.
    """
    if report.get("status") != "measured" or report.get("coverage") is None:
        return {
            "schemaVersion": 1,
            "label": label,
            "message": "unknown",
            "color": "lightgrey",
            "isError": True,
            "cacheSeconds": cache_seconds,
        }
    if report.get("config", {}).get("unreviewed_scaffold"):
        # `veridor init` declares a denial for every operation it finds, so an
        # untouched scaffold scores 100% and this badge is the artefact most
        # likely to be published from it -- before anyone has read a line of
        # the file it summarises. The percentage does not travel until the
        # operator removes _generated_by.
        return {
            "schemaVersion": 1,
            "label": label,
            "message": UNREVIEWED_BADGE_MESSAGE,
            "color": "lightgrey",
            "isError": True,
            "cacheSeconds": cache_seconds,
        }
    summary = report.get("summary", {})
    covered = summary.get("covered")
    total = summary.get("operations")
    percent = float(report["coverage"]) * 100
    if not isinstance(covered, int) or not isinstance(total, int) or total <= 0:
        message = f"{percent:.1f}% asserted"
    else:
        message = f"{format_percent(covered, total)} asserted"
    return {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": _badge_color(percent),
        "cacheSeconds": cache_seconds,
    }


def coverage_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    """Compact block meant for embedding in a run document or SARIF run properties.

    No Veridor command calls this yet: no run document and no SARIF output
    carries the block today. It is a library helper, tested on its own.
    """
    summary = report.get("summary", {})
    return {
        "status": report.get("status"),
        "coverage": report.get("coverage"),
        "operations": summary.get("operations"),
        "covered": summary.get("covered"),
        "uncovered": summary.get("uncovered"),
        "corroborated": summary.get("corroborated"),
        "weak": summary.get("weak"),
        "authentication_only": summary.get("authentication_only"),
        "excluded": summary.get("excluded"),
        "unmatched_checks": summary.get("unmatched_checks"),
        "base_path": report.get("base_path", {}).get("value"),
        "measures": CLAIM["measures"],
        "does_not_measure": CLAIM["does_not_measure"],
    }


def operation_for_check(
    report: Mapping[str, Any], check_id: str
) -> dict[str, str] | None:
    """Return ``{"path_template", "method"}`` for a check, or ``None``.

    No Veridor command calls this yet, so no finding carries a
    ``path_template`` or ``method`` property today. If one is ever attached,
    it must NEVER feed ``_finding_id``: adding it to the identity hash would
    silently invalidate every user's baseline.
    """
    for entry in report.get("operations", []):
        for record in entry.get("checks", []):
            if record.get("check_id") == check_id:
                return {
                    "path_template": entry["path_template"],
                    "method": entry["method"],
                }
    return None
