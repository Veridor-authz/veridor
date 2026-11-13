"""Ordered multi-request sequences: interpolation, capture, and grading.

A sequence is an ordered, strictly serial list of HTTP requests, each issued as
exactly one named identity, each declaring a status expectation, each optionally
naming values to carry forward. It is not a program: there are no conditionals,
no loops, no arithmetic, no expressions, no transforms, no retries, and no
user-defined functions.

Three properties govern every decision in this file.

1. **Captured values never reach disk.** They live in a flat, single-assignment
   ``dict[str, str | int]`` scoped to one sequence execution and are dropped
   when it ends. Persisted step URLs are the config TEMPLATE, ``${...}`` tokens
   intact, so the one channel by which a captured value could have reached the
   run document is closed at the source. :func:`redact_captures` is defence in
   depth behind that, not the primary control.
2. **A sequence that cannot establish its own preconditions reports
   inconclusive.** Never safe, never vulnerable. ``role`` is required with no
   default precisely so this is decidable.
3. **Fingerprints hash the template, never the resolved request.** That single
   rule keeps ids stable across runs for ``${var}``, ``${marker:X}``, and
   ``${run_id}`` alike, with no per-token exception list to get wrong.

``core`` is imported at module scope and ``core`` imports this module lazily
inside the two functions that need it, so there is no import cycle in either
direction.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
import sys
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Mapping, Sequence as _Sequence
from urllib.parse import quote_plus, urljoin, urlsplit
from urllib.request import Request

from veridor import core
from veridor.core import ConfigError
from veridor.terminal import quoted

# --------------------------------------------------------------------------
# Hard structural caps. Every one is a load-time ConfigError with no override
# flag: a 13-step sequence is a script, and a script is unreviewable.
# --------------------------------------------------------------------------
MAX_SEQUENCES: int = 64
MAX_STEPS: int = 12
MAX_TEARDOWN: int = 6
MAX_CAPTURES_PER_STEP: int = 8
MAX_INTERPOLATIONS_PER_STEP: int = 16
MAX_CAPTURE_VALUE_CHARS: int = 512

SEQUENCE_KEYS: frozenset[str] = frozenset({"id", "name", "steps", "teardown"})
STEP_KEYS: frozenset[str] = frozenset(
    {"role", "as", "request", "expect", "capture", "name"}
)
TEARDOWN_KEYS: frozenset[str] = frozenset({"as", "request", "expect", "name"})
ROLES: frozenset[str] = frozenset({"setup", "assert"})

#: Methods that cannot change server state. Condition 5 of the EFFECT-001
#: precondition asks whether an EARLIER step wrote, and this is the definition
#: of "wrote".
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

#: The complete, closed vocabulary for a capture miss. A miss always aborts the
#: sequence, so this is a diagnostic, never a control-flow input.
CAPTURE_MISS_REASONS: frozenset[str] = frozenset(
    {
        "not_json",
        "body_too_large",
        "malformed_json",
        "path_not_found",
        "unsupported_type",
        "header_absent",
        "ambiguous_header",
        "unsafe_value",
        "step_not_executed",
    }
)

#: Closed vocabulary for the write-effect property added to a write step's
#: finding by the victim read that follows it.
WRITE_EFFECT_STATES: frozenset[str] = frozenset(
    {"effect_observed", "no_effect_observed", "not_verified"}
)

#: Closed vocabulary for a sequence's ``abort_reason`` in the run document.
#: ``_SequenceRun._abort`` refuses anything else, so the set cannot go stale.
ABORT_REASONS: frozenset[str] = frozenset(
    {
        "setup_failed",
        "capture_missed",
        "execution_error",
        "path_invalid",
        "marker_reflection_blocked",
        "marker_check_incomplete",
        "step_inconclusive",
        "session_not_live",
        "response_from_cache",
    }
)

#: ``run_id`` is a reserved interpolation name, so it can never be a capture.
RESERVED_NAMES: frozenset[str] = frozenset({"run_id"})

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MARKER_PREFIX = "marker:"

#: Extractor grammar, §3.1 of the design contract, complete and normative.
#: There is deliberately no regex source and no transform: a regex over a
#: response body is an unreviewable mini-language in a config whose
#: reviewability is the product's premise, it is the one extractor form where an
#: attacker-influenced body steers WHICH bytes enter a later authenticated
#: request, and ``re`` on attacker-controlled input is a backtracking DoS in the
#: CI runner.
_HEADER_REF = re.compile(r"^header:([!#$%&'*+\-.^_`|~0-9A-Za-z]+)$")
_JSON_SEGMENT = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]*)|\[(0|[1-9][0-9]*)\]")

#: Both remediation strings live in ``core`` beside the other rules', so the
#: SARIF rule help and the finding-level text can never diverge.
_SEQ_REMEDIATION: str = core._SEQUENCE_REMEDIATION
_EFFECT_REMEDIATION: str = core._EFFECT_REMEDIATION


class _Malformed(Exception):
    """A ``${...}`` token that matches no legal form."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class _PathInvalid(Exception):
    """A path that is only invalid once a captured value is substituted.

    ``reason`` is drawn from :data:`PATH_INVALID_REASONS` and is the only part
    of this exception any caller may put in a persisted message: the ``str`` of
    a wrapped :class:`ConfigError` can quote the resolved path, and the resolved
    path can contain a captured value.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


#: Closed vocabulary for why a resolved path was refused, and the operator-
#: facing sentence for each. Constants: no part of either is built from a
#: captured value or from anything the target sent.
_PATH_INVALID_MESSAGES: dict[str, str] = {
    "cross_origin": (
        "the interpolated path resolved to a different origin, so this step "
        "was not issued"
    ),
    "fragment": (
        "the interpolated path carried a URL fragment, so this step was not "
        "issued"
    ),
    "outside_base_path": (
        "the interpolated path resolved to a URL outside the base URL's path, "
        "so this step was not issued"
    ),
    "dot_segment": (
        "the interpolated path contained a '.' or '..' segment, which URL "
        "normalization would resolve to a DIFFERENT endpoint than the one this "
        "step declares, so this step was not issued"
    ),
    "not_absolute": (
        "the interpolated path is not a valid same-origin absolute path"
    ),
}
PATH_INVALID_REASONS: frozenset[str] = frozenset(_PATH_INVALID_MESSAGES)


class _MarkerReflected(Exception):
    """A captured value carrying a configured marker reached a request."""

    def __init__(self, owner: str, capture: str) -> None:
        super().__init__(owner)
        self.owner = owner
        self.capture = capture


class _MarkerUncheckable(Exception):
    """A captured value decoded past the variant cap, so it could not be shown
    free of a configured marker. ``capture`` names it once known."""

    def __init__(self, capture: str = "") -> None:
        super().__init__(capture)
        self.capture = capture


# --------------------------------------------------------------------------
# Interpolation
# --------------------------------------------------------------------------


def scan_tokens(text: str) -> list[tuple[str, str]]:
    """Return every ``${...}`` token in ``text`` as ``(kind, name)``.

    ``kind`` is ``"var"`` (a capture name or ``run_id``) or ``"marker"``.
    Raises :class:`_Malformed` on a bare ``${``, on ``${}``, and on anything
    whose contents match neither a config identifier nor ``marker:X``. Failing
    the load is the only safe direction: the alternative is a request carrying a
    literal ``${`` to the target, which is not the request the operator wrote.
    """
    tokens: list[tuple[str, str]] = []
    index = 0
    while True:
        start = text.find("${", index)
        if start < 0:
            return tokens
        end = text.find("}", start + 2)
        if end < 0:
            raise _Malformed("${")
        inner = text[start + 2 : end]
        if _NAME.fullmatch(inner):
            tokens.append(("var", inner))
        elif inner.startswith(_MARKER_PREFIX) and len(inner) > len(_MARKER_PREFIX):
            tokens.append(("marker", inner[len(_MARKER_PREFIX) :]))
        else:
            raise _Malformed(text[start : end + 1])
        index = end + 1


def sole_token(text: str) -> tuple[str, str] | None:
    """Return the token when ``text`` is exactly one token and nothing else."""
    if not text.startswith("${") or not text.endswith("}"):
        return None
    try:
        tokens = scan_tokens(text)
    except _Malformed:
        return None
    if len(tokens) != 1:
        return None
    # "${a}${b}" ends with '}' and starts with '${' but is two tokens; the
    # length check above already rejected it. "${a}x${b}" likewise.
    kind, name = tokens[0]
    rendered = "${" + (f"{_MARKER_PREFIX}{name}" if kind == "marker" else name) + "}"
    return tokens[0] if rendered == text else None


def _starts_with_var(text: str) -> bool:
    """True when ``text`` begins with a ``${var}`` capture token at index 0.

    A capture whose value is an origin-root path (``/api/notes/n1``) carries
    the base prefix. When such a capture sits at the START of a step path, the
    resolved path begins with that prefix and ``core`` would join it under the
    base path again -- the doubling the sole-token re-expression already undoes.
    A marker token (``${marker:x}``) is a sentinel, not a path, so it does not
    count; nor does a literal prefix (``/fixed/${id}``), whose leading ``/`` is
    the operator's own base-relative path, not a captured one.
    """
    if not text.startswith("${"):
        return False
    end = text.find("}", 2)
    if end < 0:
        return False
    return _NAME.fullmatch(text[2:end]) is not None


def substitute(
    text: str,
    values: Mapping[str, Any],
    run_id: str,
    markers: Mapping[str, str],
) -> str:
    """Textually substitute every token in ``text``.

    Only ever called after load-time validation has proved every name resolves,
    so a ``KeyError`` here would be a bug in the validator rather than a config
    error.
    """
    parts: list[str] = []
    index = 0
    while True:
        start = text.find("${", index)
        if start < 0:
            parts.append(text[index:])
            return "".join(parts)
        end = text.find("}", start + 2)
        parts.append(text[index:start])
        inner = text[start + 2 : end]
        if inner == "run_id":
            parts.append(run_id)
        elif inner.startswith(_MARKER_PREFIX):
            parts.append(markers[inner[len(_MARKER_PREFIX) :]])
        else:
            parts.append(str(values[inner]))
        index = end + 1


def substitute_json(
    node: Any,
    values: Mapping[str, Any],
    run_id: str,
    markers: Mapping[str, str],
) -> Any:
    """Substitute into a JSON body, preserving one typing rule and no others.

    A JSON string value that is exactly one capture token keeps the type the
    value was captured with, so ``{"invoice_id": "${invoice_id}"}`` works
    against an API that requires an integer. Anything else is textual. Object
    keys are never interpolated -- validated at load, so nothing reaches here.
    """
    if isinstance(node, str):
        token = sole_token(node)
        if token is not None and token[0] == "var" and token[1] != "run_id":
            return values[token[1]]
        return substitute(node, values, run_id, markers)
    if isinstance(node, list):
        return [substitute_json(item, values, run_id, markers) for item in node]
    if isinstance(node, dict):
        return {
            key: substitute_json(item, values, run_id, markers)
            for key, item in node.items()
        }
    return node


def redact_captures(text: Any, values: Mapping[str, Any]) -> Any:
    """Replace every live captured value in ``text`` with ``${<name>}``.

    Defence in depth behind the rule that resolved values are never placed in a
    persisted field in the first place. Longest value first, so a value that is
    a substring of another is not partially masked. Values shorter than four
    characters are skipped: a captured ``"7"`` would otherwise redact every 7 in
    a URL and make the document less readable without making it safer.
    """
    if not isinstance(text, str) or not text or not values:
        return text
    ordered = sorted(values.items(), key=lambda pair: len(str(pair[1])), reverse=True)
    for name, value in ordered:
        literal = str(value)
        if len(literal) < 4:
            continue
        text = text.replace(literal, "${" + name + "}")
    return text


# --------------------------------------------------------------------------
# Extractor
# --------------------------------------------------------------------------


def parse_extractor(expression: Any) -> tuple[str, Any]:
    """Parse one extractor. Returns ``("header", name)`` or ``("json", segs)``.

    Raises :class:`ValueError` on anything the §3.1 grammar does not accept.
    Every rejection happens at config load, quoting the offending expression.
    """
    if not isinstance(expression, str) or not expression:
        raise ValueError("extractor must be a non-empty string")
    header = _HEADER_REF.match(expression)
    if header is not None:
        return "header", header.group(1)
    if expression.startswith("header:"):
        raise ValueError("header extractor requires a field name")
    if not expression.startswith("$") or len(expression) == 1:
        raise ValueError("extractor must be a JSON path or a header reference")
    rest = expression[1:]
    segments: list[tuple[str, Any]] = []
    position = 0
    while position < len(rest):
        match = _JSON_SEGMENT.match(rest, position)
        if match is None:
            raise ValueError("extractor is not a legal JSON path")
        if match.group(1) is not None:
            segments.append(("key", match.group(1)))
        else:
            segments.append(("index", int(match.group(2))))
        position = match.end()
    if not segments:
        raise ValueError("extractor is not a legal JSON path")
    return "json", segments


def _media_type(headers: _Sequence[tuple[str, str]]) -> str:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def resolve_extractor(
    expression: str, sink: Mapping[str, Any]
) -> tuple[Any, str | None]:
    """Apply one extractor to one response, in memory. ``(value, miss_reason)``.

    Reads the bytes ``_scan_response`` already retained for hashing; no new
    retention is introduced and the buffer is dropped by the caller on the same
    line it is dropped on today.
    """
    kind, spec = parse_extractor(expression)
    if kind == "header":
        matches = [
            value
            for name, value in sink.get("headers", ())
            if name.lower() == spec.lower()
        ]
        if not matches:
            return None, "header_absent"
        if len(set(matches)) > 1:
            # Two different values for one field name: which one the target
            # meant is unknowable, and guessing sends an authenticated request
            # somewhere the operator did not write down.
            return None, "ambiguous_header"
        value: Any = matches[0]
    else:
        media = _media_type(sink.get("headers", ()))
        if not (media == "application/json" or media.endswith("+json")):
            return None, "not_json"
        if sink.get("body_truncated"):
            # A partial JSON document is not a document.
            return None, "body_too_large"
        try:
            document = json.loads(sink.get("body") or b"")
        except (ValueError, UnicodeDecodeError):
            return None, "malformed_json"
        node: Any = document
        for segment_kind, segment in spec:
            if segment_kind == "key":
                if not isinstance(node, dict) or segment not in node:
                    return None, "path_not_found"
                node = node[segment]
            else:
                if not isinstance(node, list) or segment >= len(node):
                    return None, "path_not_found"
                node = node[segment]
        if isinstance(node, bool) or not isinstance(node, (str, int)):
            # float is excluded because its textual form is ambiguous and a
            # float object id is always a mistake; bool and null are excluded
            # because they interpolate into something that LOOKS like an
            # identifier and is not.
            return None, "unsupported_type"
        value = node
    text = value if isinstance(value, str) else str(value)
    if not 1 <= len(text) <= MAX_CAPTURE_VALUE_CHARS:
        return None, "unsafe_value"
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in text):
        # Request-splitting control: this value goes onto the wire in a URL path
        # or a header value, where a '\r' is a second request.
        return None, "unsafe_value"
    if not text.isascii():
        # Same reason, one step further out: http.client encodes the request
        # line as ASCII and header values as latin-1, so a target that answers
        # with a non-ASCII id used to raise UnicodeEncodeError from inside the
        # opener and terminate the whole run with a traceback and no run
        # document. A capture miss aborts this sequence and nothing else.
        return None, "unsafe_value"
    return value, None


# --------------------------------------------------------------------------
# Load-time validation
# --------------------------------------------------------------------------


def deferred_capture_names(raw_sequences: Any) -> frozenset[str]:
    """Names ``_expand_environment`` must leave verbatim inside ``sequences``.

    Read from the UNEXPANDED document, because ``_ENV_PATTERN`` matches
    ``${invoice_id}`` exactly and would otherwise fail every capture reference
    with "environment variable 'invoice_id' is not set". Deliberately tolerant
    of a malformed document: real validation runs later and must produce its own
    message rather than a confusing expansion error.
    """
    import os

    names: set[str] = set(RESERVED_NAMES)
    if isinstance(raw_sequences, list):
        for sequence in raw_sequences:
            if not isinstance(sequence, dict):
                continue
            steps = sequence.get("steps")
            # Tolerant, as the docstring says -- a number here raised
            # TypeError before validation could name it (exit 70, measured).
            for step in steps if isinstance(steps, list) else ():
                if not isinstance(step, dict):
                    continue
                capture = step.get("capture")
                if not isinstance(capture, dict):
                    continue
                for name in capture:
                    if isinstance(name, str):
                        names.add(name)
    for name in sorted(names):
        if name in os.environ:
            # The two namespaces can never silently overlap: an operator who
            # exported INVOICE_ID for an unrelated reason must not have their
            # capture reference quietly resolved from the environment.
            raise ConfigError(
                f"capture name {quoted(name)} collides with an environment variable "
                "of the same name; rename the capture"
            )
    return frozenset(names)


def _fail(sequence_id: str, message: str) -> None:
    raise ConfigError(f"sequence {quoted(sequence_id)} {message}")


def _validate_statuses(sequence_id: str, label: str, expect: dict[str, Any]) -> None:
    statuses = expect.get("status")
    if isinstance(statuses, int) and not isinstance(statuses, bool):
        statuses = [statuses]
        expect["status"] = statuses
    if (
        not isinstance(statuses, list)
        or not statuses
        or not all(
            isinstance(status, int)
            and not isinstance(status, bool)
            and 100 <= status <= 599
            for status in statuses
        )
    ):
        _fail(sequence_id, f"{label} requires HTTP status values")


def _validate_step_request(
    sequence_id: str, label: str, request: Any
) -> None:
    if not isinstance(request, dict):
        _fail(sequence_id, f"{label} requires a request object")
    path = request.get("path")
    probe = dict(request)
    if isinstance(path, str) and path.startswith("${"):
        # §9.4 rule 9: a path that BEGINS with an interpolation token cannot
        # satisfy the leading-'/' rule statically. Every other path rule still
        # applies here, and the leading-'/' rule is enforced at runtime against
        # the resolved path (§3.3) before a single byte reaches the wire.
        probe["path"] = "/" + path
    core._validate_request(probe, f"sequence {quoted(sequence_id)} {label}")


def _validate_marker_expectation(
    sequence_id: str,
    label: str,
    expect: dict[str, Any],
    step_identity: str,
    identities: Mapping[str, Any],
    markers: Mapping[str, str],
) -> None:
    """The check-level marker rules, minus the same-check-control requirement.

    A control is a same-check concept and is structurally unreachable for a
    step, so licensing is resolved at runtime per §7.5 and fails closed to
    ``VERIDOR-ORACLE-001``. Everything else -- both-keys, unknown identity,
    identity with no marker, excluding your own marker -- is unchanged.
    """
    suspicious = core._suspicious_keys(
        sorted(set(expect) - core._MARKER_EXPECT_KEYS), core._MARKER_EXPECT_KEYS
    )
    if suspicious:
        _fail(
            sequence_id,
            f"{label} has unsupported keys: {core.terminal_names(suspicious)} (did you "
            f"mean one of {', '.join(sorted(core._MARKER_EXPECT_KEYS))}?) "
            + core._annotation_way_out(suspicious),
        )
    contains = expect.get("contains_marker")
    excludes = expect.get("excludes_marker")
    if contains is not None and excludes is not None:
        _fail(sequence_id, f"{label} cannot set both contains_marker and excludes_marker")
    for field, owner in (("contains_marker", contains), ("excludes_marker", excludes)):
        if owner is None:
            continue
        if not isinstance(owner, str) or not owner:
            _fail(sequence_id, f"{label} {field} must name an identity")
        if owner not in identities:
            _fail(sequence_id, f"{label} {field} references unknown identity {quoted(owner)}")
        if owner not in markers:
            _fail(
                sequence_id,
                f"{label} {field} references identity {quoted(owner)}, which defines no "
                f"'marker' field.{core._MARKER_HINT}",
            )
    if excludes is not None and excludes == step_identity:
        _fail(
            sequence_id,
            f"{label} cannot exclude its own marker; excludes_marker names the "
            "identity whose data must not appear",
        )


def _body_strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, list):
        return [item for element in node for item in _body_strings(element)]
    if isinstance(node, dict):
        return [item for element in node.values() for item in _body_strings(element)]
    return []


def _object_keys(node: Any) -> list[str]:
    if isinstance(node, list):
        return [key for element in node for key in _object_keys(element)]
    if isinstance(node, dict):
        keys = [key for key in node if isinstance(key, str)]
        for element in node.values():
            keys.extend(_object_keys(element))
        return keys
    return []


def _entry_surfaces(
    sequence_id: str, label: str, request: dict[str, Any]
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Return ``(path_tokens, header_tokens, body_tokens)`` for one request."""

    def scan(text: str, where: str) -> list[tuple[str, str]]:
        try:
            return scan_tokens(text)
        except _Malformed as exc:
            _fail(
                sequence_id,
                f"{label} contains a malformed interpolation in the {where}: "
                f"{quoted(exc.token)}",
            )
            raise  # pragma: no cover - _fail always raises

    path = request.get("path")
    path_tokens = scan(path, "path") if isinstance(path, str) else []
    header_tokens: list[tuple[str, str]] = []
    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        # The same refusal core._validate_request gives after this scan. Without
        # it dict() crashed on a string, number or list: exit 70, not exit 2.
        _fail(sequence_id, f"{label}.headers must be an object")
    for name, value in headers.items():
        if isinstance(name, str) and "${" in name:
            # Interpolating a header NAME has no use case, and a name is routed
            # and logged rather than stored. Refusing it keeps the surface small
            # and cannot cost a true finding.
            _fail(sequence_id, f"{label} cannot interpolate a header name")
        if isinstance(value, str):
            header_tokens.extend(scan(value, "header value"))
    body_tokens: list[tuple[str, str]] = []
    if "json" in request:
        for key in _object_keys(request["json"]):
            if "${" in key:
                _fail(sequence_id, f"{label} cannot interpolate an object key")
        for text in _body_strings(request["json"]):
            body_tokens.extend(scan(text, "body"))
    elif isinstance(request.get("body"), str):
        body_tokens.extend(scan(request["body"], "body"))
    return path_tokens, header_tokens, body_tokens


def _validate_capture(
    sequence_id: str,
    index: int,
    step: dict[str, Any],
) -> list[str]:
    capture = step.get("capture")
    if capture is None:
        return []
    if not isinstance(capture, dict):
        _fail(sequence_id, f"step {index} capture must be an object")
    if len(capture) > MAX_CAPTURES_PER_STEP:
        _fail(
            sequence_id,
            f"step {index} declares {len(capture)} captures; the limit is "
            f"{MAX_CAPTURES_PER_STEP}",
        )
    names: list[str] = []
    for name, expression in capture.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            _fail(sequence_id, f"step {index} capture name {quoted(name)} is not an identifier")
        if name in RESERVED_NAMES:
            _fail(sequence_id, f"step {index} capture name {quoted(name)} is reserved")
        try:
            parse_extractor(expression)
        except ValueError:
            _fail(
                sequence_id,
                f"step {index} capture {quoted(name)} is not a valid extractor: "
                f"{quoted(expression)}",
            )
        names.append(name)
    return names


def _validate_markers_absent(
    markers: Mapping[str, str],
    identities: Mapping[str, Any],
    sequences: list[dict[str, Any]],
    base_url: Any,
) -> None:
    """Reflection guard over sequences, using the identical decode machinery.

    The surface inspected is the config TEMPLATE, where a sanctioned plant is
    the seven-plus characters ``${marker:owner}`` and the marker literal does not
    appear at all. So a marker LITERAL anywhere in a sequence is still a hard
    load error: someone who pastes the literal instead of using the token gets
    stopped, and the only route by which a marker reaches the wire from a
    sequence is the sanctioned token.
    """
    if not markers:
        return
    identity_surface = [
        str(item)
        for identity in identities.values()
        for pair in dict(identity.get("headers", {}) or {}).items()
        for item in pair
    ]
    for sequence in sequences:
        entries: list[tuple[str, int, dict[str, Any]]] = [
            ("step", index, step["request"])
            for index, step in enumerate(sequence["steps"])
        ]
        entries.extend(
            ("teardown entry", index, entry["request"])
            for index, entry in enumerate(sequence.get("teardown") or ())
        )
        for kind, index, request in entries:
            name, complete = core._surface_marker_owner(
                core._request_surface(
                    request, base_url=base_url, extra=identity_surface
                ),
                markers,
            )
            if name is not None:
                raise ConfigError(
                    f"identity {quoted(name)} marker appears in the request sent by "
                    f"sequence {quoted(sequence['id'])} {kind} {index}; a reflected "
                    "marker cannot prove a leak"
                )
            if not complete:
                # Held to the send-time rule: a decode that stopped at the cap
                # is not "no marker". This loaded such a request, and only a
                # captured value was refused at the cap.
                raise core._marker_check_incomplete(
                    f"the request sent by sequence {quoted(sequence['id'])} "
                    f"{kind} {index}"
                )


def validate_sequences(
    sequences: Any,
    identities: Mapping[str, Any],
    markers: Mapping[str, str],
    taken_ids: set[str],
    base_url: Any,
) -> list[dict[str, Any]]:
    """Validate the ``sequences`` block. Every failure is exit 2 at load time."""
    if not isinstance(sequences, list) or not all(
        isinstance(item, dict) for item in sequences
    ):
        raise ConfigError("sequences must be a list of objects")
    if len(sequences) > MAX_SEQUENCES:
        raise ConfigError(
            f"sequences declares {len(sequences)} entries; the limit is {MAX_SEQUENCES}"
        )
    for sequence in sequences:
        sequence_id = sequence.get("id")
        if not isinstance(sequence_id, str) or not sequence_id:
            raise ConfigError("each sequence requires a non-empty id")
        # A sequence id reaches the same console line and the same fingerprint
        # as a check id, so it is held to the same charset. See core._SAFE_NAME.
        core._validate_safe_name(sequence_id, "a sequence id")
        if sequence_id in taken_ids:
            raise ConfigError(f"duplicate id: {sequence_id}")
        taken_ids.add(sequence_id)
        suspicious = core._suspicious_keys(
            sorted(set(sequence) - SEQUENCE_KEYS), SEQUENCE_KEYS
        )
        if suspicious:
            _fail(
                sequence_id,
                f"has unsupported keys: {core.terminal_names(suspicious)} (did you mean one "
                f"of {', '.join(sorted(SEQUENCE_KEYS))}?) "
                + core._annotation_way_out(suspicious),
            )
        steps = sequence.get("steps")
        if not isinstance(steps, list) or not steps:
            _fail(sequence_id, "requires a non-empty steps list")
        if len(steps) > MAX_STEPS:
            _fail(
                sequence_id,
                f"declares {len(steps)} steps; the limit is {MAX_STEPS}",
            )
        teardown = sequence.get("teardown")
        if teardown is not None and not isinstance(teardown, list):
            _fail(sequence_id, "teardown must be a list")
        if teardown is not None and len(teardown) > MAX_TEARDOWN:
            _fail(
                sequence_id,
                f"declares {len(teardown)} teardown entries; the limit is "
                f"{MAX_TEARDOWN}",
            )
        _validate_steps(sequence_id, steps, identities, markers)
        _validate_teardown(sequence_id, steps, teardown or [], identities)
    _validate_markers_absent(markers, identities, sequences, base_url)
    return sequences


def _validate_steps(
    sequence_id: str,
    steps: list[Any],
    identities: Mapping[str, Any],
    markers: Mapping[str, str],
) -> None:
    #: Which step index first defines each capture name, for the
    #: forward-reference and single-assignment messages.
    definition_step: dict[str, int] = {}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            _fail(sequence_id, f"step {index} must be an object")
        capture = step.get("capture")
        if isinstance(capture, dict):
            for name in capture:
                if isinstance(name, str) and name not in definition_step:
                    definition_step[name] = index

    defined: set[str] = set(RESERVED_NAMES)
    for index, step in enumerate(steps):
        label = f"step {index}"
        suspicious = core._suspicious_keys(sorted(set(step) - STEP_KEYS), STEP_KEYS)
        if suspicious:
            _fail(
                sequence_id,
                f"{label} has unsupported keys: {core.terminal_names(suspicious)} (did you "
                f"mean one of {', '.join(sorted(STEP_KEYS))}?) "
                + core._annotation_way_out(suspicious),
            )
        role = step.get("role")
        # isinstance first: a list or an object is unhashable, and `in`
        # raised TypeError, exit 70 (measured).
        if not isinstance(role, str) or role not in ROLES:
            # Required with no default because BOTH defaults are wrong.
            # Defaulting to 'setup' turns a forgotten role on the attacker probe
            # into scaffolding -- a green run with the boundary never tested.
            # Defaulting to 'assert' reports a 500 on a provisioning POST as
            # 'vulnerable'. Silent under-testing and false positives are both
            # unacceptable, so the operator states it.
            _fail(sequence_id, f"{label} requires role 'setup' or 'assert'")
        identity = step.get("as")
        if not isinstance(identity, str) or identity not in identities:
            _fail(
                sequence_id,
                f"{label} 'as' references unknown identity {quoted(identity)}",
            )
        if not isinstance(step.get("request"), dict):
            _fail(sequence_id, f"{label} requires a request object")
        core._refuse_near_miss_request_keys(
            step["request"], core._REQUEST_KEYS, f"sequence {quoted(sequence_id)} {label} request"
        )
        # Interpolation is scanned BEFORE the path rules, so an operator who
        # typed '${' gets told that rather than being told their path is not
        # same-origin -- which is true but useless.
        path_tokens, header_tokens, body_tokens = _entry_surfaces(
            sequence_id, label, step["request"]
        )
        _validate_step_request(sequence_id, label, step.get("request"))
        expect = step.get("expect")
        if not isinstance(expect, dict):
            _fail(sequence_id, f"{label} requires an expect object")
        _validate_statuses(sequence_id, label, expect)
        _validate_marker_expectation(
            sequence_id, label, expect, identity, identities, markers
        )

        total = len(path_tokens) + len(header_tokens) + len(body_tokens)
        if total > MAX_INTERPOLATIONS_PER_STEP:
            _fail(
                sequence_id,
                f"{label} has {total} interpolation sites; the limit is "
                f"{MAX_INTERPOLATIONS_PER_STEP}",
            )
        for kind, name in path_tokens + header_tokens:
            if kind == "marker":
                _fail(
                    sequence_id,
                    f"{label} may only plant a marker in a request body; "
                    "a marker in a path or header is routed and logged, never "
                    "stored, and is exactly what a reflector echoes back",
                )
        for kind, name in header_tokens:
            if name == "run_id":
                _fail(sequence_id, f"{label} cannot interpolate ${{run_id}} into a header")
        planted = [name for kind, name in body_tokens if kind == "marker"]
        for owner in planted:
            if role != "setup":
                _fail(
                    sequence_id,
                    f"{label} may only plant a marker on a 'setup' step",
                )
            if owner != identity:
                _fail(
                    sequence_id,
                    f"{label} may only plant its own marker; it runs as "
                    f"{quoted(identity)} and plants {quoted(owner)}",
                )
            if owner not in identities:
                _fail(
                    sequence_id,
                    f"{label} plants a marker for unknown identity {quoted(owner)}",
                )
            if owner not in markers:
                _fail(
                    sequence_id,
                    f"{label} plants a marker for identity {quoted(owner)}, which "
                    f"defines no 'marker' field.{core._MARKER_HINT}",
                )
        if planted and (
            expect.get("contains_marker") or expect.get("excludes_marker")
        ):
            # A planting step is executed with needles=None (§7.3), so a marker
            # expectation on it would read as a control and could never be
            # satisfied. Refuse the combination rather than emit a permanent
            # ORACLE-001.
            _fail(
                sequence_id,
                f"{label} plants a marker and cannot also declare "
                "contains_marker or excludes_marker; a planting step's response "
                "is never scanned",
            )
        for kind, name in path_tokens + header_tokens + body_tokens:
            if kind != "var" or name in defined:
                continue
            later = definition_step.get(name)
            if later is not None:
                _fail(
                    sequence_id,
                    f"{label} references '${{{name}}}', which no earlier step "
                    f"captures; it is captured by step {later}, which runs later",
                )
            _fail(
                sequence_id,
                f"{label} references '${{{name}}}', which no earlier step captures",
            )
        for name in _validate_capture(sequence_id, index, step):
            if name in defined:
                first = definition_step.get(name, index)
                _fail(
                    sequence_id,
                    f"capture {quoted(name)} is defined by step {first} and step "
                    f"{index}; capture names are single-assignment within a "
                    "sequence",
                )
            defined.add(name)


def _validate_teardown(
    sequence_id: str,
    steps: list[dict[str, Any]],
    teardown: list[Any],
    identities: Mapping[str, Any],
) -> None:
    available = set(RESERVED_NAMES)
    for step in steps:
        capture = step.get("capture")
        if isinstance(capture, dict):
            available.update(name for name in capture if isinstance(name, str))
    for index, entry in enumerate(teardown):
        label = f"teardown entry {index}"
        if not isinstance(entry, dict):
            _fail(sequence_id, f"{label} must be an object")
        for banned in ("role", "capture", "contains_marker", "excludes_marker"):
            if banned in entry:
                _fail(sequence_id, f"teardown entries cannot declare {quoted(banned)}")
        suspicious = core._suspicious_keys(
            sorted(set(entry) - TEARDOWN_KEYS), TEARDOWN_KEYS
        )
        if suspicious:
            _fail(
                sequence_id,
                f"{label} has unsupported keys: {core.terminal_names(suspicious)} (did you "
                f"mean one of {', '.join(sorted(TEARDOWN_KEYS))}?) "
                + core._annotation_way_out(suspicious),
            )
        identity = entry.get("as")
        if not isinstance(identity, str) or identity not in identities:
            _fail(
                sequence_id,
                f"{label} 'as' references unknown identity {quoted(identity)}",
            )
        if not isinstance(entry.get("request"), dict):
            _fail(sequence_id, f"{label} requires a request object")
        core._refuse_near_miss_request_keys(
            entry["request"], core._REQUEST_KEYS, f"sequence {quoted(sequence_id)} {label} request"
        )
        path_tokens, header_tokens, body_tokens = _entry_surfaces(
            sequence_id, label, entry["request"]
        )
        _validate_step_request(sequence_id, label, entry.get("request"))
        expect = entry.get("expect")
        if expect is not None:
            if not isinstance(expect, dict):
                _fail(sequence_id, f"{label} expect must be an object")
            for banned in ("contains_marker", "excludes_marker"):
                if banned in expect:
                    _fail(sequence_id, f"teardown entries cannot declare {quoted(banned)}")
            _validate_statuses(sequence_id, label, expect)
        total = len(path_tokens) + len(header_tokens) + len(body_tokens)
        if total > MAX_INTERPOLATIONS_PER_STEP:
            _fail(
                sequence_id,
                f"{label} has {total} interpolation sites; the limit is "
                f"{MAX_INTERPOLATIONS_PER_STEP}",
            )
        for kind, name in path_tokens + header_tokens + body_tokens:
            if kind == "marker":
                _fail(sequence_id, f"{label} cannot plant a marker")
            if name not in available:
                _fail(
                    sequence_id,
                    f"{label} references '${{{name}}}', which no step captures",
                )
        for kind, name in header_tokens:
            if name == "run_id":
                _fail(sequence_id, f"{label} cannot interpolate ${{run_id}} into a header")


# --------------------------------------------------------------------------
# Session state: cookie jars, credential captures, injection
#
# The one failure this whole section exists to prevent: a cookie jar that leaks
# across identities turns the attacker's probe into the owner's probe, which
# gets the status the declaration allows for the owner -- or, symmetrically, a
# lost session turns it into an anonymous probe, which gets a 401 that matches a
# declared denial. BOTH directions manufacture a SAFE verdict over a live
# vulnerability. Every rule below that reads as paranoid is paying for that.
#
# Corollary that drives the rest: degraded state is never allowed to look like a
# result. A session that is not provably established makes every probe that
# depends on it `inconclusive`, never `safe`.
# --------------------------------------------------------------------------

#: At most this many cookie NAMES are listed in the run document.
MAX_RECORDED_COOKIE_NAMES: int = 16
MAX_CAPTURE_VALUE_BYTES: int = 4096
MAX_JSON_CAPTURE_BYTES: int = 1024 * 1024
MAX_HTML_CAPTURE_BYTES: int = 256 * 1024
MAX_JSON_POINTER_DEPTH: int = 16

#: Defence in depth against a target that smuggles data into the name position
#: of a cookie, which is the one half of a cookie we do record.
_COOKIE_NAME_SAFE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
REDACTED_COOKIE_NAME: str = "[REDACTED_NAME]"

#: A cookie parse error can embed the cookie, so cookie-handling failures never
#: contribute their own message -- the same rule ``_safe_error`` already applies
#: to response bytes, extended to the request side.
COOKIE_ERROR: str = "the server sent a cookie Veridor could not process"

#: Closed vocabulary for why a session failed. Constants, never derived from
#: anything the server sent.
#: Failure reasons a retry could plausibly clear: nothing was answered, so
#: nothing was decided.
TRANSIENT_SESSION_REASONS: frozenset[str] = frozenset({"login_transport_error"})

#: Login statuses that describe the target's HEALTH rather than the credential.
#: Everything else it answered with -- 400, 401, 403, 422 -- is the target
#: reading the credential and refusing it, and it will refuse identically on
#: the next run.
TRANSIENT_LOGIN_STATUSES: frozenset[int] = frozenset({408, 425, 429})


def is_transient_session_failure(reason_code: str, status: int | None) -> bool:
    """Could re-running plausibly establish this session?

    The distinction the gate turns on. A 401 on login is DETERMINISTIC -- the
    target read the credential and said no, and it will say no tomorrow -- so a
    run in which that identity was never authenticated tested nothing about any
    boundary involving it, and must not be green. A 429 on login is transient
    and must not gate, for the same reason a 429 on a probe does not.
    """
    if reason_code in TRANSIENT_SESSION_REASONS:
        return True
    if status is None:
        return False
    return status in TRANSIENT_LOGIN_STATUSES or 500 <= status <= 599


SESSION_FAILURE_REASONS: frozenset[str] = frozenset(
    {
        "login_transport_error",
        "login_status_mismatch",
        "login_capture_failed",
        "login_blocked",
        "not_established",
    }
)


class _SameOriginCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Accept and return cookies for exactly one host. Nothing else, ever.

    ``http.cookiejar`` does the PARSING -- ``Expires`` values contain commas, so
    folded headers cannot be split on one; ``Max-Age`` beats ``Expires``; path
    matching is prefix-with-boundary, not ``startswith``; ``HttpOnly`` must not
    change transmission. Every one of those is a bug we would get wrong in the
    same direction: a dropped cookie means the probe runs unauthenticated, is
    denied, and matches a declared denial. We do not get to write that parser
    and be sure.

    The POLICY is ours. Every request Veridor issues is already same-origin and
    redirects are never followed, so the host check can never change behaviour
    today; it exists so that a future code path which builds a URL some other
    way cannot silently start shipping session cookies somewhere new.
    """

    def __init__(self, host: str) -> None:
        super().__init__(
            rfc2965=False,
            hide_cookie2=True,
            strict_ns_domain=http.cookiejar.DefaultCookiePolicy.DomainStrict,
        )
        self.target_host = (host or "").lower()

    def _is_target(self, request: Any) -> bool:
        try:
            return http.cookiejar.request_host(request).lower() == self.target_host
        except Exception:  # pragma: no cover - defensive; request shape is ours
            return False

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return self._is_target(request) and super().set_ok(cookie, request)

    def return_ok(self, cookie: Any, request: Any) -> bool:
        return self._is_target(request) and super().return_ok(cookie, request)


class _MetaContent(HTMLParser):
    """First ``<meta name="X" content="Y">`` wins.

    A parser rather than a regex because a regex over HTML captures the wrong
    tag, and the wrong tag here is a token that goes onto the wire inside an
    authenticated request.
    """

    def __init__(self, wanted: str) -> None:
        super().__init__(convert_charrefs=True)
        self.wanted = wanted.lower()
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta" or self.value is not None:
            return
        mapping = {name.lower(): (value or "") for name, value in attrs}
        if mapping.get("name", "").lower() == self.wanted:
            self.value = mapping.get("content")


def _html_meta(body: bytes, name: str) -> str | None:
    parser = _MetaContent(name)
    try:
        parser.feed(body[:MAX_HTML_CAPTURE_BYTES].decode("utf-8", "replace"))
        parser.close()
    except Exception:
        return None
    return parser.value


def _json_pointer(body: bytes, pointer: str) -> str | None:
    """RFC 6901, bounded. Only a string, number, or boolean leaf resolves."""
    if len(body) > MAX_JSON_CAPTURE_BYTES:
        return None
    try:
        node: Any = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    segments = pointer.split("/")[1:]
    if len(segments) > MAX_JSON_POINTER_DEPTH:
        return None
    for segment in segments:
        key = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if key not in node:
                return None
            node = node[key]
        elif isinstance(node, list):
            if not key.isdigit() or int(key) >= len(node):
                return None
            node = node[int(key)]
        else:
            return None
    if isinstance(node, bool):
        return "true" if node else "false"
    if isinstance(node, str):
        return node
    if isinstance(node, (int, float)):
        return str(node)
    # An object or an array leaf is a capture failure: it interpolates into
    # something that looks like a token and is not.
    return None


_FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


def _inject_field_label(entry: Mapping[str, Any]) -> str:
    """Name the body field an inject entry declares, for a dropped-field note.

    Only the ``form_field`` and ``json_field`` kinds can fail to apply; a
    ``header`` always has a slot, so it never reaches this.
    """
    if "form_field" in entry:
        return f"form_field {quoted(entry['form_field'])}"
    return f"json_field {quoted(entry['json_field'])}"


def _marker_owner(value: str, markers: Mapping[str, str]) -> str | None:
    """The owner whose marker ``value`` carries, plain or encoded, else None.

    The send-time half of the load-time reflection guard, and held to the same
    rule: every surface is closed over ``core._decode_variants`` first. A plain
    substring test let a capture holding the marker base64-, percent- or
    \\u-encoded onto the wire, and a target that decodes and echoes its input
    turned a correct API into a confirmed VERIDOR-LEAK-001. The raw value is
    tested too, because ``_decode_variants`` reads a bounded prefix.

    Raises :class:`_MarkerUncheckable` when no marker was found but the
    variant cap dropped a decoding: "no marker" would be a claim about
    decodings nobody looked at.
    """
    variants, complete = core._decode_variants_checked(value)
    haystack = {variant.lower() for variant in variants}
    haystack.add(value.lower())
    for owner, marker in markers.items():
        needle = marker.lower()
        if any(needle in candidate for candidate in haystack):
            return owner
    if not complete:
        raise _MarkerUncheckable()
    return None


def _content_type(headers: Mapping[str, str]) -> str:
    for name, value in headers.items():
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def _cookie_pairs(header: str) -> set[tuple[str, str]]:
    """The ``(name, value)`` pairs in a ``Cookie`` request header, as the jar wrote it."""
    pairs = set()
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            pairs.add((name, value))
    return pairs


def _other_values(sent: set[tuple[str, str]], name: str, wires: set[str]) -> bool:
    """Does ``sent`` carry a value under ``name`` that is none of ``wires``?"""
    return any(sent_name == name and value not in wires for sent_name, value in sent)


def _cookie_wire_values(value: str) -> set[str]:
    """How the jar may write ``value`` into a ``Cookie`` header.

    As is, or -- for a cookie set with a ``Version`` attribute -- quoted with
    its quotes and backslashes escaped, which is what ``http.cookiejar`` does.
    """
    escaped = re.sub(r'(["\\])', r"\\\1", value)
    return {value, f'"{escaped}"'}


def _capture_value(value: Any) -> str | None:
    """``value`` if it may go onto the wire as a captured value, else None."""
    if not isinstance(value, str) or not value:
        return None
    if len(value.encode("utf-8", "ignore")) > MAX_CAPTURE_VALUE_BYTES:
        return None
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        # This value goes onto the wire in a header, where a '\r' is a
        # second request.
        return None
    if not value.isascii():
        # http.client encodes header values as latin-1, so a non-ASCII
        # token raises UnicodeEncodeError from inside the opener. A failed
        # capture is a typed login failure; that was an unhandled crash.
        return None
    return value


class IdentitySession:
    """One identity's live session. Credentials live here and nowhere else.

    Holds the cookie jar, the captured secrets, and the login step reports. The
    jar and the value map are dropped when :func:`execute_run` returns; neither
    is ever written to disk, in any form, under any flag. No file-backed jar
    class from the standard library is referenced anywhere in this package --
    a run must be reproducible from config plus target state alone, and a
    credential on disk is a credential leaked.
    """

    def __init__(
        self,
        name: str,
        identity: dict[str, Any],
        base_url: str,
        timeout: float,
        markers: Mapping[str, str],
    ) -> None:
        self.name = name
        self.identity = identity
        self.declaration: dict[str, Any] = identity["session"]
        self.base_url = base_url
        self.timeout = timeout
        self.markers = {owner: marker.lower() for owner, marker in markers.items()}
        self.policy = _SameOriginCookiePolicy(urlsplit(base_url).hostname or "")
        self.jar = http.cookiejar.CookieJar(self.policy)
        self.state = "pending"
        self.reason: str | None = None
        #: The closed-vocabulary half of ``reason``, plus whether a retry could
        #: change it. Fields rather than something parsed back out of the prose:
        #: a gate that reads them must never depend on message wording.
        self.reason_code: str | None = None
        self.transient: bool = False
        self.note: str | None = None
        self.steps: list[dict[str, Any]] = []
        #: The only copy of every captured secret in this process.
        self._values: dict[str, str] = {}
        #: name -> declared source, for the run document. A SOURCE, never a value.
        self._sources: dict[str, str] = {}
        #: capture name -> cookie name, for every capture whose source is a
        #: cookie. Each is read from the jar at the moment it is used, never
        #: from a copy, so an expired cookie reads as missing.
        self._live_cookies: dict[str, str] = {}
        #: The session-level ones, fixed by the declaration. Login-step cookie
        #: captures join them in :meth:`establish` as the steps run.
        self._session_cookies: dict[str, str] = {}
        #: (domain, path, name) of the jar cookie(s) that proved this session,
        #: fixed when it established. Liveness asks after these cookies and no
        #: other: a different cookie that merely shares the name, set on a
        #: narrower path or by a later response, is not the proof.
        self._proof: frozenset[tuple[str, str, str]] = frozenset()
        #: cookie name -> value, for each cookie-sourced capture the last
        #: :meth:`prepare` wrote into its request. :meth:`attach_cookies`, which
        #: always runs next on that same request, requires each of these
        #: cookies to go out with it.
        self._carried: dict[str, str] = {}
        #: Names of the cookies the target has set, usable and non-empty, since
        #: the current login began. A capture whose cookie is among them and
        #: no longer reads is a cookie that expired or was cleared, which is
        #: the target's doing, not a misspelt capture.
        self._seen: set[str] = set()
        self._injecting = False
        for capture_name, spec in (self.declaration.get("capture") or {}).items():
            self._session_cookies[capture_name] = spec["name"]
            self._sources[capture_name] = f"cookie:{spec['name']}"
        self._live_cookies.update(self._session_cookies)

    # -- jar -------------------------------------------------------------

    def attach_cookies(self, request: Request) -> str | None:
        """Put the jar's cookies on ``request``; a reason not to send it, or None.

        The reason is a key of :data:`core.UNSENT_REASONS`, and the caller must
        then send nothing. :meth:`prepare` already asked :meth:`is_live`, but
        ``add_cookie_header`` reads the clock again: a cookie that expired in
        between was silently left off and the probe went out anonymous. Against
        a target that answers an anonymous request with a 403 or 404 a denial
        declaration lists, that graded a live IDOR as safe. So the cookie that
        established the session is looked for on the request itself, after the
        jar has had its say, rather than trusted from the earlier check -- and
        so is every cookie whose value :meth:`prepare` wrote into the request.
        """
        if request.has_header("Cookie"):
            # Guaranteed unreachable by the load-time refusal of a static Cookie
            # header alongside a session. Asserted anyway, because the failure
            # mode is silent: add_cookie_header does nothing when a Cookie
            # header is already present, so the session cookie would vanish.
            raise AssertionError(
                f"identity {quoted(self.name)} request already carries a Cookie header"
            )
        self.jar.add_cookie_header(request)
        carried, self._carried = self._carried, {}
        if self.state != "established":
            # Login steps run before the session exists and carry whatever the
            # jar holds so far, as they always have.
            return None
        sent = _cookie_pairs(request.get_header("Cookie") or "")
        name = self._establishing_cookie()
        # The proof cookie itself, by value: a same-named cookie scoped to a
        # narrower path (``sid=guest; Path=/docs``) goes out under the same
        # name and would pass a check by name alone.
        if name is not None and not any(
            (name, wire) in sent
            for value in self._proof_values()
            for wire in _cookie_wire_values(value)
        ):
            if not self.is_live():
                return "session_expired"
            # Still live, yet the jar would not send it here: the cookie's Path
            # or Domain does not cover this URL. The request would go out just
            # as anonymous as an expired one.
            return "session_cookie_not_sent"
        if name is not None and _other_values(sent, name, {
            wire for value in self._proof_values() for wire in _cookie_wire_values(value)
        }):
            # The proof is on the request, and so is a different value under
            # its name: a later response set ``sid=guest; Path=/docs`` and the
            # jar writes the longer path first. A server that reads the first
            # occurrence authenticates the guest, and the guest's 404 matched
            # the declared denial. Which one the target reads is unknowable,
            # the rule establish() applies at login, applied to every request.
            return "session_cookie_ambiguous"
        for cookie, value in carried.items():
            wires = _cookie_wire_values(value)
            if not any((cookie, wire) in sent for wire in wires):
                # The request carries a value read from this cookie, in a header
                # or the body, and the jar left the cookie itself off: it
                # expired since prepare() read it, or its Path or Domain does
                # not cover this URL. A double-submit CSRF check compares the
                # two, draws a 403, and the 403 matches a declared denial.
                return "capture_cookie_not_sent"
            if _other_values(sent, cookie, wires):
                # Sent, but beside a different value under the same name, so the
                # CSRF check may compare the header with the other one.
                return "session_cookie_ambiguous"
        return None

    def _establishing_cookie(self) -> str | None:
        """The jar cookie whose presence proves this session, if one does.

        ``establishes: {"cookie": NAME}`` names it outright. A capture read
        from a cookie -- on the session or on a login step -- is the same proof
        by another name. Any other capture is a value already written into the
        request by :meth:`prepare`, which the jar cannot take back off.
        """
        establishes = self.declaration["establishes"]
        if "cookie" in establishes:
            return str(establishes["cookie"])
        return self._live_cookies.get(establishes["capture"])

    def _proof_values(self) -> list[str]:
        """The current values of the cookies that proved this session.

        Only those still usable and non-empty; an empty list once every one
        has expired, however many other cookies of that name the jar holds.
        """
        if not self._proof:
            return []
        return [
            cookie.value
            for cookie in self.jar
            if (cookie.domain, cookie.path, cookie.name) in self._proof
            and cookie.value
            and self._usable(cookie)
        ]

    def harvest(self, response: Any, request: Request) -> None:
        try:
            self.jar.extract_cookies(response, request)
        except Exception:
            self.note = COOKIE_ERROR
        self._note_cookies()

    def _note_cookies(self) -> None:
        """Remember which cookies the jar holds a usable value for, by name."""
        self._seen.update(
            cookie.name for cookie in self.jar if cookie.value and self._usable(cookie)
        )

    def _cookie_value(self, name: str) -> str | None:
        """The value of a usable cookie of this name, or None.

        An empty value (``Set-Cookie: sid=``) is no value: it is how a target
        clears a cookie, and it authenticates nothing. Counting it as present
        established a session on it and sent every probe as ``sid=``.
        """
        for cookie in self.jar:
            if cookie.name == name and cookie.value and self._usable(cookie):
                return cookie.value
        return None

    def _usable(self, cookie: Any) -> bool:
        """Could this cookie ever be returned to the target?

        Path is deliberately not checked: a ``Path=/app`` cookie is perfectly
        usable at the paths it scopes. ``Secure`` over a plain-``http`` base URL
        is checked, and it is the classic false-SAFE generator -- the cookie was
        set, is never transmitted, and every probe silently runs anonymous.
        """
        if cookie.is_expired(int(time.time())):
            return False
        if cookie.secure and urlsplit(self.base_url).scheme != "https":
            return False
        return True

    # -- captures --------------------------------------------------------

    def _extract(self, spec: dict[str, Any], sink: Mapping[str, Any]) -> str | None:
        source = spec["from"]
        if source == "cookie":
            value = self._cookie_value(spec["name"])
        elif source == "header":
            matches = [
                item
                for name, item in sink.get("headers", ())
                if name.lower() == spec["name"].lower()
            ]
            # Two different values for one field name: which one the target
            # meant is unknowable, and guessing puts the wrong token on an
            # authenticated request.
            value = matches[0] if len(set(matches)) == 1 else None
        elif source == "json_pointer":
            value = _json_pointer(sink.get("body") or b"", spec["pointer"])
        else:
            value = _html_meta(sink.get("body") or b"", spec["name"])
        return _capture_value(value)

    def lookup(self, name: str) -> str | None:
        """The current value of one capture. Cookie sources are read live.

        A live cookie passes the checks it would have passed when captured: it
        goes onto the wire just the same.
        """
        if name in self._live_cookies:
            cookie = self._live_cookies[name]
            if self._proof and cookie == self._establishing_cookie():
                values = self._proof_values()
                return _capture_value(values[0]) if values else None
            return _capture_value(self._cookie_value(cookie))
        return self._values.get(name)

    def is_live(self) -> bool:
        """Is the proof that established this session still true, right now?

        ``state`` is set once, at the end of :meth:`establish`, and never
        revisited -- but a cookie expires on a clock the target chose. When it
        does, ``add_cookie_header`` silently omits it and the probe goes out
        FULLY ANONYMOUS: it draws a 401, the 401 is the kind of status a denial
        declaration lists, the marker is absent, and the run is green over a
        live vulnerability. This re-runs exactly the check ``establish``
        finished with, immediately before each request, so that expiry is
        caught on the near side of the wire.
        """
        if self.state != "established":
            return False
        if self._establishing_cookie() is not None:
            return bool(self._proof_values())
        return bool(self.lookup(self.declaration["establishes"]["capture"]))

    # -- outbound --------------------------------------------------------

    def _substitute(self, text: str) -> tuple[str, str | None]:
        missing: str | None = None
        substituted: list[str] = []

        def replace(match: re.Match[str]) -> str:
            nonlocal missing
            value = self.lookup(match.group(1))
            if value is None:
                missing = missing or match.group(1)
                return ""
            substituted.append(value)
            if match.group(1) in self._live_cookies:
                self._carried[self._live_cookies[match.group(1)]] = value
            return value

        resolved = core._CAPTURE_REF.sub(replace, text)
        if missing is not None:
            return text, missing
        for value in substituted:
            try:
                owner = _marker_owner(value, self.markers)
            except _MarkerUncheckable:
                return text, "\x00uncheckable"
            if owner is not None:
                # A marker Veridor itself put on the wire and then matched
                # cannot prove a leak, and that is just as true of a
                # captured value as of a configured body.
                return text, "\x00marker"
        return resolved, None

    def prepare(
        self,
        headers: dict[str, str],
        body: bytes | None,
        *,
        method: str,
        graded: bool = True,
    ) -> tuple[dict[str, str], bytes | None, str | None, list[str]]:
        """Resolve captures and apply injections.

        Returns ``(headers, body, blocked, not_applied)``. ``blocked`` is a key
        of :data:`core.UNSENT_REASONS`; when it is not ``None`` the caller must
        send nothing at all. ``not_applied`` lists the declared inject fields
        this body could not carry but that were dropped rather than refused: on
        a bodyless safe method, which has nowhere to put one and no CSRF check
        to fail, and -- when ``graded`` is false -- on a teardown request, which
        is cleanup and is never graded, so the fail-closed refusal that a graded
        probe gets would only orphan the fixture it was meant to remove.
        """
        self._carried = {}
        if self.state == "established" and not self.is_live():
            # Fail closed. The alternative is an anonymous probe graded against
            # a denial declaration, which is the exact false SAFE this whole
            # section exists to prevent. Login steps run with state 'pending'
            # and are never blocked by this.
            return headers, body, "session_expired", []
        resolved: dict[str, str] = {}
        for name, value in headers.items():
            if not isinstance(value, str) or "${capture." not in value:
                resolved[name] = value
                continue
            if name.lower() in core._CREDENTIAL_HEADERS:
                return headers, body, "credential_slot_interpolation", []
            text, missing = self._substitute(value)
            if missing is not None:
                return headers, body, self._block_reason(missing), []
            resolved[name] = text
        if body is not None and b"${capture." in body:
            text, missing = self._substitute(body.decode("utf-8", "surrogateescape"))
            if missing is not None:
                return headers, body, self._block_reason(missing), []
            body = text.encode("utf-8", "surrogateescape")
        if not self._injecting:
            # Injection is applied only once the session is established. A login
            # step names its own token explicitly, which is the only ordering
            # that is decidable without a conditional.
            return resolved, body, None, []
        not_applied: list[str] = []
        for entry in self.declaration.get("inject") or ():
            value, missing = self._substitute(entry["value"])
            if missing is not None:
                return headers, body, self._block_reason(missing), []
            if "header" in entry:
                # An injected header always overrides a same-named header from
                # the request's own headers, so precedence is never guessed.
                target = entry["header"]
                resolved = {
                    name: item
                    for name, item in resolved.items()
                    if name.lower() != target.lower()
                }
                resolved[target] = value
                continue
            if body is None and method in core.SAFE_METHODS:
                # A body field has nowhere to go on a bodyless GET, HEAD or
                # OPTIONS, and no CSRF check guards one. The request still goes
                # out -- refusing it would make every read check and marker
                # probe of a form_field session inconclusive -- but the drop is
                # recorded so a clean result is not read as a field-carried one.
                not_applied.append(_inject_field_label(entry))
                continue
            if "form_field" in entry:
                # urllib sends a body with no Content-Type as form-encoded, so
                # the wire, not the config, decides what the body is.
                media = _content_type(resolved) or _FORM_MEDIA_TYPE
                if body is not None and media == _FORM_MEDIA_TYPE:
                    field = f"{quote_plus(entry['form_field'])}={quote_plus(value)}"
                    body = (body + b"&" if body else b"") + field.encode()
                    continue
            else:
                applied = _set_json_field(body, resolved, entry["json_field"], value)
                if applied is not None:
                    body = applied
                    continue
            # The declared field cannot be carried by this body.
            if graded:
                # Fail closed. Sent without its token the request draws a CSRF
                # denial, and a denial that matches a declared denial is a
                # manufactured SAFE over a boundary that was never tested.
                return headers, body, "injection_not_applicable", []
            not_applied.append(_inject_field_label(entry))
        return resolved, body, None, not_applied

    def _block_reason(self, missing: str) -> str:
        if missing == "\x00marker":
            return "marker_reflection_blocked"
        if missing == "\x00uncheckable":
            return "marker_check_incomplete"
        cookie = self._live_cookies.get(missing)
        if cookie is not None and cookie in self._seen and self._cookie_value(cookie) is None:
            # The target set this cookie under this login and it is gone now:
            # expired or cleared. That is the session's state, not a capture
            # the configuration misnamed, so it gets session advice and the
            # gate does not count it as a configuration error.
            return "capture_cookie_expired"
        return "unresolved_reference"

    # -- establishment ---------------------------------------------------

    def establish(self) -> None:
        """Run the login steps and decide, on evidence, whether we are in."""
        self.policy = _SameOriginCookiePolicy(urlsplit(self.base_url).hostname or "")
        self.jar = http.cookiejar.CookieJar(self.policy)
        self._values.clear()
        self._live_cookies = dict(self._session_cookies)
        self._proof = frozenset()
        self._seen = set()
        self.steps = []
        self.note = None
        self.reason = None
        self.reason_code = None
        self.transient = False
        self.state = "pending"
        self._injecting = False

        for index, step in enumerate(self.declaration.get("login") or ()):
            request_config = {
                key: step[key]
                for key in ("method", "path", "headers", "json", "body")
                if key in step
            }
            sink: dict[str, Any] = {}
            result = core._perform_request(
                self.base_url,
                self.timeout,
                request_config,
                self.identity,
                sink=sink,
                session=self,
            )
            record = {
                "method": result["request"]["method"],
                "url": result["request"]["url"],
                "status": result["response"]["status"],
                "duration_ms": result["response"]["duration_ms"],
                "body_bytes": result["response"]["body_bytes"],
                "body_sha256": result["response"]["body_sha256"],
                "outcome": "ok",
            }
            self.steps.append(record)
            if result["error"]:
                record["outcome"] = (
                    "not_sent"
                    if result["response"]["status"] is None
                    and result["error"] in core.UNSENT_REASONS.values()
                    else "transport_error"
                )
                sink.clear()
                self._fail(
                    "login_blocked"
                    if record["outcome"] == "not_sent"
                    else "login_transport_error",
                    index,
                )
                return
            if record["status"] not in step["expect_status"]:
                record["outcome"] = "unexpected_status"
                sink.clear()
                self._fail("login_status_mismatch", index, record["status"])
                return
            for name, spec in (step.get("capture") or {}).items():
                value = self._extract(spec, sink)
                self._sources[name] = _source_label(spec)
                if value is None:
                    record["outcome"] = "capture_failed"
                    sink.clear()
                    self._fail("login_capture_failed", index, name=name)
                    return
                # Last write wins, per identity, per name. That is a rule, not a
                # conditional: there is no "if the token changed" branch.
                if spec["from"] == "cookie":
                    # Read from the jar when used, like a session-level cookie
                    # capture. A frozen copy outlived the cookie: as the
                    # establishing proof it kept an expired session "live"
                    # and every later probe went out anonymous.
                    self._live_cookies[name] = spec["name"]
                    self._values.pop(name, None)
                else:
                    self._live_cookies.pop(name, None)
                    self._values[name] = value
            sink.clear()

        self._note_cookies()
        cookie = self._establishing_cookie()
        if cookie is not None:
            proof = [
                item
                for item in self.jar
                if item.name == cookie and item.value and self._usable(item)
            ]
            if len({item.value for item in proof}) > 1:
                # Two different values under the proving name, say one per
                # Path: which one the target authenticates is unknowable, the
                # same rule a header capture follows. Guessing could tie the
                # session to a guest cookie that outlives the real one.
                self._fail("not_established", cookie=cookie)
                return
            self._proof = frozenset((item.domain, item.path, item.name) for item in proof)
            proven = bool(self._proof)
        else:
            proven = bool(self.lookup(self.declaration["establishes"]["capture"]))
        if not proven:
            self._fail("not_established")
            return
        self.state = "established"
        self._injecting = True

    def _fail(
        self,
        reason: str,
        index: int | None = None,
        status: int | None = None,
        name: str | None = None,
        cookie: str | None = None,
    ) -> None:
        self.state = "failed"
        detail = reason
        if index is not None:
            detail += f" at login step {index}"
        if status is not None:
            detail += f" (HTTP {status})"
        if name is not None:
            detail += f" (capture {quoted(name)})"
        if cookie is not None:
            detail += f" (cookie {quoted(cookie)} is set more than once with different values)"
        self.reason = detail
        self.reason_code = reason
        self.transient = is_transient_session_failure(reason, status)
        self._injecting = False

    def reestablish_for_check(self) -> None:
        """Replace the jar and log in again, when the config asks for it."""
        if self.declaration.get("reestablish") == "check":
            self.establish()

    # -- reporting -------------------------------------------------------

    def report(self) -> dict[str, Any]:
        """The recordable half of this session, and only that half.

        Cookie NAMES are recorded because ``sessionid`` is not a credential and
        without it a failing session is undebuggable from CI artifacts alone.
        Cookie VALUES, capture values, ``Set-Cookie`` attributes, and any hash,
        prefix, suffix, or length of a secret are not: many CSRF-shaped tokens
        live in a guessable domain, and a hash of an isolated token makes
        offline confirmation trivial.
        """
        names = [_safe_cookie_name(cookie.name) for cookie in self.jar]
        listed = sorted(names)[:MAX_RECORDED_COOKIE_NAMES]
        if len(names) > MAX_RECORDED_COOKIE_NAMES:
            listed.append(f"+{len(names) - MAX_RECORDED_COOKIE_NAMES} more")
        captures = {
            name: {
                "state": "captured" if self.lookup(name) else "missing",
                "source": source,
            }
            for name, source in sorted(self._sources.items())
        }
        report: dict[str, Any] = {
            "identity": self.name,
            "state": self.state,
            "reason": self.reason,
            "cookies": {"count": len(names), "names": listed},
            "captures": captures,
            "steps": self.steps,
        }
        if self.note:
            report["note"] = self.note
        return report


def _source_label(spec: dict[str, Any]) -> str:
    return (
        f"json_pointer:{spec['pointer']}"
        if spec["from"] == "json_pointer"
        else f"{spec['from']}:{spec['name']}"
    )


def _safe_cookie_name(name: str) -> str:
    return name if _COOKIE_NAME_SAFE.match(name or "") else REDACTED_COOKIE_NAME


def _set_json_field(
    body: bytes | None, headers: Mapping[str, str], field: str, value: str
) -> bytes | None:
    """Set one TOP-LEVEL key on a JSON body. Top level only.

    A nested write needs a path grammar plus creation semantics, which is the
    first step toward a scripting language; top-level covers every real CSRF
    field. Applied only to a request that already has a JSON object body -- a
    fixed rule of the mechanism, not a condition the config can express.
    Returns ``None`` when the body is not one, and the caller sends nothing:
    returning it unchanged sent the request without the field.
    """
    media = _content_type(headers)
    if not body or not (media == "application/json" or media.endswith("+json")):
        return None
    try:
        document = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    document[field] = value
    return json.dumps(document, separators=(",", ":")).encode()


def establish_sessions(config: dict[str, Any]) -> dict[str, IdentitySession]:
    """Log every identity that declares a session in, serially, in config order.

    Returns a plain ``dict`` the caller owns and drops. There is deliberately no
    module-level registry: the jar reaches a request as an argument, so cookie
    isolation is a property of the call and not of a map someone could key
    wrongly. There is also no primitive anywhere that copies, unions, or seeds
    one jar from another -- a leak would take new code, not a forgotten flag.
    """
    base_url = config["target"]["base_url"]
    timeout = float(config["target"].get("timeout_seconds", 10))
    markers = {
        name: identity["marker"]
        for name, identity in config["identities"].items()
        if isinstance(identity, dict) and "marker" in identity
    }
    sessions: dict[str, IdentitySession] = {}
    for name, identity in config["identities"].items():
        if not isinstance(identity, dict) or not isinstance(identity.get("session"), dict):
            continue
        state = IdentitySession(name, identity, base_url, timeout, markers)
        state.establish()
        if state.state != "established":
            _warn(
                f"session for identity {quoted(name)} was not established "
                f"({state.reason}); every probe as {quoted(name)} will report "
                "inconclusive"
            )
        sessions[name] = state
    return sessions


def _warn(message: str) -> None:
    """Report an operational problem loudly, on stderr and in CI annotations.

    Silent degradation is the failure mode this whole file exists to prevent,
    and stderr is the only channel that survives an interrupted run -- no run
    document is written on cancellation.
    """
    print(f"veridor: {message}", file=sys.stderr)
    if os.environ.get("GITHUB_ACTIONS"):
        escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::warning title=veridor::{escaped}", file=sys.stderr)


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------


def step_finding_id(
    sequence_id: str, step: dict[str, Any], step_index: int, kind: str
) -> str:
    """Fingerprint one step finding.

    ``core._finding_id`` is not modified, not one character, and is unreachable
    from here. ``path`` and the body are the config TEMPLATES with ``${...}``
    tokens intact, which serves three invariants at once: ids stay stable across
    runs even though resolved values differ every run, no captured value or
    ``run_id`` can enter a hash input, and the persisted URL of §2.3 uses the
    identical string. ``step_index`` is the sole structural discriminant and it
    also guarantees distinct preimages from every check signature, which has six
    keys and never contains the substring ``"step_index"``.
    """
    request = step["request"]
    body = request.get("json", request.get("body"))
    signature = {
        "check_id": sequence_id,
        "identity": step["as"],
        "kind": kind,
        "method": request.get("method", "GET").upper(),
        "path": request["path"],
        "body_sha256": hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "expected_statuses": sorted(step["expect"]["status"]),
        "step_index": step_index,
    }
    value = json.dumps(signature, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()[:20]


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def _template_url(base_url: str, path: str) -> str:
    """The URL as WRITTEN, ``${...}`` intact. Never the resolved URL.

    ``_safe_url`` redacts query values but leaves the path intact, so persisting
    a resolved URL would write a captured value to disk through the URL field
    and defeat §2.1 without anyone touching a capture. Persisting the template
    closes that channel and makes the field byte-identical on every run.
    """
    return core._safe_url(urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/")))


def _resolve_path(
    template: str,
    values: Mapping[str, Any],
    run_id: str,
    markers: Mapping[str, str],
    base_url: str,
) -> str:
    """Resolve a step path and re-validate it. Raises :class:`_PathInvalid`."""
    token = sole_token(template)
    resolved = substitute(template, values, run_id, markers)
    if token is not None and token[0] == "var":
        resolved = _reexpress_captured(resolved, base_url)
    elif _starts_with_var(template):
        # The capture need not be the whole template. A template that only
        # BUILDS on a leading capture -- `${where}/comments` with a captured
        # `/api/notes/n1` -- puts an origin-root path at the front just as the
        # sole-token form did, so it doubled the base to /api/api/notes/n1/
        # comments. Only `sole_token` was re-expressed, so that doubled route
        # 404'd, matched a declared [403, 404], and the run was clean over a
        # live IDOR. A captured absolute URL there (`http://host/api/notes/n1`,
        # the usual Location header) was refused as `not_absolute`, so the
        # leading form now gets the sole token's whole treatment: same origin
        # and base path, or refused for the reason that applies. A leading
        # literal (`/fixed/${id}`) is the operator's own base-relative path and
        # is not touched; `_starts_with_var` fires only when the captured value
        # itself sits at the start.
        resolved = _reexpress_captured(
            _suffix_on_the_captured_path(template, values, run_id, markers),
            base_url,
        )
    if _has_dot_segment(resolved):
        # The same threat as the cross-origin case above, and strictly worse
        # because it stays on the target. `core._perform_request` builds the URL
        # with urljoin, which applies RFC 3986 remove_dot_segments, so a
        # captured '..' silently RETARGETS the probe at a different endpoint --
        # the declaration's endpoint is never requested, the probe draws a
        # plausible denial somewhere else, and the run is green over an
        # untested boundary. The persisted URL is the template, so the swap is
        # invisible even on manual review. No object identifier is ever a dot
        # segment, so refusing costs nothing.
        raise _PathInvalid("dot_segment")
    try:
        core._validate_request({"path": resolved}, "step request")
    except ConfigError:
        # The ConfigError text can quote the resolved path, and the resolved
        # path can carry a captured value. Only the closed reason escapes.
        raise _PathInvalid("not_absolute") from None
    return resolved


def _suffix_on_the_captured_path(
    template: str,
    values: Mapping[str, Any],
    run_id: str,
    markers: Mapping[str, str],
) -> str:
    """``template`` resolved with its suffix on the leading capture's PATH.

    Plain substitution appends the suffix to the captured value as a whole. A
    captured ``/api/notes/n1?created=1`` (or the absolute URL a Location header
    carries) under ``${where}/comments`` therefore became
    ``/api/notes/n1?created=1/comments``: the suffix inside the query, the
    request aimed at the note itself rather than its comments. A denial there
    matched a declared [403, 404] and the run passed clean over the endpoint
    the step declares. So the captured query is lifted out, the suffix goes on
    the path, and the captured query follows -- joined to any query the
    template itself declares. A captured fragment is refused: it is never sent,
    so the request could not be the one written.
    """
    end = template.find("}")
    captured = substitute(template[: end + 1], values, run_id, markers)
    suffix = substitute(template[end + 1 :], values, run_id, markers)
    if "?" not in captured and "#" not in captured:
        return captured + suffix
    if "#" in captured:
        raise _PathInvalid("fragment")
    captured_path, _, captured_query = captured.partition("?")
    suffix_path, _, suffix_query = suffix.partition("?")
    query = "&".join(part for part in (captured_query, suffix_query) if part)
    return captured_path + suffix_path + (f"?{query}" if query else "")


def _reexpress_captured(resolved: str, base_url: str) -> str:
    """A resolved path that starts with a captured value, made relative to the
    base path. Raises :class:`_PathInvalid`.

    A captured Location header commonly yields an absolute URL. Without the
    origin check a target could answer `Location: https://evil.example/` and
    Veridor would replay the identity's credentials to an arbitrary host. A
    protocol-relative value ('//evil.example/x') has a netloc and no scheme and
    is refused for the same reason.
    """
    parsed = urlsplit(resolved)
    if parsed.netloc:
        if not _same_origin(parsed, urlsplit(base_url)):
            raise _PathInvalid("cross_origin")
        if parsed.fragment:
            raise _PathInvalid("fragment")
        return _below_base_path(parsed.path, base_url, required=True) + (
            f"?{parsed.query}" if parsed.query else ""
        )
    if resolved.startswith("/"):
        path, mark, query = resolved.partition("?")
        return _below_base_path(path, base_url, required=False) + mark + query
    return resolved


def _below_base_path(path: str, base_url: str, *, required: bool) -> str:
    """``path``, measured from the origin root, re-expressed from the base path.

    ``core._perform_request`` joins every request path UNDER the base URL's
    path. A captured URL is measured from the origin root, so with a base URL of
    ``https://gw/api/`` a Location of ``https://gw/api/notes/n1`` or
    ``/api/notes/n1`` was joined to ``/api/api/notes/n1``: a route that does not
    exist, whose 404 matched a declared [403, 404] and passed clean over a live
    IDOR. ``_assert_same_origin`` cannot see it, because the doubled path is
    still under the base path.

    An absolute URL is unambiguous, so one outside the base path is refused
    (``required``) rather than retargeted under it. A path-absolute value that
    does not start with the base path is left as written: a backend behind a
    prefix-stripping gateway answers ``/notes/n1`` and means the base path's.
    """
    base_path = urlsplit(base_url).path.rstrip("/")
    if not base_path:
        return path
    if path == base_path or path.startswith(base_path + "/"):
        return path[len(base_path):] or "/"
    if required:
        raise _PathInvalid("outside_base_path")
    return path


#: The rule lives in ``core`` now, where every request path is validated at
#: load; a step path resolved at run time is held to the same one.
_has_dot_segment = core._has_dot_segment


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _same_origin(candidate: Any, base: Any) -> bool:
    scheme = (candidate.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS or scheme != (base.scheme or "").lower():
        return False
    if (candidate.hostname or "").lower() != (base.hostname or "").lower():
        return False
    try:
        left = candidate.port or _DEFAULT_PORTS[scheme]
        right = base.port or _DEFAULT_PORTS[scheme]
    except ValueError:
        return False
    return left == right


def _resolve_request(
    request: dict[str, Any],
    values: Mapping[str, Any],
    run_id: str,
    markers: Mapping[str, str],
    base_url: str,
) -> dict[str, Any]:
    resolved = dict(request)
    resolved["path"] = _resolve_path(
        request["path"], values, run_id, markers, base_url
    )
    headers = request.get("headers")
    if isinstance(headers, dict) and headers:
        resolved["headers"] = {
            name: substitute(value, values, run_id, markers)
            if isinstance(value, str)
            else value
            for name, value in headers.items()
        }
    if "json" in request:
        resolved["json"] = substitute_json(request["json"], values, run_id, markers)
    elif isinstance(request.get("body"), str):
        resolved["body"] = substitute(request["body"], values, run_id, markers)
    return resolved


def _planted_identities(request: dict[str, Any]) -> list[str]:
    planted: list[str] = []
    if "json" in request:
        texts = _body_strings(request["json"])
    elif isinstance(request.get("body"), str):
        texts = [request["body"]]
    else:
        texts = []
    for text in texts:
        for kind, name in scan_tokens(text):
            if kind == "marker" and name not in planted:
                planted.append(name)
    return planted


def _skipped_clause(skipped: list[tuple[int, str]]) -> str:
    if not skipped:
        return ""
    roles = {role for _, role in skipped}
    indices = ", ".join(str(index) for index, _ in skipped)
    if len(roles) == 1:
        return f" Steps {indices} ({next(iter(roles))}) were not executed."
    listed = ", ".join(f"{index} ({role})" for index, role in skipped)
    return f" Steps {listed} were not executed."


class _SequenceRun:
    """One sequence execution. Captured values live here and nowhere else."""

    def __init__(
        self,
        config: dict[str, Any],
        sequence: dict[str, Any],
        config_path: Path,
        run_id: str,
        marker_controls: Mapping[str, dict[str, Any]],
        sessions: Mapping[str, IdentitySession] | None = None,
    ) -> None:
        self.config = config
        self.sequence = sequence
        self.config_path = config_path
        self.run_id = run_id
        self.marker_controls = marker_controls
        self.sessions: Mapping[str, IdentitySession] = sessions or {}
        self.base_url: str = config["target"]["base_url"]
        self.timeout = float(config["target"].get("timeout_seconds", 10))
        #: Cleanup gets its own budget: a hung cleanup endpoint must not be able
        #: to stall CI for the full probe timeout on every teardown entry.
        self.teardown_timeout = float(
            config["target"].get("teardown_timeout_seconds", self.timeout)
        )
        self.identities: dict[str, Any] = config["identities"]
        self.markers: dict[str, str] = {
            name: identity["marker"]
            for name, identity in self.identities.items()
            if isinstance(identity, dict) and "marker" in identity
        }
        #: The only mutable state a sequence carries. Never returned, never
        #: placed in a result dict, never logged, never printed, destroyed when
        #: :meth:`execute` returns.
        self.values: dict[str, Any] = {}
        #: step index -> resolved request path, query stripped. In memory only,
        #: for the same reason ``values`` is: a resolved path can contain a
        #: captured value. It exists so EFFECT-001 can require that the earlier
        #: write and this read addressed the SAME path instead of asserting it.
        self.resolved_paths: dict[int, str] = {}
        self.steps: list[dict[str, Any]] = sequence["steps"]
        self.records: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.aborted_at: int | None = None
        self.abort_reason: str | None = None
        self.abort_step_emitted_finding = False
        self.abort_detail: str = ""
        #: identity -> earliest step index at which that identity's own marker
        #: was observed present. This is the control ladder's top tier.
        self.observed_markers: dict[str, int] = {}
        #: Every identity for which this sequence plants a marker. An identity
        #: probe is IGNORED for such an identity: the probe read a path
        #: provisioned before the run, and the sequence just created a new
        #: object the probe never saw.
        self.plants: set[str] = set()
        for step in self.steps:
            self.plants.update(_planted_identities(step["request"]))
        self.teardown_failures = 0
        self.teardown_skipped = 0
        #: Set before any step runs, so a sequence that raises out still carries
        #: a lifecycle state into the run document.
        self.teardown: list[dict[str, Any]] = []
        self.teardown_state = (
            "not_required" if not sequence.get("teardown") else "pending"
        )
        self.interrupted = False

    # -- helpers ---------------------------------------------------------

    def _needles_owner(self, step: dict[str, Any], planted: list[str]) -> str | None:
        if planted:
            # §7.3: a target that echoes the planted body back in its 201 would
            # make the planting step's own response carry the marker. A planting
            # step's response is therefore never scanned for any marker; it
            # contributes exactly the observed status and any declared captures.
            return None
        expect = step["expect"]
        return expect.get("contains_marker") or expect.get("excludes_marker")

    def _control(self, owner: str) -> tuple[str, str, str | None]:
        """Resolve the control licensing ``excludes_marker: owner`` for a step.

        Ladder: ``sequence_prior_step`` > ``identity_probe`` > ``none``. The
        ``check`` and ``check_observed`` tiers are same-check concepts and are
        structurally unreachable here.
        """
        index = self.observed_markers.get(owner)
        if index is not None:
            return "sequence_prior_step", "present", None
        if owner in self.plants:
            return "none", "missing", (
                f"this sequence plants {quoted(owner)}'s marker but no earlier step "
                f"observed it, so nothing establishes that the planted marker "
                f"is retrievable"
            )
        control = self.marker_controls.get(owner)
        if control is not None:
            state = "present" if control["state"] == "verified" else "missing"
            return "identity_probe", state, control["reason"]
        return "none", "missing", (
            f"no control established that {quoted(owner)}'s marker is live"
        )

    def _refuse_marker_reflection(self, request: dict[str, Any]) -> None:
        """Refuse to interpolate a captured value that carries a marker.

        Raises :class:`_MarkerReflected`. Only ``var`` tokens are examined: a
        ``${marker:X}`` token is the operator deliberately PLANTING the marker,
        which is how a sequence provisions the victim's object in the first
        place. A capture is different -- the target chose its contents.
        """
        if not self.markers:
            return
        for kind, token in _entry_tokens(request):
            if kind != "var" or token == "run_id" or token not in self.values:
                continue
            try:
                owner = _marker_owner(str(self.values[token]), self.markers)
            except _MarkerUncheckable:
                raise _MarkerUncheckable(token) from None
            if owner is not None:
                raise _MarkerReflected(owner, token)

    def _prior_foreign_write(
        self, identity: str, before: int, path: str | None
    ) -> int | None:
        """The earlier step that could have destroyed ``identity``'s object.

        The PATH test is what makes "against this sequence's object" a fact
        rather than a turn of phrase. Without it the first earlier foreign
        non-safe request of any kind qualifies, so a setup POST by another
        identity creating its OWN unrelated resource under a different endpoint
        is reported as a write against an object that does not exist -- combined
        with an ``absent`` scan on a path that was never provisioned, that is a
        `vulnerable` verdict over an operator misconfiguration whose honest
        answer is ORACLE-001 / inconclusive.

        The write's STATUS is deliberately NOT a condition. A refusal status
        proves nothing about effect in either direction: a 403 that deletes the
        row anyway is precisely the silent cross-tenant delete this rule exists
        to catch, and it is the case a status-only check goes green on. Only the
        victim's own read settles effect, which is the whole premise.
        """
        if path is None:
            return None
        for record in self.records:
            if record["index"] >= before or record["state"] == "skipped":
                continue
            if record["as"] == identity:
                continue
            if record["request"]["method"] in SAFE_METHODS:
                continue
            if record["response"] is None:
                # Never reached the wire, so it cannot have written.
                continue
            if self.resolved_paths.get(record["index"]) != path:
                continue
            return record["index"]
        return None

    def _base_finding(
        self, step: dict[str, Any], index: int, record: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "check_id": self.sequence["id"],
            "identity": step["as"],
            "step_index": index,
            "location": str(self.config_path),
        }

    def _evidence(
        self, step: dict[str, Any], index: int, record: dict[str, Any]
    ) -> dict[str, Any]:
        response = record["response"]
        return {
            "expected_statuses": step["expect"]["status"],
            # None when the step was never sent -- a runtime path failure, or a
            # transport error before any status existed. Recording null rather
            # than omitting the key keeps every step finding one shape.
            "actual_status": response["status"] if response else None,
            "request": record["request"],
            "response": response,
            "sequence": {
                "sequence_id": self.sequence["id"],
                "step_index": index,
                "role": step["role"],
                # Patched once the sequence finishes; a finding must carry its
                # own context so no reader has to cross-reference.
                "outcome": None,
                "skipped_steps": [],
            },
        }

    # -- execution -------------------------------------------------------

    def execute(self) -> None:
        """Run every step, then clean up. Teardown runs on EVERY path.

        Setup failure, probe failure, an unexpected exception,
        ``KeyboardInterrupt`` (SIGINT) -- the ``finally`` runs cleanup for the
        in-flight sequence regardless. SIGTERM reaches the same ``finally`` only
        because ``veridor.cli.main`` installs a handler that raises
        ``cli.Terminated``, a ``KeyboardInterrupt`` subclass; with Python's
        default disposition SIGTERM kills the interpreter and this cleanup does
        not run. A library caller that wants the same has to install an
        equivalent handler. A second SIGINT during teardown, ``SIGKILL`` and
        power loss all cut it short.
        This is exactly why teardown is per-sequence rather than deferred to the
        end of the run: earlier sequences already ran theirs in their own
        ``finally``, so at the moment of an interrupt only this one is owed
        cleanup.

        Grading happens in ``_finish``, AFTER teardown, but on records that were
        complete before teardown started -- so a teardown result cannot reach a
        verdict even in principle.
        """
        name = self.sequence.get("name", self.sequence["id"])
        try:
            for index, step in enumerate(self.steps):
                if self.aborted_at is not None:
                    self.records.append(self._skipped_record(index, step))
                    continue
                self._run_step(index, step, name)
        except BaseException:
            self.interrupted = True
            raise
        finally:
            self._run_teardown()
        self._finish(name)

    def _skipped_record(self, index: int, step: dict[str, Any]) -> dict[str, Any]:
        capture = step.get("capture") or {}
        return {
            "index": index,
            "as": step["as"],
            "role": step["role"],
            "name": step.get("name"),
            "request": {
                "method": step["request"].get("method", "GET").upper(),
                "url": _template_url(self.base_url, step["request"]["path"]),
            },
            "response": None,
            "error": None,
            "state": "skipped",
            "captures": [
                {
                    "name": key,
                    "extractor": expression,
                    "resolved": False,
                    "reason": "step_not_executed",
                }
                for key, expression in capture.items()
            ],
            "marker_planted": _planted_identities(step["request"]),
            "marker_scanned": False,
        }

    def _run_step(self, index: int, step: dict[str, Any], name: str) -> None:
        request = step["request"]
        planted = _planted_identities(request)
        template_url = _template_url(self.base_url, request["path"])
        record: dict[str, Any] = {
            "index": index,
            "as": step["as"],
            "role": step["role"],
            "name": step.get("name"),
            "request": {
                "method": request.get("method", "GET").upper(),
                "url": template_url,
            },
            "response": None,
            "error": None,
            "state": "errored",
            "captures": [],
            "marker_planted": planted,
            "marker_scanned": False,
        }
        self.records.append(record)

        session = self.sessions.get(step["as"])
        if session is not None and session.state != "established":
            # Degraded state never looks like a result: no request is issued and
            # the sequence reports inconclusive, never safe.
            record["error"] = (
                f"the session for {quoted(step['as'])} was not established "
                f"({session.reason}); this step was not issued"
            )
            self.findings.append(self._exec_finding(
                index, step, record, name, reason="session_unavailable"))
            self._abort(index, "execution_error", record["error"], emitted=True)
            return

        try:
            self._refuse_marker_reflection(request)
        except _MarkerReflected as reflected:
            # The session model already refuses to put a captured value carrying
            # a configured marker on the wire (core.UNSENT_REASONS
            # 'marker_reflection_blocked'), because a marker Veridor itself sent
            # and then matched cannot prove a leak. The sequence interpolation
            # path had no such guard: plant the marker, capture the field the
            # target echoed it back in, interpolate that capture into the
            # attacker's own query, and any ordinary echoing endpoint returns it
            # as a `confirmed` cross-identity leak. Load-time validation cannot
            # see this -- the template holds '${prov}', not the marker.
            record["error"] = (
                f"capture {quoted(reflected.capture)} carries "
                f"{quoted(reflected.owner)}'s marker; sending it would make a "
                "reflected marker look like a leak, so this step was not issued"
            )
            self.findings.append(self._exec_finding(
                index, step, record, name, reason="marker_reflection_blocked"))
            self._abort(
                index, "marker_reflection_blocked", record["error"], emitted=True
            )
            return
        except _MarkerUncheckable as unchecked:
            # The same guard, unable to finish: the capture decoded into more
            # variants than it checks, so a marker could sit in one it never
            # read. Sending it would read that silence as "no marker".
            record["error"] = (
                f"capture {quoted(unchecked.capture)} decodes into more than "
                f"{core._MAX_DECODE_VARIANTS} variants, so it could not be checked "
                "for a configured marker; sending it could make a reflected "
                "marker look like a leak, so this step was not issued"
            )
            self.findings.append(self._exec_finding(index, step, record, name))
            self._abort(
                index, "marker_check_incomplete", record["error"], emitted=True
            )
            return

        try:
            resolved = _resolve_request(
                request, self.values, self.run_id, self.markers, self.base_url
            )
        except _PathInvalid as invalid:
            # Fail closed and send nothing: a request whose path only became
            # invalid after substitution is not the request the operator wrote.
            record["error"] = _PATH_INVALID_MESSAGES.get(
                invalid.reason,
                "the interpolated path is not a valid same-origin absolute path",
            )
            self._abort(index, "path_invalid", record["error"])
            return
        self.resolved_paths[index] = resolved["path"].split("?", 1)[0]

        owner = self._needles_owner(step, planted)
        marker = self.markers.get(owner) if owner else None
        sink: dict[str, Any] = {}
        result = core._perform_request(
            self.base_url,
            self.timeout,
            resolved,
            self.identities[step["as"]],
            marker=marker,
            sink=sink,
            session=session,
        )
        # The persisted URL is the TEMPLATE, not the resolved URL. This is the
        # line that keeps captured values off disk.
        record["response"] = result["response"]
        record["error"] = redact_captures(result["error"], self.values)
        record["marker_scanned"] = marker is not None
        not_applied = result.get("injection_not_applied")
        if not_applied:
            # A bodyless GET, HEAD or OPTIONS step went out without a declared
            # body field. It is graded like any other step, so a matched denial
            # here is not a field-carried one; the record says so, and
            # core._injection_disclosures lists it with the run's other drops.
            # The field name only, never its value.
            record["injection_not_applied"] = not_applied

        if result["error"]:
            record["state"] = "errored"
            finding = self._exec_finding(index, step, record, name)
            self.findings.append(finding)
            self._abort(index, "execution_error", record["error"], emitted=True)
            return

        status = result["response"]["status"]
        matched_status = status in step["expect"]["status"]
        miss_reason = self._resolve_captures(step, record, sink)
        sink.clear()

        scan = result["response"]["marker_scan"]
        contains = step["expect"].get("contains_marker")
        if (
            contains
            and scan == "present"
            and contains == step["as"]
            and not result["response"]["from_cache"]
        ):
            # The top tier of the control ladder: this identity read back its
            # OWN marker at this path, in this sequence, at this moment. A
            # response an intermediary announced as a cache hit establishes the
            # first three and not the fourth, so it is not a control.
            self.observed_markers.setdefault(contains, index)

        if step["role"] == "setup":
            self._grade_setup(index, step, record, name, matched_status, miss_reason)
            return
        self._grade_assert(
            index, step, record, name, matched_status, miss_reason
        )

    def _resolve_captures(
        self, step: dict[str, Any], record: dict[str, Any], sink: Mapping[str, Any]
    ) -> tuple[str, str] | None:
        miss: tuple[str, str] | None = None
        for key, expression in (step.get("capture") or {}).items():
            if miss is not None:
                record["captures"].append(
                    {
                        "name": key,
                        "extractor": expression,
                        "resolved": False,
                        "reason": "step_not_executed",
                    }
                )
                continue
            value, reason = resolve_extractor(expression, sink)
            record["captures"].append(
                {
                    "name": key,
                    "extractor": expression,
                    "resolved": reason is None,
                    "reason": reason,
                }
            )
            if reason is None:
                self.values[key] = value
            else:
                miss = (key, reason)
        return miss

    def _grade_setup(
        self,
        index: int,
        step: dict[str, Any],
        record: dict[str, Any],
        name: str,
        matched_status: bool,
        miss: tuple[str, str] | None,
    ) -> None:
        status = record["response"]["status"]
        contains = step["expect"].get("contains_marker")
        scan = record["response"]["marker_scan"]
        degraded = self._degraded(step, record, bool(contains))
        if degraded is not None:
            # A setup step is a precondition. One built on an anonymous probe or
            # on a cached read has not established the state the assert steps
            # are about, so the sequence stops rather than proceeding to grade
            # a boundary against a fixture that may not exist.
            record["state"] = "mismatched"
            self._abort(index, degraded, f"received HTTP {status}")
            return
        if not matched_status:
            record["state"] = "mismatched"
            self._abort(
                index,
                "setup_failed",
                f"received HTTP {status} (declared: one of "
                f"{step['expect']['status']})",
            )
            return
        if contains and scan != "present":
            record["state"] = "mismatched"
            self._abort(
                index,
                "setup_failed",
                f"received HTTP {status} but {quoted(contains)}'s marker was not "
                "observed in that response",
            )
            return
        if miss is not None:
            record["state"] = "mismatched"
            self._abort(
                index,
                "capture_missed",
                f"did not yield capture {quoted(miss[0])} ({miss[1]})",
            )
            return
        record["state"] = "matched"

    def _grade_assert(
        self,
        index: int,
        step: dict[str, Any],
        record: dict[str, Any],
        name: str,
        matched_status: bool,
        miss: tuple[str, str] | None,
    ) -> None:
        expect = step["expect"]
        status = record["response"]["status"]
        scan = record["response"]["marker_scan"]
        contains = expect.get("contains_marker")
        excludes = expect.get("excludes_marker")
        identity = step["as"]
        finding: dict[str, Any] | None = None

        control_source: str | None = None
        control_state: str | None = None
        control_detail: str | None = None
        if excludes:
            control_source, control_state, control_detail = self._control(excludes)

        # §5.2. Condition 5 -- an earlier foreign non-safe method against the
        # same path that SUCCEEDED -- is what makes this a WRITE-EFFECT
        # statement rather than a broken fixture.
        #
        # `scan == "absent"` and not `scan != "present"`: 'absent' is the only
        # one of the four scan states that means the oracle READ the response
        # and the marker was not in it. 'unknown' means the oracle FAILED
        # (encoding_unsupported, decode_failed, truncated, incomplete_body) and
        # `None` means it never ran. Treating those as absence turned any
        # brotli-enabled CDN tier in front of a CORRECT api into a `confirmed`
        # VERIDOR-EFFECT-001, with the finding's own evidence block recording
        # `marker.state: "unknown"` while its message asserted the marker "is
        # absent now". Those states belong to the ORACLE-001 branch below.
        effect_writer: int | None = None
        if contains and contains == identity and scan == "absent":
            effect_writer = self._prior_foreign_write(
                identity, index, self.resolved_paths.get(index)
            )

        evidence = self._evidence(step, index, record)
        if contains or excludes:
            owner = contains or excludes
            evidence["marker"] = {
                "mode": "contains" if contains else "excludes",
                "owner_identity": owner,
                "state": scan,
                "reason": record["response"]["marker_scan_reason"],
                "control_state": control_state,
                "encodings_matched": record["response"]["marker_encodings"],
            }
            if excludes:
                evidence["marker"]["control_source"] = control_source
                evidence["marker"]["control_reason"] = control_detail
            evidence["marker"]["channel"] = record["response"]["marker_channel"]
            evidence["marker"]["from_cache"] = record["response"]["from_cache"]
        base = {**self._base_finding(step, index, record), "evidence": evidence}

        # Degraded state never looks like a result. A positive marker match is
        # exempt: it is evidence the marker crossed, and neither a dead session
        # nor a cache can make bytes that were on the wire not have been there.
        degraded = None if (excludes and scan == "present") else self._degraded(
            step, record, bool(contains or excludes)
        )
        if degraded is not None:
            record["state"] = "mismatched"
            self.findings.append(
                self._degraded_finding(index, step, record, name, base, degraded)
            )
            if miss is not None:
                self._abort(
                    index,
                    "capture_missed",
                    f"did not yield capture {quoted(miss[0])} ({miss[1]})",
                    emitted=True,
                )
            return

        if (
            not matched_status
            and status in core.NOT_AN_ANSWER_STATUSES
            and scan != "present"
        ):
            # The same rule `core._grade_check` applies to a single-request
            # check, applied here because sequences grade on their OWN path and
            # inherited none of it: a 429 on an assert step came out as
            # `vulnerable`, an authorization failure asserted from a rate
            # limit. Two copies of the grading logic, and the fix reached one.
            #
            # A marker actually observed still wins, exactly as it does there:
            # measured data flow outranks status semantics.
            record["state"] = "inconclusive"
            self.findings.append({
                "id": step_finding_id(self.sequence["id"], step, index, "execution"),
                "rule_id": "VERIDOR-EXEC-001",
                "level": "warning",
                "verdict": "inconclusive",
                "evidence_grade": "n/a",
                "title": f"Could not verify {name} as {identity}",
                "message": (
                    f"Identity {quoted(identity)} received HTTP {status}, which is not an "
                    "answer from the authorization layer: "
                    + core.unanswered_cause(status)
                    + " This step establishes nothing about the "
                    f"declared status {expect['status']}, in either direction."
                ),
                **base,
                "remediation": core.unanswered_remediation(status),
            })
            self._abort(
                index,
                "step_inconclusive",
                f"was answered with HTTP {status} rather than graded",
                emitted=True,
            )
            return

        if not matched_status:
            record["state"] = "mismatched"
            message = (
                f"Identity {quoted(identity)} received HTTP {status} "
                f"(declared: one of {expect['status']})."
            )
            if effect_writer is not None:
                finding = self._effect_finding(
                    index, step, record, name, base, message, effect_writer
                )
            elif excludes and scan == "present":
                finding = {
                    "id": step_finding_id(self.sequence["id"], step, index, "status"),
                    "rule_id": "VERIDOR-AUTHZ-001",
                    "level": "error",
                    "verdict": "vulnerable",
                    "evidence_grade": "confirmed",
                    "title": f"Authorization expectation failed for {name}",
                    "message": (
                        message[:-1]
                        + f" and the response carried {quoted(excludes)}'s marker: "
                        + core._observed_flow(excludes, identity)
                    ),
                    **base,
                    "remediation": core._AUTHZ_REMEDIATION,
                }
            else:
                grade = "ungraded"
                if excludes:
                    grade = "suspected"
                    why = core._unproven_reason(
                        scan,
                        record["response"]["marker_scan_reason"],
                        control_state,
                        control_detail,
                    )
                    message += (
                        f" {quoted(excludes)}'s marker was not observed ({why}), "
                        "so data exposure is unproven."
                    )
                refused = not core._target_served(status)
                if refused:
                    message += core.refusal_sentence(status)
                finding = {
                    "id": step_finding_id(self.sequence["id"], step, index, "status"),
                    "rule_id": "VERIDOR-AUTHZ-001",
                    "level": "error",
                    "verdict": "unexpected_denial" if refused else "vulnerable",
                    "evidence_grade": grade,
                    "title": f"Authorization expectation failed for {name}",
                    "message": message,
                    **base,
                    "remediation": (
                        core.denial_remediation(status)
                        if refused else core._AUTHZ_REMEDIATION
                    ),
                }
        else:
            # §4.2: a step matched iff no transport error, the status was
            # declared, every capture resolved, and any declared
            # contains_marker was observed present.
            record["state"] = (
                "matched"
                if miss is None and (not contains or scan == "present")
                else "mismatched"
            )
            if excludes and scan == "present":
                finding = {
                    "id": step_finding_id(self.sequence["id"], step, index, "marker"),
                    "rule_id": "VERIDOR-LEAK-001",
                    "level": "error",
                    "verdict": "vulnerable",
                    "evidence_grade": "confirmed",
                    "title": f"Cross-identity data flow observed for {name}",
                    "message": (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{status}, but the response carried {quoted(excludes)}'s "
                        "marker: " + core._observed_flow(excludes, identity)
                    ),
                    **base,
                    "remediation": core._LEAK_REMEDIATION,
                }
            elif effect_writer is not None:
                finding = self._effect_finding(
                    index,
                    step,
                    record,
                    name,
                    base,
                    f"Identity {quoted(identity)} received the declared HTTP {status}.",
                    effect_writer,
                )
            elif (contains and scan != "present") or (
                excludes and (scan == "unknown" or control_state != "present")
            ):
                why = core._unproven_reason(
                    scan,
                    record["response"]["marker_scan_reason"],
                    control_state,
                    control_detail,
                )
                owner = contains or excludes
                if contains:
                    message = (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{status}, but {quoted(owner)}'s marker was not observed "
                        f"({why}); marker results for this step are unverified."
                    )
                else:
                    message = (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{status}, but the absence of {quoted(owner)}'s marker could "
                        f"not be verified ({why})."
                    )
                finding = {
                    "id": step_finding_id(self.sequence["id"], step, index, "oracle"),
                    "rule_id": "VERIDOR-ORACLE-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Marker oracle unverified for {name}",
                    "message": message,
                    **base,
                    "remediation": (
                        "Confirm the marker is stored in the identity's data and "
                        "returned by this endpoint, then re-run."
                    ),
                }

        if finding is not None:
            self.findings.append(finding)
        if miss is not None:
            record["state"] = "mismatched"
            self._abort(
                index,
                "capture_missed",
                f"did not yield capture {quoted(miss[0])} ({miss[1]})",
                emitted=finding is not None,
            )

    def _degraded(
        self, step: dict[str, Any], record: dict[str, Any], marker_mode: bool
    ) -> str | None:
        """Is this response unusable as evidence? Returns a closed reason.

        Two conditions, both of which used to be graded ``matched`` and green.

        ``session_not_live``: the module header says a lost session "turns it
        into an anonymous probe, which gets a 401 that matches a declared
        denial ... manufactures a SAFE verdict over a live vulnerability".
        ``IdentitySession.is_live`` closes the half Veridor can see from its own
        jar; a session the TARGET invalidated server-side still sends a
        perfectly healthy-looking cookie, and the only trace is the
        authentication status that comes back. For a logged-in identity that
        status is ambiguous between "the boundary is enforced" and "we are not
        logged in any more", and an ambiguity is not a pass.

        ``response_from_cache``: an intermediary said this body came from its
        store. Whatever the marker scan saw was true at some earlier time.
        """
        if step["as"] in self.sessions:
            status = record["response"]["status"]
            if status in core.AUTHN_STATUSES:
                return "session_not_live"
        if marker_mode and record["response"]["from_cache"]:
            return "response_from_cache"
        return None

    def _degraded_finding(
        self,
        index: int,
        step: dict[str, Any],
        record: dict[str, Any],
        name: str,
        base: dict[str, Any],
        reason: str,
    ) -> dict[str, Any]:
        identity = step["as"]
        status = record["response"]["status"]
        if reason == "session_not_live":
            rule_id, kind = "VERIDOR-SESSION-001", "session"
            title = f"Session liveness unverified for {name}"
            message = (
                f"Identity {quoted(identity)} logs in with a session and received "
                f"HTTP {status}, which is what this runner sees when a session "
                "has ended. Veridor cannot tell that apart from the target "
                "refusing an authenticated caller, so this probe establishes "
                "nothing about the declared expectation."
            )
            remediation = core._SESSION_LIVENESS_REMEDIATION
        else:
            rule_id, kind = "VERIDOR-CACHE-001", "cache"
            title = f"Marker read from a cached response in {name}"
            message = (
                f"Identity {quoted(identity)} received HTTP {status}, but an "
                "intermediary announced the response as served from a cache. "
                "The marker result describes the object at some earlier time, "
                "so it cannot settle this step's expectation."
            )
            remediation = core._CACHE_REMEDIATION
        return {
            "id": step_finding_id(self.sequence["id"], step, index, kind),
            "rule_id": rule_id,
            "level": "warning",
            "verdict": "inconclusive",
            "evidence_grade": "n/a",
            "title": title,
            "message": message,
            **base,
            "remediation": remediation,
        }

    def _effect_finding(
        self,
        index: int,
        step: dict[str, Any],
        record: dict[str, Any],
        name: str,
        base: dict[str, Any],
        message: str,
        writer_index: int,
    ) -> dict[str, Any]:
        """``VERIDOR-EFFECT-001``: the victim's own data did not survive.

        The ``unexpected_denial`` downgrade deliberately does NOT apply here.
        Elsewhere a refusal means the target handed out nothing, so calling it
        'vulnerable' would be incoherent. That reasoning inverts when the owner
        receives 404 for their own object after another identity's write: the
        refusal IS the vulnerability, and the remediation is not "investigate
        why the target refused" but "an earlier step destroyed data that should
        have survived". Scoped to sequence steps only -- in a single request
        there is no observed prior write to attribute the loss to.
        """
        identity = step["as"]
        control_index = self.observed_markers.get(identity)
        grade = "confirmed" if control_index is not None else "suspected"
        marker_evidence = base["evidence"].get("marker")
        if isinstance(marker_evidence, dict):
            marker_evidence["control_source"] = (
                "sequence_prior_step" if control_index is not None else "none"
            )
            marker_evidence["control_step_index"] = control_index
        writer = self.records[writer_index]
        if control_index is not None:
            detail = (
                f" {quoted(identity)}'s marker was observed at step {control_index} of "
                f"this sequence and is absent now."
            )
        else:
            detail = (
                f" No earlier step in this sequence observed {quoted(identity)}'s "
                "marker, so absent-now may mean never-there."
            )
        return {
            "id": step_finding_id(self.sequence["id"], step, index, "effect"),
            "rule_id": "VERIDOR-EFFECT-001",
            "level": "error",
            "verdict": "vulnerable",
            "evidence_grade": grade,
            "title": f"Write crossed a boundary in {name}",
            "message": (
                message
                + f" {quoted(identity)}'s own marker was not observed, and step "
                f"{writer_index} issued {writer['request']['method']} as "
                f"{quoted(writer['as'])} against the same path this step reads."
                + detail
            ),
            **base,
            "remediation": _EFFECT_REMEDIATION,
        }

    def _exec_finding(
        self,
        index: int,
        step: dict[str, Any],
        record: dict[str, Any],
        name: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "id": step_finding_id(self.sequence["id"], step, index, "execution"),
            "rule_id": "VERIDOR-EXEC-001",
            "level": "warning",
            "verdict": "inconclusive",
            "evidence_grade": "n/a",
            "title": f"Could not verify {name} as {step['as']}",
            "message": core.execution_message(record["error"], reason),
            **self._base_finding(step, index, record),
            "evidence": self._evidence(step, index, record),
            # A step withheld by its own configuration gets configuration
            # advice; it used to be told to check the network.
            "remediation": core.unsent_remediation(record["error"], reason)
            or "Confirm the target is reachable from the runner and retry.",
        }

    def _abort(
        self, index: int, reason: str, detail: str, *, emitted: bool = False
    ) -> None:
        if reason not in ABORT_REASONS:
            # Unreachable while the set is complete, and asserted because the
            # failure is silent: a reason outside the vocabulary reaches the run
            # document and every consumer that trusts the set misreads it.
            raise AssertionError(f"abort reason {quoted(reason)} is not in ABORT_REASONS")
        self.aborted_at = index
        self.abort_reason = reason
        self.abort_detail = detail
        self.abort_step_emitted_finding = emitted

    # -- teardown --------------------------------------------------------

    def _run_teardown(self) -> list[dict[str, Any]]:
        """Attempt EVERY teardown entry, best effort, and never raise out.

        Three rules, all normative and all tested:

        * Every entry is attempted. One failure does not stop the ones after it;
          stopping at the first is how half a fixture set gets orphaned.
        * Nothing here creates a finding, enters ``probes``, touches a verdict
          counter, or contributes to a fingerprint. A failed cleanup is an
          operational problem, and failing a security gate on litter trains
          operators to ignore the gate.
        * Every failure and every skip is loud, on stderr and in CI
          annotations, because silent pollution is the failure this exists to
          prevent -- and stderr is the only channel that survives cancellation.
        """
        entries: list[dict[str, Any]] = []
        self.teardown = entries
        for index, entry in enumerate(self.sequence.get("teardown") or ()):
            request = entry["request"]
            record: dict[str, Any] = {
                "index": index,
                "as": entry["as"],
                "request": {
                    "method": request.get("method", "GET").upper(),
                    "url": _template_url(self.base_url, request["path"]),
                },
                "status": None,
                "matched": False,
                "state": "skipped_unresolved",
                "error": None,
            }
            entries.append(record)
            try:
                self._run_teardown_entry(entry, record)
            except Exception:
                # An unexpected failure in cleanup must not abandon the entries
                # after it, and must not escape into the caller's control flow.
                record["state"] = "errored"
                record["error"] = "teardown raised an unexpected error"
                self.teardown_failures += 1
            if record["state"].startswith("skipped"):
                self.teardown_skipped += 1
            if record["state"] != "executed" or not record["matched"]:
                self._warn_teardown(record)
        if self.interrupted:
            self.teardown_state = "aborted"
        elif not entries:
            self.teardown_state = "not_required"
        elif any(
            entry["state"] == "errored" or not entry["matched"] for entry in entries
            if not entry["state"].startswith("skipped")
        ):
            self.teardown_state = "failed"
        elif any(entry["state"].startswith("skipped") for entry in entries):
            self.teardown_state = "incomplete"
        else:
            self.teardown_state = "clean"
        return entries

    def _run_teardown_entry(
        self, entry: dict[str, Any], record: dict[str, Any]
    ) -> None:
        request = entry["request"]
        session = self.sessions.get(entry["as"])
        if session is not None and session.state != "established":
            # Teardown never re-establishes a session; it reuses the jar the
            # identity already has. With no session there is no authenticated
            # way to clean up, and guessing is worse than reporting.
            record["state"] = "skipped_session_unavailable"
            self.teardown_failures += 1
            return
        unresolved = [
            token
            for kind, token in _entry_tokens(request)
            if kind == "var" and token != "run_id" and token not in self.values
        ]
        if unresolved:
            # A literal '${invoice_id}' must never reach the wire. Skipping is
            # engine fail-safety, not config branching: nothing in the config
            # expresses a condition.
            record["state"] = "skipped_unresolved"
            self.teardown_failures += 1
            return
        try:
            resolved = _resolve_request(
                request, self.values, self.run_id, self.markers, self.base_url
            )
        except _PathInvalid:
            record["state"] = "errored"
            record["error"] = "the interpolated path is not a valid path"
            self.teardown_failures += 1
            return
        # Teardown is cleanup, not measurement: needles=None always, and
        # graded=False so a body that cannot carry a declared injection does
        # not refuse the request. Teardown is never graded, so the fail-closed
        # refusal a graded probe gets would only orphan the fixture this entry
        # exists to remove; the request is sent and the drop is noted instead.
        result = core._perform_request(
            self.base_url,
            self.teardown_timeout,
            resolved,
            self.identities[entry["as"]],
            session=session,
            graded=False,
        )
        record["error"] = redact_captures(result["error"], self.values)
        record["status"] = result["response"]["status"]
        not_applied = result.get("injection_not_applied")
        if not_applied:
            record["injection_not_applied"] = not_applied
        if result["error"]:
            record["state"] = "errored"
            self.teardown_failures += 1
            return
        record["state"] = "executed"
        expect = entry.get("expect") or {}
        statuses = expect.get("status")
        record["matched"] = (
            record["status"] in statuses if isinstance(statuses, list) else True
        )
        if not record["matched"]:
            self.teardown_failures += 1

    def _warn_teardown(self, record: dict[str, Any]) -> None:
        detail = record["error"] or (
            f"HTTP {record['status']}" if record["status"] is not None else record["state"]
        )
        _warn(
            f"teardown entry {record['index']} of sequence "
            f"{quoted(self.sequence['id'])} "
            f"({core.terminal_text(record['request']['method'])} "
            f"{core.terminal_text(record['request']['url'])}, as {quoted(record['as'])}) "
            f"did not complete cleanly: {record['state']} -- "
            f"{core.terminal_text(detail)}. The target may hold a "
            "fixture this run created."
        )

    # -- completion ------------------------------------------------------

    def _finish(self, name: str) -> None:
        skipped = [
            (record["index"], record["role"])
            for record in self.records
            if record["state"] == "skipped"
        ]
        outcome = "aborted" if self.aborted_at is not None else "completed"
        if self.aborted_at is not None and (
            skipped or not self.abort_step_emitted_finding
        ):
            self.findings.append(self._sequence_finding(name, skipped))
        for finding in self.findings:
            context = finding["evidence"]["sequence"]
            context["outcome"] = outcome
            context["skipped_steps"] = [index for index, _ in skipped]
        self._annotate_write_effects()

    def _sequence_finding(
        self, name: str, skipped: list[tuple[int, str]]
    ) -> dict[str, Any]:
        index = self.aborted_at or 0
        step = self.steps[index]
        record = self.records[index]
        message = (
            f"Sequence {quoted(self.sequence['id'])} could not be completed. Step "
            f"{index} ({step['role']}, as {quoted(step['as'])}, "
            f"{core.terminal_text(record['request']['method'])} "
            f"{core.terminal_text(step['request']['path'])}) "
            f"{self.abort_detail}, so the state the later steps depend on was "
            f"never established."
            + _skipped_clause(skipped)
            + " No conclusion about authorization was reached: this is neither "
            "a pass nor a failure of the declared expectations."
        )
        return {
            "id": step_finding_id(self.sequence["id"], step, index, "sequence"),
            "rule_id": "VERIDOR-SEQ-001",
            "level": "warning",
            "verdict": "inconclusive",
            "evidence_grade": "n/a",
            "title": f"Sequence {name} was not completed",
            "message": redact_captures(message, self.values),
            **self._base_finding(step, index, record),
            "evidence": {
                **self._evidence(step, index, record),
                "abort_reason": self.abort_reason,
                "skipped": [
                    {
                        "index": skipped_index,
                        "as": self.steps[skipped_index]["as"],
                        "role": role,
                    }
                    for skipped_index, role in skipped
                ],
            },
            "remediation": _SEQ_REMEDIATION,
        }

    def _annotate_write_effects(self) -> None:
        """Let the victim's read settle what the attacker's 200 actually meant.

        A 200 to an unauthorized DELETE that silently no-opped is indistinguishable
        from a real cross-tenant delete without a follow-up read. The verdict is
        NOT downgraded -- a target that answers 200 to an unauthorized DELETE is
        still failing the declaration, and softening it would hide a real defect
        behind an implementation detail -- but the refutation is stated inline.
        """
        effect_steps = {
            finding["step_index"]
            for finding in self.findings
            if finding["rule_id"] == "VERIDOR-EFFECT-001"
        }
        for finding in self.findings:
            if finding["rule_id"] != "VERIDOR-AUTHZ-001":
                continue
            index = finding["step_index"]
            record = self.records[index]
            if record["request"]["method"] in SAFE_METHODS:
                continue
            verifier = self._verifier_for(index, record["as"])
            if verifier is None:
                continue
            verifying = self.records[verifier]["response"]
            if verifier in effect_steps:
                state = "effect_observed"
            elif verifying["from_cache"]:
                # The one place in this file where reading stale data flips the
                # conclusion. A shared or path-keyed cache in front of the
                # target answers the verification read from a copy taken BEFORE
                # the write under test; the marker is found; and Veridor
                # appends an exculpation to a finding that describes real data
                # destruction, plus a machine-readable 'no_effect_observed' that
                # a triage pipeline will deprioritise. A cached body cannot
                # refute anything.
                state = "not_verified"
            elif verifying["marker_scan"] == "present":
                state = "no_effect_observed"
            else:
                state = "not_verified"
            finding["evidence"]["write_effect"] = {
                "verified_by_step": verifier,
                "state": state,
            }
            if state == "no_effect_observed":
                finding["message"] += (
                    f" A later step in this sequence observed "
                    f"{quoted(self.steps[verifier]['as'])}'s data still present after "
                    "this request, so this response did not take effect on the "
                    "object under test."
                )

    def _verifier_for(self, writer_index: int, writer_identity: str) -> int | None:
        written = self.resolved_paths.get(writer_index)
        if written is None:
            return None
        for index in range(writer_index + 1, len(self.steps)):
            step = self.steps[index]
            record = self.records[index]
            if record["state"] == "skipped" or record["response"] is None:
                continue
            if step["role"] != "assert":
                continue
            if self.resolved_paths.get(index) != written:
                # "did not take effect on the object under test" is a claim
                # about ONE object. A read of some other path cannot make it.
                continue
            contains = step["expect"].get("contains_marker")
            if contains and contains == step["as"] and contains != writer_identity:
                return index
        return None


def _entry_tokens(request: dict[str, Any]) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    path = request.get("path")
    if isinstance(path, str):
        tokens.extend(scan_tokens(path))
    for value in dict(request.get("headers") or {}).values():
        if isinstance(value, str):
            tokens.extend(scan_tokens(value))
    if "json" in request:
        for text in _body_strings(request["json"]):
            tokens.extend(scan_tokens(text))
    elif isinstance(request.get("body"), str):
        tokens.extend(scan_tokens(request["body"]))
    return tokens


def execute_sequences(
    config: dict[str, Any],
    config_path: Path,
    run_id: str,
    marker_controls: Mapping[str, dict[str, Any]],
    sessions: Mapping[str, IdentitySession] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Run every declared sequence serially. ``(records, findings, counters)``."""
    records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    counters = {
        "sequences": 0,
        "sequence_steps": 0,
        "sequence_steps_matched": 0,
        "sequences_aborted": 0,
        "teardown_failures": 0,
    }
    for sequence in config.get("sequences") or ():
        for state in (sessions or {}).values():
            state.reestablish_for_check()
        execution = _SequenceRun(
            config, sequence, config_path, run_id, marker_controls, sessions
        )
        execution.execute()
        counters["sequences"] += 1
        counters["sequence_steps"] += len(execution.records)
        counters["sequence_steps_matched"] += sum(
            record["state"] == "matched" for record in execution.records
        )
        counters["sequences_aborted"] += execution.aborted_at is not None
        counters["teardown_failures"] += execution.teardown_failures
        records.append(
            {
                "sequence_id": sequence["id"],
                "name": sequence.get("name"),
                "outcome": "aborted" if execution.aborted_at is not None else "completed",
                "aborted_at_step": execution.aborted_at,
                "abort_reason": execution.abort_reason,
                "steps": execution.records,
                "teardown": execution.teardown,
                # A lifecycle state, never a verdict. It is reported beside the
                # findings and feeds no exit code unless the operator opts in
                # with --require-clean-teardown.
                "teardown_state": execution.teardown_state,
            }
        )
        findings.extend(execution.findings)
        # The only copy of every captured value in this process, dropped here.
        # ``resolved_paths`` is dropped with it: a resolved path can embed one.
        execution.values.clear()
        execution.resolved_paths.clear()
    return records, findings, counters
