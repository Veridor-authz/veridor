"""OpenAPI route inventory parsing and concrete-path to template matching.

Stdlib only, and offline by construction: nothing in this module opens a socket,
issues an HTTP request, or observes an HTTP response body. It reads two files at
most -- never one named by the specification itself -- so it is safe to run in an
air-gapped CI job.

The parser walks exactly two levels of the document, ``paths.<path>`` and
``paths.<path>.<method>``. It never descends into schemas, parameters, request
bodies, or responses, which is what makes the hard refusal of external ``$ref``
at those two levels both cheap and safe.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import unquote, urlsplit


class SpecError(ValueError):
    """Raised when an OpenAPI specification cannot be parsed or is unusable."""


DEFAULT_METHODS: frozenset[str] = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
ALL_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
)
MAX_SPEC_BYTES: int = 16 * 1024 * 1024
MAX_OPERATIONS: int = 20_000
MAX_PATH_SEGMENTS: int = 64
MAX_REF_DEPTH: int = 32

#: An OpenAPI path template placeholder, e.g. ``{id}``. Public because a
#: *concrete* request path must be checked for one: a check path that still
#: reads ``/api/invoices/{id}`` matches the template it was generated from and
#: would otherwise be credited as coverage it has not earned.
TEMPLATE_TOKEN: re.Pattern[str] = re.compile(r"\{[^{}/]*\}")

_PARAMETER_SEGMENT = re.compile(r"^\{[^{}/]+\}$")
_WILDCARD_SEGMENT = re.compile(r"\{[^{}/]*[*+][^{}/]*\}")
_TEMPLATE_TOKEN = TEMPLATE_TOKEN
_SERVER_VARIABLE = re.compile(r"\{([^{}/]+)\}")
_YAML_FIRST_LINE = re.compile(r"^\s*(-\s|[A-Za-z_$\"'][^:]*:(\s|$))")

_LITERAL = 2
_MIXED = 1
_PARAMETER = 0

_YAML_REMEDY = (
    "Convert once:\n"
    "  npx @redocly/cli bundle {name} -o openapi.json\n"
    "  # or, where PyYAML is installed -- NOT in Veridor's own virtualenv,\n"
    "  # which has no dependencies by design:\n"
    "  #   python3 -c \"import yaml,json,sys; "
    "json.dump(yaml.safe_load(open(sys.argv[1])), open(sys.argv[2],'w'))\" "
    "{name} openapi.json\n"
    "\n"
    # Deliberately does NOT name a verb. This string is reached from `init`,
    # `map` and `coverage` alike, and it used to end "Then: veridor coverage
    # --config veridor.json ..." for all three -- so a user who ran `init` was
    # told to run a different command, with a flag `init` rejects. Following it
    # literally gives `unrecognized arguments: --config veridor.json`.
    "Then re-run the same command with --openapi openapi.json"
)

_mixed_cache: dict[str, re.Pattern[str]] = {}
_segment_cache: dict[tuple[str, bool], tuple[str, ...]] = {}


@dataclass(frozen=True)
class Operation:
    """One ``(path_template, METHOD)`` pair from the route inventory."""

    method: str
    path_template: str
    operation_id: str | None
    summary: str | None
    deprecated: bool
    base_paths: tuple[str, ...]
    pointer: str

    def absolute_path(self, base_path: str) -> str:
        """Return this operation's template prefixed with ``base_path``."""
        prefix = base_path.rstrip("/")
        if not prefix:
            return self.path_template
        if self.path_template == "/":
            return prefix
        return prefix + self.path_template

    def key(self) -> tuple[str, str]:
        return (self.method, self.path_template)


@dataclass(frozen=True)
class RouteInventory:
    """Every in-scope operation declared by one specification."""

    operations: tuple[Operation, ...]
    base_paths: tuple[str, ...]
    spec_version: str
    title: str | None
    path_count: int
    excluded: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...]

    def templates(self) -> tuple[str, ...]:
        """Unique path templates, in document order."""
        seen: dict[str, None] = {}
        for operation in self.operations:
            seen.setdefault(operation.path_template, None)
        return tuple(seen)

    def methods_for(self, path_template: str) -> frozenset[str]:
        """In-scope methods the spec defines for ``path_template``."""
        return frozenset(
            operation.method
            for operation in self.operations
            if operation.path_template == path_template
        )


@dataclass(frozen=True)
class MatchResult:
    """The winning template for a concrete path, plus every runner-up."""

    template: str
    score: tuple[int, ...]
    ambiguous_with: tuple[str, ...]


# ---------------------------------------------------------------------------
# loading / parsing
# ---------------------------------------------------------------------------


def _sniffs_as_yaml(text: str) -> bool:
    stripped = text.lstrip("\ufeff")
    if stripped.lstrip().startswith("---"):
        return True
    for line in stripped.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        return bool(_YAML_FIRST_LINE.match(line))
    return False


def load_spec(path: Path) -> dict[str, Any]:
    """Read and JSON-decode a specification.

    Raises ``SpecError`` with a copy-pasteable conversion remedy when the file
    content sniffs as YAML. Detection is by content, never by extension, so a
    ``.json`` file holding YAML produces the same actionable message rather than
    a confusing decoder traceback.
    """
    path = Path(path)
    name = path.name or str(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SpecError(f"cannot read OpenAPI spec {path}: {exc.strerror or exc}") from exc
    if size > MAX_SPEC_BYTES:
        raise SpecError(
            f"OpenAPI spec {path} is {size} bytes, over the {MAX_SPEC_BYTES} byte limit"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SpecError(f"cannot read OpenAPI spec {path}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_SPEC_BYTES:
        raise SpecError(
            f"OpenAPI spec {path} is {len(raw)} bytes, over the {MAX_SPEC_BYTES} byte limit"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecError(f"OpenAPI spec {path} is not valid UTF-8: {exc}") from exc

    try:
        document = json.loads(text.lstrip("\ufeff"))
    except json.JSONDecodeError as exc:
        if _sniffs_as_yaml(text):
            raise SpecError(
                f"{name} is not JSON. Veridor parses JSON specs only -- it has no YAML\n"
                "dependency by design, and a hand-written YAML parser could silently drop "
                "routes and\ninflate your coverage number.\n\n"
                + _YAML_REMEDY.format(name=name)
            ) from exc
        raise SpecError(
            f"invalid JSON in {path}: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        ) from exc
    if not isinstance(document, dict):
        raise SpecError(
            f"{path} does not contain an OpenAPI document: top level is "
            f"{type(document).__name__}, expected an object"
        )
    return document


def _resolve_pointer(document: Mapping[str, Any], ref: str, label: str) -> Any:
    pointer = ref[1:]
    if pointer and not pointer.startswith("/"):
        raise SpecError(f"{label} uses an unsupported $ref {ref!r}")
    node: Any = document
    if pointer:
        for token in pointer.split("/")[1:]:
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and token in node:
                node = node[token]
            elif isinstance(node, list) and token.lstrip("-").isdigit():
                index = int(token)
                if not 0 <= index < len(node):
                    raise SpecError(f"{label} $ref {ref!r} does not resolve")
                node = node[index]
            else:
                raise SpecError(f"{label} $ref {ref!r} does not resolve")
    return node


def _dereference(document: Mapping[str, Any], node: Any, label: str) -> Any:
    chain: list[str] = []
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if not ref.startswith("#"):
            raise SpecError(
                f"{label} uses the external $ref {ref!r}. Veridor never follows a $ref "
                "outside the document: it would mean filesystem access relative to the "
                "spec and a partially parsed spec yields a wrong denominator. Bundle the "
                "spec first, e.g. npx @redocly/cli bundle openapi.json -o bundled.json"
            )
        if ref in chain:
            raise SpecError(
                f"{label} contains a $ref cycle: {' -> '.join([*chain, ref])}"
            )
        chain.append(ref)
        if len(chain) > MAX_REF_DEPTH:
            raise SpecError(
                f"{label} exceeds the $ref depth limit of {MAX_REF_DEPTH}: "
                f"{' -> '.join(chain)}"
            )
        node = _resolve_pointer(document, ref, label)
    return node


def _normalize_base_candidate(value: str) -> str:
    candidate = normalize_path(value)
    if candidate in {"/", ""}:
        return ""
    if not candidate.startswith("/"):
        candidate = "/" + candidate
    return candidate


def _server_base_paths(servers: Any, warnings: list[str], label: str) -> tuple[str, ...]:
    if not isinstance(servers, list):
        return ()
    found: dict[str, None] = {}
    for entry in servers:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str):
            continue
        raw_path = urlsplit(url).path
        if "{" in raw_path:
            variables = entry.get("variables")
            resolved = raw_path
            missing = False
            for name in _SERVER_VARIABLE.findall(raw_path):
                default = None
                if isinstance(variables, dict) and isinstance(variables.get(name), dict):
                    default = variables[name].get("default")
                if not isinstance(default, str):
                    missing = True
                    break
                resolved = resolved.replace("{" + name + "}", default)
            if missing:
                warnings.append(
                    f"templated_server_url: {label} server url {url!r} has no default for "
                    "every path variable; candidate dropped"
                )
                continue
            raw_path = resolved
        found.setdefault(_normalize_base_candidate(raw_path), None)
    return tuple(found)


def _spec_version(document: Mapping[str, Any]) -> str:
    version = document.get("openapi")
    if isinstance(version, str) and version:
        return version
    version = document.get("swagger")
    if isinstance(version, str) and version:
        return version
    present = ", ".join(sorted(str(key) for key in document)) or "(none)"
    raise SpecError(
        "document is not an OpenAPI specification: neither 'openapi' nor 'swagger' is "
        f"present. Top-level keys found: {present}"
    )


def parse_spec(
    document: Mapping[str, Any],
    *,
    source: str = "<spec>",
    methods: frozenset[str] = DEFAULT_METHODS,
    exclude_deprecated: bool = False,
) -> RouteInventory:
    """Build a route inventory from an already-decoded specification document."""
    if not isinstance(document, dict):
        raise SpecError(f"{source} must be a JSON object")
    version = _spec_version(document)
    scope = frozenset(method.upper() for method in methods)

    paths = document.get("paths")
    if not isinstance(paths, dict):
        present = ", ".join(sorted(str(key) for key in document)) or "(none)"
        found = "missing" if "paths" not in document else type(paths).__name__
        raise SpecError(
            f"{source} has no usable 'paths' object ({found}). "
            f"Top-level keys found: {present}"
        )

    info = document.get("info")
    title = info.get("title") if isinstance(info, dict) else None
    if not isinstance(title, str):
        title = None

    warnings: list[str] = []
    excluded: list[dict[str, Any]] = []
    operations: list[Operation] = []
    seen_keys: dict[tuple[str, str], str] = {}

    if version.startswith("2"):
        base_path = document.get("basePath")
        document_bases = (
            (_normalize_base_candidate(base_path),) if isinstance(base_path, str) else ()
        )
    else:
        document_bases = _server_base_paths(document.get("servers"), warnings, source)

    path_count = 0
    for raw_path, raw_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            excluded.append(
                {"path": str(raw_path), "method": "*", "reason": "malformed_path"}
            )
            warnings.append(
                f"malformed_path: {raw_path!r} is not an absolute path and was excluded"
            )
            continue
        label = f"path item {raw_path!r}"
        item = _dereference(document, raw_item, label)
        if not isinstance(item, dict):
            excluded.append({"path": raw_path, "method": "*", "reason": "malformed_path"})
            warnings.append(
                f"malformed_path: {raw_path!r} does not describe a path item object"
            )
            continue

        template = normalize_path(raw_path)
        segments = split_segments(template)
        if len(segments) > MAX_PATH_SEGMENTS:
            excluded.append({"path": raw_path, "method": "*", "reason": "path_too_long"})
            warnings.append(
                f"path_too_long: {raw_path!r} has {len(segments)} segments, over the "
                f"limit of {MAX_PATH_SEGMENTS}; excluded"
            )
            continue
        if any(_WILDCARD_SEGMENT.search(segment) for segment in segments):
            excluded.append(
                {"path": raw_path, "method": "*", "reason": "wildcard_unsupported"}
            )
            warnings.append(
                f"wildcard_unsupported: {raw_path!r} uses a greedy parameter; excluded"
            )
            continue

        path_count += 1
        item_bases = _server_base_paths(item.get("servers"), warnings, label)
        base_paths = item_bases or document_bases
        merged = list(base_paths)
        if "" not in merged:
            merged.append("")

        for raw_method, raw_operation in item.items():
            if not isinstance(raw_method, str):
                continue
            method = raw_method.upper()
            if method not in ALL_METHODS:
                continue
            pointer = (
                "#/paths/"
                + raw_path.replace("~", "~0").replace("/", "~1")
                + "/"
                + raw_method
            )
            if method not in scope:
                excluded.append(
                    {"path": template, "method": method, "reason": "method_not_in_scope"}
                )
                continue
            operation = _dereference(document, raw_operation, f"{label} {method}")
            if not isinstance(operation, dict):
                excluded.append(
                    {"path": template, "method": method, "reason": "malformed_operation"}
                )
                warnings.append(
                    f"malformed_operation: {method} {raw_path!r} is not an object; excluded"
                )
                continue
            deprecated = operation.get("deprecated") is True
            if exclude_deprecated and deprecated:
                excluded.append(
                    {"path": template, "method": method, "reason": "deprecated"}
                )
                continue
            if isinstance(operation.get("servers"), list) and operation["servers"]:
                warnings.append(
                    f"ignored_operation_servers: {method} {template!r} declares "
                    "operation-level servers; ignored in v1"
                )
            key = (method, template)
            if key in seen_keys:
                excluded.append(
                    {"path": template, "method": method, "reason": "duplicate_operation"}
                )
                warnings.append(
                    f"duplicate_template: {method} {template!r} is declared more than once "
                    f"({seen_keys[key]} and {raw_path!r}); the first is used"
                )
                continue
            seen_keys[key] = repr(raw_path)
            operation_id = operation.get("operationId")
            summary = operation.get("summary")
            operations.append(
                Operation(
                    method=method,
                    path_template=template,
                    operation_id=operation_id if isinstance(operation_id, str) else None,
                    summary=summary if isinstance(summary, str) else None,
                    deprecated=deprecated,
                    base_paths=tuple(merged),
                    pointer=pointer,
                )
            )
            if len(operations) > MAX_OPERATIONS:
                raise SpecError(
                    f"{source} declares more than {MAX_OPERATIONS} in-scope operations"
                )

    inventory_bases: dict[str, None] = {}
    for operation in operations:
        for candidate in operation.base_paths:
            inventory_bases.setdefault(candidate, None)
    for candidate in document_bases:
        inventory_bases.setdefault(candidate, None)
    inventory_bases.setdefault("", None)

    return RouteInventory(
        operations=tuple(operations),
        base_paths=tuple(inventory_bases),
        spec_version=version,
        title=title,
        path_count=path_count,
        excluded=tuple(excluded),
        warnings=tuple(warnings),
    )


def load_inventory(
    path: Path,
    *,
    methods: frozenset[str] = DEFAULT_METHODS,
    exclude_deprecated: bool = False,
) -> RouteInventory:
    """``load_spec`` followed by ``parse_spec``."""
    path = Path(path)
    return parse_spec(
        load_spec(path),
        source=str(path),
        methods=methods,
        exclude_deprecated=exclude_deprecated,
    )


# ---------------------------------------------------------------------------
# normalization / matching
# ---------------------------------------------------------------------------


def _remove_dot_segments(path: str) -> str:
    buffer = path
    output: list[str] = []
    while buffer:
        if buffer.startswith("../"):
            buffer = buffer[3:]
        elif buffer.startswith("./"):
            buffer = buffer[2:]
        elif buffer.startswith("/./"):
            buffer = "/" + buffer[3:]
        elif buffer == "/.":
            buffer = "/"
        elif buffer.startswith("/../"):
            buffer = "/" + buffer[4:]
            if output:
                output.pop()
        elif buffer == "/..":
            buffer = "/"
            if output:
                output.pop()
        elif buffer in {".", ".."}:
            buffer = ""
        else:
            index = buffer.find("/", 1) if buffer.startswith("/") else buffer.find("/")
            if index == -1:
                index = len(buffer)
            output.append(buffer[:index])
            buffer = buffer[index:]
    return "".join(output)


def normalize_path(path: str) -> str:
    """Strip query and fragment, remove dot segments, strip one trailing slash.

    Dot-segment removal models the path ``urljoin`` actually requests at probe
    time, so a check written as ``/api/../admin`` is attributed to ``/admin``.
    Exactly one trailing slash is removed: ``/a//`` becomes ``/a/``, because an
    empty interior segment is a distinct route on most servers.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    without_query = urlsplit(path).path
    resolved = _remove_dot_segments(without_query)
    if len(resolved) > 1 and resolved.endswith("/"):
        resolved = resolved[:-1]
    return resolved


def _prepare_segment(segment: str, decode: bool) -> str:
    if decode and "{" not in segment:
        try:
            segment = unquote(segment, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
    return unicodedata.normalize("NFC", segment)


def _raw_segments(path: str) -> list[str]:
    normalized = normalize_path(path)
    if not normalized:
        return []
    if normalized.startswith("/"):
        return normalized.split("/")[1:]
    return normalized.split("/")


def split_segments(path: str, *, decode: bool = True) -> tuple[str, ...]:
    """Normalize, split on ``/``, then percent-decode each segment.

    Split-then-decode is load-bearing: ``/api/files/a%2Fb`` is one segment
    holding a literal ``/``, so it yields three segments and matches
    ``/api/files/{id}``. Decoding first would invent a phantom segment. Template
    segments containing ``{`` are never decoded.
    """
    cache_key = (path, decode)
    cached = _segment_cache.get(cache_key)
    if cached is not None:
        return cached
    segments = tuple(
        _prepare_segment(segment, decode) for segment in _raw_segments(path)
    )
    if len(_segment_cache) < 8192:
        _segment_cache[cache_key] = segments
    return segments


def undecodable_segments(path: str) -> tuple[str, ...]:
    """Raw segments of ``path`` that are not valid UTF-8 percent-escapes.

    ``errors="replace"`` is never used: U+FFFD would collide two distinct
    segments, so the raw segment is retained and reported instead.
    """
    bad: list[str] = []
    for segment in _raw_segments(path):
        if "{" in segment or "%" not in segment:
            continue
        try:
            unquote(segment, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            bad.append(segment)
    return tuple(bad)


def _segment_kind(segment: str) -> int:
    if "{" not in segment:
        return _LITERAL
    if _PARAMETER_SEGMENT.fullmatch(segment):
        return _PARAMETER
    return _MIXED


def template_specificity(template: str) -> tuple[int, ...]:
    """Per-segment kind vector: 2 literal, 1 mixed, 0 parameter."""
    return tuple(_segment_kind(segment) for segment in split_segments(template))


def _mixed_pattern(segment: str) -> re.Pattern[str]:
    pattern = _mixed_cache.get(segment)
    if pattern is not None:
        return pattern
    parts: list[str] = []
    index = 0
    for match in _TEMPLATE_TOKEN.finditer(segment):
        parts.append(re.escape(segment[index : match.start()]))
        parts.append("[^/]+?")
        index = match.end()
    parts.append(re.escape(segment[index:]))
    pattern = re.compile("^" + "".join(parts) + "$")
    if len(_mixed_cache) < 4096:
        _mixed_cache[segment] = pattern
    return pattern


def _segment_matches(template_segment: str, concrete_segment: str) -> bool:
    kind = _segment_kind(template_segment)
    if kind == _LITERAL:
        return template_segment == concrete_segment
    if kind == _PARAMETER:
        return concrete_segment != ""
    return bool(_mixed_pattern(template_segment).match(concrete_segment))


def _template_matches(
    template_segments: Sequence[str], concrete_segments: Sequence[str]
) -> bool:
    if len(template_segments) != len(concrete_segments):
        return False
    return all(
        _segment_matches(template, concrete)
        for template, concrete in zip(template_segments, concrete_segments)
    )


def match_path(
    concrete: str,
    templates: Sequence[str],
    *,
    prefer_methods: Mapping[str, frozenset[str]] | None = None,
    method: str | None = None,
) -> MatchResult | None:
    """Return the highest-specificity template matching ``concrete``.

    Specificity is the per-segment kind vector compared lexicographically
    descending, which subsumes "more literals wins", "fewer parameters wins",
    and leftmost-literal router precedence. Ties break on method availability,
    then shorter template, then lexicographic, then document order.
    """
    concrete_segments = split_segments(concrete)
    wanted = method.upper() if isinstance(method, str) else None
    ranked: list[tuple[tuple[Any, ...], str, tuple[int, ...]]] = []
    seen: set[str] = set()
    for index, template in enumerate(templates):
        if template in seen:
            continue
        seen.add(template)
        template_segments = split_segments(template)
        if not _template_matches(template_segments, concrete_segments):
            continue
        score = tuple(_segment_kind(segment) for segment in template_segments)
        defines = 0
        if wanted is not None and prefer_methods is not None:
            defines = 0 if wanted in prefer_methods.get(template, frozenset()) else 1
        sort_key = (
            tuple(-value for value in score),
            defines,
            len(template),
            template,
            index,
        )
        ranked.append((sort_key, template, score))
    if not ranked:
        return None
    ranked.sort(key=lambda entry: entry[0])
    _, winner, score = ranked[0]
    return MatchResult(
        template=winner,
        score=score,
        ambiguous_with=tuple(entry[1] for entry in ranked[1:]),
    )


def nearest_template(concrete: str, templates: Sequence[str]) -> str | None:
    """Best near-miss suggestion for a config path that matched nothing."""
    concrete_segments = split_segments(concrete)
    best_key: tuple[Any, ...] | None = None
    best: str | None = None
    fallback_key: tuple[Any, ...] | None = None
    fallback: str | None = None
    for index, template in enumerate(templates):
        template_segments = split_segments(template)
        shared = 0
        for template_segment, concrete_segment in zip(
            template_segments, concrete_segments
        ):
            if template_segment != concrete_segment:
                break
            shared += 1
        general = (-shared, abs(len(template_segments) - len(concrete_segments)),
                   len(template), template, index)
        if fallback_key is None or general < fallback_key:
            fallback_key, fallback = general, template
        if len(template_segments) != len(concrete_segments):
            continue
        differing = sum(
            0 if _segment_matches(template_segment, concrete_segment) else 1
            for template_segment, concrete_segment in zip(
                template_segments, concrete_segments
            )
        )
        key = (-shared, differing, len(template), template, index)
        if best_key is None or key < best_key:
            best_key, best = key, template
    return best if best is not None else fallback
