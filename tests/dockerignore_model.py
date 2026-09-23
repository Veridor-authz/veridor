"""A .dockerignore read the way the builder reads it, so a test can ask without docker.

The rules are the ones Docker documents and moby's patternmatcher implements:
blank lines and # comments are skipped; a trailing or leading slash is dropped;
patterns apply in order and the last one matching decides, so ! can bring back
what an earlier pattern excluded; a pattern matches a path or any directory
above it; * and ? stop at a slash; ** as a whole segment spans any number of
segments. It is a model: the CI image job is what runs the real builder over
the root file.

Syntax this does not model is refused rather than guessed at, because a check
that silently mis-read a pattern would pass vacuously.
"""

from __future__ import annotations

import re
from pathlib import Path


def read_patterns(path: Path) -> list[str]:
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _compile(body: str) -> re.Pattern[str]:
    parts = []
    segments = body.strip("/").split("/")
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            parts.append(".*" if last else "(?:.*/)?")
            continue
        if "**" in segment or any(c in segment for c in "[]\\"):
            raise AssertionError(f"unsupported .dockerignore pattern {body!r}")
        parts.append("".join({"*": "[^/]*", "?": "[^/]"}.get(c, re.escape(c)) for c in segment))
        if not last:
            parts.append("/")
    return re.compile("".join(parts))


def ignored(path: str, patterns: list[str]) -> bool:
    """Whether the builder leaves this context-relative path out."""
    rel = path.removeprefix("./").rstrip("/")
    segments = rel.split("/")
    candidates = ["/".join(segments[:end]) for end in range(1, len(segments) + 1)]
    result = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        compiled = _compile(pattern[1:] if negated else pattern)
        if any(compiled.fullmatch(candidate) for candidate in candidates):
            result = not negated
    return result
