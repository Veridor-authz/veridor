"""Put every expanded ``${NAME}`` back before anything is written or printed.

A configuration refers to its secrets as ``${NAME}``, and ``core.load_config``
expands each one from the environment. Headers never leave the process, and
query values are redacted in stored URLs -- but a value can sit anywhere a
string can: a path segment, a ``;jsessionid=`` path parameter, a base URL, a
specimen, an id. Measured before this module existed: a ``${NAME}`` in a
request path was written verbatim to the run document (``probes[].request.url``,
``findings[].evidence.request.url``, ``liveness.requests[].path``), to the
managed history and to the GitLab SAST report, and a query value that every URL
field redacted was written raw by the liveness block.

Chasing fields one at a time is how that happened, so this works on VALUES
instead. :func:`register` is called for every value ``_expand_environment``
substitutes. :func:`scrub` and :func:`scrub_text` replace each registered value
-- in every spelling :func:`_spellings` lists -- with its ``${NAME}``
reference, longest value first, so one secret that contains another is replaced
whole. ``core.write_json``, every report renderer and writer, the mutation text
report, and the CLI's stdout and stderr all go through them.

What this does NOT cover, deliberately:

* A value shorter than :data:`MIN_SCRUB_LENGTH`. ``7`` or ``inv-1`` cannot be
  told apart from ordinary text: replacing every ``7`` would rewrite
  timestamps, counts and ids across every document. Such values are recorded by
  NAME (:func:`short_names`) and the CLI says, on stderr, that they were left
  as they are. Eight characters is the minimum GitLab accepts for a masked CI
  variable, for the same reason.
* A literal credential typed straight into a configuration. Veridor only knows
  a value is secret because it came from ``${NAME}``; a token pasted into a
  path is the user's own text and is written wherever that path is written.
* A secret that reaches the output in a spelling :func:`_spellings` does not
  list (base64, say). The list is every spelling Veridor itself produces: as
  written, percent-encoded, ``+``-encoded, and the two ``core._safe_url``
  produces when it stores a URL -- the host lower-cased (``parsed.hostname``)
  and a query parameter NAME decoded and re-encoded (``_redact_query``: ``%2f``
  becomes ``%2F``, ``%20`` becomes ``+``). Those two were missing, and a
  mixed-case value in a host label was written lower-cased to every artifact
  and to stdout.

The registry is process state. ``cli.main`` resets it at the start of every
command, so one command's values never scrub another's output.
"""

from __future__ import annotations

import re
from typing import Any, TextIO
from urllib.parse import quote, quote_plus, unquote_plus

#: Values shorter than this are never scrubbed. See the module docstring.
MIN_SCRUB_LENGTH: int = 8

#: Every spelling of every registered value -> the ``${NAME}`` it came from.
_REFERENCES: dict[str, str] = {}

#: Names whose value was too short to scrub, in the order first seen.
_SHORT: dict[str, None] = {}

#: The alternation over ``_REFERENCES``, longest first. Rebuilt lazily.
_pattern: re.Pattern[str] | None = None


def reset() -> None:
    """Forget every registered value."""
    global _pattern
    _REFERENCES.clear()
    _SHORT.clear()
    _pattern = None


def _spellings(value: str) -> tuple[str, ...]:
    """Every spelling of ``value`` that Veridor itself can write.

    As written, percent-encoded and ``+``-encoded; lower-cased, because
    ``core._safe_url`` stores ``parsed.hostname``; and decoded then
    ``+``-encoded, because ``core._redact_query`` re-encodes a query
    parameter's name that way.
    """
    return (value, quote(value, safe=""), quote_plus(value), value.lower(),
            quote_plus(unquote_plus(value)))


def register(name: str, value: str) -> None:
    """Record that ``${name}`` expanded to ``value``."""
    global _pattern
    if len(value) < MIN_SCRUB_LENGTH:
        _SHORT.setdefault(name, None)
        return
    reference = "${" + name + "}"
    for form in _spellings(value):
        if len(form) >= MIN_SCRUB_LENGTH and form not in _REFERENCES:
            _REFERENCES[form] = reference
            _pattern = None


def short_names() -> list[str]:
    """Names that expanded to a value too short to scrub."""
    return list(_SHORT)


def _compiled() -> re.Pattern[str] | None:
    global _pattern
    if _pattern is None and _REFERENCES:
        forms = sorted(_REFERENCES, key=lambda form: (-len(form), form))
        _pattern = re.compile("|".join(re.escape(form) for form in forms))
    return _pattern


def scrub_text(text: str) -> str:
    """``text`` with every registered value replaced by its reference."""
    pattern = _compiled()
    if pattern is None or not isinstance(text, str):
        return text
    return pattern.sub(lambda match: _REFERENCES[match.group(0)], text)


def scrub(value: Any) -> Any:
    """``value`` with every string in it -- keys included -- scrubbed.

    Applied to a document BEFORE it is serialised, so an escape a serialiser
    adds (a JSON ``\\"``, an XML ``&amp;``) cannot hide a value from it.
    """
    if _compiled() is None:
        return value
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {scrub(key): scrub(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(scrub(item) for item in value)
    return value


class ScrubbingStream:
    """A text stream that scrubs what is written to it, and is otherwise the
    stream it wraps. ``cli.main`` puts one over stdout and stderr.

    Each ``write`` is scrubbed on its own. ``print`` hands over each argument
    whole, so a value is only missed if one call writes half of it and the next
    call the rest, which nothing in Veridor does.
    """

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        self._stream.write(scrub_text(text))
        return len(text)

    def writelines(self, lines: Any) -> None:
        for line in lines:
            self.write(line)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)
