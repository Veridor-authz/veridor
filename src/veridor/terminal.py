"""Text from the input, as a message quotes it: shown, not obeyed, and bounded.

Veridor prints what it refuses, and much of that comes from a file the
operator did not write: a capsule is written by the party ``verify`` exists to
check. Two things let such text rewrite what a human reads on the terminal.
A character the terminal acts on (an escape sequence, a line break, a bidi
override) redraws the screen; :func:`terminal_text` shows each one instead.
And a long value wraps: a quoted key of printable text and spaces painted a
whole verdict session, row by row, over the real refusal. So every quotation
of the input is bounded here, in one place: :func:`terminal_text` for a value
set into prose, :func:`terminal_names` for a list, :func:`quoted` where a
message used ``{value!r}``.

Imported by ``core`` and re-exported from it; kept apart so every module can
use it without importing ``core`` (``coverage`` is imported BY ``core``).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable

#: Unicode categories a terminal acts on instead of showing: C0, DEL and C1
#: (Cc), the bidi overrides, isolates and marks and every other format control
#: (Cf: U+202A-202E, U+2066-2069, U+200E/F, U+061C, ...), the line and
#: paragraph separators (Zl, Zp), and lone surrogates (Cs), which a UTF-8
#: stream cannot even encode.
_TERMINAL_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

#: A cheap pre-filter: printable ASCII is never a terminal control, so only
#: the rest is looked up.
_NOT_PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e]")


#: The spellings ``repr`` uses, which read better than ``\x0a``.
_SHORT_ESCAPES = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}


def _shown(match: re.Match[str]) -> str:
    character = match.group(0)
    if unicodedata.category(character) not in _TERMINAL_CATEGORIES:
        return character
    if character in _SHORT_ESCAPES:
        return _SHORT_ESCAPES[character]
    code = ord(character)
    if code < 0x100:
        return f"\\x{code:02x}"
    if code < 0x10000:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


#: The most characters of any one value from the input that a message quotes:
#: a refusal, a banner, a verdict's reason, a line of `run` output. Text that
#: wraps draws rows of its own, so a quoted value used to be able to paint a
#: whole screen: a capsule ``expect`` key of 'anonymous', spaces and a copy of
#: a genuine session, each line padded to 80 columns (4097 characters, no
#: control character), was echoed whole by "references unknown identities:",
#: and an 80x24 terminal showed a genuine-looking NOT_REPRODUCED or CONFIRMED
#: session with the real refusal wrapped off the top (measured with GNU screen
#: on a sized pty; a 120-column build did the same at 120x30). 120 characters
#: is a row and a half at 80 columns.
ECHO_LIMIT = 120

#: A backslash escape (:func:`_shown`'s or ``repr``'s) cut short at the end.
_PARTIAL_ESCAPE = re.compile(r"\\(?:x[0-9a-f]?|u[0-9a-f]{0,3}|U[0-9a-f]{0,7}|N\{[^}]*)?$")

#: A run of blanks a terminal paints as empty cells: two or more of every
#: Unicode space separator (category Zs -- the space, U+00A0, U+2000-U+200A,
#: U+3000, ...) and the tab. A forged row is padded out to the terminal's
#: width with them, so a run is shown as one space. A single one is left as
#: it was (a lone tab is still shown as ``\t``). Collapsing is not the bound
#: -- a printable blank such as U+2800 is not one of them -- ECHO_LIMIT is.
_BLANK_RUN = re.compile("[\t\u0020\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]{2,}")


def cut(text: str, limit: int, more: str = "more characters") -> str:
    """``text`` cut to ``limit`` characters, saying how many more there were.

    Never in the middle of an escape this module or ``repr`` wrote: half of
    ``\u202e`` reads as something else.
    """
    if len(text) <= limit:
        return text
    head = _PARTIAL_ESCAPE.sub("", text[:limit]).rstrip()
    return f"{head} ... ({len(text) - len(head)} {more})"


def terminal_text(
    value: object, *, keep_newlines: bool = False, limit: int | None = ECHO_LIMIT
) -> str:
    """``value`` as a message quotes it: shown rather than obeyed, and bounded.

    Every character in :data:`_TERMINAL_CATEGORIES` becomes its visible
    ``\\xNN`` / ``\\uNNNN`` spelling -- shown, not stripped, so a reader sees
    that something was there. Newline is escaped too unless ``keep_newlines``:
    a single-line field that may start a new line can draw a verdict block of
    its own with no escape sequence at all.

    A quoted value is also bounded: each run of blanks (:data:`_BLANK_RUN`)
    becomes one space and at most ``limit`` characters are shown, with a note
    of how many more there were, because a line that wraps draws rows of its
    own (:data:`ECHO_LIMIT`). ``limit=None`` escapes only: it neither cuts nor
    collapses blank runs. ``capsule.build`` uses it for text it writes into
    the capsule rather than prints. A caller that prints with it must cut
    what it prints itself: ``capsule.render``'s fields collapse
    :data:`_BLANK_RUN` and then cut to :data:`ECHO_LIMIT` (``capsule._shown``),
    and ``coverage``'s diagnostics and ``capsule.render``'s verdict reason are
    Veridor's own sentences whose quoted values were cut where they were
    written. Collapsing alone is not a bound: a printable blank such as
    U+2800 or U+3164 is not in :data:`_BLANK_RUN` and pads a forged row as
    well as a run of spaces did.
    ``keep_newlines`` is for a whole message Veridor wrote, printed once by
    ``cli._main``; the values it quotes were bounded where it was built.

    For text that did not come from Veridor and is printed where a human reads
    a verdict: a capsule is written by the party ``verify`` exists to check,
    and it used to be printed verbatim (``capsule.render``).
    """
    text = value if isinstance(value, str) else str(value)
    if keep_newlines:
        return "\n".join(_NOT_PRINTABLE_ASCII.sub(_shown, line) for line in text.split("\n"))
    if limit is None:
        return _NOT_PRINTABLE_ASCII.sub(_shown, text)
    return cut(_NOT_PRINTABLE_ASCII.sub(_shown, _BLANK_RUN.sub(" ", text)), limit)


def terminal_names(names: Iterable[object], *, limit: int = ECHO_LIMIT) -> str:
    """Names taken from input -- keys, identities, methods -- listed in a refusal.

    Comma-separated, each through :func:`terminal_text`, so a name carrying a
    line break is shown as ``\\n`` instead of starting a line of its own. Every
    refusal reaches the terminal through ``cli._main``, which keeps newlines so
    Veridor's own multi-line refusals read as written; a key that was joined
    into one raw could draw a whole verdict block below the real refusal
    (reproduced with a capsule whose ``expect`` key ended in thirty newlines
    and a copy of a genuine NOT_REPRODUCED session).

    Each name is bounded, and so is the list: names are shown until they fill
    twice ``limit``, then counted ("and 7 more"). Many short keys wrap as well
    as one long one.
    """
    names = list(names)
    shown: list[str] = []
    used = 0
    for index, name in enumerate(names):
        text = terminal_text(name, limit=limit)
        if shown and used + len(text) > 2 * limit:
            return ", ".join(shown) + f", and {len(names) - index} more"
        shown.append(text)
        used += len(text) + 2
    return ", ".join(shown)


def quoted(value: object, *, limit: int = ECHO_LIMIT) -> str:
    """``repr(value)`` for a message that quotes the input, bounded.

    What ``{value!r}`` wrote -- ``'text'`` with a newline, an escape sequence
    or a bidi control spelled out -- with each run of blanks made one space and
    at most ``limit`` characters of it between the quotes, then a note of how
    many more there were. ``repr`` escapes but does not bound: a refusal that
    quoted an identity name or a ``schema_version`` with it printed all 4000
    characters of one.
    """
    if not isinstance(value, str):
        return cut(_BLANK_RUN.sub(" ", repr(value)), limit)
    text = repr(_BLANK_RUN.sub(" ", value))
    quote, body = text[0], text[1:-1]
    if len(body) <= limit:
        return text
    head = _PARTIAL_ESCAPE.sub("", body[:limit])
    return f"{quote}{head}{quote} ... ({len(body) - len(head)} more characters)"


#: The longest line of a refusal ``cli._main`` prints whole. Longer ones keep
#: their first :data:`_REFUSAL_HEAD` and last :data:`_REFUSAL_TAIL` characters.
#: A backstop: every value a refusal quotes is bounded where the refusal is
#: written, and this holds even where one was missed (``openapi`` is kept to
#: stdlib imports and quotes with ``repr``). 1000
#: characters wrap into 13 rows at 80 columns, so the start of a one-line
#: refusal stays on a 24-row screen. The longest refusal line the fast tests
#: print is 721 characters (two long temporary paths; measured on macOS).
REFUSAL_LINE_LIMIT = 1000
_REFUSAL_HEAD = 640
_REFUSAL_TAIL = 320


def refusal_text(message: str) -> str:
    """A refusal as ``cli._main`` prints it: shown, not obeyed, lines bounded.

    Newlines are kept -- some of Veridor's refusals are several lines by
    design -- and every other character a terminal acts on is shown
    (:func:`terminal_text`). A line longer than :data:`REFUSAL_LINE_LIMIT`
    keeps its start, which names what was refused, and its end, which says
    what to do, and says how much of the middle is not shown.
    """
    lines = terminal_text(message, keep_newlines=True).split("\n")
    return "\n".join(
        line
        if len(line) <= REFUSAL_LINE_LIMIT
        else (
            f"{line[:_REFUSAL_HEAD]} ... ({len(line) - _REFUSAL_HEAD - _REFUSAL_TAIL} "
            f"characters not shown) ... {line[-_REFUSAL_TAIL:]}"
        )
        for line in lines
    )


def terminal_controls(text: str) -> list[str]:
    """Each character :func:`terminal_text` would escape, named as ``U+001B``."""
    return [
        f"U+{ord(character):04X}"
        for character in text
        if unicodedata.category(character) in _TERMINAL_CATEGORIES
    ]
