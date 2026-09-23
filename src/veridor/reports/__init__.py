"""Report formats for a Veridor run, rendered from the run document alone.

One package, five formats, one input. Every renderer here is a pure function
of a run document that has been through :func:`veridor.core.validate_run` --
``veridor report --from-run`` gets there through :func:`veridor.core.load_run`,
and ``veridor run --report`` validates the document it just wrote -- so a file
that is not a run, or a run this binary cannot fully read, is refused with exit
2 before anything is rendered.

========================  ====================================================
``sarif``                 SARIF 2.1.0 (``core.to_sarif``). GitHub code scanning.
``junit``                 JUnit XML. GitLab, Jenkins, Azure, CodeBuild test tabs.
``gitlab-sast``           GitLab security report, schema 15.2.5.
``codequality``           GitLab Code Quality (CodeClimate subset) JSON array.
``markdown``              GitHub job summary / merge request note.
========================  ====================================================

These replaced three converters that lived outside the package: they were
not in the wheel or the image, never checked the run
schema version, rendered a sequence finding as an ``<error>`` on a made-up
test case, and had no way to say that a run exited 3 for a reason that is not
a finding -- so a run that answered nothing rendered as a clean pass in every
one of them. Every format except SARIF now reads the run document's ``gate``
object, which is written by the same computation the CLI exits with
(``veridor.gate``). SARIF does not: it is byte-identical to ``run --sarif``,
which is written before the gate is decided, so a run gated to 3 for a reason
that is not a finding renders as zero results there.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any, Callable, Mapping

from veridor import core, redaction
from veridor.reports import codequality, gitlab_sast, junit, markdown, sarif
from veridor.reports._common import scrub
from veridor.terminal import quoted

#: The ``--format`` values, in the order ``--help`` lists them.
FORMATS: tuple[str, ...] = ("sarif", "junit", "gitlab-sast", "codequality", "markdown")

_RENDERERS: dict[str, Callable[..., str]] = {
    "sarif": sarif.render,
    "junit": junit.render,
    "gitlab-sast": gitlab_sast.render,
    "codequality": codequality.render,
    "markdown": markdown.render,
}

#: What ``veridor run`` prints when it names a written report, per format.
LABELS: dict[str, str] = {
    "sarif": "SARIF",
    "junit": "JUnit",
    "gitlab-sast": "GitLab SAST",
    "codequality": "GitLab Code Quality",
    "markdown": "Markdown",
}


def render(fmt: str, document: Mapping[str, Any], *, root: Path | None = None) -> str:
    """Render a VALIDATED run document as ``fmt``. Returns the file's text.

    ``root`` is the directory report paths are made relative to (the CLI passes
    its working directory). Strings are scrubbed of lone surrogates first: one
    in a target's error text made two of the old converters crash with
    ``UnicodeEncodeError`` and the third write XML no parser accepts.
    """
    if fmt not in _RENDERERS:
        raise core.ConfigError(
            f"unknown report format {quoted(fmt)}; choose one of {', '.join(FORMATS)}"
        )
    # Expanded ${NAME} values are put back first, on the document, so an XML
    # or Markdown escape cannot hide one; write_text scrubs the text again.
    return _RENDERERS[fmt](scrub(redaction.scrub(document)), root=root)


def load_run(path: Path) -> dict[str, Any]:
    """The only way a file becomes renderer input. See ``core.load_run``."""
    return core.load_run(path)


#: The counts a drift document carries at its top level. Each is printed in
#: the Markdown report, two of them in its bold headline, so each must be the
#: integer ``drift.compare`` writes: a string there was pasted in as markup.
DRIFT_COUNTS: tuple[str, ...] = (
    "comparable_cells", "measured_in_both_cells", "redirect_cells",
    "redirect_now_served_cells", "incomparable_cells", "unmeasured_cells",
    "unmeasured_cells_not_probed", "blind_cells", "blind_cells_not_probed",
    "significant",
)


def load_drift(path: Path) -> dict[str, Any]:
    """Load a drift document written by ``veridor map --baseline``.

    Refused unless it is one: drift is never a finding, so the only format it
    renders to is Markdown, and a file that is not a drift report must not be
    rendered as an empty one. A count that is not a non-negative integer is
    refused too (:data:`DRIFT_COUNTS`, each side's ``cells`` and
    ``measured_cells``, every ``counts`` value); a count absent from an older
    document is not.
    """
    from veridor import drift as drift_module  # noqa: PLC0415

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise core.ConfigError(f"drift report not found: {path}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise core.ConfigError(f"invalid drift JSON in {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("kind") != drift_module.DRIFT_KIND:
        found = document.get("kind") if isinstance(document, dict) else None
        raise core.ConfigError(
            f"{path} is not a Veridor drift report (kind {quoted(found)}, expected "
            f"{quoted(drift_module.DRIFT_KIND)}). `map --baseline ... --drift PATH` "
            "writes one; a run document renders with --from-run."
        )
    if document.get("schema_version") != drift_module.DRIFT_SCHEMA_VERSION:
        raise core.ConfigError(
            f"unsupported drift schema_version: {quoted(document.get('schema_version'))}; "
            f"this Veridor supports [{drift_module.DRIFT_SCHEMA_VERSION}]"
        )
    for key, expected in (("changes", list), ("counts", dict), ("baseline", dict),
                          ("current", dict)):
        if not isinstance(document.get(key), expected):
            raise core.ConfigError(f"drift report {path} has no {quoted(key)} {expected.__name__}")
    for index, change in enumerate(document["changes"]):
        if not isinstance(change, dict):
            raise core.ConfigError(f"drift change {index} must be an object")
    counts = [(key, document[key]) for key in DRIFT_COUNTS if key in document]
    counts += [(f"{side}.{key}", document[side][key]) for side in ("baseline", "current")
               for key in ("cells", "measured_cells") if key in document[side]]
    counts += [(f"counts.{kind}", count) for kind, count in document["counts"].items()]
    for field, value in counts:
        if not (isinstance(value, int) and not isinstance(value, bool) and value >= 0):
            found = str(value) if isinstance(value, int) and not isinstance(value, bool) else (
                f"a {type(value).__name__}")
            raise core.ConfigError(
                f"drift report {path} has {field} {found}, not a non-negative integer; "
                "`map --baseline ... --drift PATH` writes every count as one"
            )
    return document


def render_drift(document: Mapping[str, Any]) -> str:
    """Markdown for a VALIDATED drift document (see :func:`load_drift`)."""
    return markdown.render_drift(scrub(redaction.scrub(document)))


def write_text(path: Path, text: str) -> None:
    """Write a report atomically, the way ``core.write_json`` writes JSON.

    A temporary sibling, then ``replace``: a reader never sees half a report,
    and a crash never leaves one behind to be uploaded as if it were whole.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(redaction.scrub_text(text), encoding="utf-8", errors="strict")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
