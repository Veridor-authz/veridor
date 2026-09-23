"""The one YAML reader the suite uses, for the subset this repository writes.

The runtime and the tests are standard library only, so there is no PyYAML.
Two readers grew up separately -- a strict one in tests/action_harness.py for
the GitHub Action and the workflows, and a typed one here for the Helm chart,
Kustomize and the CI templates -- and each refused files the other read. They
are one parser now, with two ways to read a scalar:

``typed`` (``load_yaml_documents``, ``load_yaml``)
    Plain scalars resolve the way PyYAML resolves them for the forms this
    subset allows: ``true``/``True``/``TRUE`` and the false spellings to a
    bool, ``null``/``Null``/``NULL``/``~``/empty to None, ``-?[0-9]+`` to an
    int, ``-?[0-9]+.[0-9]+`` to a float, anything else to a string.
    ``yes``/``no``/``on``/``off`` in any spelling are REFUSED: YAML 1.1 readers
    (PyYAML, go-yaml v2, so Helm and kubectl) read them as booleans and YAML 1.2
    readers as strings, so a file that means one of them is ambiguous. Checked
    against PyYAML by ``tests/ci_validate.py schemas``.

``untyped`` (``load_yaml_text``; tests/action_harness.py's ``load_yaml``)
    Every scalar stays the string it was written as; an empty value is None.
    That is how the Actions runner hands inputs, ``with:`` and ``env:`` values
    to a step. Checked against Ruby's Psych (``to_s`` of every scalar) by
    tests/test_action.py's YAMLParserAgreementTest.

Both read: block mappings and sequences, including go-yaml's un-indented
sequence under a key; ``- key: value`` items; plain, single- and
double-quoted scalars (a plain scalar's trailing `` # comment`` is dropped);
``|``/``|-``/``>``/``>-`` block scalars, as a mapping value or a sequence item;
one-line flow sequences of scalars (``[a, "b"]``); and, typed only,
JSON-shaped flow collections (``{}``, ``{"k": 1}``, ``[{"a": 1}]``). Keys may
contain ``.``, ``/`` and spaces; a key containing ``:`` must be quoted.
``load_yaml_documents`` splits a stream on ``---`` lines.

Anything else RAISES YAMLSubsetError (a ValueError): anchors, aliases, tags,
``?`` keys, a flow mapping that is not JSON, a multi-line flow collection or
plain scalar, a plain scalar containing ``: ``, text after a quoted scalar,
keep chomping (``+``) and indentation indicators, more-indented lines in a
folded scalar, tabs in indentation, duplicate keys, and unexpected
indentation. A reader that guessed would let a file drift from what its real
consumer reads while the tests built on it stayed green.

Not collected as a test module: the file name does not start with ``test``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

__all__ = ["YAMLSubsetError", "flatten", "load_yaml", "load_yaml_documents", "load_yaml_text"]


class YAMLSubsetError(ValueError):
    """The document uses YAML this parser does not implement."""


_QUOTED_KEY = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'"
_PLAIN_KEY = r"[^\s\"'\[\]{}#&*!|>%@`,?:-][^:#]*?|-[^\s:][^:#]*?"
_MAPPING_LINE = re.compile(rf"^(?P<key>{_QUOTED_KEY}|{_PLAIN_KEY})\s*:(?:[ ](?P<rest>.*))?$")
_FORBIDDEN_START = tuple("&*!%@`?{|>")
_INT = re.compile(r"-?[0-9]+")
_FLOAT = re.compile(r"-?[0-9]+\.[0-9]+")
_BOOLEANS = {"true": True, "True": True, "TRUE": True, "false": False, "False": False, "FALSE": False}
_NULLS = {"null", "Null", "NULL", "~", ""}
_YAML11_BOOLEANS = {"yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF"}
_JSON = json.JSONDecoder(strict=False)


class _Plain(str):
    """A plain scalar as written, before typed resolution."""


def _resolve(value: Any, typed: bool, where: str) -> Any:
    if not typed or not isinstance(value, _Plain):
        return str(value) if isinstance(value, _Plain) else value
    text = str(value)
    if text in _BOOLEANS:
        return _BOOLEANS[text]
    if text in _NULLS:
        return None
    if text in _YAML11_BOOLEANS:
        raise YAMLSubsetError(f"{where}: {text!r} is a boolean to YAML 1.1 readers and a string to "
                              "YAML 1.2 readers; quote it or write true/false")
    if _INT.fullmatch(text):
        return int(text)
    if _FLOAT.fullmatch(text):
        return float(text)
    return text


class _Lines:
    def __init__(self, text: str) -> None:
        if "\t" in text:
            for number, line in enumerate(text.splitlines(), 1):
                if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
                    raise YAMLSubsetError(f"line {number}: tab in indentation")
        self.raw = text.splitlines()
        for number, line in enumerate(self.raw, 1):
            if line.startswith(("---", "...")):
                raise YAMLSubsetError(f"line {number}: document markers are not supported here")

    def __len__(self) -> int:
        return len(self.raw)

    @staticmethod
    def indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    @staticmethod
    def insignificant(line: str) -> bool:
        stripped = line.strip()
        return not stripped or stripped.startswith("#")

    def next_significant(self, index: int) -> int:
        while index < len(self.raw) and self.insignificant(self.raw[index]):
            index += 1
        return index


class _Parser:
    def __init__(self, text: str, typed: bool) -> None:
        self.lines = _Lines(text)
        self.typed = typed

    # -- scalars -----------------------------------------------------------

    @staticmethod
    def _strip_comment(text: str) -> str:
        """Remove a trailing ` # comment` from a plain scalar."""
        match = re.search(r"(^|\s)#", text)
        return text[: match.start()].rstrip() if match else text.rstrip()

    @staticmethod
    def _double_quoted(body: str, where: str) -> str:
        for escape in re.findall(r"\\(.)", body):
            if escape not in '\\"/bfnrtu':
                raise YAMLSubsetError(f"{where}: unsupported escape \\{escape} in a double-quoted scalar")
        try:
            return _JSON.decode(f'"{body}"')
        except ValueError as error:
            raise YAMLSubsetError(f"{where}: bad double-quoted scalar: {error}") from None

    def _quoted(self, rest: str, where: str) -> str:
        if rest[0] == "'":
            match = re.match(r"^'((?:[^']|'')*)'(.*)$", rest)
            if not match:
                raise YAMLSubsetError(f"{where}: unterminated or multi-line single-quoted scalar")
            value, tail = match.group(1).replace("''", "'"), match.group(2)
        else:
            match = re.match(r'^"((?:[^"\\]|\\.)*)"(.*)$', rest)
            if not match:
                raise YAMLSubsetError(f"{where}: unterminated or multi-line double-quoted scalar")
            value, tail = self._double_quoted(match.group(1), where), match.group(2)
        tail = tail.strip()
        if tail and not tail.startswith("#"):
            raise YAMLSubsetError(f"{where}: text after a quoted scalar: {tail!r}")
        return value

    def _flow(self, value: str, where: str) -> Any:
        if self.typed:
            try:
                return _JSON.decode(value)
            except ValueError:
                pass  # not JSON: a one-line flow sequence of scalars, or nothing
        if value.startswith("{"):
            raise YAMLSubsetError(f"{where}: only a JSON-shaped flow mapping is supported"
                                  + ("" if self.typed else ", and none in untyped reads"))
        if not value.endswith("]") or value.count("[") != 1 or value.count("]") != 1:
            raise YAMLSubsetError(f"{where}: only a one-line flow sequence of scalars is supported")
        body = value[1:-1].strip()
        if not body:
            return []
        items = []
        for part in re.findall(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'|[^,]+", body):
            part = part.strip()
            if not part or part == ",":
                continue
            if part[0] in "\"'":
                items.append(self._quoted(part, where))
            elif part.startswith(("{", "[", "&", "*", "!")) or ": " in part:
                raise YAMLSubsetError(f"{where}: nested flow collections are not supported")
            else:
                items.append(_resolve(_Plain(part), self.typed, where))
        return items

    def _scalar(self, rest: str, where: str) -> Any:
        if rest[:1] in "\"'":
            return self._quoted(rest, where)
        value = self._strip_comment(rest)
        if value.startswith(("[", "{")):
            return self._flow(value, where)
        if value.startswith(_FORBIDDEN_START) or value.startswith(("- ", "]", "}")):
            raise YAMLSubsetError(f"{where}: unsupported YAML construct {value[:12]!r}")
        if ": " in value or value.endswith(":"):
            raise YAMLSubsetError(f"{where}: a plain scalar may not contain ': ' ({value!r})")
        return _resolve(_Plain(value), self.typed, where)

    def _block_scalar(self, index: int, parent_indent: int, header: str, where: str) -> tuple[str, int]:
        lines = self.lines
        header = self._strip_comment(header)
        match = re.fullmatch(r"([|>])([+-]?)", header)
        if not match:
            raise YAMLSubsetError(f"{where}: unsupported block scalar header {header!r}")
        style, chomp = match.groups()
        body: list[str] = []
        content_indent = None
        while index < len(lines):
            line = lines.raw[index]
            if line.strip():
                indent = lines.indent(line)
                if indent <= parent_indent:
                    break
                if content_indent is None:
                    content_indent = indent
                elif indent < content_indent:
                    raise YAMLSubsetError(f"line {index + 1}: under-indented block scalar line")
                body.append(line[content_indent:])
            else:
                body.append("")
            index += 1
        while body and body[-1] == "":
            body.pop()
        if style == "|":
            text = "\n".join(body)
        else:
            if any(line.startswith(" ") for line in body):
                raise YAMLSubsetError(f"{where}: more-indented lines in a folded scalar")
            text = ""
            for position, line in enumerate(body):
                if position == 0:
                    text = line
                elif line == "":
                    text += "\n"
                elif body[position - 1] == "":
                    text += line
                else:
                    text += " " + line
        if not body:
            return "", index
        if chomp == "-":
            return text, index
        if chomp == "+":
            raise YAMLSubsetError(f"{where}: keep chomping (+) is not supported")
        return text + "\n", index

    # -- structure ---------------------------------------------------------

    def node(self, index: int, indent: int) -> tuple[Any, int]:
        lines = self.lines
        index = lines.next_significant(index)
        if index >= len(lines):
            return None, index
        line = lines.raw[index]
        actual = lines.indent(line)
        if actual != indent:
            raise YAMLSubsetError(f"line {index + 1}: expected indentation {indent}, found {actual}")
        content = line[actual:]
        if content == "-" or content.startswith("- "):
            return self._sequence(index, indent)
        return self._mapping(index, indent)

    def _value(self, index: int, indent: int, rest: str | None, where: str,
               sequence_allowed_at_indent: bool) -> tuple[Any, int]:
        """The value of `key:` or `- `: inline, a block scalar, or a nested block."""
        lines = self.lines
        if rest is not None and rest.strip() and not rest.strip().startswith("#"):
            text = rest.strip()
            if text[0] in "|>":
                return self._block_scalar(index, indent, text, where)
            return self._scalar(text, where), index
        nxt = lines.next_significant(index)
        if nxt >= len(lines):
            return None, nxt
        child = lines.raw[nxt]
        child_indent = lines.indent(child)
        child_content = child[child_indent:]
        if child_indent > indent:
            return self.node(nxt, child_indent)
        if (sequence_allowed_at_indent and child_indent == indent
                and (child_content == "-" or child_content.startswith("- "))):
            return self._sequence(nxt, indent)
        return None, index

    @staticmethod
    def _key(raw: str) -> str:
        if raw.startswith('"'):
            return _Parser._double_quoted(raw[1:-1], "key")
        if raw.startswith("'"):
            return raw[1:-1].replace("''", "'")
        return raw.rstrip()

    def _mapping(self, index: int, indent: int) -> tuple[dict, int]:
        lines = self.lines
        mapping: dict[str, Any] = {}
        while True:
            index = lines.next_significant(index)
            if index >= len(lines):
                return mapping, index
            line = lines.raw[index]
            actual = lines.indent(line)
            if actual < indent:
                return mapping, index
            if actual > indent:
                raise YAMLSubsetError(f"line {index + 1}: unexpected indentation")
            content = line[actual:]
            if content == "-" or content.startswith("- "):
                return mapping, index
            match = _MAPPING_LINE.match(content)
            if not match:
                raise YAMLSubsetError(f"line {index + 1}: not a `key: value` line: {content!r}")
            key = self._key(match.group("key"))
            if key in mapping:
                raise YAMLSubsetError(f"line {index + 1}: duplicate key {key!r}")
            where = f"line {index + 1} ({key})"
            value, index = self._value(index + 1, indent, match.group("rest"), where,
                                       sequence_allowed_at_indent=True)
            mapping[key] = value

    def _sequence(self, index: int, indent: int) -> tuple[list, int]:
        lines = self.lines
        items: list[Any] = []
        while True:
            index = lines.next_significant(index)
            if index >= len(lines):
                return items, index
            line = lines.raw[index]
            actual = lines.indent(line)
            if actual < indent:
                return items, index
            if actual > indent:
                raise YAMLSubsetError(f"line {index + 1}: unexpected indentation in a sequence")
            content = line[actual:]
            if not (content == "-" or content.startswith("- ")):
                return items, index
            after = content[1:]
            stripped = after.lstrip(" ")
            where = f"line {index + 1} (sequence item)"
            if not stripped or stripped.startswith("#"):
                value, index = self._value(index + 1, indent, None, where, sequence_allowed_at_indent=False)
                items.append(value)
                continue
            column = actual + 1 + (len(after) - len(stripped))
            if _MAPPING_LINE.match(stripped) and stripped[:1] != "[":
                # `- key: value` starts a mapping whose keys sit at `column`.
                lines.raw[index] = " " * column + stripped
                value, index = self._mapping(index, column)
                items.append(value)
                continue
            value, index = self._value(index + 1, actual, stripped, where, sequence_allowed_at_indent=False)
            items.append(value)


def _parse(text: str, typed: bool) -> Any:
    parser = _Parser(text, typed)
    lines = parser.lines
    start = lines.next_significant(0)
    if start >= len(lines):
        return None
    if lines.indent(lines.raw[start]) != 0:
        raise YAMLSubsetError("the document must start at column 0")
    node, end = parser.node(start, 0)
    end = lines.next_significant(end)
    if end < len(lines):
        raise YAMLSubsetError(f"line {end + 1}: content after the document root")
    return node


def load_yaml_text(text: str, *, typed: bool = False) -> Any:
    """One document with no ``---`` marker. Untyped unless asked."""
    return _parse(text, typed)


def load_yaml_documents(text: str) -> list[Any]:
    """Every non-empty document in a multi-document YAML stream, typed."""
    documents, current = [], []
    for line in text.split("\n"):
        if line.rstrip() == "---":
            documents.append("\n".join(current))
            current = []
        else:
            current.append(line)
    documents.append("\n".join(current))
    parsed = []
    for document in documents:
        value = _parse(document, typed=True)
        if value is not None:
            parsed.append(value)
    return parsed


def load_yaml(path: Path) -> Any:
    """The one document in a file, typed."""
    documents = load_yaml_documents(path.read_text(encoding="utf-8"))
    if len(documents) != 1:
        raise YAMLSubsetError(f"{path} holds {len(documents)} documents, expected 1")
    return documents[0]


def flatten(value: Any, prefix: str = "") -> list[str]:
    """Dotted paths of every leaf; a map with keys is not a leaf."""
    if isinstance(value, dict) and value:
        paths = []
        for key, item in value.items():
            paths.extend(flatten(item, f"{prefix}.{key}" if prefix else key))
        return paths
    return [prefix]
