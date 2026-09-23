"""What a message may show of the input it quotes.

A value from the input -- a capsule written by a stranger, a configuration, a
spec -- reached the terminal through refusals, banners and a verdict's reason.
Escaping the characters a terminal obeys was not enough: a long value wraps,
and wrapped rows are rows the value chose. A capsule ``expect`` key of
'anonymous', spaces and a copy of a genuine session, each line padded to 80
columns (4097 characters, no control character), was echoed whole by the
"references unknown identities" refusal, and on an 80x24 terminal the screen
was a genuine-looking NOT_REPRODUCED session with the real refusal wrapped off
the top (measured with GNU screen on a sized pty). These are the unit tests of
the bound; tests/test_refusal_lines.py plants long values everywhere.
"""

from __future__ import annotations

import ast
import contextlib
import io
import sys
import unicodedata
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import veridor  # noqa: E402
from veridor import cli, core, terminal  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

LIMIT = terminal.ECHO_LIMIT


class TerminalTextTest(unittest.TestCase):
    def test_a_short_value_is_unchanged(self) -> None:
        for value in ("invoice_owner", "GET", "/api/invoices/inv-100", "a b", "a\u00a0b"):
            with self.subTest(value=value):
                self.assertEqual(terminal.terminal_text(value), value)

    def test_a_long_value_is_cut_and_says_how_much_more(self) -> None:
        text = terminal.terminal_text("x" * 5000)
        self.assertEqual(text, "x" * LIMIT + f" ... ({5000 - LIMIT} more characters)")

    def test_each_blank_run_is_one_space(self) -> None:
        for blank in ("\t", " ", "\u00a0", "\u2007", "\u202f", "\u3000"):
            with self.subTest(blank=hex(ord(blank))):
                self.assertEqual(terminal.terminal_text("a" + blank * 3000 + "b"), "a b")
        # A single one is left as it was: a lone tab is still shown as \t.
        self.assertEqual(terminal.terminal_text("a\tb"), "a\\tb")

    def test_the_blank_class_is_every_space_separator_and_the_tab(self) -> None:
        """Derived from the Unicode database, not from the pattern under test."""
        separators = {chr(c) for c in range(sys.maxunicode + 1)
                      if unicodedata.category(chr(c)) == "Zs"} | {"\t"}
        matched = {c for c in map(chr, range(sys.maxunicode + 1))
                   if terminal._BLANK_RUN.fullmatch(c * 2)}
        self.assertEqual(matched, separators)
        self.assertGreater(len(separators), 10)

    def test_controls_are_escaped_before_the_cut_counts_them(self) -> None:
        text = terminal.terminal_text("\x1b" * 100)
        self.assertTrue(text.startswith("\\x1b" * 30), text[:40])
        self.assertIn("more characters)", text)
        self.assertLessEqual(len(text), LIMIT + len(" ... (280 more characters)"))

    def test_limit_none_escapes_only_for_text_that_is_written_not_printed(self) -> None:
        value = "a" + " " * 300 + "\x1b"
        self.assertEqual(terminal.terminal_text(value, limit=None), "a" + " " * 300 + "\\x1b")

    def test_a_whole_message_keeps_its_newlines_and_is_not_cut(self) -> None:
        message = "line one\n  line two " + "y" * 500
        self.assertEqual(terminal.terminal_text(message, keep_newlines=True), message)

    def test_core_re_exports_the_same_helpers(self) -> None:
        self.assertIs(core.terminal_text, terminal.terminal_text)
        self.assertIs(core.quoted, terminal.quoted)
        self.assertEqual(core.ECHO_LIMIT, 120)


class QuotedTest(unittest.TestCase):
    def test_it_is_repr_for_an_ordinary_value(self) -> None:
        for value in ("invoice_owner", "it's", 'say "x"', "a\nb", "\x1b[2J", "\u202e",
                      3, None, [404], {"a": 1}, "a\\b"):
            with self.subTest(value=value):
                self.assertEqual(terminal.quoted(value), repr(value))

    def test_a_long_value_keeps_its_quotes_and_says_how_much_more(self) -> None:
        text = terminal.quoted("n" * 4000)
        self.assertEqual(text, "'" + "n" * LIMIT + "'" + f" ... ({4000 - LIMIT} more characters)")

    def test_blank_runs_are_one_space_before_repr(self) -> None:
        self.assertEqual(terminal.quoted("anonymous" + " " * 4000 + "x"), "'anonymous x'")
        self.assertEqual(terminal.quoted("a\u00a0\u00a0b"), "'a b'")

    def test_a_cut_never_leaves_half_an_escape(self) -> None:
        for filler in ("\x1b", "\u202e", "\U000e0041"):
            for pad in range(8):
                with self.subTest(filler=hex(ord(filler)), pad=pad):
                    text = terminal.quoted("p" * pad + filler * 200)
                    body = text[1:text.index("' ... (")]
                    self.assertEqual(terminal._PARTIAL_ESCAPE.search(body), None, body[-12:])
                    self.assertTrue(body.endswith(("x1b", "202e", "000e0041", "p")), body[-12:])

    def test_terminal_text_never_leaves_half_an_escape_either(self) -> None:
        for pad in range(8):
            with self.subTest(pad=pad):
                text = terminal.terminal_text("p" * pad + "\u202e" * 200)
                body = text[:text.index(" ... (")]
                self.assertTrue(body.endswith(("202e", "p")), body[-12:])
                shown = len(body) + int(text[text.index(" ... (") + 6:].split()[0])
                self.assertEqual(shown, pad + 6 * 200)

    def test_a_long_non_string_is_cut_too(self) -> None:
        text = terminal.quoted(["x" * 500])
        self.assertTrue(text.startswith("['xxx"), text[:10])
        self.assertIn("more characters)", text)


class TerminalNamesTest(unittest.TestCase):
    def test_short_names_are_listed_as_before(self) -> None:
        self.assertEqual(terminal.terminal_names(["a", "b\nc"]), "a, b\\nc")

    def test_each_name_and_the_whole_list_are_bounded(self) -> None:
        # One cut name is 146 characters; a second would pass twice the limit.
        text = terminal.terminal_names(["k" * 500] * 10)
        self.assertEqual(text.count("more characters)"), 1)
        self.assertTrue(text.endswith(", and 9 more"), text[-40:])
        self.assertLess(len(text), 2 * LIMIT)
        self.assertEqual(terminal.terminal_names(["k" * 100] * 3).count("k" * 100), 2)

    def test_many_short_names_are_counted_past_the_budget(self) -> None:
        text = terminal.terminal_names([f"key{index:03d}" for index in range(200)])
        self.assertLessEqual(len(text), 2 * LIMIT + len(", and 200 more"))
        self.assertRegex(text, r", and \d+ more$")


class RefusalLineBackstopTest(unittest.TestCase):
    """cli._main prints every refusal; its lines are bounded there too."""

    def _refused(self, message: str) -> str:
        stderr = io.StringIO()
        with patch.object(cli, "_run", side_effect=core.ConfigError(message)):
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                code = veridor_main(["run", "--config", "unused.json"])
        self.assertEqual(code, 2)
        return stderr.getvalue()

    def test_a_long_line_keeps_its_start_and_its_end(self) -> None:
        printed = self._refused("check 'x' is refused: " + "R" * 5000 + " Fix it and re-run.")
        line = printed.rstrip("\n")
        self.assertNotIn("\n", line)
        self.assertTrue(line.startswith("veridor: check 'x' is refused: RRR"), line[:60])
        self.assertTrue(line.endswith("RRR Fix it and re-run."), line[-40:])
        self.assertIn("characters not shown) ...", line)
        self.assertLess(len(line), terminal.REFUSAL_LINE_LIMIT + 60)

    def test_control_a_line_at_the_limit_and_a_multi_line_refusal_are_whole(self) -> None:
        whole = "w" * terminal.REFUSAL_LINE_LIMIT
        self.assertEqual(self._refused(whole), f"veridor: {whole}\n")
        listing = "--read-only refuses POST in check 'a'.request, and 1 other:\n  POST in x  (3 requests)"
        self.assertEqual(self._refused(listing), f"veridor: {listing}\n")

    def test_the_backstop_is_above_the_longest_honest_refusal(self) -> None:
        """721 characters, measured over every refusal the fast tier prints."""
        self.assertGreater(terminal.REFUSAL_LINE_LIMIT, 721)


#: Modules held to stdlib-only imports (tests/test_coverage.py), which quote
#: with repr and rely on the refusal line bound in cli._main.
_REPR_ALLOWED = {"openapi.py", "coverage.py"}


class NoUnboundedReprTest(unittest.TestCase):
    """``{value!r}`` escapes but does not bound, so messages use quoted()."""

    def _repr_sites(self) -> dict[str, list[int]]:
        package = Path(veridor.__file__).resolve().parent
        found: dict[str, list[int]] = {}
        for path in sorted(package.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.FormattedValue) and node.conversion == ord("r"):
                    found.setdefault(path.name, []).append(node.lineno)
        return found

    def test_only_the_stdlib_only_modules_use_it(self) -> None:
        self.assertEqual(set(self._repr_sites()) - _REPR_ALLOWED, set())

    def test_control_the_scan_sees_the_ones_that_remain(self) -> None:
        found = self._repr_sites()
        self.assertTrue(found.get("openapi.py") and found.get("coverage.py"), found)


class UnboundedCallersAreNamedTest(unittest.TestCase):
    """``limit=None`` skips the cut and the blank-run collapse, so every module
    that calls it is named where terminal_text documents it. The docstring
    said it was for "the one caller" (``capsule.build``) after coverage's
    diagnostics had started printing through it without the collapse."""

    def _unbounded_sites(self) -> set[str]:
        package = Path(veridor.__file__).resolve().parent
        found: set[str] = set()
        for path in sorted(package.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name == "terminal_text" and any(
                    keyword.arg == "limit"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is None
                    for keyword in node.keywords
                ):
                    found.add(path.stem)
        return found

    def test_every_module_calling_it_is_named_in_the_docstring(self) -> None:
        doc = terminal.terminal_text.__doc__ or ""
        passage = doc[doc.index("``limit=None``"):]
        for module in sorted(self._unbounded_sites()):
            with self.subTest(module=module):
                self.assertIn(f"``{module}", passage)
        self.assertNotIn("the one caller", doc)

    def test_the_passage_does_not_offer_collapsing_as_the_bound(self) -> None:
        """The passage told a new caller that prints input to collapse
        :data:`_BLANK_RUN` "or" print a sentence whose values were bounded,
        "or a run of spaces still pads a forged row" -- as if collapsing were
        enough. It is not: U+2800 and U+3164 are printable, not in
        ``_BLANK_RUN``, and padded coverage's "nearest:" hint to a forged row
        after the collapse went in. The module's own ``_BLANK_RUN`` comment
        already said so; the passage must say a printing caller cuts."""
        doc = terminal.terminal_text.__doc__ or ""
        passage = doc[doc.index("``limit=None``"):doc.index("``keep_newlines`` is for")]
        self.assertNotIn("one or the other", passage)
        self.assertIn("Collapsing alone is not a bound", passage)
        for blank in ("U+2800", "U+3164"):
            with self.subTest(blank=blank):
                self.assertIn(blank, passage)
                # Control: what the passage names really is outside the collapse.
                self.assertIsNone(terminal._BLANK_RUN.search(chr(int(blank[2:], 16)) * 3))

    def test_control_the_scan_sees_both_callers(self) -> None:
        self.assertLessEqual({"capsule", "coverage"}, self._unbounded_sites())


if __name__ == "__main__":
    unittest.main()
