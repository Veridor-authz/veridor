"""A refusal quotes the input it refuses, and that input may not start a line.

Every refusal reaches the terminal through one line in ``cli._main``, which
escapes escape sequences and bidi controls but keeps newlines, because some of
Veridor's own refusals are several lines by design. Many raise sites joined
keys from the input into the message as they were -- "has unsupported keys:
...", "references unknown identities: ...", "defines none of ...", the verbs a
capsule would write with, a capsule's ``schema_version`` -- so a newline in a
JSON key reached stderr as a real line break. Reproduced: a capsule whose
``check.expect`` key was ``anonymous`` followed by thirty newlines and a copy of
a genuine NOT_REPRODUCED session exited 2 and sent nothing, and the visible
screen was that NOT_REPRODUCED session, the real refusal scrolled off. The
tests that should have caught it could not: their "obeyed character" check
exempted the newline.

So every key and every leaf of a capsule and of a configuration that uses
sessions and sequences gets ``"\\n\\nFORGED"`` planted in it, and no line of
the output may begin with ``FORGED``.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_capsule import VERIFIER_ENV, _RecordingOpener, _screen, _v010_capsule  # noqa: E402
from veridor import core, matrix  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

PLANT = "\n\nFORGED"


def _forged(text: str) -> list[str]:
    """Every line of ``text`` the planted value started."""
    return [line for line in text.split("\n") if line.lstrip().startswith("FORGED")]


def _places(node: Any, here: tuple = ()) -> Iterator[tuple[str, tuple]]:
    """``("key", path)`` for every object key, ``("leaf", path)`` for every scalar."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield "key", here + (key,)
            yield from _places(value, here + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _places(value, here + (index,))
    else:
        yield "leaf", here


def _planted(document: Any, kind: str, path: tuple, plant: str = PLANT) -> Any:
    """``document`` with ``plant`` appended to the key or the leaf at ``path``."""
    document = copy.deepcopy(document)
    parent = document
    for step in path[:-1]:
        parent = parent[step]
    last = path[-1]
    if kind == "key":
        items = list(parent.items())
        parent.clear()
        for key, value in items:
            parent[key + plant if key == last else key] = value
    else:
        value = parent[last]
        parent[last] = value + plant if isinstance(value, str) else plant
    return document


def _veridor(argv: list[str], document: Any) -> dict:
    """``veridor`` in process on ``document``, nothing on the wire."""
    opener = _RecordingOpener()
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        argv = [part.replace("{input}", str(path)).replace("{dir}", directory) for part in argv]
        # GITHUB_ACTIONS is what turns on `run`'s workflow commands, more lines
        # that quote the input. Set here, not inherited: this sweep used to read
        # them only on a GitHub runner, so it passed everywhere else and failed
        # on every first run there.
        with patch.dict(os.environ, {**VERIFIER_ENV, "GITHUB_ACTIONS": "true"}), \
                patch.object(core, "_OPENER", opener):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(argv)
    return {"code": code, "stdout": stdout.getvalue(), "stderr": stderr.getvalue(),
            "requests": opener.requests}


def _rich_config() -> dict:
    """A configuration that reaches the session, capture, inject, sequence and
    teardown loaders as well as the identity and check ones."""
    capsule = _v010_capsule()
    identities = copy.deepcopy(capsule["identities"])
    identities["invoice_owner"]["headers"]["X-Tenant"] = "acme"
    identities["invoice_owner"]["session"] = {
        "login": [{
            "method": "POST", "path": "/login", "json": {"user": "alice"},
            "headers": {"X-Login": "1"}, "expect_status": [200],
            "capture": {"csrf": {"from": "html_meta", "name": "csrf-token"}},
        }],
        "establishes": {"cookie": "sid"},
        "capture": {"sid_value": {"from": "cookie", "name": "sid"}},
        "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}"}],
        "reestablish": "check",
    }
    check = copy.deepcopy(capsule["check"])
    check["request"]["headers"] = {"Accept": "application/json"}
    return {
        "version": 2,
        "target": {"base_url": "http://127.0.0.1:8765", "timeout_seconds": 3},
        "identities": identities,
        "checks": [check],
        "sequences": [{
            "id": "seq",
            "steps": [
                {"role": "setup", "as": "invoice_owner",
                 "request": {"method": "POST", "path": "/things", "json": {"name": "vd-${run_id}"}},
                 "expect": {"status": [201]}, "capture": {"thing_id": "$.id"}},
                {"role": "assert", "as": "other_tenant",
                 "request": {"method": "GET", "path": "/things/${thing_id}"},
                 "expect": {"status": [403]}},
            ],
            "teardown": [{"as": "invoice_owner",
                          "request": {"method": "DELETE", "path": "/things/${thing_id}"}}],
        }],
    }


VERIFY = ["verify", "{input}", "--output-dir", "{dir}/out"]
VERIFY_BASE_URL = VERIFY + ["--base-url", "http://127.0.0.1:8765"]
RUN = ["run", "--config", "{input}", "--output-dir", "{dir}/out"]
WRITE_CAPSULE = ["capsule", "--config", "{input}", "--check", "invoice-tenant-isolation",
                 "--output", "{dir}/proof.json"]


class ForgedLineDetectorTest(unittest.TestCase):
    """The detector itself, so a clean result below means something."""

    def test_it_finds_a_planted_line_and_ignores_an_escaped_one(self) -> None:
        self.assertEqual(_forged("veridor: refused: x" + PLANT), ["FORGED"])
        self.assertEqual(_forged("veridor: refused: x\n\n   FORGED"), ["   FORGED"])
        self.assertEqual(_forged("veridor: refused: x\\n\\nFORGED"), [])

    def test_every_place_is_planted(self) -> None:
        document = {"a": {"b": [1, "x"]}}
        places = list(_places(document))
        self.assertEqual(places, [("key", ("a",)), ("key", ("a", "b")),
                                  ("leaf", ("a", "b", 0)), ("leaf", ("a", "b", 1))])
        self.assertEqual(_planted(document, "key", ("a", "b")), {"a": {"b" + PLANT: [1, "x"]}})
        self.assertEqual(_planted(document, "leaf", ("a", "b", 1))["a"]["b"][1], "x" + PLANT)

    def test_control_the_honest_documents_run_and_forge_nothing(self) -> None:
        """Planting into a document that was already refused would test the
        refusal of something else. Both load, run and send."""
        for argv, document in ((VERIFY, _v010_capsule()), (RUN, _rich_config())):
            with self.subTest(command=argv[0]):
                result = _veridor(argv, document)
                self.assertTrue(result["requests"], result["stderr"])
                self.assertEqual(_forged(result["stdout"] + result["stderr"]), [])
        written = _veridor(WRITE_CAPSULE, _rich_config())
        self.assertEqual(written["code"], 0, written["stderr"])


class PlantedLineBreakTest(unittest.TestCase):
    def _sweep(self, argv: list[str], document: Any, kind: str) -> None:
        swept = 0
        for where, path in _places(document):
            if where != kind:
                continue
            swept += 1
            with self.subTest(place=path):
                result = _veridor(argv, _planted(document, kind, path))
                output = result["stdout"] + result["stderr"]
                self.assertEqual(_forged(output), [], output[-600:])
        self.assertGreater(swept, 10)

    def test_every_capsule_key(self) -> None:
        self._sweep(VERIFY, _v010_capsule(), "key")

    def test_every_capsule_key_with_a_base_url(self) -> None:
        self._sweep(VERIFY_BASE_URL, _v010_capsule(), "key")

    def test_every_capsule_leaf(self) -> None:
        self._sweep(VERIFY, _v010_capsule(), "leaf")

    def test_every_capsule_leaf_with_a_base_url(self) -> None:
        self._sweep(VERIFY_BASE_URL, _v010_capsule(), "leaf")

    def test_every_configuration_key(self) -> None:
        self._sweep(RUN, _rich_config(), "key")

    def test_every_configuration_leaf(self) -> None:
        self._sweep(RUN, _rich_config(), "leaf")

    def test_every_configuration_key_the_capsule_writer_reads(self) -> None:
        self._sweep(WRITE_CAPSULE, _rich_config(), "key")

    def test_every_configuration_leaf_the_capsule_writer_reads(self) -> None:
        self._sweep(WRITE_CAPSULE, _rich_config(), "leaf")

    def test_every_matrix_section_key(self) -> None:
        """`map` refuses an unknown matrix or specimen key before it sends,
        and names the key. Called directly: a planted key that loads would
        start a paced scan, which is not what this measures."""
        section = {"specimens": {"/api/x/{id}": [{"label": "a", "values": {"id": "1"}}]},
                   "unauthenticated": "anonymous"}
        refusals = []
        for where, path in _places(section):
            if where == "key" and path[-1] in {"specimens", "unauthenticated", "label", "values"}:
                planted = _planted(section, "key", path)
                with self.assertRaises(matrix.MatrixError) as caught:
                    if path == ("specimens",) or path == ("unauthenticated",):
                        matrix._matrix_section({"matrix": planted})
                    else:
                        matrix._parse_specimens(planted, ["anonymous"], {})
                refusals.append(str(caught.exception))
        self.assertEqual(len(refusals), 4)
        for refusal in refusals:
            self.assertIn("unsupported keys", refusal)
            self.assertEqual(_forged(refusal), [], refusal)
            self.assertIn("\\n\\nFORGED", refusal)



# ---------------------------------------------------------------------------
# Long values: a line that wraps draws rows of its own.
#
# Escaping the newline was not enough. A capsule key of printable text and
# spaces -- 'anonymous', then spaces and a genuine session, each line padded
# to 80 columns, 4097 characters with no control character in them -- was
# echoed whole by "references unknown identities:", and on an 80x24 terminal
# the visible screen was a genuine-looking NOT_REPRODUCED (or CONFIRMED)
# session with the real refusal wrapped off the top (measured with GNU screen
# on a sized pty, and at 120x30 with a 120-column build). So every quotation
# of the input is held to ECHO_LIMIT characters with its blank runs made one
# space, and the refusal's own first line has to be on screen.
# ---------------------------------------------------------------------------

#: The most of one quoted value a message may show: README's figure.
ECHO_LIMIT = 120

#: Marks a planted value, so a line can say how many times it quotes one.
TAG = "ZQJ"

#: The shape measured: printable text padded with spaces.
SPACE_PADDED = TAG + " " * 1500 + "R" * 1500

#: Only characters a name may hold, so the values the loaders accept --
#: identity names, check ids, methods, paths -- are run and echoed too.
#: Shorter: the capsule writer's credential scan is slow on long strings, and
#: ten times the limit is enough to see a value that was not cut.
NAME_SHAPED = TAG + "R" * 1200

_FILLER = re.compile(r"R{8,}")
_BLANKS = re.compile(r"[\t\u0020\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]{16,}")


def _unbounded(text: str) -> list[str]:
    """Every line of ``text`` that shows more of a planted value than it may.

    A line may carry ECHO_LIMIT characters of it per quotation (each starts
    with TAG), and no run of blanks: those are what paint rows of a forged
    screen. Veridor's own text has neither eight R's in a row nor sixteen
    blanks.
    """
    found = []
    for line in text.split("\n"):
        shown = sum(len(run) for run in _FILLER.findall(line))
        if shown > line.count(TAG) * ECHO_LIMIT or _BLANKS.search(line):
            found.append(line)
    return found


def _squashed(line: str) -> str:
    """A line fit for a failure message."""
    return _BLANKS.sub(lambda m: f"<{len(m.group(0))} blanks>",
                       _FILLER.sub(lambda m: f"<{len(m.group(0))} R>", line))[:400]


def _refusal_rows(stderr: str, columns: int, rows: int) -> tuple[str, list[str]]:
    """The last refusal line and the screen ``columns`` x ``rows`` shows.

    The refusal is the last line ``_main`` began with ``veridor:``; nothing
    else may be printed after it but its own continuation lines.
    """
    lines = stderr.rstrip("\n").split("\n")
    last = max(i for i, line in enumerate(lines) if line.startswith("veridor: "))
    return lines[last], _screen("\n".join(lines), columns, rows)


class LongValueDetectorTest(unittest.TestCase):
    """The detector, so a clean sweep below means something."""

    def test_it_finds_a_whole_value_and_passes_a_bounded_one(self) -> None:
        whole = "veridor: check 'c' references unknown identities: anonymous" + SPACE_PADDED
        self.assertEqual(len(_unbounded(whole)), 1)
        self.assertEqual(len(_unbounded("x " + NAME_SHAPED)), 1)
        bounded = ("veridor: refused: anonymous" + TAG + " " + "R" * (ECHO_LIMIT - 4)
                   + " ... (1381 more characters)")
        self.assertEqual(_unbounded(bounded), [])
        # Two quotations may show twice as much; one may not.
        self.assertEqual(_unbounded(bounded + ", " + bounded), [])
        self.assertEqual(len(_unbounded(bounded + "R" * ECHO_LIMIT)), 1)

    def test_it_finds_blank_runs_of_every_space_separator(self) -> None:
        for blank in ("\t", " ", "\u00a0", "\u2007", "\u3000"):
            with self.subTest(blank=hex(ord(blank))):
                self.assertEqual(len(_unbounded("a" + blank * 16 + "b")), 1)
        self.assertEqual(_unbounded("  check:    x  (y)"), [])

    def test_the_screen_loses_the_refusal_line_on_the_old_output(self) -> None:
        """The screen model, on the refusal as it used to be printed, loses
        the refusal line, as measured with GNU screen."""
        prefix = "veridor: check 'invoice-tenant-isolation' references unknown identities: anonymous"
        padding = " " * (80 - len(prefix) % 80) + " " * 80 * 30 + "Veridor capsule — NOT_REPRODUCED"
        refusal, screen = _refusal_rows(prefix + padding, 80, 24)
        self.assertTrue(refusal.startswith(prefix))
        self.assertNotIn(prefix[:40], "\n".join(screen))
        self.assertIn("Veridor capsule — NOT_REPRODUCED", screen)


class PlantedLongValueTest(unittest.TestCase):
    """Every key and every leaf, both shapes, every command that loads them."""

    def _sweep(self, argv: list[str], document: Any, kind: str, plant: str,
               sections: frozenset[str] | None = None) -> None:
        swept = refused = 0
        for where, path in _places(document):
            if where != kind or (sections is not None and path[0] not in sections):
                continue
            swept += 1
            with self.subTest(place=path):
                result = _veridor(argv, _planted(document, kind, path, plant))
                for stream in ("stdout", "stderr"):
                    offending = [_squashed(line) for line in _unbounded(result[stream])]
                    self.assertEqual(offending, [], stream)
                if result["code"] == 2 and not result["stdout"]:
                    refused += 1
                    for columns, rows in ((80, 24), (120, 30)):
                        refusal, screen = _refusal_rows(result["stderr"], columns, rows)
                        self.assertIn(refusal[:columns].rstrip(), screen, _squashed(refusal))
                elif argv[0] == "verify" and result["stdout"]:
                    verdict = [line for line in result["stdout"].split("\n")
                               if re.match(r"  (CONFIRMED|NOT_REPRODUCED|INCONCLUSIVE): ", line)]
                    self.assertEqual(len(verdict), 1, result["stdout"][-400:])
                    screen = _screen(result["stderr"] + result["stdout"], 80, 24)
                    self.assertIn(verdict[0][:80].rstrip(), screen)
        self.assertGreater(swept, 10)
        self.assertGreater(refused, 0)

    def test_the_limit_is_the_one_the_code_applies(self) -> None:
        self.assertEqual(core.ECHO_LIMIT, ECHO_LIMIT)


class VerdictReasonTest(unittest.TestCase):
    """What `verify` prints after the verdict word quotes the capsule too: the
    identity names in an INCONCLUSIVE reason, and the variables its banner
    says it reads. A planted key renames one place and is refused, so these
    rename consistently and run against a target that answers."""

    def _renamed(self, identity: str) -> dict:
        document = _v010_capsule()
        document["identities"][identity] = document["identities"].pop("other_tenant")
        document["check"]["expect"][identity] = document["check"]["expect"].pop("other_tenant")
        document["claim"]["identity"] = identity
        return document

    def test_identity_names_in_every_verdict_are_bounded(self) -> None:
        from test_capsule import _demo_target, _proxy_407, _TargetOpener, _verify  # noqa: PLC0415

        long_name = "other_tenant" + NAME_SHAPED
        stale = {**VERIFIER_ENV, "VERIDOR_OTHER_TENANT_TOKEN": "expired-token"}
        # (target, environment, verdict, whether the reason names the identity)
        for label, answer, env, verdict, named in (
            ("vulnerable", _demo_target(vulnerable=True), None, "CONFIRMED", False),
            ("fixed", _demo_target(vulnerable=False), None, "NOT_REPRODUCED", False),
            ("proxy 407", _proxy_407, None, "INCONCLUSIVE", True),
            ("stale token", _demo_target(vulnerable=True), stale, "INCONCLUSIVE", True),
        ):
            with self.subTest(target=label):
                result = _verify(self._renamed(long_name), env=env, opener=_TargetOpener(answer))
                self.assertIn(f"Veridor capsule — {verdict}", result["stdout"], result["stderr"][-300:])
                output = result["stderr"] + result["stdout"]
                if named:
                    self.assertIn(TAG, result["stdout"])
                self.assertEqual([_squashed(line) for line in _unbounded(output)], [])
                verdict = [line for line in result["stdout"].split("\n")
                           if re.match(r"  (CONFIRMED|NOT_REPRODUCED|INCONCLUSIVE): ", line)]
                self.assertEqual(len(verdict), 1)
                self.assertIn(verdict[0][:80], _screen(output, 80, 24))

    def test_the_banner_lists_every_variable_each_bounded(self) -> None:
        from test_capsule import _verify  # noqa: PLC0415

        name = "VERIDOR_" + TAG + "R" * 1200
        document = _v010_capsule()
        document["identities"]["other_tenant"]["headers"]["Authorization"] = "Bearer ${" + name + "}"
        result = _verify(document, env={**VERIFIER_ENV, name: "a-long-enough-value"})
        banner = next(line for line in result["stderr"].split("\n")
                      if line.startswith("veridor: verifying capsule check"))
        self.assertIn("VERIDOR_INVOICE_OWNER_TOKEN", banner)
        self.assertIn("VERIDOR_" + TAG, banner)
        self.assertEqual(_unbounded(banner), [], _squashed(banner))


class MapOutputTest(unittest.TestCase):
    """`map` prints identity names, operations, specimen labels and ignore
    entries from the configuration and the spec. Rendered directly: a planted
    configuration that loads would start a paced scan."""

    def _rendered(self, plant: str) -> str:
        from test_blastradius import br, grouping, make_matrix  # noqa: PLC0415

        owner = "owner" + (plant if plant is NAME_SHAPED else "")
        matrix = make_matrix(
            [
                ("GET /api/invoices" + plant, "spec" + plant, {"anonymous": 200, owner: 200}),
                ("GET /api/reports", None, {"anonymous": 401, owner: 200}),
                ("GET /api/ledgers", None, {"anonymous": 401, owner: 200}),
            ],
            ignored=["GET /api/ignored" + plant],
        )
        group = grouping(matrix, unauthenticated="anonymous")
        candidates = br.find_candidates(matrix, group)
        self.assertTrue(candidates)
        return (br.render_blast_radius(br.blast_radius_report(matrix))
                + br.render_candidates(br.candidates_document(matrix, candidates, grouping=group)))

    def test_every_value_map_prints_is_bounded(self) -> None:
        for plant in (SPACE_PADDED, NAME_SHAPED):
            with self.subTest(shape=plant[:8]):
                text = self._rendered(plant)
                self.assertIn(TAG, text)
                # map wraps its prose at word boundaries, which can put a
                # quotation's TAG and the rest of it on different lines, so
                # the quotations are counted over the whole text.
                self.assertEqual(_unbounded(" ".join(text.split("\n"))), [], text[-2000:])
                self.assertEqual([_squashed(line) for line in _unbounded(text)
                                  if _BLANKS.search(line)], [])

    def test_control_every_ignore_entry_is_still_listed(self) -> None:
        text = self._rendered("")
        self.assertIn("GET /api/ignored", text)
        self.assertIn('identity "owner"', text)


def _long_value_sweep(argv: list[str], document: Any, kind: str, plant: str,
                      sections: frozenset[str] | None = None):
    def test(self: PlantedLongValueTest) -> None:
        self._sweep(argv, document(), kind, plant, sections)
    return test


#: A configuration's places, in two halves, each its own test.
_CONFIGURATION_HALVES = (
    ("identities", frozenset({"identities"})),
    ("checks_and_sequences", frozenset({"version", "target", "checks", "sequences"})),
)

# One test per command, place and shape (a configuration's also per half), so
# each stays inside the fast tier's budget: every key and every leaf of a
# capsule (verify, with and without --base-url) and of a configuration with
# sessions and sequences (run, and the capsule writer), each planted with both
# shapes.
for _name, _argv, _document, _halves in (
    ("capsule", VERIFY, _v010_capsule, (("", None),)),
    ("capsule_with_a_base_url", VERIFY_BASE_URL, _v010_capsule, (("", None),)),
    ("configuration", RUN, _rich_config, _CONFIGURATION_HALVES),
    ("configuration_the_capsule_writer_reads", WRITE_CAPSULE, _rich_config,
     _CONFIGURATION_HALVES),
):
    for _kind in ("key", "leaf"):
        for _shape, _plant in (("space_padded", SPACE_PADDED), ("name_shaped", NAME_SHAPED)):
            for _half, _sections in _halves:
                setattr(PlantedLongValueTest,
                        f"test_every_{_name}_{_kind}{'_in_' + _half if _half else ''}_{_shape}",
                        _long_value_sweep(_argv, _document, _kind, _plant, _sections))


class SweepCoversEveryPlaceTest(unittest.TestCase):
    def test_the_configuration_halves_cover_every_section(self) -> None:
        covered = frozenset().union(*(sections for _, sections in _CONFIGURATION_HALVES))
        self.assertEqual(set(_rich_config()), set(covered))

if __name__ == "__main__":
    unittest.main()
