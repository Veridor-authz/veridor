"""A field of the wrong type is a refusal (exit 2), never "a bug in Veridor".

A configuration is the operator's and a capsule is a stranger's, and both are
hand-edited. Setting each field of a configuration that uses sessions,
captures and sequences to each wrong type found six that crashed the loader
with exit 70 instead of refusing it (measured, nothing sent in any case): a
login step's ``capture`` that is not an object (AttributeError), a capture's
``from`` or a session's ``reestablish`` given a list or an object
(unhashable, TypeError), a sequence's ``steps`` given a number (TypeError),
and a step's ``role`` given a list or an object. A session-level ``capture``
that is not an object crashed the same way.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_capsule import VERIFIER_ENV, _RecordingOpener  # noqa: E402
from test_refusal_lines import _places, _rich_config  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

#: One value of each JSON type a field can wrongly hold.
WRONG = (5, "s", ["x"], {"k": "v"})


def _run(config: dict) -> dict:
    stdout, stderr = io.StringIO(), io.StringIO()
    opener = _RecordingOpener()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with patch.dict(os.environ, VERIFIER_ENV), patch.object(core, "_OPENER", opener):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(["run", "--config", str(path),
                                     "--output-dir", str(Path(directory) / "out")])
    return {"code": code, "stderr": stderr.getvalue(), "requests": opener.requests}


def _containers(document) -> list[tuple]:
    """Every path to a key or an item, leaves and containers alike."""
    paths = {path for _, path in _places(document)}
    return sorted({path[:end] for path in paths for end in range(1, len(path) + 1)},
                  key=lambda path: [str(step) for step in path])


def _replaced(document: dict, path: tuple, value) -> dict:
    document = copy.deepcopy(document)
    parent = document
    for step in path[:-1]:
        parent = parent[step]
    parent[path[-1]] = copy.deepcopy(value)
    return document


class WrongTypeTest(unittest.TestCase):
    def _sweep(self, top: str, within=lambda path: True) -> None:
        base = _rich_config()
        swept = 0
        for path in _containers(base):
            if path[0] != top or not within(path):
                continue
            for value in WRONG:
                swept += 1
                with self.subTest(path=path, value=value):
                    result = _run(_replaced(base, path, value))
                    self.assertNotEqual(result["code"], 70, result["stderr"][-400:])
                    self.assertNotIn("internal error", result["stderr"])
        self.assertGreater(swept, 8)

    def test_control_the_configuration_loads_and_sends(self) -> None:
        result = _run(_rich_config())
        self.assertTrue(result["requests"], result["stderr"])

    def test_every_identity_session_field(self) -> None:
        self._sweep("identities", lambda path: "session" in path)

    def test_every_other_identity_field(self) -> None:
        self._sweep("identities", lambda path: "session" not in path)

    def test_every_sequence_step_field(self) -> None:
        self._sweep("sequences", lambda path: "steps" in path)

    def test_every_other_sequence_field(self) -> None:
        self._sweep("sequences", lambda path: "steps" not in path)

    def test_every_check_and_target_field(self) -> None:
        self._sweep("checks")
        self._sweep("target")

    def test_the_six_reported_shapes_are_refused_naming_the_field(self) -> None:
        login = ("identities", "invoice_owner", "session", "login", 0)
        cases = [
            (login + ("capture",), "x", "capture"),
            (login + ("capture", "csrf", "from"), ["cookie"], "'from'"),
            (("identities", "invoice_owner", "session", "capture"), 7, "capture"),
            (("identities", "invoice_owner", "session", "reestablish"), ["check"],
             "'reestablish'"),
            # Refused, exit 2, but by the environment pass that runs before
            # validation: with no steps list there is no capture to defer, so
            # the teardown's ${thing_id} is read as an unset variable.
            (("sequences", 0, "steps"), 3, "thing_id"),
            (("sequences", 0, "steps", 0, "role"), {"setup": True}, "role"),
        ]
        for path, value, named in cases:
            with self.subTest(path=path):
                result = _run(_replaced(_rich_config(), path, value))
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertEqual(result["requests"], [])
                self.assertIn(named, result["stderr"])


if __name__ == "__main__":
    unittest.main()
