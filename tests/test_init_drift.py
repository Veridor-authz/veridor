"""The on-ramp for the path that declares nothing.

Drift removed the policy from the workflow, but `init` still scaffolded only
the declaration-heavy path: five guessed checks, no `matrix` section, and a
five-step list ending in "expect the first run to be red". Running `map` on that
scaffold measured nothing on the templated routes -- the tenant-object shape
this tool exists for -- because the reader was never told `matrix.specimens`
existed. A path with no on-ramp is a path nobody takes.

The dangerous part of scaffolding a specimen is the placeholder itself. A fake
id 404s, a 404 is classified `refused`, and a grid of refusals reads exactly
like a boundary that holds. Recorded as a drift baseline it is worse: the first
run with a real id then reads as reach that OPENED. So the placeholder is a
value the matrix refuses to send, and that refusal is the load-bearing test
here.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from veridor.cli import _parser, main as veridor_main  # noqa: E402
from veridor.core import load_config  # noqa: E402
from veridor.matrix import SPECIMEN_PLACEHOLDER, MatrixError, plan_matrix  # noqa: E402
from veridor.openapi import load_spec, parse_spec  # noqa: E402

SPEC = ROOT / "fixtures" / "openapi.demo.json"


class ScaffoldTest(unittest.TestCase):
    def _init(self, *extra: str) -> tuple[int, dict]:
        """Scaffold into a temporary directory, capturing what `init` printed.

        Captured rather than silenced: `init`'s console output IS its interface
        -- the numbered next-steps are how anybody gets from a scaffold to a
        first run -- so `self.printed` is asserted on below rather than thrown
        away. The fast tier refuses a test that writes to stdout, because its
        text lands after unittest's OK line where nobody reads it.
        """
        directory = tempfile.mkdtemp()
        output = Path(directory) / "veridor.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = veridor_main(
                ["init", "--openapi", str(SPEC), "--output", str(output), *extra]
            )
        self.printed = buffer.getvalue()
        document = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
        return code, document

    def test_the_drift_scaffold_declares_nothing(self) -> None:
        code, config = self._init("--for", "drift")
        self.assertEqual(code, 0)
        self.assertNotIn("checks", config)
        self.assertIn("matrix", config)
        # What it printed is the other half of the scaffold, and the reason the
        # capture above exists rather than a redirect to nowhere.
        self.assertIn("--for drift", self.printed)
        self.assertIn("nothing declared", self.printed)

    def test_every_templated_route_gets_a_specimen(self) -> None:
        """A route with no specimen is not probed at all, so an omission here
        is an invisible hole rather than a visible one."""
        code, config = self._init("--for", "drift")
        self.assertEqual(code, 0)
        inventory = parse_spec(load_spec(SPEC), source=str(SPEC))
        templated = {
            operation.path_template
            for operation in inventory.operations
            if "{" in operation.path_template
        }
        self.assertTrue(templated, "the demo spec should have a templated route")
        self.assertEqual(set(config["matrix"]["specimens"]), templated)

    def test_the_scaffold_carries_a_marker_and_names_its_owner(self) -> None:
        """Without a marker drift can only see status changes; with one it can
        report that data actually crossed."""
        _, config = self._init("--for", "drift")
        owner = config["matrix"]["marker_owner"]
        self.assertIn("marker", config["identities"][owner])

    def test_the_drift_scaffold_loads_as_a_map_config(self) -> None:
        import os  # noqa: PLC0415

        os.environ.setdefault("VERIDOR_OWNER_TOKEN", "t1")
        os.environ.setdefault("VERIDOR_OTHER_TENANT_TOKEN", "t2")
        _, config = self._init("--for", "drift")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            loaded = load_config(path, require_checks=False)
        self.assertEqual(loaded["checks"], [])

    def test_run_stays_the_default(self) -> None:
        """Existing invocations must not change shape."""
        args = _parser().parse_args(
            ["init", "--openapi", "s.json", "--output", "c.json"])
        self.assertEqual(args.scaffold_for, "run")
        code, config = self._init()
        self.assertEqual(code, 0)
        self.assertIn("checks", config)
        self.assertNotIn("matrix", config)


class PlaceholderRefusalTest(unittest.TestCase):
    """The scaffold's own output must not be probeable as written."""

    def setUp(self) -> None:
        self.inventory = parse_spec(load_spec(SPEC), source=str(SPEC))
        directory = tempfile.mkdtemp()
        self.output = Path(directory) / "veridor.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            veridor_main(["init", "--for", "drift", "--openapi", str(SPEC),
                          "--output", str(self.output)])
        self.printed = buffer.getvalue()
        # The scaffold's own warning about the placeholder is what this class is
        # about, so it is asserted here rather than discarded.
        self.assertIn(SPECIMEN_PLACEHOLDER, self.printed)
        import os  # noqa: PLC0415

        os.environ.setdefault("VERIDOR_OWNER_TOKEN", "t1")
        os.environ.setdefault("VERIDOR_OTHER_TENANT_TOKEN", "t2")

    def _plan(self):
        return plan_matrix(
            load_config(self.output, require_checks=False), self.inventory
        )

    def test_an_unedited_placeholder_is_refused(self) -> None:
        with self.assertRaises(MatrixError) as caught:
            self._plan()
        message = str(caught.exception)
        self.assertIn(SPECIMEN_PLACEHOLDER, message)
        # The reason has to travel with the refusal, or it reads as pedantry.
        self.assertIn("404", message)
        self.assertIn("reads like a boundary that holds", message)

    def test_a_real_id_plans_normally(self) -> None:
        config = json.loads(self.output.read_text(encoding="utf-8"))
        for entries in config["matrix"]["specimens"].values():
            for entry in entries:
                entry["values"] = {key: "inv-100" for key in entry["values"]}
        self.output.write_text(json.dumps(config), encoding="utf-8")
        self.assertGreater(len(self._plan().probes), 0)


class SpecimenAdviceTest(unittest.TestCase):
    """`skipped_no_specimen` is the tool's vocabulary, not the reader's."""

    def _advice(self, cells: list[dict]) -> str:
        from veridor.cli import _specimen_advice  # noqa: PLC0415

        return _specimen_advice({"cells": cells})

    def test_the_advice_is_pasteable_json_naming_the_real_routes(self) -> None:
        advice = self._advice([
            {"operation": "GET /api/invoices/{id}",
             "unknown_reason": "skipped_no_specimen"},
            {"operation": "GET /api/orgs/{org}/members/{id}",
             "unknown_reason": "skipped_no_specimen"},
        ])
        body = advice[advice.index("{"):]
        parsed = json.loads("\n".join(line.strip() for line in body.splitlines()))
        specimens = parsed["matrix"]["specimens"]
        self.assertEqual(
            sorted(specimens), ["/api/invoices/{id}", "/api/orgs/{org}/members/{id}"])
        # Every token in the template gets its own slot, not just the first.
        self.assertEqual(
            sorted(specimens["/api/orgs/{org}/members/{id}"][0]["values"]),
            ["id", "org"],
        )

    def test_the_key_is_a_path_template_and_never_carries_the_method(self) -> None:
        """`matrix.specimens` is keyed by path alone. Emitting "GET /a/{id}"
        produces a stanza the matrix REFUSES -- a documented fix that does not
        work, which is worse than no fix. `--dry-run` built the key from
        `method + operation` and operation already began with the method."""
        advice = self._advice([
            {"operation": "GET /api/invoices/{id}",
             "unknown_reason": "skipped_no_specimen"},
        ])
        self.assertIn('"/api/invoices/{id}"', advice)
        self.assertNotIn('"GET /api/invoices/{id}"', advice)

    def test_a_large_specification_is_summarised_rather_than_dumped(self) -> None:
        """60 pasted stanzas is a wall nobody reads -- and truncating silently
        would read as "that is all of them"."""
        cells = [
            {"operation": f"GET /api/v1/resource{index}/{{id}}",
             "unknown_reason": "skipped_no_specimen"}
            for index in range(60)
        ]
        advice = self._advice(cells)
        self.assertIn("and 55 more templated route(s)", advice)
        self.assertLess(advice.count("REPLACE-WITH-A-REAL-ID"), 10)
        self.assertIn("unprobed until it has a specimen", advice)

    def test_nothing_is_said_when_nothing_was_skipped(self) -> None:
        self.assertEqual(self._advice([
            {"operation": "GET /a", "unknown_reason": None},
            {"operation": "GET /b", "unknown_reason": "skipped_mutating"},
        ]), "")

    def test_the_advice_explains_why_rather_than_only_what(self) -> None:
        advice = self._advice([{"operation": "GET /a/{id}",
                                "unknown_reason": "skipped_no_specimen"}])
        self.assertIn("never enumerates ids", advice)
        self.assertIn("skipped rather than guessed at", advice)


class SignpostTest(unittest.TestCase):
    """Each scaffold has to say which path it is, and that the other exists."""

    def _output(self, *extra: str) -> str:
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        directory = tempfile.mkdtemp()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            veridor_main(["init", "--openapi", str(SPEC), "--output",
                          str(Path(directory) / "veridor.json"), *extra])
        return buffer.getvalue()

    def test_the_run_scaffold_names_itself_and_points_at_drift(self) -> None:
        text = self._output()
        self.assertIn("--for run", text)
        self.assertIn("veridor init --for drift", text)

    def test_the_drift_scaffold_names_itself_and_points_back(self) -> None:
        text = self._output("--for", "drift")
        self.assertIn("--for drift", text)
        self.assertIn("no checks, nothing declared", text)
        self.assertIn("veridor init --for run", text)

    def test_the_drift_next_steps_are_the_drift_workflow(self) -> None:
        text = self._output("--for", "drift")
        self.assertIn("--baseline", text)
        self.assertIn("--fail-on-drift", text)
        self.assertIn(SPECIMEN_PLACEHOLDER, text)
        # The limitation travels with the on-ramp, not three documents away.
        self.assertIn("blind to anything that did not change", text)
        # And it must not promise the baseline run is a test.
        self.assertIn("cannot fail", text)




class PlanBannerTest(unittest.TestCase):
    """`--dry-run` is the command the documentation tells you to run first.

    Against a 120-path specification it reported "operations: 60 (of 120 in the
    spec; 0 skipped as non-read-only)" -- and the other 60 went missing between
    two numbers with no explanation. They were the TEMPLATED routes, which is
    the shape this tool exists to measure, and they were skipped for want of a
    specimen. Half an API silently out of scope, in the one command whose whole
    job is to tell you what is about to happen.
    """

    def _plan(self, paths: dict):
        import json as _json  # noqa: PLC0415
        import tempfile as _tempfile  # noqa: PLC0415

        from veridor.core import load_config  # noqa: PLC0415

        directory = _tempfile.mkdtemp()
        spec_path = Path(directory) / "openapi.json"
        spec_path.write_text(_json.dumps({
            "openapi": "3.0.3", "info": {"title": "B", "version": "1"},
            "servers": [{"url": "http://127.0.0.1:8765"}], "paths": paths,
        }), encoding="utf-8")
        config_path = Path(directory) / "veridor.json"
        config_path.write_text(_json.dumps({
            "version": 1, "target": {"base_url": "http://127.0.0.1:8765"},
            "identities": {
                "owner": {"headers": {"Authorization": "Bearer a"}},
                "outsider": {"headers": {"Authorization": "Bearer b"}},
            },
        }), encoding="utf-8")
        inventory = parse_spec(load_spec(spec_path), source=str(spec_path))
        return plan_matrix(load_config(config_path, require_checks=False), inventory)

    def test_the_banner_counts_operations_dropped_for_want_of_a_specimen(self) -> None:
        get = {"get": {"responses": {"200": {"description": "ok"}}}}
        banner = self._plan({
            **{f"/api/r{i}": get for i in range(4)},
            **{f"/api/r{i}/{{id}}": get for i in range(4)},
        }).banner()
        self.assertIn("4 for want of a specimen", banner)

    def test_the_clause_is_absent_when_every_route_is_probed(self) -> None:
        """A count of zero is noise on the common small case."""
        get = {"get": {"responses": {"200": {"description": "ok"}}}}
        banner = self._plan({f"/api/r{i}": get for i in range(3)}).banner()
        self.assertNotIn("want of a specimen", banner)


if __name__ == "__main__":
    unittest.main()
