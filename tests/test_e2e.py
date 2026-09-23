from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from scripts.e2e_validation import validate, validate_verbs  # noqa: E402


@slow("stands up a loopback HTTP server and runs the engine against it")
class EndToEndTest(unittest.TestCase):
    def test_complete_local_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            validate(Path(directory))


@slow("stands up a loopback HTTP server and runs the engine against it")
class RepeatabilityTest(unittest.TestCase):
    """The documented command has to survive being run twice in a checkout.

    REGRESSION. ``validate_verbs`` asserts "this invocation wrote nothing" as
    ``not path.exists()`` against a directory the PREVIOUS invocation's real
    ``map`` had filled, so the second run of the README's own
    ``python3 scripts/e2e_validation.py`` failed with
    ``map --dry-run wrote an artifact`` -- a documented safety property
    announced as violated when nothing had violated it. CI stayed green
    throughout: it runs the script once, in a fresh checkout, so the
    default directory always started empty there (CiClaimTest below).
    """

    def test_the_verbs_validation_is_repeatable_in_one_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "verbs"
            for attempt in range(2):
                with self.subTest(attempt=attempt):
                    with contextlib.redirect_stdout(io.StringIO()):
                        validate_verbs(target)


@slow("stands up a loopback HTTP server and runs the engine against it")
class VerbsGateStrengthTest(unittest.TestCase):
    """Each check in ``validate_verbs`` must fail on the regression it names.

    Two passed on exactly that regression: "a promotion stub was presented as
    complete" was ``all(...)`` over the stubs, true of an empty list, and the
    mutate check accepted exit 2 -- "aberrant or errored, the engine does not
    know" -- against a deterministic demo where mutate exits 1 every time.
    Each test below breaks the product one way and requires the gate to say so.
    """

    def _validate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                validate_verbs(Path(directory) / "verbs")

    def test_a_promote_writer_that_drops_its_stubs_fails_the_gate(self) -> None:
        from veridor import cli  # noqa: PLC0415

        original = cli.write_json

        def drop_stubs(path, document, *args, **kwargs):
            if isinstance(document, dict) and "_comment" in document and "checks" in document:
                document = {**document, "checks": []}
            return original(path, document, *args, **kwargs)

        cli.write_json = drop_stubs
        try:
            with self.assertRaisesRegex(RuntimeError, "promotion stub"):
                self._validate()
        finally:
            cli.write_json = original

    def test_an_errored_mutant_fails_the_gate(self) -> None:
        from veridor import mutation  # noqa: PLC0415

        original = mutation._record
        flipped: list[bool] = []

        def errored_once(*args, **kwargs):
            if kwargs.get("outcome") == mutation.KILLED and not flipped:
                flipped.append(True)
                kwargs["outcome"] = mutation.ERRORED
                kwargs["diagnosis"] = "injected by the test"
            return original(*args, **kwargs)

        mutation._record = errored_once
        try:
            with self.assertRaisesRegex(RuntimeError, "mutate"):
                self._validate()
        finally:
            mutation._record = original
        self.assertEqual(flipped, [True], "the injection never reached a mutant")


class CiClaimTest(unittest.TestCase):
    """The stated reason CI missed the stale-artifact bug has to be true.

    Both docstrings once said CI stayed green because a local wrapper script
    removed the evidence directory. No workflow called that script: CI runs
    ``python scripts/e2e_validation.py`` once, in a fresh checkout, into a
    default directory that starts empty.
    """

    WORKFLOWS = "\n".join(path.read_text(encoding="utf-8") for path in
                          sorted((ROOT / ".github" / "workflows").glob("*.yml")))

    def _scripts_no_workflow_names(self, doc: str) -> list[str]:
        return [script for script in re.findall(r"scripts/[\w.-]+\w", doc)
                if script not in self.WORKFLOWS]

    def test_the_facts_the_docstrings_rest_on(self) -> None:
        self.assertIn("run: python scripts/e2e_validation.py\n", self.WORKFLOWS)

    def test_no_docstring_credits_ci_to_a_script_ci_does_not_run(self) -> None:
        from scripts.e2e_validation import _fresh  # noqa: PLC0415

        for name, doc in (("_fresh", _fresh.__doc__),
                          ("RepeatabilityTest", RepeatabilityTest.__doc__)):
            with self.subTest(docstring=name):
                self.assertEqual(self._scripts_no_workflow_names(doc), [])
                self.assertIn("fresh checkout", doc)

    def test_control_a_script_no_workflow_names_is_reported(self) -> None:
        """The check above finds nothing on a clean tree; show it can find something."""
        self.assertEqual(
            self._scripts_no_workflow_names("CI stayed green because scripts/local-wrapper.sh cleans up."),
            ["scripts/local-wrapper.sh"],
        )


if __name__ == "__main__":
    unittest.main()
