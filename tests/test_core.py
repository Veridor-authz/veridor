from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402

from veridor.core import (
    ConfigError,
    _load_baseline,
    _safe_error,
    _safe_url,
    load_config,
    to_sarif,
)
from veridor.core import _interpretation  # noqa: E402


class ConfigTest(unittest.TestCase):
    def _write(self, value: dict, directory: str) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def _config(self) -> dict:
        return {
            "version": 1,
            "target": {"base_url": "https://example.test"},
            "identities": {
                "owner": {"headers": {"Authorization": "Bearer test-token"}},
                "other": {"headers": {}},
            },
            "checks": [
                {
                    "id": "resource",
                    "request": {"path": "/resource"},
                    "expect": {
                        "owner": {"status": 200},
                        "other": {"status": [403, 404]},
                    },
                }
            ],
        }

    def test_expands_identity_secrets(self) -> None:
        config = self._config()
        config["identities"]["owner"]["headers"]["Authorization"] = (
            "Bearer ${OWNER_TOKEN}"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(config, directory)
            with patch.dict(os.environ, {"OWNER_TOKEN": "secret"}, clear=False):
                loaded = load_config(path)
        self.assertEqual(
            loaded["identities"]["owner"]["headers"]["Authorization"],
            "Bearer secret",
        )
        self.assertEqual(loaded["checks"][0]["expect"]["owner"]["status"], [200])

    def test_rejects_single_identity(self) -> None:
        config = {
            "version": 1,
            "target": {"base_url": "https://example.test"},
            "identities": {"owner": {"headers": {}}},
            "checks": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "at least two users"):
                load_config(self._write(config, directory))

    def test_rejects_malformed_url_without_traceback(self) -> None:
        config = self._config()
        config["target"]["base_url"] = "http://[invalid"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "base_url is invalid"):
                load_config(self._write(config, directory))

    def test_rejects_header_injection(self) -> None:
        config = self._config()
        config["identities"]["owner"]["headers"]["X-Actor"] = "owner\r\nX-Evil: 1"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "invalid value"):
                load_config(self._write(config, directory))

    def test_rejects_credentials_in_target_url(self) -> None:
        config = self._config()
        config["target"]["base_url"] = "https://user:secret@example.test"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigError, "must not contain credentials"):
                load_config(self._write(config, directory))


class BaselineTest(unittest.TestCase):
    def test_rejects_finding_without_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps({"findings": [{}]}), encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "requires a non-empty id"):
                _load_baseline(path)


class VacuousExpectationSarifTest(unittest.TestCase):
    """A check that asserts nothing was perfect on the console and invisible in CI.

    The statement lived at `runs[0].properties.nonAssertingExpectations`, which
    GitHub code scanning does not surface -- so in the setup the README
    recommends, a permanently-passing check nobody could gate on was also a
    check nobody could see.
    """

    def _result(self, entries: list[dict]) -> dict:
        return {
            "run_id": "r1", "config": "veridor.json", "findings": [],
            "non_asserting_expectations": entries,
            "summary": {}, "probes": [],
        }

    def _entry(self, check_id: str = "iso", identity: str = "outsider") -> dict:
        return {
            "check_id": check_id, "identity": identity,
            "statuses": [200, 404], "classification": "permissive",
            "statement": f"expectation for {identity!r} accepts both",
        }

    def test_it_becomes_a_sarif_result(self) -> None:
        from veridor.core import to_sarif

        sarif = to_sarif(self._result([self._entry()]))
        results = sarif["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in results], ["VERIDOR-VACUOUS-001"])
        # `note`, never `warning`: this is a fact about the DECLARATION, and
        # code scanning renders warning as something wrong with the code.
        self.assertEqual(results[0]["level"], "note")
        rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("VERIDOR-VACUOUS-001", rules)

    def test_a_config_with_none_is_byte_identical(self) -> None:
        """The rule is appended only when referenced."""
        from veridor.core import to_sarif

        sarif = to_sarif(self._result([]))
        self.assertEqual(sarif["runs"][0]["results"], [])
        rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertNotIn("VERIDOR-VACUOUS-001", rules)

    def test_the_fingerprint_survives_a_narrowed_but_still_vacuous_status(self) -> None:
        """Still the same unasserted boundary, so still the same id.

        Keyed on the statuses it would report the expectation as resolved and
        then reopened every time somebody edited the list.
        """
        from veridor.core import _vacuous_fingerprint

        wide = self._entry(); wide["statuses"] = [200, 404]
        narrow = self._entry(); narrow["statuses"] = [200, 403, 404]
        self.assertEqual(_vacuous_fingerprint(wide), _vacuous_fingerprint(narrow))

    def test_a_different_expectation_gets_a_different_fingerprint(self) -> None:
        from veridor.core import _vacuous_fingerprint

        self.assertNotEqual(
            _vacuous_fingerprint(self._entry(identity="outsider")),
            _vacuous_fingerprint(self._entry(identity="admin")),
        )


class RunStatusTest(unittest.TestCase):
    """The artifact and the exit code must not contradict each other.

    `"passed" if not findings else "failed"` counted an `inconclusive` -- a
    probe the target never answered -- as a failure. So a run against an
    unreachable target exited 3, and its own document said `failed`, and the
    viewer rendered a red FAILED badge over a build CI had called green.

    These tests used to restate the rule in ``_status`` and test the copy, so
    an edit to the expression in ``execute_run`` passed all of them. They now
    call ``core.run_status``, which ``execute_run`` uses.
    """

    VERDICTS = ("vulnerable", "unexpected_denial", "inconclusive")

    def _status(self, verdicts: list[str]) -> str:
        from veridor import core

        return core.run_status([{"verdict": verdict} for verdict in verdicts])

    def _readme_rows(self) -> dict[str, str]:
        text = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
        table = text.split("| `status` | Means |", 1)[1].split("\n\n", 1)[0]
        return dict(re.findall(r"^\| `(\w+)` \| (.+) \|$", table, re.MULTILINE))

    def test_execute_run_takes_its_status_from_run_status(self) -> None:
        import inspect

        from veridor import core

        self.assertTrue('"status": run_status(findings)' in inspect.getsource(core.execute_run),
                        "execute_run computes status some other way than run_status")

    def test_the_readme_states_the_rule_run_status_applies(self) -> None:
        """The `inconclusive` row said "nothing was measured either". The rule
        reads findings only, and an answered probe that matched its declaration
        produces none: five matched probes and one timeout is `inconclusive`."""
        import itertools

        rows = self._readme_rows()
        produced = {
            self._status(list(combo))
            for size in range(len(self.VERDICTS) + 1)
            for combo in itertools.combinations(self.VERDICTS, size)
        }
        self.assertEqual(set(rows), produced)
        cited = {
            status: set(re.findall(r"`(vulnerable|unexpected_denial|inconclusive)`", text))
            for status, text in rows.items()
        }
        # Each row names exactly the verdicts the rule consults for it.
        self.assertEqual(cited["failed"], {"vulnerable", "unexpected_denial"})
        self.assertEqual(cited["inconclusive"], set(self.VERDICTS))
        self.assertEqual(cited["passed"], set(self.VERDICTS))
        self.assertEqual(self._status(["inconclusive"]), "inconclusive")
        self.assertNotIn("nothing was measured", rows["inconclusive"])
        self.assertNotIn("something was measured", rows["passed"])

    def test_nothing_found_and_something_measured_is_passed(self) -> None:
        self.assertEqual(self._status([]), "passed")

    def test_a_target_finding_is_failed(self) -> None:
        for verdict in ("vulnerable", "unexpected_denial"):
            with self.subTest(verdict=verdict):
                self.assertEqual(self._status([verdict]), "failed")

    def test_only_inconclusive_is_neither(self) -> None:
        self.assertEqual(self._status(["inconclusive", "inconclusive"]), "inconclusive")

    def test_a_target_finding_outranks_an_inconclusive(self) -> None:
        """A real finding is never softened by an unanswered probe beside it."""
        self.assertEqual(self._status(["inconclusive", "vulnerable"]), "failed")

    def test_the_viewer_renders_all_three(self) -> None:
        """A status the viewer cannot colour renders as a lie or as nothing."""
        app = Path(__file__).resolve().parents[1] / "src/veridor/web/app.js"
        source = app.read_text(encoding="utf-8")
        self.assertIn("STATUS_TONE", source)
        for status in ("passed", "failed", "inconclusive"):
            self.assertIn(status, source)


class SarifTest(unittest.TestCase):
    def test_empty_run_is_valid_sarif_shape(self) -> None:
        sarif = to_sarif({"run_id": "run-1", "findings": []})
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 4)


class SarifLocationTest(unittest.TestCase):
    """`--config /abs/path` reached artifactLocation.uri as a local path.

    Reproduced with the demo target: a relative --config wrote
    "veridor.demo.json", an absolute one wrote the runner's whole filesystem
    path, which code scanning cannot resolve against the repository and which
    publishes the checkout layout to anyone who can read the alert.
    """

    def _sarif(self, config: str) -> dict:
        finding = {
            "id": "0ec4c5cbd79deaed6e9f", "rule_id": "VERIDOR-AUTHZ-001",
            "check_id": "iso", "identity": "outsider", "verdict": "vulnerable",
            "level": "error", "message": "m", "location": config,
        }
        entry = {
            "check_id": "iso", "identity": "outsider", "statuses": [200, 404],
            "classification": "permissive", "statement": "accepts both",
        }
        return to_sarif({
            "run_id": "r1", "config": config, "findings": [finding],
            "non_asserting_expectations": [entry],
            "interpretation": _interpretation(config),
        })

    def _locations(self, sarif: dict) -> list[dict]:
        return [
            item["locations"][0]["physicalLocation"]["artifactLocation"]
            for item in sarif["runs"][0]["results"]
        ]

    def test_an_absolute_config_under_the_working_directory_is_written_relative(self) -> None:
        absolute = str(Path.cwd() / "ci" / "veridor.json")
        for location in self._locations(self._sarif(absolute)):
            self.assertEqual(location, {"uri": "ci/veridor.json", "uriBaseId": "%SRCROOT%"})

    def test_an_absolute_config_elsewhere_never_writes_a_local_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            absolute = str(Path(directory) / "nested" / "veridor.json")
            sarif = self._sarif(absolute)
        text = json.dumps(sarif)
        self.assertNotIn(directory, text)
        self.assertNotIn(str(Path(directory).resolve()), text)
        for location in self._locations(sarif):
            self.assertEqual(location["uri"], "veridor.json")
            self.assertFalse(Path(location["uri"]).is_absolute())
        self.assertEqual(
            sarif["runs"][0]["properties"]["interpretation"]["policy_source"],
            "veridor.json",
        )

    def test_every_spelling_of_one_file_points_at_one_uri(self) -> None:
        spellings = ["veridor.json", "./veridor.json", "sub/../veridor.json",
                     str(Path.cwd() / "veridor.json")]
        uris = {
            location["uri"]
            for spelling in spellings
            for location in self._locations(self._sarif(spelling))
        }
        self.assertEqual(uris, {"veridor.json"})

    def test_the_fingerprints_do_not_move_with_the_path(self) -> None:
        def prints(config: str) -> list[dict]:
            return [item["partialFingerprints"]
                    for item in self._sarif(config)["runs"][0]["results"]]

        self.assertEqual(prints("veridor.json"), prints(str(Path.cwd() / "veridor.json")))
        self.assertEqual(prints("veridor.json")[0], {"veridorFindingId/v1": "0ec4c5cbd79deaed6e9f"})


class EvidenceSafetyTest(unittest.TestCase):
    def test_query_values_and_fragments_are_not_persisted(self) -> None:
        safe = _safe_url("https://example.test/items?token=secret&id=42#private")
        self.assertEqual(
            safe,
            "https://example.test/items?token=%5BREDACTED%5D&id=%5BREDACTED%5D",
        )
        self.assertNotIn("secret", safe)
        self.assertNotIn("private", safe)

    def test_url_credentials_are_redacted(self) -> None:
        safe = _safe_url("https://user:secret@example.test/items")
        self.assertEqual(safe, "https://REDACTED@example.test/items")
        self.assertNotIn("user", safe)
        self.assertNotIn("secret", safe)

    def test_a_valueless_query_parameter_is_redacted_whole(self) -> None:
        """``?<token>`` is an opaque pre-signed link, not a named parameter.

        parse_qsl reports it as the KEY with an empty value, so redacting only
        values left the secret intact behind a cosmetic ``=[REDACTED]``.
        """
        cases = {
            "https://example.test/x?PRESIGNEDSECRET-hhhhhhhhhh": (
                "https://example.test/x?%5BREDACTED%5D"
            ),
            "https://example.test/x?a=1&SECRETBARE": (
                "https://example.test/x?a=%5BREDACTED%5D&%5BREDACTED%5D"
            ),
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                safe = _safe_url(url)
                self.assertEqual(safe, expected)
                self.assertNotIn("SECRET", safe)

    def test_named_query_parameters_keep_their_names(self) -> None:
        self.assertEqual(
            _safe_url("https://example.test/x?api_key=SECRET&plain=1"),
            "https://example.test/x?api_key=%5BREDACTED%5D&plain=%5BREDACTED%5D",
        )


class ErrorTextSafetyTest(unittest.TestCase):
    """``error`` is persisted and republished, so it obeys the body rule too."""

    def test_bad_status_line_never_carries_the_bytes_it_saw(self) -> None:
        payload = 'SESSIONCOOKIE-zzz {"ssn": "123-45-6789"} ' * 2000
        self.assertGreater(len(payload), 64 * 1024 - 1)
        message = _safe_error(http.client.BadStatusLine(payload))
        self.assertNotIn("SESSIONCOOKIE", message)
        self.assertNotIn("123-45-6789", message)
        self.assertLessEqual(len(message), 200)
        self.assertIn("status line", message)

    def test_unknown_http_exceptions_report_only_their_class(self) -> None:
        class WeirdError(http.client.HTTPException):
            pass

        message = _safe_error(WeirdError("LEAKED RESPONSE BODY"))
        self.assertNotIn("LEAKED", message)
        self.assertIn("WeirdError", message)

    def test_locally_generated_diagnostics_survive(self) -> None:
        self.assertIn(
            "Connection refused",
            _safe_error(URLError(ConnectionRefusedError(61, "Connection refused"))),
        )
        self.assertIn("bytes read", _safe_error(http.client.IncompleteRead(b"A" * 8, 9)))

    def test_every_error_is_bounded(self) -> None:
        message = _safe_error(URLError("x" * 10_000))
        self.assertLessEqual(len(message), 203)


# ---------------------------------------------------------------------------
# Timeouts say which phase timed out, and only what that phase measured.
#
# REGRESSION. Every timeout was one string, "timed out", and its advice said
# "the probe reached it, so this is not a reachability problem". Measured on a
# kind cluster (the psa scenario of scripts/e2e_kubernetes.sh): a NetworkPolicy
# that dropped every packet produced exactly that sentence for all 6 probes. A
# connect timeout -- no TCP connection at all -- was worded as a slow target.
# Measured locally (python3.12, macOS): urllib raises URLError(TimeoutError)
# with socket.create_connection on the stack for a non-routable address, a raw
# TimeoutError from getresponse() when a server accepts and never answers, and
# a raw TimeoutError from read() when the body stalls after the headers.
# ---------------------------------------------------------------------------

def _raised_in(function_name: str) -> TimeoutError:
    """A TimeoutError whose traceback holds a frame named ``function_name``."""
    def raiser() -> None:
        raise TimeoutError("timed out")

    namespace: dict = {"raiser": raiser}
    exec(f"def {function_name}():\n    raiser()\n", namespace)  # noqa: S102 - a test-local frame
    try:
        namespace[function_name]()
    except TimeoutError as error:
        return error
    raise AssertionError("unreachable")


class TimeoutPhaseTest(unittest.TestCase):
    """Pure: the phase is read from the exception, not guessed from its text."""

    def _error(self, exc: BaseException, *, response_started: bool = False) -> str:
        from veridor.core import _transport_error  # noqa: PLC0415

        return _transport_error(exc, 1.5, response_started=response_started)

    def test_a_timeout_inside_create_connection_is_a_connect_timeout(self) -> None:
        text = self._error(URLError(_raised_in("create_connection")))
        self.assertTrue(text.startswith("connect timed out"), text)
        self.assertIn("no TCP connection", text)
        self.assertIn("1.5s", text)

    def test_a_timeout_inside_the_tls_handshake_is_named(self) -> None:
        text = self._error(URLError(_raised_in("do_handshake")))
        self.assertTrue(text.startswith("TLS handshake timed out"), text)

    def test_a_raw_timeout_from_the_opener_is_a_response_timeout(self) -> None:
        text = self._error(TimeoutError("timed out"))
        self.assertTrue(text.startswith("timed out waiting for a response"), text)

    def test_a_timeout_after_the_headers_is_a_body_timeout(self) -> None:
        for exc in (TimeoutError("timed out"), URLError(TimeoutError("timed out"))):
            with self.subTest(exc=type(exc).__name__):
                text = self._error(exc, response_started=True)
                self.assertTrue(text.startswith("timed out reading the response body"), text)

    def test_an_unplaceable_timeout_claims_no_connection(self) -> None:
        """A wrapped timeout with no recognisable frame could be the connect or
        the send. The text must not pick one."""
        text = self._error(URLError(TimeoutError("timed out")))
        self.assertTrue(text.startswith("timed out before a response"), text)
        self.assertIn("not recorded", text)
        self.assertNotIn("a TCP connection was established", text)
        self.assertNotIn("no TCP connection", text)

    def test_a_non_timeout_keeps_the_safe_error_text(self) -> None:
        refused = URLError(ConnectionRefusedError(61, "Connection refused"))
        self.assertEqual(self._error(refused), _safe_error(refused))


class TimeoutAdviceTest(unittest.TestCase):
    """The remediation says only what the phase measured."""

    UNMEASURED_REACH = ("reached it", "not a reachability problem", "the probe reached")

    def _advice(self, error: str) -> str:
        from veridor.core import _transport_remediation  # noqa: PLC0415

        return _transport_remediation(error, {"timeout_seconds": 2})

    def _phase_text(self, exc: BaseException, *, response_started: bool = False) -> str:
        from veridor.core import _transport_error  # noqa: PLC0415

        return _transport_error(exc, 2.0, response_started=response_started)

    def test_a_connect_timeout_points_at_the_network_not_the_timeout(self) -> None:
        advice = self._advice(self._phase_text(URLError(_raised_in("create_connection"))))
        self.assertIn("No TCP connection", advice)
        self.assertIn("NetworkPolicy", advice)
        self.assertIn("2s", advice)
        for claim in self.UNMEASURED_REACH + ("raise that value",):
            self.assertNotIn(claim, advice)

    def test_a_response_timeout_names_the_setting_and_what_was_measured(self) -> None:
        advice = self._advice(self._phase_text(TimeoutError("timed out")))
        self.assertIn("target.timeout_seconds (2s)", advice)
        self.assertIn("raise that value", advice)
        self.assertIn("connection was established", advice)
        for claim in self.UNMEASURED_REACH:
            self.assertNotIn(claim, advice)

    def test_a_body_timeout_says_the_response_started(self) -> None:
        advice = self._advice(self._phase_text(TimeoutError("timed out"), response_started=True))
        self.assertIn("headers arrived", advice)
        self.assertIn("target.timeout_seconds (2s)", advice)

    def test_a_bare_timed_out_claims_neither_reach_nor_slowness(self) -> None:
        """An error string from an older run document, or any other caller,
        says nothing about the phase. The advice must say so."""
        for error in ("timed out", "_ssl.c:993: The handshake operation timed out"):
            with self.subTest(error=error):
                advice = self._advice(error)
                self.assertIn("does not say whether a connection was established", advice)
                for claim in self.UNMEASURED_REACH:
                    self.assertNotIn(claim, advice)

    def test_no_message_in_core_claims_the_target_was_reached(self) -> None:
        """The grep the fix was checked with, kept. Every string literal in
        core.py that speaks of reaching something, docstrings excepted, is
        listed here after being read; a new one fails until it is reviewed."""
        import ast  # noqa: PLC0415

        source = (ROOT / "src" / "veridor" / "core.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
        }
        found = sorted(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and re.search(r"(?i)\breach", node.value)
        )
        # Reviewed 2026-09-24. None claims the target was reached: three advise
        # a check, one is about captures, two say no conclusion was reached,
        # and two (a 407, in a finding and in an unanswered probe) say the
        # request most likely never reached it.
        reviewed = (
            "Confirm the target is reachable from the runner and retry.",
            "Confirm target reachability and retry the check.",
            "check that this runner can reach target.base_url",
            "they reach a request through 'session.inject'",
            "no conclusion about authorization was reached",
            "so it reaches no conclusion rather than a pass",
            "most likely never reached the target, so this probe measured nothing",
            "so the request most likely never reached the target.",
        )
        unreviewed = [text for text in found if not any(ok in text for ok in reviewed)]
        self.assertEqual(unreviewed, [],
                         "a new message speaks of reaching something; read it, then list it")
        # The control: the scan sees string literals at all.
        self.assertTrue(any("reachable from the runner" in text for text in found))


@contextlib.contextmanager
def _silent_server(behaviour: str):
    """A loopback listener. ``accept``: accepts and never answers. ``stall``:
    answers ``status`` + headers, then stalls the body. ``backlog``: never
    accepts, and its queue is filled until a plain connect times out."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    held: list[socket.socket] = []
    stop = threading.Event()
    if behaviour == "backlog":
        server.listen(0)
    else:
        server.listen(16)
        server.settimeout(0.1)

        def serve() -> None:
            while not stop.is_set():
                try:
                    connection, _ = server.accept()
                except OSError:
                    continue
                held.append(connection)
                if behaviour.startswith("stall"):
                    connection.recv(65536)
                    status = behaviour.split(":", 1)[1]
                    connection.sendall(
                        f"HTTP/1.1 {status}\r\nContent-Length: 100\r\n\r\npartial".encode()
                    )

        threading.Thread(target=serve, daemon=True).start()
    try:
        yield server.getsockname()[1], held
    finally:
        stop.set()
        for connection in held:
            connection.close()
        server.close()


def _fill_backlog(port: int, held: list) -> bool:
    """Fill the accept queue until a plain connect times out. The control:
    True only when the kernel was MEASURED dropping a connection attempt."""
    for _ in range(2048):
        probe = socket.socket()
        probe.settimeout(0.3)
        try:
            probe.connect(("127.0.0.1", port))
        except TimeoutError:
            probe.close()
            return True
        except OSError:
            probe.close()
            return False
        held.append(probe)
    return False


@slow("opens loopback sockets that time out")
class TimeoutLiveTest(unittest.TestCase):
    """Each phase produced for real, then classified by the code under test."""

    def _probe(self, port: int, scheme: str = "http") -> dict:
        from veridor.core import _perform_request  # noqa: PLC0415

        return _perform_request(
            f"{scheme}://127.0.0.1:{port}", 0.5, {"method": "GET", "path": "/x"}, {"headers": {}}
        )

    def test_a_dropped_connection_attempt_is_a_connect_timeout(self) -> None:
        with _silent_server("backlog") as (port, held):
            if not _fill_backlog(port, held):
                self.skipTest("could not make this kernel drop a connection attempt")
            result = self._probe(port)
        self.assertIsNone(result["response"]["status"])
        self.assertTrue(result["error"].startswith("connect timed out"), result["error"])

    def test_a_server_that_never_answers_is_a_response_timeout(self) -> None:
        with _silent_server("accept") as (port, _):
            result = self._probe(port)
        self.assertTrue(result["error"].startswith("timed out waiting for a response"),
                        result["error"])

    def test_a_tls_handshake_that_never_finishes_is_named(self) -> None:
        with _silent_server("accept") as (port, _):
            result = self._probe(port, "https")
        self.assertTrue(result["error"].startswith("TLS handshake timed out"), result["error"])

    def test_a_stalled_body_is_a_body_timeout_on_any_status(self) -> None:
        """A 4xx whose body stalled used to escape the request function as a
        raw TimeoutError: the run exited 2 with "veridor: timed out" and wrote
        no run document (measured). It is an unmeasured probe like any other."""
        for status in ("200 OK", "403 Forbidden"):
            with self.subTest(status=status), _silent_server(f"stall:{status}") as (port, _):
                result = self._probe(port)
                self.assertIsNone(result["response"]["status"])
                self.assertTrue(result["error"].startswith("timed out reading the response body"),
                                result["error"])

    def test_the_run_output_names_the_phase(self) -> None:
        """What an operator reads: the finding and its advice, end to end."""
        from veridor.cli import main  # noqa: PLC0415

        with _silent_server("backlog") as (port, held):
            if not _fill_backlog(port, held):
                self.skipTest("could not make this kernel drop a connection attempt")
            with tempfile.TemporaryDirectory() as directory:
                config = {
                    "version": 1,
                    "target": {"base_url": f"http://127.0.0.1:{port}", "timeout_seconds": 0.5},
                    "identities": {"owner": {"headers": {"Authorization": "Bearer t"}},
                                   "other": {"headers": {}}},
                    "checks": [{"id": "c", "request": {"path": "/x"},
                                "expect": {"owner": {"status": [200]}, "other": {"status": [403]}}}],
                }
                path = Path(directory) / "veridor.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = main(["run", "--config", str(path), "--output-dir",
                                 str(Path(directory) / "out"), "--no-prove-liveness"])
        text = out.getvalue()
        self.assertEqual(code, 3, text + err.getvalue())
        self.assertIn("Request failed: connect timed out", text)
        self.assertIn("No TCP connection to target.base_url", text)
        self.assertNotIn("reached it", text)



class SafeCountWithoutProbesTest(unittest.TestCase):
    """`summary.safe` counts sent probes that matched, and cannot go negative.

    It was ``len(probes) - len(check findings)``. An identity whose session
    never established gets a VERIDOR-EXEC-001 finding and NO probe, so that
    finding was subtracted from a probe count it was never part of. With every
    login answered 503 the run printed "-2/0 probes matched their
    declaration", and with one of two sessions down a matched probe printed
    as "0/1".
    """

    def _run(self, logins_up: set[str], attacker_status: int = 403) -> dict:
        import email.message  # noqa: PLC0415
        import urllib.response  # noqa: PLC0415

        from veridor import core  # noqa: PLC0415

        class Target:
            def open(self, request, timeout=None):  # noqa: A003, ANN001, ANN202
                path = request.full_url.split("127.0.0.1:9", 1)[1]
                headers = email.message.Message()
                headers["Content-Length"] = "0"
                status = 503
                if path == "/login":
                    user = (request.data or b"").decode().partition("=")[2]
                    if user in logins_up:
                        status = 200
                        headers["Set-Cookie"] = f"sid={user}; Path=/"
                elif path == "/docs/1":
                    cookie = request.get_header("Cookie") or ""
                    status = {"sid=owner": 200, "sid=attacker": attacker_status}.get(
                        cookie, 401
                    )
                return urllib.response.addinfourl(io.BytesIO(b""), headers,
                                                  request.full_url, status)

        def session(user: str) -> dict:
            return {"login": [{"method": "POST", "path": "/login", "body": f"u={user}",
                               "expect_status": [200]}],
                    "establishes": {"cookie": "sid"}}

        config = {
            "version": 2,
            "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 5},
            "identities": {"owner": {"session": session("owner")},
                           "attacker": {"session": session("attacker")}},
            "checks": [{"id": "doc", "request": {"method": "GET", "path": "/docs/1"},
                        "expect": {"owner": {"status": [200]},
                                   "attacker": {"status": [403]}}}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "veridor.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with patch.object(core, "_OPENER", Target()), \
                    contextlib.redirect_stderr(io.StringIO()):
                return core.execute_run(path, output_dir=root / "history")

    def _console(self, result: dict) -> str:
        from veridor import cli  # noqa: PLC0415

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_summary(result)  # noqa: SLF001
        return out.getvalue()

    def test_every_session_down_counts_zero_of_zero(self) -> None:
        result = self._run(set())
        summary = result["summary"]
        self.assertEqual((summary["probes"], summary["inconclusive"]), (0, 2))
        self.assertEqual(summary["safe"], 0)
        self.assertIn(": 0/0 probes matched their declaration", self._console(result))

    def test_one_session_down_counts_the_other_identity_s_match(self) -> None:
        result = self._run({"owner"})
        summary = result["summary"]
        self.assertEqual((summary["probes"], summary["inconclusive"]), (1, 1))
        self.assertEqual(summary["safe"], 1)

    def test_control_a_mismatched_probe_is_still_subtracted(self) -> None:
        """Both sessions up, the attacker served the document it should not
        read: one finding about a sent probe, so one of two matched."""
        result = self._run({"owner", "attacker"}, attacker_status=200)
        summary = result["summary"]
        self.assertEqual((summary["probes"], summary["vulnerable"]), (2, 1))
        self.assertEqual(summary["safe"], 1)


if __name__ == "__main__":
    unittest.main()
