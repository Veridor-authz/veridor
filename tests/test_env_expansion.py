"""An environment variable that is set but empty is a missing credential.

GitHub Actions hands a pull request from a fork an EMPTY string for every
secret, not an unset variable, and a CI variable that was never filled in looks
the same. ``_expand_environment`` tested ``name not in os.environ`` only, so
``Authorization: Bearer ${TOKEN}`` loaded as ``Bearer `` and the run went ahead
as that identity. Reproduced against the demo target: an empty owner token
produced ``unexpected_denial`` on the owner's own invoice and exit 1 -- a
configuration problem reported as a finding about the target. An empty
attacker token is worse: a denial the blank credential draws matches a
declared denial and passes.
"""

from __future__ import annotations

import contextlib
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

from veridor import core  # noqa: E402
from veridor.cli import main  # noqa: E402
from veridor.core import ABSENT_CREDENTIAL, ConfigError, load_config  # noqa: E402

OWNER_MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"
OTHER_MARKER = "vdr-Bq3Wm8Ke5Tz1Yx7Rn2Hd4Vs6"


def _config(owner_auth: str = "Bearer ${VDR_T_OWNER}") -> dict:
    return {
        "version": 1,
        "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 1},
        "identities": {
            "owner": {"headers": {"Authorization": owner_auth}, "marker": OWNER_MARKER},
            "other": {"headers": {"Authorization": "Bearer ${VDR_T_OTHER}"}},
        },
        "checks": [
            {
                "id": "invoice-isolation",
                "request": {"method": "GET", "path": "/invoices/1"},
                "expect": {
                    "owner": {"status": [200], "contains_marker": "owner"},
                    "other": {"status": [404], "excludes_marker": "owner"},
                },
            }
        ],
    }


def _sequence_config() -> dict:
    config = _config()
    config["version"] = 2
    config["checks"] = []
    config["sequences"] = [
        {
            "id": "seq",
            "steps": [
                {
                    "role": "setup",
                    "as": "owner",
                    "request": {
                        "method": "POST",
                        "path": "/docs",
                        "headers": {"X-Tenant": "${VDR_T_TENANT}"},
                        "json": {"note": "${marker:owner}"},
                    },
                    "expect": {"status": [201]},
                    "capture": {"doc_id": "$.id"},
                },
                {
                    "role": "assert",
                    "as": "other",
                    "request": {"method": "GET", "path": "/docs/${doc_id}"},
                    "expect": {"status": [404]},
                },
            ],
        }
    ]
    return config


@contextlib.contextmanager
def _written(config: dict):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        yield path, Path(directory)


_ENV = {"VDR_T_OWNER": "owner-token", "VDR_T_OTHER": "other-token", "VDR_T_TENANT": "acme"}


class EmptyVariableRefusalTest(unittest.TestCase):
    def _load(self, config: dict, **env: str) -> dict:
        with patch.dict(os.environ, {**_ENV, **env}), _written(config) as (path, _):
            return load_config(path)

    def test_a_set_but_empty_credential_is_refused_by_name(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self._load(_config(), VDR_T_OWNER="")
        message = str(caught.exception)
        self.assertIn("'VDR_T_OWNER'", message)
        self.assertIn("set but empty", message)
        # The refusal says why an empty value is not harmless.
        self.assertIn("fork pull request", message)
        self.assertIn("finding about the target", message)

    def test_a_whitespace_only_value_is_empty_too(self) -> None:
        for value in (" ", "\t", "  \n"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ConfigError) as caught:
                    self._load(_config(), VDR_T_OTHER=value)
                self.assertIn("'VDR_T_OTHER'", str(caught.exception))

    def test_an_empty_variable_inside_sequences_is_refused(self) -> None:
        """The sequences subtree is expanded by a second call; it must not be
        the one place an empty value slips through."""
        with self.assertRaises(ConfigError) as caught:
            self._load(_sequence_config(), VDR_T_TENANT="")
        self.assertIn("'VDR_T_TENANT'", str(caught.exception))

    def test_an_empty_variable_outside_a_header_is_refused(self) -> None:
        config = _config()
        config["checks"][0]["request"]["path"] = "/tenants/${VDR_T_TENANT}/invoices/1"
        with self.assertRaises(ConfigError) as caught:
            self._load(config, VDR_T_TENANT="")
        self.assertIn("'VDR_T_TENANT'", str(caught.exception))

    def test_an_unset_variable_keeps_its_message(self) -> None:
        """Control: the unset path is unchanged."""
        environment = {key: value for key, value in os.environ.items() if key != "VDR_T_OWNER"}
        environment.update({"VDR_T_OTHER": "other-token"})
        with patch.dict(os.environ, environment, clear=True), _written(_config()) as (path, _):
            with self.assertRaises(ConfigError) as caught:
                load_config(path)
        self.assertEqual(str(caught.exception), "environment variable 'VDR_T_OWNER' is not set")

    def test_a_non_empty_value_still_loads(self) -> None:
        """Control: the refusal fires on emptiness, not on expansion."""
        loaded = self._load(_config())
        self.assertEqual(
            loaded["identities"]["owner"]["headers"]["Authorization"], "Bearer owner-token"
        )

    def test_a_command_that_sends_nothing_treats_empty_as_absent(self) -> None:
        """`coverage` loads with allow_missing_env because it issues no request;
        refusing an empty secret there would block a coverage badge on a fork
        PR for no reason. It gets the same named placeholder an unset one gets."""
        with patch.dict(os.environ, {**_ENV, "VDR_T_OWNER": ""}), _written(_config()) as (path, _):
            loaded = load_config(path, allow_missing_env=True)
        self.assertEqual(
            loaded["identities"]["owner"]["headers"]["Authorization"],
            "Bearer " + ABSENT_CREDENTIAL.format(name="VDR_T_OWNER"),
        )


class _Sent(Exception):
    pass


class RunRefusesBeforeSendingTest(unittest.TestCase):
    """The reproduction, end to end through the CLI: exit 2, nothing sent."""

    def test_run_with_an_empty_owner_token_exits_2_and_sends_nothing(self) -> None:
        sent: list[str] = []

        def recorder(base_url, timeout, request_config, identity, **kwargs):
            sent.append(request_config.get("path"))
            raise _Sent("a request reached the wire")

        stderr = io.StringIO()
        with patch.dict(os.environ, {**_ENV, "VDR_T_OWNER": ""}), _written(_config()) as (path, root):
            with patch.object(core, "_perform_request", recorder):
                with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    code = main(["run", "--config", str(path), "--output-dir", str(root / "out")])
        self.assertEqual(sent, [])
        self.assertEqual(code, 2, stderr.getvalue())
        self.assertIn("'VDR_T_OWNER'", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
