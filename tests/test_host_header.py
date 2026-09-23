"""A configured ``Host`` header is refused, wherever a header map is read.

urllib sends an explicit ``Host`` header instead of the one it derives from the
URL, and every containment check Veridor has -- the origin, the base path, the
dot-segment rule -- reads the URL. So ``"headers": {"Host": "admin.internal"}``
in a capsule kept a benign path on the target the verifier named and delivered
the request, with the verifier's credentials, to whichever virtual host that
name selects behind a gateway that routes by Host (nginx ``server_name``, an
Ingress host rule). Measured on the wire before this module existed: the
listener received ``Host: admin.internal`` from a check's request headers,
``admin2.internal`` from an identity's, ``admin3.internal`` from a marker
probe's, and the liveness sham reused the name with a fabricated value. A
gateway was measured turning a correctly-denying service-a into a
CONFIRMED from the admin vhost.

A Host override has no place in a declaration: the host is the target's, and
it is written in ``target.base_url`` or ``--base-url``.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from test_capsule import (  # noqa: E402
    LOOPBACK,
    VERIFIER_ENV,
    _listener,
    _RecordingOpener,
    _v010_capsule,
    _verify,
)
from test_refusal_lines import _rich_config  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

SPELLINGS = ("Host", "host", "HOST", "hOsT")


def _run(config: dict) -> dict:
    opener = _RecordingOpener()
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with patch.dict(os.environ, VERIFIER_ENV), patch.object(core, "_OPENER", opener):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = veridor_main(["run", "--config", str(path),
                                     "--output-dir", str(Path(directory) / "out")])
    return {"code": code, "stderr": stderr.getvalue(), "requests": opener.requests}


#: Every header map a capsule can carry, as a function that plants one.
CAPSULE_PLACES = {
    "check request": lambda d, h: d["check"]["request"].setdefault("headers", {}).update(h),
    "identity": lambda d, h: d["identities"]["other_tenant"]["headers"].update(h),
    "marker probe": lambda d, h: d["identities"]["other_tenant"]["marker_probe"].setdefault(
        "headers", {}).update(h),
}

#: And every one a configuration can carry beyond those.
CONFIG_PLACES = {
    "session login step": lambda c, h: c["identities"]["invoice_owner"]["session"]["login"][0][
        "headers"].update(h),
    "sequence step": lambda c, h: c["sequences"][0]["steps"][1]["request"].setdefault(
        "headers", {}).update(h),
    "teardown": lambda c, h: c["sequences"][0]["teardown"][0]["request"].setdefault(
        "headers", {}).update(h),
    "session inject": lambda c, h: c["identities"]["invoice_owner"]["session"]["inject"].append(
        {"header": next(iter(h)), "value": "admin.internal"}),
}


class HostHeaderLoadTest(unittest.TestCase):
    def test_every_spelling_is_refused(self) -> None:
        for name in SPELLINGS:
            with self.subTest(name=name):
                with self.assertRaises(core.ConfigError) as refused:
                    core._validate_headers({name: "admin.internal"}, "identity 'x' headers")
                message = str(refused.exception)
                self.assertIn("identity 'x' headers", message)
                self.assertIn("Host", message)
                self.assertIn("base_url", message)
                self.assertIn("Nothing has been sent", message)

    def test_control_names_that_only_contain_host_are_kept(self) -> None:
        core._validate_headers({"X-Host": "a", "Hostname": "b", "X-Forwarded-Host": "c",
                                "Accept": "application/json"}, "h")

    def test_a_capsule_with_a_host_header_sends_nothing(self) -> None:
        control = _verify(_v010_capsule(), "--base-url", LOOPBACK)
        self.assertTrue(control["requests"], control["stderr"])
        for place, plant in CAPSULE_PLACES.items():
            for name in SPELLINGS[:2]:
                with self.subTest(place=place, name=name):
                    document = _v010_capsule()
                    plant(document, {name: "admin.internal"})
                    result = _verify(document, "--base-url", LOOPBACK)
                    self.assertEqual(result["code"], 2, result["stderr"])
                    self.assertEqual(result["requests"], [])
                    self.assertIn("Host header", result["stderr"])

    def test_a_configuration_with_a_host_header_sends_nothing(self) -> None:
        control = _run(_rich_config())
        self.assertTrue(control["requests"], control["stderr"])
        places = {**CAPSULE_PLACES, **CONFIG_PLACES}
        for place, plant in places.items():
            with self.subTest(place=place):
                config = copy.deepcopy(_rich_config())
                if place in CAPSULE_PLACES:
                    config["check"] = config["checks"][0]
                    plant(config, {"Host": "admin.internal"})
                    del config["check"]
                else:
                    plant(config, {"Host": "admin.internal"})
                result = _run(config)
                self.assertEqual(result["code"], 2, result["stderr"])
                self.assertEqual(result["requests"], [])
                self.assertIn("Host header", result["stderr"])

    def test_the_send_time_layer_refuses_a_host_header_too(self) -> None:
        """Bypassing the loader, as an injected header produced at run time
        would: nothing reaches the opener."""
        for place in ("request", "identity"):
            with self.subTest(place=place):
                opener = _RecordingOpener()
                request = {"method": "GET", "path": "/api/x"}
                identity = {"headers": {"Authorization": "Bearer sk-must-not-leave"}}
                target = request if place == "request" else identity
                target.setdefault("headers", {})["host"] = "admin.internal"
                with patch.object(core, "_OPENER", opener):
                    with self.assertRaises(core.ConfigError):
                        core._perform_request(LOOPBACK, 1.0, request, identity)
                self.assertEqual(opener.requests, [])

    def test_control_the_send_time_layer_sends_an_ordinary_request(self) -> None:
        opener = _RecordingOpener()
        with patch.object(core, "_OPENER", opener):
            core._perform_request(LOOPBACK, 1.0, {"method": "GET", "path": "/api/x"},
                                  {"headers": {"X-Host": "a"}})
        self.assertEqual(len(opener.requests), 1)


@slow("runs veridor verify as a subprocess against a loopback listener")
class HostHeaderWireTest(unittest.TestCase):
    """On the wire: the Host a listener receives is the target's, or nothing
    is sent at all."""

    def _verify(self, document: dict, url: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "veridor.cli", "verify", str(path), "--base-url", url,
                 "--output-dir", str(Path(directory) / "out")],
                capture_output=True, text=True, cwd=directory, timeout=120,
                env=source_path.child_env(**VERIFIER_ENV),
            )
        return completed.returncode, completed.stdout + completed.stderr

    def test_control_the_listener_sees_the_target_s_own_host(self) -> None:
        with _listener() as (url, received):
            code, output = self._verify(_v010_capsule(url), url)
        self.assertTrue(received, output)
        netloc = url.split("//", 1)[1]
        self.assertEqual({entry["headers"].get("Host") for entry in received}, {netloc})

    def test_a_host_header_in_any_capsule_map_reaches_no_listener(self) -> None:
        for place, plant in CAPSULE_PLACES.items():
            with self.subTest(place=place), _listener() as (url, received):
                document = _v010_capsule(url)
                plant(document, {"Host": "admin.internal"})
                code, output = self._verify(document, url)
                self.assertEqual(received, [], output)
                self.assertEqual(code, 2, output)
                self.assertIn("Host header", output)


if __name__ == "__main__":
    unittest.main()
