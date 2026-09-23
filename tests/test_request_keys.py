"""A near-miss key in a request block is refused, not dropped.

Every request block -- a check's ``request``, a sequence step's and a teardown
entry's ``request``, an identity's ``marker_probe`` and a session login step --
is read for ``method``, ``path``, ``headers``, ``json`` and ``body`` and
nothing else. A check request's other keys were never looked at, so
``"Headers": {"Authorization": ...}``, ``"header"``, ``"Method"`` or
``"Body"`` loaded, and the request went out without them. Measured before this
change with ``veridor run`` against a listener: ``"headers": {"X-Tenant":
"acme"}`` put ``acme`` on the wire, and the same map under ``Headers`` or
``header`` put nothing there, exit 0. Written as an Authorization header, that
is an identity probed without the credential its author gave it. Sequence step
and teardown requests had the same gap; ``marker_probe`` and login steps
already refused near-misses.

The rule is the one ``marker_probe`` already applied (``core._suspicious_keys``):
a key that normalises onto, or is a close misspelling of, a real key is refused
with exit 2, naming the key and the real key it is nearest to.

A key that was neither still loaded and was dropped: ``params``, ``query``, a
bare ``Authorization`` and ``description`` all loaded, and the request went out
without what they held (measured with ``veridor run`` and a recording opener:
nine requests, none carrying the value), while the published schema refused
every one of them. The loader now refuses any request key the schema refuses.
The schema allows an annotation only as a key starting with ``_``, and so does
the loader.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from veridor.cli import main as veridor_main  # noqa: E402
from veridor.core import ConfigError, load_config  # noqa: E402

MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"


def _config() -> dict[str, Any]:
    """A version-2 configuration with every kind of request block in it."""
    return {
        "version": 2,
        "target": {"base_url": "http://127.0.0.1:9", "timeout_seconds": 3},
        "identities": {
            "owner": {
                "headers": {"Authorization": "Bearer owner-token"},
                "marker": MARKER,
                "marker_probe": {"method": "GET", "path": "/docs/mine"},
            },
            "member": {
                "session": {
                    "login": [{"method": "POST", "path": "/login", "body": "u=m",
                               "expect_status": [302]}],
                    "establishes": {"cookie": "sid"},
                },
            },
            "anonymous": {"headers": {}},
        },
        "checks": [{
            "id": "doc-isolation",
            "request": {"method": "GET", "path": "/docs/1",
                        "headers": {"X-Tenant": "acme"}},
            "expect": {
                "owner": {"status": [200], "contains_marker": "owner"},
                "anonymous": {"status": [401], "excludes_marker": "owner"},
            },
        }],
        "sequences": [{
            "id": "doc-delete",
            "steps": [
                {"role": "setup", "as": "owner",
                 "request": {"method": "POST", "path": "/docs", "json": {"n": 1}},
                 "expect": {"status": [201]}, "capture": {"doc_id": "$.id"}},
                {"role": "assert", "as": "anonymous",
                 "request": {"method": "DELETE", "path": "/docs/${doc_id}"},
                 "expect": {"status": [401, 404]}},
            ],
            "teardown": [{"as": "owner",
                          "request": {"method": "DELETE", "path": "/docs/${doc_id}"},
                          "expect": {"status": [204, 404]}}],
        }],
    }


def _block(pointer: str) -> Callable[[dict], dict]:
    def find(document: dict) -> dict:
        node: Any = document
        for part in pointer.split("/"):
            node = node[int(part)] if isinstance(node, list) else node[part]
        return node
    return find


#: (label as the refusal names it, where the block is).
BLOCKS = (
    ("check 'doc-isolation' request", _block("checks/0/request")),
    ("sequence 'doc-delete' step 1 request", _block("sequences/0/steps/1/request")),
    ("sequence 'doc-delete' teardown entry 0 request", _block("sequences/0/teardown/0/request")),
    ("identity 'owner' marker_probe", _block("identities/owner/marker_probe")),
    ("identity 'member' session login step 0", _block("identities/member/session/login/0")),
)

#: (the key as written, the real key the refusal must name).
NEAR_MISSES = (
    ("Headers", "headers"),
    ("header", "headers"),
    ("HEADERS", "headers"),
    ("Method", "method"),
    ("Body", "body"),
    ("Json", "json"),
    ("paths", "path"),
)


class _LoadCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="veridor-request-keys-"))
        self.addCleanup(shutil.rmtree, self.directory, True)

    def write(self, document: dict) -> Path:
        path = self.directory / f"config-{len(list(self.directory.iterdir()))}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def load(self, document: dict) -> dict:
        return load_config(self.write(document))


class NearMissRequestKeyTest(_LoadCase):
    def test_the_base_configuration_loads(self) -> None:
        """Control: every case below is one key away from this."""
        loaded = self.load(_config())
        self.assertEqual(loaded["checks"][0]["request"]["headers"], {"X-Tenant": "acme"})

    def test_a_near_miss_key_is_refused_in_every_request_block(self) -> None:
        for label, find in BLOCKS:
            for written, meant in NEAR_MISSES:
                with self.subTest(block=label, key=written):
                    document = _config()
                    block = find(document)
                    # A value the real key would accept, so the refusal can
                    # only be about the key's name.
                    block[written] = copy.deepcopy(
                        {"headers": {"Authorization": "Bearer t"}, "method": "GET",
                         "body": "x=1", "json": {"a": 1}, "path": "/docs/2"}[meant]
                    )
                    with self.assertRaises(ConfigError) as caught:
                        self.load(document)
                    message = str(caught.exception)
                    self.assertIn(f"{label} has unsupported keys: {written}", message)
                    self.assertIn(f"did you mean '{meant}'", message)

    def test_the_run_command_exits_2_naming_the_key(self) -> None:
        document = _config()
        request = document["checks"][0]["request"]
        request["Headers"] = request.pop("headers")
        path = self.write(document)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = veridor_main(["run", "--config", str(path),
                                 "--output-dir", str(self.directory / "out")])
        self.assertEqual(code, 2, err.getvalue())
        self.assertIn("check 'doc-isolation' request has unsupported keys: Headers",
                      err.getvalue())
        self.assertIn("did you mean 'headers'", err.getvalue())
        self.assertFalse((self.directory / "out").exists(), "nothing is written on a refusal")

    def test_two_near_misses_are_both_named(self) -> None:
        document = _config()
        document["checks"][0]["request"].update({"Headers": {}, "Methd": "GET"})
        with self.assertRaises(ConfigError) as caught:
            self.load(document)
        message = str(caught.exception)
        self.assertIn("unsupported keys: Headers, Methd", message)
        self.assertIn("'headers' for 'Headers'", message)
        self.assertIn("'method' for 'Methd'", message)


#: Keys that are no misspelling of a real one, with what the refusal must say.
#: Each loaded before and was dropped without a word; the schema refuses each.
UNKNOWN_KEYS = (
    ("params", {"tenant": "acme"}, "query string"),
    ("query", "tenant=acme", "query string"),
    ("Authorization", "Bearer t", "under 'headers'"),
    ("description", "why this request exists", "'_description'"),
    ("owner_note", "why", "'_owner_note'"),
)


class UnknownRequestKeyTest(_LoadCase):
    """A key the loader does not read is refused, not dropped."""

    def test_every_unknown_key_is_refused_in_every_request_block(self) -> None:
        for label, find in BLOCKS:
            for key, value, advice in UNKNOWN_KEYS:
                with self.subTest(block=label, key=key):
                    document = _config()
                    find(document)[key] = copy.deepcopy(value)
                    with self.assertRaises(ConfigError) as caught:
                        self.load(document)
                    message = str(caught.exception)
                    self.assertIn(f"{label} has unsupported keys: {key}", message)
                    self.assertIn(advice, message)

    def test_a_near_miss_beside_an_unknown_key_keeps_its_hint(self) -> None:
        document = _config()
        document["checks"][0]["request"].update({"Headers": {}, "params": {"a": 1}})
        with self.assertRaises(ConfigError) as caught:
            self.load(document)
        message = str(caught.exception)
        self.assertIn("unsupported keys: Headers, params", message)
        self.assertIn("did you mean 'headers' for 'Headers'", message)
        self.assertIn("query string", message)

    def test_the_run_command_exits_2_and_sends_nothing(self) -> None:
        document = _config()
        del document["sequences"]
        document["version"] = 1
        document["checks"][0]["request"]["params"] = {"tenant": "acme"}
        path = self.write(document)
        from unittest.mock import patch  # noqa: PLC0415

        from test_capsule import _RecordingOpener  # noqa: PLC0415
        from veridor import core  # noqa: PLC0415

        opener = _RecordingOpener()
        out, err = io.StringIO(), io.StringIO()
        with patch.object(core, "_OPENER", opener), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = veridor_main(["run", "--config", str(path),
                                 "--output-dir", str(self.directory / "out")])
        self.assertEqual(code, 2, err.getvalue())
        self.assertIn("check 'doc-isolation' request has unsupported keys: params",
                      err.getvalue())
        self.assertEqual(opener.requests, [])
        self.assertFalse((self.directory / "out").exists(), "nothing is written on a refusal")


class AnnotationControlTest(_LoadCase):
    """The rule refuses what the schema refuses, and no more: a key starting
    with '_' is an annotation in every request block, as the schema allows."""

    def test_annotations_in_request_blocks_still_load(self) -> None:
        for label, find in BLOCKS:
            for key in ("_comment", "_description", "_owner_note", "_"):
                with self.subTest(block=label, key=key):
                    document = _config()
                    find(document)[key] = "why this request exists"
                    self.load(document)


#: (label as the refusal names it, where the block is, a TLS key to plant).
#: The non-request containers below an identity and a check. Each loaded with
#: the key and did nothing, while README says a configuration naming a TLS
#: setting is refused (measured 2026-10-14).
TLS_CONTAINERS = (
    ("identity 'member' session", _block("identities/member/session"), "verify_tls"),
    ("identity 'member' session", _block("identities/member/session"), "tls"),
    ("check 'doc-isolation' expectation for 'owner'",
     _block("checks/0/expect/owner"), "verify_tls"),
    ("sequence 'doc-delete'", _block("sequences/0"), "verify_tls"),
    ("sequence 'doc-delete' step 0", _block("sequences/0/steps/0"), "client_cert"),
    ("sequence 'doc-delete' step 0 expect", _block("sequences/0/steps/0/expect"), "verify_tls"),
    ("sequence 'doc-delete' teardown entry 0", _block("sequences/0/teardown/0"), "ca_file"),
    ("sequence 'doc-delete' teardown entry 0 expect",
     _block("sequences/0/teardown/0/expect"), "ca_file"),
)


class TlsKeyEverywhereTest(_LoadCase):
    def test_a_tls_key_in_any_container_is_refused_by_name(self) -> None:
        for label, find, key in TLS_CONTAINERS:
            with self.subTest(block=label, key=key):
                document = _config()
                find(document)[key] = {"verify": False} if key == "tls" else False
                with self.assertRaises(ConfigError) as caught:
                    self.load(document)
                message = str(caught.exception)
                self.assertIn(f"{label} has {key}", message)
                self.assertIn("a TLS setting Veridor does not have", message)

    def test_control_the_same_containers_take_an_annotation(self) -> None:
        self.load(_config())
        for label, find, key in TLS_CONTAINERS:
            with self.subTest(block=label):
                document = _config()
                find(document)[f"_{key}"] = "why this is here"
                self.load(document)


def _session_config() -> dict[str, Any]:
    """:func:`_config` with a session inject entry and both kinds of capture."""
    document = _config()
    session = document["identities"]["member"]["session"]
    session["login"][0]["capture"] = {"csrf": {"from": "cookie", "name": "csrf"}}
    session["capture"] = {"jar": {"from": "cookie", "name": "sid"}}
    session["inject"] = [{"header": "X-CSRF", "value": "${capture.csrf}"}]
    return document


#: The session containers the first version of this check missed. An inject
#: entry and a capture spec both accept an unknown key as an annotation (through
#: _suspicious_keys), so a verify_tls or ca_file there loaded and did nothing, and
#: the README's "a configuration that names one ... is refused" was false for them
#: (measured 2026-10-14).
SESSION_TLS_CONTAINERS = (
    ("identity 'member' session inject 0",
     _block("identities/member/session/inject/0"), "verify_tls"),
    ("identity 'member' session inject 0",
     _block("identities/member/session/inject/0"), "ca_file"),
    ("identity 'member' session login step 0 capture 'csrf'",
     _block("identities/member/session/login/0/capture/csrf"), "verify_tls"),
    ("identity 'member' session login step 0 capture 'csrf'",
     _block("identities/member/session/login/0/capture/csrf"), "ca_file"),
    ("identity 'member' session capture 'jar'",
     _block("identities/member/session/capture/jar"), "client_cert"),
)


class SessionTlsKeyTest(_LoadCase):
    def test_a_tls_key_in_a_session_inject_entry_or_capture_spec_is_refused(
        self,
    ) -> None:
        for label, find, key in SESSION_TLS_CONTAINERS:
            with self.subTest(block=label, key=key):
                document = _session_config()
                find(document)[key] = False
                with self.assertRaises(ConfigError) as caught:
                    self.load(document)
                message = str(caught.exception)
                self.assertIn(f"{label} has {key}", message)
                self.assertIn("a TLS setting Veridor does not have", message)

    def test_control_the_same_containers_take_an_annotation(self) -> None:
        self.load(_session_config())
        for label, find, key in SESSION_TLS_CONTAINERS:
            with self.subTest(block=label):
                document = _session_config()
                find(document)[f"_{key}"] = "why this is here"
                self.load(document)


#: Containers whose unknown keys are annotations unless they are a slip of a
#: real key (``core._suspicious_keys``), each with a slip to plant.
ANNOTATED_CONTAINERS = (
    ("identity 'owner'", _block("identities/owner"), "remark"),
    ("identity 'owner'", _block("identities/owner"), "marker_note"),
    ("check 'doc-isolation' expectation for 'owner'",
     _block("checks/0/expect/owner"), "contains_marker"),
    ("identity 'member' session", _block("identities/member/session"), "injcet"),
    ("identity 'member' session inject 0", _block("identities/member/session/inject/0"),
     "Header"),
    ("identity 'member' session capture 'jar'",
     _block("identities/member/session/capture/jar"), "nmae"),
    ("sequence 'doc-delete'", _block("sequences/0"), "Steps"),
    ("sequence 'doc-delete' step 0", _block("sequences/0/steps/0"), "Capture"),
    ("sequence 'doc-delete' step 0 expect", _block("sequences/0/steps/0/expect"), "statsu"),
    ("sequence 'doc-delete' teardown entry 0", _block("sequences/0/teardown/0"), "Request"),
)


class AnnotationNearMissTest(_LoadCase):
    """A plain key that reads as a slip of a real one is refused even when it
    was meant as a note (root ``checksum`` reads as ``checks``, an identity's
    ``remark`` as ``marker``); such configurations loaded before the
    near-miss rules were tightened. The way out is the ``_`` prefix, so the
    refusal must say so and the prefixed key must load."""

    def test_a_plain_annotation_that_reads_as_a_slip_is_refused_with_the_way_out(
        self,
    ) -> None:
        for key in ("checksum", "schema", "versions", "x-version"):
            with self.subTest(root=key):
                document = _config()
                document[key] = "sha256:abc"
                with self.assertRaises(ConfigError) as caught:
                    self.load(document)
                self.assertIn("start it with '_' if it is an annotation", str(caught.exception))
        document = _config()
        document["identities"]["owner"]["remark"] = "primary tenant admin"
        with self.assertRaises(ConfigError) as caught:
            self.load(document)
        self.assertIn("unsupported keys: remark", str(caught.exception))
        self.assertIn("start it with '_' if it is an annotation", str(caught.exception))

    def test_the_same_keys_with_a_leading_underscore_load(self) -> None:
        """REGRESSION. ``_suspicious_keys`` stripped the ``_`` before
        comparing, so an identity's ``_remark`` -- the escape the refusal and
        the schema both offer -- was refused as 'marker' too, though it loaded
        before the any-order letter match was added. A key starting with
        ``_`` is never read, so it is never a slip of one that is."""
        for key in ("_checksum", "_schema", "_versions", "_x-version"):
            with self.subTest(root=key):
                document = _config()
                document[key] = "sha256:abc"
                self.load(document)
        for label, find, key in ANNOTATED_CONTAINERS:
            with self.subTest(block=label, key=key):
                document = _session_config()
                find(document)[f"_{key}"] = "why this is here"
                self.load(document)

    def test_control_the_unprefixed_slips_are_still_refused(self) -> None:
        for label, find, key in ANNOTATED_CONTAINERS:
            with self.subTest(block=label, key=key):
                document = _session_config()
                find(document)[key] = "why this is here"
                with self.assertRaises(ConfigError) as caught:
                    self.load(document)
                self.assertIn(key, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
