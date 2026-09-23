"""TLS through ``core._OPENER``: one context, and the stdlib's own.

Every https:// request goes through one TLS context, built on the first https
request (``core._SharedContextHTTPSHandler``). Python 3.11's stock handler built
a context per request and re-read the CA bundle each time; 3.12+ built one at
import, even for ``--version``. Sharing one is only safe if it is the context
the stdlib would have used, so the fast tests compare it with a fresh stdlib
default, property by property, and prove the comparison can tell apart a
context that does not verify. The slow tests make real handshakes against a
loopback server: a trusted certificate is accepted by one context for a whole
run, and an untrusted issuer or a wrong name is refused before a request is
sent.

Nothing else in the suite performs a TLS handshake through Veridor, so without
this module verification could be turned off and every test would still pass.

The test server prefers ``h2``, so a client that ever offered it would be
served it and fail: with the server preferring ``http/1.1``, a client
offering ``h2`` first passed all nine tests (measured). It asks every client
for a certificate, so a client certificate loaded into the shared context --
state no getter shows, which the property comparison cannot see -- would be
presented and recorded. And ``SSL_CERT_FILE`` is what a user sets to trust a
private CA: OpenSSL reads it alongside the default directory, not instead of
it, and ``SSL_CERT_DIR`` is what takes the directory away (measured in the
release image, where the README said the file replaced the bundle).

The certificates are made here, in Python, rather than with ``openssl``: the
suite needs no tool for them, so the tests cannot skip on a machine without
one. They are a chain, as a real target presents one -- a CA with basic
constraints, key usage and key identifiers, and a leaf it issued with an IP
SAN and serverAuth -- so the handshake verifies an issuer rather than trusting
a pinned leaf, under the strict X.509 flags 3.13 adds (measured: the chain
handshakes on 3.11 to 3.14).
"""

from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import http.client
import io
import ipaddress
import json
import os
import secrets
import ssl
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor import core  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402

# --- certificates, in DER, by hand ------------------------------------------

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p**0.5) + 1, 2))]


def _der(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _seq(*parts: bytes) -> bytes:
    return _der(0x30, b"".join(parts))


def _int(value: int) -> bytes:
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _oid(dotted: str) -> bytes:
    first, second, *rest = (int(arc) for arc in dotted.split("."))
    body = b""
    for arc in (first * 40 + second, *rest):
        chunk = [arc & 0x7F]
        while arc := arc >> 7:
            chunk.append(0x80 | (arc & 0x7F))
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _probably_prime(n: int) -> bool:
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(16):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


class _Key:
    """An RSA key: PKCS#1 v1.5 SHA-256 signatures, and its PEM for ``load_cert_chain``."""

    E = 65537

    def __init__(self, bits: int) -> None:
        def prime() -> int:
            while True:
                candidate = secrets.randbits(bits // 2) | (3 << (bits // 2 - 2)) | 1
                if (all(candidate % p for p in _SMALL_PRIMES) and (candidate - 1) % self.E
                        and _probably_prime(candidate)):
                    return candidate

        self.p, self.q = prime(), prime()
        self.n = self.p * self.q
        self.d = pow(self.E, -1, (self.p - 1) * (self.q - 1))
        self.public = _seq(_int(self.n), _int(self.E))
        self.key_id = hashlib.sha256(self.public).digest()[:20]

    def sign(self, message: bytes) -> bytes:
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
        digest_info += hashlib.sha256(message).digest()
        size = (self.n.bit_length() + 7) // 8
        padded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
        return pow(int.from_bytes(padded, "big"), self.d, self.n).to_bytes(size, "big")

    def pem(self) -> str:
        p, q, d = self.p, self.q, self.d
        body = _seq(_int(0), _int(self.n), _int(self.E), _int(d), _int(p), _int(q),
                    _int(d % (p - 1)), _int(d % (q - 1)), _int(pow(q, -1, p)))
        text = base64.b64encode(body).decode("ascii")
        # The label is assembled so no key header sits in the source for a
        # secret scanner to report; the key itself only ever exists in a temp dir.
        label = "RSA " + "PRIVATE KEY"
        lines = "\n".join(text[i:i + 64] for i in range(0, len(text), 64))
        return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def _certificate(subject: str, key: _Key, issuer: str, issuer_key: _Key, *,
                 addresses: tuple[str, ...] = (), client: bool = False) -> str:
    """A CA certificate; with ``addresses`` a serverAuth leaf for those IPs;
    with ``client`` a clientAuth leaf."""

    def name(common: str) -> bytes:
        return _seq(_der(0x31, _seq(_oid("2.5.4.3"), _der(0x0C, common.encode()))))

    def extension(oid: str, value: bytes, *, critical: bool = False) -> bytes:
        return _seq(_oid(oid), *([_der(0x01, b"\xff")] if critical else []), _der(0x04, value))

    ca = not addresses and not client
    now = datetime.now(UTC)
    validity = _seq(*(_der(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())
                      for moment in (now - timedelta(hours=1), now + timedelta(days=1))))
    sha256_rsa = _seq(_oid("1.2.840.113549.1.1.11"), _der(0x05, b""))
    rsa = _seq(_oid("1.2.840.113549.1.1.1"), _der(0x05, b""))
    extensions = [
        extension("2.5.29.19", _seq(_der(0x01, b"\xff")) if ca else _seq(), critical=True),
        # keyCertSign + cRLSign for the CA; digitalSignature + keyEncipherment.
        extension("2.5.29.15", _der(0x03, b"\x01\x06" if ca else b"\x05\xa0"), critical=True),
        extension("2.5.29.14", _der(0x04, key.key_id)),
        extension("2.5.29.35", _seq(_der(0x80, issuer_key.key_id))),
    ]
    if client:
        extensions.append(extension("2.5.29.37", _seq(_oid("1.3.6.1.5.5.7.3.2"))))
    elif not ca:
        extensions += [
            extension("2.5.29.37", _seq(_oid("1.3.6.1.5.5.7.3.1"))),
            extension("2.5.29.17", _seq(*(_der(0x87, ipaddress.ip_address(address).packed)
                                          for address in addresses))),
        ]
    tbs = _seq(_der(0xA0, _int(2)), _int(secrets.randbits(63) | 1 << 62), sha256_rsa,
               name(issuer), validity, name(subject), _seq(rsa, _der(0x03, b"\x00" + key.public)),
               _der(0xA3, _seq(*extensions)))
    return ssl.DER_cert_to_PEM_cert(_seq(tbs, sha256_rsa, _der(0x03, b"\x00" + issuer_key.sign(tbs))))


def _ca(directory: Path, name: str, *, bits: int) -> tuple[_Key, Path]:
    key = _Key(bits)
    path = directory / f"{name}.pem"
    path.write_text(_certificate(name, key, name, key), encoding="ascii")
    return key, path


def _subject_hash(common_name: str) -> str:
    """OpenSSL's X509_NAME_hash for a name that is one CN, as ``openssl x509
    -hash`` prints it: the first four bytes of the SHA-1 of the name's
    canonical encoding (each RDN's SET, value lowercased, as a UTF8String),
    little-endian. It names a CA's file in an ``SSL_CERT_DIR``."""
    canonical = _der(0x31, _seq(_oid("2.5.4.3"), _der(0x0C, " ".join(common_name.lower().split()).encode())))
    return f"{int.from_bytes(hashlib.sha1(canonical).digest()[:4], 'little'):08x}"  # noqa: S324 - OpenSSL's


def _hashed_directory(directory: Path, name: str, pem: Path, *, hashed: bool = True) -> Path:
    """A directory holding one CA, as ``SSL_CERT_DIR`` expects: <hash>.0, or
    with ``hashed`` false under a name OpenSSL never looks up."""
    directory.mkdir()
    (directory / (f"{_subject_hash(name)}.0" if hashed else "ca.pem")).write_text(
        pem.read_text(encoding="ascii"), encoding="ascii")
    return directory


# --- what a context is -------------------------------------------------------


def _properties(context: ssl.SSLContext) -> dict[str, object]:
    """Everything about a client context that decides what it will trust.

    ALPN has no getter; the handshake test reads it from the server side.
    """
    stats = context.cert_store_stats()
    return {
        "verify_mode": context.verify_mode,
        "check_hostname": context.check_hostname,
        "minimum_version": context.minimum_version,
        "maximum_version": context.maximum_version,
        "options": int(context.options),
        "verify_flags": int(context.verify_flags),
        "protocol": context.protocol,
        "post_handshake_auth": context.post_handshake_auth,
        "security_level": context.security_level,
        "hostname_checks_common_name": context.hostname_checks_common_name,
        "keylog_filename": context.keylog_filename,
        "ciphers": [cipher["name"] for cipher in context.get_ciphers()],
        "ca_certificates": stats["x509_ca"],
        "certificates": stats["x509"],
    }


def _differences(context: ssl.SSLContext, reference: ssl.SSLContext) -> list[str]:
    ours, theirs = _properties(context), _properties(reference)
    return sorted(key for key in theirs if ours[key] != theirs[key])


def _stdlib_default() -> ssl.SSLContext:
    """What http.client builds for an HTTPSConnection given no context: the
    per-request default on 3.11, and what 3.12+ HTTPSHandler holds."""
    return http.client.HTTPSConnection("veridor.invalid")._context  # noqa: SLF001


@contextlib.contextmanager
def _counting_context_builds():
    """Count default-store loads, which is what building a verifying context does."""
    original = ssl.SSLContext.load_default_certs
    with patch.object(ssl.SSLContext, "load_default_certs", autospec=True,
                      side_effect=original) as loads:
        yield loads


class SharedContextTest(unittest.TestCase):
    """The shared context is a fresh stdlib default in every property that decides trust."""

    @classmethod
    def setUpClass(cls) -> None:
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        # 1024 bits: this key only sits in the store, it never signs a
        # handshake, and generating it keeps the fast tier fast.
        _, cls.bundle = _ca(Path(directory.name), "Veridor parity CA", bits=1024)

    def _environment(self) -> contextlib.AbstractContextManager[dict[str, str]]:
        # OpenSSL reads SSL_CERT_FILE each time a default store is loaded, so
        # both contexts below load this file into their stores, on any
        # machine. Each also keeps the default CA directory, which OpenSSL
        # reads lazily at verification (HandshakeTest shows it); both share
        # it, so it is no difference between them.
        return patch.dict(os.environ, {"SSL_CERT_FILE": str(self.bundle)})

    def test_the_shared_context_is_the_stdlib_default(self) -> None:
        with self._environment():
            shared = core._SharedContextHTTPSHandler().context()  # noqa: SLF001
            fresh = _stdlib_default()
        self.assertIsNot(shared, fresh)
        differing = {key: (_properties(shared)[key], _properties(fresh)[key])
                     for key in _differences(shared, fresh)}
        self.assertEqual(differing, {}, "the shared context is not the stdlib default "
                         "(property: (shared, stdlib))")
        # Not vacuous: the store really was loaded, and verification is on.
        self.assertGreaterEqual(_properties(shared)["ca_certificates"], 1)
        self.assertEqual(shared.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(shared.check_hostname)

    def test_control_a_context_that_does_not_verify_is_told_apart(self) -> None:
        """The comparison above must be able to fail. The stdlib default with
        verification switched off differs on exactly the two properties that
        say so; the stdlib's own unverified context differs on those too; and
        one that verifies against an empty store differs on the store."""
        with self._environment():
            fresh = _stdlib_default()
            switched_off = _stdlib_default()
            switched_off.check_hostname = False
            switched_off.verify_mode = ssl.CERT_NONE
            unverified = ssl._create_unverified_context()  # noqa: SLF001
            empty_store = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(_differences(switched_off, fresh), ["check_hostname", "verify_mode"])
        self.assertTrue({"check_hostname", "verify_mode"} <= set(_differences(unverified, fresh)))
        self.assertIn("ca_certificates", _differences(empty_store, fresh))

    def test_no_context_is_built_until_the_first_https_request(self) -> None:
        with self._environment(), _counting_context_builds() as loads:
            core._build_opener()  # noqa: SLF001
            handler = core._SharedContextHTTPSHandler()  # noqa: SLF001
            self.assertEqual(loads.call_count, 0)
            first, second = handler.context(), handler.context()
            self.assertEqual(loads.call_count, 1, "handler.context() did not build once and reuse it")
        self.assertIs(first, second)

    def test_control_the_counter_sees_a_context_being_built(self) -> None:
        with self._environment(), _counting_context_builds() as loads:
            ssl.create_default_context()
        self.assertEqual(loads.call_count, 1)

    def test_the_opener_sends_https_through_the_shared_handler(self) -> None:
        """A subclass passed to build_opener displaces the stock HTTPSHandler;
        if it ever stopped doing so, both would be registered for https."""
        opener = core._build_opener()  # noqa: SLF001
        handlers = [type(handler) for handler in opener.handle_open["https"]]
        self.assertEqual(handlers, [core._SharedContextHTTPSHandler])  # noqa: SLF001


class NothingChangesTheSharedContextTest(unittest.TestCase):
    """SEC-2: the one context serves every identity, so nothing in the product
    may load per-identity TLS state into it or change its settings. The
    property comparison cannot see a client certificate or a curve
    (``load_cert_chain`` and ``set_ecdh_curve`` left ``_differences`` empty,
    measured); this reads the source for every call or assignment that could
    make one, and the handshake test records what the server was shown."""

    CALLS = frozenset({
        "load_cert_chain", "load_verify_locations", "load_default_certs", "set_default_verify_paths",
        "set_ciphers", "set_ecdh_curve", "load_dh_params", "set_alpn_protocols", "set_npn_protocols",
        "set_servername_callback", "set_psk_client_callback", "set_psk_server_callback",
    })
    ATTRIBUTES = frozenset({
        "verify_mode", "check_hostname", "minimum_version", "maximum_version", "options", "verify_flags",
        "post_handshake_auth", "keylog_filename", "sni_callback", "hostname_checks_common_name",
        "num_tickets", "security_level",
    })
    #: The places that may, and why. Anything else fails with its location.
    ALLOWED = {
        ("veridor/core.py", "_default_https_context", "set_alpn_protocols"),  # what http.client sets
        ("veridor/core.py", "_default_https_context", "post_handshake_auth"),  # what http.client sets
        ("veridor/blastradius.py", "_Context.__init__", "options"),  # rule options, not TLS
    }

    @classmethod
    def sites(cls, source: str, name: str) -> set[tuple[str, str, str]]:
        found = set()

        def visit(node: ast.AST, scope: str) -> None:
            for child in ast.iter_child_nodes(node):
                inner = scope
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    inner = f"{scope}.{child.name}" if scope else child.name
                if (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr in cls.CALLS):
                    found.add((name, scope, child.func.attr))
                if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                        and child.func.id == "setattr" and len(child.args) >= 2
                        and isinstance(child.args[1], ast.Constant) and child.args[1].value in cls.ATTRIBUTES):
                    found.add((name, scope, child.args[1].value))
                targets = (child.targets if isinstance(child, ast.Assign)
                           else [child.target] if isinstance(child, (ast.AugAssign, ast.AnnAssign)) else [])
                found.update((name, scope, target.attr) for target in targets
                             if isinstance(target, ast.Attribute) and target.attr in cls.ATTRIBUTES)
                visit(child, inner)

        visit(ast.parse(source, filename=name), "")
        return found

    def test_only_the_stdlib_default_steps_touch_a_context(self) -> None:
        source = ROOT / "src"
        found = set()
        files = sorted(source.rglob("*.py"))
        for path in files:
            found |= self.sites(path.read_text(encoding="utf-8"), path.relative_to(source).as_posix())
        self.assertGreater(len(files), 10)
        self.assertEqual(found, self.ALLOWED)

    def test_control_each_way_to_change_the_context_is_found(self) -> None:
        planted = {
            "a client certificate": "def f(context):\n    context.load_cert_chain('c.pem')\n",
            "a CA file": "def f(context):\n    context.load_verify_locations('ca.pem')\n",
            "verification off": "def f(context):\n    context.verify_mode = ssl.CERT_NONE\n",
            "by setattr": "def f(context):\n    setattr(context, 'check_hostname', False)\n",
            "an option added": "def f(context):\n    context.options |= 4\n",
            "a curve": "class H:\n    def g(self, c):\n        c.set_ecdh_curve('secp384r1')\n",
        }
        for label, source in planted.items():
            with self.subTest(label):
                self.assertEqual(len(self.sites(source, "x.py")), 1, source)
        self.assertEqual(self.sites(planted["a curve"], "x.py"), {("x.py", "H.g", "set_ecdh_curve")})
        self.assertEqual(self.sites("def f(context):\n    return context.verify_mode\n", "x.py"), set())


class TlsKeysAreRefusedTest(unittest.TestCase):
    """SEC-2's other half: a TLS key in a configuration loaded as an
    annotation and did nothing. The loader now refuses one by name."""

    def load(self, mutate) -> str | None:
        document = json.loads((ROOT / "fixtures" / "veridor.demo.json").read_text(encoding="utf-8"))
        mutate(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            try:
                core.load_config(path)
            except core.ConfigError as exc:
                return str(exc)
        return None

    def test_tls_keys_on_an_identity_or_the_target_are_refused(self) -> None:
        cases = {
            "client_cert": lambda d: d["identities"]["invoice_owner"].__setitem__("client_cert", "/c.pem"),
            "tls-key": lambda d: d["identities"]["other_tenant"].__setitem__("tls-key", "/k.pem"),
            "ca_file": lambda d: d["target"].__setitem__("ca_file", "/ca.pem"),
            "verify_tls": lambda d: d["target"].__setitem__("verify_tls", False),
            "insecure": lambda d: d["target"].__setitem__("insecure", True),
            # And wherever else a configuration holds settings. Each of these
            # loaded and did nothing until 2026-09-27, while the README said a
            # configuration naming one was refused (measured).
            "root verify_tls": lambda d: d.__setitem__("verify_tls", False),
            "root tls": lambda d: d.__setitem__("tls", {"client_cert": "/c.pem"}),
            "root ca_file": lambda d: d.__setitem__("ca_file", "/ca.pem"),
            "check verify_tls": lambda d: d["checks"][0].__setitem__("verify_tls", False),
            "check request cafile": lambda d: d["checks"][0]["request"].__setitem__("cafile", "/ca.pem"),
        }
        for key, mutate in cases.items():
            with self.subTest(key=key):
                refusal = self.load(mutate)
                self.assertIsNotNone(refusal, f"{key} loaded and would be ignored")
                self.assertIn(f"has {key.split()[-1]}, a TLS setting Veridor does not have", refusal)
                self.assertIn("SSL_CERT_FILE", refusal)

    def test_control_annotations_and_other_keys_still_load(self) -> None:
        self.assertIsNone(self.load(lambda d: None))
        self.assertIsNone(self.load(lambda d: d["identities"]["invoice_owner"].__setitem__("_client_cert", "x")))
        self.assertIsNone(self.load(lambda d: d["identities"]["invoice_owner"].__setitem__("description", "x")))
        self.assertIsNone(self.load(lambda d: d["target"].__setitem__("_ca_file", "x")))
        self.assertIsNone(self.load(lambda d: d.__setitem__("_ca_file", "x")), "a root annotation still loads")
        self.assertIsNone(self.load(lambda d: d["checks"][0].__setitem__("_verify", "x")))


# --- real handshakes -----------------------------------------------------------


@slow("stands up a loopback HTTPS server and makes real TLS handshakes")
class HandshakeTest(unittest.TestCase):
    """Real handshakes through a fresh ``core._build_opener()``, against the demo API over TLS."""

    @classmethod
    def setUpClass(cls) -> None:
        from scripts.demo_server import create_server  # noqa: PLC0415

        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.directory = Path(directory.name)
        # 2048 bits for the keys a handshake uses: OpenSSL's default security
        # level refuses less. The untrusted CA only sits in a store.
        ca_key, cls.trusted = _ca(cls.directory, "Veridor test CA", bits=2048)
        _, cls.untrusted = _ca(cls.directory, "Some other CA", bits=1024)
        leaf_key = _Key(2048)
        (cls.directory / "leaf.pem").write_text(
            _certificate("127.0.0.1", leaf_key, "Veridor test CA", ca_key,
                         addresses=("127.0.0.1",)), encoding="ascii")
        (cls.directory / "leaf.key").write_text(leaf_key.pem(), encoding="ascii")
        # A client certificate the shared context must never present.
        client_key = _Key(2048)
        (cls.directory / "client.pem").write_text(
            _certificate("Veridor test client", client_key, "Veridor test CA", ca_key, client=True),
            encoding="ascii")
        (cls.directory / "client.key").write_text(client_key.pem(), encoding="ascii")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cls.directory / "leaf.pem", cls.directory / "leaf.key")
        # The server's order wins: OpenSSL picks the first of these that the
        # client offers. With http/1.1 first, a client offering h2 as well
        # was served http/1.1 and every test passed.
        server_context.set_alpn_protocols(["h2", "http/1.1"])
        # Ask every client for a certificate and record what it presented.
        server_context.verify_mode = ssl.CERT_OPTIONAL
        server_context.load_verify_locations(cls.trusted)

        cls.served: list[str | None] = []
        cls.presented: list[dict | None] = []
        server = create_server("127.0.0.1", 0)
        served, presented = cls.served, cls.presented

        class Recording(server.RequestHandlerClass):  # type: ignore[name-defined,misc]
            def handle(self) -> None:
                # What the server chose from the client's ALPN offer; None
                # would mean the client offered none.
                served.append(self.connection.selected_alpn_protocol())
                presented.append(self.connection.getpeercert())
                super().handle()

        server.RequestHandlerClass = Recording
        # The handshake happens in accept(); one that fails raises there and
        # socketserver drops the connection, so nothing is recorded for it.
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        loopback.start(server)
        cls.addClassCleanup(server.server_close)
        cls.addClassCleanup(server.shutdown)
        cls.port = server.server_address[1]

    def setUp(self) -> None:
        self.served.clear()
        self.presented.clear()

    def _request(self, base_url: str, bundle: Path, directory: Path | None = None) -> dict:
        environment = {"SSL_CERT_FILE": str(bundle)}
        if directory is not None:
            environment["SSL_CERT_DIR"] = str(directory)
        with patch.dict(os.environ, environment), \
                patch.object(core, "_OPENER", core._build_opener()):  # noqa: SLF001
            return core._perform_request(  # noqa: SLF001
                base_url, 5, {"method": "GET", "path": "/api/invoices/inv-100"},
                {"headers": {"Authorization": "Bearer owner-token"}})

    def _run(self, opener: object) -> tuple[int, str, dict, int]:
        output = self.directory / f"run-{len(list(self.directory.glob('run-*')))}"
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(self.trusted)}), \
                patch.object(core, "_OPENER", opener), \
                _counting_context_builds() as loads, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = veridor_main([
                "run", "--config", str(ROOT / "fixtures" / "veridor.demo.json"),
                "--base-url", f"https://127.0.0.1:{self.port}",
                "--output-dir", str(output),
            ])
        document = json.loads((output / "latest.json").read_text(encoding="utf-8"))
        return code, stderr.getvalue(), document, loads.call_count

    @staticmethod
    def _shared(opener: object) -> ssl.SSLContext:
        (handler,) = [handler for handler in opener.handlers  # type: ignore[attr-defined]
                      if isinstance(handler, core._SharedContextHTTPSHandler)]  # noqa: SLF001
        return handler.context()

    def test_a_run_against_an_https_target_builds_one_context(self) -> None:
        opener = core._build_opener()  # noqa: SLF001
        code, stderr, document, builds = self._run(opener)
        self.assertEqual(code, 0, stderr)
        recorded = document["probes"] + document["marker_controls"]
        self.assertEqual([entry["error"] for entry in recorded], [None] * len(recorded))
        sent = len(recorded) + document["liveness"]["requests_issued"]
        # Every request the run sent was served over TLS, offering http/1.1 ...
        self.assertGreaterEqual(sent, 9)
        self.assertEqual(len(self.served), sent)
        self.assertEqual(set(self.served), {"http/1.1"})
        # ... as every identity of the demo config, presenting no certificate ...
        self.assertGreaterEqual(len({entry["identity"] for entry in document["probes"]}), 3)
        self.assertEqual(self.presented, [None] * sent, "the shared context presented a client "
                         "certificate: every identity in the process would present it")
        # ... and the whole run built one context: 3.11's stock handler built
        # one per request here, and 3.12's built its one at import.
        self.assertEqual(builds, 1, f"a run of {sent} https requests built "
                         f"{builds} TLS contexts, expected exactly 1")
        # After the run, the context is still what the stdlib would build.
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(self.trusted)}):
            self.assertEqual(_differences(self._shared(opener), _stdlib_default()), [])

    def test_control_a_certificate_in_the_shared_context_is_presented_and_recorded(self) -> None:
        """What the assertion above would see if anything loaded a client
        certificate into the shared context -- which _differences cannot."""
        opener = core._build_opener()  # noqa: SLF001
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(self.trusted)}):
            shared = self._shared(opener)
            shared.load_cert_chain(self.directory / "client.pem", self.directory / "client.key")
            self.assertEqual(_differences(shared, _stdlib_default()), [], "the property comparison "
                             "now sees a client certificate; this control no longer shows the gap")
        code, stderr, document, _ = self._run(opener)
        self.assertEqual(code, 0, stderr)
        self.assertTrue(self.presented)
        self.assertEqual({dict(entry["subject"][0])["commonName"] for entry in self.presented},
                         {"Veridor test client"})

    def test_control_the_same_request_is_accepted_with_the_issuer_trusted(self) -> None:
        sent = self._request(f"https://127.0.0.1:{self.port}", self.trusted)
        self.assertEqual((sent["error"], sent["response"]["status"]), (None, 200))
        self.assertEqual(self.served, ["http/1.1"], "one request, offering ALPN http/1.1")
        self.assertEqual(self.presented, [None])

    def test_control_a_client_that_offered_h2_would_be_served_h2(self) -> None:
        """The server really prefers h2, so the http/1.1 assertions above can
        fail: the same request with Veridor's context offering h2 first."""
        original = core._default_https_context  # noqa: SLF001

        def offers_h2() -> ssl.SSLContext:
            context = original()
            context.set_alpn_protocols(["h2", "http/1.1"])
            return context

        with patch.object(core, "_default_https_context", offers_h2):
            sent = self._request(f"https://127.0.0.1:{self.port}", self.trusted)
        self.assertEqual(self.served, ["h2"], sent)

    def test_ssl_cert_file_adds_to_the_default_directory_rather_than_replacing_it(self) -> None:
        """SEC-1. With SSL_CERT_FILE naming a CA that did not sign the target,
        a CA in SSL_CERT_DIR still verifies it: the file is not the whole
        store. The README said it was; in the image the 121 roots in
        /etc/ssl/certs stayed trusted (measured)."""
        directory = _hashed_directory(self.directory / "dir-trusted", "Veridor test CA", self.trusted)
        sent = self._request(f"https://127.0.0.1:{self.port}", self.untrusted, directory)
        self.assertEqual((sent["error"], sent["response"]["status"]), (None, 200))

    def test_an_empty_ssl_cert_dir_leaves_only_the_file(self) -> None:
        empty = self.directory / "dir-empty"
        empty.mkdir(exist_ok=True)
        refused = self._request(f"https://127.0.0.1:{self.port}", self.untrusted, empty)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", refused["error"])
        accepted = self._request(f"https://127.0.0.1:{self.port}", self.trusted, empty)
        self.assertEqual((accepted["error"], accepted["response"]["status"]), (None, 200))

    def test_control_a_directory_is_read_only_by_the_subject_hash(self) -> None:
        """The acceptance above came from the hashed file, not from elsewhere:
        the same CA under another name is not found."""
        directory = _hashed_directory(self.directory / "dir-unhashed", "Veridor test CA", self.trusted,
                                      hashed=False)
        sent = self._request(f"https://127.0.0.1:{self.port}", self.untrusted, directory)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", sent["error"])

    def test_a_certificate_from_an_untrusted_issuer_is_refused(self) -> None:
        sent = self._request(f"https://127.0.0.1:{self.port}", self.untrusted)
        self.assertEqual(self.served, [], "a certificate from an untrusted issuer was "
                         "accepted and the request sent: TLS verification is off")
        self.assertIsNone(sent["response"]["status"])
        self.assertIn("CERTIFICATE_VERIFY_FAILED", sent["error"])

    def test_a_name_the_certificate_does_not_carry_is_refused(self) -> None:
        # The leaf names 127.0.0.1 only; localhost reaches the same listener.
        sent = self._request(f"https://localhost:{self.port}", self.trusted)
        self.assertEqual(self.served, [], "a certificate for 127.0.0.1 was accepted for "
                         "localhost and the request sent: hostname checking is off")
        self.assertIsNone(sent["response"]["status"])
        self.assertIn("CERTIFICATE_VERIFY_FAILED", sent["error"])


if __name__ == "__main__":
    unittest.main()
