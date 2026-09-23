"""scripts/anonymous_pull_check.py: a release nobody can pull must not go green.

Whether GitHub serves a package to anyone is a setting on the package. Every
other check in release.yml runs after a login, so none of them could see it, and
every default image in deploy/ and ci/ would answer `denied` to its users.
What GitHub answers has not been seen: these tests stand in for its registry.
"""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import sys
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from scripts import anonymous_pull_check as check  # noqa: E402
from tiers import slow  # noqa: E402

DIGEST = "sha256:" + "a" * 64
REFERENCE = f"ghcr.io/acme/veridor@{DIGEST}"
TOKEN = "planted-token-value"


#: What a registry sends with a manifest. The fakes sent neither header once,
#: and the script counted any 2xx as served (an HTML login page included).
MANIFEST_HEADERS = {"Docker-Content-Digest": DIGEST,
                    "Content-Type": "application/vnd.oci.image.index.v1+json"}


class _Answer(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        super().__init__(body)
        self.status, self.headers = status, Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def __enter__(self) -> "_Answer":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "planted", Message(), None)


class _Registry:
    """Answers the two requests, and remembers what it was sent."""

    def __init__(self, token_status: int = 200, manifest_status: int = 200, body: bytes | None = None,
                 manifest_headers: dict[str, str] | None = None) -> None:
        self.token_status, self.manifest_status = token_status, manifest_status
        self.manifest_headers = MANIFEST_HEADERS if manifest_headers is None else manifest_headers
        self.body = json.dumps({"token": TOKEN}).encode() if body is None else body
        self.requests: list[urllib.request.Request | str] = []

    def __call__(self, request: urllib.request.Request | str, timeout: float = 0) -> _Answer:
        self.requests.append(request)
        if isinstance(request, str):
            if self.token_status != 200:
                raise _error(request, self.token_status)
            return _Answer(self.body)
        if self.manifest_status >= 300:
            raise _error(request.full_url, self.manifest_status)
        return _Answer(b"{}", self.manifest_status, self.manifest_headers)


def run(argv: list[str], registry: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = check.main(argv, opener=registry)
    return code, out.getvalue(), err.getvalue()


class AnonymousReadTest(unittest.TestCase):
    def test_a_served_manifest_passes(self) -> None:
        registry = _Registry()
        code, out, err = run([REFERENCE], registry)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("served with no credential", out)
        token_url, manifest = registry.requests
        self.assertEqual(token_url, "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aacme%2Fveridor%3Apull")
        self.assertEqual(manifest.full_url, f"https://ghcr.io/v2/acme/veridor/manifests/{DIGEST}")
        self.assertEqual(manifest.get_header("Authorization"), f"Bearer {TOKEN}")
        self.assertIn("application/vnd.oci.image.manifest.v1+json", manifest.get_header("Accept"))

    def test_a_refusal_at_either_step_fails_and_says_what_to_set(self) -> None:
        """The defect. Mutant: treat a refused manifest as served and this exits 0."""
        for where, registry in (("manifest", _Registry(manifest_status=401)),
                                ("manifest", _Registry(manifest_status=403)),
                                ("manifest", _Registry(manifest_status=404)),
                                ("token", _Registry(token_status=403))):
            with self.subTest(where=where, registry=registry.__dict__):
                code, _, err = run([REFERENCE], registry)
                self.assertEqual(code, 1, err)
                self.assertIn(REFERENCE, err)
                self.assertIn("Set the package to public", err)

    def test_every_reference_is_read_and_one_refusal_fails_the_run(self) -> None:
        answers = [_Registry(), _Registry(manifest_status=401)]
        code, out, err = run([REFERENCE, f"ghcr.io/acme/charts/veridor-gate@{DIGEST}"],
                             lambda request, timeout=0: answers[0 if "charts" not in str(getattr(request, "full_url", request))
                                                                 else 1](request, timeout))
        self.assertEqual(code, 1, err)
        self.assertIn("ghcr.io/acme/veridor@", out)
        self.assertIn("charts/veridor-gate", err)

    def test_not_being_able_to_ask_is_not_reported_as_an_answer(self) -> None:
        """A 500 or an unreachable registry says nothing about the package, so it
        must not tell a maintainer to go and change a setting, and must not pass."""
        def unreachable(request: object, timeout: float = 0) -> None:
            raise urllib.error.URLError("no route")

        for label, registry in (("500", _Registry(manifest_status=500)), ("unreachable", unreachable),
                                ("not json", _Registry(body=b"<html>"))):
            with self.subTest(case=label):
                code, _, err = run([REFERENCE], registry)
                self.assertEqual(code, 2, err)
                self.assertIn("says nothing about its visibility", err)
                self.assertNotIn("Set the package", err)

    def test_a_2xx_without_the_manifest_is_not_served(self) -> None:
        """Mutant: return None from _served unconditionally and these exit 0."""
        for label, registry in (
                ("html 200", _Registry(manifest_headers={"Content-Type": "text/html"})),
                ("errors body", _Registry(manifest_headers={"Content-Type": "application/json"})),
                ("no headers", _Registry(manifest_headers={})),
                ("204", _Registry(manifest_status=204)),
                ("another digest", _Registry(manifest_headers={**MANIFEST_HEADERS,
                                                               "Docker-Content-Digest": "sha256:" + "b" * 64}))):
            with self.subTest(case=label):
                code, out, err = run([REFERENCE], registry)
                self.assertEqual(code, 2, err)
                self.assertNotIn("served with no credential", out)
                self.assertIn("says nothing about its visibility", err)

    def test_either_header_alone_is_a_manifest(self) -> None:
        """Control for the test above: the rule is not "both headers"."""
        for headers in ({"Docker-Content-Digest": DIGEST},
                        {"Content-Type": "application/vnd.oci.image.manifest.v1+json; charset=utf-8"}):
            with self.subTest(headers=headers):
                self.assertEqual(run([REFERENCE], _Registry(manifest_headers=headers))[0], 0)

    def test_a_token_body_that_is_not_an_object_could_not_ask(self) -> None:
        """It raised AttributeError and exited 1 with a traceback."""
        for body in (b"[]", b'"token"', b"null", b"3"):
            with self.subTest(body=body):
                code, _, err = run([REFERENCE], _Registry(body=body))
                self.assertEqual(code, 2, err)
                self.assertIn("not an object", err)

    def test_no_token_is_a_failure_not_an_empty_bearer(self) -> None:
        code, _, err = run([REFERENCE], _Registry(body=b"{}"))
        self.assertEqual(code, 1, err)
        self.assertIn("gave no token", err)

    def test_usage(self) -> None:
        for argv in ([], ["ghcr.io/acme/veridor:0.1.0"], ["ghcr.io/acme/veridor@sha256:short"], ["GHCR.IO/a/b@" + DIGEST]):
            with self.subTest(argv=argv):
                self.assertEqual(run(argv, _Registry())[0], 2)

    def test_the_token_is_never_printed(self) -> None:
        for registry in (_Registry(), _Registry(manifest_status=401), _Registry(manifest_status=500)):
            code, out, err = run([REFERENCE], registry)
            self.assertNotIn(TOKEN, out + err, code)


@slow("stands up a loopback HTTP server")
class OverHttpTest(unittest.TestCase):
    """The tests above hand it a function. This is what urllib really does."""

    def serve(self, manifest_status: int, location: str | None = None) -> tuple[str, list[str]]:
        seen: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen.append(self.headers.get("Authorization") or "")
                ok = self.path.startswith("/token?") or manifest_status == 200 or self.path.endswith("?moved")
                self.send_response(200 if ok else manifest_status)
                if location is not None and not ok:
                    self.send_header("Location", location)
                body = json.dumps({"token": TOKEN}).encode() if self.path.startswith("/token?") else b"{}"
                if not self.path.startswith("/token?"):
                    for key, value in MANIFEST_HEADERS.items():
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        loopback.start(server)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"127.0.0.1:{server.server_address[1]}/acme/veridor@{DIGEST}", seen

    def main(self, reference: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return check.main([reference], scheme="http")

    def test_a_served_manifest_exits_0_and_only_the_second_request_has_a_token(self) -> None:
        reference, seen = self.serve(200)
        self.assertEqual(self.main(reference), 0)
        self.assertEqual(seen, ["", f"Bearer {TOKEN}"])

    def test_control_a_denied_manifest_exits_1(self) -> None:
        reference, _ = self.serve(403)
        self.assertEqual(self.main(reference), 1)

    def raw(self, token: bytes) -> str:
        """A registry whose token endpoint writes ``token`` as the whole raw answer."""
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.wfile.write(token)

            def log_message(self, *_: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        loopback.start(server)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"127.0.0.1:{server.server_address[1]}/acme/veridor@{DIGEST}"

    def test_a_broken_answer_could_not_ask(self) -> None:
        """IncompleteRead and BadStatusLine escaped as tracebacks with exit 1,
        which reads as a refusal. Mutant: drop the HTTPException clause."""
        for label, answer in (("IncompleteRead", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"tok"),
                              ("BadStatusLine", b"GARBAGE\r\n\r\n")):
            with self.subTest(case=label):
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    code = check.main([self.raw(answer)], scheme="http")
                self.assertEqual(code, 2, err.getvalue())
                self.assertIn(label, err.getvalue())

    def test_a_redirect_to_another_host_is_not_followed(self) -> None:
        """urllib followed it with the Authorization header, and the other host's
        200 counted as served. Mutant: the default opener as urllib.request.urlopen."""
        other, other_seen = self.serve(200)
        other_port = int(other.split("/")[0].split(":")[1])
        reference, seen = self.serve(307, location=f"http://localhost:{other_port}/v2/acme/veridor/manifests/{DIGEST}")
        self.assertEqual(self.main(reference), 2)
        self.assertEqual(other_seen, [])
        self.assertEqual(seen, ["", f"Bearer {TOKEN}"])

    def test_control_a_redirect_on_the_same_host_is_followed(self) -> None:
        reference, seen = self.serve(307, location=f"/v2/acme/veridor/manifests/{DIGEST}?moved")
        self.assertEqual(self.main(reference), 0)
        self.assertEqual(seen, ["", f"Bearer {TOKEN}", f"Bearer {TOKEN}"])


if __name__ == "__main__":
    unittest.main()
