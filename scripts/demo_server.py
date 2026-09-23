#!/usr/bin/env python3
"""Deterministic demo API used by the quickstart and CI validation."""

from __future__ import annotations

import argparse
import gzip
import itertools
import json
import re
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The marker planted in the invoice owner's data. 28 characters drawn from
# [A-Za-z0-9_-], so it passes validate_marker and survives JSON, HTML, percent,
# XML, and CSV encoding unchanged.
OWNER_MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"

# The OTHER tenant's own record, and its own marker. A two-tenant fixture needs
# both tenants to own something: an "attacker" identity that is served nothing
# anywhere is one whose credential the tool cannot prove live, so every denial
# it draws is equally well explained by an expired token. Veridor says so, which
# is correct and was invisible until liveness controls existed -- the demo was
# under-specified, not the tool wrong. inv-200 is what makes `other_tenant` a
# principal rather than a string.
OUTSIDER_MARKER = "vdr-Bq3Wm8Ke5Tz1Yx7Rn2Hd4Vs6"

# Markers planted in a PER-PRINCIPAL-SCOPED fleet API, where the resource path
# embeds the caller's own principal. Device A's artifact only ever exists under
# /fleet/v1/device-a/..., so device A can never be probed at device B's path and
# no same-check control is possible. Proving these markers live is exactly what
# an identity-level marker_probe is for.
DEVICE_A_MARKER = "vdr-OIItAlvvweFpwlDNmT1j5WJ8"
DEVICE_B_MARKER = "vdr-lWJ25HBfPp4Y3_MeEkYhL9Gu"

_FLEET_PRINCIPALS = {
    "Bearer device-a-token": "device-a",
    "Bearer device-b-token": "device-b",
}
_FLEET_MARKERS = {"device-a": DEVICE_A_MARKER, "device-b": DEVICE_B_MARKER}
_FLEET_ARTIFACT = re.compile(r"^/fleet/v1/([a-z0-9-]+)/artifacts/fw\.bin$")
_FLEET_MANIFEST = re.compile(r"^/fleet/v1/([a-z0-9-]+)/manifest\.json$")

# ---------------------------------------------------------------------------
# Stateful notes fixture.
#
# This exists to exercise the ONE class of defect a single-request check cannot
# express. In --vulnerable mode a cross-tenant DELETE answers 403 -- the status
# the operator declared, the status that makes a status-only check go green --
# and deletes the row anyway. Nothing in the attacker's own response reveals
# it. Only issuing the victim's read afterwards, and finding the victim's
# marker gone from data that was observed present moments earlier in the same
# run, shows that the write crossed the boundary.
#
# Nothing here is provisioned up front: the sequence creates the object as the
# victim, plants the victim's marker in it, proves it is retrievable, probes it
# as the attacker, and tears it down. That is the NEEDS_SETUP_STATE class.
# ---------------------------------------------------------------------------
NOTES_TENANTS = {
    "Bearer owner-token": "acme",
    "Bearer outsider-token": "globex",
    "Bearer admin-token": "internal",
}
_NOTES_COLLECTION = "/api/v2/notes"
_NOTE_ITEM = re.compile(r"^/api/v2/notes/([A-Za-z0-9_-]+)$")


def make_handler(
    vulnerable: bool = False,
    leak_marker: bool = True,
    silent_write: bool = True,
) -> type[BaseHTTPRequestHandler]:
    # ThreadingHTTPServer serves each request on its own thread, so the notes
    # store needs a lock. The sequence engine is strictly serial, but the demo
    # server has no way to know that.
    notes: dict[str, dict] = {}
    notes_lock = threading.Lock()
    note_ids = itertools.count(1)

    class DemoHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - standard library callback
            token = self.headers.get("Authorization", "")
            if self._notes_get(token):
                return
            if self.path == "/api/invoices/inv-100":
                if not token:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                elif token == "Bearer owner-token":
                    self._json(HTTPStatus.OK, self._invoice(OWNER_MARKER))
                elif vulnerable and token == "Bearer outsider-token":
                    # Confirmed case: the outsider sees the owner's record, and
                    # the record still carries the owner's marker.
                    self._json(
                        HTTPStatus.OK,
                        self._invoice(OWNER_MARKER if leak_marker else "[redacted]"),
                    )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if self.path == "/api/invoices/inv-200":
                # Symmetrical to inv-100 and never leaked in either mode: the
                # boundary here holds even under --vulnerable, so this route
                # proves `other_tenant` is live without ever being the finding.
                if not token:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                elif token == "Bearer outsider-token":
                    self._json(
                        HTTPStatus.OK,
                        {"id": "inv-200", "tenant": "beta",
                         "customer_ref": OUTSIDER_MARKER},
                    )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if self.path == "/api/invoices/inv-100/compressed":
                if not token:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                elif token == "Bearer owner-token":
                    self._gzip_json(HTTPStatus.OK, self._invoice(OWNER_MARKER))
                elif vulnerable and token == "Bearer outsider-token":
                    self._gzip_json(
                        HTTPStatus.OK,
                        self._invoice(OWNER_MARKER if leak_marker else "[redacted]"),
                    )
                else:
                    self._gzip_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if self.path == "/api/exports/acme.json":
                if not token:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                elif token == "Bearer owner-token":
                    self._json(
                        HTTPStatus.OK,
                        {"tenant": "acme", "rows": [{"customer_ref": OWNER_MARKER}]},
                    )
                elif vulnerable and token == "Bearer outsider-token":
                    # Suspected case: access is granted where it should not be,
                    # but no owner data actually crosses the boundary.
                    self._json(HTTPStatus.OK, {"tenant": "acme", "rows": []})
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if self.path == "/api/admin/audit":
                if token == "Bearer admin-token":
                    self._json(HTTPStatus.OK, {"events": []})
                elif token:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "admin role required"})
                else:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            if self._fleet(token):
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        # -- stateful notes fixture -------------------------------------

        def do_POST(self) -> None:  # noqa: N802 - standard library callback
            token = self.headers.get("Authorization", "")
            tenant = NOTES_TENANTS.get(token)
            if self.path != _NOTES_COLLECTION:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if tenant is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            payload = self._read_json()
            if payload is None:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
                return
            with notes_lock:
                # Long and distinctive on purpose: an id short enough to appear
                # by accident cannot prove that captured values stay off disk.
                note_id = f"note-{next(note_ids):06d}"
                notes[note_id] = {
                    "id": note_id,
                    "tenant": tenant,
                    "title": str(payload.get("title", "")),
                    "provenance": str(payload.get("provenance", "")),
                }
            self._json(
                HTTPStatus.CREATED,
                {"id": note_id, "tenant": tenant},
                extra_headers={"Location": f"{_NOTES_COLLECTION}/{note_id}"},
            )

        def do_DELETE(self) -> None:  # noqa: N802 - standard library callback
            token = self.headers.get("Authorization", "")
            match = _NOTE_ITEM.match(self.path)
            if match is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            tenant = NOTES_TENANTS.get(token)
            if tenant is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            note_id = match.group(1)
            with notes_lock:
                note = notes.get(note_id)
                if note is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                if note["tenant"] == tenant:
                    del notes[note_id]
                    self._json(HTTPStatus.NO_CONTENT, {})
                    return
                # THE FLAW. The authorization decision is rendered correctly in
                # the RESPONSE and ignored by the STORAGE layer. A status-only
                # single-request check declaring [403, 404] here matches and
                # goes green; the row is gone regardless.
                if vulnerable and silent_write:
                    del notes[note_id]
                elif vulnerable:
                    # The other direction: a 200 that silently no-ops. The
                    # attacker's own response looks like a successful
                    # cross-tenant delete and is not one.
                    self._json(HTTPStatus.OK, {"deleted": note_id})
                    return
            self._json(HTTPStatus.FORBIDDEN, {"error": "cross-tenant delete refused"})

        def _notes_get(self, token: str) -> bool:
            match = _NOTE_ITEM.match(self.path)
            if match is None:
                return False
            tenant = NOTES_TENANTS.get(token)
            if tenant is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return True
            with notes_lock:
                note = notes.get(match.group(1))
                served = dict(note) if note is not None else None
            if served is None or served["tenant"] != tenant:
                # Reads are enforced correctly, in both modes. Only the write
                # path is broken, which is precisely why the read is a usable
                # oracle for what the write did.
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return True
            if not leak_marker:
                served["provenance"] = "[redacted]"
            self._json(HTTPStatus.OK, served)
            return True

        def _read_json(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, UnicodeDecodeError):
                return None
            return payload if isinstance(payload, dict) else None

        def _fleet(self, token: str) -> bool:
            """Per-principal-scoped device API. Returns True when it handled the path.

            The path embeds the caller's own principal, so identity A and
            identity B can never address one URL. Authorization is 'the path
            principal must equal the token principal'.
            """
            artifact = _FLEET_ARTIFACT.match(self.path)
            manifest = _FLEET_MANIFEST.match(self.path)
            if not artifact and not manifest:
                return False
            scoped = (artifact or manifest).group(1)
            principal = _FLEET_PRINCIPALS.get(token)
            if principal is None:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return True
            if principal != scoped:
                self._json(HTTPStatus.FORBIDDEN, {"error": "principal mismatch"})
                return True
            if manifest:
                # Deliberately marker-free metadata about the same device. A
                # marker_probe aimed here is live but proves nothing, which is
                # the misconfiguration the control has to fail closed on.
                self._json(
                    HTTPStatus.OK,
                    {"device": scoped, "artifacts": ["fw.bin"], "size": 4096},
                )
                return True
            served = scoped
            if vulnerable and scoped == "device-b":
                # The regression: device B asks for its OWN artifact and the
                # fleet service hands back device A's. Status is exactly what
                # the client expects; only the marker reveals the crossover.
                served = "device-a"
            self._json(
                HTTPStatus.OK,
                {
                    "device": scoped,
                    "artifact": "fw.bin",
                    "provenance": (
                        _FLEET_MARKERS[served] if leak_marker else "[redacted]"
                    ),
                },
            )
            return True

        @staticmethod
        def _invoice(customer_ref: str) -> dict:
            return {"id": "inv-100", "tenant": "acme", "customer_ref": customer_ref}

        def _json(
            self,
            status: HTTPStatus,
            value: dict,
            extra_headers: dict | None = None,
        ) -> None:
            body = b"" if status == HTTPStatus.NO_CONTENT else json.dumps(value).encode()
            self.send_response(status)
            if body:
                self.send_header("Content-Type", "application/json")
            for name, header_value in (extra_headers or {}).items():
                self.send_header(name, header_value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _gzip_json(self, status: HTTPStatus, value: dict) -> None:
            # Deliberately ignores Accept-Encoding so the runner has to invert
            # the transport encoding itself.
            body = gzip.compress(json.dumps(value).encode())
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return DemoHandler


def create_server(
    host: str,
    port: int,
    vulnerable: bool = False,
    leak_marker: bool = True,
    silent_write: bool = True,
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(
        (host, port), make_handler(vulnerable, leak_marker, silent_write)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--vulnerable",
        action="store_true",
        help="intentionally expose the cross-tenant invoice",
    )
    parser.add_argument(
        "--no-marker-leak",
        dest="leak_marker",
        action="store_false",
        help="expose the resource without leaking the owner's marker",
    )
    parser.add_argument(
        "--noisy-write",
        dest="silent_write",
        action="store_false",
        help=(
            "make the cross-tenant delete answer 200 and do nothing, instead of "
            "answering 403 and deleting the row"
        ),
    )
    args = parser.parse_args()
    try:
        server = create_server(
            args.host, args.port, args.vulnerable, args.leak_marker, args.silent_write
        )
    except OSError as exc:
        # The quickstart backgrounds this script and runs `veridor run` on the
        # next line. A raw socketserver traceback there scrolls past, and the
        # run then probes whatever process already owns the port -- producing a
        # report indistinguishable from a genuine clean result. Say what
        # happened, say what it means for the next command, and exit non-zero
        # so a `&&` chain stops here.
        print(
            f"demo_server: cannot listen on {args.host}:{args.port}: {exc}\n"
            f"  Another process already holds {args.host}:{args.port}. This demo "
            "did NOT start.\n"
            "  Anything you point at that address next will be probing that "
            "other process, and a green result would say nothing about this "
            "demo.\n"
            "  Free the port, or run somewhere else and point the tool at it:\n"
            f"    python3 scripts/demo_server.py --vulnerable --port 8799 &\n"
            "    veridor run --config fixtures/veridor.demo.json "
            "--base-url http://127.0.0.1:8799",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2) from None
    print(f"Demo API: http://{args.host}:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
