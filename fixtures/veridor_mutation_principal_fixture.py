#!/usr/bin/env python3
"""Routes for the vacuities that survive a target the credential clearly reaches.

``veridor_mutation_fixture`` covers the vacuities you can see by removing a
credential. This one covers the ones you cannot, because on every route here the
credential is plainly being read -- the owner is served, everybody else is not --
and the check still proves nothing. It is the harder half of the problem and the
half a mutation engine gets wrong by accident:

``/api/orders/o-1`` (overridden)
    The shipped fixture answers 404 to ANY non-owner token, so its ``outsider``
    is indistinguishable from a credential belonging to nobody and ``M6``
    correctly refuses to call that check measured. Here the same route answers
    404 to a RECOGNISED other principal and 403 to an unrecognised credential,
    which is the evidence ``M6`` needs. This is the engine's negative control:
    every operator must be killed on it.
``/api/scoped/inv-7``
    The owner is served with their marker. A REAL, live principal that lacks the
    scope (``roleless``) is refused by a coarse role gate that fires before the
    ownership predicate ever runs -- and is answered exactly as an unrecognised
    credential is. A check naming that identity as the attacker passes green,
    scores nothing, and would not notice the ownership predicate being deleted.
    The other-tenant principal on the same route IS distinguished, so one route
    carries both the vacuous case and its control.
``/api/self/docs/<anything>``
    A caller-scoped envelope over documents that do not exist. Every id under
    the prefix answers ``200 {"requested_by": <the caller's own marker>, "data":
    null}``. That single response satisfies ``contains_marker`` on the owner --
    the echo, not the resource -- so a status-and-marker positive control is
    fully satisfied by a route with nothing behind it.
``/api/hidden/inv-42``
    Uniform existence-hiding, which is the more conservative design: 200 with
    the owner's marker to the owner, 404 to everybody else, credentialed or not.
    The other tenant's 404 equals an anonymous 404, and the check nonetheless
    catches the tenant guard being removed.
``/api/public/health``
    Public by design. 200 to everyone, credential or no credential, forever.
``/api/admin/audit``
    Nobody may read it while the guard holds. 403 to every recognised principal,
    401 to an anonymous caller. There is no owner to declare, and an absent
    route would have answered 404.

``guard_path`` is the same tier-2 seam the shipped fixture uses, and it gates
``/api/orders/o-1``, ``/api/scoped/inv-7``, ``/api/self/docs/*``,
``/api/hidden/inv-42`` and ``/api/admin/audit`` together. With it removed every
recognised principal is served on all five, except that ``roleless`` is still
refused by the role gate on ``/api/scoped/inv-7``. The public route is not
gated.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from veridor_mutation_fixture import (
    ORDER_OWNER_MARKER,
    OUTSIDER_TOKEN,
    OWNER_TOKEN,
    make_handler,
)

#: The other tenant's own marker, planted so the caller-echo route has something
#: to echo back to them. 28 characters from [A-Za-z0-9_-], like every marker.
OTHER_TENANT_MARKER = "vdr-Q2mNs4Xd_pR7bK1eZ0yTgW6h"

#: A real, live principal that simply lacks the scope this resource needs. The
#: point of the fixture: it authenticates, and it is still refused for a reason
#: that has nothing to do with the boundary under test.
ROLELESS_TOKEN = "Bearer roleless-principal-token"

#: Every credential the target recognises. Anything else is a non-principal --
#: an expired token, a typo, a fabricated one -- and is answered 403.
KNOWN_PRINCIPALS = {
    OWNER_TOKEN: ORDER_OWNER_MARKER,
    OUTSIDER_TOKEN: OTHER_TENANT_MARKER,
    ROLELESS_TOKEN: OTHER_TENANT_MARKER,
}

_DOCS_PREFIX = "/api/self/docs/"


def make_principal_handler(guard_path: Path | None = None) -> type[BaseHTTPRequestHandler]:
    base = make_handler(guard_path)

    class PrincipalFixtureHandler(base):  # type: ignore[valid-type, misc]
        def do_GET(self) -> None:  # noqa: N802 - standard library callback
            token = self.headers.get("Authorization", "")
            path = self.path

            if path.startswith(_DOCS_PREFIX):
                return self._self_doc(token)
            if path == "/api/scoped/inv-7":
                return self._scoped(token)
            if path == "/api/hidden/inv-42":
                return self._hidden(token)
            if path == "/api/public/health":
                return self._json(HTTPStatus.OK, {"status": "ok"})
            if path == "/api/admin/audit":
                return self._audit(token)
            return super().do_GET()

        # -- routes ---------------------------------------------------------

        def _orders(self, token: str) -> None:
            """The shipped route, but a non-principal is told so.

            The only change from ``veridor_mutation_fixture._orders`` is the
            last line: an unrecognised credential is answered 403 rather than
            being folded in with the recognised other tenant's 404.
            """
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if token == OWNER_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "o-1", "note": ORDER_OWNER_MARKER}
                )
            if token not in KNOWN_PRINCIPALS:
                return self._json(HTTPStatus.FORBIDDEN, {"error": "unknown credential"})
            if self._guard_removed():
                return self._json(
                    HTTPStatus.OK, {"id": "o-1", "note": ORDER_OWNER_MARKER}
                )
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _scoped(self, token: str) -> None:
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if token == OWNER_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "inv-7", "note": ORDER_OWNER_MARKER}
                )
            if token == ROLELESS_TOKEN or token not in KNOWN_PRINCIPALS:
                # The coarse role gate and the unknown-credential path are the
                # same line of code in a great many stacks, and that is exactly
                # why an attacker declared here proves nothing: the request
                # never reaches the ownership predicate the check is about.
                return self._json(HTTPStatus.FORBIDDEN, {"error": "missing scope"})
            if self._guard_removed():
                return self._json(
                    HTTPStatus.OK, {"id": "inv-7", "note": ORDER_OWNER_MARKER}
                )
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _self_doc(self, token: str) -> None:
            marker = KNOWN_PRINCIPALS.get(token)
            if marker is None:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if token != OWNER_TOKEN and not self._guard_removed():
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            # No document with this id exists -- none does, for any id. The
            # envelope echoes the CALLER, which is what makes the owner's 200
            # look like a positive control when it is nothing of the kind.
            return self._json(HTTPStatus.OK, {"requested_by": marker, "data": None})

        def _hidden(self, token: str) -> None:
            if token == OWNER_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "inv-42", "note": ORDER_OWNER_MARKER}
                )
            if token in KNOWN_PRINCIPALS and self._guard_removed():
                return self._json(
                    HTTPStatus.OK, {"id": "inv-42", "note": ORDER_OWNER_MARKER}
                )
            # Everyone else, credentialed or not: the record is not disclosed to
            # exist. This is good practice, and it makes an other-tenant 404
            # identical to an anonymous 404.
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _audit(self, token: str) -> None:
            if token not in KNOWN_PRINCIPALS:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if self._guard_removed():
                return self._json(HTTPStatus.OK, {"rows": 12})
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        # -- plumbing -------------------------------------------------------

        def _guard_removed(self) -> bool:
            return guard_path is not None and not guard_path.exists()

        def _json(self, status: HTTPStatus, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            """Silence the default stderr access log."""

    return PrincipalFixtureHandler


def create_server(
    host: str = "127.0.0.1", port: int = 0, *, guard_path: Path | None = None
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_principal_handler(guard_path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument(
        "--guard-file",
        default=None,
        help="tier-2 seam: while this file exists the tenant boundary is enforced",
    )
    arguments = parser.parse_args()
    guard = Path(arguments.guard_file) if arguments.guard_file else None
    server = create_server(arguments.host, arguments.port, guard_path=guard)
    print(
        "mutation principal fixture listening on "
        f"http://{arguments.host}:{server.server_port}"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
