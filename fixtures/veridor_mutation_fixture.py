#!/usr/bin/env python3
"""A deliberately mixed API for exercising Veridor's mutation engine.

Every route here exists to make one specific vacuity reproducible, because a
mutation engine that has only been run against a correct target has not been
tested at all. The routes are, in the order the failures actually happen in the
field:

``/api/orders/o-1``
    The honest boundary. The owner is served and their marker is in the body,
    the outsider gets 404 with nothing, the anonymous caller gets 401. Every
    operator that can measure this route kills its mutant, and that matters as
    much as the positive cases: an engine that flags everything as vacuous is
    as useless as one that flags nothing. Two are not measured. ``M3`` has
    nothing to mutate in the owner's marker assertion, which is falsifiable by
    construction. ``M6`` is not_applicable, because this route answers 404 to
    every non-owner token, so the outsider cannot be told apart from a
    credential belonging to nobody. ``veridor_mutation_principal_fixture``
    overrides the route to tell them apart, and that override is the engine's
    negative control.
``/api/settings/s-1``
    The same shape with no marker anywhere, so a check on it is status-only.
``/api/reports/r-9``
    Accepts exactly one token. A configuration whose tokens are both stale gets
    401 for both identities and reads as a tested boundary.
``/api/ghost/g-1``
    404 to everyone, always, authenticated or not. The route does not exist.
``/api/wide/w-1``
    Serves ANY caller who presents any Authorization header at all: a real
    cross-tenant read. A ``[200, 403, 404]`` expectation covers it in green.
``/api/backwards/b-1``
    Refuses a credentialed caller and serves an anonymous one. Stripping the
    credential changes the status, so the letter of a kill is satisfied, but the
    change runs the wrong way -- which is a distinct outcome, not a kill.
``/api/echo``
    Reflects the caller's Authorization header and a secret into the body, so a
    test can grep the mutation report for both and prove neither reached it.

``guard_path`` is the tier-2 seam. While that file exists, ``/api/orders/o-1``
enforces the tenant boundary; delete it and the outsider is served the owner's
record, marker and all. An operator-supplied ``apply_command`` that deletes the
file is a complete, honest worked example of a target mutation.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

#: Planted in the order owner's record. 28 characters from [A-Za-z0-9_-], so it
#: passes validate_marker and survives JSON encoding unchanged.
ORDER_OWNER_MARKER = "vdr-6B0Fa6c-z8JsRxAl85RFt00L"
#: Planted in the wide-expectation record, which the target serves to everyone.
WIDE_OWNER_MARKER = "vdr-t9VqC3rPKBf-Ptn_FARPavLv"

OWNER_TOKEN = "Bearer order-owner-token"
OUTSIDER_TOKEN = "Bearer outsider-token"
REPORT_TOKEN = "Bearer report-token"

#: Reflected by /api/echo alongside the caller's own Authorization header. A
#: test greps the mutation report for this string; finding it would mean a
#: response body reached an artifact.
ECHO_SECRET = "server-side-secret-payload-do-not-persist"


def make_handler(guard_path: Path | None = None) -> type[BaseHTTPRequestHandler]:
    class MutationFixtureHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - standard library callback
            token = self.headers.get("Authorization", "")
            path = self.path

            if path == "/api/orders/o-1":
                return self._orders(token)
            if path == "/api/settings/s-1":
                return self._settings(token)
            if path == "/api/reports/r-9":
                return self._reports(token)
            if path == "/api/ghost/g-1":
                # No authentication check at all: the route simply is not there,
                # for anybody, which is precisely why a 404 here proves nothing.
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if path == "/api/wide/w-1":
                return self._wide(token)
            if path == "/api/backwards/b-1":
                return self._backwards(token)
            if path == "/api/echo":
                return self._echo(token)
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_DELETE(self) -> None:  # noqa: N802 - standard library callback
            # Present only so a test can declare a mutating verb and watch M4
            # refuse to send an unauthenticated one. It never changes state.
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        # -- routes ---------------------------------------------------------

        def _orders(self, token: str) -> None:
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if token == OWNER_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "o-1", "note": ORDER_OWNER_MARKER}
                )
            if guard_path is not None and not guard_path.exists():
                # The guard is gone: the tenant predicate no longer runs and the
                # owner's record, marker and all, is served to the outsider.
                return self._json(
                    HTTPStatus.OK, {"id": "o-1", "note": ORDER_OWNER_MARKER}
                )
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _settings(self, token: str) -> None:
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if token == OWNER_TOKEN:
                return self._json(HTTPStatus.OK, {"id": "s-1", "theme": "dark"})
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        def _reports(self, token: str) -> None:
            if token == REPORT_TOKEN:
                return self._json(HTTPStatus.OK, {"id": "r-9", "rows": 3})
            # Any other token, valid-looking or absent, is simply not
            # authenticated. Nothing here is an authorization decision.
            return self._json(
                HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
            )

        def _wide(self, token: str) -> None:
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            # Any credential at all is enough. This is the cross-tenant read a
            # [200, 403, 404] expectation hides.
            return self._json(
                HTTPStatus.OK, {"id": "w-1", "note": WIDE_OWNER_MARKER}
            )

        def _backwards(self, token: str) -> None:
            if token:
                # A misrouted policy: presenting a credential puts the caller in
                # a role the route rejects, while presenting none falls through
                # to a public handler.
                return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return self._json(HTTPStatus.OK, {"id": "b-1", "public": True})

        def _echo(self, token: str) -> None:
            self._json(HTTPStatus.OK, {"seen": token, "secret": ECHO_SECRET})

        # -- plumbing -------------------------------------------------------

        def _json(self, status: HTTPStatus, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            """Silence the default stderr access log."""

    return MutationFixtureHandler


def create_server(
    host: str = "127.0.0.1", port: int = 0, *, guard_path: Path | None = None
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(guard_path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument(
        "--guard-file",
        default=None,
        help="tier-2 seam: while this file exists the tenant boundary is enforced",
    )
    arguments = parser.parse_args()
    guard = Path(arguments.guard_file) if arguments.guard_file else None
    server = create_server(arguments.host, arguments.port, guard_path=guard)
    print(f"mutation fixture listening on http://{arguments.host}:{server.server_port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
