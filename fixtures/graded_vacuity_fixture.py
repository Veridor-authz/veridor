#!/usr/bin/env python3
"""An independently authored graded target for scoring the mutation engine.

This fixture exists to answer one question with numbers: over a population of
checks whose vacuity is known IN ADVANCE, how many of the vacuous ones does the
engine catch, and how many of the good ones does it wrongly flag? Either number
alone is meaningless -- an engine that flags everything scores a perfect catch
rate and is worthless -- so the graded suite always carries both arms. That
suite is ``GradedVacuityTest`` in tests/test_mutation.py: one check per route
below, no survivor allowed on a GOOD check, and on each VACUOUS check the
survivor that names its vacuity required -- except ``/api/settings/s-alice``,
whose vacuous declaration the loader refuses outright and whose status-only
form must be disclosed as status-only evidence. It asserts outcomes check by
check; no catch rate or false-flag rate is published from it.

The target is written from scratch rather than reusing
``veridor_mutation_fixture``: a grading run against the same routes the engine
was developed on measures agreement with its author, not detection.

Two real principals, one credential the target does not recognise, and one
route family per failure mode:

GOOD routes -- a genuine boundary is enforced and the check over it has real
discriminating power.

``/api/docs/d-alice``        alice served with her marker, mallory refused 403.
``/api/docs/d-mallory``      the mirror image, so the grading is not measuring
                             one direction only.
``/api/invoices/inv-alice``  the same boundary expressed as a 404, with sibling
                             ids that genuinely do not exist.
``/api/projects/p-alice``    403 denial, marker present in the owner's body.
``/api/exports/e-alice``     404 denial, marker present, anonymous refused 401.
``/api/admin/audit``         role boundary: root served, both tenants refused.

VACUOUS routes -- a check over these passes green and establishes nothing.

``/api/docs/d-alice``        (again) declared against a STALE credential, so the
                             denial is a 401 about the token, not authorization.
``/api/ghost/g-1``           404 to everyone including the owner: the resource
                             id in the declaration does not exist.
``/api/wide/w-1``            serves any credentialed caller alice's record -- a
                             real cross-tenant read, covered by a [200,403,404].
``/api/settings/s-alice``    a genuine boundary carrying no marker anywhere, so
                             the ``excludes_marker`` on it can never fire. The
                             loader refuses that declaration for want of a
                             control, and the status-only form is disclosed as
                             status-only evidence. Neither is an operator
                             survivor.
``/api/beta/b-1``            403 to every bearer that is not alice, recognised
                             or not: a coarse gate in front of the boundary.
``/api/public/notice``       200 to everyone, anonymous included, declared as
                             though it were a boundary.
``/api/reports/r-9``         accepts one token nobody in the config holds, so
                             both identities are refused 401 and the check reads
                             as a tested boundary.

Every route rejects unknown ids under a known collection with 404 and never
mutates state. ``guard_path``, when supplied, is the tier-2 seam on
``/api/docs/d-alice``: while the file exists the tenant predicate runs; delete
it and mallory is served alice's record, marker and all.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

#: Planted in alice's records. 28 characters from [A-Za-z0-9_-] so it passes
#: validate_marker and survives JSON encoding unchanged.
ALICE_MARKER = "vdr-3QhG8i09qBM8bfUVxXCFmGXY"
#: Planted in mallory's own record, for the mirrored boundary.
MALLORY_MARKER = "vdr-3gnBCPwACeuFLjG7r7dsNgdd"
#: Planted in the administrator's audit record.
ROOT_MARKER = "vdr-aG-WKyRQJCk2kL4RTVz8vM5R"
#: Planted in the wide record the target hands to any credentialed caller.
WIDE_MARKER = "vdr-hV_3gsRiQ8wlaNdMCr2BtUFj"

#: Credentials the target RECOGNISES. A recognised credential names a principal,
#: which is what makes a 403 over it a statement about authorization.
ALICE_TOKEN = "Bearer tok-alice"
MALLORY_TOKEN = "Bearer tok-mallory"
ROOT_TOKEN = "Bearer tok-root"
#: A credential the target does NOT recognise. Present in the config so the
#: graded suite can carry the invalid-credential vacuity honestly.
STALE_TOKEN = "Bearer tok-expired-long-ago"
#: Accepted by /api/reports/r-9 and held by nobody in the configuration.
REPORT_TOKEN = "Bearer tok-report-service"

_KNOWN = {ALICE_TOKEN, MALLORY_TOKEN, ROOT_TOKEN}

#: Reflected by /api/echo next to the caller's own Authorization header, so a
#: grading run can grep every artifact for both and prove neither reached one.
ECHO_SECRET = "graded-fixture-secret-payload-must-not-persist"


def make_handler(guard_path: Path | None = None) -> type[BaseHTTPRequestHandler]:
    class GradedFixtureHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - standard library callback
            token = self.headers.get("Authorization", "")
            path = self.path.partition("?")[0]

            routes = {
                "/api/docs/d-alice": self._docs_alice,
                "/api/docs/d-mallory": self._docs_mallory,
                "/api/invoices/inv-alice": self._invoices_alice,
                "/api/projects/p-alice": self._projects_alice,
                "/api/exports/e-alice": self._exports_alice,
                "/api/admin/audit": self._admin_audit,
                "/api/settings/s-alice": self._settings_alice,
                "/api/wide/w-1": self._wide,
                "/api/beta/b-1": self._beta,
                "/api/reports/r-9": self._reports,
                "/api/echo": self._echo,
            }
            handler = routes.get(path)
            if handler is not None:
                return handler(token)
            if path == "/api/public/notice":
                # No authentication anywhere on this route, by design.
                return self._json(HTTPStatus.OK, {"notice": "scheduled maintenance"})
            if path == "/api/ghost/g-1":
                # Not an authorization decision: the route simply is not there,
                # for anybody, which is exactly why a 404 here proves nothing.
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            # Every other id under a known collection genuinely does not exist,
            # which is what makes the 404 negative control meaningful.
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_DELETE(self) -> None:  # noqa: N802 - standard library callback
            # Present only so the graded suite can declare a mutating verb and
            # observe that no unauthenticated request is sent for it. It never
            # changes state.
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        # -- good routes ----------------------------------------------------

        def _docs_alice(self, token: str) -> None:
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == ALICE_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "d-alice", "body": ALICE_MARKER}
                )
            if guard_path is not None and not guard_path.exists():
                # The tenant predicate is gone: alice's record, marker and all,
                # is served to a principal that must not see it.
                return self._json(
                    HTTPStatus.OK, {"id": "d-alice", "body": ALICE_MARKER}
                )
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        def _docs_mallory(self, token: str) -> None:
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == MALLORY_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "d-mallory", "body": MALLORY_MARKER}
                )
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        def _invoices_alice(self, token: str) -> None:
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == ALICE_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "inv-alice", "line": ALICE_MARKER}
                )
            # This tenant hides existence rather than admitting the record.
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _projects_alice(self, token: str) -> None:
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == ALICE_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "p-alice", "brief": ALICE_MARKER}
                )
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        def _exports_alice(self, token: str) -> None:
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == ALICE_TOKEN:
                return self._json(
                    HTTPStatus.OK, {"id": "e-alice", "rows": ALICE_MARKER}
                )
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _admin_audit(self, token: str) -> None:
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == ROOT_TOKEN:
                return self._json(HTTPStatus.OK, {"id": "audit", "entry": ROOT_MARKER})
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        # -- vacuous routes -------------------------------------------------

        def _settings_alice(self, token: str) -> None:
            """A real boundary that carries no marker anywhere, ever."""
            refusal = self._authenticate(token)
            if refusal is not None:
                return refusal
            if token == ALICE_TOKEN:
                return self._json(HTTPStatus.OK, {"id": "s-alice", "theme": "dark"})
            return self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        def _wide(self, token: str) -> None:
            """Serves alice's record to ANY caller presenting any credential."""
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            return self._json(HTTPStatus.OK, {"id": "w-1", "body": WIDE_MARKER})

        def _beta(self, token: str) -> None:
            """A coarse gate: everyone who is not alice is refused the same way.

            Recognised or not makes no difference here, which is what separates
            "denied because of who you are" from "denied because this feature is
            not switched on for you".
            """
            if not token:
                return self._json(
                    HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
                )
            if token == ALICE_TOKEN:
                return self._json(HTTPStatus.OK, {"id": "b-1", "beta": True})
            return self._json(HTTPStatus.FORBIDDEN, {"error": "beta not enabled"})

        def _reports(self, token: str) -> None:
            """Accepts exactly one token, and nobody in the config holds it."""
            if token == REPORT_TOKEN:
                return self._json(HTTPStatus.OK, {"id": "r-9", "rows": 0})
            return self._json(
                HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
            )

        def _echo(self, token: str) -> None:
            self._json(
                HTTPStatus.OK,
                {"authorization": token, "secret": ECHO_SECRET},
            )

        # -- helpers --------------------------------------------------------

        def _authenticate(self, token: str) -> None | bool:
            """401 unless the credential names a principal the target knows."""
            if token in _KNOWN:
                return None
            self._json(
                HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}
            )
            return True

        def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            """Silent: the grading run prints the only output that matters."""

    return GradedFixtureHandler


def create_server(
    host: str = "127.0.0.1", port: int = 0, *, guard_path: Path | None = None
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(guard_path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--guard-path", type=Path, default=None)
    args = parser.parse_args()
    server = create_server(args.host, args.port, guard_path=args.guard_path)
    print(f"graded fixture listening on http://{args.host}:{server.server_port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
