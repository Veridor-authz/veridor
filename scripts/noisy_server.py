#!/usr/bin/env python3
"""A demo API that is SEMANTICALLY UNCHANGING but realistically noisy.

`scripts/demo_server.py` is deterministic on purpose: it exists so a
walkthrough produces the same bytes every time. That makes it useless for the
one question a drift gate lives or dies by -- *does it stay quiet when nothing
about the authorization boundary has changed?* -- because a target that never
varies cannot answer it.

So this server varies in every way a real one does while keeping the boundary
fixed. Nobody's access changes here, ever. Every difference between two runs is
noise, and every change drift reports against it is a false positive by
construction:

* a fresh ``request_id`` and server ``timestamp`` in every body
* an ``ETag`` and ``Date`` that move
* a collection whose ordering depends on "recently updated", so a given record
  drifts between pages
* transient ``429`` under sustained probing, with ``Retry-After``
* an occasional ``503`` from one flaky dependency
* latency jitter, occasionally past a short client timeout

Rates are exaggerated relative to a healthy production API, deliberately. A
gate that survives this survives a bad afternoon; one that only survives a
quiet target tells you nothing about the day it matters.

    python3.12 scripts/noisy_server.py --port 8765 --seed 7
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: The same marker the deterministic demo plants, so the two are comparable.
OWNER_MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"

_TOKENS = {
    "Bearer owner-token": "acme",
    "Bearer outsider-token": "globex",
    "Bearer admin-token": "internal",
}


class Noise:
    """Every knob, in one place, so a run can be described by its numbers."""

    def __init__(
        self,
        seed: int = 0,
        rate_limit: float = 0.06,
        server_error: float = 0.03,
        slow: float = 0.05,
        slow_seconds: float = 2.5,
        page_size: int = 2,
        leak: bool = False,
    ) -> None:
        self.random = random.Random(seed)
        self.lock = threading.Lock()
        #: The one thing that is NOT noise. Flipping this is a real
        #: authorization regression, and it exists so the same harness can ask
        #: the other half of the question: a gate that never fires is not quiet,
        #: it is broken, and suppressing false positives is only worth
        #: anything if the true positive still gets through.
        self.leak = leak
        self.rate_limit = rate_limit
        self.server_error = server_error
        self.slow = slow
        self.slow_seconds = slow_seconds
        self.page_size = page_size
        self.counter = itertools.count(1)

    def roll(self) -> float:
        with self.lock:
            return self.random.random()

    def request_id(self) -> str:
        with self.lock:
            return f"req-{self.random.getrandbits(48):012x}"


def make_handler(noise: Noise) -> type[BaseHTTPRequestHandler]:
    class NoisyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # -- the boundary, which NEVER changes -------------------------------

        def _tenant(self) -> str | None:
            return _TOKENS.get(self.headers.get("Authorization", ""))

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback
            if self._inject_noise():
                return
            path = self.path.split("?", 1)[0]
            tenant = self._tenant()

            if path == "/api/invoices/inv-100":
                if tenant is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthenticated"})
                elif tenant == "acme" or noise.leak:
                    # Fixed for the whole life of this process unless `leak` is
                    # set. Whatever else moves, this does not.
                    self._json(HTTPStatus.OK, self._invoice())
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return

            if path == "/api/invoices":
                if tenant is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthenticated"})
                    return
                self._json(HTTPStatus.OK, self._collection(tenant))
                return

            if path == "/api/admin/audit":
                if tenant is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthenticated"})
                elif tenant == "internal":
                    self._json(HTTPStatus.OK, {"entries": []})
                else:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return

            self._json(HTTPStatus.NOT_FOUND, {"error": "no route"})

        def do_DELETE(self) -> None:  # noqa: N802
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        def do_POST(self) -> None:  # noqa: N802
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

        # -- the noise -------------------------------------------------------

        def _inject_noise(self) -> bool:
            """Return True when the request was answered with a transient."""
            roll = noise.roll()
            if roll < noise.rate_limit:
                self.send_response(HTTPStatus.TOO_MANY_REQUESTS)
                self.send_header("Retry-After", "1")
                self._finish(b'{"error":"rate limited"}')
                return True
            if roll < noise.rate_limit + noise.server_error:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "upstream"})
                return True
            if roll < noise.rate_limit + noise.server_error + noise.slow:
                time.sleep(noise.slow_seconds)
            return False

        def _invoice(self) -> dict:
            return {
                "id": "inv-100",
                "tenant": "acme",
                "customer_ref": OWNER_MARKER,
                # Body noise: new on every single response.
                "request_id": noise.request_id(),
                "retrieved_at": time.time(),
            }

        def _collection(self, tenant: str) -> dict:
            """Ordering depends on "recently updated", so page 1 is unstable.

            This is the case that matters most. The owner's record carries the
            marker, and whether a scan of page 1 sees it depends on ordering
            that has nothing to do with authorization.
            """
            records = [
                {"id": f"inv-{index}", "tenant": tenant}
                for index in range(100, 100 + 5)
            ]
            if tenant == "acme":
                records[0]["customer_ref"] = OWNER_MARKER
            noise.random.shuffle(records)
            return {
                "items": records[: noise.page_size],
                "next_cursor": noise.request_id(),
                "request_id": noise.request_id(),
            }

        # -- plumbing --------------------------------------------------------

        def _json(self, status: HTTPStatus, body: dict) -> None:
            self.send_response(status)
            self.send_header("ETag", f'W/"{noise.request_id()}"')
            self._finish(json.dumps(body).encode())

        def _finish(self, payload: bytes) -> None:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args) -> None:  # noqa: D102 - silence
            return

    return NoisyHandler


def create_server(host: str, port: int, noise: Noise) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(noise))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--rate-limit", type=float, default=0.06)
    parser.add_argument("--server-error", type=float, default=0.03)
    parser.add_argument("--slow", type=float, default=0.05)
    args = parser.parse_args()
    noise = Noise(
        seed=args.seed,
        rate_limit=args.rate_limit,
        server_error=args.server_error,
        slow=args.slow,
    )
    server = create_server(args.host, args.port, noise)
    print(f"noisy demo API on http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
