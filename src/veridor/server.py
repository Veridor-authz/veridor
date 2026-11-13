"""Small local HTTP server for persisted Veridor artifacts.

This serves the three verbs, not just ``run``. ``map`` and ``mutate`` were wired
to the CLI and then had no viewer at all, so the only way to read a blast radius
or a surviving mutant was to open the JSON by hand -- which is exactly the
friction the integration pass existed to remove.

The three artifact families stay in separate namespaces here for the same reason
they stay in separate directories on disk: **a matrix is not a run and a
candidate is not a finding.** ``/api/runs`` must never be able to return a map,
because a caller written against the run history would then treat a hypothesis
as a finding. Every endpoint below reads exactly one family from exactly one
directory.

Localhost by default and unauthenticated by design: this is a viewer for
artifacts already on your disk, not a hosted control plane. It never writes, and
serves no path outside ``output_dir``.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import re
import socket
import socketserver
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote, urlsplit


_RUN_ID = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_RUN_BYTES = 16 * 1024 * 1024
#: Every asset is served from the package, never from the artifact directory, so
#: a crafted file dropped into ``.veridor/`` can never be returned as script or
#: markup. ``theme.js`` is separate from ``app.js`` because it must run
#: synchronously in ``<head>`` and the CSP forbids inline script.
_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/theme.js": ("theme.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

#: The three documents ``veridor map`` writes for one map id, and the directory
#: each lands in. Keyed by the name the UI uses so the JSON the browser sees
#: does not carry a directory name it would then have to translate.
_MAP_PARTS = {
    "matrix": "matrix",
    "blast_radius": "blast-radius",
    "candidates": "candidates",
}

#: Written only when the operator passed ``--baseline``, so its absence is a
#: fact about the invocation and never an incomplete map. Kept out of
#: :data:`_MAP_PARTS` for exactly that reason: every ordinary map would
#: otherwise report drift as a missing part and read as half-written.
_DRIFT_PART = "drift"


def _capsule_summary(capsule: object) -> dict | None:
    if not isinstance(capsule, dict):
        return None
    return {"verdict": capsule.get("verdict"), "check_id": capsule.get("check_id")}


def _run_summary(run: dict) -> dict:
    gate = run.get("gate")
    return {
        "run_id": run.get("run_id"),
        "started_at": run.get("started_at"),
        "status": run.get("status"),
        # `status` is computed from findings alone and stays "passed" on a run
        # the gate failed with exit 3 for a reason that is not a finding. The
        # list coloured that row green from `status`; the exit code is what
        # tells the two apart. None for a run written without a gate.
        "gate_exit_code": gate.get("exit_code") if isinstance(gate, dict) else None,
        # A capsule verification (`veridor verify`) was listed as an ordinary
        # run, its findings-derived status the only word on the row: an
        # INCONCLUSIVE verification read FAILED. None for an ordinary run.
        "capsule": _capsule_summary(run.get("capsule")),
        "target": run.get("target"),
        "summary": run.get("summary", {}),
    }


def _map_summary(map_id: str, parts: dict[str, dict]) -> dict:
    """Enough to choose a map from a list, and nothing that reads as a verdict.

    ``candidates`` is reported as a count of hypotheses. It is deliberately not
    called a finding count and deliberately not given a status colour by the
    server -- the discipline is that discovery proposes and only a declared
    expectation disposes.
    """
    blast = parts.get("blast_radius") or {}
    candidates = parts.get("candidates") or {}
    matrix = parts.get("matrix") or {}
    drift = parts.get("drift") or {}
    safety = blast.get("safety") or matrix.get("safety") or {}
    return {
        "map_id": map_id,
        # Present only when this map was run against a baseline. `null` means
        # no comparison was asked for -- which is not the same as a comparison
        # that found nothing, and the list must not render them alike.
        "drift": (
            {
                "changes": len(drift.get("changes") or []),
                "significant": drift.get("significant", 0),
            }
            if drift
            else None
        ),
        "target": blast.get("target") or matrix.get("target") or {},
        "inventory": blast.get("inventory") or {},
        "identities": [
            {
                "identity": item.get("identity"),
                "counts": item.get("counts") or {},
            }
            for item in (blast.get("identities") or [])
        ],
        "candidate_count": (candidates.get("counts") or {}).get("candidates", 0),
        "matrix_counts": matrix.get("counts") or {},
        "aborted": bool(safety.get("aborted")),
        "abort_reason": safety.get("abort_reason"),
    }


def _mutation_summary(stem: str, report: dict) -> dict:
    summary = report.get("summary") or {}
    return {
        "stem": stem,
        "tier": report.get("tier"),
        "started_at": report.get("started_at"),
        "completed_at": report.get("completed_at"),
        "target": report.get("target") or {},
        "score": summary.get("score"),
        "generated": summary.get("generated"),
        "killed": summary.get("killed"),
        "survived": summary.get("survived"),
        "errored": summary.get("errored"),
        "aberrant": summary.get("aberrant"),
    }


def _read_artifact(path: Path, root: Path) -> tuple[bytes, dict]:
    """Read one JSON artifact, refusing anything that escapes ``root``.

    Generalised from the run-only reader without loosening any of it: symlinks
    are refused on both the directory and the file, the resolved path must sit
    under the resolved root, and an oversized document is refused rather than
    buffered. ``map`` added three more directories under the same tree, so this
    check now runs on three times as many paths and had to stay exactly as
    strict.
    """
    if root.is_symlink() or path.is_symlink():
        raise OSError("artifact symlinks are not allowed")
    resolved_root = root.resolve()
    resolved = path.resolve(strict=True)
    if resolved_root not in resolved.parents or not resolved.is_file():
        raise OSError("artifact is outside its directory")
    if resolved.stat().st_size > _MAX_RUN_BYTES:
        raise OSError("artifact is too large")
    body = resolved.read_bytes()
    document = json.loads(body)
    if not isinstance(document, dict):
        raise ValueError("artifact must contain an object")
    return body, document


def make_handler(output_dir: Path, host: str = "127.0.0.1") -> type[BaseHTTPRequestHandler]:
    """Build the request handler bound to one artifact directory.

    ``host`` is the address `serve` was told to bind. It is carried here for
    the Host check: a request whose Host is neither that name nor loopback is
    not a request from the operator's own browser at the URL we printed.
    """
    runs_dir = output_dir / "runs"
    mutation_dir = output_dir / "mutation"

    def _load(directory: Path, name: str) -> dict | None:
        try:
            _, document = _read_artifact(directory / f"{name}.json", directory)
        except (OSError, ValueError, json.JSONDecodeError):
            return None
        return document

    def _map_ids() -> list[str]:
        """A map id exists when at least one of its three documents does.

        Not "all three": a run aborted between writes would otherwise vanish
        from the list entirely, which hides the very thing the operator needs
        to see. The detail endpoint reports which parts are missing.
        """
        found: set[str] = set()
        for directory in _MAP_PARTS.values():
            path = output_dir / directory
            if not path.is_dir():
                continue
            for item in path.glob("*.json"):
                if _RUN_ID.fullmatch(item.stem):
                    found.add(item.stem)
        return sorted(found, reverse=True)

    #: Hosts this viewer answers to. Loopback always, plus whatever `serve`
    #: was told to bind, so `--host 0.0.0.0` still works for the operator who
    #: asked for it while a rebound attacker domain does not.
    #: Brackets come off the bound name the same way they come off a request's
    #: Host, so `--host [::1]` and `--host ::1` admit the same requests.
    _allowed_hosts = {"127.0.0.1", "localhost", "::1", _bare(host).lower()}

    class VeridorHandler(BaseHTTPRequestHandler):
        server_version = "VeridorUI/0.2"

        def do_GET(self) -> None:  # noqa: N802 - standard library callback
            if not self._host_allowed():
                # DNS rebinding. There are no CORS headers, so cross-origin JS
                # cannot READ a response -- but a page the user visits can point
                # its own hostname at 127.0.0.1 after the browser has accepted
                # the origin, and then it is same-origin by the browser's rules
                # and reads every run document: targets, finding messages,
                # config paths. The Host header is the only thing that
                # distinguishes that request from a real one, and nothing looked
                # at it. A viewer that serves an attacker's page is worse than
                # no viewer.
                self.send_error(HTTPStatus.MISDIRECTED_REQUEST, "unexpected Host")
                return
            path = unquote(urlsplit(self.path).path)
            if path == "/api/runs":
                self._list_runs()
                return
            if path.startswith("/api/runs/"):
                self._get_run(path.removeprefix("/api/runs/"))
                return
            if path == "/api/maps":
                self._list_maps()
                return
            if path.startswith("/api/maps/"):
                self._get_map(path.removeprefix("/api/maps/"))
                return
            if path == "/api/mutations":
                self._list_mutations()
                return
            if path.startswith("/api/mutations/"):
                self._get_mutation(path.removeprefix("/api/mutations/"))
                return
            if path in _ASSETS:
                self._asset(*_ASSETS[path])
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        # ------------------------------------------------------------ runs

        def _list_runs(self) -> None:
            runs = []
            if runs_dir.exists():
                for path in runs_dir.glob("*.json"):
                    try:
                        _, run = _read_artifact(path, runs_dir)
                    except (OSError, ValueError, json.JSONDecodeError):
                        continue
                    runs.append(_run_summary(run))
            runs.sort(key=lambda item: item.get("started_at") or "", reverse=True)
            self._json({"runs": runs})

        def _get_run(self, run_id: str) -> None:
            if not _RUN_ID.fullmatch(run_id):
                self.send_error(HTTPStatus.BAD_REQUEST, "invalid run id")
                return
            path = runs_dir / f"{run_id}.json"
            try:
                body, _ = _read_artifact(path, runs_dir)
            except FileNotFoundError:
                self.send_error(HTTPStatus.NOT_FOUND, "run not found")
                return
            except (OSError, ValueError, json.JSONDecodeError):
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "invalid run artifact")
                return
            self._send(body, "application/json; charset=utf-8")

        # ------------------------------------------------------------- map

        def _list_maps(self) -> None:
            maps = []
            for map_id in _map_ids():
                parts = {
                    key: _load(output_dir / directory, map_id)
                    for key, directory in _MAP_PARTS.items()
                }
                parts["drift"] = _load(output_dir / _DRIFT_PART, map_id)
                maps.append(_map_summary(map_id, {k: v for k, v in parts.items() if v}))
            self._json({"maps": maps})

        def _get_map(self, map_id: str) -> None:
            if not _RUN_ID.fullmatch(map_id):
                self.send_error(HTTPStatus.BAD_REQUEST, "invalid map id")
                return
            parts = {
                key: _load(output_dir / directory, map_id)
                for key, directory in _MAP_PARTS.items()
            }
            if not any(parts.values()):
                self.send_error(HTTPStatus.NOT_FOUND, "map not found")
                return
            # `missing` is reported rather than silently omitted: a blast radius
            # with no candidates document is not the same thing as a blast
            # radius with zero candidates, and a viewer must not render them
            # identically.
            # Deliberately outside `parts`, so it never lands in `missing`:
            # "no drift document" means no baseline was given, not a map that
            # failed to finish writing itself.
            drift = _load(output_dir / _DRIFT_PART, map_id)
            self._json(
                {
                    "map_id": map_id,
                    "missing": sorted(key for key, value in parts.items() if not value),
                    **parts,
                    "drift": drift or None,
                }
            )

        # ---------------------------------------------------------- mutate

        def _mutation_stems(self) -> list[str]:
            if not mutation_dir.is_dir():
                return []
            return sorted(
                item.stem
                for item in mutation_dir.glob("mutation*.json")
                if _RUN_ID.fullmatch(item.stem)
                # The shields.io badge `mutate` writes beside each report is not
                # a report. Case-folded: a badge is no less a badge for its case.
                and not item.stem.lower().endswith("-badge")
            )

        def _list_mutations(self) -> None:
            reports = []
            for stem in self._mutation_stems():
                report = _load(mutation_dir, stem)
                if report is not None:
                    reports.append(_mutation_summary(stem, report))
            reports.sort(key=lambda item: item.get("completed_at") or "", reverse=True)
            self._json({"mutations": reports})

        def _get_mutation(self, stem: str) -> None:
            if not _RUN_ID.fullmatch(stem) or not stem.startswith("mutation"):
                self.send_error(HTTPStatus.BAD_REQUEST, "invalid mutation id")
                return
            if stem not in self._mutation_stems():
                # Serve only what the list offers. Opening `<stem>.json` directly
                # let a case-insensitive filesystem resolve mutation-Badge to
                # the badge file, past a case-sensitive `-badge` check.
                self.send_error(HTTPStatus.NOT_FOUND, "mutation report not found")
                return
            try:
                body, _ = _read_artifact(mutation_dir / f"{stem}.json", mutation_dir)
            except FileNotFoundError:
                self.send_error(HTTPStatus.NOT_FOUND, "mutation report not found")
                return
            except (OSError, ValueError, json.JSONDecodeError):
                self.send_error(
                    HTTPStatus.INTERNAL_SERVER_ERROR, "invalid mutation artifact"
                )
                return
            self._send(body, "application/json; charset=utf-8")

        # ----------------------------------------------------------- plumbing

        def _asset(self, filename: str, content_type: str) -> None:
            body = files("veridor.web").joinpath(filename).read_bytes()
            self._send(body, content_type)

        def _json(self, value: dict) -> None:
            self._send(
                json.dumps(value, separators=(",", ":")).encode(),
                "application/json; charset=utf-8",
            )

        def _host_allowed(self) -> bool:
            """Only the address this server was told to bind, or loopback.

            A missing Host is refused too: HTTP/1.1 requires one, and the only
            clients that omit it are not browsers.
            """
            host = self.headers.get("Host")
            if not host:
                return False
            return _host_name(host) in _allowed_hosts

        def send_error(self, code, message=None, explain=None):  # noqa: A003
            """Route errors through the same headers the 200 path sets.

            `send_error` builds its own response and bypassed `_send` entirely,
            so a 400, 404 or 500 carried no CSP, no nosniff, and no
            frame-ancestors -- the paths most likely to reflect part of a
            request back. The headers belong to the SERVER, not to the happy
            path.
            """
            self._security_headers_pending = True
            super().send_error(code, message, explain)

        def end_headers(self) -> None:
            if getattr(self, "_security_headers_pending", False):
                self._security_headers_pending = False
                self._add_security_headers()
            super().end_headers()

        def _add_security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # frame-ancestors, so the viewer cannot be embedded and clickjacked
            # by a page that cannot read it directly; no-referrer, so a run id
            # never leaves in a Referer.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")

        def _send(self, body: bytes, content_type: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return VeridorHandler


def _bare(host: str) -> str:
    """``host`` without the brackets a URL puts around an IPv6 literal."""
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def _host_name(header: str) -> str:
    """The name part of a Host header, lower-cased, brackets removed.

    Splitting on the LAST colon is right for ``name:port`` and wrong for an
    IPv6 literal without a port: ``[::1]`` came out as ``[:``, which matched
    nothing, so a browser at ``http://[::1]/`` on port 80 was refused by the
    viewer it was pointed at.

    After the closing bracket only ``:port`` may follow. Taking everything up
    to the first ``]`` and ignoring the rest admitted ``[::1].evil.example``,
    ``[::1]evil`` and ``[::1]@evil.example`` as ``::1`` -- all three were 421
    before IPv6 literals were parsed, and an allow-list that widens on
    malformed input is the wrong way round. Anything else after it is no name.
    """
    header = header.strip()
    if header.startswith("["):
        match = _BRACKETED_HOST.fullmatch(header)
        return match.group(1).lower() if match else ""
    return header.rsplit(":", 1)[0].lower()


#: ``[literal]`` and an optional ``:port`` (RFC 3986 allows the port empty).
_BRACKETED_HOST = re.compile(r"\[([^\[\]]*)\](?::[0-9]*)?")


def _family(host: str) -> socket.AddressFamily:
    """The socket family ``host`` needs: IPv6 for an IPv6 literal, else IPv4.

    ThreadingHTTPServer is AF_INET whatever it is given, so `--host ::1` --
    which the exposure guard accepts as loopback -- failed in bind() with
    "[Errno 8] nodename nor servname provided": an address the CLI calls
    allowed could not be bound at all. A name (``localhost``) keeps IPv4, which
    is what it always resolved to here.
    """
    try:
        return (
            socket.AF_INET6
            if ipaddress.ip_address(_bare(host)).version == 6
            else socket.AF_INET
        )
    except ValueError:
        return socket.AF_INET


def url_host(host: str) -> str:
    """``host`` as it goes between ``http://`` and ``:port``."""
    bare = _bare(host)
    return f"[{bare}]" if ":" in bare else bare


class ListenError(OSError):
    """The viewer could not take its address; the message says which and why."""


class ListeningServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse lookup of its own address.

    ``HTTPServer.server_bind`` calls ``socket.getfqdn(host)`` after ``bind()``
    and before ``listen()``. Where the machine's own hostname does not resolve
    that lookup stalls for about 35s -- every GitHub-hosted macOS runner
    (actions/runner-images#14409, #14568) -- and a client connecting meanwhile
    is neither served nor refused: macOS leaves a SYN to a port that is bound
    but not listening unanswered, so `serve` looked hung. ``server_name`` is
    read only by CGI handlers, and there are none here.
    """

    def __init__(self, server_address, handler, address_family=socket.AF_INET) -> None:
        # Set before TCPServer.__init__, which is where the socket is made.
        self.address_family = address_family
        super().__init__(server_address, handler)

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = self.server_address[1]


def create_server(output_dir: Path, host: str, port: int) -> ThreadingHTTPServer:
    return ListeningServer(
        (_bare(host), port), make_handler(output_dir, host), _family(host)
    )


def _cannot_listen(host: str, port: int, error: OSError) -> ListenError:
    """Turn a bind failure into a sentence naming the address and the way out.

    It was the bare ``[Errno 48] Address already in use``: no address, no
    port, and nothing saying the viewer had not started -- while a browser
    already open at the printed URL keeps talking to whatever DOES hold the
    port, which can be an older `veridor serve` over a different output
    directory.
    """
    address = f"{url_host(host)}:{port}"
    if error.errno == errno.EADDRINUSE:
        return ListenError(
            f"cannot listen on {address}: {error.strerror or error}\n"
            f"  Another process already holds {address}. The viewer did NOT "
            "start; a browser open at that address is talking to that other "
            "process, not to this run history.\n"
            "  Stop that process, or serve on another port (keep any other "
            "options you passed; --port 0 takes any free port and the banner "
            "names it):\n"
            f"    veridor serve --port {port + 1 if port < 65535 else 0}"
        )
    return ListenError(f"cannot listen on {address}: {error}")


def serve(output_dir: Path, host: str, port: int) -> None:
    try:
        server = create_server(output_dir, host, port)
    except OSError as error:
        raise _cannot_listen(host, port, error) from None
    # flush: with stdout a pipe or a file (a supervisor, `> serve.log`) the
    # banner sat in the block buffer until the process exited, so the one line
    # saying where the viewer is came out only after it had stopped.
    print(f"Veridor UI: http://{url_host(host)}:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
