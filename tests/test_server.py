from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

import loopback  # noqa: E402
from tiers import slow  # noqa: E402
from veridor.server import _run_summary, create_server

#: How long the harness waits on its own loopback viewer: a client request, or
#: the server thread's exit after shutdown(). No test here is about a timeout,
#: so this is headroom, not a limit under test. It was 2 s, written out at each
#: of 14 calls, and a slow-tier run at load ~47 reported
#: test_a_map_with_no_baseline_reports_drift_as_null_not_zero as an ERROR from
#: urlopen timing out; it passed alone. With every response delayed 2.5 s, 2 s
#: gives 34 errors (subtests counted) in this module's 20 tests and 10 s gives
#: none; a response delayed 11 s still errors.
HARNESS_TIMEOUT = 10


@slow("stands up a loopback HTTP server and runs the engine against it")
class RunApiSafetyTest(unittest.TestCase):
    def test_symlinked_artifact_is_not_served(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = root / "runs"
            runs.mkdir()
            external = root / "outside.json"
            external.write_text(
                json.dumps({"run_id": "secret", "findings": []}),
                encoding="utf-8",
            )
            (runs / "linked.json").symlink_to(external)

            server = create_server(root, "127.0.0.1", 0)
            thread = loopback.start(server)
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with urlopen(f"{base_url}/api/runs", timeout=HARNESS_TIMEOUT) as response:
                    history = json.load(response)
                self.assertEqual(history["runs"], [])
                with self.assertRaises(HTTPError) as raised:
                    urlopen(f"{base_url}/api/runs/linked", timeout=HARNESS_TIMEOUT)
                self.assertEqual(raised.exception.code, 500)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=HARNESS_TIMEOUT)


@slow("stands up a loopback HTTP server and runs the engine against it")
class BrowserBoundaryTest(unittest.TestCase):
    """The viewer must answer the operator's browser and nothing else.

    There are no CORS headers, so cross-origin JavaScript cannot READ a
    response -- but DNS rebinding defeats that: a page the user visits points
    its own hostname at 127.0.0.1 after the browser has accepted the origin,
    and is then same-origin by the browser's own rules. It reads every run
    document: targets, finding messages, config paths. The Host header is the
    only thing separating that request from a real one, and nothing looked at
    it.
    """

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        (self.root / "runs").mkdir()
        (self.root / "runs" / "run-1.json").write_text(
            json.dumps({"run_id": "run-1", "status": "passed", "summary": {}}),
            encoding="utf-8",
        )
        self.server = create_server(self.root, "127.0.0.1", 0)
        thread = loopback.start(self.server)
        self.port = self.server.server_port

        def stop() -> None:
            self.server.shutdown()
            self.server.server_close()
            thread.join(timeout=HARNESS_TIMEOUT)

        self.addCleanup(stop)

    def _get(self, path: str, host: str | None):
        request = Request(f"http://127.0.0.1:{self.port}{path}")
        if host is not None:
            request.add_header("Host", host)
        return urlopen(request, timeout=HARNESS_TIMEOUT)

    def test_a_rebound_host_is_refused(self) -> None:
        for host in ("evil.example.com", "attacker.test:8877"):
            with self.subTest(host=host):
                with self.assertRaises(HTTPError) as caught:
                    self._get("/api/runs", host)
                self.assertEqual(caught.exception.code, 421)

    def test_loopback_is_answered(self) -> None:
        for host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            with self.subTest(host=host):
                with self._get("/api/runs", host) as response:
                    self.assertEqual(response.status, 200)

    def test_an_error_response_carries_the_same_headers_as_a_200(self) -> None:
        """`send_error` built its own response and bypassed every header.

        400/404/500 are the paths most likely to reflect part of a request,
        and they carried no CSP, no nosniff and no frame-ancestors.
        """
        with self.assertRaises(HTTPError) as caught:
            self._get("/api/runs/../etc/passwd", f"127.0.0.1:{self.port}")
        headers = caught.exception.headers
        self.assertEqual(
            headers["Content-Security-Policy"],
            "default-src 'self'; frame-ancestors 'none'",
        )
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_a_missing_host_is_refused(self) -> None:
        """HTTP/1.1 requires one; the clients that omit it are not browsers."""
        import http.client  # noqa: PLC0415

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=HARNESS_TIMEOUT)
        connection.putrequest("GET", "/api/runs", skip_host=True)
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 421)
        connection.close()


class RunSummaryGateTest(unittest.TestCase):
    """The run list colours each row from its summary, so the summary carries
    the gate's exit code: `status` stays `passed` on a run the gate failed for
    a reason that is not a finding, and the list painted it green."""

    def test_the_gate_exit_code_reaches_the_list(self) -> None:
        run = {"run_id": "run-1", "status": "passed", "summary": {},
               "gate": {"exit_code": 3, "reasons": [{"code": "liveness_unproven"}]}}
        self.assertEqual(_run_summary(run)["gate_exit_code"], 3)

    def test_a_run_without_a_gate_says_so(self) -> None:
        """Control: a run written before the gate was recorded has no exit code,
        which is not the same as exit 0."""
        self.assertIsNone(_run_summary({"run_id": "run-1", "status": "passed"})["gate_exit_code"])


@slow("stands up a loopback HTTP server and runs the engine against it")
class ArtifactFamilyIsolationTest(unittest.TestCase):
    """A matrix is not a run and a candidate is not a finding.

    They live in separate directories on disk for that reason, and the API keeps
    the separation: a caller written against the run history must not be able to
    receive a map, because it would then render a HYPOTHESIS with the vocabulary
    of a finding. Each endpoint reads exactly one family from one directory.
    """

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        for name in ("runs", "matrix", "blast-radius", "candidates", "mutation"):
            (self.root / name).mkdir()
        (self.root / "runs" / "run-1.json").write_text(
            json.dumps({"run_id": "run-1", "status": "passed", "summary": {}}),
            encoding="utf-8",
        )
        for directory in ("matrix", "blast-radius", "candidates"):
            (self.root / directory / "map-1.json").write_text(
                json.dumps({"kind": f"veridor.{directory}", "target": {}}),
                encoding="utf-8",
            )
        (self.root / "mutation" / "mutation.json").write_text(
            json.dumps({"tier": 1, "summary": {"score": 1.0, "survived": 0}}),
            encoding="utf-8",
        )
        self.server = create_server(self.root, "127.0.0.1", 0)
        thread = loopback.start(self.server)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

        def stop() -> None:
            self.server.shutdown()
            self.server.server_close()
            thread.join(timeout=HARNESS_TIMEOUT)

        self.addCleanup(stop)

    def get(self, path: str) -> dict:
        with urlopen(f"{self.base}{path}", timeout=HARNESS_TIMEOUT) as response:
            return json.load(response)

    def test_each_family_is_listed_by_its_own_endpoint(self) -> None:
        self.assertEqual([item["run_id"] for item in self.get("/api/runs")["runs"]], ["run-1"])
        self.assertEqual([item["map_id"] for item in self.get("/api/maps")["maps"]], ["map-1"])
        self.assertEqual(
            [item["stem"] for item in self.get("/api/mutations")["mutations"]],
            ["mutation"],
        )

    def test_a_map_id_is_not_reachable_through_the_run_endpoint(self) -> None:
        with self.assertRaises(HTTPError) as raised:
            urlopen(f"{self.base}/api/runs/map-1", timeout=HARNESS_TIMEOUT)
        self.assertEqual(raised.exception.code, 404)

    def test_a_run_id_is_not_reachable_through_the_map_endpoint(self) -> None:
        with self.assertRaises(HTTPError) as raised:
            urlopen(f"{self.base}/api/maps/run-1", timeout=HARNESS_TIMEOUT)
        self.assertEqual(raised.exception.code, 404)

    def test_a_map_reports_which_of_its_documents_are_missing(self) -> None:
        """Absent is not the same as empty, and the viewer must be able to tell.

        A map whose candidates document never got written would otherwise
        render identically to one that genuinely found nothing -- which is the
        difference between "not measured" and "nothing to see".
        """
        (self.root / "candidates" / "map-1.json").unlink()
        detail = self.get("/api/maps/map-1")
        self.assertEqual(detail["missing"], ["candidates"])
        self.assertIsNotNone(detail["matrix"])

    def test_a_map_survives_losing_all_but_one_document(self) -> None:
        for directory in ("matrix", "candidates"):
            (self.root / directory / "map-1.json").unlink()
        self.assertEqual(
            [item["map_id"] for item in self.get("/api/maps")["maps"]], ["map-1"]
        )

    def _write_drift(self, changes: list[dict], significant: int) -> None:
        (self.root / "drift").mkdir(exist_ok=True)
        (self.root / "drift" / "map-1.json").write_text(
            json.dumps({
                "kind": "veridor.matrix_drift",
                "changes": changes,
                "significant": significant,
                "baseline": {"target": "http://a", "cells": 4},
                "current": {"target": "http://a", "cells": 4},
            }),
            encoding="utf-8",
        )

    def test_a_map_with_no_baseline_reports_drift_as_null_not_zero(self) -> None:
        """Three states, not two. "No comparison was asked for" is not "a
        comparison found nothing", and a viewer that renders them alike tells
        the reader a measurement was taken when none was."""
        self.assertIsNone(self.get("/api/maps")["maps"][0]["drift"])
        self.assertIsNone(self.get("/api/maps/map-1")["drift"])

    def test_a_drift_document_is_summarised_in_the_list(self) -> None:
        self._write_drift([{"kind": "reach_opened", "significant": True}], 1)
        summary = self.get("/api/maps")["maps"][0]["drift"]
        self.assertEqual(summary, {"changes": 1, "significant": 1})

    def test_a_drift_document_is_returned_whole_in_the_detail(self) -> None:
        self._write_drift([{"kind": "status_changed", "significant": False}], 0)
        detail = self.get("/api/maps/map-1")
        self.assertEqual(detail["drift"]["significant"], 0)
        self.assertEqual(len(detail["drift"]["changes"]), 1)

    def test_an_absent_drift_document_is_never_reported_as_missing(self) -> None:
        """`missing` means "this map failed to finish writing itself". Drift is
        written only when --baseline was passed, so listing it there would make
        every ordinary map read as half-written."""
        self.assertNotIn("drift", self.get("/api/maps/map-1")["missing"])
        (self.root / "candidates" / "map-1.json").unlink()
        self.assertEqual(self.get("/api/maps/map-1")["missing"], ["candidates"])

    def test_a_drift_document_alone_does_not_invent_a_map(self) -> None:
        """Drift is keyed by the map it came from. A diff whose matrix cannot
        be found is a comparison nobody can check."""
        for directory in ("matrix", "blast-radius", "candidates"):
            (self.root / directory / "map-1.json").unlink()
        self._write_drift([], 0)
        self.assertEqual(self.get("/api/maps")["maps"], [])

    def test_a_traversing_id_is_refused_on_every_endpoint(self) -> None:
        for path in ("/api/runs/", "/api/maps/", "/api/mutations/"):
            for identifier in ("..%2F..%2Fetc%2Fpasswd", "..", "a/b"):
                with self.subTest(path=path, identifier=identifier):
                    with self.assertRaises(HTTPError) as raised:
                        urlopen(f"{self.base}{path}{identifier}", timeout=HARNESS_TIMEOUT)
                    self.assertIn(raised.exception.code, (400, 404))

    def test_the_badge_file_is_not_offered_as_a_mutation_report(self) -> None:
        """It is a shields.io endpoint document, not a report, and has no score."""
        (self.root / "mutation" / "mutation-badge.json").write_text(
            json.dumps({"schemaVersion": 1, "label": "mutation score"}),
            encoding="utf-8",
        )
        stems = [item["stem"] for item in self.get("/api/mutations")["mutations"]]
        self.assertEqual(stems, ["mutation"])

    def test_the_badge_file_is_not_served_as_a_mutation_report(self) -> None:
        """The list left `-badge` stems out and the detail endpoint did not:
        GET /api/mutations/mutation-badge returned the badge with 200, as if
        it were a report. `mutate` writes one beside every report."""
        badge = {"schemaVersion": 1, "label": "mutation score", "message": "n/a"}
        for stem in ("mutation-badge", "mutation-tier2-badge"):
            (self.root / "mutation" / f"{stem}.json").write_text(json.dumps(badge), encoding="utf-8")
            with self.subTest(stem=stem):
                with self.assertRaises(HTTPError) as raised:
                    urlopen(f"{self.base}/api/mutations/{stem}", timeout=HARNESS_TIMEOUT)
                self.assertEqual(raised.exception.code, 404)
        # Control: the report beside it is still served.
        self.assertNotIn("schemaVersion", self.get("/api/mutations/mutation"))

    def test_the_detail_endpoint_serves_only_stems_the_list_offers(self) -> None:
        """The badge refusal was a case-sensitive `endswith("-badge")`, so on a
        case-insensitive filesystem (APFS, the default on the dev platform)
        /api/mutations/mutation-Badge opened mutation-badge.json and served the
        badge with 200. A file literally named mutation-Badge.json was served
        on any filesystem, and listed too."""
        badge = {"schemaVersion": 1, "label": "mutation score", "message": "n/a"}
        mutation = self.root / "mutation"
        (mutation / "mutation-badge.json").write_text(json.dumps(badge), encoding="utf-8")
        for stem in ("mutation-Badge", "mutation-BADGE"):
            with self.subTest(stem=stem):
                with self.assertRaises(HTTPError) as raised:
                    urlopen(f"{self.base}/api/mutations/{stem}", timeout=HARNESS_TIMEOUT)
                self.assertEqual(raised.exception.code, 404)
        # Filesystem-independent: a badge whose name itself is mixed case.
        (mutation / "mutation-badge.json").unlink()
        (mutation / "mutation-tier2-Badge.json").write_text(json.dumps(badge), encoding="utf-8")
        stems = [item["stem"] for item in self.get("/api/mutations")["mutations"]]
        self.assertEqual(stems, ["mutation"])
        with self.assertRaises(HTTPError) as raised:
            urlopen(f"{self.base}/api/mutations/mutation-tier2-Badge", timeout=HARNESS_TIMEOUT)
        self.assertEqual(raised.exception.code, 404)
        # Control: the report is still served by its listed stem.
        self.assertNotIn("schemaVersion", self.get("/api/mutations/mutation"))

    def test_every_static_asset_the_page_references_is_served(self) -> None:
        """A 404 on any of these is a page that loads broken.

        The stylesheet, the anti-flash theme script and the icon are all
        same-origin by necessity -- the CSP forbids anything else -- so a
        missing one cannot be papered over by a CDN fallback.
        """
        for path, content_type in (
            ("/", "text/html"),
            ("/app.js", "text/javascript"),
            ("/theme.js", "text/javascript"),
            ("/styles.css", "text/css"),
            ("/favicon.svg", "image/svg+xml"),
        ):
            with self.subTest(path=path):
                with urlopen(f"{self.base}{path}", timeout=HARNESS_TIMEOUT) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(content_type, response.headers["Content-Type"])
                    # Assets come from the package, never the artifact
                    # directory, so a crafted file dropped into `.veridor/`
                    # can never be returned as script or markup.
                    self.assertEqual(
                        response.headers["X-Content-Type-Options"], "nosniff"
                    )
                    self.assertEqual(
                        response.headers["Content-Security-Policy"], "default-src 'self'; frame-ancestors 'none'"
                    )

    def test_an_artifact_directory_cannot_impersonate_an_asset(self) -> None:
        (self.root / "app.js").write_text("window.pwned = true;", encoding="utf-8")
        with urlopen(f"{self.base}/app.js", timeout=HARNESS_TIMEOUT) as response:
            body = response.read().decode()
        self.assertNotIn("pwned", body)

    def test_a_symlinked_map_document_is_not_served(self) -> None:
        external = self.root / "outside-map.json"
        external.write_text(json.dumps({"kind": "secret"}), encoding="utf-8")
        (self.root / "matrix" / "linked.json").symlink_to(external)
        with self.assertRaises(HTTPError) as raised:
            urlopen(f"{self.base}/api/maps/linked", timeout=HARNESS_TIMEOUT)
        self.assertEqual(raised.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
