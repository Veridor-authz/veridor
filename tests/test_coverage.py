from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import slow  # noqa: E402
from veridor.coverage import (  # noqa: E402
    AUTHN_STATUSES,
    BADGE_LABEL,
    BANNED_CLAIM_WORDS,
    CLAIM,
    DEFAULT_DENIAL_STATUSES,
    CoverageError,
    classify_expectation,
    compute_coverage,
    coverage_summary,
    format_percent,
    operation_for_check,
    render_badge,
    render_text,
    resolve_base_path,
    wrap_paragraph,
)
from veridor.terminal import ECHO_LIMIT  # noqa: E402
from veridor.openapi import (  # noqa: E402
    DEFAULT_METHODS,
    MAX_PATH_SEGMENTS,
    SpecError,
    load_inventory,
    load_spec,
    match_path,
    nearest_template,
    normalize_path,
    parse_spec,
    split_segments,
    template_specificity,
    undecodable_segments,
)

FIXTURES = ROOT / "fixtures"
DEMO_CONFIG = FIXTURES / "veridor.demo.json"
DEMO_SPEC = FIXTURES / "openapi.demo.json"

_OPENAPI_IMPORTS = {
    "__future__",
    "dataclasses",
    "json",
    "pathlib",
    "re",
    "typing",
    "unicodedata",
    "urllib.parse",
}
_COVERAGE_IMPORTS = {
    "__future__",
    "dataclasses",
    # The near-miss rule for the `coverage` block's keys, core's restated.
    "difflib",
    "datetime",
    "math",
    "pathlib",
    "textwrap",
    "typing",
    "urllib.parse",
    "veridor.openapi",
    # A leaf: stdlib only, no veridor import (TerminalIsALeafTest below), so
    # coverage stays independent of core while quoting input the same way.
    "veridor.terminal",
}


def _spec(paths: dict, **extra) -> dict:
    document = {"openapi": "3.0.3", "info": {"title": "Test API"}, "paths": paths}
    document.update(extra)
    return document


def _get(responses: tuple[int, ...] = (200,)) -> dict:
    return {"get": {"responses": {str(code): {"description": "x"} for code in responses}}}


def _config(checks: list[dict], identities: tuple[str, ...] = ("owner", "other")) -> dict:
    return {
        "version": 1,
        "target": {"base_url": "https://api.example.test"},
        "identities": {name: {"headers": {}} for name in identities},
        "checks": checks,
    }


def _check(check_id: str, path: str, expect: dict, method: str = "GET") -> dict:
    return {
        "id": check_id,
        "request": {"method": method, "path": path},
        "expect": {name: {"status": statuses} for name, statuses in expect.items()},
    }


# ---------------------------------------------------------------------------
# invariants that hold this module to its product claims
# ---------------------------------------------------------------------------


class ModuleInvariantTest(unittest.TestCase):
    """Structural guarantees: stdlib only, offline, acyclic dependencies.

    These are asserted against the import graph rather than the file text, so
    prose in a docstring cannot pass or fail them.
    """

    def _imports(self, module: str) -> set[str]:
        tree = ast.parse((ROOT / "src" / "veridor" / module).read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    self.fail(f"{module} uses a relative import")
                names.add(node.module or "")
        return names

    def test_openapi_imports_stdlib_only(self) -> None:
        self.assertEqual(self._imports("openapi.py"), _OPENAPI_IMPORTS)

    def test_coverage_imports_stdlib_and_openapi_only(self) -> None:
        self.assertEqual(self._imports("coverage.py"), _COVERAGE_IMPORTS)

    def test_coverage_never_imports_core(self) -> None:
        veridor_imports = {
            name for name in self._imports("coverage.py") if name.startswith("veridor")
        }
        self.assertEqual(veridor_imports, {"veridor.openapi", "veridor.terminal"})

    def test_the_terminal_module_it_uses_is_a_leaf(self) -> None:
        self.assertEqual(
            {name for name in self._imports("terminal.py") if name.startswith("veridor")}, set()
        )
        self.assertEqual(
            {name for name in self._imports("openapi.py") if name.startswith("veridor")},
            set(),
        )

    def test_neither_module_imports_a_networking_module(self) -> None:
        forbidden = {"socket", "ssl", "http", "http.client", "urllib.request", "asyncio"}
        for module in ("openapi.py", "coverage.py"):
            self.assertEqual(self._imports(module) & forbidden, set(), module)


# ---------------------------------------------------------------------------
# (b) normalization and route matching
# ---------------------------------------------------------------------------


class NormalizationTest(unittest.TestCase):
    def test_query_and_fragment_are_stripped(self) -> None:
        self.assertEqual(normalize_path("/api/x?limit=10"), "/api/x")
        self.assertEqual(normalize_path("/api/x#frag"), "/api/x")

    def test_dot_segments_are_removed(self) -> None:
        self.assertEqual(normalize_path("/api/x/../invoices/inv-9"), "/api/invoices/inv-9")
        self.assertEqual(normalize_path("/api/./x"), "/api/x")

    def test_exactly_one_trailing_slash_is_stripped(self) -> None:
        self.assertEqual(normalize_path("/api/x/"), "/api/x")
        self.assertEqual(normalize_path("/a//"), "/a/")
        self.assertEqual(normalize_path("/"), "/")

    def test_empty_interior_segment_is_preserved(self) -> None:
        self.assertEqual(split_segments("/a//"), ("a", ""))
        self.assertEqual(split_segments("/a"), ("a",))

    def test_percent_decode_happens_after_split(self) -> None:
        self.assertEqual(split_segments("/api/files/a%2Fb"), ("api", "files", "a/b"))

    def test_template_segments_are_not_decoded(self) -> None:
        self.assertEqual(split_segments("/api/{id}"), ("api", "{id}"))

    def test_undecodable_escape_keeps_raw_segment(self) -> None:
        self.assertEqual(split_segments("/api/x/%FF"), ("api", "x", "%FF"))
        self.assertEqual(undecodable_segments("/api/x/%FF"), ("%FF",))
        self.assertEqual(undecodable_segments("/api/x/%2F"), ())

    def test_specificity_vector(self) -> None:
        self.assertEqual(template_specificity("/api/invoices/{id}"), (2, 2, 0))
        self.assertEqual(template_specificity("/api/{resource}/{id}"), (2, 0, 0))
        self.assertEqual(template_specificity("/api/reports/{id}.json"), (2, 2, 1))


class MatchingTest(unittest.TestCase):
    """The twelve validation cases from the matching spec."""

    TEMPLATES = [
        "/api/invoices/summary",
        "/api/invoices/{id}",
        "/api/{resource}/{id}",
        "/api/files/{id}",
        "/api/files/{a}/{b}",
        "/api/invoices/{id}/x",
        "/api/reports/{id}.json",
        "/a/b/{c}",
        "/a/{b}/c",
        "/a",
        "/",
    ]

    def _match(self, concrete: str, templates=None):
        return match_path(concrete, templates if templates is not None else self.TEMPLATES)

    def test_1_literal_beats_parameter_in_earlier_segment(self) -> None:
        match = self._match("/api/invoices/inv-100")
        self.assertEqual(match.template, "/api/invoices/{id}")
        self.assertEqual(match.score, (2, 2, 0))
        self.assertIn("/api/{resource}/{id}", match.ambiguous_with)

    def test_2_all_literal_template_wins(self) -> None:
        match = self._match("/api/invoices/summary")
        self.assertEqual(match.template, "/api/invoices/summary")
        self.assertEqual(
            match.ambiguous_with, ("/api/invoices/{id}", "/api/{resource}/{id}")
        )

    def test_3_percent_encoded_slash_is_one_segment(self) -> None:
        match = self._match("/api/files/a%2Fb")
        self.assertEqual(match.template, "/api/files/{id}")
        self.assertNotIn("/api/files/{a}/{b}", match.ambiguous_with)

    def test_4_dot_segments_are_resolved_before_matching(self) -> None:
        self.assertEqual(self._match("/api/x/../invoices/inv-9").template,
                         "/api/invoices/{id}")

    def test_5_parameter_does_not_match_empty_segment(self) -> None:
        self.assertIsNone(self._match("/api/invoices//x"))

    def test_6_trailing_slash_matches_but_double_slash_does_not(self) -> None:
        self.assertEqual(self._match("/api/invoices/inv-100/").template,
                         "/api/invoices/{id}")
        self.assertIsNone(self._match("/a//", ["/a"]))

    def test_7_query_string_is_ignored(self) -> None:
        self.assertEqual(self._match("/a?limit=10").template, "/a")

    def test_8_paths_are_case_sensitive(self) -> None:
        self.assertIsNone(self._match("/API/Invoices/inv-1"))

    def test_9_mixed_segment_ranks_between_literal_and_parameter(self) -> None:
        match = self._match("/api/reports/q3.json")
        self.assertEqual(match.template, "/api/reports/{id}.json")
        self.assertEqual(match.score, (2, 2, 1))
        self.assertEqual(match.ambiguous_with, ("/api/{resource}/{id}",))

    def test_10_root_matches_root(self) -> None:
        self.assertEqual(self._match("/").template, "/")

    def test_11_leftmost_literal_precedence(self) -> None:
        self.assertEqual(self._match("/a/b/c").template, "/a/b/{c}")

    def test_12_no_match_returns_none(self) -> None:
        self.assertIsNone(self._match("/nothing/here/at/all"))

    def test_method_availability_breaks_equal_specificity_ties(self) -> None:
        templates = ["/x/{a}", "/x/{b}"]
        prefer = {"/x/{a}": frozenset({"GET"}), "/x/{b}": frozenset({"DELETE"})}
        match = match_path("/x/1", templates, prefer_methods=prefer, method="DELETE")
        self.assertEqual(match.template, "/x/{b}")

    def test_nearest_template_suggests_same_length_near_miss(self) -> None:
        self.assertEqual(
            nearest_template("/v2/export/all", ["/v1/export/{scope}", "/a"]),
            "/v1/export/{scope}",
        )


# ---------------------------------------------------------------------------
# (a) spec parsing
# ---------------------------------------------------------------------------


class SpecParsingTest(unittest.TestCase):
    def _write(self, directory: str, name: str, text: str) -> Path:
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_yaml_content_is_refused_with_conversion_commands(self) -> None:
        yaml = "openapi: 3.0.3\npaths:\n  /a:\n    get: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            # Named .json on purpose: detection is by content, not extension.
            path = self._write(directory, "openapi.json", yaml)
            with self.assertRaises(SpecError) as raised:
                load_spec(path)
        message = str(raised.exception)
        self.assertIn("is not JSON", message)
        self.assertIn("could silently drop routes", message)
        self.assertIn("npx @redocly/cli bundle", message)
        self.assertIn("yaml.safe_load", message)

    def test_document_marker_is_detected_as_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, "spec.yaml", "---\nopenapi: 3.0.3\n")
            with self.assertRaisesRegex(SpecError, "is not JSON"):
                load_spec(path)

    def test_non_yaml_json_error_reports_line_and_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, "spec.json", '{"openapi": "3.0.3",,}')
            with self.assertRaises(SpecError) as raised:
                load_spec(path)
        message = str(raised.exception)
        self.assertIn("invalid JSON", message)
        self.assertIn("line 1", message)
        self.assertIn("column", message)
        self.assertNotIn("npx", message)

    def test_missing_file_is_a_spec_error(self) -> None:
        with self.assertRaisesRegex(SpecError, "cannot read OpenAPI spec"):
            load_spec(Path("/nonexistent/veridor/spec.json"))

    def test_document_without_version_key_lists_top_level_keys(self) -> None:
        with self.assertRaises(SpecError) as raised:
            parse_spec({"info": {}, "paths": {}})
        self.assertIn("neither 'openapi' nor 'swagger'", str(raised.exception))
        self.assertIn("info, paths", str(raised.exception))

    def test_missing_paths_object_is_refused(self) -> None:
        with self.assertRaisesRegex(SpecError, "no usable 'paths' object"):
            parse_spec({"openapi": "3.0.3", "info": {}})

    def test_external_path_item_ref_is_a_hard_error(self) -> None:
        document = _spec({"/a": {"$ref": "other.yaml#/PathItem"}})
        with self.assertRaises(SpecError) as raised:
            parse_spec(document)
        self.assertIn("other.yaml#/PathItem", str(raised.exception))
        self.assertIn("bundle", str(raised.exception))

    def test_external_ref_inside_a_schema_is_invisible(self) -> None:
        document = _spec(
            {
                "/a": {
                    "get": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "shared.yaml#/Invoice"}
                                }
                            }
                        },
                        "responses": {"200": {"$ref": "shared.yaml#/Ok"}},
                    }
                }
            }
        )
        inventory = parse_spec(document)
        self.assertEqual(len(inventory.operations), 1)

    def test_internal_path_item_ref_is_resolved(self) -> None:
        document = _spec(
            {"/a": {"$ref": "#/components/pathItems/Shared"}},
            components={"pathItems": {"Shared": _get()}},
        )
        inventory = parse_spec(document)
        self.assertEqual(inventory.operations[0].key(), ("GET", "/a"))

    def test_internal_ref_cycle_is_refused(self) -> None:
        document = _spec(
            {"/a": {"$ref": "#/components/pathItems/One"}},
            components={
                "pathItems": {
                    "One": {"$ref": "#/components/pathItems/Two"},
                    "Two": {"$ref": "#/components/pathItems/One"},
                }
            },
        )
        with self.assertRaisesRegex(SpecError, "\\$ref cycle"):
            parse_spec(document)

    def test_unresolvable_ref_names_the_pointer(self) -> None:
        document = _spec({"/a": {"$ref": "#/components/pathItems/Missing"}})
        with self.assertRaisesRegex(SpecError, "does not resolve"):
            parse_spec(document)

    def test_swagger_two_basepath_becomes_a_candidate(self) -> None:
        document = {
            "swagger": "2.0",
            "info": {"title": "Legacy"},
            "basePath": "/v1",
            "paths": {"/invoices/{id}": _get()},
        }
        inventory = parse_spec(document)
        self.assertEqual(inventory.spec_version, "2.0")
        self.assertIn("/v1", inventory.base_paths)

    def test_head_and_options_are_excluded_but_recorded(self) -> None:
        document = _spec(
            {
                "/a": {
                    "get": {"responses": {}},
                    "head": {"responses": {}},
                    "options": {"responses": {}},
                }
            }
        )
        inventory = parse_spec(document)
        self.assertEqual(len(inventory.operations), 1)
        reasons = {(entry["method"], entry["reason"]) for entry in inventory.excluded}
        self.assertEqual(
            reasons,
            {("HEAD", "method_not_in_scope"), ("OPTIONS", "method_not_in_scope")},
        )

    def test_deprecated_is_included_by_default_and_removable(self) -> None:
        document = _spec({"/a": {"get": {"deprecated": True, "responses": {}}}})
        self.assertEqual(len(parse_spec(document).operations), 1)
        pruned = parse_spec(document, exclude_deprecated=True)
        self.assertEqual(len(pruned.operations), 0)
        self.assertEqual(pruned.excluded[0]["reason"], "deprecated")

    def test_wildcard_template_is_excluded_with_a_warning(self) -> None:
        inventory = parse_spec(_spec({"/files/{path*}": _get()}))
        self.assertEqual(inventory.operations, ())
        self.assertEqual(inventory.excluded[0]["reason"], "wildcard_unsupported")
        self.assertTrue(
            any("wildcard_unsupported" in warning for warning in inventory.warnings)
        )

    def test_segment_limit_excludes_the_path(self) -> None:
        long_path = "/" + "/".join(f"s{index}" for index in range(MAX_PATH_SEGMENTS + 1))
        inventory = parse_spec(_spec({long_path: _get()}))
        self.assertEqual(inventory.operations, ())
        self.assertEqual(inventory.excluded[0]["reason"], "path_too_long")

    def test_malformed_path_key_is_excluded(self) -> None:
        inventory = parse_spec(_spec({"api/invoices": _get()}))
        self.assertEqual(inventory.excluded[0]["reason"], "malformed_path")

    def test_templated_server_url_uses_variable_default(self) -> None:
        document = _spec(
            {"/a": _get()},
            servers=[
                {
                    "url": "https://api.example.test/{stage}",
                    "variables": {"stage": {"default": "prod"}},
                }
            ],
        )
        self.assertIn("/prod", parse_spec(document).base_paths)

    def test_templated_server_url_without_default_is_dropped(self) -> None:
        document = _spec(
            {"/a": _get()}, servers=[{"url": "https://api.example.test/{stage}"}]
        )
        inventory = parse_spec(document)
        self.assertEqual(inventory.base_paths, ("",))
        self.assertTrue(
            any("templated_server_url" in warning for warning in inventory.warnings)
        )

    def test_operation_level_servers_are_ignored_with_a_warning(self) -> None:
        document = _spec(
            {"/a": {"get": {"servers": [{"url": "https://other.test/x"}], "responses": {}}}}
        )
        inventory = parse_spec(document)
        self.assertTrue(
            any("ignored_operation_servers" in warning for warning in inventory.warnings)
        )

    def test_duplicate_template_keeps_the_first_entry(self) -> None:
        document = _spec({"/a": _get(), "/a/": {"get": {"responses": {"201": {}}}}})
        inventory = parse_spec(document)
        self.assertEqual(len(inventory.operations), 1)
        self.assertTrue(
            any("duplicate_template" in warning for warning in inventory.warnings)
        )

    def test_a_control_character_in_a_path_key_never_reaches_a_warning_raw(self) -> None:
        """`veridor init` prints these warnings with a bare print, so an ESC
        sequence in a hostile spec's path key could clear and repaint the
        operator's terminal. Every other warning quotes the key with repr."""
        evil = "/x\x1b[2J\x1b[31mFORGED"
        servers = _spec(
            {evil: {"get": {"servers": [{"url": "https://other.test/x"}], "responses": {}}}}
        )
        duplicate = _spec({evil: _get(), evil + "/": _get()})
        for label, document, kind in (
            ("operation servers", servers, "ignored_operation_servers"),
            ("duplicate template", duplicate, "duplicate_template"),
        ):
            with self.subTest(label):
                warnings = [w for w in parse_spec(document).warnings if kind in w]
                self.assertEqual(len(warnings), 1)
                self.assertNotIn("\x1b", warnings[0])
                self.assertIn("\\x1b[2J", warnings[0])

    def test_methods_for_reports_in_scope_methods(self) -> None:
        inventory = load_inventory(DEMO_SPEC)
        self.assertEqual(
            inventory.methods_for("/api/invoices/{id}"), frozenset({"GET", "DELETE"})
        )
        self.assertEqual(inventory.templates()[0], "/api/invoices")


# ---------------------------------------------------------------------------
# (c) owner vs challenger
# ---------------------------------------------------------------------------


class ClassificationTest(unittest.TestCase):
    CASES = (
        ([200], "allow_only"),
        ([200, 204], "allow_only"),
        ([403], "denial_only"),
        ([404], "denial_only"),
        ([403, 404], "denial_only"),
        ([401, 403], "denial_only"),
        ([401], "authn_only"),
        ([407], "authn_only"),
        ([200, 404], "permissive"),
        ([200, 403], "permissive"),
        # Not a listed denial, but `run` grades it a refusal all the same.
        ([200, 405], "permissive"),
        ([200, 302], "permissive"),
        ([200, 500], "permissive"),
        ([302], "redirect"),
        ([500], "server_error"),
        ([400], "ambiguous"),
        ([422, 403], "ambiguous"),
    )

    def test_all_documented_cases(self) -> None:
        for statuses, expected in self.CASES:
            with self.subTest(statuses=statuses):
                self.assertEqual(classify_expectation(statuses), expected)

    def test_401_alone_never_counts_as_a_boundary_assertion(self) -> None:
        self.assertNotEqual(classify_expectation([401]), "denial_only")
        self.assertNotIn(401, DEFAULT_DENIAL_STATUSES)
        self.assertEqual(AUTHN_STATUSES, frozenset({401, 407}))

    def test_declared_denial_statuses_are_honoured(self) -> None:
        self.assertEqual(
            classify_expectation([418], denial_statuses=frozenset({418})), "denial_only"
        )

    def test_empty_expectation_is_ambiguous(self) -> None:
        self.assertEqual(classify_expectation([]), "ambiguous")


# ---------------------------------------------------------------------------
# (3.2) base path resolution
# ---------------------------------------------------------------------------


class BasePathTest(unittest.TestCase):
    def _inventory(self):
        return parse_spec(
            _spec(
                {"/api/invoices/{id}": _get()},
                servers=[{"url": "https://api.example.test/v1"}],
            )
        )

    def test_auto_detection_prefers_the_candidate_that_matches(self) -> None:
        config = _config([_check("c", "/v1/api/invoices/inv-1", {"other": [403]})])
        resolution = resolve_base_path(config, self._inventory())
        self.assertEqual(resolution.value, "/v1")
        self.assertEqual(resolution.source, "auto")
        scoreboard = {entry["value"]: entry["matched_checks"] for entry in resolution.candidates}
        self.assertEqual(scoreboard, {"/v1": 1, "": 0})

    def test_scoreboard_reaches_the_report_and_the_text(self) -> None:
        config = _config([_check("c", "/v1/api/invoices/inv-1", {"other": [403]})])
        report = compute_coverage(config, self._inventory())
        self.assertEqual(report["base_path"]["value"], "/v1")
        self.assertEqual(report["base_path"]["source"], "auto")
        self.assertIn("base path: /v1", render_text(report))
        self.assertIn("auto-detected", render_text(report))

    def test_explicit_base_path_with_zero_matches_is_a_hard_error(self) -> None:
        config = _config([_check("c", "/v1/api/invoices/inv-1", {"other": [403]})])
        with self.assertRaises(CoverageError) as raised:
            resolve_base_path(config, self._inventory(), explicit="/v2")
        message = str(raised.exception)
        self.assertIn("--base-path", message)
        self.assertIn("does not silently fall back", message)

    def test_explicit_empty_base_path_is_respected(self) -> None:
        inventory = parse_spec(_spec({"/api/x": _get()}))
        config = _config([_check("c", "/api/x", {"other": [403]})])
        resolution = resolve_base_path(config, inventory, explicit="")
        self.assertEqual(resolution.value, "")
        self.assertEqual(resolution.source, "flag")


# ---------------------------------------------------------------------------
# (d)(f) what counts as covered, at operation granularity
# ---------------------------------------------------------------------------


class CoverageComputationTest(unittest.TestCase):
    def _demo(self, **kwargs):
        config = json.loads(DEMO_CONFIG.read_text(encoding="utf-8"))
        return compute_coverage(
            config,
            load_inventory(DEMO_SPEC),
            config_path=DEMO_CONFIG,
            spec_path=DEMO_SPEC,
            **kwargs,
        )

    def test_demo_fixture_is_two_of_five_operations(self) -> None:
        report = self._demo()
        self.assertEqual(report["status"], "measured")
        self.assertEqual(report["coverage"], 0.4)
        self.assertEqual(report["summary"]["operations"], 5)
        self.assertEqual(report["summary"]["covered"], 2)
        self.assertEqual(report["summary"]["corroborated"], 2)

    def test_delete_is_named_uncovered_where_a_path_metric_would_hide_it(self) -> None:
        report = self._demo()
        uncovered = {(entry["method"], entry["path_template"]): entry["reason"]
                     for entry in report["uncovered"]}
        self.assertEqual(uncovered[("DELETE", "/api/invoices/{id}")], "no_check")
        self.assertNotIn(("GET", "/api/invoices/{id}"), uncovered)
        # The same path is covered for GET: path granularity would report it done.
        self.assertEqual(report["summary"]["path_coverage"], 0.5)

    def test_identity_roles_are_derived_for_the_report_only(self) -> None:
        roles = self._demo()["identity_roles"]
        self.assertEqual(roles["other_tenant"], "challenger")
        self.assertEqual(roles["invoice_owner"], "contextual")
        self.assertEqual(roles["administrator"], "principal-owner")
        self.assertEqual(roles["anonymous"], "authenticator")

    def test_operation_for_check_maps_back_to_the_operation(self) -> None:
        report = self._demo()
        self.assertEqual(
            operation_for_check(report, "invoice-tenant-isolation"),
            {"path_template": "/api/invoices/{id}", "method": "GET"},
        )
        self.assertIsNone(operation_for_check(report, "no-such-check"))

    def test_output_is_deterministic(self) -> None:
        first = self._demo()
        second = self._demo()
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(
            json.dumps(first, sort_keys=False), json.dumps(second, sort_keys=False)
        )

    def test_anonymous_401_only_is_reported_not_counted(self) -> None:
        inventory = parse_spec(_spec({"/api/reports/{id}": _get()}))
        config = _config(
            [_check("r", "/api/reports/9", {"owner": [200], "anonymous": [401]})],
            identities=("owner", "anonymous"),
        )
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 0.0)
        self.assertEqual(report["uncovered"][0]["reason"], "authentication_only")
        self.assertEqual(report["summary"]["authentication_only"], 1)
        text = render_text(report)
        self.assertIn("authentication boundary, not an authorization one", text)

    def test_headerless_identity_expecting_403_counts(self) -> None:
        inventory = parse_spec(_spec({"/api/x": _get()}))
        config = _config([_check("x", "/api/x", {"owner": [200], "other": [403]})])
        self.assertEqual(compute_coverage(config, inventory)["coverage"], 1.0)

    def test_permissive_expectation_is_excluded_with_a_named_diagnostic(self) -> None:
        inventory = parse_spec(_spec({"/api/x": _get()}))
        config = _config([_check("x", "/api/x", {"owner": [200], "other": [200, 404]})])
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 0.0)
        self.assertEqual(report["uncovered"][0]["reason"], "permissive_only")
        codes = {entry["code"] for entry in report["diagnostics"]}
        self.assertIn("permissive_expect", codes)
        message = next(
            entry["message"]
            for entry in report["diagnostics"]
            if entry["code"] == "permissive_expect"
        )
        self.assertIn("[200, 404]", message)
        self.assertIn("accepts both access and denial", message)

    def test_redirect_and_server_error_expectations_are_diagnosed(self) -> None:
        inventory = parse_spec(_spec({"/api/x": _get(), "/api/y": _get()}))
        config = _config(
            [
                _check("x", "/api/x", {"owner": [200], "other": [302]}),
                _check("y", "/api/y", {"owner": [200], "other": [500]}),
            ]
        )
        report = compute_coverage(config, inventory)
        codes = {entry["code"] for entry in report["diagnostics"]}
        self.assertIn("redirect_expect", codes)
        self.assertIn("server_error_expect", codes)
        self.assertEqual(report["coverage"], 0.0)

    def test_all_denied_check_is_covered_but_weak(self) -> None:
        inventory = parse_spec(_spec({"/api/exports/{id}": _get()}))
        config = _config([_check("e", "/api/exports/1", {"owner": [404], "other": [404]})])
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 1.0)
        self.assertEqual(report["summary"]["weak"], 1)
        self.assertEqual(report["summary"]["corroborated"], 0)
        text = render_text(report)
        self.assertIn("Weak coverage", text)
        self.assertIn("this\n  route does not exist", text)

    def test_require_corroboration_promotes_the_stricter_number(self) -> None:
        inventory = parse_spec(_spec({"/api/exports/{id}": _get()}))
        config = _config([_check("e", "/api/exports/1", {"owner": [404], "other": [404]})])
        report = compute_coverage(config, inventory, require_corroboration=True)
        self.assertEqual(report["coverage"], 0.0)
        self.assertEqual(report["uncovered"][0]["reason"], "not_corroborated")

    def test_method_not_in_spec_is_diagnosed_and_credits_nothing(self) -> None:
        inventory = parse_spec(
            _spec({"/api/invoices/{id}": {"get": {"responses": {}}, "put": {"responses": {}}}})
        )
        config = _config(
            [_check("purge", "/api/invoices/1", {"owner": [200], "other": [403]}, "DELETE")]
        )
        report = compute_coverage(config, inventory, allow_no_matches=True)
        diagnostic = next(
            entry for entry in report["diagnostics"] if entry["code"] == "method_not_in_spec"
        )
        self.assertEqual(diagnostic["spec_methods"], ["GET", "PUT"])
        self.assertEqual(report["summary"]["covered"], 0)

    def test_case_mismatch_is_explained_rather_than_silently_matched(self) -> None:
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = _config([_check("c", "/API/Invoices/inv-1", {"other": [403]})])
        report = compute_coverage(config, inventory, allow_no_matches=True)
        codes = {entry["code"] for entry in report["diagnostics"]}
        self.assertIn("case_mismatch", codes)
        self.assertIn("unmatched_check", codes)

    def test_unmatched_check_suggests_the_nearest_route(self) -> None:
        inventory = parse_spec(_spec({"/v1/export/{scope}": _get(), "/api/x": _get()}))
        config = _config(
            [
                _check("legacy-export", "/v2/export/all", {"other": [403]}),
                _check("ok", "/api/x", {"owner": [200], "other": [403]}),
            ]
        )
        report = compute_coverage(config, inventory)
        diagnostic = next(
            entry for entry in report["diagnostics"] if entry["code"] == "unmatched_check"
        )
        self.assertEqual(diagnostic["nearest"], "/v1/export/{scope}")
        self.assertEqual(report["summary"]["unmatched_checks"], 1)

    def test_undecodable_segment_is_diagnosed(self) -> None:
        inventory = parse_spec(_spec({"/api/x/{id}": _get()}))
        config = _config([_check("c", "/api/x/%FF", {"owner": [200], "other": [403]})])
        report = compute_coverage(config, inventory)
        codes = {entry["code"] for entry in report["diagnostics"]}
        self.assertIn("undecodable_segment", codes)
        self.assertEqual(report["coverage"], 1.0)

    def test_two_checks_on_one_path_credit_their_own_operations(self) -> None:
        inventory = parse_spec(
            _spec({"/api/x/{id}": {"get": {"responses": {}}, "delete": {"responses": {}}}})
        )
        config = _config(
            [
                _check("read", "/api/x/1", {"owner": [200], "other": [403]}),
                _check("kill", "/api/x/1", {"owner": [204], "other": [403]}, "DELETE"),
            ]
        )
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 1.0)
        credited = {
            (entry["method"], tuple(record["check_id"] for record in entry["checks"]))
            for entry in report["operations"]
        }
        self.assertEqual(credited, {("GET", ("read",)), ("DELETE", ("kill",))})

    def test_declared_denial_statuses_are_echoed_in_report_and_text(self) -> None:
        inventory = parse_spec(_spec({"/api/x": _get()}))
        config = _config([_check("x", "/api/x", {"owner": [200], "other": [418]})])
        config["coverage"] = {"denial_statuses": [418]}
        report = compute_coverage(config, inventory)
        self.assertEqual(report["policy"]["denial_statuses"], [418])
        self.assertEqual(report["coverage"], 1.0)
        self.assertIn("Denial statuses in use", render_text(report))

    def test_declared_denial_statuses_cannot_relabel_authn_or_access(self) -> None:
        # Declaring 401 or a 2xx as a "denial" turned an authentication-only or
        # allow-only expectation into 100% asserted coverage and a brightgreen
        # badge, while the same report's policy block still said a 401 never
        # counts. The declaration is refused instead of honoured.
        inventory = parse_spec(_spec({"/api/x": _get()}))
        cases = (
            ([401, 403, 404], {"owner": [200], "anonymous": [401]}),
            ([407, 403], {"owner": [200], "anonymous": [407]}),
            ([200, 403], {"owner": [200], "anonymous": [200]}),
            ([302, 403], {"owner": [200], "anonymous": [302]}),
            ([500, 403], {"owner": [200], "anonymous": [500]}),
        )
        for declared, expect in cases:
            with self.subTest(declared=declared):
                config = _config(
                    [_check("x", "/api/x", expect)], identities=tuple(expect)
                )
                config["coverage"] = {"denial_statuses": declared}
                with self.assertRaises(CoverageError) as caught:
                    compute_coverage(config, inventory)
                self.assertIn("coverage.denial_statuses", str(caught.exception))
                self.assertIsNone(getattr(caught.exception, "report", None))
                with self.assertRaises(CoverageError):
                    compute_coverage(
                        _config(
                            [_check("x", "/api/x", expect)], identities=tuple(expect)
                        ),
                        inventory,
                        denial_statuses=frozenset(declared),
                    )
        # Control: a non-default 4xx refusal is still honoured.
        config = _config([_check("x", "/api/x", {"owner": [200], "other": [418]})])
        config["coverage"] = {"denial_statuses": [403, 418]}
        self.assertEqual(compute_coverage(config, inventory)["coverage"], 1.0)

    def test_excluded_operations_are_printed_above_the_headline(self) -> None:
        inventory = parse_spec(
            _spec({"/api/x": {"get": {"responses": {}}, "options": {"responses": {}}}})
        )
        config = _config([_check("x", "/api/x", {"owner": [200], "other": [403]})])
        text = render_text(compute_coverage(config, inventory))
        self.assertIn("excluded:  1 operations (1 OPTIONS)", text)
        self.assertLess(text.index("excluded:"), text.index("Authorization boundary"))

    def test_majority_unmatched_prints_a_warning_banner(self) -> None:
        inventory = parse_spec(_spec({"/api/x": _get()}))
        config = _config(
            [
                _check("a", "/api/x", {"owner": [200], "other": [403]}),
                _check("b", "/nope/1", {"other": [403]}),
                _check("c", "/nope/2", {"other": [403]}),
            ]
        )
        text = render_text(compute_coverage(config, inventory))
        self.assertIn("WARNING: 2 of 3 checks matched no operation", text)


class CoverageBlockShapeTest(unittest.TestCase):
    """The `coverage` block is read as written, or refused before computing.

    `_denial_statuses` read `section.get("denial_statuses")` and nothing else,
    so a misspelt `Denial_Statuses`, `denail_statuses` or `denialstatuses`, a
    `null`, or a `coverage` that was a list, a string or null all loaded and
    were measured against the default 403 and 404 -- even when the misspelt
    value was one the 4xx rule refuses, such as [401]. On the demo config a
    declared [403] scored 20% and the same block misspelt scored 40%, exit 0,
    with no policy line (measured). The schema refuses every one of
    these, so an editor flagged the typo while the tool accepted it.
    """

    #: Only 404 is a refusal here, so the declared [403] scores 0% and the
    #: default {403, 404} scores 100%: a block that silently falls back to the
    #: default moves the figure, which is what makes the refusal load-bearing.
    EXPECT = {"owner": [200], "other": [404]}

    def _measure(self, block: object) -> dict:
        config = _config([_check("x", "/api/x", self.EXPECT)])
        config["coverage"] = block
        return compute_coverage(config, parse_spec(_spec({"/api/x": _get()})))

    def test_the_fallback_moves_the_figure(self) -> None:
        """Control: what the refusals below prevent is a real change."""
        self.assertEqual(self._measure({"denial_statuses": [403]})["coverage"], 0.0)
        self.assertEqual(self._measure({})["coverage"], 1.0)

    def test_a_misspelt_key_is_refused_and_named(self) -> None:
        for typo in ("Denial_Statuses", "denail_statuses", "denialstatuses",
                     "denial-statuses", "DENIAL_STATUSES", "denial_statsues"):
            for value in ([403], [401]):
                with self.subTest(typo=typo, value=value):
                    with self.assertRaises(CoverageError) as caught:
                        self._measure({typo: value})
                    message = str(caught.exception)
                    self.assertIn(f"did you mean 'denial_statuses' for {typo!r}", message)
                    self.assertIsNone(getattr(caught.exception, "report", None))

    def test_any_other_unknown_key_is_refused(self) -> None:
        for block in ({"note": "x"}, {"denial_statuses": [403], "statuses": [418]},
                      {"fail_under": 80}):
            with self.subTest(block=block):
                with self.assertRaises(CoverageError) as caught:
                    self._measure(block)
                self.assertIn("coverage has unsupported keys", str(caught.exception))
                self.assertIn("start it with '_'", str(caught.exception))

    def test_a_null_denial_statuses_is_refused(self) -> None:
        with self.assertRaises(CoverageError) as caught:
            self._measure({"denial_statuses": None})
        self.assertIn("coverage.denial_statuses", str(caught.exception))

    def test_a_coverage_that_is_not_an_object_is_refused(self) -> None:
        for block in ([403], None, "403", 403, True, []):
            with self.subTest(block=block):
                with self.assertRaises(CoverageError) as caught:
                    self._measure(block)
                self.assertIn("coverage must be an object", str(caught.exception))

    def test_annotations_and_an_empty_block_still_load(self) -> None:
        """Control: '_' keys are annotations here as everywhere, and a block
        that declares nothing keeps the default."""
        report = self._measure({"_note": "ours", "_denial_statuses": [418],
                                "denial_statuses": [403]})
        self.assertEqual(report["coverage"], 0.0)
        self.assertEqual(report["policy"]["denial_statuses"], [403])
        self.assertEqual(self._measure({"_note": "ours"})["policy"]["denial_statuses"],
                         [403, 404])

    def test_the_near_miss_rule_is_the_loader_s(self) -> None:
        """coverage cannot import core, so it carries its own copy of the
        near-miss rule; it must agree with core's on every slip and non-slip."""
        from veridor import core  # noqa: PLC0415
        from veridor import coverage as coverage_module  # noqa: PLC0415

        known = coverage_module.COVERAGE_KEYS
        for key in ("Denial_Statuses", "denail_statuses", "denialstatuses",
                    "denial_statsues", "denial-statuses", "denial_status",
                    "denials", "statuses", "note", "fail_under", "", "_", "403"):
            with self.subTest(key=key):
                self.assertEqual(coverage_module._nearest_key(key, known),
                                 core._nearest_key(key, known))


# ---------------------------------------------------------------------------
# (h) undefined measurements
# ---------------------------------------------------------------------------


class UndefinedMeasurementTest(unittest.TestCase):
    def test_empty_paths_is_undefined_not_zero_percent(self) -> None:
        inventory = parse_spec(_spec({}))
        config = _config([_check("x", "/api/x", {"other": [403]})])
        with self.assertRaises(CoverageError) as raised:
            compute_coverage(config, inventory)
        report = raised.exception.report
        self.assertEqual(report["status"], "empty_inventory")
        self.assertIsNone(report["coverage"])
        badge = render_badge(report)
        self.assertEqual(badge["message"], "unknown")
        self.assertEqual(badge["color"], "lightgrey")
        self.assertTrue(badge["isError"])
        text = render_text(report)
        self.assertIn("not measured (empty_inventory)", text)
        self.assertNotIn("0.0%", text)
        self.assertNotIn("100.0%", text)

    def test_zero_matches_is_undefined_and_prints_the_scoreboard(self) -> None:
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = _config([_check("x", "/totally/other/1", {"other": [403]})])
        with self.assertRaises(CoverageError) as raised:
            compute_coverage(config, inventory, spec_path="openapi.json")
        message = str(raised.exception)
        self.assertIn("is undefined and is not reported as 0%", message)
        self.assertIn("base-path candidates scored", message)
        self.assertIn("example config paths", message)
        self.assertIn("example spec routes", message)
        self.assertIn("--base-path", message)
        report = raised.exception.report
        self.assertEqual(report["status"], "no_matches")
        self.assertIsNone(report["coverage"])

    def test_no_checks_at_all_is_diagnosed_as_no_checks(self) -> None:
        """`map` accepts a config with no checks, so this message is the first
        thing a user on the zero-declaration path reads. The generic message
        blames a path-prefix mismatch, which here is simply the wrong cause."""
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = _config([])
        with self.assertRaises(CoverageError) as raised:
            compute_coverage(config, inventory, spec_path="openapi.json")
        message = str(raised.exception)
        self.assertIn("declares no checks", message)
        self.assertIn("`map` and drift need no checks", message)
        # The wrong diagnosis must not appear.
        self.assertNotIn("different prefixes", message)
        self.assertNotIn("--base-path", message)
        # Still undefined rather than 0%: the discipline does not relax.
        self.assertIn("undefined here, not 0%", message)
        self.assertIsNone(raised.exception.report["coverage"])

    def test_allow_no_matches_returns_the_report_without_raising(self) -> None:
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = _config([_check("x", "/totally/other/1", {"other": [403]})])
        report = compute_coverage(config, inventory, allow_no_matches=True)
        self.assertEqual(report["status"], "no_matches")
        self.assertIsNone(report["coverage"])
        self.assertIsNone(report["summary"]["path_coverage"])
        text = render_text(report)
        self.assertIn("not measured (no_matches)", text)
        # No ratio is rendered at all -- not as 0%, not as a headline.
        self.assertNotIn("operations (", text)
        self.assertNotIn("Path-level coverage", text)


# ---------------------------------------------------------------------------
# (e) the honest claim boundary -- enforced, not aspirational
# ---------------------------------------------------------------------------


class HonestClaimTest(unittest.TestCase):
    def _report(self, coverage_ratio: str = "partial") -> dict:
        paths = {"/api/a": _get(), "/api/b": _get()}
        checks = [_check("a", "/api/a", {"owner": [200], "other": [403]})]
        if coverage_ratio == "full":
            checks.append(_check("b", "/api/b", {"owner": [200], "other": [403]}))
        return compute_coverage(_config(checks), parse_spec(_spec(paths)))

    def test_badge_label_is_exactly_the_agreed_wording(self) -> None:
        badge = render_badge(self._report())
        self.assertEqual(badge["label"], "authz denial asserted")
        self.assertEqual(badge["label"], BADGE_LABEL)

    def test_badge_message_ends_in_asserted(self) -> None:
        badge = render_badge(self._report())
        self.assertTrue(badge["message"].endswith(" asserted"), badge["message"])

    def test_badge_never_claims_the_target_was_tested(self) -> None:
        """`veridor coverage` issues no request, so nothing was tested.

        The badge is the artifact that travels furthest from its context, and
        `tested` is precisely the enforcement claim CLAIM['does_not_measure']
        disclaims. It must not reappear in the label or the message.
        """
        for report in (self._report(), self._report("full")):
            badge = render_badge(report)
            self.assertNotIn("tested", f"{badge['label']} {badge['message']}")
        undefined = render_badge({"status": "undefined"})
        self.assertNotIn("tested", f"{undefined['label']} {undefined['message']}")

    def test_badge_never_uses_banned_vocabulary(self) -> None:
        badge = render_badge(self._report())
        blob = json.dumps(badge).lower()
        for word in BANNED_CLAIM_WORDS:
            self.assertNotIn(word, blob)

    def test_badge_colour_thresholds(self) -> None:
        self.assertEqual(render_badge(self._report("full"))["color"], "brightgreen")
        self.assertEqual(render_badge(self._report())["color"], "orange")

    def test_report_carries_the_claim_object(self) -> None:
        report = self._report()
        self.assertIn("claim", report)
        self.assertEqual(report["claim"]["does_not_measure"], CLAIM["does_not_measure"])
        self.assertIn("enforced at runtime", report["claim"]["does_not_measure"])
        self.assertIn("tested, not proven", report["claim"]["statement"])

    def test_the_claim_states_the_rule_the_code_applies(self) -> None:
        """compute_coverage has no owner concept: it credits a denial-only
        expectation for ANY identity, whatever its name. The statement written
        into every report said "for at least one non-owner identity", a
        stricter rule than the code applies and than the README states."""
        inventory = parse_spec(_spec({"/api/x": _get()}))
        config = _config([_check("x", "/api/x", {"owner": [403], "other": [200]})])
        self.assertEqual(compute_coverage(config, inventory)["coverage"], 1.0)
        statement = CLAIM["statement"]
        self.assertNotIn("owner", statement)
        self.assertIn("denial-only outcome for at least one identity", statement)
        readme = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
        self.assertIn("outcome for at least one identity", " ".join(readme.split()))

    def test_rendered_text_contains_no_banned_word(self) -> None:
        for report in (self._report(), self._report("full")):
            text = render_text(report).lower()
            for word in BANNED_CLAIM_WORDS:
                self.assertNotIn(word, text, f"rendered text used {word!r}")

    def test_claim_paragraph_is_always_printed(self) -> None:
        inventory = parse_spec(_spec({"/api/a": _get()}))
        undefined = compute_coverage(
            _config([_check("x", "/no", {"other": [403]})]),
            inventory,
            allow_no_matches=True,
        )
        for report in (self._report(), self._report("full"), undefined):
            text = render_text(report)
            self.assertIn("is ASSERTED for each", text)
            self.assertIn("does not measure whether authorization is ENFORCED", text)
            self.assertIn("Run `veridor run` to test enforcement.", text)

    def test_the_console_prints_the_corroborated_figure_it_defines(self) -> None:
        """The paragraph defined `corroborated` and promised "both figures
        below", and no figure followed: the count lived only in the JSON."""
        config = json.loads(DEMO_CONFIG.read_text(encoding="utf-8"))
        report = compute_coverage(config, load_inventory(DEMO_SPEC),
                                  config_path=DEMO_CONFIG, spec_path=DEMO_SPEC)
        self.assertIn("\nCorroborated: 2/5 operations\n", render_text(report))
        # Control: the figure moves with the configuration. No check declares a
        # served identity here, so the same denial is asserted and uncorroborated.
        weak = compute_coverage(_config([_check("x", "/api/a", {"other": [403]})]),
                                parse_spec(_spec({"/api/a": _get()})))
        self.assertEqual(weak["summary"]["corroborated"], 0)
        self.assertIn("\nCorroborated: 0/1 operations\n", render_text(weak))
        # Where nothing is measured there is no figure, and no definition of one.
        undefined = compute_coverage(_config([_check("x", "/no", {"other": [403]})]),
                                     parse_spec(_spec({"/api/a": _get()})),
                                     allow_no_matches=True)
        self.assertNotIn("orroborated", render_text(undefined))

    def test_full_coverage_appends_the_enforcement_caveat(self) -> None:
        text = render_text(self._report("full"))
        self.assertIn("(100.0%)", text)
        self.assertIn("All inventoried operations have a denial asserted.", text)
        self.assertIn("This does not mean all are correctly enforced.", text)

    def test_coverage_summary_carries_the_claim_into_embedded_documents(self) -> None:
        summary = coverage_summary(self._report())
        self.assertEqual(summary["does_not_measure"], CLAIM["does_not_measure"])
        self.assertEqual(summary["status"], "measured")
        self.assertEqual(summary["coverage"], 0.5)

    def test_unwired_helpers_do_not_describe_a_caller(self) -> None:
        """coverage_summary said it was the block embedded in run documents
        and SARIF, and operation_for_check that core.py used it to attach a
        finding property. Nothing in src calls either, so no finding and no
        SARIF output carries what they describe. A docstring may name a caller
        only while one exists."""
        import veridor.coverage as coverage_module  # noqa: PLC0415

        referenced: set[str] = set()
        for path in (ROOT / "src" / "veridor").rglob("*.py"):
            if path.name == "coverage.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Name):
                    referenced.add(node.id)
                elif isinstance(node, ast.Attribute):
                    referenced.add(node.attr)
                elif isinstance(node, ast.alias):
                    referenced.add(node.name)
        # Control: the scan sees the coverage functions the CLI does call.
        self.assertLessEqual({"compute_coverage", "render_text", "classify_expectation"}, referenced)
        for name in ("coverage_summary", "operation_for_check"):
            with self.subTest(name=name):
                doc = " ".join((getattr(coverage_module, name).__doc__ or "").split())
                if name in referenced:
                    continue
                self.assertIn("No Veridor command calls this", doc)
                self.assertNotIn("Used by", doc)

    def test_policy_block_states_that_authn_does_not_count(self) -> None:
        policy = self._report()["policy"]
        self.assertEqual(policy["unit"], "operation")
        self.assertFalse(policy["authn_counts_as_coverage"])
        self.assertEqual(policy["denial_statuses"], [403, 404])
        self.assertEqual(policy["methods"], sorted(DEFAULT_METHODS))


# ---------------------------------------------------------------------------
# (10.2) the run document must not change when no spec is supplied
# ---------------------------------------------------------------------------


@slow("drives a live HTTP target over the network")
class RunSummaryShapeTest(unittest.TestCase):
    """Guards the exact dict equality assertion in scripts/e2e_validation.py.

    Only the coverage half of that invariant is asserted here: a run invoked
    without a spec must gain no coverage key anywhere. The historical summary
    keys are checked as a subset, because ``core.py`` is owned elsewhere and may
    legitimately add unrelated fields.
    """

    HISTORICAL_KEYS = frozenset(
        {
            "checks",
            "probes",
            "safe",
            "vulnerable",
            "inconclusive",
            "new",
            "resolved",
            "unchanged",
        }
    )

    def test_execute_run_without_openapi_adds_no_coverage(self) -> None:
        from veridor.core import execute_run

        config = {
            "version": 1,
            "target": {"base_url": "http://127.0.0.1:1", "timeout_seconds": 1},
            "identities": {"owner": {"headers": {}}, "other": {"headers": {}}},
            "checks": [_check("x", "/api/x", {"owner": [200], "other": [403]})],
        }
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "veridor.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            result = execute_run(config_path, output_dir=Path(directory) / "out")
        self.assertLessEqual(self.HISTORICAL_KEYS, set(result["summary"]))
        self.assertNotIn("boundary_coverage", result["summary"])
        self.assertNotIn("coverage", result)


class PerOperationBasePathTest(unittest.TestCase):
    """``servers`` is a list, and a path item may override the document's."""

    def test_a_path_item_server_override_is_honoured(self) -> None:
        """Folding every operation under one prefix relabels the odd one out.

        The spec places /admin/audit at /v2. Crediting a check that hits
        /api/admin/audit to it reports 100% over a route with no assertion,
        and prints an absolute_path that contradicts the spec it just read.
        """
        inventory = parse_spec(
            _spec(
                {
                    "/orders/{id}": _get(),
                    "/admin/audit": {
                        "servers": [{"url": "https://api.example.test/v2"}],
                        **_get(),
                    },
                },
                servers=[{"url": "https://api.example.test/api"}],
            )
        )
        config = _config(
            [
                _check("orders", "/api/orders/o1", {"owner": [200], "other": [404]}),
                _check("audit", "/api/admin/audit", {"owner": [200], "other": [403]}),
            ]
        )
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 0.5)
        routes = {
            entry["path_template"]: (entry["absolute_path"], entry["covered"])
            for entry in report["operations"]
        }
        self.assertEqual(routes["/admin/audit"], ("/v2/admin/audit", False))
        self.assertEqual(routes["/orders/{id}"], ("/api/orders/{id}", True))
        self.assertIn(
            "unmatched_check", {entry["code"] for entry in report["diagnostics"]}
        )
        self.assertEqual(render_badge(report)["message"], "50.0% asserted")

    def test_every_declared_server_prefix_can_satisfy_an_operation(self) -> None:
        """Two server entries mean the API is served at both, not either."""
        inventory = parse_spec(
            _spec(
                {"/orders/{id}": _get(), "/health": _get()},
                servers=[
                    {"url": "https://api.example.test/api"},
                    {"url": "https://api.example.test/api/v2"},
                ],
            )
        )
        config = _config(
            [
                _check("c1", "/api/health", {"owner": [200], "other": [403]}),
                _check("c2", "/api/v2/orders/o1", {"owner": [200], "other": [404]}),
            ]
        )
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 1.0)
        self.assertEqual(report["diagnostics"], [])
        self.assertNotIn(
            "/api/v2/health",
            {entry["absolute_path"] for entry in report["uncovered"]},
        )

    def test_an_explicit_base_path_still_overrides_the_spec(self) -> None:
        inventory = parse_spec(
            _spec(
                {"/orders/{id}": _get()},
                servers=[{"url": "https://api.example.test/api"}],
            )
        )
        config = _config([_check("c", "/forced/orders/o1", {"other": [403]})])
        report = compute_coverage(config, inventory, base_path="/forced")
        self.assertEqual(report["coverage"], 1.0)
        self.assertEqual(
            report["operations"][0]["absolute_path"], "/forced/orders/{id}"
        )


class TargetPrefixTest(unittest.TestCase):
    def test_the_target_path_prefixes_the_check_not_the_spec(self) -> None:
        """core builds the URL as base_url + request.path, so coverage must too.

        With the prefix fed to the spec side instead, no --base-path value can
        align a configuration whose probes demonstrably hit the declared route.
        """
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = {
            "version": 1,
            "target": {"base_url": "https://api.example.test/api"},
            "identities": {"owner": {"headers": {}}, "other": {"headers": {}}},
            "checks": [
                _check("inv", "/invoices/inv-1", {"owner": [200], "other": [404]})
            ],
        }
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 1.0)
        self.assertEqual(report["operations"][0]["covered"], True)

    def test_a_target_without_a_path_is_unchanged(self) -> None:
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = _config(
            [_check("inv", "/api/invoices/inv-1", {"owner": [200], "other": [404]})]
        )
        self.assertEqual(compute_coverage(config, inventory)["coverage"], 1.0)


class TemplatedCheckPathTest(unittest.TestCase):
    def test_an_unsubstituted_placeholder_credits_nothing(self) -> None:
        """`veridor init` writes templates; until they are replaced they are
        not requests anyone can issue, so they cannot earn coverage."""
        inventory = parse_spec(
            _spec({"/api/invoices/{id}": _get(), "/api/health": _get()})
        )
        config = _config(
            [
                _check(
                    "c1", "/api/invoices/{id}", {"owner": [200], "other": [404]}
                ),
                _check("c2", "/api/health", {"owner": [200], "other": [403]}),
            ]
        )
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 0.5)
        codes = [entry["code"] for entry in report["diagnostics"]]
        self.assertIn("templated_check_path", codes)
        diagnostic = next(
            entry
            for entry in report["diagnostics"]
            if entry["code"] == "templated_check_path"
        )
        self.assertEqual(diagnostic["severity"], "error")
        self.assertEqual(diagnostic["check_id"], "c1")

    def test_a_substituted_path_is_credited_normally(self) -> None:
        inventory = parse_spec(_spec({"/api/invoices/{id}": _get()}))
        config = _config(
            [_check("c1", "/api/invoices/inv-1", {"owner": [200], "other": [404]})]
        )
        report = compute_coverage(config, inventory)
        self.assertEqual(report["coverage"], 1.0)
        self.assertEqual(report["diagnostics"], [])


class UnreviewedScaffoldTest(unittest.TestCase):
    """An unedited `veridor init` file must not hand out a publishable number.

    REGRESSION. ``init`` declares 'owner allowed, other_tenant denied' for
    every in-scope operation, so every generated check is denial-only for a
    non-owner and an untouched scaffold scores 100%. The badge is the artefact
    most likely to be published from that, and it was rendering brightgreen
    before a human had read a line of the file.
    """

    def _inventory(self):
        return parse_spec(_spec({"/api/invoices/inv-1": _get()}))

    def _config(self, generated: bool) -> dict:
        config = _config(
            [_check("c1", "/api/invoices/inv-1", {"owner": [200], "other": [404]})]
        )
        if generated:
            config["_generated_by"] = "veridor init --openapi openapi.json"
        return config

    def test_a_scaffold_that_still_says_so_gets_no_percentage_badge(self) -> None:
        report = compute_coverage(self._config(True), self._inventory())
        self.assertEqual(report["coverage"], 1.0)
        self.assertTrue(report["config"]["unreviewed_scaffold"])
        badge = render_badge(report)
        self.assertEqual(badge["message"], "unreviewed")
        self.assertEqual(badge["color"], "lightgrey")
        self.assertTrue(badge["isError"])
        self.assertNotIn("100", json.dumps(badge))

    def test_the_rendered_report_says_the_number_is_not_yours_yet(self) -> None:
        text = render_text(compute_coverage(self._config(True), self._inventory()))
        self.assertIn("THIS NUMBER IS NOT YOURS YET", text)
        self.assertIn("_generated_by", text)
        # the measurement itself is unchanged and still printed
        self.assertIn("100.0%", text)

    def test_removing_the_generated_marker_claims_the_number(self) -> None:
        report = compute_coverage(self._config(False), self._inventory())
        self.assertFalse(report["config"]["unreviewed_scaffold"])
        self.assertEqual(render_badge(report)["message"], "100.0% asserted")
        self.assertNotIn("NOT YOURS YET", render_text(report))


class PercentRenderingTest(unittest.TestCase):
    def test_a_near_miss_never_renders_as_a_saturated_bound(self) -> None:
        self.assertEqual(format_percent(1999, 2000), "99.9%")
        self.assertEqual(format_percent(19999, 20000), "99.9%")
        self.assertEqual(format_percent(1, 2500), "<0.1%")
        self.assertEqual(format_percent(2000, 2000), "100.0%")
        self.assertEqual(format_percent(0, 2000), "0.0%")

    @slow("builds a 2,000-operation inventory to reach the rounding boundary")
    def test_a_single_uncovered_operation_never_earns_a_full_badge(self) -> None:
        total = 2000
        paths = {f"/api/r{index}": _get() for index in range(total)}
        config = _config(
            [
                _check(f"c{index}", f"/api/r{index}", {"owner": [200], "other": [403]})
                for index in range(1, total)
            ]
        )
        report = compute_coverage(config, parse_spec(_spec(paths)))
        self.assertEqual(report["summary"]["covered"], total - 1)
        self.assertLess(report["coverage"], 1.0)
        self.assertEqual(render_badge(report)["message"], "99.9% asserted")
        text = render_text(report)
        self.assertIn(f"{total - 1}/{total} operations (99.9%)", text)
        self.assertNotIn("100.0%", text)

    def test_the_stored_ratio_never_rounds_up_to_one(self) -> None:
        """round(19999/20000, 4) is exactly 1.0, and MAX_OPERATIONS is 20,000.

        A JSON consumer reading ``coverage: 1.0`` for an inventory with an
        untested authorization boundary is the same lie as the badge.

        The stored ratios are checked by value, not by spying on ``round``: a
        spy saw only the method used, so a ratio cut to 4 places some other
        way (``float(f"{x:.4f}")``) passed while the other ratio still called
        ``round``. 6/7 needs 6 places to land within 1e-6 of itself
        (0.857143); 0.8571 misses by 4e-5.
        """
        paths = {f"/api/r{index}": _get() for index in range(7)}
        config = _config(
            [
                _check(f"c{index}", f"/api/r{index}", {"owner": [200], "other": [403]})
                for index in range(1, 7)
            ]
        )
        report = compute_coverage(config, parse_spec(_spec(paths)))
        self.assertEqual(report["summary"]["covered"], 6)
        for key, value in (
            ("coverage", report["coverage"]),
            ("path_coverage", report["summary"]["path_coverage"]),
        ):
            with self.subTest(ratio=key):
                self.assertAlmostEqual(value, 6 / 7, delta=1e-6)

    @slow("builds a 20,000-operation inventory, the parser's ceiling")
    def test_the_worst_near_miss_the_parser_accepts_stores_below_one(self) -> None:
        """MAX_OPERATIONS operations with exactly one uncovered: both stored
        ratios must stay below 1.0, whatever method the code uses to cut them.

        Check matching scans every template per check, so a real run at this
        size takes minutes. ``match_path`` is narrowed to the one literal
        template a check can match (exact for an all-literal inventory: an
        exact literal is the most specific template there is); the counting
        and the ratios are compute_coverage's own.
        """
        from unittest import mock  # noqa: PLC0415

        import veridor.coverage as coverage_module  # noqa: PLC0415
        from veridor.openapi import MAX_OPERATIONS  # noqa: PLC0415

        real = coverage_module.match_path
        indexed: dict[int, tuple[object, frozenset[str]]] = {}

        def narrowed(concrete, templates, **kwargs):
            entry = indexed.get(id(templates))
            if entry is None or entry[0] is not templates:
                entry = (templates, frozenset(templates))
                indexed[id(templates)] = entry
            candidates = [concrete] if concrete in entry[1] else templates
            return real(concrete, candidates, **kwargs)

        total = MAX_OPERATIONS
        paths = {f"/api/r{index}": _get() for index in range(total)}
        config = _config(
            [
                _check(f"c{index}", f"/api/r{index}", {"owner": [200], "other": [403]})
                for index in range(1, total)
            ]
        )
        inventory = parse_spec(_spec(paths))
        with mock.patch.object(coverage_module, "match_path", narrowed):
            report = compute_coverage(config, inventory)
        self.assertEqual(report["summary"]["covered"], total - 1)
        self.assertEqual(report["summary"]["operations"], total)
        self.assertEqual(report["summary"]["paths_covered"], total - 1)
        self.assertEqual(report["summary"]["paths"], total)
        for key, value in (
            ("coverage", report["coverage"]),
            ("path_coverage", report["summary"]["path_coverage"]),
        ):
            with self.subTest(ratio=key):
                self.assertLess(value, 1.0)


class DiagnosticRedactionTest(unittest.TestCase):
    def test_the_undecodable_segment_diagnostic_drops_the_query(self) -> None:
        """The one path written raw; its query values must not travel with it.

        The coverage JSON is routinely uploaded or committed beside the badge.
        """
        inventory = parse_spec(_spec({"/api/y/{id}": _get()}))
        config = _config(
            [
                _check(
                    "undecodable",
                    "/api/y/%FF?api_key=QUERYSECRET-gggggggggg",
                    {"owner": [200], "other": [403]},
                )
            ]
        )
        report = compute_coverage(config, inventory)
        serialized = json.dumps(report)
        self.assertNotIn("QUERYSECRET", serialized)
        diagnostic = next(
            entry
            for entry in report["diagnostics"]
            if entry["code"] == "undecodable_segment"
        )
        self.assertEqual(diagnostic["path"], "/api/y/%FF?[REDACTED]")


class WrapParagraphTest(unittest.TestCase):
    """One wrapping implementation, and the two rules that made it worth having.

    ``blastradius`` and ``mutation`` each hand-rolled this and had drifted:
    over 1,800 randomised inputs they agreed on only ~87%. Neither divergence
    was caught by any test, which is why the contract is pinned here rather
    than left to whichever report happens to be asserted on next.
    """

    LONG = (
        "https://api.example.com/v1/tenants/acme-corp/invoices/"
        "9f3c1a2b-4d5e-6f70-8192-a3b4c5d6e7f8/attachments"
    )

    def test_a_token_longer_than_the_width_is_never_split(self) -> None:
        """The load-bearing rule. Output is evidence somebody copies.

        The stdlib defaults break on hyphens and on long words, which turned a
        103-character finding URL into ``...tenants/acme-`` / ``corp/...``.
        A URL in halves is not a URL.
        """
        lines = wrap_paragraph(f"The identity reached {self.LONG} unexpectedly.")
        self.assertIn(self.LONG, "\n".join(lines))
        whole = [line for line in lines if self.LONG in line]
        self.assertEqual(len(whole), 1, f"the URL was split across lines: {lines}")

    def test_hyphenated_identifiers_survive(self) -> None:
        for token in ("VERIDOR-AUTHZ-001", "Strict-Transport-Security",
                      "other-tenant-read-back"):
            with self.subTest(token=token):
                lines = wrap_paragraph(f"rule {token} fired on this run", indent="")
                self.assertIn(token, "\n".join(lines))
                self.assertEqual(
                    sum(token in line for line in lines), 1,
                    f"{token} was split: {lines}",
                )

    def test_a_line_that_exactly_fills_the_width_is_not_broken(self) -> None:
        """The off-by-one that made the two copies disagree.

        ``blastradius`` accumulated ``word + " "`` and then tested
        ``len(current) + len(word) + 1``, counting the stored trailing space
        twice, so it wrapped one character early.
        """
        text = " ".join(["ab"] * 26)          # 77 characters at indent ""
        self.assertEqual(len(text), 77)
        self.assertEqual(wrap_paragraph(text, indent="", width=77), [text])

    def test_the_indent_is_applied_to_every_line(self) -> None:
        lines = wrap_paragraph(" ".join(["word"] * 60), indent="    ")
        self.assertGreater(len(lines), 1)
        for line in lines:
            self.assertTrue(line.startswith("    "), repr(line))
            self.assertLessEqual(len(line), 78)

    def test_degenerate_input_does_not_raise(self) -> None:
        self.assertEqual(wrap_paragraph(""), [])
        self.assertEqual(wrap_paragraph("   "), [])

    def test_an_aligned_gutter_survives(self) -> None:
        """``mutation`` lines up four labels in one column; wrapping must not eat it.

        ``mutate`` renders ``mutation: ``, ``expected: ``, ``observed: `` and
        ``means:    ``, each padded to ten characters so the values start in
        the same column. The old hand-rolled wrapper began ``text.split()``,
        which collapses runs of whitespace, so ``means:    x`` reached the
        terminal as ``means: x`` and the alignment the author wrote was lost
        between the source and the screen. It was never tested either way.
        """
        for label in ("mutation: ", "expected: ", "observed: ", "means:    "):
            with self.subTest(label=label.strip()):
                line = wrap_paragraph(f"{label}value here", indent="      ")[0]
                self.assertEqual(
                    line, f"      {label}value here",
                    "the gutter was collapsed, so the column no longer lines up",
                )
                # All four labels are padded to the same width on purpose.
                self.assertEqual(line.index("value"), 6 + 10)

    def test_there_is_exactly_one_implementation(self) -> None:
        """The point of the change: the copies must not come back.

        Both callers keep a thin adapter -- one returns ``str``, the other
        ``list[str]`` -- but neither may hold wrapping arithmetic of its own.
        """
        import ast
        import inspect
        import textwrap as _textwrap

        from veridor import blastradius, mutation

        for module, function in (
            (blastradius, blastradius._wrap),
            (mutation, mutation._wrap),
        ):
            with self.subTest(module=module.__name__):
                tree = ast.parse(
                    _textwrap.dedent(inspect.getsource(function))
                ).body[0]
                # The docstrings below discuss the old implementation by name,
                # so read the CODE and not the prose about it.
                statements = [
                    node for node in tree.body
                    if not (isinstance(node, ast.Expr)
                            and isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str))
                ]
                code = "\n".join(ast.dump(node) for node in statements)
                self.assertIn(
                    "wrap_paragraph", code,
                    f"{module.__name__}._wrap no longer delegates",
                )
                # A re-hand-rolled version has to loop to walk the words.
                self.assertFalse(
                    any(isinstance(n, (ast.For, ast.While))
                        for node in statements for n in ast.walk(node)),
                    f"{module.__name__}._wrap is wrapping text itself again",
                )




class NoMatchesRefusalBoundTest(unittest.TestCase):
    """The no-matches refusal quotes spec routes, config paths and base-path
    candidates. They were joined in raw, and cli printed the refusal itself,
    past the bound every other refusal goes through: a route whose template
    carried newlines and a copy of a genuine session drew a verdict below the
    real refusal, and a long run of spaces wrapped into rows of its own."""

    FORGED = "\n\nVeridor capsule — NOT_REPRODUCED\n\x1b[2J"

    def _message(self, template: str, check_path: str = "/x", candidate: str = "/api") -> str:
        from veridor import coverage as coverage_module  # noqa: PLC0415

        report = {
            "base_path": {"check_paths": 2, "candidates": [{"value": candidate, "matched_checks": 0}]},
            "summary": {"operations": 3},
        }
        return coverage_module._no_matches_message(
            report, [template, "/ok"], [{"method": "GET", "path": check_path}], "spec.yaml"
        )

    def test_input_cannot_start_a_line_obey_a_control_or_wrap(self) -> None:
        hostile = self.FORGED + " " * 4000 + "tail"
        for where, message in {
            "spec route": self._message("/r" + hostile),
            "config path": self._message("/r", check_path="/x" + hostile),
            "base-path candidate": self._message("/r", candidate="/api" + hostile),
        }.items():
            with self.subTest(where=where):
                lines = message.split("\n")
                self.assertEqual([line for line in lines if line.startswith("Veridor capsule")], [])
                self.assertNotIn("\x1b", message)
                self.assertLessEqual(max(map(len, lines)), 200, max(lines, key=len)[:120])

    def test_control_a_plain_route_is_shown_as_written(self) -> None:
        message = self._message("/v1/invoices/{id}", check_path="/api/invoices/1")
        self.assertIn("    /v1/invoices/{id}", message)
        self.assertIn("    GET /api/invoices/1", message)

    def test_the_cli_prints_the_refusal_through_the_refusal_bound(self) -> None:
        import argparse  # noqa: PLC0415
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415
        from unittest import mock  # noqa: PLC0415

        from veridor import cli  # noqa: PLC0415
        from veridor.coverage import CoverageError  # noqa: PLC0415
        from veridor.terminal import REFUSAL_LINE_LIMIT  # noqa: PLC0415

        error = CoverageError("none matched:" + self.FORGED + "x" * 5000)
        stderr = io.StringIO()
        with mock.patch.object(cli, "_coverage_report", side_effect=error), \
                mock.patch.object(cli, "_write_coverage_artifacts"), \
                contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = cli._emit_coverage(argparse.Namespace())
        self.assertEqual(code, 2)
        printed = stderr.getvalue()
        self.assertNotIn("\x1b", printed)
        self.assertLessEqual(max(map(len, printed.splitlines())), REFUSAL_LINE_LIMIT + 80)


class RenderTextEscapesInputTest(unittest.TestCase):
    """The measured report quotes spec routes and base paths, and check paths
    in its diagnostics. ``render_text`` printed them raw, so a spec path key
    carrying an escape sequence or a bidi override reached the terminal
    through `veridor coverage` (exit 0), while the no-matches refusal above
    escaped the same values."""

    ESC = "\x1b[2J\x1b[H"
    BIDI = "\u202e"

    def _text(self, paths: dict, checks: list[dict], **extra) -> str:
        report = compute_coverage(_config(checks), parse_spec(_spec(paths, **extra)))
        return render_text(report)

    def _assert_shown_not_obeyed(self, text: str) -> None:
        self.assertNotIn("\x1b", text)
        self.assertNotIn(self.BIDI, text)
        self.assertIn("\\x1b[2J", text)

    def test_uncovered_routes_are_shown_not_obeyed(self) -> None:
        text = self._text(
            {"/ok": _get(), f"/admin{self.ESC}": _get(), f"/x{self.BIDI}abc{self.ESC}": _get()},
            [_check("ok", "/ok", {"owner": [200], "other": [403]})],
        )
        self._assert_shown_not_obeyed(text)
        self.assertIn("\\u202eabc", text)

    def test_weak_coverage_routes_are_shown_not_obeyed(self) -> None:
        text = self._text(
            {f"/w{self.ESC}/{{id}}": _get()},
            [_check("w", f"/w{self.ESC}/1", {"owner": [403], "other": [403]})],
        )
        self.assertIn("Weak coverage", text)
        self._assert_shown_not_obeyed(text)

    def test_diagnostics_are_shown_not_obeyed(self) -> None:
        text = self._text(
            {"/ok": _get(), f"/admin{self.ESC}/users": _get()},
            [
                _check("ok", "/ok", {"owner": [200], "other": [403]}),
                _check("near", f"/admin{self.ESC}/user", {"owner": [200], "other": [403]}),
            ],
        )
        self.assertIn("Diagnostics", text)
        self._assert_shown_not_obeyed(text)

    def test_a_diagnostic_cannot_pad_a_forged_row(self) -> None:
        """Diagnostics were escaped but not collapsed (``limit=None`` skips the
        blank-run collapse), so a spec path key of '/near/users', 400 spaces
        and a forged summary line put that line on a visual row of its own
        through the "nearest:" hint, with no escape byte at all. The
        uncovered-route line for the same key was collapsed.

        Collapsing then left the same row to a printable blank: U+2800 (So)
        and U+3164 (Lo) are not spaces, so 400 of either still made a
        546-character line with the forged text on a row of its own. The
        quoted key is now cut to ECHO_LIMIT, as the uncovered-route line is."""
        forged = "Authorization boundary coverage: 5/5 operations (100.0%)"
        spaces = (" ", "\u00a0", "\u3000")
        for blank in (*spaces, "\u2800", "\u3164", " \u2800"):
            with self.subTest(blank=" ".join(hex(ord(char)) for char in blank)):
                text = self._text(
                    {"/ok": _get(), f"/near/users{blank * 400}{forged}": _get()},
                    [
                        _check("ok", "/ok", {"owner": [200], "other": [403]}),
                        _check("near", "/near/users", {"owner": [200], "other": [403]}),
                    ],
                )
                diagnostics = [line for line in text.splitlines() if "nearest:" in line]
                # Control: the hint is printed, and still names the key.
                self.assertEqual(len(diagnostics), 1, text)
                value = diagnostics[0].split("nearest: ", 1)[1]
                self.assertTrue(value.startswith("/near/users"), value)
                shown, _, more = value.partition(" ... (")
                self.assertLessEqual(len(shown), ECHO_LIMIT, value)
                if blank in spaces:
                    # Collapsed to one space, so it fits and is shown whole.
                    self.assertEqual(value, f"/near/users {forged}")
                else:
                    self.assertNotIn(forged, diagnostics[0])
                    self.assertRegex(more, r"^\d+ more characters\)$")

    def test_every_value_a_diagnostic_quotes_is_bounded(self) -> None:
        """Each diagnostic quotes check ids, config paths, identity names and
        spec templates, with ``{value!r}`` or raw; neither bounds. A value
        padded with U+2800 and ending in a forged summary line printed whole on
        its diagnostic line, whichever site quoted it."""
        forged = "Authorization boundary coverage: 5/5 operations (100.0%)"
        pad = "\u2800" * 400
        checks = [
            _check("ok", "/ok", {"owner": [200], "other": [403]}),
            # unmatched_check: the check id and the concrete path.
            _check(f"id{pad}{forged}", f"/near{pad}{forged}", {"owner": [200]}),
            # templated_check_path: the path as written.
            _check("templated", f"/t/{{id}}{pad}{forged}", {"owner": [200]}),
            # undecodable_segment: the raw segment.
            _check("undecodable", f"/u/%ff{pad}{forged}", {"owner": [200]}),
            # case_mismatch: the spec template it differs from only in case.
            _check("case", f"/case{pad}{forged}".lower(), {"owner": [200]}),
            # method_not_in_spec: the template it matched.
            _check("method", f"/m{pad}{forged}/1", {"owner": [200]}, method="POST"),
            # *_expect: the identity name.
            _check("identity", "/ok", {f"other{pad}{forged}": [200, 404]}),
        ]
        text = self._text(
            {
                "/ok": _get(),
                f"/Case{pad}{forged}": _get(),
                f"/m{pad}{forged}/{{id}}": _get(),
            },
            checks,
        )
        lines = text.split("Diagnostics (", 1)[1].split("\n\n", 1)[0].splitlines()[1:]
        codes = {line.split()[0] for line in lines}
        # Control: every site above produced its diagnostic.
        self.assertLessEqual(
            {
                "unmatched_check",
                "templated_check_path",
                "undecodable_segment",
                "case_mismatch",
                "method_not_in_spec",
                "permissive_expect",
            },
            codes,
            text,
        )
        for line in lines:
            with self.subTest(line=line[:40]):
                self.assertNotIn(forged, line)
                self.assertNotIn("\u2800" * (ECHO_LIMIT + 1), line)

    def test_a_long_method_is_bounded_on_its_diagnostic_line(self) -> None:
        """The method was the one value both method-carrying diagnostics quoted
        raw. It is held to an HTTP token, so it cannot carry a space or a colon,
        but nothing bounds its length: a 400-character method printed whole."""
        method = "X" * 400
        checks = [
            _check("ok", "/ok", {"owner": [200], "other": [403]}),
            # unmatched_check: no operation at this path.
            _check("unmatched", "/nowhere", {"owner": [200]}, method=method),
            # method_not_in_spec: the path matches, the method does not.
            _check("wrong-method", "/ok", {"owner": [200]}, method=method),
        ]
        text = self._text({"/ok": _get()}, checks)
        lines = text.split("Diagnostics (", 1)[1].split("\n\n", 1)[0].splitlines()[1:]
        quoting = [line for line in lines if line.split()[0] in {"unmatched_check", "method_not_in_spec"}]
        # Control: both diagnostics were produced.
        self.assertEqual({line.split()[0] for line in quoting}, {"unmatched_check", "method_not_in_spec"}, text)
        for line in quoting:
            with self.subTest(code=line.split()[0]):
                self.assertNotIn("X" * (ECHO_LIMIT + 1), line)

    def test_the_base_path_is_shown_not_obeyed(self) -> None:
        text = self._text(
            {"/ok": _get()},
            [_check("ok", f"/api{self.ESC}/ok", {"owner": [200], "other": [403]})],
            servers=[{"url": f"https://api.example.test/api{self.ESC}"}],
        )
        self.assertIn("base path: /api", text)
        self._assert_shown_not_obeyed(text)

    def test_control_plain_routes_are_shown_as_written(self) -> None:
        text = self._text(
            {"/ok": _get(), "/admin/{id}": _get()},
            [_check("ok", "/ok", {"owner": [200], "other": [403]})],
        )
        self.assertIn("  GET    /admin/{id}", text)


if __name__ == "__main__":
    unittest.main()
