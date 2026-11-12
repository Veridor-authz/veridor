"""The published config schema and the loader must agree, measured both ways.

``schema/veridor-config-v1.schema.json`` is what an editor or a CI
pre-validation step (``check-jsonschema``) enforces. It contradicted the loader
in both directions, and the only test compared key sets, so it could not see:

* the ``veridor init --for run`` scaffold was schema-INVALID (``_comment`` on
  every check), while the loader accepted it;
* every version-2 ``sequences`` config was schema-invalid (``version`` was
  ``const: 1``; steps were modelled as bare requests with a required
  ``identity``), while the loader accepted it -- and so were session login
  steps carrying ``expect_status``;
* ``expect: {"a": "allow", "b": "deny"}`` and a 16-character marker were
  schema-VALID and refused by the loader.

Measured with jsonschema 4.25.1 (Draft 2020-12) before this change. The runtime
and the test suite are stdlib-only, so the schema is checked here with a small
validator for exactly the keywords the schema uses; it raises on any keyword it
does not implement, so a schema edit cannot slip a keyword past it unchecked.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import math
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from veridor import core, matrix, sequence  # noqa: E402
from veridor.cli import main  # noqa: E402
from veridor.core import ConfigError, load_config  # noqa: E402
from veridor.matrix import MatrixError  # noqa: E402
from veridor.coverage import CoverageError, compute_coverage  # noqa: E402
from veridor.openapi import parse_spec  # noqa: E402

SCHEMA_PATH = ROOT / "schema" / "veridor-config-v1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# A Draft 2020-12 validator for the subset of keywords the schema uses.
# ---------------------------------------------------------------------------

class UnsupportedKeyword(Exception):
    """The schema uses a keyword this validator does not implement."""


#: Keywords that assert nothing. ``format`` is an annotation in Draft 2020-12
#: unless a validator opts in to asserting it, and jsonschema does not by default.
_ANNOTATIONS = frozenset(
    {"$schema", "$id", "$defs", "title", "description", "default", "examples", "format"}
)


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality: ``true`` is not ``1``, and ``1`` is ``1.0``."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(map(_json_equal, left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return type(left) is type(right) and left == right


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if isinstance(value, bool):
        return False
    if name == "integer":
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not (
            isinstance(value, float) and math.isnan(value)
        )
    raise UnsupportedKeyword(f"type {name!r}")


class SubsetValidator:
    def __init__(self, root: dict) -> None:
        self.root = root

    def _resolve(self, reference: str) -> Any:
        if not reference.startswith("#"):
            raise UnsupportedKeyword(f"non-local $ref {reference!r}")
        node: Any = self.root
        for part in reference[1:].split("/")[1:]:
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return node

    def errors(self, instance: Any, schema: Any = None, path: str = "") -> list[str]:
        schema = self.root if schema is None else schema
        if schema is True:
            return []
        if schema is False:
            return [f"{path or '/'}: no value is allowed here"]
        found: list[str] = []
        here = path or "/"
        for keyword, value in schema.items():
            if keyword in _ANNOTATIONS or keyword in {"then", "else"}:
                continue
            handler = getattr(self, "_k_" + keyword.lstrip("$"), None)
            if handler is None:
                raise UnsupportedKeyword(keyword)
            found += handler(instance, value, schema, path, here)
        return found

    def _valid(self, instance: Any, schema: Any, path: str) -> bool:
        return not self.errors(instance, schema, path)

    # -- keywords --------------------------------------------------------

    def _k_ref(self, instance, value, schema, path, here):
        return self.errors(instance, self._resolve(value), path)

    def _k_type(self, instance, value, schema, path, here):
        names = value if isinstance(value, list) else [value]
        if any(_is_type(instance, name) for name in names):
            return []
        return [f"{here}: is not of type {value}"]

    def _k_enum(self, instance, value, schema, path, here):
        if any(_json_equal(instance, option) for option in value):
            return []
        return [f"{here}: {instance!r} is not one of {value}"]

    def _k_const(self, instance, value, schema, path, here):
        return [] if _json_equal(instance, value) else [f"{here}: must be {value!r}"]

    def _k_pattern(self, instance, value, schema, path, here):
        if isinstance(instance, str) and not re.search(value, instance):
            return [f"{here}: {instance!r} does not match {value!r}"]
        return []

    def _k_minLength(self, instance, value, schema, path, here):  # noqa: N802
        if isinstance(instance, str) and len(instance) < value:
            return [f"{here}: shorter than {value}"]
        return []

    def _k_maxLength(self, instance, value, schema, path, here):  # noqa: N802
        if isinstance(instance, str) and len(instance) > value:
            return [f"{here}: longer than {value}"]
        return []

    def _numeric(self, instance) -> bool:
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)

    def _k_minimum(self, instance, value, schema, path, here):
        if self._numeric(instance) and instance < value:
            return [f"{here}: below {value}"]
        return []

    def _k_maximum(self, instance, value, schema, path, here):
        if self._numeric(instance) and instance > value:
            return [f"{here}: above {value}"]
        return []

    def _k_exclusiveMinimum(self, instance, value, schema, path, here):  # noqa: N802
        if self._numeric(instance) and instance <= value:
            return [f"{here}: not above {value}"]
        return []

    def _k_minItems(self, instance, value, schema, path, here):  # noqa: N802
        if isinstance(instance, list) and len(instance) < value:
            return [f"{here}: fewer than {value} items"]
        return []

    def _k_maxItems(self, instance, value, schema, path, here):  # noqa: N802
        if isinstance(instance, list) and len(instance) > value:
            return [f"{here}: more than {value} items"]
        return []

    def _k_items(self, instance, value, schema, path, here):
        if not isinstance(instance, list):
            return []
        return [
            error
            for index, item in enumerate(instance)
            for error in self.errors(item, value, f"{path}/{index}")
        ]

    def _k_required(self, instance, value, schema, path, here):
        if not isinstance(instance, dict):
            return []
        return [f"{here}: missing {key!r}" for key in value if key not in instance]

    def _k_minProperties(self, instance, value, schema, path, here):  # noqa: N802
        if isinstance(instance, dict) and len(instance) < value:
            return [f"{here}: fewer than {value} properties"]
        return []

    def _k_maxProperties(self, instance, value, schema, path, here):  # noqa: N802
        if isinstance(instance, dict) and len(instance) > value:
            return [f"{here}: more than {value} properties"]
        return []

    def _k_dependentRequired(self, instance, value, schema, path, here):  # noqa: N802
        if not isinstance(instance, dict):
            return []
        return [
            f"{here}: {key!r} requires {needed!r}"
            for key, needs in value.items() if key in instance
            for needed in needs if needed not in instance
        ]

    def _k_properties(self, instance, value, schema, path, here):
        if not isinstance(instance, dict):
            return []
        return [
            error
            for key, subschema in value.items() if key in instance
            for error in self.errors(instance[key], subschema, f"{path}/{key}")
        ]

    def _k_patternProperties(self, instance, value, schema, path, here):  # noqa: N802
        if not isinstance(instance, dict):
            return []
        return [
            error
            for pattern, subschema in value.items()
            for key in instance if re.search(pattern, key)
            for error in self.errors(instance[key], subschema, f"{path}/{key}")
        ]

    def _k_additionalProperties(self, instance, value, schema, path, here):  # noqa: N802
        if not isinstance(instance, dict):
            return []
        named = schema.get("properties", {})
        patterns = schema.get("patternProperties", {})
        extra = [
            key for key in instance
            if key not in named and not any(re.search(p, key) for p in patterns)
        ]
        return [
            error
            for key in extra
            for error in (
                [f"{path}/{key}: is not allowed here"]
                if value is False
                else self.errors(instance[key], value, f"{path}/{key}")
            )
        ]

    def _k_propertyNames(self, instance, value, schema, path, here):  # noqa: N802
        if not isinstance(instance, dict):
            return []
        return [
            error for key in instance
            for error in self.errors(key, value, f"{path}/{key} (name)")
        ]

    def _k_allOf(self, instance, value, schema, path, here):  # noqa: N802
        return [error for subschema in value for error in self.errors(instance, subschema, path)]

    def _k_anyOf(self, instance, value, schema, path, here):  # noqa: N802
        if any(self._valid(instance, subschema, path) for subschema in value):
            return []
        return [f"{here}: matches none of anyOf"]

    def _k_oneOf(self, instance, value, schema, path, here):  # noqa: N802
        matched = sum(self._valid(instance, subschema, path) for subschema in value)
        return [] if matched == 1 else [f"{here}: matches {matched} of oneOf, not exactly 1"]

    def _k_not(self, instance, value, schema, path, here):
        return [f"{here}: matches a forbidden form"] if self._valid(instance, value, path) else []

    def _k_if(self, instance, value, schema, path, here):
        branch = "then" if self._valid(instance, value, path) else "else"
        return self.errors(instance, schema[branch], path) if branch in schema else []


VALIDATOR = SubsetValidator(SCHEMA)


def schema_errors(document: Any) -> list[str]:
    return VALIDATOR.errors(document)


# ---------------------------------------------------------------------------
# The loader side.
# ---------------------------------------------------------------------------

_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _environment_for(document: dict) -> dict[str, str]:
    """A distinct value for every ${NAME} the document reads, capture names
    excepted (the loader refuses an environment variable that shadows one)."""
    captures = set(sequence.RESERVED_NAMES)
    for entry in document.get("sequences") or []:
        for step in (entry.get("steps") or []) if isinstance(entry, dict) else []:
            if isinstance(step, dict) and isinstance(step.get("capture"), dict):
                captures.update(step["capture"])
    return {
        name: f"value-for-{name.lower()}"
        for name in _REFERENCE.findall(json.dumps(document))
        if name not in captures
    }


def loader_refusal(document: Any, *, require_checks: bool = True) -> str | None:
    """None when the loader accepts ``document``; otherwise its refusal."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        environment = _environment_for(document) if isinstance(document, dict) else {}
        try:
            with patch.dict(os.environ, environment):
                config = load_config(path, require_checks=require_checks)
                if "matrix" in config:
                    section = matrix._matrix_section(config)
                    specimens = section.get("specimens")
                    if isinstance(specimens, dict) and matrix.SPECIMEN_PLACEHOLDER not in json.dumps(
                        specimens
                    ):
                        matrix._parse_specimens(
                            section,
                            list(config["identities"]),
                            {
                                name: identity["marker"]
                                for name, identity in config["identities"].items()
                                if "marker" in identity
                            },
                        )
        except (ConfigError, MatrixError) as refusal:
            return str(refusal)
    return None


#: A one-operation specification for measuring coverage. It need not match the
#: configuration: the `coverage` block is checked before anything is matched,
#: and allow_no_matches keeps a mismatch from being the refusal.
_COVERAGE_SPEC = {"openapi": "3.0.3", "info": {"title": "parity", "version": "1"},
                  "paths": {"/parity": {"get": {"responses": {"200": {"description": "ok"}}}}}}


def coverage_refusal(document: dict) -> str | None:
    """None when the loaded ``document`` is measured; otherwise the refusal
    from the boundary-coverage measurement every command that reports
    coverage goes through (cli._coverage_report -> compute_coverage)."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with patch.dict(os.environ, _environment_for(document)):
            config = load_config(path, allow_missing_env=True)
        try:
            compute_coverage(config, parse_spec(_COVERAGE_SPEC), allow_no_matches=True)
        except CoverageError as refusal:
            return str(refusal)
    return None


# ---------------------------------------------------------------------------
# The corpus: every configuration Veridor ships, generates, or documents.
# ---------------------------------------------------------------------------

#: Fixtures a user is pointed at live in fixtures/; the ones only tests read
#: live in tests/fixtures/. The corpus is both, so moving a file between them
#: cannot drop it from the corpus.
FIXTURE_DIRS = (ROOT / "fixtures", ROOT / "tests" / "fixtures")


def _fixture_files(pattern: str) -> list[Path]:
    return sorted((path for directory in FIXTURE_DIRS for path in directory.glob(pattern)),
                  key=lambda path: path.name)


def _init_scaffolds() -> dict[str, dict]:
    scaffolds = {}
    with tempfile.TemporaryDirectory() as directory:
        for spec in _fixture_files("openapi.*.json"):
            for kind in ("run", "drift"):
                output = Path(directory) / f"{kind}-{spec.stem}.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    code = main(["init", "--for", kind, "--openapi", str(spec),
                                 "--output", str(output)])
                assert code == 0, f"init --for {kind} {spec.name} exited {code}"
                scaffolds[f"init --for {kind} --openapi {spec.name}"] = json.loads(
                    output.read_text(encoding="utf-8")
                )
    return scaffolds


def _shipped_configs() -> dict[str, dict]:
    configs = {}
    for fixture in _fixture_files("*.json"):
        document = json.loads(fixture.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "version" in document and "identities" in document:
            configs[fixture.relative_to(ROOT).as_posix()] = document
    for pair in sorted((ROOT / "fixtures" / "pairs").glob("*.json")):
        config = json.loads(pair.read_text(encoding="utf-8"))["config"]
        # The pair harness fills in the container's URL; "PROVISIONED" is its
        # placeholder, refused by the loader and the schema alike.
        config["target"]["base_url"] = "http://127.0.0.1:3000"
        configs[f"fixtures/pairs/{pair.name} (provisioned)"] = config
    return configs


_README = (ROOT / "README.md").read_text(encoding="utf-8")
_OWNER_MARKER = "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1"


def _readme_configs() -> dict[str, dict]:
    """Full configs in the README, and the two fragments completed minimally."""
    configs = {}
    for match in re.finditer(r"```json\n(.*?)```", _README, re.S):
        line = _README[: match.start()].count("\n") + 1
        try:
            document = json.loads(match.group(1))
        except ValueError as error:
            # An object's members (`"matrix": {...}`) are a deliberate
            # fragment. Anything else that does not parse is a broken
            # example, and skipping it dropped it from the corpus unseen.
            try:
                json.loads("{" + match.group(1) + "}")
            except ValueError:
                raise AssertionError(
                    f"README.md:{line}: a ```json block is not valid JSON, on "
                    f"its own or as an object's members: {error}") from None
            continue
        if not isinstance(document, dict):
            continue
        if "version" in document and "identities" in document:
            # A `map` configuration (a matrix, no checks) is named by what it
            # holds, not by its line: the line moved with every README edit
            # above it, and "README.md:314" stopped matching.
            kind = " (map: matrix, no checks)" if "matrix" in document and "checks" not in document else ""
            configs[f"README.md:{line}{kind}"] = document
        elif "sequences" in document:
            configs[f"README.md:{line} (sequences, with two identities)"] = {
                "version": document["version"],
                "target": {"base_url": "https://staging.example.com"},
                "identities": {
                    "owner": {"headers": {"Authorization": "Bearer ${OWNER_TOKEN}"},
                              "marker": _OWNER_MARKER},
                    "attacker": {"headers": {"Authorization": "Bearer ${ATTACKER_TOKEN}"}},
                },
                "sequences": document["sequences"],
            }
        elif set(document) == {"identities"}:
            identities = dict(document["identities"])
            owner = next(iter(identities))
            identities["outsider"] = {"headers": {"Authorization": "Bearer ${OUTSIDER_TOKEN}"}}
            configs[f"README.md:{line} (session, with a second identity and a check)"] = {
                "version": 1,
                "target": {"base_url": "https://staging.example.com"},
                "identities": identities,
                "checks": [{
                    "id": "doc-isolation",
                    "request": {"method": "GET", "path": "/docs/1"},
                    "expect": {
                        owner: {"status": [200], "contains_marker": owner},
                        "outsider": {"status": [404], "excludes_marker": owner},
                    },
                }],
            }
    return configs


def _annotated_config() -> dict:
    """``_comment`` at every place the schema allows an annotation."""
    note = "an annotation"
    return {
        "_comment": note,
        "version": 2,
        "target": {"base_url": "https://staging.example.com", "_comment": note,
                   "teardown_timeout_seconds": 5},
        "identities": {
            "owner": {
                "_comment": note,
                "marker": _OWNER_MARKER,
                "marker_probe": {"path": "/docs/mine", "_comment": note},
                "session": {
                    "_comment": note,
                    "login": [{"method": "POST", "path": "/login", "_comment": note,
                               "body": "password=${OWNER_PASSWORD}", "expect_status": 302,
                               "capture": {"csrf_login": {"from": "json_pointer",
                                                          "pointer": "/csrf",
                                                          "_comment": note}}}],
                    "establishes": {"cookie": "sid"},
                    "capture": {"csrf": {"from": "cookie", "name": "csrftoken",
                                         "_comment": note}},
                    "inject": [{"header": "X-CSRFToken", "value": "${capture.csrf}",
                                "_comment": note}],
                    "reestablish": "check",
                },
            },
            "attacker": {"headers": {"Authorization": "Bearer ${ATTACKER_TOKEN}"}},
            "anonymous": {},
        },
        "checks": [{
            "id": "doc-isolation",
            "name": "Doc isolation",
            "description": "free text",
            "_comment": note,
            "request": {"method": "GET", "path": "/docs/1", "_comment": note,
                        "headers": {"X-Tenant": "acme"}},
            "expect": {
                "owner": {"status": [200], "contains_marker": "owner", "_comment": note},
                "attacker": {"status": 404, "excludes_marker": "owner"},
            },
        }],
        "sequences": [{
            "id": "doc-delete",
            "name": "Cross-tenant delete",
            "_comment": note,
            "steps": [
                {"role": "setup", "as": "owner", "_comment": note, "name": "create",
                 "request": {"method": "POST", "path": "/docs",
                             "json": {"note": "${marker:owner}"}},
                 "expect": {"status": [201]},
                 "capture": {"doc_id": "$.id", "etag": "header:ETag"}},
                {"role": "assert", "as": "attacker",
                 "request": {"method": "DELETE", "path": "/docs/${doc_id}"},
                 "expect": {"status": [403, 404], "_comment": note}},
            ],
            "teardown": [{"as": "owner", "_comment": note, "name": "cleanup",
                          "request": {"method": "DELETE", "path": "/docs/${doc_id}"},
                          "expect": {"status": [204, 404], "_comment": note}}],
        }],
    }


def _no_checks(name: str) -> bool:
    """Configs written for `map`, which needs no checks."""
    return "--for drift" in name or "matrix" in name


class CorpusAgreementTest(unittest.TestCase):
    """Every configuration Veridor ships, generates or documents: the loader
    accepts it AND the schema accepts it."""

    def _assert_both_accept(self, corpus: dict[str, dict]) -> None:
        self.assertTrue(corpus, "an empty corpus proves nothing")
        for name, document in corpus.items():
            with self.subTest(document=name):
                refusal = loader_refusal(document, require_checks=not _no_checks(name))
                self.assertIsNone(refusal, f"the loader refuses {name}: {refusal}")
                self.assertEqual(schema_errors(document), [], name)

    def test_the_init_scaffolds(self) -> None:
        scaffolds = _init_scaffolds()
        self.assertEqual(len(scaffolds), 2 * len(_fixture_files("openapi.*.json")))
        self._assert_both_accept(scaffolds)

    def test_the_shipped_fixtures(self) -> None:
        configs = _shipped_configs()
        # The two blastradius fixtures that carry 20-character markers are
        # refused by the loader; they are asserted in the next test instead.
        refused = {"tests/fixtures/blastradius.benign.json", "tests/fixtures/blastradius.idor.json"}
        self.assertTrue(refused <= set(configs))
        self._assert_both_accept({k: v for k, v in configs.items() if k not in refused})

    def test_the_fixtures_the_loader_refuses_the_schema_refuses(self) -> None:
        configs = _shipped_configs()
        for name in ("tests/fixtures/blastradius.benign.json", "tests/fixtures/blastradius.idor.json"):
            with self.subTest(document=name):
                self.assertIn("marker must be between", loader_refusal(configs[name]) or "")
                self.assertNotEqual(schema_errors(configs[name]), [])

    def test_the_short_marker_is_the_only_thing_wrong_with_the_blastradius_fixtures(self) -> None:
        # The test above stays true while ANY second defect hides behind the
        # marker refusal: the generator once wrote the per-identity own_profile
        # specimen under "values", which the loader refuses and the schema
        # reports five times, and schema_errors != [] could not tell.
        configs = _shipped_configs()
        for name in ("tests/fixtures/blastradius.benign.json", "tests/fixtures/blastradius.idor.json"):
            with self.subTest(document=name):
                document = copy.deepcopy(configs[name])
                document["identities"]["alice"]["marker"] = _OWNER_MARKER
                self.assertIsNone(loader_refusal(document), name)
                self.assertEqual(schema_errors(document), [], name)

    def test_the_readme_configurations(self) -> None:
        configs = _readme_configs()
        # A full config, the map config, the sequences block and the session block.
        self.assertGreaterEqual(len(configs), 4, sorted(configs))
        self.assertTrue(any("sequences" in name for name in configs))
        self.assertTrue(any("session" in name for name in configs))
        self._assert_both_accept(configs)

    def test_a_readme_config_that_does_not_parse_is_not_skipped(self) -> None:
        """_readme_configs dropped every block json.loads refused, so a
        documented config broken by a doubled comma left the corpus without
        a word. The >= 4 floor above caught it only while the README held
        exactly four; a fifth broken config passed. The deliberate fragments
        (`"matrix": {...}` and the like) must still be skipped -- the test
        above is that control."""
        blocks = list(re.finditer(r"```json\n(.*?)```", _README, re.S))
        block = next(b for b in blocks
                     if b.group(1).lstrip().startswith("{")
                     and {"version", "target", "identities", "checks"}
                     <= set(json.loads(b.group(1))))
        comma = block.start(1) + block.group(1).index(",")
        broken = _README[:comma] + ",," + _README[comma + 1:]
        line = _README[: block.start()].count("\n") + 1
        with patch.object(sys.modules[__name__], "_README", broken):
            with self.assertRaises(AssertionError) as raised:
                _readme_configs()
        self.assertIn(f"README.md:{line}", str(raised.exception))
        self.assertIn("not valid JSON", str(raised.exception))

    def test_annotations_are_accepted_wherever_the_schema_allows_them(self) -> None:
        self._assert_both_accept({"annotated version-2 config": _annotated_config()})


def _base() -> dict:
    return copy.deepcopy(_annotated_config())


def _set(pointer: str, value: Any) -> Callable[[dict], None]:
    def apply(document: dict) -> None:
        *parents, last = pointer.strip("/").split("/")
        node: Any = document
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        if isinstance(node, list):
            node[int(last)] = value
        else:
            node[last] = value
    return apply


def _drop(pointer: str) -> Callable[[dict], None]:
    def apply(document: dict) -> None:
        *parents, last = pointer.strip("/").split("/")
        node: Any = document
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        del node[last]
    return apply


_SPECIMEN = {"label": "doc", "values": {"id": "doc-1"}}

#: (description, mutation of the annotated base, a fragment of the loader's
#: refusal). The fragment is the control: it proves the loader refused for
#: THIS reason, not for something incidental the mutation also broke.
REFUSED_FORMS: list[tuple[str, Callable[[dict], None], str]] = [
    ("expectation 'allow'", _set("checks/0/expect/owner", "allow"), "must be an object"),
    ("expectation 'deny'", _set("checks/0/expect/attacker", "deny"), "must be an object"),
    ("expect naming one identity", _drop("checks/0/expect/attacker"), "at least two users"),
    ("expectation without status", _set("checks/0/expect/attacker", {"excludes_marker": "owner"}),
     "requires HTTP status values"),
    ("empty status list", _set("checks/0/expect/attacker/status", []), "requires HTTP status"),
    ("status below 100", _set("checks/0/expect/attacker/status", [99]), "requires HTTP status"),
    ("status above 599", _set("checks/0/expect/attacker/status", 600), "requires HTTP status"),
    ("status as a string", _set("checks/0/expect/attacker/status", ["404"]), "requires HTTP status"),
    ("status as a boolean", _set("checks/0/expect/attacker/status", [True]), "requires HTTP status"),
    ("contains_marker and excludes_marker together",
     _set("checks/0/expect/owner", {"status": [200], "contains_marker": "owner",
                                    "excludes_marker": "attacker"}), "cannot set both"),
    ("a 20-character marker", _set("identities/owner/marker", "veridor-marker-alice"),
     "between 24 and 128"),
    ("a marker with a forbidden character", _set("identities/owner/marker", "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6!"),
     "only the characters"),
    ("version 3", _set("version", 3), "version 1, 2"),
    # An unhashable version raised TypeError out of the loader -- exit 70,
    # "a bug in Veridor" -- and `true` compared equal to 1 and loaded.
    ("version as an object", _set("version", {}), "version 1, 2"),
    ("version as a list", _set("version", [1]), "version 1, 2"),
    ("version true", _set("version", True), "version 1, 2"),
    ("version 1 with sequences", _set("version", 1), "requires configuration version 2"),
    ("a step without a role", _drop("sequences/0/steps/1/role"), "requires role"),
    ("a step with an unknown role", _set("sequences/0/steps/1/role", "check"), "requires role"),
    ("a step without expect", _drop("sequences/0/steps/1/expect"), "requires an expect object"),
    ("a step capture named run_id", _set("sequences/0/steps/0/capture", {"run_id": "$.id"}),
     "reserved"),
    ("a step capture that is not an extractor", _set("sequences/0/steps/0/capture/doc_id", "id"),
     "not a valid extractor"),
    ("nine captures on one step", _set("sequences/0/steps/0/capture",
                                       {f"c{i}": "$.id" for i in range(9)}), "the limit is 8"),
    ("a teardown entry with a role", _set("sequences/0/teardown/0/role", "setup"),
     "cannot declare 'role'"),
    ("a teardown entry with a capture", _set("sequences/0/teardown/0/capture", {"x": "$.id"}),
     "cannot declare 'capture'"),
    ("a sequence with no steps", _set("sequences/0/steps", []), "non-empty steps"),
    ("thirteen steps", lambda d: d["sequences"][0].__setitem__(
        "steps", d["sequences"][0]["steps"][:1] + [d["sequences"][0]["steps"][1]] * 12),
     "the limit is 12"),
    ("seven teardown entries", lambda d: d["sequences"][0].__setitem__(
        "teardown", d["sequences"][0]["teardown"] * 7), "the limit is 6"),
    ("json and body together", lambda d: d["checks"][0]["request"].update(
        {"json": {"a": 1}, "body": "x=1"}), "cannot define both"),
    ("a relative path", _set("checks/0/request/path", "docs/1"), "same-origin absolute path"),
    ("a scheme-relative path", _set("checks/0/request/path", "//evil.example/x"),
     "same-origin absolute path"),
    ("a lower-case method", _set("checks/0/request/method", "get"), "must be upper case"),
    ("a check request 'Headers' key", _set("checks/0/request/Headers", {"X-Tenant": "acme"}),
     "did you mean 'headers'"),
    ("a sequence step request 'header' key",
     _set("sequences/0/steps/1/request/header", {"X-Tenant": "acme"}), "did you mean 'headers'"),
    ("a teardown request 'Method' key", _set("sequences/0/teardown/0/request/Method", "DELETE"),
     "did you mean 'method'"),
    # Not a misspelling of anything: the loader dropped these without a word.
    ("a check request 'params' key", _set("checks/0/request/params", {"tenant": "acme"}),
     "query string"),
    ("a marker_probe 'Authorization' key",
     _set("identities/owner/marker_probe/Authorization", "Bearer x"), "under 'headers'"),
    ("a login step 'description' key",
     _set("identities/owner/session/login/0/description", "why"), "'_description'"),
    ("a sequence step request 'query' key",
     _set("sequences/0/steps/1/request/query", "tenant=acme"), "query string"),
    ("a teardown request 'timeout' key", _set("sequences/0/teardown/0/request/timeout", 5),
     "'_timeout'"),
    ("headers one level too high", _set("identities/attacker", {"Authorization": "Bearer x"}),
     "defines none of"),
    ("an identity with only an annotation", _set("identities/attacker", {"_comment": "x"}),
     "defines none of"),
    ("one identity", lambda d: d.__setitem__("identities", {"owner": d["identities"]["owner"]}),
     "at least two users"),
    ("an identity name with a space", lambda d: d["identities"].__setitem__("bad name", {}),
     "an identity name"),
    ("a check id with a space", _set("checks/0/id", "bad id"), "a check id"),
    ("a session without establishes", _drop("identities/owner/session/establishes"),
     "requires 'establishes'"),
    ("a login step without expect_status", _drop("identities/owner/session/login/0/expect_status"),
     "requires 'expect_status'"),
    ("establishes naming cookie and capture", _set("identities/owner/session/establishes",
                                                   {"cookie": "sid", "capture": "csrf"}),
     "exactly one of"),
    ("establishes with an unknown key", _set("identities/owner/session/establishes",
                                             {"csrf": "x"}), "unsupported keys"),
    ("inject naming two slots", _set("identities/owner/session/inject/0/form_field", "csrf"),
     "exactly one of"),
    ("a session capture that is not a cookie", _set("identities/owner/session/capture/csrf",
                                                    {"from": "header", "name": "X-CSRF"}),
     "'from' must be one of cookie"),
    ("a json_pointer capture without a pointer",
     _set("identities/owner/session/login/0/capture/csrf_login", {"from": "json_pointer"}),
     "requires an RFC 6901"),
    ("five login steps", lambda d: d["identities"]["owner"]["session"].__setitem__(
        "login", d["identities"]["owner"]["session"]["login"] * 5), "the limit is 4"),
    ("a marker_probe without a marker", _drop("identities/owner/marker"),
     "defines no 'marker' field"),
    # A TLS setting Veridor does not have loaded as an annotation and did nothing.
    ("an identity client_cert", _set("identities/attacker/client_cert", "/certs/attacker.pem"),
     "a TLS setting Veridor does not have"),
    ("a target ca_file", _set("target/ca_file", "/certs/ca.pem"), "a TLS setting Veridor does not have"),
    ("a target verify_tls false", _set("target/verify_tls", False), "a TLS setting Veridor does not have"),
    # The loader refuses these at the root too (core.load_config's
    # `_refuse_tls_keys(config, ...)`); the schema's root took any key, so an
    # editor showed them as valid.
    ("a root ca_file", _set("ca_file", "/certs/ca.pem"), "a TLS setting Veridor does not have"),
    ("a root verify_tls false", _set("verify_tls", False), "a TLS setting Veridor does not have"),
    ("a root tls block", _set("tls", {"ca_file": "/certs/ca.pem"}),
     "a TLS setting Veridor does not have"),
    ("a root client_cert", _set("client_cert", "/certs/c.pem"), "a TLS setting Veridor does not have"),
    # A misspelt root key dropped its whole block; see RootKeyNearMissTest.
    ("a root 'Sequences' key", lambda d: d.__setitem__("Sequences", d.pop("sequences")),
     "did you mean 'sequences'"),
    ("a root 'Checks' key", lambda d: d.__setitem__("Checks", d.pop("checks")),
     "did you mean 'checks'"),
    ("a zero timeout", _set("target/timeout_seconds", 0), "timeout_seconds"),
    ("a 61-second timeout", _set("target/timeout_seconds", 61), "timeout_seconds"),
    ("a string timeout", _set("target/timeout_seconds", "10"), "timeout_seconds"),
    ("an ftp base_url", _set("target/base_url", "ftp://example.com"), "http(s) URL"),
    ("credentials in the base_url", _set("target/base_url", "https://user:pw@example.com"),
     "must not contain credentials"),
    ("a matrix key typo", _set("matrix", {"specimen": {}}), "unsupported keys"),
    ("an annotation in matrix", _set("matrix", {"_comment": "x"}), "unsupported keys"),
    ("a specimen with values and per_identity",
     _set("matrix", {"specimens": {"/docs/{id}": [dict(_SPECIMEN, per_identity={
         "owner": {"id": "doc-2"}})]}}), "exactly one of"),
    ("a specimen with a 'shared' key",
     _set("matrix", {"specimens": {"/docs/{id}": [dict(_SPECIMEN, shared=True)]}}),
     "unsupported keys"),
    ("a specimen without a label",
     _set("matrix", {"specimens": {"/docs/{id}": [{"values": {"id": "doc-1"}}]}}),
     "label must be"),
]


class RefusedFormsTest(unittest.TestCase):
    """Every form the loader refuses, the schema refuses too."""

    def test_the_base_document_is_accepted_by_both(self) -> None:
        """Control: each case below differs from an accepted document by one edit."""
        self.assertIsNone(loader_refusal(_base()))
        self.assertEqual(schema_errors(_base()), [])
        with_matrix = _base()
        with_matrix["matrix"] = {"specimens": {"/docs/{id}": [_SPECIMEN]}}
        self.assertIsNone(loader_refusal(with_matrix))
        self.assertEqual(schema_errors(with_matrix), [])

    def test_the_loader_refuses_each_form_and_so_does_the_schema(self) -> None:
        self.assertGreater(len(REFUSED_FORMS), 40)
        # Repeated from the control above so this test cannot pass on a schema
        # that refuses everything.
        self.assertEqual(schema_errors(_base()), [])
        for description, mutate, fragment in REFUSED_FORMS:
            with self.subTest(form=description):
                document = _base()
                mutate(document)
                refusal = loader_refusal(document)
                self.assertIsNotNone(refusal, f"the loader ACCEPTS {description}")
                self.assertIn(fragment, refusal)
                self.assertNotEqual(
                    schema_errors(document), [], f"the schema accepts {description}"
                )


class CoverageSectionTest(unittest.TestCase):
    """The top-level `coverage` block README documents (`denial_statuses`).

    When the schema root began refusing unknown keys, `coverage` was not among
    its properties, so the documented block drew '/coverage: is not allowed
    here' in an editor while the loader read it. It was not a root key the
    loader knew either, so a misspelt `Coverage` was dropped without a word,
    the silent drop the near-miss refusal exists to stop."""

    def test_the_documented_block_is_accepted_by_both(self) -> None:
        document = _base()
        document["coverage"] = {"denial_statuses": [403, 404, 422]}
        self.assertEqual(schema_errors(document), [])
        self.assertIsNone(loader_refusal(document))

    def test_a_misspelt_coverage_is_refused_by_both(self) -> None:
        document = _base()
        document["Coverage"] = {"denial_statuses": [403]}
        self.assertNotEqual(schema_errors(document), [])
        refusal = loader_refusal(document)
        self.assertIsNotNone(refusal)
        self.assertIn("'coverage' for 'Coverage'", refusal)

    def test_the_schema_refuses_what_coverage_refuses(self) -> None:
        """`veridor coverage` refuses 401, 407, any 2xx and an empty list; the
        schema says so in the editor."""
        for label, statuses in (("401", [401]), ("407", [403, 407]), ("2xx", [200, 403]),
                                ("empty", []), ("not a list", 403)):
            with self.subTest(label):
                document = _base()
                document["coverage"] = {"denial_statuses": statuses}
                self.assertNotEqual(schema_errors(document), [])


class RootKeyNearMissTest(unittest.TestCase):
    """A misspelt top-level key is refused, not dropped with everything under it.

    The loader read ``"sequences" in config`` and ``config.get("checks")`` and
    never looked at the other root keys, so ``Sequences`` beside a ``checks``
    list loaded with zero sequences -- setup, the cross-tenant asserts and the
    teardown all gone -- and ``Checks`` beside ``sequences`` loaded with zero
    checks. Either way ``run`` graded what was left and stayed green (measured
    2026-10-14 on the annotated base below: no refusal, nothing printed).
    """

    def _renamed(self, real: str, typo: str) -> dict:
        document = _base()
        document[typo] = document.pop(real)
        return document

    def test_a_near_miss_of_a_root_key_is_refused_and_named(self) -> None:
        for real, typo in (
            ("sequences", "Sequences"), ("sequences", "sequence"), ("sequences", "sequencse"),
            ("sequences", "SEQUENCES"), ("checks", "Checks"), ("checks", "check"),
            ("checks", "chekcs"), ("target", "Target"), ("identities", "Identities"),
            ("identities", "identites"), ("version", "Version"),
        ):
            with self.subTest(typo=typo):
                refusal = loader_refusal(self._renamed(real, typo))
                self.assertIsNotNone(refusal, f"the loader ACCEPTS a root {typo!r}")
                self.assertIn(f"did you mean '{real}'", refusal)

    def test_the_refusal_says_what_the_misspelt_key_would_lose(self) -> None:
        """A string-valued key has nothing under it. The refusal for a root
        ``$Schema`` said everything under it would be dropped, which reads as
        though it held a block; it holds one string."""
        cases = {
            "$Schema": ("./schema/veridor-config-v1.schema.json", "its value would be dropped"),
            "Version": (2, "its value would be dropped"),
            "Matrix": ({}, "everything under it would be dropped"),
            "Checks": ([], "everything under it would be dropped"),
        }
        for typo, (value, says) in cases.items():
            with self.subTest(typo=typo):
                document = _base()
                document.pop(typo.lower(), None)
                document[typo] = value
                refusal = loader_refusal(document)
                self.assertIsNotNone(refusal)
                self.assertIn(says, refusal)
        document = _base()
        document["$Schema"] = "./schema/veridor-config-v1.schema.json"
        document["Matrix"] = {}
        refusal = loader_refusal(document)
        self.assertIsNotNone(refusal)
        self.assertIn("what each holds would be dropped", refusal)
        # Both clauses speak of several keys, not one.
        self.assertIn("Rename each, or start each with '_'", refusal)

    def test_a_dropped_block_is_what_the_refusal_prevents(self) -> None:
        """Control: the typo really did empty the block, so the refusal is not
        cosmetic. Loaded directly, the correct key yields one sequence; the
        typo'd one must not load at all. (Every ${NAME} the typo'd block reads
        is set, as _environment_for sets it, so the refusal cannot come from an
        unset variable instead.)"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "veridor.json"
            path.write_text(json.dumps(_base()), encoding="utf-8")
            with patch.dict(os.environ, _environment_for(_base())):
                self.assertEqual(len(load_config(path)["sequences"]), 1)
            typo = self._renamed("sequences", "Sequences")
            path.write_text(json.dumps(typo), encoding="utf-8")
            with patch.dict(os.environ, _environment_for(typo)):
                try:
                    loaded = load_config(path)
                except ConfigError as refusal:
                    self.assertIn("Sequences", str(refusal))
                else:
                    self.fail(f"loaded with {len(loaded.get('sequences', []))} sequences "
                              f"and {len(loaded['checks'])} checks")

    def test_annotations_and_unrelated_root_keys_still_load(self) -> None:
        """Control: the loader still treats a root key that is no near-miss as
        an annotation, as every release has."""
        for extra in ("_sequences", "_comment", "description", "owner_team"):
            with self.subTest(key=extra):
                document = _base()
                document[extra] = "a note"
                self.assertIsNone(loader_refusal(document))

    def test_the_loader_checks_every_root_key_the_schema_has(self) -> None:
        """The loader's list of root keys is the schema's root properties.

        It listed five and left out ``matrix`` and ``$schema``, so a root
        ``Matrix`` loaded and ``map`` dropped the whole block -- specimens,
        marker_owner, unauthenticated, ignore -- planned 8 requests over 2
        operations instead of 12 over 3, and exited 0 (measured 2026-10-14 on
        fixtures/veridor.map-demo.json)."""
        self.assertEqual(core._ROOT_KEYS, frozenset(SCHEMA["properties"]))

    def test_a_near_miss_of_every_schema_root_key_is_refused(self) -> None:
        """Driven by the schema's root properties, so a root key added there
        is covered here without anyone remembering to list it."""
        values = {"matrix": {}, "$schema": "./schema/veridor-config-v1.schema.json",
                  "coverage": {"denial_statuses": [403]}}
        self.assertEqual(set(SCHEMA["properties"]) - set(_base()), set(values))
        for real in SCHEMA["properties"]:
            letters = real.lstrip("$")
            middle = len(real) - len(letters) + len(letters) // 2
            swapped = real[:middle - 1] + real[middle] + real[middle - 1] + real[middle + 1:]
            for typo in (real.upper(), real[:-1] + real[-1].upper(), swapped):
                with self.subTest(real=real, typo=typo):
                    self.assertNotEqual(typo, real)
                    document = _base()
                    document[typo] = document.pop(real) if real in document else values[real]
                    refusal = loader_refusal(document)
                    self.assertIsNotNone(refusal, f"the loader ACCEPTS a root {typo!r}")
                    self.assertIn(f"did you mean '{real}' for '{typo}'", refusal)
                    self.assertNotEqual(schema_errors(document), [])
        # Control: the real keys themselves still load.
        document = _base()
        document.update(values)
        self.assertIsNone(loader_refusal(document))


def _renamed_at(pointer: str, old: str, new: str) -> Callable[[dict], None]:
    def apply(document: dict) -> None:
        node: Any = document
        for part in pointer.strip("/").split("/"):
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[new] = node.pop(old)
    return apply


def _at(document: dict, pointer: str) -> Any:
    node: Any = document
    for part in (part for part in pointer.strip("/").split("/") if part):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def _swapped(key: str) -> str:
    """``key`` with two adjacent letters near its middle swapped (``inject``
    to ``injcet``): a pair of differing letters, so the slip is a real one and
    not a separator moved."""
    for offset in range(len(key)):
        for index in {len(key) // 2 + offset, len(key) // 2 - offset}:
            if 1 <= index < len(key):
                left, right = key[index - 1], key[index]
                if left.isalnum() and right.isalnum() and left != right:
                    return key[:index - 1] + right + left + key[index + 1:]
    raise AssertionError(f"no two letters to swap in {key!r}")


#: Each object below the root whose near-misses the loader refuses, where the
#: annotated base has one, with the loader's own key set for it.
_NEAR_MISS_OBJECTS = {
    "identity": ("identities/owner", core._IDENTITY_KEYS),
    "check": ("checks/0", core._CHECK_KEYS),
    "session": ("identities/owner/session", core._SESSION_KEYS),
    "login-step capture": ("identities/owner/session/login/0/capture/csrf_login",
                           core._CAPTURE_SPEC_KEYS),
    "session capture": ("identities/owner/session/capture/csrf", core._CAPTURE_SPEC_KEYS),
    "inject entry": ("identities/owner/session/inject/0", core._INJECT_KEYS),
    "expectation": ("checks/0/expect/owner", core._MARKER_EXPECT_KEYS),
    "sequence": ("sequences/0", sequence.SEQUENCE_KEYS),
    "step": ("sequences/0/steps/0", sequence.STEP_KEYS),
    "teardown entry": ("sequences/0/teardown/0", sequence.TEARDOWN_KEYS),
}


class SwappedLettersBelowTheRootTest(unittest.TestCase):
    """Two swapped letters are a near-miss below the root as well as at it.

    The swapped-letters fallback lived only in the root check; everywhere else
    a near-miss was difflib at 0.85, which scores a swap in a six-letter key
    0.83. So a session ``injcet`` loaded with no ``inject`` and no error, the
    CSRF header never added, and ``lgoin``, a sequence or step ``nmae`` and an
    expectation ``statsu`` beside ``status`` loaded the same way (measured
    with loader_refusal)."""

    def test_the_swaps_that_loaded_are_refused(self) -> None:
        cases = {
            "session injcet": _renamed_at("identities/owner/session", "inject", "injcet"),
            "session lgoin": _renamed_at("identities/owner/session", "login", "lgoin"),
            "sequence nmae": _renamed_at("sequences/0", "name", "nmae"),
            "step nmae": _renamed_at("sequences/0/steps/0", "name", "nmae"),
            "expectation statsu": _set("checks/0/expect/owner/statsu", [403]),
            "step expectation statsu": _set("sequences/0/steps/1/expect/statsu", [200]),
        }
        for case, mutate in cases.items():
            with self.subTest(case=case):
                document = _base()
                mutate(document)
                refusal = loader_refusal(document)
                self.assertIsNotNone(refusal, f"the loader ACCEPTS {case}")
                self.assertIn("unsupported keys: " + case.split()[-1], refusal)

    def test_a_swap_of_every_key_of_every_object_is_refused(self) -> None:
        """Driven by the loader's own key sets, so a key added to one of these
        objects is covered here without anyone listing it. The swapped key is
        put beside the real one, so the refusal cannot come from the real key
        going missing."""
        for place, (pointer, known) in _NEAR_MISS_OBJECTS.items():
            for real in sorted(known):
                typo = _swapped(real)
                with self.subTest(place=place, typo=typo):
                    self.assertNotIn(typo, known)
                    document = _base()
                    node = _at(document, pointer)
                    node[typo] = copy.deepcopy(node.get(real, "x"))
                    refusal = loader_refusal(document)
                    self.assertIsNotNone(refusal, f"the loader ACCEPTS {typo!r} in a {place}")
                    self.assertIn(f"unsupported keys: {typo}", refusal)

    def test_every_near_miss_refusal_says_to_start_an_annotation_with_an_underscore(
        self,
    ) -> None:
        """REGRESSION. Only the root and identity refusals (and `coverage`'s)
        said to start an annotation with '_'; a session, capture, inject entry,
        expectation, sequence, step, teardown entry and every request-shaped
        block named the near-miss and stopped, though the README said "as the
        refusal says" (reproduced). Each now says it, and the
        advice is true: the '_' spelling of the same key loads, and the
        schema accepts it."""
        places = {"the root": ("", core._ROOT_KEYS)} | _NEAR_MISS_OBJECTS | {
            "check request": ("checks/0/request", core._REQUEST_KEYS),
            "step request": ("sequences/0/steps/0/request", core._REQUEST_KEYS),
            "teardown request": ("sequences/0/teardown/0/request", core._REQUEST_KEYS),
            "marker_probe": ("identities/owner/marker_probe", core._REQUEST_KEYS),
            "login step": ("identities/owner/session/login/0", core._LOGIN_STEP_KEYS),
            "step expect": ("sequences/0/steps/1/expect", core._MARKER_EXPECT_KEYS),
        }
        for place, (pointer, known) in places.items():
            for real in sorted(known):
                typo = _swapped(real)
                with self.subTest(place=place, typo=typo):
                    document = _base()
                    node = _at(document, pointer)
                    node[typo] = copy.deepcopy(node.get(real, "x"))
                    refusal = loader_refusal(document)
                    self.assertIsNotNone(refusal, f"the loader ACCEPTS {typo!r} in a {place}")
                    self.assertRegex(refusal, rf"unsupported (top-level )?keys: {re.escape(typo)}")
                    self.assertRegex(refusal, r"start (it|them) with '_' if (it is an "
                                              r"annotation|they are annotations)")
                    del node[typo]
                    node["_" + typo] = "a note"
                    self.assertIsNone(loader_refusal(document), f"'_{typo}' in a {place}")
                    self.assertEqual(schema_errors(document), [], f"'_{typo}' in a {place}")

    def test_a_key_that_is_no_slip_still_loads_as_an_annotation(self) -> None:
        """Control: the same objects still take a key that is no near-miss,
        so the test above is not passing on a loader that refuses everything."""
        for place, (pointer, _known) in _NEAR_MISS_OBJECTS.items():
            with self.subTest(place=place):
                document = _base()
                _at(document, pointer)["zqxw"] = "a note"
                self.assertIsNone(loader_refusal(document))


#: A matrix the annotated base's identities can carry, for the map-only places.
_MATRIX = {
    "marker_owner": "owner",
    "specimens": {"/docs/{id}": [{"label": "owner_doc", "values": {"id": "1"}}]},
}


def _with_matrix(document: dict) -> None:
    document["matrix"] = copy.deepcopy(_MATRIX)


class RootDescriptionNearMissTest(unittest.TestCase):
    """The schema's root description says where the loader refuses a near-miss
    and where it does not; each place it names is tried here.

    The description said unknown keys that are near-misses of a real key are
    refused at load, in most objects and the root included. At the root that
    was false for ``matrix``, and it was false outright for ``target`` and a
    check's own keys, where a misspelt ``teardown_timeout_seconds`` or
    ``name`` loads and is dropped (measured 2026-10-14). It then listed only
    some of the objects that refuse one: a login step, ``establishes``, an
    inject entry, a capture, a teardown entry and ``matrix`` refused near-misses
    too, and several of them every unknown key."""

    #: Each place the description says only a near-miss is refused: the
    #: pointer and the real keys there. A swap of one is refused, and beside
    #: them a key that is no slip loads.
    NEAR_MISS_IN = {"the root": ("", core._ROOT_KEYS)} | _NEAR_MISS_OBJECTS
    #: Each place it says every unknown key is refused at load.
    EVERY_KEY_IN = {
        "check request": "checks/0/request",
        "step request": "sequences/0/steps/0/request",
        "teardown request": "sequences/0/teardown/0/request",
        "marker_probe": "identities/owner/marker_probe",
        "login step": "identities/owner/session/login/0",
        "session `establishes`": "identities/owner/session/establishes",
    }
    #: Each place it says ``map`` refuses every unknown key.
    MAP_EVERY_KEY_IN = {
        "`matrix`": "matrix",
        "each specimen": "matrix/specimens/~1docs~1{id}/0",
    }
    #: The commands it says refuse every unknown key in the places below, by
    #: measuring coverage, and those places. The commands all reach
    #: compute_coverage through cli._coverage_report.
    COVERAGE_COMMANDS = {"`veridor coverage`", "`run --openapi`", "`map`"}
    COVERAGE_EVERY_KEY_IN = {"`coverage`": "coverage"}
    #: Each place it says a near-miss is not looked for, and one.
    NOT_CHECKED_IN = {
        "`target`": _renamed_at("target", "teardown_timeout_seconds", "Teardown_timeout_seconds"),
        "a teardown entry's `expect`": _set("sequences/0/teardown/0/expect/Status", [200]),
    }

    @staticmethod
    def _listed(phrase: str) -> set[str]:
        items = re.split(r",\s*(?:or\s+|and\s+)?|\s+(?:or|and)\s+", phrase)
        return {re.sub(r"^in\s+", "", item.strip()) for item in items}

    def _claim(self, pattern: str, what: str) -> re.Match:
        found = re.search(pattern, SCHEMA["description"])
        self.assertIsNotNone(found, f"the root description no longer says {what}")
        return found

    def _node(self, document: dict, pointer: str) -> dict:
        node: Any = document
        for part in (part for part in pointer.split("/") if part):
            part = part.replace("~1", "/").replace("~0", "~")
            node = node[int(part)] if isinstance(node, list) else node[part]
        return node

    def test_the_description_names_exactly_the_places_tried_here(self) -> None:
        near = self._claim(
            r"refuses one that is a near-miss of a real key, two swapped letters included "
            r"\(exit 2, at load\), at (the root) and in each ([^.;]+)\.",
            "where the loader refuses a near-miss")
        every = self._claim(
            r"It refuses every unknown key, near-miss or not, in each ([^.;]+), and `map` "
            r"does the same in ([^.;]+)\.",
            "where the loader refuses every unknown key")
        not_checked = self._claim(r"does not look for near-misses in ([^.;]+);",
                                  "where the loader does not look for near-misses")
        self.assertEqual({near.group(1)} | self._listed(near.group(2)), set(self.NEAR_MISS_IN))
        self.assertEqual(self._listed(every.group(1)), set(self.EVERY_KEY_IN))
        self.assertEqual(self._listed(every.group(2)), set(self.MAP_EVERY_KEY_IN))
        self.assertEqual(self._listed(not_checked.group(1)), set(self.NOT_CHECKED_IN))
        measured = self._claim(
            r"Whatever measures boundary coverage \(([^)]+)\) does the same in ([^.;,]+), "
            r"a `null` `denial_statuses` and a `coverage` that is not an object included, "
            r"and reports coverage as not measured\.",
            "that whatever measures coverage refuses every unknown key in its block")
        self.assertEqual(self._listed(measured.group(1)), self.COVERAGE_COMMANDS)
        self.assertEqual(self._listed(measured.group(2)), set(self.COVERAGE_EVERY_KEY_IN))

    def test_coverage_refuses_every_unknown_key_where_the_description_says(self) -> None:
        """The `coverage` block is refused by the measurement, not at load: a
        `run` without `--openapi` never reads it. Each claim is tried with the
        refusal it names, and the base is measured first as the control."""
        for place, pointer in self.COVERAGE_EVERY_KEY_IN.items():
            with self.subTest(place=place):
                document = _base()
                document["coverage"] = {"denial_statuses": [403], "_note": "an annotation"}
                self.assertIsNone(coverage_refusal(document), "control: the base is measured")
                for key in ("zqxw", "Denial_Statuses"):
                    self._node(document, pointer)[key] = [403]
                    refusal = coverage_refusal(document)
                    self.assertIsNotNone(refusal, f"the description says every unknown key "
                                         f"in {place} is refused; coverage accepts {key!r}")
                    self.assertIn(f"unsupported keys: {key}", refusal)
                    self.assertNotEqual(schema_errors(document), [])
                    del self._node(document, pointer)[key]
        for block, says in (({"denial_statuses": None}, "coverage.denial_statuses"),
                            ([403], "coverage must be an object"),
                            (None, "coverage must be an object")):
            with self.subTest(block=block):
                document = _base()
                document["coverage"] = block
                refusal = coverage_refusal(document)
                self.assertIsNotNone(refusal, f"the description says {block!r} is refused")
                self.assertIn(says, refusal)
                self.assertNotEqual(schema_errors(document), [])

    def test_the_loader_refuses_a_near_miss_where_the_description_says(self) -> None:
        for place, (pointer, known) in self.NEAR_MISS_IN.items():
            with self.subTest(place=place):
                document = _base()
                node = self._node(document, pointer)
                real = next(key for key in sorted(known) if key in node)
                node[_swapped(real)] = copy.deepcopy(node[real])
                self.assertIsNotNone(loader_refusal(document),
                                     f"the description says a near-miss in {place} is "
                                     "refused at load; the loader accepts one")
                self.assertNotEqual(schema_errors(document), [])
                # And only a near-miss: a key that is no slip loads there.
                document = _base()
                self._node(document, pointer)["zqxw"] = "a note"
                self.assertIsNone(loader_refusal(document),
                                  f"the loader refuses every unknown key in {place}; "
                                  "the description says only a near-miss")

    def test_the_loader_refuses_every_unknown_key_where_the_description_says(self) -> None:
        tables = ((self.EVERY_KEY_IN, lambda document: None),
                  (self.MAP_EVERY_KEY_IN, _with_matrix))
        for table, prepare in tables:
            for place, pointer in table.items():
                with self.subTest(place=place):
                    document = _base()
                    prepare(document)
                    self.assertIsNone(loader_refusal(document), "control: the base loads")
                    self._node(document, pointer)["zqxw"] = "a note"
                    refusal = loader_refusal(document)
                    self.assertIsNotNone(refusal, f"the description says every unknown key "
                                         f"in {place} is refused; the loader accepts 'zqxw'")
                    self.assertIn("unsupported keys: zqxw", refusal)

    def test_the_loader_does_not_check_where_the_description_says_so(self) -> None:
        """If one of these starts being refused, the loader got stricter: take
        the place out of the description's exception list (and this table)."""
        for place, mutate in self.NOT_CHECKED_IN.items():
            with self.subTest(place=place):
                document = _base()
                mutate(document)
                self.assertIsNone(loader_refusal(document))
                self.assertNotEqual(schema_errors(document), [],
                                    "the description says this schema refuses every "
                                    "unknown key")


def _node(pointer: str) -> Any:
    return VALIDATOR._resolve("#" + pointer)


def _keys(pointer: str) -> set[str]:
    return set(_node(pointer)["properties"])


class KeySetTest(unittest.TestCase):
    """Every key the schema names is one the loader reads, and the other way
    round: compared against the loader's own constants, not restated."""

    def test_object_keys(self) -> None:
        pairs = {
            "/$defs/identity": core._IDENTITY_KEYS,
            "/$defs/request": core._REQUEST_KEYS,
            "/$defs/request_shape": core._REQUEST_KEYS,
            "/properties/checks/items": core._CHECK_KEYS,
            "/$defs/expectation": core._MARKER_EXPECT_KEYS,
            "/$defs/session": core._SESSION_KEYS,
            "/$defs/login_step": core._LOGIN_STEP_KEYS,
            "/$defs/capture": core._CAPTURE_SPEC_KEYS,
            "/$defs/session/properties/establishes": core._ESTABLISHES_KEYS,
            "/$defs/session/properties/inject/items": core._INJECT_KEYS,
            "/properties/sequences/items": sequence.SEQUENCE_KEYS,
            "/$defs/sequence_step": sequence.STEP_KEYS,
            "/$defs/teardown_entry": sequence.TEARDOWN_KEYS,
            "/properties/matrix": matrix._MATRIX_KEYS,
            "/properties/matrix/properties/specimens/additionalProperties/items":
                matrix._SPECIMEN_KEYS,
        }
        for pointer, loader_keys in pairs.items():
            with self.subTest(pointer=pointer):
                self.assertEqual(_keys(pointer), set(loader_keys))

    def test_enumerations(self) -> None:
        self.assertEqual(set(_node("/properties/version")["enum"]), set(core.SUPPORTED_CONFIG_VERSIONS))
        self.assertEqual(
            set(_node("/$defs/session/properties/reestablish")["enum"]),
            set(core._REESTABLISH_SCOPES),
        )
        self.assertEqual(set(_node("/$defs/sequence_step/properties/role")["enum"]), set(sequence.ROLES))
        self.assertEqual(
            set(_node("/$defs/capture/properties/from")["enum"]), set(core._CAPTURE_SOURCES)
        )
        self.assertTrue(
            core.SAFE_METHODS <= set(_node("/$defs/request/properties/method")["enum"])
        )

    def test_limits(self) -> None:
        marker = _node("/$defs/identity/properties/marker")["pattern"]
        self.assertIn(f"{{{core.MIN_MARKER_LENGTH},{core.MAX_MARKER_LENGTH}}}", marker)
        self.assertEqual(_node("/properties/target/properties/timeout_seconds")["maximum"],
                         core.MAX_TIMEOUT_SECONDS)
        self.assertEqual(_node("/$defs/session/properties/login")["maxItems"], core.MAX_LOGIN_STEPS)
        self.assertEqual(_node("/properties/sequences")["maxItems"], sequence.MAX_SEQUENCES)
        self.assertEqual(_node("/properties/sequences/items/properties/steps")["maxItems"],
                         sequence.MAX_STEPS)
        self.assertEqual(_node("/properties/sequences/items/properties/teardown")["maxItems"],
                         sequence.MAX_TEARDOWN)
        self.assertEqual(_node("/$defs/sequence_step/properties/capture")["maxProperties"],
                         sequence.MAX_CAPTURES_PER_STEP)
        self.assertEqual(_node("/$defs/identity/properties/marker")["pattern"],
                         f"^{core.MARKER_PATTERN.pattern}{{{core.MIN_MARKER_LENGTH},"
                         f"{core.MAX_MARKER_LENGTH}}}$".replace("+{", "{"))
        self.assertEqual(_node("/properties/checks/items/properties/expect")["minProperties"], 2)
        self.assertEqual(_node("/properties/identities")["minProperties"], 2)


class ValidatorControlTest(unittest.TestCase):
    """The validator above has to be able to say no, keyword by keyword."""

    def test_each_keyword_can_fail(self) -> None:
        cases = [
            ({"type": "object"}, []),
            ({"enum": [1, 2]}, True),
            ({"const": 2}, 1),
            ({"pattern": "^a"}, "b"),
            ({"minLength": 2}, "a"),
            ({"maxLength": 1}, "ab"),
            ({"minimum": 1}, 0),
            ({"maximum": 1}, 2),
            ({"exclusiveMinimum": 0}, 0),
            ({"minItems": 1}, []),
            ({"maxItems": 1}, [1, 2]),
            ({"items": {"type": "string"}}, [1]),
            ({"required": ["a"]}, {}),
            ({"minProperties": 1}, {}),
            ({"maxProperties": 0}, {"a": 1}),
            ({"dependentRequired": {"a": ["b"]}}, {"a": 1}),
            ({"properties": {"a": {"type": "string"}}}, {"a": 1}),
            ({"patternProperties": {"^_": {"type": "string"}}}, {"_a": 1}),
            ({"additionalProperties": False}, {"a": 1}),
            ({"propertyNames": {"pattern": "^a"}}, {"b": 1}),
            ({"allOf": [{"type": "string"}]}, 1),
            ({"anyOf": [{"type": "string"}]}, 1),
            ({"oneOf": [{"type": "integer"}, {"type": "number"}]}, 1),
            ({"not": {"type": "integer"}}, 1),
            ({"if": {"type": "integer"}, "then": {"minimum": 5}}, 1),
            ({"if": {"type": "integer"}, "else": {"type": "null"}}, "x"),
            ({"$ref": "#/$defs/x", "$defs": {"x": {"type": "string"}}}, 1),
            ({"type": "integer"}, True),
        ]
        for schema, instance in cases:
            with self.subTest(schema=schema):
                self.assertNotEqual(SubsetValidator(schema).errors(instance), [])

    def test_an_unimplemented_keyword_is_an_error_not_a_pass(self) -> None:
        with self.assertRaises(UnsupportedKeyword):
            SubsetValidator({"uniqueItems": True}).errors([1, 1])

    def test_the_published_schema_uses_only_implemented_keywords(self) -> None:
        """Walks every subschema, reached by a document or not: a keyword the
        validator lacks would otherwise pass wherever no test document goes."""
        implemented = {name[3:] for name in dir(SubsetValidator) if name.startswith("_k_")}
        allowed = implemented | {"$ref"} | _ANNOTATIONS | {"then", "else"}
        seen: set[str] = set()

        def walk(node: Any, where: str) -> None:
            if isinstance(node, bool):
                return
            self.assertIsInstance(node, dict, where)
            unknown = {key for key in node if key not in allowed and key.lstrip("$") not in implemented}
            self.assertEqual(unknown, set(), f"{where} uses unimplemented keywords")
            seen.update(node)
            for key in ("properties", "patternProperties", "$defs"):
                for name, child in node.get(key, {}).items():
                    walk(child, f"{where}/{key}/{name}")
            for key in ("additionalProperties", "items", "propertyNames", "not", "if", "then", "else"):
                if key in node:
                    walk(node[key], f"{where}/{key}")
            for key in ("allOf", "anyOf", "oneOf"):
                for index, child in enumerate(node.get(key, [])):
                    walk(child, f"{where}/{key}/{index}")

        walk(SCHEMA, "#")
        self.assertIn("oneOf", seen)
        self.assertIn("$ref", seen)


if __name__ == "__main__":
    unittest.main()
