#!/usr/bin/env python3
"""Can somebody write a working config from the published documentation alone?

WHAT THIS IS NOT
----------------
It is not a user study. The honest version of this question is one person, the
README, a clock, and no help -- and nothing mechanical substitutes for that,
because the thing a real subject measures is whether the document makes SENSE,
and no script can fail that test. Treat every number here as a lower bound on
the problems a real subject would hit.

What it does measure is three failure modes that do not need a naive subject,
because they are properties of the artifacts rather than of the reader:

1. DOES THE DOCUMENTATION WORK.  Every complete configuration in the README is
   extracted and validated. A documented example that does not load is the
   worst possible first five minutes, and it is invisible to the person who
   wrote it because they already know what it meant to say.

2. IS EVERY KEY DISCOVERABLE.  The configurations this repository ships are the
   ground truth for "keys that matter". Any key a working config needs and the
   README never shows is a key a reader cannot know about, however carefully
   they read.

3. CAN YOU RECOVER FROM A MISTAKE.  A first config is wrong. What decides
   whether someone continues is the NEXT thirty seconds: does the refusal name
   the key, say what was expected, and -- when they guessed a plausible synonym
   -- name the real one? A message that says "configuration must be an object
   with version 1" when the user wrote "users" instead of "identities" is
   technically true and practically a dead end.

Run it with:

    python3.12 scripts/blind_config_study.py            # summary
    python3.12 scripts/blind_config_study.py --verbose  # every message in full
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from veridor.core import ConfigError, load_config  # noqa: E402

README = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")

#: A configuration that loads, used as the base every mistake is applied to.
#: Deliberately the minimal one the README documents for drift.
WORKING: dict[str, Any] = {
    "version": 1,
    "target": {"base_url": "http://127.0.0.1:8765"},
    "identities": {
        "owner": {"headers": {"Authorization": "Bearer owner-token"}},
        "outsider": {"headers": {"Authorization": "Bearer outsider-token"}},
    },
    "checks": [
        {
            "id": "invoice-isolation",
            "name": "Invoice isolation",
            "request": {"method": "GET", "path": "/api/invoices/inv-100"},
            "expect": {"owner": {"status": [200]}, "outsider": {"status": [404]}},
        }
    ],
}


def _load(config: dict[str, Any], **kwargs) -> tuple[str, str]:
    """Return (outcome, message). Outcome is ok / refused / crashed.

    Any ``${NAME}`` the configuration references is exported first. A reader
    following the README exports their tokens, so "you did not export
    OWNER_TOKEN" measures this harness rather than the documentation -- an
    earlier version of this script reported every README example as broken for
    exactly that reason.
    """
    for name in set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", json.dumps(config))):
        os.environ.setdefault(name, f"study-placeholder-{name.lower()}")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        try:
            load_config(path, **kwargs)
        except ConfigError as error:
            return "refused", str(error)
        except Exception as error:  # noqa: BLE001 - that is the finding
            return "crashed", f"{type(error).__name__}: {error}"
    return "ok", ""


# ---------------------------------------------------------------------------
# 1. does the documentation work
# ---------------------------------------------------------------------------


def documented_examples() -> list[dict[str, Any]]:
    """Every complete configuration the README shows, validated.

    Fragments -- a block showing only an `expect` or `identities` subtree -- are
    reported separately rather than failed. They are normal documentation, but
    they are also the blocks a reader is most likely to paste into the wrong
    place, so the count is worth seeing.

    A fragment has to be valid as what it is: an object's members, the
    `"matrix": {...}` the README shows, parse once wrapped in braces. A block
    that parses neither way is `unparseable`, and a gap. Every block that
    failed `json.loads` used to be a fragment, so a complete configuration
    broken by a doubled comma left the denominator and the study still read
    TOTAL GAPS: 0.
    """
    results = []
    for index, block in enumerate(re.findall(r"```json\n(.*?)```", README, re.DOTALL)):
        try:
            document = json.loads(block)
        except json.JSONDecodeError as error:
            try:
                json.loads("{" + block + "}")
            except json.JSONDecodeError:
                results.append({"index": index, "verdict": "unparseable",
                                "note": f"not valid JSON, on its own or as an "
                                        f"object's members: {error}"})
            else:
                results.append({"index": index, "verdict": "fragment",
                                "note": "an object's members, not valid JSON on its own"})
            continue
        # A COMPLETE configuration, not a subtree that merely parses. A block
        # showing only `identities` is a fragment illustrating one section, and
        # judging it as a config would report the documentation broken for
        # being deliberately partial.
        if not (isinstance(document, dict)
                and {"version", "target", "identities"} <= set(document)):
            results.append({"index": index, "verdict": "fragment",
                            "note": f"partial: {sorted(document)[:5]}"})
            continue
        # `map` is the verb that accepts a config with no checks.
        outcome, message = _load(document, require_checks="checks" in document)
        results.append({
            "index": index,
            "verdict": "loads" if outcome == "ok" else outcome,
            "note": message,
        })
    return results


# ---------------------------------------------------------------------------
# 2. is every key discoverable
# ---------------------------------------------------------------------------

#: Keys whose names the OPERATOR chooses. A reader cannot look these up and is
#: not meant to: they are identity names, path templates and group labels.
_OPERATOR_NAMED = re.compile(
    r"^(identities\.[^.]+|matrix\.specimens\..+|matrix\.peer_groups\.[^.]+"
    r"|checks\[\]\.expect\.[^.]+)$"
)


def _schema_keys(document: Any, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if isinstance(document, dict):
        for key, value in document.items():
            if key.startswith("_"):
                continue
            path = f"{prefix}.{key}" if prefix else key
            keys.add(path)
            keys |= _schema_keys(value, path)
    elif isinstance(document, list) and document:
        keys |= _schema_keys(document[0], prefix + "[]")
    return keys


def key_coverage() -> dict[str, Any]:
    """Every key the shipped configurations use, checked against the README."""
    keys: set[str] = set()
    for path in sorted((ROOT / "fixtures").glob("veridor*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "identities" in document:
            keys |= _schema_keys(document)

    schema = {key for key in keys if not _OPERATOR_NAMED.match(key)}
    # The leaf name is what a reader searches for.
    undocumented = sorted(
        key for key in schema
        if not re.search(rf"\b{re.escape(key.rsplit('.', 1)[-1])}\b", README)
    )
    return {"total": len(schema), "undocumented": undocumented,
            "documented": len(schema) - len(undocumented)}


# ---------------------------------------------------------------------------
# 3. can you recover from a mistake
# ---------------------------------------------------------------------------


def _rename(old: str, new: str) -> Callable[[dict], dict]:
    def mutate(config: dict) -> dict:
        config[new] = config.pop(old)
        return config
    return mutate


#: Mistakes that a working configuration ACCEPTS on purpose. Listing them keeps
#: the study honest in both directions: an accepted input is only a gap if the
#: acceptance is a trap, and these are conveniences that behave correctly.
TOLERATED: list[tuple[str, Callable[[dict], dict], str]] = [
    ("status as a bare integer",
     lambda c: _in_check(c, "expect", {"owner": {"status": 200},
                                       "outsider": {"status": 404}}),
     "normalised to [200]; a single status is a supported shorthand"),
]

#: (label, mutation, what a useful message must name, which layer validates it).
#:
#: `names` is the string a reader needs to see to know where to look. For a
#: renamed key that is the CORRECT name -- telling somebody who wrote "users"
#: that "users" is unknown helps far less than telling them the word is
#: "identities".
#:
#: `layer` matters because the config loader is not the only validator: the
#: `matrix` section is checked when the matrix is planned. An earlier version of
#: this study ran everything through `load_config` and reported the whole matrix
#: section as unguarded, when in fact it is guarded well, one layer down.
MISTAKES: list[tuple[str, Callable[[dict], dict], str, str]] = [
    ("identities spelled 'users'", _rename("identities", "users"), "identities", "config"),
    ("identities spelled 'identity'", _rename("identities", "identity"), "identities", "config"),
    ("checks spelled 'tests'", _rename("checks", "tests"), "checks", "config"),
    ("checks spelled 'endpoints'", _rename("checks", "endpoints"), "checks", "config"),
    ("target spelled 'api'", _rename("target", "api"), "target", "config"),
    ("base_url at the top level",
     lambda c: {**{k: v for k, v in c.items() if k != "target"},
                "base_url": "http://127.0.0.1:8765"}, "target", "config"),
    ("identities as a list",
     lambda c: {**c, "identities": [{"name": "owner"}, {"name": "outsider"}]},
     "identities", "config"),
    ("version missing", lambda c: {k: v for k, v in c.items() if k != "version"},
     "version", "config"),
    ("version as a string", lambda c: {**c, "version": "1"}, "version", "config"),
    ("expect as a list",
     lambda c: _in_check(c, "expect", [{"owner": {"status": [200]}}]), "expect", "config"),
    ("request.url instead of request.path",
     lambda c: _in_check(c, "request", {"method": "GET",
                                        "url": "/api/invoices/inv-100"}), "path", "config"),
    ("method in lower case",
     lambda c: _in_check(c, "request", {"method": "get",
                                        "path": "/api/invoices/inv-100"}), "method", "config"),
    ("headers misplaced above the identity",
     lambda c: {**c, "identities": {
         "owner": {"Authorization": "Bearer owner-token"},
         "outsider": {"Authorization": "Bearer outsider-token"}}}, "headers", "config"),
    ("an expectation naming an identity that does not exist",
     lambda c: _in_check(c, "expect", {"owner": {"status": [200]},
                                       "attacker": {"status": [404]}}), "attacker", "config"),
    ("contains_marker without a marker anywhere",
     lambda c: _in_check(c, "expect", {"owner": {"status": [200],
                                                 "contains_marker": "owner"},
                                       "outsider": {"status": [404]}}), "marker", "config"),
    ("two checks sharing one id",
     lambda c: {**c, "checks": [c["checks"][0], dict(c["checks"][0])]}, "id", "config"),
    ("a full URL in request.path",
     lambda c: _in_check(c, "request",
                         {"method": "GET",
                          "path": "http://127.0.0.1:8765/api/invoices/inv-100"}),
     "path", "config"),
    ("specimens as a list",
     lambda c: {**c, "matrix": {"specimens": [{"id": "inv-100"}]}}, "specimens", "matrix"),
    ("specimens keyed by a concrete path, not a template",
     lambda c: {**c, "matrix": {"specimens": {"/api/invoices/inv-100": [
         {"label": "a", "values": {"id": "inv-100"}}]}}}, "specimen", "matrix"),
    ("specimens spelled 'specimen'",
     lambda c: {**c, "matrix": {"specimen": {"/api/invoices/{id}": [
         {"label": "a", "values": {"id": "inv-100"}}]}}}, "specimen", "matrix"),
    ("peer_groups naming an unknown identity",
     lambda c: {**c, "matrix": {"specimens": {"/api/invoices/{id}": [
         {"label": "a", "values": {"id": "inv-100"}}]},
         "peer_groups": {"tenants": ["owner", "ghost"]}}}, "ghost", "matrix"),
]

#: Words that mean the message said what shape it wanted.
#: A KEYWORD PROXY for "the message said what it wanted", not a judgement of
#: prose. It has false negatives -- a message can explain itself perfectly in
#: words this list does not contain -- so the script prints every message it
#: could not confirm rather than only the count, and the reader decides.
_EXPECTATION = re.compile(
    r"\b(must|expected|requires?|should|list|object|string|integer|one of|"
    r"non-empty|unknown|unsupported|duplicate|did you mean|write|generate "
    r"one with|supported|is not|instead|only)\b", re.IGNORECASE
)


def _in_check(config: dict, key: str, value: Any) -> dict:
    check = dict(config["checks"][0])
    check.pop(key, None)
    check[key] = value
    return {**config, "checks": [check]}


def _plan(config: dict[str, Any]) -> tuple[str, str]:
    """Validate the `matrix` section the way `veridor map` does."""
    from veridor.matrix import MatrixError, plan_matrix  # noqa: PLC0415
    from veridor.openapi import load_spec, parse_spec  # noqa: PLC0415

    outcome, message = _load(config, require_checks=False)
    if outcome != "ok":
        return outcome, message
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "veridor.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        loaded = load_config(path, require_checks=False)
    spec = ROOT / "fixtures" / "openapi.demo.json"
    inventory = parse_spec(load_spec(spec), source=str(spec))
    try:
        plan_matrix(loaded, inventory)
    except (MatrixError, ConfigError) as error:
        # MatrixError is not a ConfigError by design, but the CLI turns both
        # into `veridor: ...` and exit 2, so from a reader's seat they are the
        # same event: a refusal with a message.
        return "refused", str(error)
    except Exception as error:  # noqa: BLE001 - that is the finding
        return "crashed", f"{type(error).__name__}: {error}"
    return "ok", ""


def error_recovery() -> list[dict[str, Any]]:
    results = []
    for label, mutate, needle, layer in MISTAKES:
        config = mutate(json.loads(json.dumps(WORKING)))
        outcome, message = (_plan if layer == "matrix" else _load)(config)
        names = bool(re.search(rf"\b{re.escape(needle)}\b", message, re.IGNORECASE))
        expected = bool(_EXPECTATION.search(message))
        results.append({
            "mistake": label,
            "layer": layer,
            "outcome": outcome,
            "names_the_key": names,
            "says_expected": expected,
            # The whole point: refused, points at the right word, and says what
            # it wanted. Anything less and the reader is guessing again.
            "actionable": outcome == "refused" and names and expected,
            "message": message,
            "needle": needle,
        })
    return results


def tolerated_inputs() -> list[dict[str, Any]]:
    """Inputs Veridor accepts on purpose. An acceptance is only a gap if it is
    a trap, and these are conveniences that do the right thing."""
    results = []
    for label, mutate, why in TOLERATED:
        outcome, message = _load(mutate(json.loads(json.dumps(WORKING))))
        results.append({"input": label, "outcome": outcome, "why": why,
                        "message": message})
    return results


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Blind-config study")
    parser.add_argument("--verbose", action="store_true",
                        help="print every refusal message in full")
    args = parser.parse_args(argv)

    print("BLIND-CONFIG STUDY")
    print("A mechanical proxy for a user study, not a substitute for one.")
    print("Every number here is a LOWER bound on what a real subject would hit.\n")

    print("1. DO THE README'S OWN CONFIGURATIONS LOAD?")
    examples = documented_examples()
    complete = [e for e in examples if e["verdict"] in {"loads", "refused", "crashed"}]
    loads = [e for e in complete if e["verdict"] == "loads"]
    unparseable = [e for e in examples if e["verdict"] == "unparseable"]
    broken = [e for e in complete if e["verdict"] != "loads"] + unparseable
    fragments = [e for e in examples if e["verdict"] == "fragment"]
    print(f"   {len(loads)}/{len(complete)} complete configurations load")
    print(f"   {len(fragments)} block(s) are fragments a reader must place correctly")
    if unparseable:
        print(f"   {len(unparseable)} block(s) are not valid JSON, so nobody can "
              "say whether they were complete")
    for entry in broken:
        print(f"   BROKEN block {entry['index']}: {entry['note']}")

    print("\n2. IS EVERY KEY A WORKING CONFIG NEEDS SHOWN IN THE README?")
    coverage = key_coverage()
    print(f"   {coverage['documented']}/{coverage['total']} schema keys appear")
    for key in coverage["undocumented"]:
        print(f"   UNDOCUMENTED: {key}")

    print("\n3. CAN A READER RECOVER FROM A PLAUSIBLE FIRST MISTAKE?")
    recovery = error_recovery()
    actionable = [r for r in recovery if r["actionable"]]
    crashed = [r for r in recovery if r["outcome"] == "crashed"]
    accepted = [r for r in recovery if r["outcome"] == "ok"]
    print(f"   {len(actionable)}/{len(recovery)} refusals are actionable "
          "(refused, names the right word, says what it expected)")
    print("   'says what it expected' is a keyword proxy and has false "
          "negatives; every\n   unconfirmed message is printed below so you "
          "can judge it yourself.")
    if crashed:
        print(f"   {len(crashed)} CRASHED with a traceback instead of a refusal")
    if accepted:
        print(f"   {len(accepted)} were ACCEPTED silently")

    tolerated = tolerated_inputs()
    if tolerated:
        print("\n   Accepted on purpose (a convenience, not a trap):")
        for entry in tolerated:
            state = "accepted" if entry["outcome"] == "ok" else entry["outcome"]
            print(f"     [{state}] {entry['input']} — {entry['why']}")

    for entry in recovery:
        if entry["actionable"] and not args.verbose:
            continue
        flag = {"crashed": "CRASH", "ok": "ACCEPTED"}.get(
            entry["outcome"], "OK" if entry["actionable"] else "WEAK")
        print(f"\n   [{flag}] {entry['mistake']}")
        print(f"        wanted the word {entry['needle']!r}: "
              f"{'yes' if entry['names_the_key'] else 'NO'}")
        print(f"        {entry['message'] or '(no message -- it was accepted)'}")

    failures = len(broken) + len(coverage["undocumented"]) + (
        len(recovery) - len(actionable))
    print(f"\nTOTAL GAPS: {failures}")
    print("A gap here is a place a reader stops. None of them is a crash, and "
          "that is exactly\nwhy they survive: nothing else in this repository "
          "fails when the documentation does.")
    # This returned 0 whatever it counted, so the script run by hand exited 0
    # beneath "TOTAL GAPS: 1"; only a test reading the text could fail.
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
