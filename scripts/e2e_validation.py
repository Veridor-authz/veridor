#!/usr/bin/env python3
"""Exercise runner, regression detection, SARIF, persistence, and UI APIs."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import threading
from pathlib import Path
from urllib.request import urlopen

#: The oldest interpreter this project runs on, matching ``requires-python``.
MINIMUM_PYTHON = (3, 11)

if sys.version_info < MINIMUM_PYTHON:
    # The README invokes this with a bare ``python3``. On macOS that is 3.9,
    # and without this guard the first thing a new user sees is an
    # ImportError traceback out of ``veridor/cli.py`` naming ``datetime.UTC``,
    # which looks like a bug in the product rather than a wrong interpreter.
    sys.stderr.write(
        "e2e_validation.py needs Python {}.{} or newer; this is {}.{} ({}).\n"
        "Nothing was run. On macOS the bare `python3` is 3.9 -- name the "
        "version instead:\n"
        "    python3.12 scripts/e2e_validation.py\n".format(
            MINIMUM_PYTHON[0],
            MINIMUM_PYTHON[1],
            sys.version_info[0],
            sys.version_info[1],
            sys.executable,
        )
    )
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from scripts.demo_server import OWNER_MARKER  # noqa: E402
from scripts.demo_server import create_server as create_demo_server  # noqa: E402
from veridor.cli import main as veridor_main  # noqa: E402
from veridor.server import create_server as create_ui_server  # noqa: E402


def _start(server) -> threading.Thread:
    # 0.05 s, not the stdlib's 0.5 s: tests/test_e2e.py runs this in the test
    # process, where tests/loopback.py refuses a server that polls more slowly
    # (every shutdown() would wait out the poll).
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return thread


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"E2E validation failed: {message}")


def _fresh(output_dir: Path) -> Path:
    """Empty a directory this script owns, then return it.

    Several assertions here are of the form "this invocation wrote nothing",
    and they are written as ``not path.exists()``. That is only the same
    question when the directory starts empty. It did not: ``main`` defaults to
    ``ROOT/.veridor/e2e`` and nothing cleaned it, so the SECOND run of the
    documented ``python3 scripts/e2e_validation.py`` in a checkout found the
    FIRST run's real ``map`` artifact still sitting there and reported
    ``map --dry-run wrote an artifact`` -- a documented safety property
    announced as violated when the dry run was innocent. CI never saw it:
    ``.github/workflows/veridor.yml`` runs ``python scripts/e2e_validation.py``
    once, on the Linux 3.12 leg, in a fresh checkout where ``.veridor/`` is
    untracked, so the default directory always started empty there.

    Only ever called on a directory this script creates and writes itself.
    """
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    return output_dir


def validate(output_dir: Path) -> None:
    _fresh(output_dir)
    config = ROOT / "fixtures" / "veridor.demo.json"
    safe_report = output_dir / "safe-run.json"
    regression_report = output_dir / "regression-run.json"
    sarif_report = output_dir / "veridor.sarif"
    regression_sarif = output_dir / "regression.sarif"

    safe_api = create_demo_server("127.0.0.1", 0)
    vulnerable_api = create_demo_server("127.0.0.1", 0, vulnerable=True)
    _start(safe_api)
    _start(vulnerable_api)
    try:
        safe_url = f"http://127.0.0.1:{safe_api.server_port}"
        safe_exit = veridor_main(
            [
                "run",
                "--config",
                str(config),
                "--base-url",
                safe_url,
                "--output-dir",
                str(output_dir),
                "--json",
                str(safe_report),
                "--sarif",
                str(sarif_report),
            ]
        )
        _require(safe_exit == 0, f"safe validation exited {safe_exit}")
        safe_run = _json(safe_report)
        _require(safe_run["status"] == "passed", "safe run was not marked passed")
        _require(safe_run["schema_version"] == 2, "safe run is not a v2 document")
        _require(
            safe_run["summary"]
            == {
                "checks": 2,
                "probes": 6,
                "safe": 6,
                "vulnerable": 0,
                "unexpected_denial": 0,
                "inconclusive": 0,
                "non_asserting": 0,
                "probe_licensed_exclusions": 0,
                "confirmed": 0,
                "suspected": 0,
                "ungraded": 0,
                "new": 0,
                "resolved": 0,
                "unchanged": 0,
                "escalated": 0,
            },
            "safe run summary did not match expected coverage",
        )

        vulnerable_url = f"http://127.0.0.1:{vulnerable_api.server_port}"
        regression_exit = veridor_main(
            [
                "run",
                "--config",
                str(config),
                "--base-url",
                vulnerable_url,
                "--output-dir",
                str(output_dir),
                "--baseline",
                str(safe_report),
                "--json",
                str(regression_report),
                "--sarif",
                str(regression_sarif),
            ]
        )
        _require(
            regression_exit == 1,
            "new authorization regression did not fail the gate",
        )
        regression = _json(regression_report)
        _require(regression["summary"]["new"] == 1, "expected exactly one new finding")
        _require(
            regression["findings"][0]["identity"] == "other_tenant",
            "regression was not attributed to the cross-tenant identity",
        )
        _require(
            regression["findings"][0]["evidence_grade"] == "confirmed",
            "cross-tenant leak was not confirmed by the marker oracle",
        )
        _require(
            regression["findings"][0]["evidence"]["marker"]["state"] == "present",
            "marker evidence did not record the observed marker",
        )
        for artifact in (
            safe_report,
            regression_report,
            sarif_report,
            regression_sarif,
            output_dir / "latest.json",
            *sorted((output_dir / "runs").glob("*.json")),
        ):
            _require(
                OWNER_MARKER not in artifact.read_text(encoding="utf-8"),
                f"marker literal was persisted into {artifact.name}",
            )
        sarif = _json(regression_sarif)
        _require(sarif["version"] == "2.1.0", "SARIF version is not 2.1.0")
        _require(
            sarif["runs"][0]["results"][0]["ruleId"] == "VERIDOR-AUTHZ-001",
            "SARIF does not contain the authorization finding",
        )

        ui = create_ui_server(output_dir, "127.0.0.1", 0)
        _start(ui)
        try:
            ui_url = f"http://127.0.0.1:{ui.server_port}"
            with urlopen(f"{ui_url}/api/runs", timeout=2) as response:
                history = json.load(response)
            _require(len(history["runs"]) >= 2, "UI history omitted persisted runs")
            with urlopen(ui_url, timeout=2) as response:
                _require(
                    b"Regression diff" in response.read(),
                    "UI shell omitted the regression diff view",
                )
            with urlopen(f"{ui_url}/api/runs/{regression['run_id']}", timeout=2) as response:
                detail = json.load(response)
            _require(
                detail["regression"]["new"][0]["identity"] == "other_tenant",
                "UI run API omitted the regression finding",
            )
        finally:
            ui.shutdown()
            ui.server_close()
    finally:
        safe_api.shutdown()
        safe_api.server_close()
        vulnerable_api.shutdown()
        vulnerable_api.server_close()

    print(
        "E2E PASS: safe multi-user run, regression gate, SARIF, history, findings, and diff UI"
    )


def validate_verbs(output_dir: Path) -> None:
    """The other two verbs, end to end, against the same demo API.

    Deliberately a second function with its own output directory: ``validate``
    asserts a run document byte for byte, and nothing here may perturb it.
    """
    _fresh(output_dir)
    map_config = ROOT / "fixtures" / "veridor.map-demo.json"
    spec = ROOT / "fixtures" / "openapi.demo.json"

    api = create_demo_server("127.0.0.1", 0, vulnerable=True)
    _start(api)
    try:
        base_url = f"http://127.0.0.1:{api.server_port}"

        # -- map ------------------------------------------------------------
        map_out = output_dir / "map"
        dry = veridor_main(
            [
                "map",
                "--config", str(map_config),
                "--openapi", str(spec),
                "--base-url", base_url,
                "--output-dir", str(map_out),
                "--dry-run",
            ]
        )
        _require(dry == 0, f"map --dry-run exited {dry}")
        _require(not map_out.exists(), "map --dry-run wrote an artifact")

        refused = veridor_main(
            [
                "map",
                "--config", str(map_config),
                "--openapi", str(spec),
                "--base-url", base_url,
                "--output-dir", str(map_out),
                "--max-requests", "1",
            ]
        )
        _require(refused == 2, f"an over-budget map plan exited {refused}, not 2")
        _require(not map_out.exists(), "a refused map plan wrote an artifact")

        map_exit = veridor_main(
            [
                "map",
                "--config", str(map_config),
                "--openapi", str(spec),
                "--base-url", base_url,
                "--output-dir", str(map_out),
                "--rate", "10",
                "--promote", str(output_dir / "promotions.json"),
            ]
        )
        _require(map_exit == 0, f"map exited {map_exit}; discovery is never a gate")
        candidates = _json(next((map_out / "candidates").glob("*.json")))
        _require(
            "marker_reach" in {entry["rule"] for entry in candidates["candidates"]},
            "map did not surface the planted cross-tenant read as a candidate",
        )
        _require(
            all(not entry.get("is_finding", False) for entry in candidates["candidates"]),
            "a candidate was marked as a finding",
        )
        _require(
            not (map_out / "latest.json").exists() and not (map_out / "runs").exists(),
            "map wrote into the run history",
        )
        _require(
            not list(map_out.rglob("*.sarif")), "map produced a SARIF artifact"
        )
        promotions = _json(output_dir / "promotions.json")
        # One stub per candidate, or the `all` below is true of nothing.
        _require(
            len(promotions["checks"]) == len(candidates["candidates"]),
            f"{len(promotions['checks'])} promotion stub(s) for "
            f"{len(candidates['candidates'])} candidate(s)",
        )
        _require(
            all("TODO" in check["name"] for check in promotions["checks"]),
            "a promotion stub was presented as complete",
        )

        # -- mutate ---------------------------------------------------------
        mutate_out = output_dir / "mutate"
        mutate_exit = veridor_main(
            [
                "mutate",
                "--config", str(ROOT / "fixtures" / "veridor.demo.json"),
                "--base-url", base_url,
                "--output-dir", str(mutate_out),
                # The demo server is ours and is on loopback. The default is
                # 2 req/s; asserting that default is tests/test_cli_verbs.py's
                # job, and paying for it here would add a minute to the gate.
                "--min-interval", "0",
            ]
        )
        report = _json(mutate_out / "mutation" / "mutation.json")
        _require(report["tier"] == 1, "mutate did not produce a tier 1 report")
        summary = report["summary"]
        _require(summary["generated"] > 0, "mutate generated no mutants")
        # This demo is deterministic and on loopback: every mutant is decided
        # and two survive, so mutate exits 1 every time. Exit 2 -- aberrant or
        # errored, "the engine does not know" -- is a regression here, not an
        # acceptable outcome.
        _require(
            summary["errored"] == 0 and summary["aberrant"] == 0,
            f"mutate left {summary['errored']} errored and {summary['aberrant']} "
            "aberrant mutant(s) against a deterministic demo",
        )
        _require(
            mutate_exit == 1, f"mutate exited {mutate_exit}, not 1 (survivors present)"
        )
        _require(
            "findings" not in report, "a mutation report carried a findings list"
        )
        _require(
            not list(mutate_out.rglob("*.sarif")), "mutate produced a SARIF artifact"
        )
        _require(
            not (mutate_out / "latest.json").exists(),
            "mutate wrote into the run history",
        )

        # -- tier 2 refuses without a restore command, before executing ------
        hooks = output_dir / "hooks.json"
        hooks.write_text(
            json.dumps(
                {
                    "hooks": [
                        {
                            "name": "no-way-back",
                            "removes": "a guard",
                            "apply_command": [sys.executable, "-c", "pass"],
                            "restore_command": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        refusal = veridor_main(
            [
                "mutate",
                "--config", str(ROOT / "fixtures" / "veridor.demo.json"),
                "--base-url", base_url,
                "--output-dir", str(output_dir / "tier2"),
                "--tier", "2",
                "--hooks", str(hooks),
                "--i-understand-tier-2-runs-my-commands",
            ]
        )
        _require(refusal == 2, f"a hook with no restore command exited {refusal}")
        _require(
            not (output_dir / "tier2").exists(),
            "a refused tier-2 run produced an artifact",
        )
        no_ack = veridor_main(
            [
                "mutate",
                "--config", str(ROOT / "fixtures" / "veridor.demo.json"),
                "--base-url", base_url,
                "--output-dir", str(output_dir / "tier2"),
                "--tier", "2",
                "--hooks", str(hooks),
            ]
        )
        _require(no_ack == 2, "tier 2 ran without its acknowledgement flag")
    finally:
        api.shutdown()
        api.server_close()

    print("E2E PASS: map discovery, promotion stubs, mutation score, tier-2 refusals")


def validate_drift(output_dir: Path) -> None:
    """Drift, against one server on one port, patched then regressed.

    The handler class is swapped on the live server rather than starting a
    second one, so both runs address the identical URL. That is the scenario
    drift is for -- somebody deployed -- and it keeps the comparison honest: a
    diff across two ports would be comparing deployments, not changes.

    Two properties matter equally here and only one of them is the feature.
    Drift must FIRE on a real regression, and it must stay SILENT when nothing
    moved. A gate that reports change against an unchanged target gets switched
    off in its first week, and then it is worth nothing on the week it matters.
    """
    _fresh(output_dir)
    map_config = ROOT / "fixtures" / "veridor.map-demo.json"
    spec = ROOT / "fixtures" / "openapi.demo.json"
    matrices = output_dir / "matrix"

    api = create_demo_server("127.0.0.1", 0, vulnerable=False)
    _start(api)
    try:
        base_url = f"http://127.0.0.1:{api.server_port}"

        def run_map(*extra: str) -> int:
            return veridor_main(
                [
                    "map",
                    "--config", str(map_config),
                    "--openapi", str(spec),
                    "--base-url", base_url,
                    "--output-dir", str(output_dir),
                    "--rate", "10",
                    *extra,
                ]
            )

        # -- the gate is refused rather than silently never firing -----------
        naked = run_map("--fail-on-drift", "opened")
        _require(naked == 2, f"--fail-on-drift without --baseline exited {naked}, not 2")

        # -- run 1: record ---------------------------------------------------
        first = run_map()
        _require(first == 0, f"the first map exited {first}; it has no baseline to gate on")
        _require(len(list(matrices.glob("*.json"))) == 1, "map did not record one matrix")

        # The committed-baseline pattern the README gives for CI. It is not
        # only ergonomics: every `map` writes into the directory that
        # `--baseline <dir>` resolves, so an intermediate run silently becomes
        # the baseline and the next comparison is regression-against-regression.
        # A pinned file cannot drift out from under the comparison.
        pinned = output_dir / "baseline-matrix.json"
        pinned.write_text(
            next(iter(matrices.glob("*.json"))).read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        # -- run 2: nothing changed, under the STRICTEST policy ---------------
        # The pinned FILE, not the directory: under a gate the directory form is
        # refused, precisely because this run is about to write into it.
        quiet = run_map(
            "--baseline", str(pinned),
            "--drift", str(output_dir / "quiet.json"),
            "--fail-on-drift", "any",
        )
        _require(quiet == 0, f"drift reported change against an unchanged target (exit {quiet})")
        unchanged = _json(output_dir / "quiet.json")
        _require(
            not unchanged["changes"],
            f"drift invented {len(unchanged['changes'])} change(s) on an unchanged target: "
            f"{unchanged['counts']}",
        )

        # -- somebody ships a regression -------------------------------------
        api.RequestHandlerClass = _vulnerable_handler()

        # -- drift still does not gate unless asked ---------------------------
        ungated = run_map("--baseline", str(pinned))
        _require(
            ungated == 0,
            f"map exited {ungated} without --fail-on-drift; discovery is never a gate",
        )

        # -- run 3: gate on it ------------------------------------------------
        gated = run_map(
            "--baseline", str(pinned),
            "--drift", str(output_dir / "drift.json"),
            "--fail-on-drift", "opened",
        )
        _require(gated == 1, f"drift missed a real regression (exit {gated})")
        report = _json(output_dir / "drift.json")
        kinds = set(report["counts"])
        _require(
            "reach_opened" in kinds,
            f"drift did not see the outsider go from refused to served: {sorted(kinds)}",
        )
        _require(
            "marker_appeared" in kinds,
            f"drift did not see the owner's marker cross the boundary: {sorted(kinds)}",
        )
        _require(report["significant"] >= 2, "a marker crossing was not counted as significant")

        # -- drift is not a finding -------------------------------------------
        _require(
            not (output_dir / "latest.json").exists() and not (output_dir / "runs").exists(),
            "drift wrote into the run history",
        )
        _require(not list(output_dir.rglob("*.sarif")), "drift produced a SARIF artifact")
        blob = json.dumps(report).lower()
        for word in ("vulnerab", "exploit", "insecure", "proven"):
            _require(word not in blob, f"the drift report called a change {word!r}")
    finally:
        api.shutdown()
        api.server_close()

    print("E2E PASS: drift silent on no change, gates on a real regression, never a finding")


def _vulnerable_handler():
    """The same demo API after a bad deploy: one handler class, one port."""
    from scripts.demo_server import make_handler  # noqa: PLC0415

    return make_handler(vulnerable=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / ".veridor" / "e2e",
        help=(
            "scratch directory for the evidence this script produces. Emptied "
            "on every invocation, so the run is repeatable"
        ),
    )
    args = parser.parse_args()
    try:
        validate(args.output_dir)
        validate_verbs(args.output_dir / "verbs")
        validate_drift(args.output_dir / "drift")
    except RuntimeError as exc:
        # A failed assertion is a result, not a crash. A traceback here reads
        # as "the validator broke" when it means "the product broke".
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
