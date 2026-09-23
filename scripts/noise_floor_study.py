#!/usr/bin/env python3
"""How often does drift report change when NOTHING changed?

A gate that cries wolf gets switched off in its first week, and then it is
worth nothing on the week it matters. So this is not a nice-to-have
measurement: it decides whether `--fail-on-drift` belongs in anybody's CI.

The target is `scripts/noisy_server.py`, whose authorization boundary is fixed
for the life of the process and whose everything-else moves the way a real API
moves -- request ids, timestamps, ETags, unstable collection ordering,
transient 429s and 503s, latency past the client timeout. Every change drift
reports against it is therefore a FALSE POSITIVE by construction, and the
question is only how many, of what kind, and whether any of them would fail a
build.

Two numbers matter, and they are not the same number:

    flap rate         runs reporting ANY change.        Gates on --fail-on-drift any
    false gate rate   runs reporting a SIGNIFICANT one. Gates on --fail-on-drift opened

The second is the one that decides the product. `opened` is what the README
tells people to wire into CI, so a non-zero false gate rate is a defect, not a
tuning parameter.

    python3.12 scripts/noise_floor_study.py --runs 25
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from scripts.noisy_server import Noise, create_server  # noqa: E402
from veridor import drift as drift_module  # noqa: E402

CONFIG = {
    "version": 1,
    "target": {"base_url": "http://127.0.0.1:0", "timeout_seconds": 2},
    "identities": {
        "invoice_owner": {
            "headers": {"Authorization": "Bearer owner-token"},
            "marker": "vdr-Xk7Qm2Ls9Rt4Vb8Nc3Zp6Wf1",
        },
        "other_tenant": {"headers": {"Authorization": "Bearer outsider-token"}},
        "administrator": {"headers": {"Authorization": "Bearer admin-token"}},
        "anonymous": {"headers": {}},
    },
    "matrix": {
        "specimens": {
            "/api/invoices/{id}": [{"label": "inv", "values": {"id": "inv-100"}}]
        },
        "marker_owner": "invoice_owner",
    },
}


#: The same fixed boundary the noisy target enforces, written as declarations.
#: Every finding `run` produces against this target is a FALSE finding: the
#: expectations describe exactly what the server does, and it never changes.
RUN_CONFIG = {
    "version": 1,
    "target": {"base_url": "http://127.0.0.1:0", "timeout_seconds": 2},
    "identities": CONFIG["identities"],
    "checks": [
        {
            "id": "invoice-tenant-isolation",
            "name": "Invoice tenant isolation",
            "request": {"method": "GET", "path": "/api/invoices/inv-100"},
            "expect": {
                "invoice_owner": {"status": [200], "contains_marker": "invoice_owner"},
                "other_tenant": {"status": [404], "excludes_marker": "invoice_owner"},
                "anonymous": {"status": [401]},
            },
        },
        {
            "id": "audit-admin-role",
            "name": "Audit log administrator role",
            "request": {"method": "GET", "path": "/api/admin/audit"},
            "expect": {
                "administrator": {"status": [200]},
                "invoice_owner": {"status": [403]},
                "anonymous": {"status": [401]},
            },
        },
    ],
}


def _run_gate(config_path: Path, base_url: str, output: Path) -> tuple[int, dict]:
    """One `veridor run`, returning its exit code and its run document.

    `--require-complete` because that is the gate as it ships: the GitHub
    Action, the GitLab component and the Helm chart all default it on, and
    GitLab fails the job on its exit 3. Without it this measured a posture
    nobody runs: 0/10 at the default noise (seed 7) while 6 and then 7 of
    the same 10 runs, measured twice, failed the shipped build with exit 3.
    """
    result = subprocess.run(
        [
            sys.executable, "-m", "veridor.cli", "run",
            "--config", str(config_path),
            "--base-url", base_url,
            "--output-dir", str(output),
            "--json", str(output / "run.json"),
            "--require-complete",
        ],
        cwd=ROOT,
        env=source_path.child_env(_env()),
        capture_output=True,
        text=True,
    )
    document = json.loads((output / "run.json").read_text(encoding="utf-8"))
    return result.returncode, document


def _run_map(config_path: Path, spec: Path, base_url: str, output: Path) -> int:
    return subprocess.run(
        [
            sys.executable, "-m", "veridor.cli", "map",
            "--config", str(config_path),
            "--openapi", str(spec),
            "--base-url", base_url,
            "--output-dir", str(output),
            "--rate", "10",
        ],
        cwd=ROOT,
        env=source_path.child_env(_env()),
        capture_output=True,
        text=True,
    ).returncode


def _env() -> dict:
    import os  # noqa: PLC0415

    return dict(os.environ)


def _run_mutate(config_path: Path, base_url: str, output: Path) -> tuple[int, dict]:
    """One `veridor mutate`, returning its exit code and its report."""
    result = subprocess.run(
        [
            sys.executable, "-m", "veridor.cli", "mutate",
            "--config", str(config_path),
            "--base-url", base_url,
            "--output-dir", str(output),
            "--json", str(output / "mutation.json"),
        ],
        cwd=ROOT,
        env=source_path.child_env(_env()),
        capture_output=True,
        text=True,
    )
    path = output / "mutation.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return result.returncode, report


def _study_mutate(args, work: Path, config_path: Path, base_url: str, server) -> int:
    """The third verb, under the same noise.

    `mutate` re-runs the whole suite once per mutant, so it multiplies its
    exposure to transients by the number of mutants. Its number is a SCORE --
    "0.86 of your checks can actually fail" -- and a score inflated by rate
    limits tells an operator their suite is stronger than it is, which is the
    one direction a quality metric must never be wrong in.

    The control is the score against a QUIET target: whatever that is, it is
    the truth for this configuration, and any run that beats it under noise is
    banking kills it did not earn.
    """
    scores: list[float] = []
    outcomes: Counter[str] = Counter()
    for index in range(args.runs):
        _, report = _run_mutate(config_path, base_url, work / f"mut-{index}")
        summary = report.get("summary") or {}
        if summary.get("score") is not None:
            scores.append(summary["score"])
        for key in ("killed", "survived", "aberrant", "errored",
                    "not_applicable", "skipped", "generated"):
            outcomes[key] += summary.get(key, 0)
    server.shutdown()
    server.server_close()

    if scores:
        print(f"  score           n={len(scores)}  min={min(scores):.2f}  "
              f"max={max(scores):.2f}  spread={max(scores) - min(scores):.2f}")
    else:
        print(f"  score           none of the {args.runs} runs produced a score")
    print(f"  scored runs     {len(scores)}/{args.runs}")
    print()
    print("  mutant outcomes, summed across runs:")
    for outcome, count in outcomes.most_common():
        print(f"    {outcome:18} {count}")
    return 0


def _study_run(args, work: Path, config_path: Path, base_url: str, server,
               noise: Noise) -> int:
    """The declared gate under the same noise.

    Higher stakes than drift by some distance. `run` emits findings, they carry
    an evidence grade, they become SARIF, and SARIF becomes an alert on
    somebody's pull request. A transient that grades as `vulnerable` is this
    product asserting an authorization failure that did not happen -- the one
    claim it exists to never make.
    """
    if args.detect:
        # No clean baseline needed: `run` grades against the DECLARATION,
        # so the leak is on from the first probe.
        noise.leak = True
    verdicts: Counter[str] = Counter()
    gated = 0
    confirmed = 0
    # Every non-zero exit fails the build, not only 1. An exit 3 is an honest
    # "inconclusive", but a build that goes red on it is still a build that
    # went red against a target whose boundary never moved.
    failed: Counter[int] = Counter()
    examples: list[dict] = []
    for index in range(args.runs):
        code, document = _run_gate(config_path, base_url, work / f"run-{index}")
        if any(f.get("evidence_grade") == "confirmed"
               for f in document.get("findings", [])):
            confirmed += 1
        if code == 1:
            gated += 1
        if code:
            failed[code] += 1
        for finding in document.get("findings", []):
            verdicts[finding["verdict"]] += 1
            if finding["verdict"] in ("vulnerable", "unexpected_denial"):
                examples.append(finding)
    server.shutdown()
    server.server_close()

    if args.detect:
        print(f"  DETECTION RATE   {gated}/{args.runs} ({gated / args.runs:.0%}) runs "
              "exited 1 on the REAL leak → --fail-on new --require-complete, as shipped")
        print(f"  proof-backed     {confirmed}/{args.runs} "
              f"({confirmed / args.runs:.0%}) graded `confirmed` -- the marker was "
              "actually\n                   observed in the outsider's response")
    else:
        builds = sum(failed.values())
        print(f"  FALSE GATE RATE  {builds}/{args.runs} ({builds / args.runs:.0%}) runs "
              "exited non-zero → --fail-on new --require-complete, as shipped")
        for code, count in sorted(failed.items()):
            meaning = {1: "a false finding", 3: "inconclusive: honest, but the build is red"}
            print(f"                   {count} exited {code} ({meaning.get(code, 'error')})")
    print()
    if verdicts:
        caption = ("findings by verdict:" if args.detect
                   else "findings by verdict (every one is false):")
        print(f"  {caption}")
        for verdict, count in verdicts.most_common():
            flag = ""
            if verdict in ("vulnerable", "unexpected_denial") and not args.detect:
                flag = "  <-- ASSERTS A BOUNDARY FAILURE"
            print(f"    {verdict:20} {count}{flag}")
    else:
        print("  no finding of any kind.")
    for finding in ([] if args.detect else examples[:3]):
        print(f"\n    [{finding['verdict']}] {finding.get('title')}")
        print(f"      {finding.get('message', '')[:180]}")
    if args.detect:
        return 0 if gated == args.runs else 1
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=25)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--rate-limit", type=float, default=0.06)
    parser.add_argument("--server-error", type=float, default=0.03)
    parser.add_argument("--slow", type=float, default=0.05)
    parser.add_argument("--quiet-target", action="store_true",
                        help="all noise off: the control, which must report nothing")
    parser.add_argument(
        "--detect", action="store_true",
        help=(
            "the other half of the question. Record the baseline clean, then "
            "open the boundary for real and keep the noise on. Reports a "
            "DETECTION rate, which must be 100%%: a gate that never fires is "
            "not quiet, it is broken."
        ),
    )
    parser.add_argument(
        "--verb", choices=("map", "run", "mutate"), default="map",
        help=(
            "map measures the drift gate; run measures the DECLARED gate, which "
            "emits findings and SARIF. A transient that becomes a false "
            "'vulnerable' is the worst claim this product can make"
        ),
    )
    args = parser.parse_args()

    if args.quiet_target:
        args.rate_limit = args.server_error = args.slow = 0.0

    noise = Noise(
        seed=args.seed,
        rate_limit=args.rate_limit,
        server_error=args.server_error,
        slow=args.slow,
    )
    server = create_server("127.0.0.1", 0, noise)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    print("DRIFT NOISE-FLOOR STUDY")
    # --detect opens the boundary for real (map and run; mutate ignores it).
    # The fixed-boundary caption printed regardless, so the one mode that
    # leaks on purpose called every finding it caught a false positive.
    opened = {
        "map": "boundary clean for the baseline, then opened for real",
        "run": "boundary opened for real from the first probe",
    }.get(args.verb) if args.detect else None
    print(f"  target        {base_url} ({opened or 'boundary fixed for the whole run'})")
    print(f"  noise         rate_limit={args.rate_limit} server_error="
          f"{args.server_error} slow={args.slow}")
    print(f"  runs          {args.runs}")
    if opened:
        print("  The leak below is REAL; a run that misses it is under-detection.\n")
    else:
        print("  Every change below is a FALSE POSITIVE by construction.\n")

    directory = tempfile.mkdtemp()
    work = Path(directory)
    config_path = work / "veridor.json"
    spec = ROOT / "fixtures" / "openapi.demo.json"

    if args.verb == "mutate":
        config_path.write_text(json.dumps(RUN_CONFIG), encoding="utf-8")
        return _study_mutate(args, work, config_path, base_url, server)

    if args.verb == "run":
        config_path.write_text(json.dumps(RUN_CONFIG), encoding="utf-8")
        return _study_run(args, work, config_path, base_url, server, noise)

    config_path.write_text(json.dumps(CONFIG), encoding="utf-8")

    matrices: list[dict] = []
    for index in range(args.runs + 1):
        # The baseline (index 0) is always recorded against the clean
        # boundary. In --detect mode every run after it faces a target that
        # really did open up, with the noise still running.
        if args.detect and index == 1:
            noise.leak = True
        output = work / f"run-{index}"
        code = _run_map(config_path, spec, base_url, output)
        if code != 0:
            print(f"  run {index}: map exited {code}; aborting")
            return 2
        newest = sorted((output / "matrix").glob("*.json"))[-1]
        matrices.append(json.loads(newest.read_text(encoding="utf-8")))

    server.shutdown()
    server.server_close()

    baseline = matrices[0]
    flapped = 0
    gated = 0
    kinds: Counter[str] = Counter()
    worst: list[dict] = []
    blind_runs: list[int] = []
    for index, current in enumerate(matrices[1:], start=1):
        report = drift_module.compare(baseline, current)
        changes = report["changes"]
        # The `any` policy is what it gates on, not what it prints: an
        # unmeasured cell is reported and never gated. Counting printed lines
        # here would measure the report rather than the gate.
        if drift_module.exit_code(report, "any"):
            flapped += 1
        if drift_module.exit_code(report, "opened"):
            gated += 1
            worst.extend(c for c in changes if c["significant"])
        kinds.update(c["kind"] for c in changes)
        blind_runs.append(report.get("blind_cells", 0))

    runs = len(matrices) - 1
    if args.detect:
        blindest = max(blind_runs) if blind_runs else 0
        print(f"  DETECTION RATE   {gated}/{runs} ({gated / runs:.0%}) runs caught "
              "the real regression → --fail-on-drift opened")
        print(f"  baseline blind   up to {blindest} cell(s) the BASELINE never measured. "
              "A miss here is\n                   under-detection, and the report says so "
              "above its own counts.")
        print(f"  (any policy)     {flapped}/{runs} ({flapped / runs:.0%})")
        print()
        if kinds:
            print("  by kind:")
            for kind, count in kinds.most_common():
                print(f"    {kind:20} {count}")
        missed = runs - gated
        print(f"\n  {'ALL RUNS CAUGHT IT.' if not missed else f'{missed} RUN(S) MISSED IT.'}"
              " A gate that never fires is not quiet, it is broken.")
        return 1 if missed else 0

    print(f"  flap rate        {flapped}/{runs} "
          f"({flapped / runs:.0%}) runs reported ANY change  → --fail-on-drift any")
    print(f"  FALSE GATE RATE  {gated}/{runs} "
          f"({gated / runs:.0%}) runs reported a SIGNIFICANT one → --fail-on-drift opened")
    print()
    if kinds:
        print("  by kind (all false):")
        for kind, count in kinds.most_common():
            print(f"    {kind:20} {count}")
    else:
        print("  no change of any kind was reported.")
    if worst:
        print("\n  the significant ones -- each of these would fail a build:")
        for change in worst[:5]:
            print(f"    [{change['kind']}] {change['operation']} {change['identity']}"
                  f"  {change['before']} -> {change['after']}")
    return 1 if gated else 0


if __name__ == "__main__":
    raise SystemExit(main())
