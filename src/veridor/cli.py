"""Command-line interface for Veridor.

The surface is three verbs and five utilities. The verbs are the product --
:func:`_map` asks what a compromise would reach, :func:`_run` asks whether the
boundary you declared holds, :func:`_mutate` asks whether that declaration could
ever have failed -- and the utilities are tools you reach for while using them.
:data:`_OVERVIEW` is what ``--help`` prints, and ``tests/test_cli_verbs.py``
snapshots it, because the shape of the surface is the product decision here and
it must not drift back into a flat list of nine equals.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import secrets
import signal
import sys
import tempfile
import threading
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, Sequence

from veridor import __version__
from veridor.blastradius import (
    BlastRadiusError,
    blast_radius_report,
    candidates_document,
    credential_bearing_identities,
    find_candidates,
    peer_groups,
    promotion_stub,
    rank_candidates,
    render_blast_radius,
    render_candidates,
)
from veridor import gate as gate_policy
from veridor import redaction, reports
from veridor.reports._common import pass_disclosures
from veridor.core import (
    CAPSULE_EXIT_CODES,
    DECLARATION_SCOPE,
    MARKER_UNIQUENESS_REASONS,
    PASS_SCOPE,
    SAFE_METHODS,
    ConfigError,
    _proxy_sentence,
    _validate_http_url,
    announce_proxy,
    execute_run,
    generate_marker,
    load_config,
    persist_run,
    terminal_names,
    terminal_text,
    to_sarif,
    validate_run,
    wait_for_target,
    write_json,
)
# The exit-code policy moved to `veridor.gate`, so the number the process exits
# with and the `gate` object written into the run document are one computation.
# These names are the ones this module always used; they are the same functions.
from veridor.gate import (  # noqa: F401  (re-exported for callers of the old names)
    _answered_probes,
    _assert_steps,
    _confirmed_findings,
    _declares_checks,
    _established_nothing,
    _gate_exit_code,
    _is_vacuous,
    _nothing_graded,
    _security_findings,
    _sequence_steps,
    _unanswered_count,
    _unauthenticated_identity_exit_code,
    _unproven_liveness,
    _vacuous_exit_code,
)
from veridor.coverage import (
    GENERATED_BY_KEY,
    CoverageError,
    compute_coverage,
    not_measured_report,
    render_badge,
    render_text,
)
from veridor.matrix import (
    MATRIX_DEFAULT_BUDGET,
    MATRIX_DEFAULT_RPS,
    MATRIX_DEFAULT_RUN_SECONDS,
    ON_RETRY_AFTER_CHOICES,
    ON_RETRY_AFTER_DEFAULT,
    SPECIMEN_PLACEHOLDER,
    MatrixError,
    MatrixOptions,
    default_prober,
    execute_matrix,
    matrix_document,
    plan_matrix,
)
from veridor.openapi import SpecError, load_spec, parse_spec
from veridor.server import serve
from veridor.terminal import _BLANK_RUN, cut, quoted, refusal_text

# ``veridor.mutation`` is imported inside :func:`_mutate` and nowhere else. It
# is the only module in the package that can execute an operator-supplied
# command, and keeping it off the import path of every other subcommand means
# `veridor run` in CI never even loads the code that calls ``subprocess``.

#: Where `init --for drift` tells you to record the baseline. Outside
#: `.veridor/`, which is conventionally gitignored, because a gate compares
#: against a committed file and a CI runner has no `.veridor/` from last week.
DRIFT_BASELINE = "veridor/baseline-matrix.json"

_PLACEHOLDER_BASE_URL = "https://staging.example.com"
_OWNER_IDENTITY = "owner"
_CHALLENGER_IDENTITY = "other_tenant"
_TEMPLATE_TOKEN = re.compile(r"\{[^{}/]*\}")
_NON_SLUG = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SERVER_VARIABLE = re.compile(r"\{([^{}/]+)\}")

# Every generated status set is deliberately allow-only for the owner and
# denial-only for the challenger, so a generated config is classifiable by
# veridor.coverage the moment it is written.
_OWNER_STATUSES: dict[str, list[int]] = {
    "GET": [200],
    "POST": [200, 201],
    "PUT": [200, 204],
    "PATCH": [200],
    "DELETE": [200, 204],
}
_DENIAL_STATUSES: list[int] = [403, 404]

#: Spelled out rather than abbreviated. The flag is the last thing an operator
#: types before Veridor executes commands they wrote against a target they own,
#: and the flag itself should say so.
_TIER2_ACK_FLAG: str = "--i-understand-tier-2-runs-my-commands"


def _add_coverage_arguments(parser: argparse.ArgumentParser, *, required: bool) -> None:
    group = parser.add_argument_group("boundary coverage (offline, static)")
    group.add_argument(
        "--openapi",
        type=Path,
        required=required,
        help=(
            "OpenAPI 3 or Swagger 2 JSON specification"
            + ("" if required else "; enables boundary coverage")
        ),
    )
    group.add_argument(
        "--coverage",
        dest="coverage_path",
        type=Path,
        help="write the machine-readable coverage report JSON to this path",
    )
    group.add_argument(
        "--badge",
        type=Path,
        help="write shields.io endpoint JSON for the coverage badge to this path",
    )
    group.add_argument(
        "--base-path",
        help="spec path prefix to apply (default: auto-detect and show the scoring)",
    )
    group.add_argument(
        "--allow-no-matches",
        action="store_true",
        help=(
            "report coverage as 'not measured' instead of failing when no check "
            "path matches any operation"
        ),
    )


#: What ``veridor --help`` prints above the option list. Three verbs, then the
#: utilities, visibly subordinate. The ordering is the journey: discover,
#: declare, gate, then verify the gate.
_OVERVIEW: str = """\
Check that your API still agrees with the authorization you declared.

THE THREE VERBS

  map      What don't I cover, and what would a compromise reach?
           Projects an OpenAPI inventory into an access matrix, a blast radius
           per identity, boundary coverage, and ranked anomaly candidates.
           Read-only by default, rate limited, and it refuses its own plan
           before the first request. Candidates are hypotheses, never findings.

  run      Does the boundary hold, and did it change?
           Issues every declared expectation as every declared identity, grades
           marker evidence, runs multi-step sequences, diffs against a baseline
           and sets the CI exit code. This is the gate.

  mutate   Would my suite actually catch a regression?
           Rewrites your own expectations and reports the mutants your checks
           failed to kill. A surviving mutant is a check that cannot fail.

  Discover, declare, gate, then verify the gate. `map` proposes; you decide what
  to declare; `run` holds you to it; `mutate` says whether holding you to it
  means anything.

UTILITIES

  capsule      write a portable, runnable proof of ONE finding, to attach to
               a disclosure. Carries no credential; the reader verifies it
               against their own instance with `veridor verify <file>`
  init         write a starter configuration from an OpenAPI specification
  coverage     measure boundary coverage alone, issuing no request
  new-marker   print a fresh identity marker
  report       render a run as SARIF, JUnit, GitLab SAST or Code Quality,
               or Markdown
  serve        open the local run history UI

`verify` remains an alias for `run`, and additionally takes a capsule:
`veridor verify proof.json` prints CONFIRMED / NOT_REPRODUCED / INCONCLUSIVE.
"""


def _add_matrix_arguments(parser: argparse.ArgumentParser) -> None:
    """The safety envelope. Every default is the conservative one."""
    group = parser.add_argument_group("safety envelope (read-only by default)")
    group.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "additionally exit 3 when any probed cell went unmeasured -- a rate "
            "limit, a 5xx, a timeout. Those operations are unverified rather "
            "than verified. A grid where NOTHING was measured -- every probed "
            "cell unmeasured or a redirect, which Veridor does not follow -- "
            "exits 3 with or without this flag. An --ignore, matrix.ignore or "
            "--include that leaves nothing to probe -- no operation, or only "
            "writes the read-only posture skips and routes with no specimen -- "
            "is refused before the first request (exit 2), so it never produces "
            "that empty grid"
        ),
    )
    group.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "print the plan and the safety posture, then stop. Nothing is sent. "
            "Run this first against any target you did not provision yourself"
        ),
    )
    group.add_argument(
        "--max-requests",
        type=int,
        default=MATRIX_DEFAULT_BUDGET,
        help=(
            "refuse to start when the plan is larger than this "
            f"(default: {MATRIX_DEFAULT_BUDGET}). The refusal happens before the "
            "first request, and reports the number it refused"
        ),
    )
    group.add_argument(
        "--rate",
        dest="requests_per_second",
        type=float,
        default=MATRIX_DEFAULT_RPS,
        help=f"requests per second, sequential (default: {MATRIX_DEFAULT_RPS:g})",
    )
    group.add_argument(
        "--max-run-seconds",
        type=float,
        default=MATRIX_DEFAULT_RUN_SECONDS,
        help=(
            "wall clock the whole matrix may take before it stops and reports a "
            f"partial grid (default: {MATRIX_DEFAULT_RUN_SECONDS:g})"
        ),
    )
    group.add_argument(
        "--on-retry-after",
        choices=ON_RETRY_AFTER_CHOICES,
        default=ON_RETRY_AFTER_DEFAULT,
        help=(
            "what a 429 carrying Retry-After means. continue (default) counts it "
            "toward the ordinary rate-limit budget -- three consecutive or five "
            "cumulative -- so a target that sends the header gets the same "
            "tolerance as one that does not. stop abandons the grid on the first "
            "one, which was the only behaviour and cost a spec-compliant limiter "
            "3.5x the coverage of a rude one"
        ),
    )
    group.add_argument(
        "--timeout",
        dest="matrix_timeout",
        type=float,
        help="per-request timeout (default: target.timeout_seconds)",
    )
    group.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="[METHOD ]/path/template",
        help=(
            "probe only matching operations; repeatable. Matches by PATH "
            "PREFIX, not as a glob or a regex: a match selects the route and "
            "everything beneath it, '*' is an ordinary character, and '{id}' "
            "must be spelled as the specification spells it"
        ),
    )
    group.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="[METHOD ]/path/template",
        help="never probe matching operations; repeatable, adds to matrix.ignore",
    )
    group.add_argument(
        "--allow-mutating-method",
        action="append",
        default=[],
        metavar="METHOD",
        help=(
            "name one mutating verb the matrix may send, e.g. DELETE. Repeatable, "
            "never a wildcard, and inert without --acknowledge-mutating"
        ),
    )
    group.add_argument(
        "--acknowledge-mutating",
        default="",
        metavar="TEXT",
        help=(
            "the exact acknowledgement string mutating verbs require. Two "
            "independent gates, so one stray flag cannot open both"
        ),
    )
    group.add_argument(
        "--acknowledge-target",
        default="",
        metavar="TEXT",
        help=(
            "required verbatim when the target is not loopback or a private "
            "address: 'I am authorized to test HOST'. The refusal prints the "
            "exact string. This is friction, not a security boundary"
        ),
    )


def _wait_seconds(value: str) -> int:
    """``--wait-for-target SECONDS``: a whole, non-negative number of seconds."""
    if not re.fullmatch(r"[0-9]+", value or ""):
        raise argparse.ArgumentTypeError(
            f"{quoted(value)} is not a whole number of seconds (0 or more); 0 turns the wait off"
        )
    return int(value)


def _add_wait_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--wait-for-target",
        dest="wait_for_target",
        type=_wait_seconds,
        default=0,
        metavar="SECONDS",
        help=(
            "before the first request, try a plain TCP connection to the "
            "target's host and port once a second until one is accepted or "
            "SECONDS pass (default: 0, no wait). Either way the run then goes "
            "ahead and one stderr line says which it was; a target that never "
            "accepted shows up as the probes' own transport errors. For a "
            "target that is still starting; an accepted connection does not "
            "mean the new version is serving (a previous version's pod accepts "
            "at once). The check connects directly even when a proxy carries "
            "the requests, and its line then says so. Never changes a verdict"
        ),
    )


#: Appended to every argparse refusal at the top level. The first thing most
#: people type after installing is the bare binary, and argparse's own answer
#: -- a usage line and "the following arguments are required: <command>" --
#: names neither the three verbs nor the flag that would list them.
_HELP_HINT = "Try 'veridor --help' for the three verbs (map, run, mutate) and the utilities."


class _TopLevelParser(argparse.ArgumentParser):
    """The root parser, whose refusals point at ``--help``.

    Only the root parser needs this. A subcommand's refusal already names the
    subcommand in its usage line, so the reader knows where to look; the root
    refusal is the one that leaves a new user with no next command to type.
    """

    def error(self, message: str) -> NoReturn:  # pragma: no cover - argparse exit
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        print(_HELP_HINT, file=sys.stderr)
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _TopLevelParser(
        prog="veridor",
        description=_OVERVIEW,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # No per-parser ``help=`` anywhere below, so argparse prints no flat list of
    # nine equal commands. _OVERVIEW is the listing, and it is grouped.
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="<command>",
        help="one of the verbs or utilities above; each takes its own --help",
    )

    mapper = subparsers.add_parser(
        "map",
        description=(
            "Project an OpenAPI inventory into an access matrix, then report "
            "every identity's observed reach, the boundary coverage of your "
            "declaration, and the inconsistencies worth declaring a check for. "
            "Nothing here is a finding: `map` produces no SARIF, writes nothing "
            "into the run history, and nothing it discovers can fail a build. "
            "It exits 0 when it produced a map -- unless you asked "
            "--fail-on-drift to gate on how this matrix differs from an earlier "
            "one, which is a fact about two runs rather than a verdict on one."
        ),
    )
    mapper.add_argument(
        "--config", type=Path, required=True, help="path to veridor JSON config"
    )
    mapper.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".veridor"),
        help="artifact directory (default: .veridor)",
    )
    mapper.add_argument("--base-url", help="override target.base_url")
    _add_wait_argument(mapper)
    mapper.add_argument(
        "--matrix", type=Path, help="also write the access matrix JSON here"
    )
    mapper.add_argument(
        "--blast-radius", type=Path, help="also write the blast radius JSON here"
    )
    mapper.add_argument(
        "--candidates", type=Path, help="also write the candidates JSON here"
    )
    mapper.add_argument(
        "--promote",
        type=Path,
        help=(
            "write a paste-ready, deliberately incomplete check per candidate to "
            "this path. They are stubs: what the boundary IS is your decision"
        ),
    )
    _add_matrix_arguments(mapper)
    drift_group = mapper.add_argument_group(
        "drift -- authorization regression with nothing declared"
    )
    drift_group.add_argument(
        "--baseline",
        type=Path,
        help=(
            "a previous matrix JSON, or the directory `map` writes them to "
            "(e.g. .veridor/matrix). Reports what moved since. Nobody declares "
            "anything: the first run records, later runs diff. A directory is "
            "for discovery only -- --fail-on-drift refuses it, because this run "
            "writes into the same directory"
        ),
    )
    drift_group.add_argument(
        "--drift",
        dest="drift_path",
        type=Path,
        help=(
            "write the machine-readable drift report JSON here. Needs "
            "--baseline; without one it is refused, before anything is sent"
        ),
    )
    drift_group.add_argument(
        "--fail-on-drift",
        choices=("none", "opened", "any"),
        default="none",
        help=(
            "exit non-zero on drift (default: none). `opened` fails only on "
            "changes that mean MORE access than the baseline -- a refusal that "
            "became a success, or a response that now carries another identity's "
            "marker. A redirect in the baseline that is served now is not a "
            "refusal Veridor saw, so `opened` reports it and `any` fails on it. "
            "`any` fails on any change. Either policy exits 3 instead of "
            "0 when not one cell was measured in both this run and the baseline "
            "(a baseline recorded while the target was down, say): no change "
            "could have been reported, so that is not a pass. Discovery does not "
            "gate a build unless you ask it to"
        ),
    )
    _add_coverage_arguments(mapper, required=True)

    run = subparsers.add_parser(
        "run",
        aliases=("verify",),
        description=(
            "Issue every declared expectation as every declared identity, grade "
            "the marker evidence, execute any declared multi-step sequences, "
            "diff against a baseline, and set the exit code. Sequences, their "
            "captures and identity sessions are declared in the configuration "
            "(version 2) and run as part of this command."
        ),
    )
    # `--config` is no longer argparse-required because `veridor verify
    # <capsule>` is the maintainer-facing form of this same verb. Exactly one of
    # the two is required, checked below so the message can name both. Every
    # existing `run --config` / `verify --config` invocation is unaffected.
    run.add_argument("--config", type=Path, help="path to veridor JSON config")
    run.add_argument(
        "capsule",
        nargs="?",
        type=Path,
        help=(
            "a capsule written by `veridor capsule`. Runs the single check it "
            "carries and prints CONFIRMED / NOT_REPRODUCED / INCONCLUSIVE. This "
            "is what a maintainer receives attached to a disclosure"
        ),
    )
    run.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".veridor"),
        help="run history directory (default: .veridor)",
    )
    run.add_argument("--baseline", type=Path, help="prior run JSON for regression comparison")
    run.add_argument("--base-url", help="override target.base_url")
    _add_wait_argument(run)
    run.add_argument("--json", dest="json_path", type=Path, help="write run JSON to this path")
    run.add_argument("--sarif", type=Path, help="write SARIF 2.1.0 to this path")
    run.add_argument(
        "--fail-on",
        choices=("new+confirmed", "new", "any", "confirmed", "none"),
        default="new+confirmed",
        help=(
            "policy used for the process exit code "
            "(default: new+confirmed). "
            "new+confirmed: anything absent from the baseline, PLUS anything "
            "proved by a marker regardless of age -- the default because `new` "
            "alone is decided entirely by a file the README asks you to commit, "
            "so a pull request that adds a finding id to the baseline turns a "
            "live confirmed leak into a green build. "
            "new: a finding absent from the baseline. "
            "any: any finding at all. "
            "confirmed: only a finding whose response actually carried another "
            "identity's marker. "
            "none: never fail"
        ),
    )
    run.add_argument(
        "--read-only",
        action="store_true",
        help=(
            "refuse to load a configuration that can issue any request outside "
            "GET, HEAD, or OPTIONS. Fails with exit 2 before a single request "
            "is sent. Use this for any target you did not personally provision"
        ),
    )
    run.add_argument(
        "--require-clean-teardown",
        action="store_true",
        help=(
            "additionally exit 3 when a sequence teardown did not complete "
            "cleanly. A real finding always wins the exit code"
        ),
    )
    run.add_argument(
        "--no-prove-liveness",
        dest="prove_liveness",
        action="store_false",
        help=(
            "skip the liveness controls. ON by default: for each GET, HEAD or "
            "OPTIONS request whose declaration accepts only denial statuses, "
            "Veridor issues ONE probe carrying a credential it fabricated, "
            "written into every header the identities declare but a "
            "standard non-credential one such as Accept (a header two or more "
            "identities send with one value and whose name is not a "
            "credential's, such as an API version, is sent unchanged, and one "
            "declared only beside another credential, such as a tenant, is "
            "left out), so a denial that any caller "
            "would have received cannot pass as a boundary that refused this "
            "one; and the same for a GET, HEAD or OPTIONS request that serves "
            "an identity whose credential must be proven live, so a route "
            "that serves anyone proves nothing. One extra request per such "
            "request -- not per identity -- and "
            "the fabricated value authenticates to nothing; none is sent with "
            "POST, PUT, PATCH or DELETE, inside a sequence, or when no identity "
            "declares a credential header. A denial counts as unproven only for "
            "an identity that presents a credential, in a check or sequence "
            "where some identity was served, that nothing else in the run proved "
            "live (a 2xx it drew on a request where an identity with no "
            "credential, or the fabricated credential, was refused; or its "
            "marker_probe), and whose fabricated "
            "credential drew the same denial, was not sent, failed, or drew "
            "neither a refusal nor a success. Each is printed and recorded in "
            "liveness.unproven; it moves the exit code (to 3) only with "
            "--require-complete, so under the default flags an expired token on "
            "an identity expected only to be denied still exits 0. Turn it off "
            "and that denial is not even reported"
        ),
    )
    run.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "additionally exit 3 when any probe went unanswered -- a rate "
            "limit, a 5xx, a timeout -- when an expectation accepts both access "
            "and denial, or when a denial counts as unproven in "
            "liveness.unproven (see --no-prove-liveness). Those boundaries are "
            "unverified rather than verified, and a CI job reads an exit code, "
            "not a summary. A real finding always wins the exit code"
        ),
    )
    run.add_argument(
        "--report",
        dest="reports",
        action="append",
        default=[],
        type=_report_request,
        metavar="FORMAT=PATH",
        help=(
            "also write this run as FORMAT to PATH; repeatable. FORMAT is one of "
            f"{', '.join(reports.FORMATS)}. Written whatever the gate decides, "
            "since a failing gate is when CI needs them. PATH may not be '-': "
            "`run` prints its own summary on stdout"
        ),
    )
    _add_coverage_arguments(run, required=False)

    capsule = subparsers.add_parser(
        "capsule",
        description=(
            "Write a portable, runnable proof of ONE finding: the request, the "
            "identities, the declared expectation and the marker, in a single "
            "file you can attach to a disclosure. The reader verifies it with "
            "`veridor verify <file>` against their own instance. Credentials are "
            "never included -- a capsule that would carry one is refused, "
            "because a published bearer token cannot be recalled."
        ),
    )
    capsule.add_argument("--config", type=Path, required=True, help="path to veridor JSON config")
    capsule.add_argument("--check", required=True, help="id of the check to prove")
    capsule.add_argument(
        "--from-run",
        type=Path,
        help=(
            "a run JSON whose finding for this check becomes the CLAIM the "
            "capsule carries, so the reader sees what was originally observed"
        ),
    )
    capsule.add_argument(
        "--image",
        help="container image the reporter used, ideally digest-pinned; recorded verbatim",
    )
    capsule.add_argument("--output", type=Path, help="write here (default: stdout)")

    mutate = subparsers.add_parser(
        "mutate",
        description=(
            "Rewrite your declared expectations one at a time and report which "
            "mutants your suite failed to kill. A surviving mutant is a check "
            "that cannot fail, which is a vacuous check. This measures your "
            "declaration, not your target: nothing it reports is a finding, it "
            "emits no SARIF, and its exit code is its own (0 all killed, 1 at "
            "least one survivor, 2 nothing measured or something unresolved). "
            "Unlike `map`, this verb does NOT require --acknowledge-target for a "
            "public host: it re-issues the requests YOU declared in a "
            "configuration you wrote naming a base_url, which is what `veridor "
            "run` does, so it takes `run`'s posture there rather than `map`'s. "
            "`map` fans out from a specification across every identity and is "
            "gated for that reason. --read-only and --max-requests apply here."
        ),
    )
    mutate.add_argument(
        "--config", type=Path, required=True, help="path to veridor JSON config"
    )
    mutate.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".veridor"),
        help="artifact directory; reports land under <dir>/mutation (default: .veridor)",
    )
    mutate.add_argument(
        "--require-evaluable",
        action="store_true",
        help=(
            "additionally exit 3 when a mutant could not be evaluated at all. "
            "Those sit under LIMITS ON THE EVIDENCE and are kept out of the "
            "score, which is right -- an unanswerable mutant is not a "
            "measurement -- but it leaves a suite whose only cross-tenant "
            "assertion cannot fail reporting 1.00 and exiting 0"
        ),
    )
    mutate.add_argument("--base-url", help="override target.base_url")
    mutate.add_argument(
        "--json", dest="json_path", type=Path, help="also write the report JSON here"
    )
    mutate.add_argument(
        "--text", dest="text_path", type=Path, help="also write the rendered report here"
    )
    mutate.add_argument(
        "--badge", type=Path, help="also write shields.io endpoint JSON here"
    )
    mutate.add_argument(
        "--read-only",
        action="store_true",
        help=(
            "refuse to load a configuration that can issue any request outside "
            "GET, HEAD, or OPTIONS. Fails with exit 2 before a single request is "
            "sent, at either tier. `mutate` re-issues every request you "
            "declared, DELETE included, and then issues more of its own: this is "
            "the same escape hatch `run --read-only` gives you, on the same "
            "configuration"
        ),
    )
    mutate.add_argument(
        "--max-requests",
        type=int,
        default=None,
        dest="max_requests",
        help=(
            "refuse to start when the plan -- baseline probes included -- is "
            f"larger than this (default: {MUTATE_DEFAULT_MAX_REQUESTS:,}). The "
            "refusal happens before the first request and reports the number it "
            "refused. --min-interval bounds the rate this target is hit at; this "
            "bounds the volume, and unlike the two flags below it applies at BOTH "
            "tiers. At tier 2 the baseline is charged once per hook plus once for "
            "the unmutated run, each with its liveness controls (one per "
            "denial-only GET/HEAD/OPTIONS request). Session logins and sequence "
            "steps are not counted at tier 2"
        ),
    )
    tier1 = mutate.add_argument_group(
        "tier 1 -- expectation mutation (the default), and its request envelope"
    )
    tier1.add_argument(
        "--min-interval",
        type=float,
        default=None,
        dest="min_interval",
        help=(
            "minimum seconds between requests -- ALL of them, the baseline "
            "probes included, because they are most of the traffic (default: "
            f"{MUTATE_DEFAULT_MIN_INTERVAL:g}, i.e. "
            f"{1 / MUTATE_DEFAULT_MIN_INTERVAL:.4g} req/s, matching `map`). Pass "
            "0 to turn it off against a fixture you own"
        ),
    )
    tier1.add_argument(
        "--request-budget",
        type=int,
        help=(
            "cap the ADDITIONAL target requests mutation may issue (default: "
            f"{MUTATE_DEFAULT_REQUEST_BUDGET:,}). The baseline probes are the ones "
            "`veridor run` issues anyway, and are governed by --max-requests below "
            "rather than by this flag"
        ),
    )
    tier2 = mutate.add_argument_group(
        "tier 2 -- target mutation (RUNS COMMANDS YOU SUPPLY)"
    )
    tier2.add_argument(
        "--tier",
        type=int,
        choices=(1, 2),
        default=1,
        help="mutation tier (default: 1)",
    )
    tier2.add_argument(
        "--hooks",
        type=Path,
        help=(
            "JSON file of target mutation hooks. EVERY HOOK'S apply_command AND "
            "restore_command IS EXECUTED ON THIS MACHINE, as you, with your "
            "environment. They are run as an argv list with no shell, so nothing "
            "is expanded or interpreted -- but they are still your commands and "
            "they still run. A hook without a restore_command is refused before "
            "anything executes. Requires --tier 2"
        ),
    )
    tier2.add_argument(
        _TIER2_ACK_FLAG,
        dest="tier2_acknowledged",
        action="store_true",
        help=(
            "required for --tier 2. Tier 2 alters your target and then puts it "
            "back; without this flag nothing runs"
        ),
    )

    coverage = subparsers.add_parser(
        "coverage",
        description=(
            "Measure how much of the OpenAPI inventory your declaration asserts "
            "an authorization boundary for. Issues no request."
        ),
    )
    coverage.add_argument(
        "--config", type=Path, required=True, help="path to veridor JSON config"
    )
    _add_coverage_arguments(coverage, required=True)

    initialize = subparsers.add_parser(
        "init",
        description=(
            "Scaffold a configuration from an OpenAPI specification, for one of "
            "two paths. --for run (default) writes one starter check per "
            "in-scope operation: every expectation is a placeholder, not an "
            "observation, and the first run is red by design. --for drift writes "
            "no checks at all -- two identities and one specimen per templated "
            "route -- because `map` grades no expectation and drift compares "
            "this run's matrix with an earlier one. Edit before you trust."
        ),
    )
    initialize.add_argument(
        "--for",
        dest="scaffold_for",
        choices=("run", "drift"),
        default="run",
        help=(
            "which path to scaffold: 'run' declares expectations and gates on "
            "them (default); 'drift' declares nothing and gates on what moved"
        ),
    )
    initialize.add_argument(
        "--openapi", type=Path, required=True, help="OpenAPI 3 or Swagger 2 JSON spec"
    )
    initialize.add_argument(
        "--output", type=Path, required=True, help="configuration path to create"
    )
    initialize.add_argument("--base-url", help="override the target base URL")
    initialize.add_argument(
        "--force", action="store_true", help="replace an existing --output file"
    )

    subparsers.add_parser(
        "new-marker", description="Print a fresh, high-entropy identity marker."
    )

    report = subparsers.add_parser(
        "report",
        description=(
            "Render a run JSON document as SARIF, JUnit XML, a GitLab SAST or "
            "Code Quality report, or Markdown. Every format except SARIF reads "
            "the gate decision `veridor run` recorded in the document, so a run "
            "that exited 3 because nothing was answered never renders as a pass. "
            "SARIF carries findings only and has no gate: a run that exited 3 "
            "for an unproven denial or an unclean teardown renders as zero "
            "results, so read the job's exit code, not the SARIF, for the gate. A "
            "drift report (`map --baseline ... --drift PATH`) renders to "
            "Markdown only: drift is never a finding."
        ),
    )
    report.add_argument(
        "--from-run",
        "--input",
        dest="input",
        type=Path,
        metavar="RUN.json",
        help="the run JSON `veridor run --json` wrote (--input is the older spelling)",
    )
    report.add_argument(
        "--from-drift",
        type=Path,
        metavar="DRIFT.json",
        help="a drift report written by `veridor map --baseline ... --drift`",
    )
    report.add_argument(
        "--format",
        dest="report_format",
        choices=reports.FORMATS,
        help="the report to write",
    )
    report.add_argument(
        "--output",
        metavar="PATH",
        help="where to write it; '-' or omitted writes to stdout",
    )
    report.add_argument(
        "--sarif",
        type=Path,
        help="older spelling of --format sarif --output PATH",
    )

    server = subparsers.add_parser(
        "serve", description="Open the local, read-only run history UI."
    )
    server.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".veridor"),
        help="run history directory (default: .veridor)",
    )
    server.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "address to bind (default: 127.0.0.1). Anything other than "
            "loopback publishes every run document -- targets, finding "
            "messages, config paths -- to whoever can reach it, with no "
            "authentication of any kind, and is refused without "
            "--i-understand-this-is-unauthenticated"
        ),
    )
    server.add_argument(
        "--i-understand-this-is-unauthenticated",
        dest="acknowledge_exposure",
        action="store_true",
        help=(
            "required to bind an address other than loopback. The viewer has "
            "no login and never has: it is a local reader for artifacts you "
            "already have on disk"
        ),
    )
    server.add_argument("--port", type=int, default=8787)
    return parser


def _escape_command_data(value: object) -> str:
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _escape_command_property(value: object) -> str:
    return _escape_command_data(value).replace(":", "%3A").replace(",", "%2C")


#: An annotation's message is Veridor's own sentences around values already cut
#: where they were quoted, so it is longer than one quoted value may be: about 500
#: characters on the demo's confirmed finding (measured). The limit is what holds
#: if one of those values was not cut.
_ANNOTATION_MESSAGE_LIMIT = 2000


def _emit_github_annotations(result: dict) -> None:
    """One workflow command per finding, each as bounded as any other line.

    The title quotes a check or sequence name from the configuration, whole. It
    went to the log only under GITHUB_ACTIONS, so a run on a developer's machine
    never showed that a 1200-character name reached one line of it. ``location``
    is not cut: it is the path the operator gave on the command line, not a value
    from the configuration, and GitHub places the annotation by it.
    """
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    for finding in result["findings"]:
        level = "error" if finding["level"] == "error" else "warning"
        message = _escape_command_data(
            cut(_BLANK_RUN.sub(" ", finding["message"]), _ANNOTATION_MESSAGE_LIMIT))
        title = _escape_command_property(terminal_text(finding["title"]))
        location = _escape_command_property(finding["location"])
        # The same anchor the SARIF result uses. An annotation on line 1 puts
        # every finding on the config's opening brace, where a reviewer reading
        # the diff view cannot tell them apart.
        line = finding.get("location_line")
        if not (isinstance(line, int) and not isinstance(line, bool) and line > 0):
            line = 1
        print(
            f"::{level} file={location},line={line},title={title}::{message}",
            file=sys.stderr,
        )


_MAX_LISTED_DISCLOSURES = 5


def _print_pass_disclosures(result: dict) -> None:
    """Print what a green run does not establish, on the run that establishes it.

    Each block describes an outcome that emits NO finding: a permissive
    expectation matches whatever the target does, an exclusion licensed by an
    identity ``marker_probe`` was never demonstrated at the path under test, and
    a request -- check probe, sequence step, teardown entry or marker probe --
    went out without a declared body field its body could not carry. Before
    this, each was recorded only in the raw run JSON, so a reviewer reading the
    console or the UI could not distinguish any of them from a real,
    same-path-proven pass. The groups and their headings are
    ``reports._common.pass_disclosures``, which every CI report reads too.
    """
    for _group, label, heading, entries in pass_disclosures(result):
        print(heading.format(count=len(entries)) + ":")
        for entry in entries[:_MAX_LISTED_DISCLOSURES]:
            print(f"  - {terminal_text(str(entry.get(label)))} / "
                  f"{terminal_text(str(entry.get('identity')))}: {entry.get('statement')}")
        remaining = len(entries) - _MAX_LISTED_DISCLOSURES
        if remaining > 0:
            print(f"  - ... and {remaining} more")


def _print_unreviewed_stubs(result: dict) -> None:
    """Say out loud that some of these verdicts grade an unreviewed declaration.

    ``map --promote`` writes a stub per candidate, named ``TODO: describe the
    boundary you are asserting`` because deciding what the boundary IS is the
    operator's job and not Veridor's. Pasted in unedited, those stubs grade
    normally and reach SARIF as ``error``-level results at evidence grade
    ``confirmed``. The residual "nobody reviewed this" signal was the name, and
    the name reached neither this summary -- which printed ``check_id`` only --
    nor the SARIF. It survived only in ``latest.json``.

    Printed above the findings rather than below them, because it qualifies
    every one of them, and unconditionally, because a caveat you can turn off
    is a caveat that is off on the run that needed it.
    """
    entries = result.get("unreviewed_promotion_stubs") or []
    if not entries:
        return
    print(
        f"Unreviewed: {len(entries)} check(s) still carry the name "
        "`veridor map --promote` wrote, so they are machine-generated "
        "hypotheses graded as if you had declared them. A candidate is not a "
        "finding; edit or delete them:"
    )
    for entry in entries[:_MAX_LISTED_DISCLOSURES]:
        print(f"  - {terminal_text(entry['check_id'])}: {terminal_text(entry['name'])}")
    remaining = len(entries) - _MAX_LISTED_DISCLOSURES
    if remaining > 0:
        print(f"  - ... and {remaining} more")


def _print_sequences(result: dict) -> None:
    """Report what the sequence engine did, on a run that used it.

    Sequences, response captures and identity sessions have been executable
    through ``veridor run`` since they landed -- ``core.execute_run`` runs any
    the configuration declares -- but the console said nothing about them, so a
    multi-step suite and a single-request suite printed identical output and an
    operator had no way to see that a teardown had failed without opening the
    run JSON.

    Returns immediately when the document carries no ``sequences`` key, which is
    every configuration that declares none. Their console output is unchanged,
    byte for byte.
    """
    records = result.get("sequences")
    if not records:
        return
    summary = result["summary"]
    print(
        f"Sequences: {summary.get('sequences', 0)} executed, "
        f"{summary.get('sequence_steps_matched', 0)}/"
        f"{summary.get('sequence_steps', 0)} steps matched their declaration, "
        f"{summary.get('sequences_aborted', 0)} aborted, "
        f"{summary.get('teardown_failures', 0)} teardown failure(s)"
    )
    for record in records:
        detail = ""
        if record.get("abort_reason"):
            detail = (
                f", aborted at step {record.get('aborted_at_step')}: "
                f"{terminal_text(record['abort_reason'])}"
            )
        print(
            f"  - {terminal_text(record['sequence_id'])}: {record['outcome']} "
            f"(teardown: {record.get('teardown_state') or 'none'}){detail}"
        )


def _print_summary(result: dict) -> None:
    summary = result["summary"]
    # 'safe' is a security claim about a measurement that only compared a
    # status against a list the operator wrote; coverage.BANNED_CLAIM_WORDS
    # rules the word out for exactly that reason. The JSON key keeps its name
    # for schema stability; the sentence a human reads says what happened.
    print(
        f"Veridor run {result['run_id']}: "
        f"{summary['safe']}/{summary['probes']} probes matched their "
        f"declaration, {summary['vulnerable']} vulnerable, "
        f"{summary.get('unexpected_denial', 0)} unexpected denial, "
        f"{summary['inconclusive']} inconclusive"
    )
    # The target, on the line under the verdict. A green run is only meaningful
    # if you know what it was green against, and a port is easy to get wrong:
    # a demo server that failed to bind leaves whatever else owns that port to
    # answer the probes, and every other line of this summary reads identically
    # either way. The run document has always carried it; stdout did not.
    if result.get("target"):
        print(f"Target: {result['target']}")
    print(
        f"Regression diff: {summary['new']} new, "
        f"{summary['resolved']} resolved, {summary['unchanged']} unchanged"
    )
    # Said on STDOUT and said here, above the findings. With the target down
    # the run correctly exits 3 and says so on stderr -- and then prints
    # "Regression diff: 7 new", which is what catches the eye in a scrolled CI
    # log. Seven probes that were never answered are not seven new problems.
    if _established_nothing(result):
        # A sequences-only config has no check probes; its assert steps were
        # the measurements, and "not one of 0 probe(s)" described nothing. It
        # counts assert steps, not every step: a setup that was answered is
        # not an answer, and "not one of 2 sequence step(s) was answered" was
        # false beside a setup served 201. A checks config whose sessions all
        # failed sent no probe either; it counts the probes it declared, as
        # the gate's own message does.
        steps = 0 if _declares_checks(result) else len(_assert_steps(result))
        if _nothing_graded(result):
            # Setup steps only: they were answered, and none grades anything.
            print(
                "  None of those was measured: no check is declared and no "
                "sequence has an assert step, so nothing was graded."
            )
        else:
            print(
                f"  None of those was measured: not one of "
                f"{steps or summary['probes'] or _unanswered_count(result)} "
                f"{'assert step(s)' if steps else 'probe(s)'} was answered, so "
                "every entry above is a probe that did not run, not a finding "
                "about your target."
            )
    unproven = _unproven_liveness(result)
    if unproven:
        print(
            f"Unproven denials: {len(unproven)} expectation(s) held against a "
            "denial that a credential Veridor fabricated received too"
            + (
                ", or where no fabricated credential was sent to compare with"
                if any(str(entry.get("control") or "").startswith("withheld_")
                       for entry in unproven)
                else ""
            )
            + (
                ", or where the fabricated credential's own request failed"
                if any(entry.get("control") == "control_errored"
                       for entry in unproven)
                else ""
            )
            + (
                ", or where the fabricated credential's answer was neither a "
                "refusal nor a success"
                if any(entry.get("control") == "control_uninformative"
                       for entry in unproven)
                else ""
            )
            + ", so they did not establish who was denied."
        )
        for entry in unproven[:_SUPPRESSED_LISTED]:
            # A sequence step's entry names the step, not only the sequence.
            print(f"  - {terminal_text(entry.get('where') or entry['check_id'])} / "
                  f"{terminal_text(entry['identity'])}: {entry['statement']}")
            print(f"    {entry['remediation']}")
        if len(unproven) > _SUPPRESSED_LISTED:
            print(f"  ... and {len(unproven) - _SUPPRESSED_LISTED} more")
    unchecked = (result.get("liveness") or {}).get("marker_uniqueness_not_checked")
    if unchecked:
        print(
            f"Marker uniqueness not checked: {len(unchecked)} excludes_marker "
            "expectation(s) whose marker no credential Veridor fabricated was "
            "scanned for, so a marker that crosses there is graded on the "
            "premise that it is unique to its owner:"
        )
        for entry in unchecked[:_SUPPRESSED_LISTED]:
            print(
                f"  - {terminal_text(entry.get('method'))} "
                f"{terminal_text(entry.get('path'))} "
                f"({terminal_text(entry.get('owner'))}'s marker): "
                + MARKER_UNIQUENESS_REASONS.get(
                    str(entry.get("reason")), terminal_text(entry.get("reason"))
                )
            )
        if len(unchecked) > _SUPPRESSED_LISTED:
            print(f"  ... and {len(unchecked) - _SUPPRESSED_LISTED} more")

    # What the baseline is currently absorbing, named rather than counted.
    # "0 new, 1 unchanged" is the same sentence whether the finding was
    # triaged last quarter or added to `baseline.json` in the diff under
    # review, and `unchanged` reads as `resolved` to everybody who is
    # skimming. This cannot distinguish the two -- nothing can, they are the
    # same bytes -- so it states the fact and leaves the judgement.
    suppressed = _security_findings(result.get("regression", {}).get("unchanged") or ())
    if suppressed:
        proved = _confirmed_findings(suppressed)
        print(
            f"  Suppressed by the baseline: {len(suppressed)} finding(s) about "
            f"your target are present in this run AND in the baseline, so "
            f"`--fail-on new` does not see them."
        )
        if proved:
            print(
                f"  {len(proved)} of those carr{'ies' if len(proved) == 1 else 'y'} "
                "a marker another identity's response actually contained. The "
                "default policy gates on those regardless of age; `--fail-on "
                "new` alone would not."
            )
            for finding in proved[:_SUPPRESSED_LISTED]:
                print(
                    f"    {terminal_text(finding.get('check_id'))} / "
                    f"{terminal_text(finding.get('identity'))} [{finding.get('id')}]"
                )
            if len(proved) > _SUPPRESSED_LISTED:
                print(f"    ... and {len(proved) - _SUPPRESSED_LISTED} more")
    print(
        f"Evidence: {summary.get('confirmed', 0)} confirmed, "
        f"{summary.get('suspected', 0)} suspected, "
        f"{summary.get('ungraded', 0)} ungraded, "
        f"{summary.get('escalated', 0)} escalated since the baseline"
    )
    _print_sequences(result)
    # Standing, unconditional, and adjacent to the counts it qualifies. The
    # grades above read as verdicts on the target; they are verdicts on the
    # target measured against the operator's own declaration, and a wrong
    # declaration is indistinguishable from a real break.
    print(f"Scope: {DECLARATION_SCOPE}")
    # The symmetric half. Without it the only outcome carrying no caveat is a
    # green run, which is the outcome a reader is most likely to over-read.
    print(f"Pass: {PASS_SCOPE}")
    _print_pass_disclosures(result)
    _print_unreviewed_stubs(result)
    for finding in result["findings"]:
        grade = finding.get("evidence_grade", "ungraded")
        suffix = "" if grade in {"n/a", "ungraded"} else f" ({grade})"
        print(
            f"- [{finding['verdict']}{suffix}] {terminal_text(finding['check_id'])} / "
            f"{terminal_text(finding['identity'])}: {finding['message']}"
        )
        # The remediation was written, tested, carried into SARIF and the
        # viewer -- and never printed here. A docs-only trial with
        # `timeout_seconds: 1` against a 3s target saw only "Request failed:
        # timed out", went looking at its firewall, and never saw the sentence
        # naming the setting and its configured value. Printed for every
        # finding: the web view already does that, and a rule about which
        # verdicts deserve advice is a rule somebody has to maintain.
        remediation = finding.get("remediation")
        if remediation:
            print(f"    {remediation}")


#: Addresses that reach only this machine.
#:
#: The empty string is NOT one of them and used to be listed here. To
#: ``socket.bind`` it means INADDR_ANY -- every interface -- so `--host ""`
#: took the exact blast radius this guard exists to refuse and walked straight
#: past it. Measured: the socket came up on ``*:PORT``, and from another
#: address on the LAN a request carrying ``Host: localhost`` was served 200
#: with every run document in it. The Host check downstream cannot save this,
#: because it must always answer to loopback NAMES for the operator's own
#: browser; once the socket is public, sending ``Host: localhost`` is free.
#: `--host 0.0.0.0` was refused correctly the whole time -- only the spelling
#: nobody types deliberately was let through.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _refuse_unauthenticated_exposure(args: argparse.Namespace) -> None:
    """A non-loopback bind must be typed out, like every other blast radius here.

    The viewer has no authentication and is not going to grow any -- it reads
    artifacts that are already on the operator's disk. Binding it to 0.0.0.0
    was accepted silently, which published every run document to the network:
    target URLs, finding messages, config paths. This tool already demands a
    verbatim acknowledgement to send a mutating request or to run an operator's
    own command; publishing findings is at least that.
    """
    host = (getattr(args, "host", "") or "").strip("[]").lower()
    if host in _LOOPBACK_HOSTS or getattr(args, "acknowledge_exposure", False):
        return
    raise ConfigError(
        f"--host {args.host} binds an address other than loopback, and the "
        "viewer has no authentication: every run document it serves -- target "
        "URLs, finding messages, config paths -- becomes readable by anything "
        "that can reach that address. Pass "
        "--i-understand-this-is-unauthenticated if that is what you want, or "
        "leave --host at 127.0.0.1 and use an SSH tunnel."
    )


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve()


#: How many entries of a directory :func:`_case_insensitive` looks at before it
#: gives up and returns the conservative answer. Bounded so a history directory
#: with thousands of runs costs a handful of stats, not thousands.
_CASE_PROBE_ENTRIES = 64


def _case_insensitive(directory: Path) -> bool:
    """Whether ``directory``'s filesystem matches names case-insensitively.

    Found by looking, not assumed from the platform: macOS volumes can be
    formatted case-sensitive, Linux can mount case-insensitive ones, and
    Windows directories can be flagged either way. An entry whose name has a
    case is looked up again with its case swapped -- a hit on the same file
    means case-insensitive, a miss means case-sensitive. Nothing is written.

    When no entry (and not the directory's own name) has a case to swap there
    is nothing to tell by, and the answer is True: that direction refuses two
    output names differing only in case, which costs a rename, where the other
    direction lets one output replace another.
    """
    candidates: list[Path] = []
    try:
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= _CASE_PROBE_ENTRIES:
                    break
                candidates.append(Path(entry.path))
    except OSError:
        pass
    candidates.append(directory)
    for candidate in candidates:
        swapped = candidate.name.swapcase()
        if not candidate.name or swapped == candidate.name:
            continue
        try:
            return os.path.samefile(candidate, candidate.with_name(swapped))
        except FileNotFoundError:
            return False
        except OSError:
            continue
    return True


def _nearest_existing(path: Path) -> tuple[Path, tuple[str, ...]]:
    """The deepest ancestor of ``path`` (itself included) that exists, and the
    names below it that do not exist yet."""
    missing: list[str] = []
    current = path
    while not os.path.lexists(current) and current.parent != current:
        missing.append(current.name)
        current = current.parent
    return current, tuple(reversed(missing))


def _same_file(a: Path, b: Path) -> bool:
    """Whether two resolved paths name the same file on this machine.

    ``resolve()`` keeps the case it was given, so comparing its strings called
    ``VERIDOR.DEMO.JSON`` and ``veridor.demo.json`` two files -- and on a
    case-insensitive filesystem (the macOS default, and Windows) they are one.
    Measured: ``run --json VERIDOR.DEMO.JSON`` replaced the configuration with
    the run document, and ``--baseline b.json --json B.JSON`` replaced the
    baseline being compared against. ``os.path.normcase`` does not help: it
    folds nothing on macOS.

    Both exist: device and inode decide (a hard link counts as the same file,
    which is right -- writing one rewrites the other). Otherwise the nearest
    existing directories must be the same directory, and the names below it
    equal under that directory's own case rule (:func:`_case_insensitive`).
    Unicode normalisation is not folded.
    """
    if a == b:
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        pass
    base_a, rest_a = _nearest_existing(a)
    base_b, rest_b = _nearest_existing(b)
    if not rest_a and not rest_b:
        return False
    if len(rest_a) != len(rest_b):
        return False
    try:
        if not os.path.samefile(base_a, base_b):
            return False
    except OSError:
        return False
    if rest_a == rest_b:
        return True
    if not _case_insensitive(base_a):
        return False
    return [os.path.normcase(n).casefold() for n in rest_a] == [
        os.path.normcase(n).casefold() for n in rest_b
    ]


def _validate_destinations(
    destinations: Sequence[tuple[str, Path]],
    protected_inputs: set[Path],
    output_dir: Path | None = None,
    managed_writes: Sequence[Path] = (),
) -> None:
    """Refuse any output path that would destroy an input or run history.

    ``managed_writes`` are the fixed-name files the command itself writes
    under ``--output-dir`` -- ``latest.json`` for `run` and `verify`, the
    mutation report for `mutate`. No protected input may be one of them. That
    half was missing: the explicit destinations were checked against the
    inputs, but the managed write never was, and `run --baseline
    .veridor/latest.json` was accepted. The run then replaced its own baseline
    with its own result, so the re-run -- the first thing anybody does with a
    red build -- compared a live finding against itself and exited 0 (measured
    against the demo target: exit 1, then exit 0 with "0 new, 1 unchanged").
    `--config out/latest.json --output-dir out` replaced the configuration
    with a run document the same way. ``runs/<run_id>.json`` is not in the
    list: nothing rewrites it, and it is a legitimate pinned baseline.

    Every comparison is :func:`_same_file`, never string equality: see there
    for the case-insensitive filesystem that string equality lost to.
    """
    for index, (label, path) in enumerate(destinations):
        for earlier_label, earlier in destinations[:index]:
            if _same_file(earlier, path):
                raise ConfigError(f"{earlier_label} and {label} must use different paths")
    managed_latest = output_dir / "latest.json" if output_dir is not None else None
    managed_runs = output_dir / "runs" if output_dir is not None else None
    for label, path in destinations:
        if any(_same_file(path, protected) for protected in protected_inputs):
            raise ConfigError(
                f"{label} must not overwrite a configuration, baseline, or specification"
            )
        if output_dir is not None and (
            _same_file(path, output_dir)
            or _same_file(path, managed_latest)
            or _same_file(path, managed_runs)
            or any(_same_file(parent, managed_runs) for parent in path.parents)
        ):
            raise ConfigError(f"{label} conflicts with managed run history")
    for managed in managed_writes:
        for protected in sorted(protected_inputs):
            if _same_file(protected, managed):
                raise ConfigError(
                    f"{protected} is the file this command writes its own result "
                    f"to ({managed.name} under --output-dir), so it would be "
                    "replaced as the command runs. A configuration or "
                    "specification there is destroyed; a baseline there becomes "
                    "this run's own result, and the re-run compares a live "
                    "finding against itself and exits 0. Copy it out first -- "
                    f"`cp {protected} pinned.json`, then pass pinned.json -- "
                    "or choose a different --output-dir. Nothing has been sent."
                )


#: The fix a write-preflight refusal prints for a container. The release image
#: runs as uid 10001, and a directory mounted into it is owned by whoever
#: created it on the host -- root, for a tmpfs or a fresh volume.
_CONTAINER_USER_FIX = 'docker run --user "$(id -u):$(id -g)"'


def _effective_ids() -> str:
    """``uid:gid`` of this process, as the kernel will judge the writes."""
    uid = os.geteuid() if hasattr(os, "geteuid") else "?"
    gid = os.getegid() if hasattr(os, "getegid") else "?"
    return f"{uid}:{gid}"


def _shown(path: Path) -> str:
    """The path as typed, plus where it resolves when that is not obvious."""
    if path.is_absolute():
        return str(path)
    return f"{path} (resolved: {Path.cwd() / path})"


def _relative_to(where: Path, path: Path) -> str:
    """How a refusal names the directory that failed, relative to the flag's path."""
    if where == path:
        return "it"
    if where in path.parents:
        return f"its parent directory {where}"
    return str(where)


def _write_failure(what: str, path: Path, error: OSError) -> str:
    """Say which output could not be written, and why, in the operator's terms.

    ``reports.write_text`` writes a temporary sibling first and renames it over
    ``path``, so the OSError it raises names that sibling, or a parent directory
    it tried to create. Printed raw, `report --output ro/j.xml` into a read-only
    directory said ``[Errno 13] Permission denied: 'ro/.j.xml.42f6df0f81e22ee1.tmp'``:
    a file the operator never named, and no word about the one they did.
    """
    reason = error.strerror or str(error)
    message = f"could not write {what} to {_shown(path)}: {reason}"
    failed = error.filename
    if failed is not None:
        failed = Path(os.fsdecode(failed))
        temporary = (
            failed.parent == path.parent
            and failed.name.startswith(f".{path.name}.")
            and failed.name.endswith(".tmp")
        )
        if temporary:
            message += f" (writing into {_relative_to(path.parent, path)})"
        elif failed in path.parents:
            message += f" (creating {_relative_to(failed, path)})"
        elif failed != path:
            message += f" (at {failed})"
    if isinstance(error, PermissionError):
        message += f", as uid:gid {_effective_ids()}"
    return f"{message}. Nothing was written to {path}."


def _probe_directory(directory: Path) -> tuple[str, Path, OSError] | None:
    """Create ``directory`` if needed and write, then remove, one file in it.

    Returns ``(what failed, where, error)``, or None when the directory is
    writable. Leaves nothing behind either way: the probe file is removed, and
    so is every directory this call created, so a refusal later in the command
    -- or a run that stops before writing -- finds the tree as it was.
    """
    created: list[Path] = []
    try:
        missing: list[Path] = []
        cursor = directory
        while not os.path.lexists(cursor):
            missing.append(cursor)
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        for path in reversed(missing):
            try:
                path.mkdir()
            except FileExistsError:
                continue
            except OSError as error:
                return "create", path, error
            created.append(path)
        if not directory.is_dir():
            return (
                "use",
                directory,
                NotADirectoryError(errno.ENOTDIR, "it exists and is not a directory"),
            )
        probe = directory / f".veridor-write-check-{secrets.token_hex(6)}"
        try:
            descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as error:
            return "create a file in", directory, error
        try:
            os.write(descriptor, b"veridor write check\n")
        except OSError as error:
            return "write a file in", directory, error
        finally:
            os.close(descriptor)
            try:
                probe.unlink()
            except OSError:
                pass
        return None
    except OSError as error:
        return "inspect", directory, error
    finally:
        for path in reversed(created):
            try:
                path.rmdir()
            except OSError:
                pass


def _preflight_writable(
    command: str, destinations: Sequence[tuple[str, Path, bool]]
) -> None:
    """Refuse, before the first request, a command whose results cannot be written.

    ``destinations`` is ``(flag, path, is_directory)``: every directory the
    command will write into, and every file it will write (whose directory is
    what gets probed). Measured before this existed: ``veridor run`` with an
    unwritable ``--output-dir`` sent every probe to the target and then exited
    2 with nothing but ``[Errno 13] Permission denied: <dir>``. The finding was
    lost, the exit code said "refused" about a run that had already happened,
    and a write-mode configuration would already have changed the target. A
    request whose result cannot be recorded is not sent.
    """
    checked: set[Path] = set()
    for flag, path, is_directory in destinations:
        if not is_directory and os.path.isdir(path):
            raise ConfigError(
                f"{flag} {_shown(path)} is an existing directory, so the file "
                f"`{command}` writes there cannot replace it. Nothing has been "
                "sent. Name a file path instead."
            )
        directory = path if is_directory else path.parent
        key = Path(os.path.abspath(directory))
        if key in checked:
            continue
        checked.add(key)
        failure = _probe_directory(directory)
        if failure is None:
            continue
        action, where, error = failure
        reason = error.strerror or str(error)
        container = (
            "or, in a container, run it as the owner of the mounted directory "
            f"({_CONTAINER_USER_FIX})"
        )
        if flag == "--output-dir":
            fix = (
                "pass an --output-dir this user can write (for example "
                f"--output-dir /tmp/veridor), {container}"
            )
        else:
            fix = f"point {flag.split()[0]} at a directory this user can write, {container}"
        raise ConfigError(
            f"cannot write the results of `{command}` to {flag} {_shown(path)}: "
            f"could not {action} {_relative_to(where, path)} ({reason}) "
            f"as uid:gid {_effective_ids()}. Nothing has been sent: this is "
            "checked before the first request, because a run whose results "
            "cannot be written would still probe the target and then lose what "
            f"it found. Fix: {fix}."
        )


def _run_destinations(args: argparse.Namespace) -> list[tuple[str, Path, bool]]:
    """Everything ``veridor run --config`` writes, as ``_preflight_writable`` takes it."""
    found: list[tuple[str, Path, bool]] = [
        ("--output-dir", args.output_dir, True),
        ("--output-dir", args.output_dir / "runs", True),
    ]
    for flag, path in (
        ("--json", args.json_path),
        ("--sarif", args.sarif),
        ("--coverage", getattr(args, "coverage_path", None)),
        ("--badge", getattr(args, "badge", None)),
        *(
            (f"--report {fmt}={path}", path)
            for fmt, path in getattr(args, "reports", None) or ()
        ),
    ):
        if path is not None:
            found.append((flag, path, False))
    return found


def _run_history_writes(output_dir: Path) -> list[Path]:
    """The fixed-name file `run` and `verify` rewrite on every run
    (`core.persist_run`); ``runs/<run_id>.json`` is new each time."""
    return [output_dir / "latest.json"]


def _validate_run_paths(args: argparse.Namespace) -> None:
    if args.openapi is None:
        for label, value in (
            ("--coverage", args.coverage_path),
            ("--badge", args.badge),
            ("--base-path", args.base_path),
        ):
            if value is not None:
                raise ConfigError(f"{label} requires --openapi")
        if args.allow_no_matches:
            raise ConfigError("--allow-no-matches requires --openapi")
    destinations = [
        (label, _resolved(path))
        for label, path in (
            ("--json", args.json_path),
            ("--sarif", args.sarif),
            ("--coverage", args.coverage_path),
            ("--badge", args.badge),
            *(
                (f"--report {fmt}", path)
                for fmt, path in getattr(args, "reports", None) or ()
            ),
        )
        if path is not None
    ]
    protected_inputs = {_resolved(args.config)}
    if args.baseline:
        protected_inputs.add(_resolved(args.baseline))
    if args.openapi:
        protected_inputs.add(_resolved(args.openapi))
    output_dir = _resolved(args.output_dir)
    _validate_destinations(
        destinations, protected_inputs, output_dir, _run_history_writes(output_dir)
    )


def _validate_coverage_paths(args: argparse.Namespace) -> None:
    destinations = [
        (label, _resolved(path))
        for label, path in (
            ("--coverage", args.coverage_path),
            ("--badge", args.badge),
        )
        if path is not None
    ]
    _validate_destinations(
        destinations, {_resolved(args.config), _resolved(args.openapi)}
    )


def _coverage_report(
    args: argparse.Namespace, *, require_checks: bool = True
) -> dict[str, Any]:
    config = load_config(
        args.config,
        getattr(args, "base_url", None),
        require_checks=require_checks,
        # Coverage is a static reading of the declaration against the spec and
        # sends nothing, so a missing token must not block it. `run` and `map`
        # still refuse, because they are about to authenticate.
        allow_missing_env=True,
    )
    inventory = parse_spec(load_spec(args.openapi), source=str(args.openapi))
    return compute_coverage(
        config,
        inventory,
        config_path=args.config,
        spec_path=args.openapi,
        base_path=args.base_path,
        allow_no_matches=args.allow_no_matches,
    )


def _write_coverage_artifacts(
    args: argparse.Namespace, report: dict[str, Any] | None, reason: str = ""
) -> None:
    if report is None:
        # A refusal that came before any report. The file at --coverage was
        # left as it was, so a later step read the last run's "measured"
        # figure after this one exited 2; it is rewritten as not measured, as
        # the badge below is rewritten as unknown.
        report = not_measured_report(reason or "boundary coverage was not measured")
    if args.coverage_path is not None:
        write_json(args.coverage_path, report)
    if args.badge is not None:
        # A measurement that is not defined must never leave a stale green badge
        # in place, so the badge is rewritten as 'unknown' instead of skipped.
        write_json(args.badge, render_badge(report or {}))


def _emit_coverage(args: argparse.Namespace, *, require_checks: bool = True) -> int:
    """Compute, persist, and print boundary coverage. Returns 0, or 2 if undefined.

    ``require_checks=False`` follows ``map``: a config with no expectations at
    all has NO boundary coverage, which is undefined rather than 0%, and is not
    an error. That last clause used to be true only of the docstring: the
    failure path below printed `veridor: boundary coverage was not measured` on
    stderr, with the same prefix as a genuinely fatal refusal, above the plan
    banner, on 100% of drift runs. Three separate docs-only trial runs reported it
    as a possible failure.
    """
    try:
        report = _coverage_report(args, require_checks=require_checks)
    except (ConfigError, OSError) as exc:
        # The configuration did not load, so nothing was measured; the caller
        # still reports the refusal. Neither file may keep a stale figure. An
        # OSError is a configuration that could not be read (a directory, a
        # file the runner may not open); it left both files stale.
        _write_coverage_artifacts(args, None, refusal_text(str(exc)))
        raise
    except (CoverageError, SpecError) as exc:
        report = getattr(exc, "report", None)
        _write_coverage_artifacts(args, report, refusal_text(str(exc)))
        if report is not None:
            print()
            print(render_text(report), end="")
        if getattr(exc, "reason", None) == "no_declaration" and not require_checks:
            # `map` on the zero-declaration path. Declaring no checks is the
            # documented starting state there, the full explanation is already
            # in the report printed above, and this is not a failure of
            # anything. Say it on stdout, without the prefix that means "this
            # command refused".
            print(
                "  Boundary coverage is not measured on this path: this "
                "configuration declares\n  no checks, which is what `--for "
                "drift` is. Nothing is wrong."
            )
            return 0
        print(f"veridor: boundary coverage was not measured: {refusal_text(str(exc))}", file=sys.stderr)
        return 2
    _write_coverage_artifacts(args, report)
    print()
    print(render_text(report), end="")
    return 0


#: How many baseline-suppressed confirmed findings the summary names before it
#: summarises. Same idiom as every other capped list on this surface.
_SUPPRESSED_LISTED: int = 5


def _capsule(args: argparse.Namespace) -> int:
    """Write a portable proof of one finding.

    Reads the configuration RAW rather than through ``load_config``: the loaded
    form has already resolved every ``${ENV_VAR}`` to its literal value, and
    that is precisely what must never be published.
    """
    from veridor import capsule as capsule_module  # noqa: PLC0415

    if args.output is not None:
        # Before anything is read, as for every other verb. `--output` was
        # written with no check at all: `--output veridor.json`, or
        # `VERIDOR.JSON` on a case-insensitive volume, replaced the
        # configuration with the capsule and exited 0, and `--from-run X
        # --output X` replaced the run document.
        output = _resolved(args.output)
        if args.from_run is not None and _same_file(_resolved(args.from_run), output):
            raise ConfigError(
                "--output must not overwrite the input run (--from-run). Nothing "
                "has been written."
            )
        _validate_destinations([("--output", output)], {_resolved(args.config)})

    try:
        raw = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigError(f"cannot read {args.config}: {error}") from error

    run_document = None
    if args.from_run is not None:
        try:
            run_document = json.loads(args.from_run.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ConfigError(f"cannot read {args.from_run}: {error}") from error

    built, renames = capsule_module.build_with_renames(
        raw, args.check, run_document=run_document, image=args.image
    )
    rename_note = (
        "  Renamed for the verifier, who can supply only VERIDOR_* variables: "
        + ", ".join(f"{old} -> {new}" for old, new in renames.items())
        if renames
        else None
    )
    rendered = json.dumps(built, indent=1) + "\n"
    if args.output is None:
        print(rendered, end="")
        if rename_note:
            # stdout is the capsule itself; the note must not corrupt it.
            print(f"veridor:{rename_note[1:]}", file=sys.stderr)
        return 0
    write_json(args.output, built)
    print(f"Wrote a capsule for check {quoted(args.check)} to {args.output}")
    required = built["requires_environment"]
    print(
        "  It carries NO credential. Whoever verifies it must set: "
        + (", ".join(required) if required else "(nothing)")
    )
    if rename_note:
        print(rename_note)
    print(f"  They run: veridor verify {args.output} --base-url https://their-instance")
    return 0


#: The ``run``/``verify`` options a capsule run applies. Every other option the
#: parser knows -- today's and any added later -- is refused when typed next to
#: a capsule, because ``_verify_capsule`` used to read three attributes and
#: silently drop the rest: ``verify proof.json --read-only`` sent the capsule's
#: DELETEs anyway.
_CAPSULE_OPTIONS: frozenset[str] = frozenset(
    {"capsule", "base_url", "output_dir", "read_only", "json_path", "sarif", "prove_liveness"}
)
_CAPSULE_OPTIONS_TEXT = "--base-url, --output-dir, --read-only, --json, --sarif and --no-prove-liveness"

_UNTYPED = object()


class _UntypedItems(list):
    """The sentinel for ``append``/``extend`` options such as ``--report``.

    Those actions copy what is already on the namespace and call ``.append``
    on the copy, so a bare ``object()`` sentinel made typing ``--report`` next
    to a capsule crash (exit 70) instead of being refused. The copy is a new
    object, so an identity check still tells typed from untyped."""


def _untyped_sentinel(action: argparse.Action) -> Any:
    if isinstance(action, (argparse._AppendAction, argparse._AppendConstAction, argparse._ExtendAction)):
        return _UntypedItems()
    return _UNTYPED


def _typed_options(parser: argparse.ArgumentParser, tokens: Sequence[str]) -> dict[str, str]:
    """``{dest: flag}`` for every subcommand option actually typed in ``tokens``.

    Comparing a parsed value with its default cannot tell ``--fail-on
    new+confirmed`` from no ``--fail-on`` at all, so the subcommand's own parser
    re-reads the tokens into a namespace pre-filled with a sentinel: argparse
    does not overwrite an attribute that is already present with a default, so
    whatever is no longer the sentinel was typed.
    """
    subparsers = next(
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    index = next(i for i, token in enumerate(tokens) if token in subparsers.choices)
    subparser = subparsers.choices[tokens[index]]
    actions = {
        action.dest: action
        for action in subparser._actions
        if action.dest != argparse.SUPPRESS
    }
    sentinels = {dest: _untyped_sentinel(action) for dest, action in actions.items()}
    namespace = argparse.Namespace(**sentinels)
    subparser.parse_known_args(list(tokens[index + 1:]), namespace)
    return {
        dest: "/".join(action.option_strings) or dest
        for dest, action in actions.items()
        if getattr(namespace, dest) is not sentinels[dest]
    }


def _relabel(document: Any, old: str, new: str) -> Any:
    """Replace every occurrence of the temporary config path with the capsule's."""
    encoded_old, encoded_new = json.dumps(old)[1:-1], json.dumps(new)[1:-1]
    return json.loads(json.dumps(document).replace(encoded_old, encoded_new))


def _verify_capsule(
    args: argparse.Namespace, typed: dict[str, str] | None = None
) -> int:
    """Run a capsule and print one of three verdicts.

    Exit codes are the capsule's own, not a run's: 1 means the claim reproduced
    here, which is the answer a maintainer is looking for and the opposite of a
    tool failure. A refusal is 2, like INCONCLUSIVE, and is always decided
    before anything is sent.

    The capsule is untrusted input. In order, before any request:

    1. an option this path does not apply is refused, not ignored;
    2. ``capsule.load`` refuses a claim or scope carrying a terminal control,
       because those fields are printed beside the verdict;
    3. every ``${NAME}`` must be ``VERIDOR_*`` (``capsule.verifier_environment``);
    4. ``--read-only`` refuses a capsule with any non-safe method;
    5. a capsule target that is not this machine's loopback needs --base-url;
    6. a capsule with any non-safe method needs --base-url, loopback or not:
       an untrusted DELETE aimed at 127.0.0.1 can still reach a local admin
       service, so writes only ever go to an address the verifier typed.
    """
    from veridor import capsule as capsule_module  # noqa: PLC0415
    from veridor.core import _enforce_read_only, _mutating_requests  # noqa: PLC0415

    unapplied = sorted(
        flag for dest, flag in (typed or {}).items() if dest not in _CAPSULE_OPTIONS
    )
    if unapplied:
        raise ConfigError(
            f"verify <capsule> does not apply {', '.join(unapplied)}; refused "
            "rather than ignored. A capsule run has its own exit codes (1 "
            "CONFIRMED, 0 NOT_REPRODUCED, 2 INCONCLUSIVE or refused) and takes only "
            f"{_CAPSULE_OPTIONS_TEXT}. Remove the rest and re-run; to run a "
            "configuration, use `veridor run --config FILE`. Nothing has been sent."
        )

    loaded = capsule_module.load(args.capsule)
    config = capsule_module.to_config(loaded, args.base_url)
    variables = capsule_module.verifier_environment(config)
    writes = _mutating_requests(config)
    if writes and args.read_only:
        _enforce_read_only(config)
    recorded = (loaded.get("target") or {}).get("base_url")
    if not args.base_url and not capsule_module.targets_loopback(recorded):
        raise ConfigError(
            f"this capsule's target is {quoted(recorded)}, which is not this machine's "
            "loopback. A capsule names the REPORTER's target, and `veridor verify` "
            "sends nothing to an address the capsule chose. Pass --base-url with "
            "the instance YOU are verifying, e.g. --base-url https://your-instance. "
            "Nothing has been sent."
        )
    if writes and not args.base_url:
        listed = "; ".join(
            f"{terminal_text(verb)} in {where}" for verb, where, _, _ in writes[:3]
        )
        if len(writes) > 3:
            listed += f"; and {len(writes) - 3} more"
        raise ConfigError(
            f"this capsule issues requests that can change state ({listed}). "
            "Writes never go to an address the capsule chose, loopback included: "
            "an untrusted DELETE aimed at 127.0.0.1 can reach a local admin "
            "service. Pass --base-url with the instance YOU are verifying to send "
            "them there. Nothing has been sent."
        )
    destinations = [
        (label, _resolved(path))
        for label, path in (("--json", args.json_path), ("--sarif", args.sarif))
        if path is not None
    ]
    output_dir = _resolved(args.output_dir)
    _validate_destinations(
        destinations, {_resolved(args.capsule)}, output_dir,
        _run_history_writes(output_dir),
    )
    probed = (config.get("target") or {}).get("base_url")
    _validate_http_url(probed, "--base-url" if args.base_url else "capsule target.base_url")
    _preflight_writable(
        "verify",
        [
            ("--output-dir", args.output_dir, True),
            ("--output-dir", args.output_dir / "runs", True),
            *(
                (flag, path, False)
                for flag, path in (("--json", args.json_path), ("--sarif", args.sarif))
                if path is not None
            ),
        ],
    )
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "capsule-config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        # Loaded once here, before the line below says where the values go:
        # that line used to print ahead of a capsule the loader then refused
        # (an off-origin request path, say), naming a destination nothing was
        # ever sent to. Loading sends nothing; execute_run loads it again.
        load_config(path, read_only=args.read_only)
        # "sends the values there" was false behind a proxy: the values went
        # to the proxy. A loopback target is never proxied (core.proxy_route),
        # so this clause only ever appears with --base-url.
        via = _proxy_sentence(probed)
        print(
            f"veridor: verifying capsule check {quoted(loaded['check'].get('id'))} "
            f"against {terminal_text(probed)} "
            + ("(from --base-url). " if args.base_url else "(the capsule's own loopback target). ")
            + (
                # Every name, each bounded: this is the disclosure of what is
                # read, so the list is not cut short.
                f"It reads {', '.join(terminal_text(name) for name in variables)} "
                "from your environment and sends the values there."
                if variables
                else "It reads no environment variable."
            )
            + (f" {via[:1].upper()}{via[1:]}" if via else ""),
            file=sys.stderr,
        )
        try:
            document = execute_run(
                path,
                output_dir=args.output_dir,
                base_url=None,
                read_only=args.read_only,
                prove_liveness=args.prove_liveness,
                announce_proxy_route=False,
            )
        except ConfigError:
            raise
        except OSError as error:
            print(
                capsule_module.render(
                    loaded,
                    {
                        "verdict": capsule_module.INCONCLUSIVE,
                        "reason": f"the target could not be reached: {error}",
                    },
                    probed,
                )
            )
            return 2
        # The run document names the temporary config as its source, a file
        # deleted when this block ends. Every copy names the capsule instead:
        # the relabel used to apply to --json and --sarif only, so the managed
        # history -- what `report` and `serve` read -- cited a path that no
        # longer existed.
        document = _relabel(document, str(path), str(args.capsule))

    adjudication = capsule_module.adjudicate(loaded, document)
    _record_capsule_verdict(args, loaded, document, adjudication)
    if args.sarif:
        write_json(args.sarif, to_sarif(document))

    print(capsule_module.render(loaded, adjudication, probed))
    return document["capsule"]["exit_code"]


def _record_capsule_verdict(
    args: argparse.Namespace,
    loaded: dict[str, Any],
    document: dict[str, Any],
    adjudication: dict[str, Any],
) -> None:
    """Write the capsule's verdict, and the exit code it means, into the run.

    The verdict existed only on stdout. ``execute_run`` persisted the run of
    the capsule as an ordinary run with no gate, so ``report`` re-derived one
    with the ``veridor run`` defaults -- an INCONCLUSIVE verification, exit 2,
    rendered "Gate passed (exit 0)" -- and ``serve`` listed it as a plain run
    whose status was computed from findings. Rewritten everywhere it was
    written, the way ``_record_gate`` does for ``run``.
    """
    verdict = adjudication["verdict"]
    check_id = (loaded.get("claim") or {}).get("check_id")
    document["capsule"] = {
        "verdict": verdict,
        "exit_code": CAPSULE_EXIT_CODES[verdict],
        "reason": str(adjudication.get("reason") or ""),
        "check_id": str(check_id) if check_id is not None else "",
        "path": str(args.capsule),
    }
    reproduced = [
        str(finding.get("id"))
        for finding in adjudication.get("findings") or ()
        if finding.get("verdict") == "vulnerable"
    ]
    document["gate"] = gate_policy.capsule_gate(
        verdict, document["capsule"]["reason"], reproduced
    )
    persist_run(document, args.output_dir, extra_paths=_json_paths(args))


def _run(args: argparse.Namespace) -> int:
    if args.config is None:
        raise ConfigError(
            "run requires either --config FILE (a Veridor configuration) or a "
            "capsule path (`veridor verify proof.json`). Neither was given."
        )
    _validate_run_paths(args)
    _preflight_writable("run", _run_destinations(args))
    try:
        result = execute_run(
            args.config,
            output_dir=args.output_dir,
            baseline_path=args.baseline,
            base_url=args.base_url,
            read_only=args.read_only,
            prove_liveness=args.prove_liveness,
            wait_for_target_seconds=args.wait_for_target,
            extra_paths=_json_paths(args),
        )
    except ConfigError as exc:
        # execute_run loads the configuration, so a configuration that does
        # not load is refused here, before coverage is reached. That path used
        # to leave --coverage and --badge as the previous run wrote them -- a
        # "measured" figure and a green badge after an exit 2 -- although the
        # README says such a refusal rewrites both. The destinations were
        # validated and preflighted above, so writing them here is safe.
        if args.openapi is not None:
            _write_coverage_artifacts(args, None, refusal_text(str(exc)))
        raise
    except OSError as exc:
        # A configuration that could not be read, or anything else that ends
        # the run before coverage: nothing was measured either way, and this
        # path left both files as the previous run wrote them.
        if args.openapi is not None:
            _write_coverage_artifacts(args, None, refusal_text(str(exc)))
        raise
    if args.sarif:
        write_json(args.sarif, to_sarif(result))
    _print_summary(result)
    _emit_github_annotations(result)

    # Coverage runs after the probes and never suppresses them: a stale spec is
    # a documentation problem and must not block an authorization regression.
    coverage_status = _emit_coverage(args) if args.openapi is not None else 0
    # One computation for the exit code, the stderr explanation, and the `gate`
    # object every report renders. The precedence (a real finding always wins;
    # --fail-on none moves only the two opt-in flags) lives in veridor.gate.
    decision = gate_policy.evaluate(
        result,
        fail_on=args.fail_on,
        require_complete=args.require_complete,
        require_clean_teardown=args.require_clean_teardown,
        coverage_status=coverage_status,
    )
    for message in decision.messages:
        print(message, file=sys.stderr)
    _record_gate(args, result, decision)
    return _write_run_reports(args, result, decision.exit_code)


def _record_gate(
    args: argparse.Namespace,
    result: dict[str, Any],
    decision: gate_policy.GateDecision,
) -> None:
    """Write the decision into the run document, everywhere it was written.

    ``execute_run`` persists the document before the exit code exists -- the
    policy depends on flags and on coverage, which it does not see -- so the
    managed history and ``--json`` are rewritten here with the ``gate`` object
    added. Same bytes otherwise; the key is additive.
    """
    result["gate"] = decision.to_document()
    persist_run(result, args.output_dir, extra_paths=_json_paths(args))


def _json_paths(args: argparse.Namespace) -> tuple[Path, ...]:
    """``--json``, written with the managed history from one serialization."""
    return (args.json_path,) if args.json_path else ()


def _write_run_reports(
    args: argparse.Namespace, result: dict[str, Any], exit_code: int
) -> int:
    """Render every ``--report FORMAT=PATH`` from this run's document.

    Written whatever the gate decided, because a failing gate is exactly when
    CI needs them. Rendered from a JSON round trip of the document and through
    the same validation ``veridor report --from-run`` applies, so the two paths
    cannot produce different reports for the same run.

    A report that cannot be written is said on stderr and never passes
    silently: the exit code becomes 2, unless the gate already failed on a
    finding (1), which stays the louder and more specific answer.
    """
    requested = list(getattr(args, "reports", None) or ())
    if not requested:
        return exit_code
    document = validate_run(json.loads(json.dumps(result)), source="this run")
    failed = False
    for fmt, path in requested:
        try:
            reports.write_text(path, reports.render(fmt, document, root=Path.cwd()))
        except OSError as error:
            failed = True
            print(
                f"veridor: {_write_failure(f'the {fmt} report', path, error)}",
                file=sys.stderr,
            )
            continue
        print(f"Wrote {fmt} report to {path}")
    if failed and exit_code != 1:
        return 2
    return exit_code


def _coverage(args: argparse.Namespace) -> int:
    _validate_coverage_paths(args)
    return _emit_coverage(args)


# ---------------------------------------------------------------------------
# map -- what don't I cover, and what would a compromise reach?
# ---------------------------------------------------------------------------

#: The bridge from discovery to declaration, printed under every map. Without
#: it a ranked list of candidates reads exactly like a ranked list of findings,
#: which is the one thing this command must never be mistaken for.
#: Printed after every map. The first clause is unconditional and true: nothing
#: `map` DISCOVERS is a finding. The exit-code clause is not -- drift can gate
#: when asked to -- so it is appended separately by _map rather than asserted
#: here, where it would have become a small lie the moment --fail-on-drift
#: existed.
_MAP_NEXT: str = (
    "Next: nothing above is a finding.\n"
    "  A candidate is an inconsistency between observations and a hypothesis to "
    "test.\n"
    "  Promote the ones you believe into checks (--promote writes stubs), then "
    "`veridor run`\n"
    "  gates on them and `veridor mutate` says whether the gate could ever fail."
)


def _map_id() -> str:
    """A run id in the shape ``core.execute_run`` uses, for the same reason."""
    return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"


def _map_options(args: argparse.Namespace) -> MatrixOptions:
    """Build the envelope. ``MatrixOptions`` refuses an unsafe one on construction."""
    return MatrixOptions(
        max_requests=args.max_requests,
        requests_per_second=args.requests_per_second,
        allow_mutating_methods=frozenset(
            method.strip() for method in args.allow_mutating_method if method.strip()
        ),
        mutating_acknowledgement=args.acknowledge_mutating,
        target_acknowledgement=args.acknowledge_target,
        include=tuple(args.include),
        ignore=tuple(args.ignore),
        timeout_seconds=args.matrix_timeout,
        max_run_seconds=args.max_run_seconds,
        on_retry_after=getattr(args, "on_retry_after", ON_RETRY_AFTER_DEFAULT),
    )


def _validate_map_paths(args: argparse.Namespace) -> None:
    destinations = [
        (label, _resolved(path))
        for label, path in (
            ("--matrix", args.matrix),
            ("--blast-radius", args.blast_radius),
            ("--candidates", args.candidates),
            ("--promote", args.promote),
            ("--coverage", args.coverage_path),
            ("--badge", args.badge),
            ("--drift", args.drift_path),
        )
        if path is not None
    ]
    # --baseline joins the protected inputs for the same reason run's does:
    # `--baseline b.json --drift b.json` would replace the matrix you compare
    # against with a drift report, and the failure surfaces a week later as an
    # unreadable baseline rather than here.
    protected = {_resolved(args.config), _resolved(args.openapi)}
    if args.baseline is not None:
        protected.add(_resolved(args.baseline))
    _validate_destinations(destinations, protected, _resolved(args.output_dir))


def _map_destinations(
    args: argparse.Namespace, compares: bool
) -> list[tuple[str, Path, bool]]:
    """Everything ``_write_map_artifacts``, ``_emit_coverage`` and
    ``_emit_drift`` write, as ``_preflight_writable`` takes it."""
    found: list[tuple[str, Path, bool]] = [
        ("--output-dir", args.output_dir / directory, True)
        for directory in ("matrix", "blast-radius", "candidates")
    ]
    if compares:
        found.append(("--output-dir", args.output_dir / "drift", True))
    for flag, path in (
        ("--matrix", args.matrix),
        ("--blast-radius", args.blast_radius),
        ("--candidates", args.candidates),
        ("--promote", args.promote),
        ("--coverage", args.coverage_path),
        ("--badge", args.badge),
        ("--drift", args.drift_path),
    ):
        if path is not None:
            found.append((flag, path, False))
    return found


def _write_map_artifacts(
    args: argparse.Namespace,
    documents: dict[str, dict[str, Any]],
    candidates: Sequence[Any],
    map_id: str,
) -> list[tuple[str, Path]]:
    """Managed copies always, operator copies additionally.

    Deliberately under their own directories and never into ``latest.json`` or
    ``runs/``: a matrix is not a run and a candidate is not a finding, so a UI
    or a CI script pointed at the run history must not be able to pick one up
    by accident.
    """
    written: list[tuple[str, Path]] = []
    for name, directory, explicit in (
        ("access matrix", "matrix", args.matrix),
        ("blast radius", "blast-radius", args.blast_radius),
        ("candidates", "candidates", args.candidates),
    ):
        managed = args.output_dir / directory / f"{map_id}.json"
        write_json(managed, documents[directory])
        written.append((name, managed))
        if explicit is not None:
            write_json(explicit, documents[directory])
            written.append((name, explicit))
    if args.promote is not None:
        stubs = [
            promotion_stub(candidate) for candidate in rank_candidates(candidates)
        ]
        write_json(
            args.promote,
            {
                "_comment": [
                    "Stubs, not checks. Every one is a hypothesis Veridor could "
                    "not decide: it observed an inconsistency and cannot tell "
                    "you what the boundary should be.",
                    "Fill in the name, confirm the allowed identity, delete the "
                    "ones you disagree with, then paste the rest into the "
                    "'checks' list of your configuration.",
                ],
                "checks": stubs,
            },
        )
        written.append((f"{len(stubs)} promotion stub(s)", args.promote))
    return written


#: Reasons a cell is unknown BY CHOICE. They recur identically on every run and
#: are not a coverage failure: a mutating verb the read-only posture declined to
#: send, a templated route with no specimen, or an operation the operator
#: excluded with --ignore, matrix.ignore or a non-empty --include. Counting them
#: as unmeasured would make a CRUD API look permanently broken, and made
#: `--require-complete --ignore X` exit 3 on every healthy run.
_DELIBERATE_SKIPS = ("skipped_mutating", "skipped_no_specimen", "skipped_ignored")


def _grid_coverage(matrix_document: dict[str, Any]) -> tuple[int, int, int]:
    """Return (answered, observed, probed) for the cells this run attempted.

    ``answered`` is every cell that is not ``unknown``; ``observed`` also
    leaves out a redirect, which was answered but not followed, so nothing
    behind it was seen (:func:`veridor.drift.observed`). The "records nothing" guard counts
    ``observed``; the partial arm keeps ``answered``, because an anonymous
    302 to /login is a session app's ordinary denial and `--require-complete`
    firing on it every run is a gate somebody switches off.
    """
    from veridor.drift import observed  # noqa: PLC0415

    probed = answered = seen = 0
    for cell in matrix_document.get("cells", []):
        if cell.get("unknown_reason") in _DELIBERATE_SKIPS:
            continue
        probed += 1
        if cell.get("reach") != "unknown":
            answered += 1
        if observed(cell):
            seen += 1
    return answered, seen, probed


def _map_coverage_exit_code(
    args: argparse.Namespace, matrix_document: dict[str, Any]
) -> int:
    """Exit 3 when the grid was empty, or incomplete on request.

    Three docs-only trial runs hit this independently and it was the only finding
    all three reports called disqualifying. `map --fail-on-drift` is the command the CI
    section recommends, and it exited 0 with the target switched off: every
    cell `measurement_lost`, "Drift saw 0% of the grid" printed in full, exit
    0. One run wrote a nine-line wrapper to supply the missing exit code; another
    reported the gate as not fit to wire into CI without it.

    `run` grew exactly this guard earlier and it was never carried across --
    including the argument for it, which applies here unchanged: a CI job reads
    an exit code, not a summary line.

    A PARTIAL loss gates only when the operator asks with `--require-complete`.
    Transients are why the measured noise floor is zero, and a gate that fires
    on a rate limit is one somebody switches off.
    """
    answered, seen, probed = _grid_coverage(matrix_document)
    if not probed:
        return 0
    if not seen:
        # A grid of redirects records nothing too. Measured before this arm
        # counted them: recorded against a listener that answered every request
        # with 302, `map` exited 0 with no warning, and the file it wrote made
        # `--fail-on-drift opened` exit 0 against a cross-tenant read.
        redirects = (
            f" {answered - seen} of them were answered with a redirect, which Veridor "
            "does not follow, so nothing behind them was observed: a login wall, "
            "an SSO proxy, a maintenance page, or http:// for an https-only host "
            "are the usual causes."
            if answered else ""
        )
        print(
            f"veridor: not one of {probed} probed cell(s) was measured, so this "
            f"matrix records nothing. It is not a baseline and it is not a pass."
            f"{redirects} Check the target URL, the credentials, and that the "
            "target is up.",
            file=sys.stderr,
        )
        return 3
    if answered < probed and getattr(args, "require_complete", False):
        print(
            f"veridor: {probed - answered} of {probed} probed cell(s) could not "
            "be measured, so those operations are unverified rather than "
            "verified. Re-run when the target is healthy.",
            file=sys.stderr,
        )
        return 3
    return 0


def _load_drift_baseline(args: argparse.Namespace) -> dict[str, Any] | None:
    """Resolve --baseline before the run writes anything.

    Both halves of this matter. `map` writes its matrix into `.veridor/matrix/`,
    which is exactly the directory a user passes as --baseline, so resolving it
    afterwards picks THIS run as its own baseline -- a comparison that reports
    no drift and reads like good news. And a mistyped path should fail in a
    second, not after a full probe of somebody's API.
    """
    from veridor import drift as drift_module  # noqa: PLC0415

    if args.baseline is None:
        if args.fail_on_drift != "none":
            raise ConfigError(
                "--fail-on-drift needs --baseline: there is nothing to compare "
                f"this matrix against. Record one with `map --matrix "
                f"{DRIFT_BASELINE}`, commit it, and pass that FILE on later runs."
            )
        if getattr(args, "drift_path", None) is not None:
            # Accepted and ignored before: no file at PATH, nothing printed,
            # exit 0, and a CI step reading PATH afterwards found nothing.
            raise ConfigError(
                "--drift needs --baseline: there is no drift report without a "
                "matrix to compare this one against, so nothing would be written "
                f"to {args.drift_path}. Record one with `map --matrix "
                f"{DRIFT_BASELINE}`, commit it, and pass that FILE as --baseline."
            )
        return None
    if args.fail_on_drift != "none" and args.baseline.is_dir():
        # The ratchet. A directory resolves to the NEWEST matrix in it, and this
        # run is about to write one more into the same place. Measured against a
        # live cross-tenant read: run 1 exits 1 with reach_opened and
        # marker_appeared; the identical command re-run -- the first thing
        # anybody does with a red build -- compares the regression against
        # itself, prints "Nothing moved" and exits 0. A gate that goes green on
        # a re-run with the leak still live is worse than no gate, because
        # somebody trusted it. Refused rather than warned: this run already
        # prints two loud warnings and still exits 0, and CI reads exit codes.
        raise ConfigError(
            f"--baseline {args.baseline} is a directory, which resolves to the "
            "NEWEST matrix in it -- and this run is about to write one more. "
            "Under --fail-on-drift that ratchets: the first run catches the "
            "regression and exits 1, and a re-run compares the regression "
            "against itself, reports 'Nothing moved' and exits 0 with the "
            "regression still live. A gate compares against a FIXED, reviewed "
            "artifact.\n"
            "  Record one:  veridor map --config ... --openapi ... --matrix "
            f"{DRIFT_BASELINE}\n"
            f"  Commit it, then gate against the FILE:  --baseline "
            f"{DRIFT_BASELINE} --fail-on-drift {args.fail_on_drift}\n"
            "  Accept a change by copying this run's matrix over that file in "
            "the pull request that caused it.\n"
            "  The directory form stays available for discovery: drop "
            "--fail-on-drift and it reports what moved without gating."
        )
    return drift_module.load_matrix(args.baseline)


def _map(args: argparse.Namespace) -> int:
    """Inventory -> matrix -> blast radius -> coverage -> candidates.

    Always exits 0 once a map was produced. Discovery is not a gate: a candidate
    is a hypothesis, an uncovered operation is a fact about a specification, and
    neither is grounds for failing somebody's build. ``run`` is the gate.
    """
    _validate_map_paths(args)
    # Before anything is probed: see _load_drift_baseline for why the order is
    # load-bearing rather than tidy.
    baseline = _load_drift_baseline(args)
    # require_checks=False: `map` grades no expectation, so a config with no
    # `checks` at all is a legitimate one here. It is the config a team has
    # before they have written a policy, which is the config most teams have.
    config = load_config(args.config, args.base_url, require_checks=False)
    inventory = parse_spec(load_spec(args.openapi), source=str(args.openapi))
    # Every safety gate -- off-target paths, permitted methods, the two mutating
    # acknowledgements, the target acknowledgement and the request budget -- is
    # re-derived inside plan_matrix and raises here, before a socket is opened.
    # `--dry-run` sends nothing, so a budget it would exceed is information
    # rather than a refusal: the plan it prints is exactly what an operator
    # needs to narrow it, and refusing to print it withheld the fix.
    plan = plan_matrix(
        config, inventory, options=_map_options(args), defer_budget=args.dry_run
    )
    print(plan.banner())
    print()
    if args.dry_run:
        try:
            plan.refuse_if_over_budget()
        except MatrixError as error:
            print(f"Over budget, and nothing was sent:\n  {error}")
            print()
        # The plan already knows which templates have no specimen, so the fix
        # is available before a single request. Printing it only after the run
        # meant the command the documentation tells you to try FIRST was the
        # one command that could not tell you half your API would be skipped.
        advice = _specimen_advice(
            {"cells": [
                # `operation` already reads "GET /path/{id}"; prefixing the
                # method again produced "GET GET /path/{id}", which survived
                # the split and emitted a specimens key `matrix` refuses.
                {"operation": item.operation,
                 "unknown_reason": item.unknown_reason}
                for item in plan.skipped
            ]}
        )
        if advice:
            print(advice)
            print()
        print("--dry-run: nothing was sent.")
        return 0

    _preflight_writable("map", _map_destinations(args, baseline is not None))
    announce_proxy(config["target"]["base_url"])
    if args.wait_for_target:
        # Stderr only: a matrix document is compared cell by cell against a
        # baseline, and how long the target took to open a port is not a cell.
        wait_for_target(config["target"]["base_url"], args.wait_for_target)
    matrix = execute_matrix(
        plan, prober=default_prober(config, timeout_seconds=plan.timeout_seconds)
    )
    grouping = peer_groups(config, matrix)
    credentialed = credential_bearing_identities(config, matrix.identities)
    suppressions: dict[str, int] = {}
    candidates = find_candidates(matrix, grouping, suppressions=suppressions)
    documents: dict[str, dict[str, Any]] = {
        "matrix": matrix_document(matrix),
        "blast-radius": blast_radius_report(matrix, credentialed),
        "candidates": candidates_document(
            matrix, candidates, grouping=grouping, suppressions=suppressions
        ),
    }
    map_id = _map_id()
    written = _write_map_artifacts(args, documents, candidates, map_id)

    print(render_blast_radius(documents["blast-radius"]))
    for advice in (
        _specimen_advice(documents["matrix"]),
        _specimen_reachability_advice(documents["matrix"]),
        _baseline_quality_advice(documents["matrix"]),
    ):
        if advice:
            print()
            print(advice)
    # Coverage is measured against the same specification the matrix was built
    # from, and its failure is a documentation problem. It prints, loudly, and
    # it does not decide this command's exit code -- see the docstring.
    _emit_coverage(args, require_checks=False)
    print()
    print(render_candidates(documents["candidates"]), end="")
    print()
    for label, path in written:
        print(f"Wrote {label} to {path}")

    from veridor import drift as drift_module  # noqa: PLC0415

    drift_code = _emit_drift(args, documents["matrix"], baseline, map_id)
    # A real difference outranks a coverage problem, exactly as a finding
    # outranks one in `run`. Kept in two variables rather than folded into one,
    # because the sentence below has to name the one that actually decided: a
    # run with no --baseline at all -- step 3 of the drift on-ramp, the one
    # advertised as "records the baseline, finds nothing, and says so" -- exited
    # 3 against an unreachable target and explained it as "you passed
    # --fail-on-drift 'none' and the matrix moved". No comparison had happened,
    # and 'none' cannot gate anything.
    coverage_code = 0 if drift_code else _map_coverage_exit_code(
        args, documents["matrix"]
    )
    exit_code = drift_code or coverage_code

    print()
    print(_MAP_NEXT)
    if exit_code == 0:
        print("  Nothing above changed this exit code.")
    elif drift_code == drift_module.EXIT_NOTHING_COMPARED:
        print(
            f"  Exit {drift_code}: you passed --fail-on-drift "
            f"{quoted(args.fail_on_drift)}, and the comparison with the baseline "
            "compared nothing -- no cell was measured in both runs, so the "
            "policy could not have fired. The reason is on stderr, above. That "
            "is not a pass."
        )
    elif drift_code:
        print(
            f"  Exit {drift_code}: you passed --fail-on-drift "
            f"{quoted(args.fail_on_drift)} and the matrix moved. Discovery did not "
            "decide this; your drift policy did."
        )
    else:
        print(
            f"  Exit {coverage_code}: this matrix is not what it was asked to "
            "record -- the reason is on stderr, above. Nothing discovery found "
            "decided this; what the run could not measure did."
        )
    # Still 0 for everything discovery found. The only way this command fails a
    # build is if the operator asked drift to gate it, or asked for a matrix
    # this run could not deliver. Both are opt-in; a candidate never is.
    return exit_code


#: Cells nobody could measure for a TRANSIENT reason. `skipped_mutating` and
#: `skipped_no_specimen` are deliberate and are not in here: they are choices,
#: and they recur identically on every run, so they compare cleanly.
_TRANSIENT_UNKNOWN = ("rate_limited", "server_error", "transport_error", "proxy_auth_required")

#: How many specimen stanzas to print before summarising the rest.
_SPECIMEN_ADVICE_LIMIT = 5


def _specimen_reachability_advice(matrix_document: dict[str, Any]) -> str:
    """Say it when a specimen names an object nobody was served.

    A well-formed but wrong id -- `inv-42` where the real invoice is `inv-100`,
    not the literal placeholder `plan_matrix` already refuses -- 404s. A 404 is
    classified `refused`. A grid of refusals reads exactly like a boundary that
    holds. Measured on the demo fixture: exit 0, the same `0 candidates.`, and a
    report byte-identical to the correct run except for reach counts nobody
    draws a conclusion from. The marker owner had been refused its own data and
    nothing anywhere said so.

    The unit is the SPECIMEN VALUE, not the row, and the test is 0-of-N rather
    than a share. A wrong id is served to NOBODY on ANY of its rows; a correct
    id on an admin-scoped resource is served to the admin, and a correct id on
    a route that does not implement the method is served on its other row. That
    makes this decisive rather than statistical, which is what earns it the
    right to be printed at all -- an owner-refusal-share rule was drafted first
    and measured 25% precision on this repo's own benign fixtures.
    """
    rows = [row for row in matrix_document.get("rows", []) if row.get("specimen")]
    if not rows:
        return ""
    by_row: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for cell in matrix_document.get("cells", []):
        by_row.setdefault((cell.get("operation"), cell.get("specimen")), []).append(cell)

    # Keyed by (PATH TEMPLATE, label), which is what one `matrix.specimens`
    # entry is: the same object id, reachable through every method declared on
    # that path. Neither obvious alternative works. By bare label: `matrix.py`
    # enforces label uniqueness only WITHIN a template and `init --for drift`
    # writes "specimen" for every route, so on a scaffold one reachable
    # specimen masked every dead one sharing the name -- the collision is the
    # DEFAULT state. By full operation: a `DELETE` that 405s on an id the `GET`
    # serves becomes its own dead unit, and the warning fires on most CRUD
    # specs, about a correct configuration.
    per: dict[tuple[Any, Any], dict[str, int]] = {}
    for row in rows:
        template = str(row["operation"]).split(" ", 1)[-1]
        key = (template, row["specimen"])
        for cell in by_row.get((row["operation"], row["specimen"]), []):
            seen = per.setdefault(key, {"measured": 0, "reached": 0, "cells": 0})
            seen["cells"] += 1
            if cell.get("reach") not in ("reached", "refused"):
                continue
            seen["measured"] += 1
            if cell["reach"] == "reached":
                seen["reached"] += 1
    dead = sorted(
        key
        for key, seen in per.items()
        # Fully measured, or the claim below is about cells nobody looked at.
        if seen["measured"] and seen["measured"] == seen["cells"] and not seen["reached"]
    )
    if not dead:
        return ""
    shown = dead[:_SPECIMEN_ADVICE_LIMIT]
    listed = "\n".join(
        f"    {label} on {template}: refused by all "
        f"{per[(template, label)]['measured']} cell(s) probed for it"
        for template, label in shown
    )
    if len(dead) > len(shown):
        listed += f"\n    ... and {len(dead) - len(shown)} more"
    return (
        f"  !! {len(dead)} SPECIMEN(S) WERE SERVED TO NOBODY:\n"
        f"{listed}\n"
        "     Every identity that was measured on it was refused. A well-formed "
        "id that does\n     not exist 404s, a 404 is recorded as `refused`, and a "
        "grid of refusals is\n     indistinguishable from a boundary that holds. "
        "Check that each value in\n     matrix.specimens is a real id in the "
        "environment this run pointed at, and\n     that it belongs to the "
        "identity the declaration says it does. Nothing here\n     is a finding "
        "and nothing here changed the exit code."
    )


def _baseline_quality_advice(matrix_document: dict[str, Any]) -> str:
    """Warn when the matrix just recorded would make a poor baseline.

    The drift scaffold's third step is "record the baseline", and a baseline is
    read for weeks. A cell this run could not measure becomes a cell drift can
    never report as more access -- every later comparison there is `unknown ->
    something`, which is not significant by construction. Measured against a
    noisy target, a baseline recorded through one bad minute missed a real
    boundary opening on 8 runs out of 8 while reporting nothing significant.

    That failure is invisible at the point it is created and silent forever
    after, so it is called out here, at the moment the file is written.
    """
    reasons: dict[str, int] = {}
    for cell in matrix_document.get("cells", []):
        reason = cell.get("unknown_reason")
        if reason in _TRANSIENT_UNKNOWN:
            reasons[reason] = reasons.get(reason, 0) + 1
    if not reasons:
        return ""
    total = sum(reasons.values())
    detail = ", ".join(f"{reason} x{count}" for reason, count in sorted(reasons.items()))
    return (
        f"  !! {total} cell(s) could not be measured this run ({detail}).\n"
        "  Fine for a one-off look. NOT fine as a baseline: drift can never "
        "report more access\n  on a cell the baseline never measured, so a "
        "regression there would go unreported.\n"
        "  Re-run before you commit this as a baseline."
    )


def _specimen_advice(matrix_document: dict[str, Any]) -> str:
    """Turn `skipped_no_specimen` into the JSON that fixes it.

    Without this the report names the gap in its own vocabulary and stops. The
    reader already knows a real invoice id; what they do not know is that
    `matrix.specimens` exists, or where it goes -- and the routes it silently
    drops are the templated ones, which is exactly the shape (one tenant's
    object fetched by another) this tool exists to measure. A map that skipped
    them and said nothing actionable is a map that looks complete and is not.
    """
    templates = sorted({
        str(cell.get("operation", "")).split(" ", 1)[-1]
        for cell in matrix_document.get("cells", [])
        if cell.get("unknown_reason") == "skipped_no_specimen"
    })
    if not templates:
        return ""

    # A 120-path specification skips 60 templated routes, and 60 pasted JSON
    # objects is a wall nobody reads. Show enough to copy the shape, then say
    # exactly how many were not shown -- silent truncation would read as "that
    # is all of them", which is the one thing it must not say.
    shown = templates[:_SPECIMEN_ADVICE_LIMIT]
    specimens = {
        template: [{
            "label": "specimen",
            "values": {
                token.strip("{}"): SPECIMEN_PLACEHOLDER
                for token in sorted(set(_TEMPLATE_TOKEN.findall(template)))
            },
        }]
        for template in shown
    }
    body = json.dumps({"matrix": {"specimens": specimens}}, indent=2)
    lines = [
        f"  {len(templates)} operation(s) were not probed for want of a specimen.",
        "  Veridor never enumerates ids, so a templated route with no concrete",
        "  object is skipped rather than guessed at. Add this to your config,",
        f"  replacing each {SPECIMEN_PLACEHOLDER} with an id that really exists:",
        "",
    ]
    lines += [f"    {line}" for line in body.splitlines()]
    if len(templates) > len(shown):
        lines.append(
            f"  ... and {len(templates) - len(shown)} more templated route(s), "
            "same shape. Every one of them\n  is unprobed until it has a specimen."
        )
    return "\n".join(lines)


def _emit_drift(
    args: argparse.Namespace,
    current: dict[str, Any],
    baseline: dict[str, Any] | None,
    map_id: str,
) -> int:
    """Compare this matrix with the baseline loaded before the run started.

    Separated from ``_map`` so the invariant is legible: everything above
    returns 0, and this is the single place a `map` invocation can decide
    otherwise -- only when ``--fail-on-drift`` was passed.

    The managed copy lands under the SAME ``map_id`` as the matrix it came
    from. Drift is not a fourth artifact of its own: it is what this map means
    when read against an earlier one, and a report whose matrix cannot be found
    is a diff nobody can check.
    """
    from veridor import drift as drift_module  # noqa: PLC0415

    if baseline is None:
        return 0

    report = drift_module.compare(baseline, current)
    print()
    print(drift_module.render(report))
    managed = args.output_dir / "drift" / f"{map_id}.json"
    write_json(managed, report)
    print(f"\nWrote drift report to {managed}")
    if args.drift_path is not None:
        write_json(args.drift_path, report)
        print(f"Wrote drift report to {args.drift_path}")
    policy_code = drift_module.exit_code(report, args.fail_on_drift)
    served = report.get("redirect_now_served_cells") or 0
    if served and args.fail_on_drift != "any":
        # Said on stderr too, beside the gate that does not count them: a CI
        # log is read for its warnings, and "0 that mean more access" above an
        # exit 0 is what a login redirect that became a 200 printed before.
        print(f"veridor: {drift_module.redirect_served_message(served)}",
              file=sys.stderr)
    if policy_code != drift_module.EXIT_NOTHING_COMPARED:
        return policy_code
    # A comparison that measured nothing is not a pass, and the policy alone
    # cannot say so: `opened` and `any` both gate on CHANGES between two
    # measurements, and there were none to compare. `drift.exit_code` returns 3
    # for it -- the code `map` uses when its own grid measured nothing and `run`
    # uses when no probe was answered. Only under a gate; a discovery run
    # (`--fail-on-drift none`) still reports and exits 0. This names which of
    # the two ways it happened, because the fixes are different.
    if not report["comparable_cells"]:
        print(
            f"veridor: not one of {report['incomparable_cells']} cell(s) appears in "
            "both runs, so this drift report compared nothing. It is not a pass. "
            "Check that both runs used the same specimens, identities and "
            "specification.",
            file=sys.stderr,
        )
    else:
        base, now = report["baseline"], report["current"]
        redirected = report.get("redirect_cells") or 0
        redirect_note = (
            f" {redirected} of them were answered with a redirect in at least one "
            "run, and Veridor does not follow redirects, so nothing behind them "
            "was observed."
            if redirected else ""
        )
        print(
            f"veridor: not one of the {report['comparable_cells']} cell(s) in both "
            "runs was measured in both, so this drift report compared nothing and "
            f"--fail-on-drift {args.fail_on_drift} could not have failed. It is not "
            f"a pass.{redirect_note} The baseline measured {base['measured_cells']} "
            f"of its {base['cells']} cell(s); this run measured "
            f"{now['measured_cells']} of {now['cells']}. A baseline recorded while "
            "the target was down, unreachable, or redirecting every request (a "
            "login wall, an SSO proxy, a maintenance page) records nothing: "
            "re-record it against a healthy target with `map --matrix FILE`, "
            "review it, and commit that file.",
            file=sys.stderr,
        )
    return policy_code


# ---------------------------------------------------------------------------
# mutate -- would my suite actually catch a regression?
# ---------------------------------------------------------------------------

#: Seconds between EVERY request ``mutate`` issues, unless told otherwise: 2
#: req/s, the same number ``map`` defaults to and for the same reason.
#:
#: ``mutate`` re-issues every request the operator declared and then adds its
#: own probes, and it shipped with no limit at all: a 60-check ``DELETE`` suite
#: put 120 requests on the wire in 0.031 s, which is 3,900 req/s at somebody's
#: API. ``run`` is the gate and is not throttled; ``mutate`` is the analysis
#: verb you run before merge, which is what ``map``'s posture is for.
#: ``--min-interval 0`` turns it off against a fixture you own.
MUTATE_DEFAULT_MIN_INTERVAL: float = 0.5

#: The default cap on the ADDITIONAL probes only, matching ``map``'s 500-request
#: default. The baseline probes are what ``veridor run`` issues anyway; their
#: volume is governed by ``MUTATE_DEFAULT_MAX_REQUESTS`` instead.
MUTATE_DEFAULT_REQUEST_BUDGET: int = 500

#: The ceiling on the planned requests, baseline included (at tier 2, not
#: session logins or ``sequences`` steps). ``--min-interval`` bounds
#: how fast the target is hit and this bounds how much: a 5,000-check
#: configuration put 10,500 requests on the wire, disclosed but not refused,
#: which at the default rate is about 85 minutes against somebody's API.
#: ``map`` refuses an oversized plan before the first socket; disclosure alone
#: is not a control when the only way to act on it is Ctrl-C.
MUTATE_DEFAULT_MAX_REQUESTS: int = 5_000

_HOOK_KEYS: frozenset[str] = frozenset(
    {"name", "removes", "apply_command", "restore_command", "cwd", "timeout_seconds"}
)

#: Printed before the first hook runs, every time, and not suppressible. The
#: operator supplied these commands, but they may not have supplied them today.
_TIER2_DISCLOSURE: str = (
    "!! TIER 2 EXECUTES THE COMMANDS BELOW ON THIS MACHINE, as you, with your\n"
    "!! environment and your credentials. Veridor did not write them and cannot\n"
    "!! tell what they do. Each is run as an argv list with NO SHELL, so nothing\n"
    "!! in them is expanded, globbed, or interpreted -- but they still run.\n"
    "!! Each apply_command is expected to remove ONE guard from your target; each\n"
    "!! restore_command is expected to put it back, and is run on every path\n"
    "!! including failure. Neither command's output is captured; only its exit\n"
    "!! status is read.\n"
    "!! If a restore_command does not exit 0, THE TARGET MAY STILL BE MUTATED and\n"
    "!! every later hook is skipped rather than applied on top of it."
)


def _hook_argv(entry: dict[str, Any], name: str, field: str) -> list[str]:
    """An argv list of non-empty strings, or a refusal.

    Stricter than ``mutation._validate_argv``, which also accepts ``bytes`` and
    ``PathLike`` because a library caller can legitimately pass them. Nothing
    reaching here came from Python: it came out of a JSON file, where the only
    honest argv element is a string. An int, a nested list, or an empty string
    is a malformed hook, and it is refused now -- before the apply command has
    removed a guard that only the restore command can put back.
    """
    value = entry.get(field)
    if not isinstance(value, list) or not value:
        raise ConfigError(
            f"target mutation hook {quoted(name)}: {field} must be a non-empty list of "
            'strings, e.g. ["./scripts/mutate.sh", "--guard", "tenant-filter"]. '
            "It is executed as an argv list with no shell, so a single string is "
            "not a command line and is refused."
        )
    for index, element in enumerate(value):
        if not isinstance(element, str) or not element:
            raise ConfigError(
                f"target mutation hook {quoted(name)}: {field}[{index}] is "
                f"{type(element).__name__ if not isinstance(element, str) else 'empty'}"
                "; every argument must be a non-empty string. Tier 2 removes a "
                "guard from your target and the restore command is the only way "
                "back, so a command that cannot be executed is refused before "
                "anything runs."
            )
    return list(value)


def _load_hooks(path: Path) -> list[Any]:
    """Parse and validate the hook file whole, before anything is executed."""
    from veridor import mutation  # noqa: PLC0415 -- see the module docstring

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"hooks file not found: {path}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc

    entries = document.get("hooks") if isinstance(document, dict) else document
    if not isinstance(entries, list) or not entries:
        raise ConfigError(
            f"{path} must contain a non-empty list of hooks, either as the "
            'document itself or under a "hooks" key'
        )
    hooks = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"{path}: hook {position} must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{path}: hook {position} must declare a name")
        unknown = sorted(set(entry) - _HOOK_KEYS)
        if unknown:
            raise ConfigError(
                f"target mutation hook {quoted(name)} has unsupported keys: "
                f"{terminal_names(unknown)} (supported: {', '.join(sorted(_HOOK_KEYS))})"
            )
        removes = entry.get("removes")
        if not isinstance(removes, str) or not removes.strip():
            raise ConfigError(
                f"target mutation hook {quoted(name)} must say which guard it removes, "
                "in your own words; the survivor diagnosis is written from it"
            )
        cwd = entry.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ConfigError(
                f"target mutation hook {quoted(name)} declares a cwd that is not a path"
            )
        timeout = entry.get("timeout_seconds", 300.0)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ConfigError(
                f"target mutation hook {quoted(name)} declares a non-numeric timeout"
            )
        hooks.append(
            mutation.TargetMutationHook(
                name=name,
                removes=removes,
                apply_command=_hook_argv(entry, name, "apply_command"),
                restore_command=_hook_argv(entry, name, "restore_command"),
                cwd=cwd,
                timeout_seconds=float(timeout),
            )
        )
    # Re-validated by the engine, from the objects rather than from the JSON, so
    # neither layer is anyone's only line of defence.
    mutation._validate_hooks(hooks)
    return hooks


#: The names `mutate` writes its report under, in ``<output-dir>/mutation``
#: (``mutation.write_reports``: ``<stem>.json``, ``.txt``, ``-badge.json``).
_MUTATE_STEM = "mutation"
_MUTATE_STEM_TIER2 = "mutation-tier2"


def _validate_mutate_args(args: argparse.Namespace) -> None:
    if args.tier == 2:
        if args.hooks is None:
            raise ConfigError(
                "--tier 2 requires --hooks FILE. Veridor does not generate target "
                "mutations: it does not parse your source and does not know your "
                "language. You supply the command that removes a guard and the "
                "command that puts it back."
            )
        if not args.tier2_acknowledged:
            raise ConfigError(
                f"--tier 2 requires {_TIER2_ACK_FLAG}. Tier 2 executes the "
                "apply_command and restore_command from your hooks file on this "
                "machine, as you, and leaves your target altered in between. "
                "Nothing has been run."
            )
        # Both default to None so "the operator passed this" stays
        # distinguishable from "the operator accepted the default" -- the
        # defaults are applied in _mutate, not by argparse, precisely so this
        # refusal keeps working now that there are defaults at all.
        for label, value in (
            ("--request-budget", args.request_budget),
            ("--min-interval", args.min_interval),
        ):
            if value is not None:
                raise ConfigError(f"{label} applies to tier 1 only")
    else:
        if args.hooks is not None:
            raise ConfigError("--hooks requires --tier 2")
        if args.tier2_acknowledged:
            raise ConfigError(f"{_TIER2_ACK_FLAG} requires --tier 2")
    destinations = [
        (label, _resolved(path))
        for label, path in (
            ("--json", args.json_path),
            ("--text", args.text_path),
            ("--badge", args.badge),
        )
        if path is not None
    ]
    protected = {_resolved(args.config)}
    if args.hooks is not None:
        protected.add(_resolved(args.hooks))
    output_dir = _resolved(args.output_dir)
    reports = output_dir / "mutation"
    stem = _MUTATE_STEM_TIER2 if args.tier == 2 else _MUTATE_STEM
    _validate_destinations(
        destinations, protected, output_dir,
        [reports / f"{stem}.json", reports / f"{stem}.txt", reports / f"{stem}-badge.json"],
    )


def _tier2_evidence_note(evidence: Path, unmutated: dict[str, Any]) -> str:
    """The closing line about tier-2 run documents, from what actually ran.

    The run under ``unmutated/`` was described as being there "to show the
    suite passes without a mutation" even when that run was red and was the
    reason every hook was ruled not applicable. When it was not green, no hook
    was applied, so there are no mutated-build documents to qualify either.
    """
    from veridor import mutation  # noqa: PLC0415 -- see the module docstring

    outcome = unmutated.get("outcome")
    if outcome == mutation.UNMUTATED_PASSED:
        return (
            f"Wrote tier-2 suite evidence to {evidence}. Those are run documents "
            "against a deliberately mutated build:\n"
            "  the findings in them are the measurement, not results about your "
            "real target. Do not publish them.\n"
            "  The one under unmutated/ ran against the target as it is, before "
            "any hook, and the suite passed there."
        )
    if outcome == mutation.NOT_APPLICABLE:
        why = (
            "The suite already reported findings there, so no hook was applied "
            "and nothing in this directory ran against a mutated build."
        )
    else:
        why = (
            "The suite could not run or could not grade every result there, so "
            "no hook was applied and nothing in this directory ran against a "
            "mutated build."
        )
    return (
        f"Wrote tier-2 suite evidence to {evidence}. Do not publish it.\n"
        "  The run documents under unmutated/ are from the suite run against "
        f"the target as it is, before any hook. {why}"
    )


def _tier2_banner(hooks: Sequence[Any], path: Path) -> str:
    lines = [
        f"Veridor target mutation (tier 2) -- {len(hooks)} hook(s) from {path}.",
        "",
        _TIER2_DISCLOSURE,
        "",
    ]
    for hook in hooks:
        lines.append(f"  {hook.name}: removes {hook.removes}")
        lines.append(f"    apply:   {list(hook.apply_command)}")
        lines.append(f"    restore: {list(hook.restore_command)}")
        lines.append(
            f"    cwd: {hook.cwd or '(this directory)'}    "
            f"timeout: {hook.timeout_seconds:g}s"
        )
    return "\n".join(lines)


def _mutate(args: argparse.Namespace) -> int:
    """Mutate the declaration, never the findings. Its own exit code, always.

    The report is written under ``<output-dir>/mutation`` and deliberately never
    reaches ``latest.json``, the SARIF writer, or a run's exit code: a killed
    mutant in a code-scanning UI is exactly the false alarm this module exists
    to prevent.
    """
    from veridor import mutation  # noqa: PLC0415 -- see the module docstring

    _validate_mutate_args(args)
    output_dir = args.output_dir / "mutation"
    evidence: Path | None = None
    # Loaded here as well as inside the engine, and with --read-only applied, so
    # a configuration this operator will not let write is refused before the
    # pre-flight banner claims it is about to. The engine re-derives both from
    # the file, so neither layer is anyone's only line of defence.
    config = load_config(
        args.config, args.base_url, read_only=args.read_only,
        # `run` is about to send these paths verbatim.
        require_concrete_paths=True,
    )
    max_requests = (
        MUTATE_DEFAULT_MAX_REQUESTS if args.max_requests is None else args.max_requests
    )
    # Before a hook runs or a request is sent: tier 2 alters the target, and a
    # report that cannot be written afterwards leaves an operator with a
    # mutated-and-restored target and nothing to show for it.
    _preflight_writable(
        "mutate",
        [
            ("--output-dir", output_dir, True),
            *(
                [("--output-dir", output_dir / "tier2-runs", True)]
                if args.tier == 2
                else []
            ),
            *(
                (flag, path, False)
                for flag, path in (
                    ("--json", args.json_path),
                    ("--text", args.text_path),
                    ("--badge", args.badge),
                )
                if path is not None
            ),
        ],
    )
    if args.tier == 2:
        # Parsed and validated whole BEFORE the banner, so a malformed file is
        # refused without printing a disclosure about commands that will not run.
        hooks = _load_hooks(args.hooks)
        # Tier 2 runs the suite through `run`'s own machinery, so it inherits
        # that verb's posture: no request budget and no throttle, and the
        # write disclosure below is the whole of what it adds. The volume
        # ceiling is the exception, and it is charged per hook because the
        # baseline goes on the wire once for every one of them -- plus once
        # more for the run against the unmutated target that comes first.
        # Each run is a full execute_run, liveness controls included.
        suite_runs = len(hooks) + 1
        mutation.refuse_if_over_total(
            config,
            max_requests=max_requests,
            request_budget=None,
            min_interval_seconds=0.0,
            suite_runs=suite_runs,
            prove_liveness=True,
        )
        print(
            mutation.preflight_banner(
                config,
                min_interval_seconds=0.0,
                request_budget=None,
                read_only=args.read_only,
                suite_runs=suite_runs,
                prove_liveness=True,
            )
        )
        print()
        print(_tier2_banner(hooks, args.hooks))
        print()
        evidence = output_dir / "tier2-runs"
        report = mutation.run_target_mutations(
            args.config,
            hooks,
            output_dir=evidence,
            base_url=args.base_url,
            read_only=args.read_only,
        )
        stem = _MUTATE_STEM_TIER2
    else:
        min_interval = (
            MUTATE_DEFAULT_MIN_INTERVAL
            if args.min_interval is None
            else args.min_interval
        )
        request_budget = (
            MUTATE_DEFAULT_REQUEST_BUDGET
            if args.request_budget is None
            else args.request_budget
        )
        # Before the banner: a plan that will not run does not get narrated as
        # though it is about to.
        mutation.refuse_if_over_total(
            config,
            max_requests=max_requests,
            request_budget=request_budget,
            min_interval_seconds=min_interval,
        )
        print(
            mutation.preflight_banner(
                config,
                min_interval_seconds=min_interval,
                request_budget=request_budget,
                read_only=args.read_only,
            )
        )
        print()
        # Tier 2 goes through execute_run, which says this itself.
        announce_proxy(config["target"]["base_url"])
        report = mutation.analyze(
            args.config,
            base_url=args.base_url,
            request_budget=request_budget,
            min_interval_seconds=min_interval,
            read_only=args.read_only,
        )
        stem = _MUTATE_STEM

    rendered = mutation.render_text(report)
    paths = mutation.write_reports(report, output_dir, stem=stem)
    if args.json_path is not None:
        write_json(args.json_path, report)
    if args.text_path is not None:
        args.text_path.parent.mkdir(parents=True, exist_ok=True)
        args.text_path.write_text(
            redaction.scrub_text(rendered), encoding="utf-8", errors="strict"
        )
    if args.badge is not None:
        write_json(args.badge, mutation.render_badge(report))

    print(rendered, end="")
    print()
    for label in ("text", "json", "badge"):
        print(f"Wrote mutation {label} to {paths[label]}")
    if evidence is not None:
        # Said out loud because those documents are shaped exactly like a real
        # run and are full of findings BY DESIGN -- they were produced against a
        # build with a guard deliberately removed. Nothing here converts them to
        # SARIF or merges them into run history, and neither should anything
        # else: a reader who points a code-scanning UI at that directory would be
        # reading the mutation working as intended as a report about the target.
        print(_tier2_evidence_note(evidence, report.get("unmutated_run") or {}))
    code = mutation.exit_code(report)
    if code:
        return code
    limited = (report.get("summary") or {}).get("limited") or 0
    if limited and getattr(args, "require_evaluable", False):
        print(
            f"veridor: {limited} mutant(s) could not be evaluated against this "
            "target, so the score speaks for "
            f"{(report['summary'] or {}).get('generated', 0)} of "
            f"{(report['summary'] or {}).get('evaluable', 0)} generated. A "
            "caveat that cannot move a number cannot gate a build, which is "
            "what this flag is for.",
            file=sys.stderr,
        )
        return 3
    return 0


def _slug(value: str) -> str:
    return _NON_SLUG.sub("-", _CAMEL_BOUNDARY.sub("-", value).lower()).strip("-")


def _check_id(method: str, path_template: str, operation_id: str | None) -> str:
    candidate = _slug(operation_id or "")
    if not candidate:
        candidate = _slug(f"{method} {path_template}")
    return candidate or "check"


def _spec_base_url(document: dict[str, Any]) -> str | None:
    version = str(document.get("openapi") or document.get("swagger") or "")
    if version.startswith("2"):
        host = document.get("host")
        if not isinstance(host, str) or not host:
            return None
        schemes = document.get("schemes")
        scheme = "https"
        if isinstance(schemes, list):
            scheme = next(
                (item for item in schemes if item in {"https", "http"}), "https"
            )
        base_path = document.get("basePath")
        suffix = base_path if isinstance(base_path, str) else ""
        return f"{scheme}://{host}{suffix}"
    servers = document.get("servers")
    if not isinstance(servers, list):
        return None
    for entry in servers:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        url = entry["url"]
        variables = entry.get("variables")
        for name in _SERVER_VARIABLE.findall(url):
            default = None
            if isinstance(variables, dict) and isinstance(variables.get(name), dict):
                default = variables[name].get("default")
            if isinstance(default, str):
                url = url.replace("{" + name + "}", default)
        if "{" in url:
            # An unresolved template would be written into target.base_url and
            # fail at request time; the placeholder is the honest answer.
            continue
        return url
    return None


def _init_target(
    document: dict[str, Any], base_paths: Sequence[str], override: str | None
) -> tuple[str, str, str]:
    """Return ``(base_url, path_prefix, source)`` for the generated config."""
    if override:
        candidate = override.rstrip("/") or override
        _validate_http_url(candidate, "--base-url")
        return candidate, "", "flag"
    url = _spec_base_url(document)
    if isinstance(url, str):
        candidate = url.rstrip("/") or url
        try:
            _validate_http_url(candidate, "spec server url")
        except ConfigError:
            candidate = None
        if candidate:
            return candidate, "", "spec"
    # A relative or templated server url still tells us the prefix, even though
    # it cannot be a base URL.
    prefix = next((value for value in base_paths if value), "")
    return _PLACEHOLDER_BASE_URL, prefix, "placeholder"


def _starter_config(
    inventory: Any,
    spec_path: Path,
    base_url: str,
    prefix: str,
    source: str,
) -> tuple[dict[str, Any], int]:
    checks: list[dict[str, Any]] = []
    used: dict[str, int] = {}
    placeholders = 0
    for operation in inventory.operations:
        base_id = _check_id(
            operation.method, operation.path_template, operation.operation_id
        )
        used[base_id] = used.get(base_id, 0) + 1
        check_id = base_id if used[base_id] == 1 else f"{base_id}-{used[base_id]}"
        path = operation.absolute_path(prefix)
        tokens = sorted(set(_TEMPLATE_TOKEN.findall(path)))
        notes: list[str] = []
        if tokens:
            placeholders += 1
            notes.append(
                f"Replace {', '.join(tokens)} with a concrete resource owned by "
                f"'{_OWNER_IDENTITY}'; Veridor sends this path verbatim."
            )
        notes.append(
            f"State what this operation promises: '{_OWNER_IDENTITY}' allowed, "
            f"'{_CHALLENGER_IDENTITY}' denied. Delete the check if this operation "
            "has no per-identity authorization boundary."
        )
        if operation.deprecated:
            notes.append("The specification marks this operation deprecated.")
        checks.append(
            {
                "id": check_id,
                "name": f"{operation.method} {path}",
                "_comment": " ".join(notes),
                "request": {"method": operation.method, "path": path},
                "expect": {
                    _OWNER_IDENTITY: {
                        "status": list(
                            _OWNER_STATUSES.get(operation.method, [200])
                        )
                    },
                    _CHALLENGER_IDENTITY: {"status": list(_DENIAL_STATUSES)},
                },
            }
        )

    target_note = (
        "target.base_url was copied from the specification's server url; confirm "
        "it names a test environment before running."
        if source == "spec"
        else "Replace target.base_url with your test environment."
    )
    config = {
        "version": 1,
        "_generated_by": f"veridor init --openapi {spec_path}",
        "_comment": [
            "Every in-scope operation in the specification became one check. "
            "Delete the checks whose operations have no authorization boundary.",
            "The expectations below are placeholders, not observations. Veridor "
            "never infers policy: what this file declares is the policy.",
            target_note,
            "Tokens are read from the environment at load time. Export "
            "VERIDOR_OWNER_TOKEN and VERIDOR_OTHER_TENANT_TOKEN; a missing "
            "variable fails the run before any request is sent.",
            "Markers upgrade a finding from 'suspected' to 'confirmed'. Store the "
            f"'{_OWNER_IDENTITY}' marker below in data this API returns, then add "
            f'"contains_marker": "{_OWNER_IDENTITY}" to the {_OWNER_IDENTITY} '
            f'expectation and "excludes_marker": "{_OWNER_IDENTITY}" to the '
            f"{_CHALLENGER_IDENTITY} expectation of the same check.",
            "To assert the authentication boundary as well, add an identity with "
            "no headers and expect [401]. A 401 for an anonymous caller is an "
            "authentication assertion and never counts as boundary coverage.",
        ],
        "target": {"base_url": base_url, "timeout_seconds": 10},
        "identities": {
            _OWNER_IDENTITY: {
                "headers": {"Authorization": "Bearer ${VERIDOR_OWNER_TOKEN}"},
                "marker": generate_marker(),
            },
            _CHALLENGER_IDENTITY: {
                "headers": {"Authorization": "Bearer ${VERIDOR_OTHER_TENANT_TOKEN}"}
            },
        },
        "checks": checks,
    }
    return config, placeholders


def _drift_config(
    inventory: Any,
    spec_path: Path,
    base_url: str,
    prefix: str,
    source: str,
) -> tuple[dict[str, Any], list[str]]:
    """Scaffold the path that declares nothing.

    No ``checks``: ``map`` grades no expectation, and asking for a policy
    before Veridor will look at an API is the wall this path exists to remove.
    What it DOES need is one real object id per templated route, which is the
    single thing nothing can derive -- so every template gets an entry, filled
    with a placeholder the matrix refuses to send.

    Returns the config and the templated paths a human still has to fill in.
    """
    specimens: dict[str, Any] = {}
    for operation in inventory.operations:
        path = operation.absolute_path(prefix)
        tokens = sorted(set(_TEMPLATE_TOKEN.findall(path)))
        if not tokens or path in specimens:
            continue
        specimens[path] = [
            {
                "label": "specimen",
                "values": {
                    token.strip("{}"): SPECIMEN_PLACEHOLDER for token in tokens
                },
            }
        ]

    target_note = (
        "target.base_url was copied from the specification's server url; confirm "
        "it names a test environment before running."
        if source == "spec"
        else "Replace target.base_url with your test environment."
    )
    config = {
        "version": 1,
        "_generated_by": f"veridor init --for drift --openapi {spec_path}",
        "_comment": [
            "This file declares NO expectations, on purpose. `map` records what "
            "each identity can reach today; a later run with --baseline reports "
            "what moved. Nobody writes a policy: you review a diff.",
            target_note,
            "Tokens are read from the environment at load time. Export "
            "VERIDOR_OWNER_TOKEN and VERIDOR_OTHER_TENANT_TOKEN; a missing "
            "variable fails the run before any request is sent.",
            f"Every {SPECIMEN_PLACEHOLDER} below must become an id that really "
            f"exists and belongs to '{_OWNER_IDENTITY}'. Veridor sends the path "
            "verbatim and never enumerates ids, so a route with no specimen is "
            "not probed at all.",
            f"The '{_OWNER_IDENTITY}' marker is the strongest signal available "
            "without a declaration: store it in data this API returns, and a "
            "response carrying it in another identity's hands is measured proof "
            "that data crossed. Without it drift can only see status changes.",
            "matrix.peer_groups, privilege_order and unauthenticated switch on "
            "further candidate rules. See the README's map section.",
        ],
        "target": {"base_url": base_url, "timeout_seconds": 10},
        "identities": {
            _OWNER_IDENTITY: {
                "headers": {"Authorization": "Bearer ${VERIDOR_OWNER_TOKEN}"},
                "marker": generate_marker(),
            },
            _CHALLENGER_IDENTITY: {
                "headers": {"Authorization": "Bearer ${VERIDOR_OTHER_TENANT_TOKEN}"}
            },
        },
        "matrix": {"specimens": specimens, "marker_owner": _OWNER_IDENTITY},
    }
    return config, sorted(specimens)


def _init_drift(args: argparse.Namespace, inventory: Any, base_url: str,
                prefix: str, source: str) -> int:
    config, templated = _drift_config(
        inventory, args.openapi, base_url, prefix, source
    )
    write_json(args.output, config)

    print(
        f"Wrote a drift scaffold for {inventory.path_count} paths to "
        f"{args.output}  (--for drift: no checks, nothing declared)"
    )
    print(f"  target.base_url: {base_url}  ({source})")
    if source == "spec":
        print("  Confirm that URL names a test environment before running.")
    for warning in inventory.warnings:
        print(f"  spec warning: {warning}")
    print("")
    if templated:
        print(
            f"  {len(templated)} route(s) need a real object id. Until each one "
            f"has a specimen it is\n  not probed at all, and `map` refuses to "
            f"send {SPECIMEN_PLACEHOLDER}:"
        )
        for path in templated:
            print(f"    {path}")
    else:
        print("  No templated routes: this specification needs no specimens.")
    print("")
    print("Next:")
    step = 0

    def _step(text: str) -> None:
        nonlocal step
        step += 1
        print(f"  {step}. {text}")

    _step("export VERIDOR_OWNER_TOKEN=... VERIDOR_OTHER_TENANT_TOKEN=...")
    if templated:
        _step(
            f"replace every {SPECIMEN_PLACEHOLDER} with an id that exists and "
            f"belongs to '{_OWNER_IDENTITY}'"
        )
    _step(
        f"veridor map --config {args.output} --openapi {args.openapi} "
        f"--matrix {DRIFT_BASELINE}\n"
        "     # records the baseline. Finds nothing, and says so"
    )
    _step(
        f"git add {DRIFT_BASELINE} && git commit -m 'record the authorization "
        "baseline'\n"
        "     # a gate compares against a committed FILE. A CI runner has no "
        ".veridor/ from last\n     # week, and a DIRECTORY of matrices resolves "
        "to the newest -- which after one\n     # failed build is the run that "
        "recorded the regression"
    )
    _step(
        f"veridor map --config {args.output} --openapi {args.openapi} "
        f"--baseline {DRIFT_BASELINE} --fail-on-drift opened"
    )
    print("")
    print(
        "Step 3 is not a test and cannot fail. Step 5 fails only when an "
        "identity that was\nrefused is now served, or another identity's marker "
        "turns up in a response — a fact\nabout two runs, not a verdict on your "
        "API."
    )
    print(
        "Drift is blind to anything that did not change. An endpoint open to "
        "everyone since\nbefore step 3 never moves, so it never appears. That "
        f"is what `veridor init --for run`\nand declared checks are for. "
        f'Coverage reports this scaffold as unreviewed until you delete '
        f'"{GENERATED_BY_KEY}".'
    )
    return 0


def _init(args: argparse.Namespace) -> int:
    output = args.output
    if _same_file(_resolved(output), _resolved(args.openapi)):
        raise ConfigError("--output must not overwrite the OpenAPI specification")
    if output.exists() and not args.force:
        raise ConfigError(
            f"refusing to overwrite {output}; pass --force to replace it"
        )
    document = load_spec(args.openapi)
    inventory = parse_spec(document, source=str(args.openapi))
    if not inventory.operations:
        raise SpecError(
            f"{args.openapi} declares no in-scope operations, so there is nothing "
            "to generate. Veridor writes one check per GET, POST, PUT, PATCH, or "
            "DELETE operation."
        )
    base_url, prefix, source = _init_target(
        document, inventory.base_paths, args.base_url
    )
    if args.scaffold_for == "drift":
        return _init_drift(args, inventory, base_url, prefix, source)
    config, placeholders = _starter_config(
        inventory, args.openapi, base_url, prefix, source
    )
    write_json(output, config)

    print(
        f"Wrote {len(config['checks'])} checks from "
        f"{inventory.path_count} paths to {output}  "
        "(--for run: you declare the policy, `run` gates on it)"
    )
    print(f"  target.base_url: {base_url}  ({source})")
    if source == "spec":
        print("  Confirm that URL names a test environment before running.")
    for warning in inventory.warnings:
        print(f"  spec warning: {warning}")
    mutating = sorted(
        {
            check["request"]["method"]
            for check in config["checks"]
            if check["request"]["method"] not in SAFE_METHODS
        }
    )
    if mutating:
        # Named here because this file is the one thing standing between a
        # scaffolded DELETE and someone's API, and the run below will issue it.
        print("")
        print(
            f"  This scaffold contains {', '.join(mutating)} checks. Running it "
            "writes to the target."
        )
        print(
            "  Delete those checks, or pass --read-only to refuse them before "
            "anything is sent."
        )
    print("")
    print("Next:")
    step = 0

    def _step(text: str) -> None:
        nonlocal step
        step += 1
        print(f"  {step}. {text}")

    _step("read every check: they are the tool's guesses, not your policy")
    if mutating:
        _step(
            f"decide about the {', '.join(mutating)} checks: delete them, or "
            "keep them knowing they write"
        )
    _step("export VERIDOR_OWNER_TOKEN=... VERIDOR_OTHER_TENANT_TOKEN=...")
    if placeholders:
        _step(
            f"replace the path placeholders in {placeholders} checks with "
            "real resource ids"
        )
    _step(
        f"veridor run --config {output} --openapi {args.openapi} "
        "--coverage coverage.json"
    )
    if mutating:
        print(
            "     add --read-only to that command to refuse the "
            f"{', '.join(mutating)} checks instead of\n     issuing them: it "
            "exits 2 and names the check, before anything is sent."
        )
    print("")
    print(
        "Every check is a claim you are making about your API, not a measurement. "
        "Edit before you trust."
    )
    print(
        "Expect the first run to be red: this file guesses that 'owner' is "
        "allowed everywhere,\nincluding on routes no owner is entitled to. "
        f"Coverage reports this scaffold as unreviewed until you delete "
        f'"{GENERATED_BY_KEY}".'
    )
    print(
        "\nIf writing that policy is not where you want to start, "
        "`veridor init --for drift`\nscaffolds the other path: no checks, no "
        "expectations. It records what your API does\ntoday and later runs "
        "report what moved."
    )
    return 0


def _new_marker(_: argparse.Namespace) -> int:
    print(generate_marker())
    return 0


def _report_request(value: str) -> tuple[str, Path]:
    """Parse one ``run --report FORMAT=PATH``. argparse turns a raise into exit 2."""
    fmt, separator, path = value.partition("=")
    if not separator or not fmt or not path:
        raise argparse.ArgumentTypeError(
            f"{quoted(value)} is not FORMAT=PATH; for example junit=veridor-junit.xml"
        )
    if fmt not in reports.FORMATS:
        raise argparse.ArgumentTypeError(
            f"unknown report format {quoted(fmt)}; choose one of {', '.join(reports.FORMATS)}"
        )
    if path == "-":
        raise argparse.ArgumentTypeError(
            f"{fmt}=- would interleave the report with the run summary `run` "
            "prints on stdout. Write it to a file, or render it afterwards with "
            f"`veridor report --from-run RUN.json --format {fmt} --output -`"
        )
    return fmt, Path(path)


def _report(args: argparse.Namespace) -> int:
    """Render one run (or drift) document in one format, to a file or stdout."""
    if args.sarif is not None and (
        args.report_format is not None or args.output is not None
    ):
        raise ConfigError(
            "--sarif PATH is the older spelling of --format sarif --output PATH; "
            "pass one form or the other, not both"
        )
    if (args.input is None) == (args.from_drift is None):
        raise ConfigError(
            "report needs exactly one input: --from-run RUN.json (the run JSON "
            "`veridor run --json` wrote) or --from-drift DRIFT.json"
        )
    fmt = "sarif" if args.sarif is not None else args.report_format
    if fmt is None:
        raise ConfigError(
            f"report needs --format, one of {', '.join(reports.FORMATS)}"
        )
    destination: Path | None
    if args.sarif is not None:
        destination = args.sarif
    elif args.output in (None, "-"):
        destination = None
    else:
        destination = Path(args.output)
    source = args.input if args.input is not None else args.from_drift
    label = "--sarif" if args.sarif is not None else "--output"
    if destination is not None:
        if _same_file(_resolved(source), _resolved(destination)):
            raise ConfigError(f"{label} must not overwrite the input run")
        _validate_destinations([(label, _resolved(destination))], {_resolved(source)})

    if args.from_drift is not None:
        if fmt != "markdown":
            raise ConfigError(
                f"a drift report renders to --format markdown only, not {fmt}: "
                "drift is an observation, never a finding, and SARIF, JUnit, "
                "GitLab SAST and Code Quality would all present it as one"
            )
        text = reports.render_drift(reports.load_drift(args.from_drift))
    else:
        text = reports.render(fmt, reports.load_run(args.input), root=Path.cwd())

    if destination is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return 0
    try:
        reports.write_text(destination, text)
    except OSError as error:
        raise ConfigError(
            _write_failure(f"the {reports.LABELS[fmt]} report", destination, error)
        ) from error
    print(f"Wrote {reports.LABELS[fmt]} report to {destination}")
    return 0


#: Exit codes for a command that did not finish. 70 is sysexits.h EX_SOFTWARE;
#: 130 and 143 are the shell's 128 + SIGINT and 128 + SIGTERM.
EXIT_INTERNAL_ERROR = 70
EXIT_SIGINT = 130
EXIT_SIGTERM = 143

_ISSUES_URL = "https://github.com/Veridor-authz/veridor/issues"


class Terminated(KeyboardInterrupt):
    """SIGTERM, delivered the way SIGINT is delivered.

    Python turns SIGINT into ``KeyboardInterrupt``, so every ``finally`` --
    sequence teardown above all -- runs on Ctrl-C. SIGTERM had no handler: the
    interpreter died on the spot, and a Kubernetes pod termination, a Job
    deadline or a CI runner cancelling the job left behind every fixture the
    in-flight sequence had created. Subclassing ``KeyboardInterrupt`` makes the
    two signals take literally the same path through the code; only the exit
    code tells them apart.
    """


def _on_sigterm(signum: int, frame: Any) -> None:
    # One-shot: a second SIGTERM while the first is unwinding would abort the
    # teardown the first one is waiting for. SIGKILL still ends the process.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise Terminated()


def _install_sigterm_handler() -> Any:
    """Install :func:`_on_sigterm`; return the disposition it replaced.

    Only the main thread may set a signal handler. main() called from another
    thread (a test harness, an embedding) keeps whatever disposition it had.
    """
    if threading.current_thread() is not threading.main_thread():
        return None
    return signal.signal(signal.SIGTERM, _on_sigterm)


def main(argv: Sequence[str] | None = None) -> int:
    previous = _install_sigterm_handler()
    # Every value this command expands from ${NAME} is put back as ${NAME} in
    # everything it prints, tracebacks included, as it is in everything it
    # writes (core.write_json, reports). See veridor.redaction.
    redaction.reset()
    stdout, stderr = sys.stdout, sys.stderr
    # None (no console, e.g. pythonw) stays None: print() skips a None stream.
    sys.stdout = redaction.ScrubbingStream(stdout) if stdout is not None else None
    sys.stderr = redaction.ScrubbingStream(stderr) if stderr is not None else None
    try:
        return _main(argv)
    finally:
        _note_unscrubbed_values()
        sys.stdout, sys.stderr = stdout, stderr
        redaction.reset()
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)


def _note_unscrubbed_values() -> None:
    """Say which ${NAME} values were too short to scrub, once, at the end.

    A value under redaction.MIN_SCRUB_LENGTH cannot be told apart from ordinary
    text, so it is left wherever it landed. Where that was a request path, the
    run document and the reports carry it as sent. Saying so is the difference
    between a limit and a promise that quietly does not hold.
    """
    names = redaction.short_names()
    if not names:
        return
    listed = ", ".join("${" + name + "}" for name in names)
    try:
        print(
            f"veridor: {listed} expanded to fewer than {redaction.MIN_SCRUB_LENGTH} "
            "characters, so Veridor did not replace the value with its reference "
            "in what it wrote or printed: a value that short cannot be told apart "
            "from ordinary text. Where it sits in a request path, the run "
            "document and the reports carry it as sent. Do not use a value that "
            "short for a secret.",
            file=sys.stderr,
        )
    except (OSError, ValueError):
        pass


def _main(argv: Sequence[str] | None) -> int:
    parser = _parser()
    tokens = list(sys.argv[1:] if argv is None else argv)
    if not tokens:
        # The bare binary is the first thing most people type. `--help` is the
        # best-shaped page this tool has -- it names the three verbs and the
        # journey -- so print it rather than an argparse error about a missing
        # positional. Still exit 2: no command ran.
        parser.print_help()
        return 2
    args = parser.parse_args(argv)
    try:
        if args.command == "capsule":
            return _capsule(args)
        if args.command in {"run", "verify"}:
            if args.capsule is not None:
                return _verify_capsule(args, _typed_options(parser, tokens))
            return _run(args)
        if args.command == "map":
            return _map(args)
        if args.command == "mutate":
            return _mutate(args)
        if args.command == "coverage":
            return _coverage(args)
        if args.command == "init":
            return _init(args)
        if args.command == "new-marker":
            return _new_marker(args)
        if args.command == "report":
            return _report(args)
        _refuse_unauthenticated_exposure(args)
        serve(args.output_dir, args.host, args.port)
        return 0
    # MatrixError and BlastRadiusError join the list rather than being handled
    # in _map: every one of them means "nothing was sent, and here is why",
    # which is exactly what exit 2 has always meant here.
    except (
        ConfigError,
        CoverageError,
        SpecError,
        MatrixError,
        BlastRadiusError,
        OSError,
    ) as exc:
        # Refusals quote what they refuse, and some of it comes from a file the
        # operator did not write: a capsule's schema_version or a key in the
        # location a refusal names reached the terminal with its escape
        # sequences intact. Shown here, once, for every refusal, with every line
        # bounded (refusal_text): a long quoted value wrapped into a screen of
        # its own and pushed the refusal off the top.
        print(f"veridor: {refusal_text(str(exc))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt as interrupt:
        # Reached after every `finally` below the command has run -- that is
        # where sequence teardown lives. Nothing here claims the teardown
        # succeeded: a second Ctrl-C, or SIGKILL, can still cut it short.
        name, code = (
            ("SIGTERM", EXIT_SIGTERM)
            if isinstance(interrupt, Terminated)
            else ("SIGINT", EXIT_SIGINT)
        )
        print(
            f"veridor: stopped by {name} before the command finished (exit {code}).",
            file=sys.stderr,
        )
        return code
    except Exception:  # noqa: BLE001 - the last line of defence, by design
        # Exit 1 means "the gate failed on a finding". An uncaught exception
        # used to exit 1 as well, so a crash inside Veridor was reported to the
        # pipeline as a finding about the target. 70 is EX_SOFTWARE.
        # KeyboardInterrupt and SystemExit are BaseException, not Exception,
        # so their semantics are untouched.
        traceback.print_exc(file=sys.stderr)
        print(
            f"veridor: internal error ({type(sys.exc_info()[1]).__name__}). This "
            "is a bug in Veridor, not a finding about your target, and the "
            "command did not finish. Please report it with the traceback above: "
            f"{_ISSUES_URL}",
            file=sys.stderr,
        )
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
