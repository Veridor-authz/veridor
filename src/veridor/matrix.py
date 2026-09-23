"""Access matrix planning and probing: every operation, as every identity.

WHAT THIS IS, AND THE POSTURE IT IS BUILT UNDER
===============================================

An access matrix issues ``|operations| x |identities| x |specimens|`` requests
against one target. That is categorically closer to SCANNING than to testing.
Use it only against systems you own or are explicitly authorised to test.

Every safety control in this module exists because that request shape is
dangerous, and each one is designed to fail closed:

* **Read-only by default.** Only ``GET`` and ``HEAD`` are probed. Every other
  verb in the inventory is planned as an ``unknown / skipped_mutating`` cell --
  present in the matrix, never absent, never ``refused``. The override is two
  independent gates (an explicit, wildcard-free verb set *and* an exact
  acknowledgement string), so no single stray truthy value enables it.
* **A hard request budget, checked before anything is sent.** ``plan_matrix``
  opens no socket, and ``MatrixPlan.banner()`` shows the operator the number
  first. ``execute_matrix`` re-checks the budget itself, so no future caller can
  skip the check by constructing a plan by hand.
* **Rate limited, sequential, no retries.** A minimum inter-request interval is
  enforced globally across the whole matrix -- total load on the target is what
  needs bounding. With the default ``clock`` (``time.monotonic``), which is
  the only one the CLI uses, the limiter is a GATE, not a convention: the
  interval is served in real time whatever ``sleeper`` does. An injected
  ``clock`` is a library test seam, and it is checked for two shapes only: one
  that never reaches the deadline (the sleeper does not advance it) and one
  that runs ahead of both real time and the waits asked of the sleeper (a
  counter, a clock in milliseconds). Both are served with the real
  ``time.sleep``. Any other injected clock that reaches the deadline is
  trusted, not checked: the waits it is measured against come from its own
  readings, so the seam -- a fake clock advanced by exactly the wait -- is
  accepted, and so is a clock that holds still across the sleeper calls and
  then jumps, or one that reads backwards. v1 has no concurrency and no flag to
  enable it. A failed
  request produces an ``unknown`` cell; retrying adds volume for no oracle
  value and is precisely the traffic shape that looks like an attack.
* **Bounded in wall clock, not only in count.** Every envelope knob has a hard
  ceiling: the budget, the rate, the specimen count, the per-request timeout and
  the total run duration. A slow or half-open target cannot stretch a plan past
  the time the operator was shown.
* **Abort on hostile signals.** Repeated 429s, a cumulative number of 429s,
  repeated 5xx, or a sustained bad response rate stop the run. The target asking
  us to slow down is not an invitation to grind through it -- and a throttle
  that stays under a percentage threshold is still a throttle, which is why the
  cumulative cap exists alongside the share.
* **Explicit target posture.** A public target requires the operator to type
  the hostname into an acknowledgement string. That is friction, not a security
  boundary, and it is documented as such: the point is that pointing the matrix
  at the wrong host becomes essentially impossible.

THE CORRECTNESS RULE THAT KEEPS BLAST RADIUS HONEST
====================================================

``reach`` is four-valued -- ``reached`` / ``refused`` / ``indeterminate`` /
``unknown`` -- and ``unknown`` is NEVER collapsed into ``refused``. An unprobed,
skipped, errored, or rate-limited cell is ``unknown``, and every consumer must
read that as "we do not know", never as "denied". Reading an unknown as a denial
understates blast radius, which is the dangerous direction. The matrix is dense:
every ``(operation, specimen) x identity`` cell exists, always, so a consumer can
never read a missing key as "nothing there".

INHERITED INVARIANTS (stated here so they cannot be lost)
==========================================================

* **Redirects are never followed.** This module builds no opener of its own. It
  issues every request through ``core._perform_request``, which uses
  ``core._OPENER`` with ``core._NoRedirectHandler``, so credentials are never
  forwarded cross-origin. A 3xx is recorded as ``indeterminate``: Veridor does
  not know what is on the other side, and guessing in either direction is worse
  than saying so.
* **No credential, cookie, token, header, or response body reaches any
  artifact.** A cell is built exclusively from the dict ``_perform_request``
  returns -- already audited to contain no response bytes -- plus a run-salted
  digest. Identity *names* travel; identity *headers* never leave the config
  dict, which is why ``default_prober`` closes over the config rather than
  copying headers onto a plan.
* This module never touches the ``sink`` channel and never passes one.
* Only the path component of a recorded URL is kept, and a specimen may not
  target a query parameter at all.
* **Every request stays on ``target.base_url``'s origin.** An OpenAPI document
  is untrusted input: a declared path of ``/http://elsewhere/x`` survives
  ``normalize_path`` and, once ``core._perform_request`` does
  ``urljoin(base + '/', path.lstrip('/'))``, resolves as an ABSOLUTE URL --
  sending the identity's credential to a host the operator never named, under a
  ``target_class`` and a banner computed from ``base_url`` alone. Every probe
  path is therefore joined here, up front, and the resulting origin is asserted
  against ``base_url``'s before the path can reach a prober. The check lives in
  this module because ``core``'s join is shared with the declared-run path and
  ``core`` does not know what the matrix's target is.

DEPENDENCY DIRECTION
====================

``core`` is imported lazily, inside ``default_prober``, on the request path
only -- the same way ``core.execute_run`` lazily imports ``sequence``. Nothing
at module scope imports it, so ``blastradius -> matrix`` does not drag the
request machinery (or SARIF) into a pure projection module.

One consequence is deliberate and worth stating plainly: :class:`MatrixError`
subclasses ``ValueError``, not ``core.ConfigError``, because subclassing it
would require importing ``core`` at module scope. ``core.ConfigError`` is itself
a ``ValueError``, so ``except ValueError`` catches both; a caller that wants to
distinguish them should catch ``(ConfigError, MatrixError)`` explicitly.

``Retry-After`` (was a known gap; now closed)
=============================================

A 429 carrying ``Retry-After`` is the target asking us to slow down -- RFC 9110
s10.2.3 defines it as how long to wait before a follow-up request, not as "go
away". Two things were wrong here, in sequence.

Reaching the header was the first: ``core._perform_request`` exposes response
headers only through the ``sink`` channel, this module is forbidden from using
that channel, and so the DEFAULT prober could not see it at all.

Reading it as an immediate abort was the second, and it survived the first fix.
Measured on one throttling target, 15 runs per arm with identical seeded 429
positions: with the header, 15/15 runs aborted and median grid coverage was 22%;
with the same 429s and the header stripped, 2/15 aborted and coverage was 78%. A
spec-compliant limiter was punished 3.5x for being spec-compliant. A
``Retry-After`` 429 now counts toward the SAME two rate-limit budgets as a bare
one -- three consecutive, five cumulative -- so a polite target gets the same
tolerance as a rude one and never more, and the abort reason stays
``retry_after_requested`` when the header had the last word.
``--on-retry-after stop`` restores the immediate abort for an operator who wants
it, and the matrix records which policy ran.

``core._perform_request`` now derives a headers-free ``retry_after`` boolean --
PRESENCE ONLY, never the value, so no target-controlled text can reach a matrix
artifact and no target can talk this process into sleeping -- and returns it in
``response``. ``execute_matrix`` reads it there and at the top level of the
result, which is where the :class:`Prober` protocol documents it for a custom
prober that can see headers. Both spellings mean the same thing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import secrets
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence
from urllib.parse import quote, urljoin, urlsplit

from veridor.coverage import status_class, target_base_path
from veridor.openapi import (
    ALL_METHODS,
    TEMPLATE_TOKEN,
    Operation,
    RouteInventory,
    normalize_path,
    split_segments,
)
from veridor.terminal import quoted

__all__ = [
    "ABORT_CONSECUTIVE_RATE_LIMITED",
    "ABORT_CONSECUTIVE_SERVER_ERROR",
    "ABORT_CONSECUTIVE_TRANSPORT",
    "ABORT_HOSTILE_MINIMUM",
    "ABORT_HOSTILE_SHARE",
    "ABORT_TOTAL_RATE_LIMITED",
    "AccessMatrix",
    "CLAIM",
    "Cell",
    "MATRIX_ABSOLUTE_MAX_BUDGET",
    "MATRIX_ABSOLUTE_MAX_RUN_SECONDS",
    "MATRIX_DEFAULT_BUDGET",
    "MATRIX_DEFAULT_RPS",
    "MATRIX_DEFAULT_RUN_SECONDS",
    "MATRIX_KIND",
    "MATRIX_MAX_RPS",
    "MATRIX_MAX_SPECIMENS_PER_OPERATION",
    "MATRIX_MAX_TIMEOUT_SECONDS",
    "MATRIX_MUTATING_BUDGET",
    "MATRIX_SAFE_METHODS",
    "MUTATING_ACKNOWLEDGEMENT",
    "MatrixBudgetError",
    "MatrixError",
    "MatrixOptions",
    "MatrixPlan",
    "MatrixSafetyError",
    "OPERATION_LEVEL_LIMITATION",
    "OUTCOME_OBSERVED",
    "OUTCOME_UNKNOWN",
    "PlannedProbe",
    "Prober",
    "REACH_INDETERMINATE",
    "REACH_REACHED",
    "REACH_REFUSED",
    "REACH_UNKNOWN",
    "REFUSAL_ABSENT_OR_DENIED",
    "REFUSAL_FORBIDDEN",
    "REFUSAL_METHOD_NOT_SUPPORTED",
    "REFUSAL_UNAUTHENTICATED",
    "SAFETY_POSTURE",
    "SCHEMA_VERSION",
    "SkippedProbe",
    "Specimen",
    "TARGET_ACKNOWLEDGEMENT_TEMPLATE",
    "UNKNOWN_REASONS",
    "classify_reach",
    "classify_target",
    "default_prober",
    "execute_matrix",
    "load_matrix",
    "matrix_document",
    "plan_matrix",
    "probe_url",
    "same_origin",
]


class MatrixError(ValueError):
    """Raised when an access matrix cannot be planned from a configuration.

    Not a subclass of ``core.ConfigError``: that would mean importing ``core``
    at module scope, which would drag the request machinery into every consumer
    of the matrix, including the pure projection module. Both are ``ValueError``
    subclasses, so ``except ValueError`` catches either.
    """


class MatrixSafetyError(MatrixError):
    """Raised when a run would breach a safety control (methods, rate, target)."""


class MatrixBudgetError(MatrixError):
    """Raised when a plan exceeds the request budget. Nothing has been sent."""


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION: int = 1
MATRIX_KIND: str = "veridor.matrix"

#: The only verbs probed without an explicit, acknowledged override.
MATRIX_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

MATRIX_DEFAULT_BUDGET: int = 500
#: Not overridable. An override with no ceiling is not a safety control.
MATRIX_ABSOLUTE_MAX_BUDGET: int = 20_000
#: Applies within the total, not in addition to it.
MATRIX_MUTATING_BUDGET: int = 50

MATRIX_DEFAULT_RPS: float = 2.0
MATRIX_MAX_RPS: float = 10.0

#: One specimen per operation is the recommendation. The cap is what stops the
#: matrix becoming an identifier enumerator by configuration drift.
MATRIX_MAX_SPECIMENS_PER_OPERATION: int = 3

MUTATING_ACKNOWLEDGEMENT: str = (
    "I have authorization to send mutating requests to this target"
)
TARGET_ACKNOWLEDGEMENT_TEMPLATE: str = "I am authorized to test {host}"

REACH_REACHED: str = "reached"
REACH_REFUSED: str = "refused"
REACH_INDETERMINATE: str = "indeterminate"
REACH_UNKNOWN: str = "unknown"
REACH_VALUES: tuple[str, ...] = (
    REACH_REACHED,
    REACH_REFUSED,
    REACH_INDETERMINATE,
    REACH_UNKNOWN,
)

OUTCOME_OBSERVED: str = "observed"
OUTCOME_UNKNOWN: str = "unknown"

REFUSAL_FORBIDDEN: str = "forbidden"
REFUSAL_UNAUTHENTICATED: str = "unauthenticated"
REFUSAL_ABSENT_OR_DENIED: str = "absent_or_denied"
REFUSAL_METHOD_NOT_SUPPORTED: str = "method_not_supported"

#: Closed set. A cell that is not measured always carries one of these.
UNKNOWN_REASONS: frozenset[str] = frozenset(
    {
        "not_probed",
        "skipped_mutating",
        "skipped_budget",
        "skipped_no_specimen",
        "skipped_ignored",
        "transport_error",
        "rate_limited",
        "server_error",
        "proxy_auth_required",
        "aborted",
    }
)

ABORT_CONSECUTIVE_RATE_LIMITED: int = 3
ABORT_CONSECUTIVE_SERVER_ERROR: int = 5
ABORT_CONSECUTIVE_TRANSPORT: int = 10
ABORT_HOSTILE_MINIMUM: int = 20
ABORT_HOSTILE_SHARE: float = 0.20

#: Cumulative, not consecutive, and not a share. A leaky-bucket throttle -- the
#: ordinary production shape -- answers a burst with a 429 and then refills, so
#: its 429s are isolated and stay well under any percentage. Without a total
#: cap such a target is ground through in full: 2,000 ignored throttle responses
#: in a 10,000-request plan. Five separate "slow down" responses is not
#: ambiguous, and the run stops.
ABORT_TOTAL_RATE_LIMITED: int = 5

#: What to do when a 429 carries ``Retry-After``. `stop` was the only behaviour,
#: and it read the header as "go away" when RFC 9110 s10.2.3 defines it as how
#: long to wait before a follow-up request. The cost was measured on one
#: throttling target, 15 runs per arm, identical seeded 429 positions: with the
#: header, 15/15 runs aborted and median grid coverage was 22%; with the SAME
#: 429s and the header removed, 2/15 aborted and median coverage was 78%. A
#: spec-compliant limiter was punished 3.5x for being spec-compliant, and there
#: was no flag to say otherwise.
#:
#: `continue` does not mean grind through. A Retry-After 429 still counts toward
#: both rate-limit rules, so a polite target gets the same tolerance as a rude
#: one -- three consecutive or five cumulative -- never more, and the abort
#: reason stays `retry_after_requested` when the header was the last word.
ON_RETRY_AFTER_CHOICES: tuple[str, ...] = ("continue", "stop")
ON_RETRY_AFTER_DEFAULT: str = "continue"

#: Per-request. Not adjustable upward: an unbounded timeout is how a plan whose
#: banner promised minutes runs for hours against a half-open socket.
MATRIX_MAX_TIMEOUT_SECONDS: float = 60.0

#: Total wall clock for one run. ``estimated_seconds`` covers the rate limiter
#: only and explicitly excludes response time, so the number the operator was
#: shown is a floor, not a ceiling. This is the ceiling.
MATRIX_DEFAULT_RUN_SECONDS: float = 1_800.0
#: Not overridable, for the same reason the absolute budget is not.
MATRIX_ABSOLUTE_MAX_RUN_SECONDS: float = 7_200.0

SAFETY_POSTURE: str = (
    "The access matrix issues one request per operation per identity per "
    "specimen. That is categorically closer to scanning than to testing. Use it "
    "only against systems you own or are explicitly authorised to test."
)

#: Printed on every rendering of anything derived from a matrix. v1 measures
#: operations, not objects, and must never be read as measuring objects.
OPERATION_LEVEL_LIMITATION: str = (
    "Blast radius is measured at OPERATION level. It reports which endpoints an "
    "identity was observed to reach using the specimen values you supplied. It "
    "does not report how many objects those endpoints expose. Veridor probed at "
    "most {specimens} specimen(s) per operation and never enumerated "
    "identifiers. An operation counted as reached may expose one record or "
    "every record."
)

CLAIM: dict[str, str] = {
    "measures": (
        "which operations each named identity was OBSERVED to reach, using the "
        "specimen values supplied by the operator"
    ),
    "does_not_measure": (
        "whether any observed access is authorized, and how many objects a "
        "reached operation exposes"
    ),
    "statement": (
        "The access matrix records observed responses. Reach is an observation, "
        "not a verdict: an operation an identity reached may be exactly what "
        "policy intends. Blast radius is a lower bound on observed reach, not a "
        "measure of exposure. Anomaly candidates are inconsistencies in the "
        "observations; they are hypotheses to declare and test, never findings."
    ),
}

_MATRIX_KEYS: frozenset[str] = frozenset(
    {
        "specimens",
        "ignore",
        "base_path",
        "marker_owner",
        # Consumed by the projection module, not by the prober. Accepted here
        # so a single `matrix` section serves both, and rejected as unknown
        # nowhere else: a typo in `specimens` must fail loudly, because a
        # silently unsubstituted operation is an invisible gap in the grid.
        "peer_groups",
        "privilege_order",
        "unauthenticated",
        "peer_divergence_unanimous",
    }
)
_SPECIMEN_KEYS: frozenset[str] = frozenset({"label", "values", "per_identity"})

#: What ``veridor init --for drift`` writes where a real object id belongs, and
#: what the matrix refuses to send.
#:
#: An unedited placeholder is the most dangerous input this section can take.
#: A fake id 404s, a 404 is classified as ``refused``, and a grid of refusals
#: reads exactly like a boundary that holds. Recorded as a drift baseline it is
#: worse still: every later run that uses a real id reads as reach that OPENED,
#: so the first honest measurement arrives looking like a regression. This is
#: the same trap as a check that passes because the endpoint is gone.
SPECIMEN_PLACEHOLDER: str = "REPLACE-WITH-A-REAL-ID"
_LABEL_MAX: int = 64
_VALUE_MAX: int = 256


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


def classify_reach(status: int | None) -> tuple[str, str | None, str | None]:
    """Map one observed status onto ``(reach, refusal_kind, unknown_reason)``.

    Four-valued by construction. ``unknown`` is never collapsed into
    ``refused``: a throttle is not a denial and a crash is not a boundary.
    """
    if status is None:
        return (REACH_UNKNOWN, None, "transport_error")
    if 200 <= status <= 299:
        return (REACH_REACHED, None, None)
    if 300 <= status <= 399:
        # core never follows a redirect, so what is on the other side is
        # genuinely unobserved. Counting it either way is a lie in one
        # direction; it gets its own bucket instead.
        return (REACH_INDETERMINATE, None, None)
    if status == 429:
        return (REACH_UNKNOWN, None, "rate_limited")
    if status == 407:
        # Proxy Authentication Required is the proxy's own answer: the request
        # did not reach the target, so nothing about its boundary was seen.
        # Counted as a refusal, a drift gate behind such a proxy compared a
        # run that reached nothing with a measured baseline and could pass.
        return (REACH_UNKNOWN, None, "proxy_auth_required")
    if status in (405, 501):
        # Checked ahead of the 5xx sweep on purpose: 501 is numerically a
        # server error but semantically "this verb is not implemented here",
        # which is a refusal to answer, not a crash. Either way it is not an
        # authorization signal -- see the refusal_kind below.
        return (REACH_REFUSED, REFUSAL_METHOD_NOT_SUPPORTED, None)
    if 500 <= status <= 599:
        return (REACH_UNKNOWN, None, "server_error")
    if status == 401:
        return (REACH_REFUSED, REFUSAL_UNAUTHENTICATED, None)
    if status == 403:
        return (REACH_REFUSED, REFUSAL_FORBIDDEN, None)
    if status == 404:
        # An opaque-404 denial and a genuinely absent route are
        # indistinguishable from outside. Named so nobody forgets that.
        return (REACH_REFUSED, REFUSAL_ABSENT_OR_DENIED, None)
    if 400 <= status <= 499:
        # The handler was reached and rejected the input; no data was returned.
        return (REACH_INDETERMINATE, None, None)
    return (REACH_INDETERMINATE, None, None)


def classify_target(host: str) -> str:
    """Classify a hostname as ``loopback`` / ``private`` / ``public``.

    Never resolves DNS: a name this process cannot verify offline is treated as
    ``public``, which is the conservative direction (it demands the
    acknowledgement rather than waiving it).
    """
    name = host.strip("[]").lower().rstrip(".")
    if name == "localhost" or name.endswith(".localhost"):
        return "loopback"
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return "public"
    if address.is_loopback:
        return "loopback"
    if not address.is_global:
        # ``is_global`` rather than ``is_private``: the question the
        # acknowledgement gate is really asking is "could this reach a stranger
        # over the public internet?". Everything not globally routable --
        # RFC1918, ULA, link-local, CGNAT, the documentation ranges -- answers
        # no, and demanding an acknowledgement for a lab address is friction
        # that teaches operators to paste the string without reading it.
        return "private"
    return "public"


# ---------------------------------------------------------------------------
# origin containment
# ---------------------------------------------------------------------------

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def probe_url(base_url: str, path: str) -> str:
    """The URL ``core._perform_request`` will build for ``path``.

    Reproduced here, character for character, rather than approximated: the
    origin assertion is only worth anything if it is asserted over the URL that
    is actually going to be requested.
    """
    return urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        # An unparseable port is not "the default port"; it is a URL nobody
        # should be sending. Made distinct so it can never compare equal.
        return (scheme, (parts.hostname or "").lower(), -1)
    return (
        scheme,
        (parts.hostname or "").lower(),
        port if port is not None else _DEFAULT_PORTS.get(scheme),
    )


def same_origin(base_url: str, url: str) -> bool:
    """Scheme, host and effective port all equal. Userinfo is not an origin."""
    return _origin(base_url) == _origin(url)


def _assert_on_target(base_url: str, path: str, *, where: str) -> str:
    """Refuse a probe path that would leave ``base_url``.

    An OpenAPI path is untrusted input and ``core``'s ``urljoin`` treats a path
    that lstrips to ``scheme://host/...`` as an absolute URL. The identity's
    headers travel with the request, so an escape here is credential
    exfiltration to a host that the target-acknowledgement gate, the banner and
    the artifact all fail to mention. Raised before anything is sent.
    """
    if not isinstance(path, str) or not path:
        raise MatrixSafetyError(f"{where} has no request path. Nothing has been sent.")
    if any(character <= " " or character == "\x7f" for character in path):
        raise MatrixSafetyError(
            f"{where} declares a request path containing whitespace or a control "
            f"character ({quoted(path)}). Nothing has been sent."
        )
    joined = probe_url(base_url, path)
    if not same_origin(base_url, joined):
        raise MatrixSafetyError(
            f"{where} declares the path {quoted(path)}, which resolves to {quoted(joined)} -- a "
            f"different origin from target.base_url ({quoted(base_url)}). The matrix sends "
            "each identity's credentials with every probe, so a request that leaves "
            "the declared target would hand them to a host you did not name, past "
            "the target acknowledgement and invisibly to the banner and the "
            "artifact. Fix the OpenAPI document, or exclude the operation with "
            "matrix.ignore. Nothing has been sent."
        )
    base_path = urlsplit(base_url).path.rstrip("/")
    joined_path = urlsplit(joined).path
    if base_path and not (
        joined_path == base_path or joined_path.startswith(base_path + "/")
    ):
        raise MatrixSafetyError(
            f"{where} declares the path {quoted(path)}, which resolves to {quoted(joined_path)} "
            f"and escapes the base path {quoted(base_path)} of target.base_url. Nothing "
            "has been sent."
        )
    from veridor.core import _has_dot_segment  # noqa: PLC0415 -- see module docstring

    if _has_dot_segment(path):
        # The base-path check above judges the URL after urljoin has removed a
        # literal '..', so it catches that one when it leaves the base path; a
        # percent-encoded '%2e%2e' survives urljoin, and a gateway that decodes
        # it routes the same way. `run`, `verify` and sequence steps refuse
        # both, by the same rule.
        raise MatrixSafetyError(
            f"{where} declares the path {quoted(path)}, which has a '.' or '..' segment "
            "(plain, percent-encoded any number of times or as overlong UTF-8, "
            "before a ';' path parameter, or beside an encoded '/' or '\\' such "
            "as '..%2f'; or still decoding after eight rounds). Joined onto "
            "target.base_url it would go to "
            "a different path than the one declared. Fix the OpenAPI document or "
            "the specimen, or exclude the operation with matrix.ignore. Nothing "
            "has been sent."
        )
    return joined


# ---------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------


def _refuse_nan(value: float, where: str) -> None:
    """NaN compares false with everything, so ``<= 0`` and every ceiling let it
    through: ``map --rate nan`` and ``--max-run-seconds nan`` crashed with exit
    70, and ``--timeout nan`` ran a matrix in which no request could complete.
    Infinity is left to the ceilings, which refuse it by name."""
    if math.isnan(value):
        raise MatrixSafetyError(f"{where} must be a finite number, not NaN")


def _validated_timeout(value: Any, where: str) -> float:
    """Every other envelope knob has a ceiling; so does this one.

    An unbounded per-request timeout is the one setting that can turn a plan the
    operator sized in minutes into a run of unbounded length, because the
    consecutive-transport abort only counts requests that actually come back.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MatrixSafetyError(f"{where} must be a number")
    _refuse_nan(value, where)
    if value <= 0:
        raise MatrixSafetyError(f"{where} must be greater than zero")
    if value > MATRIX_MAX_TIMEOUT_SECONDS:
        raise MatrixSafetyError(
            f"{where} {value:g} is over the ceiling of "
            f"{MATRIX_MAX_TIMEOUT_SECONDS:g}s. A per-request timeout with no ceiling "
            "makes the estimated duration meaningless; the ceiling is not adjustable."
        )
    return float(value)


@dataclass(frozen=True)
class MatrixOptions:
    """Operator-supplied safety envelope. Validated on construction.

    Validating in ``__post_init__`` rather than in ``plan_matrix`` means an
    unsafe envelope cannot be built at all, so there is no window in which one
    exists and could be handed to a future code path that forgot to check.
    """

    max_requests: int = MATRIX_DEFAULT_BUDGET
    requests_per_second: float = MATRIX_DEFAULT_RPS
    allow_mutating_methods: frozenset[str] = frozenset()
    mutating_acknowledgement: str = ""
    target_acknowledgement: str = ""
    include: tuple[str, ...] = ()
    ignore: tuple[str, ...] = ()
    timeout_seconds: float | None = None
    max_run_seconds: float = MATRIX_DEFAULT_RUN_SECONDS
    on_retry_after: str = ON_RETRY_AFTER_DEFAULT

    def __post_init__(self) -> None:
        if isinstance(self.max_requests, bool) or not isinstance(
            self.max_requests, int
        ):
            raise MatrixSafetyError("max_requests must be an integer")
        if self.max_requests < 1:
            raise MatrixSafetyError("max_requests must be at least 1")
        if self.max_requests > MATRIX_ABSOLUTE_MAX_BUDGET:
            raise MatrixSafetyError(
                f"max_requests {self.max_requests} is over the absolute maximum of "
                f"{MATRIX_ABSOLUTE_MAX_BUDGET}, which cannot be overridden. Narrow "
                "the inventory or reduce specimens instead."
            )
        if self.on_retry_after not in ON_RETRY_AFTER_CHOICES:
            raise MatrixSafetyError(
                f"on_retry_after must be one of "
                f"{', '.join(ON_RETRY_AFTER_CHOICES)}, not {quoted(self.on_retry_after)}"
            )
        if isinstance(self.requests_per_second, bool) or not isinstance(
            self.requests_per_second, (int, float)
        ):
            raise MatrixSafetyError("requests_per_second must be a number")
        _refuse_nan(self.requests_per_second, "requests_per_second")
        if self.requests_per_second <= 0:
            raise MatrixSafetyError("requests_per_second must be greater than zero")
        if self.requests_per_second > MATRIX_MAX_RPS:
            raise MatrixSafetyError(
                f"requests_per_second {self.requests_per_second} is over the ceiling "
                f"of {MATRIX_MAX_RPS}. The matrix is a scanning-shaped workload; the "
                "ceiling is not adjustable."
            )
        object.__setattr__(
            self, "allow_mutating_methods", frozenset(self.allow_mutating_methods)
        )
        object.__setattr__(self, "include", tuple(self.include))
        object.__setattr__(self, "ignore", tuple(self.ignore))
        self._validate_mutating()
        if self.timeout_seconds is not None:
            object.__setattr__(
                self,
                "timeout_seconds",
                _validated_timeout(self.timeout_seconds, "timeout_seconds"),
            )
        if isinstance(self.max_run_seconds, bool) or not isinstance(
            self.max_run_seconds, (int, float)
        ):
            raise MatrixSafetyError("max_run_seconds must be a number")
        _refuse_nan(self.max_run_seconds, "max_run_seconds")
        if self.max_run_seconds <= 0:
            raise MatrixSafetyError("max_run_seconds must be greater than zero")
        if self.max_run_seconds > MATRIX_ABSOLUTE_MAX_RUN_SECONDS:
            raise MatrixSafetyError(
                f"max_run_seconds {self.max_run_seconds:g} is over the absolute "
                f"maximum of {MATRIX_ABSOLUTE_MAX_RUN_SECONDS:g}, which cannot be "
                "overridden. A scanning-shaped workload gets a wall clock."
            )
        object.__setattr__(self, "max_run_seconds", float(self.max_run_seconds))

    def _validate_mutating(self) -> None:
        """Two independent gates, so one stray truthy value cannot open both."""
        methods = self.allow_mutating_methods
        if not methods:
            if self.mutating_acknowledgement:
                raise MatrixSafetyError(
                    "mutating_acknowledgement was supplied but "
                    "allow_mutating_methods is empty. Name the verbs explicitly; "
                    "an acknowledgement on its own enables nothing."
                )
            return
        for method in sorted(methods):
            if not isinstance(method, str) or not method:
                raise MatrixSafetyError(
                    "allow_mutating_methods must contain HTTP method names"
                )
            if method != method.upper():
                raise MatrixSafetyError(
                    f"allow_mutating_methods entry {quoted(method)} must be upper case"
                )
            if method in {"*", "ALL", "ANY"}:
                raise MatrixSafetyError(
                    f"allow_mutating_methods entry {quoted(method)} is a wildcard. Every "
                    "mutating verb must be named literally, e.g. "
                    "allow_mutating_methods={'DELETE'}."
                )
            if method in MATRIX_SAFE_METHODS:
                raise MatrixSafetyError(
                    f"allow_mutating_methods entry {quoted(method)} is already probed by "
                    "default; remove it so the list names only mutating verbs."
                )
            if method not in ALL_METHODS:
                raise MatrixSafetyError(
                    f"allow_mutating_methods entry {quoted(method)} is not an HTTP method "
                    f"Veridor recognises ({', '.join(sorted(ALL_METHODS))})"
                )
        if self.mutating_acknowledgement != MUTATING_ACKNOWLEDGEMENT:
            raise MatrixSafetyError(
                "mutating methods "
                f"({', '.join(sorted(methods))}) require mutating_acknowledgement to "
                f"be exactly {quoted(MUTATING_ACKNOWLEDGEMENT)}. Nothing has been sent."
            )

    @property
    def permitted_methods(self) -> frozenset[str]:
        return MATRIX_SAFE_METHODS | self.allow_mutating_methods

    @property
    def read_only(self) -> bool:
        return not self.allow_mutating_methods


# ---------------------------------------------------------------------------
# specimens
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Specimen:
    """One concrete set of path-parameter values for one templated operation."""

    label: str
    values: tuple[tuple[str, str], ...] = ()
    #: ``((identity, ((name, value), ...)), ...)``. When present the identities
    #: probed DIFFERENT objects, so cross-identity comparison of this operation
    #: is not meaningful and the projection module must not attempt it.
    per_identity: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()

    @property
    def shared(self) -> bool:
        return not self.per_identity

    def values_for(self, identity: str) -> dict[str, str] | None:
        """Values for ``identity``, or ``None`` when this specimen omits it."""
        if not self.per_identity:
            return dict(self.values)
        for name, pairs in self.per_identity:
            if name == identity:
                return dict(pairs)
        return None


def _validate_label(label: Any, where: str) -> str:
    if not isinstance(label, str) or not label.strip():
        raise MatrixError(f"{where} label must be a non-empty string")
    if len(label) > _LABEL_MAX:
        raise MatrixError(f"{where} label is longer than {_LABEL_MAX} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in label):
        raise MatrixError(f"{where} label must not contain control characters")
    return label


def _validate_values(
    raw: Any, template: str, where: str, markers: Mapping[str, str]
) -> tuple[tuple[str, str], ...]:
    parameters = _template_parameters(template)
    if not isinstance(raw, dict) or not raw:
        raise MatrixError(f"{where} values must be a non-empty object")
    pairs: list[tuple[str, str]] = []
    for name, value in raw.items():
        if not isinstance(name, str) or not name:
            raise MatrixError(f"{where} values keys must be non-empty strings")
        if name not in parameters:
            raise MatrixError(
                f"{where} sets {quoted(name)}, which is not a path parameter of {quoted(template)} "
                f"(it declares {', '.join(sorted(parameters)) or 'none'}). A specimen "
                "substitutes path parameters only: a query value is redacted from "
                "every artifact, so declaring one would be quietly useless."
            )
        if not isinstance(value, str) or not value:
            raise MatrixError(f"{where} value for {quoted(name)} must be a non-empty string")
        if value == SPECIMEN_PLACEHOLDER:
            raise MatrixError(
                f"{where} value for {quoted(name)} is still {quoted(SPECIMEN_PLACEHOLDER)}. "
                f"Replace it with an id that really exists in your test "
                f"environment and belongs to one of your identities — Veridor "
                f"sends this path verbatim and never enumerates ids. Left as "
                f"written it would 404, a 404 is recorded as 'refused', and a "
                f"grid of refusals reads like a boundary that holds."
            )
        if len(value) > _VALUE_MAX:
            raise MatrixError(
                f"{where} value for {quoted(name)} is longer than {_VALUE_MAX} characters"
            )
        if any(ord(character) <= 32 or ord(character) == 127 for character in value):
            raise MatrixError(
                f"{where} value for {quoted(name)} must not contain whitespace or control "
                "characters"
            )
        for owner, marker in markers.items():
            if marker and marker in value:
                # core refuses a config that would send a marker it later
                # matches, because a reflected marker is not a leak. The matrix
                # builds its own paths, so it has to refuse the same shape.
                raise MatrixError(
                    f"{where} value for {quoted(name)} contains identity {quoted(owner)}'s marker. "
                    "A marker Veridor sends is a marker Veridor can match in the "
                    "response, which proves nothing."
                )
        pairs.append((name, value))
    missing = sorted(parameters - {name for name, _ in pairs})
    if missing:
        raise MatrixError(
            f"{where} does not set {', '.join(missing)}, so {quoted(template)} cannot be "
            "made concrete. Supply every path parameter, or omit the specimen and "
            "the operation is recorded as unknown / skipped_no_specimen."
        )
    return tuple(sorted(pairs))


def _template_parameters(template: str) -> frozenset[str]:
    names: set[str] = set()
    for token in TEMPLATE_TOKEN.findall(template):
        name = token[1:-1].strip()
        if name:
            names.add(name)
    return frozenset(names)


def _parse_specimens(
    section: Mapping[str, Any], identities: Sequence[str], markers: Mapping[str, str]
) -> dict[str, tuple[Specimen, ...]]:
    raw = section.get("specimens", {})
    if not isinstance(raw, dict):
        raise MatrixError("matrix.specimens must be an object keyed by path template")
    parsed: dict[str, tuple[Specimen, ...]] = {}
    for template, entries in raw.items():
        if not isinstance(template, str) or not template.startswith("/"):
            raise MatrixError(
                f"matrix.specimens key {quoted(template)} must be an absolute path template"
            )
        if not isinstance(entries, list) or not entries:
            raise MatrixError(
                f"matrix.specimens[{quoted(template)}] must be a non-empty list"
            )
        if len(entries) > MATRIX_MAX_SPECIMENS_PER_OPERATION:
            raise MatrixError(
                f"matrix.specimens[{quoted(template)}] declares {len(entries)} specimens, "
                f"over the cap of {MATRIX_MAX_SPECIMENS_PER_OPERATION}. The cap is "
                "what keeps the matrix from becoming an identifier enumerator; one "
                "specimen per operation is the recommendation."
            )
        specimens: list[Specimen] = []
        labels: set[str] = set()
        for index, entry in enumerate(entries):
            where = f"matrix.specimens[{quoted(template)}][{index}]"
            if not isinstance(entry, dict):
                raise MatrixError(f"{where} must be an object")
            unknown = sorted(set(entry) - _SPECIMEN_KEYS)
            if unknown:
                from veridor.core import terminal_names  # noqa: PLC0415 -- see module docstring

                raise MatrixError(
                    f"{where} has unsupported keys: {terminal_names(unknown)} "
                    f"(supported: {', '.join(sorted(_SPECIMEN_KEYS))})"
                )
            label = _validate_label(entry.get("label"), where)
            if label in labels:
                raise MatrixError(f"{where} reuses the label {quoted(label)}")
            labels.add(label)
            has_values = "values" in entry
            has_per_identity = "per_identity" in entry
            if has_values == has_per_identity:
                raise MatrixError(
                    f"{where} must declare exactly one of 'values' (shared, the "
                    "default) or 'per_identity'"
                )
            if has_values:
                specimens.append(
                    Specimen(
                        label=label,
                        values=_validate_values(
                            entry["values"], template, where, markers
                        ),
                    )
                )
                continue
            per_raw = entry["per_identity"]
            if not isinstance(per_raw, dict) or not per_raw:
                raise MatrixError(f"{where}.per_identity must be a non-empty object")
            per: list[tuple[str, tuple[tuple[str, str], ...]]] = []
            for name in per_raw:
                if name not in identities:
                    raise MatrixError(
                        f"{where}.per_identity names {quoted(name)}, which is not a "
                        "declared identity"
                    )
            for name in identities:
                if name not in per_raw:
                    continue
                per.append(
                    (
                        name,
                        _validate_values(
                            per_raw[name],
                            template,
                            f"{where}.per_identity[{quoted(name)}]",
                            markers,
                        ),
                    )
                )
            specimens.append(Specimen(label=label, per_identity=tuple(per)))
        parsed[normalize_path(template)] = tuple(specimens)
    return parsed


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlannedProbe:
    """One request the plan intends to issue. Carries no header and no token."""

    operation: str
    method: str
    path_template: str
    identity: str
    specimen: str | None
    path: str
    mutating: bool

    def row(self) -> tuple[str, str | None]:
        return (self.operation, self.specimen)


def _sends_a_mutation(probe: PlannedProbe) -> bool:
    """Read from the verb that goes on the wire, not from ``probe.mutating``.

    The flag is a free field: only :func:`plan_matrix` derives it from the
    method. The mutating budget and the banner's listing counted the flag, so a
    hand-built plan whose DELETE probes said ``mutating=False`` passed both and
    could send up to ``max_requests`` of them. Either one saying "mutating" is
    enough.
    """
    return probe.mutating or probe.method not in MATRIX_SAFE_METHODS


@dataclass(frozen=True)
class SkippedProbe:
    """A grid cell the plan will NOT issue, and why. Never absent, never denied."""

    operation: str
    method: str
    path_template: str
    identity: str
    specimen: str | None
    path: str
    unknown_reason: str


@dataclass(frozen=True)
class MatrixPlan:
    """A complete, socket-free description of what a run would do."""

    base_url: str
    host: str
    target_class: str
    operations: tuple[str, ...]
    identities: tuple[str, ...]
    rows: tuple[tuple[str, str | None], ...]
    probes: tuple[PlannedProbe, ...]
    skipped: tuple[SkippedProbe, ...]
    specimens: tuple[tuple[str, tuple[Specimen, ...]], ...]
    options: MatrixOptions
    inventory_operations: int
    ignored: tuple[str, ...]
    marker_owner: str | None
    timeout_seconds: float
    #: `--include` patterns that named no operation in this specification, when
    #: at least one other pattern did. A total miss is refused in `plan_matrix`;
    #: a partial one is a legitimate thing to ask for -- one include list passed
    #: across several specifications -- but it is not silent either, because an
    #: operator who believes they are probing a route they are not is exactly
    #: the reader of a clean report. Carried here rather than printed, so the
    #: planning layer stays a description and a programmatic caller can see it.
    unmatched_include: tuple[tuple[str | None, str], ...] = ()
    #: `--include` patterns whose only matches `ignore` had already removed.
    ignored_only_include: tuple[tuple[str | None, str], ...] = ()

    @property
    def requests_planned(self) -> int:
        return len(self.probes)

    @property
    def planned_rows(self) -> int:
        """Rows that actually produce a probe.

        NOT ``len(self.rows)``. ``rows`` records every grid row the
        specification contributes, including the ones every identity skips --
        non-read-only, ignored, no specimen -- so it is the SPEC's row count
        and has no arithmetic relationship to the request count.

        The budget refusal prints an equation a reader checks on a calculator,
        and ``len(self.rows)`` made it false by a factor of two on a
        246-operation specification: "620 requests (246 rows x 5 identities)",
        where 246 x 5 is 1230. The real figure was 124 GET-only rows.
        """
        return len({probe.row() for probe in self.probes})

    @property
    def mutating_planned(self) -> int:
        return sum(1 for probe in self.probes if _sends_a_mutation(probe))

    @property
    def budget(self) -> int:
        return self.options.max_requests

    @property
    def estimated_seconds(self) -> float:
        """Wall clock the rate limiter alone imposes, excluding response time."""
        if self.requests_planned <= 1:
            return 0.0
        return (self.requests_planned - 1) / self.options.requests_per_second

    @property
    def max_specimens(self) -> int:
        return max((len(items) for _, items in self.specimens), default=1) or 1

    def refuse_if_over_budget(self) -> None:
        """Raise unless the plan fits the budget. Called before anything is sent.

        ``execute_matrix`` calls this itself rather than trusting the caller, so
        a future CLI path cannot skip the check by building a plan by hand.
        """
        planned = self.requests_planned
        if planned > MATRIX_ABSOLUTE_MAX_BUDGET:
            raise MatrixBudgetError(
                f"the access matrix plan is {planned:,} requests, over the absolute "
                f"maximum of {MATRIX_ABSOLUTE_MAX_BUDGET:,}, which cannot be "
                "overridden. Nothing has been sent."
            )
        if planned > self.options.max_requests:
            default = (
                "default "
                if self.options.max_requests == MATRIX_DEFAULT_BUDGET
                else ""
            )
            raise MatrixBudgetError(
                f"the access matrix plan is {planned:,} requests "
                f"({self.planned_rows} operation-specimen rows x "
                f"{len(self.identities)} identities), over the {default}"
                f"budget of {self.options.max_requests:,}. Nothing has been sent. At "
                f"{self.options.requests_per_second:g} req/s this run would take "
                f"{_format_duration(self.estimated_seconds)}. Narrow the inventory "
                "(--include, matrix.ignore), reduce specimens, or raise the budget "
                # Spelled as it is typed. `max_requests=` is the keyword this
                # module takes; the operator reading this is holding a command
                # line, and a remediation they cannot paste is the same defect
                # as no remediation -- it just costs them the attempt first.
                f"explicitly with --max-requests {planned}."
            )
        mutating = self.mutating_planned
        if mutating > MATRIX_MUTATING_BUDGET:
            raise MatrixBudgetError(
                f"the plan contains {mutating:,} mutating requests, over the mutating "
                f"budget of {MATRIX_MUTATING_BUDGET}. Nothing has been sent."
            )

    def refuse_if_unsafe(self) -> None:
        """Re-derive every safety gate from the plan itself.

        Deliberately independent of how the plan was built: a hand-assembled
        plan carrying a ``DELETE`` probe is refused here even if the options it
        was built with said otherwise.
        """
        for probe in self.probes:
            # First, because a probe that leaves the target takes the identity's
            # credential with it: none of the gates below would have looked at
            # the host it actually goes to.
            _assert_on_target(
                self.base_url,
                probe.path,
                where=f"{probe.operation} as {probe.identity}",
            )
        permitted = self.options.permitted_methods
        offenders = sorted(
            {probe.method for probe in self.probes if probe.method not in permitted}
        )
        if offenders:
            raise MatrixSafetyError(
                f"the plan contains {', '.join(offenders)} probes, which the permitted "
                f"method set ({', '.join(sorted(permitted))}) does not allow. Nothing "
                "has been sent."
            )
        if any(_sends_a_mutation(probe) for probe in self.probes):
            # Re-checked, not inherited: the acknowledgement gate must hold at
            # the moment of sending, not merely at the moment of configuring.
            if not self.options.allow_mutating_methods:
                raise MatrixSafetyError(
                    "the plan contains mutating probes but no mutating verb is "
                    "allowed. Name each one with --allow-mutating-method METHOD. "
                    "Nothing has been sent."
                )
            if self.options.mutating_acknowledgement != MUTATING_ACKNOWLEDGEMENT:
                raise MatrixSafetyError(
                    "the plan contains mutating probes without the exact "
                    "acknowledgement string. Pass --acknowledge-mutating "
                    f"{quoted(MUTATING_ACKNOWLEDGEMENT)}. Nothing has been sent."
                )
        if self.target_class == "public":
            expected = TARGET_ACKNOWLEDGEMENT_TEMPLATE.format(host=self.host)
            if self.options.target_acknowledgement != expected:
                # Name the FLAG, not this dataclass field. A refusal that names
                # an internal attribute is a dead end: `target_acknowledgement`
                # is not a config key either, so a reader who follows the
                # message literally hits a second, unrelated refusal about
                # unsupported keys in the `matrix` block.
                raise MatrixSafetyError(
                    f"{self.host} is not a loopback or private address. Pass "
                    f"--acknowledge-target {quoted(expected)}. This is "
                    "friction, not a security boundary: the point is that you must "
                    "type the hostname, so pointing the matrix at the wrong host is "
                    "hard to do by accident. Nothing has been sent."
                )

    def banner(self) -> str:
        """The number, and the posture, before anything is sent."""
        skipped_mutating = sum(
            1 for item in self.skipped if item.unknown_reason == "skipped_mutating"
        )
        skipped_operations = len(
            {
                item.operation
                for item in self.skipped
                if item.unknown_reason == "skipped_mutating"
            }
        )
        # Operations dropped because no specimen names a concrete object. On a
        # real specification these are the MAJORITY -- half of a 120-path API in
        # the case that prompted this line -- and they are exactly the templated
        # routes, which is the shape this tool exists to measure. The banner
        # used to report only "N skipped as non-read-only", so the rest went
        # missing between two numbers with no explanation, in the one command
        # (`--dry-run`) the documentation tells you to run first.
        no_specimen = len(
            {
                item.operation
                for item in self.skipped
                if item.unknown_reason == "skipped_no_specimen"
            }
        )
        probed_operations = len({probe.operation for probe in self.probes})
        methods = ", ".join(sorted({probe.method for probe in self.probes})) or "none"
        lines = [
            f"Veridor access matrix -- this will issue {self.requests_planned:,} "
            f"requests to {self.host}.",
            "Use it only against systems you own or are explicitly authorised to test.",
            f"  operations: {probed_operations} (of {self.inventory_operations} in the "
            f"spec; {skipped_operations} skipped as non-read-only"
            + (f", {no_specimen} for want of a specimen" if no_specimen else "")
            + ")",
            f"  identities: {len(self.identities)}      specimens: "
            f"{self.max_specimens} per operation (max)",
            f"  methods:    {methods}"
            + (" (read-only)" if self.options.read_only else " (MUTATING ENABLED)"),
            f"  rate:       {self.options.requests_per_second:g} req/s, sequential",
            f"  budget:     {self.budget:,}",
            f"  estimated:  {_format_duration(self.estimated_seconds)}"
            f" (rate limiter only; the run stops at "
            f"{_format_duration(self.options.max_run_seconds)})",
            f"  timeout:    {self.timeout_seconds:g}s per request",
            f"  target:     {self.target_class} ({_safe_base_url(self.base_url)})",
        ]
        if self.estimated_seconds > self.options.max_run_seconds:
            # The two numbers one line up have always been printed side by side
            # and never compared. The wall clock usually binds first: at the
            # default 2 req/s it caps any run at 3,600 requests, well under the
            # 20,000 budget ceiling, so an ordinary large spec trips this. The
            # cells the clock cuts off read `unknown`, which drift can never
            # later report as more access -- so a plan that cannot finish should
            # say so before it starts, not thirty minutes in. A warning and not
            # a refusal: a partial grid is a legitimate thing to ask for, which
            # is what the wall clock is for.
            reachable = int(
                self.options.max_run_seconds * self.options.requests_per_second
            )
            unreachable = max(0, self.requests_planned - reachable - 1)
            # Derived from the same arithmetic the warning reports, or the
            # advice contradicts the number beside it: a plan the ceiling covers
            # EXACTLY was told no --max-run-seconds could cover it.
            raisable = (
                self.requests_planned - 1
                <= MATRIX_ABSOLUTE_MAX_RUN_SECONDS * self.options.requests_per_second
            )
            remedy = (
                "Raise --max-run-seconds (ceiling "
                f"{_format_duration(MATRIX_ABSOLUTE_MAX_RUN_SECONDS)}) or narrow "
                "the plan."
                if raisable
                else (
                    "No --max-run-seconds can cover this plan at "
                    f"{self.options.requests_per_second:g} req/s; narrow it, or "
                    "raise --rate (ceiling "
                    f"{MATRIX_MAX_RPS:g} req/s)."
                )
            )
            lines.append(
                "  !! THIS PLAN CANNOT FINISH. The rate limiter alone needs "
                f"{_format_duration(self.estimated_seconds)} and the run stops "
                f"at {_format_duration(self.options.max_run_seconds)}. About "
                f"{unreachable:,} of {self.requests_planned:,} requests would "
                "never be sent, and their cells read 'unknown', not 'no "
                f"access'. {remedy}"
            )
        if self.ignored_only_include:
            lines.append(
                textwrap.fill(
                    _include_ignored_message(self.ignored_only_include, all_of=False),
                    width=78,
                    initial_indent="  ",
                    subsequent_indent="  ",
                )
            )
        if self.unmatched_include:
            lines.append(
                textwrap.indent(
                    _include_miss_message(
                        self.unmatched_include, self.operations, all_of=False
                    ),
                    "  ",
                    lambda line: bool(line.strip()),
                )
            )
        if skipped_mutating:
            lines.append(
                f"  {skipped_mutating:,} cells are recorded as unknown / "
                "skipped_mutating -- unknown, never refused."
            )
        lines.extend(self._mutating_lines())
        return "\n".join(lines)

    def _mutating_lines(self) -> list[str]:
        mutating = [probe for probe in self.probes if _sends_a_mutation(probe)]
        if not mutating:
            return []
        by_method: dict[str, list[PlannedProbe]] = {}
        for probe in mutating:
            by_method.setdefault(probe.method, []).append(probe)
        lines = [
            "",
            f"  !! MUTATING REQUESTS ARE ENABLED. {len(mutating)} mutating request(s) "
            "will be sent,",
            f"  !! within a mutating budget of {MATRIX_MUTATING_BUDGET}. Every one is "
            "listed below.",
        ]
        for method in sorted(by_method):
            probes = by_method[method]
            lines.append(f"  !! {method} ({len(probes)}):")
            for probe in probes:
                lines.append(f"  !!   {probe.path} as {probe.identity}")
        return lines


def _format_duration(seconds: float) -> str:
    total = int(round(seconds))
    if total < 60:
        return f"{total}s"
    minutes, remainder = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m{remainder:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m{remainder:02d}s"


def _matrix_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    section = config.get("matrix", {})
    if not isinstance(section, dict):
        raise MatrixError("matrix must be an object")
    unknown = sorted(set(section) - _MATRIX_KEYS)
    if unknown:
        from veridor.core import terminal_names  # noqa: PLC0415 -- see module docstring

        # Strict, unlike core's treatment of identity annotations: this section
        # is new, so there is no compatibility to preserve, and a typo'd
        # `specimen` would silently leave a hole in the grid rather than fail.
        raise MatrixError(
            f"matrix has unsupported keys: {terminal_names(unknown)} "
            f"(supported: {', '.join(sorted(_MATRIX_KEYS))})"
        )
    _validate_identity_references(section, config)
    return section


def _validate_identity_references(
    section: Mapping[str, Any], config: Mapping[str, Any]
) -> None:
    """Every identity this section names must exist, checked BEFORE probing.

    ``blastradius.peer_groups`` already refuses an unknown member, but it runs
    on the finished matrix -- so a typo cost a full probe of somebody's API
    first, and only then a refusal. The safety posture promises the plan is
    refused before the first request, and a name that cannot resolve is part of
    the plan.

    Silence would be worse than the wait. A misspelled peer group is not
    ignored loudly: it changes which rules can fire, and the report that comes
    back looks like a clean target rather than a misconfigured one.
    """
    known = set(config.get("identities") or {})
    if not known:
        return

    def check(name: Any, where: str) -> None:
        if not isinstance(name, str) or name in known:
            return
        raise MatrixError(
            f"{where} names {quoted(name)}, which is not one of the configured "
            f"identities ({', '.join(sorted(known))})"
        )

    for group, members in (section.get("peer_groups") or {}).items():
        if isinstance(members, list):
            for member in members:
                check(member, f"matrix.peer_groups[{quoted(group)}]")
    order = section.get("privilege_order")
    if isinstance(order, list):
        for member in order:
            check(member, "matrix.privilege_order")
    for key in ("unauthenticated", "marker_owner"):
        if key in section:
            check(section[key], f"matrix.{key}")


def _identity_markers(config: Mapping[str, Any]) -> dict[str, str]:
    identities = config.get("identities")
    if not isinstance(identities, dict):
        return {}
    markers: dict[str, str] = {}
    for name, identity in identities.items():
        if isinstance(identity, dict) and isinstance(identity.get("marker"), str):
            markers[str(name)] = identity["marker"]
    return markers


def _marker_owner(config: Mapping[str, Any], section: Mapping[str, Any]) -> str | None:
    """Which identity's marker every response is scanned for, if any.

    One marker per run: ``core._perform_request`` scans for one identity's
    needles, and scanning for several would multiply the work without changing
    what any rule can conclude. Named explicitly when there is a choice.
    """
    markers = _identity_markers(config)
    declared = section.get("marker_owner")
    if declared is not None:
        if not isinstance(declared, str) or declared not in markers:
            raise MatrixError(
                f"matrix.marker_owner {quoted(declared)} must name an identity that declares "
                f"a marker (candidates: {', '.join(sorted(markers)) or 'none'})"
            )
        return declared
    if len(markers) == 1:
        return next(iter(markers))
    if not markers:
        return None
    raise MatrixError(
        f"{len(markers)} identities declare a marker "
        f"({', '.join(sorted(markers))}); set matrix.marker_owner to name the one "
        "every response is scanned for."
    )


def _parse_ignore(
    entries: Iterable[Any], where: str
) -> tuple[tuple[str | None, str], ...]:
    parsed: list[tuple[str | None, str]] = []
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            raise MatrixError(f"{where} entries must be non-empty strings")
        text = entry.strip()
        method: str | None = None
        path = text
        if " " in text:
            head, _, tail = text.partition(" ")
            method = head.upper()
            path = tail.strip()
            if method not in ALL_METHODS:
                raise MatrixError(
                    f"{where} entry {quoted(entry)} does not start with an HTTP method"
                )
        if not path.startswith("/"):
            raise MatrixError(
                f"{where} entry {quoted(entry)} must be '/path/template' or "
                "'METHOD /path/template'"
            )
        parsed.append((method, normalize_path(path)))
    return tuple(parsed)


def _spec_base_path(operation: Operation, override: str | None) -> str:
    if override is not None:
        return override
    candidates = sorted({item for item in operation.base_paths if item})
    if not candidates:
        return ""
    if len(candidates) > 1:
        raise MatrixError(
            f"{operation.method} {operation.path_template} is declared under several "
            f"server base paths ({', '.join(candidates)}); set matrix.base_path to "
            "choose one, so every request path is unambiguous."
        )
    return candidates[0]


def _request_path(absolute: str, target_prefix: str) -> str:
    """Strip the prefix ``target.base_url`` already carries.

    ``core._perform_request`` joins the path onto ``base_url``, so a path that
    repeats a prefix the base URL already has would request it twice.
    """
    if target_prefix and (
        absolute == target_prefix or absolute.startswith(target_prefix + "/")
    ):
        remainder = absolute[len(target_prefix) :]
        return remainder or "/"
    return absolute


def _substitute(template: str, values: Mapping[str, str]) -> str:
    """Replace ``{param}`` segments with percent-encoded operator values.

    ``safe=""`` so a value containing ``/`` becomes ``%2F`` and stays one
    segment: a specimen must never be able to invent a path segment.
    """
    segments = []
    for segment in split_segments(template, decode=False):
        parameters = _template_parameters(segment)
        rendered = segment
        for name in parameters:
            rendered = rendered.replace("{" + name + "}", quote(values[name], safe=""))
        segments.append(rendered)
    return "/" + "/".join(segments) if segments else "/"


def _refuse_session_identities(identities: Mapping[str, Any]) -> None:
    """Fail closed on identities the matrix cannot authenticate as. Loudly.

    This module builds every probe from ``identities[name]["headers"]`` and
    issues it with no cookie jar and no login: there is no session engine here,
    and putting one here would be a feature, not a patch. An identity whose
    credential comes from a ``session`` block therefore gets probed
    ANONYMOUSLY, and the anonymous reach is recorded under that identity's
    name.

    Every consequence of that runs in the false-SAFE direction, which is the
    worst thing this product can do:

    * the identity's blast radius is understated -- ``map`` answers "what would
      a compromise of this identity reach?" with the reach of no credential at
      all;
    * the existing all-401 guard does not catch it whenever the target has any
      public operation, or denies with 403 rather than 401;
    * a session identity has no ``headers``, so ``blastradius`` infers it as
      THE UNAUTHENTICATED IDENTITY and runs ``unauthenticated_reach`` against
      what is in fact the authenticated one.

    None of that was visible: no artifact, banner or note contained the word
    "session". A loud refusal before the first socket beats a quiet wrong
    number, and it is the same posture ``mutation`` already takes for the same
    reason. ``run`` and the sequence engine DO log in; point them at this
    configuration, or give the matrix an identity whose credential is a static
    header.
    """
    named = sorted(
        str(name)
        for name, identity in identities.items()
        if isinstance(identity, Mapping) and "session" in identity
    )
    if named:
        raise MatrixError(
            "the access matrix cannot authenticate as a session-backed identity "
            f"({', '.join(named)}): it issues every probe from the identity's "
            "static headers, with no login and no cookie jar. Probing anyway "
            "would record the ANONYMOUS reach under that identity's name, "
            "understating its blast radius and possibly naming it the "
            "unauthenticated identity -- so nothing has been sent. Use `veridor "
            "run`, which does log in, or declare an identity for the matrix "
            "whose credential is a static header."
        )


def plan_matrix(
    config: Mapping[str, Any],
    inventory: RouteInventory,
    *,
    options: MatrixOptions = MatrixOptions(),
    defer_budget: bool = False,
) -> MatrixPlan:
    """Build the complete grid without opening a socket.

    Every cell of ``|rows| x |identities|`` is accounted for: it is either a
    :class:`PlannedProbe` or a :class:`SkippedProbe` carrying an
    ``unknown_reason``. Nothing is silently omitted, because a missing key reads
    as "nothing there" and that is the failure mode this design exists to avoid.
    """
    target = config.get("target")
    if not isinstance(target, dict) or not isinstance(target.get("base_url"), str):
        raise MatrixError("target.base_url must be an http(s) URL")
    base_url = target["base_url"]
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise MatrixError(
            f"target.base_url {quoted(base_url)} must be an http(s) URL with a host; the "
            "matrix has no override for another scheme."
        )
    host = (
        parsed.hostname
        if parsed.port is None
        else f"{parsed.hostname}:{parsed.port}"
    )
    target_class = classify_target(parsed.hostname)

    identities_raw = config.get("identities")
    if not isinstance(identities_raw, dict) or not identities_raw:
        raise MatrixError("identities must define at least one identity")
    _refuse_session_identities(identities_raw)
    identities = tuple(str(name) for name in identities_raw)

    section = _matrix_section(config)
    markers = _identity_markers(config)
    marker_owner = _marker_owner(config, section)
    specimens = _parse_specimens(section, identities, markers)
    base_path_override = section.get("base_path")
    if base_path_override is not None and (
        not isinstance(base_path_override, str) or not base_path_override.startswith("/")
    ):
        raise MatrixError("matrix.base_path must be an absolute path")
    if isinstance(base_path_override, str):
        base_path_override = normalize_path(base_path_override).rstrip("/")

    ignore = _parse_ignore(section.get("ignore", ()), "matrix.ignore") + _parse_ignore(
        options.ignore, "options.ignore"
    )
    include = _parse_ignore(options.include, "options.include")
    target_prefix = target_base_path(config)
    permitted = options.permitted_methods

    operations: list[str] = []
    rows: list[tuple[str, str | None]] = []
    probes: list[PlannedProbe] = []
    skipped: list[SkippedProbe] = []
    used_specimens: dict[str, tuple[Specimen, ...]] = {}
    ignored_operations: list[str] = []
    #: Every operation `ignore` or `--include` kept out of the grid, for the
    #: refusal below when that is all of them.
    excluded_operations: set[str] = set()
    #: Which --include patterns actually selected something. A pattern is a
    #: promise about a set, and nothing anywhere told the operator that the
    #: matching is by PATH PREFIX -- so `--include 'GET /api/v1/invoices/{id}'`
    #: silently selected five operations, and `--include '.../*'` silently
    #: selected none and produced a clean-looking empty grid.
    matched_include: set[tuple[str | None, str]] = set()
    selected_include: set[tuple[str | None, str]] = set()

    for operation in inventory.operations:
        absolute = normalize_path(
            operation.absolute_path(_spec_base_path(operation, base_path_override))
        )
        key = f"{operation.method} {absolute}"
        operations.append(key)
        path_template = _request_path(absolute, target_prefix)
        # Before the operation can become a probe, a skipped cell, or a line in
        # the banner. A spec that declares an off-target path is refused whole:
        # silently dropping it would leave the operator believing the matrix
        # covered an operation it never sent, and planning it would send an
        # identity's credential to a host base_url never named.
        _assert_on_target(base_url, path_template, where=key)
        candidates = specimens.get(absolute, specimens.get(path_template, ()))
        if candidates:
            used_specimens[key] = candidates

        include_hits = {
            pattern
            for pattern in include
            if _matches([pattern], operation.method, absolute)
            or _matches([pattern], operation.method, path_template)
        }
        # Counted whatever the operation's fate below: the question this answers
        # is "did the operator's pattern name a real operation", and an
        # operation excluded for some other reason still answers it. Otherwise
        # `--include X --ignore X` reports X as a typo.
        matched_include |= include_hits

        reason: str | None = None
        if _matches(ignore, operation.method, absolute) or _matches(
            ignore, operation.method, path_template
        ):
            reason = "skipped_ignored"
            ignored_operations.append(key)
        elif include and not include_hits:
            reason = "skipped_ignored"
        elif operation.method not in permitted:
            reason = "skipped_mutating"
        elif _template_parameters(path_template) and not candidates:
            reason = "skipped_no_specimen"

        if reason == "skipped_ignored":
            excluded_operations.add(key)

        if include_hits and key not in ignored_operations:
            # Matched AND survived `ignore`. Kept apart from `matched_include`
            # so the refusal can tell "you spelled it wrong" from "ignore ate
            # it", which are opposite instructions to the operator. A cell
            # skipped for a mutating verb or a missing specimen still counts as
            # selected: the pattern named something real that ignore left alone.
            selected_include |= include_hits

        row_specimens: tuple[Specimen | None, ...]
        if _template_parameters(path_template) and candidates:
            row_specimens = candidates
        else:
            row_specimens = (None,)

        for specimen in row_specimens:
            label = specimen.label if specimen is not None else None
            rows.append((key, label))
            for identity in identities:
                values = (
                    specimen.values_for(identity) if specimen is not None else {}
                )
                if reason is None and values is None:
                    # A per-identity specimen that omits this identity: there is
                    # no object to request, so there is no observation. Recorded,
                    # never guessed at.
                    skipped.append(
                        SkippedProbe(
                            operation=key,
                            method=operation.method,
                            path_template=path_template,
                            identity=identity,
                            specimen=label,
                            path=path_template,
                            unknown_reason="skipped_no_specimen",
                        )
                    )
                    continue
                if reason is not None:
                    skipped.append(
                        SkippedProbe(
                            operation=key,
                            method=operation.method,
                            path_template=path_template,
                            identity=identity,
                            specimen=label,
                            path=path_template,
                            unknown_reason=reason,
                        )
                    )
                    continue
                concrete = (
                    _substitute(path_template, values) if values else path_template
                )
                # ``_substitute`` percent-encodes with ``safe=""`` so a specimen
                # cannot invent a segment, but the assertion is repeated over
                # the concrete path rather than reasoned about: this is the
                # exact string that becomes a URL.
                _assert_on_target(base_url, concrete, where=f"{key} ({label or 'no specimen'})")
                probes.append(
                    PlannedProbe(
                        operation=key,
                        method=operation.method,
                        path_template=path_template,
                        identity=identity,
                        specimen=label,
                        path=concrete,
                        mutating=operation.method not in MATRIX_SAFE_METHODS,
                    )
                )

    # A TOTAL miss is refused here, before a socket. A PARTIAL one rides on the
    # plan and is rendered by `banner()`. Printing it from this function put
    # prose on stdout from the layer whose whole job is to be a description --
    # "a complete, socket-free description of what a run would do" -- so a
    # caller reading the plan programmatically got 600 bytes it did not ask for
    # and could not see the warning in the object it was handed.
    unmatched_include: tuple[tuple[str | None, str], ...] = ()
    ignored_only_include: tuple[tuple[str | None, str], ...] = ()
    if include:
        known = tuple(dict.fromkeys(operations))
        ignored_only_include = tuple(
            pattern
            for pattern in include
            if pattern in matched_include and pattern not in selected_include
        )
        if len(ignored_only_include) == len(include):
            raise MatrixError(
                _include_ignored_message(ignored_only_include, all_of=True)
            )
        unmatched_include = tuple(
            pattern for pattern in include if pattern not in matched_include
        )
        if len(unmatched_include) == len(include):
            # Every pattern missed, so the selection is empty and the run would
            # send nothing. `map` does exit 3 on a matrix that measured nothing,
            # but it blames the target URL, the credentials and whether the
            # target is up -- none of which is the cause. Refused here instead,
            # naming the rules nobody could have guessed.
            raise MatrixError(
                _include_miss_message(unmatched_include, known, all_of=True)
            )

    # The general case of the two refusals above. Each include refusal sees one
    # rule emptying the grid; `--ignore '/'` alone, a matrix.ignore that covers
    # the spec, or an include whose patterns each half-missed empty it without
    # either firing. Excluded cells are deliberate skips -- right for a partial
    # exclusion, so a healthy run with `--ignore X` is not "incomplete" -- which
    # made such a run plan 0 requests, send nothing and exit 0, while a grid
    # that measured nothing is documented to exit 3. Refused here, before a
    # socket, as the include miss is.
    #
    # "Excluded every operation" was the wrong test, because it counted
    # operations the plan would never have probed anyway. `--ignore 'GET /'` on
    # a spec of GETs and writes, or an `--include` naming only a DELETE, left a
    # write or a specimen-less template, planned 0 requests and exited 0 under
    # `--require-complete` -- the same empty grid by another route. So the
    # test is now "the selection removed something and nothing is left to
    # probe". A selection that removed nothing (an ignore entry naming no
    # operation in the spec) left the plan exactly as it would be without one,
    # which is the deliberate unselected case: an all-mutating spec under the
    # read-only posture is not refused here.
    known_operations = tuple(dict.fromkeys(operations))
    if known_operations and excluded_operations and not probes:
        sources = [
            name
            for name, given in (
                ("matrix.ignore", section.get("ignore")),
                ("--ignore", options.ignore),
                ("--include", include),
            )
            if given
        ]
        left = [key for key in known_operations if key not in excluded_operations]
        if not left:
            raise MatrixError(
                _empty_selection_message(sources, len(known_operations))
            )
        reasons: dict[str, set[str]] = {}
        for item in skipped:
            if item.operation in left:
                reasons.setdefault(item.operation, set()).add(item.unknown_reason)
        raise MatrixError(
            _unprobed_selection_message(
                sources,
                len(known_operations),
                kept=len(left),
                mutating=sum(1 for key in left if "skipped_mutating" in reasons.get(key, ())),
                no_specimen=sum(
                    1 for key in left
                    if "skipped_mutating" not in reasons.get(key, ())
                ),
            )
        )

    timeout = options.timeout_seconds
    if timeout is None:
        declared = target.get("timeout_seconds", 10)
        timeout = (
            _validated_timeout(declared, "target.timeout_seconds")
            if isinstance(declared, (int, float)) and not isinstance(declared, bool)
            else 10.0
        )

    plan = MatrixPlan(
        base_url=base_url,
        host=host,
        target_class=target_class,
        operations=tuple(dict.fromkeys(operations)),
        identities=identities,
        rows=tuple(rows),
        probes=tuple(probes),
        skipped=tuple(skipped),
        specimens=tuple(sorted(used_specimens.items())),
        options=options,
        inventory_operations=len(inventory.operations),
        ignored=tuple(dict.fromkeys(ignored_operations)),
        marker_owner=marker_owner,
        timeout_seconds=float(timeout),
        unmatched_include=unmatched_include,
        ignored_only_include=ignored_only_include,
    )
    plan.refuse_if_unsafe()
    # The budget refusal is deferrable ONLY for `--dry-run`, which sends
    # nothing: refusing to describe a plan because it is too large to run is
    # refusing the one command that would have told the operator how to shrink
    # it. `execute_matrix` calls this itself, so nothing can be SENT over
    # budget regardless -- the safety property is unchanged, and the safety
    # refusals above still fire here for every caller.
    if not defer_budget:
        plan.refuse_if_over_budget()
    return plan


#: How many operations a --include miss lists before it summarises the rest.
INCLUDE_MISS_EXAMPLES: int = 5


def _include_patterns(patterns: Sequence[tuple[str | None, str]]) -> str:
    return ", ".join(
        f"{method + ' ' if method else ''}{template}" for method, template in patterns
    )


def _include_ignored_message(
    only_ignored: Sequence[tuple[str | None, str]], *, all_of: bool
) -> str:
    """Explain an --include whose only matches `ignore` had already removed.

    Distinct from the miss message on purpose: those patterns DID name real
    operations, so "matched none of the N operations in the specification"
    followed by a lecture on prefix matching sends the operator to fix a
    spelling that is already correct.
    """
    message = (
        f"--include {_include_patterns(only_ignored)} matched only operations "
        "that `ignore` removes. Ignore is applied first and wins, so nothing "
        "they selected is probed. Drop the matrix.ignore / --ignore entry, or "
        "the --include one."
    )
    return message + " Nothing has been sent." if all_of else message


def _empty_selection_message(sources: Sequence[str], operations: int) -> str:
    """Explain an `ignore` / `--include` selection that left nothing to probe."""
    named = sources[0] if len(sources) == 1 else (
        ", ".join(sources[:-1]) + " and " + sources[-1]
    )
    fix = "Remove an ignore entry" + (
        " or widen --include" if "--include" in sources else ""
    )
    return (
        f"{named} {'leaves' if len(sources) == 1 else 'together leave'} none of "
        f"the {operations} operations in the specification to probe, so the "
        "matrix would send nothing and record a grid that measured nothing, "
        f"which is not a pass. {fix}. Nothing has been sent."
    )


def _unprobed_selection_message(
    sources: Sequence[str],
    operations: int,
    *,
    kept: int,
    mutating: int,
    no_specimen: int,
) -> str:
    """Explain a selection whose remaining operations are none of them probed.

    Said apart from :func:`_empty_selection_message` because the selection did
    leave operations; "leaves none of the N operations" would be false, and
    the operator needs to know why the ones it left are not sent. The two
    counts use the banner's own words.
    """
    named = sources[0] if len(sources) == 1 else (
        ", ".join(sources[:-1]) + " and " + sources[-1]
    )
    why = ", ".join(
        part
        for part in (
            f"{mutating} skipped as non-read-only" if mutating else "",
            f"{no_specimen} for want of a specimen" if no_specimen else "",
        )
        if part
    )
    # Widening the selection changes WHICH operations are probed. An operation
    # the selection kept and that waits only on a specimen is probed by giving
    # it one, and the refusal used to name only the selection fixes.
    parts = [
        part
        for part in (
            "remove an ignore entry"
            if any(source != "--include" for source in sources) else "",
            "widen --include" if "--include" in sources else "",
            "add a matrix.specimens entry naming a real object for each "
            "templated route without one" if no_specimen else "",
        )
        if part
    ]
    fix = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " or " + parts[-1]
    fix = fix[:1].upper() + fix[1:]
    return (
        f"{named} {'leaves' if len(sources) == 1 else 'together leave'} "
        f"{kept} of the {operations} operations in the specification, and none "
        f"of those is probed ({why}), so the matrix would send nothing and "
        "record a grid that measured nothing, which is not a pass. "
        f"{fix}. Nothing has been sent."
    )


def _include_miss_message(
    unmatched: Sequence[tuple[str | None, str]],
    operations: Sequence[str],
    *,
    all_of: bool,
) -> str:
    """Explain an --include that selected nothing, and how the matching works.

    The rules are not guessable and were written down nowhere: not in the help
    text, not in the README, not in a test. A prefix match that also selects
    every route beneath it looks like an exact match until the request count is
    five times what was authorised, and a `*` looks like a glob until the grid
    comes back empty.
    """
    shown = _include_patterns(unmatched)
    examples = "\n".join(f"    {key}" for key in operations[:INCLUDE_MISS_EXAMPLES])
    more = len(operations) - INCLUDE_MISS_EXAMPLES
    if more > 0:
        examples += f"\n    ... and {more} more"
    head = (
        f"--include {shown} matched none of the {len(operations)} "
        "operations in the specification"
    )
    if all_of:
        head += ", so the matrix would probe nothing. Nothing has been sent."
    else:
        head += (
            ". The rest of the selection is intact and the run continues; those "
            "routes are simply not in it."
        )
    head = textwrap.fill(head, width=78)
    return (
        f"{head}\n\n"
        "  --include matches by PATH PREFIX. It is not a glob and not a regex:\n"
        "    '*' is an ordinary character and matches only a literal '*' segment\n"
        "    '{id}' must be spelled exactly as the specification spells it\n"
        "    paths are compared case-sensitively\n"
        "    a match selects the route AND everything beneath it, so\n"
        "    '/api/invoices/{id}' also selects '/api/invoices/{id}/lines'\n\n"
        f"  The specification declares:\n{examples}"
    )


def _matches(
    patterns: Sequence[tuple[str | None, str]], method: str, path: str
) -> bool:
    for wanted_method, template in patterns:
        if wanted_method is not None and wanted_method != method:
            continue
        if template == path or path.startswith(template.rstrip("/") + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# cells and matrix
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Cell:
    """One observation, or one recorded absence of an observation.

    Built exclusively from ``core._perform_request``'s return dict plus a
    run-salted digest. It carries no header, no cookie, no token, no body text,
    and no query value -- see the module docstring.
    """

    operation: str
    identity: str
    specimen: str | None
    url_path: str
    outcome: str
    reach: str
    status: int | None = None
    status_class: str | None = None
    refusal_kind: str | None = None
    duration_ms: float | None = None
    body_bytes: int | None = None
    body_empty: bool | None = None
    body_digest: str | None = None
    marker_scan: str | None = None
    marker_owner: str | None = None
    unknown_reason: str | None = None

    @property
    def measured(self) -> bool:
        """True only when a rule may read this cell.

        ``outcome`` and ``reach`` are kept in agreement: a 429 or a 5xx did
        produce a response, but it says nothing about the boundary, so it is not
        an observation any rule may use.
        """
        return self.outcome == OUTCOME_OBSERVED and self.reach != REACH_UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "identity": self.identity,
            "specimen": self.specimen,
            "url_path": self.url_path,
            "outcome": self.outcome,
            "reach": self.reach,
            "status": self.status,
            "status_class": self.status_class,
            "refusal_kind": self.refusal_kind,
            "duration_ms": self.duration_ms,
            "body_bytes": self.body_bytes,
            "body_empty": self.body_empty,
            "body_digest": self.body_digest,
            "marker_scan": self.marker_scan,
            "marker_owner": self.marker_owner,
            "unknown_reason": self.unknown_reason,
        }


@dataclass(frozen=True)
class AccessMatrix:
    """A dense grid of cells, plus the safety facts about how it was gathered."""

    base_url: str
    host: str
    target_class: str
    operations: tuple[str, ...]
    identities: tuple[str, ...]
    rows: tuple[tuple[str, str | None], ...]
    cells: tuple[Cell, ...]
    planned: int
    issued: int
    aborted: bool = False
    abort_reason: str | None = None
    read_only: bool = True
    permitted_methods: tuple[str, ...] = tuple(sorted(MATRIX_SAFE_METHODS))
    requests_per_second: float = MATRIX_DEFAULT_RPS
    max_specimens: int = 1
    shared_specimen_rows: tuple[tuple[str, str | None], ...] = ()
    ignored: tuple[str, ...] = ()
    marker_owner: str | None = None
    on_retry_after: str = ON_RETRY_AFTER_DEFAULT
    #: How many 429s carried the header. Recorded because the policy above
    #: changes what the run did, and an artifact that does not say so leaves a
    #: reviewer comparing two matrices gathered under different rules.
    retry_after_seen: int = 0

    def _index(self) -> dict[tuple[str, str, str | None], Cell]:
        cached = getattr(self, "_cell_index", None)
        if cached is None:
            cached = {
                (cell.operation, cell.identity, cell.specimen): cell
                for cell in self.cells
            }
            object.__setattr__(self, "_cell_index", cached)
        return cached

    def cell(
        self, operation: str, identity: str, specimen: str | None = None
    ) -> Cell | None:
        return self._index().get((operation, identity, specimen))

    def row(self, identity: str) -> tuple[Cell, ...]:
        """Every cell for one identity: the input to that identity's reach."""
        return tuple(cell for cell in self.cells if cell.identity == identity)

    def column(self, operation: str) -> tuple[Cell, ...]:
        """Every cell for one operation, across identities."""
        return tuple(cell for cell in self.cells if cell.operation == operation)

    def is_shared_specimen(self, operation: str, specimen: str | None) -> bool:
        """Whether all identities were probed against the SAME object.

        A per-identity specimen means the identities requested different
        objects, so comparing their outcomes is meaningless. This is a
        correctness gate for the projection module, not a heuristic.

        Membership is strict: a row this matrix does not list as shared is not
        shared. The unknown case therefore suppresses a comparison rather than
        licensing one, because a comparison across two different objects
        produces a confidently wrong candidate.
        """
        return (operation, specimen) in self.shared_specimen_rows

    def counts(self) -> dict[str, int]:
        totals = {value: 0 for value in REACH_VALUES}
        for cell in self.cells:
            totals[cell.reach] += 1
        totals["cells"] = len(self.cells)
        return totals


class Prober(Protocol):
    """Issues one planned probe and returns ``core._perform_request``'s dict.

    A prober may add a boolean ``retry_after`` key (presence of the header, never
    its value); ``core._perform_request`` supplies the same boolean inside
    ``response``, and :func:`execute_matrix` honours either. Nothing else is read
    from the result.
    """

    def __call__(self, probe: PlannedProbe) -> Mapping[str, Any]:  # pragma: no cover
        ...


def default_prober(
    config: Mapping[str, Any], *, timeout_seconds: float | None = None
) -> Prober:
    """Build the real prober. The only place this module touches ``core``.

    ``core`` is imported here, inside the function body, so importing
    ``matrix`` (or anything that projects over it) never pulls in the request
    machinery. Requests go through ``core._perform_request`` unchanged, which
    means the shared opener, the no-redirect handler, the identity
    Accept-Encoding override, and the in-memory-only body scan all apply. No
    ``sink`` is passed, so no header and no body byte can reach this module.

    ``timeout_seconds`` is the per-request timeout; pass the plan's
    (``MatrixPlan.timeout_seconds``), which is the one the banner prints.
    Without it the prober falls back to ``target.timeout_seconds`` -- which
    is how ``map --timeout`` once changed the banner and no request.
    """
    from veridor import core  # noqa: PLC0415 -- request path only, see docstring

    target = config["target"]
    base_url = target["base_url"]
    if timeout_seconds is not None:
        timeout = _validated_timeout(timeout_seconds, "timeout_seconds")
    else:
        declared = target.get("timeout_seconds", 10)
        timeout = (
            _validated_timeout(declared, "target.timeout_seconds")
            if isinstance(declared, (int, float)) and not isinstance(declared, bool)
            else 10.0
        )
    identities = config["identities"]
    section = _matrix_section(config)
    owner = _marker_owner(config, section)
    marker = identities[owner].get("marker") if owner else None

    def prober(probe: PlannedProbe) -> Mapping[str, Any]:
        identity = identities[probe.identity]
        request_config = {"method": probe.method, "path": probe.path}
        return core._perform_request(
            base_url, timeout, request_config, identity, marker=marker
        )

    return prober


class _AbortState:
    """Stops the run on signals that mean "you are not welcome here"."""

    def __init__(self, *, stop_on_retry_after: bool = False) -> None:
        self.stop_on_retry_after = stop_on_retry_after
        self.retry_after_seen = 0
        self.issued = 0
        self.hostile = 0
        self.total_rate_limited = 0
        self.consecutive_rate_limited = 0
        self.consecutive_server_error = 0
        self.consecutive_transport = 0
        self.reason: str | None = None

    def observe(self, status: int | None, error: Any, retry_after: bool) -> str | None:
        self.issued += 1
        if status == 429:
            self.consecutive_rate_limited += 1
            self.consecutive_server_error = 0
            self.consecutive_transport = 0
            self.hostile += 1
            self.total_rate_limited += 1
            if retry_after:
                self.retry_after_seen += 1
                # `Retry-After` is "come back in N seconds", not "go away", and
                # reading it as the second cost a spec-compliant limiter 3.5x
                # the grid coverage of a rude one emitting identical 429s: this
                # branch returned before the two rules below, so the header
                # bought a tolerance of ONE 429 against their three and five.
                # The header is still the last word when the operator asks for
                # that with --on-retry-after stop, and it is still the reason
                # recorded when a polite target exhausts the ordinary budget --
                # `rate_limited` would name the rule and lose the courtesy.
                if self.stop_on_retry_after:
                    return self.stop("retry_after_requested")
                if (
                    self.consecutive_rate_limited >= ABORT_CONSECUTIVE_RATE_LIMITED
                    or self.total_rate_limited >= ABORT_TOTAL_RATE_LIMITED
                ):
                    return self.stop("retry_after_requested")
            if self.consecutive_rate_limited >= ABORT_CONSECUTIVE_RATE_LIMITED:
                return self.stop("rate_limited")
            if self.total_rate_limited >= ABORT_TOTAL_RATE_LIMITED:
                # Cumulative, because the streak rule and the share rule both
                # miss the ordinary leaky-bucket shape: a burst draws a 429, the
                # bucket refills, and the 429s are neither consecutive nor a
                # large enough fraction to trip anything. Isolated throttles are
                # still throttles.
                return self.stop("rate_limited_total")
        elif status is not None and 500 <= status <= 599:
            self.consecutive_server_error += 1
            self.consecutive_rate_limited = 0
            self.consecutive_transport = 0
            self.hostile += 1
            if self.consecutive_server_error >= ABORT_CONSECUTIVE_SERVER_ERROR:
                return self.stop("server_error")
        elif status is None or error:
            self.consecutive_transport += 1
            self.consecutive_rate_limited = 0
            self.consecutive_server_error = 0
            if self.consecutive_transport >= ABORT_CONSECUTIVE_TRANSPORT:
                return self.stop("transport")
        else:
            self.consecutive_rate_limited = 0
            self.consecutive_server_error = 0
            self.consecutive_transport = 0
        if (
            self.issued >= ABORT_HOSTILE_MINIMUM
            # ``>=``, not ``>``: with a strict comparison the documented 20%
            # threshold actually sat at 25%, so one-in-five hostile responses
            # ran the plan to completion.
            and self.hostile >= self.issued * ABORT_HOSTILE_SHARE
        ):
            return self.stop("hostile_rate")
        return None

    def stop(self, reason: str) -> str:
        self.reason = reason
        return reason


#: How many times the injected sleeper is given the chance to honour a wait
#: before the real clock takes over. Small: this is a seam, not a strategy.
_THROTTLE_ATTEMPTS: int = 3

#: How far the injected clock may run ahead of what can account for it before
#: it stops being trusted. Covers the order the two clocks are read in, nothing
#: more.
_CLOCK_SLACK_SECONDS: float = 0.001


def _throttle(
    last_started: float, last_real: float, interval: float, clock: Any, sleeper: Any
) -> None:
    """Do not return before ``interval`` has passed since the last request.

    The rate limit was the one control in this module that a public keyword
    argument could switch off: ``sleeper=lambda _: None`` turned a declared
    1 req/s into 400,000 req/s with nothing raised, while the plan, the banner
    and the artifact all continued to report the declared rate. ``max_requests``
    has an un-overridable ceiling re-derived inside :func:`execute_matrix`
    precisely so a future caller cannot skip it; the interval now has the same
    property.

    With the default ``clock`` (``time.monotonic``) this holds in real time
    whatever ``sleeper`` does, and that is the only clock the CLI uses.

    An injected ``clock`` is a test seam, and its verdict is accepted when,
    after the sleeper calls, it reads at or past the deadline and has advanced
    since ``last_started`` by no more than the larger of the real time elapsed
    and the total of the waits asked of the sleeper (plus
    :data:`_CLOCK_SLACK_SECONDS` for the order the clocks are read in). Two
    shapes fail that and
    are served against the real monotonic clock instead (``last_real`` is when
    the previous request started on it):

    * a clock still short of the deadline after a few sleeper calls -- the
      sleeper does not advance it -- is served with ``time.sleep``;
    * a clock that runs ahead of both real time and the waits asked of the
      sleeper -- a counter, a clock in milliseconds -- is not accepted. It used
      to satisfy every deadline without any wait: 40 requests at a declared
      1 req/s went out in 0.0005s. A fake clock that also advances outside the
      sleeper, say to simulate latency in the prober, is this shape too, so
      each of its requests costs a real interval.

    Every other injected clock is trusted, not checked. The waits it is
    measured against are computed from its own readings, so this cannot tell
    the ordinary test shape -- a fake clock the sleeper advances by exactly
    the wait, which never touches real time -- from a clock that holds still
    across the sleeper calls and then jumps by up to the total asked, or one
    that reads backwards and so inflates the waits. Each of those passes with
    a sleeper that does nothing. Only a library caller can pass a clock.
    """
    deadline = last_started + interval
    asked = 0.0
    for _ in range(_THROTTLE_ATTEMPTS):
        wait = deadline - clock()
        if wait <= 0:
            break
        sleeper(wait)
        asked += wait
    real_elapsed = time.monotonic() - last_real
    now = clock()
    if now >= deadline and now - last_started <= max(real_elapsed, asked) + _CLOCK_SLACK_SECONDS:
        return
    # Bounded by one interval from the previous request's real start, so a
    # nonsensical injected clock cannot stall the run: the guarantee needed is
    # "not faster than the declared rate", and one real interval delivers
    # exactly that.
    target = last_real + interval
    while True:
        left = target - time.monotonic()
        if left <= 0:
            return
        time.sleep(left)


def _assert_result_on_target(
    base_url: str, probe: PlannedProbe, result: Mapping[str, Any]
) -> None:
    """The URL that was actually requested must be on the target's origin.

    The pre-send assertion covers every path this module plans. This covers the
    prober: a caller-supplied one is arbitrary code, and a matrix whose cells
    keep only ``urlsplit(url).path`` would otherwise record ``/steal`` with no
    host and no way for a reviewer to see that a request left the target.
    """
    request = result.get("request")
    url = request.get("url") if isinstance(request, Mapping) else None
    if not isinstance(url, str) or not url:
        return
    if not same_origin(base_url, url):
        raise MatrixSafetyError(
            f"the prober issued {probe.operation} as {probe.identity} to {quoted(url)}, "
            f"which is not on target.base_url's origin ({quoted(base_url)}). Identity "
            "credentials travel with every probe, so the run is abandoned rather "
            "than recorded: the matrix keeps only a URL's path, and this would be "
            "invisible in the artifact."
        )


def _digest(salt: bytes, body_sha256: Any) -> str | None:
    """Salt core's body hash so it is comparable within a run and nowhere else.

    The body itself never leaves ``core``, so the salt is applied to the digest
    core computed. Equality semantics are identical -- same bytes give the same
    value within one run -- while a dictionary attack on a small API body
    (``{"ok":true}``, ``[]``) needs the salt, which is never persisted.
    """
    if not isinstance(body_sha256, str) or not body_sha256:
        return None
    return hashlib.sha256(salt + body_sha256.encode("ascii", "ignore")).hexdigest()[:32]


def _cell_from_result(
    probe: PlannedProbe,
    result: Mapping[str, Any],
    salt: bytes,
    marker_owner: str | None,
) -> Cell:
    response = result.get("response") or {}
    request = result.get("request") or {}
    error = result.get("error")
    status = response.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        status = None
    if error:
        reach, refusal, unknown_reason = (REACH_UNKNOWN, None, "transport_error")
        status = None
    else:
        reach, refusal, unknown_reason = classify_reach(status)
    url = request.get("url")
    url_path = urlsplit(url).path if isinstance(url, str) and url else probe.path
    body_bytes = response.get("body_bytes")
    if isinstance(body_bytes, bool) or not isinstance(body_bytes, int):
        body_bytes = None
    duration = response.get("duration_ms")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        duration = None
    marker_scan = response.get("marker_scan")
    if not isinstance(marker_scan, str):
        marker_scan = None
    measured = reach != REACH_UNKNOWN
    return Cell(
        operation=probe.operation,
        identity=probe.identity,
        specimen=probe.specimen,
        url_path=url_path,
        outcome=OUTCOME_OBSERVED if measured else OUTCOME_UNKNOWN,
        reach=reach,
        status=status,
        status_class=status_class(status) if status is not None else None,
        refusal_kind=refusal,
        duration_ms=float(duration) if duration is not None else None,
        body_bytes=body_bytes,
        body_empty=(body_bytes == 0) if body_bytes is not None else None,
        body_digest=_digest(salt, response.get("body_sha256")),
        marker_scan=marker_scan,
        marker_owner=marker_owner if marker_scan else None,
        unknown_reason=unknown_reason,
    )


def _unknown_cell(
    operation: str,
    identity: str,
    specimen: str | None,
    url_path: str,
    reason: str,
) -> Cell:
    if reason not in UNKNOWN_REASONS:  # pragma: no cover - programming error
        raise MatrixError(f"unknown_reason {quoted(reason)} is not in the closed set")
    return Cell(
        operation=operation,
        identity=identity,
        specimen=specimen,
        url_path=url_path,
        outcome=OUTCOME_UNKNOWN,
        reach=REACH_UNKNOWN,
        unknown_reason=reason,
    )


def execute_matrix(
    plan: MatrixPlan,
    *,
    prober: Prober,
    clock: Any = time.monotonic,
    sleeper: Any = time.sleep,
) -> AccessMatrix:
    """Issue the plan, sequentially and rate limited, and build the grid.

    Every safety gate is re-checked here before the first call to ``prober``,
    so a caller that skipped ``plan_matrix``'s checks -- or hand-built a plan --
    still cannot send anything the envelope forbids. The wall clock is
    enforced against the real monotonic clock rather than against ``clock``.

    ``clock`` and ``sleeper`` are test seams for *observing* the limiter. With
    the default ``clock``, the only one the CLI uses, :func:`_throttle` serves
    the interval in real time whatever ``sleeper`` does, so a ``--no-throttle``
    flag wired to ``sleeper`` cannot exist -- the rate limit is the only
    control bounding instantaneous load on the target, and the run document
    reports the rate as though it had been honoured. An injected ``clock`` is
    checked for two shapes only, one that does not reach the deadline and one
    that runs ahead of real time and of the waits asked of the sleeper; both are
    served in real time. Any other injected clock is trusted, not checked: the
    seam's fake clock advanced by exactly the wait, but also a clock that holds
    still across the sleeper calls and then jumps, or one that reads
    backwards. See :func:`_throttle`.
    """
    plan.refuse_if_unsafe()
    plan.refuse_if_over_budget()

    salt = secrets.token_bytes(32)
    interval = 1.0 / plan.options.requests_per_second
    deadline = time.monotonic() + plan.options.max_run_seconds
    abort = _AbortState(
        stop_on_retry_after=plan.options.on_retry_after == "stop"
    )
    cells: dict[tuple[str, str, str | None], Cell] = {}

    for item in plan.skipped:
        cells[(item.operation, item.identity, item.specimen)] = _unknown_cell(
            item.operation,
            item.identity,
            item.specimen,
            item.path,
            item.unknown_reason,
        )

    issued = 0
    last_started: float | None = None
    last_real = 0.0
    aborted = False
    for probe in plan.probes:
        key = (probe.operation, probe.identity, probe.specimen)
        if aborted:
            cells[key] = _unknown_cell(*key, probe.path, "aborted")
            continue
        if time.monotonic() >= deadline:
            # Real time, not ``clock``: ``estimated_seconds`` counts the rate
            # limiter and nothing else, so a slow or half-open target is exactly
            # the case this exists for, and it is not a case a fake clock should
            # be able to wish away.
            aborted = True
            abort.stop("time_limit")
            cells[key] = _unknown_cell(*key, probe.path, "aborted")
            continue
        if last_started is not None:
            # Global, not per-identity: total load on the target is what needs
            # bounding.
            _throttle(last_started, last_real, interval, clock, sleeper)
        last_started = clock()
        last_real = time.monotonic()
        result = prober(probe)
        issued += 1
        if not isinstance(result, Mapping):  # pragma: no cover - contract breach
            raise MatrixError("prober must return a mapping")
        _assert_result_on_target(plan.base_url, probe, result)
        cells[key] = _cell_from_result(probe, result, salt, plan.marker_owner)
        response = result.get("response") or {}
        # Two places, one meaning. The Prober protocol documents a top-level
        # ``retry_after`` for a custom prober that can see headers;
        # ``core._perform_request`` carries the same presence-only boolean
        # inside ``response``, which is what the DEFAULT prober returns. Reading
        # only the first left the ``retry_after_requested`` abort unreachable in
        # the shipped configuration.
        retry_after = bool(result.get("retry_after") or response.get("retry_after"))
        if abort.observe(response.get("status"), result.get("error"), retry_after):
            aborted = True

    for row_operation, row_specimen in plan.rows:
        for identity in plan.identities:
            key = (row_operation, identity, row_specimen)
            if key not in cells:  # pragma: no cover - defensive density guard
                cells[key] = _unknown_cell(
                    row_operation, identity, row_specimen, row_operation, "not_probed"
                )

    ordered: list[Cell] = []
    for row_operation, row_specimen in plan.rows:
        for identity in plan.identities:
            ordered.append(cells[(row_operation, identity, row_specimen)])

    per_identity_rows = {
        (operation, specimen.label)
        for operation, items in plan.specimens
        for specimen in items
        if not specimen.shared
    }
    shared_rows = tuple(row for row in plan.rows if row not in per_identity_rows)
    return AccessMatrix(
        base_url=plan.base_url,
        host=plan.host,
        target_class=plan.target_class,
        operations=plan.operations,
        identities=plan.identities,
        rows=plan.rows,
        cells=tuple(ordered),
        planned=plan.requests_planned,
        issued=issued,
        aborted=aborted,
        abort_reason=abort.reason,
        read_only=plan.options.read_only,
        permitted_methods=tuple(sorted(plan.options.permitted_methods)),
        requests_per_second=plan.options.requests_per_second,
        max_specimens=plan.max_specimens,
        shared_specimen_rows=shared_rows,
        ignored=plan.ignored,
        marker_owner=plan.marker_owner,
        on_retry_after=plan.options.on_retry_after,
        retry_after_seen=abort.retry_after_seen,
    )


# ---------------------------------------------------------------------------
# serialisation
# ---------------------------------------------------------------------------


def matrix_document(matrix: AccessMatrix) -> dict[str, Any]:
    """The ``veridor.matrix`` artifact. Contains observations, never evidence.

    Written under ``output_dir/matrix/``, never into ``latest.json`` and never
    merged into a run document: a matrix is not a run and its cells are not
    findings.
    """
    counts = matrix.counts()
    document: dict[str, Any] = {
        "kind": MATRIX_KIND,
        "schema_version": SCHEMA_VERSION,
        "claim": dict(CLAIM),
        "limitation": OPERATION_LEVEL_LIMITATION.format(
            specimens=matrix.max_specimens
        ),
        "safety": {
            "posture": SAFETY_POSTURE,
            "read_only": matrix.read_only,
            "permitted_methods": list(matrix.permitted_methods),
            "requests_per_second": matrix.requests_per_second,
            "concurrency": "sequential",
            "retries": 0,
            "follows_redirects": False,
            "planned": matrix.planned,
            "issued": matrix.issued,
            "aborted": matrix.aborted,
            "abort_reason": matrix.abort_reason,
            "on_retry_after": matrix.on_retry_after,
            "retry_after_seen": matrix.retry_after_seen,
        },
        "target": {
            "base_url": _safe_base_url(matrix.base_url),
            "host": matrix.host,
            "target_class": matrix.target_class,
        },
        "identities": list(matrix.identities),
        "operations": list(matrix.operations),
        "max_specimens": matrix.max_specimens,
        "rows": [
            {
                "operation": operation,
                "specimen": specimen,
                "shared_specimen": matrix.is_shared_specimen(operation, specimen),
            }
            for operation, specimen in matrix.rows
        ],
        "ignored": list(matrix.ignored),
        "marker_owner": matrix.marker_owner,
        "counts": counts,
        "cells": [cell.to_dict() for cell in matrix.cells],
    }
    return document


def _safe_base_url(base_url: str) -> str:
    """Scheme, host, port and path only. No credentials, no query."""
    parsed = urlsplit(base_url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}{parsed.path}"


def load_matrix(path: Path) -> AccessMatrix:
    """Read a ``veridor.matrix`` document back into an :class:`AccessMatrix`."""
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MatrixError(f"access matrix not found: {path}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"invalid JSON in {path}: {exc}") from exc
    return matrix_from_document(document)


def matrix_from_document(document: Mapping[str, Any]) -> AccessMatrix:
    """Rebuild an :class:`AccessMatrix` from a decoded document."""
    if not isinstance(document, Mapping):
        raise MatrixError("access matrix document must be an object")
    if document.get("kind") != MATRIX_KIND:
        raise MatrixError(
            f"document kind {quoted(document.get('kind'))} is not {quoted(MATRIX_KIND)}"
        )
    if document.get("schema_version") != SCHEMA_VERSION:
        raise MatrixError(
            f"access matrix schema_version {quoted(document.get('schema_version'))} is not "
            f"supported (this build reads {SCHEMA_VERSION})"
        )
    safety = document.get("safety") or {}
    target = document.get("target") or {}
    cells: list[Cell] = []
    for raw in document.get("cells") or ():
        if not isinstance(raw, Mapping):
            raise MatrixError("every cell must be an object")
        reach = raw.get("reach")
        if reach not in REACH_VALUES:
            raise MatrixError(f"cell reach {quoted(reach)} is not one of {REACH_VALUES}")
        reason = raw.get("unknown_reason")
        if reach == REACH_UNKNOWN and reason not in UNKNOWN_REASONS:
            raise MatrixError(
                f"an unknown cell must carry a reason from the closed set, got "
                f"{quoted(reason)}"
            )
        cells.append(
            Cell(
                operation=str(raw.get("operation")),
                identity=str(raw.get("identity")),
                specimen=raw.get("specimen"),
                url_path=str(raw.get("url_path", "")),
                outcome=str(raw.get("outcome", OUTCOME_UNKNOWN)),
                reach=str(reach),
                status=raw.get("status"),
                status_class=raw.get("status_class"),
                refusal_kind=raw.get("refusal_kind"),
                duration_ms=raw.get("duration_ms"),
                body_bytes=raw.get("body_bytes"),
                body_empty=raw.get("body_empty"),
                body_digest=raw.get("body_digest"),
                marker_scan=raw.get("marker_scan"),
                marker_owner=raw.get("marker_owner"),
                unknown_reason=reason,
            )
        )
    rows_raw = document.get("rows") or ()
    rows = tuple(
        (str(row.get("operation")), row.get("specimen"))
        for row in rows_raw
        if isinstance(row, Mapping)
    )
    # Strict, as is_shared_specimen promises: a row that does not say it is
    # shared is not. Defaulting a missing key to True -- and reading "false" as
    # truthy -- licensed peer_divergence to compare two identities' answers
    # about two different objects. Veridor's writer always emits a bool, so
    # anything else is a document this module did not write.
    for row in rows_raw:
        if isinstance(row, Mapping) and "shared_specimen" in row and not isinstance(
            row["shared_specimen"], bool
        ):
            raise MatrixError(
                f"row {quoted(row.get('operation'))} has shared_specimen "
                f"{quoted(row['shared_specimen'])}; it must be true or false"
            )
    shared = tuple(
        (str(row.get("operation")), row.get("specimen"))
        for row in rows_raw
        if isinstance(row, Mapping) and row.get("shared_specimen") is True
    )
    return AccessMatrix(
        base_url=str(target.get("base_url", "")),
        host=str(target.get("host", "")),
        target_class=str(target.get("target_class", "public")),
        operations=tuple(str(item) for item in document.get("operations") or ()),
        identities=tuple(str(item) for item in document.get("identities") or ()),
        rows=rows,
        cells=tuple(cells),
        planned=int(safety.get("planned", 0) or 0),
        issued=int(safety.get("issued", 0) or 0),
        aborted=bool(safety.get("aborted", False)),
        abort_reason=safety.get("abort_reason"),
        on_retry_after=str(
            safety.get("on_retry_after") or ON_RETRY_AFTER_DEFAULT
        ),
        retry_after_seen=int(safety.get("retry_after_seen", 0) or 0),
        read_only=bool(safety.get("read_only", True)),
        permitted_methods=tuple(
            str(item) for item in safety.get("permitted_methods") or ()
        ),
        requests_per_second=float(
            safety.get("requests_per_second", MATRIX_DEFAULT_RPS) or MATRIX_DEFAULT_RPS
        ),
        max_specimens=int(document.get("max_specimens", 1) or 1),
        shared_specimen_rows=shared,
        ignored=tuple(str(item) for item in document.get("ignored") or ()),
        marker_owner=document.get("marker_owner"),
    )
