"""Configuration, execution, regression comparison, and report generation."""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import html
import http.client
import io
import ipaddress
import json
import math
import os
import posixpath
import re
import secrets
import socket
import ssl
import sys
import time
import traceback
import zlib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, NamedTuple, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import (
    SplitResult,
    parse_qsl,
    quote_plus,
    unquote,
    unquote_plus,
    unquote_to_bytes,
    urljoin,
    urlsplit,
    urlunsplit,
)
from urllib.request import (  # noqa: PLC2701 -- _parse_proxy: see _via_proxy
    AbstractHTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    _parse_proxy,
    build_opener,
    getproxies_environment,
    proxy_bypass_environment,
)

from veridor import redaction
from veridor.credentials import is_benign_header, presents_credential  # noqa: F401
from veridor.coverage import (
    AUTHN_STATUSES,
    DEFAULT_DENIAL_STATUSES,
    classify_expectation,
)
# Re-exported: every refusal site in this module and its callers quote the
# input through these (see veridor.terminal).
from veridor.terminal import (  # noqa: F401 -- re-exported
    ECHO_LIMIT,
    quoted,
    terminal_controls,
    terminal_names,
    terminal_text,
)


class ConfigError(ValueError):
    """Raised when a Veridor configuration is invalid."""


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_INVALID_HEADER_VALUE = re.compile(r"[\x00-\x08\x0A-\x1F\x7F]")
_MAX_RESPONSE_BYTES = 1024 * 1024

SCHEMA_VERSION: int = 2
#: A run is written with this version IFF the config declared at least one
#: sequence. Otherwise it is written with ``SCHEMA_VERSION``, byte-identically
#: to today. The bump exists so an older ``veridor report`` handed a document
#: full of step findings exits 2 rather than rendering an under-reported
#: summary -- the same fail-closed logic the config version gate applies.
SEQUENCE_SCHEMA_VERSION: int = 3
SUPPORTED_RUN_SCHEMA_VERSIONS: frozenset[int] = frozenset({1, 2, 3})
SUPPORTED_CONFIG_VERSIONS: frozenset[int] = frozenset({1, 2})
EVIDENCE_GRADES: tuple[str, ...] = ("n/a", "ungraded", "suspected", "confirmed")

#: The contract, in one sentence. Veridor measures observed behaviour and
#: compares it against a declaration the operator wrote; it never audits the
#: declaration. An over-strict expectation is indistinguishable from a real
#: break, so this sentence must accompany every count of findings Veridor
#: prints and every report it emits. A correct, entitled read grades
#: 'confirmed' when the declaration forbids it: the declaration is what is
#: wrong, and the finding reads like any other.
#:
#: ASCII only: this is printed on every run, including on consoles whose
#: encoding cannot represent typographic punctuation.
DECLARATION_SCOPE: str = (
    "Veridor evaluates the expectations you declared. A finding means observed "
    "behaviour differed from your declaration; it does not establish that the "
    "declaration is correct."
)

#: The symmetric sentence, for the outcome a reader is most likely to
#: over-read. ``DECLARATION_SCOPE`` qualifies what a FINDING means; nothing
#: qualified what a PASS means, so a run reporting "N/N probes matched" read as
#: a clean bill of health. It is not one: a probe that matched its declaration
#: agreed with the operator's configuration for exactly one request, and an
#: expectation that accepts both access and denial matches trivially.
#:
#: ASCII only, for the same reason as ``DECLARATION_SCOPE``.
PASS_SCOPE: str = (
    "A matched probe means the target agreed with your declaration for that "
    "one request. It is not evidence that the boundary is enforced, and an "
    "expectation that accepts both access and denial matches trivially."
)

#: Statuses in which the target REFUSED the request. Sourced from the coverage
#: module rather than restated, so the grader and the coverage classifier can
#: never drift: a 404 that ``coverage.status_class`` calls an 'authz_denial'
#: must not be graded 'vulnerable' by the runner.
REFUSAL_STATUSES: frozenset[int] = DEFAULT_DENIAL_STATUSES | AUTHN_STATUSES

#: Mirrors matrix.MATRIX_MAX_TIMEOUT_SECONDS. Restated rather than imported so
#: `core` keeps importing nothing from `matrix`; a test pins them equal.
MAX_TIMEOUT_SECONDS: float = 60.0

#: Header names that carry an identity. Two identities agreeing on all of
#: these are the same caller under two names.
_CREDENTIAL_HEADER_NAMES: frozenset[str] = frozenset(
    {"authorization", "cookie", "x-api-key", "x-auth-token", "api-key", "token"}
)

#: A header name that looks like it carries a credential although it is not
#: one of the six above. It decides that two byte-identical header sets are
#: one caller rather than two deliberate anonymous ones, and that a header two
#: or more identities share is still fabricated in the liveness sham rather
#: than sent unchanged (:func:`_credential_named_header`). A name it matches
#: by accident costs a duplicate-identity warning, or a fabricated shared
#: header: a target that answers that value 400 leaves the denial unproven,
#: and one that answers it 404 before reading the credential (an unknown
#: `X-Workspace-Key`) can prove a credential live that was not. That second
#: case is a known limit, not a guarantee.
_CUSTOM_CREDENTIAL_HINT = re.compile(
    r"token|auth|key|secret|session|cookie|credential|passw|jwt|signature",
    re.IGNORECASE,
)

#: Statuses that are not an answer from the authorization layer at all.
#:
#: A 429 means the request was throttled before anything decided who you are; a
#: 5xx means the handler fell over. Neither establishes that a boundary held OR
#: that it failed, and grading them against a declared status list produces the
#: worst claim this product can make. Measured against a target with a fixed
#: boundary and realistic transients, `run` graded a 429 as VULNERABLE and
#: failed the build on 70% of runs -- once reporting that 'anonymous' received
#: 429 where 401 was declared, which is anonymous being denied HARDER, called an
#: authorization failure and written into SARIF.
#:
#: `matrix.classify_reach` has always read these as `unknown`. This is the same
#: knowledge, for the verb that emits findings.
TRANSIENT_STATUSES: frozenset[int] = frozenset({429}) | frozenset(range(500, 600))
#: A 407 (Proxy Authentication Required) is a proxy's own answer: the request
#: most likely never reached the target, so, like a throttle or a crash, it says
#: nothing about the target's boundary. It is not transient, so it is kept apart.
PROXY_ANSWER_STATUSES: frozenset[int] = frozenset({407})
#: Statuses that are not an answer from the target's authorization layer.
NOT_AN_ANSWER_STATUSES: frozenset[int] = TRANSIENT_STATUSES | PROXY_ANSWER_STATUSES

MARKER_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9_-]+")
MIN_MARKER_LENGTH: int = 24
MAX_MARKER_LENGTH: int = 128
MIN_MARKER_DISTINCT: int = 10
MAX_MARKER_CHAR_FREQUENCY: float = 0.4
MAX_MARKER_CHAR_RUN: int = 4

_MAX_MARKER_SCAN_BYTES: int = 8 * 1024 * 1024
_CHUNK_BYTES: int = 65536
_SUPPORTED_CONTENT_ENCODINGS: frozenset[str] = frozenset({"gzip", "x-gzip", "deflate"})
_GRADE_ORDER: dict[str, int] = {"n/a": 0, "ungraded": 1, "suspected": 2, "confirmed": 3}
_MARKER_HINT = " Generate one with: veridor new-marker"
_NEEDLE_ENCODINGS: tuple[str, ...] = ("ascii", "utf-16le", "utf-16be")
_MARKER_EXPECT_KEYS = frozenset({"status", "contains_marker", "excludes_marker"})
_IDENTITY_KEYS = frozenset({"headers", "marker", "marker_probe", "session"})
_REQUEST_KEYS = frozenset({"method", "path", "headers", "json", "body"})

#: Identity-level session state. Every key is optional except ``establishes``,
#: which is what makes "the session is up" a measured fact rather than an
#: assumption; see :func:`_validate_session`.
_SESSION_KEYS = frozenset({"login", "establishes", "capture", "inject", "reestablish"})
#: Exactly one of these proves the login worked. Enumerated so the loader can
#: refuse anything else rather than ignore it -- see the check in
#: :func:`_validate_session`.
_ESTABLISHES_KEYS = frozenset({"cookie", "capture"})
_LOGIN_STEP_KEYS = frozenset(_REQUEST_KEYS | {"expect_status", "capture"})
_CAPTURE_SPEC_KEYS = frozenset({"from", "name", "pointer"})
_INJECT_KEYS = frozenset({"header", "form_field", "json_field", "value"})
_CAPTURE_SOURCES = frozenset({"cookie", "header", "json_pointer", "html_meta"})
_REESTABLISH_SCOPES = frozenset({"run", "check"})

#: A credential slot may only ever be filled by the identity's own static
#: headers or its own cookie jar. Interpolating a capture into one of these is
#: how one identity would borrow another's credential, which manufactures a
#: `confirmed` finding out of an identity's own legitimate access.
_CREDENTIAL_HEADERS = frozenset({"cookie", "authorization", "proxy-authorization"})

#: Request headers Veridor owns outright. A configured or injected value for any
#: of these is dropped and replaced, for the same reason ``Accept-Encoding`` is:
#: an authorization oracle must observe the target, not an intermediary's copy
#: of an earlier observation, and compression buys the oracle nothing.
_OVERRIDDEN_REQUEST_HEADERS: frozenset[str] = frozenset(
    {"accept-encoding", "cache-control", "pragma"}
)
_FORCED_REQUEST_HEADERS: dict[str, str] = {
    "Accept-Encoding": "identity",
    # Without these, a shared or path-keyed cache in front of the target can
    # answer a write-effect verification read from a copy taken BEFORE the write
    # under test. A stale 'the data is still there' is the one observation that
    # flips a real destruction into an exculpation.
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

#: Response headers that say "this body did not come from the origin just now".
#: A closed list of exact field names; the VALUE test is a fixed membership or
#: integer test, never a substring search over target-controlled text that could
#: be gamed into a false negative.
_CACHE_HIT_HEADERS: dict[str, frozenset[str]] = {
    "x-cache": frozenset({"hit"}),
    "x-cache-status": frozenset({"hit", "stale", "revalidated", "updating"}),
    "x-proxy-cache": frozenset({"hit"}),
    "cf-cache-status": frozenset({"hit", "stale", "revalidated", "updating"}),
    "x-drupal-cache": frozenset({"hit"}),
    "x-varnish-cache": frozenset({"hit"}),
}

#: Methods that cannot change server state. Restated here rather than imported
#: from ``sequence`` because ``load_config`` must not import the sequence engine
#: for a config that declares none.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

MAX_LOGIN_STEPS: int = 4

#: ``${capture.<name>}``. The dot is load-bearing: ``_ENV_PATTERN``'s character
#: class provably cannot match it, so capture references pass through
#: ``_expand_environment`` untouched and the two namespaces can never collide.
_CAPTURE_REF = re.compile(r"\$\{capture\.([A-Za-z_][A-Za-z0-9_]*)\}")

#: A capture name. Deliberately narrower than ``_HTTP_TOKEN``: a name has to be
#: spellable inside ``${capture.<name>}``.
_CAPTURE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: An OpenAPI path template left unsubstituted in a request path, e.g. ``{id}``.
#: Deliberately the same shape as ``veridor.openapi.TEMPLATE_TOKEN`` so the
#: request side and the coverage side cannot disagree about what a placeholder
#: is. RFC 3986 excludes braces from pchar, so a raw brace in a request-target
#: is already malformed -- and `%7Bid%7D` is the escape hatch for the vanishing
#: case of a resource genuinely named with braces.
_PATH_PLACEHOLDER = re.compile(r"\{[^{}/]*\}")

#: Decoding budget for the reflection guard. Config request surfaces are small;
#: these bounds only exist so a pathological config cannot blow up load time.
_MAX_SURFACE_CHARS: int = 64 * 1024
_MAX_DECODE_ROUNDS: int = 3
_MAX_DECODE_VARIANTS: int = 256
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9A-Fa-f]{2}){12,}")
_ESCAPE_SEQUENCE = re.compile(r"\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2}))")

#: Longest error string ever persisted. Defence in depth behind
#: :func:`_safe_error`, which already refuses to persist server-supplied text.
_MAX_ERROR_CHARS: int = 200

#: ``http.client`` exceptions whose ``str()`` embeds raw bytes the server sent.
#: ``BadStatusLine`` carries the entire first line -- up to ``_MAXLINE``, 64 KiB
#: of verbatim response bytes. Response bodies are never persisted, and a
#: malformed response is still a response, so these are described by a constant
#: instead of by their own message. Ordered: more specific subclasses first.
_OPAQUE_HTTP_ERRORS: tuple[tuple[type[BaseException], str], ...] = (
    (
        http.client.RemoteDisconnected,
        "the server closed the connection without sending a response",
    ),
    (
        http.client.BadStatusLine,
        "the server did not return a valid HTTP status line",
    ),
    (
        http.client.UnknownProtocol,
        "the server announced an unsupported HTTP version",
    ),
)

#: Exceptions whose message is generated locally and carries no server bytes.
#: Matched by exact type, so a future subclass that embeds wire bytes -- as
#: ``InvalidChunkLength`` does on the versions that define it -- is not exempt.
_TRANSPARENT_HTTP_ERRORS: frozenset[type[BaseException]] = frozenset(
    {http.client.IncompleteRead, http.client.LineTooLong}
)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Treat redirects as observed responses and never forward credentials."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _default_https_context() -> ssl.SSLContext:
    """The context ``http.client`` builds for an ``HTTPSConnection`` given none.

    The same three steps (``http.client._create_https_context`` on 3.12+,
    inline in ``HTTPSConnection.__init__`` on 3.11): the stdlib's default https
    context -- certificate and hostname verification on, the default CA store
    -- then ALPN ``http/1.1`` and post-handshake auth. It calls the PEP 476
    hook, ``ssl._create_default_https_context``, rather than
    ``create_default_context``, so a platform that overrides the hook is
    honoured here exactly as urllib honours it. tests/test_tls.py compares the
    result with a fresh stdlib context, property by property.
    """
    context = ssl._create_default_https_context()  # noqa: SLF001 -- see above
    context.set_alpn_protocols(["http/1.1"])  # what HTTPSConnection speaks
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


class _SharedContextHTTPSHandler(HTTPSHandler):
    """Every https:// request in the process through ONE context, built on the first.

    The stock handler builds too many or builds too early. On 3.11 it passes
    ``context=None`` down, so every ``HTTPSConnection`` built its own context
    and re-read the whole CA bundle: a 200-check run against a loopback https
    target built 603 contexts, and what that cost grew with the size of the
    bundle. From 3.12 it builds one, but inside ``build_opener`` -- at import
    -- so ``--version``, the offline verbs and http:// targets paid for a
    context they never used. CHANGELOG.md (Unreleased) has both measurements,
    with the bundle sizes. Only the count and the moment change; what the
    context is, is :func:`_default_https_context`.
    """

    def __init__(self) -> None:
        # Not HTTPSHandler.__init__: from 3.12 it builds the context right there.
        AbstractHTTPHandler.__init__(self)
        self._context: ssl.SSLContext | None = None

    def context(self) -> ssl.SSLContext:
        # Two threads racing here would each build an identical context and
        # one would be kept. Requests are sent one at a time today.
        if self._context is None:
            self._context = _default_https_context()
        return self._context

    def https_open(self, req: Request) -> Any:
        return self.do_open(http.client.HTTPSConnection, req, context=self.context())


#: ``ProxyHandler({})`` replaces the one ``build_opener`` adds by default, which
#: reads the proxy settings once at import -- from the environment and, on
#: macOS and Windows, from the SYSTEM network configuration -- and routes every
#: request through them, loopback included, without a word. Measured: with
#: ``http_proxy`` set, or with only a system proxy, the target received nothing
#: and the proxy every probe with its bearer token, while the verify banner
#: said the values went to the capsule's loopback target. The route is now
#: decided per request by :func:`proxy_route` and said by :func:`proxy_notice`.
#: ``_SharedContextHTTPSHandler`` replaces the default ``HTTPSHandler`` (a
#: subclass passed to ``build_opener`` displaces it); tests build a fresh opener
#: here to watch a context being built.
def _build_opener() -> OpenerDirector:
    return build_opener(ProxyHandler({}), _NoRedirectHandler, _SharedContextHTTPSHandler)


_OPENER = _build_opener()


class ProxyRoute(NamedTuple):
    """A proxy that will carry the requests for one target."""

    #: The variable's value, as urllib reads it (may carry ``user:pass@``).
    proxy: str
    #: How Veridor talks to the proxy: ``http`` or ``https``.
    scheme: str
    #: ``host:port`` of the proxy, never its userinfo. Safe to print.
    address: str
    #: The environment variable it came from, spelled as it is set.
    variable: str


def _loopback_host(host: str | None) -> bool:
    """``localhost``, or an IP literal in 127.0.0.0/8 or ::1."""
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _proxy_variable(scheme: str, value: str) -> str:
    """The name of the variable ``getproxies_environment`` took ``value`` from.

    It prefers the lower-case spelling, so this does too; any other spelling
    that holds the same value is the one set.
    """
    wanted = f"{scheme}_proxy"
    if os.environ.get(wanted) == value:
        return wanted
    for name, candidate in os.environ.items():
        if name.lower() == wanted and candidate == value:
            return name
    return wanted.upper()


def proxy_route(url: str) -> ProxyRoute | None:
    """The proxy a request to ``url`` goes through, or None for a direct one.

    Only the environment counts: ``<scheme>_proxy`` in either case, with
    ``no_proxy`` honoured, exactly as ``urllib.request.getproxies_environment``
    and ``proxy_bypass_environment`` read them. The operating system's own
    proxy configuration is never consulted: nobody configuring a system proxy
    for a browser has agreed to route a test identity's credentials through
    it, and nothing on the terminal would have said so.

    A loopback target is never proxied, whatever the environment says. A proxy
    resolves ``127.0.0.1`` on ITS host, so the request would reach some other
    machine's loopback -- and ``verify`` sends a capsule's credentials without
    ``--base-url`` only because the target is THIS machine.
    """
    parts = urlsplit(url)
    if _loopback_host(parts.hostname):
        return None
    proxies = getproxies_environment()
    proxy = proxies.get(parts.scheme)
    if not proxy or proxy_bypass_environment(parts.netloc, proxies):
        return None
    variable = _proxy_variable(parts.scheme, proxy)
    # The value is never quoted in a refusal: a proxy URL can carry
    # user:password@.
    unreadable = ConfigError(
        f"{variable} is set, and urllib cannot read a proxy host from it (a "
        "proxy is written http://host:port, or http://user:password@host:port "
        "with any '@', ':' or '/' in the user or password percent-encoded). "
        f"Its value is not printed. Fix or unset {variable}, or "
        f"{_no_proxy_clause(parts)} to connect directly. Nothing has been sent."
    )
    try:
        scheme, _user, _password, address = _parse_proxy(proxy)
    except ValueError as error:
        # urllib raised this from inside the opener, mid-run: exit 70, "a bug
        # in Veridor", for a variable the operator set (measured).
        raise unreadable from error
    # The address is printed and connected to exactly as written, never
    # decoded: decoding all of it turned a separator written as %40 into
    # "user:password@host", and the notice printed the password (measured).
    # Anything but host[:port] -- a stray '@', a '%', a path after it -- is a
    # value urllib reads some other way than its author meant.
    authority = proxy.split("://", 1)[1] if "://" in proxy else proxy
    if (
        not _PROXY_ADDRESS.fullmatch(address)
        or authority[len(authority.split("/", 1)[0]):] not in {"", "/"}
    ):
        raise unreadable
    scheme = scheme or parts.scheme
    if scheme == "https" and parts.scheme == "https":
        raise ConfigError(
            f"{variable} names an https:// proxy for an https:// target. urllib "
            "opens a tunnel to a proxy over plain TCP, so the CONNECT line and "
            f"any user:password in {variable} would cross the network in "
            "plaintext, whatever the scheme says. Write the proxy as "
            f"http://host:port if it accepts that, or {_no_proxy_clause(parts)} "
            "to connect directly. Its value is not printed. Nothing has been "
            "sent."
        )
    return ProxyRoute(proxy=proxy, scheme=scheme, address=address, variable=variable)


#: A proxy's ``host[:port]`` as it may be printed and connected to: a name, an
#: IPv4 address or a bracketed IPv6 one, and a port.
_PROXY_ADDRESS = re.compile(
    r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?"
)


def _no_proxy_variable() -> str | None:
    """The no_proxy variable ``getproxies_environment`` reads, when one is set.

    It prefers the lower-case spelling: with both set, NO_PROXY is ignored.
    """
    if "no_proxy" in os.environ:
        return "no_proxy"
    for name, value in os.environ.items():
        if name.lower() == "no_proxy" and value:
            return name
    return None


def _no_proxy_clause(parts: SplitResult) -> str:
    """How to send this target's requests direct, in the variable urllib reads.

    "Set NO_PROXY=host" did nothing when a lower-case ``no_proxy`` was set,
    and for an IPv6 target urllib compares the bracketed host (both measured).
    """
    host = parts.hostname or ""
    name = f"[{host}]" if ":" in host else host
    in_effect = _no_proxy_variable()
    if in_effect:
        return f"add {name} to {in_effect} (set here, and read in place of NO_PROXY)"
    return f"set NO_PROXY={name}"


def _no_proxy_hint(parts: SplitResult) -> str:
    clause = _no_proxy_clause(parts)
    return f"{clause[0].upper()}{clause[1:]} to connect directly."


def _via_proxy(request: Request, route: ProxyRoute) -> None:
    """Send ``request`` through ``route``, as ``ProxyHandler.proxy_open`` would.

    The same three steps, so behaviour behind a proxy is unchanged except for
    where the decision is made: Basic ``Proxy-Authorization`` from the
    variable's ``user:pass@``, then ``set_proxy`` -- an absolute-URI request to
    the proxy for http, a ``CONNECT`` tunnel for https. ``_parse_proxy`` is the
    stdlib's own parser for the value, used so both agree on what it names.
    """
    _scheme, user, password, _address = _parse_proxy(route.proxy)
    if user and password:
        credentials = base64.b64encode(
            f"{unquote(user)}:{unquote(password)}".encode()
        ).decode("ascii")
        request.add_header("Proxy-authorization", f"Basic {credentials}")
    request.set_proxy(route.address, route.scheme)


def _proxy_sentence(base_url: str) -> str | None:
    route = proxy_route(base_url)
    if route is None:
        return None
    parts = urlsplit(base_url)
    if parts.scheme == "https":
        # Both cases, because Veridor cannot tell them apart: judging the peer
        # certificate's issuer cannot separate a corporate root from a public
        # one. This used to promise the tunnel unconditionally, and a proxy
        # inspecting TLS with a CA the runner trusted decrypted every bearer
        # token while the line said it saw only the host and port (measured).
        sees = (
            "the target is https://, so a proxy that only tunnels sees the host "
            "and port of each connection, but one that inspects TLS with a "
            "certificate authority this machine trusts, as many corporate "
            "proxies do, reads every request in full, credentials included"
        )
    else:
        sees = "the target is http://, so it sees every request in full, credentials included"
    return (
        f"requests to {parts.netloc} go through the proxy {route.address} named by "
        f"{route.variable}, not straight to the target: {sees}. {_no_proxy_hint(parts)}"
    )


def proxy_notice(base_url: str) -> str | None:
    """One stderr line saying a proxy will carry the requests, or None."""
    sentence = _proxy_sentence(base_url)
    return None if sentence is None else f"veridor: {sentence}"


def announce_proxy(base_url: str) -> None:
    """Print :func:`proxy_notice`, before the first request, when there is one."""
    notice = proxy_notice(base_url)
    if notice is not None:
        print(notice, file=sys.stderr)


#: Substituted for a missing ``${VAR}`` when the caller will not send anything.
#: Recognisable on sight if it ever escapes into an artifact, which it must not.
#:
#: Carries the variable NAME so two absent credentials stay distinguishable. A
#: single shared sentinel made every unset token identical, which tripped the
#: indistinguishable-identity guard and refused a configuration whose only sin
#: was not exporting secrets for a command that sends nothing.
ABSENT_CREDENTIAL: str = "<absent:{name}>"


def _empty_variable_error(name: str) -> ConfigError:
    """The refusal for ``${NAME}`` when NAME is set to an empty string.

    Only ``name not in os.environ`` used to be refused, so an empty value was
    substituted and the run went ahead: ``Bearer ${TOKEN}`` became ``Bearer ``.
    GitHub Actions gives a pull request from a fork an EMPTY string for every
    secret, and a CI variable nobody filled in looks the same. Reproduced on
    the demo target, an empty owner token produced ``unexpected_denial`` on the
    owner's own invoice and exit 1: a configuration problem reported as a
    finding about the target. An empty attacker token is worse, because the
    denial a blank credential draws can match a declared denial and pass.
    """
    return ConfigError(
        f"environment variable {quoted(name)} is set but empty. Veridor refuses it "
        "rather than send an empty value: a withheld secret (a fork pull request "
        "gets an empty string, not an unset variable) would otherwise be probed "
        "as a real identity and read as a finding about the target. Set it to "
        "the real value, or do not run this job when the secret is unavailable. "
        "Nothing has been sent."
    )


def _expand_environment(
    value: Any,
    *,
    deferred: frozenset[str] = frozenset(),
    allow_missing: bool = False,
) -> Any:
    """Expand ``${NAME}`` from the environment, leaving ``deferred`` names alone.

    ``_ENV_PATTERN`` matches ``${invoice_id}`` exactly as readily as
    ``${API_TOKEN}``, so without ``deferred`` every sequence capture reference
    would fail the load with "environment variable 'invoice_id' is not set".

    Rejected alternatives, both worse than the problem: a second sigil
    (``{{var}}``), because two interpolation syntaxes in one file is a trap; and
    leaving every unknown name literal, because that turns a typo'd
    ``${API_TOEKN}`` from a load error into a request carrying that text to the
    target. ``deferred`` is a closed set read from the config's own capture
    names, is scoped to the ``sequences`` subtree by the caller, and collides
    with no environment variable (that is a load error in itself). With the
    default argument this function behaves exactly as it always has.

    A variable that is set but empty (or only whitespace) is refused exactly as
    an unset one is. See :func:`_empty_variable_error`.
    """
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in deferred:
                return match.group(0)
            present = os.environ.get(name)
            if present is None or not present.strip():
                if allow_missing:
                    # `coverage` reads the declaration and issues no request --
                    # its own help says "Issues no request" and groups its flags
                    # under "(offline, static)". Demanding live tokens to count
                    # declarations blocked a coverage badge in CI for no reason,
                    # and a docs-only trial hit it on its first attempt. An
                    # empty value is the same absence and gets the same
                    # placeholder.
                    return ABSENT_CREDENTIAL.format(name=name)
                if present is None:
                    raise ConfigError(f"environment variable {quoted(name)} is not set")
                raise _empty_variable_error(name)
            # Recorded so every writer and printer can put ``${NAME}`` back:
            # the value can land anywhere a string can -- see veridor.redaction.
            redaction.register(name, present)
            return present

        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [
            _expand_environment(item, deferred=deferred, allow_missing=allow_missing)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _expand_environment(
                item, deferred=deferred, allow_missing=allow_missing
            )
            for key, item in value.items()
        }
    return value


def generate_marker() -> str:
    """Return a fresh marker guaranteed to pass :func:`validate_marker`."""
    for _ in range(8):
        candidate = f"vdr-{secrets.token_urlsafe(18)}"
        try:
            return validate_marker(candidate, "generated marker")
        except ConfigError:
            continue
    raise RuntimeError("could not generate a marker that passes validation")


def validate_marker(value: object, label: str) -> str:
    """Return ``value`` when it is a strong marker; raise :class:`ConfigError` otherwise.

    A weak marker manufactures false confirmations, and a false confirmation is
    the one claim the product cannot afford to get wrong, so every gate fails
    closed. There is deliberately no warn-and-continue mode and no override.
    """
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be a string.{_MARKER_HINT}")
    length = len(value)
    if not MIN_MARKER_LENGTH <= length <= MAX_MARKER_LENGTH:
        raise ConfigError(
            f"{label} must be between {MIN_MARKER_LENGTH} and {MAX_MARKER_LENGTH} "
            f"characters, got {length}.{_MARKER_HINT}"
        )
    if not MARKER_PATTERN.fullmatch(value):
        # The [A-Za-z0-9_-] alphabet is what makes JSON, HTML, percent, XML, and
        # CSV encoding identity operations on the marker, so the body is never
        # decoded before matching.
        raise ConfigError(
            f"{label} must use only the characters A-Z a-z 0-9 _ -.{_MARKER_HINT}"
        )
    counts = Counter(value)
    if len(counts) < MIN_MARKER_DISTINCT:
        raise ConfigError(
            f"{label} must contain at least {MIN_MARKER_DISTINCT} distinct "
            f"characters, got {len(counts)}.{_MARKER_HINT}"
        )
    if max(counts.values()) / length > MAX_MARKER_CHAR_FREQUENCY:
        raise ConfigError(
            f"{label} must not repeat one character more than "
            f"{int(MAX_MARKER_CHAR_FREQUENCY * 100)}% of its length.{_MARKER_HINT}"
        )
    longest_run = current_run = 1
    for index in range(1, length):
        current_run = current_run + 1 if value[index] == value[index - 1] else 1
        longest_run = max(longest_run, current_run)
    if longest_run > MAX_MARKER_CHAR_RUN:
        raise ConfigError(
            f"{label} must not repeat a character more than "
            f"{MAX_MARKER_CHAR_RUN} times in a row.{_MARKER_HINT}"
        )
    for period in range(1, length):
        if length % period == 0 and value == value[:period] * (length // period):
            raise ConfigError(
                f"{label} must not repeat a {period}-character pattern.{_MARKER_HINT}"
            )
    return value


def marker_needles(marker: str) -> tuple[bytes, ...]:
    """Return the lowercased needle variants ``(ascii, utf-16le, utf-16be)``.

    Only the needle is ever transformed. Transforming the haystack enlarges the
    preimage set of a match and is exactly where false confirmations live.
    """
    return (
        marker.encode("ascii").lower(),
        marker.encode("utf-16-le").lower(),
        marker.encode("utf-16-be").lower(),
    )


def _validate_marker_set(markers: dict[str, str]) -> None:
    for name, marker in markers.items():
        for other_name, other in markers.items():
            if name == other_name:
                continue
            if marker.lower() == other.lower():
                raise ConfigError(
                    f"identities {quoted(name)} and {quoted(other_name)} share the same marker; "
                    f"a match must identify exactly one owner.{_MARKER_HINT}"
                )
            if marker.lower() in other.lower():
                raise ConfigError(
                    f"identity {quoted(name)} marker is a substring of identity "
                    f"{quoted(other_name)} marker; a match must identify exactly one "
                    f"owner.{_MARKER_HINT}"
                )


def _unescape_match(match: re.Match[str]) -> str:
    return chr(int(match.group(1) or match.group(2), 16))


def _decode_once(value: str) -> set[str]:
    """Return every plaintext one decoding step could recover from ``value``.

    The reflection guard has to see what the TARGET sees, not what the config
    file says. A server percent-decodes a query string, JSON-unescapes a body,
    and base64-decodes an opaque header before it echoes any of them back, so a
    literal substring test over the raw config text is defeated by encoding a
    single character of the marker.
    """
    variants: set[str] = set()
    for decoder in (unquote, unquote_plus):
        try:
            variants.add(decoder(value))
        except (UnicodeDecodeError, ValueError):
            pass
    variants.add(html.unescape(value))
    # Targeted rather than codecs 'unicode_escape': that codec decodes latin-1
    # and would mangle a UTF-8 surface. The marker alphabet is ASCII, so \uXXXX
    # and \xNN are the only escapes that can hide a marker character.
    variants.add(_ESCAPE_SEQUENCE.sub(_unescape_match, value))
    for token in _BASE64_TOKEN.findall(value):
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                variants.add(decoder(padded).decode("utf-8", "ignore"))
            except (binascii.Error, ValueError):
                continue
    for token in _HEX_TOKEN.findall(value):
        try:
            variants.add(bytes.fromhex(token).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return {item for item in variants if item}


def _decode_variants(value: str) -> set[str]:
    """Close ``value`` over :func:`_decode_once` a bounded number of times."""
    return _decode_variants_checked(value)[0]


def _decode_variants_checked(value: str) -> tuple[set[str], bool]:
    """:func:`_decode_variants`, and whether every variant found was kept.

    The second item is False when the ``_MAX_DECODE_VARIANTS`` cap dropped a
    decoding, or the value was longer than ``_MAX_SURFACE_CHARS`` and only its
    prefix was decoded: a marker hidden in what was dropped was never looked
    for, so a caller that puts the value on the wire must refuse rather than
    read the answer as "no marker". The walk is sorted at every step. It walked Python
    sets, so WHICH variants the cap kept followed the per-process string hash,
    and the same captured value was checked in one run and sent unchecked in
    the next.
    """
    seen = {value[:_MAX_SURFACE_CHARS]}
    # A value past the surface bound was decoded from its prefix only, so the
    # rest of it was never read: that is an unfinished check too.
    whole = len(value) <= _MAX_SURFACE_CHARS
    frontier = sorted(seen)
    for _ in range(_MAX_DECODE_ROUNDS):
        produced: list[str] = []
        for item in frontier:
            for candidate in sorted(_decode_once(item)):
                if candidate in seen or len(candidate) > _MAX_SURFACE_CHARS:
                    continue
                if len(seen) >= _MAX_DECODE_VARIANTS:
                    return seen, False
                seen.add(candidate)
                produced.append(candidate)
        if not produced:
            break
        frontier = produced
    return seen, whole


def _surface_marker_owner(
    surface: Sequence[str], markers: Mapping[str, str]
) -> tuple[str | None, bool]:
    """The owner whose marker any value in ``surface`` carries, plain or
    decoded, and whether every decoding of every value was checked.

    The load-time half of the reflection guard, shared by the check and the
    sequence checks. Both used ``_decode_variants`` alone, which drops the
    completeness flag, so a request whose value decoded past the variant cap
    was read as "no marker" and loaded, with a marker in a decoding nobody
    looked at; the send-time check (``sequence._marker_owner``) already
    refused. The raw value is tested too, as it is at send time.
    """
    haystack: set[str] = set()
    complete = True
    for value in surface:
        variants, done = _decode_variants_checked(value)
        complete = complete and done
        haystack.update(variant.lower() for variant in variants)
        haystack.add(value.lower())
    for name, marker in markers.items():
        needle = marker.lower()
        if any(needle in candidate for candidate in haystack):
            return name, complete
    return None, complete


def _marker_check_incomplete(where: str) -> ConfigError:
    """The load-time refusal for a request the reflection guard could not finish."""
    return ConfigError(
        f"{where} could not be checked for a configured marker: one of its values "
        f"decodes into more than {_MAX_DECODE_VARIANTS} variants or is longer than "
        f"{_MAX_SURFACE_CHARS} characters, and a marker in a decoding that was not "
        "read would be sent and then matched as a leak. Shorten or split that "
        "value; identity headers count, as they are sent with every request."
    )


def _request_surface(
    request: dict[str, Any],
    *,
    base_url: Any = None,
    extra: Sequence[str] = (),
) -> list[str]:
    """Every string Veridor puts on the wire for one check.

    Method, base URL, path, header NAMES and values, and the body all reach the
    target and can all be echoed back by it. ``_HTTP_TOKEN`` -- the alphabet
    accepted for a method and for a header name -- is a strict superset of the
    marker alphabet, so a marker is a legal value in either slot.
    """
    surface = [
        str(request.get("method", "GET")),
        str(request.get("path", "")),
    ]
    if isinstance(base_url, str):
        surface.append(base_url)
    if "json" in request:
        surface.append(json.dumps(request["json"], sort_keys=True))
    elif isinstance(request.get("body"), str):
        surface.append(request["body"])
    for name, value in dict(request.get("headers", {}) or {}).items():
        surface.append(str(name))
        surface.append(str(value))
    surface.extend(extra)
    return surface


def _validate_markers_absent_from_requests(
    markers: dict[str, str],
    identities: dict[str, Any],
    checks: list[Any],
    base_url: Any = None,
) -> None:
    """Reject configurations where Veridor would send a marker it later matches.

    A reflection endpoint that echoes our own input would otherwise grade a
    benign echo as ``confirmed``, which is the one claim the product cannot
    afford to get wrong. Every component of the request is inspected, and each
    is inspected through the decodings a target may apply before echoing.
    """
    if not markers:
        return
    identity_surface = [
        str(item)
        for identity in identities.values()
        for pair in dict(identity.get("headers", {}) or {}).items()
        for item in pair
    ]

    def reject(surface: Sequence[str], describe: Any, where: str) -> None:
        owner, complete = _surface_marker_owner(surface, markers)
        if owner is not None:
            raise ConfigError(describe(owner))
        if not complete:
            # "No marker" from a check that stopped short is not an answer.
            raise _marker_check_incomplete(where)

    for check in checks:
        reject(
            _request_surface(
                check["request"], base_url=base_url, extra=identity_surface
            ),
            lambda name, check_id=check["id"]: (
                f"identity {quoted(name)} marker appears in the request sent by check "
                f"{quoted(check_id)}; a reflected marker cannot prove a leak"
            ),
            f"the request sent by check {quoted(check['id'])}",
        )
    for owner, identity in identities.items():
        session = identity.get("session")
        if not isinstance(session, dict):
            continue
        # §4.3: a fixture body is held to the same rule as a check body. A
        # marker Veridor itself sent and then matched cannot prove a leak, and
        # a login request is no different.
        for index, step in enumerate(session.get("login") or ()):
            if not isinstance(step, dict):
                continue
            reject(
                _request_surface(step, base_url=base_url, extra=identity_surface),
                lambda name, who=owner, at=index: (
                    f"identity {quoted(name)} marker appears in the request sent by "
                    f"identity {quoted(who)} session login step {at}; a reflected "
                    "marker cannot prove a leak"
                ),
                f"the request sent by identity {quoted(owner)} session login step {index}",
            )
        # An inject entry is added to EVERY request this identity sends once
        # the session is up -- checks, controls, sequence steps -- so it is held
        # to the rule on its own, whatever requests the config declares. It was
        # the one slot not read here, and `IdentitySession._substitute` only
        # inspects captured values, so a literal marker went out unchecked.
        for index, entry in enumerate(session.get("inject") or ()):
            if not isinstance(entry, dict):
                continue
            reject(
                [
                    str(entry[slot])
                    for slot in ("header", "form_field", "json_field", "value")
                    if slot in entry
                ],
                lambda name, who=owner, at=index: (
                    f"identity {quoted(name)} marker appears in identity "
                    f"{quoted(who)} session inject {at}, which is sent on every "
                    "request after login; a reflected marker cannot prove a leak"
                ),
                f"identity {quoted(owner)} session inject {index}, which is sent on "
                "every request after login,",
            )
    for probe_owner, identity in identities.items():
        probe = identity.get("marker_probe")
        if not isinstance(probe, dict):
            continue
        # A marker control probe is held to the same rule as a check. If the
        # probe's own request carried the marker, a target that merely echoes
        # its input would report the marker as live and would promote every
        # exclusion naming this identity from inconclusive to verified -- the
        # exact false confirmation the guard exists to prevent.
        reject(
            _request_surface(probe, base_url=base_url, extra=identity_surface),
            lambda name, owner=probe_owner: (
                f"identity {quoted(name)} marker appears in the marker_probe request for "
                f"identity {quoted(owner)}; a reflected marker cannot prove the marker is live"
            ),
            f"the marker_probe request for identity {quoted(probe_owner)}",
        )


def _suspicious_keys(keys: Sequence[str], known: frozenset[str]) -> list[str]:
    """Return unknown keys that look like typos of ``known`` keys.

    Configurations have always carried annotations (``_comment``,
    ``description``, team conventions), and ``veridor init`` writes ``_comment``
    itself, so an unrecognised key is accepted. A key that is a near-miss of a
    real one is not: a typo'd ``contain_marker`` would silently disable a
    security oracle rather than produce a visibly wrong result.

    Every caller passes keys ALREADY filtered to the unknown ones
    (``set(block) - KNOWN``), so nothing arriving here is a real key. That makes
    a key which *normalises onto* a known one the worst case in the set, not a
    safe one: ``excludes_marker_``, ``Excludes_Marker``, ``excludes-marker`` and
    ``containsmarker`` all normalise to a known key and none of them matches at
    lookup time. Skipping those -- which this function used to do -- accepted the
    config, never ran the oracle, and returned a green build. Measured against
    the vulnerable demo target: the correct key exits 1 with the cross-tenant
    leak confirmed, and ``excludes_marker_`` exits 0 with 6/6 probes "matched".
    A separator or a capital is a likelier slip than a dropped letter, so this
    was the fail-open path most likely to be taken, in a tool whose entire claim
    is that it fails closed.

    Two swapped letters count too (``injcet``): difflib scores that 0.83 on a
    six-letter key, under the 0.85 cutoff, and it is the commonest slip there
    is. Only the root check had this fallback, so a session ``injcet`` loaded
    with no ``inject`` and the CSRF header was never added, and ``lgoin``, a
    sequence or step ``nmae`` and an expectation ``statsu`` beside ``status``
    loaded the same way.

    A key starting with ``_`` is never judged: it is the annotation spelling
    the schema allows in every object and the refusals themselves offer as the
    way out ("start it with '_'"). Normalizing stripped the ``_``, so
    ``_remark`` on an identity was refused as ``marker`` as well, and
    ``_status`` or ``_contains_marker`` -- a key deliberately set aside --
    as the very key it was set aside from.
    """
    return sorted(str(key) for key in keys
                  if not str(key).startswith("_")
                  and (_nearest_key(str(key), known) or "marker" in _normalized_key(str(key))))


def _annotation_way_out(keys: Sequence[str]) -> str:
    """The way out every near-miss refusal offers: rename the key, or keep it
    as an annotation by starting it with ``_``, which is never judged.

    Only the root, identity and ``coverage`` refusals said the second half, so
    a near-miss meant as a note anywhere else -- a session, a capture, an
    inject entry, an expectation, a sequence, a step, a teardown entry or a
    request block -- was told what it resembled and not how to keep it.
    """
    if len(keys) == 1:
        return "Rename it, or start it with '_' if it is an annotation."
    return "Rename them, or start them with '_' if they are annotations."


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _nearest_key(key: str, known: frozenset[str]) -> str | None:
    """The real key ``key`` is a slip of, or None: the same key once case and
    separators are dropped, a difflib match at 0.85, or the same letters in
    another order (two swapped letters, which difflib scores under the cutoff)."""
    normalized = _normalized_key(key)
    if not normalized:
        return None
    by_normal = {_normalized_key(item): item for item in known}
    if normalized in by_normal:
        return by_normal[normalized]
    close = difflib.get_close_matches(normalized, sorted(by_normal), n=1, cutoff=0.85)
    if close:
        return by_normal[close[0]]
    by_letters = {"".join(sorted(item)): real for item, real in by_normal.items()}
    return by_letters.get("".join(sorted(normalized)))


#: Keys, anywhere a configuration holds settings, that name a TLS setting or TLS material, compared
#: lower-cased with separators removed, plus any key starting with one of
#: _TLS_KEY_PREFIXES. Veridor has no such setting: every https request
#: verifies the target against the default CA store and presents no client
#: certificate (``_default_https_context``). Any other unknown key is an
#: annotation and is ignored, so these loaded without a word and did nothing
#: -- ``client_cert`` on an identity, ``ca_file`` or ``verify_tls: false`` on
#: the target (measured) -- which reads as a setting that is in force.
_TLS_KEY_NAMES = frozenset({
    "cert", "certificate", "certfile", "clientcert", "clientcertificate", "clientcertfile",
    "clientkey", "keyfile", "privatekey", "pkcs12", "p12", "pfx",
    "ca", "cafile", "cacert", "cacerts", "cabundle", "capath", "cadir", "cacertificate",
    "verify", "verifytls", "verifyssl", "verifycert", "verifycerts", "verifycertificate",
    "insecure", "insecureskipverify", "skipverify", "skiptlsverify", "nosslverify",
})
_TLS_KEY_PREFIXES = ("tls", "ssl", "mtls")


def _refuse_tls_keys(block: dict[str, Any], where: str) -> None:
    """Refuse ``block``'s keys that name a TLS setting (_TLS_KEY_NAMES)."""
    found = sorted(
        key for key in block
        if isinstance(key, str) and not key.startswith("_")
        and ((normalized := re.sub(r"[^a-z0-9]", "", key.lower())) in _TLS_KEY_NAMES
             or normalized.startswith(_TLS_KEY_PREFIXES))
    )
    if found:
        raise ConfigError(
            f"{where} has {terminal_names(found)}, a TLS setting Veridor does not have: every https "
            "request verifies the target against the default CA store and presents no client "
            "certificate, so the key would be ignored. To trust a private CA, point SSL_CERT_FILE "
            "at it (and SSL_CERT_DIR at an empty directory to trust it alone). Remove the key, or "
            "start it with '_' if it is an annotation."
        )


def _refuse_sequence_tls_keys(sequences: Any) -> None:
    """:func:`_refuse_tls_keys` on every container a sequence holds settings in.

    The request blocks inside a sequence already refuse an unknown key; the
    sequence, its steps, its teardown entries and their ``expect`` blocks treat
    one as an annotation, so a ``verify_tls`` there loaded and did nothing.
    """
    if not isinstance(sequences, list):
        return
    for sequence in sequences:
        if not isinstance(sequence, dict):
            continue
        where = f"sequence {quoted(sequence.get('id'))}"
        _refuse_tls_keys(sequence, where)
        for kind, label in (("steps", "step"), ("teardown", "teardown entry")):
            entries = sequence.get(kind)
            for index, entry in enumerate(entries if isinstance(entries, list) else ()):
                if not isinstance(entry, dict):
                    continue
                _refuse_tls_keys(entry, f"{where} {label} {index}")
                if isinstance(entry.get("expect"), dict):
                    _refuse_tls_keys(entry["expect"], f"{where} {label} {index} expect")


#: Keys that hold a query string somewhere else. A request block has none: the
#: query string is part of ``path``.
_QUERY_LIKE_KEYS = frozenset({
    "params", "query", "querystring", "queryparams", "qs", "parameters", "search",
})


def _unknown_request_key_advice(key: str) -> str:
    """What to write instead of a request key that is no misspelling."""
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if normalized in _QUERY_LIKE_KEYS:
        return f"put {quoted(key)} in 'path' as a query string, e.g. '/items?tenant=acme'"
    if "-" in key or normalized in {"authorization", "cookie", "accept", "contenttype",
                                    "useragent"} or key.lower().startswith("x-"):
        return f"a header goes under 'headers', e.g. \"headers\": {{{quoted(key)}: ...}}"
    return f"an annotation starts with '_': write '_{terminal_text(key)}'"


def _refuse_near_miss_request_keys(
    block: dict[str, Any], known: frozenset[str], label: str
) -> None:
    """Refuse every request-block key the loader does not read.

    A request block is read for its known keys and nothing else, so
    ``"Headers": {"Authorization": ...}`` used to load and the request went out
    without it: the identity was probed without the credential its author gave
    it. A near-miss is named with the real key it is nearest to.

    Every other key is refused too, unless it starts with ``_``, which is how
    the published schema spells an annotation in every request block. Before,
    only near-misses were refused: ``params``, ``query``, a bare
    ``Authorization`` and ``description`` loaded and were dropped, and the
    request went out without them -- measured with ``veridor run``, nine
    requests and none carrying the value -- while the schema refused all four.
    """
    unknown = sorted(
        str(key) for key in set(block) - known if not str(key).startswith("_")
    )
    if not unknown:
        return
    suspicious = set(_suspicious_keys(unknown, known))
    nearest = {key: _nearest_key(key, known) for key in unknown if key in suspicious}
    if len(unknown) == 1 and nearest.get(unknown[0]):
        hint = f"did you mean {quoted(nearest[unknown[0]])}?"
    elif len(nearest) == len(unknown) and all(nearest.values()):
        hint = "did you mean " + ", ".join(
            f"{quoted(nearest[key])} for {quoted(key)}" for key in unknown
        ) + "?"
    elif len(nearest) == len(unknown):
        hint = f"did you mean one of {', '.join(sorted(known))}?"
    else:
        parts = []
        near = [key for key in unknown if nearest.get(key)]
        if near:
            parts.append("did you mean " + ", ".join(
                f"{quoted(nearest[key])} for {quoted(key)}" for key in near
            ) + "?")
        parts += [
            _unknown_request_key_advice(key) for key in unknown if not nearest.get(key)
        ]
        hint = "; ".join(parts)
    slips = [key for key in unknown if key in suspicious]
    raise ConfigError(
        f"{label} has unsupported keys: {terminal_names(unknown)} ({hint}) Veridor "
        f"reads {', '.join(sorted(known))} here and nothing else, so what an "
        "unknown key holds would never be sent. Nothing has been sent."
        + (f" {_annotation_way_out(slips)}" if slips else "")
    )


#: The top-level keys whose near-misses are refused: every root property the
#: schema has (tests/test_schema_parity.py holds the two equal). Most hold a
#: whole block, so a slip in the name drops everything under it -- a root
#: ``Matrix`` took specimens, marker_owner, unauthenticated and ignore with it
#: and ``map`` planned a third fewer requests and exited 0.
_ROOT_KEYS = frozenset(
    {"$schema", "version", "target", "identities", "checks", "sequences", "matrix", "coverage"}
)


def _refuse_near_miss_root_keys(config: dict[str, Any]) -> None:
    """Refuse a top-level key that is a slip of a real one (_nearest_key).

    Any other unknown top-level key is an annotation and is ignored, and that
    used to include the near-misses: ``Sequences`` beside a ``checks`` list
    loaded with zero sequences -- setup, cross-tenant asserts and teardown all
    gone -- and ``Checks`` beside ``sequences`` loaded with zero checks, and
    ``run`` graded what was left and reported green (measured 2026-10-14).
    Checked before ${ENV} expansion, so a misspelt ``sequences`` is named as
    the cause rather than its capture references as unset variables. Two
    swapped letters (``chekcs``) count, as they do everywhere (_nearest_key).
    """
    unknown = sorted(
        key for key in config
        if isinstance(key, str) and not key.startswith("_") and key not in _ROOT_KEYS
    )
    nearest = {key: _nearest_key(key, _ROOT_KEYS) for key in unknown}
    slips = [key for key in unknown if nearest[key]]
    if slips:
        # `$schema` and `version` hold one value, not a block.
        if len(slips) > 1:
            lost, it = "what each holds", "each"
        elif isinstance(config[slips[0]], (dict, list)):
            lost, it = "everything under it", "it"
        else:
            lost, it = "its value", "it"
        raise ConfigError(
            f"the configuration has unsupported top-level keys: {terminal_names(slips)} "
            "(did you mean "
            + ", ".join(f"{quoted(nearest[key])} for {quoted(key)}" for key in slips)
            + f"?) Veridor ignores a top-level key it does not read, so {lost} "
            f"would be dropped without a word. Rename {it}, or start {it} with '_' if it "
            "is an annotation."
        )


def load_config(
    path: Path,
    base_url: str | None = None,
    *,
    read_only: bool = False,
    require_checks: bool = True,
    allow_missing_env: bool = False,
    require_concrete_paths: bool = False,
) -> dict[str, Any]:
    """Load, expand, and validate a JSON configuration.

    ``read_only`` is a hard refusal, stricter than the default posture: the load
    fails if ANY request the configuration can issue uses a method outside
    :data:`SAFE_METHODS`. It fails here, before a single request is sent, which
    is what makes it safe to point a suite at an environment you do not own.

    ``require_checks=False`` is for ``map`` alone. Discovery evaluates no
    expectation, so requiring a non-empty ``checks`` list before Veridor will
    look at an API charges the user a declaration for the one command that does
    not need one -- and that declaration is the whole adoption wall. `run` and
    `mutate` keep the requirement, because a gate with nothing to gate on is a
    different mistake and still worth refusing.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration not found: {path}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    except RecursionError as exc:
        # json.loads recurses per nesting level, so a deeply nested document
        # blows the stack inside the decoder rather than raising
        # JSONDecodeError. It surfaced as a traceback and exit 1 -- "the gate
        # failed" -- for what is only a malformed input.
        raise ConfigError(
            f"{path} is nested too deeply to parse. This is a malformed "
            "configuration, not an authorization result."
        ) from exc

    if isinstance(raw, dict):
        _refuse_near_miss_root_keys(raw)

    # Deferred imported here rather than at module scope: ``sequence`` imports
    # ``core``, and this keeps the dependency one-directional in both files.
    from veridor import sequence as sequence_engine

    if isinstance(raw, dict) and "sequences" in raw:
        # Only the sequences subtree ever sees a deferred name, so deferral can
        # never reach checks, identities, or target. For every config without
        # sequences this is a single call with the default argument -- bit for
        # bit today's behaviour.
        deferred = sequence_engine.deferred_capture_names(raw["sequences"])
        config = _expand_environment(
            {key: item for key, item in raw.items() if key != "sequences"},
            allow_missing=allow_missing_env,
        )
        config["sequences"] = _expand_environment(
            raw["sequences"], deferred=deferred, allow_missing=allow_missing_env
        )
    else:
        config = _expand_environment(raw, allow_missing=allow_missing_env)
    version = config.get("version") if isinstance(config, dict) else None
    if (
        not isinstance(config, dict)
        # An object or a list is unhashable: `in` raised TypeError, which left
        # the loader as exit 70 ("a bug in Veridor") for a malformed input. And
        # `true == 1`, so `"version": true` loaded as version 1.
        or isinstance(version, bool)
        or not isinstance(version, (int, float))
        or version not in SUPPORTED_CONFIG_VERSIONS
    ):
        # Message unchanged for the inputs it always fired on. Version 2 is
        # additive and exists only to gate `sequences`.
        versions = ", ".join(str(v) for v in sorted(SUPPORTED_CONFIG_VERSIONS))
        # Named one version while accepting two, so `version: 3` was told
        # to use 1 and never learned that 2 exists -- which is the version
        # `run --help` refers to and the one sequences require.
        raise ConfigError(
            f"configuration must be an object with version {versions} "
            "(2 adds `sequences`)"
        )
    declares_sequences = "sequences" in config
    if declares_sequences and config.get("version") != 2:
        # An older shipped binary ignores unknown top-level keys, so without
        # this gate a version-1 config carrying sequences would run there,
        # silently execute only the checks, and report a green run with half the
        # security tests dropped. The gate makes the old binary fail loudly.
        raise ConfigError("sequences requires configuration version 2")

    target = config.get("target")
    if not isinstance(target, dict):
        raise ConfigError("target must be an object")
    # Wherever a configuration holds settings, not only the target and the
    # identities: a root-level `ca_file`, `verify_tls: false` or `tls: {...}`,
    # or one on a check or its request, loaded without a word and did nothing
    # while the README said such a key was refused (measured 2026-09-27). A
    # root-level `ca_file` meant to narrow trust left the default store in
    # force, which is a setting that reads as enforcing and enforces nothing.
    _refuse_tls_keys(config, "the configuration")
    _refuse_tls_keys(target, "target")
    if base_url:
        target["base_url"] = base_url
    target_url = target.get("base_url")
    _validate_http_url(target_url, "target.base_url")
    timeout = target.get("timeout_seconds", 10)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout <= 0
        # NaN fails every comparison, so `timeout <= 0` lets it through and it
        # reaches socket.settimeout as a ValueError. `math.isfinite` is the
        # only check that catches NaN and the infinities together.
        or not math.isfinite(timeout)
        # The ceiling `matrix` has always enforced. `run` validated only
        # "greater than zero", so 1e30 crashed with OverflowError out of
        # socket.settimeout -- exit 1, which this project's own exit table
        # reads as "the gate failed". The validation existed; the verb that
        # gates a build did not call it.
        or timeout > MAX_TIMEOUT_SECONDS
    ):
        raise ConfigError(
            "target.timeout_seconds must be a number greater than zero and no "
            f"more than {MAX_TIMEOUT_SECONDS:g}s. A per-request timeout with no "
            "ceiling makes a run's duration unbounded."
        )
    if "teardown_timeout_seconds" in target:
        # Cleanup gets its own budget so a hung cleanup endpoint cannot stall CI
        # for as long as the probe timeout allows on every teardown step.
        teardown_timeout = target["teardown_timeout_seconds"]
        if (
            not isinstance(teardown_timeout, (int, float))
            or isinstance(teardown_timeout, bool)
            or teardown_timeout <= 0
        ):
            raise ConfigError(
                "target.teardown_timeout_seconds must be greater than zero"
            )

    identities = config.get("identities")
    if not isinstance(identities, dict) or len(identities) < 2:
        raise ConfigError("identities must define at least two users")
    markers: dict[str, str] = {}
    for name, identity in identities.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("identity names must be non-empty strings")
        # Same reason as a check id: an identity name is a fingerprint input
        # and is printed on every finding line.
        _validate_safe_name(name, "an identity name")
        if not isinstance(identity, dict):
            raise ConfigError(f"identity {quoted(name)} must be an object")
        _validate_headers(identity.get("headers", {}), f"identity {quoted(name)} headers")
        # Unrecognised keys are annotations and are ignored, as every release
        # before markers existed did. Only near-misses of a real key are
        # rejected, because those fail silently rather than visibly.
        suspicious = _suspicious_keys(sorted(set(identity) - _IDENTITY_KEYS), _IDENTITY_KEYS)
        if suspicious:
            raise ConfigError(
                f"identity {quoted(name)} has unsupported keys: {terminal_names(suspicious)}"
                f" (did you mean one of {', '.join(sorted(_IDENTITY_KEYS))}?) "
                + _annotation_way_out(suspicious)
            )
        _refuse_tls_keys(identity, f"identity {quoted(name)}")
        if isinstance(identity.get("session"), dict):
            _refuse_tls_keys(identity["session"], f"identity {quoted(name)} session")
        extra = sorted(key for key in set(identity) - _IDENTITY_KEYS
                       if not key.startswith("_"))
        if identity and not (set(identity) & _IDENTITY_KEYS):
            # Headers written one level too high -- {"owner": {"Authorization":
            # "..."}} instead of {"owner": {"headers": {...}}}. Every key is an
            # unrecognised annotation, so the identity authenticates with
            # nothing and is probed ANONYMOUSLY under its own name. That is the
            # one direction this tool must never be wrong in: reach recorded
            # against 'owner' that anonymous actually had, and a boundary that
            # looks held because nobody was ever logged in.
            #
            # An identity that is *meant* to be anonymous says so with an
            # explicit empty `headers`, which lands in _IDENTITY_KEYS and is
            # never reached here.
            first = terminal_text(extra[0]) if extra else ""
            hint = (
                f' Did you mean {{"{name}": {{"headers": {{"{first}": ...}}}}}}?'
                if extra else ""
            )
            raise ConfigError(
                f"identity {quoted(name)} defines none of "
                f"{', '.join(sorted(_IDENTITY_KEYS))}"
                + (f" — only {terminal_names(extra)}." if extra else ".")
                + hint
                + " As written this identity sends no credentials, so it would "
                "be probed anonymously under its own name. Declare "
                '"headers": {} if it is genuinely meant to be anonymous.'
            )
        if "marker" in identity:
            markers[name] = validate_marker(
                identity["marker"], f"identity {quoted(name)} marker"
            )
        if "marker_probe" in identity:
            _validate_marker_probe(name, identity, markers)
        _reject_capture_references(
            identity.get("headers", {}), f"identity {quoted(name)} headers"
        )
        if "session" in identity:
            _validate_session(name, identity, markers)
    _validate_marker_set(markers)
    _refuse_indistinguishable_identities(identities)

    checks = config.get("checks")
    if declares_sequences or not require_checks:
        # Relaxed to "a list" in two cases, and only these two. With sequences,
        # because a config may declare only sequences. And for `map`, because
        # discovery evaluates no expectation: demanding a `checks` list before
        # Veridor will look at an API is demanding the policy the user came
        # here without. When neither applies the historical message fires on
        # exactly the inputs it fires on today, verbatim.
        if checks is None:
            checks = config["checks"] = []
        if not isinstance(checks, list):
            raise ConfigError("checks must be a list")
    elif not isinstance(checks, list) or not checks:
        raise ConfigError("checks must be a non-empty list")
    check_ids: set[str] = set()
    for check in checks:
        if isinstance(check, dict):
            _refuse_tls_keys(check, f"check {quoted(check.get('id'))}")
            if isinstance(check.get("request"), dict):
                _refuse_tls_keys(check["request"], f"check {quoted(check.get('id'))} request")
            if isinstance(check.get("expect"), dict):
                for who, expectation in check["expect"].items():
                    if isinstance(expectation, dict):
                        _refuse_tls_keys(
                            expectation,
                            f"check {quoted(check.get('id'))} expectation for {quoted(who)}",
                        )
        _validate_check(check, identities, check_ids, markers)
    if require_concrete_paths:
        _refuse_unsubstituted_paths(checks)
    _validate_markers_absent_from_requests(
        markers, identities, checks, target.get("base_url")
    )
    if declares_sequences:
        _refuse_sequence_tls_keys(config["sequences"])
        sequence_engine.validate_sequences(
            config["sequences"],
            identities,
            markers,
            # Shared id space: `check_id` stays an unambiguous key for the UI
            # and for every downstream consumer.
            check_ids,
            target.get("base_url"),
        )
        if not config["sequences"] and not checks:
            raise ConfigError("checks must be a non-empty list")
    if read_only:
        _enforce_read_only(config)
    return config


#: The one surface the write-mode disclosure leaves out; see
#: :func:`_mutating_disclosure_surface` for why.
_LOGIN_SURFACE = "login"


def _mutating_requests(config: dict[str, Any]) -> list[tuple[str, str, str, int]]:
    """Every ``(method, where, surface, fan_out)`` in ``config`` that is not safe.

    One traversal, used by both ``--read-only`` and the write-mode disclosure,
    so the two can never disagree about what counts as a write. ``surface``
    names the kind of declaration the request came from, so a caller can select
    on it without parsing ``where``.

    ``fan_out`` is how many requests that one declaration puts on the wire. It
    is 1 everywhere except a check, which is issued once per identity its
    ``expect`` names -- so a banner that counted declarations understated the
    wire by exactly that factor.
    """
    found: list[tuple[str, str, str, int]] = []

    def visit(request: Any, where: str, surface: str, fan_out: int = 1) -> None:
        if not isinstance(request, dict):
            return
        method = str(request.get("method", "GET")).upper()
        if method not in SAFE_METHODS:
            found.append((method, where, surface, fan_out))

    for name, identity in (config.get("identities") or {}).items():
        if isinstance(identity, dict):
            visit(
                identity.get("marker_probe"),
                f"identity {quoted(name)} marker_probe",
                "marker_probe",
            )
            session = identity.get("session")
            if isinstance(session, dict):
                for index, step in enumerate(session.get("login") or ()):
                    visit(
                        step,
                        f"identity {quoted(name)} session login step {index}",
                        _LOGIN_SURFACE,
                    )
    for check in config.get("checks") or ():
        if isinstance(check, dict):
            expect = check.get("expect")
            visit(
                check.get("request"),
                f"check {quoted(check.get('id'))} request",
                "check",
                len(expect) if isinstance(expect, dict) else 1,
            )
    for sequence in config.get("sequences") or ():
        if not isinstance(sequence, dict):
            continue
        for index, step in enumerate(sequence.get("steps") or ()):
            if isinstance(step, dict):
                visit(
                    step.get("request"),
                    f"sequence {quoted(sequence.get('id'))} step {index}",
                    "sequence",
                )
        for index, entry in enumerate(sequence.get("teardown") or ()):
            if isinstance(entry, dict):
                visit(
                    entry.get("request"),
                    f"sequence {quoted(sequence.get('id'))} teardown entry {index}",
                    "sequence",
                )
    return found


def _mutating_disclosure_surface(
    config: dict[str, Any],
) -> list[tuple[str, str, str, int]]:
    """Every mutating request this run can put on the wire, minus the login.

    The run document's ``mutation`` block exists to answer one question without
    anyone having to reason about the configuration: *did this run change my
    target?* That answer is only worth having if it covers every mutating
    request, wherever it was declared.

    It did not. This used to select ``sequence`` surfaces alone, on the ground
    that a ``POST`` check request "has always been legal and is not new
    information" -- but the filter dropped ``DELETE``, ``PUT`` and ``PATCH``
    check requests with it, and ``veridor init`` scaffolds a ``DELETE`` check
    by default. A first run against the user's own API therefore issued
    ``DELETE`` and ``POST`` while the persisted artifact recorded no writes and
    stderr carried no banner. ``--read-only`` refused the very same
    configuration, which is the proof that the tool always knew: only the
    disclosure disagreed. Backward compatibility of a document is not a reason
    to under-report what went on the wire.

    The login stays out, and that carve-out is narrow and deliberate: a login
    is authentication, not fixture provisioning. It creates no object in the
    target and needs no cleanup, so it does not make a run "a run that writes".
    ``--read-only`` still refuses it -- that flag is about the wire, this block
    is about blast radius.
    """
    return [entry for entry in _mutating_requests(config) if entry[2] != _LOGIN_SURFACE]


#: How many mutating declarations a refusal lists before it summarises. 122
#: mutating checks produce a 123-line message, and nothing bounds a scaffold.
#: Same idiom and same number as ``blastradius._MAX_LISTED``.
_MAX_LISTED_MUTATING: int = 50


def _enforce_read_only(config: dict[str, Any]) -> None:
    """Refuse, and name EVERY mutating declaration in one pass.

    This raised on ``mutating[0]`` alone, so a config with three mutating checks
    took three runs to enumerate -- one edit and one full re-read per offender
    -- to learn what a single traversal already knew. A generated scaffold with
    122 of them took 122.
    """
    mutating = _mutating_requests(config)
    if not mutating:
        return
    method, where = terminal_text(mutating[0][0]), mutating[0][1]
    # The first offender stays the literal first clause. That sentence is what
    # people search for and what four existing assertions match on.
    headline = f"--read-only refuses {method} in {where}"
    if len(mutating) == 1:
        raise ConfigError(headline)
    verbs = terminal_names(sorted({verb for verb, _, _, _ in mutating}))
    # "up to", not "would": `mutate --read-only` shares this message, and there
    # every declared request is re-issued once per baseline probe and again per
    # mutation probe. Stating a total that a run can exceed is the one direction
    # a disclosure must never be wrong in.
    declared = sum(fan_out for _, _, _, fan_out in mutating)
    lines = [
        f"{headline}, and {len(mutating) - 1} other mutating declaration(s). "
        f"All {len(mutating)} are listed below (verbs: {verbs}); nothing has "
        f"been sent, and together they declare {declared} request(s) -- more "
        "under `mutate`, which re-issues each one per probe:"
    ]
    for verb, location, _surface, fan_out in mutating[:_MAX_LISTED_MUTATING]:
        suffix = f"  ({fan_out} requests)" if fan_out > 1 else ""
        lines.append(f"  {terminal_text(verb)} in {location}{suffix}")
    if len(mutating) > _MAX_LISTED_MUTATING:
        lines.append(f"  ... and {len(mutating) - _MAX_LISTED_MUTATING} more")
    raise ConfigError("\n".join(lines))


def _validate_http_url(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label} must be an http(s) URL")
    # C1 and the bidi and format controls too: the rule said "control
    # characters" and checked only C0, space and DEL, so a capsule base_url
    # carrying U+009B (CSI) or U+202E passed and was printed raw in the verify
    # banner and verdict.
    if any(ord(character) <= 32 or ord(character) == 127 for character in value) or (
        terminal_controls(value)
    ):
        raise ConfigError(f"{label} must not contain whitespace or control characters")
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{label} is invalid: {terminal_text(exc)}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError(f"{label} must be an http(s) URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError(f"{label} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ConfigError(f"{label} must not contain a query or fragment")
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise ConfigError(f"{label} port must be between 1 and 65535")


#: Why a declared ``Host`` header is refused, wherever it is declared.
_HOST_HEADER_REFUSAL = (
    "{where} sets a Host header ({name}). urllib sends it in place of the "
    "host in the URL, and a gateway that routes by Host delivers the request, "
    "with the identity's credentials, to whichever application that name "
    "selects, while every check Veridor makes on where a request goes reads "
    "only the URL. Put the host in target.base_url (or pass --base-url) and "
    "remove the header. Nothing has been sent."
)


def _refuse_host_header(name: str, where: str) -> None:
    """A declared ``Host`` header, in any case, is refused with exit 2."""
    if name.lower() == "host":
        raise ConfigError(_HOST_HEADER_REFUSAL.format(where=where, name=quoted(name)))


def _validate_headers(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    for name, header_value in value.items():
        if not isinstance(name, str) or not _HTTP_TOKEN.fullmatch(name):
            raise ConfigError(f"{label} contains an invalid header name")
        # Every header map a configuration or capsule can declare comes
        # through here: identity headers, and through _validate_request those
        # of checks, marker probes, login steps, sequence steps and teardown.
        _refuse_host_header(name, label)
        if not isinstance(header_value, str) or _INVALID_HEADER_VALUE.search(header_value):
            raise ConfigError(f"{label} contains an invalid value for {quoted(name)}")
        if any(ord(character) > 0xFF for character in header_value):
            # http.client encodes header values as latin-1; anything above
            # U+00FF raises UnicodeEncodeError from inside the opener, which
            # used to escape as an unhandled crash rather than a refusal.
            raise ConfigError(f"{label} contains an invalid value for {quoted(name)}")


def probe_answered(probe: Mapping[str, Any]) -> bool:
    """Did the AUTHORIZATION LAYER answer this probe?

    The single definition of "answered", exported because `cli` needs it to
    decide whether a run established anything and had been carrying its own
    copy. The two disagreed: `cli` counted any arriving status, so a target
    returning `500` to every probe was "answered" and the no-flag vacuity exit
    never fired -- while this module graded those same probes `inconclusive`,
    printing "this probe establishes nothing about the declared status, in
    either direction" and then exiting `0`. A README line promising "not one
    probe answered -> exit 3" was false for every uniformly-5xx target.

    Four things are not answers:

    * a transport error -- nothing arrived at all;
    * no status;
    * a `429` or a `5xx` (:data:`TRANSIENT_STATUSES`) -- the request was
      throttled before anything decided who you are, or the handler fell over;
    * a `407` (:data:`PROXY_ANSWER_STATUSES`) -- a proxy answered, and the
      request most likely never reached the target;
    * a body the scanner could not read to the end. The status did arrive, so
      this one is a judgement rather than a fact: a marker assertion over a
      truncated body is ungradeable, and a 500 MB body or a gzip bomb reaches
      exit `0` by exactly this route. Counting it as unanswered is the loud
      direction, which is the one this product takes when it is unsure whether
      a measurement happened.
    """
    if probe.get("error"):
        return False
    response = probe.get("response") or {}
    status = response.get("status")
    if not status:
        return False
    if status in NOT_AN_ANSWER_STATUSES:
        return False
    return not (
        response.get("body_scan_truncated") or response.get("body_truncated")
    )


def unanswered_cause(status: int | None) -> str:
    """Why a status in :data:`NOT_AN_ANSWER_STATUSES` is not an answer."""
    if status in PROXY_ANSWER_STATUSES:
        return (
            "a proxy between this runner and the target answered 407 (Proxy "
            "Authentication Required), so the request most likely never reached "
            "the target."
        )
    return "the request was throttled or the handler failed."


def unanswered_remediation(status: int | None) -> str:
    """What to do about a probe that drew a status that is not an answer."""
    if status in PROXY_ANSWER_STATUSES:
        return (
            "Give the proxy the credentials it needs, or exclude the target from "
            "it with no_proxy, and re-run. Until then this boundary is "
            "unverified, not verified."
        )
    return "Re-run when the target is healthy. Until then this boundary is unverified, not verified."


def refusal_sentence(status: int | None) -> str:
    """What a refusal the declaration did not expect says about the target.

    A 407 is Proxy Authentication Required, a proxy's own answer: behind an
    authenticating proxy urllib cannot satisfy, every probe drew one and the
    target received nothing, while the finding said "The target refused this
    request" (measured).
    """
    if status == 407:
        return (
            " HTTP 407 is Proxy Authentication Required: a proxy between this "
            "runner and the target refused the request, which most likely "
            "never reached the target, so this probe measured nothing about it."
        )
    return (
        " The target refused this request, so nothing was returned to this "
        "identity on this probe."
    )


def _target_served(status: int | None) -> bool:
    """Did the target hand this identity a successful response?

    The whole `vulnerable` / `unexpected_denial` split turns on this one
    question, and it used to be answered by an ALLOW-LIST of denial statuses
    (401/403/404/407). Everything outside that list defaulted to `vulnerable`,
    which put nine ordinary non-success codes on the wrong side of it: a sweep of status
    codes found 204, 301, 302, 400, 405, 409, 418, 422 and 451 all reported as
    authorization breaches at SARIF `error` level.

    The worst of those is 302. A redirect to a login page is THE denial in
    every session-based application, and Veridor never follows redirects, so
    not one byte of protected content was served -- and it was reported as a
    boundary failure.

    A success list answers the question the verdict actually asks. 2xx means
    the target served this identity; anything else means it did not, whatever
    the reason. 204 stays on the `vulnerable` side deliberately: a 204 to an
    attacker's DELETE is the target
    performing the write, and for a mutating request success IS the harm, body
    or no body.
    """
    return status is not None and 200 <= status <= 299


def _refuse_unsubstituted_paths(checks: list[dict[str, Any]]) -> None:
    """Refuse a check whose path still carries `{id}`, naming all of them.

    Only for the verbs that SEND the path. `coverage` is a static reading and
    already reports a templated check as a `templated_check_path` diagnostic
    with zero credit; `init` writes placeholders deliberately and tells you to
    replace them. Refusing at load time would make the tool's own scaffold
    unloadable by every command, which is a worse first five minutes than the
    defect.

    `map` refuses to send `REPLACE-WITH-A-REAL-ID` before opening a socket.
    `run` sent `/api/v1/orgs/{id}` verbatim and reported the resulting 404 as
    an authorization finding -- 100 of them in one run, for a docs-only trial
    that had just scaffolded a 250-route config, with nothing anywhere saying
    the cause was its own placeholder. Two commands, opposite postures, the
    same mistake.

    Aggregated on purpose. Refusing one at a time would mean 100 runs to
    enumerate 100 offenders, which is the complaint `--read-only` already
    earns. And it is a refusal rather than a warning because the wrong findings
    otherwise reach the baseline, the SARIF and the exit code -- a warning is
    one line among a hundred false alarms.
    """
    offenders = []
    for check in checks:
        request = check.get("request")
        if not isinstance(request, dict):
            continue
        path = request.get("path")
        if not isinstance(path, str):
            continue
        # The PATH component only. A `{` inside a query string is not a
        # template, and matching the whole string would refuse a legitimate
        # config -- the same false-positive class this guard exists to remove.
        if _PATH_PLACEHOLDER.search(urlsplit(path).path):
            offenders.append(f"{check.get('id', '?')} ({path})")
    if not offenders:
        return
    listed = "\n  ".join(offenders[:10])
    more = (
        f"\n  ... and {len(offenders) - 10} more"
        if len(offenders) > 10
        else ""
    )
    raise ConfigError(
        f"{len(offenders)} check(s) still contain an unsubstituted path "
        f"placeholder, so they name no concrete resource:\n  {listed}{more}\n"
        "Veridor sends the path verbatim and never enumerates ids, so each of "
        "these would request a literal '{id}' and report the refusal as a "
        "finding. Replace each placeholder with a real resource id. If a path "
        "genuinely contains braces, percent-encode them as %7B and %7D."
    )


def _refuse_indistinguishable_identities(identities: dict[str, Any]) -> None:
    """Two identities that send the same credential cannot test each other.

    A docs-only trial's configuration repeated an identity block with a new name and the
    same token, and got `2/2 probes matched their declaration`, exit 0, status
    "passed". Every probe was the owner talking to itself. Nothing about a
    boundary was measured and nothing said so.

    This is a comparison of two dicts, available before a socket is opened, and
    it is deterministic: unlike a rate limit it will be just as wrong tomorrow.
    An identity that deliberately sends nothing is exempt -- several configs
    declare more than one anonymous caller on purpose. A session identity is
    not: its login steps are its credential, compared with its static ones.
    """
    seen: dict[tuple, str] = {}
    for name, identity in identities.items():
        if not isinstance(identity, dict):
            continue
        headers = identity.get("headers") or {}
        if not isinstance(headers, dict):
            continue
        credentials: tuple = tuple(sorted(
            (key.lower(), value) for key, value in headers.items()
            if key.lower() in _CREDENTIAL_HEADER_NAMES
        ))
        if not credentials and any(
            _CUSTOM_CREDENTIAL_HINT.search(key) for key in headers
        ):
            # A credential under a name outside the six (X-Access-Token,
            # PRIVATE-TOKEN) used to be invisible here. It is compared as the
            # whole header set, so two identities collide only when every header
            # they send is byte-identical -- one caller on the wire, whatever
            # its names mean.
            credentials = ("headers",) + tuple(sorted(
                (key.lower(), value) for key, value in headers.items()
            ))
        session = identity.get("session")
        if isinstance(session, dict):
            # A session used to exempt the identity outright, static headers
            # included, so a copy-pasted session block loaded and logged in as
            # the same user twice. The login steps are what make it a caller.
            credentials = ("session", json.dumps(
                session.get("login"), sort_keys=True, default=str
            )) + credentials
        if not credentials:
            continue
        first = seen.setdefault(credentials, name)
        if first != name:
            raise ConfigError(
                f"identities {quoted(first)} and {quoted(name)} send identical credentials, "
                "so every probe would compare an identity with itself and every "
                "expectation between them would pass without testing anything. "
                "Give them different credentials, or delete one."
            )


def _transport_remediation(error: str, target: Mapping[str, Any]) -> str:
    """Name the likely cause, because "unreachable" sends people to the firewall.

    A timeout and a refused connection are different problems with different
    fixes, and the generic advice fits only the second. Measured against a
    healthy target answering in 2.5s with `timeout_seconds: 1`, every probe came
    back "Request failed: timed out. Confirm the target is reachable from the
    runner and retry." -- correct about the symptom, and pointing at networking
    when the fix was one number in the operator's own configuration.

    The fix for that overshot. Every timeout then got "the probe reached it, so
    this is not a reachability problem", including a connect timeout, where
    nothing was reached: on a kind cluster a NetworkPolicy that dropped every
    packet printed that sentence for all 6 probes. So a timeout now carries the
    phase :func:`_transport_error` measured, and the advice says only what that
    phase shows. An error that does not name its phase (a run document written
    before this, or another caller) gets advice that claims neither.
    """
    advice = unsent_remediation(error)
    if advice is not None:
        return advice
    lowered = str(error).lower()
    configured = target.get("timeout_seconds", 10)
    if lowered.startswith("connect timed out"):
        return (
            "No TCP connection to target.base_url was established within "
            f"target.timeout_seconds ({configured}s): the connection attempt got "
            "no answer at all. A network path that drops packets (a firewall, a "
            "Kubernetes NetworkPolicy, a cloud security group), a wrong address, "
            "or a host that is down looks like this. Nothing here shows the "
            "target is merely slow; check that this runner can reach "
            "target.base_url."
        )
    if lowered.startswith("tls handshake timed out"):
        return (
            "A TCP connection was established, but the TLS handshake did not "
            f"finish within target.timeout_seconds ({configured}s). Check that "
            "the port in target.base_url serves TLS, and anything in between (a "
            "proxy or sidecar) that terminates it."
        )
    if lowered.startswith("timed out waiting for a response"):
        return (
            "A TCP connection was established and the request written, but no "
            f"response arrived within target.timeout_seconds ({configured}s). "
            "Whatever accepted the connection -- the target, or a proxy or "
            "sidecar in front of it -- did not answer in time. If the target is "
            "simply slow, raise that value and re-run."
        )
    if lowered.startswith("timed out reading the response body"):
        return (
            "The response started -- the status line and headers arrived -- but "
            "the body stalled for longer than target.timeout_seconds "
            f"({configured}s). If the target sends large or slow bodies, raise "
            "that value and re-run."
        )
    if "timed out" in lowered or "timeout" in lowered:
        return (
            f"Nothing came back within target.timeout_seconds ({configured}s), "
            "and this error does not say whether a connection was established. "
            "A slow target (raise that value) and a network path that drops "
            "packets (check that this runner can reach target.base_url) both "
            "look like this."
        )
    if "refused" in lowered:
        return (
            "Nothing was listening on target.base_url. Check the host and port, "
            "and that the target is up."
        )
    # The resolver's words, not an errno: the message is all this sees. glibc
    # says "Name or service not known", macOS "nodename nor servname provided",
    # and musl -- the release image is python:3.12-alpine -- "Name does not
    # resolve", which fell through to the general advice until 2026-09-27.
    if any(phrase in lowered for phrase in (
            "name or service not known", "nodename nor servname", "name does not resolve")):
        return "The host in target.base_url did not resolve. Check the spelling."
    if "certificate" in lowered or "ssl" in lowered:
        return (
            "The TLS handshake failed. Check the target's certificate and that "
            "the runner trusts its issuer."
        )
    return "Confirm the target is reachable from the runner and retry."


#: What a server may read as a path separator once a segment is decoded: the
#: slash, and the backslash IIS and Windows back ends read as one.
_DECODED_SEPARATORS = re.compile(r"[/\\]")

#: An overlong UTF-8 encoding of an ASCII character: two bytes (C0/C1), three
#: (E0 80-81) or four (F0 80 80-81) where one would do. Invalid UTF-8, so no
#: honest path carries one, but a lenient decoder reads ``%c0%af`` as ``/``
#: and ``%c0%ae`` as ``.`` (IIS 4 and 5, and Tomcat with a UTF-8 URIEncoding
#: in CVE-2008-2938, did; not measured here).
_OVERLONG_ASCII = re.compile(
    rb"[\xc0\xc1][\x80-\xbf]|\xe0[\x80\x81][\x80-\xbf]|\xf0\x80[\x80\x81][\x80-\xbf]"
)

#: How many times a segment is decoded before it is judged undecidable.
_DECODE_ROUNDS = 8


def _overlong_ascii(match: re.Match[bytes]) -> bytes:
    """The one ASCII byte an overlong sequence encodes."""
    data = match.group(0)
    return bytes([((data[-2] & 0x3F) << 6 | (data[-1] & 0x3F)) & 0x7F])


def _decoded_once(text: str) -> str:
    """One round of percent-decoding, reading overlong UTF-8 as its ASCII."""
    raw = _OVERLONG_ASCII.sub(_overlong_ascii, unquote_to_bytes(text))
    return raw.decode("utf-8", "replace")


def _has_dot_segment(path: str) -> bool:
    """True when any path segment is ``.`` or ``..``, however it is encoded.

    A segment counts by what comes before its first ``;``, too: Tomcat and
    Jetty strip a path parameter before they normalise, so ``..;`` (and
    ``..;jsessionid=x``, ``%2e%2e;``, ``..%3b``) is ``..`` to them. Those
    passed this rule, and under a base URL of ``https://gateway/service-a/``
    ``/..;/service-b/admin`` was sent with every identity's credentials.

    And a segment is judged in pieces after it is decoded, split again on
    ``/`` and ``\\``, because a separator can arrive encoded: ``..%2f`` is one
    literal segment whose decoded form, ``../service-b``, is not ``..``, so
    ``/..%2fservice-b/admin`` passed while nginx, which decodes ``%2f``,
    routed ``/service-a/..%2fservice-b/admin`` to service-b (measured). An
    encoded separator inside a name -- ``group%2Fproject`` -- has no ``.`` or
    ``..`` piece and is kept.

    Each segment is decoded until it stops changing, not a fixed number of
    times, and an overlong UTF-8 encoding of an ASCII character is read as
    that character (:data:`_OVERLONG_ASCII`). The rule decoded exactly twice,
    so ``..%25252f`` (``../`` after three) passed, and read ``%c0%af`` as two
    U+FFFD (reproduced: both accepted at load and at send). A segment still
    changing after :data:`_DECODE_ROUNDS` rounds is judged a dot segment: what
    it becomes cannot be seen. Not judged: spellings only one server family
    reads, such as IIS's ``%u002e`` or a segment with trailing spaces.

    Shared with ``sequence``, which refuses a step path resolved at run time
    by the same rule, and with ``matrix``.
    """
    for segment in path.split("?", 1)[0].split("/"):
        spelling = segment
        for _ in range(_DECODE_ROUNDS + 1):
            for piece in _DECODED_SEPARATORS.split(spelling):
                if piece.split(";", 1)[0] in {".", ".."}:
                    return True
            decoded = _decoded_once(spelling)
            if decoded == spelling:
                break
            spelling = decoded
        else:
            return True
    return False


def _outside_base_path(base_url: str, url: str) -> bool:
    """Whether ``url``'s path leaves the path of ``base_url``.

    The rule `map` has always applied (``matrix._assert_on_target``): with a
    base URL of ``https://gateway/service-a/`` a request must stay at or under
    ``/service-a``. A base URL with no path contains nothing beyond its origin,
    exactly as before.
    """
    base_path = urlsplit(base_url).path.rstrip("/")
    joined_path = urlsplit(url).path
    return bool(base_path) and not (
        joined_path == base_path or joined_path.startswith(base_path + "/")
    )


def _validate_request(request: dict[str, Any], label: str) -> None:
    """Validate one outbound request surface.

    Shared verbatim by check requests and by identity ``marker_probe``
    requests: a control probe reaches the same target over the same opener, so
    it is held to the same same-origin, HTTP-token, and header rules. ``label``
    reproduces the caller's phrasing so historical error text is unchanged.
    """
    method = request.get("method", "GET")
    path = request.get("path")
    if not isinstance(method, str) or not _HTTP_TOKEN.fullmatch(method):
        raise ConfigError(f"{label}.method must be an HTTP token")
    if method.isalpha() and method != method.upper():
        # Not pedantry, and not silently upper-cased either. The safety
        # envelope evaluates `method.upper()` -- so `delete` is correctly
        # refused by --read-only -- while the request goes out with whatever
        # was written. The gate and the wire would be reasoning about
        # different verbs, and a target that routes case-insensitively would
        # act on one the gate never saw. Refusing keeps them the same verb.
        #
        # `isalpha()` restricts this to tokens that could plausibly BE a verb.
        # Every standard method is alphabetic, as is every realistic mistake
        # ('get', 'post', 'delete'). Anything else -- a marker planted in the
        # method slot, say -- belongs to the reflection guard further down,
        # and reporting it as a casing problem would bury the real finding.
        # Upper-casing instead of refusing would be worse still: it would
        # destroy the very string that guard exists to detect.
        raise ConfigError(
            f"{label}.method must be upper case: write {quoted(method.upper())}, "
            f"not {quoted(method)}. HTTP methods are case-sensitive, and Veridor's "
            "safety gates match on the upper-case form."
        )
    try:
        parsed_path = urlsplit(path) if isinstance(path, str) else None
        # What _perform_request actually joins onto base_url is
        # ``path.lstrip("/")``, not ``path``. ``/http://collector/x`` parses
        # here with no scheme and no host, and lstrips to an ABSOLUTE URL that
        # urljoin sends -- with every identity's credentials -- to that host.
        # Measured: a loopback capsule whose check path was
        # ``/http://127.0.0.1:<collector>/steal`` passed every verify gate and
        # delivered the verifier's VERIDOR_* tokens to the collector. So the
        # joined form is judged too.
        joined_path = urlsplit(path.lstrip("/")) if isinstance(path, str) else None
    except ValueError as exc:
        raise ConfigError(f"{label}.path is invalid: {terminal_text(exc)}") from exc
    if (
        parsed_path is None
        or joined_path is None
        or not path.startswith("/")
        or path.startswith("//")
        or parsed_path.scheme
        or parsed_path.netloc
        or parsed_path.fragment
        or any(ord(character) <= 32 or ord(character) == 127 for character in path)
        # http.client encodes the request line as ASCII. A non-ASCII path
        # raises UnicodeEncodeError from inside the opener, which is not a
        # transport error and used to abort the entire process. Refusing it
        # here turns an unhandled crash into a normal, typed refusal.
        or not path.isascii()
    ):
        raise ConfigError(f"{label}.path must be a same-origin absolute path")
    if joined_path.scheme or joined_path.netloc:
        # The path is deliberately not quoted: it has been expanded from the
        # environment by now and can carry a credential.
        raise ConfigError(
            f"{label}.path must be a same-origin absolute path. Without its "
            "leading '/' it reads as a URL with a scheme of its own, and Veridor "
            "joins it onto target.base_url in that form, so the request would "
            "not be the path you wrote -- an absolute URL such as "
            "'/http://host/x' would go, with every identity's credentials, to "
            "that host instead of the target. Nothing has been sent. If a "
            "segment before the first '/' really contains ':', percent-encode "
            "that ':' as %3A."
        )
    if _has_dot_segment(path):
        # urljoin applies RFC 3986 dot-segment removal, so '/../service-b/x'
        # against a base URL of 'https://gateway/service-a/' was sent to
        # '/service-b/x' -- another application behind the same gateway, with
        # every identity's credentials, while the banner named service-a. A
        # percent-encoded '%2e%2e' is refused too: urljoin leaves it, and a
        # gateway that decodes it routes the same way. `map` and sequence
        # step paths resolved at run time already refused both.
        raise ConfigError(
            f"{label}.path must not contain a '.' or '..' segment: plain, "
            "percent-encoded any number of times or as overlong UTF-8 "
            "('%c0%ae' is '.' to a lenient decoder), before a ';' path parameter "
            "('..;' is '..' to a servlet container), or next to an encoded "
            "'/' or '\\' ('..%2f' is '../' to a gateway that decodes it); a "
            "segment still decoding after eight rounds is refused as well. "
            "Veridor joins the path onto "
            "target.base_url, and such a segment moves the request to a "
            "different path than the one you wrote, outside the base URL's "
            "path if it has one. Write the path you mean. Nothing has been "
            "sent."
        )
    _validate_headers(request.get("headers", {}), f"{label}.headers")
    # A configured Accept-Encoding is accepted and then ignored: _perform_request
    # strips every Accept-Encoding header and sets 'identity' unconditionally,
    # so the value can never reach the wire. Failing the load instead would buy
    # no safety and would break configurations earlier releases accepted.
    if "json" in request and "body" in request:
        raise ConfigError(f"{label} cannot define both json and body")
    if "body" in request and not isinstance(request["body"], str):
        raise ConfigError(f"{label}.body must be a string")


def _validate_marker_probe(
    name: str, identity: dict[str, Any], markers: dict[str, str]
) -> None:
    """Validate one identity-level marker control probe.

    A ``marker_probe`` exists to prove that ``identity``'s own marker is live
    and observable somewhere the API will serve it. Naming an identity that
    plants no marker is therefore not a degraded configuration but a
    meaningless one, and it fails the load.
    """
    probe = identity["marker_probe"]
    label = f"identity {quoted(name)} marker_probe"
    if not isinstance(probe, dict):
        raise ConfigError(f"{label} must be an object")
    if name not in markers:
        raise ConfigError(
            f"{label} names an identity that defines no 'marker' field; a marker "
            f"probe exists to prove that identity's marker is live.{_MARKER_HINT}"
        )
    _refuse_near_miss_request_keys(probe, _REQUEST_KEYS, label)
    _validate_request(probe, label)


def _capture_references(value: Any) -> list[str]:
    """Every ``${capture.<name>}`` referenced anywhere inside ``value``."""
    if isinstance(value, str):
        return _CAPTURE_REF.findall(value)
    if isinstance(value, list):
        return [name for item in value for name in _capture_references(item)]
    if isinstance(value, dict):
        return [
            name
            for pair in value.items()
            for item in pair
            for name in _capture_references(item)
        ]
    return []


def _reject_capture_references(value: Any, label: str) -> None:
    """Refuse ``${capture.…}`` outside a session, where nothing would resolve it.

    Left unchecked the literal text ``${capture.csrf}`` would be sent to the
    target, which is not the request the operator wrote.
    """
    for name in _capture_references(value):
        raise ConfigError(
            f"{label} references undefined capture {quoted(name)}; only an identity "
            "'session' declares captures, and they reach a request through "
            "'session.inject' or a login step"
        )


def _capture_map(value: Any, label: str) -> dict[Any, Any]:
    """A ``capture`` block, which maps capture names to declarations.

    Absent is empty. Anything but an object is refused: ``.items()`` on a
    string or a number raised AttributeError, which the command reports as
    exit 70, "a bug in Veridor" (measured).
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object mapping capture names to declarations")
    return value


def _validate_capture_spec(spec: Any, label: str, allowed: frozenset[str]) -> str:
    """Validate one capture declaration and return its recorded source string."""
    if not isinstance(spec, dict):
        raise ConfigError(f"{label} must be an object")
    # Unknown keys that are not near misses load as annotations, so a TLS key
    # here would otherwise load and do nothing.
    _refuse_tls_keys(spec, label)
    unknown = _suspicious_keys(sorted(set(spec) - _CAPTURE_SPEC_KEYS), _CAPTURE_SPEC_KEYS)
    if unknown:
        raise ConfigError(
            f"{label} has unsupported keys: {terminal_names(unknown)}"
            f" (did you mean one of {', '.join(sorted(_CAPTURE_SPEC_KEYS))}?) "
            + _annotation_way_out(unknown)
        )
    source = spec.get("from")
    # A list or an object is unhashable: `in` raised TypeError, exit 70.
    if not isinstance(source, str) or source not in allowed:
        raise ConfigError(
            f"{label} 'from' must be one of {', '.join(sorted(allowed))}"
        )
    if source == "json_pointer":
        pointer = spec.get("pointer")
        if not isinstance(pointer, str) or not pointer.startswith("/"):
            raise ConfigError(f"{label} requires an RFC 6901 'pointer' starting with '/'")
        return f"json_pointer:{pointer}"
    name = spec.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{label} requires a non-empty 'name'")
    if source == "header" and not _HTTP_TOKEN.fullmatch(name):
        raise ConfigError(f"{label} 'name' is not a valid header name")
    return f"{source}:{name}"


def _validate_session(name: str, identity: dict[str, Any], markers: dict[str, str]) -> None:
    """Validate one identity's session declaration. Every failure is exit 2.

    No message in this function ever echoes a header value, a cookie value, or a
    capture value -- the precedent ``_validate_headers`` set, extended to the
    credentials this feature introduces.
    """
    session = identity["session"]
    label = f"identity {quoted(name)} session"
    if not isinstance(session, dict):
        raise ConfigError(f"{label} must be an object")
    unknown = _suspicious_keys(sorted(set(session) - _SESSION_KEYS), _SESSION_KEYS)
    if unknown:
        raise ConfigError(
            f"{label} has unsupported keys: {terminal_names(unknown)}"
            f" (did you mean one of {', '.join(sorted(_SESSION_KEYS))}?) "
            + _annotation_way_out(unknown)
        )
    for header in identity.get("headers", {}) or {}:
        if isinstance(header, str) and header.lower() == "cookie":
            # CookieJar.add_cookie_header does nothing when a Cookie header is
            # already present, so this combination would silently send the
            # stale static cookie and drop the live session cookie: a probe that
            # runs unauthenticated, is denied, and matches a declared denial.
            raise ConfigError(
                f"identity {quoted(name)} declares both a static Cookie header and a "
                "session; the session cookie would be silently dropped. Remove one."
            )

    declared: dict[str, str] = {}
    for capture_name, spec in _capture_map(session.get("capture"), f"{label} 'capture'").items():
        if not isinstance(capture_name, str) or not _CAPTURE_NAME.fullmatch(capture_name):
            raise ConfigError(f"{label} capture names must be identifiers")
        declared[capture_name] = _validate_capture_spec(
            spec,
            f"{label} capture {quoted(capture_name)}",
            # A session-level capture is read live at send time, and the jar is
            # the only source that HAS a live value; the rest are properties of
            # one response and belong on the login step that produced it.
            frozenset({"cookie"}),
        )

    login = session.get("login")
    if login is not None and (not isinstance(login, list) or not login):
        raise ConfigError(f"{label} 'login' must be a non-empty list of requests")
    steps = login or []
    if len(steps) > MAX_LOGIN_STEPS:
        raise ConfigError(
            f"{label} declares {len(steps)} login steps; the limit is {MAX_LOGIN_STEPS}"
        )
    for index, step in enumerate(steps):
        step_label = f"{label} login step {index}"
        if not isinstance(step, dict):
            raise ConfigError(f"{step_label} must be an object")
        _refuse_near_miss_request_keys(step, _LOGIN_STEP_KEYS, step_label)
        _validate_request(step, step_label)
        statuses = step.get("expect_status")
        if isinstance(statuses, int) and not isinstance(statuses, bool):
            statuses = [statuses]
            step["expect_status"] = statuses
        if (
            not isinstance(statuses, list)
            or not statuses
            or not all(
                isinstance(status, int)
                and not isinstance(status, bool)
                and 100 <= status <= 599
                for status in statuses
            )
        ):
            raise ConfigError(
                f"{step_label} requires 'expect_status' (a 302 login is common; "
                "declare it)"
            )
        for header in step.get("headers", {}) or {}:
            if isinstance(header, str) and header.lower() in _CREDENTIAL_HEADERS:
                if _capture_references(step["headers"][header]):
                    raise ConfigError(
                        f"{step_label} cannot fill the {quoted(header)} header from a "
                        "capture; the cookie jar and the identity's static "
                        "headers own the credential slots"
                    )
        for capture_name, spec in _capture_map(
            step.get("capture"), f"{step_label} 'capture'"
        ).items():
            if not isinstance(capture_name, str) or not _CAPTURE_NAME.fullmatch(capture_name):
                raise ConfigError(f"{step_label} capture names must be identifiers")
            if capture_name in declared:
                raise ConfigError(
                    f"{label} declares capture {quoted(capture_name)} more than once"
                )
            declared[capture_name] = _validate_capture_spec(
                spec, f"{step_label} capture {quoted(capture_name)}", _CAPTURE_SOURCES
            )

    inject = session.get("inject")
    if inject is not None and not isinstance(inject, list):
        raise ConfigError(f"{label} 'inject' must be a list")
    for index, entry in enumerate(inject or []):
        entry_label = f"{label} inject {index}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{entry_label} must be an object")
        # As for a capture spec: an unknown key is an annotation, so a TLS key
        # must be refused by name or it loads and does nothing.
        _refuse_tls_keys(entry, entry_label)
        unknown = _suspicious_keys(sorted(set(entry) - _INJECT_KEYS), _INJECT_KEYS)
        if unknown:
            raise ConfigError(
                f"{entry_label} has unsupported keys: {terminal_names(unknown)}"
                f" (did you mean one of {', '.join(sorted(_INJECT_KEYS))}?) "
                + _annotation_way_out(unknown)
            )
        slots = [slot for slot in ("header", "form_field", "json_field") if slot in entry]
        if len(slots) != 1:
            raise ConfigError(
                f"{entry_label} must set exactly one of 'header', 'form_field', "
                "or 'json_field'"
            )
        target = entry[slots[0]]
        if not isinstance(target, str) or not target:
            raise ConfigError(f"{entry_label} {quoted(slots[0])} must be a non-empty string")
        if slots[0] == "header":
            if not _HTTP_TOKEN.fullmatch(target):
                raise ConfigError(f"{entry_label} 'header' is not a valid header name")
            _refuse_host_header(target, entry_label)
            if target.lower() in _CREDENTIAL_HEADERS:
                raise ConfigError(
                    f"identity {quoted(name)} session inject cannot set the {quoted(target)} "
                    "header; the session cookie jar owns it"
                )
        value = entry.get("value")
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{entry_label} requires a 'value'")
        if _INVALID_HEADER_VALUE.search(value):
            raise ConfigError(f"{entry_label} 'value' contains a control character")

    establishes = session.get("establishes")
    if not isinstance(establishes, dict):
        raise ConfigError(
            f"identity {quoted(name)} session requires 'establishes' naming the cookie "
            "or capture that proves login succeeded"
        )
    # Unknown keys are refused rather than ignored. `establishes` was the one
    # object in the session schema that accepted anything: an operator who
    # wrote `"csrf": {...}` here -- a reasonable guess, since CSRF really is a
    # session concern -- got silence and a session that established nothing of
    # the sort. Silently ignoring configuration is how a check becomes vacuous,
    # which is the failure this whole product is built to surface, so it cannot
    # be the loader's own behaviour.
    unsupported = sorted(set(establishes) - _ESTABLISHES_KEYS)
    if unsupported:
        raise ConfigError(
            f"identity {quoted(name)} session 'establishes' has unsupported keys: "
            f"{terminal_names(unsupported)} (expected one of "
            f"{', '.join(sorted(_ESTABLISHES_KEYS))}). A CSRF token is captured "
            "on a login step and applied with 'inject', not declared here."
        )
    present = [key for key in ("cookie", "capture") if key in establishes]
    if len(present) != 1 or not isinstance(establishes[present[0]], str) or not establishes[present[0]]:
        raise ConfigError(
            f"identity {quoted(name)} session 'establishes' must set exactly one of "
            "'cookie' or 'capture'"
        )
    if present[0] == "capture" and establishes["capture"] not in declared:
        raise ConfigError(
            f"{label} 'establishes' names capture {quoted(establishes['capture'])}, "
            "which the session does not declare"
        )

    reestablish = session.get("reestablish", "run")
    if not isinstance(reestablish, str) or reestablish not in _REESTABLISH_SCOPES:
        raise ConfigError(
            f"{label} 'reestablish' must be one of {', '.join(sorted(_REESTABLISH_SCOPES))}"
        )

    for referenced in _capture_references(
        [session.get("login"), session.get("inject")]
    ):
        if referenced not in declared:
            raise ConfigError(f"{label} references undefined capture {quoted(referenced)}")
    if not steps and not declared:
        raise ConfigError(
            f"{label} declares neither 'login' nor 'capture', so it establishes "
            "nothing"
        )


#: What a check id, sequence id or identity name may contain.
#:
#: These strings are interpolated into console output, into GitHub workflow
#: commands, and into SARIF. A check id carrying `ESC[9A` (cursor up nine
#: lines) and `ESC[J` (erase to end of screen) rewrote the run summary in a
#: terminal and in any CI log viewer that renders ANSI -- reproduced, and the
#: forged text was a clean-looking pass. The exit code stayed correct, so this
#: never defeated the gate; it defeated the human reading the log. Since the
#: README asks you to COMMIT veridor.json, the threat model is a pull request,
#: which is the threat model the gate exists for.
#:
#: Validated rather than stripped. A check id is a fingerprint input -- it
#: decides which baseline entry a finding matches -- so silently rewriting one
#: would silently re-key somebody's baseline. Refusing says so instead. Same
#: charset the viewer already requires of a run id (`server._RUN_ID`).
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

#: Deliberately not in _SAFE_NAME: a name is a key, not prose. `name` and
#: `description` are free text and are NOT constrained here -- they are not
#: fingerprint inputs and not path components. They are escaped where they are
#: printed instead.
_SAFE_NAME_HINT = (
    "letters, digits, dot, underscore and hyphen only -- it is a fingerprint "
    "input and is written to your terminal, so control characters are refused"
)


def _validate_safe_name(value: str, label: str) -> None:
    if not _SAFE_NAME.match(value):
        raise ConfigError(f"{label} must be {_SAFE_NAME_HINT}: {quoted(value)}")


def declared_statuses(value: Any) -> list[int] | None:
    """The HTTP statuses an expectation's ``status`` declares, or ``None``.

    A single integer is read as a one-element list: the schema documents that
    shorthand. ``None`` means the value declares nothing an answer could
    match (a string, a bool, an empty list, a number outside 100-599).

    One rule for every reader of an expectation. The config loader applied it
    to its own copy only, and the capsule reads the file as written, so the
    shorthand reached ``capsule._unmeasured`` as a bare ``404`` and its
    membership test raised TypeError -- `verify` exited 70 on exactly the run
    where the boundary held.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        value = [value]
    if isinstance(value, list) and value and all(
        isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599
        for status in value
    ):
        return list(value)
    return None


def _validate_check(
    check: Any,
    identities: dict[str, Any],
    check_ids: set[str],
    markers: dict[str, str] | None = None,
) -> None:
    if not isinstance(check, dict):
        raise ConfigError("each check must be an object")
    check_id = check.get("id")
    if not isinstance(check_id, str) or not check_id:
        raise ConfigError("each check requires a non-empty id")
    _validate_safe_name(check_id, "a check id")
    if check_id in check_ids:
        raise ConfigError(f"duplicate check id: {check_id}")
    check_ids.add(check_id)

    request = check.get("request")
    if not isinstance(request, dict):
        raise ConfigError(f"check {quoted(check_id)} requires a request object")
    _refuse_near_miss_request_keys(request, _REQUEST_KEYS, f"check {quoted(check_id)} request")
    _validate_request(request, f"check {quoted(check_id)} request")
    # A check capture would be shared across identities and would let one
    # identity borrow another's credential; there is no such thing, and the
    # literal text must never reach the wire either.
    _reject_capture_references(request, f"check {quoted(check_id)} request")

    expected = check.get("expect")
    if not isinstance(expected, dict) or len(expected) < 2:
        raise ConfigError(f"check {quoted(check_id)} must expect results for at least two users")
    unknown = set(expected) - set(identities)
    if unknown:
        raise ConfigError(
            f"check {quoted(check_id)} references unknown identities: "
            f"{terminal_names(sorted(unknown))}"
        )
    for identity, expectation in expected.items():
        if not isinstance(expectation, dict):
            raise ConfigError(
                f"check {quoted(check_id)} expectation for {quoted(identity)} must be an object"
            )
        statuses = declared_statuses(expectation.get("status"))
        if statuses is None:
            raise ConfigError(
                f"check {quoted(check_id)} expectation for {quoted(identity)} requires HTTP status values"
            )
        expectation["status"] = statuses
        _validate_marker_expectation(
            check_id, identity, expectation, expected, identities, markers or {}
        )


def _validate_marker_expectation(
    check_id: str,
    identity: str,
    expectation: dict[str, Any],
    expected: dict[str, Any],
    identities: dict[str, Any],
    markers: dict[str, str],
) -> None:
    """Resolve every marker reference at load time so runtime cannot fail."""
    label = f"check {quoted(check_id)} expectation for {quoted(identity)}"
    # A typo such as 'contain_marker' would silently disable a security oracle,
    # so near-misses of a real key fail closed. An unrecognised key that is not
    # a near-miss is an annotation and is ignored, as earlier releases did.
    suspicious = _suspicious_keys(
        sorted(set(expectation) - _MARKER_EXPECT_KEYS), _MARKER_EXPECT_KEYS
    )
    if suspicious:
        raise ConfigError(
            f"{label} has unsupported keys: {terminal_names(suspicious)}"
            f" (did you mean one of {', '.join(sorted(_MARKER_EXPECT_KEYS))}?) "
            + _annotation_way_out(suspicious)
        )
    contains = expectation.get("contains_marker")
    excludes = expectation.get("excludes_marker")
    if contains is not None and excludes is not None:
        raise ConfigError(
            f"{label} cannot set both contains_marker and excludes_marker"
        )
    for field, owner in (("contains_marker", contains), ("excludes_marker", excludes)):
        if owner is None:
            continue
        if not isinstance(owner, str) or not owner:
            raise ConfigError(f"{label} {field} must name an identity")
        if owner not in identities:
            raise ConfigError(f"{label} {field} references unknown identity {quoted(owner)}")
        if owner not in markers:
            raise ConfigError(
                f"{label} {field} references identity {quoted(owner)}, which defines no "
                f"'marker' field.{_MARKER_HINT}"
            )
    if excludes is None:
        return
    if excludes == identity:
        raise ConfigError(
            f"{label} cannot exclude its own marker; excludes_marker names the "
            "identity whose data must not appear"
        )
    if _has_check_control(expected, excludes):
        return
    owner_identity = identities.get(excludes)
    if isinstance(owner_identity, dict) and "marker_probe" in owner_identity:
        # A per-principal-scoped API paths the resource by the CALLER's own
        # principal, so the marker owner can never be probed at the attacker's
        # path and a same-check control is impossible. The identity-level
        # marker_probe is that control, run once per run before the checks.
        return
    # Without a control the absence of a marker is unfalsifiable, so a control
    # is mandatory rather than advisory.
    example = json.dumps(
        {excludes: {"status": [200], "contains_marker": excludes}},
        sort_keys=True,
    )
    raise ConfigError(
        f"{label} excludes_marker {quoted(excludes)} requires a control in the same "
        f"check; add {example} to check {quoted(check_id)} expect, or give identity "
        f"{quoted(excludes)} a 'marker_probe' naming a path where its own marker is served"
    )


def _has_check_control(expected: dict[str, Any], owner: str) -> bool:
    """True when this check probes ``owner`` and asserts ``owner``'s own marker."""
    control = expected.get(owner)
    return isinstance(control, dict) and control.get("contains_marker") == owner


def _is_implicit_control(check: dict[str, Any], owner: str) -> bool:
    """True when ``owner`` is probed by this check and could act as a control.

    The check already issues the request under test as ``owner``, and some
    other identity in the same check must not receive ``owner``'s marker. That
    response is therefore free evidence about the only question a control can
    answer -- can this path surface ``owner``'s marker at all? -- and it costs
    no extra request to scan it.

    Excluded when ``owner``'s own expectation already names a marker: an
    explicit ``contains_marker: owner`` is the stronger declared control and is
    handled ahead of this, and any other declared marker means the single
    per-probe scan is already committed elsewhere.
    """
    expectation = check["expect"].get(owner)
    if not isinstance(expectation, dict):
        return False
    if expectation.get("contains_marker") or expectation.get("excludes_marker"):
        return False
    return any(
        name != owner
        and isinstance(other, dict)
        and other.get("excludes_marker") == owner
        for name, other in check["expect"].items()
    )


def _redact_query(query: str) -> str:
    """Redact every query value, and every valueless parameter outright.

    ``parse_qsl`` reports ``?<token>`` as the key ``<token>`` with an empty
    value. Redacting only the value half would leave an opaque pre-signed or
    unsubscribe token fully intact while a cosmetic ``=[REDACTED]`` made the
    URL look scrubbed, so a parameter with no ``=`` is replaced whole: with no
    key/value split, the parameter IS the value.
    """
    parts: list[str] = []
    for element in query.split("&"):
        if not element:
            continue
        name, separator, _ = element.partition("=")
        if not separator:
            parts.append(quote_plus("[REDACTED]"))
            continue
        decoded = parse_qsl(f"{name}=", keep_blank_values=True)
        key = decoded[0][0] if decoded else ""
        parts.append(f"{quote_plus(key)}={quote_plus('[REDACTED]')}")
    return "&".join(parts)


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    redacted_query = _redact_query(parsed.query)
    host = parsed.hostname
    if host:
        safe_host = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            safe_host = f"{safe_host}:{parsed.port}"
        netloc = (
            f"REDACTED@{safe_host}"
            if parsed.username is not None or parsed.password is not None
            else safe_host
        )
    else:
        netloc = "[REDACTED]" if parsed.netloc else ""
    return urlunsplit((parsed.scheme, netloc, parsed.path, redacted_query, ""))


def _finding_id(
    check: dict[str, Any],
    identity: str,
    kind: str,
    expected_statuses: list[int],
) -> str:
    request = check["request"]
    body = request.get("json", request.get("body"))
    signature = {
        "check_id": check["id"],
        "identity": identity,
        "kind": kind,
        "method": request.get("method", "GET").upper(),
        "path": request["path"],
        "body_sha256": hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "expected_statuses": sorted(expected_statuses),
    }
    value = json.dumps(signature, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()[:20]


def _request_body(request_config: dict[str, Any]) -> bytes | None:
    if "json" in request_config:
        return json.dumps(request_config["json"], separators=(",", ":")).encode()
    body = request_config.get("body")
    return body.encode() if isinstance(body, str) else None


def _normalize_content_encoding(value: str | None) -> str:
    if not value:
        return "identity"
    tokens = [token.strip().lower() for token in value.split(",")]
    tokens = [token for token in tokens if token]
    if not tokens or tokens == ["identity"]:
        return "identity"
    if len(tokens) == 1 and tokens[0] in _SUPPORTED_CONTENT_ENCODINGS:
        return "deflate" if tokens[0] == "deflate" else "gzip"
    return "unsupported"


def _safe_error(exc: BaseException) -> str:
    """Describe a failed request without persisting any bytes the server sent.

    ``error`` is copied verbatim into the run JSON, the SARIF message, stdout,
    and the GitHub Actions annotation, and ``veridor serve`` republishes it, so
    it is held to the same rule as a response body: no response text, no
    headers, no tokens are ever written to disk. Several ``http.client``
    exceptions carry the raw wire bytes that confused the parser, which is a
    response body by another name, so those never contribute their own message.
    """
    reason: Any = exc.reason if isinstance(exc, URLError) else exc
    if isinstance(reason, BaseException):
        for kind, description in _OPAQUE_HTTP_ERRORS:
            if isinstance(reason, kind):
                return description
        if (
            isinstance(reason, http.client.HTTPException)
            and type(reason) not in _TRANSPARENT_HTTP_ERRORS
        ):
            # An unfamiliar HTTPException may embed wire bytes too; report the
            # class and nothing else.
            return f"the server sent a malformed HTTP response ({type(reason).__name__})"
    text = " ".join(str(reason).split())
    if len(text) > _MAX_ERROR_CHARS:
        return text[:_MAX_ERROR_CHARS] + "..."
    return text


def _timeout_phase(exc: BaseException, *, response_started: bool) -> str | None:
    """Which phase of a request timed out, read from the exception itself.

    Measured on python 3.11, 3.12 and 3.13 with urllib: a timeout while
    connecting (or during the TLS handshake, or while writing the request) is
    wrapped in ``URLError`` by ``AbstractHTTPHandler.do_open``, and its
    traceback names ``create_connection`` for the TCP connect or
    ``do_handshake`` for TLS; a timeout in ``getresponse()`` -- connection up,
    request written, no status line yet -- is a bare ``TimeoutError``; one
    while reading the body comes after the response object existed. A wrapped
    timeout naming neither frame stays "before a response" and claims no more.
    """
    reason = exc.reason if isinstance(exc, URLError) else exc
    if not isinstance(reason, TimeoutError):
        return None
    if response_started:
        return "body"
    if not isinstance(exc, URLError):
        return "response"
    frames = {frame.f_code.co_name for frame, _ in traceback.walk_tb(reason.__traceback__)}
    if "do_handshake" in frames:
        return "tls"
    if "create_connection" in frames:
        return "connect"
    return "before_response"


def _transport_error(exc: BaseException, timeout: float, *, response_started: bool) -> str:
    """The persisted ``error`` for a request that failed in transport.

    A timeout says which phase timed out and what that phase establishes --
    nothing more. Every other failure keeps :func:`_safe_error`'s text.
    """
    phase = _timeout_phase(exc, response_started=response_started)
    seconds = f"{timeout:g}s"
    if phase == "connect":
        return f"connect timed out: no TCP connection to the target was established within {seconds}"
    if phase == "tls":
        return (
            "TLS handshake timed out: a TCP connection was established, but the "
            f"TLS handshake did not finish within {seconds}"
        )
    if phase == "response":
        return (
            "timed out waiting for a response: a TCP connection was established "
            f"and the request written, but no response arrived within {seconds}"
        )
    if phase == "body":
        return (
            "timed out reading the response body: the status line and headers "
            f"arrived, but the body stalled for longer than {seconds}"
        )
    if phase == "before_response":
        return (
            f"timed out before a response, within {seconds}, while connecting or "
            "writing the request; whether a connection was established was not "
            "recorded"
        )
    return _safe_error(exc)


def _decompress_members(
    decompressor: Any, chunk: bytes, budget: int
) -> tuple[Any, bytes]:
    """Decode ``chunk`` across concatenated members, up to ``budget`` bytes.

    One ``decompressobj`` decodes exactly one gzip member: at its trailer it
    sets ``eof``, parks every remaining byte in ``unused_data``, and returns
    ``b''`` forever after. Concatenated members are legal ``Content-Encoding:
    gzip`` (RFC 1952 section 2.2) and are what streaming producers emit, so
    stopping at member one would let Veridor claim a marker was absent from a
    body it never decoded. Returns the decompressor to carry into the next
    chunk, which is a fresh object whenever a member boundary was crossed.
    """
    parts: list[bytes] = []
    pending = chunk
    while budget > 0:
        if decompressor.eof:
            pending = decompressor.unused_data + pending
            if not pending:
                break
            decompressor = zlib.decompressobj(zlib.MAX_WBITS | 32)
        elif not pending:
            break
        produced = decompressor.decompress(pending, max_length=budget)
        parts.append(produced)
        budget -= len(produced)
        pending = decompressor.unconsumed_tail
        if not produced and not decompressor.eof:
            # The decoder consumed the input without emitting anything (a
            # partial header); it needs the next chunk.
            break
    return decompressor, b"".join(parts)


def _body_incomplete(stream: Any) -> bool:
    """True when the peer closed before the declared body length was delivered.

    ``http.client.HTTPResponse.read(amt)`` deliberately returns ``b''`` instead
    of raising ``IncompleteRead`` when a ``Content-Length`` body is cut short,
    so the read loop cannot tell a real end of body from a severed socket. The
    unread remainder is left on ``length``, which is ``0`` for a complete body
    and for the bodiless responses (HEAD, 204, 304) the client zeroes up front.
    """
    remaining = getattr(stream, "length", None)
    return isinstance(remaining, int) and not isinstance(remaining, bool) and remaining > 0


def _scan_response(
    stream: Any,
    content_encoding: str | None,
    needles: tuple[bytes, ...] | None,
) -> tuple[bytes, bool, str | None, str | None, list[str], str | None, int, bool]:
    """Stream, optionally decompress, and scan a response without retaining it.

    Returns ``(retained_wire_bytes, body_truncated, marker_scan,
    marker_scan_reason, marker_encodings, body_encoding, body_scanned_bytes,
    body_scan_truncated)``. ``retained_wire_bytes`` holds at most
    ``_MAX_RESPONSE_BYTES + 1`` raw wire bytes purely so the caller can hash and
    measure them; the caller discards it immediately afterwards.
    """
    body_encoding = _normalize_content_encoding(content_encoding)
    retained = bytearray()
    matched: list[str] = []
    reason: str | None = None
    decoded_seen = 0
    wire_fed = 0
    scan_truncated = False
    reached_eof = False
    overlap = b""
    window = (max(len(needle) for needle in needles) - 1) if needles else 0
    scanning = needles is not None and body_encoding != "unsupported"
    if needles is not None and body_encoding == "unsupported":
        reason = "encoding_unsupported"
    decompressor = (
        # MAX_WBITS | 32 auto-detects gzip and zlib-wrapped deflate. Raw
        # headerless deflate raises zlib.error, which is the safe direction.
        zlib.decompressobj(zlib.MAX_WBITS | 32)
        if scanning and body_encoding in {"gzip", "deflate"}
        else None
    )

    while True:
        chunk = stream.read(_CHUNK_BYTES)
        if not chunk:
            reached_eof = True
            break
        if len(retained) <= _MAX_RESPONSE_BYTES:
            retained.extend(chunk[: _MAX_RESPONSE_BYTES + 1 - len(retained)])
        if scanning:
            remaining = _MAX_MARKER_SCAN_BYTES - decoded_seen
            if remaining <= 0:
                scan_truncated = True
                scanning = False
            else:
                decoded = b""
                if decompressor is not None:
                    wire_fed += len(chunk)
                    try:
                        # max_length bounds a decompression bomb at the scan
                        # ceiling; unconsumed_tail is only ever non-empty once
                        # that ceiling is reached, and we stop scanning there.
                        decompressor, decoded = _decompress_members(
                            decompressor, chunk, remaining
                        )
                    except zlib.error:
                        scanning = False
                        body_encoding = "unsupported"
                        reason = "decode_failed"
                else:
                    decoded = chunk[:remaining]
                if scanning and decoded:
                    decoded_seen += len(decoded)
                    buffered = overlap + decoded
                    haystack = buffered.lower()
                    matched = [
                        label
                        for label, needle in zip(_NEEDLE_ENCODINGS, needles or ())
                        if needle in haystack
                    ]
                    if matched:
                        scanning = False
                    else:
                        overlap = buffered[-window:] if window else b""
                if scanning and decoded_seen >= _MAX_MARKER_SCAN_BYTES:
                    scan_truncated = True
                    scanning = False
        if len(retained) > _MAX_RESPONSE_BYTES and not scanning:
            # Never stop before the digest window is complete while a scan is
            # still live, so body_sha256 is unchanged for bodies <= 1 MiB.
            break

    if (
        reached_eof
        and decompressor is not None
        and wire_fed
        and not matched
        and reason is None
        and not scan_truncated
        and not decompressor.eof
    ):
        # A compressed stream that ended mid-member was not fully materialized,
        # so its silence is not evidence of absence.
        body_encoding = "unsupported"
        reason = "decode_failed"

    if (
        reached_eof
        and needles is not None
        and not matched
        and reason is None
        and not scan_truncated
        and _body_incomplete(stream)
    ):
        # Identity-encoded bodies reach this branch, and they carry the
        # overwhelming majority of real responses. A body cut short on the wire
        # was not fully materialized, so its silence is not evidence of absence
        # -- the same rule the compressed guard above applies.
        reason = "incomplete_body"

    if needles is None:
        marker_scan: str | None = None
        reason = None
        matched = []
    elif matched:
        marker_scan = "present"
        reason = None
    elif reason is not None:
        marker_scan = "unknown"
    elif scan_truncated:
        marker_scan = "unknown"
        reason = "truncated"
    else:
        marker_scan = "absent"
    return (
        bytes(retained),
        len(retained) > _MAX_RESPONSE_BYTES,
        marker_scan,
        reason,
        matched,
        body_encoding,
        decoded_seen,
        scan_truncated,
    )


def _scan_headers_for_marker(
    headers: Sequence[tuple[str, str]], needles: tuple[bytes, ...] | None
) -> list[str]:
    """Run the marker needles over the RESPONSE HEADERS, in memory.

    ``_scan_response`` consumes only the body stream, but a marker crosses a
    boundary just as completely in ``Content-Disposition: filename="…"``, in a
    ``Location`` pointing at a foreign resource, in an ``ETag`` derived from
    foreign content, or in a debug header naming the owning tenant. Grading
    those ``absent`` reports a boundary as intact while the other identity's
    data is on the wire.

    The header list is already in memory -- it is collected for the sequence
    extractors -- so this retains nothing new, and only the label list escapes.
    """
    if not needles or not headers:
        return []
    haystack = (
        "\r\n".join(f"{name}: {value}" for name, value in headers)
        .lower()
        .encode("utf-8", "surrogateescape")
    )
    return [
        label
        for label, needle in zip(_NEEDLE_ENCODINGS, needles)
        if needle in haystack
    ]


def _retry_after_requested(headers: Sequence[tuple[str, str]]) -> bool:
    """True when the response carried a ``Retry-After`` header. Presence only.

    The VALUE is deliberately not returned, and not because parsing it is hard.
    ``Retry-After`` is target-controlled input, it is either a delay or an
    HTTP-date, and the only thing any caller here does with it is stop. A
    boolean cannot be echoed into an artifact, cannot be used to sleep for an
    hour on a target's say-so, and cannot disagree with itself between the two
    modules that read it.

    This exists so ``matrix`` can honour the politeness signal without touching
    the ``sink`` channel: that channel carries real response headers, and the
    matrix modules are forbidden from reading it precisely so no header byte can
    reach a matrix artifact. Without this, ``matrix``'s ``retry_after_requested``
    abort was unreachable with the default prober and a target that said
    "Retry-After" on its first 429 still received two more requests.
    """
    return any(name.lower() == "retry-after" for name, _ in headers)


def _served_from_cache(headers: Sequence[tuple[str, str]]) -> bool:
    """True when the response announces that it did not come from the origin.

    Only a derived boolean is kept. A cached body is a photograph of the past,
    and the one place that matters is a write-effect verification read: a cache
    that answers it from a copy taken before the write turns a real cross-tenant
    destruction into "no effect observed". Detection is best-effort by
    construction -- a silent cache cannot be seen -- which is why
    :data:`_FORCED_REQUEST_HEADERS` also asks every hop not to serve one.
    """
    for name, value in headers:
        lowered = name.lower()
        if lowered == "age":
            try:
                if int(value.strip()) > 0:
                    return True
            except ValueError:
                pass
            continue
        wanted = _CACHE_HIT_HEADERS.get(lowered)
        if wanted is None:
            continue
        # A multi-tier cache writes 'MISS, HIT'; one hop reporting a hit is a
        # hit for our purposes.
        for token in value.replace(",", " ").split():
            if token.lower() in wanted:
                return True
    return False


#: Every reason a request is abandoned before it reaches the wire. A closed
#: vocabulary of constants: none of these strings is ever built from a cookie
#: value, a captured value, or anything the server sent.
UNSENT_REASONS: dict[str, str] = {
    "unresolved_reference": (
        "a ${capture.…} reference in this request had no value, so the request "
        "was not sent"
    ),
    "credential_slot_interpolation": (
        "this request would fill a credential header from a capture, which the "
        "session model forbids, so the request was not sent"
    ),
    "marker_reflection_blocked": (
        "an interpolated value carried a configured marker, which would make a "
        "reflected marker look like a leak, so the request was not sent"
    ),
    "marker_check_incomplete": (
        "an interpolated value decoded into more variants than Veridor checks "
        "for a configured marker, so it could not be shown free of one and the "
        "request was not sent"
    ),
    "session_unavailable": (
        "the session for this identity was not established, so the request was "
        "not sent"
    ),
    "session_expired": (
        "the session for this identity is no longer live, so the request would "
        "have gone out unauthenticated and was not sent"
    ),
    "injection_not_applicable": (
        "this identity's session injects a form_field or json_field, and this "
        "request has no form-encoded or JSON object body to carry it, so the "
        "request would have gone out without it and was not sent"
    ),
}


#: The exact ``error`` texts :func:`_unsent_result` writes. A result carrying
#: one of these was withheld before the socket; anything else -- including a
#: transport failure -- may have reached the target, so it counts as issued.
_UNSENT_ERRORS: frozenset[str] = frozenset(UNSENT_REASONS.values())


#: Advice for a request the configuration itself made unsendable. Nothing went
#: out, so the transport advice ("confirm the target is reachable") pointed the
#: operator at a healthy network while the fix was in their own config.
INJECTION_REMEDIATION: str = (
    "Nothing was sent, so this is not a network problem: the fix is in the "
    "configuration. The identity's session.inject declares a form_field or "
    "json_field this request has no body to carry. Give the request a "
    "form-encoded body (for a form_field) or a JSON object body (for a "
    "json_field), or remove that field from session.inject."
)


def execution_message(error: str) -> str:
    """The message of an EXEC-001 finding: "not sent" when it was not."""
    if error in _UNSENT_ERRORS:
        return f"Request not sent: {error}"
    return f"Request failed: {error}"


_NOT_THE_NETWORK = (
    "Nothing was sent, so this is not a network problem: the fix is in the "
    "configuration. "
)

#: Advice for every unsent reason the configuration causes. Only
#: injection_not_applicable had any; the other three got "Confirm the target
#: is reachable from the runner and retry", and a run withheld entirely by
#: any of them was told to check the target URL and that the target is up.
#: The two session reasons are absent on purpose: a session that did not
#: establish can be the target's doing.
CONFIGURATION_UNSENT_REMEDIATION: dict[str, str] = {
    "injection_not_applicable": INJECTION_REMEDIATION,
    "marker_reflection_blocked": _NOT_THE_NETWORK + (
        "A value interpolated into this request carries a configured marker, "
        "and a marker Veridor itself sent cannot prove a leak. Do not "
        "interpolate a capture holding a planted marker into a later request: "
        "capture an id or another field the target does not echo the marker in."
    ),
    "credential_slot_interpolation": _NOT_THE_NETWORK + (
        "This request fills a credential header from a capture, which the "
        "session model forbids. Put the credential in the identity's static "
        "headers or its session.inject instead."
    ),
    "unresolved_reference": _NOT_THE_NETWORK + (
        "A ${capture.…} reference in this request had no value: the capture it "
        "names is not declared, or the login step meant to produce it did not "
        "find it. Check the capture's name and its extractor against the login "
        "response."
    ),
}

#: The UNSENT_REASONS text of each configuration-caused reason, to its code.
CONFIGURATION_UNSENT_ERRORS: dict[str, str] = {
    UNSENT_REASONS[reason]: reason for reason in CONFIGURATION_UNSENT_REMEDIATION
}


def unsent_remediation(error: str, reason: str | None = None) -> str | None:
    """Configuration advice for a request withheld by the configuration.

    ``reason`` names the code when the error text is not the shared one, as
    for a sequence step whose own message names the capture it refused.
    """
    code = CONFIGURATION_UNSENT_ERRORS.get(error, reason)
    return CONFIGURATION_UNSENT_REMEDIATION.get(code) if code else None


def _issued_mutating(results: Iterable[dict[str, Any]]) -> int:
    """How many of these probe results were mutating AND actually sent."""
    return sum(
        1
        for result in results
        if result.get("request", {}).get("method") not in SAFE_METHODS
        and result.get("error") not in _UNSENT_ERRORS
    )


def _unsent_result(
    url: str, method: str, reason: str, *, needles: bool = False
) -> dict[str, Any]:
    """The result shape for a request that was deliberately never issued.

    Same keys as a real result so every consumer -- grading, the run document,
    SARIF -- needs no special case. ``status`` is ``None`` and the marker scan
    is ``unknown``, which is what routes the outcome to `inconclusive`.
    """
    return {
        "request": {"method": method, "url": _safe_url(url)},
        "response": {
            "status": None,
            "duration_ms": 0.0,
            "body_bytes": 0,
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "body_truncated": False,
            "marker_scan": "unknown" if needles else None,
            "marker_scan_reason": "request_not_sent" if needles else None,
            "marker_encodings": [],
            "marker_channel": None,
            "body_encoding": None,
            "body_scanned_bytes": 0,
            "body_scan_truncated": False,
            "from_cache": False,
            "retry_after": False,
        },
        "error": UNSENT_REASONS[reason],
    }


def _apply_forced_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop every header Veridor owns and set its own value for each.

    A ``Host`` header is refused rather than dropped: it is refused at load
    wherever one can be declared, so one here came from somewhere the loader
    did not see, and the request must not go out at all. ``_perform_request``
    calls this before the Request exists and again after a session's
    injections, so nothing is built with one.
    """
    for name in headers:
        _refuse_host_header(name, "a request")
    kept = {
        name: value
        for name, value in headers.items()
        if name.lower() not in _OVERRIDDEN_REQUEST_HEADERS
    }
    kept.update(_FORCED_REQUEST_HEADERS)
    return kept


def _assert_same_origin(base_url: str, url: str) -> None:
    """Refuse, before anything is built or sent, a URL that left ``base_url``.

    The origin rule is ``matrix.same_origin`` -- scheme, host and effective
    port -- imported rather than restated so the two containment checks cannot
    drift. Imported here rather than at module scope for the same reason
    ``sequence`` is: ``core`` stays importable without the matrix machinery.

    On the origin, the URL must also stay within the base URL's path
    (:func:`_outside_base_path`, `map`'s rule) and carry no ``.`` or ``..``
    segment (:func:`_has_dot_segment`; urljoin has removed the literal ones by
    now, so this catches a percent-encoded one). The loaders refuse every path
    they know of that would fail this; it is here for the ones produced at run
    time.
    """
    from veridor.matrix import same_origin  # noqa: PLC0415

    if same_origin(base_url, url):
        parts = urlsplit(url)
        if _outside_base_path(base_url, url) or _has_dot_segment(parts.path):
            raise ConfigError(
                "a request resolved outside the path of target.base_url "
                f"({quoted(base_url)}): the request would go to a different "
                "application on the same host, with an identity's credentials. "
                "Nothing was sent. This is a bug in whatever produced the path; "
                "the configuration loader refuses every such path it knows of."
            )
        return
    parts = urlsplit(url)
    # Only the origin is named. The path can carry an expanded credential.
    where = f"{parts.scheme}://{parts.netloc}" if parts.netloc else f"{parts.scheme}:"
    raise ConfigError(
        f"a request resolved to {quoted(where)}, a different origin from "
        f"target.base_url ({quoted(base_url)}). Every request carries an identity's "
        "credentials, so Veridor refuses to send one anywhere but the target. "
        "Nothing was sent. This is a bug in whatever produced the path; the "
        "configuration loader refuses every such path it knows of."
    )


def _perform_request(
    base_url: str,
    timeout: float,
    request_config: dict[str, Any],
    identity: dict[str, Any],
    *,
    marker: str | None = None,
    sink: dict[str, Any] | None = None,
    session: Any = None,
    graded: bool = True,
) -> dict[str, Any]:
    """Issue one request as one identity and return ``request/response/error``.

    Shared by check probes and by identity marker control probes so that both
    use the same opener, the same redirect policy, the same Accept-Encoding
    override, and the same in-memory-only scan. Nothing derived from the body
    beyond booleans and scalars is returned, so nothing that could be persisted
    contains response text.

    ``sink``, when supplied, additionally receives the response headers and the
    already-retained wire bytes so a sequence step can run its extractor over
    them. It is a strictly separate channel from the returned dict, which is the
    only thing any caller persists; the sequence engine reads the sink and
    clears it on the next line. No new bytes are retained -- these are the same
    bytes ``_scan_response`` holds to compute ``body_sha256``. Check probes pass
    no sink, so their behaviour is byte-identical.

    ``session``, when supplied, is the issuing identity's own session: it fills
    ``${capture.…}`` references, applies that identity's declared injections,
    attaches its cookie jar, and stores the response's cookies back into it. The
    jar is a PARAMETER, never module state, so cookie isolation is a property of
    the call rather than of a registry someone could key wrongly. ``session`` is
    ``None`` everywhere it was ``None`` before, and that path is byte-for-byte
    today's behaviour: no Cookie header is added and no Set-Cookie is stored.

    ``graded`` is true for every probe whose result a verdict reads. A graded
    request whose body cannot carry a declared injection is refused outright
    (fail closed). Teardown passes ``graded=False``: it is cleanup, never
    graded, so such a request is sent anyway and the dropped field is reported
    on the result as ``injection_not_applied`` rather than orphaning the fixture.
    """
    url = urljoin(f"{base_url.rstrip('/')}/", request_config["path"].lstrip("/"))
    # Every request Veridor sends is built on this line -- checks, marker and
    # liveness controls, session logins, sequence steps, matrix cells, mutation
    # probes -- so this is the one place an origin assertion covers them all.
    # The loaders refuse every escaping path they know of before anything is
    # sent; this refuses the ones nobody has thought of yet, before a Request
    # object (and so a credential header) exists.
    _assert_same_origin(base_url, url)
    headers = dict(request_config.get("headers", {}))
    headers.update(identity.get("headers", {}))
    body = _request_body(request_config)
    if "json" in request_config:
        headers.setdefault("Content-Type", "application/json")
    # Compression has no upside for an authorization oracle; refuse it at the
    # source and decode anyway if the server ignores us. Caching is refused for
    # the same class of reason: a cached body answers a question about the past.
    headers = _apply_forced_headers(headers)
    method = request_config.get("method", "GET").upper()
    not_applied: list[str] = []
    if session is not None:
        headers, body, blocked, not_applied = session.prepare(
            headers, body, method=method, graded=graded
        )
        if blocked is not None:
            # Fail closed and send nothing. An untokened or unresolved request
            # draws a denial, and a denial that matches a declared denial is a
            # manufactured SAFE over a boundary that was never tested.
            return _unsent_result(url, method, blocked, needles=bool(marker))
        # Re-asserted after injection for the same reason it is asserted above:
        # an injected header must not be able to re-enable compression or
        # re-enable caching.
        headers = _apply_forced_headers(headers)
    request = Request(url, data=body, headers=headers, method=method)
    # Cookies first, as urllib's own processor order has it: set_proxy turns an
    # http:// request routed through an https:// proxy into type "https", and
    # the jar then attached Secure cookies to a request for an http:// target.
    if session is not None:
        session.attach_cookies(request)
    route = proxy_route(url)
    if route is not None:
        _via_proxy(request, route)
    needles = marker_needles(marker) if marker else None
    started = time.monotonic()
    # Set once a status line has arrived, so a timeout after it is reported as
    # a stalled body rather than as a target that never answered.
    response_started = False
    try:
        try:
            with _OPENER.open(request, timeout=timeout) as response:
                response_started = True
                if session is not None:
                    # Before the body is streamed, so a scan failure cannot lose
                    # the session.
                    session.harvest(response, request)
                scan = _scan_response(
                    response, response.headers.get("Content-Encoding"), needles
                )
                status = response.status
                error = None
                response_headers = list(response.headers.items())
        except HTTPError as exc:
            # Nested, so a failure while streaming THIS body falls through to
            # the transport handler below. It used not to: a 403 whose body
            # stalled raised a bare TimeoutError out of this function, and the
            # run exited 2 with "veridor: timed out" and no run document.
            response_started = True
            if session is not None:
                # The overwhelmingly common real login -- POST /login -> 302
                # with Set-Cookie -- lands HERE, because _NoRedirectHandler
                # refuses the redirect. Extracting cookies on this path is
                # mandatory.
                session.harvest(exc, request)
            scan = _scan_response(exc, exc.headers.get("Content-Encoding"), needles)
            status = exc.code
            error = None
            response_headers = list(exc.headers.items())
    except (
        URLError,
        TimeoutError,
        OSError,
        http.client.HTTPException,
        # A target-chosen value can make http.client refuse to encode the
        # request line (ascii) or a header (latin-1). That raises
        # UnicodeEncodeError, which is a ValueError and was NOT caught here, so
        # it escaped through the sequence engine and the CLI and killed the
        # whole run before any run document was written -- every other check in
        # the config lost with it. Every other failure in this file is a typed,
        # fail-closed inconclusive, and so is this one now.
        UnicodeError,
    ) as exc:
        scan = (
            b"",
            False,
            "unknown" if needles is not None else None,
            "request_failed" if needles is not None else None,
            [],
            None,
            0,
            False,
        )
        status = None
        error = _transport_error(exc, timeout, response_started=response_started)
        response_headers = []

    (
        response_body,
        truncated,
        marker_scan,
        marker_scan_reason,
        marker_encodings,
        body_encoding,
        scanned_bytes,
        scan_truncated,
    ) = scan
    response_body = response_body[:_MAX_RESPONSE_BYTES]
    marker_channel = "body" if marker_scan == "present" else None
    if needles is not None and marker_scan != "present":
        # Response headers are response bytes. Scanning them only ever turns an
        # 'absent' or an 'unknown' into a 'present': positive evidence that the
        # marker crossed, which no oracle failure elsewhere can contradict.
        header_matched = _scan_headers_for_marker(response_headers, needles)
        if header_matched:
            marker_scan = "present"
            marker_scan_reason = None
            marker_encodings = header_matched
            marker_channel = "header"
    if sink is not None:
        sink["body"] = response_body
        sink["body_truncated"] = truncated
        sink["headers"] = response_headers
    result = {
        "request": {
            "method": request.method,
            "url": _safe_url(url),
        },
        "response": {
            "status": status,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "body_bytes": len(response_body),
            "body_sha256": hashlib.sha256(response_body).hexdigest(),
            "body_truncated": truncated,
            "marker_scan": marker_scan,
            "marker_scan_reason": marker_scan_reason,
            "marker_encodings": marker_encodings,
            "marker_channel": marker_channel,
            "body_encoding": body_encoding,
            "body_scanned_bytes": scanned_bytes,
            "body_scan_truncated": scan_truncated,
            "from_cache": _served_from_cache(response_headers),
            # Presence, never the value. See :func:`_retry_after_requested`.
            "retry_after": _retry_after_requested(response_headers),
        },
        "error": error,
    }
    if not_applied:
        # The request went out without a declared injection it had no body to
        # carry. Record it so a clean grade is not read as a field-carried pass;
        # the field name only, never its value.
        result["injection_not_applied"] = not_applied
    return result


def _execute_probe(
    base_url: str,
    timeout: float,
    check: dict[str, Any],
    identity_name: str,
    identity: dict[str, Any],
    *,
    marker: str | None = None,
    session: Any = None,
) -> dict[str, Any]:
    """Issue one check request as one identity. Shape and keys are unchanged."""
    return {
        "check_id": check["id"],
        "identity": identity_name,
        **_perform_request(
            base_url, timeout, check["request"], identity, marker=marker, session=session
        ),
    }


def _execute_marker_controls(
    config: dict[str, Any],
    sessions: dict[str, Any] | None = None,
    *,
    pace: Callable[[], None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run every identity's ``marker_probe`` once, before any check.

    These are CONTROLS, not checks. They answer one question -- is this
    identity's marker actually live and observable? -- and nothing else. They
    never produce a finding, never enter ``probes``, never touch a fingerprint,
    and never change the check tally. Their only effect is to license (or to
    refuse to license) an ``excludes_marker`` assertion that names the identity.

    Cost is one extra request per identity that configures a probe, per run,
    regardless of how many checks reference that identity.

    ``pace``, when supplied, is called immediately before each request that is
    actually issued, and is expected to block until the caller's rate limit
    allows it. ``run`` passes none and is byte-identical; ``mutate`` passes its
    own limiter, because a rate limit with a hole in it is not a rate limit.
    """
    controls: dict[str, dict[str, Any]] = {}
    sessions = sessions or {}
    base_url = config["target"]["base_url"]
    timeout = float(config["target"].get("timeout_seconds", 10))
    for name, identity in config["identities"].items():
        probe = identity.get("marker_probe")
        if not isinstance(probe, dict):
            continue
        session = sessions.get(name)
        if session is not None and session.state != "established":
            # Not issued at all. The control is unverified with the session's
            # own reason, so every exclusion naming this identity degrades to
            # 'suspected' through the existing _resolve_control path.
            controls[name] = {
                "identity": name,
                "state": "unverified",
                "reason": (
                    f"the session for {quoted(name)} was not established "
                    f"({session.reason}); the marker probe was not issued"
                ),
                **_unsent_result(
                    urljoin(f"{base_url.rstrip('/')}/", probe["path"].lstrip("/")),
                    probe.get("method", "GET").upper(),
                    "session_unavailable",
                    needles=True,
                ),
            }
            continue
        if pace is not None:
            pace()
        # Login ran before this, in this identity's own jar, so a marker control
        # works against a cookie-authenticated target -- which it could not do
        # before, because the probe was issued with no session and got a 401.
        result = _perform_request(
            base_url,
            timeout,
            probe,
            identity,
            marker=identity["marker"],
            session=session,
        )
        scan = result["response"]["marker_scan"]
        error = result["error"]
        # Fail closed. Only an observed marker licenses an exclusion; an error,
        # an unscannable body, and a plain absence are all equally unlicensed.
        verified = (
            error is None
            and scan == "present"
            # Mirrors sequence.py, which has always refused to promote a cached
            # read to a control. A stale control licensing a live exclusion is
            # the same defect one level up.
            and not result["response"]["from_cache"]
        )
        controls[name] = {
            "identity": name,
            "state": "verified" if verified else "unverified",
            "reason": None if verified else _control_reason(name, scan, result),
            **result,
        }
    return controls


#: Statuses that mean "denied" and carry no information about WHO was denied.
#: A declaration made only of these can be satisfied by a boundary that works
#: and, identically, by a credential the target never recognised.
DENIAL_ONLY_STATUSES: frozenset[int] = frozenset({401, 403, 404, 405, 407})


def _denial_only(expectation: Any) -> bool:
    """Does this expectation accept nothing but a denial?

    Such an expectation is the vacuous-pass shape: it holds whenever the target
    refuses, and a target refuses an expired token exactly as it refuses an
    attacker. Nothing else in a declaration has that property.
    """
    if isinstance(expectation, str):
        return expectation == "deny"
    if not isinstance(expectation, Mapping):
        return False
    statuses = expectation.get("status") or ()
    return bool(statuses) and all(
        isinstance(status, int) and status in DENIAL_ONLY_STATUSES
        for status in statuses
    )


def _tells_a_credential_apart(status: Any) -> bool:
    """Does a fabricated credential's answer show the application judged it?

    Only a refusal from the authorization layer (401, 403, 404, 405) or a
    2xx/3xx does. A 400 is a parser rejecting the token's shape, a 406 an
    Accept the sham reused, a 407 a proxy, a 429 a limiter -- and the sham is
    sent after the run's own requests, when a limiter is likeliest to trip --
    and a 5xx a handler falling over. Each differs from a dead token's 401
    without the application having recognised either credential, and reading
    the difference as proof passed an expired token. The pairs harness's
    ``_tells_a_credential_apart`` (scripts/patched_pairs.py) applies the same
    rule.
    """
    return isinstance(status, int) and (
        status in DENIAL_ONLY_STATUSES - PROXY_ANSWER_STATUSES
        or 200 <= status <= 399
    )


def _liveness_key(check: Mapping[str, Any]) -> tuple[str, str]:
    """One sham probe answers for every identity denied on the same request."""
    request = check.get("request") or {}
    return (str(request.get("method", "GET")).upper(), str(request.get("path", "")))


def _sham_credential_headers(names: Iterable[str], token: str) -> dict[str, str]:
    """Fabricated values for the headers an identity identifies itself with.

    The real values are never read. Same construction ``mutate`` uses: an
    ``Authorization`` gets a bearer token so the scheme parses, anything else
    gets the bare string. Minted once per run, recognisable in an access log,
    and authenticates to nothing -- so this probe can never accidentally BE a
    credential.
    """
    return {
        name: (f"Bearer {token}" if name.lower() == "authorization" else token)
        for name in names
    }


def _liveness_scan_markers(
    config: Mapping[str, Any],
) -> dict[tuple[str, str], dict[str, str]]:
    """Every owner's marker a sham on each request must be scanned for.

    Collected from EVERY excludes_marker on the request, not one per request.
    A dict keyed by (method, path) where the last check won let a later
    status-only check on the same request set the scan to nothing, and a
    later check excluding a different owner replace the first owner's marker
    -- either way an earlier check's shared build id was never compared, and
    graded `confirmed`. Keyed by owner, because that is what `_grade_check`
    holds when it asks.
    """
    identities = config.get("identities") or {}
    markers: dict[tuple[str, str], dict[str, str]] = {}
    for check in config.get("checks") or ():
        for expectation in (check.get("expect") or {}).values():
            owner = (
                expectation.get("excludes_marker")
                if isinstance(expectation, Mapping)
                else None
            )
            if not isinstance(owner, str):
                continue
            identity = identities.get(owner)
            if isinstance(identity, Mapping) and isinstance(identity.get("marker"), str):
                markers.setdefault(_liveness_key(check), {}).setdefault(
                    owner, identity["marker"]
                )
    return markers


def _rescan_retained(sink: Mapping[str, Any], marker: str) -> str:
    """Scan bytes a control already holds for one more marker. Sends nothing.

    One sham per request is the documented cost, so a request that must be
    scanned for a second owner's marker is not probed twice: the same response
    is scanned again, from the wire bytes ``_perform_request`` retained for its
    digest and the headers it collected, through the same ``_scan_response``
    and ``_scan_headers_for_marker``. Those bytes stop at
    ``_MAX_RESPONSE_BYTES``; past that an absence is ``unknown``, never
    ``absent``, and an ``unknown`` licenses no downgrade.
    """
    needles = marker_needles(marker)
    headers = list(sink.get("headers") or ())
    if _scan_headers_for_marker(headers, needles):
        return "present"
    encoding = next(
        (value for name, value in headers if name.lower() == "content-encoding"),
        None,
    )
    state = _scan_response(io.BytesIO(sink.get("body") or b""), encoding, needles)[2]
    if state == "absent" and sink.get("body_truncated"):
        return "unknown"
    return state or "unknown"


#: What proves an identity's credential live, as the banners, the
#: remediation text and the docs state it. A 2xx alone did, anywhere in the
#: run -- including a public route that serves every caller -- so one check on
#: such a route silently cancelled every unproven denial for that identity.
_PROOF_OF_LIFE = (
    "a 2xx it drew on a request where an identity with no credential, or the "
    "fabricated credential, was refused; or its marker_probe"
)

#: A refusal from the authorization layer: what makes a 2xx on the same
#: request discriminate. A 407 is a proxy's, not the target's.
_REFUSAL_STATUSES: frozenset[int] = DENIAL_ONLY_STATUSES - PROXY_ANSWER_STATUSES


#: When a denial-only expectation counts as unproven, as `_liveness_unproven`
#: and the run-level filter in `execute_run` apply it. Every liveness banner
#: ends with it: they said "unless it is proven live elsewhere" and left out
#: the served-identity precondition, so an all-deny check printed the banner
#: and was never judged.
_UNPROVEN_WHEN = (
    "counts as unproven when the identity presents a credential, some identity "
    "was served in the same check, and nothing else in this run proves the "
    f"identity live ({_PROOF_OF_LIFE})"
)


def _identities_needing_proof(config: Mapping[str, Any]) -> set[str]:
    """Identities that present a credential and are asserted denied somewhere.

    Their denials count as unproven unless a 2xx on a discriminating request
    or a marker_probe proves the credential live. Socket-free.
    """
    identities = config.get("identities") or {}
    named = {
        name
        for check in config.get("checks") or ()
        for name, expectation in (check.get("expect") or {}).items()
        if _denial_only(expectation)
    } | {
        step.get("as")
        for sequence in config.get("sequences") or ()
        for step in sequence.get("steps") or ()
        if step.get("role") == "assert" and _denial_only(step.get("expect"))
    }
    return {
        name
        for name in named
        if isinstance(identities.get(name), Mapping)
        and presents_credential(identities[name])
    }


def _accepts_service(expectation: Any) -> bool:
    """Does this expectation accept a 2xx?"""
    if not isinstance(expectation, Mapping):
        return False
    return any(
        isinstance(status, int) and _target_served(status)
        for status in expectation.get("status") or ()
    )


#: How many requests a liveness notice names before it says "and N more".
_NOTICE_LISTED = 10


def _named_requests(requests: Iterable[tuple[str, str]]) -> str:
    """``METHOD path`` for each request, in order, for a console notice.

    The notices used to give a count (and the verbs), so an operator could not
    tell which declarations were left without a liveness control. Both
    halves come from the config, so both go through ``terminal_text`` (the
    path through ``_safe_url`` first), which bounds a planted long method as
    it bounds every other quoted value.
    """
    named = [
        f"{terminal_text(method)} {terminal_text(_safe_url(path))}"
        for method, path in requests
    ]
    shown = ", ".join(named[:_NOTICE_LISTED])
    if len(named) > _NOTICE_LISTED:
        shown += f", and {len(named) - _NOTICE_LISTED} more"
    return shown


def plan_liveness_reasons(
    config: Mapping[str, Any],
) -> dict[tuple[str, str], set[str]]:
    """Every safe-method request a sham is planned for, and why. Socket-free.

    ``denial_only``: an expectation accepts only denial statuses, and the
    sham's answer tells a working boundary from a dead token.

    ``excludes_marker``: an expectation excludes an owner's marker. The
    sham's response is scanned for it: a marker a credential nobody issued
    gets back is not unique to its owner, and no ``confirmed`` is issued on
    it. Planned only beside a denial-only expectation, a 2xx-accepting check
    -- a list the outsider may read whose body must not carry the owner's
    marker -- graded a build id served to everyone LEAK-001 ``confirmed``.

    ``proves_live``: an identity whose denials need proof of life expects a
    2xx here. That 2xx proves its credential live only when something on the
    same request was refused -- the sham, or an identity with no credential --
    so the sham is what turns "it was served" into proof. Not planned where
    the check already asks an identity with no credential to be refused. It
    is planned on a route declared public too: a target that refuses a bad
    token even there (GitHub answers 401 'Bad credentials') refuses the sham
    on the same request the identity was served, which is the proof. Where
    the route serves the sham as well, nothing is claimed for it
    (:func:`_public_requests`).
    """
    identities = config.get("identities") or {}
    needing_proof = _identities_needing_proof(config)
    planned: dict[tuple[str, str], set[str]] = {}
    for check in config.get("checks") or ():
        request = check.get("request") or {}
        if str(request.get("method", "GET")).upper() not in SAFE_METHODS:
            continue
        expect = check.get("expect") or {}
        reasons: set[str] = set()
        if any(_denial_only(expectation) for expectation in expect.values()):
            reasons.add("denial_only")
        if any(
            isinstance(expectation, Mapping)
            and isinstance(expectation.get("excludes_marker"), str)
            for expectation in expect.values()
        ):
            reasons.add("excludes_marker")
        anonymous_refusal = any(
            _denial_only(expectation)
            and isinstance(identities.get(name), Mapping)
            and not presents_credential(identities[name])
            for name, expectation in expect.items()
        )
        if not anonymous_refusal and any(
            name in needing_proof and _accepts_service(expectation)
            for name, expectation in expect.items()
        ):
            reasons.add("proves_live")
        if reasons:
            planned.setdefault(_liveness_key(check), set()).update(reasons)
    return planned


def plan_liveness_controls(config: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The distinct requests a liveness proof would probe. Socket-free.

    Deduplicated by (method, path) rather than per identity: one credential the
    target cannot recognise answers "does this endpoint refuse anything?" for
    every identity denied on it. On the shipped fixtures that is 7 requests
    rather than 12 -- +33% instead of +57%. See :func:`plan_liveness_reasons`
    for why each is planned.
    """
    return list(plan_liveness_reasons(config))


def plan_unsafe_liveness(config: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The denial-only requests no sham is sent to, because of their method.

    A fabricated credential is never sent with a method that can change state.
    That is deliberate, and it used to be silent: these requests were simply
    left out of the plan, so an expired token on a DELETE passed with nothing
    unproven, nothing printed, and --require-complete satisfied. A denial on
    one of these now counts as unproven unless the identity is proven live
    some other way, and the requests are listed in the banner and the run
    document. Socket-free.
    """
    planned: dict[tuple[str, str], None] = {}
    for check in config.get("checks") or ():
        request = check.get("request") or {}
        if str(request.get("method", "GET")).upper() in SAFE_METHODS:
            continue
        if any(
            _denial_only(expectation)
            for expectation in (check.get("expect") or {}).values()
        ):
            planned.setdefault(_liveness_key(check), None)
    return list(planned)


def _presents_static_credential(identity: Mapping[str, Any]) -> bool:
    """Does this identity send a credential in a static header?"""
    headers = identity.get("headers") or {}
    return isinstance(headers, Mapping) and any(
        isinstance(name, str) and _credential_bearing_header(name) for name in headers
    )


def plan_sequence_liveness(
    config: Mapping[str, Any],
) -> list[tuple[str, int, str, str, tuple[int, ...]]]:
    """Denial-only assert steps no sham is sent for.

    Each is (sequence id, step index, method, path template, statuses).

    Only steps taken as an identity that presents a credential in a static
    header -- any header :func:`_credential_bearing_header` accepts, so an
    ``Accept``-only anonymous identity is not one. A session identity's step
    already has its own rule (``session_not_live``), and an identity that
    sends nothing has no credential that could be dead. Socket-free.

    No fabricated credential is sent inside a sequence: a step's request
    depends on what earlier steps captured and created, and a sham replaying
    it would be a request the operator never declared, against state the
    sequence set up. Liveness planning used to read ``checks`` only, so an
    expired token passed every denial-only assert step with nothing
    unproven -- see :func:`_sequence_liveness_unproven`.
    """
    identities = config.get("identities") or {}
    planned: list[tuple[str, int, str, str, tuple[int, ...]]] = []
    for sequence in config.get("sequences") or ():
        for index, step in enumerate(sequence.get("steps") or ()):
            identity = identities.get(step.get("as"))
            if (
                step.get("role") != "assert"
                or not _denial_only(step.get("expect"))
                or not isinstance(identity, Mapping)
                or not _presents_static_credential(identity)
            ):
                continue
            request = step.get("request") or {}
            planned.append((
                str(sequence.get("id")),
                index,
                str(request.get("method", "GET")).upper(),
                str(request.get("path", "")),
                tuple((step.get("expect") or {}).get("status") or ()),
            ))
    return planned


def _refused(status: Any) -> bool:
    return isinstance(status, int) and status in _REFUSAL_STATUSES


def _check_discriminates(
    check: Mapping[str, Any],
    probes: Mapping[str, Mapping[str, Any]],
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
    credentialed: Iterable[str],
) -> bool:
    """Was some caller other than a credentialed identity refused on this request?

    Either an identity with no credential, or the fabricated credential. Only
    then does a 2xx on the same request show the target recognised the
    credential it served: a route that serves everybody serves a dead token
    too.
    """
    credentialed = set(credentialed)
    if any(
        name not in credentialed
        and not probe.get("error")
        and _refused((probe.get("response") or {}).get("status"))
        for name, probe in probes.items()
    ):
        return True
    control = (liveness or {}).get(_liveness_key(check))
    return bool(
        control is not None
        and not control.get("error")
        and _refused((control.get("response") or {}).get("status"))
    )


def _proven_live_by_service(
    config: Mapping[str, Any],
    probes: Iterable[Mapping[str, Any]],
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
    sequence_records: Iterable[Mapping[str, Any]],
    credentialed: Iterable[str],
) -> set[str]:
    """Identities a 2xx in this run proves live: served where somebody was refused.

    A 2xx proves a credential live only on a request that discriminates --
    where an identity with no credential, or the fabricated credential, was
    refused on that same request. Any 2xx anywhere used to count, so one check
    on a public route that serves anonymous callers cancelled every unproven
    denial for each identity it served, and a dead token on a DELETE exited 0
    under --require-complete.

    Checks are keyed by (method, path), so a sham or an anonymous refusal on
    one check's request discriminates for another check on the same request.
    A sequence step or teardown request is keyed by (sequence, method, path
    template): no sham rides a sequence, and a template resolves to the same
    request only inside the sequence that captured its values.
    """
    credentialed = set(credentialed)
    checks = {check.get("id"): check for check in config.get("checks") or ()}
    refused: set[tuple] = set()
    served: list[tuple[tuple, str]] = []

    def observe(key: tuple, identity: Any, status: Any, error: Any) -> None:
        if error or not isinstance(identity, str):
            return
        if identity not in credentialed and _refused(status):
            refused.add(key)
        elif _target_served(status):
            served.append((key, identity))

    for probe in probes:
        check = checks.get(probe.get("check_id"))
        if check is None:
            continue
        observe(("check", *_liveness_key(check)), probe.get("identity"),
                (probe.get("response") or {}).get("status"), probe.get("error"))
    for (method, path), control in (liveness or {}).items():
        if not control.get("error") and _refused(
            (control.get("response") or {}).get("status")
        ):
            refused.add(("check", method, path))
    for record in sequence_records:
        sequence_id = record.get("sequence_id")
        for step in record.get("steps") or ():
            request = step.get("request") or {}
            observe(("sequence", sequence_id, request.get("method"), request.get("url")),
                    step.get("as"), (step.get("response") or {}).get("status"),
                    step.get("error"))
        for entry in record.get("teardown") or ():
            request = entry.get("request") or {}
            observe(("sequence", sequence_id, request.get("method"), request.get("url")),
                    entry.get("as"), entry.get("status"), entry.get("error"))
    return {identity for key, identity in served if key in refused}


def _sequence_liveness_unproven(
    planned: list[tuple[str, int, str, str, tuple[int, ...]]],
    sequence_records: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Every matched denial-only assert step no comparison could prove.

    The same preconditions a check has, read off the sequence: the step
    matched its declaration with a response, and SOME identity was served in
    the same sequence (a step or a teardown entry drew a 2xx) -- without that
    the sequence says "nobody may have this", and a dead token being refused
    is the declaration coming true. Whether the identity is proven live
    elsewhere in the run is settled once, by the caller, for checks and
    sequences together.
    """
    records = {record.get("sequence_id"): record for record in sequence_records}
    entries: list[dict[str, Any]] = []
    for sequence_id, index, method, _path, statuses in planned:
        record = records.get(sequence_id)
        if record is None:
            continue
        served = any(
            _target_served((step.get("response") or {}).get("status"))
            for step in record.get("steps") or ()
        ) or any(
            _target_served(entry.get("status"))
            for entry in record.get("teardown") or ()
        )
        if not served:
            continue
        step = next(
            (step for step in record.get("steps") or () if step.get("index") == index),
            None,
        )
        if step is None or step.get("state") != "matched" or step.get("error"):
            continue
        status = (step.get("response") or {}).get("status")
        if status is None:
            continue
        identity = step.get("as")
        entries.append(
            {
                "check_id": sequence_id,
                "check_name": record.get("name") or sequence_id,
                "sequence_id": sequence_id,
                "step_index": index,
                "where": f"sequence {sequence_id} step {index}",
                "identity": identity,
                "status": status,
                "expected_statuses": list(statuses),
                "control": "withheld_sequence_step",
                "statement": (
                    f"{quoted(identity)} received HTTP {status} on step {index} "
                    f"({method}) of sequence {quoted(sequence_id)}. Veridor does "
                    "not send a credential it fabricated inside a sequence, so "
                    "nothing here shows the target recognised "
                    f"{quoted(identity)}'s credential. The step accepts only "
                    "denial statuses, so it is satisfied by a boundary that "
                    "refuses this identity AND by a credential that expired or "
                    "was mistyped. This step does not distinguish them."
                ),
                "remediation": (
                    f"Give {quoted(identity)} a marker_probe naming something it "
                    "SHOULD be served, or declare a check or a step where it is "
                    "served and an identity with no credential is refused on the "
                    "same request (a GET check also gets a fabricated credential "
                    "that must be refused). Either proves the credential live "
                    "and this disclosure disappears."
                ),
            }
        )
    return entries


def _execute_liveness_controls(
    config: Mapping[str, Any],
    token: str,
    *,
    pace: Callable[[], None] | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Probe each denial-carrying request once with a credential nobody issued.

    A CONTROL, not a check: it produces no finding of its own, never enters
    ``probes``, and never touches a fingerprint. It answers one question --
    would this endpoint have answered the same way to a caller it cannot
    possibly know? -- and that question is the difference between a boundary
    that works and a token that expired last Tuesday.

    No identity's credential is ever sent. The declared headers' NAMES are
    reused with a fabricated value (:func:`_sham_header_names`), so the sham
    is shaped like a credential without being one; a non-credential header
    two or more identities send with one value (an API version) rides along
    unchanged -- see :func:`_sham_shared_headers`.
    """
    controls: dict[tuple[str, str], dict[str, Any]] = {}
    base_url = config["target"]["base_url"]
    timeout = float(config["target"].get("timeout_seconds", 10))
    header_names = _sham_header_names(config)
    if not header_names:
        # Nothing to shape a sham on. Not a pass: every denial-only request
        # then has no control, and _liveness_unproven treats that as it treats
        # a write -- see plan_liveness_controls' callers in execute_run.
        return controls
    sham = {"headers": {
        **_sham_shared_headers(config),
        **_sham_credential_headers(header_names, token),
    }}
    # Which markers each control scans for. A control that does not scan cannot
    # answer the second question it exists to answer: is this marker unique to
    # the owner's data, or does it come back to anybody who asks?
    markers = _liveness_scan_markers(config)
    for method, path in plan_liveness_controls(config):
        if pace is not None:
            pace()
        owners = list((markers.get((method, path)) or {}).items())
        sink: dict[str, Any] = {}
        control = _perform_request(
            base_url, timeout, {"method": method, "path": path}, sham,
            marker=owners[0][1] if owners else None,
            sink=sink,
        )
        # Per owner, so each check is graded against the marker IT excludes.
        # Internal only: the run document records the request, never this.
        control["marker_scans"] = {
            owner: (
                control["response"]["marker_scan"]
                if index == 0
                else _rescan_retained(sink, marker)
            )
            for index, (owner, marker) in enumerate(owners)
        }
        sink.clear()
        controls[(method, path)] = control
    return controls


def _credential_bearing_header(name: str) -> bool:
    """Could the target accept or reject something in this header?

    Any header that is not a standard request header that never carries a
    credential (:func:`veridor.credentials.is_benign_header`). It used to be
    six well-known names and a regex, while the set of identities that
    "present a credential" counted every declared header: an anonymous
    identity that sends only ``Accept`` was listed unproven although it sent
    nothing the target could reject. One list now answers "presents a
    credential" everywhere. Which of these headers a fabricated value is
    written into is a narrower question: :func:`_sham_header_names`.
    """
    return not is_benign_header(name)


#: Header names a fabricated value is written into although
#: ``_CUSTOM_CREDENTIAL_HINT`` does not match them: the WebSocket handshake
#: header carries a bearer token to the Kubernetes API server
#: (``veridor.credentials``).
_SHAM_EXTRA_CREDENTIAL_NAMES: frozenset[str] = frozenset({"sec-websocket-protocol"})


def _credential_named_header(name: str) -> bool:
    """Does this header's NAME mark it as a credential? The sham fabricates these.

    The same heuristic the duplicate-identity check uses: the six well-known
    credential names, or a name containing token, auth, key, secret, session,
    cookie, credential, passw, jwt or signature -- plus
    ``Sec-WebSocket-Protocol``. Every non-benign header used to be
    fabricated, so an ``X-Api-Version`` or ``Stripe-Version`` declared
    beside ``Authorization`` carried ``veridor-sham-...`` too: a target that
    refuses an unknown version answered every sham 400, every denial went
    ``control_uninformative``, and an ordinary suite exited 3 under
    --require-complete. A benign header is never one, whatever its name.
    """
    if is_benign_header(name):
        return False
    return (
        name.lower() in _CREDENTIAL_HEADER_NAMES
        or name.lower() in _SHAM_EXTRA_CREDENTIAL_NAMES
        or bool(_CUSTOM_CREDENTIAL_HINT.search(name))
    )


def _sham_header_names(config: Mapping[str, Any]) -> list[str]:
    """The header names a sham fabricates, values never read.

    Every non-benign header (:func:`_credential_bearing_header`) except the
    ones :func:`_sham_shared_headers` sends unchanged and the context headers
    :func:`_sham_context_headers` leaves out. Every declared name once
    qualified, so one benign header -- an ``Accept`` on the anonymous
    identity -- became the whole sham, and a target answering the unparseable
    Accept with 406 "told the credentials apart". Then only credential-NAMED
    headers qualified, which left out the header an auth proxy names the
    caller by (``X-Remote-User``), so no sham could be shaped and every denial
    was withheld. Then every unshared header qualified, and an X-Tenant-Id
    beside Authorization carried the fabricated value: a target that resolves
    the tenant first answered 404 "tenant not found", which read as the
    credential refused and proved an expired token live. A header no name
    heuristic recognises is fabricated only where it may be the credential:
    some identity declaring it presents no other.

    Empty when no identity declares a header to fabricate -- cookie-session
    identities beside an anonymous one, or only a shared ``X-Api-Version`` --
    and then no sham is sent: those denials count as
    ``withheld_no_credential_header``.
    """
    skipped = {name.lower() for name in _sham_shared_headers(config)}
    skipped |= _sham_context_headers(config)
    return sorted({
        name
        for identity in config["identities"].values()
        if isinstance(identity, Mapping)
        for name in (identity.get("headers") or {})
        if isinstance(name, str) and _credential_bearing_header(name)
        and name.lower() not in skipped
    })


def _presents_another_credential(identity: Mapping[str, Any]) -> bool:
    """A session, or a header whose name marks it a credential."""
    headers = identity.get("headers") or {}
    return bool(identity.get("session")) or (
        isinstance(headers, Mapping)
        and any(isinstance(name, str) and _credential_named_header(name) for name in headers)
    )


def _sham_context_headers(config: Mapping[str, Any]) -> set[str]:
    """Lowercased names of the headers the sham leaves out: not benign, not
    credential-named, not shared (:func:`_sham_shared_headers`), and declared
    only by identities that present another credential.

    Beside an identity's Authorization or session, an ``X-Tenant-Id`` or a
    version only it sends is routing, not what the target authenticates. A
    fabricated value there gave the target a reason to refuse the sham that
    has nothing to do with the credential -- "tenant not found", "unknown
    version" -- and a refusal is what proves a credential live. Left out, a
    target that requires it answers 400, which tells no credential apart, so
    the denial stays unproven rather than proven by accident. Where some
    declarer presents no other credential (``X-Remote-User`` behind an auth
    proxy) the header may be the credential and is fabricated.
    """
    shared = {name.lower() for name in _sham_shared_headers(config)}
    beside: dict[str, bool] = {}
    for identity in config["identities"].values():
        if not isinstance(identity, Mapping):
            continue
        headers = identity.get("headers") or {}
        if not isinstance(headers, Mapping):
            continue
        other = _presents_another_credential(identity)
        for name in headers:
            if (
                isinstance(name, str)
                and _credential_bearing_header(name)
                and not _credential_named_header(name)
                and name.lower() not in shared
            ):
                beside[name.lower()] = beside.get(name.lower(), True) and other
    return {name for name, context in beside.items() if context}


def _sham_shared_headers(config: Mapping[str, Any]) -> dict[str, str]:
    """Non-credential headers the sham sends with their declared value.

    A non-benign header whose name does not mark it a credential (an
    ``X-Api-Version``, a ``Notion-Version``, an ``X-Tenant-Id``) is sent
    unchanged when at least two identities declare it and every identity that
    declares it sends the same value: a value several callers share is not
    what tells any of them apart, and a target that checks it (400 on an
    unknown API version) then answers the sham for its credential. Any other
    such header is left out beside another credential
    (:func:`_sham_context_headers`) and otherwise fabricated
    (:func:`_sham_header_names`): a value that differs across identities, or
    that only one identity sends, may be its credential under a name the
    heuristic misses, so the sham never sends it.
    """
    # Keyed by the lowercased name, as HTTP compares them.
    values: dict[str, list[Any]] = {}
    declarers: dict[str, int] = {}
    spelling: dict[str, str] = {}
    for identity in config["identities"].values():
        if not isinstance(identity, Mapping):
            continue
        headers = identity.get("headers") or {}
        if not isinstance(headers, Mapping):
            continue
        mine: set[str] = set()
        for name, value in headers.items():
            if (
                isinstance(name, str)
                and _credential_bearing_header(name)
                and not _credential_named_header(name)
            ):
                spelling.setdefault(name.lower(), name)
                values.setdefault(name.lower(), []).append(value)
                mine.add(name.lower())
        for lowered in mine:
            declarers[lowered] = declarers.get(lowered, 0) + 1
    shared: dict[str, str] = {}
    for lowered, name in sorted(spelling.items()):
        sent = values[lowered]
        if declarers[lowered] >= 2 and all(
            isinstance(value, str) and value == sent[0] for value in sent
        ):
            shared[name] = sent[0]
    return shared


def _liveness_unproven(
    check: Mapping[str, Any],
    identity: str,
    expectation: Any,
    probes: Mapping[str, Mapping[str, Any]],
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
    credential_live: bool = False,
    presents_credential: bool = True,
) -> bool:
    """Did this denial prove anything about who was denied?

    Every precondition here is load-bearing, and three of them are lifted
    directly from ``mutate``'s M6, which has been making this comparison for a
    while and learned where it produces nonsense.

    * The expectation must be DENIAL-ONLY. An expectation that accepts a served
      status is falsified by the target serving something else; it cannot pass
      vacuously.
    * SOME identity in this check must have been SERVED. Without that, the
      check says "nobody may have this", and a fabricated credential also being
      refused is the declaration coming true rather than a dead token. Dropping
      this precondition manufactures a finding on every correctly-restrictive
      suite -- which is why M6 has it.
    * The identity must present a credential at all. An anonymous identity has
      none to be dead, and comparing it with a sham compares two absences.
    * The sham's own request must have succeeded to PROVE anything. An
      errored control (a timeout, a reset) licenses nothing, in either
      direction -- so, like a control that was never sent, it leaves the
      denial unproven. It used to count as proof: a target slow on, or
      dropping, unknown tokens turned this check off without a word.
    """
    if liveness is None or not _denial_only(expectation):
        return False
    # An identity that sends nothing has no credential that could be dead.
    # Comparing it with a fabricated one compares an absence with a forgery,
    # and the 401 it draws is the boundary working -- the best news the run can
    # carry. This is the same distinction `credential_bearing_identities` draws
    # in `blastradius`, and getting it wrong there suppressed the anonymous
    # identity from every rule.
    if not presents_credential:
        return False
    # No sham is sent with a method that can change state, nor when no
    # identity declares a credential header to shape one on, so there is no control to
    # compare against -- and no control is not a pass. The denial is unproven
    # on every precondition below except the comparison itself.
    control = liveness.get(_liveness_key(check))
    withheld = control is None or bool(control.get("error"))
    probe = probes.get(identity)
    if probe is None or probe.get("error"):
        return False
    identities_served = any(
        _target_served((other.get("response") or {}).get("status"))
        for other in probes.values()
    )
    if not identities_served:
        return False
    # The identity's own credential may already be PROVEN LIVE, in which case
    # its denial here is a boundary refusing a caller the target recognises --
    # which is the thing being tested, not a vacuity.
    #
    # This precondition is why a conservative API is not punished. `mutate`'s
    # M6 reaches the same place from the other direction: it grades a matching
    # 404 `not_applicable` rather than a survivor, because "calling it a
    # vacuity penalises the more conservative design and would reappear on
    # every CI run forever". The difference here is that `run` CAN often prove
    # liveness -- from a 2xx this identity drew elsewhere in the same run, or
    # from its own marker_probe control -- and only says "I cannot tell" when
    # nothing in the configuration establishes it.
    if credential_live:
        return False
    if withheld:
        return True
    sham_status = (control.get("response") or {}).get("status")
    if probe["response"].get("status") == sham_status:
        return True
    # A different answer proves the identity's credential was recognised only
    # when the sham's own answer came from the authorization layer.
    return not _tells_a_credential_apart(sham_status)


#: Why an excludes_marker request's marker was never compared with a
#: fabricated credential's response, as the console says it.
MARKER_UNIQUENESS_REASONS: dict[str, str] = {
    "unsafe_method": "no fabricated credential is sent with a method that can "
    "change state",
    "no_credential_header": "no identity declares a credential header to shape "
    "a fabricated credential on",
    "prove_liveness_off": "--no-prove-liveness was passed",
    "control_errored": "the fabricated credential's request failed",
    "control_unscannable": "the fabricated credential's response could not be "
    "scanned for the marker",
}


def _marker_uniqueness_not_checked(
    config: Mapping[str, Any],
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
    prove_liveness: bool,
) -> list[dict[str, Any]]:
    """Every (request, owner) an excludes_marker names that no sham was scanned for.

    Without that scan a marker that crosses is graded ``confirmed`` on the
    premise that it is unique to its owner, and nothing said the premise went
    untested.
    """
    sham_headers = bool(_sham_header_names(config))
    entries: list[dict[str, Any]] = []
    for (method, path), owners in sorted(_liveness_scan_markers(config).items()):
        control = (liveness or {}).get((method, path))
        for owner in sorted(owners):
            if method not in SAFE_METHODS:
                reason = "unsafe_method"
            elif not prove_liveness:
                reason = "prove_liveness_off"
            elif not sham_headers or control is None:
                reason = "no_credential_header"
            elif control.get("error"):
                reason = "control_errored"
            elif (control.get("marker_scans") or {}).get(owner) not in (
                "present", "absent",
            ):
                reason = "control_unscannable"
            else:
                continue
            entries.append({"method": method, "path": _safe_url(path),
                            "owner": owner, "reason": reason})
    return entries


def _marker_not_unique(
    check: Mapping[str, Any],
    owner: str,
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
) -> bool:
    """Positive evidence that ``owner``'s marker is NOT owner-specific.

    True only when the sham control -- a credential the target cannot have
    recognised -- got that marker back too. That is not ambiguity, it is
    disproof: whatever the string is, it is not gated on being the owner.

    Absence of this evidence is not proof of uniqueness, which is why the
    `confirmed` wording no longer claims it. It says the string was observed to
    cross, and states what that does and does not establish.
    """
    if liveness is None:
        return False
    control = liveness.get(_liveness_key(check))
    if control is None or control.get("error"):
        return False
    return (control.get("marker_scans") or {}).get(owner) == "present"


def _served_sham_status(
    check: Mapping[str, Any],
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
) -> int | None:
    """The 2xx the target answered this request's sham with, or None.

    A served sham means the target accepted a credential nobody issued. That
    is not evidence about a marker's uniqueness, and it is never silent: see
    :func:`_served_sham_disclosures`.
    """
    if liveness is None:
        return None
    control = liveness.get(_liveness_key(check))
    if control is None or control.get("error"):
        return None
    status = (control.get("response") or {}).get("status")
    return status if _target_served(status) else None


def _public_requests(config: Mapping[str, Any]) -> set[tuple[str, str]]:
    """Requests some check declares an identity with no credential served on.

    A route declared public serves any caller, so a fabricated credential
    served there is what the declaration says the route does: it is not a
    target accepting a credential it never issued.
    """
    identities = config.get("identities") or {}
    return {
        _liveness_key(check)
        for check in config.get("checks") or ()
        for name, expectation in (check.get("expect") or {}).items()
        if _accepts_service(expectation)
        and isinstance(identities.get(name), Mapping)
        and not presents_credential(identities[name])
    }


def _served_sham_disclosures(
    config: Mapping[str, Any],
    liveness: Mapping[tuple[str, str], Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """One oracle disclosure per check whose request served the sham.

    The target answered a credential Veridor fabricated with a 2xx. Nothing in
    the declaration asked about that, so no finding is emitted for it -- but a
    run that saw a target accept a credential nobody issued and said nothing
    would be the silent pass this product exists to refuse.
    """
    entries: list[dict[str, Any]] = []
    public = _public_requests(config)
    for check in config.get("checks") or ():
        status = _served_sham_status(check, liveness)
        if status is None or _liveness_key(check) in public:
            continue
        method, path = _liveness_key(check)
        entries.append(
            {
                "check_id": check["id"],
                "identity": "fabricated credential",
                "control_source": "fabricated_credential",
                "request_method": method,
                "request_path": _safe_url(path),
                "status": status,
                # Only what was measured: the status. It said "what this
                # request returns, it returns to any caller that presents a
                # credential-shaped header", and a target that served the sham
                # an empty, tenant-filtered list returned no such thing.
                "statement": (
                    f"the fabricated credential was served HTTP {status} on "
                    f"{method} {_safe_url(path)} (veridor-sham-...), so the "
                    "target accepted a credential it never issued. No expectation asked "
                    "about that, so it is not a finding; declare one for an "
                    "identity with a forged or expired credential to gate on it"
                ),
            }
        )
    return entries


def _control_reason(name: str, scan: str | None, result: dict[str, Any]) -> str:
    """Say precisely why a marker control failed to license an exclusion."""
    if result["error"]:
        return f"the marker probe for {quoted(name)} failed: {result['error']}"
    if scan == "unknown":
        detail = result["response"]["marker_scan_reason"]
        return (
            f"the marker probe for {quoted(name)} could not be fully scanned: {detail}"
        )
    if result["response"]["from_cache"]:
        return (
            f"the marker probe for {quoted(name)} was answered from a cache, so it "
            "describes the object at some earlier time and cannot establish "
            "that the marker is live now"
        )
    return (
        f"the marker probe for {quoted(name)} returned HTTP "
        f"{result['response']['status']} without the marker, so the marker is "
        "not known to be live"
    )


def _probe_marker(
    config: dict[str, Any],
    check: dict[str, Any],
    identity: str,
    expectation: dict[str, Any],
) -> str | None:
    """Return the marker literal this probe must scan for, or ``None``."""
    owner = expectation.get("contains_marker") or expectation.get("excludes_marker")
    if owner:
        return config["identities"][owner].get("marker")
    if _is_implicit_control(check, identity):
        # Scan this identity's own response for its own marker even though the
        # config never asked. It is the implicit same-check control; see
        # _observed_check_control for what it is allowed to conclude.
        return config["identities"][identity].get("marker")
    return None


def _unproven_reason(
    scan: str | None,
    reason: str | None,
    control_state: str | None,
    control_detail: str | None = None,
) -> str:
    if scan == "unknown":
        return f"body could not be fully scanned: {reason}"
    if control_state is not None and control_state != "present":
        return control_detail or "the control probe did not observe its own marker"
    return "response did not contain it"


def _resolve_control(
    check: dict[str, Any],
    excludes: str,
    probes: dict[str, dict[str, Any]],
    marker_controls: dict[str, dict[str, Any]],
) -> tuple[str, str | None, str | None]:
    """Return ``(source, state, reason)`` for the control behind an exclusion.

    Precedence is deliberate and conservative. A same-check control probes the
    marker owner at the very path under test, so it proves the marker is
    observable THERE; an identity ``marker_probe`` only proves the marker is
    live SOMEWHERE. Where the stronger evidence exists, it stays authoritative
    and the identity probe cannot paper over it -- so this can only ever
    withhold a licence, never grant one it would otherwise withhold.

    The tiers, strongest first:

    ``check``
        The config declared ``contains_marker: owner`` on ``owner``'s probe of
        this request.
    ``check_observed``
        The config declared no control, but this check probes ``owner`` anyway
        and the target SERVED that probe. Veridor scans it regardless of what
        the config asked for, because a 2xx to the marker's own owner at the
        path under test settles whether this path can surface that marker.
        When it cannot, absence in another identity's response proves nothing,
        and an identity ``marker_probe`` of some unrelated path must not be
        allowed to license the assertion anyway -- that escape hatch turned an
        unfalsifiable check into a clean green run.
    ``identity_probe``
        ``owner`` is not probed by this check at all, or was refused when it
        was, so no same-path evidence exists and none can be obtained. This is
        the per-principal-scoped case the identity probe exists for. It is a
        genuinely weaker licence and is disclosed as such; see
        ``_oracle_disclosure``.
    """
    if _has_check_control(check["expect"], excludes):
        control = probes.get(excludes)
        if control is None:
            return "check", "missing", None
        if control["response"]["from_cache"]:
            return "check", "unknown", (
                "the same-check control was answered from a cache, so it "
                "describes the object at some earlier time"
            )
        return "check", control["response"]["marker_scan"], None
    observed = _observed_check_control(check, excludes, probes)
    if observed is not None:
        return observed
    control = marker_controls.get(excludes)
    if control is not None:
        # 'present'/'missing' rather than 'verified'/'unverified' so that every
        # downstream comparison against "present" keeps one meaning.
        state = "present" if control["state"] == "verified" else "missing"
        return "identity_probe", state, control["reason"]
    return "none", "missing", (
        f"no control established that {quoted(excludes)}'s marker is live"
    )


def _observed_check_control(
    check: dict[str, Any],
    excludes: str,
    probes: dict[str, dict[str, Any]],
) -> tuple[str, str, str | None] | None:
    """Grade the marker owner's own probe of this request as a control.

    Returns ``None`` when this check yields no same-path evidence -- the owner
    is not probed here, the request failed, or the target refused it. A refusal
    tells us nothing: the owner never received their data at this path, so the
    absence of their marker is expected and says nothing about whether the path
    could surface it. Only a served response (2xx) settles the question.
    """
    if not _is_implicit_control(check, excludes):
        return None
    probe = probes.get(excludes)
    if probe is None or probe["error"]:
        return None
    status = probe["response"]["status"]
    if not isinstance(status, int) or not 200 <= status < 300:
        return None
    if probe["response"]["marker_scan"] == "present":
        return "check_observed", "present", None
    return (
        "check_observed",
        "missing",
        (
            f"{quoted(excludes)} was served this exact request (HTTP {status}) and its "
            f"own marker was not observed in that response, so this path is not "
            f"known to surface {quoted(excludes)}'s marker at all"
        ),
    )


def _observed_flow(owner: str, identity: str) -> str:
    """The strongest claim an observed marker licenses, and its exact limit.

    A marker in the wrong identity's response proves the STRING crossed:
    ``owner``'s declared marker was observed in ``identity``'s response. That
    much Veridor measured directly.

    It is evidence of DATA FLOW only insofar as the marker is unique to
    ``owner``'s data, and that premise is the operator's, not Veridor's. The
    old wording was falsified -- "bytes that exist only in
    owner's data" -- against a target returning the same build id to every
    caller, where that id happened to be the declared marker: two byte-identical
    responses, nothing crossed any boundary, and `confirmed` issued. When the
    run has positive evidence the marker is NOT owner-specific -- the sham
    credential got it back too -- this sentence is not emitted at all: a status
    that differed from the declaration grades AUTHZ-001 ``suspected`` on the
    status alone, and a status that matched is an unverified oracle
    (ORACLE-001, inconclusive), because nothing else in that probe suggests a
    leak. Absence of that evidence is not proof of
    uniqueness, so the claim is stated at the strength it actually has.

    It does not prove POLICY. Whether ``identity`` is entitled to ``owner``'s
    data is a statement the operator made in the configuration; Veridor
    consumes that statement and has no way to audit it. Wording that asserts a
    boundary was crossed makes a wrong declaration indistinguishable from a
    real vulnerability: an administrator's entitled read under an over-strict
    expectation still grades ``confirmed``.

    The hedge must name the right half. This sentence is only ever emitted
    under ``excludes_marker``, which means the operator DID declare the flow
    impermissible; saying "whether X may see Y's data is your declaration"
    reads as though no such declaration exists and turns the product's
    strongest measurement into a shrug. What is unaudited is whether that
    declaration is CORRECT, so that -- and only that -- is what is disclaimed.
    """
    return (
        f"{quoted(owner)}'s declared marker was observed in {quoted(identity)}'s response. "
        f"That is proof the string crossed, and proof of data flow insofar as "
        f"the marker is unique to {quoted(owner)}'s data. You declared that "
        f"{quoted(identity)} must not receive {quoted(owner)}'s data, and Veridor measured "
        "that it did. Whether that declaration is correct is not something "
        "Veridor can check."
    )


#: Remediation text separates measurement from declaration exactly as every
#: other emitted string does. A bare imperative to change the target ("Enforce
#: authorization ... before returning data") asserts that the target is the
#: broken half, which is the one thing Veridor cannot establish -- and it is
#: also the more expensive hypothesis to eliminate. Each of these leads with
#: the declaration and mirrors the SARIF rule help for the same rule, so a
#: run-JSON or UI consumer and a code-scanning consumer read the same advice.
_AUTHZ_REMEDIATION: str = (
    "Confirm the declared expectation is the policy you intend, then enforce "
    "that identity, role, and tenant authorization on the target. If the "
    "declaration is wrong, correct the configuration instead."
)

#: The target refused; there is nothing to stop returning. Telling an operator
#: to stop serving data on a probe that returned 404 and no data is incoherent.
_DENIAL_REMEDIATION: str = (
    "Confirm the declared status is the outcome you intend for this identity. "
    "If it is, investigate why the target refused this request -- an absent "
    "route, an unshipped feature, or an over-restriction. If the declaration "
    "is wrong, correct the configuration instead."
)

#: 401 and 407 are authentication statuses: the likeliest reason a declared
#: grant drew one is the credential the runner sent, not the boundary. A
#: rotated token produced four unexpected denials whose advice named a route,
#: a feature and an over-restriction -- everything except the token.
_CREDENTIAL_STATUSES = frozenset({401, 407})

_CREDENTIAL_DENIAL_REMEDIATION: str = (
    "Confirm the declared status is the outcome you intend for this identity. "
    "If it is, investigate why the target refused this request -- an absent "
    "route, an unshipped feature, an over-restriction, or an expired/invalid "
    "credential. If the declaration is wrong, correct the configuration "
    "instead."
)


def denial_remediation(status: int | None) -> str:
    """The remediation for an unexpected denial, by the status that drew it."""
    if status in _CREDENTIAL_STATUSES:
        return _CREDENTIAL_DENIAL_REMEDIATION
    return _DENIAL_REMEDIATION


def credential_suspects(result: Mapping[str, Any]) -> list[str]:
    """Identities refused with 401/407 on every request they were answered on.

    Counted over everything the identity sent -- check probes, its
    marker_probe, and sequence steps -- because one 200 anywhere proves the
    credential worked. An identity whose refusals were all DECLARED (an
    anonymous caller expected to draw 401) is not named: only one with at
    least one unexpected_denial is. A request that drew no status (transport
    error, never sent) says nothing either way and is skipped, never counted
    as a refusal. This is a hint, not a verdict: no grade or exit code reads it.
    """
    statuses: dict[str, list[int]] = {}

    def note(identity: Any, response: Any) -> None:
        status = response.get("status") if isinstance(response, Mapping) else None
        if isinstance(identity, str) and isinstance(status, int):
            statuses.setdefault(identity, []).append(status)

    for probe in result.get("probes") or ():
        note(probe.get("identity"), probe.get("response"))
    for control in result.get("marker_controls") or ():
        note(control.get("identity"), control.get("response"))
    for record in result.get("sequences") or ():
        for step in (record.get("steps") or []) + list(record.get("teardown") or ()):
            note(step.get("as"), step.get("response"))
    denied = {
        finding.get("identity")
        for finding in result.get("findings") or ()
        if finding.get("verdict") == "unexpected_denial"
    }
    return sorted(
        identity
        for identity, seen in statuses.items()
        if identity in denied and all(status in _CREDENTIAL_STATUSES for status in seen)
    )


_LEAK_REMEDIATION: str = (
    "Confirm your declaration that this identity must not receive the other "
    "identity's data. If it holds, remove that data from this response, "
    "including error and diagnostic payloads. If this identity is entitled to "
    "it, correct the configuration instead."
)

#: One string for VERIDOR-ORACLE-001's finding remediation and its SARIF help.
_ORACLE_REMEDIATION: str = (
    "Confirm the marker is stored in the identity's data and "
    "returned by this endpoint, then re-run."
)

#: A sequence that could not establish its own preconditions measured nothing.
#: The remediation must not read as either outcome, so it names the fixture as
#: the thing to fix and says nothing about the boundary.
_SEQUENCE_REMEDIATION: str = (
    "Establish that the setup steps succeed against this target -- a failed "
    "fixture is a configuration or environment problem, not an authorization "
    "result. Re-run once the failing step completes as declared."
)

#: Lives here rather than in ``sequence`` so the SARIF rule help and the
#: finding-level remediation are one string from one source, exactly as every
#: other rule already is.
_EFFECT_REMEDIATION: str = (
    "Confirm your declaration that this identity's data must persist. If it "
    "holds, the write issued by the earlier step in this sequence took effect "
    "across the boundary -- enforce authorization on that write path. If the "
    "earlier identity is entitled to modify this object, correct the "
    "configuration instead."
)

_SESSION_LIVENESS_REMEDIATION: str = (
    "Veridor cannot distinguish a target that denies an authenticated caller "
    "with this status from a session that died mid-run, and grading the second "
    "as a pass would hide a live vulnerability. Give the identity a session "
    "that outlives the run, set reestablish so the login is repeated, or have "
    "the endpoint answer 403 rather than 401 for an authenticated caller it "
    "refuses -- then re-run."
)

_CACHE_REMEDIATION: str = (
    "Point the runner at the origin rather than through the cache, or "
    "configure the cache to vary on the credential and to honour the "
    "no-cache request Veridor already sends, then re-run. A response an "
    "intermediary served from its own store says nothing about the target's "
    "current state."
)


def _oracle_disclosure(
    check: dict[str, Any],
    identity: str,
    excludes: str,
    control_state: str | None,
    marker_controls: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Record one exclusion licensed by evidence weaker than a same-path control.

    Carries the probe URL so a reviewer can see, without reading code, that the
    marker was proven live somewhere other than the path under test. The URL is
    already redacted by ``_perform_request``; no body and no marker literal is
    recorded here or anywhere else.
    """
    control = marker_controls.get(excludes) or {}
    request = control.get("request") or {}
    return {
        "check_id": check["id"],
        "identity": identity,
        "owner_identity": excludes,
        "control_source": "identity_probe",
        "control_state": control_state,
        "control_url": request.get("url"),
        "request_path": check["request"]["path"],
        "statement": (
            f"the absence of {quoted(excludes)}'s marker in {quoted(identity)}'s response was "
            f"licensed by {quoted(excludes)}'s identity marker_probe, which proves the "
            f"marker is live at {request.get('url') or 'the probe path'} -- not "
            f"that this check's path can surface it"
        ),
    }


#: What each kind of request is called in an ``injection_disclosures``
#: statement, and what its drop means for a reader of a clean run.
_INJECTION_DISCLOSURE_WORDING: dict[str, tuple[str, str]] = {
    "check": (
        "request",
        "so a matched denial may be the target refusing the missing field "
        "rather than the identity",
    ),
    "sequence_step": (
        "request",
        "so a matched denial may be the target refusing the missing field "
        "rather than the identity",
    ),
    "teardown": (
        "teardown request",
        "and teardown is never graded, so a target that requires the field may "
        "have refused the cleanup",
    ),
    "marker_probe": (
        "marker probe",
        "so it did not exercise the field-guarded path",
    ),
}


def _injection_disclosures(
    probes: Iterable[dict[str, Any]],
    sequences: Iterable[dict[str, Any]] = (),
    marker_controls: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    """One entry per request that went out without a declared inject field.

    A bodyless safe method has nowhere to carry a form_field or json_field and
    no CSRF check to fail, so the request is sent rather than refused, and a
    teardown request is sent whatever its body, because teardown is cleanup and
    is never graded. A matched denial over such a request may be the target
    refusing the missing field rather than the identity, so it establishes no
    more than a non-asserting expectation does. Every kind of request a
    session's injection reaches is read here -- check probes, sequence steps,
    teardown entries and identity marker probes -- so that the console, the
    web UI, SARIF and every ``veridor report`` format can say so, as they do
    for ``oracle_disclosures`` and ``non_asserting_expectations``, rather than
    leaving the drop on a record nobody reads. The Markdown report prints the
    statements, so they are held to ``coverage.BANNED_CLAIM_WORDS``. Field
    names only; ``_perform_request`` records no value.

    Each entry is ``{source, where, identity, statement}``: ``source`` is one of
    ``check``, ``sequence_step``, ``teardown`` or ``marker_probe``, and
    ``where`` is the label a reader can find the request by. A check entry also
    carries ``check_id``, as its sibling disclosures do.
    """
    disclosures: list[dict[str, Any]] = []

    def add(
        source: str, where: str, identity: str, fields: list[str], **extra: Any
    ) -> None:
        request, consequence = _INJECTION_DISCLOSURE_WORDING[source]
        disclosures.append(
            {
                "source": source,
                "where": where,
                **extra,
                "identity": identity,
                "statement": (
                    f"the {request} went out without {', '.join(fields)}, which "
                    f"this body could not carry, {consequence}"
                ),
            }
        )

    for probe in probes:
        fields = probe.get("injection_not_applied")
        if fields:
            add(
                "check", probe["check_id"], probe["identity"], fields,
                check_id=probe["check_id"],
            )
    for sequence in sequences:
        label = f"sequence {quoted(sequence['sequence_id'])}"
        for kind, source, key in (
            ("step", "sequence_step", "steps"),
            ("teardown", "teardown", "teardown"),
        ):
            for record in sequence.get(key) or ():
                fields = record.get("injection_not_applied")
                if fields:
                    add(
                        source, f"{label} {kind} {record['index']}", record["as"],
                        fields,
                    )
    for control in marker_controls:
        fields = control.get("injection_not_applied")
        if fields:
            add("marker_probe", "marker_probe", control["identity"], fields)
    return disclosures


def _grade_check(
    check: dict[str, Any],
    probes: dict[str, dict[str, Any]],
    config_path: Path,
    marker_controls: dict[str, dict[str, Any]] | None = None,
    disclosures: list[dict[str, Any]] | None = None,
    session_failures: dict[str, str] | None = None,
    session_codes: dict[str, str | None] | None = None,
    session_transient: dict[str, bool] | None = None,
    target: Mapping[str, Any] | None = None,
    liveness: dict[tuple[str, str], dict[str, Any]] | None = None,
    live_credentials: set[str] | None = None,
    credentialed: set[str] | None = None,
    liveness_unproven: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Grade every probe of one check, at most one finding per probe.

    Findings are emitted in ``check['expect']`` insertion order. The exclusion
    grade depends on a control -- either the same-check control probe or the
    marker owner's identity-level ``marker_probe`` -- so the whole check is
    graded as a unit.

    ``disclosures``, when supplied, collects the provenance of every exclusion
    licensed by evidence weaker than a same-path control. A passing exclusion
    emits no finding, so without this the reader of a green run could not tell
    an exclusion proven at the path under test from one licensed by a probe of
    an unrelated endpoint.
    """
    marker_controls = marker_controls or {}
    # Served here counts too, when something on this request was refused: an
    # identity the target answered 2xx beside a refused sham or anonymous
    # caller holds a credential the target recognises.
    live_credentials = set(live_credentials or ())
    credentialed = set(credentialed or ())
    # Only where this request discriminates: see _proven_live_by_service.
    if _check_discriminates(check, probes, liveness, credentialed):
        live_credentials |= {
            name
            for name, probe in probes.items()
            if _target_served((probe.get("response") or {}).get("status"))
        }
    session_failures = session_failures or {}
    session_codes = session_codes or {}
    session_transient = session_transient or {}
    check_name = check.get("name", check["id"])
    findings: list[dict[str, Any]] = []
    for identity, expectation in check["expect"].items():
        expected_statuses = expectation["status"]
        if identity in session_failures:
            # Degraded state is never allowed to look like a result. No request
            # was issued for this probe, so there is nothing to compare against
            # the declaration -- neither a pass nor a failure.
            #
            # The fingerprint uses the EXISTING (check, identity, "execution",
            # statuses) signature: adding a session to an identity does not
            # touch check['request'], so the id is byte-identical to the one an
            # unreachable target already produces and no baseline is broken.
            findings.append(
                {
                    "id": _finding_id(check, identity, "execution", expected_statuses),
                    "rule_id": "VERIDOR-EXEC-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Could not verify {check_name} as {identity}",
                    "message": (
                        f"Session for {quoted(identity)} was not established "
                        f"({session_failures[identity]}); this probe was not issued."
                    ),
                    "check_id": check["id"],
                    "identity": identity,
                    "evidence": {
                        "expected_statuses": expected_statuses,
                        "actual_status": None,
                        "request": None,
                        "response": None,
                        "session": {
                            "identity": identity,
                            "state": "failed",
                            "reason": session_failures[identity],
                            # Structural, so the gate never parses the prose.
                            "reason_code": session_codes.get(identity),
                            "transient": session_transient.get(identity, True),
                        },
                    },
                    "location": str(config_path),
                    "remediation": (
                        "Confirm the identity's session login steps succeed "
                        "against this target, then re-run. Until the session "
                        "establishes, this identity measures nothing."
                    ),
                }
            )
            continue
        probe = probes[identity]
        response = probe["response"]
        actual_status = response["status"]
        contains = expectation.get("contains_marker")
        excludes = expectation.get("excludes_marker")
        owner = contains or excludes
        scan = response["marker_scan"]
        control_state: str | None = None
        control_source: str | None = None
        control_detail: str | None = None
        if excludes:
            control_source, control_state, control_detail = _resolve_control(
                check, excludes, probes, marker_controls
            )
        evidence: dict[str, Any] = {
            "expected_statuses": expected_statuses,
            "actual_status": actual_status,
            "request": probe["request"],
            "response": response,
        }
        if owner:
            evidence["marker"] = {
                "mode": "contains" if contains else "excludes",
                "owner_identity": owner,
                "state": scan,
                "reason": response["marker_scan_reason"],
                "control_state": control_state,
                "encodings_matched": response["marker_encodings"],
            }
            if excludes:
                # New concepts ride as properties. Nothing here reaches
                # _finding_id, so no baseline is invalidated.
                evidence["marker"]["control_source"] = control_source
                evidence["marker"]["control_reason"] = control_detail
        base = {
            "check_id": check["id"],
            # The name travels with the finding. It is the only place a check
            # says what it MEANS, and for a `--promote` stub it is the only
            # place that says nobody reviewed it -- ``_print_summary`` printed
            # the id alone and ``to_sarif`` carried the id alone, so a name of
            # "TODO: describe the boundary you are asserting" was dropped at
            # both points a human or a code-scanning UI reads the result.
            # Not part of _finding_id, so no baseline is invalidated.
            "check_name": check_name,
            "identity": identity,
            "evidence": evidence,
            "location": str(config_path),
        }

        if probe["error"]:
            findings.append(
                {
                    "id": _finding_id(check, identity, "execution", expected_statuses),
                    "rule_id": "VERIDOR-EXEC-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Could not verify {check_name} as {identity}",
                    "message": execution_message(probe["error"]),
                    **base,
                    "remediation": _transport_remediation(
                        probe["error"], target or {}
                    ),
                }
            )
            continue

        if (
            actual_status not in expected_statuses
            and actual_status in NOT_AN_ANSWER_STATUSES
            # The carve-out is a LEAK inside a transient, not any marker at
            # all. `excludes_marker` + present means another identity's data
            # came back, which outranks the status; `contains_marker` present
            # is the owner seeing their own data, which proves nothing and must
            # not stop a 500 being reported as unmeasured.
            and not (excludes and scan == "present")
        ):
            # Not an answer, so not evidence -- in either direction. The one
            # carve-out is a marker actually observed in the body: measured
            # data flow outranks status semantics, and a leak that arrives
            # inside a 500 is still a leak. That case falls through below.
            #
            # The id uses the `execution` component, the same one an
            # unreachable target produces, so a probe that is a timeout on
            # Monday and a 429 on Tuesday is ONE recurring inconclusive rather
            # than two findings churning through the baseline diff.
            findings.append(
                {
                    "id": _finding_id(check, identity, "execution", expected_statuses),
                    "rule_id": "VERIDOR-EXEC-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Could not verify {check_name} as {identity}",
                    "message": (
                        f"Identity {quoted(identity)} received HTTP {actual_status}, which is "
                        "not an answer from the authorization layer: "
                        + unanswered_cause(actual_status)
                        + " This probe establishes "
                        f"nothing about the declared status {expected_statuses}, in "
                        "either direction."
                    ),
                    **base,
                    "remediation": unanswered_remediation(actual_status),
                }
            )
            continue

        if actual_status not in expected_statuses:
            # Measured fact first, declaration second, and the two never fused:
            # the status is what Veridor saw, the list is what the operator
            # wrote down.
            message = (
                f"Identity {quoted(identity)} received HTTP {actual_status} "
                f"(declared: one of {expected_statuses})."
            )
            grade = "ungraded"
            if excludes:
                if scan == "present" and _marker_not_unique(check, owner, liveness):
                    # The marker came back to a credential the target cannot
                    # have recognised, so it is not owner-specific: a build id,
                    # a shared config value, a string that occurs naturally.
                    # `confirmed` means the string crossed, which is evidence of
                    # DATA FLOW only insofar as the string belongs to the owner
                    # -- and here the run has positive evidence it does not.
                    #
                    # Not gated on byte-identical bodies, which was the obvious
                    # fix and is wrong: the flagship IDOR serves the attacker
                    # the victim's record VERBATIM, so identical bytes is the
                    # signature of the true positive. `blastradius` reached the
                    # same conclusion and says so at TAG_IDENTICAL_BODY: "used
                    # only to rank down -- never to raise a candidate, and never
                    # to drop one."
                    grade = "suspected"
                    message = (
                        f"Identity {quoted(identity)} received HTTP {actual_status} "
                        f"(declared: one of {expected_statuses}) and the response "
                        f"carried {quoted(owner)}'s marker -- but so did a request "
                        "carrying a credential Veridor fabricated, which the "
                        f"target cannot have recognised. {quoted(owner)}'s marker is "
                        "therefore not unique to its data, so the string "
                        "crossing proves nothing about data flow. Plant a marker "
                        "that appears only in that identity's records."
                    )
                elif scan == "present":
                    grade = "confirmed"
                    message = (
                        f"Identity {quoted(identity)} received HTTP {actual_status} "
                        f"(declared: one of {expected_statuses}) and the response "
                        f"carried {quoted(owner)}'s marker: "
                        + _observed_flow(owner, identity)
                    )
                else:
                    grade = "suspected"
                    why = _unproven_reason(
                        scan,
                        response["marker_scan_reason"],
                        control_state,
                        control_detail,
                    )
                    message += (
                        f" {quoted(owner)}'s marker was not observed ({why}), "
                        "so data exposure is unproven."
                    )
            # Direction matters. 'vulnerable' claims the target handed out
            # something it should not have; a REFUSAL handed out nothing. An
            # absent route, an unshipped feature, or a 404 where 403 was
            # declared are all failed declarations and all still findings, but
            # calling them vulnerable contradicts Veridor's own model -- the
            # coverage classifier reads 403 and 404 as denials. The verdict is
            # a finding property and is absent from _finding_id, so narrowing
            # it invalidates no baseline.
            refused = grade != "confirmed" and not _target_served(actual_status)
            if refused:
                message += refusal_sentence(actual_status)
            findings.append(
                {
                    "id": _finding_id(check, identity, "status", expected_statuses),
                    "rule_id": "VERIDOR-AUTHZ-001",
                    "level": "error",
                    "verdict": "unexpected_denial" if refused else "vulnerable",
                    "evidence_grade": grade,
                    "title": f"Authorization expectation failed for {check_name}",
                    "message": message,
                    **base,
                    "remediation": (
                        denial_remediation(actual_status)
                        if refused else _AUTHZ_REMEDIATION
                    ),
                }
            )
            continue

        sham_served = _served_sham_status(check, liveness)
        if (excludes and scan == "present" and sham_served is not None
                and _marker_not_unique(check, owner, liveness)):
            # The sham got the marker -- but the target SERVED it, so it
            # accepted a credential nobody issued. That says nothing about
            # whether the marker is unique to its owner; it says the endpoint
            # hands its data to any caller with a header, which is the leak
            # this probe is looking for, wider. Reading it as "not unique"
            # graded a real cross-tenant leak ORACLE-001 inconclusive, exit 0,
            # where the same leak without a denial-only expectation beside it
            # (so no sham) was LEAK-001 confirmed, exit 1: declaring more made
            # the grade weaker.
            #
            # `suspected`, not `confirmed`: with the run unable to show the
            # marker is the owner's alone, the crossing is not proof of data
            # flow -- but it is still a leak, so the default gate fails on it
            # and --fail-on confirmed does not.
            findings.append(
                {
                    "id": _finding_id(check, identity, "marker", expected_statuses),
                    "rule_id": "VERIDOR-LEAK-001",
                    "level": "error",
                    "verdict": "vulnerable",
                    "evidence_grade": "suspected",
                    "title": f"Cross-identity data flow observed for {check_name}",
                    "message": (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{actual_status}, but the response carried {quoted(owner)}'s "
                        "marker. A request carrying a credential Veridor "
                        f"fabricated was served too (HTTP {sham_served}) and got "
                        "the same marker: the target accepted a credential "
                        "nobody issued, so this run cannot show the marker is "
                        f"unique to {quoted(owner)}'s data, and the grade is "
                        "suspected rather than confirmed. The marker went to a "
                        "credential the target never issued as well as to "
                        f"{quoted(identity)}."
                    ),
                    **base,
                    "remediation": _LEAK_REMEDIATION,
                }
            )
            continue

        if excludes and scan == "present" and _marker_not_unique(check, owner, liveness):
            # The status matched, so the marker is the ONLY evidence -- and the
            # sham got it back too, which disproves it. Nothing is left that
            # suggests a leak. Grading this `confirmed` issued the strongest
            # grade on a build id any caller can read; capping it at LEAK-001
            # `suspected` still said `vulnerable`, which the default
            # new+confirmed gate fails on, beside a message saying the crossing
            # proves nothing.
            #
            # The status-mismatch branch above keeps `vulnerable` because
            # there the status alone is evidence. Here it is an oracle that
            # could not be verified, graded exactly as an unverified
            # excludes_marker is below: ORACLE-001, inconclusive, which
            # --require-complete turns into exit 3.
            findings.append(
                {
                    "id": _finding_id(check, identity, "oracle", expected_statuses),
                    "rule_id": "VERIDOR-ORACLE-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Marker observed but not unique to its owner for {check_name}",
                    "message": (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{actual_status}, and the response carried {quoted(owner)}'s "
                        "marker -- but so did a request carrying a credential "
                        "Veridor fabricated, which the target cannot have "
                        f"recognised. {quoted(owner)}'s marker is therefore not "
                        "unique to its data, so the string crossing proves nothing "
                        "about data flow. Plant a marker that appears only in that "
                        "identity's records."
                    ),
                    **base,
                    "remediation": _ORACLE_REMEDIATION,
                }
            )
            continue

        if excludes and scan == "present":
            # A correct status with the other identity's marker in the body is
            # still a measured data flow, and it is invisible to a status-only
            # oracle.
            findings.append(
                {
                    "id": _finding_id(check, identity, "marker", expected_statuses),
                    "rule_id": "VERIDOR-LEAK-001",
                    "level": "error",
                    "verdict": "vulnerable",
                    "evidence_grade": "confirmed",
                    "title": f"Cross-identity data flow observed for {check_name}",
                    "message": (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{actual_status}, but the response carried {quoted(owner)}'s "
                        "marker: " + _observed_flow(owner, identity)
                    ),
                    **base,
                    "remediation": _LEAK_REMEDIATION,
                }
            )
            continue

        if owner and response["from_cache"]:
            # The README has always said a cached response "cannot license a
            # pass and it cannot refute a write". It was true only for
            # sequences: VERIDOR-CACHE-001 was emitted from exactly one site,
            # in sequence.py, and `_grade_check` never read `from_cache` at
            # all. A docs-only trial built a target answering the attacker's
            # probe with `Age: 600` and got "2/2 probes matched", exit 0.
            #
            # Placement is load-bearing. This sits AFTER the leak branch, so an
            # observed marker still grades `confirmed` -- a cache cannot make
            # bytes that were on the wire not have been there -- and after the
            # status branch, so no error-level finding is ever softened into a
            # warning. The only outcomes it converts are passes and unproven
            # oracles.
            findings.append(
                {
                    "id": _finding_id(check, identity, "cache", expected_statuses),
                    "rule_id": "VERIDOR-CACHE-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Marker read from a cached response for {check_name}",
                    "message": (
                        f"Identity {quoted(identity)} received the declared HTTP "
                        f"{actual_status}, but an intermediary announced the "
                        "response as served from a cache. The marker result "
                        "describes the object at some earlier time, so it "
                        "cannot settle this check's expectation."
                    ),
                    **base,
                    "remediation": _CACHE_REMEDIATION,
                }
            )
            continue

        if (contains and scan != "present") or (
            excludes and (scan == "unknown" or control_state != "present")
        ):
            why = _unproven_reason(
                scan, response["marker_scan_reason"], control_state, control_detail
            )
            if contains:
                message = (
                    f"Identity {quoted(identity)} received the declared HTTP "
                    f"{actual_status}, but {quoted(owner)}'s marker was not observed "
                    f"({why}); exclusion results for this check are unverified."
                )
            else:
                message = (
                    f"Identity {quoted(identity)} received the declared HTTP "
                    f"{actual_status}, but the absence of {quoted(owner)}'s marker could "
                    f"not be verified ({why})."
                )
            findings.append(
                {
                    "id": _finding_id(check, identity, "oracle", expected_statuses),
                    "rule_id": "VERIDOR-ORACLE-001",
                    "level": "warning",
                    "verdict": "inconclusive",
                    "evidence_grade": "n/a",
                    "title": f"Marker oracle unverified for {check_name}",
                    "message": message,
                    **base,
                    "remediation": _ORACLE_REMEDIATION,
                }
            )
            continue

        # The status matched and the oracle held -- but a denial-only
        # expectation is satisfied identically by a boundary that works and by
        # a credential the target never recognised. If a caller Veridor
        # fabricated got the same answer, this probe distinguished nothing.
        #
        # Deliberately LAST, after every other grade. A status mismatch, a
        # transient, a leak and a failed oracle are all more informative than
        # "we could not tell", and none of them should be replaced by it.
        if _liveness_unproven(
            check, identity, expectation, probes, liveness,
            credential_live=identity in live_credentials,
            presents_credential=identity in credentialed,
        ) and liveness_unproven is not None:
            # A DISCLOSURE, not a finding, and the distinction is the whole
            # design. This shape -- an identity asserted only to be denied, and
            # never served anywhere -- is the ordinary shape of an
            # authorization suite, not an anomaly: most people assert that the
            # attacker is refused and never that it is served. Emitting a
            # finding fired on the majority of correct configurations, which is
            # the definition of crying wolf, and `mutate`'s M6 refused the same
            # move for the same reason ("would reappear on every CI run
            # forever", mutation.py).
            #
            # So the fact is always recorded and always printed, and it changes
            # an exit code only when the operator asked for measurement
            # completeness with --require-complete -- which the GitHub Action
            # turns on by default, so CI gets the gate and an interactive run
            # gets the truth without a red build.
            method = _liveness_key(check)[0]
            control = liveness.get(_liveness_key(check))
            withheld = (
                "withheld_unsafe_method" if method not in SAFE_METHODS
                else "withheld_no_credential_header"
                if control is None
                else "control_errored"
                if control.get("error")
                else "control_uninformative"
                if (control.get("response") or {}).get("status")
                != probe["response"]["status"]
                else None
            )
            liveness_unproven.append(
                {
                    "check_id": check["id"],
                    "check_name": check_name,
                    "identity": identity,
                    "status": probe["response"]["status"],
                    "expected_statuses": list(expected_statuses),
                    # Present only when no sham answer could be compared, so
                    # an entry made the old way is byte-identical.
                    **({"control": withheld} if withheld else {}),
                    **(
                        {"control_error": str(control["error"])}
                        if withheld == "control_errored"
                        else {}
                    ),
                    **(
                        {"control_status": control["response"]["status"]}
                        if withheld == "control_uninformative"
                        else {}
                    ),
                    "statement": (
                        (
                            f"{quoted(identity)} received HTTP "
                            f"{probe['response']['status']} on this request. No "
                            "identity in this configuration declares a header a "
                            "fabricated credential can be shaped on (any header "
                            "but a standard, shared or context one), so "
                            "Veridor had nothing to shape a fabricated credential "
                            "on and sent none, and nothing here shows the target "
                            f"recognised {quoted(identity)}'s credential. The "
                            f"declaration for {quoted(identity)} accepts only "
                            "denial statuses, so it is satisfied by a boundary "
                            "that refuses this identity AND by a credential that "
                            "expired or was mistyped. This probe does not "
                            "distinguish them."
                        )
                        if withheld == "withheld_no_credential_header"
                        else (
                            f"{quoted(identity)} received HTTP "
                            f"{probe['response']['status']} on this {method} "
                            "request. Veridor does not send a credential it "
                            f"fabricated with a {method}, because the method can "
                            "change state, so nothing here shows the target "
                            f"recognised {quoted(identity)}'s credential. The "
                            f"declaration for {quoted(identity)} accepts only "
                            "denial statuses, so it is satisfied by a boundary "
                            "that refuses this identity AND by a credential that "
                            "expired or was mistyped. This probe does not "
                            "distinguish them."
                        )
                        if withheld == "withheld_unsafe_method"
                        else (
                            f"{quoted(identity)} received HTTP "
                            f"{probe['response']['status']} on this request. "
                            "Veridor sent a credential it fabricated to compare "
                            f"with, and that request failed ({control['error']}), "
                            "so nothing here shows the target recognised "
                            f"{quoted(identity)}'s credential. The declaration "
                            f"for {quoted(identity)} accepts only denial "
                            "statuses, so it is satisfied by a boundary that "
                            "refuses this identity AND by a credential that "
                            "expired or was mistyped. This probe does not "
                            "distinguish them."
                        )
                        if withheld == "control_errored"
                        else (
                            f"{quoted(identity)} received HTTP "
                            f"{probe['response']['status']} on this request, and "
                            "a credential Veridor fabricated received HTTP "
                            f"{control['response']['status']}: neither a refusal "
                            "nor a success, so that answer came from something "
                            "other than the application judging the credential "
                            "(a parser, a proxy, a rate limiter, a server error) "
                            "and nothing here shows the target recognised "
                            f"{quoted(identity)}'s credential. The declaration "
                            f"for {quoted(identity)} accepts only denial "
                            "statuses, so it is satisfied by a boundary that "
                            "refuses this identity AND by a credential that "
                            "expired or was mistyped. This probe does not "
                            "distinguish them."
                        )
                        if withheld == "control_uninformative"
                        else (
                            f"{quoted(identity)} received HTTP {probe['response']['status']} "
                            "on this request, and so did a credential Veridor "
                            "fabricated that the target cannot have recognised. The "
                            f"declaration for {quoted(identity)} accepts only denial "
                            "statuses, so it is satisfied by a boundary that refuses "
                            "this identity AND by a credential that expired or was "
                            "mistyped. This probe does not distinguish them."
                        )
                    ),
                    "remediation": (
                        f"Give {quoted(identity)} a marker_probe naming something it "
                        "SHOULD be served, or declare a check where it is served "
                        "and the fabricated credential or an identity with no "
                        "credential is refused on the same request. Either "
                        "proves the credential live and this disclosure "
                        "disappears. If the target hides existence uniformly, the "
                        "boundary cannot be measured from outside it."
                    ),
                }
            )

        # Nothing to report: the status matched and the oracle held, so this
        # probe PASSED. Only now is it true that an absence was licensed by the
        # weaker control -- which is what the disclosure says.
        #
        # It used to be appended at the top of the loop, before the probe was
        # graded at all, so it printed "the absence of 'owner''s marker in
        # 'outsider''s response was licensed by ..." on findings where the
        # marker was PRESENT. It described the declaration and called it an
        # observation.
        if disclosures is not None and control_source == "identity_probe":
            disclosures.append(
                _oracle_disclosure(
                    check, identity, excludes, control_state, marker_controls
                )
            )
    return findings


def _load_baseline(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        baseline = json.loads(raw)
    except FileNotFoundError as exc:
        raise ConfigError(f"baseline not found: {path}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"invalid baseline JSON in {path}: {exc}") from exc
    if not isinstance(baseline, dict) or not isinstance(baseline.get("findings"), list):
        raise ConfigError("baseline must be a Veridor run JSON document")
    run_id = baseline.get("run_id")
    if run_id is not None and not isinstance(run_id, str):
        raise ConfigError("baseline run_id must be a string")
    finding_ids: set[str] = set()
    for index, finding in enumerate(baseline["findings"]):
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("id"), str)
            or not finding["id"]
        ):
            raise ConfigError(f"baseline finding {index} requires a non-empty id")
        if finding["id"] in finding_ids:
            raise ConfigError(f"baseline contains duplicate finding id: {finding['id']}")
        finding_ids.add(finding["id"])
    # Stashed under a private key rather than returned alongside, because every
    # caller of this function wants the document and exactly one wants the
    # digest. Stripped before the document is ever compared or persisted.
    baseline["_digest"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
    return baseline


#: The ``kind`` a run document may carry. Run documents have never carried one,
#: so its absence means "run"; the sibling documents all do carry one
#: (``veridor.matrix``, ``veridor.matrix_drift``, the coverage report), which is
#: what lets a run reader refuse them by name instead of rendering an empty run.
RUN_KIND: str = "veridor.run"

#: The exit code of ``veridor verify`` for each capsule verdict. A capsule's
#: own scale, not a run's: 1 means the claim reproduced. Here, in ``core``,
#: because the run validator below holds a written document to it and
#: ``capsule`` and ``gate`` both import from this module.
CAPSULE_EXIT_CODES: dict[str, int] = {
    "CONFIRMED": 1,
    "NOT_REPRODUCED": 0,
    "INCONCLUSIVE": 2,
}


def load_run(path: Path) -> dict[str, Any]:
    """Load and validate a persisted run for report generation."""
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"run not found: {path}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"invalid run JSON in {path}: {exc}") from exc
    return validate_run(result, source=str(path))


def validate_run(result: Any, *, source: str = "run") -> dict[str, Any]:
    """Refuse anything a report renderer could misread as a run.

    Every renderer is fed through here -- ``veridor report --from-run`` via
    :func:`load_run`, and ``veridor run --report`` with the document it just
    wrote -- so a document that is not a run, or a run this binary cannot fully
    read, fails closed with exit 2 instead of rendering as an empty, green run.
    The type checks cover every container a renderer walks: a string where
    ``evidence`` should be an object used to crash ``report`` with a traceback
    and exit 1, the code that means "the gate failed".
    """
    if not isinstance(result, dict):
        raise ConfigError(
            f"{source} is not a Veridor run JSON document (it holds a JSON "
            f"{type(result).__name__}, not an object). Pass the file `veridor run "
            "--json` or `.veridor/latest.json` wrote."
        )
    kind = result.get("kind")
    if kind is not None and kind != RUN_KIND:
        raise ConfigError(
            f"{source} is a {quoted(kind)} document, not a Veridor run. `report "
            "--from-run` renders the run JSON `veridor run --json` writes"
            + (
                "; a drift report renders with `report --from-drift`."
                if kind == "veridor.matrix_drift"
                else "."
            )
        )
    if (
        not isinstance(result.get("run_id"), str)
        or not result["run_id"]
        or not isinstance(result.get("findings"), list)
    ):
        raise ConfigError("run must be a Veridor run JSON document")
    # A missing schema_version means 1: documents written before grading exist
    # in the wild and must keep loading.
    schema_version = result.get("schema_version", 1)
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in SUPPORTED_RUN_SCHEMA_VERSIONS
    ):
        raise ConfigError(
            f"unsupported run schema_version: {schema_version}; this Veridor "
            f"supports {sorted(SUPPORTED_RUN_SCHEMA_VERSIONS)}. Render it with the "
            "Veridor version that wrote it, or upgrade this one."
        )
    required = {
        "id": str,
        "rule_id": str,
        "level": str,
        "message": str,
        "location": str,
        "check_id": str,
        "identity": str,
        "verdict": str,
    }
    for index, finding in enumerate(result["findings"]):
        if not isinstance(finding, dict):
            raise ConfigError(f"run finding {index} must be an object")
        for field, expected_type in required.items():
            if not isinstance(finding.get(field), expected_type) or not finding[field]:
                raise ConfigError(
                    f"run finding {index} requires a non-empty {field}"
                )
        if schema_version >= 2 and finding.get("evidence_grade") not in EVIDENCE_GRADES:
            raise ConfigError(
                f"run finding {index} requires an evidence_grade in "
                f"{list(EVIDENCE_GRADES)}"
            )
        for field, expected in (("evidence", dict), ("title", str),
                                ("remediation", str), ("check_name", str)):
            if field in finding and finding[field] is not None and not isinstance(
                finding[field], expected
            ):
                raise ConfigError(
                    f"run finding {index} has a {field} that is a "
                    f"{type(finding[field]).__name__}, not a {expected.__name__}"
                )
        line = finding.get("location_line")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
            raise ConfigError(f"run finding {index} has a non-integer location_line")
    for field, expected in (
        ("probes", list), ("summary", dict), ("regression", dict),
        ("liveness", dict), ("sequences", list),
        ("non_asserting_expectations", list), ("gate", dict),
        ("injection_disclosures", list),
        ("target_wait", dict), ("capsule", dict),
    ):
        if field in result and not isinstance(result[field], expected):
            raise ConfigError(
                f"run {field} is a {type(result[field]).__name__}, not a "
                f"{expected.__name__}"
            )
    for field in (
        "probes", "sequences", "non_asserting_expectations", "injection_disclosures",
    ):
        for index, entry in enumerate(result.get(field) or ()):
            if not isinstance(entry, dict):
                raise ConfigError(f"run {field}[{index}] must be an object")
    _validate_nested_run_fields(result)
    if "capsule" in result:
        _validate_capsule_record(result)
    if "gate" in result:
        _validate_gate_record(result["gate"], capsule="capsule" in result)
    return result


def _validate_capsule_record(result: dict[str, Any]) -> None:
    """The ``capsule`` object ``veridor verify`` writes, and the gate beside it.

    A capsule verification exits with the capsule's verdict, which the
    findings alone cannot reproduce: an INCONCLUSIVE run can hold no finding
    the default policy gates on, and was rendered "Gate passed (exit 0)"
    while ``verify`` had exited 2. So the verdict, its exit code and the
    recorded gate must agree, and a document where they do not -- or with no
    gate to agree with -- is refused rather than re-derived as a run.
    """
    record = result["capsule"]
    verdict = record.get("verdict")
    if verdict not in CAPSULE_EXIT_CODES:
        raise ConfigError(
            f"run capsule.verdict must be one of {sorted(CAPSULE_EXIT_CODES)}; "
            "the run document was edited or is corrupt"
        )
    code = record.get("exit_code")
    if code != CAPSULE_EXIT_CODES[verdict] or isinstance(code, bool):
        raise ConfigError(
            f"run capsule.exit_code is {json.dumps(code)} but a {verdict} capsule exits "
            f"{CAPSULE_EXIT_CODES[verdict]}; the run document was edited or is corrupt"
        )
    for key in ("reason", "check_id", "path"):
        if key in record and not isinstance(record[key], str):
            raise _shape_error(f"capsule.{key}", record[key], "a string")
    gate = result.get("gate")
    if not isinstance(gate, dict) or gate.get("exit_code") != code:
        raise ConfigError(
            "run capsule verdict has no gate that records its exit code; the run "
            "document was edited or is corrupt"
        )


def _shape_error(where: str, value: Any, expected: str) -> ConfigError:
    found = "missing" if value is None else f"a {type(value).__name__}"
    return ConfigError(
        f"run {where} is {found}, not {expected}; the run document was edited "
        "or is corrupt. Render the file `veridor run --json` or "
        "`.veridor/latest.json` wrote."
    )


def _validate_nested_run_fields(result: dict[str, Any]) -> None:
    """The fields below the top level that a renderer reads.

    Checking only the top-level containers left each of these to crash a
    renderer with AttributeError, TypeError or KeyError -- exit 70, "a bug in
    Veridor" -- on a hand-edited document: measured by setting every nested
    field of a run document to the wrong type, or deleting it, and rendering
    every format. tests/test_reports.py repeats that sweep.
    """
    for index, finding in enumerate(result["findings"]):
        request = (finding.get("evidence") or {}).get("request")
        if request is not None and not isinstance(request, dict):
            raise _shape_error(f"finding {index} evidence.request", request, "an object")
    for index, probe in enumerate(result.get("probes") or ()):
        response = probe.get("response")
        if response is not None and not isinstance(response, dict):
            raise _shape_error(f"probes[{index}].response", response, "an object")
    unproven = (result.get("liveness") or {}).get("unproven")
    if unproven is not None:
        _require_list_of(unproven, dict, "liveness.unproven")
    for key in ("new", "unchanged", "resolved"):
        entries = (result.get("regression") or {}).get(key)
        if entries is not None:
            _require_list_of(entries, dict, f"regression.{key}")
    for index, sequence in enumerate(result.get("sequences") or ()):
        steps = sequence.get("steps")
        if steps is not None:
            _require_list_of(steps, dict, f"sequences[{index}].steps")
    for index, entry in enumerate(result.get("non_asserting_expectations") or ()):
        for key in ("check_id", "identity", "classification", "statement"):
            if not isinstance(entry.get(key), str):
                raise _shape_error(
                    f"non_asserting_expectations[{index}].{key}", entry.get(key), "a string"
                )
    for index, entry in enumerate(result.get("injection_disclosures") or ()):
        keys = ("source", "where", "identity", "statement")
        if entry.get("source") == "check":
            keys += ("check_id",)
        for key in keys:
            if not isinstance(entry.get(key), str):
                raise _shape_error(
                    f"injection_disclosures[{index}].{key}", entry.get(key), "a string"
                )


_KIND_NAMES = {dict: "an object", str: "a string"}


def _require_list_of(value: Any, kind: type, where: str) -> None:
    if not isinstance(value, list):
        raise _shape_error(where, value, "a list")
    for index, item in enumerate(value):
        if not isinstance(item, kind):
            raise _shape_error(f"{where}[{index}]", item, _KIND_NAMES[kind])


def _validate_gate_record(gate: dict[str, Any], *, capsule: bool = False) -> None:
    """The ``gate`` object ``veridor run`` writes. See ``veridor.gate``.

    ``veridor verify`` takes no ``--fail-on``, so the gate it writes beside a
    ``capsule`` object carries ``fail_on: null`` rather than a policy it never
    applied.
    """
    code = gate.get("exit_code")
    if not isinstance(code, int) or isinstance(code, bool):
        raise ConfigError("run gate.exit_code must be an integer")
    if not isinstance(gate.get("fail_on"), str) and not (
        capsule and gate.get("fail_on") is None
    ):
        raise ConfigError("run gate.fail_on must be a string")
    for key in ("reasons", "not_enforced"):
        entries = gate.get(key, [])
        if not isinstance(entries, list):
            raise ConfigError(f"run gate.{key} must be a list")
        for index, entry in enumerate(entries):
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("code"), str)
                or not isinstance(entry.get("exit_code"), int)
            ):
                raise ConfigError(
                    f"run gate.{key}[{index}] must be an object with a string "
                    "code and an integer exit_code"
                )
            # The three lists a renderer joins or iterates: finding_ids, and
            # identities or sequences in reason_sentence. sequences was left
            # out, so a hand-edited `"sequences": 5` passed here and every
            # text renderer but SARIF crashed with exit 70 (measured).
            for listed in ("finding_ids", "identities", "sequences"):
                if listed in entry:
                    _require_list_of(entry[listed], str, f"gate.{key}[{index}].{listed}")
    reasons = gate.get("reasons") or []
    # The one invariant a renderer leans on: the first reason decides the code.
    expected = reasons[0]["exit_code"] if reasons else 0
    if code != expected:
        raise ConfigError(
            f"run gate.exit_code is {code} but its first reason says {expected}; "
            "the gate object was edited or is corrupt"
        )


def _interpretation(
    policy_source: str | None = None, *, has_sequences: bool = False
) -> dict[str, str]:
    """Machine-readable statement of what a Veridor finding is and is not.

    Emitted on every run so downstream consumers -- dashboards, ticket
    openers, risk registers -- inherit the caveat with the data instead of
    re-deriving it, or worse, dropping it.
    """
    statement = {
        "summary": DECLARATION_SCOPE,
        "measures": (
            "For each check Veridor issued the configured request as each named "
            "identity and recorded the observed HTTP status and, where a marker "
            "is configured, whether that marker was present in the response "
            "body. Response bodies are scanned in memory and never persisted."
        ),
        "finding_means": (
            "Observed behaviour differed from the expectation declared for that "
            "identity in the configuration."
        ),
        "finding_does_not_mean": (
            "That the declaration is correct. The configuration is the policy "
            "statement; Veridor consumes it and cannot audit it. An over-strict "
            "declaration produces a finding on entitled, legitimate behaviour."
        ),
        "pass_means": PASS_SCOPE,
        "pass_does_not_mean": (
            "That the boundary is enforced. Veridor only compares against the "
            "expectations you wrote: an expectation that accepts both access "
            "and denial matches whatever the target does, and an exclusion "
            "licensed by an identity marker_probe was never demonstrated at "
            "the path under test."
        ),
        "confirmed_grade_means": (
            "One identity's marker was observed in another identity's response. "
            "That is proof the string crossed, and proof of data flow insofar "
            "as the marker is unique to that identity's data. It is never "
            "proof of policy."
        ),
        "reference": "https://github.com/Veridor-authz/veridor#confirmed-proves-data-flow-never-policy",
    }
    if has_sequences:
        # VERIDOR-EFFECT-001 grades 'confirmed' on a marker's ABSENCE, which
        # would make the unconditional sentence above false. Conditional
        # emission follows the discipline already used three times in
        # execute_run: a sequence-free run emits byte-identical strings.
        statement["measures"] += (
            " A sequence additionally issues an ordered list of requests, each "
            "as one named identity, carrying named values forward in memory "
            "only; captured values are never persisted in any form."
        )
        statement["confirmed_grade_means"] = (
            "A marker was observed where the declaration says it must not be, "
            "or was observed to have been destroyed where the declaration says "
            "it must persist, with the marker's presence established earlier in "
            "the same run. Either way: proof of a data effect, never proof of "
            "policy."
        )
    if policy_source is not None:
        statement["policy_source"] = policy_source
    return statement


def _is_escalation(current_grade: str, baseline_grade: str) -> bool:
    """Only a transition into 'confirmed' escalates.

    'ungraded' -> 'suspected' fires merely because a user added marker config,
    so treating it as an escalation would manufacture CI noise.
    """
    return (
        _GRADE_ORDER.get(current_grade, 0) == _GRADE_ORDER["confirmed"]
        and _GRADE_ORDER.get(baseline_grade, 0) < _GRADE_ORDER["confirmed"]
    )


#: Verdicts that are a statement about the TARGET rather than about the run.
#: `cli._TARGET_VERDICTS` is the same set for the same reason; this module owns
#: the document, so the document's own status is derived here.
_TARGET_VERDICTS = frozenset({"vulnerable", "unexpected_denial"})


def run_status(findings: Iterable[Mapping[str, Any]]) -> str:
    """A run document's ``status``, from its findings and nothing else.

    ``failed``: at least one finding is ``vulnerable`` or
    ``unexpected_denial``. ``inconclusive``: none is, and at least one is
    ``inconclusive``. ``passed``: no finding at all.

    Probes are not read. An answered probe that matched its declaration
    produces no finding, so ``inconclusive`` does NOT mean nothing was measured
    -- five matched probes and one timeout is ``inconclusive``. "Not one probe
    was answered" is the gate's ``nothing_answered`` reason, not this.
    """
    verdicts = [finding.get("verdict") for finding in findings]
    if any(verdict in _TARGET_VERDICTS for verdict in verdicts):
        return "failed"
    if "inconclusive" in verdicts:
        return "inconclusive"
    return "passed"


def _compare_findings(
    findings: list[dict[str, Any]], baseline: dict[str, Any] | None
) -> dict[str, Any]:
    current_by_id = {finding["id"]: finding for finding in findings}
    baseline_findings = baseline.get("findings", []) if baseline else []
    baseline_by_id = {finding["id"]: finding for finding in baseline_findings}
    current_ids = set(current_by_id)
    baseline_ids = set(baseline_by_id)
    unchanged_ids = sorted(current_ids & baseline_ids)
    return {
        "baseline_run_id": baseline.get("run_id") if baseline else None,
        # The bytes this comparison was made against. Not a signature and not
        # an integrity check -- anyone who can edit the baseline can edit it
        # again and the digest simply follows. It is here so that two runs
        # reporting different diffs against "the same" baseline can be shown to
        # have read different files, which is otherwise unrecoverable after the
        # fact.
        "baseline_digest": baseline.get("_digest") if baseline else None,
        "new": [current_by_id[item] for item in sorted(current_ids - baseline_ids)],
        "resolved": [baseline_by_id[item] for item in sorted(baseline_ids - current_ids)],
        "unchanged": [current_by_id[item] for item in unchanged_ids],
        # A view over 'unchanged', not a partition: new/resolved/unchanged
        # arithmetic is unaffected.
        "escalated": [
            current_by_id[item]
            for item in unchanged_ids
            if _is_escalation(
                current_by_id[item].get("evidence_grade", "ungraded"),
                baseline_by_id[item].get("evidence_grade", "ungraded"),
            )
        ],
    }


def _non_asserting_expectations(config: dict[str, Any]) -> list[dict[str, Any]]:
    """List every expectation that accepts both access and denial.

    Such an expectation asserts nothing about the boundary: whatever the target
    does, the probe matches, the run reports it as safe, and the operator reads
    a green run as a tested boundary. ``veridor coverage`` has always known
    this -- ``classify_expectation`` returns ``permissive`` and the diagnostic
    says so in as many words -- but that classifier only ran behind
    ``--openapi``, so the default ``veridor run`` path never surfaced it.

    Reused rather than reimplemented so the run and the coverage report can
    never disagree about what counts as an assertion. Deliberately NOT a
    finding: emitting one would change the exit code of configurations that
    already exist, which the compatibility promise forbids. It is a disclosure
    attached to the pass, which is where the over-reading happens.
    """
    flagged: list[dict[str, Any]] = []
    for check in config["checks"]:
        for identity, expectation in check["expect"].items():
            statuses = expectation.get("status")
            if not isinstance(statuses, list):
                continue
            if classify_expectation(statuses) != "permissive":
                continue
            flagged.append(
                {
                    "check_id": check["id"],
                    "identity": identity,
                    "statuses": list(statuses),
                    "classification": "permissive",
                    "statement": (
                        f"expectation {list(statuses)} for identity {quoted(identity)} on "
                        f"check {quoted(check['id'])} accepts both access and denial, so "
                        "it asserts nothing about the boundary; it matches "
                        "whatever the target does"
                    ),
                }
            )
    return flagged


#: The marker ``blastradius.promotion_stub`` opens every stub name with.
#: Duplicated here rather than imported: ``core`` is the base module and must
#: not depend on a projection built on top of it. A test runs a real stub
#: through this matcher, so the two spellings cannot drift apart.
#:
#: Anchored, and a word on its own: a partially edited stub that still opens
#: "TODO -- decide this" is unreviewed and must be flagged, while a check
#: legitimately named "Today's boundary" is not.
_PROMOTION_STUB_NAME = re.compile(r"^TODO\b", re.IGNORECASE)


def _unreviewed_promotion_stubs(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Every check still carrying the name ``--promote`` wrote for it.

    ``map`` is scrupulous that a candidate is a hypothesis and not a finding.
    ``--promote`` then writes a paste-ready check per candidate whose ``name``
    is a ``TODO`` precisely because what the boundary IS remains the operator's
    decision. Paste one in unedited and ``run`` grades it like any other
    declaration: an ``error``-level SARIF result at evidence grade
    ``confirmed``, the strongest thing this tool emits.

    That much is defensible -- ``run`` cannot audit a declaration and never
    claims to. What was not defensible is that the ONLY residual trace of "no
    human ever agreed to this assertion" was the ``TODO:`` name, and the name
    reached neither the console nor the SARIF. It appeared 14 times in
    ``latest.json`` and zero times in both places a human or a code-scanning UI
    actually reads. The laundering was not the grading; it was the silence.

    Deliberately a disclosure and not a finding, and deliberately not a
    refusal: an unreviewed declaration is a process fact, and turning it into
    an exit code would fail builds that already exist. It rides next to the
    verdict instead, which is where the over-reading happens.
    """
    flagged: list[dict[str, Any]] = []
    for check in config["checks"]:
        name = check.get("name")
        if not isinstance(name, str) or not _PROMOTION_STUB_NAME.match(name.strip()):
            continue
        flagged.append(
            {
                "check_id": check["id"],
                "name": name,
                "statement": (
                    f"check {quoted(check['id'])} is still named {quoted(name)}. That is the "
                    "name `veridor map --promote` writes into a stub, so this "
                    "declaration was machine-generated from a candidate and has "
                    "not been reviewed. A candidate is a hypothesis; the "
                    "assertion below is graded as if you had written it"
                ),
            }
        )
    return flagged


def _config_line_index(raw: str) -> dict[tuple, int]:
    """Map every JSON path in ``raw`` to the 1-based line its value starts on.

    One forward pass over the characters, tracking string boundaries and
    container nesting. A text search for the check's id cannot do this: an
    ``"id"`` key inside a request body is indistinguishable from a check's own
    id, and anchoring a finding to the WRONG declaration is worse than anchoring
    every finding to line 1. Later keys overwrite earlier ones, so a duplicate
    object key resolves the way ``json.loads`` resolves it -- last wins.
    """
    from bisect import bisect_right  # noqa: PLC0415

    starts = [0]
    for offset, char in enumerate(raw):
        if char == "\n":
            starts.append(offset + 1)

    index: dict[tuple, int] = {}
    stack: list[list] = []
    pending_key: str | None = None
    position = 0
    length = len(raw)

    def child_path() -> tuple:
        if not stack:
            return ()
        kind, base, counter = stack[-1]
        if kind == "arr":
            return (*base, counter)
        return (*base, pending_key) if pending_key is not None else ()

    def consume() -> None:
        nonlocal pending_key
        if stack and stack[-1][0] == "arr":
            stack[-1][2] += 1
        pending_key = None

    def record(offset: int) -> None:
        path = child_path()
        if path:
            index[path] = bisect_right(starts, offset)

    while position < length:
        char = raw[position]
        if char in " \t\r\n,:":
            position += 1
            continue
        if char == '"':
            end = position + 1
            while end < length:
                if raw[end] == "\\":
                    end += 2
                    continue
                if raw[end] == '"':
                    end += 1
                    break
                end += 1
            if stack and stack[-1][0] == "obj" and pending_key is None:
                pending_key = json.loads(raw[position:end])
                position = end
                continue
            record(position)
            consume()
            position = end
            continue
        if char in "{[":
            record(position)
            path = child_path()
            consume()
            stack.append(["obj" if char == "{" else "arr", path, 0])
            position += 1
            continue
        if char in "}]":
            if stack:
                stack.pop()
            pending_key = None
            position += 1
            continue
        end = position
        while end < length and raw[end] not in " \t\r\n,]}":
            end += 1
        record(position)
        consume()
        position = end
    return index


def _annotate_finding_lines(
    findings: list[dict[str, Any]], config_path: Path, config: dict[str, Any]
) -> None:
    """Anchor each finding to the line of the declaration it graded.

    Every SARIF result pointed at ``veridor.json:1``, so eight findings landed
    on the opening brace and code scanning had nothing to sort by. The
    fingerprints were distinct, which is why dedup worked and triage did not.

    Indexed by POSITION in the checks/sequences list rather than by matching id
    text, so a ``${ENV_VAR}`` inside an id -- which ``load_config`` has already
    expanded and the file on disk has not -- cannot mislocate anything. Best
    effort and purely additive: a finding whose declaration cannot be located
    keeps no ``location_line``, and ``to_sarif`` falls back to line 1.
    """
    try:
        _annotate_finding_lines_unguarded(findings, config_path, config)
    except Exception:  # noqa: BLE001
        # One handler over the whole body, deliberately broad. This runs AFTER
        # every probe has been issued -- the run is already paid for -- and its
        # entire product is a cosmetic line number whose absence is already the
        # tested fallback. A config that is a list, a cell that is not a dict, a
        # surrogate in the file: three ways this raised something `main` does
        # not catch, turning a finished run into a traceback and exit 1.
        return


def _annotate_finding_lines_unguarded(
    findings: list[dict[str, Any]], config_path: Path, config: dict[str, Any]
) -> None:
    """The body of :func:`_annotate_finding_lines`. Never call this directly."""
    raw = config_path.read_text(encoding="utf-8")
    on_disk = json.loads(raw)
    if not isinstance(on_disk, dict):
        return
    # A positional anchor is only valid against the text ``load_config`` parsed,
    # and this re-read happens after every probe has been issued -- a window as
    # long as the run. An insert or delete inside that window shifts every
    # position after it, which anchors a finding to a NEIGHBOURING declaration:
    # precisely the outcome the scanner above refuses to risk.
    for key in ("checks", "sequences"):
        on_disk_list = on_disk.get(key) or ()
        loaded = config.get(key) or ()
        if not isinstance(on_disk_list, (list, tuple)) or len(on_disk_list) != len(loaded):
            return
        # Length alone let an equal-count edit -- delete one check, add another
        # -- shift every line while the guard saw nothing, anchoring findings to
        # their neighbours. The id settles it where the id is a literal; an id
        # carrying `${ENV_VAR}` is expanded in memory and not on disk, which is
        # exactly why the index is positional, so those skip the assertion.
        for position, entry in enumerate(on_disk_list):
            raw_id = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(raw_id, str) or "${" in raw_id:
                continue
            if raw_id != (loaded[position] or {}).get("id"):
                return
    index = _config_line_index(raw)
    checks = {
        check.get("id"): position
        for position, check in enumerate(config.get("checks") or ())
    }
    sequences = {
        sequence.get("id"): position
        for position, sequence in enumerate(config.get("sequences") or ())
    }
    for finding in findings:
        check_id = finding.get("check_id")
        identity = finding.get("identity")
        line = None
        if check_id in checks:
            position = checks[check_id]
            line = index.get(("checks", position, "expect", identity)) or index.get(
                ("checks", position)
            )
        elif check_id in sequences:
            position = sequences[check_id]
            step = finding.get("step_index")
            if isinstance(step, int) and not isinstance(step, bool):
                line = index.get(("sequences", position, "steps", step))
            line = line or index.get(("sequences", position))
        if isinstance(line, int) and line > 0:
            finding["location_line"] = line


#: Seconds between the TCP connects ``--wait-for-target`` makes.
WAIT_FOR_TARGET_INTERVAL: float = 1.0


def target_address(base_url: str) -> tuple[str, int]:
    """``(host, port)`` of an http(s) base URL; the port defaults from the scheme."""
    parts = urlsplit(base_url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.hostname or "", port


def wait_for_target(
    base_url: str,
    seconds: int,
    *,
    connect: Callable[..., Any] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Wait until the target accepts a plain TCP connection, for at most ``seconds``.

    Motivated by a measured race: in the Argo CD PostSync end-to-end run the
    gate Job was created in the same second its new target pod turned Ready,
    three probes got ECONNREFUSED, and the gate exited 3 (1 run in 4). One
    connect every :data:`WAIT_FOR_TARGET_INTERVAL` seconds until one succeeds or
    the time is up; the connection is closed at once and nothing is sent on it.

    It never changes a verdict: when the target never accepts, the run goes
    ahead anyway and each probe records its own transport error, which is what
    the gate already knows how to read. An accepted connection says a port is
    open, not that the service behind it is ready; the probes decide that.

    Prints one stderr line either way and returns the record the run document
    carries as ``target_wait``. ``connect`` is looked up at call time so the
    test tiers' network guard sees it.
    """
    host, port = target_address(base_url)
    connect = connect or socket.create_connection
    started = clock()
    deadline = started + seconds
    attempts = 0
    last_error: str | None = None
    accepted = False
    while True:
        attempt_started = clock()
        attempts += 1
        try:
            timeout = max(0.1, min(WAIT_FOR_TARGET_INTERVAL, deadline - attempt_started))
            with connect((host, port), timeout=timeout):
                accepted = True
        except OSError as error:
            last_error = _safe_error(error)
        if accepted:
            break
        now = clock()
        if now >= deadline:
            break
        sleep(max(0.0, min(attempt_started + WAIT_FOR_TARGET_INTERVAL, deadline) - now))
    elapsed = round(clock() - started, 1)
    address = f"{host}:{port}"
    # The check connects straight to the target; the requests may not. Behind a
    # proxy a name only the proxy resolves waited the whole time, "nodename nor
    # servname", and the run then succeeded through the proxy (measured), with
    # nothing saying the two took different paths.
    route = proxy_route(base_url)
    path = (
        f" That check connects directly; the requests go through the proxy "
        f"{route.address} named by {route.variable}, which it does not test."
        if route is not None
        else ""
    )
    if accepted:
        print(
            f"veridor: target {address} accepted a connection after {elapsed:g}s "
            f"(--wait-for-target {seconds}, {attempts} attempt(s)).{path}",
            file=sys.stderr,
        )
    else:
        print(
            f"veridor: target {address} did not accept a connection within "
            f"{seconds}s (--wait-for-target, {attempts} attempt(s); last: "
            f"{last_error}); running anyway, probes will record their own "
            f"transport errors.{path}",
            file=sys.stderr,
        )
    return {
        "requested_seconds": seconds,
        "address": address,
        "accepted": accepted,
        "elapsed_seconds": elapsed,
        "attempts": attempts,
        **({} if accepted else {"last_error": last_error}),
    }


def execute_run(
    config_path: Path,
    *,
    output_dir: Path,
    baseline_path: Path | None = None,
    base_url: str | None = None,
    read_only: bool = False,
    prove_liveness: bool = True,
    wait_for_target_seconds: int = 0,
    announce_proxy_route: bool = True,
    extra_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    """Execute all configured identity probes and persist a run document.

    ``wait_for_target_seconds`` > 0 waits for the target to accept a TCP
    connection before the first request (:func:`wait_for_target`), after the
    disclosures above it are printed. Recorded as ``target_wait``; never a
    finding and never an input to the gate.

    ``announce_proxy_route`` prints :func:`proxy_notice` with the other
    disclosures; ``verify`` turns it off because its own banner says it.

    ``extra_paths`` (``run --json``) get the same bytes as the managed history,
    from the same serialization: :func:`persist_run`.
    """
    # `run` sends every declared path verbatim, so an unsubstituted `{id}` is
    # refused here rather than reported 100 times as an authorization finding.
    config = load_config(
        config_path, base_url, read_only=read_only, require_concrete_paths=True
    )
    baseline = _load_baseline(baseline_path)
    started_at = datetime.now(UTC)
    # Minted once per run so an operator reading their access log sees one
    # Veridor run rather than a credential-stuffing pattern.
    sham_token = f"veridor-sham-{generate_marker()}"
    run_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
    probes: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    mutating = _mutating_disclosure_surface(config)
    if mutating:
        # Printed once, before the first request, because a run that writes to
        # the target is a categorically different thing from a run that reads.
        print(
            "veridor: write mode -- up to "
            f"{sum(fan_out for _, _, _, fan_out in mutating)} mutating request(s) "
            f"({terminal_names(sorted({verb for verb, _, _, _ in mutating}))}) will be "
            f"issued against {urlsplit(config['target']['base_url']).hostname}. "
            "Do not run this against production. Pass --read-only to refuse "
            "instead, before anything is sent.",
            file=sys.stderr,
        )

    # Disclosed before the first request, like the write-mode banner above and
    # for the same reason: this is the one place `run` issues something the
    # operator did not declare. Stated whether it is on or off, because "we did
    # not check" is as load-bearing as "we did", and an operator who turned it
    # off should be reminded on the run where it would have mattered.
    _liveness_reasons = plan_liveness_reasons(config)
    _planned_liveness = list(_liveness_reasons)
    _unsafe_liveness = plan_unsafe_liveness(config)
    # Counted from the plan, the banner announced shams that
    # _execute_liveness_controls then never sent, because no identity declared
    # a header to shape one on. Only the denial-only requests are listed: a
    # request planned to prove a 2xx live carries no denial to leave unproven.
    _unshaped_liveness = (
        [key for key, reasons in _liveness_reasons.items() if "denial_only" in reasons]
        if not _sham_header_names(config)
        else []
    )
    _proof_only = sum(
        reasons == {"proves_live"} for reasons in _liveness_reasons.values()
    )
    _marker_only = sum(
        "excludes_marker" in reasons and "denial_only" not in reasons
        for reasons in _liveness_reasons.values()
    )
    if _unshaped_liveness and prove_liveness:
        print(
            f"veridor: liveness controls -- {len(_unshaped_liveness)} request(s) "
            "accept only denial statuses "
            f"({_named_requests(_unshaped_liveness)}), but no identity declares a credential "
            "header to shape a fabricated credential on (any header but a "
            "standard one such as Accept, one that two or more identities send "
            "with the same value under a non-credential name, or a tenant or "
            "other context header declared beside another credential), so "
            "none is sent. A denial there "
            f"{_UNPROVEN_WHEN}.",
            file=sys.stderr,
        )
    elif _planned_liveness and prove_liveness:
        print(
            f"veridor: liveness controls -- {len(_planned_liveness)} extra "
            "request(s) carrying a credential Veridor fabricated, one per GET, "
            "HEAD or OPTIONS request whose declaration accepts only denial "
            "statuses"
            + (
                f", or ({_marker_only} of them) excludes an owner's marker, to "
                "check that the marker is unique to its owner"
                if _marker_only
                else ""
            )
            + (
                f", or ({_proof_only} of them) serves an identity whose "
                "credential a 2xx must prove live: a 2xx proves it only where "
                "the fabricated credential is refused"
                if _proof_only
                else ""
            )
            + ". Without them an expired token reads as a boundary that "
            "held. A denial the fabricated credential's answer does not tell "
            f"apart {_UNPROVEN_WHEN}. The value authenticates to nothing; pass "
            "--no-prove-liveness to skip them.",
            file=sys.stderr,
        )
    _sequence_liveness = plan_sequence_liveness(config)
    if _sequence_liveness and prove_liveness:
        print(
            f"veridor: liveness controls -- {len(_sequence_liveness)} sequence "
            "assert step(s) accept only denial statuses ("
            + _named_requests(
                (method, path) for _, _, method, path, _ in _sequence_liveness
            )
            + "), and Veridor sends no "
            "credential it fabricated inside a sequence. A denial there counts "
            "as unproven when the identity presents a static credential header, "
            "some identity was served in the same sequence, and nothing else in "
            f"this run proves the identity live ({_PROOF_OF_LIFE}).",
            file=sys.stderr,
        )
    if _unsafe_liveness and prove_liveness:
        verbs = terminal_names(sorted({method for method, _ in _unsafe_liveness}))
        print(
            f"veridor: liveness controls -- {len(_unsafe_liveness)} {verbs} "
            "request(s) accept only denial statuses "
            f"({_named_requests(_unsafe_liveness)}), and Veridor never sends a "
            "credential it fabricated with a method that can change state. A "
            f"denial there {_UNPROVEN_WHEN}.",
            file=sys.stderr,
        )
    _denial_requests = sorted(
        [key for key, reasons in _liveness_reasons.items() if "denial_only" in reasons]
        + _unsafe_liveness
    ) + [(method, path) for _, _, method, path, _ in _sequence_liveness]
    if _denial_requests and not prove_liveness:
        print(
            f"veridor: liveness controls SKIPPED (--no-prove-liveness). "
            f"{len(_denial_requests)} expectation-bearing request(s) accept "
            f"only denial statuses ({_named_requests(_denial_requests)}), so "
            "each of them is satisfied by a boundary "
            "that refused this identity AND by a credential that expired. This "
            "run cannot tell those apart.",
            file=sys.stderr,
        )

    # Where the requests physically go, when that is not the target itself.
    if announce_proxy_route:
        announce_proxy(config["target"]["base_url"])

    # Before the first request of any kind -- a session login is one.
    target_wait = (
        wait_for_target(config["target"]["base_url"], wait_for_target_seconds)
        if wait_for_target_seconds
        else None
    )

    # Sessions are established BEFORE the marker controls, in each identity's
    # own jar, because a marker probe against a cookie-authenticated target
    # cannot work without one.
    sessions: dict[str, Any] = {}
    if any(
        isinstance(identity, dict) and isinstance(identity.get("session"), dict)
        for identity in config["identities"].values()
    ):
        from veridor import sequence as sequence_engine

        sessions = sequence_engine.establish_sessions(config)

    def session_failures() -> dict[str, str]:
        return {
            name: state.reason or "not_established"
            for name, state in sessions.items()
            if state.state != "established"
        }

    def session_codes() -> dict[str, str | None]:
        return {
            name: getattr(state, "reason_code", None)
            for name, state in sessions.items()
            if state.state != "established"
        }

    def session_transient() -> dict[str, bool]:
        return {
            name: bool(getattr(state, "transient", True))
            for name, state in sessions.items()
            if state.state != "established"
        }

    # Controls run first and once: an exclusion asserted by any check may
    # depend on any identity's marker being live, and re-probing per check
    # would multiply cost without adding information.
    marker_controls = _execute_marker_controls(config, sessions)
    # A credential the target cannot possibly recognise, probed once per
    # request that carries a denial-only expectation. See _liveness_unproven.
    liveness_controls = (
        _execute_liveness_controls(config, sham_token) if prove_liveness else None
    )
    # Identities whose credential the run can already prove live, from a
    # marker_probe control that came back with the marker. Extended below with
    # every identity the target serves a 2xx anywhere in the run, because that
    # is equally good proof and costs nothing.
    live_credentials: set[str] = {
        name
        for name, control in marker_controls.items()
        if control.get("state") == "verified"
    }
    #: Identities that send something a target could accept or reject. An
    #: anonymous identity is not one, and a 401 it draws everywhere is the
    #: boundary working rather than a token that expired.
    #: The same classifier the sham planner and `blastradius` use: a session,
    #: or any header that is not a standard non-credential request header. It
    #: counted every declared header, so an anonymous identity sending only
    #: `Accept` was listed unproven, and exited 3 under require-complete.
    credentialed: set[str] = {
        name
        for name, identity in config["identities"].items()
        if isinstance(identity, Mapping) and presents_credential(identity)
    }
    liveness_unproven: list[dict[str, Any]] = []
    disclosures: list[dict[str, Any]] = []

    for check in config["checks"]:
        for state in sessions.values():
            state.reestablish_for_check()
        unusable = session_failures()
        # All probes of a check run before it is graded, because an exclusion
        # grade depends on the control probe of the same check.
        check_probes: dict[str, dict[str, Any]] = {}
        for identity_name, expectation in check["expect"].items():
            if identity_name in unusable:
                continue
            probe = _execute_probe(
                config["target"]["base_url"],
                float(config["target"].get("timeout_seconds", 10)),
                check,
                identity_name,
                config["identities"][identity_name],
                marker=_probe_marker(config, check, identity_name, expectation),
                session=sessions.get(identity_name),
            )
            probes.append(probe)
            check_probes[identity_name] = probe
        findings.extend(
            _grade_check(
                check,
                check_probes,
                config_path,
                marker_controls,
                disclosures=disclosures,
                session_failures=unusable,
                session_codes=session_codes(),
                session_transient=session_transient(),
                target=config.get("target", {}),
                liveness=liveness_controls,
                live_credentials=live_credentials,
                credentialed=credentialed,
                liveness_unproven=liveness_unproven,
            )
        )


    # Sequences run LAST. A sequence's teardown can delete an object a check
    # depends on, so running every check first preserves today's behaviour for a
    # mixed config: the checks see the same pre-run state they see now.
    sequence_records: list[dict[str, Any]] = []
    sequence_counters: dict[str, int] = {}
    # 'safe' means "a PROBE matched its declaration", so it is computed against
    # the check findings only. Frozen here, before any step finding is appended,
    # which stops a sequence-only config reporting a negative count.
    #
    # And only against findings about a probe that was SENT. An identity whose
    # session never established gets an EXEC-001 finding and no probe, so
    # subtracting every check finding took that finding out of a count it was
    # never part of: every login answered 503 printed "-2/0 probes matched",
    # and one session down beside a matched probe printed "0/1". _grade_check
    # writes at most one finding per (check, identity), so counting the probes
    # with no finding is the old arithmetic wherever every finding had a probe,
    # and it cannot leave [0, len(probes)].
    graded_keys = {
        (finding.get("check_id"), finding.get("identity")) for finding in findings
    }
    matched_probes = sum(
        1
        for probe in probes
        if (probe.get("check_id"), probe.get("identity")) not in graded_keys
    )
    if config.get("sequences"):
        from veridor import sequence as sequence_engine

        sequence_records, sequence_findings, sequence_counters = (
            sequence_engine.execute_sequences(
                config, config_path, run_id, marker_controls, sessions
            )
        )
        findings.extend(sequence_findings)

    # Liveness is a RUN-level fact, and grading is per-check. An identity the
    # target serves on check A, on a request where a sham or an identity with
    # no credential was refused, holds a credential it recognises, which settles
    # the question for check B -- but check B was graded before check A's
    # probes existed in this loop's view, or after, depending on declaration
    # order. Rather than make the grade order significant, the claim is
    # withdrawn here, once, against every probe and every sequence step and
    # teardown request the run issued, and every marker_probe that verified.
    # After the sequences, because their denial-only assert steps are judged
    # by the same rule, and a step that served an identity beside a refusal
    # proves its credential as well as a check does.
    if liveness_controls is not None:
        liveness_unproven = liveness_unproven + _sequence_liveness_unproven(
            _sequence_liveness, sequence_records
        )
        proven_live = set(live_credentials) | _proven_live_by_service(
            config, probes, liveness_controls, sequence_records, credentialed
        )
        liveness_unproven = [
            entry
            for entry in liveness_unproven
            if entry["identity"] not in proven_live
        ]

    # After the sequence findings are appended, so step findings are annotated
    # too, and before the diff, which never reads this key.
    _annotate_finding_lines(findings, config_path, config)

    regression = _compare_findings(findings, baseline)
    sham_served = _served_sham_disclosures(config, liveness_controls)
    uniqueness_unchecked = _marker_uniqueness_not_checked(
        config, liveness_controls, prove_liveness
    )
    non_asserting = _non_asserting_expectations(config)
    injection_disclosures = _injection_disclosures(
        probes, sequence_records, marker_controls.values()
    )
    unreviewed_stubs = _unreviewed_promotion_stubs(config)
    # No cookie value, no capture value, and no request header at any depth;
    # see IdentitySession.report, which builds the recordable half only.
    session_reports = [state.report() for state in sessions.values()]
    sessions_failed = sum(
        report["state"] != "established" for report in session_reports
    )
    teardown_skipped = sum(
        entry["state"].startswith("skipped")
        for record in sequence_records
        for entry in record.get("teardown") or ()
    )
    # Every mutating request this run actually put on the wire, counted over
    # the same surfaces _mutating_disclosure_surface declares -- checks, marker
    # controls and sequences -- so `verbs` and `requests_issued` describe one
    # set. Logins are excluded from both, for the reason given there.
    mutation_issued = (
        _issued_mutating(probes)
        + _issued_mutating(marker_controls.values())
        + sum(
            1
            for record in sequence_records
            for entry in (record["steps"] + list(record.get("teardown") or ()))
            if entry.get("request", {}).get("method") not in SAFE_METHODS
            and entry.get("state") not in {"skipped", "skipped_unresolved",
                                           "skipped_session_unavailable"}
        )
    )
    vulnerable = sum(finding["verdict"] == "vulnerable" for finding in findings)
    inconclusive = sum(finding["verdict"] == "inconclusive" for finding in findings)
    unexpected_denial = sum(
        finding["verdict"] == "unexpected_denial" for finding in findings
    )
    grades = Counter(
        finding.get("evidence_grade", "ungraded") for finding in findings
    )
    result = {
        "schema_version": (
            SEQUENCE_SCHEMA_VERSION if sequence_records else SCHEMA_VERSION
        ),
        "run_id": run_id,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "target": _safe_url(config["target"]["base_url"]),
        "config": str(config_path),
        # THREE values, not two. `"passed" if not findings else "failed"`
        # counted an `inconclusive` -- a probe the target never answered -- as
        # a failure, so a run could exit 0 while its own artifact said "failed"
        # and the viewer rendered a red FAILED badge. A build CI called green
        # showed red to a human reading the same document.
        #
        # This still cannot mean "the exit code", because the exit code depends
        # on --fail-on and this module does not know it. It means what it can
        # honestly mean: did anything get found ABOUT THE TARGET, and if not,
        # did anything go ungraded. Same three words the verdicts use; see
        # run_status for what `inconclusive` does and does not say.
        "status": run_status(findings),
        # Purely additive and near the top of the document on purpose: a
        # consumer that reads 'summary' should not have to go looking for the
        # limit that qualifies it. Nothing keys off this block and nothing in
        # it reaches a fingerprint.
        "interpretation": _interpretation(
            str(config_path), has_sequences=bool(sequence_records)
        ),
        "summary": {
            "checks": len(config["checks"]),
            "probes": len(probes),
            # Step requests are deliberately NOT probes and are NOT counted
            # here. 'safe' is the probes with no finding; a three-step sequence
            # with zero findings would add 3 to a number whose meaning is "a
            # probe matched its declaration". The precedent is marker_controls,
            # a sibling of probes for exactly this reason.
            "safe": matched_probes,
            "vulnerable": vulnerable,
            "unexpected_denial": unexpected_denial,
            "inconclusive": inconclusive,
            # Two disclosure counters, both of which qualify a PASS rather than
            # a finding. They exist because the outcomes they describe emit no
            # finding at all and were therefore invisible in every human-facing
            # channel.
            "non_asserting": len(non_asserting),
            "probe_licensed_exclusions": len(disclosures),
            "confirmed": grades["confirmed"],
            "suspected": grades["suspected"],
            "ungraded": grades["ungraded"],
            "new": len(regression["new"]),
            "resolved": len(regression["resolved"]),
            "unchanged": len(regression["unchanged"]),
            "escalated": len(regression["escalated"]),
            # Present only when the config declares sequences, so a config
            # without them produces the summary object it produced before.
            **sequence_counters,
            # Added only when non-zero, for the same reason. A cleanup counter
            # is never a verdict input: it is reported beside the verdict and
            # feeds no exit code unless --require-clean-teardown asks for it.
            **({"sessions_failed": sessions_failed} if sessions_failed else {}),
            **({"teardown_skipped": teardown_skipped} if teardown_skipped else {}),
        },
        "findings": findings,
        # What was issued beyond the declaration, and why. Never silent: an
        # extra request to somebody's target is disclosed in the artifact as
        # well as on the console.
        "liveness": {
            "enabled": prove_liveness,
            "requests_issued": len(liveness_controls or {}),
            # _safe_url, as every other stored URL: this field kept the raw
            # path, so a query value every probe URL redacted was written here
            # in full.
            # A control whose own request failed carries its error, so a
            # denial left unproven by it can be traced to why.
            "requests": [
                {
                    "method": method,
                    "path": _safe_url(path),
                    **(
                        {"error": str(control["error"])}
                        if control.get("error")
                        else {}
                    ),
                }
                for (method, path), control in sorted(
                    (liveness_controls or {}).items()
                )
            ],
            "sham_token_prefix": "veridor-sham-",
            # Denial-only requests no sham was sent to, and why: the method
            # can change state, or no identity declares a credential header to shape one
            # on. Their denials are judged unproven without one. Omitted when
            # there are none, so such a document is unchanged.
            **(
                {
                    "requests_not_probed": [
                        {"method": method, "path": _safe_url(path), "reason": reason}
                        for method, path, reason in sorted(
                            [(m, p, "unsafe_method") for m, p in _unsafe_liveness]
                            + [(m, p, "no_credential_header")
                               for m, p in _unshaped_liveness]
                        )
                    ]
                    # One per denial-only assert step, by the sequence that
                    # declares it; the path is the declared template, never a
                    # captured value.
                    + [
                        {"method": method, "path": _safe_url(path),
                         "reason": "sequence_step", "sequence_id": sequence_id,
                         "step_index": index}
                        for sequence_id, index, method, path, _ in _sequence_liveness
                    ]
                }
                if prove_liveness
                and (_unsafe_liveness or _unshaped_liveness or _sequence_liveness)
                else {}
            ),
            # Requests carrying an excludes_marker expectation whose marker no
            # fabricated credential was scanned for, and why: a marker that
            # crosses there is graded on the operator's premise that it is
            # the owner's alone. Omitted when there are none.
            **(
                {"marker_uniqueness_not_checked": uniqueness_unchecked}
                if uniqueness_unchecked
                else {}
            ),
            # Expectations satisfied by a denial that a credential nobody
            # issued received too. Facts about the DECLARATION, not findings
            # about the target: they change an exit code only under
            # --require-complete.
            "unproven": liveness_unproven,
        },
        "regression": regression,
        "probes": probes,
        # Deliberately a sibling of 'probes', not a member of it. A control is
        # not a check: it asserts nothing about authorization, it cannot pass
        # or fail, and folding it into 'probes' would inflate summary.probes
        # and summary.safe with requests that were never graded. Absent from
        # the document entirely when no identity configures a marker_probe, so
        # v1 and v2 readers see byte-identical output for existing configs.
        **({"marker_controls": list(marker_controls.values())} if marker_controls else {}),
        # Both omitted entirely when empty, so a suite that declares neither a
        # marker_probe nor a permissive expectation produces the same document
        # it produced before.
        # The marker_probe licences above, and every request whose
        # fabricated-credential control the target SERVED: a target that
        # accepts a credential nobody issued is said out loud, never only
        # inferred from a grade. probe_licensed_exclusions still counts the
        # licences alone.
        **(
            {"oracle_disclosures": disclosures + sham_served}
            if disclosures or sham_served
            else {}
        ),
        **({"non_asserting_expectations": non_asserting} if non_asserting else {}),
        # One entry per check probe that went out without a declared inject
        # field its body could not carry. Omitted when empty, so a suite that
        # carries every field produces the document it produced before.
        **(
            {"injection_disclosures": injection_disclosures}
            if injection_disclosures
            else {}
        ),
        # Omitted entirely when no check still carries a --promote stub name, so
        # a hand-written suite produces the document it produced before.
        **(
            {"unreviewed_promotion_stubs": unreviewed_stubs} if unreviewed_stubs else {}
        ),
        # Also a sibling of 'probes', for the same reason marker_controls is,
        # and omitted entirely when the config declares no sequences. No field
        # in this block, at any depth, holds a captured value or a response
        # byte: every step URL is the config template, tokens intact.
        **({"sequences": sequence_records} if sequence_records else {}),
        # Omitted entirely when no identity declares a session, exactly as
        # marker_controls is. Holds cookie NAMES and capture STATES; never a
        # cookie value, a captured value, or a request header.
        **({"sessions": session_reports} if session_reports else {}),
        # Present only with --wait-for-target. A wait is never a finding and
        # nothing in veridor.gate reads it: it records how long the run held
        # its first request back, and whether the port ever opened.
        **({"target_wait": target_wait} if target_wait else {}),
        # The artifact states whether this run wrote to the target. Present
        # whenever the configuration can issue a mutating request from ANY
        # surface -- check, marker control, sequence step or teardown -- so a
        # configuration whose only writes are ordinary checks can no longer
        # produce an artifact that denies them. Absent for a genuinely
        # read-only configuration, which is what makes its absence mean
        # something.
        **(
            {
                "mutation": {
                    "verbs": sorted({verb for verb, _, _, _ in mutating}),
                    "requests_issued": mutation_issued,
                }
            }
            if mutating
            else {}
        ),
    }
    persist_run(result, output_dir, extra_paths=extra_paths)
    return result


def persist_run(
    result: Mapping[str, Any], output_dir: Path, *, extra_paths: Sequence[Path] = ()
) -> None:
    """Write ``result`` to the managed history: ``runs/<run_id>.json`` and
    ``latest.json``, then to ``extra_paths``, in that order, from one
    serialization. ``veridor run`` calls it again once the gate is decided."""
    runs_dir = output_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    write_json_many(
        (runs_dir / f"{result['run_id']}.json", output_dir / "latest.json", *extra_paths),
        result,
    )


def write_json(path: Path, value: Any) -> None:
    """Write ``value`` atomically, every expanded ``${NAME}`` value put back.

    Every JSON file Veridor writes goes through here or through
    :func:`write_json_many`: run documents and their history copies, matrices,
    drift, blast radius, coverage, badges, mutation reports. Scrubbed as a
    structure, before ``json.dumps``, so JSON escaping cannot hide a value from
    :func:`veridor.redaction.scrub`.
    """
    write_json_many((path,), value)


def write_json_many(paths: Sequence[Path], value: Any) -> None:
    """:func:`write_json` to each of ``paths``, in order, serializing once.

    The run document went to three files per write -- ``runs/<id>.json``,
    ``latest.json``, ``--json`` -- and was scrubbed and re-encoded for each:
    six ``json.dumps(indent=2)`` per ``run --json``, where before 3.13 an
    indented dump cannot use the C encoder. Serializing once per write makes
    a large ``run --json`` faster and smaller in memory (CHANGELOG.md,
    Unreleased, has the measurement). Every file still gets the same bytes,
    each written to a temporary file and renamed into place.
    """
    text = json.dumps(redaction.scrub(value), indent=2) + "\n"
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        try:
            temporary.write_text(text, encoding="utf-8", errors="strict")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def _vacuous_fingerprint(entry: Mapping[str, Any]) -> str:
    """A stable id for one non-asserting expectation.

    Same shape as a finding fingerprint so code scanning can track it across
    runs, and keyed on the same three things that identify the expectation:
    the check, the identity, and the fact that it is permissive. NOT the
    statuses -- narrowing `[200, 404]` to `[200, 403, 404]` is still the same
    unasserted boundary, and a fingerprint that moved would report it as
    resolved and reopened.
    """
    digest = hashlib.sha256(
        "\x1f".join(
            ("vacuous", str(entry["check_id"]), str(entry["identity"]))
        ).encode("utf-8")
    )
    return digest.hexdigest()[:20]


def _sarif_artifact_location(location: Any) -> dict[str, str]:
    """Where a SARIF result points: the config, relative to the source root.

    ``--config /abs/path/veridor.json`` used to be written into
    ``artifactLocation.uri`` verbatim. Code scanning resolves that against the
    repository, matches nothing, and the uploaded file publishes the runner's
    home directory and checkout layout to everyone who can read the alert.
    An absolute path is made relative to the working directory, where the
    workflow runs; one outside it is reduced to its file name, so a local path
    is never written. ``uriBaseId`` says what the relative uri is relative to.
    Fingerprints are untouched: no finding id reads the location.
    """
    text = str(location or "")
    if not text:
        return {"uri": ""}
    path = Path(text)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(Path.cwd().resolve())
        except (OSError, ValueError):
            path = Path(path.name)
    return {"uri": posixpath.normpath(path.as_posix()), "uriBaseId": "%SRCROOT%"}


def _sarif_line(finding: Mapping[str, Any]) -> int:
    """The config line this finding graded, or 1 when it is not known.

    A run document written by an older build carries no ``location_line``, and
    ``veridor report`` must keep converting it. Line 1 is what those documents
    have always produced. Computed at RUN time rather than here, because
    `report --input run.json` may run on a machine where the config has moved.
    """
    line = finding.get("location_line")
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        return line
    return 1


#: GitHub code scanning reads ``properties.security-severity`` (a numeric
#: string, 0.0-10.0) from a rule to rank its alerts, and only for rules tagged
#: ``security``. Given ONLY to the rules whose results are findings about the
#: target. The rules that mean "nothing was measured" (EXEC, ORACLE, SEQ,
#: SESSION, CACHE) and the declaration note (VACUOUS) carry the tag and no
#: severity: a security severity on a probe that never ran would present an
#: unmeasured boundary as a rated weakness. None reaches 9.0 ("critical"):
#: every finding is graded against a declaration Veridor cannot audit.
SARIF_SECURITY_SEVERITY: dict[str, str] = {
    "VERIDOR-AUTHZ-001": "7.5",
    "VERIDOR-LEAK-001": "8.8",
    "VERIDOR-EFFECT-001": "8.8",
}

#: Tags every rule carries. ``security`` is what GitHub keys security alerts
#: on; ``authorization`` says which kind.
SARIF_RULE_TAGS: tuple[str, ...] = ("security", "authorization")

#: The prefix of ``runs[].automationDetails.id``. GitHub derives the analysis
#: CATEGORY from everything before the last ``/``, so ``veridor/<run_id>``
#: files every run under one stable category, ``veridor``, while the id stays
#: unique per run. A bare run id -- what this used to write -- has no ``/``.
SARIF_CATEGORY: str = "veridor"


def _sarif_rule_properties(rule_id: str) -> dict[str, Any]:
    properties: dict[str, Any] = {"tags": list(SARIF_RULE_TAGS)}
    if rule_id in SARIF_SECURITY_SEVERITY:
        properties["security-severity"] = SARIF_SECURITY_SEVERITY[rule_id]
    return properties


def to_sarif(result: dict[str, Any]) -> dict[str, Any]:
    """Convert one Veridor run to SARIF 2.1.0."""
    # Read at call time, never bound at import: the SARIF must name the build
    # that wrote it. It said "0.1.0" as a literal, which stays true only until
    # the first release after it.
    import veridor  # noqa: PLC0415
    # Every rule string is scoped to the declaration. SARIF often outlives the
    # console output that produced it -- it lands in a code-scanning UI where
    # the reader never sees the run summary -- so the limit travels with the
    # rule, not only with the run.
    interpretation = result.get("interpretation") or _interpretation()
    # The same config path rides along in the interpretation block, so it gets
    # the same treatment as artifactLocation: the run document keeps what the
    # operator typed, the SARIF never carries a local absolute path.
    if interpretation.get("policy_source"):
        interpretation = {
            **interpretation,
            "policy_source": _sarif_artifact_location(
                interpretation["policy_source"]
            )["uri"],
        }
    rules = {
        "VERIDOR-AUTHZ-001": {
            "id": "VERIDOR-AUTHZ-001",
            "shortDescription": {"text": "Authorization expectation failed"},
            "fullDescription": {
                "text": (
                    "The HTTP status observed for this identity differed from "
                    "the status declared for it in the Veridor configuration. "
                    + DECLARATION_SCOPE
                ),
            },
            # One string, one source: the finding-level remediation and the
            # SARIF help for a rule must not diverge, or the code-scanning
            # consumer and the run-JSON consumer read different advice for the
            # identical finding.
            "help": {"text": _AUTHZ_REMEDIATION},
            "defaultConfiguration": {"level": "error"},
        },
        "VERIDOR-LEAK-001": {
            "id": "VERIDOR-LEAK-001",
            "shortDescription": {"text": "Cross-identity data flow observed"},
            "fullDescription": {
                "text": (
                    "The response served to one identity carried another "
                    "identity's marker. That is proof the string crossed, and "
                    "proof of data flow insofar as the marker is unique to that "
                    "identity's data; when a credential Veridor fabricated gets "
                    "the same marker back, it is not this rule: the finding is "
                    "VERIDOR-AUTHZ-001 suspected when the status also differed "
                    "from the declared one, and VERIDOR-ORACLE-001 inconclusive "
                    "when it did not. Whether "
                    "the flow is permitted is set by the excludes_marker "
                    "declaration in your configuration, which Veridor consumes "
                    "and cannot audit."
                ),
            },
            "help": {"text": _LEAK_REMEDIATION},
            "defaultConfiguration": {"level": "error"},
        },
        "VERIDOR-EXEC-001": {
            "id": "VERIDOR-EXEC-001",
            "shortDescription": {"text": "Authorization check was inconclusive"},
            "fullDescription": {
                "text": (
                    "The request could not be completed, so nothing was "
                    "measured for this identity. This is neither a pass nor a "
                    "failure of the declared expectation."
                ),
            },
            "help": {
                "text": (
                    "Confirm target reachability and retry the check. A finding "
                    "that says the request was not sent because the identity's "
                    "session injects a form_field or json_field is a "
                    "configuration problem instead: give the request a "
                    "form-encoded or JSON object body, or remove that field "
                    "from session.inject. So is one not sent because an "
                    "interpolated value carried a configured marker, a capture "
                    "would fill a credential header, or a ${capture.…} "
                    "reference had no value: the finding's remediation names "
                    "the fix."
                ),
            },
            "defaultConfiguration": {"level": "warning"},
        },
        "VERIDOR-ORACLE-001": {
            "id": "VERIDOR-ORACLE-001",
            "shortDescription": {"text": "Marker oracle could not be verified"},
            "fullDescription": {
                "text": (
                    "The marker was not observed where the configuration says "
                    "it should be, or it was observed beside the declared "
                    "status but a credential Veridor fabricated got it back "
                    "too, so it is not unique to its owner. Either way, "
                    "marker-based conclusions for this check carry no evidence."
                ),
            },
            "help": {"text": _ORACLE_REMEDIATION},
            "defaultConfiguration": {"level": "warning"},
        },
    }
    # Appended only when a result references them, so SARIF for an existing
    # config stays byte-identical. Help text mirrors the finding-level
    # remediation exactly -- one string, one source.
    optional_rules = {
        "VERIDOR-SEQ-001": {
            "id": "VERIDOR-SEQ-001",
            "shortDescription": {"text": "Sequence could not be completed"},
            "fullDescription": {
                "text": (
                    "A step the rest of the sequence depends on did not "
                    "complete as declared, so the later steps were not "
                    "executed and no conclusion about authorization was "
                    "reached. This is neither a pass nor a failure of the "
                    "declared expectations."
                ),
            },
            "help": {"text": _SEQUENCE_REMEDIATION},
            "defaultConfiguration": {"level": "warning"},
        },
        "VERIDOR-EFFECT-001": {
            "id": "VERIDOR-EFFECT-001",
            "shortDescription": {"text": "Write crossed a boundary"},
            "fullDescription": {
                "text": (
                    "An identity read back its own object after an earlier "
                    "step in the same sequence wrote to it as a different "
                    "identity, and the identity's own marker was no longer "
                    "there. That is proof of a data effect. Whether the "
                    "earlier identity may write to that object is set by your "
                    "configuration, which Veridor consumes and cannot audit."
                ),
            },
            "help": {"text": _EFFECT_REMEDIATION},
            "defaultConfiguration": {"level": "error"},
        },
        "VERIDOR-SESSION-001": {
            "id": "VERIDOR-SESSION-001",
            "shortDescription": {"text": "Session liveness unverified"},
            "fullDescription": {
                "text": (
                    "A logged-in identity's request drew an authentication "
                    "status. That is what a dead session looks like from the "
                    "runner's side, and a dead session turns the probe into an "
                    "anonymous request whose denial matches a declared denial. "
                    "Veridor cannot tell that apart from the target genuinely "
                    "refusing an authenticated caller, so it reaches no "
                    "conclusion rather than a pass."
                ),
            },
            "help": {"text": _SESSION_LIVENESS_REMEDIATION},
            "defaultConfiguration": {"level": "warning"},
        },
        "VERIDOR-CACHE-001": {
            "id": "VERIDOR-CACHE-001",
            "shortDescription": {"text": "Marker read from a cached response"},
            "fullDescription": {
                "text": (
                    "An intermediary announced that this response was served "
                    "from a cache, so what the marker scan saw is the state of "
                    "the object at some earlier time, not now. A cached copy "
                    "cannot settle whether an earlier write took effect."
                ),
            },
            "help": {"text": _CACHE_REMEDIATION},
            "defaultConfiguration": {"level": "warning"},
        },
    }
    sarif_results = []
    for finding in result["findings"]:
        location = finding["location"]
        marker = (finding.get("evidence") or {}).get("marker")
        if finding["rule_id"] in optional_rules:
            rules[finding["rule_id"]] = optional_rules[finding["rule_id"]]
        properties = {
            "checkId": finding["check_id"],
            # What the check CLAIMS, alongside what it is called. A `--promote`
            # stub says "TODO: describe the boundary you are asserting" here,
            # and that sentence reaching a code-scanning UI is the difference
            # between a reviewed assertion and a machine hypothesis presented
            # as one. Falls back to the id for a sequence finding, which has no
            # separate name.
            "checkName": finding.get("check_name") or finding["check_id"],
            "identity": finding["identity"],
            "verdict": finding["verdict"],
            "evidenceGrade": finding.get("evidence_grade", "ungraded"),
            "runId": result["run_id"],
        }
        if isinstance(finding.get("step_index"), int):
            properties["stepIndex"] = finding["step_index"]
        if isinstance(marker, dict):
            properties["markerState"] = marker.get("state")
        sarif_results.append(
            {
                "ruleId": finding["rule_id"],
                "level": finding["level"],
                "message": {"text": finding["message"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": _sarif_artifact_location(location),
                            "region": {"startLine": _sarif_line(finding)},
                        }
                    }
                ],
                "partialFingerprints": {
                    "veridorFindingId/v1": finding["id"],
                },
                "properties": properties,
            }
        )

    # Non-asserting expectations, as RESULTS rather than as a run-level
    # property. The console has always said this perfectly -- "1 expectation(s)
    # accept both access and denial, so they assert nothing about the boundary"
    # -- and the statement lived at runs[0].properties, which GitHub code
    # scanning does not surface. So in the CI setup this README recommends, a
    # check that asserts nothing was completely invisible.
    #
    # level "note", never "warning": this is a fact about the DECLARATION, not
    # a finding about the target, and code scanning renders warning and error
    # as things wrong with the code under test. The rule is appended only when
    # a result references it, so SARIF for a config with none stays
    # byte-identical.
    vacuous = result.get("non_asserting_expectations") or ()
    if vacuous:
        rules["VERIDOR-VACUOUS-001"] = {
            "id": "VERIDOR-VACUOUS-001",
            "shortDescription": {"text": "Expectation asserts nothing"},
            "fullDescription": {
                "text": (
                    "The declared statuses accept both access and denial, so "
                    "the probe matches whatever the target does. The check "
                    "passes unconditionally and its pass is not evidence that "
                    "the boundary holds."
                ),
            },
            "help": {
                "text": (
                    "Narrow the expectation to the statuses you actually "
                    "require -- the denial statuses for an identity that must "
                    "be refused, the success statuses for one that must be "
                    "served."
                ),
            },
            "defaultConfiguration": {"level": "note"},
        }
    for entry in vacuous:
        sarif_results.append(
            {
                "ruleId": "VERIDOR-VACUOUS-001",
                "level": "note",
                "message": {"text": entry["statement"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": _sarif_artifact_location(
                                result.get("config")
                            ),
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    "veridorFindingId/v1": _vacuous_fingerprint(entry),
                },
                "properties": {
                    "checkId": entry["check_id"],
                    "identity": entry["identity"],
                    "classification": entry["classification"],
                    "runId": result["run_id"],
                },
            }
        )
    return {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Veridor",
                        "informationUri": "https://github.com/Veridor-authz/veridor",
                        "semanticVersion": veridor.__version__,
                        "shortDescription": {
                            "text": (
                                "Authorization regression runner. Compares "
                                "observed behaviour against declared "
                                "expectations."
                            ),
                        },
                        "fullDescription": {"text": DECLARATION_SCOPE},
                        "rules": [
                            {**rule, "properties": _sarif_rule_properties(rule["id"])}
                            for rule in rules.values()
                        ],
                    }
                },
                "results": sarif_results,
                "automationDetails": {
                    "id": f"{SARIF_CATEGORY}/{result['run_id']}"
                },
                # A passing check emits no SARIF result, so anything that
                # qualifies a PASS has to ride on the run properties or it is
                # lost entirely to a code-scanning consumer.
                "properties": {
                    "interpretation": interpretation,
                    **(
                        {"oracleDisclosures": result["oracle_disclosures"]}
                        if result.get("oracle_disclosures")
                        else {}
                    ),
                    **(
                        {
                            "nonAssertingExpectations": result[
                                "non_asserting_expectations"
                            ]
                        }
                        if result.get("non_asserting_expectations")
                        else {}
                    ),
                    **(
                        {"injectionDisclosures": result["injection_disclosures"]}
                        if result.get("injection_disclosures")
                        else {}
                    ),
                    # The one qualification that attaches to a FAILING result
                    # rather than a passing one: these findings were graded
                    # against a declaration no human agreed to.
                    **(
                        {
                            "unreviewedPromotionStubs": result[
                                "unreviewed_promotion_stubs"
                            ]
                        }
                        if result.get("unreviewed_promotion_stubs")
                        else {}
                    ),
                },
            }
        ],
    }
