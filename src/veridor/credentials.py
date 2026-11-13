"""Which request headers carry a credential, and who presents one.

Shared by ``core`` and ``blastradius`` so the two cannot disagree. ``core``
must not import ``blastradius`` (it pulls in ``matrix``), so the list lives
here and ``blastradius`` re-exports it. Standard library only, imports nothing
from Veridor.
"""

from __future__ import annotations

from typing import Any, Mapping


#: Header names that are known NOT to carry a credential. This answers "could
#: the target have accepted or rejected something here", and it used to be
#: answered from the six names `core` treats as credentials -- so any other
#: authentication header read as no credential at all. A benign `Accept` or
#: `Origin` is not a credential, and counting it as one kept the M1 regression
#: alive for every anonymous identity that has to send one -- which is most of
#: them, and every browser or SPA client. This is the list that is closed, not
#: the credential one: a header outside it, and outside
#: :data:`BENIGN_HEADER_PREFIXES`, counts as a credential.
#:
#: Only standard request headers that never carry a credential belong here.
#: `X-CSRF-Token` and `X-Forwarded-For` do not: one is part of a session, the
#: other is what an IP allowlist reads.
BENIGN_HEADER_NAMES: frozenset[str] = frozenset(
    {
        # content negotiation and the body
        "accept", "content-type", "content-length", "content-encoding",
        "content-language",
        # caching and conditional requests (If-* is a prefix below)
        "cache-control", "pragma", "range",
        # the client and where the request came from
        "user-agent", "origin", "referer", "x-requested-with", "dnt",
        "upgrade-insecure-requests", "save-data", "priority",
        "sec-gpc", "sec-purpose",
        # connection management
        "host", "connection", "keep-alive", "te", "expect",
        # tracing and request correlation
        "traceparent", "tracestate", "x-request-id", "x-correlation-id",
        "request-id",
    }
)

#: Prefixes of standard request-header families that never carry a
#: credential: `Accept-*` (`Accept-Language`, `Accept-Encoding`), `If-*`
#: (`If-None-Match`, `If-Modified-Since`), and the browser's fetch-metadata
#: `Sec-Fetch-*` and client-hint `Sec-CH-*` families (`Sec-Fetch-Mode`,
#: `Sec-CH-UA`). Each ends at the hyphen, so a `Secret-Token` or an
#: `Accepted-Token` is not covered.
#:
#: `Sec-*` as a whole is NOT benign: `Sec-WebSocket-Protocol` carries a bearer
#: token to the Kubernetes API server
#: (`base64url.bearer.authorization.k8s.io.<token>`), so the WebSocket
#: handshake family stays a credential. The other benign `Sec-*` names are
#: listed one by one in :data:`BENIGN_HEADER_NAMES`.
BENIGN_HEADER_PREFIXES: tuple[str, ...] = ("accept-", "if-", "sec-fetch-", "sec-ch-")


def is_benign_header(name: Any) -> bool:
    """Is this a standard request header that never carries a credential?"""
    lowered = str(name).lower()
    return lowered in BENIGN_HEADER_NAMES or lowered.startswith(BENIGN_HEADER_PREFIXES)


def presents_credential(entry: Any) -> bool:
    """Does this identity declaration SEND anything the target could reject?

    Any static header counts except the standard request headers that
    :func:`is_benign_header` recognises -- this module does not know which header a
    target authenticates on, and guessing from a list of six names is how a
    GitLab `PRIVATE-TOKEN` was classified as no credential at all: a stale one
    was never suppressed, never warned about, and was inferred to be the
    unauthenticated identity. An identity declared with nothing but
    ``{"headers": {"Accept": ..., "Origin": ...}}`` presents no credential; the guide asks an
    anonymous identity to declare ``"headers": {}``, and that is the shape this
    reads.

    The one answer to "does this identity present a credential", for every
    module that asks: ``blastradius`` suppressing a stale token's row, and
    ``core`` deciding whose denial a liveness rule judges and which header
    names a fabricated credential is shaped on. ``Sec-WebSocket-Protocol``
    counts -- it carries a bearer token to the Kubernetes API server.

    A declaration of an unexpected shape counts as credentialed: a caller may
    hand this identities built elsewhere, and the conservative direction is the
    one that keeps today's suppression.
    """
    if not isinstance(entry, Mapping):
        return True
    if "session" in entry:
        return True
    headers = entry.get("headers") or {}
    if not isinstance(headers, Mapping):
        return True
    return not all(is_benign_header(name) for name in headers)
