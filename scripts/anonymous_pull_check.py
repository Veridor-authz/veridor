#!/usr/bin/env python3
"""A published image or chart must be readable by someone who is not logged in.

    python3 scripts/anonymous_pull_check.py REFERENCE@sha256:DIGEST [...]

Every default in deploy/ and ci/ pulls the image with no credential, and
SECURITY.md's `cosign verify` reads it the same way. Whether a registry serves a
package to anyone is a setting on the package, which no file here holds, and
every other check in release.yml runs after a login, so a release could go green
with every default returning `denied` to its users.

This holds no credential and asks the way a registry client does: an anonymous
token for that repository, then the manifest by digest. Nothing it reads is
printed, the token included.

Served means HTTP 200 with the manifest: a Docker-Content-Digest equal to the
digest asked for, or, without that header, a manifest media type. A 2xx that is
neither (an HTML page, an errors body, a 204) is not an answer about the
package, and neither is a redirect to another host, which is refused rather
than followed with the token.

Exit 0: every reference was served.
Exit 1: the registry refused one. The message says which setting to look at.
Exit 2: usage, or the registry could not be asked, which says nothing either way.
"""

from __future__ import annotations

import http.client
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

_REFERENCE = re.compile(r"^([a-z0-9.-]+(?::\d+)?)/([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})$")

#: What a registry needs to be told it may answer with: an image index, a single
#: image, or a chart, which is an OCI image manifest with its own config type.
_MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
_MANIFESTS = ", ".join(_MANIFEST_TYPES)

_TIMEOUT_SECONDS = 30


class CouldNotAsk(Exception):
    """The registry did not give an answer about the package."""


def _refused(error: urllib.error.HTTPError) -> bool:
    return error.code in (401, 403, 404)


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """urllib follows a redirect anywhere and keeps the Authorization header, so
    a manifest redirect to another host received the token and its answer
    counted as served (measured on loopback: exit 0, the other host saw it)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001,ANN201
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise CouldNotAsk(f"HTTP {code} redirect to another host, {new.netloc or newurl!r}; not followed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirects)


def _served(answer: object, digest: str) -> None:
    """Return when ``answer`` is the manifest asked for, else raise CouldNotAsk."""
    status = getattr(answer, "status", None)
    headers = getattr(answer, "headers", None) or {}
    served = headers.get("Docker-Content-Digest")
    media = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if status != 200:
        raise CouldNotAsk(f"HTTP {status} without a manifest")
    if served is not None and served.strip() != digest:
        raise CouldNotAsk("the registry answered with a different Docker-Content-Digest")
    if served is None and media not in _MANIFEST_TYPES:
        raise CouldNotAsk(f"HTTP 200 without a manifest (Content-Type {media or 'absent'!r}, "
                          "no Docker-Content-Digest)")


def anonymous_read(reference: str, *, scheme: str = "https",
                   opener: Callable = _OPENER.open) -> str | None:
    """None when ``reference`` is served without a credential, else why it was not."""
    match = _REFERENCE.match(reference)
    if match is None:
        raise ValueError(f"{reference!r} is not REGISTRY/NAME@sha256:<64 hex>")
    host, name, digest = match.groups()
    query = urllib.parse.urlencode({"service": host, "scope": f"repository:{name}:pull"})
    try:
        with opener(f"{scheme}://{host}/token?{query}", timeout=_TIMEOUT_SECONDS) as answer:
            document = json.loads(answer.read().decode("utf-8"))
        if not isinstance(document, dict):
            raise CouldNotAsk(f"the token endpoint answered JSON that is not an object ({type(document).__name__})")
        token = document.get("token")
        if not isinstance(token, str) or not token:
            return "the token endpoint gave no token"
        request = urllib.request.Request(
            f"{scheme}://{host}/v2/{name}/manifests/{digest}",
            headers={"Authorization": f"Bearer {token}", "Accept": _MANIFESTS})
        with opener(request, timeout=_TIMEOUT_SECONDS) as answer:
            _served(answer, digest)
            return None
    except urllib.error.HTTPError as error:
        if _refused(error):
            return f"the registry answered HTTP {error.code} to a request with no credential"
        raise CouldNotAsk(f"HTTP {error.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise CouldNotAsk(str(getattr(error, "reason", error))) from None
    except http.client.HTTPException as error:
        # IncompleteRead, BadStatusLine, ...: a broken answer, not a refusal.
        raise CouldNotAsk(f"{type(error).__name__} from the registry") from None


def main(argv: list[str] | None = None, **ask: object) -> int:
    references = sys.argv[1:] if argv is None else argv
    if not references:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    code = 0
    for reference in references:
        try:
            why = anonymous_read(reference, **ask)  # type: ignore[arg-type]
        except ValueError as error:
            print(f"::error title=anonymous pull::{error}", file=sys.stderr)
            return 2
        except CouldNotAsk as error:
            print(f"::error title=anonymous pull::could not ask about {reference}: {error}; "
                  "this says nothing about its visibility", file=sys.stderr)
            code = max(code, 2)
            continue
        if why is None:
            print(f"{reference}: served with no credential")
        else:
            print(f"::error title=anonymous pull::{reference}: {why}. Users cannot pull it. Set the package "
                  "to public in its package settings on GitHub, then re-run this job "
                  "(CONTRIBUTING.md, \"Releasing\")", file=sys.stderr)
            code = max(code, 1)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
