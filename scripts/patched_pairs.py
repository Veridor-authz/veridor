#!/usr/bin/env python3.12
"""Run one Veridor configuration against a vulnerable build and its fix.

Catching a bug does not establish regression safety. A negative control on a
correctly gated sibling endpoint of the same vulnerable build is weak evidence
for "Veridor goes green when you fix the bug". That claim needs a true
vulnerable->patched differential: the same endpoint and the same configuration.

This is the harness that measures one. Each pair names a published advisory, an
image, and the two tags either side of the fix. The same configuration runs
against both, and the pair passes only when the verdict flips.

    python3.12 scripts/patched_pairs.py                 # every pair
    python3.12 scripts/patched_pairs.py --pair gitea-…  # one
    python3.12 scripts/patched_pairs.py --pull          # docker pull by digest first
    python3.12 scripts/patched_pairs.py --json          # machine readable

**Every pair runs everywhere.** CI is configured to run every pair on every pull
request and every push to main, and the release to run every pair against the
wheel it is about to publish. There is no lighter subset: a pair too large to pull on a pull
request is replaced by a smaller one for the same shape of bug, not skipped, and
a fixture carrying the old `"heavy"` key is refused. `scripts/pair_sizes.py`
reads what a pair downloads from the registry. `--pair` that names no pair exits
2: running nothing is not a pass. Every pair it leaves out is named, with the
reason, in the output and in `--json`.

**Your own pairs.** `--pairs-dir DIR` (or `VERIDOR_PAIRS_DIR`) also runs the
pairs in DIR. A fixture describes the bug it tests, so a finding whose details
are not public cannot ship here: it lives in a directory of its own, outside the
repository, and the run says how many pairs came from where. A `provisioners.py`
in DIR is imported and may ADD runtimes and provisioners; it may not rebind one
this harness ships, and a pair name may not be used twice, so a private
directory cannot quietly replace a published advisory's pair.

**Pinned by digest.** Every image runs as `image:tag@sha256:…`. Docker resolves
the digest and ignores the tag -- `gitea/gitea:1.26.4@<1.27.0's digest>`
inspects as the 1.27.0 image (measured) -- so the digest is what runs and the
tag is for the reader. Before anything runs, each tag this Docker already holds
is checked against the pin, and a tag that now names another build (re-pushed
upstream, or pulled from elsewhere) stops the run.

**Which Veridor.** The run prints the `veridor` package it imports. Under
`VERIDOR_TEST_AGAINST=installed` it refuses to start when that is not an
installed package: when the interpreter cannot import `veridor.cli`, imports
it from this checkout's `src/`, or imports a file no installed
distribution's RECORD lists (a copy of the package, or a `veridor/`
directory in the working directory).

**Three assertions, not one.** A verdict that flips is necessary but not
sufficient, and the second and third are what stop this harness lying:

1. the vulnerable build produces a finding, and each check the pair names in
   `vulnerable_failing_checks` (a pair with one check may leave it out), and
   no other, fails with evidence of exactly the grade the pair declares in
   `expected_evidence`, `confirmed` when it declares none. `confirmed` is
   graded by the marker, not inferred from a status code. A status-only
   differential has no marker to plant and can never reach it, so a pair
   whose control sets `expect_marker` false declares `ungraded` and is held to
   a status flip: weaker evidence, and the output names the grade each pair
   was held to (every shipped pair that declares `ungraded` is such a pair).
   A pair's other checks must pass on the vulnerable build too: the Bugsink
   pair's second check is the direct route, refused on 2.1.3, and a leak
   there as well used to pass the pair unchanged (measured with stub
   documents);
2. the patched build is green, and every denial on it reached a credential
   the run proved live. The harness decides this itself, for each expectation
   that accepts only a denial (401, 403, 404, 405, 407) from an identity that
   presents a credential: that identity was served a 2xx on some check of the
   patched run (its document's `probes`), or the harness's own request on the
   same check, with every provisioned value in that identity's headers
   replaced by one nobody issued, drew a different status from the identity's,
   and that status is itself a refusal or a 2xx/3xx. Anything else fails the
   pair, naming the check and identity: a denial a fabricated credential also
   draws is the answer a dead attacker session gets, and certifies nothing;
   a 429, a 5xx or a 400 is a rate limiter, a server error or a parser
   answering, and counts as a request that did not answer. Veridor's
   `liveness.unproven` was the only input before, and Veridor leaves it empty
   when nobody is served on the check (Vikunja's one check expects 403 and 404)
   or its control errored.
   It is still read, and an entry there fails the pair too;
3. the endpoint is STILL THERE on the patched build. Against a release where
   the route simply 404s, Veridor also exits non-zero, and "a missing feature
   mislabelled vulnerable" is not a fix. A pair whose owner control probe stops
   answering on the patched build proves nothing about authorization, so it
   fails here. Where the control expects the marker, the owner must still be
   served it; where it sets `expect_marker` false, that check is not made, and
   the result lists it under `not_evaluated`, never among the checks passed.

Requires Docker. Every container is ephemeral (`--tmpfs`), bound to loopback,
and removed on the way out including on failure.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
PAIRS_DIR = ROOT / "fixtures" / "pairs"
SRC = ROOT / "src"

#: A registry digest as a fixture must write it: an index (or manifest) digest.
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
#: Each side of a pair: the field naming its tag, and the field pinning it.
SIDES = (("vulnerable", "vulnerable_digest"), ("patched", "patched_digest"))
#: A package's published file hash: 64 lowercase hex, as PyPI and npm give it.
FILE_HASH = re.compile(r"[0-9a-f]{64}")
#: Each side of a BUILT pair: the field naming its release, and the field
#: pinning that release's published file.
BUILD_SIDES = (("vulnerable", "vulnerable_sha256"), ("patched", "patched_sha256"))
#: Where a built pair's recipe lives, inside the directory its fixture is in.
#: Not "build": the repository ignores every build/ directory, so a recipe
#: there is never committed and the pair would fail in CI for want of it.
BUILD_RECIPES = "recipes"
#: The repository every built image is tagged under, so a built image can never
#: be mistaken for, or shadow, one pulled from a registry.
BUILT_PREFIX = "veridor-pair-build/"
#: A recipe is one directory under recipes/, named by one path segment, so a
#: fixture cannot point the build at a directory outside its own recipes.
RECIPE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*")
#: A base image is named by digest, the way every registry pair is.
PINNED_BASE = re.compile(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}")
#: What proves a built image holds the release its fixture names, asked of the
#: image itself after it is built. argv[1] is the package, argv[2] the version.
PYTHON_VERSION_PROBE = (
    "import importlib.metadata, sys; "
    "found = importlib.metadata.version(sys.argv[1]); "
    "print(found); sys.exit(0 if found == sys.argv[2] else 3)"
)
#: At most this many `docker pull`s run at once under --pull.
PULL_CONCURRENCY = 4
PULL_TIMEOUT_SECONDS = 900
#: What `veridor_under_test` asks the interpreter the pairs will run under:
#: the file `python -m veridor.cli` runs, and whether an installed
#: distribution's RECORD lists that file. One JSON line.
UNDER_TEST_PROBE = """\
import importlib.metadata as metadata, json, os
import veridor.cli as cli
module = cli.__file__ and os.path.realpath(cli.__file__)
try:
    found = metadata.distribution("veridor")
    listed = {os.path.realpath(found.locate_file(entry)) for entry in found.files or ()}
    installed = bool(module) and module in listed
except metadata.PackageNotFoundError:
    installed = False
print(json.dumps({"module": module, "installed": installed}))
"""

# Which Veridor the pairs run: this checkout's src/ by default, the installed
# package under VERIDOR_TEST_AGAINST=installed -- the switch the suite uses, so
# a release can run the baseline against the wheel it is about to publish.
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402

#: Long enough for a cold image on a slow laptop, short enough that a hung
#: container fails the run rather than the run hanging.
HEALTH_TIMEOUT_SECONDS = 180
DOCKER_STOP_TIMEOUT = "5"
#: How long any one docker command may take before the pair is given up.
DOCKER_TIMEOUT_SECONDS = 600


class PairError(RuntimeError):
    """A pair could not be evaluated. Distinct from a pair that failed."""


# --------------------------------------------------------------- plumbing


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    try:
        completed = subprocess.run(
            ["docker", *args],
            capture_output=capture,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        # TimeoutExpired's own text is the whole command line, and provisioning
        # passes passwords in it: `gitea admin user create ... --password ...`
        # reached stdout this way, and --json's error field. `from None`, so a
        # traceback does not print it either.
        raise PairError(f"docker {args[0]} gave no answer in {DOCKER_TIMEOUT_SECONDS}s") from None
    if check and completed.returncode != 0:
        # Docker's own reason. CalledProcessError kept only the exit status, so
        # a pair that failed at `docker run` read "exit status 125" and nothing
        # else, in CI as here. The arguments are not repeated: provisioning
        # passes passwords in them.
        detail = (completed.stderr or "").strip()[-400:] if capture else ""
        raise PairError(f"docker {args[0]} exited {completed.returncode}: {detail or '(no stderr captured)'}")
    return completed


def _http(
    url: str, *, token: str | None = None, method: str = "GET", body: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    if token:
        request.add_header("Authorization", f"token {token}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def _basic_auth_post(url: str, user: str, password: str, body: Any) -> tuple[int, str]:
    import base64

    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    request.add_header("Authorization", f"Basic {credentials}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def _bearer(
    url: str,
    *,
    token: str | None = None,
    method: str = "GET",
    body: Any = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Like `_http`, but the `Authorization` scheme is `Bearer`.

    Gitea takes `token <sha1>`; audiobookshelf is a JWT-bearer API and
    InvoiceShelf a Sanctum-bearer one. This is only used by those provisioners
    to stand the target up -- the harness control probe
    and Veridor itself still use their own header handling.
    """
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for name, value in (extra_headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def _wait_healthy(base_url: str, path: str) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    last = ""
    while time.monotonic() < deadline:
        try:
            status, _ = _http(f"{base_url}{path}")
            if status == 200:
                return
            last = f"HTTP {status}"
        except OSError as error:
            last = str(error)
        time.sleep(1)
    raise PairError(f"target never became healthy at {base_url}{path} ({last})")


# ------------------------------------------------------------ provisioners
#
# A provisioner puts the target into the state the check assumes and returns
# the environment the configuration interpolates. It is deliberately per-pair
# code rather than config: standing up two identities and a resource one of
# them owns is a real cost of pointing Veridor at an application, and pretending
# it is declarative would hide the cost rather than pay it.


def _gitea_user(container: str, name: str, password: str) -> None:
    # `gitea admin` refuses to run as root, and `docker exec` is root by
    # default -- so this must run as the `git` user or every pair fails with an
    # unrelated-looking fatal error.
    _docker(
        "exec", "-u", "git", container, "gitea", "admin", "user", "create",
        "--username", name, "--password", password,
        "--email", f"{name}@example.invalid", "--must-change-password=false",
    )


def _gitea_token(base_url: str, name: str, password: str, scopes: list[str]) -> str:
    status, body = _basic_auth_post(
        f"{base_url}/api/v1/users/{name}/tokens",
        name, password,
        {"name": f"veridor-pair-{time.time_ns()}", "scopes": scopes},
    )
    if status not in (200, 201):
        raise PairError(f"could not mint a token for {name}: HTTP {status} {body[:200]}")
    return json.loads(body)["sha1"]


def _provision_gitea_private_org(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-58417: a non-member must not be able to confirm a private org.

    No marker anywhere: on the vulnerable build the stranger receives 200 with
    an EMPTY member list, so nothing leaks except the organisation's existence.
    That is still an authorization boundary, and it is the pair that exercises
    the status oracle with the marker deliberately absent.
    """
    _gitea_user(container, "owner", "Ownerpass123")
    _gitea_user(container, "stranger", "Strangerpass123")
    owner = _gitea_token(base_url, "owner", "Ownerpass123", ["all"])
    stranger = _gitea_token(base_url, "stranger", "Strangerpass123", ["all"])

    status, body = _http(
        f"{base_url}/api/v1/orgs", token=owner, method="POST",
        body={"username": "secretorg", "visibility": "private", "description": marker},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the private organisation: HTTP {status} {body[:200]}")
    return {
        "VERIDOR_PAIR_OWNER_TOKEN": owner,
        "VERIDOR_PAIR_STRANGER_TOKEN": stranger,
    }


def _provision_gitea_public_only_team(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-58431: the public-only token restriction skipped team routes.

    Both identities are the SAME human. The boundary under test is the token's
    own scope, not who is holding it: a `public-only` token must not reach a
    private organisation's team even when its owner could.
    """
    _gitea_user(container, "owner", "Ownerpass123")
    full = _gitea_token(base_url, "owner", "Ownerpass123", ["all"])
    restricted = _gitea_token(
        base_url, "owner", "Ownerpass123",
        ["public-only", "read:organization", "read:repository"],
    )

    status, body = _http(
        f"{base_url}/api/v1/orgs", token=full, method="POST",
        body={"username": "secretorg", "visibility": "private", "description": marker},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the private organisation: HTTP {status} {body[:200]}")
    _http(
        f"{base_url}/api/v1/orgs/secretorg/teams", token=full, method="POST",
        body={"name": "core", "permission": "read", "units": ["repo.code"]},
    )
    status, body = _http(f"{base_url}/api/v1/orgs/secretorg/teams", token=full)
    teams = json.loads(body) if status == 200 else []
    if not teams:
        raise PairError("no team was created on the private organisation")
    # The id differs between builds, so it is interpolated into the config
    # rather than hard-coded -- 1.26.4 numbered this team 2 and 1.27.0 numbered
    # it 1, which would otherwise make the pair silently probe the wrong team.
    return {
        "VERIDOR_PAIR_OWNER_TOKEN": full,
        "VERIDOR_PAIR_RESTRICTED_TOKEN": restricted,
        "VERIDOR_PAIR_TEAM_ID": str(teams[0]["id"]),
    }


def _provision_gitea(container: str, base_url: str, marker: str) -> dict[str, str]:
    """Two users, a private repo carrying the marker, granted then REVOKED.

    The star is the load-bearing step: the revoked collaborator starred the
    repository while they still had access, and the advisory is that the
    starred list keeps handing it back afterwards.
    """
    def admin_user(name: str, password: str) -> None:
        # `gitea admin` refuses to run as root, and `docker exec` is root by
        # default -- so this must run as the `git` user or every pair fails
        # with an unrelated-looking fatal error.
        _docker(
            "exec", "-u", "git", container, "gitea", "admin", "user", "create",
            "--username", name, "--password", password,
            "--email", f"{name}@example.invalid", "--must-change-password=false",
        )

    def token_for(name: str, password: str) -> str:
        status, body = _basic_auth_post(
            f"{base_url}/api/v1/users/{name}/tokens",
            name, password, {"name": "veridor-pair", "scopes": ["all"]},
        )
        if status not in (200, 201):
            raise PairError(f"could not mint a token for {name}: HTTP {status} {body[:200]}")
        return json.loads(body)["sha1"]

    admin_user("owner", "Ownerpass123")
    admin_user("outsider", "Outsider123")
    # A user who never had access. Their 200-without-marker is the shape a
    # correctly-behaving target produces, so they double as a manufactured-
    # finding control: if Veridor flags them, it is inventing.
    admin_user("stranger", "Stranger123")
    owner = token_for("owner", "Ownerpass123")
    outsider = token_for("outsider", "Outsider123")
    stranger = token_for("stranger", "Stranger123")

    status, body = _http(
        f"{base_url}/api/v1/user/repos", token=owner, method="POST",
        body={"name": "secret-project", "private": True, "description": marker},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the private repository: HTTP {status} {body[:200]}")

    collaborator = f"{base_url}/api/v1/repos/owner/secret-project/collaborators/outsider"
    _http(collaborator, token=owner, method="PUT", body={"permission": "read"})
    _http(f"{base_url}/api/v1/user/starred/owner/secret-project", token=outsider, method="PUT")
    status, _ = _http(collaborator, token=owner, method="DELETE")
    if status not in (204, 200):
        raise PairError(f"revoking the collaborator did not take: HTTP {status}")

    return {
        "VERIDOR_PAIR_OWNER_TOKEN": owner,
        "VERIDOR_PAIR_REVOKED_TOKEN": outsider,
        "VERIDOR_PAIR_STRANGER_TOKEN": stranger,
    }


def _provision_audiobookshelf(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-42884: collection endpoints skipped the per-library access check.

    A user with no access to a library could still read that library's
    collections -- name, description and full book metadata -- through
    `GET /api/collections/:id`, which loaded the collection by primary key and
    never asked `checkCanAccessLibrary`. The fix (2.34.0) returns 404 to a user
    the library is not shared with; the owner still gets 200. The marker rides
    in the collection name and description, so the leak is graded `confirmed`.

    Provisioning is identical for both tags: an owner, a restricted attacker,
    a one-book library and a collection over it. Nothing here is
    tag-conditional -- the only thing that differs between the builds is whether
    the collection route enforces library access.
    """
    owner_pw = "Ownerpass123!"
    stranger_pw = "Strangerpass123!"

    def login(username: str, password: str) -> str:
        # `x-return-tokens` puts the JWT access token in the body rather than
        # only in a cookie, which is what the config's Bearer header wants.
        status, body = _bearer(
            f"{base_url}/login", method="POST",
            body={"username": username, "password": password},
            extra_headers={"x-return-tokens": "true"},
        )
        if status != 200:
            raise PairError(f"login failed for {username}: HTTP {status} {body[:200]}")
        return json.loads(body)["user"]["accessToken"]

    # 1. Root user. `/healthcheck` can answer before the root-user check is
    #    ready, so init is retried briefly rather than assumed.
    deadline = time.monotonic() + 60
    while True:
        status, body = _bearer(
            f"{base_url}/init", method="POST",
            body={"newRoot": {"username": "owner", "password": owner_pw}},
        )
        if status == 200:
            break
        if time.monotonic() > deadline:
            raise PairError(f"could not initialise the root user: HTTP {status} {body[:200]}")
        time.sleep(1)
    owner = login("owner", owner_pw)

    # 2. A book for the library to contain. The folder name carries the marker
    #    (so the scanned title does too); anullsrc mints a valid 1s mp3 with the
    #    image's bundled ffmpeg, so no media fixture has to ship in the repo.
    book_dir = f"/audiobooks/{marker}-book"
    _docker(
        "exec", container, "sh", "-c",
        f"mkdir -p '{book_dir}' && /usr/bin/ffmpeg -f lavfi "
        f"-i anullsrc=r=44100:cl=mono -t 1 -q:a 9 '{book_dir}/track.mp3' -y",
    )

    # 3. The owner's library.
    status, body = _bearer(
        f"{base_url}/api/libraries", token=owner, method="POST",
        body={"name": "OwnerLib", "folders": [{"fullPath": "/audiobooks"}], "mediaType": "book"},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the library: HTTP {status} {body[:200]}")
    library = json.loads(body)
    library_id = (library.get("library") or library)["id"]

    # 4. Scan and wait for the item, which the collection must reference.
    _bearer(f"{base_url}/api/libraries/{library_id}/scan", token=owner, method="POST")
    item_id = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status, body = _bearer(f"{base_url}/api/libraries/{library_id}/items", token=owner)
        if status == 200:
            results = json.loads(body).get("results") or []
            if results:
                item_id = results[0]["id"]
                break
        time.sleep(1)
    if not item_id:
        raise PairError("library scan produced no item to collect")

    # 5. The attacker: an active, legitimate account with NO library access.
    #    Every user type defaults to accessAllLibraries=true, so it MUST be set
    #    false explicitly -- otherwise the attacker would be entitled and the
    #    pair would manufacture a non-finding. `isActive` defaults false, and an
    #    inactive account cannot log in at all.
    status, body = _bearer(
        f"{base_url}/api/users", token=owner, method="POST",
        body={
            "username": "stranger",
            "password": stranger_pw,
            "type": "user",
            "isActive": True,
            "permissions": {"accessAllLibraries": False},
            "librariesAccessible": [],
        },
    )
    if status not in (200, 201):
        raise PairError(f"could not create the restricted user: HTTP {status} {body[:200]}")
    stranger = login("stranger", stranger_pw)

    # 6. The collection, marker in name and description. Create requires a book.
    status, body = _bearer(
        f"{base_url}/api/collections", token=owner, method="POST",
        body={
            "libraryId": library_id,
            "name": marker,
            "description": f"private-{marker}",
            "books": [item_id],
        },
    )
    if status not in (200, 201):
        raise PairError(f"could not create the collection: HTTP {status} {body[:200]}")
    collection_id = json.loads(body)["id"]

    return {
        "VERIDOR_PAIR_OWNER_TOKEN": owner,
        "VERIDOR_PAIR_STRANGER_TOKEN": stranger,
        "VERIDOR_PAIR_COLLECTION_ID": collection_id,
    }


def _provision_vikunja_comment_idor(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-33313: a task comment was readable through any task you can read.

    `GET /api/v1/tasks/{taskID}/comments/{commentID}` checked read access on
    the task named in the URL, then loaded the comment by its own id alone. So
    an attacker who can read ANY task -- its own -- reads another user's
    private comment by pairing its own task id with that comment's id. The fix
    (2.2.0) also requires the comment to belong to that task, and answers 404.

    Two users registered identically on both builds, each with a private
    project holding one task. The owner comments on its task with the marker.
    Measured by hand before this was written, on both tags: the attacker gets
    403 asking for the owner's task directly (it holds no grant) and 200 for its
    own task (its token works on the fixed build too, so the fixed build's 404
    is the fix, not a refused credential).
    """
    def call(method: str, path: str, token: str | None = None, body: Any = None) -> Any:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        status, payload = _http(f"{base_url}{path}", method=method, body=body, headers=headers)
        if status not in (200, 201):
            raise PairError(f"vikunja {method} {path}: HTTP {status} {payload[:200]}")
        return json.loads(payload)

    tokens: dict[str, str] = {}
    tasks: dict[str, int] = {}
    for user in ("owner", "attacker"):
        password = f"{user.title()}pass123!"
        call("POST", "/api/v1/register",
             body={"username": user, "email": f"{user}@example.invalid", "password": password})
        tokens[user] = call("POST", "/api/v1/login", body={"username": user, "password": password})["token"]
        project = call("PUT", "/api/v1/projects", tokens[user], {"title": f"{user}-private"})
        tasks[user] = call("PUT", f"/api/v1/projects/{project['id']}/tasks", tokens[user], {"title": f"{user}-task"})["id"]
    comment = call("PUT", f"/api/v1/tasks/{tasks['owner']}/comments", tokens["owner"], {"comment": marker})
    return {
        "VERIDOR_PAIR_OWNER_TOKEN": tokens["owner"],
        "VERIDOR_PAIR_ATTACKER_TOKEN": tokens["attacker"],
        "VERIDOR_PAIR_OWNER_TASK_ID": str(tasks["owner"]),
        "VERIDOR_PAIR_ATTACKER_TASK_ID": str(tasks["attacker"]),
        "VERIDOR_PAIR_COMMENT_ID": str(comment["id"]),
    }


# ------------------------------------------------------------ lubelogger
#
# LubeLogger authenticates with HTTP Basic against its own AuthN scheme when
# EnableAuth is set, and that scheme accepts Basic on every route -- not only
# /api -- so each identity is a static Authorization header the same way gitea's
# token is. The container is born with root credentials injected as the SHA-256
# hashes the app stores (see _lubelogger_runtime), so no interactive setup step
# is needed; the provisioner holds the matching plaintext only to mint the two
# regular users, and never puts a credential in an error.

#: A throwaway root credential. The container is given only its SHA-256 hashes
#: (the app's own hash), so nothing secret rides in the image or the fixture;
#: the provisioner needs the plaintext to create the two regular users.
_LUBELOGGER_ROOT = ("veridor-root", "veridor-pair-not-a-real-secret")
_LUBELOGGER_OWNER = ("owner", "Ownerpass123!")
_LUBELOGGER_ATTACKER = ("attacker", "Attackerpass123!")


def _lubelogger_basic(credential: tuple[str, str]) -> str:
    import base64

    return base64.b64encode(f"{credential[0]}:{credential[1]}".encode()).decode()


def _lubelogger_http(
    base_url: str, path: str, *, basic: str, method: str = "GET",
    form: dict[str, str] | None = None, json_body: Any = None,
) -> tuple[int, str]:
    """One LubeLogger request as an authenticated user.

    `basic` is the base64 of `user:password`; it is never included in an error,
    so a failure names the route and the response, never a credential. Form
    bodies are urlencoded because the MVC actions bind from form fields; only
    /api/vehicles/add takes JSON.
    """
    import urllib.parse

    data = None
    headers = {"Authorization": f"Basic {basic}"}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def _provision_lubelogger_supply_idor(container: str, base_url: str, marker: str) -> dict[str, str]:
    """GHSA-qw92-hqxv-2x9g: a plan template's supply list ignored vehicle access.

    `GET /Vehicle/GetSupplyRecordsForPlanRecordTemplate?planRecordTemplateId=<id>`
    loaded the template by id and returned the supply records of the template's
    vehicle without checking the caller could view that vehicle. So a user who
    owns a different vehicle reads another user's supply records -- descriptions,
    part numbers, costs -- by naming the victim's template id. v1.7.1 adds
    `UserCanEditVehicle(..., View)` and answers 200 with an "Access Denied" JSON
    body carrying no records; the owner still gets 200 with the records. Status
    is 200 on both builds, so only the marker distinguishes them -- the shape a
    status oracle cannot see, and the owner in the same check is the live control
    that proves the marker was reachable.

    Two regular users, created identically on both tags. `owner` owns a vehicle
    whose one supply record has the marker as its description and part number,
    and one plan template on that vehicle; `attacker` owns nothing of the
    owner's and shares no household, so it cannot reach that vehicle by any
    allowed route. The template id is server-assigned, so it is read back from
    the template list and interpolated into the config. Measured by hand on both
    tags before this was written: the attacker gets 403 at /api/vehicle/info for
    the owner's vehicle and 200 for a template of its own (its credential is
    valid on the fixed build), so the fixed build's marker-free 200 is the fix,
    not a refused credential.
    """
    import re
    import urllib.parse

    root = _lubelogger_basic(_LUBELOGGER_ROOT)

    def make_user(credential: tuple[str, str], email: str) -> None:
        # No bootstrap step: the container is born with root credentials (hashed,
        # via env), and root mints a single-use registration token per user.
        # Register consumes the token, so exactly one is listed when it is read
        # back. The token body is short and public; nothing here logs a password.
        status, body = _lubelogger_http(
            base_url,
            "/Admin/GenerateNewToken?" + urllib.parse.urlencode(
                {"emailAddress": email, "autoNotify": "false"}
            ),
            basic=root, method="POST",
        )
        if status != 200 or '"success":true' not in body:
            raise PairError(f"could not mint a registration token: HTTP {status} {body[:200]}")
        status, body = _lubelogger_http(base_url, "/Admin/GetTokenPartialView", basic=root)
        found = re.search(r'copyToClipboard\(this\)">([^<]+)</td>', body)
        if status != 200 or not found:
            raise PairError(f"could not read the registration token back: HTTP {status}")
        token = found.group(1).strip()
        status, body = _lubelogger_http(
            base_url, "/Login/Register", basic=root, method="POST",
            form={"Token": token, "EmailAddress": email,
                  "UserName": credential[0], "Password": credential[1]},
        )
        if status != 200 or '"success":true' not in body:
            raise PairError(f"could not register {credential[0]}: HTTP {status} {body[:200]}")

    make_user(_LUBELOGGER_OWNER, "owner@example.invalid")
    make_user(_LUBELOGGER_ATTACKER, "attacker@example.invalid")
    owner = _lubelogger_basic(_LUBELOGGER_OWNER)
    attacker = _lubelogger_basic(_LUBELOGGER_ATTACKER)

    # The owner's vehicle, via the JSON API, which returns the new id.
    status, body = _lubelogger_http(
        base_url, "/api/vehicles/add", basic=owner, method="POST",
        json_body={"Year": "2020", "Make": "Test", "Model": "Car",
                   "Identifier": "LicensePlate", "LicensePlate": "OWNER123",
                   "FuelType": "Gasoline"},
    )
    if status != 200:
        raise PairError(f"could not create the owner's vehicle: HTTP {status} {body[:200]}")
    vehicle_id = json.loads(body)["additionalData"]["vehicleId"]

    # A supply record on that vehicle carrying the marker in its description and
    # part number. Quantity must be > 0 or the endpoint drops it before render.
    status, body = _lubelogger_http(
        base_url, "/Vehicle/SaveSupplyRecordToVehicleId", basic=owner, method="POST",
        form={"VehicleId": str(vehicle_id), "Date": "2020-01-01",
              "Description": marker, "PartNumber": f"P-{marker}",
              "Quantity": "5", "Cost": "10"},
    )
    if '"success":true' not in body:
        raise PairError(f"could not create the marker supply record: HTTP {status} {body[:200]}")

    # A plan template on that vehicle. ImportMode 0 is ServiceRecord.
    status, body = _lubelogger_http(
        base_url, "/Vehicle/SavePlanRecordTemplateToVehicleId", basic=owner, method="POST",
        form={"VehicleId": str(vehicle_id), "Description": "OwnerTemplate",
              "ImportMode": "0", "Priority": "0", "Progress": "0", "Cost": "0"},
    )
    if '"success":true' not in body:
        raise PairError(f"could not create the plan template: HTTP {status} {body[:200]}")

    # Read the server-assigned template id back from the template list.
    status, body = _lubelogger_http(
        base_url, f"/Vehicle/GetPlanRecordTemplatesForVehicleId?vehicleId={vehicle_id}",
        basic=owner,
    )
    found = re.search(r"showEditPlanRecordTemplateModal\((\d+)\)", body)
    if status != 200 or not found:
        raise PairError(f"could not read the plan template id back: HTTP {status}")

    return {
        "VERIDOR_PAIR_OWNER_BASIC": owner,
        "VERIDOR_PAIR_ATTACKER_BASIC": attacker,
        "VERIDOR_PAIR_TEMPLATE_ID": found.group(1),
    }


# ------------------------------------------------------------ bugsink
#
# Bugsink is a Django error tracker; its issue-event web pages authenticate with
# a Django session cookie, so each identity is a static `Cookie: sessionid=<key>`
# header the same way lubelogger's is an HTTP Basic header. The provisioner mints
# the two users, their projects and their sessions through the app's own ORM over
# `docker exec bugsink-manage shell`, then ingests one event per project through
# the real Sentry-compatible ingest endpoint; it never puts a session or DSN key
# in an error.

#: Create two users, a project each, a membership each, and an authenticated
#: Django session for each. Printed as VERIDOR_PAIR_* lines. The two DSN keys
#: (sentry_key) are needed to ingest and are used only inside the provisioner.
_BUGSINK_SETUP = (
    "from django.contrib.auth import get_user_model, SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY\n"
    "from django.contrib.sessions.backends.db import SessionStore\n"
    "from teams.models import Team\n"
    "from projects.models import Project, ProjectMembership\n"
    "U = get_user_model()\n"
    "owner = U.objects.create_user('owner', 'owner@example.invalid', 'Ownerpass123!')\n"
    "attacker = U.objects.create_user('attacker', 'attacker@example.invalid', 'Attackerpass123!')\n"
    "team = Team.objects.create(name='veridor-team')\n"
    "pa = Project.objects.create(name='OwnerProject', team=team)\n"
    "pb = Project.objects.create(name='AttackerProject', team=team)\n"
    "ProjectMembership.objects.create(project=pa, user=owner, accepted=True)\n"
    "ProjectMembership.objects.create(project=pb, user=attacker, accepted=True)\n"
    "def _session(user):\n"
    "    store = SessionStore()\n"
    "    store[SESSION_KEY] = str(user.pk)\n"
    "    store[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'\n"
    "    store[HASH_SESSION_KEY] = user.get_session_auth_hash()\n"
    "    store.create()\n"
    "    return store.session_key\n"
    "print('VERIDOR_PAIR_PROJA_ID=' + str(pa.id))\n"
    "print('VERIDOR_PAIR_PROJA_KEY=' + pa.sentry_key.hex)\n"
    "print('VERIDOR_PAIR_PROJB_ID=' + str(pb.id))\n"
    "print('VERIDOR_PAIR_PROJB_KEY=' + pb.sentry_key.hex)\n"
    "print('VERIDOR_PAIR_OWNER_SESSION=' + _session(owner))\n"
    "print('VERIDOR_PAIR_ATTACKER_SESSION=' + _session(attacker))\n"
)

#: After ingest (asynchronous through snappea), read back each project's first
#: digested event and the issue it was grouped into.
_BUGSINK_POLL = (
    "from events.models import Event\n"
    "from projects.models import Project\n"
    "owner_event = Event.objects.filter(project__name='OwnerProject').order_by('id').first()\n"
    "attacker_event = Event.objects.filter(project__name='AttackerProject').order_by('id').first()\n"
    "if owner_event:\n"
    "    print('VERIDOR_PAIR_OWNER_EVENT_ID=' + str(owner_event.id))\n"
    "    print('VERIDOR_PAIR_OWNER_ISSUE_ID=' + str(owner_event.issue_id))\n"
    "if attacker_event:\n"
    "    print('VERIDOR_PAIR_ATTACKER_ISSUE_ID=' + str(attacker_event.issue_id))\n"
)


def _bugsink_shell(container: str, script: str) -> dict[str, str]:
    """Run one `bugsink-manage shell -c` script as the image's `bugsink` user
    (uid 14237, which owns /data) and collect its VERIDOR_PAIR_* lines. The
    session and DSN keys it prints never reach an error message."""
    completed = _docker(
        "exec", "-u", "bugsink", container, "bugsink-manage", "shell", "-c", script, check=False
    )
    env: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if line.startswith("VERIDOR_PAIR_"):
            key, _, value = line.partition("=")
            env[key] = value.strip()
    return env if completed.returncode == 0 else {}


def _bugsink_send_envelope(base_url: str, project_id: str, sentry_key: str, event: dict[str, Any]) -> None:
    """POST one Sentry envelope to Bugsink's ingest endpoint. `sentry_key`
    authenticates ingest and is a credential, so it rides only in the query
    string and never appears in a raised message (which names the project only)."""
    body = (
        json.dumps({"event_id": event["event_id"]}).encode()
        + b"\n" + json.dumps({"type": "event"}).encode()
        + b"\n" + json.dumps(event).encode()
    )
    request = urllib.request.Request(
        f"{base_url}/api/{project_id}/envelope/?sentry_key={sentry_key}",
        data=body, method="POST", headers={"Content-Type": "application/x-sentry-envelope"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    except urllib.error.URLError as error:
        raise PairError(f"bugsink ingest to project {project_id} could not connect: {error.reason}") from None
    if status != 200:
        raise PairError(f"bugsink ingest to project {project_id} returned HTTP {status}")


def _provision_bugsink_event_cross_project(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-47715: an issue-event page loaded the event by id without scoping
    it to the issue in the URL, so a member of one project read another project's
    event data through an issue they were allowed to access.

    `_get_event` matched `Event.objects.get(pk=event_pk)` on the caller-supplied
    id alone; the `issue_event_stacktrace`/`_details`/`_breadcrumbs` views are only
    `@issue_membership_required`, i.e. they check membership of the URL's ISSUE,
    not that the event belongs to it. 2.2.0 matches `Event.objects.get(issue=issue,
    pk=event_pk)` and, when it does not match, renders an "event not in this issue"
    page -- still HTTP 200 -- so the status is 200 on BOTH builds and only the
    planted marker distinguishes them. The owner reading its own event in the
    control proves the marker is live on the patched build, so the attacker's
    marker-free 200 there is the fix, not a removed feature.

    Two unrelated users, provisioned identically on both tags: `owner` owns a
    project holding one event whose exception value is the marker (the stacktrace
    page renders it); `attacker` owns a different project holding one benign event,
    so it has an issue of its own to name in the URL and no access to the owner's
    project. Ids are server-assigned, so they are interpolated into the config.
    Measured by hand on both tags before this was written: the attacker reads the
    owner's event (200 + marker) on 2.1.3 and gets a marker-free 200 on 2.2.0; its
    session is valid on 2.2.0 (it reads its own event 200), so the exclusion is the
    fix, not a refused credential; the owner is 403 on the attacker's issue on both.
    The fixture's second check is the direct route, measured on both tags rather
    than inferred by symmetry: the attacker naming the owner's own issue and event
    is 403 without the marker, and the owner reading that page is 200 with it. A
    fabricated or absent session is 302 to the login page on both, so that 403 is
    a live session refused, not a dead credential.
    """
    env = _bugsink_shell(container, _BUGSINK_SETUP)
    needed = ("VERIDOR_PAIR_PROJA_ID", "VERIDOR_PAIR_PROJA_KEY", "VERIDOR_PAIR_PROJB_ID",
              "VERIDOR_PAIR_PROJB_KEY", "VERIDOR_PAIR_OWNER_SESSION", "VERIDOR_PAIR_ATTACKER_SESSION")
    if any(key not in env for key in needed):
        # stdout carries the session and DSN keys, so it is not echoed here.
        raise PairError("bugsink setup did not return the two identities and their projects")

    # The owner's event carries the marker as its exception value; the attacker's
    # is benign and exists only so the attacker has an issue of its own to name.
    owner_event = {
        "event_id": os.urandom(16).hex(), "timestamp": time.time(), "platform": "python",
        "level": "error", "exception": {"values": [{"type": "MarkerError", "value": marker}]},
    }
    attacker_event = {
        "event_id": os.urandom(16).hex(), "timestamp": time.time(), "platform": "python",
        "level": "error", "exception": {"values": [{"type": "BenignError", "value": "veridor pair benign"}]},
    }
    _bugsink_send_envelope(base_url, env["VERIDOR_PAIR_PROJA_ID"], env["VERIDOR_PAIR_PROJA_KEY"], owner_event)
    _bugsink_send_envelope(base_url, env["VERIDOR_PAIR_PROJB_ID"], env["VERIDOR_PAIR_PROJB_KEY"], attacker_event)

    # Ingestion is asynchronous (snappea digests in the background), so the ids
    # are polled rather than assumed present the instant ingest returns.
    wanted = {"VERIDOR_PAIR_OWNER_EVENT_ID", "VERIDOR_PAIR_OWNER_ISSUE_ID", "VERIDOR_PAIR_ATTACKER_ISSUE_ID"}
    deadline = time.monotonic() + 60
    ids: dict[str, str] = {}
    while time.monotonic() < deadline:
        ids = _bugsink_shell(container, _BUGSINK_POLL)
        if wanted <= set(ids):
            break
        time.sleep(2)
    if not wanted <= set(ids):
        raise PairError("bugsink events were not digested in time (snappea assigned no issue)")

    return {
        "VERIDOR_PAIR_OWNER_SESSION": env["VERIDOR_PAIR_OWNER_SESSION"],
        "VERIDOR_PAIR_ATTACKER_SESSION": env["VERIDOR_PAIR_ATTACKER_SESSION"],
        "VERIDOR_PAIR_OWNER_ISSUE_ID": ids["VERIDOR_PAIR_OWNER_ISSUE_ID"],
        "VERIDOR_PAIR_OWNER_EVENT_ID": ids["VERIDOR_PAIR_OWNER_EVENT_ID"],
        "VERIDOR_PAIR_ATTACKER_ISSUE_ID": ids["VERIDOR_PAIR_ATTACKER_ISSUE_ID"],
    }


# ------------------------------------------------------------ ghost
#
# Ghost's Admin API authenticates a staff user with a signed session cookie, so
# each identity is a static `Cookie: ghost-admin-api-session=<value>` header the
# same way bugsink's is. The provisioner runs the image's own setup endpoint,
# plants a marker integration, and redeems a Contributor invitation; it never
# puts a password, a session or an invite token in an error message.

_GHOST_OWNER = ("owner@example.invalid", "Ownerpass123!x")
_GHOST_CONTRIBUTOR = ("contributor@example.invalid", "Contribpass123!x")
_GHOST_SESSION_COOKIE = "ghost-admin-api-session"
#: Ghost 4's Admin API under its versioned path. `canary` is the same code.
_GHOST_API = "/ghost/api/v4/admin"

#: Mark the pending invitation sent, and print its token.
#:
#: Ghost creates the invite row, then emails it, and sets `status` to 'sent'
#: only once the mail transport accepted it. A container with no mail server
#: cannot: `POST /invites/` answers 500 EmailError (measured on both tags) and
#: leaves the row `pending`, while `invitations/accept.js` matches
#: `{token, status: 'sent'}` and answers "Invite not found" for a pending one
#: (measured). So the row is marked sent here, through the image's own bundled
#: sqlite3, and the invitation is then redeemed through Ghost's own public
#: accept endpoint -- which is what creates the user, with the role the invite
#: names. Nothing about the boundary under test is touched: no permission, no
#: role and no integration is written here. The token is a credential, so it is
#: printed on its own line and never repeated in an error.
_GHOST_INVITE_TOKEN = """\
const sqlite3 = require("/var/lib/ghost/current/node_modules/sqlite3");
const db = new sqlite3.Database("/var/lib/ghost/content/data/ghost.db");
db.serialize(() => {
  db.run("update invites set status = 'sent' where email = ?", [process.argv[1]], function (e) {
    if (e) { console.error("marking the invitation sent failed: " + e.message); process.exit(1); }
    console.log("GHOST_INVITES_MARKED_SENT=" + this.changes);
  });
  db.all("select token from invites where email = ?", [process.argv[1]], (e, rows) => {
    if (e) { console.error("reading the invitation back failed: " + e.message); process.exit(1); }
    rows.forEach((row) => console.log("GHOST_INVITE_TOKEN=" + row.token));
  });
});
"""


def _ghost_api(
    base_url: str, path: str, *, method: str = "GET", body: Any = None, cookie: str | None = None,
) -> tuple[int, str, Any]:
    """One Ghost Admin API request: (status, body, response headers).

    `_http` cannot be used for the login because the session arrives in
    `Set-Cookie`, which it discards. `Origin` is sent on every write: Ghost's
    session endpoint refuses a cross-origin write without it.
    """
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"{base_url}{_GHOST_API}{path}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
        request.add_header("Origin", base_url)
    if cookie:
        request.add_header("Cookie", f"{_GHOST_SESSION_COOKIE}={cookie}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace"), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), error.headers


def _ghost_session(base_url: str, credential: tuple[str, str]) -> str:
    """Log in and return the session cookie's VALUE. Neither the password nor
    the session reaches the error, which names the account only."""
    status, body, headers = _ghost_api(
        base_url, "/session/", method="POST",
        body={"username": credential[0], "password": credential[1]},
    )
    if status != 201:
        raise PairError(f"ghost login for {credential[0]} failed: HTTP {status} {body[:200]}")
    for value in headers.get_all("Set-Cookie") or ():
        found = re.match(rf"{_GHOST_SESSION_COOKIE}=([^;]+)", value)
        if found:
            return found.group(1)
    raise PairError(f"ghost returned no {_GHOST_SESSION_COOKIE} for {credential[0]}")


def _provision_ghost_integration_keys(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2021-39192: every authenticated staff user could read the integrations.

    `core/server/models/integration.js` overrode `permissible()` to add the
    hosted `customIntegrations` limit check and then `return true` -- discarding
    the permission answer it was overriding. So the integrations endpoints
    granted every authenticated staff user, a Contributor included, the
    integration list with each integration's ADMIN API key secret, which is a
    privilege escalation to full Admin on the API. 4.10.0 takes
    `hasUserPermission, hasApiKeyPermission` and throws `NoPermissionError`;
    the Contributor is then 403 and the owner still reads the list.

    Confirmed from the source inside both images: 4.9.4's `permissible` ends
    `return true;` with no `hasUserPermission` anywhere in the file, 4.10.0's
    throws on it (a `customIntegrations` grep found 2 lines in both, so the
    empty result was not a grep that could not fail).

    Two identities, provisioned identically on both tags: the site `owner` from
    the image's own setup endpoint, and a `contributor` redeeming a Contributor
    invitation. The owner's custom integration carries the marker as its name
    and description, so what crosses is a string the owner planted. The
    integration id is server-assigned and differs between builds, so it is
    interpolated into the config rather than hard-coded.

    Measured by hand on both tags before this was written: the contributor
    reads `GET /integrations/?include=api_keys` 200 with the marker and every
    admin key secret on 4.9.4, and 403 without the marker on 4.10.0; its
    session is valid on 4.10.0 (it reads /users/me/, /posts/ and /settings/
    200), so the 403 is the fix and not a dead credential; the owner is 200
    with the marker on both. No cookie and a fabricated cookie are 403 on both,
    which is why the contributor's own 200 responses are the credential's
    evidence rather than its status on the leaking route.

    And no allowed route reaches the marker: 27 admin routes swept with the
    contributor's session on 4.10.0 answered 200 on 11 of them and carried the
    marker on none, with /db/ -- the content export that would hold it -- 403.
    The same sweep with the owner's session answered 200 on 20 and found the
    marker on exactly two, /integrations/ and /integrations/?include=api_keys,
    so the contributor's zero is an absence rather than a detector that cannot
    fire.
    """
    status, body, _ = _ghost_api(
        base_url, "/authentication/setup/", method="POST",
        body={"setup": [{"name": "Owner", "email": _GHOST_OWNER[0],
                         "password": _GHOST_OWNER[1], "blogTitle": "Veridor"}]},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the ghost owner: HTTP {status} {body[:200]}")
    owner = _ghost_session(base_url, _GHOST_OWNER)

    # The marker rides in the integration's name AND description, so it is
    # present whether or not the response embeds the api_keys.
    status, body, _ = _ghost_api(
        base_url, "/integrations/", method="POST", cookie=owner,
        body={"integrations": [{"name": marker, "description": f"private-{marker}"}]},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the marker integration: HTTP {status} {body[:200]}")
    integration_id = json.loads(body)["integrations"][0]["id"]

    # The Contributor role id is assigned per install, so it is read back.
    status, body, _ = _ghost_api(base_url, "/roles/?permissions=assign", cookie=owner)
    roles = json.loads(body).get("roles") or [] if status == 200 else []
    role_id = next((role["id"] for role in roles if role["name"] == "Contributor"), None)
    if not role_id:
        raise PairError(f"ghost offered no assignable Contributor role: HTTP {status}")

    # The invitation. The 500 its mail step returns is expected and is not the
    # answer: the row it left behind is, and the token is required below, so a
    # Ghost that destroyed the invite would fail here rather than silently.
    _ghost_api(base_url, "/invites/", method="POST", cookie=owner,
               body={"invites": [{"role_id": role_id, "email": _GHOST_CONTRIBUTOR[0]}]})
    completed = _docker("exec", container, "node", "-e", _GHOST_INVITE_TOKEN,
                        _GHOST_CONTRIBUTOR[0], check=False)
    token = next((line.partition("=")[2].strip() for line in completed.stdout.splitlines()
                  if line.startswith("GHOST_INVITE_TOKEN=")), None)
    if not token:
        # stdout carries the token, so it is not echoed; stderr is the script's
        # own message and holds nothing secret.
        raise PairError("ghost left no redeemable invitation for the contributor: "
                        f"{(completed.stderr or '').strip()[-200:] or '(no stderr)'}")
    status, body, _ = _ghost_api(
        base_url, "/authentication/invitation", method="POST",
        body={"invitation": [{"token": token, "email": _GHOST_CONTRIBUTOR[0],
                              "name": "Contributor", "password": _GHOST_CONTRIBUTOR[1]}]},
    )
    if status != 200:
        raise PairError(f"the contributor could not redeem the invitation: HTTP {status} {body[:200]}")
    contributor = _ghost_session(base_url, _GHOST_CONTRIBUTOR)

    # The attacker must really be a Contributor. Without this the pair would
    # still pass if a future Ghost ignored the invitation's role and made the
    # account an Administrator -- which is entitled, so the check would be
    # asserting nothing while reading as an authorization boundary.
    status, body, _ = _ghost_api(base_url, "/users/me/?include=roles", cookie=contributor)
    names = [role["name"] for role in json.loads(body)["users"][0]["roles"]] if status == 200 else []
    if names != ["Contributor"]:
        raise PairError(f"the attacker is {names or 'HTTP ' + str(status)}, not a Contributor")

    return {
        "VERIDOR_PAIR_OWNER_SESSION": owner,
        "VERIDOR_PAIR_CONTRIBUTOR_SESSION": contributor,
        "VERIDOR_PAIR_INTEGRATION_ID": integration_id,
    }


def _provision_datasette_private_instance(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2023-40570: the API explorer at /-/api skipped view-instance.

    The instance is made private by the recipe's serve.py at startup, because
    datasette reads its metadata only then; this mints the owner's API token
    with the secret the container already holds. No marker: with the whole
    instance denied, 1.0a3 answers the anonymous /-/api with 200 but names no
    database or table in it (measured: 0 hits for either name in the anonymous
    page, 2 each in the owner's). The refusal the fix added is what the pair
    holds the release to -- the status oracle, as in gitea-private-org.
    """
    minted = _docker("exec", container, "datasette", "create-token", "owner", check=False)
    lines = (minted.stdout or "").strip().splitlines()
    token = lines[-1] if lines else ""
    if minted.returncode != 0 or not token.startswith("dstok_"):
        # Never the output itself: on success it is the token.
        raise PairError(f"datasette create-token gave no token (exit {minted.returncode}, "
                        f"{len(token)} chars): {(minted.stderr or '').strip()[-200:]}")
    return {"VERIDOR_PAIR_OWNER_TOKEN": token}


# ------------------------------------------------------------ invoiceshelf
#
# InvoiceShelf's API authenticates with a Sanctum Bearer token and scopes every
# request to the company named in a `company` header, so each identity is a
# static pair of headers. The provisioner stands up two company owners that
# share no company:
#
#   - the ATTACKER owns company A (the seeded "xyz" company) and is a member of
#     no other company that holds the victim;
#   - the VICTIM owns company B and is a member of company B only.
#
# `UserPolicy::view` on 2.4.0 returns `$user->isOwner()` alone, and `isOwner()`
# is true for any user who owns the company named in the `company` header. So the
# attacker, owner of A, reads a user of B through `GET /api/v1/users/{id}` by
# naming their own company in the header -- the record is loaded by global id.
# 2.4.1 adds `sharesActiveCompany($model)`, which answers 403 when the target does
# not belong to the header's company. The victim reading its own record (owner of
# B, header B) stays 200 on both builds, which is the pair's control.
#
# The marker rides in the victim's name and email, so the leak the attacker draws
# on 2.4.0 is graded by a string the victim planted, and the victim's own read is
# what proves that string is live on 2.4.1. No token or password reaches an
# error.

#: The admin the install seed creates: owner of the seeded company (id 1), which
#: this pair uses as company A. Public, fixed by database/seeders/UsersTableSeeder.
_INVOICESHELF_ADMIN = ("admin@invoiceshelf.com", "invoiceshelf@123")
#: A throwaway password for the victim account, minted and used inside this run.
#: Never printed; it authenticates nothing outside this ephemeral container.
_INVOICESHELF_VICTIM_PASSWORD = "veridor-pair-not-a-real-secret"
#: Where the entrypoint created the empty sqlite database (see the runtime).
_INVOICESHELF_SQLITE = "/var/www/html/storage/app/database.sqlite"


def _invoiceshelf_ok(
    base_url: str, path: str, where: str, *, method: str = "GET", body: Any = None,
    token: str | None = None, company: str | None = None,
) -> dict[str, Any]:
    """One InvoiceShelf API request that must succeed, its JSON body parsed.

    `Accept: application/json` makes Laravel answer a refusal as JSON rather
    than a redirect. A failure names the route and the response only, never the
    token.
    """
    headers = {"Accept": "application/json"}
    if company is not None:
        headers["company"] = company
    status, payload = _bearer(f"{base_url}{path}", token=token, method=method, body=body, extra_headers=headers)
    if status not in (200, 201):
        raise PairError(f"{where}: HTTP {status} {payload[:200]}")
    try:
        return json.loads(payload)
    except ValueError:
        raise PairError(f"{where}: HTTP {status}, non-JSON response {payload[:120]!r}") from None


def _invoiceshelf_login(base_url: str, email: str, password: str) -> str:
    body = {"username": email, "password": password, "device_name": "veridor-pair"}
    result = _invoiceshelf_ok(base_url, "/api/v1/auth/login", f"login for {email}", method="POST", body=body)
    token = result.get("token")
    if not token:
        raise PairError(f"login for {email} returned no token")
    return token


def _provision_invoiceshelf_user_cross_company(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-55610: a company owner could read a user of another company.

    Measured by hand on both tags before this was written. On 2.4.0 the attacker
    (owner of company A, header A) reads the victim of company B at
    GET /api/v1/users/{victim} with HTTP 200 and the marker; on 2.4.1 the same
    request is 403 with no marker. The victim reading its own record (owner of
    B, header B) is 200 with the marker on both, so the fix is the attacker's
    403 and not a removed route. A request with a fabricated Bearer token is 401
    on both, so the attacker's 403 on 2.4.1 is a live credential refused.
    """
    # 1. Install: migrate --seed creates the admin and the seeded company A.
    _invoiceshelf_ok(
        base_url, "/api/v1/installation/database/config", "install database/config",
        method="POST",
        body={"app_url": base_url, "database_connection": "sqlite", "database_name": _INVOICESHELF_SQLITE},
    )

    # 2. The admin is the attacker: owner of the seeded company A.
    attacker = _invoiceshelf_login(base_url, *_INVOICESHELF_ADMIN)

    # 3. Company A is the admin's only company at this point; read its id back
    #    rather than assume 1, so the pair does not depend on the seed's numbering.
    companies = _invoiceshelf_ok(base_url, "/api/v1/companies", "list the admin's companies",
                                 token=attacker, company="1").get("data") or []
    if not companies:
        raise PairError("the admin owns no company after install")
    company_a = str(companies[0]["id"])

    # 4. Company B, created by the admin (so owned by the admin for now).
    company_b = str(
        _invoiceshelf_ok(base_url, "/api/v1/companies", "create company B", method="POST",
                         token=attacker, company=company_a,
                         body={"name": "Veridor Company B", "currency": 1,
                               "address": {"country_id": 1}})["data"]["id"]
    )

    # 5. The victim: a member of company B only, carrying the marker in its name
    #    and email. createFromRequest syncs membership from the `companies` list,
    #    so the victim never joins company A whatever header is set here.
    victim_record = _invoiceshelf_ok(
        base_url, "/api/v1/users", "create the victim user", method="POST",
        token=attacker, company=company_a,
        body={
            "name": marker,
            "email": f"{marker}@victim.invalid",
            "password": _INVOICESHELF_VICTIM_PASSWORD,
            "companies": [{"id": int(company_b), "role": "super admin"}],
        },
    )
    victim_id = str((victim_record.get("data") or victim_record)["id"])

    # 6. Hand company B to the victim, so the victim is its owner (isOwner true
    #    under header B) and the attacker no longer is. The attacker stays a
    #    member of B, which does not matter: the fix checks the VICTIM's
    #    membership of the header's company, not the caller's.
    _invoiceshelf_ok(base_url, f"/api/v1/transfer/ownership/{victim_id}", "transfer company B to the victim",
                     method="POST", token=attacker, company=company_b)

    # 7. The victim's own credential, for the control and the marker probe.
    victim = _invoiceshelf_login(base_url, f"{marker}@victim.invalid", _INVOICESHELF_VICTIM_PASSWORD)

    return {
        "VERIDOR_PAIR_ATTACKER_TOKEN": attacker,
        "VERIDOR_PAIR_VICTIM_TOKEN": victim,
        "VERIDOR_PAIR_VICTIM_ID": victim_id,
        "VERIDOR_PAIR_COMPANY_A_ID": company_a,
        "VERIDOR_PAIR_COMPANY_B_ID": company_b,
    }


# ------------------------------------------------------------ hawkbit
#
# The target is Eclipse hawkBit's Direct Device Integration (DDI) API. A device
# authenticates with its own per-target security token
# (Authorization: TargetToken <token>), and the controllerId in the DDI path
# must be that token's own target -- hawkBit refuses a token presented against
# another controllerId with 401. So the owner (device A) can never be probed at
# the attacker's path, and the marker owner's reachability is established by the
# identity-level marker_probe rather than a same-check control.
#
# The provisioner uses only the Management REST API as admin (Basic admin/admin):
# it enables per-target token authentication, creates two software modules,
# uploads artifacts to them, creates two distribution sets and two targets,
# assigns one set to each target, and returns each target's security token, the
# module ids and the name of device A's marker-bearing artifact. Device A's
# module holds two artifacts: one named by the marker, which the DDI listing
# surfaces, and one with a plain name whose bytes carry the marker, which the
# DDI download streams. The pair measures both paths. The admin credential is
# static and never echoed; a failure names the route and the response only.

#: hawkBit's built-in superuser on the default single-tenant image.
_HAWKBIT_ADMIN = ("admin", "admin")
#: The DDI tenant of the default image.
_HAWKBIT_TENANT = "DEFAULT"
#: The two devices. controllerIds are chosen here (not server-assigned), so
#: they are fixed strings; the security tokens are read back per run.
_HAWKBIT_CONTROLLER_A = "veridor-device-a"
_HAWKBIT_CONTROLLER_B = "veridor-device-b"
_HAWKBIT_FIRMWARE_A = "device-a-firmware.bin"


def _hawkbit_admin_header() -> str:
    raw = f"{_HAWKBIT_ADMIN[0]}:{_HAWKBIT_ADMIN[1]}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _hawkbit_mgmt(base_url: str, path: str, *, method: str = "GET", body: Any = None) -> tuple[int, str]:
    """One hawkBit Management REST call as admin.

    Not `_http`: the images are linux/amd64 only and run emulated on arm64
    hosts, so this keeps a 30-second timeout rather than `_http`'s 20.
    """
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method)
    request.add_header("Authorization", _hawkbit_admin_header())
    if data is not None:
        request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def _hawkbit_upload(base_url: str, path: str, *, filename: str, content: bytes) -> tuple[int, str]:
    """Multipart artifact upload as admin, built by hand to avoid a dependency."""
    boundary = f"----veridor{uuid.uuid4().hex}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    data = head + content + tail
    request = urllib.request.Request(f"{base_url}{path}", data=data, method="POST")
    request.add_header("Authorization", _hawkbit_admin_header())
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def _hawkbit_expect(status: int, body: str, ok: tuple[int, ...], what: str) -> Any:
    if status not in ok:
        raise PairError(f"hawkBit: could not {what}: HTTP {status} {body[:200]}")
    return json.loads(body) if body.strip() else None


def _provision_hawkbit_ddi_cross_device(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-16454: the DDI controller API ignored per-device assignment.

    A device naming another device's software module id, with its own
    controllerId and token, reached that module's artifacts on 1.0.3: the
    download `.../softwaremodules/{smId}/artifacts/{fileName}` when the request
    carried a Range header (the only assignment check ran inside logDownload,
    which a ranged request skipped), and the listing
    `.../softwaremodules/{smId}/artifacts` on every request. 1.0.4 checks the
    assignment on both and answers 404 when the module is not the caller's.

    Device A owns module A and is assigned it; device B owns module B and is
    assigned it, so device B's token is provably live on the patched build (it
    lists its own module 200). Measured on both tags: device B's ranged download
    of device A's artifact is 206 with the marker on 1.0.3 and 404 on 1.0.4; its
    listing of device A's module is 200 with the marker on 1.0.3 and 404 on
    1.0.4; a fabricated TargetToken gets 401 on both.
    """
    # Per-target security tokens must be enabled for TargetToken auth to work.
    status, body = _hawkbit_mgmt(
        base_url,
        "/rest/v1/system/configs/authentication.targettoken.enabled",
        method="PUT",
        body={"value": True},
    )
    _hawkbit_expect(status, body, (200, 204), "enable target token authentication")

    def make_module(name: str) -> int:
        status, body = _hawkbit_mgmt(
            base_url, "/rest/v1/softwaremodules", method="POST",
            body=[{"name": name, "version": "1.0", "type": "os"}],
        )
        return _hawkbit_expect(status, body, (200, 201), f"create software module {name}")[0]["id"]

    def make_set(name: str, module_id: int) -> int:
        status, body = _hawkbit_mgmt(
            base_url, "/rest/v1/distributionsets", method="POST",
            body=[{"name": name, "version": "1.0", "type": "os",
                   "modules": [{"id": module_id}]}],
        )
        return _hawkbit_expect(status, body, (200, 201), f"create distribution set {name}")[0]["id"]

    module_a = make_module("veridor-module-a")
    module_b = make_module("veridor-module-b")

    # Device A's module carries two artifacts. The first has the marker in its
    # filename, which the listing returns verbatim. The second has a plain
    # filename and the marker only in its bytes, which the download streams:
    # a marker in the download URL would be a reflected marker, which Veridor
    # refuses as proof. Device B's artifact carries no marker.
    status, body = _hawkbit_upload(
        base_url, f"/rest/v1/softwaremodules/{module_a}/artifacts",
        filename=f"{marker}.bin", content=b"device A firmware payload",
    )
    _hawkbit_expect(status, body, (200, 201), "upload device A's marker-named artifact")
    status, body = _hawkbit_upload(
        base_url, f"/rest/v1/softwaremodules/{module_a}/artifacts",
        filename=_HAWKBIT_FIRMWARE_A, content=f"device A firmware payload {marker}\n".encode(),
    )
    _hawkbit_expect(status, body, (200, 201), "upload device A's marker-bearing artifact")
    status, body = _hawkbit_upload(
        base_url, f"/rest/v1/softwaremodules/{module_b}/artifacts",
        filename="device-b-firmware.bin", content=b"device B firmware payload",
    )
    _hawkbit_expect(status, body, (200, 201), "upload device B's artifact")

    set_a = make_set("veridor-set-a", module_a)
    set_b = make_set("veridor-set-b", module_b)

    status, body = _hawkbit_mgmt(
        base_url, "/rest/v1/targets", method="POST",
        body=[{"controllerId": _HAWKBIT_CONTROLLER_A, "name": _HAWKBIT_CONTROLLER_A},
              {"controllerId": _HAWKBIT_CONTROLLER_B, "name": _HAWKBIT_CONTROLLER_B}],
    )
    _hawkbit_expect(status, body, (200, 201), "create the two targets")

    def token_of(controller_id: str) -> str:
        status, body = _hawkbit_mgmt(base_url, f"/rest/v1/targets/{controller_id}")
        target = _hawkbit_expect(status, body, (200,), f"read {controller_id}'s security token")
        token = target.get("securityToken")
        if not token:
            raise PairError(f"hawkBit: {controller_id} has no security token")
        return token

    token_a = token_of(_HAWKBIT_CONTROLLER_A)
    token_b = token_of(_HAWKBIT_CONTROLLER_B)

    def assign(set_id: int, controller_id: str) -> None:
        status, body = _hawkbit_mgmt(
            base_url, f"/rest/v1/distributionsets/{set_id}/assignedTargets",
            method="POST", body=[{"id": controller_id}],
        )
        _hawkbit_expect(status, body, (200,), f"assign set {set_id} to {controller_id}")

    assign(set_a, _HAWKBIT_CONTROLLER_A)
    assign(set_b, _HAWKBIT_CONTROLLER_B)

    return {
        "VERIDOR_PAIR_A_CONTROLLER": _HAWKBIT_CONTROLLER_A,
        "VERIDOR_PAIR_B_CONTROLLER": _HAWKBIT_CONTROLLER_B,
        "VERIDOR_PAIR_A_TOKEN": token_a,
        "VERIDOR_PAIR_B_TOKEN": token_b,
        "VERIDOR_PAIR_SM_A_ID": str(module_a),
        "VERIDOR_PAIR_SM_B_ID": str(module_b),
        "VERIDOR_PAIR_TENANT": _HAWKBIT_TENANT,
        "VERIDOR_PAIR_A_FILENAME": _HAWKBIT_FIRMWARE_A,
    }


# ------------------------------------------------------------ domoticz
#
# The bug is a missing authorization check (CWE-862). The `udevices` web command
# (Cmd_UpdateDevices in WebServerCmds.cpp) runs a lua parser script named by the
# `script` query parameter through CLuaHandler::executeLuaScript. On 2026.2 the
# handler has no rights gate, so a VIEWER-level session reaches it. Fix commit
# 73ed0495 adds `if (session.rights == URIGHTS_VIEWER || session.rights ==
# URIGHTS_NONE) { reply forbidden; return; }` at the top of the handler, so a
# viewer is answered 403 on 2026.3. The advisory also fixes a path-traversal half
# (the `..` guard), which is a separate weakness and NOT what this pair claims:
# the pair exercises only the role gate, so the planted script name is a plain
# file in the parser directory and never contains `..`.
#
# Provisioning is identical on both tags:
#
#   - the container is started with -nowwwpwd, which makes loopback a trusted
#     network (temporary bootstrap admin) so the two users and the one setting can
#     be created over the API with no credential yet in hand;
#   - an ADMIN user (rights 2) and a VIEWER user (rights 0) are created through
#     the adduser command; their passwords are stored as Domoticz stores them, the
#     md5 hex of the plaintext;
#   - storesettings turns AllowPlainBasicAuth on (so HTTP Basic auth is accepted
#     over the loopback, non-HTTPS connection) and clears WebLocalNetworks, which
#     REMOVES the -nowwwpwd trust again: after this an unauthenticated request is
#     401, and each identity is just an HTTP Basic header the way gitea's token or
#     lubelogger's Basic header is;
#   - a parser script is planted at userdata/scripts/lua_parsers/veridor.lua via
#     docker exec, identical on both sides. It is needed because executeLuaScript
#     returns true only when the file loads: without it the vulnerable build's
#     viewer gets 400 (status ERR) rather than a clean 200, so there would be no
#     status differential to measure.
#
# Measured by hand on both tags before this was written (status only, no marker,
# so the grade is `ungraded` like gitea-private-org and datasette):
#
#   GET /json.htm?type=command&param=udevices&script=veridor.lua
#     admin  Basic : 200 on 2026.2, 200 on 2026.3  (control: endpoint survives)
#     viewer Basic : 200 on 2026.2, 403 on 2026.3  (the role gate the fix adds)
#   A viewer Basic header with a wrong password is 401 on both tags, and an
#   unauthenticated request is 401 on both, so the viewer's 403 on 2026.3 is a
#   live credential refused, not a dead session or a removed route.

#: Throwaway credentials, valid only inside this ephemeral container. The
#: plaintext is base64'd into the identity's Basic header; it is never printed.
_DOMOTICZ_ADMIN = ("veridor_admin", "veridor-pair-admin-not-a-real-secret")
_DOMOTICZ_VIEWER = ("veridor_viewer", "veridor-pair-viewer-not-a-real-secret")
#: The parser script name invoked through the `script` parameter. A plain file
#: name, no `..`: this pair claims the role gate, not the path-traversal half.
_DOMOTICZ_SCRIPT = "veridor.lua"
_DOMOTICZ_PARSER_DIR = "/opt/domoticz/userdata/scripts/lua_parsers"


def _domoticz_basic(credential: tuple[str, str]) -> str:
    return base64.b64encode(f"{credential[0]}:{credential[1]}".encode()).decode()


def _domoticz_ok(base_url: str, path: str, where: str) -> dict[str, Any]:
    """One unauthenticated Domoticz API GET that must answer status OK. A
    failure names the route and the response only."""
    status, body = _http(f"{base_url}{path}")
    if status != 200:
        raise PairError(f"{where}: HTTP {status} {body[:160]}")
    try:
        parsed = json.loads(body)
    except ValueError:
        raise PairError(f"{where}: HTTP 200 but non-JSON {body[:120]!r}") from None
    if parsed.get("status") != "OK":
        raise PairError(f"{where}: Domoticz answered {parsed.get('status')!r} ({body[:160]})")
    return parsed


def _domoticz_adduser(base_url: str, credential: tuple[str, str], rights: int) -> None:
    # No credential is sent: this runs during the -nowwwpwd bootstrap window,
    # when loopback is a trusted network, so the API answers as admin. The
    # password is stored the way Domoticz stores it, the md5 hex of the
    # plaintext, so the Basic header (plaintext) authenticates against it later.
    password = hashlib.md5(credential[1].encode()).hexdigest()
    path = (
        "/json.htm?type=command&param=adduser"
        f"&enabled=true&username={credential[0]}&password={password}"
        f"&rights={rights}&RemoteSharing=false&TabsEnabled=15"
    )
    _domoticz_ok(base_url, path, f"adduser {credential[0]} (rights {rights})")


def _provision_domoticz_viewer_lua_parser(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-75520: a VIEWER could invoke the udevices lua parser command.

    See the section comment above for the measured statuses. `marker` is
    unused: this is a status-only differential (200 vs 403), graded `ungraded`.
    """
    # 1. The two users, created over the trusted-loopback bootstrap window.
    _domoticz_adduser(base_url, _DOMOTICZ_ADMIN, 2)
    _domoticz_adduser(base_url, _DOMOTICZ_VIEWER, 0)

    # 2. Allow Basic auth over HTTP, and clear WebLocalNetworks so the -nowwwpwd
    #    trust is removed: after this an unauthenticated request is 401 and each
    #    identity is only its Basic credential. Still sent over the bootstrap
    #    window (Basic auth is not accepted until this call enables it).
    _domoticz_ok(
        base_url,
        "/json.htm?type=command&param=storesettings"
        "&AllowPlainBasicAuth=on&WebLocalNetworks="
        "&ShortLogInterval=5&WindUnit=0&TempUnit=0&WeightUnit=0",
        "storesettings (enable Basic auth, clear trusted networks)",
    )

    # 3. Confirm Basic auth is now required and works: the admin is served and an
    #    unauthenticated caller is refused. This proves the trust was dropped, so
    #    the viewer's later 403 cannot be read as a trusted-network artefact.
    anon_status, _ = _http(f"{base_url}/json.htm?type=command&param=getusers")
    if anon_status != 401:
        raise PairError(f"expected 401 for an unauthenticated API call after clearing trust, got {anon_status}")
    admin_status, _ = _http(f"{base_url}/json.htm?type=command&param=getusers",
                            headers={"Authorization": f"Basic {_domoticz_basic(_DOMOTICZ_ADMIN)}"})
    if admin_status != 200:
        raise PairError(f"admin Basic auth did not work after enabling it: HTTP {admin_status}")

    # 4. Plant the parser script, identical on both sides, so executeLuaScript
    #    loads a file and returns true on the vulnerable build (clean 200).
    _docker(
        "exec", container, "sh", "-c",
        f"mkdir -p {_DOMOTICZ_PARSER_DIR} && "
        f"printf 'print(\"veridor pair\")\\n' > {_DOMOTICZ_PARSER_DIR}/{_DOMOTICZ_SCRIPT}",
    )

    return {
        "VERIDOR_PAIR_ADMIN_BASIC": _domoticz_basic(_DOMOTICZ_ADMIN),
        "VERIDOR_PAIR_VIEWER_BASIC": _domoticz_basic(_DOMOTICZ_VIEWER),
    }


# ------------------------------------------------------------ ghost 6
#
# CVE-2026-105678 (also CVE-2026-104412), GHSA-4pvx-fwjj-8gpc. On Ghost 6.63.0 an
# Editor can promote any lower-privileged staff user to Editor by PUTting that
# user's roles to the Editor role id -- the Editor's OWN role. 6.64.0 fixes it.
#
# Same authentication as the Ghost 4 pair above (a staff session cookie), but not
# the same helpers: Ghost 6 serves the Admin API unversioned at /ghost/api/admin,
# and its image bundles better-sqlite3 rather than sqlite3, so the invitation
# script differs too. The owner's credential and the cookie name are shared.
#
# The provisioner does the identical thing on both builds -- no branching on
# version. It sets up the owner, invites and redeems an Editor and an Author, and
# returns the attacker (Editor) session, the owner session, the victim (Author)
# user id and the Editor role id. The marker is accepted for the fixture's schema
# but not planted: this is a privilege escalation, not a data read, so nothing of
# the owner's crosses to the attacker. The pair is graded by the status oracle,
# like gitea-private-org. No password, session or invite token reaches an error.

_GHOST6_EDITOR = ("editor@example.invalid", "Editorpass123!x")
_GHOST6_AUTHOR = ("author@example.invalid", "Authorpass123!x")
#: Ghost 6's Admin API, unversioned.
_GHOST6_API = "/ghost/api/admin"

#: Mark the pending invitation 'sent' and print its token, through the image's
#: own bundled better-sqlite3. Ghost creates the invite row then emails it, and
#: a container with no mail server cannot: POST /invites/ answers 500 and leaves
#: the row 'pending', while the public accept endpoint matches {token, status:
#: 'sent'}. Nothing about the boundary under test is touched here -- no
#: permission, role or user is written; the row is only marked sent so Ghost's
#: own accept endpoint can create the user with the role the invite names. The
#: token is a credential, so it is printed on its own line and never repeated.
_GHOST6_INVITE_TOKEN = r"""
const Database = require("/var/lib/ghost/current/node_modules/better-sqlite3");
const db = new Database("/var/lib/ghost/content/data/ghost.db");
const email = process.argv[1];
const info = db.prepare("update invites set status='sent' where email=?").run(email);
console.log("GHOST_INVITES_MARKED_SENT=" + info.changes);
for (const row of db.prepare("select token from invites where email=?").all(email)) {
  console.log("GHOST_INVITE_TOKEN=" + row.token);
}
"""


def _ghost6_api(
    base_url: str, path: str, *, method: str = "GET", body: Any = None, cookie: str | None = None,
) -> tuple[int, str, Any]:
    """One Ghost 6 Admin API request: (status, body, response headers). As
    `_ghost_api`, under Ghost 6's unversioned path."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"{base_url}{_GHOST6_API}{path}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
        request.add_header("Origin", base_url)
    if cookie:
        request.add_header("Cookie", f"{_GHOST_SESSION_COOKIE}={cookie}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace"), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), error.headers


def _ghost6_session(base_url: str, credential: tuple[str, str]) -> str:
    """Log in; return the session cookie VALUE. Neither password nor session
    reaches an error, which names the account only."""
    status, body, headers = _ghost6_api(
        base_url, "/session/", method="POST",
        body={"username": credential[0], "password": credential[1]},
    )
    if status != 201:
        raise PairError(f"ghost login for {credential[0]} failed: HTTP {status} {body[:200]}")
    for value in headers.get_all("Set-Cookie") or ():
        found = re.match(rf"{_GHOST_SESSION_COOKIE}=([^;]+)", value)
        if found:
            return found.group(1)
    raise PairError(f"ghost returned no {_GHOST_SESSION_COOKIE} for {credential[0]}")


def _ghost6_invite_and_redeem(
    container: str, base_url: str, owner_cookie: str, role_id: str, credential: tuple[str, str],
) -> None:
    # The invitation's mail step answers 500 here; the row it left behind is
    # what matters, and the token is required below, so a Ghost that destroyed
    # the invite fails here rather than silently.
    _ghost6_api(base_url, "/invites/", method="POST", cookie=owner_cookie,
                body={"invites": [{"role_id": role_id, "email": credential[0]}]})
    completed = _docker("exec", container, "node", "-e", _GHOST6_INVITE_TOKEN, credential[0], check=False)
    token = next((line.partition("=")[2].strip() for line in completed.stdout.splitlines()
                  if line.startswith("GHOST_INVITE_TOKEN=")), None)
    if not token:
        # stdout carries the token, so it is not echoed; stderr is the script's
        # own message and holds nothing secret.
        raise PairError("ghost left no redeemable invitation for "
                        f"{credential[0]}: {(completed.stderr or '').strip()[-200:] or '(no stderr)'}")
    status, body, _ = _ghost6_api(
        base_url, "/authentication/invitation", method="POST",
        body={"invitation": [{"token": token, "email": credential[0],
                              "name": credential[0].split("@")[0], "password": credential[1]}]},
    )
    if status != 200:
        raise PairError(f"{credential[0]} could not redeem the invitation: HTTP {status} {body[:200]}")


def _provision_ghost_editor_promotes_author(container: str, base_url: str, marker: str) -> dict[str, str]:
    """CVE-2026-105678: an Editor may promote a lower user to Editor.

    `core/server/models/user.js` permissible(): when an Editor PUTs a victim's
    roles to the Editor role id, `roleId === contextRoleId` makes the
    `else if (roleId !== contextRoleId)` guard false, so the `assign.role`
    permission check is skipped and the edit falls through to resolve. 6.64.0's
    guard is `roleId !== contextRoleId || editedUserId !== context.user`, which
    is true for a victim who is not the caller, so `canThis().assign.role` runs
    and an Editor, lacking it, is refused. Confirmed from the source inside both
    images: 6.63.0 line ~1040 reads `else if (roleId !== contextRoleId) {`,
    6.64.0 `else if (roleId !== contextRoleId || editedUserId !== context.user) {`.

    Two identities, provisioned identically on both tags: the site `owner` from
    the image's own setup endpoint, and an `editor` redeeming an Editor
    invitation. The victim is an `author` redeeming an Author invitation; its
    user id is server-assigned and differs between builds, so it is interpolated
    into the config rather than hard-coded, as is the Editor role id the attack
    body sets.

    Measured by hand on both tags before this was written: the editor PUTs the
    author's roles to the Editor role id and gets 200 with the author now an
    Editor on 6.63.0, and 403 with the author still an Author on 6.64.0; the
    owner gets 200 on both (the mutation endpoint is still there and still works
    for an entitled caller). The editor reads /users/me/ 200 on both, so the 403
    is the fix and not a dead session. The PUT is idempotent on both builds --
    repeating it returns the same status and leaves the author's role unchanged
    from the first result -- so a replayed request cannot exhaust the victim.
    No fabricated cookie is accepted: /users/me/ refuses a sham cookie on both,
    which is why the editor's own 200 there is its proof of life.
    """
    status, body, _ = _ghost6_api(
        base_url, "/authentication/setup/", method="POST",
        body={"setup": [{"name": "Owner", "email": _GHOST_OWNER[0],
                         "password": _GHOST_OWNER[1], "blogTitle": "Veridor"}]},
    )
    if status not in (200, 201):
        raise PairError(f"could not create the ghost owner: HTTP {status} {body[:200]}")
    owner = _ghost6_session(base_url, _GHOST_OWNER)

    # Role ids are assigned per install, so they are read back.
    status, body, _ = _ghost6_api(base_url, "/roles/?permissions=assign", cookie=owner)
    roles = json.loads(body).get("roles") or [] if status == 200 else []
    editor_role = next((role["id"] for role in roles if role["name"] == "Editor"), None)
    author_role = next((role["id"] for role in roles if role["name"] == "Author"), None)
    if not editor_role or not author_role:
        raise PairError(f"ghost offered no assignable Editor/Author role: HTTP {status}")

    _ghost6_invite_and_redeem(container, base_url, owner, editor_role, _GHOST6_EDITOR)
    _ghost6_invite_and_redeem(container, base_url, owner, author_role, _GHOST6_AUTHOR)
    editor = _ghost6_session(base_url, _GHOST6_EDITOR)

    status, body, _ = _ghost6_api(base_url, "/users/?limit=all&include=roles", cookie=owner)
    users = {user["email"]: user for user in json.loads(body)["users"]} if status == 200 else {}
    author = users.get(_GHOST6_AUTHOR[0])
    if not author:
        raise PairError(f"ghost did not create the author user: HTTP {status}")

    # The attacker must really be an Editor, not something entitled: without
    # this the pair would still pass if a future Ghost ignored the invitation's
    # role and made the account an Administrator, which can assign roles.
    editor_roles = [role["name"] for role in users.get(_GHOST6_EDITOR[0], {}).get("roles", [])]
    if editor_roles != ["Editor"]:
        raise PairError(f"the attacker is {editor_roles or 'HTTP ' + str(status)}, not an Editor")
    author_roles = [role["name"] for role in author.get("roles", [])]
    if author_roles != ["Author"]:
        raise PairError(f"the victim is {author_roles or 'HTTP ' + str(status)}, not an Author")

    return {
        "VERIDOR_PAIR_OWNER_SESSION": owner,
        "VERIDOR_PAIR_EDITOR_SESSION": editor,
        "VERIDOR_PAIR_AUTHOR_ID": author["id"],
        "VERIDOR_PAIR_EDITOR_ROLE_ID": editor_role,
    }


def _gitea_runtime(base_url: str) -> list[str]:
    return [
        "--tmpfs", "/data:rw,size=512m",
        "-e", "GITEA__security__INSTALL_LOCK=true",
        "-e", "GITEA__database__DB_TYPE=sqlite3",
        "-e", "GITEA__database__PATH=/data/gitea.db",
        "-e", f"GITEA__server__ROOT_URL={base_url}/",
    ]


def _lubelogger_runtime(base_url: str) -> list[str]:
    # LiteDB and config live under /App/data (tmpfs, empty each run). EnableAuth
    # turns on the AuthN scheme; UserNameHash/UserPasswordHash are the SHA-256
    # hashes (the app's own hash) of _LUBELOGGER_ROOT, injected as config so root
    # Basic auth works from the first request with no interactive setup, and the
    # provisioner mints the two regular users through it. base_url is unused: the
    # app is same-origin and needs no external URL.
    return [
        "--tmpfs", "/App/data:rw,size=128m",
        "-e", "EnableAuth=true",
        "-e", "UserNameHash=" + hashlib.sha256(_LUBELOGGER_ROOT[0].encode()).hexdigest(),
        "-e", "UserPasswordHash=" + hashlib.sha256(_LUBELOGGER_ROOT[1].encode()).hexdigest(),
    ]


def _audiobookshelf_runtime(base_url: str) -> list[str]:
    # /config and /metadata hold the sqlite db and scan logs; /audiobooks is the
    # library root the provisioner plants a book into. Every run starts empty.
    # `base_url` is unused: the API is same-origin and needs no external URL.
    return [
        "--tmpfs", "/config:rw,size=256m",
        "--tmpfs", "/metadata:rw,size=256m",
        "--tmpfs", "/audiobooks:rw,size=64m",
    ]


def _vikunja_runtime(base_url: str) -> list[str]:
    # SQLite and uploaded files on tmpfs owned by the image's user (1000).
    return [
        "--tmpfs", "/db:rw,size=128m,uid=1000,gid=1000",
        "--tmpfs", "/app/vikunja/files:rw,size=64m,uid=1000,gid=1000",
        "-e", "VIKUNJA_DATABASE_TYPE=sqlite",
        "-e", "VIKUNJA_DATABASE_PATH=/db/vikunja.db",
        "-e", "VIKUNJA_SERVICE_JWTSECRET=veridor-pair-not-a-real-secret",
        "-e", f"VIKUNJA_SERVICE_PUBLICURL={base_url}/",
    ]


def _bugsink_runtime(base_url: str) -> list[str]:
    # SQLite at /data (created by the image, owned by the bugsink user uid 14237;
    # the tmpfs must carry that uid/gid or the db file cannot be opened). The
    # snappea background-task queue is a separate SQLite file the image keeps on
    # its own container-local temp path. SECRET_KEY is a throwaway that only has
    # to pass Django's deploy check (>= 50 chars, several distinct characters);
    # PHONEHOME is turned off so the container makes no outbound call;
    # BASE_URL/ALLOWED_HOSTS let it answer on loopback.
    return [
        "--tmpfs", "/data:rw,size=256m,uid=14237,gid=14237",
        "-e", "SECRET_KEY=veridor-pair-bugsink-not-a-real-secret-0123456789abcdefghij",
        "-e", "PHONEHOME=False",
        "-e", f"BASE_URL={base_url}",
        "-e", "ALLOWED_HOSTS=127.0.0.1,localhost",
    ]


def _ghost_runtime(base_url: str) -> list[str]:
    # The content directory holds the sqlite db, the default themes the
    # entrypoint seeds and the image's logs; it is owned by the image's `node`
    # user (uid 1000), so the tmpfs must carry that uid/gid or Ghost cannot
    # create the db. `url` is Ghost's own setting for the site's own address:
    # the admin API refuses a session minted against another origin, so it must
    # be the loopback URL this container was published on.
    return [
        "--tmpfs", "/var/lib/ghost/content:rw,size=256m,uid=1000,gid=1000",
        "-e", f"url={base_url}",
    ]


def _datasette_runtime(base_url: str) -> list[str]:
    # serve.py writes the database and metadata to /data at startup, as the
    # image's unprivileged user. DATASETTE_SECRET signs the owner's token;
    # both `datasette serve` and `datasette create-token` read it.
    return [
        "--tmpfs", "/data:rw,size=64m,uid=65534,gid=65534",
        "-e", "DATASETTE_SECRET=veridor-pair-not-a-real-secret",
    ]


def _invoiceshelf_runtime(base_url: str) -> list[str]:
    # Single-container sqlite mode. AUTORUN_ENABLED is turned OFF: the image's
    # default entrypoint otherwise runs `migrate` (no seed) at boot, which would
    # install the schema with no admin and leave the install wizard blocked. With
    # it off the 00-setup step still creates the empty sqlite database and an
    # APP_KEY, and the provisioner drives `installation/database/config`, whose
    # `migrate --seed` creates the admin and the first company. CACHE_STORE and
    # SESSION_DRIVER are files so no cache or session table is needed before that
    # migration. The database lives on the container's own layer, which starts
    # empty from the image every run and goes with the container, so no tmpfs is
    # needed for ephemerality. `base_url` is InvoiceShelf's own APP_URL, the
    # loopback address this container was published on.
    return [
        "-e", "AUTORUN_ENABLED=false",
        "-e", "DB_CONNECTION=sqlite",
        "-e", f"DB_DATABASE={_INVOICESHELF_SQLITE}",
        "-e", "CACHE_STORE=file",
        "-e", "SESSION_DRIVER=file",
        "-e", f"APP_URL={base_url}",
    ]


def _hawkbit_runtime(base_url: str) -> list[str]:
    # The image runs embedded H2 and stores artifacts on a container-local
    # path, which goes with the container. hawkBit derives the DDI artifact URLs
    # from the request Host header, so no base URL has to be injected. /tmp is a
    # tmpfs so nothing the run writes there outlives it. base_url is unused.
    return ["--tmpfs", "/tmp:rw,size=128m"]


def _domoticz_runtime(base_url: str) -> list[str]:
    # userdata (the sqlite db, the planted parser script, logs) is a tmpfs, so
    # every run starts empty and leaves nothing behind; the image's entrypoint
    # chowns it to uid 1000, so no uid is set here. EXTRA_CMD_ARG=-nowwwpwd makes
    # loopback a trusted network at startup and seeds a bootstrap admin, which is
    # how the provisioner creates the users and the one setting before any
    # credential exists; the provisioner then clears WebLocalNetworks, which drops
    # that trust for the rest of the run. `base_url` is unused: the API is
    # same-origin and needs no external URL.
    return [
        "--tmpfs", "/opt/domoticz/userdata:rw,size=128m",
        "-e", "EXTRA_CMD_ARG=-nowwwpwd",
    ]


def _ghost6_runtime(base_url: str) -> list[str]:
    # Ghost 6's production default database is MySQL, so `_ghost_runtime`
    # (url and a tmpfs, enough for Ghost 4, whose default is sqlite) leaves a
    # 6.x image trying 127.0.0.1:3306, and it shuts down before health
    # (measured: `connect ECONNREFUSED 127.0.0.1:3306`, then "Ghost has shut
    # down"). `NODE_ENV=development` and the explicit sqlite settings make it use
    # a file database on the tmpfs instead. The tmpfs carries uid 1000 so the
    # image's `node` user can write the db; `url` is Ghost's own site address,
    # which the Admin API requires the session to be minted against.
    return [
        "--tmpfs", "/var/lib/ghost/content:rw,size=512m,uid=1000,gid=1000",
        "-e", f"url={base_url}",
        "-e", "NODE_ENV=development",
        "-e", "database__client=sqlite3",
        "-e", "database__connection__filename=/var/lib/ghost/content/data/ghost.db",
        "-e", "database__useNullAsDefault=true",
    ]


#: What `docker run` needs for an image beyond its loopback port: state on a
#: tmpfs (every run starts empty and leaves nothing behind) and whatever the
#: image reads to skip its interactive setup. Keyed by image, so a pair names
#: only its advisory, tags and provisioner.
RUNTIMES = {
    "gitea/gitea": _gitea_runtime,
    "ghcr.io/hargata/lubelogger": _lubelogger_runtime,
    "advplyr/audiobookshelf": _audiobookshelf_runtime,
    "vikunja/vikunja": _vikunja_runtime,
    "bugsink/bugsink": _bugsink_runtime,
    "ghost": _ghost_runtime,
    "veridor-pair-build/datasette": _datasette_runtime,
    "invoiceshelf/invoiceshelf": _invoiceshelf_runtime,
    "hawkbit/hawkbit-update-server": _hawkbit_runtime,
    "domoticz/domoticz": _domoticz_runtime,
    # Ghost 6 needs its own runtime (see _ghost6_runtime), so its pair names the
    # image by its canonical spelling, `library/ghost`, and this key does not
    # rebind `ghost`, which the Ghost 4 pair runs under. Docker resolves
    # `library/ghost` to the same image as `ghost`, and _repository() reads both
    # as `ghost`, so the pin is checked against the same ghost@sha256 digest:
    # the image that runs is identical, and only the runtime differs.
    "library/ghost": _ghost6_runtime,
}

PROVISIONERS = {
    "gitea": _provision_gitea,
    "gitea_private_org": _provision_gitea_private_org,
    "gitea_public_only_team": _provision_gitea_public_only_team,
    "lubelogger_supply_idor": _provision_lubelogger_supply_idor,
    "audiobookshelf": _provision_audiobookshelf,
    "vikunja_comment_idor": _provision_vikunja_comment_idor,
    "bugsink_event_cross_project": _provision_bugsink_event_cross_project,
    "ghost_integration_keys": _provision_ghost_integration_keys,
    "datasette_private_instance": _provision_datasette_private_instance,
    "invoiceshelf_user_cross_company": _provision_invoiceshelf_user_cross_company,
    "hawkbit_ddi_cross_device": _provision_hawkbit_ddi_cross_device,
    "domoticz_viewer_lua_parser": _provision_domoticz_viewer_lua_parser,
    "ghost_editor_promotes_author": _provision_ghost_editor_promotes_author,
}


# ------------------------------------------------------------------- run


def _veridor_process(
    args: list[str], *, timeout: int, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """`sys.executable *args`, the way every pair runs Veridor.

    The one place the interpreter, the environment and the working directory
    are chosen, for the pairs and for `veridor_under_test`'s probe alike: the
    probe's answer is only the pairs' answer if both ask the same interpreter,
    with the same PYTHONPATH, from the same directory (Python puts that
    directory first on sys.path). They used to build their calls separately,
    and a probe run from another directory, or pairs that kept PYTHONPATH,
    passed every test in tests/test_patched_pairs.py. `environment` is what a
    provisioner returned, added on top."""
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True, text=True, env=source_path.child_env(**(environment or {})), cwd=None,
        timeout=timeout,
    )


def _run_veridor(config_path: Path, base_url: str, output: Path, environment: dict[str, str]) -> dict[str, Any]:
    completed = _veridor_process(
        [
            "-m", "veridor.cli", "run",
            "--config", str(config_path),
            "--base-url", base_url,
            "--output-dir", str(output),
        ],
        timeout=300, environment=environment,
    )
    document: dict[str, Any] = {}
    latest = output / "latest.json"
    if latest.is_file():
        document = json.loads(latest.read_text(encoding="utf-8"))
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "document": document,
    }


#: What Docker says when the host port _free_port found was taken before
#: Docker could bind it.
PORT_TAKEN = ("address already in use", "port is already allocated")
PORT_ATTEMPTS = 3


def is_built(pair: dict[str, Any]) -> bool:
    """The pair's builds are made here from published package files, not pulled."""
    return "build" in pair


def recipe_dir(pair: dict[str, Any]) -> Path:
    """The recipe a built pair names, in the directory its fixture came from, so
    a private --pairs-dir carries its own recipes."""
    return Path(pair.get("_dir") or PAIRS_DIR) / BUILD_RECIPES / pair["build"]["recipe"]


def build_tag(pair: dict[str, Any], side: str) -> str:
    """The local tag a built side is given: the release, then a hash of every
    input the image depends on -- the base digest, the recipe's files and the
    pinned file hash. A changed input is a new tag, so an image built from an
    older recipe or pin is never reused under the same name."""
    digest = hashlib.sha256()
    digest.update(pair["build"]["base"].encode())
    digest.update(pair["build"]["package"].encode())
    digest.update(pair[side].encode())
    digest.update(pair[side + "_sha256"].encode())
    for path in sorted(recipe_dir(pair).rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(recipe_dir(pair)).as_posix().encode())
            digest.update(path.read_bytes())
    return f"{pair['image']}:{pair[side]}-{digest.hexdigest()[:16]}"


def built_pin_problems(pair: dict[str, Any], where: str) -> None:
    """Refuse a built pair that pins less than a registry pair does.

    A registry pair names both builds by digest. A built pair names what it is
    built FROM just as exactly: a base image by digest, and each side's
    published package file by its sha256. Anything looser -- a base by tag, a
    missing hash, the same hash both sides, registry digests alongside the build
    -- is refused here, before anything is built."""
    build = pair.get("build")
    if not isinstance(build, dict) or not all(isinstance(build.get(k), str) and build.get(k)
                                              for k in ("recipe", "base", "package")):
        raise PairError(f"{where}: build must name a recipe, a base and a package")
    if not RECIPE_NAME.fullmatch(build["recipe"]):
        raise PairError(f"{where}: build.recipe must be one directory name under {BUILD_RECIPES}/, "
                        f"found {build['recipe']!r}")
    if any(field in pair for _, field in SIDES):
        raise PairError(
            f"{where}: names both a build and registry digests; a pair is pinned one way, so it is not "
            "clear which build would run"
        )
    if not PINNED_BASE.fullmatch(build["base"]):
        raise PairError(
            f"{where}: build.base must name its image by digest (name@sha256:<64 hex>); found "
            f"{build['base']!r}. A base by tag builds whatever that tag names on the day"
        )
    if not str(pair.get("image", "")).startswith(BUILT_PREFIX):
        raise PairError(
            f"{where}: a built pair's image must start {BUILT_PREFIX!r}, so a built image can never shadow "
            f"one pulled from a registry; found {pair.get('image')!r}"
        )
    recipe = recipe_dir(pair)
    if not (recipe / "Dockerfile").is_file():
        raise PairError(f"{where}: no recipe at {recipe} (it must hold a Dockerfile)")
    for side, field in BUILD_SIDES:
        pinned = pair.get(field)
        if not isinstance(pinned, str) or not FILE_HASH.fullmatch(pinned):
            raise PairError(
                f"{where}: {field} must be the sha256 of {build['package']} {pair.get(side)}'s published file, "
                f"64 lowercase hex; found {pinned!r}"
            )
    if pair["vulnerable_sha256"] == pair["patched_sha256"]:
        raise PairError(f"{where}: vulnerable_sha256 and patched_sha256 are one file, so the pair would compare "
                        "a build with itself")


def run_ref(pair: dict[str, Any], side: str) -> str:
    """What `docker run` is given for one side: `image:tag@digest`, or for a
    built pair the local tag :func:`build_tag` names.

    The digest is what runs. Docker resolves it and ignores the tag: measured,
    `docker image inspect gitea/gitea:1.26.4@<1.27.0's digest>` answers with
    the 1.27.0 image and no error. So the tag here is for a reader, and
    `check_local_tags` is what compares tag and pin where both are present."""
    if is_built(pair):
        return build_tag(pair, side)
    return f"{pair['image']}:{pair[side]}@{pair[side + '_digest']}"


def pin_of(pair: dict[str, Any], side: str) -> str:
    """What pins one side: its image digest, or a built side's file sha256."""
    return pair[side + ("_sha256" if is_built(pair) else "_digest")]


def pull_ref(pair: dict[str, Any], side: str) -> str:
    """What `docker pull` is given for one side under --pull: `image@digest`,
    or for a built pair its pinned base, which is all that can be pulled."""
    if is_built(pair):
        return pair["build"]["base"]
    return f"{pair['image']}@{pair[side + '_digest']}"


def build_side(pair: dict[str, Any], side: str) -> str:
    """Build one side of a built pair and prove, from inside the image, that it
    holds the release the fixture names. Returns the tag.

    The recipe installs the published file by its hash (pip --require-hashes),
    so a file that is not the pinned one is refused while building. The check
    afterwards asks the image which release it holds: a recipe that ignored its
    arguments, or installed from somewhere else, would otherwise build and run
    a pair against the wrong code with every other assertion green."""
    tag = build_tag(pair, side)
    build = pair["build"]
    _docker(
        "build", "--quiet", "--tag", tag,
        "--build-arg", f"BASE={build['base']}",
        "--build-arg", f"PACKAGE={build['package']}",
        "--build-arg", f"VERSION={pair[side]}",
        "--build-arg", f"SHA256={pair[side + '_sha256']}",
        str(recipe_dir(pair)),
    )
    probe = _docker(
        "run", "--rm", "--network", "none", "--entrypoint", "python", tag,
        "-c", PYTHON_VERSION_PROBE, build["package"], pair[side], check=False,
    )
    held = (probe.stdout or "").strip()
    if probe.returncode != 0 or held != pair[side]:
        raise PairError(
            f"{pair['name']}: the {side} build {tag} holds {build['package']} {held or '(none found)'}, "
            f"not {pair[side]}: {(probe.stderr or '').strip()[-200:]}"
        )
    return tag


def _start(pair: dict[str, Any], side: str, container: str) -> str:
    """`docker run` the build on a free loopback port and return its URL.

    _free_port releases the port it found, and the runtime needs the URL
    before the container exists, so another process can take the port in
    between. Measured once in the publication gate: Jellyfin's `docker run`
    exited 125, and the daemon's log gave the reason, "failed to bind host port
    127.0.0.1:58475/tcp: address already in use". Only that answer is retried,
    on a fresh port; the container was created before the bind failed, so it
    is removed first. Any other failure is raised at once.
    """
    for attempt in range(1, PORT_ATTEMPTS + 1):
        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        _docker("rm", "-f", container, check=False)
        try:
            _docker(
                "run", "-d", "--name", container,
                # Loopback only. This stands up a KNOWN-VULNERABLE build; it
                # must not be reachable from anywhere but this machine.
                "-p", f"127.0.0.1:{port}:{pair['container_port']}",
                *RUNTIMES[pair["image"]](base_url),
                run_ref(pair, side),
            )
            return base_url
        except PairError as error:
            if attempt == PORT_ATTEMPTS or not any(taken in str(error) for taken in PORT_TAKEN):
                raise
    raise AssertionError("unreachable")


def _evaluate_build(pair: dict[str, Any], side: str, workdir: Path) -> dict[str, Any]:
    """Stand one side up, run the pair against it, and remove the container.

    The removal runs however the pair ended, and never replaces the reason it
    ended. It used to be a `finally` of `docker stop` then `docker rm -f`: a
    stop that hung past the timeout raised from the `finally`, which dropped
    the pair's own error in favour of the stop's and never reached `rm -f`,
    leaving a known-vulnerable build running on loopback (measured with a
    docker that sleeps on `stop` and the timeout cut to a second)."""
    tag = pair[side]
    container = f"veridor-pair-{os.getpid()}-{tag.replace('.', '-')}"
    try:
        result = _run_build(pair, side, container, workdir)
    except BaseException as error:
        for problem in _remove_container(container)[1]:
            error.add_note(f"and removing {container}: {problem}")
        raise
    removed, problems = _remove_container(container)
    if not removed:
        raise PairError(f"{container} may still be running, a known-vulnerable build on loopback: "
                        + "; ".join(problems))
    return result


def _remove_container(container: str) -> tuple[bool, list[str]]:
    """`docker stop`, then `docker rm -f` whatever the stop did: (removed, what went wrong).

    A stop that failed or hung is reported but does not decide `removed`;
    `rm -f` kills a running container. A container that does not exist counts
    as removed: docker 29 exits 0 for one and prints "No such container"
    (measured), and that answer is accepted with a non-zero exit too."""
    problems = []
    try:
        stopped = _docker("stop", "-t", DOCKER_STOP_TIMEOUT, container, check=False)
    except (PairError, subprocess.SubprocessError, OSError) as error:
        problems.append(f"docker stop: {type(error).__name__}: {error}")
    else:
        if stopped.returncode != 0 and "no such container" not in (stopped.stderr or "").lower():
            problems.append(f"docker stop exited {stopped.returncode}: {(stopped.stderr or '').strip()[-200:]}")
    try:
        removed = _docker("rm", "-f", container, check=False)
    except (PairError, subprocess.SubprocessError, OSError) as error:
        problems.append(f"docker rm -f: {type(error).__name__}: {error}")
        return False, problems
    if removed.returncode != 0 and "no such container" not in (removed.stderr or "").lower():
        problems.append(f"docker rm -f exited {removed.returncode}: {(removed.stderr or '').strip()[-200:]}")
        return False, problems
    return True, problems


def _run_build(pair: dict[str, Any], side: str, container: str, workdir: Path) -> dict[str, Any]:
    tag = pair[side]
    base_url = _start(pair, side, container)
    _wait_healthy(base_url, pair["health_path"])
    environment = PROVISIONERS[pair["provision"]](container, base_url, pair["marker"])

    config = json.loads(json.dumps(pair["config"]))
    config["target"]["base_url"] = base_url
    config_path = workdir / f"veridor-{tag}.json"
    config_path.write_text(json.dumps(config, indent=1), encoding="utf-8")

    result = _run_veridor(config_path, base_url, workdir / f"out-{tag}", environment)
    if side == "patched":
        # While the build is up: what a credential nobody issued draws on each
        # denial the patched build must hold. See unproven_denials.
        result["fabricated"] = _fabricated_controls(pair["config"], base_url, environment)

    # The "green because gone" control, asked directly rather than inferred
    # from the run. Each pair names the path a legitimately-entitled
    # identity should still be served, because a fix that deletes the route
    # would otherwise look identical to a fix that adds a check.
    control = pair["control"]
    path = _interpolate(control["path"], environment)
    # The owner authenticates the way the application does. `token` is
    # gitea's `Authorization: token <value>`; `headers` is anything else
    # (a Bearer JWT, X-Api-Key, an HTTP Basic credential), filled from the
    # provisioner's values. Before `headers` existed, every application
    # that did not speak gitea's scheme was out of reach: its owner probe
    # was refused on the patched build, and the pair read as "endpoint gone".
    if "headers" in control:
        headers = {name: _interpolate(value, environment) for name, value in control["headers"].items()}
        control_status, control_body = _http(f"{base_url}{path}", headers=headers)
    else:
        control_status, control_body = _http(
            f"{base_url}{path}", token=environment[control["token"]]
        )
    result["endpoint_present"] = control_status == control.get("status", 200)
    # None, not True, when the pair's control asks for no marker: the check
    # was not made, and evaluate() reports it as not evaluated.
    result["marker_reachable_by_owner"] = (
        pair["marker"] in control_body if control.get("expect_marker", True) else None
    )
    return result


def _interpolate(template: str, environment: dict[str, str]) -> str:
    """Fill ${NAME} from what the provisioner returned. An unresolved name is
    refused rather than sent literally; the message names the template, never
    the filled-in text, which may hold a credential."""
    text = template
    for key, value in environment.items():
        text = text.replace(f"${{{key}}}", value)
    if "${" in text:
        raise PairError(
            f"unresolved placeholder in {template!r}; the provisioner returned {sorted(environment)}"
        )
    return text


def _findings(document: dict[str, Any]) -> list[dict[str, Any]]:
    return document.get("findings") or []


#: The statuses that are a refusal and nothing else, as Veridor reads them
#: (`DENIAL_ONLY_STATUSES` in veridor/core.py). An expectation that accepts
#: only these holds for a dead credential exactly as for a working boundary.
DENIAL_ONLY_STATUSES = frozenset({401, 403, 404, 405, 407})
#: The methods a fabricated credential is sent on. A write is never replayed.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: A provisioned value in an identity's header template.
PLACEHOLDER = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def _denial_only(expectation: Any) -> bool:
    if isinstance(expectation, str):
        return expectation == "deny"
    statuses = expectation.get("status") if isinstance(expectation, dict) else None
    return bool(statuses) and all(status in DENIAL_ONLY_STATUSES for status in statuses)


def _presents_credential(identity: Any) -> bool:
    """An identity that sends nothing has no credential to be dead; its
    refusal is the boundary working, whatever a fabricated one draws."""
    return isinstance(identity, dict) and (bool(identity.get("headers")) or "session" in identity)


def _fabricated_controls(config: dict[str, Any], base_url: str, environment: dict[str, str]) -> list[dict[str, Any]]:
    """For each denial-only expectation of a credentialed identity, the same
    request with that identity's own headers, every provisioned value in them
    replaced by one minted here that nobody issued.

    The identity's own templates, not Veridor's construction (which sends the
    bare token as the whole header value), so a sham cookie keeps its cookie
    name and a sham bearer its scheme: the only difference from the real
    request is the credential. One request per distinct (method, path,
    headers). Never on a write, and never for an identity with no header to
    fabricate (a `session` login): those get an entry with no status, and
    unproven_denials fails them unless they were served."""
    token = f"veridor-pair-sham-{secrets.token_hex(8)}"
    answered: dict[tuple[Any, ...], dict[str, Any]] = {}
    controls = []
    for check in config.get("checks") or ():
        request = check.get("request") or {}
        method = str(request.get("method", "GET")).upper()
        for name, expectation in (check.get("expect") or {}).items():
            identity = (config.get("identities") or {}).get(name)
            if not _denial_only(expectation) or not _presents_credential(identity):
                continue
            entry: dict[str, Any] = {"check_id": check.get("id"), "identity": name, "method": method}
            templates = identity.get("headers") or {}
            if method not in SAFE_METHODS:
                controls.append({**entry, "status": None, "error": f"{method} is a write; no fabricated credential is sent on one"})
                continue
            if not any(PLACEHOLDER.search(value) for value in templates.values()):
                controls.append({**entry, "status": None, "error": "no provisioned header value to fabricate"})
                continue
            headers = {header: _interpolate(value, environment)
                       for header, value in (request.get("headers") or {}).items()}
            headers.update({header: PLACEHOLDER.sub(token, value) for header, value in templates.items()})
            path = _interpolate(str(request.get("path", "")), environment)
            key = (method, path, tuple(sorted(headers.items())))
            if key not in answered:
                try:
                    status, _ = _http(f"{base_url}{path}", method=method, headers=headers)
                    answered[key] = {"status": status}
                except (OSError, http.client.HTTPException) as error:
                    answered[key] = {"status": None, "error": f"{type(error).__name__}: {error}"[:200]}
            controls.append({**entry, **answered[key]})
    return controls


#: Proxy Authentication Required: a proxy's answer before the request reached
#: the application. A denial for grading, but never the application telling
#: two credentials apart.
_PROXY_REFUSAL = 407


def _tells_a_credential_apart(status: int) -> bool:
    """Whether a fabricated credential's answer, when it differs from the
    identity's, shows the application told the two credentials apart: a
    refusal (DENIAL_ONLY_STATUSES other than 407) or a 2xx/3xx. A 429, a 5xx
    or a 400 is a rate limiter, a server error or a parser answering, and the
    sham is sent after Veridor's whole run, when a limiter is most likely to
    trip. A 407 is a proxy's, and the set was taken whole, so a proxy refusing
    the sham certified a dead credential behind it."""
    if status == _PROXY_REFUSAL:
        return False
    return status in DENIAL_ONLY_STATUSES or 200 <= status <= 399


def unproven_denials(pair: dict[str, Any], build: dict[str, Any]) -> list[str]:
    """The patched build's denials that no evidence ties to a live credential,
    one line each naming the identity and check.

    For each expectation that accepts only a denial from an identity that
    presents a credential, one of two things must hold: the identity was
    served a 2xx on some check of this run (the document's `probes`), or the
    fabricated-credential request on the same check (`build["fabricated"]`)
    drew a status different from the identity's that is a refusal or a
    2xx/3xx. Absent evidence fails: no probe for the identity, an identity
    whose own request drew a proxy's 407 (it never reached the application,
    so nothing can be compared with it, and being served on another check
    does not change that), no fabricated request, one that
    errored, or one that drew a proxy's 407, a 429, a 5xx, a 400 or any other
    status that is neither a refusal nor a success.
    Veridor's own `liveness.unproven` entries are added for any pair of
    identity and check not already named."""
    config = pair["config"]
    document = build.get("document") or {}
    probes = document.get("probes") or []
    served = {probe.get("identity") for probe in probes
              if isinstance((probe.get("response") or {}).get("status"), int)
              and 200 <= probe["response"]["status"] <= 299}
    statuses = {(probe.get("check_id"), probe.get("identity")): (probe.get("response") or {}).get("status")
                for probe in probes}
    fabricated = {(entry.get("check_id"), entry.get("identity")): entry
                  for entry in build.get("fabricated") or ()}
    problems: dict[tuple[Any, Any], str] = {}
    for check in config.get("checks") or ():
        for name, expectation in (check.get("expect") or {}).items():
            if (not _denial_only(expectation)
                    or not _presents_credential((config.get("identities") or {}).get(name))):
                continue
            key = (check.get("id"), name)
            status = statuses.get(key)
            # Before the `served` skip: an identity served a 2xx on another
            # check is live there, but this request never reached the
            # application, so its 407 is a proxy's answer and no denial. The
            # skip ran first, and accepted it.
            if status != _PROXY_REFUSAL and name in served:
                continue
            if not isinstance(status, int):
                problems[key] = f"{name}: {check.get('id')}; no answer to this identity in the run, so nothing shows its credential live"
                continue
            if status == _PROXY_REFUSAL:
                # The identity's own request never reached the application, so
                # no sham can be compared with it: a sham's 403 differed from
                # this 407 and certified a dead credential behind the proxy.
                problems[key] = (f"{name}: {check.get('id')} (HTTP {status}); the identity's own request "
                                 "drew HTTP 407, a proxy's answer before the request reached the "
                                 "application, so nothing shows its credential live")
                continue
            where = f"{name}: {check.get('id')} (HTTP {status}); never served in the run, and "
            control = fabricated.get(key)
            if control is None:
                problems[key] = where + "no fabricated-credential request was made on it"
            elif not isinstance(control.get("status"), int):
                problems[key] = where + f"the fabricated-credential request did not answer ({control.get('error')})"
            elif control["status"] == status:
                problems[key] = where + f"a fabricated credential drew HTTP {status} too"
            elif control["status"] == _PROXY_REFUSAL:
                problems[key] = where + ("the fabricated-credential request drew HTTP 407, a proxy's answer "
                                         "before the request reached the application, which shows nothing "
                                         "about the credential")
            elif not _tells_a_credential_apart(control["status"]):
                problems[key] = where + (f"the fabricated-credential request drew HTTP {control['status']}, neither "
                                         "a refusal nor a success, which shows nothing about the credential")
    for entry in (document.get("liveness") or {}).get("unproven") or ():
        key = (entry.get("check_id"), entry.get("identity"))
        problems.setdefault(key, f"{entry.get('identity')}: {entry.get('check_id')} (HTTP {entry.get('status')}); "
                                 "Veridor's own fabricated credential drew the same answer (liveness.unproven)")
    return list(problems.values())


def failing_checks(pair: dict[str, Any], where: str | None = None) -> list[str]:
    """The checks whose findings the vulnerable build must produce, sorted:
    `vulnerable_failing_checks`, or the one check of a one-check pair. Every
    other check must pass there. Refused, naming ``where``, when a pair with
    more than one check does not say, or names a check its config lacks."""
    where = where or pair.get("_file") or pair.get("name")
    checks = [check.get("id") for check in (pair.get("config") or {}).get("checks") or []]
    declared = pair.get("vulnerable_failing_checks")
    if declared is None:
        if len(checks) != 1:
            raise PairError(
                f"{where}: {len(checks)} checks and no vulnerable_failing_checks. Name the checks the vulnerable "
                "build must fail; the others must pass there, or a leak through any of them passes the pair."
            )
        return checks
    if (not isinstance(declared, list) or not declared or len(set(declared)) != len(declared)
            or not set(declared) <= set(checks)):
        raise PairError(f"{where}: vulnerable_failing_checks must list distinct check ids from {checks}; "
                        f"found {declared!r}")
    return sorted(declared)


def evaluate(pair: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        workdir = Path(directory)
        vulnerable = _evaluate_build(pair, "vulnerable", workdir)
        patched = _evaluate_build(pair, "patched", workdir)

    vulnerable_findings = _findings(vulnerable["document"])
    # The grade a pair can reach is a property of the BUG, not of the tool. A
    # status-only differential -- no marker anywhere, nothing to plant -- can
    # never be graded `confirmed`, and holding it to that would either drop the
    # pair or, worse, invite someone to relax the assertion for the pairs that
    # can meet it. Each pair declares what it should reach and is held to that.
    expected_grade = pair.get("expected_evidence", "confirmed")
    graded = [
        finding for finding in vulnerable_findings
        if finding.get("evidence_grade") == expected_grade
    ]
    patched_findings = _findings(patched["document"])
    failing = sorted({str(finding.get("check_id")) for finding in vulnerable_findings})
    # The grade is held per declared check, not once per pair: one confirmed
    # finding among them used to pass a pair whose other declared check had
    # fallen to `suspected` or `ungraded` (measured on the Ghost pair's two).
    below_grade = sorted(set(failing_checks(pair))
                         - {str(finding.get("check_id")) for finding in graded})
    # A denial on the patched build is the fix only if the attacker's
    # credential is live. Veridor's liveness.unproven alone missed it: Veridor
    # records nothing there when no identity is served on the check, or when
    # its control errored, so a dead Vikunja attacker drawing the 404 a
    # fabricated token draws passed (reproduced on loopback stubs). The harness
    # decides it from the run's probes and its own fabricated request.
    patched_liveness = patched["document"].get("liveness") or {}
    patched_unproven = unproven_denials(pair, patched)

    checks = {
        "vulnerable_build_fails": vulnerable["exit_code"] == 1,
        f"vulnerable_evidence_{expected_grade}": bool(graded) and not below_grade,
        # Which checks failed, not only that one did: each declared check,
        # and no other.
        "vulnerable_fails_exactly_the_declared_checks": failing == failing_checks(pair),
        "patched_build_passes": patched["exit_code"] == 0 and not patched_findings,
        # Veridor's liveness controls off, or a document without them, still
        # fails: a run that skipped them is not the run this harness certifies.
        "patched_denials_reach_a_live_credential": patched_liveness.get("enabled") is True and not patched_unproven,
        # Without this a removed route reads as a fix.
        "endpoint_survives_the_fix": patched["endpoint_present"],
    }
    # A pair whose control sets expect_marker false never asks for the marker.
    # Its result used to carry this check as true, printed `ok` and passed in
    # --json for the four status-only pairs; a check nobody made is named as
    # not evaluated instead, and is not one of the checks `passed` rests on.
    not_evaluated = {}
    if pair["control"].get("expect_marker", True):
        checks["marker_still_reachable_by_owner"] = patched["marker_reachable_by_owner"] is True
    else:
        not_evaluated["marker_still_reachable_by_owner"] = (
            "the pair's control sets expect_marker false: the owner's control is held to its status only"
        )
    return {
        "name": pair["name"],
        "advisory": pair["advisory"],
        "image": pair["image"],
        "vulnerable_tag": pair["vulnerable"],
        "patched_tag": pair["patched"],
        "vulnerable_image": run_ref(pair, "vulnerable"),
        "patched_image": run_ref(pair, "patched"),
        # What each side is pinned by: the image digest, or for a built pair
        # the published package file's sha256 and the base it was built on.
        "vulnerable_pin": pin_of(pair, "vulnerable"),
        "patched_pin": pin_of(pair, "patched"),
        "built_from": pair["build"] if is_built(pair) else None,
        "checks": checks,
        "not_evaluated": not_evaluated,
        "passed": all(checks.values()),
        "vulnerable": {
            "exit_code": vulnerable["exit_code"],
            "findings": len(vulnerable_findings),
            "failing_checks": failing,
            "graded": len(graded),
            "expected_grade": expected_grade,
            "below_grade": below_grade,
            "message": (graded or vulnerable_findings or [{}])[0].get("message", "")[:400],
        },
        "patched": {
            "exit_code": patched["exit_code"],
            "findings": len(patched_findings),
            "endpoint_present": patched["endpoint_present"],
            "unproven": patched_unproven,
        },
    }




# -------------------------------------------------------------- selection


#: The file a pairs directory may carry to teach the harness about its own
#: images and applications. It is imported, so a directory named here runs its
#: code: name only a directory you own. `register(runtimes, provisioners)` is
#: called with the two tables, and may only ADD to them -- a directory that
#: rebound an existing key could silently replace a shipped provisioner with
#: one that manufactures a passing verdict.
EXTENSION = "provisioners.py"

#: The same list as --pairs-dir, for a gate that sets it once for every run.
PAIRS_DIR_ENV = "VERIDOR_PAIRS_DIR"


def pair_directories(extra: list[str] | None = None) -> list[Path]:
    """Where pairs are read from: the shipped fixtures, then any `--pairs-dir`.

    A published advisory's pair belongs in fixtures/pairs/ and runs in CI. An
    organisation's own findings, whose details are not public, cannot: a fixture
    describes the bug, so publishing one discloses it. Such pairs live in a
    directory of their own, outside the repository, and are named here.
    """
    directories = [PAIRS_DIR]
    for name in (extra or []):
        path = Path(name).expanduser()
        if not path.is_dir():
            raise PairError(f"--pairs-dir {name}: not a directory")
        resolved = path.resolve()
        if resolved not in {d.resolve() for d in directories}:
            directories.append(resolved)
    return directories


def load_extension(directory: Path) -> list[str]:
    """Import `<directory>/provisioners.py` and let it add runtimes and
    provisioners. Returns what it added, so the run can say so."""
    module_path = directory / EXTENSION
    if not module_path.is_file():
        return []
    spec = importlib.util.spec_from_file_location(f"veridor_pairs_{abs(hash(str(directory)))}", module_path)
    if spec is None or spec.loader is None:
        raise PairError(f"{module_path}: could not be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register = getattr(module, "register", None)
    if not callable(register):
        raise PairError(f"{module_path}: must define register(runtimes, provisioners)")
    runtimes, provisioners = dict(RUNTIMES), dict(PROVISIONERS)
    register(runtimes, provisioners)
    added = []
    for table, fresh, label in ((RUNTIMES, runtimes, "runtime"), (PROVISIONERS, provisioners, "provisioner")):
        for key, value in fresh.items():
            if key in table and table[key] is not value:
                raise PairError(
                    f"{module_path}: rebinds the {label} {key!r}, which this harness already ships. An extension "
                    "may only add: rebinding one could replace a shipped provisioner with one that passes."
                )
            if key not in table:
                table[key] = value
                added.append(f"{label} {key}")
    return added


def load_pairs(only: str | None = None, *, extra_dirs: list[str] | None = None) -> list[dict[str, Any]]:
    """Every pair in every pairs directory, checked, or only the one `only` names.

    Everything is refused here, before any container starts, rather than as a
    KeyError halfway through the vulnerable build. That includes a pair not
    pinned by digest: it would run whatever its tag names on the day it is
    pulled, and ImagePinningTest never read the fixtures, only the workflows.
    """
    pairs = []
    directories = pair_directories(extra_dirs)
    for directory in directories:
        load_extension(directory)
    seen: dict[str, Path] = {}
    for directory in directories:
        for path in sorted(directory.glob("*.json")):
            pair = json.loads(path.read_text(encoding="utf-8"))
            if "heavy" in pair:
                # Refused whatever its value: `"heavy": false` would read as a
                # choice someone still gets to make.
                raise PairError(
                    f'{path.name}: "heavy" is not a fixture field any more. Every pair runs everywhere: on every pull '
                    "request, every push to main and every release. Remove the key; a pair too large for that is "
                    "replaced by a smaller one for the same bug, not skipped."
                )
            if pair.get("image") not in RUNTIMES:
                raise PairError(f"{path.name}: no runtime for image {pair.get('image')!r} (RUNTIMES)")
            if pair.get("provision") not in PROVISIONERS:
                raise PairError(f"{path.name}: no provisioner {pair.get('provision')!r} (PROVISIONERS)")
            if ("token" in pair.get("control", {})) == ("headers" in pair.get("control", {})):
                raise PairError(f"{path.name}: control names exactly one of `token` or `headers`")
            if is_built(pair):
                pair["_dir"] = str(directory)
                built_pin_problems(pair, path.name)
            else:
                if any(field in pair for _, field in BUILD_SIDES):
                    raise PairError(
                        f"{path.name}: names a package file hash (*_sha256) but no build block, so nothing would "
                        "build from it; a registry pair is pinned by vulnerable_digest and patched_digest"
                    )
                for side, field in SIDES:
                    digest = pair.get(field)
                    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                        raise PairError(
                            f"{path.name}: {field} must be the registry digest of {pair.get('image')}:"
                            f"{pair.get(side)}, sha256:<64 lowercase hex>; found {digest!r}. Without it the pair "
                            "runs whatever that tag names on the day it is pulled."
                        )
                if pair["vulnerable_digest"] == pair["patched_digest"]:
                    raise PairError(
                        f"{path.name}: vulnerable_digest and patched_digest are one image, so the pair would "
                        "compare a build with itself"
                    )
            failing_checks(pair, path.name)
            # One name, one pair, across every directory: two pairs of the same
            # name would make --pair NAME ambiguous, and a private directory could
            # shadow a shipped pair, which would drop a published advisory from the run
            # while the output still named it.
            if pair["name"] in seen:
                raise PairError(f"{path}: the pair name {pair['name']!r} is already used by {seen[pair['name']]}")
            seen[pair["name"]] = path
            pair["_file"] = path.name
            pair["_dir"] = str(directory)
            pair["_shipped"] = directory.resolve() == PAIRS_DIR.resolve()
            pairs.append(pair)
    if not pairs:
        raise PairError("no pair in " + ", ".join(str(d) for d in directories))
    if only is None:
        return pairs
    return select_pairs(pairs, only=only)[0]


def _names(pair: dict[str, Any], only: str) -> bool:
    return only in (pair["name"], Path(pair.get("_file", "")).stem)


def select_pairs(
    pairs: list[dict[str, Any]], *, only: str | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """(the pairs to run, every pair left out and why).

    Every pair, unless `only` names one. An empty selection raises instead of
    returning: a run of nothing exits 0, and a job that runs nothing would read
    as a detection baseline that held.
    """
    if only is not None and not any(_names(pair, only) for pair in pairs):
        raise PairError(f"no pair matched {only!r} in {PAIRS_DIR}, and a run of nothing is not a pass, "
                        "so nothing was run")
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for pair in pairs:
        if only is None or _names(pair, only):
            selected.append(pair)
        else:
            skipped.append({"name": pair["name"], "reason": f"--pair {only} names another pair"})
    if not selected:
        raise PairError("the selection holds no pair, and a run of nothing is not a pass, so nothing was run")
    return selected, skipped


# ------------------------------------------------------ what runs, and how


def veridor_under_test_decision(
    mode: str, returncode: int, stdout: str, stderr: str, *,
    python: str = sys.executable, src: Path = SRC,
) -> tuple[str | None, str | None]:
    """(the veridor package the pairs will run, or why the run must not start).

    The answer to `UNDER_TEST_PROBE`, asked through `_veridor_process`, so it
    is what the pairs will import. Kept pure so the rule is tested without an
    interpreter to break. Installed mode used to say nothing about it. With no
    veridor installed it still stood up both builds and reported a detection
    failure, with `vulnerable_build_fails` marked ok: Python's own "No module
    named veridor" exits 1, the code a finding exits with (measured on the
    vikunja pair). An editable install would have tested src/ while the job
    said it tested the package.

    Installed mode then accepted anything outside src/. The probe printed
    `veridor.__file__`, which is None for a bare `veridor/` directory in the
    working directory (a namespace package); that read as the working
    directory, and the pairs failed on "No module named veridor.cli" with
    `vulnerable_build_fails` marked ok again (measured). A copy of the package
    in the working directory was tested in place of the wheel. So the probe
    now imports the module the pairs run, and installed mode accepts it only
    when an installed distribution's RECORD lists that file.
    """
    source = Path(os.path.realpath(src))
    if returncode != 0:
        lines = [line for line in stderr.strip().splitlines() if line.strip()]
        why = lines[-1].strip() if lines else f"exit {returncode}, no output"
        advice = "Install the wheel into that interpreter, or run this with one that has it. " if mode == "installed" else ""
        return None, f"VERIDOR_TEST_AGAINST={mode}, and {python} cannot import veridor ({why}). {advice}Nothing was run."
    printed = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not printed:
        return None, f"VERIDOR_TEST_AGAINST={mode}: {python} imported veridor and printed no path. Nothing was run."
    try:
        answer = json.loads(printed[-1])
    except ValueError:
        answer = None
    if not (isinstance(answer, dict) and set(answer) == {"module", "installed"}
            and isinstance(answer["installed"], bool)
            and (answer["module"] is None or isinstance(answer["module"], str))):
        return None, (f"VERIDOR_TEST_AGAINST={mode}: {python} printed {printed[-1][:200]!r}, not the probe's answer. "
                      "Nothing was run.")
    if not answer["module"]:
        return None, f"VERIDOR_TEST_AGAINST={mode}: {python} imported veridor.cli from no file. Nothing was run."
    package = Path(os.path.realpath(answer["module"])).parent
    inside = package.is_relative_to(source)
    if mode == "installed" and inside:
        return None, (
            f"VERIDOR_TEST_AGAINST=installed, but {python} imports veridor from {package}, inside this checkout's "
            f"{source} (an editable install, or a working directory that shadows the package). The pairs would "
            "test the checkout, not the package. Nothing was run."
        )
    if mode == "installed" and not answer["installed"]:
        return None, (
            f"VERIDOR_TEST_AGAINST=installed, but {python} imports veridor from {package}, and no installed "
            "distribution's RECORD lists it (a copy on sys.path, or a directory in the working directory that "
            "shadows the package). The pairs would not test an installed package. Nothing was run."
        )
    if mode != "installed" and not inside:
        return None, (
            f"VERIDOR_TEST_AGAINST={mode}, but {python} imports veridor from {package}, not from {source}. "
            "Nothing was run."
        )
    return str(package), None


def veridor_under_test() -> tuple[str | None, str | None]:
    """Ask the interpreter the pairs run under which veridor it imports."""
    try:
        completed = _veridor_process(["-c", UNDER_TEST_PROBE], timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"could not ask {sys.executable} which veridor it imports: {type(error).__name__}: {error}"
    return veridor_under_test_decision(source_path.MODE, completed.returncode, completed.stdout, completed.stderr)


def docker_on_path() -> bool:
    return shutil.which("docker") is not None


def _repository(name: str) -> str:
    """A Docker Hub repository however a daemon spells it."""
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name.removeprefix("library/")


def local_tag_status(
    image: str, tag: str, digest: str, returncode: int, stdout: str, stderr: str
) -> tuple[str, str | None]:
    """How this Docker's `image:tag` compares with the pin: (status, problem).

    Given `docker image inspect --format '{{json .RepoDigests}}' image:tag`'s
    answer. "match" and "absent" carry no problem; "moved" and "error" do.
    "absent" is not a pass, it is cannot-see: nothing here holds that tag, and
    the run pulls and runs the digest alone. On a fresh CI runner that is every
    image, so there the pin is enforced by Docker's digest check, and nothing
    here can say whether the tag has moved upstream since.
    """
    ref = f"{image}:{tag}"
    if returncode != 0:
        if "no such image" in stderr.lower():
            return "absent", None
        return "error", f"docker image inspect {ref} exited {returncode}: {stderr.strip()[-300:] or '(no stderr)'}"
    try:
        digests = json.loads(stdout)
    except ValueError:
        digests = None
    if not isinstance(digests, list):
        return "error", f"docker image inspect {ref} printed {stdout.strip()[:200]!r}, not a list of RepoDigests"
    for entry in digests:
        name, _, found = str(entry).rpartition("@")
        if found == digest and _repository(name) == _repository(image):
            return "match", None
    held = ", ".join(str(entry) for entry in digests) or "an image with no registry digest (built or loaded here)"
    return "moved", (
        f"{ref} on this Docker is {held}, but the fixture pins {digest}. The tag was re-pushed upstream after "
        "the pin was taken, or this copy came from somewhere else. Find out which, then re-pin the fixture or "
        "remove the local tag."
    )


def check_local_tags(pairs: list[dict[str, Any]]) -> tuple[dict[str, int], list[tuple[str, str]]]:
    """Every tag the selection names that this Docker holds, against its pin:
    (how many matched or are not held here, every (status, problem) that
    stops the run). The status says which kind: "moved" or "error"."""
    counts = {"match": 0, "absent": 0}
    problems = []
    # A built pair has no registry tag to compare: its pins are checked by
    # built_pin_problems at load and by build_side, from inside the image.
    wanted = sorted({(pair["image"], pair[side], pair[field])
                     for pair in pairs if not is_built(pair) for side, field in SIDES})
    for image, tag, digest in wanted:
        completed = _docker("image", "inspect", "--format", "{{json .RepoDigests}}", f"{image}:{tag}", check=False)
        status, problem = local_tag_status(image, tag, digest, completed.returncode, completed.stdout, completed.stderr)
        if problem:
            problems.append((status, problem))
        else:
            counts[status] += 1
    return counts, problems


#: The last line of a run check_local_tags stopped, by what stopped it. Both
#: used to end "A pinned tag no longer names the pinned build", including a
#: run whose only problem was a docker daemon it could not reach.
LOCAL_TAG_SUMMARY = {
    "moved": "A pinned tag no longer names the pinned build, so nothing was run.",
    "error": "Docker could not say which build a pinned tag names here, so nothing was run.",
}


def _describe(error: BaseException) -> str:
    """An error as a pair reports it, with any note added on the way out
    (a container that could not be removed, say)."""
    notes = "".join(f"; {note}" for note in getattr(error, "__notes__", ()))
    return f"{type(error).__name__}: {error}{notes}"


def _pull_one(ref: str) -> tuple[bool, str]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["docker", "pull", "--quiet", ref], capture_output=True, text=True, timeout=PULL_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        return False, f"docker pull gave no answer in {PULL_TIMEOUT_SECONDS}s"
    except OSError as error:
        return False, f"docker pull could not start: {error}"
    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout or "").strip()[-400:]
        return False, f"docker pull exited {completed.returncode}: {reason or '(no output)'}"
    return True, f"{time.monotonic() - started:.1f}s"


def pull_images(refs: list[str], say: Callable[[str], None]) -> list[dict[str, Any]]:
    """`docker pull` each ref, at most PULL_CONCURRENCY at once, saying how each went.

    A failure is recorded, not raised: it fails the pairs that need that image,
    with Docker's reason, and every other pair still runs.
    """
    outcomes = []
    with ThreadPoolExecutor(max_workers=PULL_CONCURRENCY) as pool:
        futures = {pool.submit(_pull_one, ref): ref for ref in refs}
        for future in as_completed(futures):
            ref = futures[future]
            try:
                pulled, detail = future.result()
            except Exception as error:  # noqa: BLE001 -- a failure must still name its image
                pulled, detail = False, f"{type(error).__name__}: {error}"
            say(f"{'pulled' if pulled else 'FAILED':6s}  {ref}  ({detail})")
            outcomes.append({"image": ref, "pulled": pulled, "detail": detail})
    return sorted(outcomes, key=lambda outcome: outcome["image"])


# -------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", help="run only this pair (name or filename stem); CI and the release run every pair")
    parser.add_argument("--pull", action="store_true",
                        help=f"docker pull every image the selection needs, by digest, at most {PULL_CONCURRENCY} "
                             "at once, before evaluating")
    parser.add_argument("--pairs-dir", action="append", metavar="DIR", default=None,
                        help="also run the pairs in DIR (repeatable). For findings whose details are not public: "
                             f"a fixture describes the bug, so it cannot ship here. A {EXTENSION} in DIR is "
                             "imported and may ADD runtimes and provisioners, so name only a directory you own. "
                             f"Also read from {PAIRS_DIR_ENV} (os.pathsep-separated)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON (progress goes to stderr)")
    args = parser.parse_args(argv)
    extra = list(args.pairs_dir or [])
    from_env = os.environ.get(PAIRS_DIR_ENV, "")
    extra += [part for part in from_env.split(os.pathsep) if part]
    stream = sys.stderr if args.json else sys.stdout

    def say(text: str) -> None:
        print(text, file=stream, flush=True)

    # What to run, and which Veridor runs it, before anything needs docker:
    # both are wrong or right without it, and are tested without it.
    try:
        pairs, skipped = select_pairs(load_pairs(None, extra_dirs=extra), only=args.pair)
    except PairError as error:
        print(str(error), file=sys.stderr)
        return 2
    under_test, refusal = veridor_under_test()
    if refusal:
        print(refusal, file=sys.stderr)
        return 2
    say(f"veridor under test: {under_test}")
    private = [pair for pair in pairs if not pair.get("_shipped")]
    if private:
        say(f"{len(private)} pair(s) from a --pairs-dir, not from this repository: "
            + ", ".join(sorted({str(pair["_dir"]) for pair in private})))
    say(f"{len(pairs)} of {len(pairs) + len(skipped)} pair(s) selected")
    for entry in skipped:
        say(f"skipped  {entry['name']}: {entry['reason']}")

    if not docker_on_path():
        print("docker is not on PATH; this harness stands up real builds", file=sys.stderr)
        return 2

    try:
        local, problems = check_local_tags(pairs)
    except (PairError, subprocess.SubprocessError, OSError) as error:
        print(f"could not compare the local tags with the pins: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    if problems:
        for _, problem in problems:
            print(problem, file=sys.stderr)
        for status in sorted({status for status, _ in problems}, reverse=True):
            print(LOCAL_TAG_SUMMARY[status], file=sys.stderr)
        return 2
    say(f"local tags against the pins: {local['match']} match, {local['absent']} not held here "
        "(those run by digest alone)")

    pulls: list[dict[str, Any]] = []
    if args.pull:
        pulls = pull_images(sorted({pull_ref(pair, side) for pair in pairs for side, _ in SIDES}), say)
    failed = {outcome["image"]: outcome["detail"] for outcome in pulls if not outcome["pulled"]}

    # Built pairs are built here, every run: the tag names every input, so an
    # unchanged recipe reuses the layer cache, and a changed one cannot reuse a
    # stale image. A build that fails fails its own pair, like a failed pull;
    # one whose base did not pull is not built, and reports the pull.
    built_failed: dict[str, str] = {}
    for pair in pairs:
        if not is_built(pair) or pair["build"]["base"] in failed:
            continue
        for side, _ in BUILD_SIDES:
            try:
                say(f"built   {build_side(pair, side)}")
            except (PairError, subprocess.SubprocessError, OSError) as error:
                built_failed[pair["name"]] = f"could not build the {side} side: {_describe(error)}"
                say(f"FAILED  build of {pair['name']} ({side}): {_describe(error)}")
                break

    results = []
    for pair in pairs:
        if pair["name"] in built_failed:
            results.append({"name": pair["name"], "passed": False, "error": built_failed[pair["name"]]})
            continue
        # Once each: a built pair's two sides share one base.
        refs = dict.fromkeys(pull_ref(pair, side) for side, _ in SIDES)
        missing = [f"{ref}: {failed[ref]}" for ref in refs if ref in failed]
        if missing:
            results.append({"name": pair["name"], "passed": False, "error": "could not pull " + "; ".join(missing)})
            continue
        try:
            results.append(evaluate(pair))
        except (PairError, subprocess.SubprocessError, OSError) as error:
            results.append({
                "name": pair["name"], "passed": False,
                "error": _describe(error),
            })

    passed = sum(1 for result in results if result["passed"])
    code = 0 if passed == len(results) else 1
    if args.json:
        print(json.dumps({
            "veridor_under_test": under_test,
            "selection": {"pair": args.pair, "pairs_dirs": [str(d) for d in pair_directories(extra)]},
            "local_tags": local,
            "pulls": pulls,
            "pairs": results,
            "skipped": skipped,
        }, indent=1))
        return code

    for result in results:
        print(f"\n{'PASS' if result['passed'] else 'FAIL'}  {result['name']}")
        if "error" in result:
            print(f"      could not evaluate: {result['error']}")
            continue
        advisory = result["advisory"]
        print(f"      {advisory['id']}: {advisory['summary']}")
        print(f"      {result['image']}:{result['vulnerable_tag']} -> :{result['patched_tag']}")
        if result.get("built_from"):
            print(f"      built from {result['built_from']['package']} files sha256:{result['vulnerable_pin'][:12]}… "
                  f"-> sha256:{result['patched_pin'][:12]}…, on {result['built_from']['base'][:26]}…")
        else:
            print(f"      pinned: @{result['vulnerable_pin'][:19]}… -> @{result['patched_pin'][:19]}…")
        for label, ok in result["checks"].items():
            print(f"        {'ok  ' if ok else 'FAIL'}  {label}")
        for label, why in (result.get("not_evaluated") or {}).items():
            print(f"        n/a   {label} -- not evaluated: {why}")
        vulnerable, patched = result["vulnerable"], result["patched"]
        print(
            f"      vulnerable: exit {vulnerable['exit_code']}, "
            f"{vulnerable['graded']} {vulnerable['expected_grade']} of "
            f"{vulnerable['findings']} finding(s)"
        )
        if vulnerable.get("below_grade"):
            print(f"      below {vulnerable['expected_grade']}: {', '.join(vulnerable['below_grade'])}")
        print(
            f"      patched:    exit {patched['exit_code']}, "
            f"{patched['findings']} finding(s), endpoint present: {patched['endpoint_present']}"
        )
        for entry in patched.get("unproven") or ():
            print(f"      unproven:   {entry}")
        if vulnerable["message"]:
            print(f"      evidence:   {vulnerable['message']}")

    print(f"\n{passed} of {len(results)} pair(s) show a true vulnerable -> patched differential.")
    if skipped:
        print(f"{len(skipped)} skipped, not run: {', '.join(entry['name'] for entry in skipped)}.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
