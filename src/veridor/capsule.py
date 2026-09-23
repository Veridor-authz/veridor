"""A portable, runnable proof of one authorization finding.

A capsule is the distribution mechanism, not a feature. The first person to run
Veridor is the *reporter*, not the maintainer: a capsule attached to a
disclosure puts a runnable proof in front of someone at the exact moment they
are deciding whether to believe a claim. Given curl's published figures --
report volume doubling while the valid rate sits at 15-16% -- being cheap to
verify is the scarcest property a disclosure can have.

    veridor capsule --config veridor.json --check <id> --output proof.json
    veridor verify proof.json

**A capsule goes to a stranger, so it must never carry a credential.** It is
built from the configuration *as written*, before environment interpolation,
and emitting one is REFUSED when any identity's credential is a literal rather
than an ``${ENV_VAR}`` reference. There is deliberately no override flag: the
failure mode it prevents is a reporter pasting their own bearer token into a
public advisory, which is unrecoverable, and the fix is one line in their
config.

That refusal used to look at identity headers only, and the capsule copied
everything else verbatim: a session login step whose body said
``"password": "hunter2-LITERAL"`` was published (reproduced for a JSON body and
a form-encoded one, exit 0), while the same value as an ``Authorization``
header was refused. So the finished document is scanned as a whole before it is
returned (:func:`literal_credentials`): every ``headers`` map and session
``inject`` wherever it sits, every credential-named key, credential-named
parameters in query strings, form bodies and JSON text, and ``user:pass@`` in
any URL. The scan walks the finished capsule rather than the places a
credential is known to live, so a field added later is covered without anyone
remembering to add it here.

The capsule therefore carries the *shape* of the proof -- the request, the two
identities, the declared expectation, the marker -- and names the environment
variables the verifier must supply from their own instance. That is also the
honest division of labour: the maintainer should be running this against their
own deployment with their own credentials, not replaying the reporter's.

**Verifying is the other direction, and the capsule is the untrusted party.**
``veridor verify`` expands a capsule's ``${NAME}`` references from the
VERIFIER's environment and sends the result to a target. It used to expand any
name, at the capsule's own ``base_url``: a capsule that said
``"Bearer ${MY_CLOUD_SECRET}"`` and pointed at the reporter's listener received
the verifier's secret (reproduced: 5 requests, 2 carrying it). So a capsule may
reference only ``VERIDOR_*`` names (:data:`VERIFIER_VARIABLE`), found by
scanning its content rather than trusting its ``requires_environment``; the
writer renames anything else so what ``capsule`` writes, ``verify`` accepts;
and ``cli._verify_capsule`` sends nothing to an address the capsule chose unless
it is this machine's loopback and every request is a read.

Scope is deliberately small and should stay that way: one check, one file, one
verdict.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from veridor import __version__
from veridor.core import (
    _ENV_PATTERN,
    DECLARATION_SCOPE,
    EVIDENCE_GRADES,
    ConfigError,
    declared_statuses,
    terminal_controls,
)
from veridor.terminal import (
    _BLANK_RUN,
    ECHO_LIMIT,
    cut,
    quoted,
    terminal_names,
    terminal_text,
)

#: An ``${ENV_VAR}`` reference. A credential that is not one of these is a
#: literal, and a literal must never leave the reporter's machine.
_ENV_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")

#: Header names whose value is a credential. Matched case-insensitively.
_CREDENTIAL_HEADERS = frozenset(
    {"authorization", "cookie", "x-api-key", "x-auth-token", "api-key", "token"}
)

#: Key names whose value is a credential, matched against the whole key in any
#: case. A key that ENDS in password (also password1, password2,
#: password_confirmation, passwordConfirm, password_again, password_repeat),
#: passwd, passphrase, passwort, kennwort, contrasena / contraseña,
#: mot_de_passe, secret, token, jwt, credential(s), api key, private key,
#: secret key, access key, passcode, pin code, otp code, mfa code,
#: verification code or client assertion counts with or without a separator
#: before the word (``access_token``, ``accessToken``, ``clientSecret``,
#: ``aws_secret_access_key``, ``new_password1``, ``mfaCode``). The short
#: words ``pass``, ``pwd``, ``senha``, ``pin``, ``otp``, ``totp`` and ``hotp``
#: count only as a whole word: the entire key, after ``_``, ``.`` or ``-``, or
#: (pass, pwd, pin, otp, totp) as a capitalised camelCase word (``pass``,
#: ``user_pass``, ``userPass``, ``dbPwd``, ``userPin``, ``smsOtp``), so
#: ``bypass``, ``compass``, ``resenha``, ``spin`` and ``laptop`` do not;
#: ``userpass``, ``userpwd``, ``dbpass`` and ``adminpwd`` count as whole keys.
#: The one-time codes, PINs and client assertions were missing, so a literal
#: under ``passcode``, ``pin``, ``otp``, ``mfa_code`` or ``client_assertion``
#: was published while the same value under ``password`` was refused
#: (measured).
#:
#: It used to require a separator before every word, so ``accessToken``,
#: ``refreshToken``, ``userPassword``, ``secret_key`` and ``pass`` were
#: published verbatim, and later Django's ``password1``/``password2``,
#: ``password_confirmation``, JSON ``jwt``, ``userpass`` and ``passwort`` were
#: (measured, capsule and chart alike).
#:
#: The SAME pattern the Helm chart's literal-credential refusal uses (``$credKey``
#: in deploy/helm/veridor-gate/templates/_helpers.tpl), so a value one of them
#: refuses the other does not publish; tests/test_capsule.py pins them equal.
#: Written for both engines: Go's RE2 has no lookbehind, and both read the
#: scoped ``(?-i:...)`` that keeps the camelCase capital a capital. The ñ of
#: contraseña is matched as one or two non-ASCII characters: percent-decoded,
#: ``%C3%B1`` is ñ here and one U+FFFD in the chart, which reads every escaped
#: UTF-8 sequence as one character and decodes only ASCII and four letters.
CREDENTIAL_FIELD = re.compile(
    r"(?i)^(?:.*(?:password(?:[_-]?(?:confirm(?:ation)?|again|repeat|[0-9]))?|passwd|passphrase|passwort|kennwort"
    r"|contrase(?:n|[^\x00-\x7f]{1,2})a|mot[_-]?de[_-]?passe|secret|token|jwt|credentials?|api[_-]?key"
    r"|private[_-]?key|secret[_-]?key|access[_-]?key"
    r"|pass[_-]?code|pin[_-]?code|otp[_-]?code|mfa[_-]?code|verification[_-]?code|client[_-]?assertion)"
    r"|(?:.*[_.-])?(?:pwd|pass|senha|pin|otp|totp|hotp)|.*(?-i:[a-z0-9]P)(?:wd|ass|in)"
    r"|.*(?-i:[a-z0-9](?:O|T[Oo]))tp|(?:user|db|admin)(?:pass|pwd))$"
)

#: Names that are a credential only as a ``name=value`` parameter in a string
#: (a query string, a form body, a ``;`` path parameter): Google APIs take an
#: API key as ``?key=``, Firebase a token as ``?auth=``, Azure Functions a key
#: as ``?code=``, Azure SAS a signature as ``sig=``, servlet containers a
#: session as ``;jsessionid=`` (measured: each was published). Matched
#: against the whole decoded name, not a bracketed segment, and not as a JSON
#: key, where ``key`` and ``code`` are too often something else. A non-secret
#: under one of these names (an object key, a country code) is refused too.
#: The chart's ``$pairOnlyKey``, pinned equal.
PAIR_CREDENTIAL = re.compile(r"(?i)^(?:key|auth|sig|signature|code|j?session[_-]?id|sid)$")

#: Keys directly under a credential-named key (or a labelled pair's value)
#: that describe the credential rather than hold it, walked by the ordinary
#: rules: Keycloak's ``{"type": "password", "value": ..., "temporary":
#: false}``, ``{"credentials": {"user": "alice"}}``. Every other string or
#: number anywhere beneath a credential-named key is held to the reference
#: rule: ``{"password": {"value": "hunter2"}}`` (Okta's
#: ``credentials.password.value``) was walked by the ordinary rules and
#: published (measured). Space-separated, lower case; the chart's
#: ``$credentialDescriptors``, pinned equal.
CREDENTIAL_DESCRIPTORS = "type temporary username user email id name"

#: The keys that name the credential in a name/value object: ``{"name":
#: "password", "value": ...}``, ``{"type": "password", "value": ...}``. When
#: one of them holds a credential name, the object's ``value`` is a
#: credential. The chart's ``$pairLabels``, pinned equal.
PAIR_LABELS = "name key field type"

#: A capture extractor: a sequence capture's JSON path or ``header:NAME``
#: (the schema's pattern, which sequence.parse_extractor implements). Under a
#: ``capture`` map a credential-NAMED key holding one of these (or an object
#: whose ``from`` is a capture source) is a capture, not a credential; any
#: other value there is held to the credential rule, so ``{"capture":
#: {"password": "hunter2"}}`` in a request body no longer passes (measured:
#: it was published). The chart's ``$captureExtractor``, pinned equal.
CAPTURE_EXTRACTOR = re.compile(
    r"^(\$(\.[A-Za-z_][A-Za-z0-9_-]*|\[(0|[1-9][0-9]*)\])+|header:[!#$%&'*+.^_`|~0-9A-Za-z-]+)$"
)
_CAPTURE_SOURCES = frozenset({"cookie", "header", "json_pointer", "html_meta"})

#: Header names that carry a credential, matched anywhere in the name
#: (Authorization, Proxy-Authorization, Cookie, X-Api-Key, X-Session-Id,
#: X-CSRF-Token, ...). The chart's test for "this header name is a credential"
#: (its ``allowLiteralHeaders`` refusal), pinned equal by the same test.
CREDENTIAL_HEADER_WORD = re.compile(r"(?i)(auth|cookie|token|secret|key|session|passw|credential)")

#: The only value a credential header may carry: one reference, optionally
#: after one auth-scheme word -- ``Bearer ${VERIDOR_OWNER_TOKEN}``. The chart's
#: ``$headerOk``, pinned equal. ``${capture.csrf}`` counts as a reference: it
#: is filled at run time from the target's own response, never from the file.
REFERENCE_ONLY_HEADER = re.compile(
    r"^[\t\n\f\r ]*([A-Za-z][A-Za-z0-9._~+/-]*[\t\n\f\r ]+)?\$\{[A-Za-z_][A-Za-z0-9_.]*\}[\t\n\f\r ]*$"
)

#: Any ``${...}`` the engine resolves at run time: an environment variable, a
#: ``capture.`` value, a sequence capture. None of them is a literal.
_ANY_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_.]*\}")

#: ``name=value`` pairs in a query string, a form body or a Cookie-like list.
_PAIR = re.compile(r"(?:^|[?&;])[\t\n\f\r ]*([^=&;?#\t\n\f\r ]+)=([^&;#\t\n\f\r ]*)")

#: The userinfo of a URL written anywhere in a string: ``scheme://USERINFO@``.
_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#@\t\n\f\r ]*)@")

#: Whitespace, read exactly as the chart's Go reads it. The three patterns
#: above spell out ``[\t\n\f\r ]``, which is what ``\s`` means in Go's RE2;
#: Python's ``\s`` also matches U+000B, U+001C-U+001F, U+0085, U+00A0 and the
#: other Unicode spaces, so the same pattern text split ``a=1&<U+00A0>key=...``
#: at ``key`` here and read the name ``<U+00A0>key`` in the chart, which then
#: rendered a literal the capsule refused (measured with helm template, as
#: was U+000B). Trimming is the chart's sprig ``trim``, Go's
#: ``strings.TrimSpace``: the characters below, measured with helm over every
#: BMP code point. Python's ``str.strip()`` also strips U+001C-U+001F, so JSON
#: text after a U+001C was parsed and refused here and skipped and rendered
#: there. tests/fixtures/credential_parity.json has the ``whitespace:`` cases.
_TRIM_SPACE = (
    "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)

CAPSULE_KIND = "veridor.capsule"
CAPSULE_SCHEMA_VERSION = 1

#: The three verdicts a capsule run can produce. Deliberately not the same
#: vocabulary as a run: a capsule answers "did this specific claim reproduce",
#: which is a narrower question than "does this target hold its boundaries".
CONFIRMED = "CONFIRMED"
NOT_REPRODUCED = "NOT_REPRODUCED"
INCONCLUSIVE = "INCONCLUSIVE"


#: The only environment variable names ``veridor verify`` will expand for a
#: capsule. A capsule comes from someone else; restricting it to a prefix the
#: verifier exports on purpose is what stops it naming ``AWS_SECRET_ACCESS_KEY``.
VERIFIER_VARIABLE = re.compile(r"VERIDOR_[A-Z0-9_]+")


class CapsuleError(ConfigError):
    """A capsule could not be built or read."""


def _references(value: Any, where: str = "") -> Iterator[tuple[str, str]]:
    """Every ``${NAME}`` the config loader would expand in ``value``.

    Yields ``(NAME, location)`` in document order. Uses the loader's own
    ``_ENV_PATTERN`` and walks exactly what ``core._expand_environment`` walks
    -- string values inside lists and objects, not object keys, which are never
    expanded -- so this scan and the expansion cannot disagree about what
    reads the environment.
    """
    if isinstance(value, str):
        for match in _ENV_PATTERN.finditer(value):
            yield match.group(1), where or "(top level)"
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _references(item, f"{where}.{key}" if where else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _references(item, f"{where}[{index}]")


def verifier_environment(config: dict[str, Any]) -> list[str]:
    """The environment variables verifying ``config`` reads, or refuse.

    Derived from the content that will actually be expanded -- the capsule's
    own ``requires_environment`` is a claim by the party this check exists to
    distrust, so it is not consulted. Any name outside :data:`VERIFIER_VARIABLE`
    is refused before anything is read or sent.
    """
    found = list(_references(config))
    foreign = [(name, where) for name, where in found if not VERIFIER_VARIABLE.fullmatch(name)]
    if foreign:
        listed = "; ".join(f"${{{name}}} in {where}" for name, where in foreign[:10])
        if len(foreign) > 10:
            listed += f"; and {len(foreign) - 10} more"
        raise CapsuleError(
            f"this capsule references {listed}. `veridor verify` expands only "
            "VERIDOR_* variables in a capsule: a capsule comes from someone else, "
            "and every variable it references is read from YOUR environment and "
            "sent to the target. Nothing has been sent. If you trust the "
            "reference, edit the capsule to use a VERIDOR_ name and export that "
            "with a value from your own instance."
        )
    return sorted({name for name, _ in found})


def targets_loopback(base_url: Any) -> bool:
    """True only for an http(s) URL whose host is provably this machine.

    Stricter than ``matrix.classify_target`` on purpose: that one asks whether
    a stranger could be reached, this one decides whether an untrusted file may
    choose where the verifier's credentials go. An IP literal in 127.0.0.0/8,
    ``::1``, or exactly ``localhost``; not ``*.localhost``, whose resolution is
    up to whatever resolver is configured, and not an unexpanded ``${...}``.
    """
    if not isinstance(base_url, str) or "${" in base_url:
        return False
    try:
        parts = urlsplit(base_url)
        host = parts.hostname
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"} or not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _verifier_name(original: str, identity: str | None) -> str:
    stem = original.upper()
    if identity is None:
        return f"VERIDOR_{stem}"
    prefix = re.sub(r"[^A-Za-z0-9]+", "_", identity).strip("_").upper() or "IDENTITY"
    if stem.startswith(prefix + "_"):
        stem = stem[len(prefix) + 1:]
    return f"VERIDOR_{prefix}_{stem}"


def _rename(value: Any, renames: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(
            lambda match: "${" + renames.get(match.group(1), match.group(1)) + "}", value
        )
    if isinstance(value, dict):
        return {key: _rename(item, renames) for key, item in value.items()}
    if isinstance(value, list):
        return [_rename(item, renames) for item in value]
    return value


def _verifier_renames(
    identities: dict[str, Any], target: dict[str, Any], check: dict[str, Any]
) -> dict[str, str]:
    """Map every non-``VERIDOR_*`` reference to a name ``verify`` will accept.

    A config that says ``${MY_TOKEN}`` is fine for the reporter and would be
    refused by every verifier, so the writer renames it: ``VERIDOR_<IDENTITY>_
    <NAME>`` inside an identity, ``VERIDOR_<NAME>`` elsewhere. One original name
    maps to one new name (the same value stays the same value), names already
    acceptable are kept verbatim, and a new name never collides with one.
    """
    order: list[tuple[str, str | None]] = []
    for name, identity in identities.items():
        order += [(ref, name) for ref, _ in _references(identity)]
    order += [(ref, None) for ref, _ in _references(target)]
    order += [(ref, None) for ref, _ in _references(check)]
    taken = {ref for ref, _ in order if VERIFIER_VARIABLE.fullmatch(ref)}
    renames: dict[str, str] = {}
    for ref, identity in order:
        if ref in taken or ref in renames:
            continue
        base = _verifier_name(ref, identity)
        candidate, suffix = base, 2
        while candidate in taken:
            candidate, suffix = f"{base}_{suffix}", suffix + 1
        taken.add(candidate)
        renames[ref] = candidate
    return renames


def _env_references(value: Any) -> list[str]:
    if isinstance(value, str):
        return [m.group(0) for m in _ENV_REFERENCE.finditer(value)]
    if isinstance(value, dict):
        return [n for item in value.values() for n in _env_references(item)]
    if isinstance(value, list):
        return [n for item in value for n in _env_references(item)]
    return []


def _refuse_literal_credentials(identities: dict[str, Any]) -> list[str]:
    """Return the env vars a verifier must supply, or raise.

    Every credential-bearing header must be an ``${ENV_VAR}`` reference. This
    is the one hard gate in the module: a capsule is published, and a published
    bearer token cannot be recalled.
    """
    required: list[str] = []
    for name, identity in identities.items():
        headers = (identity or {}).get("headers") or {}
        for header, value in headers.items():
            if header.lower() not in _CREDENTIAL_HEADERS:
                continue
            references = _env_references(value)
            if not references:
                # The suggested value has to fit the header it replaces --
                # "Bearer" in a Cookie is nonsense, and a fix-it hint that does
                # not work is worse than none.
                variable = f"VERIDOR_{re.sub(r'[^A-Za-z0-9]+', '_', name).upper()}_TOKEN"
                example = (
                    f'"Bearer ${{{variable}}}"'
                    if header.lower() == "authorization"
                    else f'"${{{variable}}}"'
                )
                raise CapsuleError(
                    f"identity {quoted(name)} carries a literal {header} value, and a "
                    "capsule is meant to be attached to a disclosure and read by "
                    "someone else. Move it to an environment variable first, for "
                    f'example "{header}": {example}, and re-run. '
                    "Nothing has been written."
                )
            required.extend(reference.strip("${}") for reference in references)
    return sorted(set(required))


# ---------------------------------------------------------------------------
# The final pass: no literal credential anywhere in the finished document.
#
# The Helm chart's refusal (deploy/helm/veridor-gate/templates/_helpers.tpl)
# is this same walk in Go templates, with _ANY_REFERENCE, _PAIR and _USERINFO
# pinned equal to its patterns. tests/fixtures/credential_parity.json is
# decided by both (tests/test_credential_parity.py). The two deliberate
# differences are cases there with their reasons; the known ones that need
# inputs no configuration should contain are listed in that test's docstring,
# and in each the chart refuses more:
#   * The chart requires EVERY header value to be a reference unless the
#     header is listed in allowLiteralHeaders. A capsule has no allow-list, and
#     a literal ``X-Tenant: acme`` is part of a proof, so here only
#     credential-named headers (CREDENTIAL_HEADER_WORD) must be references.
#   * The chart refuses ``user:pass@`` in target.base_url even when both are
#     references, because the loader refuses credentials in that URL at run
#     time; here references there are accepted like anywhere else.
# ---------------------------------------------------------------------------


#: The four characters Python's and Go's case rules relate to an ASCII letter
#: differently. Measured over every code point: Python's ``re`` with ``(?i)``
#: matches U+0130 and U+0131 as ``i`` and Go's RE2 does not; ``str.lower()``
#: makes U+0130 ``i`` plus U+0307 where Go's ``strings.ToLower`` makes ``i``; both relate
#: U+017F to ``s`` and U+212A to ``k``. No other code point is related to an
#: ASCII letter by either. So the chart and this scan disagreed: ``apİ_key``
#: and ``credentİals`` holding a literal were refused here and rendered by the
#: chart, and ``İd`` under ``password`` was a descriptor there and not here.
#: Both now read a name through :func:`_fold` wherever a match makes the scan
#: STRICTER (a credential name, a parameter-only name, a credential header,
#: the ``headers`` key), and compare only an ASCII key wherever a match
#: EXEMPTS (a descriptor, a Cookie read one cookie at a time): a look-alike
#: letter counts toward a credential and never excuses one. The chart's
#: ``veridor-gate.fold``; tests/fixtures/credential_parity.json has the cases.
_ASCII_FOLD = str.maketrans({"\u0130": "i", "\u0131": "i", "\u017f": "s", "\u212a": "k"})


def _fold(name: str) -> str:
    """``name`` with the four characters above read as their ASCII letter."""
    return name.translate(_ASCII_FOLD)


def _join(path: str, key: Any) -> str:
    key = str(key)
    if re.fullmatch(r"[A-Za-z0-9_-]+", key):
        return f"{path}.{key}" if path else key
    return f"{path}[{json.dumps(key)}]"


def _is_literal(value: Any) -> bool:
    """Does ``value`` carry anything besides ``${...}`` references?

    Empty and whitespace-only strings carry nothing. Numbers are literals (a
    numeric PIN is still a PIN); booleans and ``None`` are not credentials.
    """
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return True
    if not isinstance(value, str):
        return False
    return bool(_ANY_REFERENCE.sub("", value).strip(_TRIM_SPACE))


def _credential_name(name: str) -> bool:
    """A credential-named field, including the bracketed ``user[password]``."""
    name = _fold(name)
    segments = [segment for segment in re.split(r"[\[\]]", name) if segment]
    return any(CREDENTIAL_FIELD.fullmatch(candidate) for candidate in [name, *segments[-1:]])


def _credential_header(name: str) -> bool:
    name = _fold(name)
    return name.lower() in _CREDENTIAL_HEADERS or bool(CREDENTIAL_HEADER_WORD.search(name))


def _scan_header(path: str, name: str, value: Any) -> Iterator[tuple[str, str, str]]:
    if not _credential_header(name) or not _is_literal(value):
        return
    text = str(value)
    if name.isascii() and name.lower() in {"cookie", "set-cookie"}:
        for part in text.split(";"):
            cookie, separator, cookie_value = part.partition("=")
            if not separator:
                cookie_value, cookie = cookie, name
            if _is_literal(cookie_value):
                yield path, f"cookie {quoted(cookie.strip(_TRIM_SPACE))} in the {terminal_text(name)} header", cookie.strip(_TRIM_SPACE)
        return
    if not REFERENCE_ONLY_HEADER.fullmatch(text):
        stem = "token" if name.lower() in {"authorization", "proxy-authorization"} else name
        yield path, f"the {terminal_text(name)} header", stem


def _scan_string(path: str, text: str) -> Iterator[tuple[str, str, str]]:
    """Credentials inside one string: URL userinfo, name=value pairs, JSON text."""
    for match in _USERINFO.finditer(text):
        if _is_literal(match.group(1).replace(":", "")):
            yield path, "user:password@ in a URL", "password"
    for match in _PAIR.finditer(text):
        name = unquote_plus(match.group(1))
        if (_credential_name(name) or PAIR_CREDENTIAL.fullmatch(_fold(name))) and _is_literal(unquote_plus(match.group(2))):
            yield path, f"parameter {quoted(name)}", name
    stripped = text.strip(_TRIM_SPACE)
    if stripped[:1] in {"{", "["}:
        try:
            parsed = json.loads(stripped)
        except (ValueError, RecursionError):
            return
        if isinstance(parsed, (dict, list)):
            for inner, what, stem in _scan(parsed, ""):
                yield path, f"{what} at {quoted(inner)} of the JSON text", stem


def _is_extractor(value: Any) -> bool:
    """A capture's extractor: ``{"from": "header", ...}`` or ``"$.token"``."""
    if isinstance(value, dict):
        source = value.get("from")
        return isinstance(source, str) and source in _CAPTURE_SOURCES
    return isinstance(value, str) and bool(CAPTURE_EXTRACTOR.fullmatch(value))


def _pair_label(value: dict[Any, Any]) -> str | None:
    """The credential name a name/value object labels its ``value`` with."""
    if "value" not in value:
        return None
    for label in PAIR_LABELS.split():
        named = value.get(label)
        if isinstance(named, str) and _credential_name(named):
            return named
    return None


def _scan(value: Any, path: str, *, capture_names: bool = False) -> Iterator[tuple[str, str, str]]:
    """Every literal credential in ``value``, as (path, what, name stem).

    ``capture_names`` marks a mapping whose keys are capture NAMES (``capture:
    {"token": "header:X-Token"}``): a credential-named key there whose value
    is an extractor is a capture, not a secret.
    """
    if isinstance(value, str):
        yield from _scan_string(path, value)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _scan(item, f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    label = _pair_label(value)
    for key, item in value.items():
        here = _join(path, key)
        if label is not None and key == "value":
            yield from _scan_credential_value(item, here, label)
            continue
        # Any case: a request's "Headers" was walked as an ordinary object, so
        # "Authorization: Bearer <literal>" under it was published (measured).
        if isinstance(key, str) and _fold(key).lower() == "headers" and isinstance(item, dict):
            for header, header_value in item.items():
                yield from _scan_header(_join(here, header), str(header), header_value)
        elif key == "inject" and isinstance(item, list):
            for index, entry in enumerate(item):
                if not isinstance(entry, dict):
                    continue
                at = f"{here}[{index}].value"
                if isinstance(entry.get("header"), str):
                    for found in _scan_header(at, entry["header"], entry.get("value")):
                        yield at, f"injected {found[1]}", found[2]
                for slot in ("form_field", "json_field"):
                    field = entry.get(slot)
                    if isinstance(field, str) and _credential_name(field) and _is_literal(entry.get("value")):
                        yield at, f"injected field {quoted(field)}", field
        elif (
            isinstance(key, str)
            and _credential_name(key)
            and not (capture_names and _is_extractor(item))
        ):
            yield from _scan_credential_value(item, here, key)
            continue
        yield from _scan(item, here, capture_names=key == "capture")


def _scan_credential_value(value: Any, path: str, key: str) -> Iterator[tuple[str, str, str]]:
    """The value of a credential-named key, at any depth.

    A scalar must carry no literal, and so must every scalar beneath it:
    through nested lists (``"password": ["hunter2"]`` was walked as an
    ordinary list and published, measured) and through objects
    (``{"password": {"value": "hunter2"}}`` was walked by the ordinary rules
    and published, measured). Only a key that describes the credential
    (CREDENTIAL_DESCRIPTORS: ``type``, ``username``, ...) is walked by the
    ordinary rules.
    """
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _scan_credential_value(item, f"{path}[{index}]", key)
    elif isinstance(value, dict):
        for inner, item in value.items():
            here = _join(path, inner)
            if isinstance(inner, str) and inner.isascii() and inner.lower() in CREDENTIAL_DESCRIPTORS.split():
                yield from _scan(item, here)
            else:
                yield from _scan_credential_value(item, here, key)
    elif _is_literal(value):
        yield path, "a credential-named field", key


def literal_credentials(document: Any) -> list[tuple[str, str]]:
    """``(json path, what)`` for every literal credential in ``document``.

    Never returns a value: the path and a description of the slot are all a
    caller needs to point the reporter at it, and all a log may carry.
    """
    return [(path, what) for path, what, _ in _scan(document, "")]


def _refuse_literal_values(document: dict[str, Any]) -> None:
    """Refuse a capsule that would publish any literal credential. Exit 2."""
    found = list(dict.fromkeys(_scan(document, "")))
    if not found:
        return
    path, what, stem = found[0]
    identity = path.split(".")[1].split("[")[0] if path.startswith("identities.") else None
    variable = _verifier_name(re.sub(r"[^A-Za-z0-9]+", "_", stem).strip("_") or "value", identity)
    if what.startswith("the Authorization header") or what.startswith("injected the Authorization"):
        example = f'"Bearer ${{{variable}}}"'
    elif what.startswith("user:password@"):
        example = f'a header carrying "${{{variable}}}" instead of user:password@ in the URL'
    else:
        example = f'"${{{variable}}}"'
    listed = "; ".join(f"{terminal_text(where)} ({slot})" for where, slot, _ in found[:10])
    if len(found) > 10:
        listed += f"; and {len(found) - 10} more"
    raise CapsuleError(
        f"this capsule would publish {len(found)} literal credential "
        f"value{'s' if len(found) != 1 else ''}: {listed}. A capsule is meant to be "
        "attached to a disclosure and read by someone else, so a credential in "
        "it may only be a ${VERIDOR_...} reference the verifier fills from their "
        "own instance. The values are not printed here. Move each one into an "
        f"environment variable and reference it, for example {example}, and "
        "re-run. Nothing has been written."
    )


def _identities_for(check: dict[str, Any], identities: dict[str, Any]) -> dict[str, Any]:
    """The identities this one check needs, and nothing else.

    A capsule proving one finding has no business shipping the reporter's whole
    identity roster -- that is more of their environment than the claim needs,
    and every extra identity is another credential to get wrong.
    """
    wanted = set((check.get("expect") or {}).keys())
    for expectation in (check.get("expect") or {}).values():
        for key in ("contains_marker", "excludes_marker"):
            owner = (expectation or {}).get(key)
            if isinstance(owner, str):
                wanted.add(owner)
    missing = wanted - set(identities)
    if missing:
        raise CapsuleError(
            f"check names identities the configuration does not define: "
            f"{terminal_names(sorted(missing))}"
        )
    return {name: identities[name] for name in sorted(wanted)}


def build(
    config: dict[str, Any],
    check_id: str,
    *,
    run_document: dict[str, Any] | None = None,
    image: str | None = None,
) -> dict[str, Any]:
    """Build a capsule from a configuration **as written on disk**.

    ``config`` must be the raw parsed JSON, not the product of
    ``core.load_config`` -- the loaded form has already resolved every
    ``${ENV_VAR}`` to its literal value, which is exactly what must not be
    published.
    """
    return build_with_renames(config, check_id, run_document=run_document, image=image)[0]


def build_with_renames(
    config: dict[str, Any],
    check_id: str,
    *,
    run_document: dict[str, Any] | None = None,
    image: str | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """:func:`build`, plus the ``{reporter name: capsule name}`` renames it made.

    The renames are for telling the REPORTER what changed; they are not written
    into the capsule, which names only what the verifier must export.
    """
    checks = config.get("checks") or []
    matching = [check for check in checks if check.get("id") == check_id]
    if not matching:
        available = terminal_names(sorted(str(c.get("id")) for c in checks)) or "none"
        raise CapsuleError(f"no check with id {quoted(check_id)}; the config declares: {available}")
    check = matching[0]

    identities = _identities_for(check, config.get("identities") or {})
    _refuse_literal_credentials(identities)

    claim: dict[str, Any] = {"check_id": check_id, "check_name": check.get("name")}
    if run_document:
        findings = [
            finding for finding in (run_document.get("findings") or [])
            if finding.get("check_id") == check_id
        ]
        if findings:
            # The vulnerable finding is the claim, as `adjudicate` reads it.
            # `run` emits a check's findings in expect order, so findings[0]
            # was usually the owner's control: a refused or inconclusive
            # control became the published claim and `verify` reported a
            # grade mismatch against the finding it actually reproduced.
            finding = next(
                (f for f in findings if f.get("verdict") == "vulnerable"), findings[0]
            )
            grade = finding.get("evidence_grade")
            if grade is not None and not (isinstance(grade, str) and grade in EVIDENCE_GRADES):
                # `load` refuses such a grade, so writing it would publish a
                # capsule no verifier can run.
                raise CapsuleError(
                    f"the run's finding for check {quoted(check_id)} carries "
                    f"evidence_grade {quoted(grade)}, which is not a grade Veridor "
                    f"writes ({', '.join(EVIDENCE_GRADES)}). Pass --from-run a run "
                    "document `veridor run` wrote. Nothing has been written."
                )
            claim.update({
                "finding_id": finding.get("id"),
                "identity": finding.get("identity"),
                "verdict": finding.get("verdict"),
                "evidence_grade": finding.get("evidence_grade"),
                "statement": finding.get("message"),
            })
        claim["observed_in_run"] = run_document.get("run_id")
    # The claim is prose printed in someone else's terminal, and `load`
    # refuses a claim carrying a terminal control. A check name or finding
    # message with one (a tab, a newline) is written visibly escaped, so what
    # this writes `verify` accepts. check_id is left alone: it must equal the
    # check's own id, which the config loader already holds to _SAFE_NAME.
    claim = {
        key: terminal_text(value, limit=None)
        if key != "check_id" and isinstance(value, str) else value
        for key, value in claim.items()
    }

    target = dict(config.get("target") or {})
    if image:
        target["image"] = image

    renames = _verifier_renames(identities, target, check)
    identities = _rename(identities, renames)
    target = _rename(target, renames)
    check = _rename(check, renames)
    # `load` holds check.name to the same rule as the claim, so a name carrying
    # a terminal control is written escaped here too. _rename returned a copy.
    if isinstance(check.get("name"), str):
        check["name"] = terminal_text(check["name"], limit=None)
    # The schema's single-integer status is written as the list it stands for,
    # so no verifier that reads the capsule as written meets a bare `404`: the
    # one that shipped with `_unmeasured` crashed on it (exit 70) whenever the
    # boundary held. A value that is no status is copied unchanged, and `load`
    # refuses it.
    expect = check.get("expect")
    for expectation in expect.values() if isinstance(expect, dict) else ():
        if isinstance(expectation, dict):
            statuses = declared_statuses(expectation.get("status"))
            if statuses is not None:
                expectation["status"] = statuses
    # Every reference the capsule carries, not only the credential headers: a
    # ${VERIDOR_TENANT} in a path is read from the verifier's environment too.
    required_env = sorted(
        {name for part in (identities, target, check) for name, _ in _references(part)}
    )

    capsule = {
        "kind": CAPSULE_KIND,
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "veridor_version": __version__,
        "claim": claim,
        # Reproduced verbatim so a capsule cannot quietly assert more than the
        # run it came from. A reader who only reads this block still learns
        # that the finding is measured against a declaration, not against a
        # policy Veridor knows.
        "scope": DECLARATION_SCOPE,
        "target": target,
        "identities": identities,
        "check": check,
        "requires_environment": required_env,
        "how_to_verify": [
            "Provision the identities named above on YOUR OWN instance -- do not "
            "reuse the reporter's credentials.",
            f"Export: {', '.join(required_env) if required_env else '(none)'}",
            "`veridor verify` reads only VERIDOR_* variables, and only the ones "
            "this file references; it refuses anything else before sending.",
            "Run: veridor verify <this file> --base-url https://your-instance "
            "(the flag may be omitted only when the target above is this "
            "machine's loopback and the check only reads)",
            "CONFIRMED means the declared expectation failed the same way here. "
            "NOT_REPRODUCED means it held. Neither tells you whether the "
            "declaration itself is correct.",
        ],
    }
    # Last, over the whole finished document: whatever the writer copied from
    # wherever, a literal credential in it is refused before anything is
    # printed or written.
    _refuse_literal_values(capsule)
    return capsule, renames


def to_config(capsule: dict[str, Any], base_url: str | None = None) -> dict[str, Any]:
    """The smallest runnable configuration this capsule describes."""
    if capsule.get("kind") != CAPSULE_KIND:
        raise CapsuleError(
            f"not a Veridor capsule (kind={quoted(capsule.get('kind'))}). "
            "`veridor verify` takes a capsule; use --config for a configuration."
        )
    version = capsule.get("schema_version")
    if version != CAPSULE_SCHEMA_VERSION:
        raise CapsuleError(
            f"capsule schema version {quoted(version)} is not supported by veridor "
            f"{__version__} (expected {CAPSULE_SCHEMA_VERSION})"
        )
    target = dict(capsule.get("target") or {})
    target.pop("image", None)  # documentation for the reader, not a config key
    if base_url:
        target["base_url"] = base_url
    return {
        "version": 2 if "sequences" in capsule else 1,
        "target": target,
        "identities": capsule["identities"],
        "checks": [capsule["check"]],
    }


def adjudicate(capsule: dict[str, Any], run_document: dict[str, Any]) -> dict[str, Any]:
    """Turn a run of the capsule into one of three verdicts.

    A capsule answers a narrower question than a run: *did this specific claim
    reproduce here*. So `INCONCLUSIVE` is a first-class outcome rather than a
    failure -- an unreachable target or an unverifiable marker is precisely the
    case where a maintainer must not be told "not reproduced".

    `NOT_REPRODUCED` is the one verdict that needs a measurement behind it, so
    it is the one that is earned rather than fallen into: every identity of
    the check was probed and answered with a status the capsule declares,
    every marker the check grades was observed where it had to be, nothing
    was inconclusive, and the run's liveness control, when it ran, did not
    find a denial a fabricated credential also drew. Anything less is
    `INCONCLUSIVE`, with a reason naming what was not measured.

    It used to be whatever was left once nothing was `vulnerable` or
    `inconclusive`, so a run whose every probe was REFUSED with a status the
    capsule does not declare -- `unexpected_denial` -- came out "the declared
    expectation held on this target", exit 0. Reproduced: a proxy answering
    407 to every request (the target received none), and the verifier's
    VERIDOR_* tokens gone stale against a vulnerable target (401 to both).
    """
    claim = capsule["claim"]
    check_id = claim["check_id"]
    findings = [
        finding for finding in (run_document.get("findings") or [])
        if finding.get("check_id") == check_id
    ]
    inconclusive = [f for f in findings if f.get("verdict") == "inconclusive"]
    reproduced = [f for f in findings if f.get("verdict") == "vulnerable"]
    refused = [f for f in findings if f.get("verdict") == "unexpected_denial"]
    probes = [
        probe for probe in (run_document.get("probes") or [])
        if isinstance(probe, dict) and probe.get("check_id") == check_id
    ]

    summary = run_document.get("summary") or {}
    if summary.get("probes", 0) == 0 or not probes:
        return {
            "verdict": INCONCLUSIVE,
            "reason": "no probe reached the target, so nothing was measured",
            "findings": findings,
        }
    if reproduced:
        finding = reproduced[0]
        claimed = claim.get("evidence_grade")
        observed = finding.get("evidence_grade")
        note = ""
        if claimed and observed and claimed != observed:
            note = (
                f" The original claim was graded {quoted(claimed)}; here it is "
                f"{quoted(observed)}, which is a different strength of evidence."
            )
        return {
            "verdict": CONFIRMED,
            "reason": f"the declared expectation failed here as well.{note}",
            "evidence_grade": observed,
            "findings": findings,
        }
    if inconclusive:
        # The first probe's own message says why; every other identity whose
        # probe was inconclusive is named too, so a verifier sees who was not
        # measured, not only the first (each name bounded like any quoted input).
        reason = inconclusive[0].get("message", "the run could not decide")
        first = inconclusive[0].get("identity")
        others = sorted({
            f.get("identity") for f in inconclusive[1:]
            if isinstance(f.get("identity"), str) and f.get("identity") != first
        })
        if others:
            reason += f" Also inconclusive here: the probes as {terminal_names(others)}."
        return {
            "verdict": INCONCLUSIVE,
            "reason": reason,
            "findings": findings,
        }
    if refused:
        return {
            "verdict": INCONCLUSIVE,
            "reason": _refusal_reason(refused),
            "findings": findings,
        }
    unmeasured = _unmeasured(capsule, probes, run_document)
    if unmeasured:
        listed = "; ".join(unmeasured[:5])
        if len(unmeasured) > 5:
            listed += f"; and {len(unmeasured) - 5} more"
        return {
            "verdict": INCONCLUSIVE,
            "reason": f"the claim was not measured on this target: {listed}.",
            "findings": findings,
        }
    reason = (
        "the declared expectation held on this target. That is not proof the "
        "boundary is enforced -- only that this one declaration was met here."
    )
    liveness = run_document.get("liveness")
    if isinstance(liveness, dict) and liveness.get("enabled") is False:
        reason += (
            " Liveness controls were off (--no-prove-liveness), so a denial "
            "here could also be a credential this target does not recognise."
        )
    return {"verdict": NOT_REPRODUCED, "reason": reason, "findings": findings}


#: HTTP 407 is Proxy Authentication Required: the answer of a proxy, not of
#: the target behind it.
_PROXY_REFUSAL = 407


def _refusal_reason(refused: list[dict[str, Any]]) -> str:
    """Why a refusal the capsule does not declare measured nothing."""
    listed = []
    for finding in refused[:5]:
        evidence = finding.get("evidence") or {}
        listed.append(
            f"{quoted(finding.get('identity'))} received HTTP "
            f"{quoted(evidence.get('actual_status'))} where the capsule declares one of "
            f"{quoted(evidence.get('expected_statuses'))}"
        )
    if len(refused) > 5:
        listed.append(f"and {len(refused) - 5} more")
    proxy = any(
        (finding.get("evidence") or {}).get("actual_status") == _PROXY_REFUSAL
        for finding in refused
    )
    return (
        "the claim was not measured on this target: "
        + "; ".join(listed)
        + ". "
        + (
            "HTTP 407 is a proxy asking for its own credentials, so those "
            "requests most likely never reached the target. "
            if proxy
            else ""
        )
        + "A refusal the capsule does not declare is not the boundary it "
        "describes answering: a VERIDOR_* credential may be expired or not "
        "valid on this instance, a proxy or gateway may have answered, or this "
        "target refuses with a different status than the reporter's did. Fix "
        "whichever it is and re-run."
    )


def _unmeasured(
    capsule: dict[str, Any],
    probes: list[dict[str, Any]],
    run_document: dict[str, Any],
) -> list[str]:
    """What a run of the capsule's check did not measure, in words.

    Read from the probes the run recorded, not only from its findings: a
    matched probe emits no finding, so the absence of one is not evidence
    that anything was measured. The grading in ``core`` reaches the same
    conclusions today and turns each into an ``inconclusive`` finding; this
    holds the verdict to them independently, so NOT_REPRODUCED cannot become
    reachable again by a change there.
    """
    by_identity = {probe.get("identity"): probe for probe in probes}
    expect = (capsule.get("check") or {}).get("expect") or {}
    gaps: list[str] = []
    claimed = capsule["claim"].get("identity")
    if isinstance(claimed, str) and claimed not in by_identity:
        gaps.append(f"no probe was sent as {quoted(claimed)}, the identity the claim is about")
    for identity, expectation in expect.items():
        if not isinstance(expectation, dict):
            continue
        probe = by_identity.get(identity)
        if probe is None:
            if identity != claimed:
                gaps.append(f"no probe was sent as {quoted(identity)}")
            continue
        response = probe.get("response") or {}
        status = response.get("status")
        # Read through the config loader's own rule, not tested raw: `load`
        # already hands this a list, and this function is also called on
        # documents that never went through `load`. A bare `404` used to reach
        # `status not in declared` and raise TypeError (exit 70); a value that
        # declares no status is a declaration nothing can meet, so a gap.
        written = expectation.get("status")
        declared = declared_statuses(written)
        if probe.get("error") or declared is None or status not in declared:
            gaps.append(
                f"{quoted(identity)} received "
                + (f"HTTP {quoted(status)}" if status is not None else "no answer")
                + f" where the capsule declares one of "
                + quoted(declared if declared is not None else written)
            )
            continue
        scan = response.get("marker_scan")
        if expectation.get("excludes_marker") and scan != "absent":
            gaps.append(
                f"{quoted(identity)}'s response could not be shown free of "
                f"{quoted(expectation['excludes_marker'])}'s marker (scan: {quoted(scan)})"
            )
        if expectation.get("contains_marker") and scan != "present":
            gaps.append(
                f"{quoted(expectation['contains_marker'])}'s marker was not observed in "
                f"{quoted(identity)}'s response, so its absence elsewhere proves nothing"
            )
    liveness = run_document.get("liveness")
    unproven = liveness.get("unproven") if isinstance(liveness, dict) else None
    for entry in unproven or ():
        # A sequence step's entry carries its sequence id in check_id; a check
        # of the same name is a different request.
        if (isinstance(entry, dict) and "sequence_id" not in entry
                and entry.get("check_id") == capsule["claim"]["check_id"]):
            gaps.append(
                f"{quoted(entry.get('identity'))} received HTTP {quoted(entry.get('status'))}, "
                + (
                    "and no credential Veridor fabricated was sent to compare "
                    "with, so that denial does not show this target recognised "
                    "the identity's credential (a marker_probe on "
                    f"{quoted(entry.get('identity'))}, naming something it is "
                    "served, would prove it live)"
                    if str(entry.get("control") or "").startswith("withheld_")
                    else "and the credential Veridor fabricated to compare with "
                    "got no answer (its request failed), so that denial does not "
                    "show this target recognised the identity's credential"
                    if entry.get("control") == "control_errored"
                    else "and the credential Veridor fabricated to compare with "
                    f"drew HTTP {quoted(entry.get('control_status'))}, neither a "
                    "refusal nor a success, so that denial does not show this "
                    "target recognised the identity's credential"
                    if entry.get("control") == "control_uninformative"
                    else "and so did a credential Veridor fabricated, so that "
                    "denial does not show this target recognised the identity's "
                    "credential"
                )
            )
    return gaps


def load(path: Path) -> dict[str, Any]:
    try:
        capsule = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        # The config loader and the OpenAPI loader both refuse this cleanly;
        # the capsule loader was missed, so handing `verify` a binary file was
        # a traceback and exit 1 -- "the gate failed" -- for a wrong file.
        raise CapsuleError(
            f"{path} is not valid UTF-8, so it is not a Veridor capsule."
        ) from error
    except RecursionError as error:
        raise CapsuleError(
            f"{path} is nested too deeply to parse, so it is not a Veridor capsule."
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise CapsuleError(f"cannot read capsule {path}: {error}") from error
    if not isinstance(capsule, dict):
        raise CapsuleError(f"capsule {path} must contain an object")
    for key in ("kind", "identities", "check", "claim"):
        if key not in capsule:
            raise CapsuleError(f"capsule {path} is missing {quoted(key)}")
    # A capsule is untrusted input: a wrong shape is a refusal (exit 2), not an
    # AttributeError out of the verifier (exit 70, "internal error").
    for key in ("identities", "check", "claim", "target"):
        if key in capsule and not isinstance(capsule[key], dict):
            raise CapsuleError(f"capsule {path} {quoted(key)} must be an object")
    if not isinstance(capsule["claim"].get("check_id"), str):
        raise CapsuleError(f"capsule {path} claim is missing its 'check_id'")
    _refuse_terminal_controls(capsule, path)
    grade = capsule["claim"].get("evidence_grade")
    if grade is not None and not (isinstance(grade, str) and grade in EVIDENCE_GRADES):
        # Printed beside the verdict and quoted in Veridor's own CONFIRMED
        # reason, after the verdict word. `build` copies it from a finding,
        # which carries one of these or nothing, so anything else was edited
        # in: a 3774-character grade of spaces and a copy of a NOT_REPRODUCED
        # session wrapped into that session on an 80x24 screen over a real
        # CONFIRMED (exit 1; measured with GNU screen on a sized pty).
        raise CapsuleError(
            f"capsule {path} claim.evidence_grade is {quoted(grade)}, which is not "
            f"a grade Veridor writes ({', '.join(EVIDENCE_GRADES)}). The grade is "
            "printed beside the verdict, and `veridor capsule` never writes "
            "another. Nothing has been sent. Ask the reporter for the file "
            "exactly as `veridor capsule` wrote it."
        )
    claimed, checked = capsule["claim"]["check_id"], capsule["check"].get("id")
    if claimed != checked:
        # adjudicate() reads findings under the claim's id and the run writes
        # them under the check's, so a mismatch matched nothing and came out
        # NOT_REPRODUCED, exit 0, whatever the target did (measured with
        # nothing listening at all).
        raise CapsuleError(
            f"capsule {path} claims check {quoted(claimed)} but carries check "
            f"{quoted(checked)}. A verdict about one cannot be measured by running the "
            "other, so nothing has been sent. Ask the reporter for the file "
            "exactly as `veridor capsule` wrote it."
        )
    # Every status the check declares, read by the config loader's rule and
    # written back as a list. `adjudicate` reads this document, not the loaded
    # config, and the loader normalised only its own copy: the schema's
    # single-integer shorthand (`"status": 404`), which `veridor capsule`
    # copied verbatim, reached a membership test as an int and exited 70 on
    # the run where the boundary held. Anything that is no status is refused
    # here, exit 2, as the config loader would refuse it.
    expect = capsule["check"].get("expect")
    for identity, expectation in expect.items() if isinstance(expect, dict) else ():
        if not isinstance(expectation, dict):
            continue
        statuses = declared_statuses(expectation.get("status"))
        if statuses is None:
            raise CapsuleError(
                f"capsule {path} check.expect for {quoted(identity)} declares status "
                f"{quoted(expectation.get('status'))}, which is not an HTTP status "
                "(100-599) or a non-empty list of them. Nothing has been sent. "
                "Ask the reporter for the file exactly as `veridor capsule` wrote it."
            )
        expectation["status"] = statuses
    return capsule


def _texts(where: str, value: Any) -> Iterator[tuple[str, str]]:
    """Every string in ``value``, keys included, at any depth, with its place.

    Only a claim value that was itself a string used to be checked, so
    ``"check_name": ["ESC[2J..."]`` loaded without a word. The place is shown
    through terminal_text, so naming a key cannot print what it carries.
    """
    stack = [(where, value)]
    while stack:
        here, item = stack.pop()
        if isinstance(item, str):
            yield here, item
        elif isinstance(item, dict):
            for key, inner in item.items():
                place = f"{here}.{terminal_text(key)}"
                if isinstance(key, str):
                    yield place, key
                stack.append((place, inner))
        elif isinstance(item, list):
            stack.extend((f"{here}[{index}]", inner) for index, inner in enumerate(item))


def _refuse_terminal_controls(capsule: dict[str, Any], path: Path) -> None:
    """Refuse a claim or scope that carries a character a terminal obeys.

    These fields are display text: ``render`` prints the claim beside the
    verdict, and printed the capsule's scope until it began printing Veridor's
    own. A capsule whose scope began ``ESC[2J ESC[H`` cleared the screen and
    drew a CONFIRMED block over a real INCONCLUSIVE (reproduced), and U+202E
    reorders a line without any escape sequence. ``render`` escapes them
    regardless; this says out loud that the file was edited to do it, because
    ``build`` never writes one (it escapes them).
    """
    fields = [("claim", capsule["claim"]), ("scope", capsule.get("scope")),
              # Not printed by verify, but copied into every finding of its
              # run, which `report` prints: junit and codequality wrote U+009B
              # and U+202E from it raw to stdout (measured).
              ("check.name", capsule["check"].get("name"))]
    for where, value in (found for field in fields for found in _texts(*field)):
        found = list(dict.fromkeys(terminal_controls(value)))
        if found:
            what = "a character" if len(found) == 1 else "characters"
            raise CapsuleError(
                f"capsule {path} {where} carries {', '.join(found)}: {what} a "
                "terminal acts on instead of showing (an escape sequence, a bidi "
                "override, a line break). The claim is written to be read beside "
                "the verdict, so one of these can rewrite that verdict on your "
                "screen, and `veridor capsule` never writes one. Nothing has been "
                "sent. Ask the reporter for the file exactly as `veridor capsule` "
                "wrote it."
            )


#: The most of the reporter's statement ``render`` prints, in characters. The
#: statement is copied from a finding message (the demo's is about 500
#: characters), and the capsule file keeps all of it. A bound matters because
#: text that wraps can draw rows of its own: a 3814-character statement of
#: spaces and printable text left a whole NOT_REPRODUCED session on an 80x24
#: screen over a real CONFIRMED (reproduced with GNU screen on a sized pty).
_STATEMENT_LIMIT = 600

#: The bound for every other capsule field ``render`` prints: the one every
#: message applies to a value it quotes.
_FIELD_LIMIT = ECHO_LIMIT


def _shown(value: Any, limit: int = _FIELD_LIMIT) -> str:
    """A capsule-sourced value as ``render`` prints it.

    Terminal controls escaped (:func:`terminal_text`), every run of blanks
    made one space, and at most ``limit`` characters, with a note of how many
    more the file holds. Collapsing is not the bound -- a row can be padded
    with a printable blank such as U+2800 -- the limit is, and printing
    Veridor's own verdict after the last capsule-sourced line is what decides
    what the bottom of the screen says.
    """
    text = terminal_text(_BLANK_RUN.sub(" ", str(value)), limit=None).strip()
    return cut(text, limit, "more characters in the capsule")


def render(
    capsule: dict[str, Any],
    adjudication: dict[str, Any],
    target: str | None = None,
) -> str:
    """The text a maintainer reads. Verdict first and last, caveat attached.

    ``target`` is the instance actually probed, which is usually NOT the one
    recorded in the capsule -- the maintainer runs this against their own
    deployment. Printing the reporter's URL next to a verdict about the
    maintainer's would be a small lie in the one document whose entire job is
    to be believable.

    Everything that came from the capsule is printed ABOVE Veridor's own
    verdict line, and only Veridor's Scope sentence follows it. The reporter's
    statement used to be printed after the verdict and its reason, so a long
    one could scroll them away and draw a verdict of its own by wrapping.
    """
    claim = capsule.get("claim") or {}
    recorded = (capsule.get("target") or {}).get("base_url")
    probed = target or recorded
    verdict = adjudication["verdict"]
    # Every value below except the verdict word came from the capsule or from
    # a run of it, so every one is printed through terminal_text: a capsule
    # used to be able to clear the screen and print a verdict of its own.
    lines = [
        f"Veridor capsule — {verdict}",
        "",
        f"  check:    {_shown(claim.get('check_id'))}"
        + (f"  ({_shown(claim.get('check_name'))})" if claim.get("check_name") else ""),
        f"  verified: {_shown(probed)}",
    ]
    if recorded and probed != recorded:
        lines.append(f"  reported: {_shown(recorded)}  (the reporter's target, not this one)")
    if claim.get("finding_id"):
        lines.append(f"  claim:    finding {_shown(claim['finding_id'])} graded "
                     f"{_shown(claim.get('evidence_grade'))} by the reporter")
    if verdict == CONFIRMED and claim.get("statement"):
        lines += [
            "",
            "  The reporter's original statement:",
            f"    {_shown(claim['statement'], _STATEMENT_LIMIT)}",
        ]
    # Veridor's verdict and reason, after everything the capsule supplied.
    # The reason is Veridor's sentence; what it quotes from the capsule or the
    # run was bounded where it was written (quoted()), so it is escaped here,
    # not cut.
    lines += ["", f"  {verdict}: {terminal_text(adjudication['reason'], limit=None)}", ""]
    # The verifier's own scope, never the capsule's copy: the boundary of this
    # verdict belongs to the tool that measured it, and the capsule's copy is
    # whatever its author typed.
    lines.append(f"  Scope: {DECLARATION_SCOPE}")
    return "\n".join(lines)
