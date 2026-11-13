# Changelog

Notable changes to Veridor. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the usual `0.x`
caveat that the interface may still move.

## [Unreleased]

Nothing here has been released: there is no tag, and no package, image or
chart (see [0.1.0]). These entries record development before the first public
version, and no public version carried the earlier behaviour they describe. Read
"used to" and "now" as what changed during that development, and the Security
section as defects found and fixed before any release, not as advisories for
something you installed.

### Security

- **A session proved by two copies of its cookie kept sending after one copy
  changed.** A login that set `sid=attacker` on `/` and on `/docs` (or
  host-only and with `Domain=`) established, with both copies as the proof. A
  later response set `sid=guest; Path=/docs`, replacing one copy, and
  `/docs/1` went out as `Cookie: sid=guest; sid=attacker`. The refusal of a
  second value beside the proof (next entry) compared the request with every
  proof value, and the guest was one of them, so it found nothing different. A
  server that reads the first occurrence authenticated the guest, whose `404`
  matched the declared denial (reproduced: safe 2, vulnerable 0,
  `liveness.unproven` empty; with `other=guest` instead, `VERIDOR-AUTHZ-001`
  confirmed). Once the cookies that proved a session no longer carry one
  value, every request of that session is now refused as
  `session_cookie_ambiguous`, the rule a login already followed. Behaviour
  change: that includes a request that only the unchanged copy would reach.
- **A same-named cookie set after login rode in front of the session's
  cookie, and a live IDOR was graded safe.** A response after login set
  `sid=guest; Path=/docs`; the jar sends longer paths first, so a request for
  `/docs/1` went out as `Cookie: sid=guest; sid=attacker`. The check on the
  outgoing request found the proof cookie's value and let it go. A server that
  reads the first occurrence (Express's cookie-parser, PHP, Go's `r.Cookie`)
  authenticated the guest, whose `404` matched the declared denial
  (reproduced: safe 2, vulnerable 0, `liveness.unproven` empty, because the
  marker probe ran before the guest cookie arrived; with `other=guest`
  instead, `VERIDOR-AUTHZ-001` confirmed). A request that would carry the
  proof cookie, or a cookie a `${capture.…}` value was read from, beside a
  different value under the same name is now not sent and is graded
  `inconclusive`, with its own reason (`session_cookie_ambiguous`), the rule a
  login already followed. Behaviour change: a target that sets a second,
  differently valued session cookie on a sub-path now gets `inconclusive` on
  every request under that path, including where it would have authenticated
  the right one.
- **With `"reestablish": "check"`, a denial was proven live by a login it was
  not sent under.** The identity's `marker_probe` runs once, under the login
  before the first check; every check then logs in again. A re-login that drew
  a cookie the target treats as anonymous got the declared `404`, and the
  denial was graded `safe` with `liveness.unproven` empty, on the strength of
  the first login's marker (reproduced: safe 2, vulnerable 0; every login real,
  `VERIDOR-AUTHZ-001` confirmed). A 2xx in an earlier check, under that
  check's own login, cancelled it the same way. For such an identity, only a
  2xx in the same sequence, or the fabricated credential's answer, now proves
  a denial; otherwise it is listed in `liveness.unproven`, with advice to use
  `"reestablish": "run"` if sessions last the run. Behaviour change: a
  `"reestablish": "check"` identity whose denials were proven only by its
  `marker_probe` is now listed as unproven, and exits `3` under
  `--require-complete`.
- **A cookie read live is held to the checks a captured value gets.** A
  `cookie` capture read from the jar at send time now passes the same size,
  control-character and ASCII checks as one captured from a login response, a
  change made with the live login-step capture below and not recorded until
  now. Before it, a value with a space, a
  Latin-1 character or over 4096 bytes was injected into the request as is,
  and one outside Latin-1 failed inside the HTTP client and was reported as a
  failed request rather than one not sent (measured on each). Such a
  reference is now unresolved and the request is not sent. No test covered
  it; one does now.
- **A CSRF cookie that expired since login was reported as a configuration
  error.** A `${capture.…}` read from a cookie the target had set, and that
  had since expired, was refused as `unresolved_reference`: "the capture it
  names is not declared, or the login step meant to produce it did not find
  it", with configuration advice, and counted by the gate's vacuous-run message
  as withheld by the configuration. It now has its own reason,
  `capture_cookie_expired`, with session advice. A capture whose cookie never
  had a value in the current login keeps `unresolved_reference`. Nothing is
  sent either way, and the verdict stays `inconclusive`.
- **A login step's cookie capture outlived its cookie, and as the session's
  proof it kept an expired session live.** A capture declared on a login step
  was copied once and frozen, whatever its source. With `establishes:
  {"capture": NAME}` naming one read from a cookie, the session still looked
  live after that cookie expired, and the check on the outgoing request had no
  cookie to look for: the graded probe went out with an empty `Cookie` header,
  drew the target's anonymous `404`, and a confirmed IDOR was graded `safe`
  (reproduced: safe 2, vulnerable 0; with the cookie alive, `VERIDOR-AUTHZ-001`
  confirmed). A login step's `cookie` capture is now read from the jar when it
  is used, like a session-level one, so it expires with its cookie and is the
  cookie the request is checked for.
- **An empty session cookie established the session.** `Set-Cookie: sid=` is
  how a target clears a cookie, but establishing and liveness asked only
  whether a cookie of that name existed, so `establishes: {"cookie": "sid"}`
  succeeded on it and every probe went out as `sid=`, which the target
  answered as anonymous (reproduced: safe 2, vulnerable 0 over a confirmed
  IDOR). A capture proof already had to be non-empty. An empty cookie is now
  no value anywhere: it does not establish a session, keeps none live, and a
  `${capture.…}` reference to one is unresolved, so an empty CSRF cookie is
  no longer injected as an empty `X-CSRFToken` header that drew a CSRF `403`
  (reproduced: safe 2, vulnerable 0).
- **A different cookie of the same name stood in for the one that proved the
  session.** Liveness took any usable cookie of the proving name, and the
  check on the outgoing request matched by name. A `sid=guest; Path=/docs`
  beside the real `sid` outlived it, and the probe went out as the guest
  (reproduced: safe 2, vulnerable 0; the liveness disclosure listed the check
  as unproven). The proof is now the cookie itself, by name, domain and path,
  checked on the request by its current value; and a login that leaves two
  different values under the proving name does not establish, because which
  one the target authenticates is unknowable.
- **A CSRF token went out without the cookie it was read from.** A request
  carrying a value captured from a cookie, such as a CSRF cookie injected as
  `X-CSRFToken`, was sent when the jar left that cookie off: because its
  `Path` did not cover the URL, or because it expired between the moment its
  value was read and the moment the jar attached cookies. A double-submit CSRF
  check refused it with a `403` the declaration listed, and a confirmed IDOR
  was graded `safe` (reproduced both ways: safe 2, vulnerable 0). Such a
  request is now not sent and is graded `inconclusive`, with its own reason
  (`capture_cookie_not_sent`).
- **A session cookie that expired between the liveness check and the send
  went out missing, and a live IDOR was graded safe.** Each request asked
  whether the session was still live, then the cookie jar read the clock
  again when it attached cookies and silently left off one that had expired
  in between. The probe went out anonymous; against a target that answers an
  anonymous request with a `403` or `404` the declaration lists, a check
  probe was graded `safe` and a sequence assert step `matched` over a
  confirmed IDOR (reproduced by forcing the expiry into that gap; measured on
  a real clock, the gap is about 0.012 ms median and 0.113 ms at worst, so
  rare but silent). Only a `401` was caught, by the session-401 rule. The cookie
  named in `establishes` (or behind an `establishes` capture read from a
  cookie) is now looked for on the request after the jar has attached its
  cookies; if it is missing nothing is sent and the request is graded
  `inconclusive` as an expired session. The same check refuses an
  establishing cookie whose `Path` or `Domain` does not cover the request's
  URL, which also went out anonymous, with its own reason
  (`session_cookie_not_sent`). A session established by a capture from a
  login response's header or body is unaffected: its value is already in the
  request.
- **A drift document's counts were pasted into the Markdown summary as
  markup.** `report --from-drift` checked the drift document's kind, schema
  version and containers but not its counts, and the summary interpolated
  them raw, `redirect_now_served_cells` in the bold headline. A string there
  put HTML and a link under "N that mean more access". A count that is not a
  non-negative integer is now refused with exit `2`, and the renderer escapes
  one it is handed anyway. A string in `redirect_cells`, which crashed the
  render with a `ValueError` in a document without `measured_in_both_cells`,
  is refused the same way.
- **A captured URL under a base path was requested with the base path doubled,
  and a live IDOR passed clean.** With `target.base_url` ending in a path such
  as `/api/`, a captured same-origin `Location` (`https://host/api/notes/n1`
  or `/api/notes/n1`) was joined under the base path again and requested as
  `/api/api/notes/n1`; that route's `404` matched a declared `[403, 404]` and
  the run passed. A captured path that starts with the base path, whether it
  is the whole step path or starts one (`${where}/comments`), is now
  re-expressed relative to it, and a same-origin absolute URL outside the base
  path is refused (`outside_base_path`) instead of being requested under it. A
  same-origin absolute URL that starts a step path (`${where}/comments` with
  `https://host/api/notes/n1`) was refused as `not_absolute` and graded
  `inconclusive`; it now gets the same origin check and re-expression as a
  whole-path capture, and one from another origin is refused as
  `cross_origin`. A captured value with a query (`/api/notes/n1?created=1`,
  absolute or from the origin root) put the step path's suffix inside that
  query, so `${where}/comments` requested `/api/notes/n1?created=1/comments`
  (the note itself, not its comments) and a denial there passed clean; the
  suffix now goes on the path and the captured query follows it
  (`/api/notes/n1/comments?created=1`, joined with `&` to any query the step
  path declares), and a captured fragment under a suffix is refused
  (`fragment`). A base URL without a path was not affected.
- **A session's `form_field` or `json_field` injection was skipped without a
  word, and the request went out without its token.** A `body` with no
  `Content-Type` (which urllib sends form-encoded), a write with no body, or a
  body of the wrong kind (a JSON array, say) left the field out, so a CSRF
  `403` matched the declared denial and the run passed. A `body` with no
  `Content-Type` now carries a form field, and a graded request that cannot
  carry its field is not sent (`injection_not_applicable`) and graded
  `inconclusive`; its finding says "Request not sent" and gives the
  configuration fix (a form-encoded or JSON object body, or drop the field
  from `session.inject`), where it first said "Request failed" and told the
  operator to confirm the target was reachable. A bodyless `GET`, `HEAD` or `OPTIONS` and a teardown request
  still go out without it, and each one, whether a check probe, sequence step,
  teardown entry or marker probe, is listed in `injection_disclosures`, on the
  console, on the dashboard, in SARIF, and in every `veridor report` format.
- **A captured value holding a planted marker in encoded form was sent back to
  the target.** The send-time check that keeps a marker out of outgoing
  requests was a plain substring test, so a capture holding the marker
  base64-, percent- or `\u`-encoded went out, and a target that decodes and
  echoes its input was graded VERIDOR-LEAK-001 `confirmed`. Sequence steps and
  session substitutions now decode the value the way the load-time check does,
  so an encoded marker blocks the step (`marker_reflection_blocked`,
  `inconclusive`). That decoding stops at 256 variants, and which ones it kept
  followed the per-process string hash, so a session capture of a few hundred
  hex- or base64-shaped tokens had its hidden marker found in some runs and
  sent in others. The variants are now walked in a fixed order, and a value
  whose decodings pass the cap is not sent: the step aborts with
  `marker_check_incomplete`, and a session request is not sent with the
  same reason, both `inconclusive`. The load-time check still read a value
  that decoded past the cap as "no marker", so a check, sequence step or
  teardown entry, login step, session `inject` or `marker_probe` holding one
  loaded with a marker in a decoding nobody read. Such a configuration is now
  refused at load with exit `2`, naming the request, as is a value longer
  than the 64 KiB the decoder reads; the raw value is also searched, as it is
  at send time.
- **A marker in a session `inject` value went out on every request.** The
  load-time reflection check read static headers, check requests, login steps
  and `marker_probe`, but not `inject`, so a literal marker there was sent on
  every request after login and a target that echoed it was graded
  VERIDOR-LEAK-001 `confirmed`. Such a configuration is now refused at load
  with exit `2`, as the same value in a static header already was.
- **A second check on the same request could switch off the marker-uniqueness
  control.** The fabricated-credential control was scanned for one owner's
  marker per method and path, the last check declared winning, so a later
  status-only check, or one excluding a different owner, left an earlier
  check's shared marker (a build id served to everyone, say) unscanned, and it
  graded `confirmed`. The one control request is now scanned for every owner's
  marker on that request, with no extra request sent.
- **A TLS key still loaded, and did nothing, below the identity and check
  level.** `verify_tls`, `ca_file`, `client_cert` or a `tls` block in a
  session, a session `inject` entry, a login-step or session capture spec, a
  per-identity expectation, a sequence, or a sequence step or teardown entry
  or its `expect` loaded as an annotation, while the README says a
  configuration naming a TLS setting is refused. Each is now refused with exit
  `2` and the same message as at the root, the target, an identity and a
  check.
- **A hand-built `map` plan could get past the mutating-request budget by
  mislabelling its probes.** The 50-request mutating budget and the banner's
  listing of mutating requests read each probe's `mutating` flag rather than
  its method, so a plan of DELETE probes flagged `mutating=False` passed both
  and could send up to `max_requests` of them. Both now count any method other
  than GET or HEAD as mutating, whatever the flag says. Only a library caller
  building a plan by hand could do this; plans from `plan_matrix`, and so the
  CLI, were not affected.
- **An OpenAPI path key could drive the terminal through `veridor init` and
  `veridor coverage`.** Two `init` parse warnings
  (`ignored_operation_servers`, `duplicate_template`) and `veridor coverage`'s
  text report (its uncovered and weak-coverage lists, base-path line and
  diagnostics) printed spec path keys and check paths raw, so an escape
  sequence or bidi override in a hostile spec reached the terminal from a
  command that exits `0`. The warnings now quote the template, the report
  shows each value escaped, and every value a `coverage` diagnostic quotes,
  the request method included, is cut to 120 characters, the bound every other
  quoted value has; before, a key padded with blanks (U+2800 and U+3164 among
  them) could carry a forged summary of any length onto a row of its own.
- **A capsule, and the Helm chart, published literal one-time codes and
  PINs.** The credential-name rule had no second-factor names, so a literal
  under `passcode`, `pin`, `pinCode`, `otp`, `totp`, `mfa_code`,
  `verification_code` or `client_assertion` in a session login body was
  written into the capsule and rendered by the chart, while the same value
  under `password` was refused. Those names now count in both refusals, which
  share one rule; `spin`, `laptop` and `otp_enabled` still do not.
- **The GitLab component could leave a proxy in place while logging that none
  was set.** Its proxy removal found `*_proxy` variables with `env`, `sed` and
  `printenv` and never checked those tools existed, so in a job image missing
  one of them nothing was removed, the log said "no proxy variable is set",
  and `http_proxy` or `HTTPS_PROXY` carried every request, credentials
  included, to the proxy. The job now refuses such an image with exit `2`
  before anything is sent. The shipped images have all three tools.
- **`scripts/secrets_audit.py` let a fixture hint anywhere on a line excuse a
  real credential.** The hints include `veridor`, `xxx`, any lowercase tag and
  `localhost`, so a real-shaped token in `VERIDOR_GH_TOKEN`, in a `<td>` or
  beside a `# xxx` comment gave "0 finding(s) need review" and exit `0`. A
  hint is now read from the matched value only, and a CRITICAL hit counts
  toward the verdict even when it is tagged. The password, secret and
  AWS-secret rules also now match a JSON key (`"password": "..."`) and an
  environment-variable name (`DB_PASSWORD=`, `APP_SECRET=`), which they missed
  entirely. The AWS-secret rule's match ran past its value to the next space,
  so on a compact JSON line or a `a=b&c=d` query string a later field's
  `localhost` still excused a real key; its value is now captured on its own
  and only that is searched. The captured value is 20 characters or more up
  to a space, a quote, a backslash or a separator (`,`, `&`, `;`, a bracket),
  after a `=`, a `:` or a space (as in `aws configure set
  aws_secret_access_key KEY`, when the next word has a lowercase letter or a
  digit, so an environment variable's name is not read as a value), then any
  run of punctuation and an optional string prefix, so a key in a shell string
  (`echo "aws_secret_access_key=\"KEY\""`), a YAML flow list (`["KEY"]`), a
  Python string prefix (`b'KEY'`, `r"KEY"`) and a doubly escaped quote, each
  of which an earlier form of that capture stopped matching, still count.
  One form bounded it to the AWS alphabet, 40 or more, which dropped a
  31-character B2 key and a value with `-`, `_` or `.` that the previous rule
  had counted, and one dropped the previous rule's `=` or `:`, so a list of key
  names read the next name as a value. A JSON-escaped slash (`\/`, as PHP writes
  every `/`) no longer ends the value; the previous rule missed a secret written
  that way too. A
  value that is a whole `{NAME}` format placeholder is tagged, as `${NAME}`
  is, and the space separator reads only the value's own characters, so a
  variable name followed by an escaped `\n` is not read as a secret.

- **`map` and drift counted a proxy's 407 as a measured refusal.** A 407 is
  Proxy Authentication Required, the proxy's own answer before the request
  reached the target, but `matrix.classify_reach` recorded it as the
  credential being refused. A drift gate behind a proxy answering 407 to
  everything therefore compared a run that reached nothing with a measured
  baseline, and could pass. A 407 is now an unmeasured cell
  (`proxy_auth_required`), so such a comparison exits `3`, and a row of 407s
  is no longer read as a credential the target never accepted. `run` and
  `verify` already treated a 407 as the proxy's answer.

- **`veridor coverage` quoted spec routes and config paths unbounded.** Its
  no-matches refusal joined the spec's route templates, the config's check
  paths and the base-path candidates in raw, and the command printed that
  refusal itself, past the bound every other refusal goes through: a route
  whose template carried newlines and a copy of a genuine session drew a
  verdict below the real refusal, and a run of spaces wrapped into rows of its
  own. Each value is now shown, not obeyed, and bounded, and the refusal goes
  through the same line bound as the rest.

- **`verify` said NOT_REPRODUCED when nothing had been measured.** A run
  whose probes were refused with a status the capsule does not declare fell
  through to "the declared expectation held on this target", exit `0`.
  Measured: a vulnerable target behind a proxy answering `407` to every
  request received none of them, and the verifier's stale `VERIDOR_*` tokens
  drew `401` from a vulnerable target; both printed NOT_REPRODUCED. Now
  NOT_REPRODUCED needs every identity of the check answered with a declared
  status, every graded marker observed where it had to be, and no denial that
  the liveness control's fabricated credential drew too. Anything else is
  INCONCLUSIVE, exit `2`, naming each identity and the status it received. A
  target that refuses with a different status than the capsule declares
  (`404` where it says `403`) is now INCONCLUSIVE too. With
  `--no-prove-liveness` a NOT_REPRODUCED says the control was off.
- **A capsule's `check.name` and non-string claim values escaped the
  control-character rule.** Only claim values that were strings were
  checked, so `"check_name": ["ESC[2J..."]` loaded, and the check's own
  `name`, which every finding of the run carries into `report`, reached
  stdout raw from the JUnit and Code Quality formats (U+009B and U+202E,
  measured). Every string in the claim, keys included, and `check.name` are
  now held to the rule at load, exit `2`; `veridor capsule` writes the check
  name escaped, so what it writes `verify` accepts.
- **A long reporter statement could draw a verdict by wrapping.** `verify`
  printed the capsule's `claim.statement` after its own verdict and reason,
  with no bound on its length or its runs of spaces. Reproduced with GNU
  screen on an 80x24 pty: a 3814-character statement of spaces and printable
  text, against a vulnerable target (exit `1`), left a complete
  NOT_REPRODUCED session on the visible screen. The capsule's fields are
  now printed above Veridor's verdict line, which names the verdict
  (`CONFIRMED: the declared expectation failed here as well.`) and is
  followed only by the `Scope:` sentence. The verdict line's own reason can
  still quote the capsule (an identity name, the grade the reporter
  claimed), bounded like every other quoted value. The statement is shown
  with runs of spaces collapsed (U+00A0 and the other space separators
  included) and cut at 600 characters, every other capsule field at 120.
- **The claimed evidence grade reached Veridor's verdict reason whole.**
  `verify` quotes the capsule's `claim.evidence_grade` in its own CONFIRMED
  reason, after the verdict word, and accepted any value there. Reproduced
  with GNU screen: a 3774-character grade of spaces and a copy of a
  NOT_REPRODUCED session, against a vulnerable target (exit `1`), left that
  session on the 80x24 screen. A grade that is not one Veridor writes
  (`n/a`, `ungraded`, `suspected`, `confirmed`) is now refused at load, exit
  `2`, before anything is sent, and the grade is quoted bounded wherever it
  is printed. `veridor capsule` refuses to copy such a grade from a
  hand-edited `--from-run` document, so what it writes `verify` accepts.
- **A proxy answering `200` to everything reads as CONFIRMED (documented,
  not changed).** Measured: through a proxy that answered `200` with its own
  page to every request, `verify` printed CONFIRMED, exit `1`, graded
  `suspected`, and the counting target received none of the four requests.
  The run records the same statuses, marker scans and liveness result as an
  endpoint that serves anyone, and a genuinely vulnerable instance where the
  reporter's markers were never planted also leaves the owner's marker
  unobserved, so grading it INCONCLUSIVE would do the same to real
  findings. The README's `verify` section now says so and what to check.
- **The proxy notice promised an `https://` target's requests were
  unreadable.** It said the proxy "sees only the host and port of each
  connection", and SECURITY.md and the README said the same. A proxy that
  inspects TLS with a certificate authority the runner trusts, as corporate
  egress proxies commonly do, reads every request: measured, an inspecting
  proxy logged both identities' bearer tokens under that notice. The notice
  and both documents now say a tunnelling proxy sees the host and port and
  an inspecting one reads everything, and that Veridor cannot tell which it is.
- **Proxy-handling gaps.** The notice decoded the whole proxy address,
  so `http://user:pass%40host:3128` printed the password as part of the host
  (measured); a proxy value that is not `host:port` after its
  `user:password@` is now refused with exit `2`, unprinted. An `https://`
  proxy for an `https://` target was spoken to in plaintext (urllib opens the
  tunnel over plain TCP, CONNECT and `user:password` included); it is now
  refused with exit `2`. For an `http://` target urllib does use TLS to an
  `https://` proxy (measured), so that stays, and the session's cookies are
  now attached before the proxy is set, as urllib orders it, so a Secure
  cookie is no longer attached to a request for an `http://` target. The
  hint "Set NO_PROXY=host" did nothing when a lower-case `no_proxy` was set,
  or for an IPv6 host; it now names the variable urllib reads and the
  bracketed host. `--wait-for-target` checks the target directly, and its
  line now says so when a proxy carries the requests.
- **A refusal could still print a line the input chose.** Refusals kept
  newlines, and many joined keys or values from the capsule or configuration
  into the message as they were: the unsupported-keys lists, "references
  unknown identities", "defines none of", the methods a capsule would write
  with, a capsule's `schema_version`, the capsule writer's check and identity
  lists. Reproduced: a capsule whose `expect` key ended in thirty newlines
  and a copy of a genuine NOT_REPRODUCED session exited `2` and sent nothing,
  and the screen showed that session with the real refusal scrolled off. Each
  of these now shows a newline as `\n`, like an escape sequence; Veridor's
  own multi-line refusals are unchanged.
- **A refusal could still draw a screen by line wrapping.** Escaping the
  newline left the length: a value a refusal quoted was printed whole, and a
  line that wraps draws rows of its own. Reproduced with GNU screen on a
  sized pty: a capsule whose `expect` key was `anonymous`, spaces and a copy
  of a genuine session, each line padded to 80 columns (4097 characters, no
  control character), exited `2` and sent nothing, and the 80x24 screen was
  that session, NOT_REPRODUCED or CONFIRMED, row for row the same as a
  genuine one, with the real refusal wrapped off the top; a 120-column build
  did the same at 120x30. A value a message quotes from the input is now
  shown with each run of blanks (the Unicode space separators and the tab)
  as one space and at most 120 characters, then `... (N more characters)`,
  and a list of keys stops at about twice that and counts the rest. Every
  `{value!r}` outside the OpenAPI and coverage modules goes through one
  bounded helper (a test holds that), and so do the refusal lists,
  `verify`'s banner and verdict reason, the check, identity and sequence
  names on `run`'s finding lines, and the identities and operations in
  `map`'s candidates and notes. A refusal line longer than 1000 characters
  keeps its start and its end, for a value quoted somewhere that was missed;
  the OpenAPI and coverage refusals rely on that alone (those two modules
  import only the standard library). Measured after, on the same pty: the
  refusal line stays on screen at 80x24 and 120x30. The tests plant long
  space-padded and name-shaped values in every key and leaf of a capsule and
  a configuration.
- **A capsule could print its own verdict over the real one.** `verify`
  printed the capsule's `claim` fields, its `scope` and its recorded
  `base_url` verbatim. Reproduced: a `scope` beginning `ESC[2J ESC[H` cleared
  the terminal and drew a CONFIRMED block over a real INCONCLUSIVE (and a
  NOT_REPRODUCED over a real CONFIRMED works the same way), `claim.check_id`
  rewrote its own line, U+202E in `claim.check_name` reordered it, and C1 or
  bidi characters in `target.base_url` reached the banner. The exit code was
  right each time. Now a `claim` field or `scope` carrying a terminal control
  (C0, C1, a line break, a Unicode format control) is refused at load with
  exit `2`, naming the field and the code point; a base URL with a C1 or
  format control is refused like one with a C0 control; everything `verify`
  prints from a capsule or its run, and every refusal, shows such characters
  escaped (`\x1b`); the `Scope:` line is Veridor's own; and `veridor capsule`
  writes a check name or finding message that carries one escaped, so what
  it writes `verify` accepts.
- **Requests went through a proxy nobody configured for Veridor, silently.**
  SECURITY.md said Veridor connects only to the target, and `verify` said a
  capsule's values go to its loopback target. The opener used urllib's
  default proxy handling, which reads `http_proxy`/`https_proxy` and, on
  macOS and Windows, the system proxy settings, and applies them to loopback
  too. Measured with a counting target and proxy: with `http_proxy` set, or
  with only a (simulated) system proxy, the target received nothing and the
  proxy every probe, bearer tokens included, and nothing said so. Now only
  the environment variables count (`no_proxy` honoured), the system settings
  are never read, a loopback target is always reached directly, and `run`,
  `verify` (in its banner), `map` and `mutate` say on stderr, before the
  first request, which proxy carries the requests, from which variable, and
  what it can read. A proxy variable urllib cannot read a host from (such as
  `http:/proxy`) is refused with exit `2` before anything is sent, without
  printing its value; it crashed the run with exit `70`.
- **A `Host` header retargeted requests past every containment check.** A
  header map accepted `Host`, urllib sent it instead of the host in the URL,
  and the origin, base-path and dot-segment checks read only the URL.
  Measured on the wire: a capsule's `Host: admin.internal` in its check, its
  identity or its marker probe reached the listener as the request's Host,
  and the liveness sham reused the name. Behind a gateway that routes by
  Host, that delivers the verifier's credentials to another virtual host. A
  `Host` header is now refused with exit `2`, in any case, in every header
  map (checks, identities, marker probes, login steps, sequence steps and
  teardown) and as a session `inject` target, and a request that somehow
  carries one is refused before it is built.
- **`..%2f` got past the dot-segment rule.** The rule split a path on a
  literal `/` and then decoded each segment, so `..%2fservice-b` decoded to
  `../service-b`, not `..`, and passed at load and at send. Reproduced:
  `verify --base-url http://gateway/service-a/` with a capsule path of
  `/..%2fservice-b/admin` was sent with the verifier's tokens, and nginx
  1.27, which decodes `%2f`, routes that path to service-b (measured behind
  a path-routed nginx). A decoded segment is now split
  again on `/` and `\`, and decoded until it stops changing, so `..%2f`,
  `..%2F`, `..%5c`, `..%252f` and `..%25252f` are refused like `..`, in
  `run`, `verify`, `map` and sequence steps; a segment still decoding after
  eight rounds is refused too. It was decoded exactly twice at first, so
  `..%25252f` passed. An overlong UTF-8 encoding of an ASCII character is
  read as that character, so `..%c0%af` and `%c0%ae%c0%ae` are refused (a
  lenient decoder reads them as `../` and `..`, as IIS 4 and 5 and Tomcat
  in CVE-2008-2938 did; no server was measured here); they passed as two
  U+FFFD. Spellings only one server family reads, such as IIS's `%u002e` or
  trailing spaces, are not judged. An encoded `/` inside a name
  (`group%2Fproject`) is kept.
  A `map` specimen value such as `../../admin`, planned before as
  `..%2F..%2Fadmin`, is now refused.
- **`..;` got past the dot-segment rule.** A segment was compared whole with
  `.` and `..`, so `/..;/service-b/admin` (and `.;`, `%2e%2e;`, `..%3b`,
  `..;jsessionid=x`) passed, and `verify --base-url
  https://gateway/service-a/` sent it with the verifier's tokens. Tomcat and
  Jetty drop a `;` path parameter before normalising, so behind one that
  reaches `/service-b/admin` (the servlet side was not measured here). A
  segment is now judged by what comes before its first `;`, decoded or not,
  in `run`, `verify`, `map` and sequence steps alike.
- **A capsule whose claim named another check always said NOT_REPRODUCED.**
  `verify` read findings under `claim.check_id` while the run wrote them
  under `check.id`, so when the two differed nothing matched: measured with
  nothing listening at all, the verdict was `NOT_REPRODUCED`, exit `0`, "the
  declared expectation held on this target". Such a capsule is now refused
  at load with exit `2`, naming both ids.
- **`veridor verify` no longer sends your secrets, or writes, where a capsule
  says.** A capsule is written by someone else, and `verify` treated it as
  trusted configuration. Reproduced: a capsule whose identity header read
  `Bearer ${MY_CLOUD_SECRET}` and whose `base_url` was its author's listener
  made `verify` send the verifier's `MY_CLOUD_SECRET` there. Now, before
  anything is sent: every `${NAME}` in a capsule must match
  `VERIDOR_[A-Z0-9_]+`, a set derived from the capsule's content (its own
  `requires_environment` is not trusted); a target that is not loopback needs
  an explicit `--base-url`; and a capsule with any method other than GET, HEAD
  or OPTIONS needs `--base-url` even on loopback. Each refusal exits `2`.
- **A request path could still send every identity's credentials to another
  host.** `/http://host/x` passed the path check, which parsed it as written
  (no scheme, no host), and then became an absolute URL when its leading `/`
  was stripped and it was joined onto `base_url`. Reproduced: `veridor verify`
  on a loopback capsule whose check path was `/http://127.0.0.1:<port>/steal`
  sent 4 requests to that port, 2 carrying the verifier's `VERIDOR_*` tokens,
  with no flags, with `--base-url` and with `--read-only`; a
  `marker_probe.path` and `veridor run --read-only` with the path in a
  configuration did the same. Such a path is now refused at load with exit
  `2` and nothing sent, in checks, marker probes, login steps and sequence
  steps, and in a sequence path resolved at run time. Every request is also
  checked against the target's origin once more before it is sent. `verify`
  loads the capsule before it prints where it will send your values.
- **Expanded `${NAME}` values were written to disk and printed.** SECURITY.md
  said credentials are not written to any artifact and the README that no
  token is written to disk; that held for header values only. A `${NAME}` in a
  path segment or a `;jsessionid=` path parameter was written as its value to
  the run document, the managed history and the GitLab SAST report, and
  `report --from-run` printed it; the liveness block wrote query values that
  every other URL field redacted. Every value Veridor expands is now written
  back as its `${NAME}` (as written, percent-encoded and `+`-encoded, and in
  the two spellings Veridor's own URL handling produces: lower-cased in a host
  name, and decoded and re-encoded in a query parameter name) in every JSON
  document and report it writes and on stdout and stderr, tracebacks
  included, and the liveness block redacts query values. The two URL
  spellings were missed at first: a mixed-case `${NAME}` in the base URL's
  host was written lower-cased to every artifact and to the `Target:` line.
  A value shorter than 8 characters is not replaced, because it cannot be
  told apart from ordinary text; the command names each such `${NAME}` on
  stderr instead. A literal credential typed into a configuration or a flag
  such as `--base-url` is not recognised and is written as typed.
- **`verify --read-only` was ignored.** A DELETE capsule sent its DELETEs with
  the flag set. `--read-only` now refuses a mutating capsule, a session login
  included, before anything is sent. Every other run option typed next to a
  capsule is refused by name instead of dropped, and `--json` and `--sarif`
  now write the capsule run's documents.
- **`veridor capsule` could publish a literal credential.** It checked identity
  headers only; a literal password in a session login body, a literal token in
  a check, marker-probe or login header, a session inject value, a
  credential-named query parameter and a `user:pass@` URL were all copied into
  the capsule (8 of 8 reproduced). The finished capsule is now scanned, and a
  hit exits `2` naming the JSON path, never the value. Nothing is written.
- **A literal one level down under a credential name was published.** Both
  `veridor capsule` and the Helm chart's render refusal walked an object
  under a credential-named key by the ordinary rules, so Okta's
  `credentials.password.value`, `oldPassword.value`, Keycloak's
  `credentials: [{type: password, value: ...}]` and reset-password body,
  `{"password": {"value": ...}}` and name/value lists
  (`[{name: password, value: ...}]`) went into the capsule, which said it
  carried no credential, and into the chart's ConfigMap (measured, both).
  Keys under any `capture` map also skipped the name check, so
  `{"capture": {"password": ...}}` in a request body passed. Now every
  string or number anywhere beneath a credential-named key must be a
  reference, except under keys that describe the credential (`type`,
  `temporary`, `username`, `user`, `email`, `id`, `name`); an object whose
  `name`, `key`, `field` or `type` holds a credential name has its `value`
  held to the same rule; and a capture map exempts a credential-named key
  only when its value is an extractor. A non-secret under a credential key
  in another slot (`{"secret": [{"note": "blue"}]}`) is now refused too.
- **The chart and `veridor capsule` read whitespace differently.** Their
  shared patterns used `\s`, which is ASCII in Go and Unicode in Python, and
  Python's `strip()` removes U+001C-U+001F where Go's `trim` does not. So the
  chart rendered into its ConfigMap literals the capsule refused: a form body
  `a=1&<U+00A0>key=...` or `<U+000B>key=...`, and JSON text after a U+001C
  holding a literal password (measured with helm template). Both now use
  Go's reading: `[\t\n\f\r ]` in the patterns, and `strings.TrimSpace`'s
  characters when trimming. The capsule now refuses a U+00A0 in URL userinfo
  or between `Bearer` and a reference, as the chart did, and accepts a name
  preceded by U+00A0 or U+000B and JSON text after a U+001C, as the chart
  did. The docs had said the chart only ever refused more.
- **The documented check for release files accepted a substituted file.**
  SECURITY.md and the notes every release publishes said
  `gh attestation verify FILE --repo Veridor-authz/veridor`. That accepts an
  attestation from any workflow in the repository at any ref, so a workflow
  pushed on a branch could replace a release file and attest the
  replacement. Measured with gh 2.95.0 on another project's real attestation,
  made on `refs/heads/main`: `--repo` alone passed it, and an exact
  `--cert-identity` passed only the real signer. Both places now pin
  `--cert-identity https://github.com/Veridor-authz/veridor/.github/workflows/release.yml@refs/tags/vX.Y.Z`,
  and SECURITY.md says what a pass does and does not prove. The Jenkins,
  Azure and CodeBuild zipapp notes point to that command instead of
  `SHA256SUMS`, which comes from the same page and cannot detect a
  substitution.
- **Whoever could start a Jenkins or Azure build chose where the credentials
  went.** The Jenkins template took the base URL as a `string` build
  parameter and the Azure template as a runtime parameter, and Veridor sends
  every identity's credential to the base URL. Measured: the two templates'
  gate shells, run with only that value changed, sent the owner,
  other-tenant and admin tokens to a capture server. The same parameters
  could turn the gate down: Azure's `failOn` offered `none`, and Jenkins'
  and Azure's allow-unmeasured switches turned exit `3` green. The base URL,
  the configuration, the fail-on policy, the baseline and the exit-3 switch
  are now `environment` entries in the Jenkinsfile and a `variables:` block
  in the Azure YAML, changed by a commit. On Jenkins 2.568.3 an `environment`
  entry beat a build parameter of the same name, declared or added in the job
  (measured). Azure documents that a YAML variable cannot be overridden at
  queue time. The CodeBuild buildspec and `ci/README.md` say that
  `StartBuild` can override any variable and the buildspec, and name the IAM
  condition keys that deny it. The GitLab docs say a `base_url` variable is
  safe only where pipeline variables are restricted, because GitLab ranks a
  pipeline variable above the dotenv value.
- **A proxy variable set when a pipeline started redirected every credential,
  literal base URL or not.** The docs said a literal `base_url` changes only
  by a commit. Veridor follows `http_proxy` / `https_proxy` for a target that
  is not loopback, and a GitLab pipeline variable or an Azure queue-time
  variable of that name reaches the gate. Measured outside both platforms,
  with the literal base URL `http://staging.invalid:8080`: the GitLab job and
  the Azure gate step each sent 9 requests carrying the owner, other-tenant
  and admin tokens to a capture server named only by `http_proxy` or
  `HTTP_PROXY`. The GitLab component now runs Veridor without any `*_proxy`
  variable (any case) unless the new `proxy_from_environment` input is
  `true`, and says in the job log which ones it removed; in the end-to-end
  run the recording proxy then received 0 requests, and 9 with the input
  `true`. This is a change for a runner that needs a proxy to reach the
  target: set `proxy_from_environment: true`. The Jenkins, Azure and
  CodeBuild templates, `ci/README.md` and the README now name the proxy and
  `PIP_INDEX_URL` variables, and each platform's setting that decides who may
  add a variable when a build starts (GitLab's Minimum role to use pipeline
  variables, Azure's Limit variables that can be set at queue time, Jenkins'
  `keepUndefinedParameters`, CodeBuild's environment-override deny).
- **A TLS key in a configuration was accepted and did nothing.** Unknown
  keys are annotations, so `client_cert` on an identity, or `ca_file` or
  `verify_tls: false` on the target, loaded without a word (measured): no
  client certificate was presented, and verification stayed as it always is.
  The loader now refuses a key that names a TLS setting (`cert`,
  `client_key`, `ca_file`, `verify`, `insecure`, anything starting `tls` or
  `ssl`, and the like) wherever a configuration holds settings -- the root,
  the target, an identity, a check and a check's request -- with exit `2`, and
  says to use `SSL_CERT_FILE` and `SSL_CERT_DIR`. It first covered only the
  target and identities, while the README said any configuration naming one
  was refused: a root-level `ca_file` meant to narrow trust loaded and left
  the default store in force (measured). A key starting with `_` is still an
  annotation.

### Added

- **Datasette CVE-2023-40570 in the detection baseline, the first pair built
  from published files.** On 1.0a3 the API explorer at `/-/api` answered an
  unauthenticated caller on an instance whose metadata allows view-instance to
  one actor; 1.0a4 refuses it (fix `01e0558`). No image of either release
  exists, so a fixture may now carry a `build` block in place of digests: a
  recipe under `fixtures/pairs/recipes/`, a base image by digest, and each
  side's published file by its sha256. Anything looser is refused at load. The
  harness builds both sides before any pair runs, with `pip --require-hashes`,
  asks each image which release it holds, and tags it with a hash of every
  input; a failed build fails only that pair. The pair is status-only: in this
  configuration the 1.0a3 page names no database or table to the anonymous
  caller (0 hits for either name, 2 each in the owner's page). It is the
  second pair guarding the status oracle: blinding that oracle to an
  undeclared 200 fails it, blinding the marker oracle does not (measured). A
  second check, the instance root, is refused on both releases and must pass on
  both, so the differential is the explorer and not an open instance.
  `scripts/pair_sizes.py` sizes a built pair from its base's registry and each
  pinned file's PyPI entry, found by hash: 0.05 GB, and 1.12 GB for every pair
  together. The lock carries both architectures' hashes for its two compiled
  wheels; resolved on arm64 alone, pip refused it on linux/amd64 (measured).
- **Ghost CVE-2021-39192 in the detection baseline.** `core/server/models/
  integration.js` overrode `permissible()` to add a hosted-plan limit check and
  then `return true`, discarding the permission answer it was overriding, so a
  Contributor could list every integration with `?include=api_keys` and read
  each one's admin API key: an escalation to full Admin on the API. 4.10.0
  checks the permission and throws. Both routes are checks: the list and the
  single integration by id, each measured leaking on 4.9.4 and refused on
  4.10.0 with the Contributor's session still valid there. It is the defect
  shape this project names for itself, a permission hook that reads as
  enforcing and enforces nothing, in someone else's code. 0.19 GB.
- **`scripts/patched_pairs.py --pairs-dir DIR` runs pairs the repository cannot
  carry** (repeatable, or `VERIDOR_PAIRS_DIR`). A fixture describes the bug it
  tests, so a finding whose details are not public cannot ship in
  `fixtures/pairs/`. A `provisioners.py` in DIR is imported and may add
  runtimes and provisioners. It may not rebind one the harness ships, which
  could replace a shipped provisioner with one that passes, and a pair name may
  not be used twice, which would let a private directory stop a published advisory
  running while the output still named it. A directory that is not one exits
  `2`. Every pair records the directory it came from, in the output and in
  `--json`.

- **Four more published advisories in the detection baseline, from four more
  applications.** LubeLogger (GHSA-qw92-hqxv-2x9g), Bugsink (CVE-2026-47715),
  Audiobookshelf (CVE-2026-42884) and Vikunja (CVE-2026-33313) join the three
  Gitea pairs, and Ghost (below) makes eight: 48 assertions, in Go, Python,
  C# and Node.
  LubeLogger and Bugsink replaced the Jellyfin and wger pairs first added
  here, and cover the same cross-user read in the same languages for a
  quarter of the download. Each of the four flips in the harness and fails
  when Veridor's marker detection is broken (measured 2026-09-27); LubeLogger,
  Bugsink and Vikunja were also reproduced by hand on both tags first
  (Audiobookshelf's fixed build only through the harness). The harness gained
  what they needed: a docker runtime per image, and an owner control probe
  that authenticates the way the application does (`control.headers`) instead
  of always sending gitea's `Authorization: token`, which had put every
  Bearer, API-key and cookie application out of reach. It also now runs the
  Veridor that `VERIDOR_TEST_AGAINST` picks, so a release can run it against
  the wheel.

- **CI is configured to run the published-advisory detection baseline
  (`detection-baseline`).** `scripts/patched_pairs.py` runs one configuration
  against a published advisory's own software at the tags either side of the fix, and
  passes only when the verdict flips and the endpoint survives. It was in the
  tree and ran in no gate: its only reference was a schema test that parses its
  configs. Every other test in the suite measures Veridor against a target this
  project wrote. `tests/test_workflows.py` now refuses a CI file that drops the
  job or makes it conditional, and checks each pair still names a published
  advisory and two tags. It is configured to run every pair on every pull
  request and every push to main (see Changed).

- **`scripts/pair_sizes.py` says what the pairs download.** For each fixture,
  or `--pair NAME`, it reads both pinned indexes from Docker Hub or ghcr.io
  (anonymous tokens; any other registry is refused by name), checks them
  against their digests, picks `--platform` (default linux/amd64) and prints
  the compressed layer bytes per pair and for every pair together, each layer
  counted once. A side it cannot measure makes the total PARTIAL and the exit
  `1`. It never reads local disk. All eight pairs: 1.07 GB for linux/amd64
  (1,071,435,500 bytes, twelve images, 2026-09-27).
- **The Bugsink pair checks the direct route too.** The attacker naming the
  owner's own issue and event is refused (403, no marker) on 2.1.3 and on
  2.2.0 (measured on 2026-09-27; it had been inferred), so the pair's leak is
  the unscoped event lookup and not a missing membership check. Every run
  holds both halves: a pair names the checks its vulnerable build must fail
  (`vulnerable_failing_checks`, required once a pair has more than one
  check), and a finding from any other check fails the pair. The harness used
  to ask only for one confirmed finding, so a 2.1.3 that also leaked through
  the direct route passed (measured with stub documents).

- **Report formats.** `veridor run --report FORMAT=PATH` (repeatable) and
  `veridor report --from-run RUN.json --format FORMAT` write `sarif`, `junit`,
  `gitlab-sast` (GitLab security report schema 15.2.5), `codequality` (GitLab
  Code Quality) and `markdown` (a job summary or merge request note), whatever
  the gate decides. The run document gains a `gate` object (`fail_on`,
  `exit_code` and machine-readable `reasons`) computed by the same code that
  sets the exit code, so the JUnit, GitLab SAST, Code Quality and Markdown
  reports show an exit `3` as not passed. SARIF carries findings only. See
  [docs/report-formats.md](docs/report-formats.md).
- **`python -m veridor`**, with the same exit codes as the `veridor` command.
- **A GitLab CI/CD component**, `templates/veridor.yml`: one gate job with
  typed `spec:inputs` that publishes JUnit, SAST and Code Quality reports
  through `artifacts:reports`. Exit `3` fails the job unless
  `allow_unmeasured: true`. It has not run on a GitLab runner;
  `scripts/e2e_gitlab_job.sh` runs the job's own rendered script in docker
  against the demo API.
- **Kubernetes gates.** The `veridor-gate` Helm chart
  (`deploy/helm/veridor-gate`) renders a Job that runs the gate as an Argo CD
  PostSync hook, a Helm post-install/post-upgrade hook, or a plain Job:
  `backoffLimit: 0`, the Pod Security `restricted` fields, uid 10001, no
  service account token, and credentials only from existing Secrets. A literal
  credential in a header, a session inject, a credential-named field, a URL or
  a credential-named parameter in a form-encoded body (percent-decoded) fails
  the render.
  `deploy/kustomize/veridor-gate` renders the same Job without Helm, as a
  plain Job, held equal to the chart's default Job by a test.
  `deploy/argo-rollouts` adds a job-provider AnalysisTemplate
  (`failureLimit: 0`) and `deploy/argocd` an Application example.
  `scripts/e2e_kubernetes.sh` runs them all on a kind cluster.
- **A release pipeline**, `.github/workflows/release.yml`, started only by
  pushing a `vX.Y.Z` tag: the version check and the full suite on Python 3.11,
  3.12 and 3.13, then the wheel, sdist and zipapp with a CycloneDX SBOM,
  `SHA256SUMS` and build provenance; PyPI through Trusted Publishing; a
  linux/amd64 and linux/arm64 image with SBOM and provenance, signed with
  cosign; the Helm chart to an OCI registry, signed. None of it has run, and
  nothing has been published.
- **A release image** (`Dockerfile`): the `python:3.12-alpine` base pinned by
  digest, the wheel installed with no package index from a read-only mount of
  the build stage, pip removed in the same layer, the CLI's imports compiled
  at build time, uid 10001, `ENTRYPOINT ["veridor"]`.
- **A single-file zipapp.** `python3.12 scripts/build_zipapp.py` builds
  `dist/veridor-<version>.pyz`. Two builds are byte-identical, and the same
  sha256 was measured on macOS arm64 and on Linux arm64 and amd64. It needs
  Python 3.11 or newer.
- **Continuous integration** in `.github/workflows/veridor.yml`, every job
  passing on GitHub-hosted runners on 2026-11-08 (CI run 42508338432, private
  repository): both test tiers on Python 3.11, 3.12 and 3.13 and
  on macOS, with helm, kubectl and shellcheck required; the suite again
  against the installed wheel; the Action through `uses: ./`; actionlint,
  shellcheck and the Helm chart; the kind and GitLab end-to-end scripts, the
  GitLab one with its three controls, and with rows under busybox sh, dash and
  bash, each starting with GitLab Runner's own script header; the GitLab and
  Azure YAML against those
  platforms' published schemas; and the image run as the gate. Every action is
  pinned to a commit.
- **`scripts/release_check.py`.** `versions` holds every hard-coded copy of
  the version (51 today) to `pyproject.toml` and fails on a version-shaped
  string it does not know about; `bump X.Y.Z` rewrites them all; `notes`
  prints a version's section of this file; `dist` checks the built artifacts;
  `identity` lists every use of the project's organisation, registry and
  domain names.
- `VERIDOR_TEST_AGAINST=installed` runs the suite against an installed
  Veridor instead of `src/`.
- GOVERNANCE.md, SUPPORT.md, a CODEOWNERS file and a feature request template.

- **The GitHub Action publishes outputs.** It had none, and the step that runs
  Veridor carried no `id:`, so `steps.<id>.outputs.*` was unreachable: a caller
  could see the job go red and learn nothing else without re-parsing artifacts
  by hand. Fourteen outputs now, including `exit-code`, the paths to the run,
  drift and coverage documents (always written, to a scratch path when you
  named none), the finding counts by verdict, `coverage-percent`, and
  `drift-blind-cells`. Veridor's exit code becomes the job's verdict in a
  separate final step, so outputs are read from a step that completed; that
  step fails closed when the code cannot be determined.

- **`map --baseline`: authorization regression testing with nothing declared.**
  Run `map` once to record an access matrix, pass `--baseline` on later runs,
  and Veridor reports what moved. No policy, no expectations, no checks — the
  bargain snapshot testing makes. `--fail-on-drift {none,opened,any}` turns it
  into a gate (`opened` fires when an identity that was refused is now served,
  or another identity's marker appeared); `--drift PATH` writes the report as
  JSON. Opt-in: without `--fail-on-drift`, `map` still exits `0`.
- **`mode: drift` in the GitHub Action**, with `matrix-baseline`,
  `fail-on-drift`, `drift`, `matrix`, `acknowledge-target`, `max-requests` and
  `rate`. A `matrix-baseline` that does not exist fails the step rather than
  passing as a gate with nothing to compare. Inputs belonging to the other mode
  are refused, not ignored.
- **Proof capsules.** `veridor capsule` builds a portable, runnable proof of one
  finding for a maintainer to verify against their own instance; `veridor
  verify` adjudicates it as `CONFIRMED` / `NOT_REPRODUCED` / `INCONCLUSIVE`.
  Building refuses outright if any credential is a literal rather than an
  `${ENV_VAR}` reference, and there is no override flag.
- `mutate --max-requests`, giving mutation runs the same explicit request
  budget the matrix has.
- **`veridor init --for drift`** — an on-ramp for the path that declares
  nothing. It writes two identities, a marker, and one `matrix.specimens` entry
  per templated route, and no checks at all. Its next steps are *export two
  tokens, replace the placeholder ids, record a baseline, then gate*. `--for
  run` stays the default and is unchanged.
- **Drift in the local viewer.** `map --baseline` now writes a managed copy of
  the drift report under the same id as its matrix, and `veridor serve` renders
  it inside the map view — not in a tab of its own, because drift is what a map
  means read against an earlier one rather than a fourth verb. Three states
  render three ways: no baseline and the panel is absent; a baseline that
  matched says *nothing moved, which is not a clean bill of health*; a baseline
  that did not lists every change with its own caveat. Significant changes are
  amber, never the red reserved for a measured departure from a declaration.
- `map` now prints pasteable JSON when an operation was skipped for want of a
  specimen, naming the real path templates, instead of reporting
  `skipped_no_specimen` in its own vocabulary and stopping. The routes it
  silently dropped were the templated ones — the shape this tool exists to
  measure.

- **`--on-retry-after {continue,stop}`** on `veridor map`.
- **`read-only`, `require-complete` and `require-clean-teardown` inputs on the
  GitHub Action.** All three flags existed on the CLI and no Action input
  reached them, so `with: read-only: true` produced an "Unexpected input(s)"
  warning and a green step — the silent drop every other input in that file is
  written to prevent. `require-complete` works in both modes; the other two are
  run-mode only and are refused in drift mode rather than ignored.

### Changed

- **Behaviour changes** a configuration or a CI job can notice:
  - **A denial on a write, or where no fabricated credential can be shaped,
    counts as unproven.** The liveness control is only sent with GET, HEAD
    and OPTIONS, and only when an identity declares a credential header to
    shape it on; POST, PUT, PATCH and DELETE requests, and configs with no
    credential header (cookie sessions beside an anonymous identity), were
    left out of the liveness plan without a word: an expired attacker token
    on a DELETE check left `liveness.unproven` empty and exited `0` even under
    `--require-complete`, while the banner announced controls that were never
    sent. Such a denial now counts as unproven when the identity presents a
    credential, some identity was served on that check, and nothing else in
    the run proves the identity live (a 2xx it drew on a request where an
    identity with no credential, or the fabricated credential, was refused;
    or its `marker_probe`);
    the banners name those requests (method and path) and why, as
    `liveness.requests_not_probed` does in the run document, and the
    `--no-prove-liveness` notice names every denial-only request it leaves
    unchecked (it printed only a count, and the banners a count and the
    verbs). A write check where every identity
    is refused is still not judged, as a GET check is not. Under
    `--require-complete`, which the GitHub Action, the GitLab component and
    the Helm chart turn on by default, such a run now exits `3` where it
    exited `0`.
  - **A denial-only sequence assert step never had its credential checked.**
    Liveness planning read `checks` only, and a step's own degraded rule
    covers session identities only, so a static-header identity whose token
    the target rejected passed every `[401, 403, 404]` assert step: exit `0`
    under `--require-complete`, nothing unproven, and output identical to a
    target that refused a valid token. The same declaration written as a
    check exited `3`. No fabricated credential is sent inside a sequence; a
    denial-only assert step by an identity that presents a static credential
    header now counts as unproven (`control: withheld_sequence_step`, listed
    in `liveness.requests_not_probed` as `sequence_step`) when some identity
    was served in that sequence and nothing else in the run proves the
    identity live. A 2xx a sequence step or teardown request drew for an
    identity now proves it live for checks too, when an identity with no
    credential was refused on the same request in that sequence.
  - **A run the configuration withheld entirely was told to check the
    network.** When every probe was withheld before the socket for a reason
    the configuration causes (`injection_not_applicable`,
    `marker_reflection_blocked`, `credential_slot_interpolation`,
    `unresolved_reference`), the run exited `3` with "Check the target URL,
    the credentials, and that the target is up", though nothing was sent and
    the target was healthy; and every one of those reasons but the first gave
    each finding "Confirm the target is reachable". The vacuity message now
    says the configuration withheld them, names the reasons and says it is
    not a network problem (beside the network advice when only some were
    withheld), and each finding's remediation gives the configuration fix
    for its reason. A sequence step skipped because an earlier step was
    withheld by the configuration counts with the withheld ones: it counted
    as unanswered, so a sequences-only run whose first step was withheld
    still got the network advice.
  - **Docs: every require-complete passage now gives every cause of an
    unproven denial.** The GitLab component's `require_complete`, the
    README's Action and GitLab input rows, the Action's `require-complete`,
    the Helm `values.yaml` and the Argo CD README gave the rule without its
    preconditions or with only some of its causes (the GitLab example, an
    expired token refused on a write, is not judged when nobody was served in
    that check). Each now states the preconditions (the identity presents a
    credential, some identity was served in the same check or sequence, a
    sequence assert step counts, nothing else proved it live) and every
    cause (the same denial, none sent, the fabricated request failed, an
    answer that is neither a refusal nor a success), as
    `docs/report-formats.md` and the Helm README do, and a doc test reads
    each passage for all of them. The Helm README's remedy "or a check where
    that identity is served" now says the fabricated credential or an
    identity with no credential must be refused on the same request: a check
    on a public route serves the identity and proves nothing, and the doc
    test reads every such remedy for the refusal.
  - **JUnit never attached an unproven sequence step to its testcase.**
    Unproven entries were attached per (check, identity), and a sequence
    step's entry carries the sequence id in its check id, so it matched no
    step testcase: the assert steps rendered as clean passes, while the same
    denial declared as a check carried its note. Each step's entry now goes
    to that step's testcase as `system-out`.
  - **`veridor verify` of a write capsule is `NOT_REPRODUCED` only with a
    `marker_probe`.** Counting a denial on a write as unproven reached
    `verify` too, and nothing said so: a `DELETE` capsule whose denied
    identity has no `marker_probe` is `INCONCLUSIVE` (exit `2`) against a
    fixed target, where it was `NOT_REPRODUCED` (exit `0`), because no
    fabricated credential is sent with a write and a capsule holds no other
    check to prove the identity live. That is the rule: `verify` does not
    claim `NOT_REPRODUCED` without a liveness proof. The README's verify
    section now states it, and the verdict's reason names the
    `marker_probe` that would supply the proof.
  - **The served-fabricated-credential disclosure claimed more than it
    measured.** It said whatever the request returns, it returns to any
    caller with a credential-shaped header; a target that served the
    fabricated credential an empty, tenant-filtered list returned no such
    thing, and the run was clean. It now says only that the fabricated
    credential was served HTTP <status>, so the target accepted a credential
    it never issued; the LEAK-001 message beside a served sham no longer
    claims the owner's data goes to everyone.
  - **A marker served to everyone was still `confirmed` on a check that
    accepts a 2xx.** The fabricated-credential control that tests whether an
    owner's marker is unique to its data was sent only for a request with a
    denial-only expectation, so a list endpoint the outsider may read, whose
    body must not carry the owner's marker, never got one: a build id served
    to every caller was graded `VERIDOR-LEAK-001` `confirmed` in the same run
    that graded it "not unique" on a 403 check. That one request is now sent
    for every GET, HEAD or OPTIONS request carrying an `excludes_marker` too,
    and counted in the banner and the request budgets. Where it cannot be
    (a write, no credential header to shape it on, `--no-prove-liveness`, a
    failed or unscannable response), the console and
    `liveness.marker_uniqueness_not_checked` say the marker's uniqueness was
    not checked, and why.
  - **A 2xx on a route that serves everyone proved a dead token live.** Any
    2xx anywhere in the run counted as proof an identity's credential was
    live, so one check on a public route that also serves anonymous callers
    removed every unproven denial for each identity it served: a dead
    attacker token on a DELETE exited `0` under `--require-complete`, where
    the same config without the public check exited `3`. A 2xx now proves a
    credential live only on a request where an identity with no credential,
    or the fabricated credential, was refused (or through the identity's
    `marker_probe`), for checks and sequence steps alike. So that an ordinary
    suite keeps its proof, a GET, HEAD or OPTIONS check that serves an
    identity whose denials need proof also gets one fabricated-credential
    request (counted in the banner and the request budgets), unless the
    check already asks an identity with no credential to be refused. On a
    route an identity with no credential is declared served on, the
    fabricated credential is still sent, because a target that refuses a bad
    token even there (GitHub answers 401) proves the credential live; where it
    is served, that is what the declaration says the route does, and it is
    not reported as a served sham.
  - **A benign header such as `Accept` became the fabricated credential.**
    The sham reused every header name any identity declared, so an `Accept`
    on the anonymous identity was enough to send one: `Accept:
    veridor-sham-...`, with no cookie or other credential, against which
    cookie-session identities were then judged. A target answering the
    unparseable Accept with 406 made a dead session cookie pass with exit `0`
    under `--require-complete`. The sham is now shaped only on names that are
    not standard non-credential request headers (`blastradius`'s list:
    `Accept`, `Content-Type`, `Origin`, `If-*` and the like are not; a custom
    `X-Tenant` or `Sec-WebSocket-Protocol` is); with none declared, the
    request is listed as `no_credential_header` and its denials count as
    unproven, as with no header at all.
  - **The fabricated credential overwrote an API-version header.** It was
    written into every non-benign header, so an `X-Api-Version`,
    `X-GitHub-Api-Version`, `Stripe-Version` or `Notion-Version` declared
    beside `Authorization` carried `veridor-sham-...` too. A target that
    refuses an unknown version answered every fabricated-credential request
    `400`, every denial went `control_uninformative`, and an ordinary suite
    exited `3` under `--require-complete`. A non-benign header that two or
    more identities send with the same value, and whose name does not mark it
    a credential, is now sent with that value. Any other such header is left
    out when every identity declaring it also sends a credential-named header
    or has a session: a fabricated `X-Tenant-Id` beside `Authorization` drew
    "tenant not found" from a target that resolves the tenant first, which
    read as the credential refused and proved an expired token live. Where it
    is an identity's only credential, such as the `X-Remote-User` an auth
    proxy names the caller by, it still gets the fabricated value; leaving it
    out there meant no fabricated credential could be shaped and every denial
    was withheld. With no header left to fabricate the request is listed
    `no_credential_header`, as before. Which identities present a credential
    is unchanged.
  - **An anonymous identity that sends only `Accept` was listed unproven.**
    Whether an identity presents a credential was decided three ways: the
    check path counted any declared header, sequence planning any static
    header, and the sham planner six names and a regex. So an `Accept`-only
    anonymous identity's denial was listed unproven -- with a `marker_probe`
    remedy it cannot use -- and exited `3` under the default require-complete
    of the Action, the GitLab component and the Helm chart, while a custom
    `X-Tenant` credential shaped no sham. One classifier, shared with
    `blastradius`, now answers both: a session, or any header that is not a
    standard non-credential request header.
  - **A fabricated-credential request that failed counted as proof the
    credential was live.** A sham that timed out or had its connection reset
    gives no comparison at all, yet every denial-only expectation on that
    request passed as established: a target slow on, or dropping, unknown
    tokens left `liveness.unproven` empty, recorded nothing about the error,
    and exited `0` under `--require-complete`. Such a denial now counts as
    unproven (`control: control_errored`, with `control_error`), the error is
    recorded on the request in `liveness.requests`, and the console and the
    gate say a re-run may answer it.
  - **A fabricated credential's 400, 406, 407, 429 or 5xx counted as proof
    the identity's credential was live.** Any answer that differed from the
    identity's denial was read as the target telling the two credentials
    apart, so a parser rejecting a non-JWT bearer with 400, a proxy's 407 or a
    limiter's 429 on the late sham made an expired token's 401 pass, with
    `liveness.unproven` empty and exit `0` under `--require-complete`. Only a
    refusal (401, 403, 404, 405) or a 2xx/3xx tells credentials apart now,
    the rule the pairs harness already applied; any other answer leaves the
    denial unproven (`control: control_uninformative`, with
    `control_status`).
  - **A marker that a refused fabricated credential also got back, beside a
    matched status, is VERIDOR-ORACLE-001 `inconclusive`, not a leak.** An
    outsider that drew its declared status with a marker the run's
    fabricated-credential control also received was graded VERIDOR-LEAK-001
    `vulnerable`/`confirmed`, the grade `--fail-on confirmed` gates on, though
    the control had shown the marker is not the owner's. When the target
    refused the fabricated credential it is now ORACLE-001 `inconclusive`,
    grade `n/a`: no `--fail-on` policy fails on it, and `--require-complete`
    exits `3`. Its finding id changes, because the id is derived from the
    finding's kind (`oracle`, was `marker`), so a baseline entry for the old
    finding no longer matches it.
  - **A fabricated credential the target served was read as "this marker is
    not unique", and a real cross-tenant leak exited `0`.** Against a target
    that accepts any `Bearer` header, a list endpoint with its tenant filter
    removed, and an `anonymous: [401]` expectation beside it (which is what
    sends the fabricated credential), the outsider's leak was graded
    ORACLE-001 `inconclusive` where the same config without the anonymous line
    was LEAK-001 `confirmed`: declaring more made the grade weaker, and in
    tier 2 the hook went from killed to errored. A target that serves a
    credential nobody issued says nothing about a marker's uniqueness, so the
    leak is now LEAK-001 `vulnerable`, graded `suspected` (the default gate
    fails on it, `--fail-on confirmed` does not), and every request whose
    fabricated credential was served a 2xx is named on the console and in
    `oracle_disclosures` (`control_source: fabricated_credential`).
  - **A sequences-only `run` that answered nothing exits `3`, not `0`.** With
    `checks: []` beside sequences, the "not one probe was answered" guard
    counted check probes only and could never trip, so a target that refused
    connections or answered `503` to every step exited `0` with an empty gate
    and nothing on stderr. With no check probes the sequence steps now decide,
    so such a run exits `3` (`nothing_answered`) with no flag, as a run with
    checks already did; `--fail-on none` still exits `0`.
  - **A checks-only `run` that sent no probe, because no session came up,
    exits `3`, not `0`.** A probe is skipped for an identity whose session did
    not establish, so when every login drew a `503` (transient, which
    `identity_unauthenticated` rightly leaves alone) the run appended no
    probe, the guard read that as "no checks", found no sequence steps either,
    and exited `0` having sent nothing but logins; the same outage written as
    a sequence exited `3`. A declared check none of whose probes was sent is
    now unanswered, so such a run exits `3` (`nothing_answered`) with no flag;
    `--fail-on none` still exits `0`. Check probes and sequence assert steps
    are judged together: the run is vacuous only when neither a probe nor an
    assert step was answered. A setup step grades no declaration and is not an
    answer: counting any answered step let a run whose check probes all went
    unanswered (or that had no checks) and whose sequence's only answered
    request was its setup, the assert having drawn a `503`, exit `0` with an
    empty gate; it now exits `3`, and the console's sequences-only line counts
    assert steps. That rule also made a run of setup steps only exit `3`
    (rightly: it grades nothing) with "not one of 1 probe(s) was answered ...
    check that the target is up" about a setup served `200`, and gave the same
    network advice when every assert was skipped behind a setup answered with
    an undeclared status. The first says the configuration declares nothing to
    grade, with `count` `0`; the second says the target did answer and which
    steps were skipped. The first version of this fix let declared checks decide
    alone, so a run whose check sessions all drew a `503` while a sequence on
    other identities was answered exited `3` and said it established nothing,
    though the sequence had measured a boundary. Such a run, and one whose
    sent check probes all timed out beside an answered sequence (which exited
    `3` before either fix), now exits `0` with those probes `inconclusive`,
    and `3` under `--require-complete`.
  - **`map` treats operations excluded by `--ignore`, `matrix.ignore` or
    `--include` as deliberate skips.** They were counted as probed but
    unmeasured, so `--require-complete` exited `3` on a healthy target and
    said to re-run when it was healthy, and a run whose exclusions left
    nothing to probe exited `3` saying the matrix records nothing, with or
    without the flag. They now count like a mutating verb the read-only
    posture declined: a healthy run with exclusions exits `0`, and a cell
    actually lost to the target still exits `3` under `--require-complete`.
    An exclusion that leaves nothing to probe (`--ignore '/'`, a
    `matrix.ignore` covering the spec, or `--include` and `--ignore` that
    empty it together) is refused before the first request with exit `2`, as
    an `--include` that matches nothing already was; counted as deliberate
    skips alone, such a run sent nothing and exited `0`, even under
    `--require-complete`. So is one that leaves only writes the read-only
    posture skips or routes with no specimen (`--ignore 'GET /'` on a spec
    whose other operations are writes, or an `--include` naming only a
    `DELETE`): the first version of the refusal counted those as operations
    left to probe, so such a run still planned 0 requests and exited `0`.
    When routes with no specimen are among those left, the refusal also says
    to add a `matrix.specimens` entry for them; it named only the selection
    fixes (remove an ignore entry, widen `--include`), though a specimen is
    what gets the route it kept probed. A selection that excludes no operation is not refused, so a spec of writes
    alone still plans nothing and exits `0`, as it does with no selection.
  - **`map --drift PATH` without `--baseline` is refused.** It was accepted
    and ignored: the run probed the target, wrote nothing at `PATH`, said
    nothing about it and exited `0` on a healthy target, so a CI step reading
    `PATH` afterwards found no report. It now exits `2` before anything is
    sent, as `--fail-on-drift` without `--baseline` already did.
  - **A misspelt top-level key is refused, and so are two swapped letters
    below the root.** The loader never checked root keys for near-misses and
    the schema root accepted any key, so `Sequences` beside a `checks` list
    loaded with zero sequences (setup, cross-tenant asserts and teardown
    gone), `Checks` beside `sequences` loaded with zero checks, `Matrix`
    dropped a `map` run's specimens, and each run stayed green; the schema
    also accepted root-level TLS keys the loader refuses. A root key that is a
    case variant, close misspelling or transposition of `$schema`, `version`,
    `target`, `identities`, `checks`, `sequences`, `matrix` or `coverage` now
    exits `2`
    naming the real key, and the schema root refuses every unknown key that is
    not a `_` annotation. Below the root, a two-letter swap (`injcet`,
    `lgoin`, `statsu`) is now a near-miss in every object that checks for one:
    a session `injcet` loaded with no `inject`, so its CSRF header was never
    added. **Upgrading:** this refuses plain annotation keys that loaded
    before. A root `checksum` (read as `checks`), `schema` (`$schema`),
    `versions` or `x-version` (`version`), and an identity's `remark` (the
    letters of `marker`), now exit `2`; start an annotation with `_`
    (`_checksum`, `_remark`), as the refusal says. A key starting with `_` is
    never judged a slip, in any object that takes annotations: the check
    stripped the `_` first, so `_remark` was refused as `marker` too, and
    `_status` or `_contains_marker` as the very key it set aside. Every
    near-miss refusal now says to start an annotation with `_`: only the
    root, identity and `coverage` refusals did, and a session, capture,
    inject entry, expectation, sequence, step, teardown entry or request
    block named the slip and stopped. The schema now takes a `_` key in a
    capture, as the loader already did.
  - **Two identities that send the same credential through a session or a
    custom header are refused.** The identical-credentials check skipped every
    identity with a session, its static headers included, and compared only
    six header names, so a copy-pasted session block or a shared
    `X-Access-Token` loaded and every probe compared one caller with itself. A
    session identity is now compared on its login steps together with its
    static credential headers, an identity whose only credential is in another
    header (`X-Access-Token`, `PRIVATE-TOKEN`) on its whole header set, and a
    match exits `2`.
  - **`coverage.denial_statuses` accepts only 4xx refusals other than `401`
    and `407`.** The key took any status from 100 to 599 and is read before
    the authentication and 2xx rules, so declaring `401` turned an anonymous
    401-only expectation into 100% "authz denial asserted" with a brightgreen
    badge while the report's policy block said a 401 never counts, and a `200`
    did the same for an allow-only expectation. Any other value now exits `2`
    and a `--badge` file is rewritten as `unknown`. The key is now documented
    in the README, the configuration schema accepts the `coverage` block and
    checks it by the same rule, and a misspelt `coverage` is refused like any
    other top-level key.
  - **A misspelt or malformed `coverage` block is refused, not measured
    against the defaults.** Only `coverage.denial_statuses` was read, so a
    `Denial_Statuses`, `denail_statuses` or any other key inside the block, a
    `"denial_statuses": null`, and a `coverage` that was a list, a string or
    null all loaded, and the figure was computed against 403 and 404 with exit
    `0` -- even when the misspelt value was one the rule above refuses, such
    as `[401]`. On the demo, a declared `[403]` scored 20% and the same block
    misspelt scored 40%. `veridor coverage` and `run --openapi` now refuse
    each of these before computing, naming `denial_statuses` for a near-miss:
    `coverage` exits `2`, `run` treats it as coverage that was not measured,
    as it does a spec that matches nothing, and a `--badge` file is rewritten
    as `unknown`. Keys starting with `_` are annotations, as everywhere.
  - **A refused coverage measurement rewrites the `--coverage` file as not
    measured.** The badge was rewritten as `unknown`, but the file at
    `--coverage` was left as it was, so a later step that read it after exit
    `2` found the previous run's `measured` figure. On any refusal before a
    report exists (a `coverage` block refused as above, a specification or a
    configuration that does not load), it now holds `"status":
    "not_measured"`, a `null` `coverage` and the `reason`. A configuration that
    does not load also left the badge as it was; it is rewritten as `unknown`
    too. That includes one that cannot be read at all, a directory or a file
    the runner may not open, on `run --openapi` and on `coverage`: only a
    parse refusal rewrote the two files.
  - **`map --timeout` is the timeout requests use.** It set only the banner's
    "timeout: Xs per request" line, and every request used
    `target.timeout_seconds`. Requests now use the flag's value; without the
    flag they still use `target.timeout_seconds`.
  - **`mutate --tier 2` runs the suite against the unmutated target first.** A
    suite already red against the real target scored every hook killed, a hook
    whose commands do nothing included, with score 1.00 and exit `0`. A red
    unmutated run now makes every hook not applicable, and one that could not
    grade every result makes every hook errored; no hook is applied in either
    case, the report records why under `unmutated_run`, and `mutate` exits
    `2`. The extra run is charged to `--max-requests`.
  - **`mutate --tier 2` does not kill a hook on an inconclusive result.** A
    mutated-build run whose only findings were inconclusive
    (VERIDOR-ORACLE-001, VERIDOR-CACHE-001) counted as a kill, so a hook that
    only stripped the owner's marker, or one that answered `503` to the owner,
    scored killed with exit `0`. A mutated run whose findings are all
    inconclusive is now errored.
  - **`mutate --tier 2` kills a hook only when the suite sees access granted.**
    A refusal counted as a kill, so a hook whose apply rebuilt the target and
    lost its fixtures, answering the owner `404` with no guard removed, scored
    killed, 1.00, exit `0` on the owner's `unexpected_denial` alone, while the
    outsider's `excludes_marker` check had lost its control and measured
    nothing. A kill now needs a `vulnerable` finding, because granting access
    is what removing a guard does. A mutated run whose only findings about the
    target are refusals is aberrant, naming each identity refused and the
    check, and `mutate` exits `2`. Its reason is worded for what happened to
    each identity: one the declaration expects to serve was refused, or one
    it expects refused drew a different refusal (`401` declared, `302` drawn;
    `403` declared, `404` drawn). Every such run first said "the build
    refused an identity it should serve", which was false for the second
    case and sent its reader to check data and credentials. The reason for
    the second case then said a changed refusal "is not a guard's removal",
    which Veridor cannot know: a guard removal that turns `403` into `404`
    lands there. It now says what the suite saw and that Veridor cannot tell
    whether the guard's removal caused it.
  - **`mutate`'s `limited` count is exactly what LIMITS ON THE EVIDENCE
    prints.** It counted every not-applicable mutant, including the structural
    M3 record every owner `contains_marker` produces, so the suite's own
    perfect configuration printed "1 could not be evaluated" over an empty
    LIMITS block and `--require-evaluable` exited `3` on it, while M4's
    public-read and uniform-existence-hiding results, which the module
    documentation promised there, never printed. Now M4's and M6's
    target-limited results are printed and counted, structural records and an
    already-failing baseline are neither, and `--require-evaluable` exits `0`
    on a correct configuration and `3` on a public-read check. The README's
    `mutate` sample output is re-measured.
  - **`mutate --tier 2` charges each suite run's liveness controls against
    `--max-requests`.** They were left out, so a plan at or just under the
    ceiling was accepted and more went on the wire, while the banner said
    there were no additional probes. The count now includes them and the
    unmutated run, so a plan near the ceiling may now be refused. Session
    logins and sequence steps are still not counted at tier 2, and the help,
    the README and the API documentation now say so instead of promising the
    ceiling bounds the whole plan.
  - **A drift gate that measured nothing in both runs exits `3`, not `0`.** A
    baseline recorded while the target was down has every cell `unknown`, and
    `--fail-on-drift opened` and `any` both exited `0` against it: every
    comparison was `unknown -> something`, which neither policy counts.
    Reproduced with the demo target serving another tenant's invoice. Under a
    gating policy, a comparison with no cell measured in both this run and the
    baseline now exits `3`; a difference (`1`) still wins, and
    `--fail-on-drift none` still exits `0`. The drift JSON gains
    `measured_in_both_cells` and each side's `measured_cells`, and the text
    and Markdown reports say that no cell was measured in both runs. The
    Action's drift mode, and any CI job that runs `map --fail-on-drift`, get
    the same exit code; the Action's error annotation for exit `3` now names
    drift's causes in drift mode instead of run mode's.
  - **A redirect is not a measurement.** Veridor never follows a redirect, and
    the matrix records a `3xx` as `indeterminate`, but the rule above and
    `map`'s "records nothing" guard counted every cell that was not `unknown`
    as measured. Reproduced against a listener that answered every request
    with `302`: `map --matrix` recorded the baseline with exit `0` and no
    warning, and `--fail-on-drift opened` with it then exited `0` against the
    demo target serving another tenant's invoice; with the target still
    redirecting, `opened` and `any` both exited `0` although no request reached
    the application in either run. A cell that is a redirect in either run no
    longer counts toward `measured_in_both_cells` or a side's `measured_cells`,
    and a `map` grid of nothing but unmeasured cells and redirects exits `3`.
    The drift JSON gains `redirect_cells`. A redirect beside measured cells,
    such as an anonymous `302` to a login page, is still compared, still
    reported, and does not trip `--require-complete`; a `400`, `409` or `422`
    still counts as measured.
  - **A misspelt key in a check, sequence step or teardown request is
    refused.** Those blocks were read for `method`, `path`, `headers`, `json`
    and `body` and nothing else, so `"Headers": {"Authorization": ...}`,
    `header`, `Method` or `Body` loaded and the request went out without it:
    measured against a listener, a header under `Headers` never reached the
    wire and the run exited `0`. A key that differs from a real one only in
    case or separators, or is a close misspelling of one, now exits `2`
    naming the real key (`did you mean 'headers'?`), as `marker_probe` and
    login steps already did; those two now name it too.
  - **Any other unknown key in a request block is refused too**, in checks,
    marker probes, session login steps, sequence steps and teardown entries.
    `params`, `query`, a bare `Authorization` and `description` loaded and
    were dropped: measured with `veridor run`, nine requests went out and none
    carried the value, while the published schema refused all four. Each now
    exits `2` naming the key and what to write instead (a query string in
    `path`, a header under `headers`). An annotation is a key starting with
    `_`, such as `_comment`, which is what the schema has always allowed.
  - **The GitLab component runs the gate in every pipeline by default.** The
    `job_rules` default, merge request pipelines plus the default branch, left
    the job out of 13 of 24 kinds of pipeline, among them the branch pipeline
    for a merge request's branch, tags and a child of a merge request pipeline,
    and nothing showed it was missing; under GitLab's Branch-Pipelines workflow
    the gate never ran before merge. The default is now `- when: on_success`.
    Without `workflow:rules`, a push to a branch with an open merge request now
    makes two pipelines and the gate runs in both; `ci/.gitlab-ci.yml` shows
    GitLab's recipe for one. The pipeline kinds were evaluated against the
    variables GitLab documents, not on a GitLab instance.
  - **GitLab component inputs refuse a `$` that does not begin `$NAME` or
    `${NAME}`.** GitLab writes input text into the job's script before the
    shell reads it. `$(...)` in `base_url`, `config`, `pip_package`,
    `baseline` or `openapi` ran when the rendered script did (measured), and
    `${HOME:X}` there or in `extra_args` evaluated X's value as arithmetic,
    which can run a command. Such a value now fails when the pipeline is
    created, and `extra_args` no longer accepts literal braces.
  - **More key names count as credential names**, in `veridor capsule`'s
    literal-credential refusal and in the Helm chart's render refusal, which
    share one rule. A separator was required before the credential word, so
    `accessToken`, `refreshToken`, `apiToken`, `userPassword`, `secret_key`,
    `aws_secret_access_key` and `pass` matched nothing: `capsule` wrote a
    literal `refreshToken` into a capsule and the chart rendered one into a
    ConfigMap. A key ending in password, secret, token, credential(s) or
    api/private/secret/access key now counts with or without a separator, as
    do `pass` and `pwd` as a word of their own. Every value in a list under
    such a key is checked, a request's `headers` map is found in any letter
    case, and the chart no longer skips JSON text holding `NaN`, `Infinity`
    or a number beyond float64 (see Fixed for the forms the first version of
    that missed). A field that is not a secret but has such a
    name, such as `pageToken` or `nextPageToken`, is now refused when it holds
    a literal value.
  - **Still more names count as credential names, in both refusals.** Measured
    before this change, each of these was published by `veridor capsule` and
    rendered by the chart: Django's `password1`/`password2` and
    `new_password1`, `password_confirmation`, `passwordConfirmation`,
    `password_confirm`, JSON `jwt`, `userpass`, `userpwd`, `passwort`,
    `kennwort`, `contrasena`/`contraseña`, `mot_de_passe` and `senha`. As a
    query, form or `;` path parameter (not a JSON key) the whole names `key`,
    `auth`, `code`, `sig`, `signature`, `sessionid`, `session_id`,
    `jsessionid` and `sid` now count too, because Google APIs, Firebase,
    Azure Functions and Azure SAS put credentials there; the chart's
    `target.baseUrl` refuses `;jsessionid=` and `?key=` literals the same
    way. A value under those names that is not a secret, such as an object
    key in `?key=` or a country in `?code=US`, must now be a `${NAME}`
    reference as well.
  - **The plain-Job Kubernetes flow deletes the previous Job and waits for this
    run's outcome.** The Kustomize README and plain overlay said `kubectl apply
    -k` then `kubectl wait --for=condition=Complete job/veridor-gate`.
    Re-applying an unchanged overlay runs no new Job, and the wait read the
    previous run's: measured on kind, a gate that had passed stayed green after
    the target was redeployed vulnerable. The chart's `hook.mode: none`
    rendered with `helm template` did the same, its Job always being `-r1`.
    The documented flow now deletes the previous Job, applies, and polls the
    new Job until it is Complete or Failed, passing only on Complete; a Job it
    cannot read fails it. Replace the two old commands with the block in
    [deploy/kustomize/veridor-gate/README.md](deploy/kustomize/veridor-gate/README.md)
    or the chart README's "hook.mode none" section.
  - **The plain-Job flow checks every step and waits only for the Job it
    created.** The Kustomize README let its block run without `set -e`, and
    there a refused `kubectl delete` fell through: measured on kind with a
    ServiceAccount allowed to create but not delete Jobs, `apply` printed
    `unchanged` and the block exited `0` on the previous run's Complete Job
    against a target that had since turned vulnerable. The chart README's
    `hook.mode: none` block did the same (measured), and a `helm template`
    that refused the values fell through the same way, leaving the manifest
    empty. Both blocks now exit `1`
    when the render, a read, the delete or the apply fails, or when `apply`
    created no new Job (its uid is unchanged), and the wait reads the Job's
    uid with its conditions, so a Job replaced under the same name fails the
    block. The e2e runs both blocks under plain `sh`, including as that
    ServiceAccount. Replace the block you copied.
  - **The Helm chart refuses values that rendered a gate that could not
    gate**, each of which rendered with exit `0` before (measured on kind):
    `hook.helm.events` pre-install, pre-upgrade or pre-rollback and
    `hook.argocd.phase: PreSync`, which run before the chart's ConfigMap is
    created or updated (pre-install could not mount it; pre-upgrade ran the
    previous revision's configuration); a `job.podLabels` entry for a selector
    label, which detached the NetworkPolicy from the pod; empty or null
    `networkPolicy.dns.peers` or `dns.ports`, since a rule with no peers is
    egress to every destination (a pod that was not DNS answered on port 53),
    and a `targetPorts` or `dns.ports` entry with no port, which allows every
    port of its protocol; `target.baseUrl` with no `config.target` object,
    which Veridor refuses on every run (`config.target: {}` is enough); and a
    `target.baseUrl` holding a `${NAME}`, which is not expanded there, or a
    literal credential-named parameter such as `?api_key=`.
  - **The Helm chart refuses hook values under which a release or sync
    succeeds without the gate running.** `hook.helm.deletePolicy` must
    include `before-hook-creation`: the Job keeps one name, and with
    `hook-failed` a `helm upgrade` exited `0` on the Complete Job the install
    had left, running nothing (measured on kind: one Job uid across install
    and upgrade). `hook.argocd.deletePolicy` must likewise include
    `BeforeHookCreation`, and now also accepts it combined with
    `HookSucceeded` or `HookFailed`.
  - **`hook.helm.events` must include both `post-install` and `post-upgrade`.**
    With `test` or `post-rollback` alone, `helm install` and `helm upgrade`
    created no Job and exited `0` with the release deployed while NOTES said
    the gate had run (measured on kind). `test` and `post-rollback` may be
    added to the two. NOTES now name the hook that ran for this install or
    upgrade, and with `test` say that `helm test`'s exit status is then the
    gate and that a failed test leaves the release `deployed` (measured).
  - **`hook.argocd.phase: Sync` is refused; only `PostSync` is accepted.**
    Argo CD runs a Sync hook together with the apply of the application's
    manifests, not once they are Healthy, so the gate probed whatever the
    Service still routed to, the version being replaced. Any other value
    (`SyncFail`, `Skip`, another letter case) is refused too.
  - **The chart's hook refusals read the values the way Helm and Argo CD do.**
    With the schema skipped (`--skip-schema-validation`, or Argo CD's
    `skipSchemaValidation`), `Pre-Install`, `post-install,PRE-UPGRADE`,
    ` PreSync` and `PreSync,PostSync` rendered, because the refusal compared
    the raw text while Helm lower-cases and trims each event and Argo CD
    trims each phase (measured: `PRE-UPGRADE` ran as a pre-upgrade hook that
    read the previous revision's configuration). The values are now split on
    commas, trimmed, and lower-cased for Helm before they are checked, and the
    Job's annotations are rendered in that form.
  - **The chart refuses `extraArgs` that override a flag it sets.**
    `extraArgs` come after the chart's arguments, and Veridor keeps a flag's
    last value and reads any unambiguous prefix of a flag as the flag, so
    `--base-url` or `--base-u` there replaced `target.baseUrl` without its
    credential check: the Job's arguments carried a literal `;token=` and
    Veridor probed that URL (measured). An element that starts with a prefix
    of `--config`, `--output-dir`, `--fail-on`, `--base-url`,
    `--require-complete`, `--require-clean-teardown`, `--read-only`,
    `--no-prove-liveness`, `--sarif` or `--wait-for-target`, with or without
    `=value`, is now refused, and so are `--help` and `-h`, which exit `0`
    having run nothing. Set the corresponding value instead. A single-dash
    cluster such as `-hx` got past that: argparse reads it as `-h` (measured:
    exit `0`, nothing run). Every single-dash token with an `h` in it is now
    refused too.
  - **The chart refuses hook annotations in `job.annotations`.** They were
    rendered after the hook annotations the chart checks, as duplicate keys,
    and Helm keeps the last: `helm.sh/hook: test` there made `helm install`
    and `helm upgrade` run no gate, `helm.sh/hook: pre-install` turned a
    `hook.mode: none` Job into a pre-install hook past the pre-phase refusal,
    and `argocd.argoproj.io/hook: Sync` rendered past the Sync refusal
    (measured with `helm template`). `helm.sh/hook*`,
    `argocd.argoproj.io/hook*` and `argocd.argoproj.io/sync-wave` are now
    refused there in every mode; set `hook.*` instead.
  - **On a digest-pinned chart, `image.tag` alone is refused.** The release
    workflow publishes the chart with `image.digest` set to its own image,
    and `--set image.tag=0.1.1` on it rendered
    `ghcr.io/veridor-authz/veridor:0.1.1@<the 0.1.0 digest>`. The kubelet pulls the
    digest and ignores the tag (measured on kind), so the gate kept running
    the release's image while the manifest named the new tag. A digest is now
    used only with the tag it belongs to, the new `image.digestTag` (default:
    the chart's `appVersion`). To change the tag, set `image.digest: ""`, or
    set `image.digest` to that tag's digest and `image.digestTag` to the tag.
  - **A crash exits `70`, not `1`.** An uncaught exception exited `1`, the
    code for "the gate failed on a finding", so a bug in Veridor read as a
    finding about your target. It now prints the traceback and a request to
    report it, and exits `70`.
  - **SIGTERM runs teardown and exits `143`.** SIGTERM had no handler, so a
    Kubernetes pod termination, a Job deadline or a cancelled CI job ended
    Veridor without running sequence teardown (measured: the teardown request
    never reached the target). It now takes SIGINT's path: teardown for the
    in-flight sequence runs first, and a second SIGTERM during it is ignored.
  - **An empty `${NAME}` is refused** with exit `2`, like an unset one. A pull
    request from a fork gets empty secrets; an empty token used to be sent,
    and the denial it drew read as a finding about the target.
  - **Verifying a capsule needs `--base-url`** unless its target is loopback
    and it only reads (see Security).
  - **The Azure Pipelines template fails the step on exit `3`.** It turned
    exit `3` into SucceededWithIssues and then exit `0` by default (measured:
    exit `0` against an unreachable target). `VERIDOR_ALLOW_UNMEASURED:
    "true"` in the YAML opts back in. The Jenkins template
    (`VERIDOR_ALLOW_UNMEASURED`, UNSTABLE) and the GitLab component
    (`allow_unmeasured`) also fail on `3` unless asked; CodeBuild has no
    warning state, so there it always fails.
  - **The Action's boolean inputs accept only `true` or `false`**, in any
    letter case. `read-only: yes` compared unequal to `true` and silently
    turned the refusal of writes off; any other value now exits `2`, naming
    the input. An input that belongs to the other mode is refused, not
    ignored, though an empty one cannot be told apart from one left out.
- **Nothing in a release publishes before every build job passes, and every
  publishing job waits for an approval GitHub enforces.** The image job needed
  only the version check and the tests, and the chart job the version check
  and the image, so a failed build, provenance or PyPI job still let the image
  be pushed and signed, and the chart after it (simulated over the jobs'
  `needs`). The publishes now run in order after the build (provenance, PyPI,
  image, chart, GitHub release), so a failure stops the rest. Each of them
  runs in the protected `release` environment, where GitHub holds it for a
  reviewer. An earlier version of this change had one approval job in
  `release` and the PyPI job in a `pypi` environment that CONTRIBUTING said to
  leave without a reviewer. Only the workflow file asked for that approval, so
  a workflow at another commit could leave it out. CONTRIBUTING now says to
  register PyPI's trusted publisher with environment `release`, and lists the
  environment settings and a tag ruleset. Each publishing job first fails
  unless `release` requires a reviewer that administrators cannot bypass,
  since GitHub creates a missing environment unprotected and lets
  administrators bypass one by default. It reads those settings, and cannot
  show who approved. The release image job's binfmt, BuildKit and SBOM-scanner
  images, which followed moving tags next to the registry login, are pinned by
  digest; helm is installed from a sha256-checked download instead of
  `azure/setup-helm`, in the chart job and in four CI and release test jobs;
  the signed chart pins the signed image by digest; and the release notes give
  the image's and the chart's digests. None of it has run.
- **The release SBOM's syft is pinned by sha256.** The build job made the
  CycloneDX SBOM with `anchore/sbom-action`, which downloads syft's
  `install.sh` at the release tag and runs it; that script checks syft only
  against the same release's checksums, and syft ran after `dist/` was built
  and before `SHA256SUMS`, provenance and the PyPI upload.
  `.github/scripts/install-syft.sh` now downloads syft 1.51.1 and refuses it
  unless its sha256 matches the pinned one (the published checksums, whose
  signature by anchore/syft's release workflow `cosign verify-blob`
  accepted), and the job runs `syft scan` itself. A test refuses the action
  in any workflow.
- **The PyPI publish action's container is pinned by digest.**
  `pypa/gh-action-pypi-publish` does the upload, and the exchange that mints
  the PyPI token, in `ghcr.io/pypa/gh-action-pypi-publish` under a tag named
  after the action's commit. A tag names whichever build was pushed to it
  last: that commit's tag and its `v1.14.2` tag name two different builds. The
  PyPI job now pulls the digest the commit's tag named on 2026-09-24 and tags
  it under that name. The runner starts the action's container with
  `docker run` and no pull (read from actions/runner), so that image is the
  one that runs; with docker 29, a local tag of that name ran while the
  registry's tag named another build. A step after the upload fails the job if
  the action named another image or the name moved. The action still does the
  upload: PyPI's documentation says the manual token exchange is not a stable
  interface, and the action uploads PEP 740 attestations.
  `ossf/scorecard-action` runs `ghcr.io/ossf/scorecard-action:v2.4.4`, which
  the runner pulls by tag before the job's first step, so nothing here can pin
  it. `dependabot.yml` and the tests now name both images.
- **The detection baseline's images are pinned by digest, and the release
  runs every pair against the wheel.** The ten images ran by tag from
  `fixtures/pairs/`, which the workflow image-pin test never read: whatever
  `gitea/gitea:1.26.4` named the day a runner pulled it. Each pair now pins
  both builds (`vulnerable_digest`, `patched_digest`);
  `scripts/patched_pairs.py` refuses a pair without them, runs
  `image:tag@digest`, and stops before any pair when a tag the local Docker
  holds no longer names the pinned build. The README and CI said the images
  were about 7 GB, which was the disk usage Docker reported for them on one
  arm64 laptop (the compressed layers plus their unpacked copy, not a
  download); a linux/amd64 runner downloads 1.07 GB compressed for all
  twelve, each layer counted once (`scripts/pair_sizes.py`, 2026-09-27).
  `detection-baseline` is configured to run every pair on every pull request
  and every push to main; a fixture carrying the old `"heavy"` key is refused, and a `--pair`
  that names nothing exits `2` instead of passing, naming every pair it left
  out. `--pull` pulls the images by digest, four at a time, and a failed pull
  fails only the pairs that need it. The set keeps a status-only pair and
  marker pairs, and a test holds it to both: on 2026-09-27 the status oracle
  blind to an undeclared 200 failed the status-only pair, and a matched marker
  read as absent failed the seven marker pairs, each run exiting `1`.
  `release.yml` did not run the baseline at all. Its new `detection-baseline`
  job runs every pair against the built wheel, installed alone in a fresh
  virtual environment, and provenance and the PyPI upload wait for it. Under
  `VERIDOR_TEST_AGAINST=installed` the harness prints which `veridor` it
  imports and refuses to start when it cannot import `veridor.cli`, imports it
  from `src/`, or imports a file no installed distribution's RECORD lists.
  The CI job passed on a GitHub-hosted runner on 2026-11-08; the release job
  has not run.
- **`release_check.py notes` refuses notes that are not release notes**: a
  section with a line starting "Not released." or "Nothing here has been
  released", and a non-empty `[Unreleased]`. `notes v0.1.0` exited `0` and
  printed the 0.1.0 placeholder, which the release would have posted as its
  notes.
- **The GitLab component's `python_image` default is pinned by digest.** It
  was the tag `python:3.12-slim`, and with `install: pip` the job runs pip and
  the gate in that image with every credential; the registry can move a tag.
  The default is now the digest the release Dockerfile builds on: first
  `python:3.12-slim`'s (the registry resolved the tag to the same digest on
  2026-09-24), and `python:3.12-alpine`'s since the image moved to Alpine
  (next entry). A test holds the two equal, so Dependabot's Dockerfile bump
  fails until the component follows; `.github/dependabot.yml` lists it among
  the pins bumped by hand.
- **The release image is Alpine and less than half the size.** Both
  Dockerfile stages build on `python:3.12-alpine`, pinned by digest: the same
  CPython 3.12.14, on musl. The GitLab component's `python_image` default
  follows it. Compressed, from OCI exports on 2026-09-27: 48.1 MB -> 20.9 MB
  for linux/amd64 and 48.3 MB -> 21.4 MB for linux/arm64. The wheel is read
  through a build mount instead of a COPY layer that the next step deleted
  and every pull downloaded, and pip and ensurepip are removed in the layer
  that ran pip. For users: the image has no bash and no pip, the GitLab job's
  POSIX script runs under busybox sh, and building it needs BuildKit. Its CA
  bundle is Alpine's: 121 roots against slim's 150, without some legacy roots
  Debian's bundle still carries, among them DigiCert Global Root CA and
  GlobalSign Root CA. A target whose chain ends only at one of those fails TLS
  in this image; mount a file that holds the root and set `SSL_CERT_FILE`. It
  adds to the image's roots: to trust the file alone, also point
  `SSL_CERT_DIR` at an empty directory. The hint for a host
  that does not resolve recognises musl's wording ("Name does not resolve")
  as well as glibc's and macOS's.
- **Starting or running the image compiles no module from source.** Neither
  Python base ships bytecode, and the image's user cannot write any, so the
  only bytecode was what pip wrote for its own imports. Six modules the CLI
  imports were compiled on every start, and moving one `ENV` line made it 109
  without a test failing. The build now compiles what the CLI's verbs import,
  including what they import lazily and the codecs a run looks up by name.
  Measured in the image on 2026-09-27: `--version`, `--help`, `run`, `map`,
  `mutate`, `report`, `capsule`, `verify`, `init`, `coverage`, `new-marker`
  and `serve` each compiled 0 modules from source (with only `veridor.cli`'s
  imports compiled, `run`, `map`, `mutate` and `verify` each compiled two).
  `scripts/image_bytecode_check.py` checks `--version` and a `run` of the
  demo in the image. The CI image job runs it on the image and on two control
  images it must fail, and the release workflow is configured to run it on
  each platform's image before the push and on the pushed digest before
  signing it, so the linux/arm64 image is started before it is published. `tests/test_packaging.py` runs
  every verb and fails when one imports a module the build does not compile.
- **The GitLab include example is pinned to a commit, with `integrity`.** It
  included the component from the `v0.1.0` tag URL. GitLab fetches a remote
  include again for every pipeline, with no notice when it changes, and the
  included job runs with the project's CI/CD variables; a moved tag would run
  changed code there. The README and `ci/.gitlab-ci.yml` now show the commit
  URL, an `integrity` line (GitLab 17.9 or later) and how to get both values.
- **The GitHub Action runs from its own checkout** with `python -P -m
  veridor`: nothing is installed and no package index is contacted. It needs
  Python 3.11 or newer on `PATH` and exits `2` naming what it found
  otherwise. It used to pip-install itself from source, which needed an index
  and failed with `127` on a runner that had `python3` but no `python`. It now
  writes the job summary and JUnit and Markdown reports, and has the outputs
  `version`, `sarif`, `junit`, `markdown`, `gate-exit-code` and
  `gate-reasons`.
- **The Jenkins, Azure Pipelines and CodeBuild templates** call `veridor run
  --report ...`, name every exit code (`0`, `1`, `2`, `3`, `70`, `130`, `143`)
  and exit with Veridor's own. CodeBuild declares `shell: bash`, and Azure
  refuses a secret mapping left as a literal `$(NAME)`. None of the three has
  run on its platform.
- **`veridor capsule` renames non-`VERIDOR_` references** to
  `VERIDOR_<IDENTITY>_<NAME>` or `VERIDOR_<NAME>`, says what it renamed, and
  lists every reference in `requires_environment`, so the capsules it writes
  are ones `verify` accepts.
- **A timeout says which phase timed out**: connecting, the TLS handshake,
  waiting for a response, or reading the body. Every timeout used to say the
  probe reached the target, including a connect timeout behind a
  NetworkPolicy that dropped every packet.
- **SARIF.** `semanticVersion` comes from `veridor.__version__` (it was the
  literal "0.1.0"); rules carry `tags`, and `security-severity` for findings
  about the target; `runs[].automationDetails.id` is `veridor/<run_id>`.
- **The configuration JSON schema** covers configuration versions 1 and 2.
  Every configuration the loader accepts with only known keys is
  schema-valid, and every form the loader refuses is schema-invalid; the
  schema is stricter in one deliberate way, refusing unknown keys the loader
  ignores, so a typo shows in an editor. The `init` scaffold and every
  version-2 configuration were schema-invalid, and several forms the loader
  refuses were schema-valid.
- **`map` no longer requires a `checks` list.** It grades no expectation, so
  demanding a non-empty policy before Veridor would look at an API charged a
  declaration for the one command that needs none. `run` and `mutate` still
  refuse a config with no checks.
- `map`'s exit code is no longer unconditionally `0`: `--fail-on-drift` can
  make it `1`. Nothing `map` *discovers* can fail a build — only a diff against
  a baseline you recorded. README, `--help` and the docs were corrected
  together.
- Boundary coverage now diagnoses a config with no checks as exactly that,
  instead of suggesting a `--base-path` prefix mismatch that is not the cause.
  It still declines to report the result as 0%.

- `--fail-on new|any|confirmed` no longer fire on `inconclusive`. **Deliberate
  change to a documented promise**: a gate that fires when nothing was measured
  is wrong, not strict. Findings about the target gate exactly as before.
- **A run where not one probe was answered now exits 3**, with no flag. Taking
  `inconclusive` out of the gate would otherwise let a wrong base URL exit 0
  with "0 probes matched" and read as verified. `--require-complete` extends
  that to any unanswered probe.

- **Every https:// request goes through one TLS context, built on the
  first.** On Python 3.11 urllib built a new context, and re-read the CA
  bundle, for every request, so what that cost grew with the bundle. A
  200-check run against a loopback https target (603 requests) built 603
  contexts and took 2.32 s with a 129-certificate bundle and 0.72 s with a
  one-certificate bundle; it builds one and takes 0.63 s with either (3.11.15,
  medians of 3 interleaved runs, ranges 2.31-2.35, 0.72-0.74, 0.63-0.64 s). On
  3.12 and 3.13 urllib built one at import, so `--version` and runs against
  http:// targets paid for a context they never used; `--version` on 3.12
  takes 66.0 ms instead of 70.6 ms (median of 15). One laptop, 2026-09-27.
  The context is the one the standard library builds when given none, with
  the same verification, CA store and protocol settings. `tests/test_tls.py`
  compares the two property by property and makes the suite's first real TLS
  handshakes: an untrusted issuer and a wrong name are refused before a
  request is sent, the client offers ALPN http/1.1 alone to a server that
  prefers h2, and no identity presents a client certificate.
- **`run` serializes the run document once per write, not once per file.**
  `runs/<id>.json`, `latest.json` and `--json` were each encoded separately,
  before the gate and again after it: six encodings for `run --json`, now
  two, and `tests/test_gate.py` checks that every copy holds the same bytes.
  A 2000-check `run --json` on 3.12 takes 1.48 s instead of 1.68 s, and its
  peak RSS is 72.5 MB instead of 89.8 MB (medians of 3 interleaved runs,
  2026-09-27).
- **The sdist no longer carries `tests/`.** It held 51 test modules and none
  of the helpers they import (`source_path`, `tiers`), so none of them could
  run from it, and they were half its size: 1.11 MB -> 0.55 MB (1,109,219
  to 1,109,244 bytes before this change, 548,140 to 548,177 now, built as the
  release builds it from `git archive` and working-tree copies, 2026-09-27;
  file times move the total by tens of bytes). Leaving `tests/` out changes no
  wheel entry (names, sizes and CRCs compared).
  `scripts/release_check.py dist` now refuses an sdist with `tests/`, `docs/`
  or bytecode, and one missing any file the wheel installs. Run the suite
  from a clone.
- **The slow tier takes 293.2 s serially instead of 508.6 s,** with 780
  tests where the tree before this change had 742. One laptop, 2026-09-27,
  medians of 3 runs: 508.6 s before (range 508.4-509.3), and 293.2 s now
  (range 292.9-300.6). Test servers poll for shutdown every 0.05 s instead of
  0.5 s, the stubbed Kubernetes end-to-end runs cap each `sleep` at one
  second, and two `map` tests run at `--rate 10`, the ceiling.
- **`scripts/run_tests.py --tier slow --jobs N`** runs the slow tier in N
  worker processes (78.2 s at N=4, range 77.7-84.8, in the same runs as the
  293.2 s) and fails unless together they started exactly the serial
  selection. CI and the release workflow use `--jobs 4`.

- `interpretation.reference`, in every run document and SARIF file, is now the
  URL of the README section on what a `confirmed` finding proves. It was a path
  relative to this repository, which names nothing in a user's CI artifact: the
  wheel and the image ship no `docs/`.

### Removed

- **`ci/tools/*.py`**, the report converters. They were outside the wheel and
  the image, so no documented CI layout could reach them, and they rendered a
  run that answered nothing as a pass. `veridor run --report` replaces them.
- **`workflow_dispatch` on the release workflow**, which skipped the tag check
  on a branch and would still have published, and the moving `v0` tag that
  workflow maintained. There is no moving major tag while the version is
  `0.x`.

### Fixed

- **A sequence step whose session never established was told to check the
  network.** Its finding said "Request failed" and "Confirm the target is
  reachable from the runner and retry", while a check probe for the same
  identity got session-login advice. That was wrong when the login answered
  `200` and its cookie was the problem (already expired, `Secure` over
  `http`, a different name). The step now says "Request not sent" and gets
  the check path's advice, and a request withheld because the session
  expired or its cookie would not be sent says how to fix that instead of
  naming the network. Verdicts and exit codes are unchanged.
- **A run with no `--baseline` reported a regression diff it never made.**
  The summary printed "Regression diff: 1 new, 0 resolved, 0 unchanged" and
  "Evidence: ... 0 escalated since the baseline" whether or not a baseline
  was given; without one, every finding is "new" only because nothing was
  compared. Such a run now prints "Regression diff: no baseline given, so
  every finding (1) counts as new" and an Evidence line without the
  escalated clause, and the Markdown job summary says the same under its
  counts table. A clean run with no baseline says "no baseline given and no
  findings, so nothing was compared" rather than "every finding (0)". A run
  given a baseline prints exactly what it did before, including one whose
  baseline file has no `run_id`, and the run JSON is unchanged.
- **The viewer's run list said "1 new" on a run with no baseline**, the same
  comparison the console stopped claiming, and the run page said "No
  baseline" over a diff made against a baseline file with no `run_id`. The
  list now says "1 finding, no baseline" when the run records that it had
  none, and the page names a digest-only baseline as one.
- **The viewer's footer was cut off behind the sidebar.** The footer spanned
  both grid columns while the sidebar is sticky to the whole page, so on a
  desktop the sidebar stayed pinned over its first 320px and the visible text
  began mid-sentence at "writes, issues no request." in both themes. The
  footer now sits in the content column beside the sidebar; below 900px,
  where the sidebar stacks above the content, it is full width as before.
- **The map called every cell in the grid "Cells probed".** The tile showed
  `matrix.counts.cells`, the grid total, on a page that also said "8 Unknown"
  and "8 of 20 cell(s) WERE NEVER PROBED". It is now "Cells in grid". No
  probed count is shown, because the document records none: `unknown` mixes
  cells never sent with cells sent and not answered.
- **The access matrix said "every cell is a measured status"** above cells
  drawn as a dot because they were never measured. It now says a number is an
  observed status and a dot was not measured, with the reason in the dot's
  tooltip; a cell the document does not hold at all says "no cell recorded".
- **`map --dry-run` exited `0` on a plan the run refuses.** With
  `--max-requests 5` and a 12-request plan, the dry run printed "Over budget"
  and exited `0`, while `map --max-requests 5` refuses with exit `2`. The dry
  run still prints the plan, then gives the same refusal on stderr, says the
  run refuses it the same way, and exits `2`, as it already did for every
  other safety gate.
- **A misspelt check key was refused for something else, or not at all.**
  `"expectt"` was refused as "must expect results for at least two users",
  `"reqeust"` as a missing request, and `"descriptionn"` or `"Name"` loaded and
  was dropped. A check's own keys now get the near-miss refusal every other
  block has: it names the key and the keys a check takes (`description`,
  `expect`, `id`, `name`, `request`), exits `2`, and says to start an
  annotation with `_`. A key that is no slip of a real one still loads as an
  annotation.
- **`report --output` into a directory it cannot write named a file nobody
  typed.** It printed `[Errno 13] Permission denied:
  'ro/.j.xml.42f6df0f81e22ee1.tmp'`, the temporary sibling the atomic write
  creates first. It now says it could not write the report to the `--output`
  path, the reason, whether it failed writing into or creating the parent
  directory, and the uid:gid for a permission error, and exits `2`. A `run
  --report` write that fails after the run (a full disk) says the same.
- **The Action's drift-mode exit-3 annotation said "no drift was found" over
  a report listing 12 changes.** A baseline recorded with the target down,
  compared with a live run, gains a measurement on every cell, so the report
  lists those changes while no cell was measured in both runs and `map` exits
  `3`. The annotation now says the drift gate did not fire and that changes may
  still be listed: cells measured in only one run, or changes `fail-on-drift`
  does not gate on.
- **`mutate` with its target down printed `Mutation score: 0.00`.** Every
  generated mutant errored, and an errored mutant sits in the denominator as a
  miss, so the score was `0 / 13`: a measured failure of checks that were never
  exercised, where the documentation promised `n/a`. When no generated mutant
  was evaluated, `score` (and `score_of_evaluable`, per operator and per tier-2
  hook) is now `null`, the text prints `n/a` and says why, the badge is
  `unknown` in grey, and `serve` shows no score for it, including for a report
  written before this change. Errored mutants beside at least one evaluated one
  still count as misses, and the run still exits `2`.
- **`report` rendered an INCONCLUSIVE capsule verification as "Gate passed
  (exit 0)", and `serve` listed it as a failed run.** `verify` wrote the run of
  the capsule to `--output-dir` as an ordinary run: no gate, no verdict, and a
  `config` naming a temporary file deleted before the command returned. The
  verdict and its exit code existed only on stdout, so `report --from-run`
  re-derived a gate with the `run` defaults (a `500` grades `inconclusive`,
  which they do not gate on) and `serve` coloured the row from the status the
  findings give. `verify` now writes `capsule` (verdict, exit code, reason,
  check, capsule path) and a `gate` whose exit code is the verdict's into
  `latest.json`, `runs/` and `--json`, and names the capsule as `config`.
  `markdown` and `junit` lead with the verdict (`gitlab-sast` and
  `codequality` carry an INCONCLUSIVE one as a non-finding gate reason; `sarif`
  has no gate and carries none), `serve` shows
  `capsule · INCONCLUSIVE` (amber), `CONFIRMED` (red) or `NOT REPRODUCED`, and
  a document whose verdict, exit code and gate disagree is refused with exit
  `2`. Run documents without `capsule` render as before.
- **`serve` could sit unreachable for about 35s on a Mac whose hostname does
  not resolve.** `http.server` looks up the server's own name after `bind()`
  and before `listen()`; where that lookup stalls (every GitHub-hosted macOS
  runner, actions/runner-images#14409), a browser or client connecting in
  that window was neither served nor refused, because macOS leaves a SYN to a
  bound port that is not yet listening unanswered. The UI server, the demo API
  and the noise-study server no longer make the lookup.
- **`run --openapi` left a stale coverage file and green badge when the
  configuration did not load.** `run` loads the configuration before it
  reaches coverage, so that refusal exited `2` with the previous run's
  `"measured"` `--coverage` file and `--badge` still in place, although the
  README says such a refusal rewrites both. Both are now rewritten as not
  measured (`"status": "not_measured"` with the reason, and `unknown`), as
  `veridor coverage` already did. A refused output path still writes nothing.
- **`summary.safe` went negative when a session did not come up.** It was the
  probe count minus the check findings, and an identity whose session never
  established gets a finding and no probe, so with every login answered `503`
  the console printed "-2/0 probes matched their declaration", and with one
  of two sessions down a matched probe printed as "0/1". It now counts the
  sent probes that have no finding, so it stays between `0` and the probe
  count and is unchanged on a run where every finding is about a sent probe.
- **The JUnit, Code Quality, GitLab SAST and Markdown reports passed a probe
  the console qualified.** A request that went out without its declared
  `form_field` or `json_field` (`injection_disclosures`), an exclusion licensed
  by a `marker_probe` and a fabricated credential the target served
  (`oracle_disclosures`) were printed on the console and carried in SARIF, but
  JUnit read only non-asserting expectations and unproven denials, Code Quality
  only non-asserting expectations, and GitLab SAST and Markdown none. A GET
  probe that matched its declared denial without its CSRF field was an
  unqualified pass in the formats a merge request shows. Every format now
  reads the list the console prints: JUnit puts each on the probe or sequence
  step case it qualifies and the rest on `veridor.gate`, Code Quality makes
  each an `info` issue, GitLab SAST an `info` scan message, and Markdown lists
  them under "What the matched probes do not establish". A non-asserting
  expectation or unproven denial whose probe has no JUnit case was dropped;
  it now goes on `veridor.gate`. The injection statement said "does not prove
  the field-guarded path is safe", a word the Markdown report may not print;
  it now says the denial may be the target refusing the missing field rather
  than the identity.
- **The SARIF rule text for VERIDOR-LEAK-001 was garbled and claimed proof of
  data flow without its condition.** Emitted in every SARIF document, it read
  "the string crossed, and that is data another. That is proof of data flow.",
  dropping the "insofar as the marker is unique" condition the finding message
  carries. It now carries that condition and names how a marker that a
  fabricated credential also received is graded instead, and
  `interpretation.confirmed_grade_means` no longer reads "That is evidence
  flow".
- **A login redirect that became a success passed `--fail-on-drift opened`
  with "0 that mean more access" in the headline.** A cell the baseline
  answered with a 3xx and the current run serves, such as an anonymous `302`
  to `/login` that is now a `200`, is not counted by `opened`, and the report
  said the baseline never measured it. `opened` still does not count it, since
  counting every redirect would fail on each trailing-slash or https fix, but
  the drift document now records `redirect_now_served_cells`, the text and
  Markdown headlines give the count, and stderr says `opened` does not count
  them under every policy except `any`, which fails on them.
- **The `--no-prove-liveness` help described a stricter default than ships.**
  It implied that with liveness controls on, an expired token fails the gate;
  under the default flags an identity expected only to be denied exits `0`
  with an expired token either way, and only `--require-complete` turns an
  unproven denial into exit `3`. The help now says so, and the README no
  longer gives an expired token as an example of the no-answer exit.
- **`report --help` and docs/report-formats.md said every format reads the
  gate.** SARIF carries findings only, so a run that exited `3` only for an
  unproven denial or an unclean teardown renders as zero SARIF results, the
  same bytes as an exit-`0` run. The help, the report formats page, the README
  and the reports package documentation now name SARIF as the exception and
  point at the job's exit code.
- **The test that `--drift` may not overwrite `--baseline` could not fail.**
  It pointed at a baseline file that did not exist, so the run exited `2` for
  the missing file whether or not the protection was there. It now uses a real
  baseline, checks the refusal message and that the file is untouched, and
  fails when the protection is removed.
- **The case-sensitivity probe's test passed a probe hard-coded to either
  answer.** It checked only that the probe returned a bool, though every
  case-variant output-path test relies on it. It is now checked against an
  independent look at the real filesystem, and made to return both answers.
- **A sequence step or teardown request whose `headers` was not an object
  crashed the loader.** A string, number or list there stopped `veridor run`
  with an internal error (exit `70`) before the request rules could refuse it.
  It is now refused with exit `2`, as the same value on a check already was.
- **`ABORT_REASONS` was incomplete and enforced nowhere.** It lacked four
  reasons the engine writes to the run document (`marker_reflection_blocked`,
  `step_inconclusive`, `session_not_live`, `response_from_cache`). It is now
  complete, and recording a reason outside it is an internal error.
- **Running a test file directly skipped every class after a mid-file
  `unittest.main()` guard.** Thirteen test modules, among them the sequence,
  session, docs and release-files suites, put the guard above live test
  classes, so `python tests/test_x.py` stopped before those classes existed
  and still printed OK; discovery and CI always ran them. Every guard is now
  last in its file, and a test fails when any test file puts a statement after
  it, or has other than exactly one guard it can see; a guard with CRLF line
  endings, in parentheses or written `"__main__" == __name__` was invisible
  to that check and passed whatever followed it.
- **`mutate` counted an uncorroborated M5 as a kill.** When M5's negative
  control (the fabricated-id request) was not sent, because the request budget
  ran out, the method changes state or the path has no resource id, or when
  that request failed, M5 was recorded killed on the owner's status alone. It
  is now skipped with the reason, or errored, as M4 and M6 already were. A run
  whose budget runs out before M5 still scores as it did, because a skipped
  mutant is outside the score, but the report now lists the skip instead of an
  ordinary kill.
- **`mutate`'s M4 left check-level credential headers on its unauthenticated
  copy.** It removed a check's own header only when it was named `Cookie`,
  `Authorization` or `Proxy-Authorization`, so a check authenticating with
  `X-Api-Key` kept the key: an identity with no headers of its own was skipped
  as having no credential to strip, and a 2xx through the key was read as a
  public route. M4 now removes every header a check sends that
  `veridor capsule` counts as a credential header.
- **The credential-parity tests could not catch a refusal that echoed the
  value it refused.** They checked only that one shared corpus literal was
  absent, and several refusal cases (`abc`, `theme=dark`, `123456`, `bob` and
  others) never contain it. Each case now records the value it refuses, both
  the capsule and the chart side are checked for it, and controls make each
  kind of refusal echo its value to show the check can fail.
- **Blast radius counted a credential in an unrecognised header as no
  credential.** Only six header names counted, so a stale GitLab
  `PRIVATE-TOKEN` or `X-Access-Token` was never suppressed or warned about,
  and could be inferred as the unauthenticated identity with a note saying its
  headers map was empty. Every header now counts except a closed list of
  standard request headers that never carry one (content negotiation, caching,
  `Origin`, `Referer`, tracing, and the `Accept-*`, `If-*`, `Sec-Fetch-*` and
  `Sec-CH-*` families). `Sec-WebSocket-Protocol` still counts, because
  Kubernetes carries a bearer token in it.
- **One unmeasured sibling switched `sibling_asymmetry` off for its whole path
  family, uncounted.** A templated sibling with no specimen, one
  `matrix.ignore` entry or one failed probe made the rule skip the family for
  every identity, which read exactly like a family with no asymmetry. The
  unmeasured member is now dropped from the comparison and counted as
  `sibling_asymmetry_member_unmeasured`.
- **An injected clock running faster than real time skipped `execute_matrix`'s
  rate limit.** A library caller passing a counter or a millisecond clock sent
  40 requests at a declared 1 req/s in under a millisecond, while the run
  document still reported 1 req/s. Such a clock is no longer trusted and the
  interval is served in real time. The docstrings now say the real-time
  guarantee holds for the default clock, the only one the CLI uses, and which
  other injected clocks are trusted rather than checked.
- **Blast radius explained a `400` or `422` as a redirect.** Every unresolved
  cell was labelled "redirect, not followed", with advice to declare a
  post-redirect status that no setting accepts. Redirects and other unresolved
  statuses are now reported separately without that advice, and the
  stale-credential line says `401` rather than `401/407`, because a `407` is
  counted as unmeasured.
- **A loaded matrix row with no `shared_specimen` key counted as shared.** A
  missing key, or a non-boolean such as the string `"false"`, let
  `peer_divergence` compare answers about two different objects. A missing key
  now means not shared and a non-boolean is refused. Only library callers
  loading hand-edited matrices could reach this.
- **The blast-radius vocabulary check missed forms of a policed word that
  change its stem.** It did not match `vulnerabilities`, `leakage`,
  `exploitation`, `severities` or `unauthorised`, nor base forms such as
  `guarantee` and `verify`, so the tests that police rendered candidate text
  could not fail on them. It now matches the base, present and common derived
  forms of each policed stem, and no longer flags `severed` or `severing`. No
  shipped human-readable text used any of the missed forms.
- **Nothing tested the stored coverage ratio's precision.** The regression
  test for the six-decimal ratio checked the builtin `round` on literals and
  never called `compute_coverage`, so a return to four places, which stores
  `1.0` for 19,999 of 20,000 operations, passed every test. The tests now
  check the ratios `compute_coverage` stores, including on a 20,000-operation
  inventory with one operation uncovered.
- **`veridor capsule --from-run` could publish the wrong finding as the
  claim.** It took the run's first finding for the check whatever its verdict,
  and `run` emits findings in expect order, so an owner control's refusal
  often became the claim: `verify` then reported a spurious grade mismatch and
  printed the control's message as the reporter's statement. The claim is now
  the vulnerable finding when the run has one.
- **The coverage report's published claim described a rule it does not
  apply.** Its statement counted a denial asserted "for at least one non-owner
  identity", but coverage has no owner concept and counts any identity's
  denial-only expectation, as the README says. The statement now says "for at
  least one identity".
- **Two coverage helpers were documented as wired when nothing called them.**
  `coverage_summary` was described as the block embedded in run documents and
  SARIF, and `operation_for_check` as attaching a finding property; neither is
  called, so no output carries either. Their documentation now says so.
- **The UI server served a mutation badge as a mutation report.**
  `/api/mutations` leaves `-badge` files out, but
  `/api/mutations/mutation-badge` returned the shields.io badge with `200`,
  and on a case-insensitive filesystem so did any letter case of it. The
  detail endpoint now serves only the stems the list offers, and the list
  matches the `-badge` suffix in any case.
- **The viewer said "Nothing moved" over a drift comparison that compared
  little or nothing.** The drift panel chose its sentence from an empty change
  list alone, so re-seeded specimens hiding a `200` that carried the victim's
  marker rendered like a quiet run, while the CLI printed "Nothing to compare"
  and exited `3` under a gate. The panel now withholds the sentence when the
  CLI does, says how much of the grid the comparison saw, and shows the
  unmeasured, never-probed, incomparable, redirect and blind-baseline warnings
  above the changes, as the README promised.
- **The viewer painted a run the gate had failed as a green PASS.** A run's
  `status` comes from findings alone, so a run that exited `3` for an unproven
  denial, an unclean teardown or a non-asserting expectation stays `passed`,
  and the run view and run list coloured it like a run that exited `0`. The
  badge and the list dot are now amber when the gate's exit code is not `0`,
  the badge names the code, the run view lists the reasons, and the run-list
  API carries `gate_exit_code`.
- **The viewer's mutate view said "Every mutant was killed" when nothing was
  measured.** The green hero and the all-clear keyed on surviving mutants
  alone, so a report that generated no mutant, or whose only unkilled mutants
  errored (both exit `2`), showed as clean. Green and the all-clear now mean
  what exit `0` means, and an empty mutant set says nothing was measured.
- **The docs said every non-loopback `map` target needs
  `--acknowledge-target`.** The code waives it, deliberately, for every
  address that is not globally routable (RFC 1918, CGNAT, ULA, link-local
  including `169.254.169.254`, and the documentation ranges), and SECURITY.md
  called probing such a host without it a vulnerability. README and
  SECURITY.md now state the rule as shipped: a globally routable address, or
  any hostname but `localhost`, needs it.
- **The code of conduct presented an unverified reporting address as
  working.** Nobody has shown that the conduct address receives mail. The code
  of conduct now says it is unconfirmed and names a private fallback, and a
  test fails if it and CONTRIBUTING.md disagree.
- **The release workflow test did not tie the PyPI publish action's container
  digest to the action's SHA.** A bump that moved the SHA and left the old
  digest passed the test and both `pin-action-image.sh` steps, and the new
  action ran the old container under the new tag, though `dependabot.yml` said
  the test fails until the new digest is named. Each SHA's digest is now
  recorded in the test, and a moved SHA fails until its digest is resolved and
  recorded.
- **The GitHub release notes gave verify commands that fail on files the
  release attaches.** They said to run `gh attestation verify` on "a
  download", but only the wheel, sdist and zipapp carry provenance, not the
  SBOM or SHA256SUMS, and their `sha256sum --check SHA256SUMS` exits `1` for
  anyone who did not download every file. The notes now say which files carry
  provenance and give `sha256sum --check --ignore-missing SHA256SUMS`. The
  workflow test reads only the text the notes groups append to `notes.md`,
  reads each `sha256sum` the way `sha256sum` reads its arguments, and fails
  when `--notes-file` does not reach the `gh release create` line or a line
  between the groups and that line names the notes file: it had passed with
  the changelog generator moved after the groups, a truncation before the
  release, or the flag only in an `echo`. It also fails when a second notes
  source reaches that line (`--notes`, `-n`, `--notes-file` or `-F` naming
  anything else, or `--notes-from-tag`), on the line itself or in a later
  `flags+=(...)`, a conditional one included: it had passed with a trailing
  `--notes ''` beside the flag. An append it cannot read fails too: a
  backtick command substitution or an expansion standing as a word of its own
  (`flags+=($EXTRA)`), either of which may be a notes option when the step
  runs, had passed while `"${extra[@]}"` was refused; an expansion that is an
  option's value (`--title "$NAME"`) is still read. The same holds for an
  unquoted `${extra[@]}` or a `$EXTRA` word on the create line itself and an
  element set by index (`flags[99]=--notes`), an expansion inside an
  option's name (`--$OPT`, `--notes$SUFFIX`), an unquoted expansion where the
  tag goes, an array filled by `mapfile` or `read -a`, and
  `--generate-notes`, which gh prepends the notes to. The notes file spelled
  `${RUNNER_TEMP}/notes.md` is no longer called a second source, and a glob
  or a trailing `/` under `$RUNNER_TEMP` is no longer called a file beside
  it. A line naming another
  file under `$RUNNER_TEMP` is named for that file, not called the notes
  file.
- **The Dependabot configuration said every Dockerfile pins its base image by
  digest.** The kind demo image, which is not released, builds from the moving
  `python:3.12-slim` tag. It is now listed under "Not pinned at all", and a
  test fails when a Dockerfile Dependabot covers uses a tag-only base the
  header does not list.
- **Nothing ran the GitHub Action's drift mode against the real package.**
  Every drift-mode test used a stub that wrote the JSON the test supplied, so
  renaming a drift-document key inside the package left the
  `drift-blind-cells` output empty while every Action test passed. A test now
  runs `action.yml`'s drift mode against the real package.
- **The GitLab component said no exit code but `3` can ever be allowed to
  fail.** A rule passed in `job_rules` can set `allow_failure`, which GitLab
  documents as overriding the job's own, so such a rule could show a finding
  (exit `1`) as a warning. The input descriptions, the template header, the
  README and ci/README.md now name that exception and the exit codes it
  reaches (`1`, `2`, `3` and `70`), and the allow-failure test checks each
  rule as well as the job.
- **The kind demo's seed carried on when its demo target did not come up.** It
  probed whatever else answered on the port, or nothing, and exited `0`, so
  the viewer started without the finding the README says it shows. It now
  refuses a port something already answers on, and fails when the target exits
  or does not answer within 10 seconds, so the viewer does not start.
- **`scripts/patched_pairs.py` held the evidence grade once per pair, not per
  declared failing check.** On a pair declaring several failing checks, one
  `confirmed` finding passed the pair even when every other declared check had
  fallen to `suspected` or `ungraded`. Every declared failing check now needs
  a finding at the expected grade, and those that do not are listed as
  `below_grade` and printed.
- **`scripts/patched_pairs.py` could certify a fix against a dead attacker
  credential.** It never read `liveness.unproven`, so a patched build where
  the attacker's session was dead, and refused like a fabricated credential,
  exited `0` with no finding and passed the pair. The harness now decides
  liveness itself: each denial-only expectation of an identity that presents a
  credential passes only if that identity was served a 2xx somewhere in the
  patched run, or the harness's own fabricated-credential request on that
  check drew a different refusal or a 2xx or 3xx. A `429`, a 5xx or a `400`
  proves nothing and fails the pair, as does an entry in `liveness.unproven`.
  So does a `407`: it counts as a denial when grading, but it is a proxy's
  answer before the request reached the application, and the rule first took
  the whole denial set, so a proxy refusing the sham certified a dead
  credential behind it. The same holds on the identity's side: when the
  identity's own request drew `407`, a sham's `403` differed from it and
  certified a credential that never reached the application; such a denial
  is now unproven whatever the sham drew, and whether or not the identity was
  served on another check: that rule ran after the served-elsewhere skip, so
  an identity live on one check had a proxy's `407` on another accepted.
- **`scripts/pre-push` tested the working tree, not the commits being
  pushed.** It ignored the refs git passes on stdin, so a red commit went out
  whenever the checkout was green: an uncommitted fix, or
  `git push origin <red branch>` from a green one. It now exports each
  distinct pushed tip with `git archive`, an annotated tag peeled to its
  commit, runs the fast tier there, and refuses naming the commit that failed.
- **The Ghost pair's provisioner still said the owner's sweep found the marker
  on four routes.** The fixture records exactly two, `/integrations/` and
  `/integrations/?include=api_keys`, and says four did not reproduce. The
  docstring now names the two, and a test compares it with the fixture.
- **The test that a stdout leak fails the fast tier passed without the leak
  branch's exit.** It checked only that `main()` held a `return 1`, and it
  holds four. It now runs `main()` on a planted leaking test and asserts exit
  `1`, beside a quiet control.
- **The stdlib-only guard missed dynamic imports spelled any way but two.**
  `from importlib import import_module`, an aliased `importlib`,
  `builtins.__import__` and `runpy.run_module` passed the scan, though the
  module says every runtime import is checked. It now resolves those names per
  file and lists what they import, and an importer passed around uncalled is
  listed as `<dynamic>`.
- **The fast tier's per-test budget never saw class or module fixtures.** It
  timed `startTest` to `stopTest`, and unittest runs `setUpClass`,
  `setUpModule` and their teardowns outside that window, so a class that spent
  seconds in `setUpClass` passed. The time between test classes is now held to
  the same budget and named for the classes on either side.
- **`scripts/noise_floor_study.py --verb run` measured a gate nobody ships.**
  It ran `veridor run` without `--require-complete` and counted only exit `1`,
  so it reported a 0/10 false gate rate where most of the same runs exit `3`
  under the posture the Action, the GitLab component and the Helm chart ship.
  It now passes `--require-complete`, counts every non-zero exit as a failed
  build with a breakdown by exit code, labels its rate with the posture it ran
  (in `--detect` mode too), and exits `1` when any run failed.
- **The Kubernetes end-to-end negative control ran nowhere.**
  `E2E_CONTROL=gate-passes-wrongly` is documented as ending in exit `1`, but
  no workflow ran it, so CI never showed the script's zero-mismatch result
  could fail. The Kubernetes e2e job now runs it and fails unless it exits `1`
  with mismatch rows, and a test holds every control the script knows to a CI
  step.
- **`scripts/blind_config_study.py` hid a README configuration that was not
  valid JSON.** A JSON block that failed to parse was classed a fragment and
  counted toward nothing, so a complete example broken by a doubled comma left
  the denominator and the study reported `TOTAL GAPS: 0`; it also exited `0`
  when it did count a gap. A block is now a fragment only if it parses as an
  object's members, anything else is reported BROKEN, the study exits `1` on
  any gap and its test prints the study's report, and the schema-parity README
  corpus no longer drops such a block silently.
- **Two checks in `scripts/e2e_validation.py` passed on the regressions they
  named.** The promotion-stub check was true of an empty list, and the
  `mutate` check accepted exit `2` (an errored or aberrant mutant) against a
  deterministic demo that exits `1` every run. It now requires one stub per
  candidate, no errored or aberrant mutant, and `mutate` exit `1`.
- **Two docstrings credited CI's green end-to-end run to a script no workflow
  calls.** CI runs
  `scripts/e2e_validation.py` once, in a fresh checkout, into an empty default
  directory, which is why it missed the stale-artifact bug. Both now say so.
- **The precision fixture ranked its two same-tenant peers without saying what
  the ranking moves.** Tests now show that precision and bob's marker-backed
  IDOR hold with the peers unranked or `privilege_order` absent, that ranking
  bob above the marker owner costs a counted `marker_reach` suppression rather
  than passing silently, and that the `inverted_guard` candidate on carol's
  `GET /api/admin/keys` does follow the ranking. The comment above
  `privilege_order` now says exactly that.
- **The precision fixture's `own_profile` specimen was declared as shared.**
  The generator wrote it under `values` instead of `per_identity`, so the
  shipped blast-radius configurations carried a second load refusal hidden
  behind their short-marker refusal, and contradicted the matrix's
  `shared_specimen: false`. It is now `per_identity`, and a test shows the
  marker is the only thing still wrong with those configurations.
- **`tests/fixtures/matrix.observed.json` was not a matrix its paired config could
  produce.** It recorded `GET /health` as measured for every identity,
  anonymous included, with 53 requests and nothing ignored, while
  `matrix.demo.json` ignores `/health` and plans 48. It now records the
  ignore, and a test plans each shipped config and matrix pair and requires
  the canned matrix to match.
- **The committed matrix fixtures had drifted from what Veridor writes.** The
  precision matrices, `matrix.observed.json`, `matrix.sibling.json` and
  `matrix.shared.json` lacked two safety keys a run now writes, and the
  precision generator's docstring counted 43 operations where it builds 44.
  All are corrected, and tests now require the precision matrices to be
  byte-identical to the generator's output and every canned matrix to
  re-serialise unchanged.
- **The principal mutation fixture's docstring named three guard-gated routes;
  the guard gates five.** `/api/scoped/inv-7` and `/api/admin/audit` also open
  when the guard file is removed. The docstring names all five, and a test
  compares it with what the live fixture does.
- **The map demo config said its checks were the same as
  `veridor.demo.json`'s; one is not.** Its `audit-admin-role` check asserts
  `anonymous` -> `401` where the demo asserts `other_tenant` -> `403`. The
  comment now says so, and a test compares the two files.
- **The shipped mutation fixture called `/api/orders/o-1` the negative
  control.** That route answers `404` to every non-owner token, so M6 is
  reported `not_applicable` there, neither a kill nor a survivor; the real
  negative control is the principal fixture's override. The docstrings now say
  so, and a test checks them against an engine run.
- **The graded vacuity fixture shipped with nothing that ran it.** A test now
  runs it with one check per route and asserts both arms: no survivor on a
  good check, and on each vacuous check the survivor that names its vacuity.
  Its summary names the one vacuous route that has no survivor, and a test
  holds the summary to that.

- **Three tests released a port to the kernel and used it later**
  (`_free_port`, `_closed_port`, the zipapp `serve` probe), so another process
  could be handed it in between. They now take a port from outside the
  ephemeral range, and under `--jobs` each worker picks from its own share of
  it: nothing reserves such a port, and two processes seeded alike picked
  the same one (measured).

- **`scripts/run_tests.py` passed runs that had not run their tests.** A
  `SystemExit` from a class or module fixture (argparse's `--version`, say)
  ended the fast tier, the serial slow tier and `all` with exit `0`, no "Ran"
  line and nothing after it run. A tree with no test module passed every
  tier, `--jobs` included. Under `--jobs`, a class whose `setUpClass` skipped
  because another worker held a lock was excused, though a serial run ran it
  (each measured on a planted tree). Every tier now fails unless it started
  each test it selected or unittest skipped it with its fixture, a tier that
  selects nothing fails, and a class a fixture skipped in a worker runs again,
  alone, after the others. A test server started around `tests/loopback.py`
  (with `operator.methodcaller`, say, or `http.server.test`) is refused when
  it starts, where the source scan could not see it.
- **CI could skip its own checks and stay green.** `if: ${{ false }}` or
  `continue-on-error: true` on the image's bytecode check or its gate, the
  GitLab end-to-end script or its controls, or any test-tier step, and
  deleting a fast-tier step, each left every workflow test passing
  (measured). `tests/test_workflows.py` now refuses each, and counts the fast
  tier's runs as it counted the slow tier's.

- **`scripts/patched_pairs.py` printed a hung docker command's arguments, and
  its cleanup could hide a failure.** A docker command that timed out was
  reported with Python's own text for the timeout, which is the whole command
  line, so `gitea admin user create ... --password` put a provisioning
  password (a hard-coded test value for a throwaway container) on stdout and
  in `--json` (measured with the timeout cut to a second). It now names the
  subcommand and the timeout only. Each build's cleanup was a `finally` of
  `docker stop` then `docker rm -f`: a stop that hung replaced the pair's own
  error and never reached `rm -f`, leaving a known-vulnerable build running on
  loopback. `rm -f` now runs whatever the stop did, the pair keeps its own
  error with the cleanup failure added to it, and a container that could not
  be removed fails the pair. A run stopped only by an unreachable docker
  daemon ended "A pinned tag no longer names the pinned build"; it now says
  Docker could not answer.

- **The chart's helm-mode cluster check needs `list` on ConfigMaps, and said so
  nowhere.** `hook.mode: helm` asks Helm to `lookup` ConfigMaps in the release
  namespace to tell the Helm CLI from Argo CD, and Helm passes back anything
  that is not a 404, so a least-privilege installer without that `list` fails
  the render with Kubernetes' own `forbidden` rather than the chart's message.
  The chart README now states the requirement and the escape
  (`hook.helm.allowRenderWithoutCluster`, read before the lookup).

- **`verify` crashed on a capsule written from a single-integer status.**
  The config schema reads `"status": 404` as `[404]`, but only the config
  loader's own copy was normalised: `veridor capsule` copied the scalar into
  the capsule as written, and the NOT_REPRODUCED check tested
  `status not in 404`, which raised TypeError. Measured with two demo
  servers: a capsule `veridor capsule` wrote from such a config exited `70`
  ("internal error") against the fixed target, where it must print
  NOT_REPRODUCED, and `CONFIRMED` against the vulnerable one. The capsule
  loader now reads every declared status by the config loader's rule, a
  status that is no HTTP status is refused at load (exit `2`, nothing sent),
  and `veridor capsule` writes the shorthand as the list it stands for.
- **The Argo CD docs said every sync runs the gate.** The Argo CD guide,
  the chart README, NOTES, `values.yaml` and the chart's messages said each
  sync runs `veridor run` with a Job of its own, and told readers to alert on
  a `Failed` operation. Argo CD v3.5.3 runs no hook for a sync that names
  resources (`argocd app sync --resource`, some resources from the UI,
  self-heal) or uses the apply strategy (`--strategy apply`, *Apply Only*):
  the operation ends `Succeeded`, `successfully synced (all tasks run)`, with
  no `PostSync` entry and no gate Job, whatever it applied. Measured on kind
  with the vulnerable version deployed right after its full sync `Failed` on
  the gate. The docs now name those syncs wherever they say a sync runs the
  gate, and say to alert on a `Succeeded` operation with no `PostSync` entry
  as well; the e2e's `argocd` scenario has the two syncs as rows.
- **Argo CD could render the chart in `hook.mode: helm`, with one fixed Job
  name.** The chart refused argocd mode under the Helm CLI but not the
  mirror: helm mode rendered by Argo CD, which the chart README's
  dependency recipe leads to when the app is deployed through Argo CD. Argo
  CD maps `post-install,post-upgrade` to `PostSync` and
  `before-hook-creation` to `BeforeHookCreation`, so every sync's gate Job
  had one name, the shape argocd mode left. Measured on kind with Argo CD
  v3.5.3, in an Application of the gate alone with the target switched on
  every sync: 14 of 80 helm-mode syncs were reported from the previous
  sync's Job, 6 of the 40 vulnerable ones `Succeeded` with their own gate at
  exit 1 (argocd mode: 0 of 50; with the app rolling on every sync, helm
  mode 24 of 24 correct). Helm mode now refuses a render that reaches no
  cluster, which is how Argo CD renders, so the Application shows a
  `ComparisonError` naming the refusal. This also refuses `helm template`
  and `helm install --dry-run=client` of helm mode: set the new
  `hook.helm.allowRenderWithoutCluster: true` for those (a boolean; never
  under Argo CD). `helm install` and `helm upgrade` are unchanged.
- **No Kustomize overlay for Argo CD.** `overlays/argocd` rendered the gate
  as a `PostSync` hook with one fixed name and `BeforeHookCreation`, and
  Argo CD v3.5.3 reported syncs from the previous sync's Job: its e2e leg
  reported a sync `Failed` whose gate exited 0 (the chart's Job, named the
  same way, below). Argo CD's remedy is `generateName`, and Kustomize refuses
  it: `kubectl kustomize` (Kustomize v5.7.1) and the Kustomize in Argo CD
  v3.5.3 (v5.8.1) stop with `missing metadata.name` on a Job that has only
  `generateName`, in a base or after a patch that removes the name
  (measured). The overlay and `deploy/argocd/application-kustomize-example.yaml`
  are removed; with Argo CD the gate comes from the chart, which Argo CD
  renders itself, next to an app that can stay Kustomize.
- **`job.annotations` could keep a stale gate result.** Only the hook keys
  were refused there, and the chart's own test rendered
  `helm.sh/resource-policy: keep` as an ordinary annotation. Measured on kind
  with `hook.mode: none`: `helm uninstall` kept the passing Job, the target
  was switched to vulnerable, and `helm install` with the same values adopted
  that Job (same uid, still `Complete`), ran no gate, and the NOTES wait
  exited 0; without the annotation the same install ran a new Job, which
  failed. Every key under `helm.sh/` and `argocd.argoproj.io/` is now refused
  in `job.annotations`.
- **The chart README's revision-label snippet was not complete.** Its
  Service used `targetPort: http` and the Deployment half showed only the
  pod labels; an app whose container port has another name gets a Service
  with no endpoints. The snippet is now a whole Deployment with a container
  port named `http`, and a test renders it from the README.
- **The chart said `strategy: Recreate` avoided the default-flags hazard.**
  NOTES and the chart README blamed the hook probing the version being
  replaced on `RollingUpdate` alone, and the README called `Recreate`
  "measured correct" without saying it was measured with
  `--rollback-on-failure`. Measured on kind with `Recreate` and Helm's
  default flags: 2 of 2 vulnerable upgrades were `deployed` with the gate at
  exit 0, every gate request answered by the replaced pod, which was still
  terminating when the hook started. Both now say so, and the README's table
  has the row.
- **The GitHub Action's path outputs named files it had not written.**
  `run-json`, `sarif`, `junit`, `markdown`, `drift-json` and `coverage-json`
  were set on every path out of the step, refusals included, so after an
  exit `2` `outputs.sarif` named whatever an earlier step had left at
  `veridor.sarif` (reproduced with the test harness: all five run-mode path
  outputs set after a refusal, two of them naming stale files). Each is now
  set only when Veridor wrote that file during the step, by the same
  device-and-inode check the counts already used, and is empty otherwise.
- **The README's SARIF upload example uploaded a stale file after a
  refusal.** It ran on `always() && hashFiles('veridor.sarif') != ''`, which
  is true for a file an earlier step left at that path. It now runs on
  `steps.veridor.outputs.sarif != ''` and uploads that output, which the
  Action sets only when it wrote the SARIF during the step.
- **`report --from-run` exits `2`, naming the field, on a hand-edited run
  document.** The run check looked at top-level containers only, so a wrong
  type or a missing key one level down (a probe's `response`, a finding's
  `evidence.request`, a gate reason's `finding_ids` or `identities`,
  `liveness.unproven`, a `regression` list, a sequence's `steps`, a
  non-asserting expectation's keys) crashed a renderer with exit `70`, "a bug
  in Veridor". Measured by setting every nested field to each wrong type, or
  deleting it, and rendering every format: 14 field paths crashed; none does
  now, and docs/report-formats.md, which already said such a run exits `2`,
  is now true. That sweep missed a gate reason's `sequences` (written for
  `--require-clean-teardown`), which the Markdown, JUnit, GitLab SAST and
  Code Quality renderers join: `"sequences": 5` was exit `70` in all four
  (measured). It is held to a list of strings now, in `reasons` and
  `not_enforced` alike.
- **A `407` is the proxy's answer, not a finding about the target.** A probe
  refused with `407 Proxy Authentication Required` was an unexpected denial
  whose message said "The target refused this request"; behind an
  authenticating proxy urllib cannot satisfy, every probe got one and the
  target received none (measured). It is now graded like a `429` or a `5xx`:
  not an answer from the authorization layer, an inconclusive probe (exit `3`,
  not `1`), whose message says a proxy answered and the request most likely
  never reached the target, in checks and sequence steps alike.
- **The README no longer says a passing run means every expectation held.**
  Two sentences did (in "Mutate" and "No proof of security"), the claim the
  CI gate lines were corrected for: a finding the gate does not fail on, and
  an unanswered probe without `--require-complete`, exit `0` too. They now say
  nothing the gate fails on was found.
- **Wrong-typed session and sequence fields are refused, not crashed on.**
  A login step's or a session's `capture` that is not an object, a
  capture's `from` or a session's `reestablish` given a list or an object, a
  sequence's `steps` given a number, and a step's `role` given a list or an
  object each ended `run` and `verify` with exit `70`, "a bug in Veridor"
  (measured by setting every field of a configuration with sessions and
  sequences to each wrong type). Each is exit `2` now; nothing was sent
  before or after.
- **`map --rate nan`, `--max-run-seconds nan` and `--timeout nan` are refused
  with exit `2`.** NaN compares false with everything, so it passed both the
  "greater than zero" check and every ceiling: the first two crashed with exit
  `70` before anything was sent, and `--timeout nan` ran a matrix in which no
  request could complete (exit `3`). Measured on each.
- **`hook.mode: helm`, as documented, gated the version being replaced.** The
  chart README said a failed gate makes `helm upgrade` exit non-zero and never
  said how to run it. Helm starts post-upgrade hooks as soon as it has
  applied the manifests (Helm 4's default `--wait=hookOnly`), while a
  `RollingUpdate` Deployment's previous pods are still Ready: measured on
  kind, 2 of 2 vulnerable upgrades were `deployed` with the gate at exit `0`,
  every gate request answered by the replaced pod, `--wait-for-target`
  returning at 0 s. Waiting is not enough: with `--wait` or
  `--rollback-on-failure` aimed at the app's own Service the replaced pod
  still answered, and 1 of 3 and 2 of 6 vulnerable upgrades passed. The
  chart README, values and NOTES now give the invocation measured correct
  with the Helm CLI: the gate as a dependency of the app's chart, aimed at a
  Service that selects only this release revision's pods (or the app on
  `strategy: Recreate`), with `helm upgrade --install
  --rollback-on-failure`, which also rolls a failed release back (without
  it the vulnerable version stayed serving). The e2e's `helm` scenario runs
  that invocation, with Helm's defaults as its control. The revision label
  does not carry over to Argo CD (see the next entry).
- **The Argo CD docs sent `PostSync` users to a recipe that does nothing under
  Argo CD.** `values.yaml` (`hook.argocd`), the main README and the chart
  README pointed Argo CD users at the Service on a `.Release.Revision` label,
  and this changelog said the Argo CD docs gave "the invocation measured
  correct"; it had been measured with the Helm CLI only. Argo CD renders
  charts with `helm template`, where the revision is always `1`, so the old
  and the new pods carry the same label and the Service lists both. Measured
  through Argo CD by the e2e's `argocd` scenario, which now syncs a
  `RollingUpdate` app from fixed to vulnerable: with the revision label both
  pods were labelled `"1"` and the gate's Service still listed the replaced
  pod after the sync in 5 of 5 runs; the replaced pod answered 13 of 25 gate
  requests, and the gate passed the vulnerable version in 2 of 5. The docs now
  say the revision label is for the Helm CLI, and give Argo CD a label hashed
  from the rendered pod template (measured in 5 runs: the Service listed only
  the new pod in each, the replaced pod answered none of the 20 gate requests
  counted in 4 of them, and the gate failed in the 4 whose exit code was read;
  in the fifth the gate had not finished when it was read; in 5 more runs with
  the Job named per sync, 0 of 25 and 5 of 5), `strategy: Recreate` (the gate
  exited 1, 10 of 10), and an Argo Rollouts canary as the only way to keep a
  failing version from taking traffic.
- **Argo CD reported syncs from the previous sync's gate Job.** In `hook.mode:
  argocd` the Job had one fixed name, re-created each sync under
  `BeforeHookCreation`, and Argo CD v3.5.3 reported some syncs from the
  previous sync's Job. Measured on kind with the chart as an Application's
  only source, alternating a vulnerable and a fixed target: 5 of 24 syncs
  whose gate passed were reported `Failed`; with a stand-in Job, 5 of 13 whose
  Job failed were reported `Succeeded`; and the e2e reported a vulnerable sync
  `Succeeded` with its gate at exit 1 in 4 of 5 runs of the `argocd` scenario.
  The Job now has `metadata.generateName`, and Argo CD names each sync's Job
  `<release>-veridor-gate-<revision>-postsync-<start>`: the same harness
  reported every sync from its own Job (36 of 36 with this chart), and in 5
  runs of the e2e's `argocd` scenario every sync's phase matched its own gate
  Job's exit, 35 of 35. The e2e reads each sync's Job by the name its
  `syncResult` records, created after the sync started, instead of one name
  fixed in advance, and records the sync's phase against it again.
  `BeforeHookCreation` no longer deletes anything in this mode (one Job per
  sync until `job.ttlSecondsAfterFinished`), so it is no longer required, and
  a `null` TTL is refused unless `HookSucceeded` and `HookFailed` both delete
  every Job. The Kustomize overlay could not follow (above).
- **`helm install` of the chart in `hook.mode: argocd` is refused.** The
  unnamed Job failed a server-side install, but with `--server-side=false`,
  the way Helm 3 applies, `helm install` exited `0` with the release
  `deployed` and a Job the API server named, which nothing waited for
  (measured with Helm 4.2.2). The render now refuses argocd mode when it
  reaches a cluster, which Argo CD's `helm template` never does: client-side,
  server-side and `--dry-run=server` installs are refused with no Job and no
  release, and the e2e has the row.
- **The Kubernetes e2e is split to fit its CI job (not yet timed).** The last complete run of
  `scripts/e2e_kubernetes.sh` took about 31 minutes against the CI job's 30.
  In the next, the `helm` scenario alone took 21, 20 of them in a settle loop
  that waited for one pod labelled `app.kubernetes.io/instance=shop`: the
  gate's finished pod carries that label too, so the loop never saw one pod
  and waited out its timeout after each of the four upgrades (measured: their
  gates ran 304 to 318 s apart). It now selects the app's pods only (not
  re-timed: the cluster's Docker stopped on a full disk during that run). The
  CI job runs the scenarios in two groups on two kind clusters, `helm` alone
  and the rest together (`argocd` and `kustomize` took 6.5 to 7.7 minutes
  together in 5 runs), and a test holds every scenario to exactly one group.
- **A configuration whose `version` is an object or a list exits `2`.** It
  raised `TypeError` inside the loader, which the command reports as exit `70`,
  a bug in Veridor, for what is a malformed input. `"version": true` is refused
  too; it compared equal to `1` and loaded as version 1.
- **`run` and `verify` stay under the base URL's path.** They contained
  requests to the base URL's origin only, while `map` refused a path outside
  its base path. Reproduced with `verify <capsule> --base-url
  http://127.0.0.1:PORT/service-a/` and a check path of `/../service-b/admin`:
  the banner named service-a, and the verifier's tokens went to
  `/service-b/admin`, with a `DELETE` capsule as a `DELETE`; `veridor run` with
  that base URL did the same. A request path with a `.` or `..` segment,
  percent-encoded or not, is now refused with exit `2` when it is loaded, in
  checks, marker probes, session logins and sequence steps, and `map` refuses
  a percent-encoded one as well. Every request is also checked, just before it
  is sent, against the base URL's path when it has one. A base URL with no
  path still contains requests to its origin only.
- **`veridor capsule --output` could replace the configuration.** It was the
  one output with no destination check: `--output veridor.json` over the
  `--config` file, its upper-case spelling on a case-insensitive volume, and
  `./sub/../veridor.json` each replaced the configuration with the capsule and
  exited `0`, and `--from-run run.json --output run.json` replaced the run.
  Both are now refused with exit `2` before anything is read or written.
- **A run could replace its own baseline, and a re-run then passed.** The
  output-path checks compared every explicit output with the inputs, but not
  the file the command itself rewrites under `--output-dir`. Reproduced with
  the demo target and a new, unconfirmed cross-tenant read:
  `run --baseline .veridor/latest.json` exited `1`, and the identical re-run
  exited `0` ("0 new, 0 resolved, 1 unchanged") with the finding still live,
  under the default `--fail-on new+confirmed` and under `new`.
  `--config out/latest.json --output-dir out` replaced the configuration with
  a run document, and `verify out/latest.json --output-dir out` the capsule.
  An input that is `latest.json` under `--output-dir` (for `run` and
  `verify`) or the `mutation/` report (for `mutate`) is now refused with exit
  `2` before anything is sent, in any spelling that names the same file. A
  run under `runs/` is still accepted as a baseline, because nothing rewrites
  it.
- **Scrubbing no longer breaks the drift gate.** A matrix is written with
  every expanded `${NAME}` value put back as its reference, keys included, and
  `map --baseline` compared that file with this run's matrix straight from
  memory, where the value was still in it. A specimen label, an identity name
  or a base URL containing such a value no longer matched itself: reproduced
  with a specimen labelled `invoice inv-000123456` whose id came from
  `${VERIDOR_INV}`, 16 cells "existed in only one run" and
  `--fail-on-drift opened` and `any` exited `0` against a target serving the
  invoice to another tenant. Drift now scrubs both matrices before it joins
  them, so a baseline holding the raw value, written before the value moved
  into `${NAME}`, still lines up too.
- **The chart and `veridor capsule` read look-alike letters in names the
  same way.** Go and Python relate four characters to ASCII letters
  differently (measured over every code point): Python's `(?i)` reads `İ`
  and `ı` as `i` and Go's does not, and Python lower-cases `İ` to `i` plus
  a combining dot where Go makes `i`. The chart rendered `apİ_key`,
  `credentİals` and `?apİ_key=` holding a literal into its ConfigMap while
  the capsule refused them, and read `İd` under `password` as a descriptor.
  Both now read `İ`, `ı`, `ſ` and `K` (U+212A) as `i`, `i`, `s` and `k`
  wherever that makes the scan stricter (credential names, parameter
  names, the `headers` key, including percent-escapes) and never let them
  make a key a descriptor or a header a `Cookie`. The chart also reads an
  escaped multi-byte character as one character, not one per byte: with
  three, `contrase%E2%82%ACa=` rendered what the capsule refused.
- **The Kustomize README's overlay repoints every credential it moves.** Its
  patch moved `VERIDOR_OWNER_TOKEN` to `invoices-gate-credentials` and left
  `VERIDOR_OUTSIDER_TOKEN` and `VERIDOR_ADMIN_TOKEN` reading the base's
  `veridor-gate-credentials` (env entries merge by name), so with only the
  Secret the example names, Veridor exited `2` on an unset variable
  (measured). The example now lists all three, says that creating
  `veridor-gate-credentials` needs no patch, and a test builds it.
- **The Argo CD docs say how long the hook Job's log stays readable.** They
  said `BeforeHookCreation` keeps it "until the next sync". The chart and the
  Kustomize base also set `ttlSecondsAfterFinished` (3600), and the TTL
  controller deletes a finished Job carrying the hook annotations like any
  other (measured with 15 s). Each sync's Job now has a name of its own, so
  the next sync deletes nothing: the docs say the Job and its log stay for
  the TTL (measured with 30 s: 10 syncs, no Job or pod left 50 s after the
  last).
- **The chart's NOTES in `hook.mode: argocd` no longer promise a failed
  sync to the Helm CLI.** They said "When the Job fails, the sync operation
  fails", but NOTES are printed only by `helm install` / `helm upgrade`,
  which do not read Argo CD annotations. Measured on kind: in argocd mode
  against a vulnerable target, `helm install` exited `0` at once with the
  release `deployed`, and the Job failed a moment later with the release
  still `deployed`. That install is now refused (above); NOTES, printed by a
  dry run only, say what Argo CD does with the Job and how to find each
  sync's Job.
- **The chart no longer says a Complete Job means every expectation held.**
  Its README and NOTES said a Complete Job meant "the target matched the
  declared expectations for the requests sent", and NOTES listed exit `1`
  among the Job's failures whatever `gate.failOn` was. Exit `0` means
  nothing the selected gate selects was present: under `gate.failOn: none` a
  vulnerable target completes the Job (measured), and a finding the policy
  does not select, or an unanswered probe with `gate.requireComplete: false`,
  leaves it Complete too. Both now say that, and NOTES name the policy and
  drop exit `1` when it is `none`.
- **The chart's quick start and the Argo CD example failed a fixed target.**
  Both declared `other_tenant` with a denial and no `marker_probe`. The demo
  API answers an unknown token with the same `404`, so the denial was
  unproven, and with the chart's default `gate.requireComplete: true` the gate
  exited `3` (`liveness_unproven`) against a fixed target: measured with the
  chart's own arguments, and on kind as a failed `helm install`. The e2e
  substituted its own configuration, so the documented one never ran. Both
  now give `other_tenant` a `marker` and a `marker_probe` (fixed exit `0`,
  vulnerable exit `1`), the chart README's "Exit 3" names
  `liveness_unproven` and its remedy, and the e2e's `argocd` scenario runs
  the example's own gate values.
- **The Helm chart rendered a literal password in JSON text next to some
  numbers beyond float64.** Its second parse, for text Go's parser refuses
  and Python's (the capsule's) reads, rewrote only exponents of three or more
  digits and runs of 300 digits ending at a word boundary, so `1` with 250
  zeros and `e60`, or 301 digits glued to `e9`, still failed, the text was
  skipped, and the literal went into the ConfigMap while `veridor capsule`
  refused it (measured with `helm template`). The second parse now reads
  `NaN`, `Infinity` and every number outside a string as `0`, keeping string
  literals as written, so keys cannot merge and `"${A-1}"` does not become a
  reference.
- **An output path that differed from an input only in letter case replaced
  it** on a case-insensitive filesystem (the macOS default, NTFS). The checks
  compared resolved path strings, which keep the case they were given.
  Reproduced on macOS: `run --json VERIDOR.DEMO.JSON` replaced the
  configuration `veridor.demo.json`, `--baseline b.json --json B.JSON` the
  baseline being compared against, `report --output RUN.JSON` its own input
  and `init --force --output OPENAPI.DEMO.JSON` the specification; two outputs
  differing only in case were both accepted, one replacing the other. Paths
  are now compared as files: the same device and inode when both exist,
  otherwise the same directory and names equal under that directory's own
  case rule. The case-sensitive branch was exercised by simulation, not on a
  case-sensitive volume.
- **The GitLab component's `base_url` example could not work.** It suggested
  `$CI_ENVIRONMENT_URL`, which GitLab sets only in a job that declares an
  environment; the gate job declares none, so following the example stopped
  every pipeline with exit `2`. The example is now a variable the deploy job
  writes to a dotenv report (`$REVIEW_APP_URL`), and the refusal says what an
  empty input means: the configuration's own `target.base_url` is probed.
- The GitLab component and `ci/README.md` said a job on a checkout its user
  cannot write would find out only after probing the target. Veridor refuses
  such an `--output-dir` before it sends anything (measured: exit `2`, 0
  requests), and both now say so.
- **Scripts still put `src/` on the path under
  `VERIDOR_TEST_AGAINST=installed`.** `scripts/e2e_validation.py` and
  `scripts/blind_config_study.py`, which tests import or run, inserted `src/`, so a targeted run of `tests.test_e2e`
  tested the checkout instead of the installed package. They now go through
  `tests/source_path.py`, and the guard now parses every test module and
  every script a test imports or runs, and knows 19 ways of putting `src/` on
  the path instead of one exact string.
- Test gaps that let a fail-open edit pass: the workflow checks skipped
  `.yaml` files; the Jenkins, Azure and CodeBuild shells were run with gating
  defaults the test supplied instead of the ones the files ship; the
  AnalysisTemplate's default `fail-on` was only parsed, so `none` passed; the
  scan for a `kubectl` or `helm` call without `--context` missed 19 of 26
  command forms. In `scripts/e2e_gitlab_job.sh`, an unreadable request count
  read as `0`, a refusal row could not see a request that fell through to the
  target, and seven inputs never ran off their defaults (it now runs 105
  checks). Each now fails on the edit it missed.
- **The release's version check passed a tag the tree did not match.** The
  step piped `release_check.py versions` into `tee` and set no shell, so GitHub
  ran it as `bash -e`, where a pipeline has `tee`'s exit status. Run that way,
  tag `v0.2.0` on the 0.1.0 tree exited `0` with empty version outputs. The
  workflows now set `defaults.run.shell: bash`, so every run step runs with
  `-eo pipefail`. `scorecard.yml` is the exception: the Scorecard API rejects
  a workflow that sets defaults, and it has no run step. A test holds every
  run step to this and runs the check step with a mismatched tag.
- **The fast-tier guard blocks what it claims.** It patched three calls, and
  27 of 30 probed routes to a socket or a process escaped it (`connect_ex`,
  UDP `sendto`, name resolution, `os.system`, `posix_spawn`, `fork`, `exec`,
  multiprocessing and more). It now replaces all of them and adds an audit
  hook.
- **The installed-package CI job tested the checkout.** Every test module put
  `src/` first on `sys.path`, so "install the wheel, then run the suite"
  imported the source tree.
- **A 4xx whose body stalled** ended the run with exit `2` and no run
  document. It is now an unmeasured probe, like any other body timeout.
- **LICENSE held only the copyright notice**, not the Apache-2.0 text that
  section 4(a) requires recipients to get. It is now the licence text, and the
  notice is in NOTICE.
- **The README's GitHub Action outputs example was invalid YAML**: a plain
  scalar containing `: `. A test now parses every YAML example in that
  section.
- **SECURITY.md said `veridor serve --host` had no gate.** A host other than
  loopback is refused with exit `2` unless
  `--i-understand-this-is-unauthenticated` is typed; the policy now says so.
- **`plan_matrix` no longer writes to stdout.** It is the socket-free planning
  layer — "a complete, socket-free description of what a run would do" — and had
  no `print()` at all before the `--include` warnings were added to it. Printing
  from there put ~600 bytes on the stdout of any programmatic caller and left
  the warning invisible in the object that caller was handed. The two partial
  cases now ride on `MatrixPlan` as `unmatched_include` and
  `ignored_only_include`, rendered by `banner()` with the rest of the plan; the
  two total-miss cases stay refusals, which is correct where they are. A test
  asserts the module contains no `print` call at all.

- **`--include` no longer disables the mutating-verb and no-specimen gates.** A
  regression introduced by the `--include` refusal itself: the new clause was
  written `elif include:`, which is true whenever the flag is set, so the two
  clauses below it never ran for anything a pattern selected. A templated route
  with no specimen was then probed with the literal `{id}` in its path — the
  target 404s, a 404 is recorded `refused`, and a grid of refusals is
  indistinguishable from a boundary that holds. Exit 0, no warning. An
  `--include` prefix that also covered a `DELETE` was refused outright instead
  of recording it `skipped_mutating`.
- **A drift comparison where the cells do not line up is no longer reported as
  "Nothing moved".** Cells are keyed by specimen, and only whole operations and
  whole identities were diffed for add/remove — so re-seeding a fixture made
  every affected cell vanish from the comparison. A baseline refusal at `403`
  and a current `200` carrying the victim's marker produced zero changes, zero
  census, and the reassuring sentence. Those cells are now counted and named,
  the report refuses to say "Nothing moved" when nothing was comparable, and
  under `--fail-on-drift` a void comparison exits `3` rather than passing.
- **An anonymous identity that sends `Accept` is no longer treated as
  credential-bearing.** The previous fix counted *any* header as a credential,
  so the regression it was written to close stayed open for every anonymous
  identity that has to send one — which is most of them. Only credential-shaped
  headers count now, and the identity named by `matrix.unauthenticated` is
  never classified as credential-bearing whatever it sends.
- **One member's failed probe no longer deletes a `peer_divergence` row.** The
  rule vetoed the whole row if any active member's cell was unmeasured;
  un-suppressing the no-credential identity moved it into that set, so a single
  missed request erased a cross-tenant read the other members measured
  perfectly well — silently. Unmeasured members are dropped and counted.
- **The vacuous-run sentence no longer prints over a real finding.** It was
  gated on half the predicate the exit code uses, so a run whose checks all
  timed out while a sequence step served another tenant's order printed "every
  entry above is a probe that did not run, not a finding about your target" two
  lines above a confirmed cross-tenant read.
- **The README's outputs recipe no longer turns the gate off.** It set
  `continue-on-error: true` with nothing to re-fail on, so a run that found a
  live leak left the build green. The recipe now re-fails on `exit-code`, and
  both the README and the `exit-code` output description say plainly that
  `continue-on-error` makes the Action advisory.
- Smaller: the grid-share line no longer rounds up to "100% of the grid" while
  reporting unmeasured cells; a malformed baseline is an input error rather than
  an `AttributeError` traceback on the gate path; the SARIF staleness guard
  compares ids and not just list lengths, and the anchor can no longer cost a
  finished run; the dead-specimen warning is keyed by path template so a
  scaffold's colliding `"specimen"` labels stop masking each other; an
  `--include` matched only by `ignore` is told so; the "CANNOT FINISH" advice
  no longer contradicts its own arithmetic at the ceiling; and `matrix.py`'s
  module docstring no longer documents the removed Retry-After behaviour.

- **The README's session example is a configuration Veridor refused to load.**
  It declared `capture.csrf` on a login step *and* on the session, which is a
  load error by design — capture names are one flat namespace per identity, and
  single-assignment — so anyone who copied the document's flagship session
  example was stopped at exit `2` before a single request. The example now uses
  two names, because they are two different values with two different
  lifetimes, and the document states the rule and the two capture kinds. A test
  extracts the example from the README and loads it.
- **The three safety numbers are written down, and the tool catches the trap
  they set.** The rate ceiling (10 req/s), the absolute request maximum
  (20,000) and the wall clock (1,800s, capped at 7,200s) appeared in no
  document. They also interact, and the wall clock usually binds first: at the
  default 2 req/s it caps a run at 3,600 requests, so an ordinary
  1,000-operation spec across five identities cannot finish. The banner printed
  the estimate and the stop side by side and never compared them; the cells the
  clock cuts off read `unknown`, which drift can never later report as more
  access. `--dry-run` now says so before the run starts, and the remedy it
  offers is one that works — at 2 req/s it does not send you to a
  `--max-run-seconds` value that cannot exist.
- **The measured detection rate was wrong.** The drift noise-floor table
  said `88%`, which does not reproduce at any seed. The current measured
  rate is 97% (87 of 90 runs, seeds 1–9), the README gives the command, and the
  false-alarm rates remain 0% on every seed. Checking the number also caught
  the defect that made detection genuinely worse: the noisy server
  sends `Retry-After`, which used to abandon the matrix on the first `429`.
- **`--read-only` names every mutating declaration in one pass.** It raised on
  the first, so a config with three mutating checks took three runs to
  enumerate — one edit and one full re-read per offender.
- **`mutate` explains its `skipped` count.** The number was published with its
  reasons only in the JSON, so a reader could not tell "the budget ran out"
  from "there was nothing here to strip". Six closed reasons, printed with
  their counts, and a test asserts they partition the count so an untagged
  future skip site cannot reintroduce the silence.
- **The README no longer implies `map` never sends a write.** It can, behind two
  independent opt-ins; what it does not send is recorded `unknown /
  skipped_mutating`, never `refused`. Drift's blindness to that half of a CRUD
  grid is now stated where drift's other limits are.

- **SARIF results and GitHub annotations point at the declaration they graded.**
  Every result anchored to `veridor.json:1` — eight findings on the config's
  opening brace. The fingerprints were distinct, so deduplication worked and
  triage-by-location did not: code scanning had nothing to sort or group by.
  Each finding now carries the line of the `expect` entry (or sequence step)
  it graded, computed at run time and read by both emitters. A run document
  written before this still converts, falling back to line 1. The anchor is
  positional, and it is dropped entirely if the config on disk changed under
  the run — being confidently wrong about which line a finding is about is
  worse than pointing at line 1.
- **`map` says when a specimen was served to nobody.** A well-formed but wrong
  id — `inv-42` where the real invoice is `inv-100`, not the literal
  placeholder `map` already refuses — 404s, and a 404 is recorded as `refused`.
  A grid of refusals is indistinguishable from a boundary that holds: the run
  exits 0, reports the same candidate count, and differs from a correct run
  only in reach counts nobody draws a conclusion from. The marker owner had
  been refused its own data with nothing saying so. The test is decisive rather
  than statistical — a specimen no identity reached on any of its rows — so an
  admin-only object, or a `DELETE` that 405s on an id the `GET` serves, stays
  quiet. It warns, gates nothing, and never becomes a finding.

- **A `429` carrying `Retry-After` no longer costs a target 3.5x its grid
  coverage.** The header short-circuited the abort rules, so a target that
  followed the spec got a tolerance of exactly one rate-limit response while a
  target that sent nothing got three consecutive or five cumulative. Measured
  on one throttling target, 15 runs per arm with identical seeded `429`
  positions: with the header, 15/15 runs aborted and median grid coverage was
  22%; with the same `429`s and the header stripped, 2/15 aborted and coverage
  was 78%. A `Retry-After` `429` now counts toward the same budget, so a polite
  target receives exactly what a rude one receives and never more — measured at
  parity, 132 requests either way, up from 54. The abort reason stays
  `retry_after_requested`. `--on-retry-after stop` restores the old behaviour,
  and the matrix records which policy ran.
- **`--include` says what it matches.** It matches by path *prefix*, which was
  written down nowhere: `--include 'GET /api/v1/invoices/{id}'` silently
  selected five operations when the operator asked for one, and
  `--include '.../*'` silently selected none, because `*` is an ordinary
  character. An include list where every pattern misses is now refused before a
  socket opens, with the rules and the specification's actual operations in the
  message; a partial miss warns and continues, so one include list can still be
  passed across several specifications.

- **A drift gate no longer goes green on a re-run with the regression still
  live.** `--baseline` accepts a directory, which resolves to the newest matrix
  in it — and `map` writes one more into that same directory on every run.
  Under `--fail-on-drift` that ratchets: measured against a live cross-tenant
  read, run 1 exits `1` on `reach_opened` and `marker_appeared`, and the
  identical command re-run — the first thing anybody does with a red build —
  compares the regression against itself, prints "Nothing moved" and exits `0`.
  A directory baseline is now refused under a gate, in the CLI and in the
  Action, with the recorded-and-committed form spelled out in the message. The
  directory form is untouched for discovery (`--fail-on-drift none`, the CLI
  default), which is its honest use. `init --for drift` now scaffolds five
  steps: record to `veridor/baseline-matrix.json`, commit it, then gate against
  that file.
- **`map` no longer blames the drift policy for a measurement failure.** A run
  with no `--baseline` at all — step 3 of the drift on-ramp, "records the
  baseline, finds nothing, and says so" — against an unreachable target exits
  `3` correctly, and then explained it as "you passed `--fail-on-drift 'none'`
  and the matrix moved": a comparison that never ran, under a policy that
  cannot gate. The two exit codes are now attributed separately.

- **An identity that presents no credential is no longer punished for being
  correctly refused.** A row of 401s has two opposite meanings — a token the
  target rejected, and no token at all being turned away — and the matrix
  cannot tell them apart, because it records identity names and not what they
  sent. Every 401-everywhere identity was read as the first, so declaring an
  anonymous identity the way the README asks (`"headers": {}`, plus
  `matrix.unauthenticated`) printed "the target never accepted this credential"
  about a working boundary, and suppressed that identity from every rule. The
  cost was concrete: on an operation two tenants both reached, the anonymous
  401 is the refusal that makes `peer_divergence` a candidate at all, so
  declaring the identity deleted the finding. `map` now reads the config for
  the one fact the matrix cannot hold. A genuinely stale credential is still
  suppressed. If you declare an anonymous identity as a peer-group member you
  may see many more candidates than before — that volume comes from the
  declaration, not from this fix: the same fixture with an anonymous identity
  that reaches one public route already produced 76 candidates.
- **Drift no longer reports a rate limit that never happened.** Cells the plan
  deliberately never sent — a mutating method, a missing specimen, an
  `matrix.ignore` entry — are `unknown` just like a timeout is, and drift read
  only the reach. Every CRUD-shaped spec therefore printed two alarming
  warnings above `0 change(s)`, on a perfectly quiet target, forever: "a rate
  limit, a server error or a timeout", and the advice to re-record the baseline
  against a quiet target, which produces byte-identical output every time it is
  followed. The two causes are now separated, each gets the advice that can
  actually work, and each warning names only the reasons for the cells it
  counts.
- **The remediation is printed on the console.** Findings have carried a
  remediation sentence into SARIF and the viewer for some time; the terminal
  showed only the message. A run against a slow target printed "Request failed:
  timed out" and nothing about `target.timeout_seconds` or its configured
  value.
- **A vacuous run says so above its own diff.** With the target down, `run`
  correctly exits `3` and explains itself on stderr — then printed "Regression
  diff: 7 new" on stdout, which is the line that catches the eye in a scrolled
  CI log. Seven probes that were never answered are not seven new problems, and
  the console and the exit code now share one definition of an answered probe.

- **A mistyped password produced a fully green build.** The identity's session
  never established, every probe as that identity reported inconclusive, and
  the run exited 0 — with the attacker's boundary untested. The vacuous guard
  could not catch it, because the *other* identity answered fine. A login the
  target answered and refused is now exit 3, no flag: it is deterministic and
  will refuse identically on the next run. A `408`, `429` or `5xx` on login
  stays transient and never gates, so the measured noise floor is unchanged.
- **`run` sent `{id}` literally and reported the 404 as a finding.** A
  docs-only trial (an automated run given only the wheel and the docs, not a person)
  that had just scaffolded a 250-route config got 100 ×
  `[unexpected_denial] … received HTTP 404 … The target refused this request`,
  with nothing saying the cause was its own placeholder — while `map` refuses to
  send `REPLACE-WITH-A-REAL-ID` before opening a socket. `run` and `mutate` now
  refuse, naming every offender at once. `coverage` and `init` are unaffected:
  the scaffold is *meant* to carry placeholders, and coverage already reports
  them as `templated_check_path` with zero credit. Percent-encode braces
  (`%7B`/`%7D`) for a path that genuinely contains them.
- **A cached response licensed a pass, contradicting the README in writing.**
  The documented rule — a cached body "cannot license a pass and it cannot
  refute a write, so the step reports `VERIDOR-CACHE-001` / inconclusive" — was
  implemented for sequences only. `core._grade_check`, the grader for every
  single-request check, never read `from_cache`, while the rule's SARIF entry
  and remediation text sat in `core.py` unreachable. A target answering the
  attacker's probe with `Age: 600` produced `2/2 probes matched`, exit 0. All
  three sites are closed: the check grader, the identity `marker_probe`
  control, and the same-check control. An observed marker still outranks the
  cache — a cache cannot make bytes that were on the wire not have been there.
- The over-budget refusal's arithmetic was wrong by a factor of two: it printed
  the specification's row count where the planned row count belonged, so "620
  requests (246 rows x 5 identities)" did not multiply. A reader sizing a run on
  a calculator was misled.
- A diagnostic code ran into its own message — `templated_check_pathcheck
  'get-org' …` — because `templated_check_path` is exactly the hard-coded field
  width. The width now comes from the data.
- The "checks matched no operation" warning blamed "the base path or the spec",
  and in the docs-only trial that hit it 102 times both were correct; the real
  cause was unsubstituted path placeholders, which the lines directly above
  already named. It now names the cause it can see, and never rules out the base
  path unless that base path resolved every check.
- `map` on the zero-declaration path no longer opens with `veridor: boundary
  coverage was not measured`. Declaring no checks is what `--for drift` *is*;
  printing it on stderr with the prefix that means "this command refused", above
  the plan banner, made three separate docs-only trial runs report it as a possible
  failure of the run.
- The "unproven oracle" notice claimed an absence was licensed on findings where
  the marker was **present**. It was appended before the probe was graded at
  all, so it described the declaration and called it an observation.
- **The quickstart could not run from a `pip install`.** Its first command is
  `--config fixtures/veridor.demo.json`, and a wheel ships neither `scripts/`
  nor `fixtures/` — so minute zero was `configuration not found`, which reads as
  a broken install. Two of the eight docs-only trials — automated runs, each given only
  the wheel and the docs — reported it as the worst point of the run. The
  section now says so and points wheel users straight at their own API.
- **The front door turned away teams with no OpenAPI spec.** It said "start from
  a specification. There are two on-ramps" and both were `--openapi` — while
  `run`, `mutate`, `capsule` and `verify` need none. It now says which verbs
  require a spec, and shows the four-line route stub that unlocks the rest.
- The README described a config the loader refuses: "you do not have to declare
  [the same-check control] for it to bind". You do, and the refusal is at load
  time.
- The CI example passed `baseline: baseline.json` on a first run, which nothing
  produces and which is a hard exit 2. It is commented out with the reason.
- The recommended committed baseline moved out of `.veridor/` — a must-commit
  file inside the directory every team gitignores.
- "An input belonging to the other mode is refused, never ignored" was false
  three ways: the check compares each input to its *default*, so a default value
  on the wrong step is indistinguishable from an absent one. The README now
  admits what the guard cannot catch.
- **`coverage` demanded live credentials while documenting itself as offline.**
  Its help says "Issues no request" and groups its flags under "(offline,
  static)", then exited 2 on an unset token — blocking a coverage badge in CI
  for a command that sends nothing. It now reads the declaration without them;
  `run` and `map` still refuse, because they are about to authenticate.
- The version error named one supported version while accepting two, so
  `version: 3` was told to use 1 and never learned that 2 exists — the version
  `run --help` refers to and the one `sequences` requires.
- The YAML remediation ended `Then: veridor coverage --config …` regardless of
  which verb produced it, so a user who ran `init` was sent to a different
  command with a flag `init` rejects. It now says to re-run the same command,
  and notes that the Python conversion one-liner needs PyYAML, which Veridor's
  own dependency-free virtualenv does not have.
- **Two identities sending the same credential are refused at load time.** A
  copy-pasted identity block with the name changed and not the token produced
  `2/2 probes matched their declaration`, exit 0, status `passed` — every probe
  was the owner talking to itself. The comparison happens after `${VAR}`
  expansion, because two different variables holding one token are still one
  caller. Deliberate anonymity and shared non-credential headers are unaffected.
- **"Not one probe was answered" fired on a run where both were answered.** The
  guard tested probes that *matched* rather than probes that got a *response*,
  so a pair of `HEAD` requests — 200 on the wire, inconclusive because there is
  no body for the marker oracle — told the operator their target was down.
- **A redirect to a login page was reported as an authorization breach.** The
  `vulnerable` / `unexpected_denial` split was decided by an allow-list of four
  denial statuses, so every other non-success code defaulted to `vulnerable` at
  SARIF `error`. A sweep of status codes found nine: 204, 301, 302, 400, 405, 409, 418,
  422, 451. A 302 is the standard denial in session-based apps and Veridor never
  follows redirects, so nothing was served. `vulnerable` now requires a 2xx —
  the target actually handed something over. 204 stays on the `vulnerable` side:
  a 204 to an attacker's DELETE is the write succeeding.
- **`map --fail-on-drift` exited 0 with the target switched off.** Every cell
  `measurement_lost`, "Drift saw 0% of the grid" printed in full, green build.
  A grid where nothing was measured now exits 3 with no flag required, and
  `map --require-complete` extends that to any partial loss. `run` grew this
  guard earlier and it was never carried across.
- **Four inputs crashed with a traceback and exit 1** — which this project's own
  table reads as "the gate failed". `timeout_seconds: 1e30` (the ceiling
  validation existed in `matrix`; `run` never called it), a `NaN` timeout,
  deeply nested JSON, and a binary file handed to `verify`. All four are exit 2
  refusals now.
- **Sequences graded a `429` as `vulnerable` too.** They grade on their own
  path and inherited none of the transient fix — the two share a message string
  and not the logic behind it — so a rate limit on an assert step asserted a
  boundary failure, on the surface that also writes to the target. A marker
  actually observed in the body still wins: a leak inside a 500 is still a leak.
- The over-budget refusal told you to raise the ceiling "with
  `max_requests=800`" — the keyword this module takes, not the flag you are
  holding a command line for. It now says `--max-requests 800`. A test scans
  every runtime message for `--flags` the CLI does not accept, with the two
  deliberate foreigners enumerated rather than pattern-matched away.
- **`--dry-run` did not mention the operations it was about to skip.** On a
  120-path specification it reported "operations: 60 (of 120 in the spec; 0
  skipped as non-read-only)" and the other 60 vanished between two numbers.
  They were the templated routes — the shape this tool exists to measure —
  dropped for want of a specimen. The plan banner now counts them, and
  `--dry-run` prints the pasteable fix it already prints after a run, capped
  with an explicit count of what was not shown.
- A transport failure now names its likely cause. "Confirm the target is
  reachable from the runner" fits a refused connection and misleads on a
  timeout: a healthy target answering in 2.5s with `timeout_seconds: 1` sent
  operators to their firewall rules when the fix was one number in their own
  configuration. Timeouts, refusals, DNS and TLS each get their own answer, and
  an unrecognised error keeps the honest general one.
- **A mutation score silently narrowed under load.** When a baseline probe went
  unanswered, `mutate` recorded that mutant `not_applicable` and dropped it from
  the denominator — the same bucket as "this operator does not apply here",
  which is structural and recurs every run. Against a noisy target that took a
  run from 15 generated mutants to 11 and still reported 1.00 and exit 0. An
  unanswered baseline is now `errored`, so the run exits 2 and says it does not
  know. A healthy target is unaffected.
- **`run` graded a `429` as `vulnerable`.** The verb that emits findings and
  SARIF asserted an authorization failure that did not happen — once reporting
  that `anonymous` received 429 where 401 was declared, which is anonymous being
  denied *harder*. It failed the build on 70% of runs against a target whose
  boundary never moved. A 429 or a 5xx is not an answer from the authorization
  layer, so it is now `inconclusive`, like the timeout it resembles.
- **Drift's false-alarm rate, measured and then removed.** Against a target
  whose authorization boundary never changes and whose everything-else moves
  like a real API, drift fired `--fail-on-drift any` on 100% of runs and
  `opened` on 20% (up to 75% on a quiet target). All three causes were category
  errors: a rate limit reported as `reach_closed`; a timeout in one run versus a
  `429` in the other reported as `status_changed`; and a marker appearing in its
  OWN owner's response counted as a boundary crossing, which is the owner
  reading their own data. Both rates are now 0% over five seeds, while a real
  boundary opening is still caught on most runs; the README gives the current
  measured rate, the seeds, and the command that reproduces it. (The `88%`
  originally published here was not reproducible at any seed.)
  `scripts/noise_floor_study.py` measures both halves.
- Under-detection is now impossible to miss. A baseline recorded through a bad
  minute is blind on those cells forever — every later comparison there is
  `unknown -> something`, never "more access" — so `map` warns when the matrix
  it wrote would make a poor baseline, and a drift report against a blind
  baseline says so above its own counts.
- **`requires-python = ">=3.11"` was never run.** CI tested 3.12 only and the
  classifiers claimed 3.11 alone, so the floor pip enforces was a guess and the
  version actually developed on was undeclared. The fast tier and a wheel
  build-and-install now run on 3.11, 3.12 and 3.13; the classifiers list all
  three; and a test refuses to let `requires-python`, the classifiers and the CI
  matrix disagree again.
- The matrix refuses to send `REPLACE-WITH-A-REAL-ID`, the value the drift
  scaffold writes. An unedited placeholder 404s, a 404 is recorded as
  `refused`, and a grid of refusals reads exactly like a boundary that holds —
  and as a drift baseline it is worse, because the first run with a real id
  then reads as reach that opened.
- **Three configuration mistakes that used to be accepted silently**, each
  found by `scripts/blind_config_study.py`. Credentials written one level above
  `headers` meant the identity authenticated with nothing and was probed
  anonymously under its own name; a lower-case `method` meant the safety gates
  matched on `GET` while the request went out as `get`; and an identity named in
  `matrix.peer_groups`, `privilege_order`, `unauthenticated` or `marker_owner`
  that did not exist was only caught after the matrix had already been probed.
  All three are now refusals, the last one at plan time, before any request.
- `--drift` joined the output-path guard and `--baseline` the protected inputs:
  `--baseline b.json --drift b.json` used to overwrite the matrix you compare
  against with a drift report, surfacing a week later as an unreadable baseline.
- The drift baseline is resolved before the run probes or writes. Resolving it
  afterwards made a run its own baseline — no drift, exit `0`, indefinitely.
- Drift report notes are wrapped, and the specimen is printed: drift on one
  object is not the same claim as drift on the whole operation.
- The packaged wheel now ships `web/*.svg`, so the viewer no longer 404s its own
  icon when installed from a wheel rather than run from the repository.
- **The GitLab component's `fail_on` description said the default "cannot be
  defeated by editing the baseline".** That holds only for a confirmed
  finding. A suspected one (a 200 where 403 was declared, no marker in the
  response) or an ungraded one stops gating once its id is in the baseline,
  and the baseline file is part of the merge request's diff. Reproduced
  through the rendered job at the default policy: exit 1, then exit 0 with
  that run as the baseline. A confirmed finding still exits 1. The `fail_on`
  and `baseline` descriptions and the README's inputs table now say which
  findings a baseline can suppress, and recommend Code Owner approval for the
  file.
- **Every CI template's exit-0 line said "Every declared expectation held".**
  Exit `0` means only that nothing the `--fail-on` policy gates on was found.
  Measured: the GitLab job with a baseline holding a suspected finding, and
  the Azure and CodeBuild shells with the policy at `none`, exited `0` and
  printed that sentence under a run that recorded 1 vulnerable. The GitLab,
  Jenkins, Azure and CodeBuild lines, and the Jenkinsfile's exit-code header,
  now name the policy and say that a finding it does not gate on also gives
  `0` (in GitLab, so does an unanswered probe when `require_complete` is
  false).
- **The GitLab component's docs did not say to run the gate after the
  deploy.** It probes whatever `base_url` serves when the job starts, its
  default stage is `test`, which GitLab runs before its default `deploy`
  stage, and the example aims it at staging. Followed as written in such a
  pipeline, it would measure the previous deployment (inferred from GitLab's
  stage order, not run on GitLab). The `stage` input, `ci/.gitlab-ci.yml` and
  the README now say to put it in a later stage, or in the deploy job's stage
  with `needs:` on it.
- **The GitHub Action could report an earlier step's document as its own.**
  It read a document back when its modification time was not older than the
  step's start. A stale `json:` file from an earlier step in the same second
  (on a filesystem with one-second times) or from a clock ahead passed, and a
  refused step then reported that file's run id and counts (reproduced with a
  stale file 30 s ahead: exit `2`, and the stale `run-id` in the outputs). The
  step now records which file sits at each document path before Veridor
  starts and reads a path only if a different file is there afterwards;
  Veridor writes every document by renaming a new file over the path.

## [0.1.0]

Not released. There is no `v0.1.0` tag, and no package, image or chart for
0.1.0. It is the version the source has carried from the start, and the feature
set the entries above are written against: `map`, `run` and `mutate`; the
marker oracle and evidence grades; boundary coverage; baselines and the
regression diff; sequences and session state; SARIF 2.1.0 and the GitHub
Action; the local viewer. If the first release is 0.1.0, fold [Unreleased] into
this section before tagging it (CONTRIBUTING.md, "Releasing").
