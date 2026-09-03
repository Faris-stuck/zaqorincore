# Round 17 — 1 finding

| Field            | Value                                                            |
|------------------|------------------------------------------------------------------|
| Round            | 17                                                               |
| Cycle            | 99                                                               |
| Phase            | 1 (SECURITY track, NARROW SCOPE)                                 |
| Date             | 2026-09-04                                                       |
| Commit under audit | `4b3c894` (v3.4.29)                                            |
| Scope            | `server/src/zaqorincore_server/api/v1/ingest_cloudflare.py` (post-CSP fixes; new endpoint for Cloudflare Logpush ingest, 578 LOC) |
| Question         | Does the Cloudflare Logpush HMAC-authenticated NDJSON ingest endpoint carry any HMAC timing oracle, body DoS, parser-bomb (nested JSON / string-repetition), length-unbounded field, auth escalation, error-disclosure, secret-logging, or SSRF vector? |
| Result           | **1 Low-severity finding (F-027)** — `json.loads` per-line has no nesting-depth cap; everything else CLEAN |

## Scope and method

Cycle 99 brief asked a narrow deep-audit of the new Cloudflare
Logpush ingest endpoint:
`server/src/zaqorincore_server/api/v1/ingest_cloudflare.py` (578 LOC)
at commit `4b3c894` (v3.4.29). The endpoint is the HMAC-authenticated
ingest surface for Cloudflare Logpush NDJSON pushes, added after the
CSP-fix cycle.

The audit re-traced the eight vectors from the brief:

1. **HMAC verification** — constant-time? secret storage? timing oracle?
2. **Body size cap** — DoS via huge payload? Content-Length pre-check,
   stream limit?
3. **JSON parsing** — DoS via deeply-nested JSON, string-repetition,
   yaml/json mix?
4. **Field validation** — user-controlled fields length-limited and
   type-checked?
5. **Auth** — API key check, role check, no escalation path.
6. **Error responses** — do they leak secret names, internal paths,
   stack traces?
7. **Logging** — any PII, secrets, or tokens logged?
8. **SSRF** — does the endpoint make any outbound requests based on
   user input?

## Findings

### 1. HMAC verification — CLEAN (constant-time, length-checked, secret in env)

`_verify_hmac` (lines 320–349) uses `hmac.compare_digest` (line 349)
to compare the presented hex signature against
`hmac.new(_HMAC_SECRET, body, hashlib.sha256).hexdigest()`. Defensive
ordering:

1. **Line 334** — empty signature → `False` early.
2. **Line 338** — wrong-length signature (`!= 64`) → `False` early,
   before computing HMAC. This avoids feeding attacker-controlled
   bytes into `compare_digest`.
3. **Line 345** — HMAC computed only after both empty-check and
   length-check pass.
4. **Line 349** — `hmac.compare_digest(expected, presented.lower())`
   runs in time independent of where the strings diverge.

Secret storage (lines 138–166): `_env_secret` is read from
`ZAQORIN_CLOUDFLARE_INGEST_SECRET` at module import, refused in
production if unset (line 154) or if set to the well-known dev
placeholder `_DEV_PLACEHOLDER` (line 159). The dev-placeholder check
mirrors the same pattern as `evidence.py` per the module docstring
point (7). After load, `_HMAC_SECRET = _env_secret.encode("utf-8")`
and `del _env_secret` (line 166) wipes the str from the module
namespace — only the bytes form remains.

There is one subtlety worth noting: `_HMAC_SECRET` is a module-level
constant. CPython interns the bytes object and `del _env_secret`
removes the str binding but the underlying bytes buffer is reference-
held by `_HMAC_SECRET`. That is the *correct* behaviour (the secret
needs to persist for the lifetime of the process to verify every
subsequent request); the `del` is hygiene for the str binding, not a
wipe of the secret value.

Timing oracle surface: `hmac.compare_digest` is the documented
constant-time primitive in CPython's stdlib (implemented in C,
`Modules/_operator.c`). It compares byte-strings with a
length-dependent fixed-time loop and XOR-accumulator that does not
short-circuit on first mismatch. ✓

**Result: HMAC verification is CLEAN.**

### 2. Body size cap — CLEAN (Content-Length pre-check + post-read cap)

Two-layer guard:

1. **Content-Length pre-check** (lines 378–388). Read header *before*
   reading body. If present and > `MAX_BODY_BYTES = 5 MiB` (line
   102), reject with 413 immediately. If non-integer, treated as
   oversized (`cl = -1` then check on line 384). If missing, fall
   through to the body-read guard.
2. **Post-read cap** (lines 396–401). After `await request.body()`,
   if `len(body) > MAX_BODY_BYTES`, reject with 413. This catches the
   chunked-transfer / lying-peer case where Content-Length is absent
   or wrong.

`MAX_BODY_BYTES = 5 * 1024 * 1024` (5 MiB) is documented as
headroom over typical 1–2 MiB Cloudflare Logpush batches (line 102
comment). The 413 detail message echoes `{cl}` or the constant, which
is operator-internal — the body is already rejected before any side
effect. ✓

Stream limit: `request.body()` in FastAPI/Starlette loads the full
body into memory, bounded by the post-read cap. There is no separate
stream-limit parameter because the body is read once, in full, and
rejected before the HMAC check (no DB / Redis / log writes on the
failure path). ✓

**Result: body cap is CLEAN.**

### 3. JSON parsing — **F-027 (Low)** on unbounded nesting depth

The per-line loop (lines 467–481) parses each NDJSON line with
`json.loads(line)` (line 478). Per-line **byte** size is capped at
`MAX_LINE_BYTES = 64 KiB` (line 106, enforced at line 474), but there
is **no cap on nesting depth**. A 64-KiB line can be a single dict
nested thousands of levels deep (each `{"a":` is only 5 bytes).

`json.loads` in CPython uses recursive descent; at ~1000 levels it
hits `sys.setrecursionlimit` and raises `RecursionError`. The
exception is caught by the broad `except Exception` at line 511, the
batch is rolled back, and the endpoint returns 500 with a noisy stack
trace in `log.exception`.

Impact is bounded because exploitation requires the HMAC secret
(Cloudflare Logpush is the realistic source, and Cloudflare records
are depth ≤ 2 in practice). The amplification factor is real
though: 5 MiB body cap × 64 KiB per line = ~80 lines × ms-scale
recursion cost = several seconds of CPU per request, all rolled
back. Authenticated DoS, not unauthenticated.

See **[F-027](F-027-cloudflare-json-depth-dos.md)** for full impact
analysis and the recommended fix (depth cap before or after
`json.loads`).

Other parser-bomb vectors checked and CLEAN:

- **String-repetition DoS** — Python's `json.loads` uses the C
  accelerator and does not backtrack on long strings. The per-line
  byte cap already bounds the worst case.
- **yaml/json mixing** — `yaml` is not imported in this file (verified
  by `grep -n yaml`). Only `json.loads`. CWE-502 (unsafe
  deserialization) does not apply. ✓
- **UnicodeDecodeError** — `json.loads(line)` is called on `bytes`
  (line 478). The C accelerator accepts bytes directly and decodes
  them with the strict codec; on malformed UTF-8 the call raises
  `UnicodeDecodeError`, which is *explicitly* caught at line 479 and
  counted as rejected. ✓

**Result: 1 Low-severity finding (F-027) on JSON nesting depth.**

### 4. Field validation — CLEAN (length-limited, type-coerced)

`_truncate` (lines 233–242) coerces every metadata value to `str` and
truncates to `MAX_METADATA_CHARS = 4096` (line 111). `_build_metadata`
(lines 245–259) iterates only over the **fixed allowlist**
`_CF_TO_METADATA` (line 215, 14 entries); unknown fields in the
record are dropped. The Cloudflare field types are coerced via
`str(value)` — a numeric `BotScore` or `WAFRuleID` becomes its str
form (`"42"`), an empty/missing field becomes `None` and is dropped.

Type enforcement is **post-truncation, post-coercion** rather than at
parse time — the parsed JSON dict is iterated and any field that is
not str/int/float/bool/None will be `str()`-coerced. This is
intentional: Cloudflare Logpush occasionally emits the same field as
str in one record and int in another (e.g. `BotScore`), and
normalising to str matches the JSONB column's text semantics.

`MAX_METADATA_CHARS = 4096` per value × ~14 keys = ~56 KiB worst-case
metadata blob, well within JSONB practical limits. ✓

`_parse_timestamp` (lines 262–274) handles non-string or
unparseable `EdgeStartTimestamp` by falling back to `datetime.now(
timezone.utc)`. This is documented (line 264 comment) — a single
bad timestamp should not drop the whole batch. ✓

**Result: field validation is CLEAN.**

### 5. Auth — CLEAN (HMAC-only, no escalation)

The endpoint deliberately omits `dependencies=[Depends(require_api_key)]`
(line 177 comment + the router declaration at lines 179–182). The
HMAC is the *only* authentication mechanism; no API key, no JWT, no
role check, no session cookie. The `request: Request` parameter is
used only for `headers.get(...)` and `await request.body()` — no
`request.state.user`, no privilege escalation, no role lookup.

The auth flow:
1. `Content-Length` pre-check (line 378) — fail with 413.
2. Body read + length cap (line 396) — fail with 413.
3. `x_zaqorin_signature` header presence (line 360) — fail with 401
   empty body if missing.
4. `_verify_hmac` (line 413) — fail with 401 empty body if mismatch.

Steps 1–2 are unauthenticated (necessary to read the body to
verify the HMAC against it). Steps 3–4 are the auth gate. No path
exists for an attacker to bypass step 4 and reach `_ingest_ndjson`.

The module docstring (point 7, lines 51–57) explicitly documents
the design choice and offers the belt-and-braces option of
terminating Cloudflare traffic behind a reverse proxy that adds
`X-API-Key`. ✓

**Result: auth is CLEAN.**

### 6. Error responses — CLEAN (empty body on auth fail; operator-internal on DB fail)

Three failure surfaces:

- **HMAC fail (lines 408–421):** returns `Response(status_code=401)`
  directly, NOT `HTTPException`. The explicit comment at line 405
  explains why: FastAPI's `HTTPException(401)` would attach a
  `{"detail": "Unauthorized"}` body, turning the endpoint into a
  forgery oracle ("the server is telling me my signature was
  *unauthorized*" vs "the server said nothing"). The empty-body
  response is the correct forgery-oracle-resistant shape.
- **Body too large (lines 385–388, 398–401):** returns
  `HTTPException(413, detail=f"body too large: {cl} > {MAX_BODY_BYTES}")`.
  The detail echoes the requested Content-Length or the constant.
  This is reached *before* HMAC check, so an attacker can probe it
  unauthenticated — but the message leaks no secret, no path, no
  internal info beyond the constant `MAX_BODY_BYTES = 5 MiB` which
  is already documented in the module docstring (point 3, lines
  28–33). Acceptable.
- **DB persistence fail (lines 501–517):** returns
  `HTTPException(500, detail="persistence failed")`. The detail is
  a fixed string — no path, no SQL fragment, no exception message
  echoed to the caller. The full traceback goes to the server log
  via `log.exception(...)` (lines 506, 513), which is the correct
  operator-internal hygiene (operator needs the trace; caller does
  not).

No path leak, no secret-name leak, no stack-trace leak. ✓

**Result: error responses are CLEAN.**

### 7. Logging — CLEAN (no body, no IP, no secret)

Two loggers, both used deliberately:

- **`std_log.warning("cloudflare ingest: HMAC verification failed")`**
  (line 417) — fixed string, no body content, no peer IP, no
  signature bytes. Logged on every HMAC fail. Operator-actionable
  but content-free. ✓
- **`log.info("cloudflare ingest", accepted=N, rejected=M, source=...)`**
  (line 527) — structured counters only. No body, no metadata
  content. ✓
- **`log.exception(...)`** on DB error (lines 506, 513) — full stack
  trace. Operator-internal hygiene, not a caller-facing leak (see §6).
- **`log.exception(..., event_id=str(row.id))`** on stream publish
  fail (line 567) — operator-internal, includes server-assigned UUID
  only (not user input).

`_HMAC_SECRET` is never logged (verified by `grep -n _HMAC_SECRET`
on the file — appears only at lines 138–165 setup and line 345
HMAC compute). The HMAC header value `x_zaqorin_signature` is never
logged either. ✓

No PII: the user-controlled fields in Cloudflare Logpush records are
ClientIP, ClientRequestURI, ClientRequestUserAgent, etc. These are
**stored** in the events table (line 495 `raw=line.decode(...)`) and
in `metadata_` (line 496) — that is the design — but they are
**never logged** at the ingestion path. ✓

**Result: logging is CLEAN.**

### 8. SSRF — CLEAN (no outbound requests)

Verified by full-file review and by `grep -n -E
"urllib|requests|httpx|aiohttp|socket\.|\.open_connection|asyncio\.open"`
on the file: no outbound HTTP/TCP/UDP client primitives appear
anywhere. The endpoint:

- Reads the request body (line 396) — inbound only.
- Writes to the local DB via `pg_insert` (lines 290–310) — outbound
  only to the configured DB DSN, no user input in the target.
- Publishes to the configured Redis stream via `publish_event`
  (line 559 → `streams/publisher.py:81`) — outbound only to the
  configured Redis DSN, no user input in the target.

No URL construction, no DNS resolution, no `fetch`, no `curl`-style
invocation. CWE-918 does not apply. ✓

**Result: SSRF surface is CLEAN.**

## Conclusion

The Cloudflare Logpush ingest endpoint at commit `4b3c894` (v3.4.29)
is free of HMAC timing oracle, body DoS, string-repetition DoS,
yaml/json mixing, length-unbounded fields, auth escalation,
forgery-oracle error leaks, secret logging, and SSRF. The one
finding is **F-027 (Low)** — `json.loads` per-line has no
nesting-depth cap, allowing an HMAC-authenticated attacker (or a
misconfigured Cloudflare push job) to amplify CPU cost via deeply
nested JSON that hits `RecursionError` and rolls back the batch.

The fix is small (<10 lines, no third-party deps) and is documented
in F-027 §"Recommended fix". This round is audit-only.

## Adjacent surfaces (out of scope, but checked for regression)

- **`streams/publisher.publish_event`** — unchanged since the F-018
  fix cycle. Still `XADD` with `MAXLEN ~` trim. No new SSRF surface
  introduced by this round.
- **`Event` / `Host` models** — referenced at lines 83, 489–498, 282–312
  but not modified. The `metadata_` JSONB column is still text, still
  bounded by the per-value `_truncate` cap.
- **`get_session_factory()`** — the existing session-factory pattern
  is reused for both the write session (line 461) and the read-back
  session inside `_publish_accepted` (line 545). No new dependency
  on raw connections or external clients.
- **Other ingest endpoints** (`agents.py`, `evidence.py`,
  `whoami.py`) — not in scope this round; same pattern (HMAC or
  API-key, NDJSON or JSON body, audit hook) means the F-027 JSON-
  depth concern should be revisited for any other endpoint that
  calls `json.loads` on per-line input. Suggested follow-up cycle.

## Files touched this round

- `docs/security/findings/F-027-cloudflare-json-depth-dos.md` (new)
- `docs/security/findings/ROUND17-CLEAN.md` (this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 17 section appended)
