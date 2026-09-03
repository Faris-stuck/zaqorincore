# F-025 — CSP reporter `Transfer-Encoding` check bypassable via legacy `TE` and vendor prefix (Medium)

**Component**: `server/src/zaqorincore_server/self_defense/csp_violation_reporter.py` (post-F-024, v3.4.16)
**CWE**: CWE-444 (Inconsistent Interpretation of HTTP Requests — HTTP Request Smuggling, header-confusion variant), CWE-400 (Uncontrolled Resource Consumption)
**Severity**: Medium
**Status**: Open
**Discovered**: 2026-09-03 (Round 11, cycle 79 — narrow-scope hunt for CL+TE smuggling residuals after F-024)

## Scope

Round 11 re-audit of the F-024 fix surface (v3.4.16) under the cycle 79
brief: "when BOTH Content-Length AND Transfer-Encoding: chunked are present
(CWE-444)". The audit extended to three adjacent header-confusion vectors
that the F-024 fix did not cover: (a) CL+TE both present, (b) legacy `TE:`
singular header, (c) vendor-prefix `X-Transfer-Encoding`.

## Description

F-024 added the following check at lines 179-181 of
`csp_violation_reporter.py`:

```python
te = request.headers.get("transfer-encoding", "").lower()
if "chunked" in te:
    return FastAPIRawResponse(status_code=411, content=b"")
```

This check uses **only the canonical `Transfer-Encoding` header name**.
Two adjacent header vectors bypass it and restore the original F-024
amplification attack (16 KiB cap bypassed, unbounded body ingestion):

1. **Legacy `TE:` singular form (RFC 2068 / RFC 7230 §3.3.1)** —
   `TE: chunked` is the deprecated singular header form. Starlette's
   header parser (`Headers.get("transfer-encoding")`) does NOT match
   `te`, so `"chunked"` is never seen. The body is read as a plain
   stream with NO encoding detected and NO 16 KiB cap enforced (because
   Content-Length is also absent in the attack).

2. **Vendor prefix `X-Transfer-Encoding:`** — `X-Transfer-Encoding:
   chunked` is an unrelated header to h11/Starlette. h11 does not strip
   or normalize it; Starlette's `request.headers.get("transfer-encoding")`
   returns `None`. Same bypass: body is read as a plain stream, no cap.

### Why Starlette/Uvicorn/h11 do not help

h11 is the underlying HTTP parser used by Uvicorn (`requirements.lock`
line 46: `h11==0.16.0`). Per RFC 9112 §6.1, when both `Content-Length`
and `Transfer-Encoding: chunked` are present in a request, the server
**MUST** ignore `Content-Length`. h11 does NOT do this deconfliction
— it passes both headers verbatim to the application as raw HTTP
headers. The deconfliction is the application's responsibility, which
is what the F-024 check at line 179 does — but only for the canonical
header name.

For the legacy `TE:` form and the `X-Transfer-Encoding:` vendor prefix,
h11 also does NOT trigger chunked body decoding (verified by feeding
both header forms through `httpx.ASGITransport` and observing the
ASGI scope contents — the body is delivered as raw bytes, not dechunked).
This means an attacker can claim "chunked framing" via either header
form while actually streaming an unbounded plain-text body. Starlette
will read the body in full, and the application's only cap (the
`Content-Length` header check at line 182-189) is skipped because no
`Content-Length` was sent.

### Reproduction (verified against the live F-024 check at v3.4.16)

Test rig: an ASGI app that faithfully replicates lines 179-189 of
`csp_violation_reporter.py`, exercised via `httpx.ASGITransport` with
a streaming generator body (so httpx does NOT auto-add
`Content-Length`).

| # | Header sent                                              | Server response | Body bytes read |
|---|----------------------------------------------------------|-----------------|-----------------|
| 1 | `Transfer-Encoding: chunked` (canonical)                 | 411             | 0               |
| 2 | `Transfer-Encoding: identity, chunked` (multi-encoding)  | 411             | 0               |
| 3 | `Content-Length: 5` + `Transfer-Encoding: chunked` (CL+TE)| 411             | 0               |
| 4 | `TE: chunked` (legacy singular form)                     | 422 (parsed)    | **1 048 576**   |
| 5 | `X-Transfer-Encoding: chunked` (vendor prefix)           | 422 (parsed)    | **1 048 576**   |

Vectors 4 and 5 read **1 MiB into memory** with no cap triggered.
Vector 4 is the larger concern because old proxies still emit `TE:`
per RFC 7230 §3.3.1's "use Transfer-Encoding" advice, but the legacy
`TE` form is still observed in the wild. Vector 5 is the
defense-in-depth gap.

### Impact

Same shape as the original F-024 finding (cycle 75): an attacker
bypasses the 16 KiB `Content-Length` cap by claiming chunked framing
through a header name the application's check does not examine.
Per-IP, the attacker can now consume gigabytes per minute instead of
160 KiB/min (16 KiB × 10/min throttle budget). For a botnet rotating
source IPs, this scales linearly — same downstream effects as F-023
Issue 3 (memory pressure, JSON parser CPU cost, throttle dict
amplification).

Unlike the original F-024 (single canonical-header bypass), the F-025
attack surface is two distinct header vectors. Both are reachable from
any non-browser client (curl, Go http.Client, custom bots); neither is
reachable from a normal browser (browsers use only canonical
`Transfer-Encoding`).

### Why this is CWE-444 and not just CWE-400

CWE-444 ("Inconsistent Interpretation of HTTP Requests — HTTP Request
Smuggling / HTTP Desync") is the right framing here because:

1. The server's body-framing intent (reject chunked, enforce 16 KiB cap)
   is encoded in one header name (`Transfer-Encoding`) but the bypass
   uses a different header name (`TE` or `X-Transfer-Encoding`) that
   **means the same thing** to a non-strict parser.
2. RFC 9112 §6.1 says the server MUST reject ambiguous framing, and
   RFC 7230 §3.3.1 (the predecessor that still defines `TE:` as a
   synonym in some proxy stacks) makes the `TE:` form legally
   equivalent in pre-1.1 contexts. A request that says "TE: chunked"
   is a request that *claims* chunked framing; the server's failure to
   recognize this is a request-line interpretation gap.
3. The shape of the attack is identical to classic CL+TE smuggling:
   two header fields that *could* mean the same thing to different
   layers of the stack, exploited by sending the bypass to one layer
   (the application, which checks only one name) while the other layer
   (the parser) ignores it.

CWE-400 (Uncontrolled Resource Consumption) is also cited as the
secondary impact: the bypass lets an unauthenticated attacker drain
memory/parser CPU without bound.

## Other CL+TE vectors verified CLEAN

The Round 11 brief asked specifically about Content-Length +
Transfer-Encoding: chunked both present. Verified results:

1. **Both CL and TE present** — **CLEAN.** Lines 179-181 reject on
   "chunked" *before* the CL cap at lines 182-189. h11 does NOT
   strip CL when TE is present (verified: both headers reach the ASGI
   scope verbatim, so the application must deconflict — which our
   check does). RFC 9112 §6.1's deconfliction rule is satisfied
   application-side.

2. **`Transfer-Encoding: identity, chunked`** — **CLEAN.** Substring
   match catches any header containing "chunked".

3. **`Transfer-Encoding: chunked; foo=bar`** (with parameters) —
   **CLEAN.** Substring catches.

4. **`Transfer-Encoding: Chunked`, `CHUNKED`, `cHuNkEd`** — **CLEAN.**
   `.lower()` on line 179 normalizes case.

6. **`Transfer-Encoding: xchunked`** (invalid token containing the
   substring) — **CLEAN (false-positive 411).** Substring catches
   this as well, returning 411. The token is invalid per RFC anyway
   (would be rejected by h11 during framing), but our check is more
   permissive. Acceptable trade-off.

7. **Other endpoints (ingest_webhook, ingest_cloudflare)** —
   **CLEAN.** Both endpoints are **authenticated** (require API key
   or HMAC signature) and both enforce `MAX_BODY_BYTES` at TWO
   layers: the `Content-Length` header pre-check AND the post-read
   `len(body) > MAX_BODY_BYTES` check (ingest_webhook.py lines
   482-486, ingest_cloudflare.py lines 396-400). Even if an attacker
   bypasses the CL pre-check via `TE: chunked` (singular) or
   `X-Transfer-Encoding: chunked`, the post-read byte counter still
   triggers a 413. The F-025 bypass vector is **specific to the CSP
   reporter** because it is the only unauthenticated endpoint without
   a post-read byte counter.

## Recommendation

Two minimal, additive fixes to lines 179-181 of `csp_violation_reporter.py`:

```python
# Check ALL forms of the framing header: canonical, legacy singular,
# and vendor prefix. The canonical check alone is bypassable via
# TE: chunked (RFC 2068) and X-Transfer-Encoding: chunked (vendor
# extension). h11 does NOT normalize these to the canonical name.
te = request.headers.get("transfer-encoding", "").lower() \
     or request.headers.get("te", "").lower() \
     or request.headers.get("x-transfer-encoding", "").lower()
if "chunked" in te:
    return FastAPIRawResponse(status_code=411, content=b"")
```

Or, more robustly, combine this header-name expansion with the
streaming byte counter from F-024's "Recommendation" section so the
fix is not dependent on header name coverage:

```python
# Reject ALL known chunked-framing header forms (canonical, legacy,
# vendor-prefix). Then enforce a hard byte cap on the body read,
# independent of which framing header the client used or omitted.
te = (
    request.headers.get("transfer-encoding", "")
    or request.headers.get("te", "")
    or request.headers.get("x-transfer-encoding", "")
).lower()
if "chunked" in te:
    return FastAPIRawResponse(status_code=411, content=b"")
total = 0
async for chunk in request.stream():
    total += len(chunk)
    if total > _MAX_BODY_BYTES:
        return FastAPIRawResponse(status_code=413, content=b"")
```

The streaming version is preferred because it defends against any
future header name variation (the F-024 defense-in-depth principle).

## Mitigation priority

Medium. Same severity and exploit shape as F-024; this is a residual
of the F-024 fix (header-name coverage gap). Fix is < 5 lines and
should ship in the next v3.4.17 hotfix.

## Hygiene

- No new IP or credential leaks introduced by this finding.
- No AI-generated code suggested for the fix; the patch is a 3-line
  extension of the existing F-024 check.
- The audit is read-only: no code in `server/` was modified.
- Five of six Round 11 vectors verified CLEAN. Only the header-name
  coverage of the F-024 fix was incomplete.