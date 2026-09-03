# F-024 — CSP reporter 16 KiB cap bypassable via chunked transfer encoding (Medium)

**Component**: `server/src/zaqorincore_server/self_defense/csp_violation_reporter.py` (post-F-023, v3.4.15)
**CWE**: CWE-400 (Uncontrolled Resource Consumption), CWE-444 (Inconsistent Interpretation of HTTP Requests — "HTTP Request Smuggling" cousin, body-size variant)
**Severity**: Medium
**Status**: Open
**Discovered**: 2026-09-03 (Round 9, cycle 75 — narrow-scope audit of F-023 fix surface)

## Scope

Narrow re-audit of the F-023 fix surface (v3.4.14) to verify each of the
six residual issues called out in F-023 was actually closed. F-023 was
nominally "Closed in v3.4.14" with a 16 KiB Content-Length cap, threading
lock, eviction, and no-emit-on-throttle. This finding covers the one
residual that survived the fix.

## Description

F-023 Issue 3 was closed by adding a 16 KiB Content-Length check at
`csp_violation_reporter.py` lines 169-180:

```python
cl = request.headers.get("content-length")
if cl is not None:
    try:
        if int(cl) > _MAX_BODY_BYTES:
            return FastAPIRawResponse(status_code=413, content=b"")
    except ValueError:
        return FastAPIRawResponse(status_code=400, content=b"")
```

This check is **bypassable** by sending the body with
`Transfer-Encoding: chunked` instead of a `Content-Length` header. When
chunked encoding is used, `request.headers.get("content-length")`
returns `None`, the check is skipped, and FastAPI/Starlette will read
the body in full and pass it to `payload: dict[str, Any]` for parsing.
There is no global body-size middleware in the app (verified: only
`SecurityHeadersMiddleware`, `RateLimitMiddleware`, `RequestIDMiddleware`,
`ErrorEnvelopeMiddleware`, and optional CORS — none enforce body size).

The attacker path is:

1. `POST /api/v1/_csp-report` with `Transfer-Encoding: chunked` and
   no `Content-Length`.
2. Stream arbitrarily large chunks (megabytes to gigabytes, bounded
   only by Starlette/Uvicorn's per-message read buffer and timeout).
3. FastAPI parses the full body into a Python dict.
4. Throttle still applies (10/min/src_ip), so this is bounded per-IP,
   but **per-IP the attacker can now consume gigabytes per minute
   instead of 160 KiB/min** (16 KiB × 10/min).

For a single src_ip behind a botnet rotating source IPs, this scales
linearly with botnet size. The attacker can sustain ~N × 10 MiB/min
of unauthenticated JSON parsing, where N is the number of distinct
src_ips in the botnet — same shape as F-023 Issue 3, but the 100×
overshoot (1 MiB × 10/min/IP → 100 MiB/min/IP or more) is now
restored by the chunked bypass.

The route does **not** consume the body via `Request.stream()` and
manually enforce a byte counter, so there is no per-stream cap. The
16 KiB cap is purely a hint-based check on a header that the client
chooses to omit.

## Impact

- Unauthenticated ingress amplification restored: an attacker
  bypassing Content-Length via chunked encoding consumes the
  equivalent of F-023 Issue 3's pre-fix state.
- Same downstream effect as F-023 Issue 3: memory pressure on the
  FastAPI worker, JSON-parser CPU cost, and (because throttle is
  per-src_ip) the bypass only adds amplification when the attacker
  rotates src_ips — which is the same shape as Issue 2 (no
  IP eviction in the dict) and the same fix surface as F-023.
- CWE-444 is the closest CWE mapping: the server trusts a header
  (Content-Length absent = OK) without enforcing the intended limit
  against the alternative framing (Transfer-Encoding: chunked).

## Reproduction (conceptual, no live payload)

```bash
# Bypass the 16 KiB cap by sending chunked encoding.
# Uvicorn/curl --data-binary @large.json with -T triggers chunked.
curl -fsS -X POST http://target/api/v1/_csp-report \
  -H 'Content-Type: application/csp-report' \
  -H 'Transfer-Encoding: chunked' \
  -T <(yes '{"document-uri":"https://x/"}' | head -c 100000000)
# Server reads and parses 100 MB; 16 KiB cap did not trigger.
```

```python
# Server-side equivalent using httpx with chunked encoding.
import httpx
with httpx.Client() as c:
    def gen():
        for _ in range(10_000):
            yield b'{"document-uri":"https://x/"}\n'
    c.post(
        "http://target/api/v1/_csp-report",
        content=gen(),
        headers={"Content-Type": "application/csp-report"},
    )
```

## Other vectors checked and CLEAN

The remaining five vectors in the Round 9 checklist were verified
against the v3.4.15 source at commit `ea713cd`:

1. **Lock scope (global vs per-IP).** `threading.Lock` is module-level
   (`_throttle_lock` at line 89) and guards both the `_recent` dict
   and every per-IP deque. The lock is acquired inside
   `_throttle_allowed` (line 115), so every read-modify-write of
   `_recent` is atomic. **Clean.**

2. **`_evict_stale()` actually evicts.** Trace with mixed IPs:
   - IP A receives at t=0 and t=30 (deque=[0.0, 30.0], latest=30.0).
   - IP B receives at t=10 only (deque=[10.0], latest=10.0).
   - At t=70, cutoff=10.0. IP A's latest=30.0 ≥ cutoff, stays.
     IP B's latest=10.0 ≥ cutoff (boundary: `bucket[-1] < cutoff` is
     strict less-than, so 10.0 is **not** stale), stays.
   - At t=71, cutoff=11.0. IP B's latest=10.0 < 11.0, evicted.
   - Logic is correct: only entries whose **most recent** timestamp
     is fully outside the window are removed. **Clean.**

3. **`_throttle_lock` acquisition point.** Acquired inside
   `_throttle_allowed` (line 115), which is the only mutator. The
   `receive_csp_report` handler does not need to acquire it directly
   because the helper encapsulates the critical section. **Clean.**

4. **SSRF risk in CSP payload.** `blocked_uri` is parsed and stored
   on the event (event_normalizer.py line 193) but **never** used to
   trigger an outbound HTTP request. The only outbound from
   `csp_violation_reporter.py` is `emit(event)` which writes to the
   in-process `_STREAM`. **Clean** (no SSRF).

5. **`_resolve_src_ip` against XFF injection.** Starlette's
   `request.headers.get()` returns the parsed header value (CRLF
   rejected at the HTTP parser layer; one logical header value per
   `request.headers`). The `split(",", 1)[0].strip()` operates on a
   sanitized string. An attacker injecting `"1.2.3.4, 5.6.7.8\r\nX-Evil: 1"`
   as a single header value would get the literal string back from
   Starlette (the CRLF in the value is preserved as data, not as a
   header separator — Starlette uses a real HTTP parser, not a
   string-split). The first token `1.2.3.4` would be the resulting
   src_ip. **Clean.** Minor defense-in-depth note: no length cap on
   the XFF value before dict-keying, but Starlette/Uvicorn cap total
   header size (typically 64 KiB) so this is bounded in practice.
   Not enough to file a separate finding.

## Recommendation

Single change, ~5 lines:

```python
# Replace the Content-Length-only check with a streaming body read
# that enforces a hard byte cap. Chunked encoding transfers must be
# counted by actual bytes read, not by an advisory header.
async def receive_csp_report(payload: dict[str, Any], request: Request):
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_BODY_BYTES:
            return FastAPIRawResponse(status_code=413, content=b"")
    # … rest of handler unchanged
```

Or, if a middleware-level fix is preferred, add a
`BodySizeLimitMiddleware` that reads the body once and rejects
oversized requests regardless of framing. The streaming approach
above is local to the endpoint and matches the F-023 spirit.

## Mitigation priority

Medium. The endpoint is unauthenticated and the F-023 Issue 3 fix
was incomplete. The fix is < 10 lines and ships in the next v3.4.16
hotfix cycle.

## Hygiene

- No new IP or credential leaks introduced by this finding.
- No AI-generated code suggested for the fix; the file is short
  enough to patch in-place.
- The audit is read-only: no code in `server/` was modified.
- Five of the six Round 9 vectors verified CLEAN. Only the
  Content-Length-only cap was found to be incomplete.