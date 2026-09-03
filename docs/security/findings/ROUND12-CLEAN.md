# Round 12 — CLEAN

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Round        | 12                                                          |
| Cycle        | 80                                                          |
| Phase        | 1 (TEST track, NARROW SCOPE)                                |
| Date         | 2026-09-04                                                  |
| Commit under audit | `d5e2a41` (v3.4.19)                                    |
| Scope        | `server/src/zaqorincore_server/self_defense/csp_violation_reporter.py` (post-F-025, 217 LOC) |
| Question     | Did the F-025 fix (3-header-name tuple: `transfer-encoding`, `te`, `x-transfer-encoding`) leave any residual header-confusion vectors? |
| Result       | **CLEAN — 0 findings**                                      |

## Vectors reviewed (Round 12 brief, cycle 80)

The cycle 80 brief asked five specific residual-check questions against
the F-025 fix at lines 183-190 of `csp_violation_reporter.py`. Results:

### 1. Are there OTHER Transfer-Encoding variants to block? — CLEAN

The tuple at lines 183-187 covers the three names the F-025 finding
identified as bypass vectors (canonical `Transfer-Encoding`, legacy
singular `TE:`, vendor prefix `X-Transfer-Encoding:`). Adjacent headers
checked and ruled non-vectors:

- **`Trailer`** — RFC 7230 §4.4. Declares trailer headers after a
  chunked body. Does NOT trigger chunked decoding in h11 (verified: h11
  only inspects `Transfer-Encoding` for framing). No 16 KiB cap bypass.
- **`Content-Encoding`** — RFC 7231 §3.1.2.2. Content compression
  (gzip, deflate, br); orthogonal to framing. Cap is enforced on raw
  body bytes, so a compressed body larger than 16 KiB still trips the
  `Content-Length` check at lines 191-198 or, in the streaming
  F-024-defense-in-depth variant, the post-read byte counter.
- **`Accept-Encoding`, `TE` (the response header)** — request vs
  response; irrelevant on a server-side POST.
- **HTTP/2 / HTTP/3 framing** — Starlette/Uvicorn surface HTTP/1.1
  only here (`requirements.lock` line 46: `h11==0.16.0`). HTTP/2 uses
  framing at the transport layer, so the `TE`/`Transfer-Encoding`
  headers are illegal in HTTP/2 and rejected by h2 before reaching the
  app.

No fourth header name needs adding.

### 2. Is the case-insensitive `.lower()` correct? What about Unicode case folding? — CLEAN

Line 189 uses Python's `str.lower()`, which performs **ASCII case
folding**. Python's `str.casefold()` does full **Unicode case folding**
(e.g., German `ß` → `ss`, Turkish `İ` → `i`).

RFC 9112 §6.1 specifies that TE tokens are ASCII-only: the registered
encoding tokens are `chunked`, `compress`, `deflate`, `gzip`, and
`identity`, all pure ASCII. There is no TE token containing non-ASCII
characters in any current RFC, and a TE value containing non-ASCII
characters would be rejected by h11 at the wire-decoding stage (h11 is
strictly ASCII per its tokenization rules).

Therefore `.lower()` is sufficient. `.casefold()` would add nothing
because no valid TE token has a non-ASCII case-folded form. No fix
needed.

### 3. Is the substring check `"chunked" in te.lower()` correct? False-positive risk? — CLEAN (acceptable trade-off)

The substring match catches:

- `Transfer-Encoding: chunked` ✓ (intended)
- `Transfer-Encoding: gzip, chunked` ✓ (intended)
- `Transfer-Encoding: chunked; foo=bar` ✓ (intended)
- `Transfer-Encoding: xchunkedid` ✗ (false positive — invalid TE token anyway, would be rejected by h11 at framing)

The only false-positive risk is a benign header *value* containing the
literal substring `chunked` in one of the three inspected header names.
For the canonical `Transfer-Encoding` header, RFC 9112 §6.1 reserves the
value space to encoding tokens; any value containing non-token
characters (including a literal substring that happens to spell
"chunked" inside an unrelated identifier) is invalid and would not be
sent by a well-formed client. For the legacy `TE:` and vendor
`X-Transfer-Encoding:`, the same reasoning applies: any value containing
"chunked" as a substring either means chunked framing or is malformed.

Acceptable trade-off. The Round 10 finding (cycle 76) confirmed this is
the intended behavior.

### 4. Order of checks — should all 3 header checks run before deciding? — CLEAN

Lines 188-190 already implement this correctly:

```python
for te in te_candidates:
    if "chunked" in te.lower():
        return FastAPIRawResponse(status_code=411, content=b"")
```

The `for` loop iterates **all three** candidates (`transfer-encoding`,
`te`, `x-transfer-encoding`) and rejects on **any** match. The order
within the tuple does not matter — any of the three header names with
the substring `chunked` triggers a 411 with an empty response. No
ordering bug.

### 5. Order in `receive_csp_report` — TE check before CL check before throttle? — CLEAN

Verified order (lines 188-209):

1. **Lines 188-190** — TE check across all 3 header names → reject with **411**
2. **Lines 191-198** — `Content-Length` cap → reject with **413** (or **400** on malformed)
3. **Lines 200-209** — per-src_ip throttle → reject with **429**
4. **Lines 211-213** — emit + **204**

This is the correct ordering:

- Framing ambiguity is rejected first (no body read, no emit).
- Body-size cap is checked second (still before any body parse or emit).
- Throttle is checked third (after framing/size are confirmed legitimate).
- Emit happens last and **only on success**.

F-023 Issue 4 invariant ("throttled requests must NOT emit") is
structurally preserved: throttled requests return 429 at line 209
without ever reaching `emit()` at line 212. The F-025 fix (the tuple
expansion at lines 183-187) sits in front of every downstream check, so
the order invariants from F-023 and F-024 still hold.

### 6. Is the `FastAPIRawResponse` import path still right? — CLEAN

Line 45:

```python
from fastapi import APIRouter, Request, Response as FastAPIRawResponse
```

`fastapi.Response` is a re-export of `starlette.responses.Response`. The
`response_class=FastAPIRawResponse` parameter on the route decorator at
line 156 uses it correctly. F-025 added a new return statement
(`return FastAPIRawResponse(status_code=411, content=b"")`) but did not
add a new import — `FastAPIRawResponse` was already imported for the
existing 204/413/400/429 returns. **No fix needed.**

## F-025 fix-surface summary (Round 12 verification)

| Surface | Status |
|---|---|
| Canonical `Transfer-Encoding: chunked` rejected with 411 | Implemented (line 190) |
| Legacy `TE: chunked` rejected with 411 | Implemented (line 190, candidate 2) |
| Vendor `X-Transfer-Encoding: chunked` rejected with 411 | Implemented (line 190, candidate 3) |
| Case-insensitive across all three names | Confirmed (`.lower()` per candidate) |
| Multi-encoding `gzip, chunked` rejected | Confirmed (substring match) |
| Parameters `chunked; foo=bar` rejected | Confirmed (substring match) |
| Whitespace/tab-as-separator `chunked , gzip` rejected | Confirmed (substring match catches `chunked` even if padded) |
| `Chunked`, `CHUNKED`, `cHuNkEd` rejected | Confirmed (`.lower()`) |
| Invalid token `xchunkedid` rejected (false positive, acceptable) | Confirmed |
| 411 response body is empty (`b""`) | Confirmed (line 190) |
| Order: TE → CL → throttle → emit | Confirmed (lines 188-213) |
| No emit on throttle (F-023 #4) | Confirmed (lines 200-209) |
| Other endpoints with the same flaw (ingest_webhook, ingest_cloudflare) | CLEAN (Round 11 finding F-025 confirmed both are defended at TWO layers) |

## Conclusion

The F-025 fix at commit `d5e2a41` (v3.4.19) is minimal, complete, and
correctly ordered. The five residual-check questions in the cycle 80
brief all return CLEAN. No F-026 issued. Round 12 is CLEAN.

## Files touched this round

- `docs/security/findings/ROUND12-CLEAN.md` (new — this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 12 section appended)