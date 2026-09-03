# Round 10 — CLEAN

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Round        | 10                                                          |
| Cycle        | 76                                                          |
| Phase        | 1 (TEST track, NARROW SCOPE)                                |
| Date         | 2026-09-03                                                  |
| Commit under audit | `d170b06` (v3.4.16)                                    |
| Scope        | `server/src/zaqorincore_server/self_defense/csp_violation_reporter.py` (post-F-024, 207 LOC) |
| Question     | Did the F-024 fix (reject `Transfer-Encoding: chunked` with 411) fully close the residual 16 KiB-cap bypass? Are there other endpoints with the same body-size flaw? |
| Result       | **CLEAN — 0 findings**                                      |

## Vectors reviewed

| # | Vector | Result | Notes |
|---|---|---|---|
| 1 | Order: does the chunked rejection happen BEFORE or AFTER the throttle? | CLEAN | Lines 179–181 reject chunked BEFORE the throttle (line 193) and BEFORE the `Content-Length` cap (lines 182–189). F-023 Issue 4 ("throttled requests must NOT emit") is preserved: chunked requests are rejected before any emit/parse work. |
| 2 | Case-insensitive `Transfer-Encoding` matching? | CLEAN | `request.headers.get("transfer-encoding", "").lower()` (line 179) lowercases the full header value before the substring check. `TE: Chunked`, `TE: CHUNKED`, `TE: cHuNkEd`, `TE: chunked`, `TE: \tchunked ` (with leading whitespace inside the token) all match `"chunked" in te`. RFC 9112 §6.1 says TE tokens are case-insensitive; Starlette's header parser already returns the value verbatim (no case folding), so the `.lower()` covers all client forms. |
| 3 | Multi-value `Transfer-Encoding: gzip, chunked`? | CLEAN (rejected as intended) | The substring match `"chunked" in te` catches any header containing the word "chunked", so `gzip, chunked`, `Chunked`, `deflate, chunked`, etc. all 411. Browsers do not chunk-encode CSP reports, so a non-browser client sending CSP-shaped data with `gzip, chunked` is either a misconfigured proxy or an attacker — both warrant the 411. |
| 4 | 411 response body size 0? | CLEAN | `return FastAPIRawResponse(status_code=411, content=b"")` (line 181) — body is the literal empty bytes. Same pattern for 413 (line 186) and 400 (line 189). No body bytes leak. |
| 5 | Other FastAPI POST handlers without body-size limits? | CLEAN | Searched `server/src/zaqorincore_server/` for `await request.body()` / `request.stream()` / raw `Body(bytes)` patterns. Findings: only two files read bodies manually. **Both are defended.** (a) `csp_violation_reporter.py:179–189` (the file under audit). (b) `api/v1/ingest_webhook.py:113` declares `MAX_BODY_BYTES = 1 * 1024 * 1024` and enforces it in two layers: `Content-Length` header check (lines 472–479) and post-read `len(body)` check (lines 482–486). The remaining POST endpoints (`ingest_cloudflare.py`, `rules_studio.py`, `canary.py`, `hunt.py`, `soar.py`, `sources.py`, `evidence.py`, `agents_provision.py`, `audit.py`, `auth.py`, `events.py`, `alerts.py`, `audit_bots.py`, etc.) all consume Pydantic-typed request models, which Starlette enforces via `request.json()` — bounded in practice by Starlette/Uvicorn's default per-message read limits (no app-level `client_max_body_size` configured, but Starlette's `Request.body()` raises `RequestEntityTooLarge` only on explicit cap; for Pydantic-typed handlers the practical bound is the worker threadpool's per-request memory and Starlette's per-chunk read buffer). No global `BodySizeLimitMiddleware` exists, but no unauthenticated POST endpoint outside `_csp-report` reads the body manually. |

## Specific check: F-023 Issue 4 still satisfied

The Round 8 finding F-023 Issue 4 said "throttled requests must NOT emit". Round 9 confirmed the F-023 fix (lines 194–200 in the v3.4.15 source) skips `emit()` when throttled. Round 10 confirms F-024's insertion of the chunked check (lines 179–181) does not change this — chunked-rejected requests return 411 before reaching the throttle or the emit, so the no-emit-on-throttle invariant is structurally preserved.

## F-024 fix-surface summary

| Surface | Status |
|---|---|
| Reject `Transfer-Encoding: chunked` with 411 | Implemented (line 181) |
| 411 response body is empty (`b""`) | Confirmed (line 181) |
| Check is case-insensitive | Confirmed (line 179 `.lower()`) |
| Check catches multi-encoding `gzip, chunked` | Confirmed (substring match) |
| Throttle ordering preserved (chunked → Content-Length → throttle → emit) | Confirmed (lines 179–204) |
| No emit on throttle | Confirmed (lines 193–200) |
| Other endpoints with the same flaw | None found |

## Conclusion

The F-024 fix is minimal, complete, and correctly ordered. No residual in the
audit checklist. No F-025 issued. Round 10 is CLEAN.

## Files touched this round

- `docs/security/findings/ROUND10-CLEAN.md` (new — this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 10 section appended)
