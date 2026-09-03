# F-030 — Server-wide audit: residual `json.loads` calls without depth cap (Low — defence-in-depth)

| Field | Value |
|---|---|
| **ID** | F-030 |
| **Round** | 19 (cycle 103) |
| **Phase** | 1 (SECURITY track, NARROW SCOPE) |
| **Date** | 2026-09-04 |
| **Commit under audit** | `a671977` (v3.4.30) |
| **Component** | `server/src/zaqorincore_server/evidence.py` (line 244), `server/src/zaqorincore_server/api/v1/evidence.py` (line 108), `server/src/zaqorincore_server/error_envelope.py` (line 211) |
| **CWE** | CWE-400 (defence-in-depth) |
| **Severity** | **Low** |
| **Status** | **Closed in v3.4.31** (cycle 103) |

## Summary

After closing F-027 (Cloudflare Logpush NDJSON), F-028 (webhook body
+ per-record message), and F-029 (WS HELLO + event frames), a
server-wide grep for remaining `json.loads` calls surfaced three
more sites. None of them accept untrusted external input directly,
but each runs in a request path and parses JSON, so a defence-in-
depth application of the same depth-limited decoder is cheap and
consistent.

## Sites audited

| File | Line | Input source | Risk class | Fix |
|------|------|--------------|------------|-----|
| `server/src/zaqorincore_server/evidence.py` | 244 | Operator disk: `sidecar_path.read_bytes()` | Local-trusted; only request-path exposure is the operator calling the API | `safe_loads` |
| `server/src/zaqorincore_server/api/v1/evidence.py` | 108 | Operator disk: `sidecar_path.read_text()` | Same | `safe_loads` |
| `server/src/zaqorincore_server/error_envelope.py` | 211 | Upstream HTTP error body | Could be untrusted external if the server proxies or fetches from a third party | `safe_loads` |

## Why defence-in-depth is worth the churn

The pattern that produced F-027 → F-028 → F-029 was that every fix
surfaces a new instance of the same class. Continuing the audit one
cycle later catches the remaining sites before the next round
finds them, and the cost of converting `json.loads` →
`safe_loads` is one import + one call-site change per file (~6
lines per file). The pattern is now consistent across the entire
server.

## Verification

After the patch, `grep -rn "json.loads" server/src/` returns no
hits outside `utils/depth_json.py`. All 23 prior tests still pass
(8 F-027 + 7 F-028 + 8 F-029) since this round only added
defence-in-depth without changing observable behaviour for
non-pathological inputs.

## Test coverage

No new test file for F-030. The `safe_loads` helper is already
covered by the F-027 / F-028 / F-029 test files; this round only
applied the same helper to additional call sites.
