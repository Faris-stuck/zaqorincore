# Round 3 audit — self_defense module — CLEAN

**Date:** 2026-09-03
**Scope:** `server/src/zaqorincore_server/self_defense/` (3 files:
`__init__.py`, `csp_violation_reporter.py`, `event_normalizer.py`)
**Commit audited:** `ef1edfb` (v3.4.4)

Round 3 audit found no new findings. Self-defense module is clean.

## Vectors reviewed

| Vector | Result | Notes |
|---|---|---|
| Path traversal in `document_uri` parsing | CLEAN | `document_uri` is read but never used as a filesystem path. The event `route` field is hardcoded to `/api/v1/_csp-report`. `document_uri` itself is intentionally dropped after parsing (not surfaced in the event). |
| JSON injection (CWE-91) from CSP body into YAML/serialized output | CLEAN | CSP report dict is projected to a typed `ZaqorinEvent` (frozen dataclass). The event is appended to an in-process deque — never serialized back into YAML, JSON config, or shell. The Sigma engine reads the dataclass via `.to_metadata()` and gets Python-native types only. |
| Integer overflow in throttle counter | CLEAN | `_THROTTLE_BUDGET = 10`, compared to `len(bucket)` on a Python `deque`. Python ints are arbitrary precision — no overflow possible. `time.time()` returns float (IEEE-754); used only for window-cutoff arithmetic, not security-critical comparison. |
| TOCTOU race on `_recent` throttle dict | LOW (not a finding) | `_throttle_allowed` does `setdefault` then mutate without a lock. A concurrent burst can briefly double-count one report. The window is 60s, budget 10, and the consequence is at most one extra accepted report per IP per race. No security boundary crossed; the global `RateLimitMiddleware` is the authoritative DoS control. |
| Missing rate-limit on a sensitive endpoint | CLEAN | `/api/v1/_csp-report` is throttled 10/min per src_ip (F-017 fix, v3.4.2). `_STREAM` and `emit()`/`drain()` are in-process internals, not HTTP endpoints. |

## Conclusion

The module is small (3 files, ~470 LOC) and tightly scoped. After F-017
(throttle by src_ip) and F-018 (thread-safe `_STREAM`), no exploitable
weakness remains in scope. No new finding IDs (F-019+) issued.