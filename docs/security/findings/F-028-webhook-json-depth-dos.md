# F-028 — `/api/v1/ingest/webhook` JSON parsing has no nesting-depth cap (F-027 sibling)

| Field             | Value                                                            |
|-------------------|------------------------------------------------------------------|
| ID                | F-028                                                            |
| Round             | 9b                                                               |
| Cycle             | 99                                                               |
| Phase             | 1 (SECURITY track, NARROW SCOPE — sibling audit of F-027)        |
| Date              | 2026-09-04                                                       |
| Commit under audit| `a815ced` (v3.4.29)                                              |
| Severity          | Low                                                              |
| Class             | Denial of service — algorithmic complexity (CWE-400, CWE-770)   |
| Component         | `server/src/zaqorincore_server/api/v1/ingest_webhook.py`        |
| Status            | OPEN (audit-only cycle; no fix in this commit)                   |

## Summary

The F-027 fix (v3.4.29) added a depth-limited JSON decoder
(`_DepthLimitedDecoder`) to the Cloudflare Logpush ingest endpoint to
prevent a parser DoS via deeply-nested JSON. A sibling audit of every
other server-side JSON parse surface found that
`/api/v1/ingest/webhook` still uses raw `json.loads` with **no
nesting-depth cap** at two sites:

1. **Top-level body parse** — `ingest_webhook.py:497`
   ```python
   parsed = json.loads(body)
   ```
   This parses the vendor envelope (whole SIEM webhook body, capped at
   `MAX_BODY_BYTES = 1 MiB`).

2. **Per-record `message` field parse inside Sumo Logic batch path** —
   `ingest_webhook.py:304`
   ```python
   parsed = json.loads(msg)
   ```
   The Sumo translator iterates `body["records"]` and recursively
   `json.loads` the inner `message` string field of each record. There
   is **no per-`msg` byte cap** and no nesting-depth cap.

Both call sites can be reached by anyone holding the operator
`X-API-Key` (lower trust than HMAC, but still a real auth gate).
Either path accepts deeply-nested JSON and triggers the same
`RecursionError` → batch rollback → 500 amplification pattern that
F-027 documented for Cloudflare Logpush.

## Vulnerable code

`server/src/zaqorincore_server/api/v1/ingest_webhook.py:497`
```python
# ---- (3) Parse JSON ---------------------------------------------
try:
    parsed = json.loads(body)             # ← no depth cap (F-028)
except (ValueError, UnicodeDecodeError):
    raise HTTPException(status_code=422, detail="malformed JSON")
```

`server/src/zaqorincore_server/api/v1/ingest_webhook.py:290-310`
(Sumo Logic batch translator inside `_sumo_translate`):
```python
for rec in records_raw:
    if not isinstance(rec, dict):
        continue
    msg = rec.get("message")
    if not isinstance(msg, str):
        continue
    # Try JSON first.
    try:
        parsed = json.loads(msg)          # ← no depth cap (F-028)
    except (ValueError, UnicodeDecodeError):
        parsed = None
```

## Why this is a sibling of F-027, not a new class

The Cloudflare path's HMAC gives a per-push-job trust model and the
1 MiB NDJSON body cap is generous but bounded. The webhook path is
X-API-Key gated, also 1 MiB capped, and the Sumo path adds a
per-message `json.loads` inside a batch loop — which means a single
authenticated request can pack `len(body) // 64` nested parses per
batch, exactly the amplification pattern F-027 named.

## Reproduction

```python
# 1 MiB body, top-level parse path:
import json
deep = {"a": deep}  # build 1500-deep dict by reduce
body = json.dumps(deep).encode()  # ~5 KiB total
# POST /api/v1/ingest/webhook with this body + X-API-Key header:
# → RecursionError → 500.

# Sumo path: pack ~14k records, each with a 1500-deep message field:
rec = {"message": json.dumps(deep)}
body = {"records": [rec] * 14000}  # ~70 MiB; clipped by 1 MiB cap to ~200
# → 200 × RecursionError → batch rolled back → 500.
```

## Recommendation

Port the `_DepthLimitedDecoder` helper from
`ingest_cloudflare.py` (or extract it to a shared `server/src/
zaqorincore_server/_json_depth.py` module) and apply it to **both**
`json.loads(body)` and `json.loads(msg)` sites. Default depth limit
should match F-027's choice (depth = 32) to stay compatible with
SIEM vendors that emit modestly-nested envelopes.

Additionally:

- Per-`msg` byte cap (mirror `MAX_LINE_BYTES` pattern from
  `ingest_cloudflare.py`) — a Sumo `message` field is typically
  sub-10 KiB.
- Count nested-parse failures separately from envelope-level
  failures so an attacker burning CPU on deep JSON cannot mask a
  legitimate 422 from the audit trail.

## Closure plan

Dispatch to Coding Bot in the next loop cycle (cycle 100):
1. Extract `_DepthLimitedDecoder` to shared module.
2. Apply to both `json.loads` sites in `ingest_webhook.py`.
3. Add per-`msg` byte cap mirroring `MAX_LINE_BYTES`.
4. Add tests: 1500-deep body → 422, 1500-deep Sumo message → 422,
   normal envelopes → 200.
5. Update status to **Closed in v3.4.30** in `index.md` and
   `CHANGELOG.md`.

## Cross-references

- F-027 (Cloudflare NDJSON depth DoS) — same bug class, sibling
  endpoint. Closed in v3.4.29.
- `/ws/agent` (`stream.py:105, 252`) — `json.loads` calls but only
  reachable AFTER HMAC nonce echo + signature verify + `v == 2`
  protocol check; per-frame byte cap exists at the WS layer via
  uvicorn's `ws_max_size` (set in `main.py`). **Not vulnerable** —
  documented for completeness.
- `evidence.py:108` `json.loads(sidecar_path.read_text())` — reads
  from a local file written by the server itself; not exposed to
  untrusted input. **Not vulnerable**.