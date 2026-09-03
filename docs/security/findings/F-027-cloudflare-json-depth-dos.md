# F-027 — Cloudflare Logpush ingest: NDJSON lines unbounded nesting depth → parser DoS

| Field            | Value                                                            |
|------------------|------------------------------------------------------------------|
| ID               | F-027                                                            |
| Round            | 17                                                               |
| Cycle            | 99                                                               |
| Phase            | 1 (SECURITY track, NARROW SCOPE)                                 |
| Date             | 2026-09-04                                                       |
| Commit under audit | `4b3c894` (v3.4.29)                                            |
| Severity         | Low                                                              |
| Class            | Denial of service — algorithmic complexity (CWE-400, CWE-770)   |
| Component        | `server/src/zaqorincore_server/api/v1/ingest_cloudflare.py`     |
| Status           | OPEN (audit-only cycle; no fix in this commit)                   |

## Summary

The Cloudflare Logpush ingest endpoint parses each NDJSON line with the
stdlib `json.loads` (line 478). The per-line *byte* size is capped at
`MAX_LINE_BYTES = 64 KiB` (line 106, enforced at line 474), but there is
**no cap on JSON nesting depth**. A producer (Cloudflare push job) or an
attacker who has already compromised the HMAC secret can send
`{"a":{"a":{"a":...}}}` nested 1000+ levels deep — `json.loads` in CPython
uses recursive descent on the default C-accelerated decoder, hits the
interpreter's `sys.setrecursionlimit` (default 1000), and raises
`RecursionError`. That exception is caught by the broad
`except Exception` at line 511, the batch is rolled back, and the
endpoint returns `500`.

Worse: `json.loads` is called in a per-line loop, so the attacker can
pack **many deep-nested lines in one batch** (one per 64 KiB). The CPU
cost per line is small (a few ms for 1000-deep nested dicts) but
multiplied by batch line count it becomes a meaningful amplification
factor — a single HMAC-authenticated request that should "ingest ~100
Logpush records" instead becomes a 10-second CPU burn that is rolled
back wholesale, achieving nothing except denial of service.

The brief explicitly asked: *"JSON parsing: any DoS via deeply-nested
JSON?"* — this is the answer.

## Vulnerable code

`server/src/zaqorincore_server/api/v1/ingest_cloudflare.py:467-481`
(the per-line loop in `_ingest_ndjson`):

```python
for line in body.splitlines():
    # Strip CR/LF (Cloudflare NDJSON is \n-separated but
    # tolerate CRLF just in case).
    if line.endswith(b"\r"):
        line = line[:-1]
    if not line:
        continue  # blank lines are not an error
    if len(line) > MAX_LINE_BYTES:
        rejected += 1
        continue
    try:
        record = json.loads(line)   # ← unbounded nesting depth
    except (ValueError, UnicodeDecodeError):
        rejected += 1
        continue
    if not isinstance(record, dict):
        rejected += 1
        continue
```

The byte cap (`MAX_LINE_BYTES = 64 * 1024`) is enforced *before*
`json.loads` (line 474) but does not constrain the JSON's nesting
depth — a 64 KiB line can be a single dict nested 1000 deep (each
`{"a":` is only 5 bytes).

## Impact

1. **Authenticated DoS.** Only a holder of the HMAC secret (the
   configured Cloudflare push job, or an attacker who has exfiltrated
   it) can trigger this. Cloudflare Logpush does not natively sign
   payloads, so any compromise of the Logpush configuration surfaces
   here.
2. **Resource amplification.** Per-line parsing cost grows roughly
   linearly with nesting depth; the 5 MiB body cap means an attacker
   can fit ~80 lines of 64-KiB deeply-nested JSON in a single request.
   Each request burns several seconds of CPU and is rolled back,
   achieving nothing. The attacker controls the rate.
3. **No data corruption.** The batch is rolled back on `RecursionError`
   (caught by `except Exception` line 511), so no partially-persisted
   state. The impact is purely availability, not integrity or
   confidentiality.

## Severity rationale

Severity is **Low** because:

- Exploitation requires the HMAC secret, which is held in
  `ZAQORIN_CLOUDFLARE_INGEST_SECRET` and is at least as privileged as
  any other operator secret. An attacker with this secret already has
  ingest authority and could flood the DB with arbitrary rows — the
  recursion-amplified DoS is incremental damage relative to the
  baseline.
- Cloudflare itself is the only realistic push source, and Cloudflare
  does not produce deeply-nested JSON in practice (Logpush records are
  flat key/value with arrays of strings, depth ≤ 2). The realistic
  attack surface is "misconfigured push job" or "secret leak".
- The endpoint already mitigates the bulk of DoS surface: body cap
  (5 MiB), per-line cap (64 KiB), HMAC auth, no parser-bomb on
  string repetition (json.loads is bounded by the per-line cap).

The brief asked the question. The answer is "yes, depth is unbounded"
— and that is exactly what the Low rating is for. Recommended fix is
small and cheap.

## Recommended fix

Add a per-line depth cap before `json.loads` (line 478). Two options:

**Option A — pre-parse scan (cheapest, no third-party deps):**
count the maximum nesting depth from the raw line by tracking
`{` / `[` brackets while ignoring those inside JSON string literals.
Reject the line if depth > 32 (or whatever cap matches the actual
Cloudflare record schema, which is depth ≤ 2 in practice).

**Option B — recursive walk after parse (also cheap):**
wrap the parsed `record` in a depth-counting walk that raises if depth
exceeds 32. Slightly more overhead (parses first, then walks), but
works correctly without a hand-rolled bracket scanner.

Either option adds <10 lines, runs in O(n) over the line, and turns
the deep-nest attack from "rolled-back batch with stack trace" into
"line counted as rejected, batch continues normally". The brief is
audit-only so no fix is included in this commit.

## Notes for the fix author

- The Cloudflare Logpush http_requests schema has no nested objects
  beyond what `_CF_TO_METADATA` already flattens (line 215). A depth
  cap of 8 is generous; 16 is paranoid-safe.
- The same pattern should be checked against any *other* NDJSON
  endpoint that calls `json.loads` per-line (out of scope for this
  round but worth a follow-up cycle).
- `log.exception` at line 506 / line 513 will currently write a
  full `RecursionError` traceback on every deep-nest attempt. After
  the fix, those traces should not appear — log volume is a useful
  canary that the fix landed.
