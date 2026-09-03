# F-013: Ingest endpoints (Cloudflare, webhook) never call `audit.record()`

| Field | Value |
|---|---|
| Severity | Low |
| CWE | CWE-778 (Insufficient Logging) |
| CVSS-like | 3.7 (AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N) |
| Location | `server/src/zaqorincore_server/api/v1/ingest_cloudflare.py:356`, `server/src/zaqorincore_server/api/v1/ingest_webhook.py:446` |
| Status | Open |

## Description

The `audit` module is explicitly opt-in: *"Callers that want their events captured call
``record()`` explicitly."*

A `search_files` for `audit.record` across `server/src/` returns no callers in the
ingest modules. Neither `ingest_cloudflare.py` nor `ingest_webhook.py` records the
fact that an upstream pushed events — neither on the success path (1 accepted) nor on
the failure paths (HMAC mismatch, body too large, JSON parse error).

The router is mounted without `dependencies=[Depends(record_audit)]` either; no audit
hook fires on entry.

## Impact

* **No ingestion audit trail** — the only signal that an external producer pushed
  events is the row inserts into `events`. If the upstream is compromised and is
  used to flood the system with garbage, there is no audit log line identifying
  which source did what.
* **Correlation gap** — incident responders trying to answer "what did the Cloudflare
  Logpush job push at 03:00?" have to derive it from the `events` table rather than
  read an `audit` row directly.

## POC sketch

Not directly exploitable; this is a forensics / observability issue.

## Remediation sketch

1. Add `audit.record(actor=...source..., action="ingest", target=...remote_addr...,
   status=...)` at the top of each ingest handler.
2. Add a dedicated `IngestAuditMiddleware` that fires `record()` for any POST to
   `/api/v1/ingest/*`, since these endpoints are the only routes that ingest
   untrusted data.
3. Promote `audit` to the SQL-backed store called out in F-008 so the log
   survives process restart.