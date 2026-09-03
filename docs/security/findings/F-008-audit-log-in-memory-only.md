# F-008: Audit log is in-memory only — survives only until process restart

| Field | Value |
|---|---|
| Severity | Medium |
| CWE | CWE-778 (Insufficient Logging) — specifically the persistence half |
| CVSS-like | 5.3 (AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N) |
| Location | `server/src/zaqorincore_server/audit.py:33-77` |
| Status | Open (Phase-1 placeholder, intentionally documented) |

## Description

The `audit` module is a 1024-entry ring buffer in process memory:

```python
# server/src/zaqorincore_server/audit.py
_log: "deque[dict[str, Any]]" = deque(maxlen=AUDIT_MAX)   # in-memory, line 36

def record(*, actor, action, target, status=None, extra=None):
    ...
    with _lock:
        _log.append(item)            # only writes to memory
```

The module docstring acknowledges this is a phase-1 placeholder:

> * No persistence yet — process restart clears the log.
> * No write-side hook into every endpoint (yet). Callers that want their events captured
>   call ``record()`` explicitly.

The buffer is bounded (`maxlen=1024`) so a misconfigured caller that hammers `record()`
will also silently evict old entries — there is no alert on overflow.

## Impact

* **No post-mortem evidence across restarts** — when an operator restarts the server for
  a routine deploy, every prior audit event is gone. An attacker that crashes the
  process deliberately after pivoting through it leaves zero forensic trace.
* **Bounded buffer = silent loss even without restart** — the 1024-entry cap means the
  audit log starts shedding entries once the operator exceeds ~17 audit events per
  minute over an hour. There is no log line on eviction; the only signal is the
  downstream `snapshot()` returning the last 1024 entries.
* **Selective record** — only endpoints that explicitly call `audit.record()` contribute
  events. Most v1 endpoints never call `record()`, so the audit log is sparse even
  before the buffer limit bites.

## POC sketch

1. Operator rotates `ZAQORIN_API_KEY_WRITE` (which is itself an auditable event in
   well-designed systems).
2. Server restart occurs for any reason — the rotation event is gone.
3. Attacker who obtained the leaked credential between rotation events now operates
   inside a window where there is no record they were active.

## Remediation sketch

Promote `audit.py` to a SQL-backed table (`audit_events`) with:

* `INSERT ... RETURNING id` so the writer can detect DB unavailability.
* Append-only enforcement: `GRANT INSERT, SELECT` only; no `UPDATE` or `DELETE` on
  this table.
* WAL-based archival (`pg_basebackup` / continuous archiving) for tamper-evident
  retention.
* Wire `audit.record(...)` into the existing middleware chain
  (`RequestIDMiddleware` → `RateLimitMiddleware` → auth dep → handler) so every state-
  changing endpoint is covered without per-handler plumbing.

The phase-2 increment that was originally proposed in the audit.py docstring.