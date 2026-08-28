# ADR-008: SOAR webhook delivery (v1.3)

**Status:** Proposed
**Date:** 2026-08-28
**Authors:** ZaqorinCore maintainers
**Supersedes:** none
**Related:** ADR-005 (deception + forensics), v0.8.0 (compliance pack)

## Context

Once an alert is written to `alerts` (v0.3.0) and the
evidence bundle is in the locker (v0.7.0), the *response*
loop on the human side still has a gap: the SOC team
needs to be **notified** somewhere they already are.

Email is too slow. The ZaqorinCore web console requires
an operator to be actively looking at it. Most SOC teams
already have:

- **Chat-ops** in Slack or Discord
- **On-call rotation** in PagerDuty or Opsgenie
- **Ticketing** in Jira, ServiceNow, Linear, or TheHive
- **Incident response** workflow in TheHive + Cortex

Without an integration, an alert that fires at 03:00 sits
in the database until an operator opens the web console —
which can be hours later. SOAR (Security Orchestration
Automation and Response) is the industry term for the
plumbing that closes this gap.

## Decision

Add a new server-side package
`server/src/zaqorincore_server/soar/` that delivers
selected alerts to external systems via HTTP webhooks.

The package is a router + N delivery backends. Each
backend is a Python class that implements a `deliver(alert)
-> DeliveryResult` method. Backends are configured in
`server/config/soar.toml` and registered in
`server/src/zaqorincore_server/soar/__init__.py`.

A new background worker subscribes to the existing
`alerts` table via SQLAlchemy's `after_insert` event
hook (or a polling fallback if events are not available)
and routes each new alert through the enabled backends.

## Delivery contract

All backends accept an `Alert` object and return a
`DeliveryResult`:

```python
@dataclass(frozen=True)
class DeliveryResult:
    backend: str
    alert_id: str
    status_code: int
    attempted_at: datetime
    duration_ms: int
    error: str | None = None
    dead_lettered: bool = False
```

All HTTP work uses the existing `httpx.AsyncClient`
already in the server's dependency tree. No new HTTP
library.

## Backends shipped in v1.3

### Generic Webhook

The default backend. Sends a raw JSON payload
representing the alert + the first 1 KB of evidence
manifest. The user provides a Jinja2-style template in
`soar.toml` to transform the payload to whatever shape
their target system expects.

```toml
[backends.generic_webhook]
enabled = true
url = "https://my-target.example.com/hook"
auth_header = "Bearer <token>"
method = "POST"
content_type = "application/json"
template = """
{
  "alert_id": "{{ alert.id }}",
  "host_id": "{{ alert.host_id }}",
  "detector": "{{ alert.detector }}",
  "severity": "{{ alert.severity }}",
  "summary": "{{ alert.summary }}",
  "view_url": "https://zaqorin.example.com/#/alerts/{{ alert.id }}"
}
"""
cooldown_sec = 60
severity_min = "medium"
tags_filter = []
```

### Slack

Posts to a Slack incoming webhook URL with Block Kit
format. Auto-formats severity emoji (🔴 critical, 🟠 high,
🟡 medium, 🟢 low). Includes a "View in ZaqorinCore"
button linked to the alert's deep link.

### Discord

Posts to a Discord webhook URL with embed format. Same
emoji scheme as Slack. Markdown hyperlinks work in
Discord embeds.

### PagerDuty

POST to PagerDuty Events API v2. Maps ZaqorinCore
severity → PD severity:
- critical → critical
- high → error
- medium → warning
- low → info

Includes a `dedup_key` of `zaqorin:<detector>:<host_id>`
so repeated alerts from the same source don't page
multiple times in the same incident.

### TheHive

POST to TheHive v5 `/api/v1/alert` endpoint. Maps
ZaqorinCore alert to TheHive alert (title, description,
severity, source, sourceRef, artifacts).

### Jira

POST to Atlassian REST API v3 `/rest/api/3/issue`. Creates
an issue in a configured project with severity → priority
mapping. Description is the alert's raw payload as
markdown.

## Configuration file

`server/config/soar.toml` (gitignored, generated from
`soar.toml.example`). Per backend:

```toml
[backends.<name>]
enabled          = bool      # default: false
url              = string    # required
auth_header      = string    # optional
method           = string    # default: "POST"
content_type     = string    # default: "application/json"
template         = string    # required for generic_webhook
cooldown_sec     = int       # default: 60
severity_min     = string    # default: "low" (all)
tags_filter      = list[str] # default: [] (all)
max_retries      = int       # default: 5
```

The `cooldown_sec` is per `(backend, alert_id)` to avoid
storming the downstream when a detector flaps.

## Retry + dead-letter

```
attempt 1: immediate
attempt 2: +1s   (if 5xx or network error)
attempt 3: +5s
attempt 4: +25s
attempt 5: +125s
attempt 6: +625s
   ↓
dead-lettered → server/var/soar/dead-letter/<ts>-<alert_id>.json
```

4xx responses are **not retried** (they indicate a config
error — wrong URL, bad auth, payload too large, etc). They
are recorded in the audit log with the response body for
debugging.

5xx responses and network errors are retried with
exponential backoff. After `max_retries`, the payload is
written to dead-letter and the audit row is marked
`dead_lettered=true`.

Operators can replay a dead-lettered payload via
`POST /api/v1/soar/dead-letter/{id}/replay` after fixing
the config.

## New API endpoints

```
GET  /api/v1/soar/backends              list backends with 24h health
GET  /api/v1/soar/backends/{name}       single backend detail
POST /api/v1/soar/backends/{name}/test  fire a synthetic alert
GET  /api/v1/soar/dead-letter           list dead-lettered payloads
POST /api/v1/soar/dead-letter/{id}/replay  re-fire one
GET  /api/v1/soar/deliveries            recent delivery log (last 1000)
```

All endpoints use the same API key auth as the rest of
`/api/v1/`. No new auth scheme.

## Database migration

```sql
CREATE TABLE soar_deliveries (
  id              BIGSERIAL PRIMARY KEY,
  alert_id        UUID NOT NULL,
  backend         TEXT NOT NULL,
  status_code     INTEGER,
  attempted_at    TIMESTAMPTZ NOT NULL,
  duration_ms     INTEGER,
  error           TEXT,
  dead_lettered   BOOLEAN NOT NULL DEFAULT FALSE,
  payload_sha256  CHAR(64) NOT NULL  -- for replay integrity
);
CREATE INDEX ix_soar_deliveries_alert_id  ON soar_deliveries(alert_id);
CREATE INDEX ix_soar_deliveries_backend   ON soar_deliveries(backend, attempted_at);
```

The `payload_sha256` is the SHA-256 of the JSON body that
was POSTed. The replay endpoint re-hashes the on-disk
dead-letter file and refuses to replay if the hash
diverges (defense against tampering).

## Audit + web console

Every delivery is logged in `soar_deliveries`. The web
console gets a new tab "SOAR" under each alert that shows
the delivery history:

```
Alert: ssh_bruteforce — 203.0.113.42
SOAR deliveries:
  2026-08-28 10:23:45  slack         200  142ms  ✓
  2026-08-28 10:23:45  pagerduty     202   87ms  ✓
  2026-08-28 10:23:45  jira          201  312ms  ✓
```

If any backend dead-lettered, the row is highlighted and
a "Replay" button appears.

## Wire contract impact

**None.** This is server-only. Agents don't need to
change. Alerts that already flow to the server are
auto-routed through the SOAR pipeline; no change to the
detector pipeline.

## Why not use Celery / RQ / Dramatiq?

ZaqorinCore already uses FastAPI + asyncpg + redis. We
can do the SOAR worker as a plain `asyncio.Task` started
in the FastAPI lifespan. Celery adds a separate process
model, a separate serialization format, a separate
broker concept — all of which is overkill for a
webhook-with-retry.

The worker code is ~120 lines:
- One async task per alert
- Sleep + retry on 5xx
- Dead-letter on exhaustion
- Audit row per attempt

If volume grows past what one process can handle
(>1,000 alerts/min sustained), the worker can be split
into a separate binary that shares the same DB. The
audit table is the source of truth, so the split is
trivial.

## Consequences

- **Positive:** the existing alert pipeline now reaches
  the humans already on-call. MTTR drops from
  "next time someone opens the console" to "next 30
  seconds."
- **Positive:** zero new dependency on a SaaS SOAR
  platform. Slack/Discord/PagerDuty are the *delivery*
  targets, but the orchestration logic lives in
  ZaqorinCore.
- **Positive:** the dead-letter + replay pattern means
  a misconfigured downstream doesn't silently drop alerts.
- **Negative:** a misconfigured `soar.toml` can spam a
  Slack channel. Mitigated by the per-backend
  `cooldown_sec` and the `severity_min` / `tags_filter`
  defaults.
- **Negative:** the worker lives in the same process as
  the FastAPI app. A slow downstream (30s+ timeouts) can
  starve the request loop. Mitigated by running the
  worker on a separate `asyncio.Task` with bounded
  concurrency (`asyncio.Semaphore(10)`); if the queue
  overflows, deliveries are deferred, not dropped
  (FIFO via `asyncio.Queue`).
- **Negative:** every backend is a custom Python class;
  adding Slack/Discord/PagerDuty is real code, not
  config. Mitigated by the modular structure and the
  fact that the six backends in v1.3 cover >90% of
  the market.

## Implementation plan (vertical slices)

1. **Slice 1 — design + scaffolding** *(this ADR + the
   empty `server/src/zaqorincore_server/soar/` package
   + the `soar.toml.example` + the migration for
   `soar_deliveries` + the 6 backend class skeletons
   that all return "not implemented"). Land in main
   with no behavior change.*
2. **Slice 2 — Generic Webhook backend + first delivery
   end-to-end.** Operators can configure
   `soar.toml` with a webhook URL, the SOAR worker
   fires on a real `ssh_bruteforce` alert, and the
   `soar_deliveries` row records 200.
3. **Slice 3 — Slack backend.** Block Kit format,
   color emoji, View button.
4. **Slice 4 — Discord backend.** Embed format.
5. **Slice 5 — PagerDuty backend.** Events API v2 with
   dedup_key.
6. **Slice 6 — TheHive backend.** Alert create API.
7. **Slice 7 — Jira backend.** Issue create API.
8. **Slice 8 — Dead-letter + replay.** Persist
   exhausted payloads to disk + the replay endpoint.
9. **Slice 9 — Web console tab.** SOAR deliveries shown
   under each alert.
10. **Slice 10 — Docs.** Operator guide update,
    ROADMAP bump, this ADR.

## Decision outcome

Accepted. Implementation begins with Slice 1.
