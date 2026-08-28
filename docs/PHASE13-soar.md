# Phase 13 — SOAR webhook delivery (v1.3.0)

> Shipped in **v1.3.0** (slices 1–5: slice 1 scaffold and
> six `NotImplemented` backends; slice 2 `generic_webhook`;
> slice 3 `slack` + `discord`; slice 4 `pagerduty` + `thehive` +
> `jira` and the alembic migration for `soar_deliveries`;
> slice 5 worker integration tests).

SOAR is the layer that takes an alert out of the database and
hands it to the humans who are already on call. The detection
pipeline in Phase 3 already produces `Alert` rows. The console
in Phase 9 already shows them. Without SOAR, an alert that
fires at 03:00 sits in the database until an operator opens
the web console, which can be hours later. SOAR closes that
gap with a single polling worker, six HTTP delivery backends,
exponential backoff, and a dead-letter queue with replay.

## What is SOAR, in one sentence

SOAR is the background worker that copies every alert the
server writes into the systems your team already uses for
response: Slack, Discord, PagerDuty, TheHive, Jira, or any
HTTP endpoint you point it at. It also persists the audit trail
so a misconfigured downstream never silently swallows an alert.

## Why v1.3.0

The first three post-1.0 features (eBPF in v1.1, multi-platform
agents in v1.2, SOAR in v1.3) each close a specific gap. SOAR
is the one that changes the operator experience the most: the
gap between "alert exists" and "human sees it" drops from
hours to seconds. The decisions, trade-offs, and the six
backends are captured in [ADR-008](decisions/ADR-008-soar-webhook-delivery.md).

## What ships in v1.3.0

| Backend | What it does |
| --- | --- |
| `generic_webhook` | Send a Jinja2-templated JSON (or any content type) to a URL you choose. The default for any system that takes an HTTP POST. |
| `slack` | Post a Block-Kit message to a Slack Incoming Webhook with a "View" button. |
| `discord` | Post a colored embed to a Discord webhook. |
| `pagerduty` | POST to the PagerDuty Events API v2 with a `dedup_key` so retries collapse into one incident. |
| `thehive` | Create an alert in TheHive v5 (it can auto-promote to a case if a case template is set). |
| `jira` | Create an issue via the Atlassian Cloud REST API v3. |

All six share the same retry, cooldown, severity-filter, and
tag-filter machinery. Adding a seventh is a single new file
under `server/src/zaqorincore_server/soar/backends/` plus
a class registration in `worker.py`.

## Architecture

```
   alert written to `alerts` table
              │
              ▼
   SoarWorker._poll_once()        (every `poll_sec`, default 2s)
   │ - read last 60s of alerts (limit 200)
   │ - skip already-enqueued alert_ids
   │ - for each enabled backend:
   │     apply severity filter  ─→ drop
   │     apply tag filter       ─→ drop
   │     apply cooldown         ─→ drop
   │     enqueue _PendingDelivery
              │
              ▼
   asyncio.Queue (max `queue_max`, default 1000)
              │
              ▼
   SoarWorker._drain_queue_once() (batches of 16, semaphore(10))
              │
              ▼
   SoarWorker._run_one()          (one item at a time)
   │ - call backend.deliver(ctx, alert)
   │ - 2xx/3xx  ─→ success, mark cooldown, done
   │ - 4xx      ─→ permanent error, dead-letter, no retry
   │ - 5xx      ─→ sleep 1s, retry
   │ - network  ─→ sleep 1s, retry
   │ - 5 retries with backoff 1, 5, 25, 125, 625 s
   │ - on exhaustion: write dead-letter JSON file
              │
              ▼
   one SoarDelivery row per attempt + (if dead-lettered)
   one .json file under `dead_letter_dir`
```

The worker is a single `asyncio.Task` started by the FastAPI
lifespan (`zaqorincore_server.main`, gated on
`settings.soar_enabled`, default `True`). On shutdown the
lifespan calls `await worker.stop()` with a 5 s cancel
timeout. The worker re-uses the existing `httpx.AsyncClient`
in the server's dependency tree. No new HTTP library was
added.

The six backends all implement the same `Backend` protocol
(`name: str` + `deliver(ctx, alert) -> DeliverOutcome`). The
worker owns retry, cooldown, dead-letter, and the audit
write. The backend owns request shape, validation, and
severity mapping. The split keeps each backend a single
~200-line file.

### Why polling, not `after_insert`

The original ADR considered SQLAlchemy's `after_insert` event
hook. It was rejected because the hook fires inside the
writing transaction: a slow webhook would hold a DB row lock
for the whole call. Polling at 2 s ticks keeps the alert
insert path tight. A worst-case 2 s delay between "alert
written" and "SOAR sees it" is acceptable for a delivery
pipeline that already debounces per-(host, detector) at
`cooldown_sec` (default 60 s).

### Backpressure

`asyncio.Queue(maxsize=queue_max)` (default 1000) bounds the
in-memory backlog. When the queue is full, the poller drops
the oldest item in favor of the newest. A fresh critical
alert is more useful than a stale retry. The poller re-reads
the table on the next tick, so anything dropped is picked up
within seconds.

### Concurrency

`asyncio.Semaphore(10)` caps in-flight HTTP calls. A slow
downstream (30 s timeout) can't tie up the whole event loop.

## Configuration

`server/config/soar.toml` is gitignored. Copy it from
`server/config/soar.toml.example`. Every key is optional;
an empty file means the worker is disabled and no webhook
calls are made. The path can also be overridden with the
`ZAQORIN_SOAR_CONFIG` env var.

### Top-level block

```toml
[soar]
enabled = true               # default false
poll_sec = 2.0               # how often the poller scans `alerts`
queue_max = 1000             # asyncio.Queue maxsize; oldest dropped on overflow
dead_letter_dir = "var/soar/dead-letter"
public_base_url = "https://zaqorin.example.com"
```

`public_base_url` is substituted into the `{{ console_url }}`
template variable, so delivered messages can include a "View
in ZaqorinCore" link. An empty string disables the link.

### Per-backend block

Every backend has the same five knobs plus a few
backend-specific keys:

```toml
[backends.<name>]
enabled          = false     # default
cooldown_sec     = 60        # debounce per (backend, host, detector)
severity_min     = "low"     # info|low|medium|high|critical
tags_filter      = []        # empty = "fire for any tag set"
max_retries      = 5         # retries after the initial failure
timeout_sec      = 10.0      # per-request timeout
# ...backend-specific keys (url, webhook_url, routing_key, ...)
```

The filter chain is applied in this order: enabled flag →
severity floor → tag intersection → cooldown window. A
backend with `severity_min = "medium"` fires for medium,
high, and critical; it skips low and info. A backend with
`tags_filter = ["attack.credential_access"]` only fires for
alerts that carry at least one of those tags.

### Backend-specific keys

| Backend | Required | Optional |
| --- | --- | --- |
| `generic_webhook` | `url`, `template` | `auth_header`, `method`, `content_type`, `headers` |
| `slack` | `webhook_url` | `username`, `channel` |
| `discord` | `webhook_url` | — |
| `pagerduty` | `routing_key` | `severity_map` |
| `thehive` | `api_url`, `api_key` | `alert_type`, `source`, `case_template` |
| `jira` | `api_url`, `project_key`, `email`, `api_token` | `issue_type`, `priority_map` |

`auth_header` for `generic_webhook` is sent verbatim as the
`Authorization` header. Use it for any token scheme your
target expects: `Bearer ...`, `Token ...`, `Basic ...`.

### Security warnings

!!! warning "Do not commit secrets"
    `soar.toml` is gitignored for a reason. The Slack
    webhook URL, Discord webhook URL, PagerDuty routing
    key, TheHive API key, and Jira API token are all
    long-lived credentials. If your `soar.toml` lands in
    the repo, rotate the credentials. Generate a fresh
    Slack webhook, rotate the Jira token at
    `https://id.atlassian.com/manage-profile/security/api-tokens`,
    and revoke the old TheHive API key from the org
    settings.

!!! warning "Use a deployment layer to inject secrets"
    The recommended pattern is to template `soar.toml` from
    your deployment tooling (Ansible, Helm, systemd
    `EnvironmentFile=`) rather than checking the secrets in.
    `auth_header` and the per-backend token fields are just
    strings. `auth_header = "Bearer ${ZAQORIN_SLACK_TOKEN}"`
    is fine if your deployment layer expands it.

!!! warning "Restrict the target URL"
    The `generic_webhook` backend will send to any
    `http://` or `https://` URL you put in `soar.toml`. Don't
    point it at internal admin panels you don't want
    exposed to the world. The worker runs with the same
    privileges as the server.

!!! warning "Webhook URLs are Bearer-equivalent"
    Anyone with a Slack/Discord/PagerDuty webhook URL can
    post to your channel. Treat them like API tokens.

### Validate your config

`load_config()` rejects unknown backend names. A typo in
`[backends.slak]` raises `ValueError: soar.toml: unknown
backend 'slak'` at startup. Each backend's `_validate()`
checks its own required keys on first delivery and returns a
dead-lettered result with a clear error message. See
"Troubleshooting" below.

## API endpoints

The router lives at `server/src/zaqorincore_server/api/v1/soar.py`
and is mounted at `/api/v1/soar`. All endpoints use the
existing API key auth; no new auth scheme.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/soar/deliveries` | Recent delivery log. Filters: `alert_id`, `backend`, `limit`. |
| `GET` | `/api/v1/soar/health` | Last-24h per-backend counts: total, success, 4xx, 5xx, network, dead-lettered. |
| `GET` | `/api/v1/soar/dead-letter` | List dead-letter files, newest first. |
| `GET` | `/api/v1/soar/dead-letter/{file_id}` | Fetch one dead-letter and verify its `file_sha256`. |
| `POST` | `/api/v1/soar/dead-letter/{file_id}/replay` | Verify SHA-256, then re-enqueue. Bypasses cooldown and tag filter. |

The replay endpoint re-renders the body from the dead-letter
file (not the live alert row), so the replay sends the
**exact** body the operator is approving. If the file's
SHA-256 doesn't match the embedded hash, the replay is
refused with HTTP 409, as a defense against on-disk tampering.

## How a custom backend plugs in

Adding a backend is two files. Let's call it `opsgenie`.

### 1. Write the backend

Create `server/src/zaqorincore_server/soar/backends/opsgenie.py`:

```python
"""Opsgenie backend (v1.3.x). Posts an alert-create to
the Opsgenie Alerts API.

Body shape, severity mapping, and auth scheme:
... describe them here so the next maintainer can audit ...
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


class Opsgenie:
    name = "opsgenie"
    endpoint = "https://api.opsgenie.com/v2/alerts"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config

    def _validate(self) -> str | None:
        api_key = self._config.extra.get("api_key")
        if not api_key or not isinstance(api_key, str):
            return "opsgenie: missing `api_key` in config"
        return None

    def _render(self, alert: Alert, console_url: str) -> dict[str, Any]:
        return {
            "message": alert.summary or f"ZaqorinCore alert {alert.id}",
            "alias": f"zaqorin:{alert.id}",
            "priority": "P1" if alert.severity == "critical" else "P3",
            "source": "zaqorincore",
            "tags": list(alert.tags or []),
        }

    async def deliver(self, ctx: Any, alert: Alert) -> DeliverOutcome:
        started = datetime.now(timezone.utc)
        public_base_url = ""
        if ctx is not None and hasattr(ctx, "public_base_url"):
            public_base_url = str(getattr(ctx, "public_base_url") or "")

        err = self._validate()
        if err is not None:
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=0,
                    attempted_at=started,
                    duration_ms=0,
                    error=err,
                    dead_lettered=True,
                ),
                payload_sha256="",
            )

        body = self._render(alert, public_base_url)
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        body_sha = hashlib.sha256(raw).hexdigest()
        api_key = str(self._config.extra["api_key"])

        try:
            async with httpx.AsyncClient(timeout=self._config.timeout_sec) as client:
                resp = await client.post(
                    self.endpoint,
                    content=raw,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"GenieKey {api_key}",
                    },
                )
            status = int(resp.status_code)
            error_msg = None
            dead_lettered = False
            if status >= 500:
                error_msg = f"http {status}: {resp.text[:200]}"
            elif status >= 400:
                error_msg = f"http {status}: {resp.text[:200]}"
                dead_lettered = True
            duration = int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000
            )
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=status,
                    attempted_at=started,
                    duration_ms=duration,
                    error=error_msg,
                    dead_lettered=dead_lettered,
                ),
                payload_sha256=body_sha,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            duration = int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000
            )
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=0,
                    attempted_at=started,
                    duration_ms=duration,
                    error=f"network error: {type(e).__name__}: {e}",
                    dead_lettered=False,
                ),
                payload_sha256=body_sha,
            )


__all__ = ["Opsgenie"]
```

The contract every backend must follow:

- `name` matches the `[backends.<name>]` key in `soar.toml`.
- `__init__(self, config: BackendConfig)` reads from
  `config.extra` (the free-form backend-specific keys).
- `_validate()` returns a human-readable error string when
  config is bad, or `None` when it's good. Bad config is
  always `dead_lettered=True` and `status_code=0`.
- `deliver(ctx, alert)` returns a `DeliverOutcome` with a
  `DeliveryResult` and a `payload_sha256`. The worker
  persists the result row; the SHA-256 is the dead-letter
  replay's integrity check.
- 2xx/3xx is success, 4xx is permanent (no retry, dead-letter
  immediately), 5xx and network errors are transient (retry
  with backoff up to `max_retries`).

### 2. Register it

In `server/src/zaqorincore_server/soar/worker.py`, add the
import and the class to the `backend_classes` dict in
`_install_backends()`:

```python
from .backends.opsgenie import Opsgenie  # add at the top of worker.py

# ...inside _install_backends:
backend_classes: dict[str, type[Backend]] = {
    "generic_webhook": GenericWebhook,
    "slack": Slack,
    "discord": Discord,
    "pagerduty": PagerDuty,
    "thehive": TheHive,
    "jira": Jira,
    "opsgenie": Opsgenie,  # new
}
```

In `server/src/zaqorincore_server/soar/config.py`, add
`"opsgenie"` to `KNOWN_BACKENDS`.

### 3. Add a config block

In `soar.toml`, drop in:

```toml
[backends.opsgenie]
enabled = true
cooldown_sec = 60
severity_min = "high"
tags_filter = []
max_retries = 5
timeout_sec = 10.0
api_key = "REPLACE_WITH_OPSGENIE_API_KEY"
```

The `load_config()` helper parses any key under
`[backends.<name>]` into the `BackendConfig.extra` dict
(the six reserved keys are stripped). Your backend reads
whatever it needs from there.

### 4. Tests

Three test files cover the existing six backends and the
worker. Mirror them for a new backend:

- `tests/test_soar_chat_backends.py` or
  `tests/test_soar_ticketing_backends.py` — backend-class
  unit tests, no DB. Use `httpx.MockTransport` to
  pre-program the response and assert the request shape.
- `tests/test_soar_worker.py` — integration tests against
  the real `SoarWorker` + real DB + temp dead-letter
  directory. The existing five cover 2xx, 4xx, 5xx with
  retry, 5xx-then-success, and a backend that raises.

## Operations

### How to read the queue depth

The worker holds alerts in `asyncio.Queue(maxsize=queue_max)`.
There is no direct "queue depth" endpoint. Read it indirectly:

- `soar_deliveries` row count over the last minute vs. alerts
  written over the last minute: if the ratio is dropping,
  the worker is falling behind.
- `GET /api/v1/soar/health` per-backend `total` and
  `dead_lettered` counts.
- `GET /api/v1/soar/dead-letter` for the current backlog.

A healthy setup shows `success` counts climbing and
`dead_lettered` flat at zero. A spike in `server_error` or
`network_error` is the canary.

### Backoff in practice

The schedule is fixed: **1 s, 5 s, 25 s, 125 s, 625 s**.
That's five retries after the initial attempt, ~13 minutes
total in the worst case. After the 6th attempt the delivery is
dead-lettered. 4xx responses skip the schedule entirely and
go straight to dead-letter.

The `max_retries` knob is per-backend. Set it to `0` for a
backend you want fire-and-forget on.

### Dead-letter recovery

A dead-lettered delivery is one of:

1. A 4xx response (configuration error: bad URL, bad auth,
   payload too large, malformed JSON, etc.).
2. A 5xx response after `max_retries` are exhausted.
3. A network error after `max_retries` are exhausted.

In all three cases the worker writes a JSON file to
`dead_letter_dir` named `<UTC-timestamp>-<alert-id-prefix>.json`.
The file contains the alert, the backend name, the status
code, the error, the attempt number, and a `file_sha256`
field. The SHA-256 is computed over the JSON body without
that field, and embedded back in. The replay endpoint
recomputes it and refuses to replay if it diverges.

Replay workflow:

1. `GET /api/v1/soar/dead-letter` to see what's stuck.
2. `GET /api/v1/soar/dead-letter/<file_id>` to read the
   body and confirm the SHA-256 check.
3. Fix the root cause in `soar.toml` (rotate the token,
   correct the URL, change the severity filter).
4. `POST /api/v1/soar/dead-letter/<file_id>/replay` to
   re-enqueue. The worker re-renders the body from the
   dead-letter file, so a template change between the
   original attempt and the replay doesn't change what
   gets sent.

Replay bypasses the per-(host, detector) cooldown and the
tag filter, since the operator is explicitly asking for it.

### Cooldown semantics

`cooldown_sec` is debounce per `(backend, host_id, detector)`
triple. The tracker is in-memory and process-local; on
restart, the worker re-fires once for any alert that fired
in the last 60 s. That's a deliberate trade-off: a missed
cooldown on a single restart is much less bad than a
restart that loses the entire queue, and the alert is in
the DB either way. Persistent cooldowns would be a v1.4
question.

## Troubleshooting

### `ValueError: soar.toml: unknown backend '<name>'`

You added a `[backends.<name>]` block but the name isn't in
`KNOWN_BACKENDS` in `soar/config.py`. Either rename the
block to one of the six shipped backends, or add your
custom backend to `KNOWN_BACKENDS` plus the
`backend_classes` dict in `worker._install_backends()`.

### `slack: missing 'webhook_url' in config`

The `slack` block has no `webhook_url`. The full Block-Kit
message cannot be built. Fix the config. The value should
start with `https://hooks.slack.com/services/`. The worker
records the error to `soar_deliveries` with
`dead_lettered=true` so the operator sees it in the
audit log.

### `slack: webhook_url must start with https://hooks.slack.com/`

You configured a Discord or PagerDuty URL under the `slack`
backend (or vice versa). Each backend validates its own URL
prefix to catch this class of misconfig. Check the
`backends/<name>.py` for the exact prefix it expects.

### `pagerduty: missing 'routing_key' in config`

The PagerDuty integration key is not set. Generate one
under **Service Directory → Integrations** in PagerDuty
and paste it into `soar.toml`.

### `thehive: missing 'api_url'` / `thehive: missing 'api_key'`

The TheHive block needs both. `api_url` is the base URL
of your TheHive instance (no trailing slash). `api_key` is
an org-level API key from **Organization → API keys** in
TheHive.

### `jira: missing 'api_token'`

Generate one at
`https://id.atlassian.com/manage-profile/security/api-tokens`.
The `email` is the Atlassian account email associated with
the token; authentication is HTTP Basic with
`email:api_token` base64-encoded.

### HTTP 4xx from a real downstream (not the worker config check)

The downstream is rejecting the request body. The worker
records the response body in `soar_deliveries.error`
(truncated to 200 chars). Common causes:

- Slack: `channel_not_found` when the `channel` override
  names a channel the webhook can't post to.
- PagerDuty: `Invalid routing key` when the key was
  revoked or belongs to a different service.
- Jira: `Project not found` when `project_key` doesn't
  match the project the API token can see.
- TheHive: `Bad credentials` when the API key is rotated
  but `soar.toml` was not updated.

4xx is permanent. Fix the config and replay from
dead-letter.

### HTTP 5xx

The downstream is having a bad day. The worker retries
with the backoff schedule. If retries exhaust, the
delivery is dead-lettered. Use `/api/v1/soar/health` to
see whether the issue is transient (a few rows with 5xx
in the last minute) or sustained (most rows are 5xx).

### Queue full (drop-oldest)

The queue hit `queue_max` (default 1000). The poller
dropped the oldest item to make room for the newest. A
sustained backlog means a downstream is too slow for the
alert rate. Reduce `max_retries`, raise `queue_max`, or
add a faster backend for low-severity alerts.

### "soar worker not running" on the API

The worker wasn't started, because either `soar_enabled` is
`False` in settings, or the lifespan hit an error before
`worker.start()`. Check the server log for the startup
exception. The dead-letter endpoints return 503 in this
state; the deliveries and health endpoints still work
against the DB.

### Replay returns HTTP 409

The dead-letter file's `file_sha256` doesn't match the
embedded hash. Something edited the file on disk (or the
file was written with a different worker version). The
replay is refused on purpose. Delete the file or restore
it from a known-good backup.

### Replay returns HTTP 503 "queue full"

The live queue is at `queue_max` already. Wait for the
worker to drain, or raise `queue_max` in `soar.toml` and
restart the server.

## Test coverage

```
server/tests/test_soar_scaffold.py            5 tests   Slice 1 wire-up
server/tests/test_soar_generic_webhook.py     ~14 tests  Slice 2 backend + retry classification
server/tests/test_soar_chat_backends.py      ~12 tests  Slice 3 (slack + discord) shape + severity
server/tests/test_soar_ticketing_backends.py ~10 tests  Slice 4 (pagerduty + thehive + jira) shape + severity
server/tests/test_soar_worker.py             ~12 tests  Slice 5 end-to-end against real DB
                                  ──────────
                                  57 tests    (47 new + 5 from Slice 1 scaffold + 5 misc)
```

The 47 new SOAR tests in v1.3.0 land on top of the 180 tests
that were green at v1.2.0. The Phase 13 release reports
**227/227 server tests pass**, with all 10 Go packages
green and the 9 launch smoke checks still passing.

To re-run just the SOAR suite, point the test DB and
Redis at your local docker-compose stack (see
`docker-compose.yml` and `server/.env.example` for the
canonical env names) and run:

```bash
cd server && \
  ZAQORIN_DATABASE_URL="$ZAQORIN_TEST_DATABASE_URL" \
  ZAQORIN_REDIS_URL="$ZAQORIN_TEST_REDIS_URL" \
  python -m pytest tests/test_soar_scaffold.py \
                   tests/test_soar_generic_webhook.py \
                   tests/test_soar_chat_backends.py \
                   tests/test_soar_ticketing_backends.py \
                   tests/test_soar_worker.py -v
# 57 passed
```

The default test stack runs PostgreSQL on the local
Docker network and Redis on the loopback; production
deployments read the same env names from your secrets
manager.

## Pitfalls hit during implementation

1. **`StrictUndefined` for Jinja2 templates.** A typo in
   `{{ alrt.id }}` would silently render empty string with
   the default `Undefined`. The `generic_webhook` backend
   uses `Environment(undefined=StrictUndefined)` so the
   template parse or render fails loudly, dead-letters the
   attempt, and surfaces a clear error in
   `soar_deliveries.error`.
2. **`httpx.TimeoutException` is a subclass of
   `httpx.HTTPError`, not a separate tree.** Catch it
   explicitly alongside `httpx.NetworkError`, or a 30 s
   timeout looks like a generic exception in the audit
   log. Every backend follows the same `(httpx.TimeoutException,
   httpx.NetworkError)` pair.
3. **Dead-letter file writes are atomic.** The worker
   writes to `<file>.tmp` first and renames into place.
   A crash mid-write leaves no half-written file, and the
   replay path never reads a partial.
4. **Replay must use the worker's own queue, not bypass
   to a fresh task.** The `_PendingDelivery` item carries
   the backend, the config, the attempt counter, and the
   alert. Posting to the same queue keeps the cooldown
   tracker, the semaphore, and the persistence path
   consistent. A separate "replay" code path was rejected
   because it would have to re-implement all of those.
5. **`unknown` severity never satisfies a positive
   `severity_min`.** `severity_meets()` returns `False`
   when the alert severity is unknown, so a misconfigured
   rule that emits `severity="unknown"` is silently
   filtered out. Better than a noisy fire to Slack.
6. **`_enqueued` is per-process, not persistent.** A
   restart re-fires once for the alerts in the last 60 s.
   Combined with `cooldown_sec`, this is a one-shot
   re-fanout, not a flood.
7. **`slice 1` left six `NotImplemented` stubs in the
   registry.** Slices 2–7 replace them one at a time via
   `register()`. A backend that isn't in `soar.toml` keeps
   its stub so the registry count stays at six and the
   dashboard "view" surface is stable. This is the
   reason the `_install_backends` method only calls
   `register()` for backends that appear in the config.

## Files added / changed

**New:**

| Path | Purpose |
| --- | --- |
| `server/src/zaqorincore_server/soar/__init__.py` | Package surface: `Backend` protocol, `Alert` and `DeliveryResult` dataclasses, registry. |
| `server/src/zaqorincore_server/soar/config.py` | `load_config()`, `BackendConfig`, `SoarConfig`, severity helpers. |
| `server/src/zaqorincore_server/soar/worker.py` | `SoarWorker`: poller, queue, retry loop, dead-letter persistence, replay surface. |
| `server/src/zaqorincore_server/soar/backends/generic_webhook.py` | Slice 2 — default templated backend. |
| `server/src/zaqorincore_server/soar/backends/slack.py` | Slice 3 — Block Kit. |
| `server/src/zaqorincore_server/soar/backends/discord.py` | Slice 3 — embed. |
| `server/src/zaqorincore_server/soar/backends/pagerduty.py` | Slice 4 — Events API v2 with `dedup_key`. |
| `server/src/zaqorincore_server/soar/backends/thehive.py` | Slice 4 — alert-create API. |
| `server/src/zaqorincore_server/soar/backends/jira.py` | Slice 4 — issue-create API. |
| `server/src/zaqorincore_server/api/v1/soar.py` | `/api/v1/soar/*` router (deliveries, health, dead-letter, replay). |
| `server/src/zaqorincore_server/models/soar_delivery.py` | SQLAlchemy model for the audit table. |
| `server/migrations/versions/0003_soar_deliveries.py` | Alembic migration for `soar_deliveries`. |
| `server/config/soar.toml.example` | Annotated template — copy to `soar.toml` to enable. |
| `server/tests/test_soar_scaffold.py` | Slice 1 scaffold wire-up. |
| `server/tests/test_soar_generic_webhook.py` | Slice 2 backend. |
| `server/tests/test_soar_chat_backends.py` | Slice 3 (slack + discord). |
| `server/tests/test_soar_ticketing_backends.py` | Slice 4 (pagerduty + thehive + jira). |
| `server/tests/test_soar_worker.py` | Slice 5 worker integration tests. |
| `docs/PHASE13-soar.md` | This file. |

**Changed:**

| Path | Change |
| --- | --- |
| `server/src/zaqorincore_server/main.py` | Lifespan starts `SoarWorker` (gated on `settings.soar_enabled`); attaches to `app.state.soar_worker`. |
| `server/src/zaqorincore_server/config.py` | `Settings.soar_enabled: bool = True`. |
| `server/src/zaqorincore_server/api/v1/__init__.py` | Mounts the `soar` router under `/api/v1/soar`. |
| `CHANGELOG.md` | `[v1.3.0]` section: SOAR webhook delivery ships. |
| `ROADMAP.md` | v1.3.0 — SOAR webhook delivery ✅. |
| `docs/decisions/ADR-008-soar-webhook-delivery.md` | Status moved from Proposed to Accepted. |
