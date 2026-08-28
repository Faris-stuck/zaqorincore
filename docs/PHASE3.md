# Phase 3 — Detector pipeline (v0.3.0)

## Goal

A background detector pipeline that consumes events from the
`zaqorin:events` Redis stream, runs registered detector rules
against them, and persists `Alert` rows when a rule fires.

## What shipped

### Detector framework (`server/src/zaqorincore_server/detectors/`)

- **`base.py`** — `Detector` protocol, `DetectorContext` (gives
  the detector access to Redis + settings + a session
  factory), `DetectionResult` (what a detector returns), and
  `ParsedEvent` (the minimal projection of a wire event the
  detector sees).
- **`registry`** (`__init__.py`) — `BUILTIN_DETECTORS` list.
  Adding a new detector = drop a new file with a `DETECTOR`
  instance and append it to the list. No DB migration.
- **`ssh_bruteforce.py`** — the first detector. See below.
- **`alert_service.py`** — `write_alert(session_factory,
  ...)`. Plain insert; dedup is at the detector layer.
- **`runner.py`** — owns the XREADGROUP loop. Started in
  FastAPI lifespan as a background task, cancelled on
  shutdown.

### `ssh_bruteforce` detector

Sliding-window rule:

> When a single source IP generates at least
> `ZAQORIN_SSH_BRUTEFORCE_THRESHOLD` (default 5) failed
> SSH-login events inside
> `ZAQORIN_SSH_BRUTEFORCE_WINDOW_SEC` (default 60s) from
> the same host, fire one `medium` alert and cool down for
> `ZAQORIN_SSH_BRUTEFORCE_COOLDOWN_SEC` (default 300s).

State per (host_id, source_ip) lives in Redis as a sorted
set:

- key: `zc:rule:ssh_bruteforce:<host_id>:<ip>`
- value: `event_id → unix_timestamp`
- operations per event: `ZREMRANGEBYSCORE` to drop old
  entries, `ZADD` to add the new event, `ZCARD` to count
  remaining entries, `EXPIRE` to clean up
- cooldown key: `<key>:cooldown` (SET NX EX) so the same
  IP doesn't spam alerts

The detector is **fail-open** on Redis errors — it logs
the error and passes the event through. Better than
locking the stream.

Source IP is read from `event.metadata["source_ip"]` if
present; otherwise the detector falls back to a regex on
the raw auth.log line.

A failed login is identified by `event.metadata["status"]
in {"failed","failure","invalid"}` or by the regex
`Failed password for (?:invalid user )?\S+ from <ip>`.

### Real `/api/v1/alerts`

The Phase 2 stub `[]` is replaced with a paginated,
filterable list:

```
GET /api/v1/alerts?host_id=&detector=&since=&until=&limit=
```

Response shape:
```json
{
  "items": [
    {
      "id": "uuid",
      "host_id": "uuid|null",
      "detector": "ssh_bruteforce",
      "severity": "medium",
      "summary": "...",
      "detail": { ... },
      "created_at": "RFC3339",
      "acknowledged_at": "RFC3339|null"
    }
  ],
  "next_before": "RFC3339|null"
}
```

The dedup signature and cooldown are stored inside
`detail.dedup_key` and `detail.cooldown_sec` so the
dashboard can render the source IP and the cooldown
window without a separate schema change.

### Lifespan integration

The detector runner starts as an `asyncio.create_task` in
the FastAPI lifespan, only when `ZAQORIN_STREAMS_ENABLED`
and `ZAQORIN_DETECTORS_ENABLED` are both true (both
default to true). The task is cancelled on shutdown, and
the lifespan awaits the cancellation so the runner has
a chance to ack in-flight stream messages before the
process exits.

## E2E verified

- **28/28 pytest unit tests pass** (was 17 in v0.2.0; +5
  detector rule tests, +2 alert writer tests, +3 alerts
  API tests, +1 test for the alerts-empty stub update).
- **`scripts/smoke_detector.py`** — sends HELLO + 5
  failed-login events from `203.0.113.42` + BYE over
  WebSocket. Within ~1s, `GET /api/v1/alerts` returns
  the `ssh_bruteforce` alert with all expected fields.
- **`scripts/smoke.py`** (Phase 2 regression) — still
  passes; events with `status != "failed"` do **not**
  trigger alerts, confirming the detector's filter.

## Pitfalls / lessons

- **Function-scoped event loop** in pytest
  (`asyncio_default_fixture_loop_scope = "function"`) is
  required for the new detector tests that use real
  Redis. The previous `session` scope was a leftover
  from the Phase 2 TestClient deadlock workaround and is
  no longer needed.
- **`app_client` fixture now depends on `engine`** so
  that the FastAPI app sees the test database schema
  (the singleton `zdb._engine` is wired by the
  `engine` fixture).
- **Host-id leakage in detector tests**: every
  `_make_event()` in the detector test used a fresh
  `uuid.uuid4()` for `host_id`, which meant every event
  went to a different Redis key. **Fix**: pin a single
  `_TEST_HOST_ID` for the module.
- **FK violation in alert writer tests**: `host_id` is
  declared nullable in the model, but the tests were
  passing a random `host_id` without first inserting
  the corresponding host row. **Fix**: insert a host
  row before writing the alert in tests that supply a
  `host_id`.
- **Two-tuple select into alert writer**: when calling
  `select(Event.raw, Event.metadata_)` the result row
  shape depends on which type you used to declare the
  column. SQLAlchemy's `mapped_column("metadata", JSONB)`
  exposes it as `Event.metadata_` in Python.

## What's NOT in this phase

- **No auto-response.** Alerts only. Phase 4 wires
  command frames back to the agent (HMAC-signed).
- **No new detector types.** The framework supports
  more (`web_attack`, `network_scan`, `c2_beaconing`
  from `ARCHITECTURE.md`); they ship when we need them.
- **No DB-backed detector config.** Thresholds are
  env-var-only. Phase 5 may move them to
  `detector_configs` for live tuning.
- **No `/api/v1/alerts/{id}/ack` endpoint.** That's a
  dashboard concern (Phase 5+).

## DoD checklist

- [x] `detectors/` package with `base.py` +
  `ssh_bruteforce.py` + `runner.py` + `alert_service.py`
- [x] Lifespan wiring (start on startup, cancel on
  shutdown)
- [x] Real `/api/v1/alerts` with filtering + pagination
- [x] E2E with the running server: WS → DB → detector →
  alert (smoke_detector.py)
- [x] 28/28 pytest pass
- [x] `docs/PHASE3.md`, `CHANGELOG` v0.3.0, `ROADMAP`
  Phase 3 ✅
- [x] Tagged v0.3.0 + pushed
