# Phase 3 — Detector pipeline (v0.3.0)

## Goal

A background detector pipeline that consumes events from the
`zaqorin:events` Redis stream, runs registered detector rules
against them, and persists `Alert` rows when a rule fires. The
pipeline lives **in the server process** (FastAPI lifespan), not a
separate process, so the Phase 2 deploy story stays simple.

## Locked scope

- One detector: **`ssh_bruteforce`**.
  Sliding-window rule over `auth.log`-style events: at least
  `threshold` (default 5) failed SSH login events from the same
  source IP within `window_sec` (default 60s) → fire a
  `medium` severity alert.
- Rule state lives **in Redis** (sorted set per source IP, scored
  by event timestamp, trimmed by window) so multiple server
  processes share state correctly later.
- Consumer: Redis Streams `XREADGROUP` loop, `consumer name =
  zaqorin-detector-<pid>`, block=1000ms, count=100, manual XACK
  after the detector succeeds.
- Pipeline started in FastAPI lifespan alongside the existing WS
  server. Config flag `detectors_enabled` (default `True`); tests
  set it to `False` so they don't leak a background loop.
- Failure isolation: a detector that throws is logged and the
  message is still acked (otherwise a single bad rule blocks the
  stream). Add an in-memory `detector_errors_total` counter for
  the future `/metrics` endpoint.
- REST: `GET /api/v1/alerts?since=&until=&host_id=&detector=`
  replaces the Phase 2 empty stub. The schema already exists; we
  just wire it.

## Explicitly NOT in scope

- **Auto-response (Phase 4)** — alerts only, no commands sent back
  to agents in this phase.
- **More detector types** — only `ssh_bruteforce` ships in
  v0.3.0. Adding a second detector = new file under
  `server/src/zaqorincore_server/detectors/`. The framework is
  plugin-friendly by design.
- **Detector config in DB** — rule thresholds are settings on
  `detector_ssh_bruteforce_*` env vars. Phase 5 may move them
  to DB-backed `detector_configs` for live tuning.
- **Per-detector rate-limit / circuit breaker** — just log+ack
  on error.
- **Multi-process scaling** — the consumer group already supports
  it (just add a second server process). We don't ship the
  deployment story for that until the dashboard exists.

## Wire-level event shape (recap)

The agent's `event.metadata` field is a flat `dict[str,str]`. The
`ssh_bruteforce` detector looks at events where:

- `source == "auth"` (or any source whose `raw` matches an SSH
  "Failed password" line) **AND**
- `metadata["status"] == "failed"` (we'll have the Phase 1 agent
  emit this; if absent the detector falls back to regex on
  `raw`).

The `source_ip` is read from `metadata["source_ip"]` (Phase 1
agent already fills this) or parsed from `raw` as a fallback.

## Detector contract

```python
class Detector(Protocol):
    name: str
    async def on_event(self, event: dict, ctx: "DetectorContext") -> list[DetectionResult]: ...
```

`DetectorContext` exposes:
- `redis` — async Redis client (for sliding-window state)
- `settings` — server settings
- `session_factory` — for writing Alert rows
- `log` — structlog bound logger

## DoD

- [x] `detectors/` package with `base.py` (Detector protocol +
  context) and `ssh_bruteforce.py` (the rule).
- [x] `detectors/runner.py` — async task that owns the
  XREADGROUP loop, dispatches events, writes alerts.
- [x] `detector/alert_service.py` — function that inserts an
  Alert row + idempotency (don't double-write if same
  (host_id, source_ip, window_start) arrives twice).
- [x] Lifespan wiring: start runner task on startup, cancel on
  shutdown. Graceful stop waits for current event to finish.
- [x] `/api/v1/alerts` real implementation (paginated,
  filterable).
- [x] E2E: feed 6 SSH failed-login events (same source IP,
  within window) via the running server, assert 1 alert row
  appears in DB.
- [x] pytest unit: rule scoring logic + idempotency of
  alert writer + (optional) integration test of runner.
- [x] `docs/PHASE3.md` + `CHANGELOG` v0.3.0 + `ROADMAP`
  Phase 3 ✅.
- [x] Tag v0.3.0 + push.

## Risks

- **Detached background task on lifespan shutdown** — the loop
  uses an `asyncio.CancelledError` boundary; tests must not
  leak the task.
- **Alert spam** — if the threshold is too low we emit an alert
  per failed attempt. Mitigation: collapse consecutive windows
  with a 5-min cooldown per `(host_id, source_ip)`.
- **Rule state in Redis** — if Redis is down, the rule degrades
  to "always allow" (fail-open) for that event. Better than
  locking the stream.
- **Rule state in Redis** (other angle) — for `ssh_bruteforce`
  we use `ZADD/ZRANGEBYSCORE/ZREMRANGEBYSCORE` per source IP.
  Key format: `zc:rule:ssh_bruteforce:<host_id>:<ip>`. TTL on
  the key = 5×window so old IPs disappear.
