# Phase 2 — Server (v0.2.0)

## Goal

A central server that accepts the Phase 1 WebSocket stream from any
`zaqorin-agent` v0.1.0+, persists events to PostgreSQL, fans them
through Redis Streams, and exposes a read-only REST API.

Phase 2 deliberately does **not** include detection or auto-response
— those land in Phase 3 and Phase 4 respectively.

## What ships

- **FastAPI** server with:
  - `GET /healthz` (liveness) and `GET /readyz` (readiness: DB + Redis)
  - `WS /ws/agent` accepting the v0.1.0 wire contract (HELLO / EVENT / BYE)
  - `GET /api/v1/hosts` and `GET /api/v1/hosts/{agent_id}`
  - `GET /api/v1/events?since=&until=&host_id=&source=`
  - `GET /api/v1/alerts` (returns `[]` — Phase 3 will populate)
  - `GET /docs` (auto-generated OpenAPI)
- **PostgreSQL 16** schema with 4 tables:
  - `hosts` (one row per agent; `id` is the agent UUID, last_seen, version)
  - `events` (one row per event; PK is the wire-provided UUID for idempotency)
  - `alerts` (placeholder; Phase 3 detectors will insert here)
  - `actions` (placeholder; Phase 4 will insert signed actions here)
- **Redis Streams** publisher: every persisted event is also `XADD`'d
  to `zaqorin:events` with consumer group `zaqorin-detectors` (Phase 3).
- **Alembic** migrations under `server/migrations/`.
- **17 unit + integration tests**, all green.
- **End-to-end smoke** (`scripts/smoke.py`) — verified against the
  real `zaqorin-agent` v0.1.0 binary.

## What does NOT ship (intentional)

- No detection rules / thresholding (Phase 3).
- No signed commands / auto-response (Phase 4).
- No dashboard (Phase 2.5 or 3).
- No authentication on the WebSocket — agents are identified by
  the `agent_id` they present. A future Phase 2.1 will add
  per-agent shared-secret auth.

## Wire contract (v0.1.0 — unchanged in Phase 2)

The server accepts the exact frames the v0.1.0 agent sends:

```json
// HELLO (first frame on every connection)
{"type": "hello", "agent_id": "<uuid>", "version": "1.0"}

// EVENT (zero or more)
{"type": "event", "event": {
    "schema": "1.0",
    "id": "<uuid>",
    "timestamp": "<RFC3339Nano>",
    "host_id": "<uuid>",          // == agent_id
    "source": "auth",
    "raw": "Accepted publickey for foo",
    "metadata": {}
}}

// BYE (graceful shutdown)
{"type": "bye", "reason": "agent stopping"}
```

Server→client COMMAND frames are accepted by the parser but
**logged only** in Phase 2. Phase 4 will sign and apply them.

## Operational notes

- The dev loop uses an **existing** `zc-postgres` container on
  `127.0.0.1:25432` (the Cogniflux production postgres owns
  `5432`, so we collide-avoid). Production deploys should use
  the `docker-compose.yml` here for a self-contained stack.
- Redis is **shared** with the existing `laporin-redis` instance
  using database number 5 (db0 holds 422 production keys, must
  not be touched). Production should deploy its own Redis.
- The server is **stateless** beyond the DB + Redis connection
  pools. Multiple replicas can run side-by-side; consumer-group
  load balancing happens in Phase 3.

## Testing

- 17 unit + integration tests, all green in ~4.5s.
- 2 service-layer tests for host upsert + event persist.
- 1 service test for idempotency on duplicate event ids.
- 2 WebSocket handler tests (full hello+event+bye persistence,
  rejection of non-hello first frame).
- 8 schema tests for the Pydantic v2 wire format.
- 3 health-API tests.
- 1 end-to-end `scripts/smoke.py` exercising a real uvicorn +
  `zaqorin-agent` v0.1.0 binary + a real `agent_id`.

## What's next

Phase 3 will populate `alerts` by consuming `zaqorin:events` from
Redis Streams and applying thresholding / pattern-detection rules.
Phase 4 will sign and emit COMMAND frames back to agents.
