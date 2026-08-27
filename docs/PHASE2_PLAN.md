# Phase 2 — Central Server (Plan, locked 2026-08-28)

> **Goal:** a self-hosted FastAPI server that accepts the WebSocket
> stream from any `zaqorin-agent` v0.1.0+, persists events to
> PostgreSQL, fans them through Redis Streams, and exposes a read-only
> REST API for the eventual dashboard. No detection, no auto-response —
> those are Phases 3 and 4.

This plan is the same shape as `docs/PHASE1_PLAN.md` was for Phase 1:
locked decisions up front so the work is mechanical.

---

## 1. Out of scope (deliberately)

- Detection logic — Phase 3
- Auto-response (`block_ip`, `kill_process`, etc.) — Phase 4
- Authentication, multi-user, RBAC — Phase 6
- HMAC command signing — Phase 4 (the server already understands the
  `command` frame envelope so the wire contract stays stable, but it
  will not actually push commands yet)
- Dashboard UI — Phase 2.5 (separate plan); for Phase 2 the API is
  the deliverable
- TLS termination — left to a reverse proxy (Caddy / nginx) in front
  of the server
- High availability, replication, multi-region — non-goal

## 2. Locked decisions

### 2.1 Stack

- **Python 3.11+** (matches the VPS runtime)
- **FastAPI 0.115+** + **uvicorn[standard]**
- **SQLAlchemy 2.0+** (async) with **asyncpg** driver
- **Alembic** for migrations
- **Pydantic v2** for schemas
- **Redis 7+** client = `redis-py` async
- **websockets** library (FastAPI's underlying WS server uses it
  via Starlette — we don't need a separate dep)
- **pytest + pytest-asyncio + httpx** for tests

### 2.2 Project layout (locked)

```
server/
├── pyproject.toml            # uv / pip-tools friendly
├── README.md
├── .env.example
├── alembic.ini
├── migrations/
│   ├── env.py
│   └── versions/
│       └── 0001_initial.py
├── src/zaqorincore_server/
│   ├── __init__.py
│   ├── main.py               # FastAPI app, lifespan, router include
│   ├── config.py             # pydantic-settings, env override
│   ├── logging.py            # structlog setup
│   ├── db.py                 # async engine, session factory
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py           # DeclarativeBase
│   │   ├── host.py           # one row per agent_id
│   │   ├── event.py
│   │   ├── alert.py          # placeholder, unused in Phase 2
│   │   └── action.py         # placeholder, unused in Phase 2
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── wire.py           # helloFrame / eventFrame / byeFrame / commandFrame (Pydantic)
│   ├── api/
│   │   ├── __init__.py
│   │   ├── health.py         # GET /healthz, /readyz
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── hosts.py      # GET /api/v1/hosts, /api/v1/hosts/{id}
│   │   │   ├── events.py     # GET /api/v1/events?host=&since=&limit=
│   │   │   └── stream.py     # WS /ws/agent  (the consumer endpoint)
│   ├── streams/
│   │   ├── __init__.py
│   │   ├── publisher.py      # publish event to "zaqorin:events" stream
│   │   └── consumer.py       # stub consumer for future detectors
│   └── service/
│       ├── __init__.py
│       ├── host_service.py   # upsert host on HELLO
│       └── event_service.py  # persist event + publish to stream
├── tests/
│   ├── conftest.py           # fixtures: app, db, redis, client, fake agent
│   ├── test_schemas.py
│   ├── test_api_health.py
│   ├── test_ws_hello_event_bye.py
│   └── test_e2e_agent_to_db.py  # boots the real v0.1.0 binary
├── scripts/
│   └── smoke.sh              # spins up server + runs agent against it
└── docker-compose.yml        # server + postgres + redis (one stack)
```

### 2.3 Wire contract — server-side (mirrors agent v0.1.0)

The server **only consumes** `hello`, `event`, and `bye` in Phase 2.
The `command` frame is **parsed** so we never break the contract, but
no command is sent back to the agent in this phase.

```json
// Server accepts from agent
{"type": "hello",  "agent_id": "<uuid>", "version": "1.0"}
{"type": "event",  "event": {"schema": "1.0", "id": "<uuid>", "timestamp": "2026-08-28T...", "host_id": "<uuid>", "source": "auth", "raw": "..."}}
{"type": "bye",    "reason": "context_canceled"}

// Server may eventually send (Phase 4, not now)
{"type": "command", "id": "<uuid>", "kind": "block_ip", "target": "1.2.3.4", "ttl_sec": 3600}
```

`host_id` on the event equals `agent_id` on the hello (Phase 1
convention). The server will store both, indexed, and treat the
agent_id as the primary host identity.

### 2.4 Database schema (initial, migration 0001)

```sql
CREATE TABLE hosts (
  id              UUID PRIMARY KEY,          -- = agent_id
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_version    TEXT,
  hostname        TEXT,                     -- filled in by the agent in a later phase
  meta            JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_hosts_last_seen ON hosts(last_seen_at DESC);

CREATE TABLE events (
  id            UUID PRIMARY KEY,            -- = event.id from the wire
  host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  schema        TEXT NOT NULL,
  occurred_at   TIMESTAMPTZ NOT NULL,        -- event.timestamp
  received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  source        TEXT NOT NULL,               -- event.source
  raw           TEXT NOT NULL,               -- event.raw
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_events_host_time ON events(host_id, occurred_at DESC);
CREATE INDEX idx_events_received  ON events(received_at DESC);

-- Phase 2 placeholders so the table doesn't have to be added in Phase 3/4:
CREATE TABLE alerts (
  id            UUID PRIMARY KEY,
  host_id       UUID REFERENCES hosts(id) ON DELETE CASCADE,
  detector      TEXT NOT NULL,
  severity      TEXT NOT NULL,  -- info | low | medium | high | critical
  summary       TEXT NOT NULL,
  detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ
);
CREATE INDEX idx_alerts_host_time ON alerts(host_id, created_at DESC);

CREATE TABLE actions (
  id            UUID PRIMARY KEY,
  host_id       UUID REFERENCES hosts(id) ON DELETE CASCADE,
  alert_id      UUID REFERENCES alerts(id) ON DELETE SET NULL,
  kind          TEXT NOT NULL,  -- block_ip | kill_process | disable_user | notify
  target        TEXT NOT NULL,
  ttl_sec       INT,
  status        TEXT NOT NULL DEFAULT 'pending',  -- pending | sent | acked | failed
  sent_at       TIMESTAMPTZ,
  acked_at      TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_actions_host_time ON actions(host_id, created_at DESC);
```

`alerts` and `actions` are created empty in this phase so we can
demonstrate the API surface; they get populated starting in
Phase 3 and Phase 4 respectively.

### 2.5 Endpoints

**Public REST (no auth in Phase 2):**

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | liveness, returns `200 OK` if the process is up |
| GET | `/readyz` | readiness, returns `200 OK` only if DB + Redis are reachable |
| GET | `/api/v1/hosts` | list of known hosts, paginated |
| GET | `/api/v1/hosts/{id}` | one host with event count and last-event timestamp |
| GET | `/api/v1/events` | recent events, `?host=&since=&limit=` |
| GET | `/api/v1/alerts` | alerts (always empty in Phase 2, but the endpoint works) |

**WebSocket:**

| Path | Caller | Direction |
|---|---|---|
| `/ws/agent` | `zaqorin-agent` | client → server (hello / event / bye) |

The server is the WebSocket **server**; the agent is the client. This
is the inverse of how `websocat` is used in the agent's smoke test —
the server has to **read** frames, not echo them.

### 2.6 Redis Streams

- Stream name: `zaqorin:events`
- One entry per persisted event, fields: `event_id`, `host_id`, `source`, `occurred_at_unix`
- Consumer group: `zaqorin-detectors` (created lazily; empty in Phase 2)
- Max length: `~ 10000` (approximate trim) — keeps memory bounded
- A stub `consumer.py` is included that reads from the stream and logs
  (no detector logic yet). It exists so the path is exercisable in
  smoke tests.

### 2.7 Configuration

`pydantic-settings`-driven, all overridable via env. `.env.example`
documents every var. `ZAQORIN_` prefix for everything server-related
to avoid colliding with the agent's `ZAQORIN_*` on the same host.

```
ZAQORIN_SERVER_HOST=0.0.0.0
ZAQORIN_SERVER_PORT=8000
ZAQORIN_LOG_LEVEL=info
ZAQORIN_DATABASE_URL=postgresql+asyncpg://zaqorin:***@127.0.0.1:5432/zaqorin
ZAQORIN_REDIS_URL=redis://127.0.0.1:6379/0
ZAQORIN_STREAM_MAXLEN=10000
```

### 2.8 Observability

- Structured JSON logs via `structlog` (one line per event)
- One log per WS frame (`type`, `host_id`, `event_id`)
- One log per HTTP request (uvicorn default + a small middleware that
  adds `request_id`)
- No Prometheus yet (Phase 2.5 / 3)

## 3. Definition of Done (Phase 2)

- [ ] `docker compose up` brings up server + postgres + redis on a clean host
- [ ] `curl /healthz` returns 200, `/readyz` returns 200
- [ ] `GET /api/v1/hosts` returns 0 rows on a fresh DB
- [ ] Run `agent/scripts/smoke.sh` against `ws://localhost:8000/ws/agent`
      and the server logs show 1 HELLO + 3 EVENT, 1 BYE
- [ ] `GET /api/v1/hosts` then returns 1 row; `GET /api/v1/events?host=<id>`
      returns 3 rows
- [ ] `pytest -q` green: 1 schema test, 2 API tests, 2 WS tests, 1 end-to-end
- [ ] `pg_dump` against the running DB shows the `hosts` and `events` tables
- [ ] No secret in any committed file (audit: grep for token/password/bearer)
- [ ] `docs/PHASE2.md` operator walkthrough written
- [ ] CHANGELOG has v0.2.0 entry, ROADMAP Phase 2 row ticked
- [ ] Tag `v0.2.0` pushed

## 4. Out-of-scope reminders

The following items are **explicitly NOT in this phase**. If they
appear in code or in the changelog, that's a bug:

- Auth, sessions, login, RBAC
- Detection rules, alerts being created
- Commands being pushed to agents
- Dashboard UI
- TLS termination (Caddy / nginx in front)
- mTLS, client cert pinning
- Background detector worker pool (just the stream consumer stub)

## 5. Risk register

| Risk | Mitigation |
|---|---|
| VPS RAM 3.6 GB OOMs when postgres + redis + server run together | Postgres + redis use Alpine images (~80 MB each); server runs in a venv, not Docker; explicit memory limits in `docker-compose.yml` |
| Server blocks under WS load (thousands of agents) | Not relevant for v0.2.0 — we expect a single-digit number of agents in testing. Realistic load test is a future phase. |
| DB schema migrations break existing data | Alembic with a single 0001 migration; we own the schema and there is no prod data yet. |
| Agent v0.1.0 wire format diverges | The server is the **canonical** wire format definition (mirrored from agent). Pydantic schemas give us validation at the boundary. |

## 6. Estimated effort

~3-4 hours of focused work. Phase 1 took longer because the
agent's tailer and transport had real correctness challenges;
Phase 2 is more straightforward plumbing.
