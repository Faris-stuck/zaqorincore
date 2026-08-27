# Quick start

## Development (reusing host containers)

The dev loop expects `zc-postgres` (postgres:16-alpine) on
`127.0.0.1:25432` and the existing `laporin-redis` container.

```bash
# 1. Create the dev DB if it doesn't exist
docker exec zc-postgres psql -U zaqorin -d postgres \
    -c 'CREATE DATABASE zaqorin;'

# 2. Install deps + apply migrations
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env  # edit ZAQORIN_DATABASE_URL password (***) as needed
alembic upgrade head

# 3. Run the server
zaqorin-server
# or
uvicorn zaqorincore_server.main:app --reload
```

## End-to-end smoke

The `scripts/smoke.py` script opens a WebSocket to the running
server, sends a HELLO + 3 EVENT + BYE, and verifies rows in the
DB. Run it against a running server:

```bash
source .venv/bin/activate
python scripts/smoke.py
```

## Tests

```bash
source .venv/bin/activate
export ZAQORIN_DATABASE_URL=postgresql+asyncpg://zaqorin:***@127.0.0.1:25432/zaqorin_test
export ZAQORIN_REDIS_URL=redis://127.0.0.1:6379/15
pytest
```

## Production (docker compose)

```bash
docker compose up -d --build
# Then apply migrations inside the server container:
docker compose exec server alembic upgrade head
```

## API

- `GET  /healthz` — liveness
- `GET  /readyz`  — readiness (pings DB + Redis)
- `WS   /ws/agent` — agent v0.1.0 wire contract
- `GET  /api/v1/hosts` — paginated list
- `GET  /api/v1/hosts/{agent_id}` — single host
- `GET  /api/v1/events?since=&until=&host_id=&source=` — filtered events
- `GET  /api/v1/alerts` — empty in Phase 2; Phase 3 will populate
- `GET  /docs` — auto-generated OpenAPI
