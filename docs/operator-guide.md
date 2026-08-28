# Operator guide

This is the **one page** an operator needs to get from a fresh checkout
to a working ZaqorinCore deployment. The phase docs go deeper; this
guide tells you what to do and where to look for the "why".

## 0. What you're deploying

ZaqorinCore has three moving parts:

```
┌────────────────────┐    WebSocket     ┌───────────────────────┐
│  AGENT (per host)  │ ───────────────▶ │  CENTRAL SERVER       │
│  Go single-binary  │   events stream  │  FastAPI + Postgres   │
│  5 MB              │ ◀─────────────── │  + Redis Streams      │
└────────────────────┘   commands back  └───────────────────────┘
                                                 │
                                                 ▼
                                        ┌────────────────┐
                                        │  WEB CONSOLE   │
                                        │  http://:8000/ │
                                        │  (SPA, same    │
                                        │  FastAPI)      │
                                        └────────────────┘
```

- **Agent** watches the host's logs and files, ships structured events.
- **Server** runs detectors, fires alerts, decides what to do, and
  sends commands back to the agent.
- **Console** is the operator UI — same process as the server, served
  from `/` on the same port as the API.

## 1. One-time host prep

You'll need:

- Linux x86_64 host for the server (Ubuntu 22.04+ tested)
- Go 1.22+ to build the agent
- Python 3.11+ for the server
- PostgreSQL 16+ (the `zaqorin_test` and `zaqorin_app_test` DBs are
  created at first run by the migration script)
- Redis 7+ (Streams; the agent's `XREADGROUP` and the detector
  runner's `XREADGROUP` both depend on consumer groups)

Network:

- Agent → Server: outbound TCP 8000 (WebSocket). The agent connects
  from every host you want to protect, so make sure 8000 is reachable
  from those hosts (Tailscale, WireGuard, internal VPN, or a public IP
  behind mTLS).
- Operator → Server: outbound TCP 8000 to read the console.

## 2. Server: build + run

```bash
# Get the code
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore

# Install Python deps
cd server
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Set env (DB + Redis)
export ZAQORIN_DATABASE_URL='postgresql+asyncpg://zaqorin:CHANGE_ME@127.0.0.1:5432/zaqorin'
export ZAQORIN_REDIS_URL='redis://127.0.0.1:6379/0'
export ZAQORIN_DEPLOYMENT_MODE=individual   # or: startup, enterprise

# Run
zaqorin-server
# -> INFO  Uvicorn running on http://0.0.0.0:8000
```

Open `http://<server>:8000/` in a browser. You should see the
ZaqorinCore console with the Alerts view, currently empty.

## 3. Smoke-test the server (no agent yet)

The server exposes a synthetic event ingest endpoint specifically for
this — `POST /api/v1/events` (the same one the agent uses, but you
can curl it directly). The `scripts/` folder has end-to-end smoke
tests; see `docs/PHASE1.md` for the original `smoke.py`.

## 4. Agent: build + run

```bash
cd ../agent
make build
# -> bin/zaqorin-agent  (~5 MB static binary)

# Edit the config
cp agent.example.toml /etc/zaqorin/agent.toml
sudoedit /etc/zaqorin/agent.toml
# Set:
#   server_url = "ws://<your-server>:8000/api/v1/stream"
#   [[log_source]]
#   path = "/var/log/auth.log"     # or any log you want to watch
#   tag = "auth"

# Run in the foreground
./bin/zaqorin-agent --config /etc/zaqorin/agent.toml
```

You should see log lines streaming to the server console, and the
Agents view in the web console should now show this host as "online".

## 5. Install the agent as a systemd service (Linux)

```bash
sudo install -m 0755 bin/zaqorin-agent /usr/local/bin/zaqorin-agent
sudo install -d -m 0755 /etc/zaqorin
sudo install -m 0600 agent.example.toml /etc/zaqorin/agent.toml
sudoedit /etc/zaqorin/agent.toml
sudo cp packaging/zaqorin-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zaqorin-agent
sudo journalctl -u zaqorin-agent -f
```

## 6. Verify the loop is closed

In the web console:

1. **Alerts** — should be empty until a rule fires. If you've
   configured `auth.log`, try `ssh admin@<host>` with the wrong
   password 6 times in 5 minutes and watch the `ssh_bruteforce`
   rule fire.
2. **Hunt** — pick `ssh_bruteforce` and "last 24h". Should show your
   test attempts even if no alert was raised.
3. **Evidence** — if you set up the `evidence_capture` action on any
   alert, the bundle should show up here. Click "Verify signature" to
   confirm the chain of custody.
4. **Canary** — create a `file` canary at `/tmp/canary.txt`. On the
   protected host, `cat /tmp/canary.txt` and watch a "touched" event
   fire within ~1 second.

## 7. Where to read next

| If you want to… | Read |
| --- | --- |
| Understand the architecture | [`ARCHITECTURE.md`](https://github.com/Faris-stuck/zaqorincore/blob/main/ARCHITECTURE.md) |
| Ship a custom rule | [PHASE6](PHASE6.md), then [PHASE8](PHASE8.md) |
| Map a rule to a control | [PHASE8 — Compliance pack](PHASE8.md) |
| Set up a canary | [PHASE7 — Deception + forensics](PHASE7.md) |
| Tune auto-response | [PHASE6 — 9 action kinds](PHASE6.md), then `docs/operator-guide.md` action reference (post-1.0) |
| Plan the upgrade path | [Roadmap](roadmap.md) |

## 8. When things go wrong

| Symptom | First thing to check |
| --- | --- |
| Agent connects then disconnects | `journalctl -u zaqorin-agent`; usually a config typo. |
| Server won't start | `zaqorin-server` exits with a stack trace → check `ZAQORIN_DATABASE_URL` and `ZAQORIN_REDIS_URL`. |
| Console loads but Alerts is empty | Check the **Hunt** view with `last 24h`. If Hunt sees events but Alerts doesn't, a detector rule is broken — see `server/rules/builtin/` and `docs/PHASE3.md`. |
| Console won't load | `curl -i http://<server>:8000/` — should return 200 + the SPA shell. If 404, the `webui/` directory wasn't found at server start; see `docs/PHASE9.md`. |
| Rule fires but no auto-response | Check `actions` permission in the agent config and the `evidence_capture` HMAC key on both sides. See `docs/PHASE4.md`. |
