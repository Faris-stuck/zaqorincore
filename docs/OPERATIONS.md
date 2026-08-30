# Operations

This is the runbook for getting ZaqorinCore from a fresh checkout to
a working deployment that fires a real alert against a real log line.
It complements `docs/operator-guide.md` (which explains the *why*);
this page is the *how*, end to end, in copy-pasteable order.

If you only have five minutes, run sections 1, 2 and 5. If you have
twenty, add sections 3, 4 and 6. Section 7 is the reference card for
the v2.1.x operator surface (role-based auth, `--version`, the two new
MITRE ATT&CK rules). Section 8 covers the v2.2.0 Q3 Detection Pack
(five new Sigma rules) and the per-dependency health probe.

## 1. What you are deploying

ZaqorinCore has three processes:

| Process | Language | Role |
|---|---|---|
| `zaqorin-server` | Python (FastAPI) | Receives events, runs detectors, signs and ships commands, serves the web console on the same port. |
| `zaqorin-agent` | Go (single static binary) | Tails logs / watches files / runs eBPF probes on a host, ships structured events over WebSocket. |
| PostgreSQL 16 + Redis 7 | — | Persistent state (hosts, alerts, actions, evidence) and the event stream consumer groups. |

Agent -> Server uses outbound TCP 8000 (WebSocket). Operator -> Server
uses the same port for the console and the REST API. No other inbound
ports are required.

## 2. One-time host prep

You need:

- Linux x86_64 for the server (Ubuntu 22.04+ tested).
- Go 1.22+ on the build host (for the agent).
- Python 3.11+ on the server host.
- PostgreSQL 16+ with the `zaqorin` and `zaqorin_test` databases.
  The first run of the server creates them and applies Alembic
  migrations; you only need the role.
- Redis 7+ with Streams enabled.

Open the firewall:

- Agent hosts -> server: TCP 8000 outbound.
- Operator laptop -> server: TCP 8000 outbound (or via Tailscale).

That is the whole list. No SaaS, no outbound telemetry, no phone-home.

## 3. Build and run the server

```bash
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore/server
python -m venv .venv
source .venv/bin/activate
pip install -e .

export ZAQORIN_DATABASE_URL='postgresql+asyncpg://zaqorin:CHANGE_ME@127.0.0.1:5432/zaqorin'
export ZAQORIN_REDIS_URL='redis://127.0.0.1:6379/0'
export ZAQORIN_DEPLOYMENT_MODE=individual   # or: startup, enterprise

zaqorin-server
# -> INFO  Uvicorn running on http://0.0.0.0:8000
```

Open `http://<server>:8000/` in a browser. The console renders with
zero alerts (empty state). The /healthz and /readyz probes return
200 once the DB and Redis pools are warm; the launch smoke confirms
both without docker:

```bash
python scripts/smoke_launch.py
# -> 9/9 checks PASS
```

## 4. Build and run the agent

```bash
cd ../agent
make build
# -> bin/zaqorin-agent  (~5 MB static binary)

cp agent.example.toml /etc/zaqorin/agent.toml
sudoedit /etc/zaqorin/agent.toml
# Set:
#   server_url = "ws://<your-server>:8000/api/v1/stream"
#   [[log_source]]
#   path = "/var/log/auth.log"
#   tag = "auth"

./bin/zaqorin-agent --config /etc/zaqorin/agent.toml
```

The agent prints `connected to <server>` on stdout and the console
flips the host to `online` in the Agents view. Run it as a systemd
unit (see `packaging/zaqorin-agent.service`) in production. The agent
binary also accepts `--version` (added in v2.1.1) for ops scripts:

```bash
./bin/zaqorin-agent --version
# -> zaqorin-agent 2.1.4
```

## 5. Verify with a sample Sigma rule

This is the test that proves the whole loop. Drop the new v2.1.2
T1059.004 rule (Unix shell one-liner) on the server, then trigger
the pattern locally and confirm an alert fires.

The rule ships at
`server/rules/builtin/mitre_attack/T1059_unix_shell_exec.yml`. It
matches `bash -c "..."`, `sh -c '...'`, and the same for `dash`,
`zsh`, `ksh` — the classic exploit-chain / web shell pattern. Filter
suppresses the empty interactive shell.

Trigger it on the agent host:

```bash
ssh user@agent-host 'bash -c "id; uname -a"'
```

Within two seconds the console shows a `high` alert tagged
`attack.t1059`, and `GET /api/v1/alerts` returns one row with the
dedup key `<user>:<source_ip>`.

Repeat with the v2.1.3 T1053.003 rule (cron persistence):

```bash
ssh user@agent-host 'echo "* * * * * /tmp/x.sh" | crontab -'
```

Same loop: alert within two seconds, level `high`, tags
`attack.t1053` + `attack.persistence`. If neither fires, the agent
is not sending the event shape the rule expects; see the
troubleshooting checklist in `docs/PHASE13-soar.md`.

## 6. Lock down the API (v2.1.0 IMP-1)

The role-based auth split replaces the legacy `ZAQORIN_API_KEY`
binary check with three named roles:

| Role | Verb allowlist | Typical caller |
|---|---|---|
| `read` | GET, HEAD, OPTIONS | Dashboard, hunt queries, triage tooling. |
| `write` | Any verb | Admins, legacy F6 key, automation that mutates. |
| `ingest` | POST only | Push-only agents / CDN webhooks that never read back. |

Set one or more of the role env vars (the legacy `ZAQORIN_API_KEY`
still works and maps to `write`):

```bash
export ZAQORIN_API_KEY_READ='r_<random_32_bytes>'
export ZAQORIN_API_KEY_WRITE='w_<random_32_bytes>'
export ZAQORIN_API_KEY_INGEST='i_<random_32_bytes>'
```

If no env vars are set, the server runs in dev mode (open with a
single startup warning) so a fresh install still works without
ceremony. In production set at least `ZAQORIN_API_KEY_WRITE` and
`ZAQORIN_API_KEY_INGEST`.

The current role for a given key is visible to the dashboard via
`GET /api/v1/auth/whoami` (returns 401 if no role can be derived).
Key lookup is constant-time (`hmac.compare_digest`) — no timing
oracle on role guessing.

## 7. Daily ops reference

Quick checks:

```bash
# Server health
curl -fsS http://<server>:8000/healthz
curl -fsS http://<server>:8000/readyz

# Agent version on a host
ssh <host> zaqorin-agent --version

# Count alerts in the last hour
curl -fsS -H "X-API-Key: $ZAQORIN_API_KEY_READ" \
  'http://<server>:8000/api/v1/alerts?since=1h' | jq '.items | length'

# Replay a Sigma rule against history (read role)
curl -fsS -H "X-API-Key: $ZAQORIN_API_KEY_READ" \
  -X POST 'http://<server>:8000/api/v1/hunt/run' \
  -d '{"rule_id":"builtin-mitre-attack-T1059-unix-shell-exec","days":7}'
```

Where things live:

| Path | Purpose |
|---|---|
| `/etc/zaqorin/agent.toml` | Agent config. |
| `packaging/zaqorin-agent.service` | systemd unit. |
| `server/rules/builtin/` | Sigma rules shipped with the binary. |
| `server/rules.local_overrides/` | Operator additions / overrides; wins over builtins by id. |
| `scripts/smoke_launch.py` | DB-free launch smoke (no docker, <1 s). |
| `scripts/smoke.sh` | Live-stack end-to-end smoke (needs running server + agent). |
| `docs/PHASE*-*.md` | Phase-level design notes; the rationale behind each section of the operator surface. |

When in doubt, the phase doc that covers the area you are touching is
the authoritative design reference; this runbook is the procedure.

## 8. v2.2.0 — Q3 Detection Pack + per-dep health probe

v2.2.0 ships **five new Sigma rules** for the MITRE ATT&CK techniques
operators asked for the most after v2.1.x. All five are in
`server/rules/builtin/mitre_attack/` and ship enabled by default.

| Rule file | MITRE | What it catches |
|---|---|---|
| `T1059_unix_shell_exec.yml` | T1059.004 | `bash -c "..."`, `sh -c '...'`, `dash`, `zsh`, `ksh` one-liners — classic exploit-chain / web shell pattern. |
| `T1053_cron_persistence.yml` | T1053.003 | Writes to `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/*`; `crontab -` invocations from a non-daemon parent. |
| `T1070_file_deletion.yml` | T1070.004 | `rm -rf`, `shred`, `wipe`, `srm`, `find … -delete` targeting sensitive paths (`/var/log`, `/etc`, `/root`, history files, journald). |
| `T1548_setuid_setgid_abuse.yml` | T1548.001 | `chmod u+s`, `chmod g+s`, `install -m … -o root`, `cp/mv /bin/… && chmod 4…` — SUID/SGID persistence. |
| `T1053_at_scheduled_task.yml` | T1053.005 | `at`, `atq`, `atrm`, `batch`, and direct writes to `/var/spool/at*` — one-shot scheduled execution. |

Trigger each one on the agent host to confirm the loop end-to-end:

```bash
# T1059.004 — unix shell one-liner
ssh user@agent-host 'bash -c "id; uname -a"'

# T1053.003 — cron persistence
ssh user@agent-host 'echo "* * * * * /tmp/x.sh" | crontab -'

# T1070.004 — destructive file deletion
ssh user@agent-host 'shred -vfzu /var/log/auth.log.1'

# T1548.001 — SUID abuse
ssh user@agent-host 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash'

# T1053.005 — at-scheduled task
ssh user@agent-host 'echo "id > /tmp/p.txt" | at 02:00'
```

Each one fires within two seconds; the alert lands tagged
`attack.tNNNN`, level `high`, dedup key `<user>:<source_ip>`. If the
`/healthz/deps` probe below is green but the rule never fires, the
agent is not sending the event shape the rule expects — see
`docs/PHASE13-soar.md` for the event-shape checklist.

### 8.1 Per-dependency health probe

v2.1.6 added `/healthz/deps` alongside the existing `/healthz` and
`/readyz`. It returns one row per dependency (Postgres pool, Redis
pool, migration head, alert backlog) with structured status for ops
dashboards and on-call scripts:

```bash
curl -fsS http://<server>:8000/healthz/deps | jq
```

Example healthy response:

```json
{
  "status": "ok",
  "deps": [
    {"name": "postgres", "status": "ok", "latency_ms": 3, "pool_size": 5},
    {"name": "redis",    "status": "ok", "latency_ms": 1, "pool_size": 10},
    {"name": "migrations", "status": "ok", "head": "head_2026_08_30"},
    {"name": "alerts",   "status": "ok", "backlog": 0}
  ]
}
```

Use it as a Prometheus blackbox target, an Alertmanager receiver, or
just a curl loop from cron:

```bash
# /etc/cron.d/zaqorin-health (every minute)
* * * * * www-data curl -fsS http://127.0.0.1:8000/healthz/deps \
  | jq -e '.status == "ok"' >/dev/null \
  || echo "zaqorin deps degraded: $(date)" | mail -s "zaqorin degraded" ops@example.com
```

`status: "degraded"` fires when any single dep is slow, down, or
backlogged; treat it as a page-able signal in the same rotation as
`/healthz` 5xx.