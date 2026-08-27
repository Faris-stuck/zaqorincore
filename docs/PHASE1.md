# Phase 1 — Operator Guide

> **Status:** v0.1.0 (Phase 1 MVP). The agent tails log files and ships
> each new line to a WebSocket server. No detection, no response. That
> is Phase 3 / Phase 4.

This guide covers the install, run, and troubleshoot path for an
operator who has never seen ZaqorinCore before.

## 1. What you need

- A Linux host (amd64 or arm64) with `systemd` (any modern distro).
- A WebSocket server to ship to. For a first test, `websocat` works
  as a one-line echo server — see the smoke test below.
- A regular user account with `sudo` for the install.
- About 5 MB of disk for the static binary.

## 2. Install

### 2.1 Build from source (recommended for now)

```bash
# Clone
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore/agent

# Build a static binary
make build
# -> bin/zaqorin-agent  (~5 MB, statically linked, stripped)
```

### 2.2 Install the binary

```bash
sudo install -m 0755 bin/zaqorin-agent /usr/local/bin/zaqorin-agent
```

### 2.3 Drop a config

```bash
sudo install -d -m 0755 -o root -g root /etc/zaqorin
sudo cp ../agent.example.toml /etc/zaqorin/agent.toml
sudo chmod 0600 /etc/zaqorin/agent.toml
sudoedit /etc/zaqorin/agent.toml
```

The minimum required fields are `server_url` and at least one
`[[log_source]]` entry:

```toml
server_url = "wss://zaqorin.example.com/api/v1/events"
log_level  = "info"

[[log_source]]
name = "auth"
path = "/var/log/auth.log"
```

See `agent.example.toml` at the repo root for every field with
inline comments.

### 2.4 Install the systemd unit

```bash
sudo cp packaging/zaqorin-agent.service /etc/systemd/system/zaqorin-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now zaqorin-agent
```

The unit runs as `root` because `/var/log/auth.log` is only
readable by root on most distros. Phase 4 will tighten this with
`CapabilityBoundingSet=CAP_NET_ADMIN` only.

## 3. Verify

```bash
sudo systemctl status zaqorin-agent      # service is active
sudo journalctl -u zaqorin-agent -f      # live logs (JSON, one per line)
```

A healthy startup looks like:

```
{"time":"2026-08-28T05:38:43Z","level":"INFO","msg":"zaqorin-agent: generated new agent_id","agent_id":"..."}
{"time":"2026-08-28T05:38:43Z","level":"INFO","msg":"transport: connected","agent_id":"...","url":"wss://..."}
```

If you set `agent_id = "auto"` (the default), the agent will
generate a UUID v4 on first start and persist it to
`/var/lib/zaqorin-agent/agent_id`. The same host will keep that
ID across restarts.

## 4. Quick smoke test (no server needed)

If you just want to see the agent work without standing up the
central server, `websocat` makes a one-liner echo server:

```bash
# Terminal 1 — echo server
websocat -s 127.0.0.1:9001

# Terminal 2 — config that points to it
cat > /tmp/agent.toml <<EOF
server_url = "ws://127.0.0.1:9001"
agent_id   = "auto"
log_level  = "info"
state_dir  = "/tmp/zaqorin-state"

[[log_source]]
name = "test"
path = "/tmp/zaqorin-test.log"
EOF
mkdir -p /tmp/zaqorin-state

# Terminal 3 — agent
zaqorin-agent --config /tmp/agent.toml --log-format text

# Terminal 4 — append a line; you should see it land in Terminal 1
echo "$(date -Ins) hello" >> /tmp/zaqorin-test.log
```

For a more thorough end-to-end check, run the bundled smoke script:

```bash
cd zaqorincore/agent
make smoke
# -> builds the agent, brings up websocat, writes 3 lines, asserts
#    the server received 1 HELLO + 3 EVENT frames, then tears down.
```

## 5. Common errors

| Symptom | Cause | Fix |
|---|---|---|
| `config: server_url scheme must be ws:// or wss://` | Operator wrote `http://` or `https://` | Change to `ws://` (plain) or `wss://` (TLS). The agent never speaks plain HTTP. |
| `config: at least one [[log_source]] entry is required` | Config has zero `[[log_source]]` blocks | Add at least one block. |
| `config: log_source[0] (auth): path must be absolute, got "auth.log"` | Relative path | Use the full path, e.g. `/var/log/auth.log`. |
| `transport: connection lost, reconnecting` repeated | Cannot reach `server_url` | Check the URL, network, and TLS. The agent retries with exponential backoff (1s, 2s, 4s, ..., cap 30s). |
| `tail: initial open failed, will retry` | Log file does not exist at agent start | Expected if the service that writes the file is down. The agent will keep retrying with backoff. |
| Service starts then immediately stops | `systemd-analyze verify` would have shown the cause | Run `sudo journalctl -u zaqorin-agent -n 50` and look for the first error line. |

## 6. Log destinations

| Stream | Default location | Override |
|---|---|---|
| stdout/stderr (JSON) | captured by `journald` | `--log-format text` for a human-readable stream |
| runtime state (agent_id) | `/var/lib/zaqorin-agent/` | `state_dir` in config |
| structured agent logs (future) | `/var/log/zaqorin-agent/` | `LogsDirectory=` in the unit |

## 7. Uninstall

```bash
sudo systemctl disable --now zaqorin-agent
sudo rm /etc/systemd/system/zaqorin-agent.service
sudo rm /usr/local/bin/zaqorin-agent
sudo rm -rf /etc/zaqorin /var/lib/zaqorin-agent /var/log/zaqorin-agent
sudo systemctl daemon-reload
```

## 8. What Phase 1 does NOT do

- It does not parse log lines into structured fields. The full
  `raw` line is shipped to the server.
- It does not detect anything. That is Phase 3 (SSH brute-force).
- It does not block anything. That is Phase 4 (HMAC-signed
  `block_ip` commands, iptables / nftables).

If you point the agent at a Phase 1 server (a generic WebSocket
echo), the only thing the server should do is **log the frames
it receives**. Anything fancier is on the Phase 2 / 3 roadmap.

## 9. Where things live

```
/usr/local/bin/zaqorin-agent           # the static binary
/etc/zaqorin/agent.toml                # your config (mode 0600)
/etc/zaqorin/zaqorin-agent.env         # optional: secrets via env
/etc/systemd/system/zaqorin-agent.service
/var/lib/zaqorin-agent/                # state (agent_id)
/var/log/zaqorin-agent/                # future: agent's own structured logs
```

## 10. Next steps

When Phase 2 (the FastAPI central server) lands, the same
`zaqorin-agent` binary will be able to point at it without any
config change beyond `server_url`. Phase 1 is intentionally
forward-compatible: the wire frames (`hello`, `event`, `bye`,
`command`) are stable and the schema is versioned.
