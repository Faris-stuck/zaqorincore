# ZaqorinCore

> **Proactive defense for the people who run their own infrastructure.**

ZaqorinCore is a self-hosted, open-core platform that **detects attacks in real time and responds automatically**. Drop a lightweight agent on each host you want to protect, point it at your central server, and the platform watches your logs, fires alerts, and blocks bad actors — usually before the second attempt lands.

The whole loop — log tail → stream → detection → alert → action — runs in **under 2 seconds**. No five-minute cron, no per-host SSH, no dashboard that takes a week to learn.

---

## What it does (today)

- ✅ **Log tailing agent (Phase 1)** — a ~5 MB Go single-binary that tails `auth.log` (or any file), packages each line as a structured event, and ships it over WebSocket. Hardened systemd unit, rotation-safe, auto-reconnect.
- 🔎 **Real-time attack detection (Phase 3)** — events stream from agent to server, detectors run as they arrive
- 🛡️ **Defensive auto-response (Phase 4)** — block IPs via `iptables`/`nftables` directly on the offending host (no shared ban list, no upstream service)
- 🧩 **Plugin detectors** — write a detector in Python, drop it in `detectors/`, restart the server
- 📊 **Multi-host dashboard** — bundled React web console at `http://<server>/`; filter alerts, run hunts, verify evidence, manage canaries from any browser on the trusted network
- 🖥️ **Web console (v0.9.0)** — alerts / hunt / evidence / canary, single page, served from the same FastAPI as the API
- 🔐 **Self-hosted** — your logs never leave your network

## What it does *not* do

- ❌ No offensive tooling. ZaqorinCore detects and blocks; it does not retaliate, exploit, or scan
- ❌ No external SaaS. Your server, your data, your rules
- ❌ No telemetry, no phone-home, no account required

## Quick start

### 1. Run the agent (Phase 1 — works today)

```bash
# Clone
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore/agent

# Build a static binary
make build
# -> bin/zaqorin-agent  (~5 MB)

# One-line echo server (separate terminal) — point the agent at it
websocat -s 127.0.0.1:9001

# Edit agent.example.toml: set server_url = "ws://127.0.0.1:9001" and
# add a [[log_source]] pointing at any file on your host.
./bin/zaqorin-agent --config ./agent.example.toml
```

For a full end-to-end check, `make smoke` brings up a websocat echo server, writes 3 lines, and asserts 1 HELLO + 3 EVENT frames arrived.

### 2. Install the agent as a systemd service (Linux)

```bash
sudo install -m 0755 bin/zaqorin-agent /usr/local/bin/zaqorin-agent
sudo install -d -m 0755 /etc/zaqorin
sudo install -m 0600 agent.example.toml /etc/zaqorin/agent.toml
sudoedit /etc/zaqorin/agent.toml         # set server_url, log sources

sudo cp packaging/zaqorin-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zaqorin-agent
sudo journalctl -u zaqorin-agent -f
```

Full operator walkthrough: [`docs/PHASE1.md`](./docs/PHASE1.md).

### 3. Central server (Phase 2 — not yet shipped)

```bash
# Will land with Phase 2
docker compose up -d
```

Then open `http://localhost:8080` for the dashboard.

## Architecture

```
┌──────────────────┐   WSS stream          ┌──────────────────────────┐
│  AGENT (host A)  │ ─────────────────────▶ │                          │
│  log tailer      │   HELLO/EVENT/BYE      │   CENTRAL SERVER         │
│  (Phase 4:       │ ◀───────────────────── │   API · detectors        │
│   iptables hook) │   block commands       │   PostgreSQL · Redis     │
└──────────────────┘                        │   React dashboard        │
┌──────────────────┐                        │                          │
│  AGENT (host B)  │ ─────────────────────▶ │   (Phase 2, not yet)     │
│  log tailer      │   events               │                          │
└──────────────────┘                        └──────────────────────────┘
```

The agent's wire frames (`hello`, `event`, `bye`, `command`) are
versioned and forward-compatible — Phase 1 ships the transport,
Phase 2 adds the server that consumes it. Details in
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

## Roadmap snapshot

| Phase | What ships | Status |
|---|---|---|
| **1** | Go agent — log tailer, WebSocket push, systemd | ✅ Shipped (v0.1.0) |
| **2** | Central server (FastAPI + PostgreSQL + Redis) | ✅ Shipped (v0.2.0) |
| **3** | Detector plugin: SSH brute-force | ✅ Shipped (v0.3.0) |
| **4** | Auto-response: agent-side nftables block + HMAC | ✅ Shipped (v0.4.0) |
| **5** | 3-tier runtime (home / SMB / enterprise) | ✅ Shipped (v0.5.0) |
| **6** | 9 action kinds + Sigma-compatible rule engine | ✅ Shipped (v0.6.0) |
| **7** | Deception (4 canary kinds) + evidence locker (HMAC + SHA-256, key rotation) | ✅ Shipped (v0.7.0) |
| **8** | Compliance pack — 51 rules across 4 frameworks (ISO 27001, NIST 800-53, PCI DSS 4.0, UU PDP) + MITRE ATT&CK | ✅ Shipped (v0.8.0) |
| **9** | Web console (alerts / hunt / evidence / canary) | ✅ Shipped (v0.9.0) |
| **10** | Docs site + launch smoke + HN post | ✅ Shipped (v1.0.0) |
| **26** | WebUI Agents: zero-terminal onboarding (Agent Provisioner, Rule Studio, Source Connector) | ✅ Shipped (v3.1.0) |
| **29** | T1583.001 Domain Acquisition Detection Pack — 5 precision Sigma rules + Levenshtein engine | ✅ Shipped (v3.2.0) |

**v1.0.0 is the first production-ready release.** 170/170 server
tests pass. 10/10 Go packages pass. 9/9 launch smoke checks pass.

## Detection coverage

MITRE ATT&CK Enterprise techniques detected by ZaqorinCore:

* **17 / 200 (8.5%)** — last bump: v3.2.0 added T1583.001 (5 rules)

| Technique | Status | Pack |
|---|---|---|
| T1583.001 Acquire Infrastructure: Domains | ✅ Shipped (v3.2.0) | 5 rules: typosquat (Levenshtein 1–2), NRD, TLD burst, dormant, internal registration |
| T1003.001 LSASS memory dump | ✅ Shipped (v2.9.0) | 1 rule |
| T1056.001 Keylogging | ✅ Shipped (v2.9.0) | 1 rule |
| T1110.001 Password guessing | ✅ Shipped (v2.9.0) | 1 rule |
| SSH brute-force, web shell, C2 beacon, lateral movement, and 9 more | ✅ Shipped (v0.3.0 → v1.0.0) | per-technique |

Full coverage table and per-rule examples live under
[`server/rules/builtin/mitre_attack/`](./server/rules/builtin/mitre_attack/).
The canonical design doc for the latest pack is
[`docs/PHASE29-dns-intel-detection.md`](./docs/PHASE29-dns-intel-detection.md).

## Recent releases

* **v3.2.0 — 2026-09-03** — T1583.001 Domain Acquisition Detection
  Pack (5 precision Sigma rules + Levenshtein engine; MITRE 16/200 → 17/200).
* **v3.1.0 — 2026-09-02** — WebUI Agents (Agent Provisioner, Rule Studio, Source Connector).
* **v2.9.0 — 2026-Q3** — Q4 Detection Pack v1 (T1003.001, T1056.001, T1110.001).
* **v1.0.0 — 2026-08** — First production-ready release. 170/170 server tests pass.
See [`docs/operator-guide.md`](./docs/operator-guide.md) and the
live docs site at
`https://faris-stuck.github.io/zaqorincore/`.

Full plan in [`ROADMAP.md`](./ROADMAP.md). Per-phase change log in [`CHANGELOG.md`](./CHANGELOG.md).

## Project status

⚠️ **Phase 1 shipped.** The agent runs today and can stream `auth.log` (or any file) to a WebSocket server. The central server, detectors, and auto-response land in Phases 2-4.

If you want to follow along, ⭐ the repo or watch releases.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). We welcome detector plugins, documentation, bug reports, and thoughtful feedback on the architecture.

## Security

Found a vulnerability? Read [`SECURITY.md`](./SECURITY.md) for the responsible disclosure process. **Do not open a public issue.**

## License

[MIT](./LICENSE) — see the file for full text. Free to use, modify, and ship, as long as the copyright notice is preserved.

## Code of conduct

[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) — Contributor Covenant v2.1. Be kind, assume good faith, stay on topic.

---

Built by [Faris-stuck](https://github.com/Faris-stuck) · A personal project, MIT licensed, no affiliation with any employer.
