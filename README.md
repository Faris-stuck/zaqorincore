# ZaqorinCore

> **Proactive defense for the people who run their own infrastructure.**

ZaqorinCore is a self-hosted, open-core platform that **detects attacks in real time and responds automatically**. Drop a lightweight agent on each host you want to protect, point it at your central server, and the platform watches your logs, fires alerts, and blocks bad actors — usually before the second attempt lands.

The whole loop — log tail → stream → detection → alert → action — runs in **under 2 seconds**. No five-minute cron, no per-host SSH, no dashboard that takes a week to learn.

---

## What it does (today)

- 🔎 **Real-time attack detection** — events stream from agent to server over WebSocket/gRPC, detectors run as they arrive
- 🛡️ **Defensive auto-response** — block IPs via `iptables`/`nftables` directly on the offending host (no shared ban list, no upstream service)
- 🧩 **Plugin detectors** — write a detector in Python, drop it in `detectors/`, restart the server
- 📊 **Multi-host dashboard** — see every protected host, every event, every action from one place
- 🔐 **Self-hosted** — your logs never leave your network

## What it does *not* do

- ❌ No offensive tooling. ZaqorinCore detects and blocks; it does not retaliate, exploit, or scan
- ❌ No external SaaS. Your server, your data, your rules
- ❌ No telemetry, no phone-home, no account required

## Quick start (preview — Phase 1+)

> Currently in **Phase 0 (spec & scaffolding)**. Real install steps land with Phase 1.

```bash
# 1. Clone
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore

# 2. Start the central server
docker compose up -d

# 3. Install the agent on each host
curl -sSL https://raw.githubusercontent.com/Faris-stuck/zaqorincore/main/agent/install.sh | bash -s -- \
    --server https://your-server:8443 \
    --token <registration-token>

# 4. Open the dashboard
open http://localhost:8080
```

## Architecture

```
┌──────────────────┐   WSS/gRPC stream   ┌──────────────────────────┐
│  AGENT (host A)  │ ──────────────────▶ │                          │
│  log tailer      │   events            │   CENTRAL SERVER         │
│  iptables hook   │ ◀────────────────── │   API · detectors        │
└──────────────────┘   block commands    │   PostgreSQL · Redis     │
┌──────────────────┐                     │   React dashboard        │
│  AGENT (host B)  │ ──────────────────▶ │                          │
│  log tailer      │   events            │                          │
│  iptables hook   │ ◀────────────────── │                          │
└──────────────────┘   block commands    └──────────────────────────┘
```

Details in [`ARCHITECTURE.md`](./ARCHITECTURE.md). Phase plan in [`ROADMAP.md`](./ROADMAP.md).

## Roadmap snapshot

| Phase | What ships | Status |
|---|---|---|
| **0** | Spec, repo scaffolding, governance files | ✅ In progress |
| **1** | Go agent — log tailer, WebSocket push | ⏳ Next |
| **2** | Central server (FastAPI + PostgreSQL + Redis) | ⏳ |
| **3** | Detector plugin: SSH brute-force | ⏳ |
| **4** | Auto-response: agent-side `iptables` block | ⏳ |
| **5** | Detectors: web attack, network scan, C2 beaconing | ⏳ |
| **6** | Auth + multi-user + RBAC | ⏳ |
| **7** | Packaging: Docker compose + Helm + install scripts | ⏳ |
| **8** | Public launch + docs site | ⏳ |

## Project status

⚠️ **Early stage.** Source code lands in Phase 1 (estimated 1–2 weeks from now). Until then, the repo is governance, documentation, and a public commitment to the design.

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
