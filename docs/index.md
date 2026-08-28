# ZaqorinCore

> **Proactive defense for the people who run their own infrastructure.**

ZaqorinCore is a self-hosted, open-core platform that **detects attacks in
real time and responds automatically**. Drop a lightweight Go agent on
each host you want to protect, point it at your central server, and the
platform watches your logs, fires alerts, and blocks bad actors — usually
before the second attempt lands.

The whole loop — *log tail → stream → detection → alert → action* —
runs in **under 2 seconds**. No five-minute cron, no per-host SSH, no
dashboard that takes a week to learn.

## Why ZaqorinCore

| What | How |
| --- | --- |
| **Real-time** | Event from log line to action on the offending host in <2 s, end to end. |
| **Self-hosted** | Your server, your data, your rules. No SaaS, no telemetry, no phone-home. |
| **Defensive only** | No offensive tooling, no exploitation, no scanning. Detection + auto-response. |
| **MIT licensed** | Forever. The whole repo. No BSL, no "open core" bait-and-switch. |
| **Zero AI** | Every decision is a rule. No LLM, no ML, no "intelligence" that quietly phones home. |
| **Black-hat grade** | Built to the same bar as Wazuh, OSSEC, Suricata, CrowdStrike. |
| **Compliance-aware** | 56 Sigma rules mapped to ISO 27001, NIST 800-53, PCI DSS, UU PDP, MITRE ATT&CK. |
| **3-tier** | Individual → startup → enterprise. One binary, one config flag, no fork. |

## Get the loop running in 5 minutes

```bash
# 1. Clone
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore

# 2. Run the server (needs PostgreSQL + Redis on localhost)
cd server && pip install -e . && zaqorin-server

# 3. Open the console
xdg-open http://127.0.0.1:8000/   # SPA: alerts / hunt / evidence / canary

# 4. Build the agent
cd ../agent && make build

# 5. Drop the binary on a host you want to protect
scp bin/zaqorin-agent user@victim:/usr/local/bin/
# (then follow the agent setup in PHASE1.md)
```

## What's in the box (v0.9.0)

- **Agent** — single ~5 MB Go binary, WebSocket stream, log tailer,
  filesystem watcher, deception tokens, evidence packer.
- **Server** — async Python (FastAPI + SQLAlchemy 2 + Redis Streams),
  Sigma-compatible rule engine, 56 rules, hunt API, evidence locker
  with HMAC-signed chain of custody, canary store, dispatcher.
- **Web console** — bundled React 18 SPA, alerts / hunt / evidence /
  canary, served from the same FastAPI as the API. No auth UI yet —
  assumes trusted network (Tailscale, internal VPN, localhost).
- **9 action kinds** — `block_ip`, `kill_process`, `disable_account`,
  `quarantine_file`, `revoke_token`, `notify`, `isolate_host`,
  `snapshot`, `evidence_capture`.
- **4 canary kinds** — `file`, `tcp_socket`, `http_endpoint`,
  `credential` (file canaries via `fsnotify`, sockets via `net.Listen`).
- **Evidence locker** — tarball + SHA-256, HMAC-SHA256 sidecar, key
  rotation (`rotate()` keeps old keys for verifying old evidence),
  one-click verify from the console.
- **3-tier runtime** — `individual` / `startup` / `enterprise` config
  flag, picks a sane default action set per tier.

## Where to go next

- **New to ZaqorinCore?** Read the [Operator guide](operator-guide.md).
- **Want the design rationale?** Read the [Roadmap](roadmap.md) and the
  [ADRs under Decisions](decisions/ADR-001-scope-universal-platform.md).
- **Want to ship a rule?** Read [PHASE6 — Sigma engine](PHASE6.md) and
  [PHASE8 — Compliance pack](PHASE8.md).
- **Want to run a hunt?** Read [PHASE9 — Web console](PHASE9.md) (Hunt
  view) and [PHASE7 — Deception + forensics](PHASE7.md).

## License

MIT. See [`LICENSE`](https://github.com/Faris-stuck/zaqorincore/blob/main/LICENSE).
