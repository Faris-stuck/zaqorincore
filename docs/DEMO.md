# ZaqorinCore v1.0.0 — 5-minute demo

A scripted walkthrough that pairs with `scripts/smoke_launch.py`
to show the full log-tail → alert → evidence → canary loop. Designed
to be shown to a security team in 5 minutes. No vendor lock-in,
no SaaS, no AI.

## What you need

- ZaqorinCore v1.0.0 source tree (`git clone …`)
- Docker (for the live stack — postgres + redis + server + agent)
- A terminal

## Setup (~90s)

```bash
git clone https://github.com/Faris-stuck/zaqorincore.git
cd zaqorincore
docker compose up -d
# wait for healthz
until curl -s http://127.0.0.1:8000/healthz | grep -q '"status":"ok"'; do sleep 1; done
```

## Demo flow

### 1. Show the SPA (10s)

Open <http://127.0.0.1:8000/> in a browser. You should see the
ZaqorinCore console with four views: **Alerts / Hunt / Evidence /
Canary**. No login, no auth, no tracking — just an operator console.

View page source. You should see:

- `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; …">`
- The CSP **does not** allow `unsafe-inline` or `unsafe-eval`. React
  is loaded from `https://esm.sh` (documented limitation, vendor
  planned for v1.x).
- The bundle is a single 12 KB `static/app.js`. No build step.

### 2. Run the DB-free smoke (5s)

```bash
cd server && python scripts/smoke_launch.py
```

Expected:

```
ZaqorinCore v1.0.0 launch smoke (DB-free, in-process)
  [PASS] GET / serves SPA shell
  [PASS] GET /static/app.js serves React bundle
  [PASS] Security headers on SPA (CSP/XFO/nosniff)
  [PASS] Security headers on API (XFO/nosniff)
  [PASS] GET /healthz returns 200 ok
  [PASS] FastAPI app version is 0.9.0 or 1.0.0
  [PASS] GET /api/v1/hunt/rules returns >= 50 rules
  [PASS] GET /docs serves Swagger UI
  [PASS] OpenAPI exposes all v1.0.0 endpoints
  9 / 9 checks passed
```

**56 rules** (5 baseline + 51 compliance). **All v1.0.0 endpoints
exposed** in the OpenAPI schema. **CSP, X-Frame-Options, nosniff**
on every response.

### 3. Run the full smoke against the live stack (10s)

```bash
cd .. && bash scripts/smoke.sh
```

This boots the real Postgres + Redis + server + agent stack and
exercises the full transport + detector + auto-response loop:

- SSH brute-force from a fake `203.0.113.42` source
- Detector fires → Alert row
- Action dispatch → HMAC-signed block command
- Agent applies nftables block → command_ack
- Evidence bundle + sidecar written + verified
- All in under 5 seconds

### 4. Show the canary system (30s)

```bash
# Create a file canary
curl -s -X POST 'http://127.0.0.1:8000/api/v1/canary?host_id=demo-host' \
    -H 'content-type: application/json' \
    -d '{"kind": "file", "path": "/tmp/canary_demo.txt"}' | jq .

# Touch it (simulating attacker)
curl -s -X POST 'http://127.0.0.1:8000/api/v1/canary/touched' \
    -H 'content-type: application/json' \
    -d "{\"canary_id\": \"$CID\", \"host_id\": \"demo-host\", \"touched_by\": \"demo\"}" | jq .

# View alerts (should include the canary hit)
curl -s 'http://127.0.0.1:8000/api/v1/alerts' | jq '.items[0]'
```

**Four canary kinds ship**: `file`, `tcp_socket`, `http_endpoint`,
`credential`. All four are zero-cost (no external SaaS) and the
`credential` canary is a fake AWS key that triggers on a logged
use — no actual AWS access happens.

### 5. Show the compliance packs (30s)

```bash
# Count rules by pack
curl -s http://127.0.0.1:8000/api/v1/hunt/rules | \
  jq -r '.rules[].tags[]' | grep -E 'iso|nist|pci|uu_pdp|mitre' | \
  sort | uniq -c
```

Expected:

```
   5  attack.*
  13  framework.iso27001
  13  framework.nist_800_53
  13  framework.pci_dss
  13  framework.uu_pdp
  12  mitre_attack
```

**51 compliance rules** + **5 baseline rules** = **56 total**. Each
rule cites the specific control ID (e.g. `ISO 27001 A.5.15`, `PCI DSS
4.0 §1.2.1`, `UU PDP Pasal 32`, `MITRE ATT&CK T1110`).

### 6. Show the evidence locker (30s)

```bash
# Pick the most recent alert
AID=$(curl -s 'http://127.0.0.1:8000/api/v1/alerts?limit=1' | jq -r '.items[0].id')

# Verify the evidence bundle (chain-of-custody check)
curl -s "http://127.0.0.1:8000/api/v1/evidence/$AID/verify" | jq .

# Download the sidecar (proves the bundle was signed)
curl -s "http://127.0.0.1:8000/api/v1/evidence/$AID/sidecar" | jq .
```

**HMAC + SHA-256** sign every bundle. **Key rotation** is supported:
the store retains old keys so old evidence still verifies after a
rotation. **Wipe the active key** → old evidence FAILS verify
(chain-of-custody is preserved even on adversarial key destruction).

## Talking points

- **Zero AI** — every rule is a static YAML Sigma-compatible file.
  No LLM, no embeddings, no "AI-powered" marketing.
- **Black-hat defensive** — the same primitives an attacker would
  use to hide, we use to detect (CFI, stack canary XOR, MITRE ATT&CK
  mapping, MulVAL-style attack graphs).
- **MIT-licensed, OSS** — no SaaS, no per-seat, no telemetry. The
  binary you build is the binary you run.
- **Universal** — works for a 5-person startup and a 5,000-employee
  enterprise. The same agent binary runs on a Raspberry Pi and a
  datacenter fleet.
- **Proactive** — detectors fire on the anomaly, canaries lure
  attackers, auto-response blocks them, evidence preserves the
  chain. Not just SIEM, not just IDS.

## What comes after v1.0.0

Tracked in the [Roadmap](roadmap.md):

- **v1.1** — vendored React (drop esm.sh), SRI hash, optional auth UI
- **v1.2** — Linux kernel hardening pack (AppArmor, sysctl)
- **v1.3** — Cloud detectors (AWS CloudTrail, Azure Activity Log)
- **v1.4** — Sigma upstream feed ingestion
- **v1.5** — EDR mode (kernel module)
- **v1.6** — MITRE D3FEND mapping for every detector
- **v1.7** — Multi-tenant SaaS mode (self-hosted, not cloud)

No AI in any of these. Pure rule-based, MIT-licensed, OSS.
