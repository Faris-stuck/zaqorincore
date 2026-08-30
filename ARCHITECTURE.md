# Architecture

> Living document. This describes the *intended* architecture for ZaqorinCore.
> Source code in `agent/`, `server/`, and `dashboard/` will follow the contract described here.

## Goals (recap)

1. **Real-time** — end-to-end latency from event arriving on host to response action applied, under 2 seconds at the 95th percentile.
2. **Defensive only** — no offensive tooling, no exploit primitives, no upstream ban sharing.
3. **Self-hosted** — the central server and every agent run on infrastructure the operator controls. No external network calls.
4. **Multi-tenant UI** — one server can manage many agents across many hosts; the UI separates them cleanly.
5. **Plugin-friendly** — adding a new detector or response action should not require patching the core.

## High-level diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              OPERATOR HOST(S)                            │
│                                                                          │
│  ┌─────────────────┐  WSS stream    ┌──────────────────────────┐          │
│  │  AGENT          │ ─────────────▶ │                          │          │
│  │  ─ log tailer   │  events        │   CENTRAL SERVER         │          │
│  │  ─ iptables     │ ◀───────────── │   ─ FastAPI / Go API     │          │
│  │  ─ process info │  commands      │   ─ detector pool        │          │
│  └─────────────────┘                │   ─ PostgreSQL           │          │
│  ┌─────────────────┐                │   ─ Redis Streams        │          │
│  │  AGENT          │ ─────────────▶ │   ─ Web dashboard (React)│          │
│  │  ...            │                │                          │          │
│  └─────────────────┘                └──────────────────────────┘          │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Components

### Agent (Go single-binary)

Runs on each protected host. Responsibilities:

- **Log tailing** — wrap the OS log sources we monitor (`/var/log/auth.log`, nginx `access.log`, etc.) with a tailer that survives rotation.
- **Event emission** — push structured events over WebSocket (or gRPC if the operator prefers) to the configured central server.
- **Action executor** — receive commands from the server and apply them locally. Default command: `iptables -I INPUT -s <ip> -j DROP` with TTL.

Design constraints:

- Single static binary, no runtime dependencies. Easy to ship to any Linux host.
- Runs as a low-privilege user by default; only escalates to `root` (via `sudo` allowlist or systemd unit) when applying a block.
- All commands are **signed** by the server (HMAC over a per-agent shared secret) to prevent replay or impersonation if the wire is ever intercepted.

### Central server (Python / FastAPI for now, possibly Go later)

Responsibilities:

- **API surface** — REST + WebSocket for the agent and the dashboard.
- **Detector pool** — runs the registered detector plugins against each incoming event.
- **Persistence** — PostgreSQL for users, agents, events, alerts, actions.
- **Stream** — Redis Streams as the in-process event bus between the API layer and the detector pool.
- **Decision engine** — when a detector fires, decide whether to alert, auto-block, both, or neither. Rules are configurable per detector.

### Detectors (Python plugins)

A detector is a small Python file that exposes a single function:

```python
def detect(event: dict, ctx: "DetectorContext") -> "DetectionResult | None":
    ...
```

`DetectorContext` gives the plugin read access to recent events for the same host (for sliding-window analysis) and write access to fire `DetectionResult` objects back.

Built-in detectors (planned):

1. `ssh_bruteforce` — failed `auth.log` entries from the same source IP within a sliding window
2. `web_attack` — SQLi / XSS / path-traversal / scanner signatures in HTTP access logs
3. `network_scan` — port scan detection from `conn.log` (Zeek) or `journalctl` for `iptables` rejects
4. `c2_beaconing` — periodic outbound connection analysis (later phase)

Adding a new detector = drop a file in `server/detectors/`, restart the server. No DB migration required.

### Dashboard (React + Vite, dark UI)

Operator-facing UI. Shows:

- Hosts and their current health
- Live event stream (filtered by severity / host / detector)
- Alerts with one-click acknowledgment
- Action history (which IPs were blocked, when, by which detector)
- Detector configuration and per-detector thresholds

### Storage

- **PostgreSQL** — users, agents, events (sampled), alerts, actions, detector config
- **Redis** — event stream between API and detector pool, plus short-lived state (recent failed-login counts per IP, etc.)

Event retention defaults: 30 days hot in Postgres, then optional cold export (operator's choice — we don't ship a closed-format archive).

## Auto-response actions (whitelist)

| Action | What it does | Where it runs |
|---|---|---|
| `block_ip` | Add `iptables`/`nftables` DROP with TTL | Agent |
| `kill_process` | SIGKILL a PID by ID | Agent |
| `disable_user` | `usermod -L <user>` | Agent |
| `notify` | Send a webhook / Telegram / email | Server |

Anything not on this list is **not supported**. The agent will refuse unknown action types. This is a hard contract — auto-response that can run arbitrary commands is a footgun we are not shipping.

## Threat model (short version)

We assume:

- The agent's host is not yet compromised at install time.
- The network between agent and server may be hostile (signed commands).
- The server's host is operator-controlled and reasonably hardened.
- The operator is not actively malicious toward themselves.

We do **not** protect against:

- An already-compromised host installing our agent (the agent will be subverted with the rest of the system).
- Insider threats at the operator's organization.
- Zero-days in Go, Python, or our deps (we ship SBOM and follow `govulncheck` / `pip-audit` in CI).

## Why these choices

- **Agent in Go** — single static binary, no `glibc` drama, easy to ship, fast to start.
- **Server in Python (FastAPI)** — fastest path to a useful MVP; detector plugins are easiest to write in Python. We can rewrite the hot path in Go later without breaking the wire protocol.
- **Redis Streams** instead of Kafka — one less thing to operate, plenty of throughput for our scale. Kafka is a future option if we outgrow it.
- **WebSocket first** — simpler than gRPC for the agent, no protobuf codegen step. gRPC stays an option for higher-throughput agents later.

## Open questions

- Multi-region / failover for the central server — not in scope for the first release.
- Sharing ban lists *between* ZaqorinCore instances — explicit non-goal for now. The agent ↔ server loop is the unit of protection.
- macOS / Windows agents — Linux first, others later, and only if there is real demand.

## Sigma rule engine — defensive guidance for rule authors

The rule engine in `server/src/zaqorincore_server/rule_engine/sigma.py`
implements a subset of the Sigma spec: `field|startswith:`, `field|endswith:`,
`field|ge:`, `field|lt:`, plus `re:` and `contains:` literal forms. The matcher
checks each selection key against `event.metadata[key]` first and falls back to
`event.source` for the `source` key only.

### Known matcher sharp edges

1. **`contains:` is a raw substring match.** It runs against
   `str(actual)` *and* `event.raw` (the unparsed tail line). If a rule's
   filter keyword appears anywhere in the parsed metadata or in the raw
   tail, the rule fires. This is intentional for noisy log sources but
   means rule authors should anchor their keyword to a token boundary.
2. **`startswith:` / `endswith:` are case-sensitive.** `"LSASS.EXE"`
   does not match `endswith: lsass.exe`. Operators writing rules for
   Windows process names must match the case the agent actually emits.
3. **`_match_modifier` returns `False` (fail-safe) for non-numeric
   `actual` values against `ge:` / `lt:`.** A rule written as
   `count|ge: 10` against an event whose `count` field is the string
   `"ten"` will never fire. This is the intended fail-safe; rewrite the
   rule to coerce upstream.
4. **Filter-path leakage.** If a Sigma rule's `selection` block uses
   `contains:`, the needle is compared against `event.raw` as well as the
   parsed field. A rule that says `contains: /var/log/` will fire on any
   event whose log path passes through `/var/log/`, including unrelated
   events emitted from that path. Anchor the needle (`contains: bash`)
   or restrict to a specific key (`bash_command|contains: bash`) to
   avoid false positives.

### Defending in v2.4.x rule authoring

Until v2.5.0 lands a tokenizer-aware matcher (tracked in the Q3 backlog),
follow these rules when writing or reviewing Sigma rules:

- **Prefer anchored patterns over bare substrings.** Use
  `contains: bash ` (trailing space) or `contains: bash$` style anchors
  rather than `contains: bash` alone.
- **Scope every selection to a specific metadata key.** Avoid
  rule bodies that match against keys whose values include the rule's
  own filter path.
- **Add negative selections (`filter`) whenever the `selection` block
  could match legitimate baseline traffic.** The engine evaluates
  `filter` after `selection`, and the order is preserved in
  `CompiledSigmaRule`.
- **Run `scripts/lint_sigma_rules.sh` before merging.** The cycle 27
  pre-commit script checks for unanchored `contains:` patterns and
  flags known-shape false-positive candidates.
- **Add tests for both the positive case and the *near-miss* case.**
  Every rule should have at least one test asserting it does NOT fire
  on traffic that shares a substring with the rule keyword.

### Planned v2.5.0+ work

- **Tokenizer-aware matcher.** Replace raw `contains:` against
  `event.raw` with a word-boundary regex. This removes the
  filter-path leakage class of false positives without breaking
  compatible rules.
- **Case-insensitive `contains:` opt-in.** Add a `icontains:` modifier
  so Windows process-name rules don't have to enumerate casings.
- **Per-rule severity inheritance.** Let a rule's `level` field
  populate the alert's severity unless explicitly overridden in the
  detector pipeline.
- **Sigma rule hot reload.** Today rules are loaded at startup; v2.5.0+
  should support `SIGHUP`-style reload so operators don't need to
  bounce the server when shipping a new rule bundle.
