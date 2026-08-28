# Phase 5 — Universal Platform Scope

**Status:** shipped as v0.5.0 (2026-08-28).

## Goal

Turn ZaqorinCore from a single-host IDS into a **universal cyber
security platform** that runs on a Raspberry Pi 4 for a homelab
user, on a 4 GB VPS for a startup, and on multi-cloud for an
enterprise — same code, same binary, runtime mode flag.

## What changed

### Multi-scale deployment

`server/deployment.py` introduces three mode presets:

| Mode | Host | DB | Redis | Detectors | Stream | Default pool |
|---|---|---|---|---|---|---|
| `individual` | RPi 4 / homelab | SQLite (planned Phase 6) | embedded | 5 | in-process | 2 |
| `startup` | 4 GB VPS | PostgreSQL 16 | 1 instance | 12 | enabled | 5 |
| `enterprise` | multi-cloud | PostgreSQL 16 | Streams cluster | 25+ | required | 20 |

The mode is set by `ZAQORIN_DEPLOYMENT_MODE` and the server applies
the preset on startup. Operators can still override any field.

### Nine action kinds

`server/action_kinds.py` is the single source of truth for what
the platform can do. The dispatcher validates every action against
this registry before signing a command.

| Kind | Target shape | Default TTL | Opt-in? |
|---|---|---|---|
| `block_ip` | ipv4 | 3600s | yes |
| `tarpit_ip` | ipv4 | 1800s | yes |
| `canary_alert` | absolute path | n/a | no |
| `isolate_host` | hostname | 0 (manual) | yes |
| `kill_process` | pid>1 | 0 (one-shot) | yes |
| `quarantine_file` | absolute path | permanent | yes |
| `revoke_session` | session-id string | 86400s | yes |
| `webhook_soar` | https:// URL | n/a | yes |
| `evidence_capture` | host-id | n/a | no |

`agent/internal/response/kinds/kinds.go` provides a uniform
executor signature for all 9. Each one has a format gate that
runs before any system call — `kill_process` refuses PID 1,
`webhook_soar` requires `https://`, etc.

### Four new detectors

In addition to `ssh_bruteforce`:

- `port_scan` — sliding window on distinct destination ports
  per source IP, tarpits on threshold (20 ports / 30s default).
- `web_attack` — regex sweep on HTTP request lines
  (SQLi, XSS, path traversal, scanner fingerprint). Cooldown
  per (host, ip, tag).
- `dns_tunnel` — long leftmost label + high query rate signals
  DNS-based exfiltration.
- `auth_anomaly` — first-time IP for a user, plus multiple
  distinct IPs in a 5-minute window.

All four are pure rule-based, deterministic, and fail-open on
Redis errors.

## Test results

- Server: 55 → 118 tests (+63: action_kinds, deployment,
  new_detectors, dispatcher kind-gate).
- Agent: 9 → 27 tests (+18 kinds executors).
- E2E smoke (`scripts/smoke_detector.py`): unchanged.
  SSH brute-force still closes the loop in <2s.

## Decisions

The five ADRs in `docs/decisions/` capture the rationale:

- ADR-001 — scope: universal platform, not just an IDS.
- ADR-002 — multi-scale via runtime mode flag.
- ADR-003 — nine action kinds, not just block_ip.
- ADR-004 — Sigma-compatible custom rule engine (planned Phase 6).
- ADR-005 — deception and forensics via zero-cost, deterministic
  mechanisms (planned Phase 7).

## Pitfalls

- The detector library grew from 1 to 5. Operators need a way to
  disable detectors per-host. **Phase 6 will add a per-host
  detector allowlist** so the platform can be tuned without
  shipping a fork.
- The dispatcher now consults `action_kinds.KINDS` on every
  command. A bad kind in a stale Action row from a previous
  schema could trip the validation. The dispatcher already
  handles this by logging and marking the action failed.
- The `webhook_soar` executor requires `https://`. Operators
  who have an internal SOAR over plain HTTP must use a
  reverse proxy (Caddy, nginx) in front.

## What's next

Phase 6 (Sigma rule engine + hunt query) is the next big unlock:
operators write rules in YAML, no Python needed. Phase 7
(deception + forensics) plants canary tokens and captures
evidence on every alert. Phase 8 ships the compliance pack.
Phase 9 builds the real web UI. Phase 10 is the public launch.
