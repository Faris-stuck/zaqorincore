# ADR-005: Deception and Forensics via Zero-Cost, Deterministic Mechanisms

## Status
Accepted

## Date
2026-08-28

## Context

A "proactive" cyber security platform must include two capabilities that
the original ZaqorinCore roadmap didn't mention:

1. **Deception** — placing decoys that an attacker will touch, then
   alerting with zero false positive when they do.
2. **Forensics** — capturing the evidence chain when an incident is
   detected, so the operator can investigate post-hoc.

Both are well-known in commercial tools (Thinkst Canarytokens, Velociraptor,
OSQuery) but most enterprise-grade options are commercial or have heavy
dependencies.

## Decision

We ship a **zero-cost, deterministic** deception and forensics module in
Phase 7, with no new external dependencies:

### Deception

| Mechanism | How it works | False positive rate |
|---|---|---|
| **File canary** | A file in a watched path with a hash in the event stream. Any `open()`, `read()`, or `unlink()` triggers an alert. | 0% (the file has no legitimate use) |
| **Credential canary** | A fake SSH key or API token in a watched path. Any use of the credential triggers an alert. | 0% (the credential is fake) |
| **Cookie canary** | A `canarytoken`-style HTTP cookie planted on internal web apps. Any browser request with the cookie triggers an alert. | ~0% (only used by attackers who steal cookies) |
| **Socket canary** | A Go `net.Listener` bound to an unused port. Any inbound connection triggers an alert. | 0% (the port is not in any service map) |
| **Tarpit** | A Go `net.Listener` that accepts connections but never reads or writes. The attacker's scanner hangs. | n/a (not an alert, a slowdown) |
| **Breadcrumbs** | Fake config files, fake `.env`, fake database dumps. Any read by an unexpected process triggers an alert. | 0% (the files have no legitimate use) |

All deception alerts are signed with the existing HMAC wire protocol and
flow through the same `Action` table as `block_ip`.

### Forensics

- **Evidence locker** — a directory tree under `/var/lib/zaqorin/evidence/`
  with one subdirectory per incident, named by `incident_id` (UUIDv4).
- **Chain of custody** — every file in the locker carries a sidecar
  `.sha256` file with the SHA-256 of the captured file and the timestamp
  of capture. A manifest `MANIFEST.json` lists all files in the locker.
- **Capture sources** — `journalctl` (last 24h), `auth.log` (last 24h),
  `ps auxf`, `netstat -tulpn`, the running process tree, the list of
  open files for the offending PID, and a tarball of the offender's
  home directory.
- **Upload** — optional S3-compatible upload via env vars; otherwise
  the evidence stays on the host.

## Alternatives Considered

### Adopt Thinkst Canarytokens (commercial SaaS)
- Pros: ready-made, polished.
- Cons: requires a paid account, sends data to a third party, MIT
  self-hostable project cannot depend on it.
- Rejected: defeats the self-hostable goal.

### Adopt Velociraptor for forensics
- Pros: powerful, MIT.
- Cons: Velociraptor is its own platform with its own agent and its
  own server. Adding it as a dependency is not "zero cost" — it
  doubles the operational surface.
- Rejected: we want a single binary per host.

### Build forensics around OSQuery
- Pros: SQL-based, well-known.
- Cons: OSQuery is heavy (~80 MB binary) and slow on cold start.
  Pulling in OSQuery's agent is a major dependency.
- Rejected: too heavy for the agent budget.

### Defer deception and forensics to Phase 8+
- Pros: focus on detection in v0.5.0–v0.6.0.
- Cons: "proactive" requirement is not met without deception; the
  user explicitly listed proactive as a non-negotiable.
- Rejected: deception is part of the v0.7.0 scope, not later.

## Consequences

- The agent gains `internal/canary` (file/credential/cookie/socket
  watchers) and `internal/tarpit` (slow accept listener).
- The agent gains `internal/evidence` (capture + hash + manifest).
- The server gains a `forensics` table and endpoints to list and
  fetch evidence bundles.
- Operators deploy canary tokens by listing them in
  `agent.example.toml` under `[canary.files]` etc.
- Evidence captures count against the host's disk budget; the agent
  rotates old evidence after a configurable retention (default 30
  days).

## Notes

- All deception is "low interaction" — we don't run a full honeypot.
  The canary is a marker, not a fake service.
- Evidence capture must never block the agent's main loop. If the
  tarball is too large, the capture is skipped with a warning.
