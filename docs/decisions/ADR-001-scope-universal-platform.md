# ADR-001: Scope — ZaqorinCore is a Universal Cyber Security Platform

## Status
Accepted

## Date
2026-08-28

## Context

The original ZaqorinCore roadmap (v0.1.0 through v0.4.0) defined the project as an
infrastructure security agent + server focused on auto-blocking brute-force IPs. That
scope is too narrow to fulfill the project's mission:

- **Multi-scale requirement**: the same codebase must serve a single home user on a
  Raspberry Pi, a 10-host startup, and a 10 000-host enterprise.
- **Full-spectrum requirement**: blocking IPs is a tiny slice of cybersecurity. The
  operator also needs intrusion detection, vulnerability detection, behavior analysis,
  lateral movement detection, data exfiltration detection, deception, compliance
  reporting, and forensic evidence capture.
- **Proactive requirement**: the system must hunt, predict, and preempt — not just
  react to log lines.
- **Universal requirement**: the same rules must work whether the operator is a
  single homelab user or a SOC team.

## Decision

We redefine ZaqorinCore's scope as a **universal cyber security platform** with the
following non-negotiable properties:

1. **Multi-scale by design.** Three deployment tiers ship from the same codebase:
   - `individual` — single binary, no server, local SQLite (5 MB RAM, 1.5% CPU).
   - `startup` — 1–10 agents + 1 server, PostgreSQL + Redis.
   - `enterprise` — 100–10 000 agents + clustered server + Redis Streams.
2. **Full-spectrum coverage.** The detector library ships with at least one
   detector per category: network, web, auth, file, process, lateral, exfil, vuln,
   compliance.
3. **Proactive, not just reactive.** The system includes a hunt query engine, a
   deception module (canary tokens, tarpits, breadcrumbs), and periodic baseline
   scans.
4. **Rule-based, deterministic, no AI.** Every decision is a boolean match on
   a rule; no LLM, no ML, no probabilistic inference.
5. **MIT-licensed, self-hostable, no SaaS commercial tier.** All four deployment
   tiers are free and open source.

## Alternatives Considered

### Stay narrow (block IP only)
- Pros: smaller scope, faster to ship.
- Cons: fails the multi-scale, full-spectrum, and proactive requirements.
- Rejected: the user's mission is broader than a block-IP tool.

### Pivot to a SIEM-style aggregator
- Pros: closer to enterprise SOC stack.
- Cons: forks away from the rule-based agent focus; competes head-on with Wazuh.
- Rejected: we want to be the agent, not the SIEM. ZaqorinCore already has a
  lean agent-server model that SIEM tools do not.

### Adopt a probabilistic detection core
- Pros: more flexible detection, can catch unknown patterns.
- Cons: introduces AI/ML — explicitly forbidden by the user. Probabilistic
  detection also creates alert fatigue (false positives) and silent misses
  (false negatives) — the opposite of black-hat-grade defense.
- Rejected: determinism is non-negotiable.

## Consequences

- Every phase from Phase 5 onward must expand the detector library, not just
  harden the existing one.
- The 9 action kinds (block_ip, tarpit, canary_alert, isolate_host,
  kill_process, quarantine_file, revoke_session, webhook_soar, evidence_capture)
  ship as a complete set, not one at a time.
- The deployment mode is a runtime flag, not a fork of the codebase.
- We will publish a comparison table (vs Wazuh, vs OSSEC, vs CrowdStrike) to
  make the positioning clear.

## Non-goals (for now)

- We do not build a SIEM-style full-text log search across all sources.
- We do not replace the OS firewall — we call nftables/iptables.
- We do not provide managed SOC services.
- We do not add LLM/ML/AI features under any name.
