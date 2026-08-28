# ADR-004: Sigma-Compatible Custom Rule Engine

## Status
Accepted

## Date
2026-08-28

## Context

ZaqorinCore needs to ship a large detector library (12+ detectors at v0.5.0,
25+ at v0.6.0, 50+ at v0.8.0). Writing each detector as a Python class is
fast for the first few but becomes a bottleneck:

- Every new detector requires a code change, a PR review, a release.
- Operators cannot write their own detectors without forking the project.
- The community cannot share detectors because each is in a different
  language or format.

Sigma is the de-facto open standard for sharing detection rules
(MIT-licensed, used by Elastic, Splunk, and others). A Sigma-compatible
engine would let the operator:

- Write a rule in YAML, not Python.
- Reuse rules from the public SigmaHQ repository (after a one-time
  conversion).
- Add new rules without redeploying the server.

## Decision

We ship a **Sigma-compatible custom rule engine** in Phase 6:

- Rules are written in YAML, in a Sigma-style format (with our own
  extensions for ZaqorinCore-specific fields like `target_kind`).
- The engine matches rules against normalized events in pure Python
  (no LISP/DSL, no compilation step).
- The engine is **read-only against the Sigma standard** — we accept
  Sigma rules as input, but our output is still ZaqorinCore-native
  alerts (we don't speak the Sigma output protocol).
- Operators can drop YAML files in `server/rules/` and the engine
  picks them up at startup.

Example rule:

```yaml
id: ssh_bruteforce_external
title: SSH brute force from external IP
description: >-
  More than 5 failed SSH login attempts from the same source IP within
  60 seconds.
detection:
  selection:
    event.kind: auth
    event.action: failed
    event.source: sshd
  condition: selection
threshold:
  count: 5
  window_sec: 60
action:
  kind: block_ip
  ttl_sec: 300
level: high
tags:
  - attack.brute_force
  - attack.t1110
```

## Alternatives Considered

### Hand-write every detector as Python
- Pros: familiar to contributors.
- Cons: scales poorly past 10 detectors. Locks out operator-defined rules.
- Rejected: doesn't meet the "operator can write their own rules" goal.

### Adopt Sigma as a hard dependency
- Pros: full Sigma compatibility out of the box.
- Cons: Sigma's pySigma is GPL-3.0; using it would force us out of MIT.
  We would also depend on a project whose roadmap we don't control.
- Rejected: license incompatibility is a deal-breaker.

### Use a different standard (YARA, Suricata rules)
- Pros: YARA is for file scanning, not event correlation. Suricata
  rules are network-packet-specific.
- Cons: neither fits the event-correlation use case.
- Rejected: wrong tool for the job.

### Custom DSL
- Pros: total control.
- Cons: nobody else writes rules in our DSL.
- Rejected: we want to leverage community knowledge.

## Consequences

- We add a `server/rule_engine/` package that loads YAML, normalizes
  events to a `SigmaEvent` shape, and runs the match.
- Existing detectors (`ssh_bruteforce`) can stay as Python classes; new
  detectors can ship as YAML. The runner treats them uniformly.
- The rule format is documented in `docs/RULE_FORMAT.md`.
- We commit to a one-time converter (`tools/sigma_to_zaqorin.py`) that
  ingests SigmaHQ rules and produces ZaqorinCore rules. The converter
  is **not** a runtime dependency — it's a developer tool.

## Notes

- We name our format "ZaqorinCore Rule Format" (ZRUF) to make clear
  that it is Sigma-inspired, not Sigma-conformant.
- The rule engine is single-threaded at v0.6.0. Parallel matching
  lands in Phase 7 if benchmarks demand it.
