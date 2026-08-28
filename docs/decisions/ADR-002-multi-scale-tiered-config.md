# ADR-002: Multi-Scale Deployment via Runtime Mode Flag

## Status
Accepted

## Date
2026-08-28

## Context

ZaqorinCore must run on a Raspberry Pi 4 (1 GB RAM) for an individual homelab
user, on a 4 GB VPS for a startup, and on a multi-node cluster for an
enterprise. Each tier has very different resource budgets and operational
requirements.

We need a way to ship one codebase that adapts to all three without making
the individual user carry the weight of the enterprise configuration or the
enterprise operator wade through homelab-friendly defaults.

## Decision

We use a **runtime mode flag** on both the agent and the server:

- `zaqorin-agent --mode=individual|startup|enterprise`
- `zaqorin-server --mode=individual|startup|enterprise`

The mode flag selects a config profile that controls:

| Concern | individual | startup | enterprise |
|---|---|---|---|
| Storage | SQLite (local) | PostgreSQL | PostgreSQL cluster |
| Transport | local socket | WebSocket | WebSocket + mTLS |
| Detector set | core (4) | standard (12) | full (25+) |
| Action kinds | 3 (block, alert, evidence) | 7 | 9 (all) |
| Memory budget | < 20 MB | < 200 MB | < 1 GB |
| CPU budget | < 1.5% | < 5% | < 10% |
| Dashboard | optional | yes | yes (multi-tenant) |
| Hunt engine | no | yes | yes |
| Federation | no | no | yes (peer-to-peer) |

The default mode is `startup` (the most common deployment). The mode flag
overrides defaults but never overrides explicit operator config — explicit
config always wins.

## Alternatives Considered

### Separate binaries (`zaqorin-agent-lite`, `zaqorin-agent-full`)
- Pros: clean separation of concerns.
- Cons: two release pipelines, two test matrices, two documentation sites.
- Rejected: maintenance cost outweighs the simplicity gain.

### Tiered plugins loaded at runtime
- Pros: more flexible.
- Cons: introduces a plugin loader, which is more attack surface and more
  configuration complexity.
- Rejected: a single mode flag covers the use case without the loader.

### Per-tier forks of the repository
- Pros: independent evolution.
- Cons: massive code drift over time, no shared bug fixes.
- Rejected: defeats the purpose of one platform.

## Consequences

- The mode flag is a first-class argument; the help text documents the
  resources of each tier.
- The server's FastAPI app boots different feature sets based on mode
  (e.g. federation endpoints only register in `enterprise`).
- The agent's config validation rejects combinations that don't fit the
  mode (e.g. you cannot use SQLite in `enterprise` mode).
- Tests run against all three modes in CI to catch drift.

## Notes

- The `individual` mode is a stepping-stone to onboarding — once a user has
  more than one host, they should switch to `startup` mode and run a
  server.
- Mode is also exposed via the `/api/v1/server/info` endpoint so the
  dashboard can render the right UI.
