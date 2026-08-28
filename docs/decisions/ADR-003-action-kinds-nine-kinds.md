# ADR-003: Nine Action Kinds (Not Just block_ip)

## Status
Accepted

## Date
2026-08-28

## Context

The original ZaqorinCore only supported one action kind: `block_ip`. That
covers a tiny fraction of the responses a security operator might want.

For ZaqorinCore to be a real cyber security platform, it must support the
full range of response options that a SOC analyst would consider. Every
detector that fires should be able to choose the right response for the
threat — not be forced to drop a packet just because that's the only
action kind the system supports.

## Decision

We ship **nine action kinds** in v0.5.0:

| Kind | Use case | Mechanism |
|---|---|---|
| `block_ip` | brute force, port scan | nftables drop (existing) |
| `tarpit_ip` | slow probe, scanner | nftables quota + Go net throttle |
| `canary_alert` | canary token touched | file/socket watch + alert (zero FP) |
| `isolate_host` | lateral movement detected | nftables + WS kill switch |
| `kill_process` | malware process detected | Go signal via cgroups |
| `quarantine_file` | malware file drop | chmod 000 + move to vault |
| `revoke_session` | compromised credential | Redis blacklist + token revoke |
| `webhook_soar` | custom response | HTTP POST to SOAR endpoint (HMAC signed) |
| `evidence_capture` | forensic snapshot | tar + chain-of-custody hash + S3 upload |

Every action is signed with the same HMAC-SHA256 protocol as the existing
`block_ip` command, with a canonical pipe-separated payload:

```
{cmd_id}|{kind}|{target}|{ttl_sec}|{issued_at}
```

The dispatcher picks the right action for the detector, but operators can
override via config (`detector.<name>.action_kind = "tarpit_ip"`).

## Alternatives Considered

### One action kind, let the operator post-process
- Pros: simpler dispatcher.
- Cons: forces the operator to write a separate wrapper for every response.
  Defeats the purpose of an integrated platform.
- Rejected: too much glue for the operator.

### Build a "policy engine" before the action kinds
- Pros: more flexible.
- Cons: defers value; the user wants action variety now, not a policy
  framework in 6 months.
- Rejected: ship the kinds first; the policy engine can come later as a
  Phase 11 feature.

### Each action kind = its own wire protocol
- Pros: type-safe per kind.
- Cons: 9 protocols to maintain, 9 implementations on the agent.
- Rejected: HMAC-signed canonical form already works for all kinds;
  the kind field discriminates which executor to invoke.

## Consequences

- The `Action` table grows a `kind` column (already exists) and we
  validate it against the allowed enum.
- The agent gains an `internal/response` package with one executor per
  kind, all registered in a map.
- The server dispatcher validates the requested kind against the host's
  allowlist (per-host opt-in, like `auto_block`).
- The dashboard gains an "Action history" page that filters by kind.
- Each new kind ships with at least one test and one smoke script.

## Non-goals

- We do not allow operator-defined action kinds in v0.5.0. Adding one
  should be a code change, not a config change. (A plugin interface for
  custom kinds lands in Phase 9.)
