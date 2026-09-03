# T1078.002 — shared_secret HMAC auth from new src_ip (credential reuse)

**MITRE**: [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Sub-technique**: T1078.002 (ZaqorinCore-specific extension; closely
related to [T1078.001 — Default Accounts](https://attack.mitre.org/techniques/T1078/001/))
**Severity**: High
**Status**: Experimental
**Mapped finding**: F-1 from AUDIT-2026-09-03 (HMAC challenge-response
replay fix; closed in v3.2.1)

## Summary

Detects a successful HMAC-authenticated WebSocket HELLO from a
previously unseen `src_ip` using the same `key_id` within a short
window. A single shared secret authenticating from multiple source IPs
in 5 minutes strongly suggests credential capture and replay, or a
shared secret between distinct operators.

This rule complements the brute-force detection rule T1190.002; the
two together cover both the success-side (stolen secret reused) and
failure-side (secret being guessed) of the same attack.

Threshold is intentionally loose: 2 distinct `src_ip` values for one
`key_id` within 300s. The runner applies a per-`key_id` correlation
window.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: server
detection:
  selection:
    event_type: ws.hello
    auth_method: hmac
    status: 200
  condition: selection
  timeframe: 300s
  count: 2
  by: key_id
fields:
  - src_ip
  - key_id
  - agent_id
level: high
```

## Sample event

```json
{
  "event_type": "ws.hello",
  "auth_method": "hmac",
  "status": 200,
  "src_ip": "203.0.113.77",
  "key_id": "key-shared-01",
  "agent_id": "agent-prod-03",
  "ts": "2026-09-04T14:11:02Z"
}
```

## Tuning

- **Whitelist**: `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list) for
  multi-NIC agents.
- **Threshold**: 2 distinct `src_ip` per `key_id` in 300s. Lower to 1
  if you operate single-host agents exclusively.
- **Known false positives**:
  - Agent migrating to a new IP within the window.
  - Multi-NIC agent with several active interfaces.
  - Operator key being shared between two distinct consoles (rotate
    the key and split the secret).

## References

- https://attack.mitre.org/techniques/T1078/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03](../../security/AUDIT-2026-09-03.md)