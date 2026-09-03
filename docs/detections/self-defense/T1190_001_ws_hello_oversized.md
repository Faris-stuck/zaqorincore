# T1190.001 — WS HELLO frame malformed or oversized

**MITRE**: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
**Sub-technique**: T1190.001 (ZaqorinCore-specific extension)
**Severity**: High
**Status**: Experimental
**Mapped finding**: [F-001 v3.2.1](../../security/AUDIT-2026-09-03.md#f-001)

## Summary

Detects malformed or oversized WebSocket HELLO frames that may indicate
exploit attempts against `/ws/agent`. After v3.2.1 added the HMAC
challenge and frame size cap, this rule fires when the cap is tripped
(>= 8192 bytes) or when the frame is empty (0 bytes). Either signal
indicates an attempt to abuse the endpoint before the cap rejects it.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: server
detection:
  selection:
    event_type: ws.hello
  filter_oversized:
    message_size_bytes: "|ge: 8192"
  filter_empty:
    message_size_bytes: 0
  condition: selection and (filter_oversized or filter_empty)
  timeframe: 60s
  count: 1
fields:
  - src_ip
  - agent_id
  - message_size_bytes
level: high
```

## Sample event

```json
{
  "event_type": "ws.hello",
  "src_ip": "203.0.113.42",
  "agent_id": "agent-prod-07",
  "message_size_bytes": 16384,
  "route": "/ws/agent",
  "ts": "2026-09-03T12:14:08Z"
}
```

## Tuning

- **Whitelist**: `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list, applied
  by the runner; rules remain placeholders only).
- **Threshold**: A single matching frame is enough to fire — keep the
  cap at 8192 bytes unless you have a legitimate reason to relax it.
- **Known false positives**:
  - Legitimate large HELLO from heavy-tailed agent build (whitelist
    via `ZAQORIN_SELF_DEFENSE_WHITELIST`).
  - Misconfigured CI runner retrying empty HELLO after an auth failure.

## References

- https://attack.mitre.org/techniques/T1190/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03 finding F-001](../../security/AUDIT-2026-09-03.md)