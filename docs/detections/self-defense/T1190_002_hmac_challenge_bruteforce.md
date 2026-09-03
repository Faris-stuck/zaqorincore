# T1190.002 — WS HMAC challenge failures burst from single src_ip

**MITRE**: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
**Sub-technique**: T1190.002 (ZaqorinCore-specific extension;
brute-force variant of T1190)
**Severity**: Medium
**Status**: Experimental
**Mapped finding**: F-1 from AUDIT-2026-09-03 (HMAC challenge-response;
closed in v3.2.1)

## Summary

Detects a burst of failed HMAC challenges on `/ws/agent` from a single
source IP. 10 failures inside a 60-second window is a strong signal of
a brute-force attempt against the HMAC challenge secret (the v3.2.1
fix added the challenge-response; this rule fires when an attacker is
guessing).

The threshold is generous to absorb clock-skew and small network
glitches; legitimate agents that repeatedly fail should be investigated
for misconfiguration rather than whitelisted.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: server
detection:
  selection:
    event_type: ws.hello
    auth_method: hmac
    status: 401
  condition: selection
  timeframe: 60s
  count: 10
  by: src_ip
fields:
  - src_ip
  - key_id
level: medium
```

## Sample event

```json
{
  "event_type": "ws.hello",
  "auth_method": "hmac",
  "status": 401,
  "src_ip": "203.0.113.42",
  "key_id": "key-7d9f-2b1a",
  "ts": "2026-09-04T03:51:08Z"
}
```

## Tuning

- **Whitelist**: Use sparingly. Misconfigured agents should be fixed,
  not whitelisted.
- **Threshold**: 10 failures per `src_ip` per 60s. Lower to 5 for
  stricter posture; raise to 20 only if you have a known clock-skew
  problem across the fleet.
- **Known false positives**:
  - Clock skew on the agent causing legitimate failures.
  - Agent rebooting repeatedly inside the window.
  - Misconfigured agent with rotated secret not yet propagated.

## References

- https://attack.mitre.org/techniques/T1190/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03](../../security/AUDIT-2026-09-03.md)