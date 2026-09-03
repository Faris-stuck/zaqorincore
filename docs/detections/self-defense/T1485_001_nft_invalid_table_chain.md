# T1485.001 — nft binary add/insert called with non-whitelisted table/chain

**MITRE**: [T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/)
**Sub-technique**: T1485.001 (ZaqorinCore-specific extension for
firewall-config destruction; closely related to [T1562.004 — Disable
or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/))
**Severity**: High
**Status**: Experimental
**Mapped finding**: F-4 from AUDIT-2026-09-03 (closed in v3.2.1)

## Summary

Detects attempts to invoke the `nft` binary with a table or chain name
that is not in the operator whitelist. After the v3.2.1 fix the agent
validates user-supplied table/chain strings against a whitelist before
passing them to `nft add rule` / `nft insert`. This rule fires when
validation REJECTS an input — meaning a probe or exploit attempt is
reaching the agent.

Operators with custom table layouts must extend the whitelist inside
the agent; this rule is intentionally strict and will produce false
positives for non-standard topologies.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: agent
detection:
  selection:
    event_type: nft.call
  filter_bad_table:
    target_table: 're:[/;|&$`]|\.\.'
  filter_bad_chain:
    target_chain: 're:[/;|&$`]|\.\.'
  condition: selection and (filter_bad_table or filter_bad_chain)
fields:
  - src_ip
  - agent_id
  - target_table
  - target_chain
level: high
```

## Sample event

```json
{
  "event_type": "nft.call",
  "src_ip": "198.51.100.10",
  "agent_id": "agent-edge-04",
  "target_table": "inet; DROP TABLE",
  "target_chain": "input",
  "ts": "2026-09-04T08:21:17Z"
}
```

## Tuning

- **No whitelist** — every rejection is meaningful. Whitelist operator
  custom tables by extending the agent's static whitelist.
- **Threshold**: Single rejection. Do not raise.
- **Known false positives**:
  - Legitimate operator using custom nft tables (extend agent whitelist).
  - Agent that has not been upgraded to v3.2.1 (no validation in place;
    upgrade required).

## References

- https://attack.mitre.org/techniques/T1485/
- https://attack.mitre.org/techniques/T1562/004/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03](../../security/AUDIT-2026-09-03.md)