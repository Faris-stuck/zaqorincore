# T1098.001 — Audit log JSONL persistence silently disabled

**MITRE**: [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
**Sub-technique**: T1098.001 (ZaqorinCore-specific extension; closely
related to [T1562.008 — Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
and [T1070.002 — Clear Linux or Mac Logs](https://attack.mitre.org/techniques/T1070/002/))
**Severity**: High
**Status**: Experimental
**Mapped finding**: [F-008 v3.2.1](../../security/AUDIT-2026-09-03.md#f-008)

## Summary

Detects the audit-log JSONL persistence being disabled unexpectedly. The
audit healthcheck emits an `audit.healthcheck` event every 5 minutes
carrying `jsonl_persistence_enabled`. A single observation of `false`
is a signal — silent disable is a stealth attack pattern (defence
evasion and impair defenses).

The rule is intentionally noisy at threshold 1 because a single
disabling event is enough to require operator review; the false
positives listed below are rare and worth investigating regardless.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: audit
detection:
  selection:
    event_type: audit.healthcheck
    jsonl_persistence_enabled: false
  condition: selection
  timeframe: 24h
  count: 1
fields:
  - src_ip
  - audit_log_dir
  - jsonl_persistence_enabled
level: high
```

## Sample event

```json
{
  "event_type": "audit.healthcheck",
  "src_ip": "198.51.100.10",
  "audit_log_dir": "/var/log/zaqorincore",
  "jsonl_persistence_enabled": false,
  "ts": "2026-09-03T12:05:00Z"
}
```

## Tuning

- **No whitelist** — disabling JSONL persistence should never be
  silent. Investigate every hit.
- **Threshold**: Single observation in 24 hours. Do not raise.
- **Known false positives**:
  - Operator intentionally disabled JSONL for a one-off debug session
    (should be re-enabled before deploy).
  - Filesystem permission drift on `ZAQORIN_AUDIT_LOG_DIR` after a
    `chmod` change.

## References

- https://attack.mitre.org/techniques/T1098/
- https://attack.mitre.org/techniques/T1562/008/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03 finding F-008](../../security/AUDIT-2026-09-03.md)