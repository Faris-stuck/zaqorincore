# T1078.001 — API key use from new src_ip or unusual hour

**MITRE**: [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Sub-technique**: T1078.001 (ZaqorinCore-specific extension; map to
ATT&CK [T1078.001 — Default Accounts](https://attack.mitre.org/techniques/T1078/001/)
or [T1078.004 — Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
when applicable)
**Severity**: Medium
**Status**: Experimental
**Mapped finding**: [F-006 v3.2.1](../../security/AUDIT-2026-09-03.md#f-006)

## Summary

Detects anomalous use of a valid API key. Two sub-signals combine:

1. `key_id` seen from a `src_ip` it has never been seen from before
   (baseline is per-process; degrade gracefully if baseline is absent).
2. 200-level API key authentication outside hours 06:00-22:00 local
   (operator-tunable via `ZAQORIN_SELF_DEFENSE_BUSINESS_HOURS`).

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: server
detection:
  selection:
    event_type: http.request
    auth_method: api_key
    status: 200
  filter_new_src_ip:
    key_first_seen_from_ip: true
  filter_off_hours:
    hour_of_day_local: "|lt: 6"
  condition: selection and (filter_new_src_ip or filter_off_hours)
  timeframe: 60s
  count: 1
fields:
  - src_ip
  - key_id
  - route
  - hour_of_day_local
level: medium
```

## Sample event

```json
{
  "event_type": "http.request",
  "auth_method": "api_key",
  "status": 200,
  "src_ip": "203.0.113.99",
  "key_id": "key-3a2c-9f0e",
  "route": "/api/v1/rules",
  "hour_of_day_local": 3,
  "ts": "2026-09-03T03:14:55Z"
}
```

## Tuning

- **Whitelist**: `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list).
- **Business hours**: Configure `ZAQORIN_SELF_DEFENSE_BUSINESS_HOURS`
  to override the default 06:00-22:00 local window. The runner emits
  `hour_of_day_local` based on the host timezone.
- **Baseline cold-start**: The rule degrades gracefully when the
  per-process baseline is empty — only the off-hours sub-signal will
  fire until the baseline warms up.
- **Known false positives**:
  - Operator working late hours (off-hours sub-signal).
  - CI/CD pipeline IP rotation (new-src-ip sub-signal; whitelist via
    `ZAQORIN_SELF_DEFENSE_WHITELIST`).

## References

- https://attack.mitre.org/techniques/T1078/
- https://attack.mitre.org/techniques/T1078/001/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03 finding F-006](../../security/AUDIT-2026-09-03.md)