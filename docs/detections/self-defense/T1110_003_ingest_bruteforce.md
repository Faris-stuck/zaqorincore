# T1110.003 — Ingest endpoint 401/403 burst from single IP

**MITRE**: [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
**Sub-technique**: [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
**Severity**: High
**Status**: Experimental
**Mapped finding**: [F-013 v3.2.1](../../security/AUDIT-2026-09-03.md#f-013)

## Summary

Detects credential stuffing and brute-force against the ingest endpoints.
Fires when a single `src_ip` produces 20 or more 401/403 responses
against `/api/v1/ingest/*` routes in a 5-minute window. The rule
complements the existing rate-limit middleware by producing a Sigma-level
signal that the runner can correlate with other behaviour, not just a
429 response.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: server
detection:
  selection:
    event_type: http.request
    route: "|startswith: /api/v1/ingest/"
    status:
      - 401
      - 403
  condition: selection
  timeframe: 5m
  count: 20
fields:
  - src_ip
  - route
  - status
  - key_id
level: high
```

## Sample event

```json
{
  "event_type": "http.request",
  "src_ip": "203.0.113.42",
  "route": "/api/v1/ingest/events",
  "status": 401,
  "key_id": "key-7d9f-2b1a",
  "ts": "2026-09-03T03:42:11Z"
}
```

## Tuning

- **Whitelist**: `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list).
- **Threshold**: 20 failures in 5 minutes is the default. Raise to 50
  if you run an aggressive penetration test schedule; lower to 10 for
  stricter posture.
- **Known false positives**:
  - Single misconfigured client retrying after credential rotation.
  - Penetration-test traffic (whitelist via
    `ZAQORIN_SELF_DEFENSE_WHITELIST`).

## References

- https://attack.mitre.org/techniques/T1110/003/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [AUDIT-2026-09-03 finding F-013](../../security/AUDIT-2026-09-03.md)