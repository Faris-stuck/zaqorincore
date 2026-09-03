# T1505.003 — WebUI CSP violation (blocked inline script or style)

**MITRE**: [T1505 — Server Software Component](https://attack.mitre.org/techniques/T1505/)
**Sub-technique**: T1505.003 (ZaqorinCore-specific extension; closely
related to [T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/))
**Severity**: Medium
**Status**: Experimental
**Mapped finding**: [F-007 v3.2.1](../../security/findings/F-007-csp-permits-cdn-react.md)
and [F-016 v3.2.1](../../security/findings/F-016-csp-unsafe-inline-style.md)

## Summary

Detects browser-side CSP violation reports. The `/api/v1/_csp-report`
endpoint ingests the standard CSP violation JSON. The rule fires when
3 or more reports come from the same `src_ip` within 10 minutes AND
the violated directive is `script-src` or `style-src` (the two
XSS-relevant directives). Single reports are normal during WebUI
development; the threshold filters out the noise.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: webui
detection:
  selection:
    event_type: csp.violation
    violated_directive:
      - script-src
      - style-src
  condition: selection
  timeframe: 10m
  count: 3
fields:
  - src_ip
  - violated_directive
  - blocked_uri
  - document_uri
level: medium
```

## Sample event

```json
{
  "event_type": "csp.violation",
  "src_ip": "198.51.100.10",
  "violated_directive": "script-src",
  "blocked_uri": "inline",
  "document_uri": "https://zaqorin.example.com/agents",
  "ts": "2026-09-03T09:11:24Z"
}
```

## Tuning

- **Whitelist**: `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list) for
  operator networks with noisy browser extensions.
- **Threshold**: 3 reports per 10 minutes per `src_ip`. Lower to 1 if
  you run the WebUI in a tightly locked environment.
- **Known false positives**:
  - Browser extensions injecting inline styles into the WebUI
    (operator can whitelist their own network).
  - Browser bugs producing duplicate reports on first page load.

## References

- https://attack.mitre.org/techniques/T1505/
- https://attack.mitre.org/techniques/T1189/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [F-007 finding](../../security/findings/F-007-csp-permits-cdn-react.md)
- [F-016 finding](../../security/findings/F-016-csp-unsafe-inline-style.md)