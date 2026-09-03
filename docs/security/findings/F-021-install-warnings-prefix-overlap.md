# F-021 — F-019 redaction logic bypassed by DNS-name prefixes that overlap RFC1918 octets

| Field        | Value                                                                  |
|--------------|------------------------------------------------------------------------|
| ID           | F-021                                                                  |
| Severity     | Low                                                                    |
| CWE          | CWE-200 Information Exposure (re-opens F-019)                          |
| Affected     | `server/src/zaqorincore_server/api/v1/agents_provision.py`            |
| Endpoint     | `POST /api/v1/agents/provision/install-command`                       |
| Discovered   | cycle 67 — Round 6 (Phase 1) SECURITY audit                           |
| Status       | Open                                                                   |

## Summary

The F-019 redaction guard (commit `5d4a689`, v3.4.7) classifies a `host`
value as "internal" and skips redaction when it starts with one of these
**literal** prefixes (lines 713–714 of `agents_provision.py`):

```python
if not host.startswith(("zaqorin-", "10.", "192.168.", "172.")):
    # … redact hostname in response …
```

The `10.` and `172.` prefixes are RFC1918 octet prefixes, but the
check is a substring match against the **start of the host string** —
not against a parsed IP address. Any **public DNS name** whose first
label happens to start with `10`, `100`, `101`, … `109` (or `1720`,
`1721`, … `1729`) will satisfy `host.startswith("10.")` /
`host.startswith("172.")` and the warning will be **skipped**, so the
literal hostname is echoed back to the response — the exact leak F-019
was meant to close.

`192.168.` is unlikely to collide with public DNS (every registrable
label starting with `192.168.` would have to be a `.168` sub-label of
a `192.` TLD-or-lower zone, which isn't realistic today). The
`zaqorin-` prefix is a separate concern and out of scope for this
finding.

## Reproduction

```bash
# Public DNS name starting with "10" — redaction SKIPPED:
curl -X POST https://zaqorin/api/v1/agents/provision/install-command \
     -H "X-API-Key: ***" -H "Content-Type: application/json" \
     -d '{"agent_id":"a","host":"10x.example.com"}'
# → response.warnings contains:
#     "host '10x.example.com' is a public DNS name …"   ← LEAK

# Public DNS name starting with "1720" — redaction SKIPPED:
curl -X POST https://zaqorin/api/v1/agents/provision/install-command \
     -H "X-API-Key: ***" -H "Content-Type: application/json" \
     -d '{"agent_id":"a","host":"1720-sensor.example.com"}'
# → same leak as above

# Public DNS name starting with "v" (the original F-019 example):
curl -X POST https://zaqorin/api/v1/agents/provision/install-command \
     -H "X-API-Key: ***" -H "Content-Type: application/json" \
     -d '{"agent_id":"a","host":"vps-jakarta-web-01.example.com"}'
# → redacted correctly (F-019 fix works for this case).
```

## Impact

Same shape as F-019: the response body echoes a hostname the caller
already supplied, confirming how the server classified their input.
The original F-019 reasoning still applies — disclosure is low-impact
in isolation (the caller already knew the value they sent), but the
response shape still violates the principle that the response body
should not echo server-side classification metadata.

The Round 4 (cycle 63) test `test_install_command_warnings_redact_public_dns`
uses `vps-jakarta-web-01.example.test` and so does not exercise the
overlap cases — the bug shipped without test coverage.

## Recommendation

Decide **either** by trying to parse `host` as an IP address
(`ipaddress.ip_address(host)`) **or** by requiring the prefix match to
be the full first label of an RFC1918 address (i.e. exactly `10`,
`172`, or `192.168`, followed by `.` and an IP octet). The cleanest
fix is the IP-parse path:

```python
import ipaddress

def _is_rfc1918(host: str) -> bool:
    # Bracketed IPv6 literals arrive from _safe_host already-stripped
    # for the regex test, but here we try the raw string first.
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False  # Not an IP → treat as DNS name → redact
    return (
        ip in ipaddress.ip_network("10.0.0.0/8")
        or ip in ipaddress.ip_network("172.16.0.0/12")
        or ip in ipaddress.ip_network("192.168.0.0/16")
    )

# …

if not _is_rfc1918(host) and not host.startswith("zaqorin-"):
    # redact
```

This forces a clean separation: IPs go through the IP parser, DNS
names go through the DNS branch. The current substring check
conflates the two.

A second, smaller fix is to add a regression test
(`test_install_command_warnings_redact_dns_prefix_overlap`) that
submits `host="10x.example.com"` and asserts the literal hostname is
not echoed — the test will fail today and pass after the fix.

## Defense in depth

The `self_defense/event_normalizer.py::_redact_hostname` helper
mentioned in F-019's "defense in depth" section is the right place to
land this fix once — both the CSP report path and the install-command
endpoint should call the same helper so a future field cannot regress
either of them.

## Status

Open. Round 6 audit (cycle 67) reports; Phase 2 of cycle 67 will fix
+ add regression test, following the same workflow that closed F-019
in cycle 63.