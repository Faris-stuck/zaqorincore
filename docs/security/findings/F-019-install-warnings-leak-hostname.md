# F-019 — install-command warnings field may echo the requester's public DNS hostname

| Field        | Value                                                                    |
|--------------|--------------------------------------------------------------------------|
| ID           | F-019                                                                    |
| Severity     | Low                                                                      |
| CWE          | CWE-200 Information Exposure                                            |
| Affected     | `server/src/zaqorincore_server/api/v1/agents_provision.py`              |
| Endpoint     | `POST /api/v1/agents/provision/install-command`                         |
| Discovered   | cycle 57 — CEO discovery during F-015 fix testing                        |
| Closed in    | cycle 63 — Phase 1 (v3.4.7)                                             |

## Summary

The `/api/v1/agents/provision/install-command` response includes a
`warnings: list[str]` field. When the requester's `host` value is
classified as a public DNS name (does not match any RFC1918 / known
internal prefix), the warning text `"host 'X' is a public DNS name"`
echoes the literal hostname back to the caller.

An operator (or an attacker who can read their own response payload)
can therefore confirm that the value they submitted is, in fact,
treated by the server as a public DNS name. Low impact — the same
attacker already *knew* the hostname they sent — but the disclosure
shape still violates the principle that the response body should
contain only what the client needs to act on, not server-side
classification metadata.

The server-side log already records the request with the full
hostname for the operator to correlate on, so the warning can fire
without echoing it in the response body.

## Reproduction

```bash
curl -X POST https://zaqorin/api/v1/agents/provision/install-command \
     -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
     -d '{"agent_id":"a","host":"vps-jakarta-web-01"}'
# → response.warnings contains:
#     "host 'vps-jakarta-web-01' is a public DNS name; ..."
```

The literal hostname appears in the JSON response body.

## Recommendation

Replace the hostname in the warning string with a stable SHA-256
prefix. The warning should still fire (the operator can correlate
the hash against the request log to recover the full value), but
the response should not echo the literal name.

Fix sketch:

```python
warnings.append(
    f"host {hashlib.sha256(host.encode()).hexdigest()[:12]} "
    "is a public DNS name (name redacted — see server logs)"
)
```

This is deterministic (same input → same hash prefix) so the
operator can grep the request log for the prefix and find the
full hostname.

## Status

Closed in v3.4.7 by the cycle 63 Phase 1 SECURITY fix. The warning
LOG continues to record the literal hostname for the operator; only
the response field is redacted.

## Defense in depth

`sserver/src/zaqorincore_server/self_defense/event_normalizer.py`
gains a `_redact_hostname` helper used wherever a hostname-shaped
value (e.g. `document-uri`) flows into a `ZaqorinEvent`. The CSP
report path does not currently attach a hostname to the event, but
the helper is wired in so a future field addition cannot regress
this guarantee.