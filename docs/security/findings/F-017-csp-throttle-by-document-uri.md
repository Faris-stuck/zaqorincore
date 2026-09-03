# F-017 — CSP report endpoint throttle keyed by document_uri instead of src_ip (Medium)

**Component**: `server/src/zaqorincore_server/self_defense/csp_violation_reporter.py` (added in v3.3.0)
**CWE**: CWE-770 (Allocation of Resources Without Limits or Throttling)
**Severity**: Medium
**Status**: Open
**Discovered**: 2026-09-03 (Round 2 post-v3.4.0 audit)

## Description

The `POST /api/v1/_csp-report` endpoint is rate-limited by a sliding-window
throttle, but the throttle key is the **`document-uri` host** parsed out of
the report body (line 100) rather than the **source IP** of the HTTP request.

```python
# Lines 92-100 of csp_violation_reporter.py
# We do not have access to ``Request`` here without changing
# the signature; the throttle is keyed by the document-uri
# host (best-effort anti-abuse). Operators wanting stronger
# source-IP binding should front this endpoint with a proxy
# that injects ``X-Forwarded-For`` and use the
# ``src_ip_header`` config (out of scope here).
document_uri = ""
if isinstance(payload.get("csp-report"), dict):
    document_uri = str(payload["csp-report"].get("document-uri") or "")
```

## Impact

An attacker controlling many victim browsers (or a single browser that
follows many malicious links) can submit CSP reports for arbitrary
`document-uri` values, each consuming a fresh 10-reports-per-minute
budget keyed on the attacker's chosen host. This effectively bypasses
the per-src_ip intent of the throttle.

In the worst case, a botnet submitting forged CSP reports at
`document-uri=https://attacker.example/` would never trip the throttle
because each new host is a fresh bucket.

The endpoint also has **no body size limit** beyond the global 1 MiB
guard in `Content-LengthMiddleware`. An attacker can POST 1 MiB bodies
repetitively within the budget window.

## Reproduction (conceptual, no live payload)

```bash
# 100 reports, each with a unique document-uri. None are rate-limited.
for i in $(seq 1 100); do
  curl -fsS -X POST http://target/api/v1/_csp-report \
    -H 'Content-Type: application/csp-report' \
    -d "{\"csp-report\":{\"document-uri\":\"https://attacker$i.example/\",\"violated-directive\":\"script-src\"}}"
done
```

All 100 requests return 204. With proper src_ip throttling, the 11th
request from a single IP would return 429.

## Recommendation

1. Add `Request` parameter to `receive_csp_report` and throttle on
   `request.client.host` (with `X-Forwarded-For` opt-in via
   `src_ip_header` config).
2. Add a global per-endpoint body size guard (e.g. 64 KiB) since CSP
   reports are tiny in practice.
3. Add a Sigma rule to detect this attack pattern: many CSP reports
   with distinct document-uri from a single src_ip.

## Mitigation priority

Medium. The endpoint is unauthenticated and the rate limit bypass
enables resource exhaustion. Fix should ship in v3.4.1 hotfix.
