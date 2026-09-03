# F-010: No explicit CORS policy — Starlette default is permissive for browser fetches

| Field | Value |
|---|---|
| Severity | Medium |
| CWE | CWE-942 (Permissive Cross-domain Policy with Untrusted Domains) |
| CVSS-like | 5.4 (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) |
| Location | `server/src/zaqincore_server/main.py:122-180` (no CORS middleware) |
| Status | Open |

## Description

The middleware stack in `create_app()` is:

```python
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(ErrorEnvelopeMiddleware)
```

There is no `CORSMiddleware` from `starlette.middleware.cors`. FastAPI / Starlette's
default behavior with no CORS middleware is to **not emit any `Access-Control-*`
headers**, which means browsers will block cross-origin requests that need preflight
(`OPTIONS` + `Access-Control-Request-Method`). For simple GET / POST without custom
headers, browsers will *attempt* the request and *not* send cookies.

That is correct security-by-default behavior — but only if it stays that way. The risk is:

* **WebUI at `/` with `localStorage` cache** — if a future engineer adds a
  `CORSMiddleware(allow_origins=["https://example.com"])` to "fix" an integration
  bug, every site on the internet could then call `/api/v1/*` with the operator's
  cached `X-API-Key` (if it ever gets cached there). The current absence of CORS
  middleware is fine; the absence of any **documented policy** is the issue.
* **No preflight protection** for the operator UI — if a third-party site embeds the
  WebUI via an iframe, modern browsers will block it (good), but the failure mode
  (`X-Frame-Options: DENY` is set, which catches this). The interaction between
  `X-Frame-Options: DENY` and CORS is implicit.

## Impact

Today: low impact — Starlette's default is "no CORS = browser blocks", which is the
desired behavior.

Forward-looking: medium impact — the moment a future contributor adds CORS middleware
without reading this concern, every browser-credentialed integration becomes a
cross-origin-attack surface. Documentation gap = future CVE.

## POC sketch

Today: not directly exploitable. A preflight `OPTIONS` to any `/api/v1/*` route from a
cross-origin script is rejected by the browser (no `Access-Control-Allow-Origin`).

## Remediation sketch

Either:

* Document in `ARCHITECTURE.md` and `SECURITY.md` that ZaqorinCore intentionally runs
  **without** CORS middleware, the WebUI is same-origin only, and any cross-origin
  integration must proxy through a server the operator controls; OR

* Add `CORSMiddleware` with `allow_origins=[]` and `allow_credentials=False`
  explicitly to make the policy self-documenting and unambiguous to future
  contributors.