# Phase 9 — Web Console

> Shipped in **v0.9.0** (commit &lt;filled-at-release&gt;, tag `v0.9.0`)

Phase 9 brings everything together under one roof: a single-page
operator console that talks to the same FastAPI the Go agent uses.

The console is **bundled with the server** — no separate build step, no
Node toolchain required. Drop the binary on a host, point a browser at
`http://<host>:8000/`, get the whole SOC.

## What's in the box

| View | URL hash | Talks to |
| --- | --- | --- |
| Alerts | `#/alerts` | `GET /api/v1/alerts?severity&host_id&limit&before` |
| Hunt | `#/hunt` | `GET /api/v1/hunt/rules`, `POST /api/v1/hunt/run` |
| Evidence | `#/evidence` | `GET /api/v1/evidence`, `POST /api/v1/evidence/{id}/verify` |
| Canary | `#/canary` | `GET/POST /api/v1/canary`, `GET /api/v1/canary/touched` |

All four views live in one React 18 SPA loaded from a single
`static/app.js` file. The page itself is plain HTML/CSS — no framework
beyond React itself, no build pipeline, no JSX compilation.

## How it's served

The server mounts the bundled SPA from `/webui/` at the repo root:

```
GET /              → webui/index.html  (the SPA shell)
GET /static/*      → webui/static/*    (React 18 + the app bundle)
GET /api/v1/*      → FastAPI routers   (the existing REST surface)
```

`/webui/` ships in the repository (no install step needed). The wiring
is gated on `_WEBUI_DIR.exists()` so a server-only deployment (no
console files copied) still boots cleanly — `/` simply 404s.

## Security headers

The Phase 9 server adds a single middleware (`SecurityHeadersMiddleware`)
that applies a baseline of HTTP security headers to **every** response —
both the API and the SPA. The defaults:

| Header | Value | Why |
| --- | --- | --- |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' https://esm.sh; …` | Limits what the page can load. The `esm.sh` exception is the one current escape hatch — see "Hardening roadmap" below. |
| `X-Content-Type-Options` | `nosniff` | Disables MIME sniffing. |
| `X-Frame-Options` | `DENY` | The console is never supposed to be in an iframe. |
| `Referrer-Policy` | `no-referrer` | This is a SOC console; do not leak. |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | A SOC console never needs any of these. |

Tested in `tests/test_webui.py::test_security_headers_on_spa` and
`test_security_headers_on_api`.

## Hardening roadmap (post-1.0)

The current CSP allows `https://esm.sh` because the console loads
React 18 from the CDN. This is a deliberate trade-off for v0.9.0:
no build step, no vendored deps, zero Node toolchain. After 1.0 the
plan is to:

1. Vendor `react@18.3.1`, `react-dom@18.3.1`, and the `scheduler`
   packages into `webui/static/vendor/`.
2. Update the importmap to point at `/static/vendor/...` (same origin).
3. Tighten CSP to `script-src 'self'` (drop the `https://esm.sh`
   exception).
4. Add a `Subresource Integrity` hash on the vendor `<script>` tag for
   belt-and-suspenders verification.

The test in `tests/test_webui.py` will be updated to assert the
post-1.0 CSP and a 200 response from `/static/vendor/react.js`.

## No auth (yet)

The console has **no authentication UI** in v0.9.0. It assumes the
server is reachable only on a trusted network (Tailscale, internal VPN,
localhost). Adding auth (OIDC / SAML / mTLS / simple bearer token) is
a v1.0+ task. When the user opens the page, every API call goes
through whatever the server's existing auth story is — in v0.9.0
that's *no auth at all*. See `ROADMAP.md` for the auth timeline.

## Files added / changed

| Path | Change |
| --- | --- |
| `webui/index.html` | NEW. SPA shell. |
| `webui/static/app.js` | NEW. React 18 bundle. |
| `server/src/zaqorincore_server/security.py` | NEW. Security headers middleware. |
| `server/src/zaqorincore_server/main.py` | Mount `/static`, serve `/`, add middleware, bump to `0.9.0`. |
| `server/tests/test_webui.py` | NEW. 6 tests covering SPA serving + security headers. |

## Verification

```bash
cd server && \
  ZAQORIN_DATABASE_URL='postgresql+asyncpg://zaqorin:zaqorin@127.0.0.1:25432/zaqorin_test' \
  ZAQORIN_REDIS_URL='redis://127.0.0.1:6379/15' \
  python -m pytest

# 170/170 PASS  (was 164 at v0.8.0; +6 webui tests)
```

Manual smoke (with the server running):

```bash
curl -i http://127.0.0.1:8000/                | head  # SPA shell, security headers
curl -i http://127.0.0.1:8000/static/app.js   | head  # React bundle
curl -i http://127.0.0.1:8000/api/v1/alerts   | head  # API + headers
```
