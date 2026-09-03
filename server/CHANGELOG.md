# Changelog

All notable changes to ZaqorinCore Server are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project adheres to [Semantic Versioning](https://semver.org/).

## [3.2.3] - 2026-09-03 - Security: lockfile, CI security-audit, WS size cap, CORS, CSP local-bundle + style nonce

### Security fixes (AUDIT-2026-09-03 Group C, D, E)

- **F-011** — Lockfile for server deps. Added `server/requirements.lock`
  pinning 87 packages (12 direct + 75 transitive). Widened the upper
  bounds in `pyproject.toml` so they no longer contradict the locked
  versions. The agent's `go.sum` was already present and is now
  covered by the new audit workflow.
- **F-014** — CI security audit. Added
  `.github/workflows/security-audit.yml` running `pip-audit` on the
  server and `govulncheck` on the agent weekly and on every PR that
  touches a dep manifest. SARIF is uploaded to the Security tab.
- **F-009** — WebSocket DoS hardening. Per-frame size cap
  (`ZAQORIN_WS_MAX_MSG_BYTES`, default 1 MiB) and a per-connection
  message-rate cap (`ZAQORIN_WS_MAX_MSG_PER_MIN`, default 100/min).
  Violations drop the connection with code `1009` (msg too big) or
  `1013` (try again later).
- **F-010** — Explicit CORS middleware. Replaced Starlette's default
  wildcard with an allowlist driven by `ZAQORIN_API_CORS_ORIGINS`
  (comma-separated). Allowed methods: GET/POST/PUT/DELETE. Allowed
  headers: `X-ZaQorin-Key`, `Content-Type`. Wildcard is rejected when
  `allow_credentials=True`.
- **F-007** — CSP no longer trusts `https://esm.sh`. The bundled web
  console is plain HTML/CSS/JS — no React CDN is loaded at runtime —
  so the `script-src` directive now lists `'self'` only. The console
  is server-served and self-contained.
- **F-016** — Removed `'unsafe-inline'` from `style-src`. The console
  has zero `style=` attributes and no inline `<style>` tags (the
  stylesheet moved to `/static/app.css`). When a future patch adds
  inline styling, the middleware will mint a per-request CSP nonce
  and accept only nonce-bearing `<style>` blocks.

### Tests

- New `server/tests/test_security_v3_2_3.py` covers all six fixes.

## [3.2.2] - 2026-09-03 - Security: app.version metadata, stats/version auth, audit JSONL, whoami redaction, ingest audit hooks

(F-005, F-006, F-008, F-012, F-013. See git log b1eb601.)
