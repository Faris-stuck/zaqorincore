# ZaqorinCore v3.2.1 — Remediation Plan (PHASE 3 findings)

Owner: TBD (orchestrator decides)
Generated: 2026-09-03
Source: `docs/security/AUDIT-2026-09-03.md`

## Prioritization

Order is by `(severity, exploit-precondition, blast-radius)`:

| # | ID | Title | Severity | Why prioritized |
|---|---|---|---|---|
| 1 | F-006 | Unauth `/stats` and `/version` leak | Medium | Zero-auth, zero-skill, immediate recon |
| 2 | F-008 | Audit log lost on restart | Medium | Forensic gap that compounds every other finding |
| 3 | F-011 | No lockfile on deps | Medium | Affects every `pip install` until fixed |
| 4 | F-007 | CSP allows CDN React, no SRI | Medium | Browser-side compromise = operator key exfil |
| 5 | F-009 | WebSocket no size cap / no heartbeat | Medium | Easy DoS, requires no credentials |
| 6 | F-010 | CORS policy not explicit | Medium | Future-contributor foot-gun |
| 7 | F-005 | `app.version` drift | Low | 1-line fix, prevents operator confusion |
| 8 | F-012 | `whoami` dev-mode leak | Low | Same root cause as F-006 — fix together |
| 9 | F-013 | Ingest missing audit hooks | Low | Couples to F-008 |
| 10 | F-014 | No `pip-audit` / `govulncheck` in CI | Low | Adds gate; pairs with F-011 |
| 11 | F-015 | `curl | bash` installer no signature | Low | Upstream-controlled risk; out of repo scope |
| 12 | F-016 | CSP `style-src 'unsafe-inline'` | Low | Couples to F-007 cleanup |

## Grouped fix proposals

### Group A — "Auth / disclosure surface" (F-005, F-006, F-012)

Single PR: gate `/api/v1/version`, `/api/v1/stats`, and reduce `/auth/whoami` payload.

* `api/v1/version.py:81` — put `dependencies=[Depends(require_role(Role.READ))]` on the
  router or split public version (no SHA) from operator version (with SHA).
* `api/v1/stats.py:59` — same.
* `api/v1/auth.py:46` — drop `dev_mode` and `configured_roles` from `WhoAmIOut`; keep
  only `role`.
* `main.py:130` — bump `version="3.2.0"` → `version="3.2.1"`.

Estimated diff: <50 lines.

### Group B — "Audit log promotion" (F-008, F-013)

Two-step:

1. Add `INSERT` into a `audit_events` table with append-only grant.
2. Wire `record()` into:
   * `RequestIDMiddleware` (catch every request)
   * ingest endpoints (Cloudflare, webhook) — explicit calls inside the handlers
3. Move in-memory ring buffer to a thin cache layer on top of the SQL store (so
   `snapshot()` still serves `/audit` quickly).

Estimated diff: ~150 lines + 1 Alembic migration.

### Group C — "Supply chain" (F-011, F-014)

1. Generate `server/requirements.lock` via `pip-compile pyproject.toml --generate-hashes`.
2. Generate `agent/go.sum` validation step (Go's `go mod verify` in CI).
3. Add CI steps:
   * `pip install pip-audit && pip-audit -r requirements.lock`
   * `go install golang.org/x/vuln/cmd/govulncheck@latest && cd agent && govulncheck ./...`
4. Gate merges on green audit.

### Group D — "WebUI hardening" (F-007, F-016)

1. Vendor React under `webui/static/vendor/react.js` + `react-dom.js`. Update
   `importmap` to point at local paths.
2. Tighten CSP: drop `https://esm.sh` from `script-src` and drop `'unsafe-inline'`
   from `style-src` (move inline styles to a stylesheet).
3. Add SRI attributes to any future CDN-hosted resource.

Estimated diff: ~10 lines of CSP, ~3 vendored files (~700 KB minified).

### Group E — "WebSocket hardening" (F-009)

1. Wrap `ws.receive_text()` with a 64 KiB cap; close 1009 on overflow.
2. Add `ping_interval=30`, `ping_timeout=10` to uvicorn.
3. Consider per-IP connection cap (use Starlette's middleware + a Redis-free in-memory
   counter since WS is server-side only).

Estimated diff: ~30 lines.

### Group F — "Future-proof CORS" (F-010)

Add `CORSMiddleware(allow_origins=[], allow_credentials=False)` explicitly. Currently a
no-op (Starlette default already returns no CORS headers), but documents the intent.

Estimated diff: 5 lines.

### Group G — "Installer signing" (F-015)

Out-of-repo (release server). Document the contract in `SECURITY.md`:
"ZaqorinCore releases ship with an `install.sig` companion to `install.sh`; the
provisioner endpoint returns the verified SHA-256 next to the rendered command."

## Validation steps (after fixes ship)

* Re-run `search_files` for the patterns in the original Phase 3 sweep; every hit
  should be in a comment, a doc, or a test fixture.
* Re-run `pip-audit` against the new lockfile — should be zero findings.
* `curl http://localhost/api/v1/stats` without `X-API-Key` should return 401.
* `curl http://localhost/api/v1/version` without `X-API-Key` should return 401.
* `pytest server/tests/` — full suite, no regressions.

## Risk of doing nothing

* Recon: any operator with a reachable port 8443 gives an attacker an exact version +
  commit + agent count.
* Forensics: an attacker who crashes the process deletes the audit log.
* Supply chain: a transitive dep's malicious release lands on every `pip install`
  with no hash gate.
* DoS: a single TCP peer can hold the WebSocket slot indefinitely.

The fixes are mostly small, isolated, and behind the existing test suite. None of
them require new infra.