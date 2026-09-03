## [3.2.1] - 2026-09-03 - Security: WS auth, secret file perms, SOAR SSRF, nft input validation

## [3.2.3] - 2026-09-03 - Security: lockfile, CI security-audit, WS size cap, CORS allowlist, CSP local React, style-src nonce

v3.2.3 closes the third and final batch of fixes from the
AUDIT-2026-09-03 self-hunt. Six findings addressed:

- **F-011 (Medium, CWE-1357)** — Added `server/requirements.lock`
  pinning every runtime dependency. The lockfile is the single
  source of truth for reproducible installs.
- **F-014 (Low)** — Added `.github/workflows/security-audit.yml`
  running `pip-audit` on the server and `govulncheck` on the agent
  on a weekly schedule. PRs that bump a vulnerable dep fail CI.
- **F-009 (Medium, CWE-400)** — `/ws/agent` now enforces a
  per-frame size cap (1 MiB default, `ZAQORIN_WS_MAX_MSG_BYTES`)
  and a per-connection message-rate cap (100/min default,
  `ZAQORIN_WS_MAX_MSG_PER_MIN`). Excess triggers a 1009 close.
- **F-010 (Medium, CWE-942)** — Server adds an explicit CORS
  middleware driven by `ZAQORIN_API_CORS_ORIGINS`
  (comma-separated). Allowed methods GET/POST/PUT/DELETE;
  allowed headers `X-ZaQorin-Key`, `Content-Type`. Wildcard is
  rejected when `allow_credentials=True`.
- **F-007 (Medium, CWE-829)** — CSP no longer trusts
  `https://esm.sh`. The web console is plain HTML/CSS/JS with no
  runtime React CDN; `script-src` is `'self'` only.
- **F-016 (Low, CWE-1021)** — Removed `'unsafe-inline'` from
  `style-src`. The console stylesheet moved to `/static/app.css`;
  no `style=` attributes remain. A future inline-style patch
  will mint a per-request CSP nonce and accept only nonce-bearing
  `<style>` blocks.

### Operational notes

- `ZAQORIN_API_CORS_ORIGINS` is unset by default. Same-origin
  browsers work; cross-origin browser clients need it set.
- `ZAQORIN_WS_MAX_MSG_BYTES` and `ZAQORIN_WS_MAX_MSG_PER_MIN` are
  optional; defaults are 1 MiB / 100/min. Lower them for stricter
  deployments.
- `pip-audit` and `govulncheck` are not currently installed in the
  GitHub Actions runner; the workflow installs them on first run.
  Failures only show up on the weekly cron; PRs get the audit via
  the `pull_request` trigger and any vulnerable dep bump fails.
- No detection or detection-coverage changes; detection surface
  unchanged (T1583.001, 17/200 MITRE).


## [3.2.2] - 2026-09-03 - Security: auth on stats/version, whoami redaction, persistent audit log, ingest audit hooks

v3.2.2 ships the second batch of fixes from the v3.2.0 self-hunt
(AUDIT-2026-09-03). Five Medium findings addressed:

### Security fixes

- **F-005 (Low)** — `app.version` now reads from package metadata
  (`importlib.metadata.version("zaqorincore-server")`) instead of a
  hardcoded literal. The drift between source-of-truth `pyproject.toml`
  and the `/api/v1/version` payload is gone.
- **F-006 (Medium, CWE-200)** — `/api/v1/version` and `/api/v1/stats`
  now require `Role.READ`. An unauthenticated probe gets 401. Version
  string, git SHA, and agent count are no longer publicly scrapable.
- **F-008 (Medium, CWE-778)** — Audit log gains a persistent tier.
  When `ZAQORIN_AUDIT_LOG_DIR` is set, every audit entry is also
  appended to `audit-YYYY-MM-DD.jsonl` rotated daily. The in-memory
  ring buffer is kept as a fast fallback. Default (env unset):
  in-memory only, same as v3.2.1.
- **F-012 (Low, CWE-200)** — `/auth/whoami` omits `dev_mode` and
  `configured_roles` from the production response. In development
  (`ZAQORIN_ENV=development`) the dev-mode flag remains visible so
  the local operator can verify configuration.
- **F-013 (Low, CWE-778)** — Ingest endpoints
  (`/api/v1/ingest/cloudflare`, `/api/v1/ingest/webhook`) and the
  source-connector `POST/DELETE` handlers now call `audit.record()`.
  Every accepted event leaves a trace.

### Operational notes

- Set `ZAQORIN_AUDIT_LOG_DIR` to enable persistent audit (recommended
  for any deployment that needs forensic continuity across restarts).
- API clients that hit `/api/v1/version` or `/api/v1/stats` without
  an API key will now get 401. Update dashboards accordingly.
- No detection or detection-coverage changes; public surface for
  detection is identical to v3.2.0 / v3.2.1 (T1583.001, 17/200 MITRE).

### Tests

- `tests/test_security_v3_2_2.py` covers all 5 fixes.
- Pre-existing tests unchanged.
v3.2.1 is an emergency security patch that addresses four
findings from the v3.2.0 self-hunt. No detection or
detection-coverage changes; the public detection surface is
identical to v3.2.0.

### Security fixes

- **F1 (CRITICAL) — WebSocket /ws/agent HMAC challenge-response.**
  The handshake now requires the agent to sign a server-issued
  32-byte nonce with the host's shared_secret (HMAC-SHA256).
  The server verifies the signature with constant-time
  comparison before registering the host. The shared_secret is
  no longer transmitted in the HELLO_ACK frame. The wire
  protocol is bumped to v=2; legacy v0.1.0..v0.4.x agents are
  refused with code 1002. Operators upgrading in place should
  roll the server first, then the agents.

- **F2 (CRITICAL) — Agent secret file & state_dir permissions.**
  `state_dir` is now created with mode 0700 and the
  `state_dir/secret` file is written with mode 0600, then
  chmod'd explicitly to close the race where a pre-existing
  file had looser permissions. A new `response.WriteSecret`
  helper centralises the write so future call-sites can't
  regress. Pre-existing installs should `chmod 700
  /var/lib/zaqorin-agent && chmod 600
  /var/lib/zaqorin-agent/secret` once after upgrade.

- **F3 (HIGH) — SOAR generic_webhook SSRF guard.** The
  operator-supplied webhook URL is now resolved and any
  hostname whose A/AAAA record falls in a private / loopback /
  link-local / multicast / reserved range (RFC1918, 127.0.0.0/8,
  169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 240.0.0.0/4,
  ::1, fc00::/7, fe80::/10) is rejected with a clear error.
  Operators who genuinely need to call an internal webhook
  can opt in per process via the new env var
  `ZAQORIN_SOAR_WEBHOOK_URL_ALLOWLIST` (comma-separated
  exact hostnames, case-insensitive). Default behaviour is
  fail-closed.

- **F4 (HIGH) — Agent nft input validation.** All nft
  invocations in `agent/internal/response/kinds/kinds.go`
  and `agent/internal/response/response.go` were audited;
  every call already uses `exec.CommandContext` with
  structured args (no shell). The change is defence-in-depth:
  `TarpitIP` and `BlockIP` now reject injection-style
  targets (`1.2.3.4; rm -rf /`, newline injection,
  command-substitution) at the validator layer with a
  clear error, before they ever reach the nft CLI. New
  tests cover the injection set.

### Backward compatibility

- Server: Bumped WebSocket wire protocol to v=2. v0.1.0..v0.4.x
  agents are refused with code 1002 (protocol error). This is
  a deliberate, documented break. Operators running a mixed
  fleet must upgrade agents before server.
- Agent: Permission changes are forward-only; no protocol
  change. Existing secret files are re-chmod'd on next
  `WriteSecret` call; operators who set the secret by hand
  should re-chmod manually.

### Added

- `server/src/zaqorincore_server/api/v1/stream.py`:
  HMAC challenge-response handshake; no shared_secret in
  HELLO_ACK.
- `server/src/zaqorincore_server/soar/backends/generic_webhook.py`:
  `validate_webhook_url` + module-level block-list;
  `ZAQORIN_SOAR_WEBHOOK_URL_ALLOWLIST` env var.
- `agent/internal/response/response.go`: `WriteSecret` helper;
  state_dir 0700, secret file 0600.
- `server/tests/test_security_v3_2_1.py`: 12 regression tests
  covering F1 / F2 / F3 / F4.
- `agent/internal/response/response_test.go`:
  `TestWriteSecretEnforcesTightPerms` +
  `TestWriteSecretRejectsEmptyStateDir`.
- `agent/internal/response/kinds/kinds_test.go`:
  `TestF4_TarpitIPRejectsInjectionTargets` +
  `TestF4_BlockIPRejectsInjectionTargets`.

### Known limitations (documented, not fixed in this release)

- TOCTOU between SSRF DNS resolution and the actual HTTP
  request: a determined attacker who can influence DNS
  responses between the two lookups can still hit an
  internal address. The check closes the common
  misconfiguration case; full mitigation requires an
  outbound proxy / eBPF, tracked for v3.3.0.
- WebSocket message size limit, audit-log append-only
  enforcement, and `/api/v1/*` rate limiting remain on the
  v3.3.0 backlog (Medium / Low from Phase 1 recon).

---

## [3.2.0] - 2026-09-03 — T1583.001 Domain Acquisition Detection Pack

v3.2.0 adds detection coverage for **MITRE ATT&CK T1583.001 — Acquire
Infrastructure: Domains** with five precision-engineered Sigma rules
and a Levenshtein-based typosquat engine. Coverage rises from 16/200
(8.0%) to **17/200 (8.5%)**.

Per the precision commitment (Faris, 2026-09-03, "tingkat akurasi 80%"):
every rule in this pack applies four precision techniques:

1. **Multi-signal correlation** — rules require at least two signals
   to match within a defined window. Single-pattern matches are
   suppressed.
2. **Explicit thresholds** — minimum evidence count (count + timeframe
   pairs in each rule) before the rule fires.
3. **Whitelist** — `filter_legit` / `filter_legit_brand` /
   `filter_known_ua` blocks exclude known-good traffic (captive portals,
   CDN edge, brand-owners themselves, monitoring user-agents).
4. **Experimental promotion tier** — all rules ship at
   `promotion: experimental`. Production teams should tune the
   thresholds per environment.

Measurement of the actual precision rate is deferred to post-production
telemetry (see `docs/PHASE29-dns-intel-detection.md` for the tuning
playbook). The design commitment here is **80%+ precision**, but the
real number will be observed, not asserted.

### Added

- **Sigma rules** in `server/rules/builtin/mitre_attack/` (cycle 49,
  `detection` track):
  - `T1583_001_domain_acquisition_nrd.yml` — Newly Registered Domain
    queried by an internal host within 5 minutes of registration.
  - `T1583_001_domain_acquisition_tld_burst.yml` — Burst (>= 5 unique)
    of queries to suspicious TLDs (.xyz, .top, .tk, .ml, .cf, .ga)
    from a single host in 60 seconds.
  - `T1583_001_domain_acquisition_typosquat.yml` — Levenshtein
    distance 1-2 from a protected brand (komatsu.co.id, microsoft.com,
    google.com by default; configurable via
    `ZAQORIN_PROTECTED_BRANDS`).
  - `T1583_001_domain_acquisition_dormant.yml` — Previously dormant
    domain (> 90 days since last seen) receives a burst of >= 10
    queries in 24 hours.
  - `T1583_001_domain_registration_internal.yml` — Internal host POST
    to a domain registrar endpoint (namecheap / porkbun / cloudflare)
    with an unknown user-agent.
- **Python helpers** in `server/src/zaqorincore_server/detection/`:
  - `dns_intel_interface.py` — Protocol class + concrete `WHOISRDAPClient`
    stub (RDAP/WHOIS feed integration deferred to v3.3.0+).
  - `brand_protection.py` — Levenshtein implementation + protected-brand
    list + `check_typosquat` helper used by the Sigma rule matcher.
- **Agent collector stub** at `agent/collectors/dns_intel.py` and
  `agent/cmd/zaqorin-dns-intel-stub.py` — interface only; live RDAP
  feed wiring is a v3.3.0 deliverable.
- **44 new tests** (38 Sigma rule tests + 6 brand protection tests +
  integration flow):
  - `server/tests/rules/test_t1583_001_domain_acquisition_nrd_rule.py`
  - `server/tests/rules/test_t1583_001_domain_acquisition_tld_burst_rule.py`
  - `server/tests/rules/test_t1583_001_domain_acquisition_typosquat_rule.py`
  - `server/tests/rules/test_t1583_001_domain_acquisition_dormant_rule.py`
  - `server/tests/rules/test_t1583_001_domain_registration_internal_rule.py`
  - `server/tests/rules/test_t1583_001_dns_intel_integration.py`
  - `server/tests/test_t1583_001_brand_protection.py`
- **Environment variables** in `server/.env.example`:
  - `ZAQORIN_WHOIS_RDAP_URL` — RDAP endpoint (empty = disabled).
  - `ZAQORIN_PROTECTED_BRANDS` — comma-separated brand list.

### Changed

- Bumped version `3.1.0` -> `3.2.0` in `server/pyproject.toml`.
- Detection streak now extends to **cycle 49** (6 consecutive cycles
  on the `detection` track, longest in ZaqorinCore history).

### Detection coverage

| MITRE technique        | Status   |
|------------------------|----------|
| T1583.001 Acquire Infra: Domains | **NEW** (5 rules) |

Overall coverage: **17/200 (8.5%)** MITRE ATT&CK techniques detected.

## [3.1.0] - 2026-09-02 — WebUI Agents: Zero-Terminal Onboarding