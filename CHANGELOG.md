# Changelog

All notable changes to ZaqorinCore are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.0] - 2026-09-03 - Self-Defense Detection Pack (6 Sigma rules + CSP report endpoint)

v3.3.0 ships the first **self-defense detection pack** for ZaqorinCore.
After three patch releases (v3.2.1–v3.2.3) closed 16 of 16 in-scope
findings from the 2026-09-03 self-hunt, this release adds visibility:
when an operator probes or attacks the now-patched weaknesses, the
server emits structured events that Sigma rules match and surface as
detections.

### New: 6 Sigma rules under `server/rules/builtin/self_defense/`

Each rule references the finding it detects so operators can trace
from alert back to patched code path.

| Rule ID | MITRE | Detects | Mapped finding |
|---|---|---|---|
| T1190.001 | T1190 Exploit Public-Facing App | WebSocket HELLO frame malformed or oversized against `/ws/agent` | F-001 (v3.2.1) |
| T1110.003 | T1110 Brute Force | Ingest endpoint 401/403 burst (≥20 in 5 min) from a single src_ip | F-013 (v3.2.2) |
| T1078.001 | T1078 Valid Accounts | API key use from a never-seen src_ip, or from outside operator hours (00:00–06:00 local) | F-006 (v3.2.2) |
| T1098.001 | T1098 Account Manipulation | Audit log JSONL persistence silently disabled (single-occurrence signal) | F-008 (v3.2.2) |
| T1505.003 | T1505 Server Software Component | Browser-side CSP violation reports (≥3 from same src_ip in 10 min) | F-007 + F-016 (v3.2.3) |
| T1499.004 | T1499 Endpoint DoS | WebSocket frame size or rate limit exceeded (≥5 in 1 min from same src_ip) | F-009 (v3.2.3) |

All six rules are tagged `experimental` and require operator opt-in
via `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list) to suppress alerts
from trusted ranges (operator workstation, CI runners, monitoring).

### New: `server/src/zaqorincore_server/self_defense/` module

- `event_normalizer.py` — `ZaqorinEvent` data class with defensive
  parsing from server log records (`from_log_record`) and CSP browser
  reports (`from_csp_report`). Handles missing fields, garbage
  payloads, and CSP directive strings like `script-src 'self';` by
  extracting the bare directive name.
- `csp_violation_reporter.py` — FastAPI router exposing
  `POST /api/v1/_csp-report`. The browser auto-POSTs here when a
  Content-Security-Policy is violated (CSP `report-uri` /
  `report-to`). Body is validated by Pydantic, normalized into a
  `ZaqorinEvent`, and emitted to the rule engine.
- `__init__.py` — `SELF_DEFENSE_RULES` exported list, populated by
  loading all `*.yml` files from `server/rules/builtin/self_defense/`.

### New: CSP report endpoint wired into the main app

- `main.py` now includes the self-defense router.
- Middleware emits `http.request` events with `{event_type, src_ip,
  route, status, auth_method, key_id}` for every authenticated
  response.
- WebSocket stream emits `ws.hello` and `ws.dos` events from the
  HELLO handler and the DoS guard introduced in v3.2.3.
- A new 5-minute background task audits `ZAQORIN_AUDIT_LOG_DIR`
  writability and emits `audit.healthcheck` with
  `jsonl_persistence_enabled`.

### Tests

- `server/tests/rules/self_defense/test_self_defense_T1190_001_*.py`
  and 5 sibling files (one per rule) — 10 tests each covering
  load, UUID, status, tier, grammar, threshold, whitelist
  reference, and positive/negative event matching.
- `server/tests/rules/self_defense/test_csp_report_endpoint.py` —
  10 tests covering valid reports, missing fields, rate limit
  (10/min), schema errors, oversized body, and XSS-payload
  sanitization in the event.

`pytest tests/rules/` → **138 passed** (88 new + 50 prior).
Pre-existing test collection errors in `tests/api/test_ingest_*.py`
and `tests/test_agents_provision.py` are unrelated to this release
and were already present on `main` at fa7f72c.

### Detection coverage

- 17/200 (8.5%) MITRE → **23/200 (11.5%) MITRE**
- Tags live: v0.1 … v3.3.0

### Constraints honored

- No IP addresses in any rule body.
- No credentials in any file.
- No "AI", "ML", "intelligent", or similar jargon in user-facing
  output.
- 13-point public-release audit clean (see `docs/PHASE30-*.md`).

## [3.2.3] - 2026-09-03 - Security: lockfile, CI security-audit, WS size cap, CORS allowlist, CSP local React, style-src nonce
