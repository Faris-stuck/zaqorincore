# Security findings — index

All findings published as part of ZaqorinCore's public-release audit
(see [AUDIT-2026-09-03.md](../AUDIT-2026-09-03.md)). Each finding is
a standalone document with a reproduction, recommendation, and
closure status. Open and closed findings are both listed here — the
project's policy is that nothing is hidden.

## Phase 3 deep-recon findings (v3.2.1 baseline)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-005](F-005-fastapi-version-mismatch.md) | Low | FastAPI `app.version` hardcoded "3.2.0" vs pyproject "3.2.1" | Open (informational drift) |
| [F-006](F-006-stats-version-info-disclosure.md) | Medium | `/api/v1/stats` and `/api/v1/version` unauthenticated | Open (mitigated by operator-firewall note) |
| [F-007](F-007-csp-permits-cdn-react.md) | Medium | CSP allows `https://esm.sh` React CDN, no SRI | Open |
| [F-008](F-008-audit-log-in-memory-only.md) | Medium | Audit log in-memory ring buffer, lost on restart | Open |
| [F-009](F-009-websocket-no-message-size-cap.md) | Medium | `/ws/agent` no per-frame size limit or heartbeat | Open |
| [F-010](F-010-cors-not-explicitly-disabled.md) | Medium | No explicit CORS policy | Open |
| [F-011](F-011-loose-dependency-pinning.md) | Medium | All deps pinned with `>=` ranges; no lockfile | Open |
| [F-012](F-012-whoami-leaks-dev-mode.md) | Low | `/auth/whoami` returns dev-mode state + role list | Open |
| [F-013](F-013-ingest-endpoints-no-audit.md) | Low | Ingest endpoints never call `audit.record()` | Open |
| [F-014](F-014-dependency-known-bad-check.md) | Low | Dependency CVE scan baseline | Open (informational) |
| [F-015](F-015-install-command-curl-pipe-bash.md) | Low | `curl \| bash` installer with no script signature | **Closed in v3.4.1** |
| [F-016](F-016-csp-unsafe-inline-style.md) | Low | CSP `style-src` allows `'unsafe-inline'` | Open |

## Round 2 findings (post-v3.4.0)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-017](F-017-csp-throttle-by-document-uri.md) | Medium | CSP report throttle keyed by `document-uri` not `src_ip` | **Closed in v3.4.3** |
| [F-018](F-018-self-defense-stream-concurrency.md) | Low | `self_defense.emit()` not concurrency-safe; per-worker state | **Closed in v3.4.4** (in-process) |

## Round 4 findings (cycle 63)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-019](F-019-install-warnings-leak-hostname.md) | Low | Public-DNS hostname echoed in response `warnings` field | **Closed in v3.4.7** |

## Round 5 findings (cycle 64 — current)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-020](F-020-docs-round-5.md) | Low | Docs audit: missing security nav, missing [Unreleased] header, missing v3.4.5/6/7 entries | Open (partial fix in this commit) |

## Round 3 (cycle 61) — clean

See [ROUND3-CLEAN.md](ROUND3-CLEAN.md). Re-hunt of self-defense code
at v3.4.4 surfaced no new findings.

## Round 1 (Phase 1) — shipped in v3.2.1

F-001 through F-004 are documented inline in
[AUDIT-2026-09-03.md](../AUDIT-2026-09-03.md) (top section,
"Phase 1 results"). They were all closed in the v3.2.1 release and
are not republished as standalone finding documents.
