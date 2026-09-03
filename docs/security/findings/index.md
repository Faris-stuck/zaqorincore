# Security findings — index

All findings published as part of ZaqorinCore's public-release audit
(see [AUDIT-2026-09-03.md](../AUDIT-2026-09-03.md)). Each finding is
a standalone document with a reproduction, recommendation, and
closure status. Open and closed findings are both listed here — the
project's policy is that nothing is hidden.

## Phase 3 deep-recon findings (v3.2.1 baseline)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-005](F-005-fastapi-version-mismatch.md) | Low | FastAPI `app.version` hardcoded "3.2.0" vs pyproject "3.2.1" | **Closed in v3.2.2** |
| [F-006](F-006-stats-version-info-disclosure.md) | Medium | `/api/v1/stats` and `/api/v1/version` unauthenticated | **Closed in v3.2.2** |
| [F-007](F-007-csp-permits-cdn-react.md) | Medium | CSP allows `https://esm.sh` React CDN, no SRI | **Closed in v3.2.3** |
| [F-008](F-008-audit-log-in-memory-only.md) | Medium | Audit log in-memory ring buffer, lost on restart | **Closed in v3.2.2** |
| [F-009](F-009-websocket-no-message-size-cap.md) | Medium | `/ws/agent` no per-frame size limit or heartbeat | **Closed in v3.2.3** |
| [F-010](F-010-cors-not-explicitly-disabled.md) | Medium | No explicit CORS policy | **Closed in v3.2.3** |
| [F-011](F-011-loose-dependency-pinning.md) | Medium | All deps pinned with `>=` ranges; no lockfile | **Closed in v3.2.3** |
| [F-012](F-012-whoami-leaks-dev-mode.md) | Low | `/auth/whoami` returns dev-mode state + role list | **Closed in v3.2.2** |
| [F-013](F-013-ingest-endpoints-no-audit.md) | Low | Ingest endpoints never call `audit.record()` | **Closed in v3.2.2** |
| [F-014](F-014-dependency-known-bad-check.md) | Low | Dependency CVE scan baseline | **Closed in v3.2.3** (CI gate) |
| [F-015](F-015-install-command-curl-pipe-bash.md) | Low | `curl \| bash` installer with no script signature | **Closed in v3.4.1** |
| [F-016](F-016-csp-unsafe-inline-style.md) | Low | CSP `style-src` allows `'unsafe-inline'` | **Closed in v3.2.3** |

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
| [F-020](F-020-docs-round-5.md) | Low | Docs audit: missing security nav, missing [Unreleased] header, missing v3.4.5/6/7 entries | **Closed in v3.4.8** |

## Round 6 findings (cycle 67)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-021](F-021-install-warnings-prefix-overlap.md) | Low | F-019 redaction logic bypassed by DNS-name prefixes that overlap RFC1918 octets | **Closed in v3.4.10** |

## Round 7 (cycle 68) — clean

See [ROUND7-CLEAN.md](ROUND7-CLEAN.md). Re-hunt of the entire server
tree at v3.4.10 for F-021-style prefix-overlap bugs surfaced no new
findings.

## Round 8 findings (cycle 72)

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-023](F-023-csp-reporter-throttle-eviction.md) | Medium | CSP reporter throttle: race in `_throttle_allowed`, no eviction in `_recent`, no per-endpoint body cap, throttled traffic evicts `_STREAM` audit | **Closed in v3.4.14** |

## Round 9 (cycle 97) — index hygiene sync

Re-verification of F-005..F-023 against HEAD (v3.4.29). All 13 findings
previously marked "Open" in this index are in fact closed in the source
code. The "Open" status was stale. This entry documents the catch-up so
the index matches reality.

| ID | Closed in | Originally shipped |
|----|-----------|-------------------|
| F-005 | v3.2.2 | b1eb601 |
| F-006 | v3.2.2 | b1eb601 |
| F-007 | v3.2.3 | fa7f72c |
| F-008 | v3.2.2 | b1eb601 |
| F-009 | v3.2.3 | fa7f72c |
| F-010 | v3.2.3 | fa7f72c |
| F-011 | v3.2.3 | fa7f72c |
| F-012 | v3.2.2 | b1eb601 |
| F-013 | v3.2.2 | b1eb601 |
| F-014 | v3.2.3 | fa7f72c (CI) |
| F-016 | v3.2.3 | fa7f72c |
| F-020 | v3.4.8 | f646de9 |
| F-023 | v3.4.14 | 7360f47 |

## Round 9b (cycle 99) — narrow NDJSON depth audit

Re-hunt of every server-side JSON parse surface for the F-027 class of
bug (NDJSON / JSON `loads` with no nesting-depth cap). One
sibling endpoint (`/api/v1/ingest/webhook`) is missing the depth cap
that was added to `ingest_cloudflare.py` for F-027; documented as F-028.

| ID  | Severity | Title | Status |
|-----|----------|-------|--------|
| [F-027](F-027-cloudflare-json-depth-dos.md) | Low | Cloudflare Logpush: NDJSON lines unbounded nesting depth → parser DoS | **Closed in v3.4.29** (`_depth_decoder` in `ingest_cloudflare.py`) |
| [F-028](F-028-webhook-json-depth-dos.md) | Low | `/api/v1/ingest/webhook` uses raw `json.loads` with no nesting-depth cap (F-027 sibling) | **Closed in v3.4.30** (`safe_loads` from `utils.depth_json`) |
| [F-029](F-029-ws-hello-uncapped.md) | Medium | WebSocket HELLO frame uncapped + `json.loads` unbounded depth (F-009 residual) | **Closed in v3.4.30** (HELLO cap + `safe_loads`) |

## Round 3 (cycle 61) — clean

See [ROUND3-CLEAN.md](ROUND3-CLEAN.md). Re-hunt of self-defense code
at v3.4.4 surfaced no new findings.

## Round 1 (Phase 1) — shipped in v3.2.1

F-001 through F-004 are documented inline in
[AUDIT-2026-09-03.md](../AUDIT-2026-09-03.md) (top section,
"Phase 1 results"). They were all closed in the v3.2.1 release and
are not republished as standalone finding documents.
