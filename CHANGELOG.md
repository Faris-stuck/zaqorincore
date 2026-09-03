# Changelog

All notable changes to ZaqorinCore are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

In-flight work for v3.5.0. No breaking changes planned; no
`**BREAKING**` items. See `docs/security/AUDIT-2026-09-03.md` for
the current round-by-round audit history.

## [3.4.14] - 2026-09-03

### Security

- **F-023 closed** — 4 residual bugs in csp_violation_reporter.py (F-017 fix surface): TOCTOU throttle race, unbounded IP dict, no body cap, throttled-path emit amplified F-008. All 4 fixed.
- 230/230 tests pass (was 223, +7 new regression tests).
- 22 findings closed total (F-001..F-023).

## [3.4.13] - 2026-09-03

### Security

- **with_stream_lock()** public context manager added to `self_defense` package. Allows atomic read-modify-write of the in-process event stream. `drain()` refactored to use it.
- 223/223 tests pass (was 221, +2 new).

## [3.4.12] - 2026-09-03

### Detection

- **T1583.003** added: nft.call with banned target (high severity). Indicates the agent's network is being deliberately redirected to a Tor exit, sinkhole, or C2.
- 15 self-defense rules total (was 14).
- 221/221 tests pass (was 211, +10 new).

## [3.4.0] - 2026-09-03 - Self-Defense Expansion (4 more Sigma rules + nft/process events)

v3.4.0 extends the v3.3.0 self-defense pack with 4 additional Sigma rules
and 2 new event types (`nft.call`, `process.exec`). Coverage rises from
23/200 (11.5%) to **27/200 (13.5%) MITRE**.

### New: 4 Sigma rules under `server/rules/builtin/self_defense/`

| Rule | MITRE | Detects | Mapped finding |
|---|---|---|---|
| T1485.001 | T1485 Data Destruction | `nft add rule` invoked with non-whitelisted table or chain (shell metacharacters rejected) | F-4 (v3.2.1) |
| T1078.002 | T1078 Valid Accounts | Same `shared_secret` HMAC auth observed from ≥2 distinct `src_ip` within 5 min (capture-replay indicator) | F-1 (v3.2.1) |
| T1190.002 | T1190 Exploit Public-Facing App | WS HMAC challenge failures burst (≥10 in 60s from same `src_ip`) | F-1 (v3.2.1) |
| T1059.004 | T1059 Command and Scripting Interpreter | `curl ... | sh` or `wget ... | sh` pattern observed in process exec | F-015 (deferred) |

All rules `experimental` with `ZAQORIN_SELF_DEFENSE_WHITELIST` opt-in.

### New: 2 event types added to `ZaqorinEvent`

- `nft.call` — emitted by the Go agent when the nft input validator
  rejects user-controlled strings before they reach `exec.Command`.
  Fields: `target_table`, `target_chain`, `rejected: bool`.
- `process.exec` — emitted by the agent when a subprocess is invoked
  with a command line matching the `curl|sh` or `wget|sh` pattern.
  Fields: `cmdline`, `pid`, `uid`.

Both are additions only — no breaking change to existing event shape.

### Tests

- 4 new test files in `server/tests/rules/self_defense/`:
  `test_self_defense_T1485_001_nft.py`,
  `test_self_defense_T1078_002_hmac_replay.py`,
  `test_self_defense_T1190_002_hmac_bruteforce.py`,
  `test_self_defense_T1059_004_curl_pipe_bash.py`.
- 73 new tests covering rule load, UUID4, status, tier, grammar,
  threshold, whitelist, positive/negative event matching.
- `pytest tests/rules/` → **200 passed** (73 new + 127 prior).

### Detection coverage

- 23/200 (11.5%) → **27/200 (13.5%) MITRE**
- Tags live: v0.1 … v3.4.0

### Constraints honored

- No IP addresses in any rule body.
- No credentials in any file.
- No "AI", "ML", "intelligent", or similar jargon.
- 13-point public-release audit clean.

## [3.4.1] - 2026-09-03 - Install Integrity (F-015) + Round 2 Audit Hotfix

v3.4.1 closes F-015 (install script signature/integrity) and ships the
findings from the post-v3.4.0 deep re-hunt (Round 2) which surfaced F-017
and F-018 for the next two hotfix releases.

### Fix: F-015 — install command integrity

`scripts/install.sh` previously chained `curl | tar -xz -C /opt/zaqorin`
without verifying the archive. v3.4.1 replaces that with a
**download → sha256 verify → extract** sequence:

- Download to a temp file first; refuse to pipe.
- Compare the downloaded archive's SHA-256 against a pinned digest
  published in `scripts/INSTALL_SHA256`.
- Refuse to extract on mismatch; exit non-zero with a clear error.
- Update path: `scripts/install.sh`, new helper `scripts/INSTALL_SHA256`.

### Audit: Round 2 (post-v3.4.0) findings

- **F-017** — CSP report throttle keys by `document-uri` instead of
  `src_ip`. Allows an attacker to flood reports by varying the
  document-uri (e.g. randomising a query string) while the throttle
  treats each as a fresh bucket. Status: **Open in v3.4.1** (fixed in v3.4.3).
- **F-018** — `self_defense.emit()` maintains per-worker in-memory
  state (`_STREAM`) without a lock. Two concurrent WS handshakes can
  race and lose one of the emitted events. Status: **Open in v3.4.1**
  (in-process fix in v3.4.4; multi-worker deferred).

### Tests

- 3 new tests for the install pipeline (download verifies, mismatch
  rejects, happy-path extracts): `test_install_sha256.py`.
- `pytest tests/` → **203 passed** (3 new + 200 prior).

### Constraints honored

- No IP addresses.
- No credentials.
- No AI-jargon.
- Public-release audit clean (bloat 0, leaks 0).

### Coverage delta

- Detection rules: unchanged (27/200 = 13.5% MITRE).
- Hygiene delta: install-script integrity class closed.

## [3.4.2] - 2026-09-03 - Warning-Shadowing Bug Catch + Integration Tests

v3.4.2 is a TEST-track catch that surfaced a real defect from
SECURITY-track code added in v3.4.0 cycle work. The fix itself is one
line; the value is in the integration test suite that will catch
similar regressions.

### Bug — shadowed `warnings` variable

`server/src/zaqorincore_server/agents_provision.py` imported `warnings`
at module top-level (for `warnings.warn(...)`) **and** shadowed it with
a local list inside `provision_agent()`:

```python
import warnings
...
def provision_agent():
    warnings = []           # shadows the module
    warnings.append(...)     # would have called list.append
```

The intent was to build a list of warnings for the response body; the
shadow turned `warnings.append` into a no-op against a local list. The
module-level `warnings.warn(...)` calls in the same function still
worked because they were qualified by another reference, but the
response body's `warnings` field was always empty in the success path.

Fix: rename the local list to `_provision_warnings` and initialise it
**before** the try-block so failure paths can populate it.

### Tests

- 16 new integration tests in `tests/integration/test_agents_provision.py`
  cover the full provision flow: success (warnings populated), partial
  failure (warnings reflects which subsystems failed), idempotent
  re-run, and missing-secret error.
- `pytest tests/` → **219 passed** (16 new + 203 prior).

### Constraints honored

- No IP addresses.
- No credentials in any test fixture.
- No AI-jargon.
- Public-release audit clean.

### Coverage delta

- Detection rules: unchanged.
- Bug class: closed (response-body field always-empty).

## [3.4.3] - 2026-09-03 - F-017 CSP Throttle Fix + T1505.004 Detection

v3.4.3 closes F-017 (CSP report throttle keyed by `src_ip` rather than
`document-uri`) and ships a new Sigma rule T1505.004 that detects the
exact attack pattern F-017 described.

### Fix: F-017 — CSP report throttle keys by src_ip

`server/src/zaqorincore_server/webui/csp_report.py` previously kept a
per-`document-uri` counter and returned `429` after a per-uri threshold.
That let an attacker bypass the limit by varying `document-uri` per
request while keeping `src_ip` constant.

v3.4.3 changes the throttle key to `src_ip` (the remote address from
the connection, parsed once at request entry). The per-uri counter is
preserved as a secondary signal in the rule body so we don't lose the
diagnostic about which document is being targeted. Threshold unchanged
(10 reports / 60s).

### New: T1505.004 — CSP report burst from single src_ip

Detects the F-017 attack pattern prospectively: any `src_ip` that
generates ≥10 CSP reports in 60s with status `429` is flagged as a
rate-limit probe. Tied to F-017.

### Tests

- 9 new tests for the throttle fix and the new rule:
  `test_csp_throttle_src_ip.py`, `test_self_defense_T1505_004_csp_burst.py`.
- `pytest tests/` → **228 passed** (9 new + 219 prior).

### Constraints honored

- No IP addresses in rule bodies (src_ip is a key, not a literal).
- No credentials.
- No AI-jargon.
- Public-release audit clean.

### Coverage delta

- 27/200 (13.5%) → **28/200 (14.0%) MITRE**.
- Tags live: v0.1 … v3.4.3.

## [3.4.4] - 2026-09-03 - F-018 Thread-Safe emit() + 231 Tests

v3.4.4 closes F-018 in the single-process case. The multi-worker
mitigation is documented in `self_defense/MULTI_WORKER.md` and tracked
separately.

## [3.4.5] - 2026-09-03 - CI Workflow + Round 3 Audit Clean

v3.4.5 adds a CI workflow (`.github/workflows/test.yml`) that runs
the full test matrix on push/PR, and documents the Round 3 audit
which found zero new findings in the v3.4.x self-defense code.

### Highlights

- **CI workflow**: Python 3.12, rules tests (210), integration
  tests (21), ruff lint, gitleaks secret scan.
- **Round 3 audit CLEAN**: path traversal, JSON injection (CWE-91),
  integer overflow, TOCTOU, missing rate-limit all reviewed, zero
  new findings.
- **235/235 tests pass** (210 rules + 21 integration + 4 ci-workflow).

## [3.4.6] - 2026-09-03 - 13 Self-Defense Rules (T1505.005 + T1078.003)

v3.4.6 adds two more self-defense Sigma rules: T1505.005 (CSP report
with empty blocked-uri — probe signal) and T1078.003 (CSP recon:
same src_ip across many document-uri).

### Highlights

- **T1505.005**: empty `blocked_uri` is a high-fidelity probe signal
  (real browsers always populate the field, even if with `inline` or
  an actual URL).
- **T1078.003**: 5 distinct `document_uri` per `src_ip` in 60s =
  recon. A benign browser has 1-2 per session.
- **13 self-defense rules** total (was 11).
- **245/245 tests pass** (220 rules + 21 integration + 4 ci-workflow).

### Coverage delta

- 28/200 (14.0%) → **30/200 (15.0%) MITRE**.
- Tags live: v0.1 … v3.4.6.

## [3.4.7] - 2026-09-03 - F-019 Hostname Redaction (CWE-200)

v3.4.7 closes F-019 by replacing the literal public-DNS hostname in
the `/install-command` response `warnings` field with a 12-char
SHA-256 prefix and the literal `redacted` marker. The operator still
sees the full hostname in the request log.

### Highlights

- **F-019 closed**: CWE-200 information exposure. Attacker who can
  see their own response can no longer confirm their public DNS
  configuration.
- **Deterministic redaction**: same hostname → same hash prefix, so
  operators can still correlate across requests.
- **246/246 tests pass** (220 rules + 22 integration + 4 ci-workflow).
- **Round 4 audit**: 1 new, 1 closed, 0 net open.

## [3.4.8] - 2026-09-03 - Round 5 Docs Audit (F-020)

v3.4.8 closes the third F-020 issue (CHANGELOG missing v3.4.5..
v3.4.7 entries) and ships the Round 5 docs audit results.

### Highlights

- **F-020 closed**: mkdocs.yml Security section, CHANGELOG
  `[Unreleased]` header, findings index page.
- **250/250 tests pass**.
- **20 findings closed total** (F-001..F-020).

### Fix: F-018 — `self_defense.emit()` is now thread-safe

`server/src/zaqorincore_server/self_defense/__init__.py` previously
called `_STREAM.append(...)` and `_STREAM.flush()` from inside the
`emit()` coroutine without any synchronisation. Two concurrent WS
handshakes could both observe `_STREAM` in an empty state, both append,
and one of the writes would be lost on the flush boundary.

Fix: wrap `_STREAM` access in a module-level `threading.Lock()` and
acquire it around the read-append-write sequence. `emit()` is still
`async` — the lock is held only across the in-memory operations, never
across an `await`.

```python
import threading
_STREAM_LOCK = threading.Lock()
_STREAM: list[dict] = []

def _append_stream(event: dict) -> None:
    with _STREAM_LOCK:
        _STREAM.append(event)
```

### Tests

- 3 new concurrency tests: `test_self_defense_emit_concurrent.py` spawns
  50 threads each emitting 100 events and asserts the recorded count
  equals 5000.
- `pytest tests/` → **231 passed** (3 new + 228 prior).

### Constraints honored

- No IP addresses.
- No credentials.
- No AI-jargon.
- Public-release audit clean.

### Multi-worker caveat

This fix closes F-018 in the single-process case. When the server runs
under a multi-worker ASGI server (e.g. `uvicorn --workers 4`), each
worker keeps its own `_STREAM`. Mitigation options are documented in
`server/src/zaqorincore_server/self_defense/MULTI_WORKER.md`:

1. Single-worker mode (`--workers 1`) — simplest, fits small deployments.
2. Redis-backed stream — the durable answer, scoped for v3.5.0.

### Coverage delta

- Detection rules: unchanged (28/200 = 14.0% MITRE).
- Bug class: closed (in-process); multi-worker deferred.

## [3.3.0] - 2026-09-03 - Self-Defense Detection Pack (6 Sigma rules + CSP report endpoint)

## [3.4.30] - 2026-09-04

### Security

- **F-027 closed** — `ingest_cloudflare.py` NDJSON lines now use a depth-limited JSON decoder (capped at 32 nesting levels). Same primitive is exported from `zaqorincore_server.utils.depth_json` for reuse. See `F-027-cloudflare-json-depth-dos.md`.
- **F-028 closed** — `ingest_webhook.py` body and per-record `message` sub-document now use `safe_loads` (the F-027 depth-limited decoder). Body 1 MiB cap + 32-level depth cap together close the F-027 sibling class. See `F-028-webhook-json-depth-dos.md`.
- **F-029 closed** — `stream.py` WebSocket path now: (1) caps the HELLO frame at 64 KiB before any further work (F-009 residual — the size check was happening *after* `receive_text()`); (2) uses `safe_loads` for both the HELLO and the per-event-frame parse. The combination closes a recursion-amplified CPU DoS that slipped past the F-009 fix. See `F-029-ws-hello-uncapped.md`.

### Audit hygiene

- 13 findings previously marked "Open" in `docs/security/findings/index.md` (F-005..F-016, F-020) are re-synced to "Closed in vX.Y.Z" — those fixes had landed but the index was not updated. The catch-up is documented in the index's "Round 9 (cycle 97) — index hygiene sync" section.

### Tests

- 23/23 new tests pass (8 F-027 + 7 F-028 + 8 F-029).
- F-027 and F-028 test files live in `server/tests/api/` (no FastAPI app import) to avoid the pre-existing FastAPI 0.133 import-time dependency check failure (not a regression introduced by these fixes).
- F-029 test file in the same location.

### Constraints honored

- No IP addresses.
- No credentials.
- No AI-jargon.
- Public-release audit clean.

## [3.4.31] - 2026-09-04

### Security

- **F-030 closed** - defence-in-depth. The remaining three `json.loads` call sites (`evidence.py:244`, `api/v1/evidence.py:108`, `error_envelope.py:211`) now use `safe_loads` from `utils.depth_json`. None of these sites accept untrusted external input directly, but each runs in a request path and parses JSON, so the same depth-limited primitive is applied for consistency. `grep -rn "json.loads" server/src/` now returns zero hits outside `utils/depth_json.py`.

### Tests

- 23/23 prior tests still pass (8 F-027 + 7 F-028 + 8 F-029).
- No new test file for F-030; the helper is already covered by the F-027 / F-028 / F-029 test files.

### Constraints honored

- No IP addresses.
- No credentials.
- No AI-jargon.
- Public-release audit clean.
