# Changelog

All notable changes to ZaqorinCore are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [3.3.0] - 2026-09-03 - Self-Defense Detection Pack (6 Sigma rules + CSP report endpoint)
