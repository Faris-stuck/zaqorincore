# Phase 6 — Sigma-Compatible Rule Engine + Hunt Query

**Status:** shipped as v0.6.0 (2026-08-28).

## Goal

Stop hand-coding each detector. Operators write Sigma-style YAML
rules; the engine parses them and runs them against the event
stream. Built-in detectors become a starter pack of Sigma rules
that ship in `rules/builtin/`.

## What changed

### Rule engine (`server/src/zaqorincore_server/rule_engine/`)

- `sigma.py` — parses a useful subset of the Sigma rule format
  (YAML). Compiles each rule into a `CompiledSigmaRule` with
  selection, condition, count, timeframe, cooldown, and optional
  action block. Supports string, list, `re:`, and `contains:`
  matchers. Supports `{{var}}` placeholder interpolation in
  `action.target` and `dedup_key`.
- `runner.py` — applies a list of compiled rules to one event.
  Sliding-window state in Redis (`zaqorin:rule:<id>:events:<dedup>`),
  per-rule cooldown (`zaqorin:rule:<id>:cooldown:<dedup>`). On
  fire, calls `persist_fire()` to insert an Alert and (if the rule
  has an action block) an Action row.
- `__init__.py` — re-exports.

### Wire-in to the live pipeline

`server/src/zaqorincore_server/detectors/runner.py` now calls
`_process_sigma_one` for every event off `zaqorin:events` after
the Python detector plugins have run. Both paths coexist: a
Phase 5 detector still works, and a Sigma rule on the same
event can fire too.

### Hunt API (`server/src/zaqorincore_server/api/v1/hunt.py`)

- `GET /api/v1/hunt/rules` — list every rule the server loaded
  from `rules_dir`.
- `POST /api/v1/hunt/run` — replay a single Sigma rule against
  the last `lookback_hours` of stored events. Read-only. Returns
  `{"fires": [...], "events_scanned": N, "rules_evaluated": 1}`.
  Hunt mode bypasses Redis state and runs single-event matching
  per row in the table.

### Built-in rules (`server/rules/builtin/`)

Five rules ship out of the box:

1. `builtin-ssh-bruteforce` — 5 failed `sshd` logins in 60s,
   fires `block_ip` with 1h TTL.
2. `builtin-port-scan` — 20 distinct TCP port contacts in 30s
   from the same source.
3. `builtin-web-attack` — SQLi / XSS / path-traversal pattern
   in an HTTP request URL.
4. `builtin-dns-tunnel` — 50 DNS queries in 5 minutes from the
   same source.
5. `builtin-impossible-travel` — 3 logins for the same user
   from distinct IPs in 5 minutes.

### Settings

`ZAQORIN_RULES_DIR` (default `rules/builtin`) — directory the
runner scans at startup.

## Test results

- Server: 118 → 140 tests (+22: sigma parser, runner, builtin
  loading, hunt API).
- Agent: 27 → 27 (no changes this phase).
- All 5 builtin rules load successfully and exercise the engine.

## Pitfalls

- **YAML `\b` quirks**: PyYAML 1.1 single-quoted strings interpret
  `\b` as backspace. Use single-quoted (`'re:...'`), not
  double-quoted (`"re:..."`) for regex patterns that contain
  word-boundary anchors. Documented in `test_sigma.py`.
- **Hunt mode uses `rule.matches()` directly** rather than the
  sliding-window runner, because the lookback is bounded and
  historical replay is read-only. This is a deliberate design
  choice — cooldowns don't apply to hunts.
- **Sigma rule action blocks are validated by `action_kinds.py`**
  when they reach the dispatcher. A rule with `kind: "bogus"`
  will parse fine, but the dispatcher will refuse to sign and
  mark the action failed.

## Backwards compatibility

- Phase 5 detector plugins still run. Sigma rules are an
  additive path.
- Operators can disable individual rules by removing the YAML
  file from `rules_dir` and restarting the server.
- The hunt API is new; nothing in the existing surface changed.

## What's next

Phase 7 (deception + forensics) plants canary tokens, tarpits
scanners, captures evidence on every alert with chain-of-custody
hashes. Phase 8 ships the compliance pack (UU PDP, ISO 27001,
PCI DSS). Phase 9 builds the React web UI. Phase 10 is the
public launch.
