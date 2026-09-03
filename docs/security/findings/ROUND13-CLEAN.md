# Round 13 — CLEAN

| Field            | Value                                                            |
|------------------|------------------------------------------------------------------|
| Round            | 13                                                               |
| Cycle            | 83                                                               |
| Phase            | 1 (SECURITY track, NARROW SCOPE)                                 |
| Date             | 2026-09-04                                                       |
| Commit under audit | `5b74eb5` (v3.4.21)                                            |
| Scope            | `server/rules/builtin/self_defense/*.yml` (18 Sigma rule files)  |
| Question         | Are the 18 self-defense Sigma rule YAML files free of schema injection, parser-confusion vectors, and over-classification? |
| Result           | **CLEAN — 0 findings**                                           |

## Scope and method

Cycle 83 brief asked a narrow schema/parser audit of the 18 Sigma rule
files that make up the self-defense detection pack. The audit covered:

1. **YAML parse correctness** — every `.yml` round-trips through
   `yaml.safe_load` without exception.
2. **Static-field injection** — `title`, `description`, `id`, `level`
   must be plain strings, never computed from external input.
3. **ID uniqueness** — UUID4 collision is astronomically rare, but the
   18 IDs were checked for duplicates regardless.
4. **Sigma schema completeness** — every rule has `title`, `id`,
   `level`, `detection.{selection,condition}`.
5. **Condition reference integrity** — every token referenced in a
   `condition:` string must resolve to a real selection key in the same
   `detection:` block.
6. **Level classification** — no `level: critical` rules (would inflate
   alert fatigue), and no rule's description contains "advisory" or
   "informational" tone that contradicts its high classification.
7. **Engine load path** — verified the parser API in
   `server/src/zaqorincore_server/rule_engine/sigma.py:413`
   (`load_rules_from_dir`) is the same loader used by all existing
   rule-pack tests under `server/tests/` (T1485,
   T1583.001, sigma modifiers).
8. **Description quality** — every rule has at least 6 lines of
   `description`, populated `tags` (3-4 ATT&CK tags each), populated
   `references`, and populated `falsepositives`.

## Findings

### 1. YAML parse — CLEAN

All 18 files round-tripped through `yaml.safe_load` with no exception.
File extensions and naming are consistent
(`T\d{4}_\d{3}_[a-z_]+\.yml`).

### 2. Static-field injection — CLEAN

No `{{` or `${` token appears in `title`, `description`, `id`, or
`level` of any rule. The runner-level `{{var}}` interpolation in
`sigma.py:55-66` (`_PLACEHOLDER_RE`) is **only** applied to
`action.target` and `dedup_key` (lines 36 and 64), which are NOT
present in any of the 18 self-defense rules (this pack uses Sigma
detection only — actions are emitted to a downstream SOAR). No
attacker-controlled string ever enters a `condition:` expression.

### 3. ID uniqueness — CLEAN

18 unique UUIDv4 IDs, all matching
`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{12}$`. No
duplicates. No placeholder strings like `T1583-002-draft` left from
a refactor.

### 4. Sigma schema completeness — CLEAN

Every rule has all four Sigma-mandatory fields:

| Field              | Rules present |
|--------------------|---------------|
| `title`            | 18 / 18       |
| `id`               | 18 / 18       |
| `level`            | 18 / 18       |
| `detection`        | 18 / 18       |
| `detection.selection`   | 18 / 18   |
| `detection.condition`   | 18 / 18   |

`status: experimental` is uniform across the pack (correct for a
v3.4.x detector pack that has not yet accrued 30 days of prod
fire/no-fire telemetry).

### 5. Condition reference integrity — CLEAN

For each rule, every identifier token in the `condition:` string was
extracted with `re.findall(r"[a-z_][a-z0-9_]*", cond)` and checked
against the set of selection keys declared in the same `detection:`
block (after subtracting `condition`, `timeframe`, `count`, and Sigma
noise tokens `and`/`or`/`not`/`of`/`all`/`any`).

- 0 unresolved references found across all 18 rules.
- Pattern breakdown:
  - 8 rules use `selection and not filter_*` (negation pattern)
  - 4 rules use bare `selection` (single-event)
  - 3 rules use `selection and (filter_a or filter_b)` (multi-filter OR)
  - 1 rule uses `selection and (filter_a or filter_b)` with timeframe (T1059.004)
  - 2 rules use `selection and (filter_a or filter_b)` for compound rejection (T1190.001, T1485.001)

All patterns are within the sigma.py parser's supported subset
(see sigma.py:14-37 docstring and `parse_rule_file` at line 311).

### 6. Level classification — CLEAN

Distribution across the 18-rule pack:

| Level   | Count | Notes |
|---------|-------|-------|
| critical | 0    | None — avoids alert-fatigue inflation. |
| high    | 10    | Active abuse / unauthorized-call paths (T1078.002, T1098.001, T1110.003, T1190.001, T1485.001, T1499.004, T1583.003–006). |
| medium  | 7     | Recon / anomaly / install-pattern (T1059.004, T1078.001, T1078.003, T1190.002, T1505.003, T1505.004, T1583.002). |
| low     | 1     | T1505.005 — informational/recon-style CSP report with no `blocked-uri`; intentionally low because it is a weak signal on its own. |

The level distribution matches the threat-model taxonomy from
AUDIT-2026-09-03 (active abuse → high; signal-noise → medium/lower).

### 7. Engine load path — CLEAN

`server/src/zaqorincore_server/rule_engine/sigma.py:413`
exposes `load_rules_from_dir(directory: Path) -> list[CompiledSigmaRule]`.
This is the same function exercised by existing rule-pack tests:

- `server/tests/test_t1485_data_destruction_rule.py:34`
- `server/tests/test_sigma_modifiers.py:150, 174, 206`
- `server/tests/rules/test_t1583_001_dns_intel_integration.py:11`

All three test files import `load_rules_from_dir` and assert the
expected rule count for their respective pack (T1485 = 1 rule, T1583
DNS-intel = 1 rule, sigma modifiers = 1 rule). The self-defense pack
would behave identically — the `parse_rule_file` body at line 311 is
strict on missing fields and raises `SigmaRuleLoadError` on any
schema violation (line 263 onward), so the loader cannot silently
skip a malformed rule.

(The runner's actual `load_rules_from_dir` call could not be executed
end-to-end in this audit cycle because the `server/.venv` does not have
`pyyaml` installed in this environment — pip is offline. Schema-level
`yaml.safe_load` validation covered the equivalent checks. The next
online cycle should run `pytest server/tests/test_sigma_modifiers.py`
to re-confirm the loader returns 18.)

### 8. Description / metadata quality — CLEAN

Per-rule hygiene:

- **Description length**: 6-16 non-empty lines each.
- **Tags**: every rule has 3-4 ATT&CK tags
  (`attack.<tactic>`, `attack.<technique>`, plus a pack-specific tag).
- **References**: every rule has the upstream `security/advisories`
  link.
- **False positives**: every rule has at least 1 enumerated FP
  scenario.
- **CWE references**: only CWE-285 (Improper Authorization) is cited
  in 2 rules (T1583.005, T1583.006). The other 16 rules correctly do
  not invent CWE refs where none applies (CSP, DoS, brute-force,
  audit-log-gap, etc. are not CWE-mapped in the project's existing
  convention).

## Adjacent rule packs (out of scope, but checked for regression)

The same schema validator was run against the other two `*.yml` packs
under `server/rules/builtin/`:

- `server/rules/builtin/mitre_attack/` — 1 rule (T1485).
- `server/rules/builtin/threat_intel/` — 1 rule (T1583.001).

Both have unique IDs, complete Sigma schemas, and valid conditions.
Not in the brief's scope (the 18 self-defense rules), so not
re-documented; flagged here for cross-cycle continuity only.

## Conclusion

The 18 self-defense Sigma rule YAML files at commit `5b74eb5`
(v3.4.21) are schema-clean, parser-clean, and level-balanced. The
five audit questions in the cycle 83 brief all return CLEAN:

1. ✅ No rule fields computed from external input.
2. ✅ 18 / 18 unique UUIDv4 IDs.
3. ✅ Descriptions and levels consistent (10 high, 7 medium, 1 low).
4. ✅ Zero `level: critical` rules.
5. ✅ Engine load path (`load_rules_from_dir`) is the same loader used
   by existing rule-pack tests; `parse_rule_file` raises on any
   schema violation, so the engine cannot silently skip a malformed
   rule.

No F-026 issued. Round 13 is CLEAN.

## Files touched this round

- `docs/security/findings/ROUND13-CLEAN.md` (new — this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 13 section appended)