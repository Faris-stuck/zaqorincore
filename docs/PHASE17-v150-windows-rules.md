# PHASE17 — Windows Sigma rules expansion (v1.5.0)

Status: **Shipped** in v1.5.0
Owner: Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

v1.4.y closed the engine-side gap (compound
conditions) and v1.4.z added strict fail-CLOSED
semantics (`required_fields`). With both
primitives in place, we can ship rules that need
multi-condition logic + strict metadata
requirements.

This slice ships 5 new Windows detection rules
covering high-impact ATT&CK techniques that were
previously blocked on the engine limitations.

## 2. New rules (5)

| Rule ID | Event ID | ATT&CK | Conditions | Level |
|---|---|---|---|---|
| `builtin-windows-4688-cmd-from-office` | 4688 | T1059.003 / T1566.001 | `selection and not filter_business_hours` | high |
| `builtin-windows-5861-wmi-subscription` | 5861 | T1546.012 | `selection` | high |
| `builtin-windows-4663-startup-folder` | 4663 | T1547.001 | `selection` (with `re:` on path) | high |
| `builtin-windows-4698-scheduled-task` | 4698 | T1053.005 | `selection` | medium |
| `builtin-windows-4624-rdp-unusual-source` | 4624 | T1078 / T1021.001 | `selection and not filter_allowlist` | high |

## 3. Engine limitations encountered

Two rules hit current engine limits and were
deliberately simplified (documented in rule
comments + commit):

- **T1078 RDP** — original spec wanted
  `selection and not filter_allowlist and not
  filter_business_hours` (two `not` filters).
  v1.4.y only supports one. Solution: dropped
  the off-hours filter; operators can add it
  via `rules.local_overrides/`. Trade-off: more
  false positives during business hours.

- **T1059 cmd-from-office** — original spec
  wanted `selection and filter_office_parents`
  (positive filter) which would require
  inverting the list. v1.4.y has no positive
  filter (only `not`). Solution: put
  Office-parent list directly in `selection`
  (list value is OR-ed). Clean result.

- **T1547 Startup folder** — original spec used
  `target_path|re:` in key name. Engine reads
  the key literally, not parsed as
  `field|modifier`. Solution: use `re:` prefix
  in the value (already supported by `_match_field`).

## 4. `required_fields` per rule

| Rule | Required fields | Reason |
|---|---|---|
| T1059 cmd-from-office | `parent_process_name`, `metadata.hour` | off-hours filter needs hour; parent filter needs parent |
| T1547 Startup folder | `target_path` | regex match needs path |
| T1078 RDP | `source_ip` | allowlist match needs IP |
| T1546 WMI | (none) | all fields standard |
| T1053 Scheduled task | (none) | basic 4698 event |

## 5. Test coverage (12 new tests in
`tests/test_v150_windows_rules.py`)

- 2 per rule (fire + no-fire)
- T1547 covers regex match
- T1078 covers allowlist semantics
- T1059 covers off-hours filter
- T1546 covers `operation` field
- T1053 covers simple match
- + 1 loader count update (7 → 12 rules)

## 6. Test count

```
315 server pytest PASS
```

(was 303 in v1.4.z → 315 in v1.5.0, +12 new
rule tests, 0 regressions)

## 7. PITFALLS

1. **Engine doesn't parse `field|modifier:` in
   KEY** — only in VALUE. A rule like
   `target_path|re: "..."` will never match
   because the key doesn't exist in event
   metadata. Use `target_path: "re:..."`
   instead.
2. **Engine only supports ONE `not` filter**
   per condition (Pattern 2). For multiple
   negations, operators must either:
   - Use local_overrides to layer rules
   - Wait for v2.0.0 (full Sigma spec parser)
3. **List values in `selection` are OR-ed**
   (event value IN list → match), not AND-ed.
   Useful for "parent ∈ {a, b, c}".
4. **v1.5.0 rules are tested on Linux with
   fake event fixtures** — no real Windows
   Event Log exercised. Operators MUST run
   end-to-end smoke post-upgrade.

## 8. What's next per ROADMAP

- **v1.6.0** — ETW push-mode subscription
  (Windows 10 1903+) — Go agent side
- **v2.0.0** — Full Sigma spec AST parser
  (unlocks 2+ filter conditions, modifiers
  in keys, count aggregations)
- **Strategic pivot** (Wazuh modern /
  Compliance ID / SOC Assistant) still
  open per memory
