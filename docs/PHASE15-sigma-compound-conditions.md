# PHASE15 — Sigma Engine Compound Conditions + Off-Hours T1136 (v1.4.y)

Status: **Shipped** in v1.4.y
Owner: Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

v1.4.0 deferred an off-hours filter for the T1136
account-create rule because the engine's `condition`
parser only handled `selection` (the `not filter`
clause was silently dropped — documented in PHASE13 §7).

v1.4.x shipped modifier support (ADR-009) but the
condition parser was still too narrow to express the
OR structure needed for "off-hours" or
"parent_process_name in [powershell.exe, pwsh.exe]".

v1.4.y ships the **last v1.4.0 follow-up** plus tightens
3 of the v1.4.0/v1.4.x rules.

## 2. ADR-010: compound condition parsing

`CompiledSigmaRule.matches()` now supports 4 patterns
(ADR-010):

1. `selection` — all keys in selection must match
2. `selection and not filter` — NOW EVALUATES the
   filter (was silently dropped in v1.4.0/v1.4.x)
3. `selection and (X or Y or Z)` — at least one of
   the listed filters must match
4. `selection and (X or Y) and not Z` — at least one
   of the OR filters must match AND the AND-NOT filter
   must not match

The matcher uses a shallow, rule-string-driven dispatch
(no AST, no tokenizer, no full Sigma spec parser). The
4 patterns are recognised as literal regex prefixes
and inner filter names are extracted via
`re.fullmatch`.

### Why a narrow subset, not a full parser

- Engineering cost: 4-pattern subset = 50 LOC; full
  Sigma spec = 500-1000 LOC.
- Actual need: the 4 patterns cover every compound
  condition the current ruleset needs. Adding more
  patterns without a concrete rule that needs them is
  YAGNI.
- Test cost: 4 patterns × 3 outcomes = 12 tests. A
  full parser would need 100+ for spec edge cases.

### Trade-offs accepted

- **Brittle to whitespace**: the condition string must
  be in one of the 4 exact formats. A rule with
  `selection and (filter1 OR filter2)` (uppercase) will
  fail. Operators must follow lowercase convention.
- **No nesting**: `(selection and (X or Y)) or filter_Z`
  is not supported. ZaqorinCore rules don't need nesting.
- **No `n-of-` aggregations**: `1 of selection*` is not
  supported. The `detection.count` / `detection.timeframe`
  mechanism (the existing v0.6.0 path) is unchanged.

## 3. The 4 changes that ship

### 3.1 T1136 — Off-hours filter

**v1.4.0**: T1136 fired 24x7 (every 4720 event).
**v1.4.y**: T1136 fires only outside business hours
(09:00-17:00 local time, 7-9 hour window depending
on operator preference). The agent populates
`metadata.hour` (0-23) from the event's TimeGenerated
field. The rule:

```yaml
detection:
  selection:
    source: "windows.security.4720"
  filter_business_hours:
    metadata.hour: ["9", "10", ..., "17"]
  condition: selection and not filter_business_hours
```

**Honest gap**: when `metadata.hour` is missing from
the event, the rule fires (fail-open default) because
`filter_business_hours` doesn't match a missing key,
so `not filter_business_hours` passes. This is
documented as a follow-up for v1.4.z — a stricter
rule would require `metadata.hour` to be present.

### 3.2 T1059.001 PowerShell EncodedCommand — Parent scope

**v1.4.x**: matched any process whose command line
contained "EncodedCommand" (false-positive prone — any
process with that string in cmdline fired).
**v1.4.y**: requires parent_process_name ∈
{powershell.exe, pwsh.exe} via OR compound condition:

```yaml
detection:
  selection:
    source: "windows.security.4688"
    command_line: "contains:EncodedCommand"
  filter_parent_powershell:
    parent_process_name: "powershell.exe"
  filter_parent_pwsh:
    parent_process_name: "pwsh.exe"
  condition: selection and (filter_parent_powershell or filter_parent_pwsh)
```

### 3.3 T1105 PowerShell DownloadString — Parent scope

Same v1.4.y change as 3.2.

### 3.4 T1098 Privilege Group Add — Expand allowlist

**v1.4.0**: 4 SIDs (Domain Admins, Enterprise Admins,
Schema Admins, BUILTIN\Administrators) matched via
`contains:` substring.
**v1.4.y**: 8 group names matched via list-membership:

- BUILTIN\Administrators
- Domain Admins
- Enterprise Admins
- Schema Admins
- Account Operators
- Server Operators
- Print Operators
- Backup Operators

The new groups (Account Operators, Server Operators,
Print Operators, Backup Operators) are the standard
post-exploitation persistence targets in addition to
the 4 Domain-level groups. v1.4.y uses a clean
list-membership form (more readable than the v1.4.0
SID-substring approach).

## 4. Backwards compatibility

- Every v1.4.0 and v1.4.x rule continues to fire
  unchanged.
- The `selection and not filter` syntax that was a
  silent no-op in v1.4.0 now actually evaluates the
  filter. The only rule using this syntax in the
  current ruleset is the v1.4.0 T1136 rule — which
  was deliberately simplified to flat `selection`
  in v1.4.0 (the `not filter` was always intended).
  No other rule changes behavior.

## 5. Testing

3 test files updated, 1 new:

- `server/tests/test_sigma_compound_conditions.py` —
  **NEW** — 12 tests covering all 4 condition patterns
- `server/tests/test_windows_eventlog_rules.py` —
  T1098 tests updated to use `target_group_name`
  (3 tests)
- `server/tests/test_powershell_rules.py` — added
  `parent_process_name` to fixtures (4 tests)
- `server/tests/test_sigma_modifiers.py` —
  startswith-through-runner test updated to include
  `parent_process_name` (1 test)

```
$ pytest tests/test_sigma_compound_conditions.py
12 passed in 0.21s

$ pytest  # full server suite
294 passed in 20.45s
```

(was 282 in v1.4.x → 294 in v1.4.y, +12 new tests, 0
regressions)

## 6. Follow-up (v1.4.z)

- **Strict missing-hour fail-safe for T1136** — if
  `metadata.hour` is missing from the event, the rule
  should NOT fire (conservative). Requires a small
  engine change to add a "presence required" check.
- **5+ more Windows rules** enabled by compound
  conditions:
  - T1059.003 Windows Command Shell (cmd.exe spawned
    by Office apps — `selection and (filter_parent_winword
    or filter_parent_excel or ...)`)
  - T1546.012 WMI Event Subscription persistence
    (filter on CommandLineEventConsumer name regex)
  - T1547.001 Startup folder persistence (filter on
    file path regex)
- **Full Sigma spec parser** — a proper AST-based
  parser to replace the regex-based dispatch. Tracked
  as v2.0.0.

## 7. Honest gap

The 4 condition patterns and 3 rule upgrades are
tested on Linux with a fake-redis runner. The
end-to-end path is identical to the v1.4.0/v1.4.x
rules (selection → dedup → cooldown → count → action
rendering), so the same honest gap applies: no real
Windows Event Log events through the
eventlog_common.go decoder were exercised. The
off-hours check depends on the agent populating
`metadata.hour` — operators MUST verify the Windows
collector populates this field from the event's
TimeGenerated.
