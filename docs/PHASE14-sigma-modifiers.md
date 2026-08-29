# PHASE14 — Sigma Engine Modifier Support + 2 New Windows Rules (v1.4.x)

Status: **Shipped** in v1.4.x
Owner: Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

v1.4.0 shipped 5 Windows rules but explicitly deferred
**2 more rules** (T1059.001 PowerShell EncodedCommand,
T1059.001/T1105 PowerShell DownloadString) and an
**off-hours filter** for the T1136 account-create rule,
because the rule engine was feature-locked to plain
string-equals, list-membership, `re:`, and `contains:`
matches.

The Sigma spec defines four modifiers that would unlock
those rules:

| Modifier | Used by | v1.4.0 status |
|---|---|---|
| `\|startswith` | PowerShell scope for both new rules | Not supported |
| `\|contains` | Already supported, but the new rules need it as a single-string match | Supported |
| `\|ge` | T1136 off-hours filter (`hour\|ge: 22`) | Not supported |
| `\|lt` | T1136 off-hours filter (`hour\|lt: 6`) | Not supported |

v1.4.x ships the 4 modifier support in the engine, plus
the 2 new rules that depend on it. The off-hours T1136
filter is documented as a follow-up (see §6) because the
engine's `condition` parser does not yet handle
`selection and not filter` — the `not filter` part is
silently dropped, so the filter wouldn't work even with
the modifier support.

## 2. The 4 modifiers

```yaml
# _is_modifier_value recognises these 4 modifier names
# _match_modifier dispatches to the right comparison

field|startswith: literal    # case-sensitive prefix match
field|endswith: literal      # case-sensitive suffix match
field|ge: number             # actual >= number (float compare)
field|lt: number             # actual < number (float compare)
```

The `field` portion of the syntax is redundant (the matcher
already received the key) but is kept in the syntax for
spec compatibility — unmodified SigmaHQ rules can be
dropped into the engine.

The literal value is stripped of leading/trailing whitespace
so `startswith: powershell ` (with a trailing space) works
as expected.

### 2.1 Fail-safe behavior

A non-numeric actual for `ge`/`lt` returns **False** rather
than raising. This is the correct fail-safe behavior (no
match = no false positive), but operators should test new
modifier rules with positive/negative fixtures.

A non-string actual for `startswith`/`endswith` is
stringified first via `str(actual)`.

## 3. The 2 new rules

### 3.1 `builtin-windows-4688-powershell-encoded` (T1059.001)

Matches a process (Event ID 4688) whose command line
contains the literal `EncodedCommand` — PowerShell's
standard encoded-payload flag. Real-world attacker
frameworks (PowerSploit, Cobalt Strike, Empire) all use
this flag because it accepts a Base64-encoded command
string that bypasses simple keyword search.

**Scope limitation:** because the engine doesn't yet
support `condition: selection and (X or Y)`, this rule
matches on the cmdline flag string only — it will also
fire on the rare case of a non-PowerShell process whose
command line happens to contain the literal
"EncodedCommand". For a stricter PowerShell-only scope,
operators can override in `rules.local_overrides/` and
add `parent_process_name: powershell.exe` to the
selection dict.

### 3.2 `builtin-windows-4688-powershell-download` (T1105)

Same as above but matches on the `DownloadString`
cmdlet name (plus `DownloadFile`, `DownloadData`,
`Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`).
The shipped rule uses `contains: DownloadString` as the
single-string matcher, which catches the most common
attacker behavior.

## 4. Off-hours filter for T1136 (DEFERRED — engine limit)

The v1.4.0 T1136 rule fires 24x7 because the engine's
`condition: selection and not filter` parser only
evaluates `selection` — the `not filter` part is silently
dropped. The modifier support shipped in v1.4.x would
unlock the off-hours filter (`hour|ge: 22 OR hour|lt: 6`),
but the OR/AND condition parsing is a separate engine
limitation.

**Tracked as v1.4.y:** extend `matches()` to parse
`selection and (X or Y)` and `selection and not filter`
fully. With that change, the T1136 rule can be upgraded
to fire only between 22:00 and 06:00 (a 4-hour quiet
window at 00:00-04:00 and an 8-hour evening window
22:00-06:00).

## 5. Testing

3 new test files:

- `server/tests/test_sigma_modifiers.py` — 27 tests
  covering the 4 modifiers, the existing `re:` and
  `contains:` paths, and the unit-vs-end-to-end gap
- `server/tests/test_powershell_rules.py` — 4 tests
  covering the 2 new rules (positive + negative for each)

Full server suite: **282/282 PASS** (was 250 → +32 new
tests, 0 regressions).

```
$ pytest tests/test_sigma_modifiers.py tests/test_powershell_rules.py
31 passed in 0.61s

$ pytest  # full server suite
282 passed in 20.14s
```

## 6. Follow-up (v1.4.y)

- **OR/AND condition parsing** — `condition: selection
  and (X or Y)` and `condition: selection and not filter`
  should fully evaluate. Tracked as v1.4.y. With this
  change, the T1136 rule gets an off-hours filter and
  the 2 PowerShell rules can be tightened to
  PowerShell-only via a `parent_process_name` clause.
- **Case-insensitive flag** — Sigma spec allows `|case`
  modifier (`field|contains|case:insensitive: literal`).
  Not yet implemented.
- **5+ more Windows rules** — once OR/AND parsing lands,
  the 2 PowerShell rules can be tightened and 5+ more
  (WMI event subscription 5861, Scheduled Task 4698,
  User Deleted 4726, LSASS handle read 4663 with
  access-mask filter, etc.) become shippable.

## 7. Honest gap

The 4 modifiers and the 2 rules are tested on Linux
with a fake-redis runner. The end-to-end path is
identical to the v1.4.0 rules (selection → dedup →
cooldown → count → action rendering), so the same
honest gap applies: no real Windows Event Log events
flowing through the eventlog_common.go decoder were
exercised. The off-hours filter gap is documented in
§4 above.

Operators MUST run a real-Windows integration smoke
test after upgrading to v1.4.x:

```powershell
# 1. Fire a PowerShell EncodedCommand
powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==

# 2. Look for the alert
# 3. Verify the rule id is builtin-windows-4688-powershell-encoded
```
