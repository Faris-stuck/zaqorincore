# ADR-009: Sigma Engine Modifier Support

## Status
Accepted

## Date
2026-08-29

## Context

The Sigma engine shipped in v0.6.0 (ADR-004) supports four
match operators:

- `re:` — regex
- `contains:` — substring
- list-membership
- string-equals

That's enough to ship the 5 Windows rules in v1.4.0, but it
leaves the 10+ "real-world" Sigma rules on the shelf because
they depend on modifiers the engine doesn't yet parse:

| Modifier | Sigma meaning | Example | v1.4.0 status |
|---|---|---|---|
| `|startswith` | value begins with literal | `command_line\|startswith: 'powershell '` | Not supported |
| `|endswith` | value ends with literal | `target_filename\|endswith: 'lsass.exe'` | Not supported |
| `|ge` | numeric ≥ | `hour\|ge: 8` | Not supported |
| `|lt` | numeric < | `hour\|lt: 18` | Not supported |

Two concrete consequences:

1. **PowerShell EncodedCommand** (T1059.001) needs
   `command_line|startswith: 'powershell '` to avoid
   matching `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   as a file-open. The v1.4.0 brute-force rule doesn't ship
   because of this gap.

2. **T1136 off-hours** rule needs `hour|ge: 22 OR hour|lt: 6`
   to match events that happened between 10pm and 6am. The
   v1.4.0 T1136 rule ships as 24x7 coverage instead, which
   creates alert fatigue for SOC operators during business
   hours.

## Decision

We extend `_match_field` in
`server/src/zaqorincore_server/rule_engine/sigma.py` with
**four modifiers**: `|startswith`, `|endswith`, `|ge`, `|lt`.

The extension follows the Sigma spec modifier syntax
(`field|modifier: value`) and is **backwards-compatible**:
existing rules with `re:` and `contains:` continue to work
unchanged.

### Implementation

```python
# server/src/zaqorincore_server/rule_engine/sigma.py
def _match_field(actual, expected):
    if isinstance(expected, str):
        # NEW: Sigma spec modifiers
        if "|" in expected:
            field, _, mod_spec = expected.partition("|")
            if ":" in mod_spec:
                mod, _, value = mod_spec.partition(":")
                if mod == "startswith":
                    return str(actual).startswith(value)
                if mod == "endswith":
                    return str(actual).endswith(value)
                if mod == "ge":
                    try:
                        return float(actual) >= float(value)
                    except (TypeError, ValueError):
                        return False
                if mod == "lt":
                    try:
                        return float(actual) < float(value)
                    except (TypeError, ValueError):
                        return False
        # EXISTING
        if expected.startswith("re:"):
            ...
        if expected.startswith("contains:"):
            ...
    ...
```

The modifier string `field|modifier: value` is parsed
**first** (before the prefix-style `re:` / `contains:`),
because the two syntaxes are mutually exclusive — a value
that starts with `re:` or `contains:` will not have `|` in
the right position.

The `field` portion of the modifier string is **ignored** by
the matcher today (the matcher already received the
already-extracted `actual` value), but is kept in the syntax
for compatibility with the Sigma spec — so a rule written
as `command_line|startswith: 'powershell '` can be dropped
into the engine without changes to the YAML.

### Test coverage

New tests in `server/tests/test_sigma_modifiers.py`:
- `test_startswith_matches` / `test_startswith_rejects`
- `test_endswith_matches` / `test_endswith_rejects`
- `test_ge_matches` / `test_ge_rejects_non_numeric`
- `test_lt_matches` / `test_lt_rejects_non_numeric`

Plus regression: the existing 250 server tests must continue
to pass without changes.

### Rules unlocked

The new modifiers unlock **2 new Windows rules** shipped in
v1.4.x:

1. `builtin-windows-4688-powershell-encoded` (T1059.001) —
   `command_line|startswith: 'powershell '` +
   `command_line|contains: 'EncodedCommand'`
2. `builtin-windows-4688-powershell-download` (T1059.001) —
   `command_line|startswith: 'powershell '` +
   `command_line|contains: 'DownloadString'`

Plus an upgrade to the v1.4.0 T1136 rule:
- New `off_hours_filter` block using
  `hour|ge: 22 OR hour|lt: 6` (out-of-hours window 22:00-06:00)
  to silence the 24x7 firehose

## Consequences

### Positive

- 3+ more Windows rules shippable (the 2 PowerShell rules
  above + off-hours filter for T1136)
- Sigma spec compliance moves from "read-only subset" to
  "supports the modifier syntax operators" — opens the door
  to importing more public SigmaHQ rules
- No breaking change to existing rules

### Negative

- New attack surface: `|ge` and `|lt` parse `actual` and
  `value` as `float()`. A malformed rule value like
  `hour|ge: 'banana'` will silently no-match (return False)
  rather than raise. This is the correct fail-safe behavior
  (no match = no false positive), but operators should test
  new modifier rules with positive/negative fixtures.
- String modifier matches (`|startswith`, `|endswith`) are
  case-sensitive. The Sigma spec allows `|contains` with
  case-insensitive flag; we don't add a `|case` modifier
  yet (deferred to v1.4.y if operators ask).

## Alternatives considered

### Add only `|contains` (case-insensitive substring)

Already partially supported. The case-sensitivity gap is
small and a separate `|case` modifier is cleaner than
changing `|contains` semantics.

### Add only `|startswith` (no `|endswith`)

The LSASS rule already uses `|contains: 'lsass.exe'`
because we needed substring. `|endswith` is needed for
exactly one of the new rules (PowerShell encoded command
chained with a literal-equals match). Skipping `|endswith`
to save 5 lines of code isn't worth the limitation.

### Add modifier parsing in the rule YAML loader (not in `_match_field`)

Would require every modifier to be parsed at load time and
stored as a structured dict. More work, no benefit at the
volume of rules we have. The single-line check in
`_match_field` is enough.

## Rollback

If the modifier parser causes a regression, the fix is a
single 2-line change in `_match_field`: remove the `if "|" in
expected:` block. No rules that worked before will break.
