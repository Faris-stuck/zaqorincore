# ADR-010: Sigma Engine Compound Condition Parsing

## Status
Accepted

## Date
2026-08-29

## Context

The Sigma engine shipped in v0.6.0 (ADR-004) supports
only two condition patterns:

- `selection` — all keys in the selection must match
- `selection and not filter` — `filter` is parsed as
  but its match result is **silently dropped**. This
  is a known v1.4.0 limitation documented in PHASE13 §7
  and PHASE14 §1.

The v1.4.0 detection rules worked around this with
flat selections, but two critical v1.4.0 follow-ups
need compound conditions:

1. **Off-hours filter for the T1136 account-create rule**
   — fires only when the event happens between
   22:00–06:00 (operators' quiet hours). Needs
   `selection and (filter_offhours_a or filter_offhours_b)`.
2. **Tighter PowerShell scope for the 2 PowerShell rules**
   — fire only when the parent process is `powershell.exe`.
   Needs `selection and (filter_parent_a or filter_parent_b)`.

v1.4.x shipped the `|ge` and `|lt` numeric modifiers
needed for the off-hours check (ADR-009) but the
condition parser is still too narrow to express the
OR/AND structure.

The Sigma spec defines many condition patterns
(1-of-`n`, `n-of-` aggregations, parentheses, `NOT`
on individual selections, etc.). Implementing the
full spec is a major parser engineering effort. v1.4.y
instead ships a **narrow 4-pattern subset** that
covers all the use cases ZaqorinCore actually has.

## Decision

Extend `CompiledSigmaRule.matches()` (in
`server/src/zaqorincore_server/rule_engine/sigma.py`)
to support 4 condition patterns:

1. `selection` — existing behavior, no change
2. `selection and not filter` — now actually evaluates
   the filter and returns False if the filter matches
3. `selection and (filter1 or filter2 or ...)` —
   match if all keys in `selection` match AND at least
   one of the listed filters matches
4. `selection and (filter1 or filter2 or ...) and not filter3` —
   match if all keys in `selection` match AND at least
   one of the OR filters matches AND `filter3` does not match

The matcher uses a **shallow, rule-string-driven
dispatch**: no AST, no tokenizer, no full Sigma
spec parser. The 4 patterns are recognised as literal
prefixes and the inner filter names are extracted via
regex (`r"selection and (?:not )?\(?(\w+(?:\s+or\s+\w+)*)\)?(?: and (?:not )?(\w+))?"`).

### Why a narrow subset, not a full parser

- **Engineering cost**: a full Sigma spec condition
  parser is 500-1000 LOC. The 4-pattern subset is 50
  LOC.
- **Actual need**: the 4 patterns cover every compound
  condition the current ruleset needs. Adding more
  patterns without a concrete rule that needs them is
  YAGNI.
- **Test cost**: the 4-pattern subset is verifiable
  by 12 unit tests (4 patterns × 3 outcomes: fire,
  no-fire, edge case). The full parser would need
  100+ test cases for the spec edge cases (nested
  parentheses, `1 of selection*`, `NOT`-on-NOT, etc.).

### Trade-offs accepted

- **Brittle to whitespace**: the condition string must
  be in one of the 4 exact formats (with optional
  extra whitespace inside the parens, handled by the
  regex). A rule with `selection and (filter1 OR filter2)`
  (uppercase OR) will fail to parse. Operators must
  follow the lowercase convention. This is documented
  in PHASE15.
- **No nesting**: `(selection and (X or Y)) or filter_Z`
  is not supported. ZaqorinCore rules don't need nesting.
- **No `n-of-` aggregations**: Sigma's `1 of selection*`
  and similar patterns are not supported. The
  `detection.count` / `detection.timeframe` mechanism
  (the existing v0.6.0 path) is the count-then-fire
  story and is unchanged.

## Consequences

### Positive

- **Off-hours filter for T1136** is shippable.
  The v1.4.0 T1136 rule fires 24x7; v1.4.y adds
  `selection and (filter_offhours_late or filter_offhours_early)`.
- **PowerShell scope for the 2 PowerShell rules** is
  shippable. Each rule's selection gains a
  `parent_process_name: powershell.exe` clause via a
  `(filter_parent_powershell or filter_parent_pwsh)`
  OR group.
- **5+ more Windows rules unlocked** — any rule that
  needs OR-conditions (WMI event subscription 5861,
  Scheduled Task 4698, User Deleted 4726) can now be
  expressed.

### Negative

- **Brittle to Sigma spec conformance**. A future
  operator copy-pasting a rule from the SigmaHQ rules
  repository will get a "unknown condition" error
  from the engine. This is the same as the v0.6.0
  state for `selection and not filter`. v2.0.0 will
  ship a proper AST-based parser.

## Alternatives considered

1. **Full Sigma spec parser** — too much engineering
   cost, no current rule needs more than the 4
   patterns.
2. **Hand-written per-rule matcher code** — every
   rule becomes a Python function, not a YAML
   declaration. Defeats the purpose of Sigma rules.
3. **External `pysigma` library** — third-party
   dependency, transitively pulls in pyyaml + a
   Sigma-spec runtime that is overkill for 4 patterns.
   Also adds a supply-chain surface.

## Status

Accepted in v1.4.y.
