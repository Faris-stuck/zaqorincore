# ADR-011: Sigma engine `required_fields` fail-closed semantics

## Status
Accepted

## Date
2026-08-29

## Context

The T1136 account-create rule (shipped in v1.4.y with
off-hours filter) consumes the `metadata.hour` key
emitted by the Windows collector. If an agent cannot
populate `metadata.hour` (older firmware, no
timezone context, collector bug), the rule's
`filter_business_hours` block does not match
(missing key), so `not filter_business_hours`
evaluates True, so the rule fires.

That is **fail-OPEN** for an off-hours rule. In a SOC,
fail-OPEN is the wrong default: pager noise during
a fleet-wide agent upgrade is worse than a transient
detection gap for a single rule.

The same problem applies to any rule that consumes
a metadata key not universally emitted by all
agents (geolocation, AS number, container label,
etc.).

## Decision

Add a new rule attribute `required_fields: [str]`
top-level YAML key. The engine checks that ALL
listed fields exist in the event metadata BEFORE
evaluating the condition. If any field is missing,
the rule does NOT fire (fail-CLOSED).

Rules without `required_fields` are unaffected
(backwards-compatible default: empty tuple).

## Consequences

### Positive
- Off-hours rules (and any rule depending on
  optional agent metadata) have a documented
  fail-CLOSED opt-in
- No pager noise during partial fleet upgrades
- Operators can detect "rule not firing" via
  hit-rate metrics, fix the agent, no silent
  false positives
- Same primitive works for any future
  optional-metadata rule (geolocation, AS number,
  container label, etc.)

### Negative
- A rule that previously fired (fail-OPEN) will
  stop firing after this change for agents that
  don't send the required metadata. T1136 in
  v1.4.y had this exact behavior — must be
  flagged in CHANGELOG as a breaking change for
  the T1136 test fixture.

### Neutral
- Required_fields is a tuple on the dataclass
  (frozen), list→tuple conversion in the loader.
  Backwards-compatible for all existing rules.
- ADR-010 (compound conditions) and ADR-011
  (required_fields) are independent. A rule can
  use both: `required_fields` gates the rule;
  compound conditions evaluate after.

## Alternatives considered

- **Global `ZAQORIN_RULE_MISSING_FIELD_MODE` env
  var** — rejected. Wrong granularity. Different
  rules need different behavior.
- **Log warning + fire anyway** — rejected. Pager
  noise is the worst outcome.
- **Engine-side TZ inference from `occurred_at`
  + system timezone** — rejected for v1.4.z.
  Engine doesn't have reliable TZ context; the
  collector does.

## Implementation

- `CompiledSigmaRule.required_fields: tuple[str, ...] = ()`
  new field
- `CompiledSigmaRule.matches()` checks required
  fields first
- `_compile()` reads from top-level YAML, validates
  type, converts to tuple
- T1136 rule updated to declare
  `required_fields: [metadata.hour]`
- 9 new tests in `tests/test_required_fields.py`
- 1 test fixture update in
  `tests/test_windows_eventlog_rules.py`
  (T1136 now needs `metadata.hour: "23"` to fire)
