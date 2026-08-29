# PHASE16 — Sigma engine `required_fields` strict fail-safe (v1.4.z)

Status: **Shipped** in v1.4.z
Owner: Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

The v1.4.y T1136 account-create rule narrows detection to
off-hours (outside 09:00-17:00 local). The rule consumes
the `metadata.hour` metadata key emitted by the
Windows collector from the event's `TimeGenerated`
field.

But agents on older firmware, or agents that can't
reliably compute the local hour (timezone-naive
environments), do not send `metadata.hour`. For those
events, the rule's `filter_business_hours` block
(`metadata.hour: ["9", "10", ..., "17"]`) does not match
because the key is missing, so `not filter_business_hours`
evaluates True, and the rule fires.

That is **fail-OPEN semantics** for an off-hours rule.
In a SOC, the cost of an off-hours false positive
(noisy pager) is small. The cost of a false negative
(missed persistence) is large. Fail-CLOSED is the
correct default: if the agent cannot prove the
event was off-hours, the rule does not fire.

## 2. Decision

Add a `required_fields: [str]` rule attribute
(top-level YAML key, next to `id`/`title`/`level`).
The engine checks all listed fields exist in the
event's metadata BEFORE evaluating the condition.
If any field is missing, the rule does NOT fire.

Rules without `required_fields` are unaffected
(backwards-compatible).

## 3. Engine changes

- `CompiledSigmaRule.required_fields: tuple[str, ...] = ()`
  new field (default empty)
- `CompiledSigmaRule.matches()` checks required_fields
  first, returns False if any missing
- `_compile()` reads `required_fields` from raw YAML
  (top-level), validates it's a list of strings
- `SigmaRuleLoadError` raised if `required_fields`
  is not a list

## 4. T1136 upgrade

T1136 now declares:
```yaml
required_fields:
  - metadata.hour
```

The existing T1136 test had to be updated to pass
`metadata.hour: "23"` (off-hours) — the previous test
ran without `metadata.hour` and relied on fail-OPEN
which is no longer the contract.

## 5. Test coverage (9 new tests in
`tests/test_required_fields.py`)

- `test_no_required_fields_fires_normally` — backwards compat
- `test_required_fields_all_present_fires` — happy path
- `test_required_fields_one_missing_no_fire` — fail-closed
- `test_required_fields_all_missing_no_fire` — fail-closed
- `test_required_fields_extra_metadata_ok` — extra keys OK
- `test_required_fields_with_compound_condition_still_fail_closed`
  — required check happens BEFORE condition dispatch
- `test_loader_accepts_required_fields_top_level` — YAML loads
- `test_loader_rejects_required_fields_not_a_list` — invalid type
- `test_loader_default_required_fields_is_empty` — backwards compat

## 6. Trade-offs and rejected alternatives

- **Alternative A: add a global "fail mode" env var
  (`ZAQORIN_RULE_MISSING_FIELD_MODE=open|closed`)** —
  rejected. Operators must opt INTO fail-open for
  specific rules via `required_fields: []` (default),
  not opt out of fail-closed globally. Fail-closed
  is the safe default.
- **Alternative B: log a warning when missing + fire
  anyway** — rejected. Pager noise during a
  fleet-wide upgrade is worse than a transient
  detection gap. Operators get a clear "rule not
  firing" via the rule's hit-rate metrics, can
  investigate and fix the agent.
- **Alternative C: try to infer hour from
  `occurred_at` (UTC) + system timezone** — rejected
  for v1.4.z. The collector knows the local timezone
  context; the engine does not. Engine-side TZ math
  would require shipping the system's tzdata, which
  is fragile in containers.

## 7. PITFALLS

- `ParsedEvent` signature is `(event_id: UUID,
  host_id: UUID, source: str, raw: str, metadata: dict,
  occurred_at: datetime)` — NOT the older `(event_id,
  source, host_id, timestamp, metadata)`. Pyright
  caught this.
- `selection and filter_a` (without `not`) is NOT a
  recognized compound pattern in v1.4.y — it falls
  through to no-match. Test that asserts "compound
  fires" must use `selection and not filter_a` or
  `selection and (X or Y)`.
- The T1136 v1.4.0 test relied on fail-OPEN semantics
  (passed no `metadata.hour`, expected fire). v1.4.z
  breaks that contract. Test must be updated to
  pass `metadata.hour: "23"` (off-hours) explicitly.
- `required_fields` is a tuple on the dataclass
  (frozen), not a list. Loaders convert list→tuple
  to keep immutability.

## 8. What's next per ROADMAP

- **v1.5.0** — 5+ more Windows Sigma rules enabled
  by compound conditions
- **v1.6.0** — ETW push-mode subscription (Windows
  10 1903+)
- **v2.0.0** — Full Sigma spec AST parser
