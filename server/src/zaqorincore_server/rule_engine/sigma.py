"""Sigma-style rule loader (Phase 6, ADR-004).

Parses a subset of the Sigma rule format (YAML) and compiles each
rule into a callable matcher that returns `True` when an event
satisfies the rule's conditions.

We don't depend on SigmaHQ or sigmac. We adopt the wire format
because it is the de-facto standard for shareable detection
content, and an operator who already has Sigma rules can paste
them into `rules/custom/*.yml` and the ZaqorinCore runner will
execute them.

Supported Sigma fields (minimal subset — enough to be useful,
not the full Sigma grammar):

```yaml
title: SSH brute force
id: ssh-bf-001
level: high             # low | medium | high | critical
detection:
  selection:
    source: "sshd"
    status: "failed"
  condition: selection
  timeframe: 60s        # optional; default 60
  count: 5              # optional; default 1 (single-event rule)
action:                 # optional; emits an Action row on fire
  kind: block_ip
  target: "{{source_ip}}"
  ttl_sec: 3600
cooldown_sec: 300       # optional
dedup_key: "{{source_ip}}"
```

`{{var}}` placeholders in `action.target` and `dedup_key` are
filled from the event's metadata.

Backwards compat: the Phase 5 built-in detectors (ssh_bruteforce,
port_scan, web_attack, dns_tunnel, auth_anomaly) keep working.
Sigma rules are an additive path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..detectors.base import ParsedEvent


_PLACEHOLDER_RE = re.compile(r"\{\{([a-zA-Z0-9_]+)\}\}")


def _interpolate(template: str, metadata: dict[str, str]) -> str:
    """Replace `{{var}}` placeholders in `template` with values
    from `metadata`. Unknown variables are left as the literal
    `{{var}}` string so a typo in the rule is visible at fire
    time, not silently swallowed."""
    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return str(metadata.get(key, match.group(0)))
    return _PLACEHOLDER_RE.sub(_replace, template)


def _match_selection(event: ParsedEvent, selection: dict[str, Any]) -> bool:
    """Return True if every key in `selection` matches the event.

    Matching rules:
    - If the value is a string, the event metadata value must
      equal it (case-sensitive).
    - If the value is a list, the event metadata value must be
      in the list.
    - If the value starts with `re:` the rest is a regex.
    - If the value starts with `contains:` the event metadata
      value (or the raw event) must contain the rest as a
      substring.
    - Missing keys in the event metadata fail the match.
    """
    for key, expected in selection.items():
        actual = event.metadata.get(key)
        if actual is None:
            # Also check the source field directly.
            if key == "source":
                actual = event.source
            else:
                return False
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, str):
            # Sigma spec modifier syntax: `field|modifier: value`.
            # Checked first so that values starting with `re:` or
            # `contains:` (which also contain `:`) don't accidentally
            # match this branch. The `field` portion is redundant
            # here (the caller already passed the key) but is kept
            # in the syntax for spec compatibility — operators can
            # drop unmodified SigmaHQ rules into the engine.
            if _is_modifier_value(expected):
                if not _match_modifier(actual, expected):
                    return False
            elif expected.startswith("re:"):
                pattern = expected[3:]
                if not re.search(pattern, str(actual)):
                    return False
            elif expected.startswith("contains:"):
                needle = expected[9:]
                if needle not in str(actual) and needle not in event.raw:
                    return False
            else:
                if str(actual) != expected:
                    return False
        else:
            if actual != expected:
                return False
    return True


def _is_modifier_value(value: str) -> bool:
    """Return True if `value` looks like a Sigma spec modifier
    expression `field|modifier: literal`.

    The first `|` splits field/modifier, and the modifier part
    must contain `:` to be a modifier (not a literal pipe).
    The supported modifiers are: startswith, endswith, ge, lt.
    """
    if "|" not in value:
        return False
    _, _, mod_spec = value.partition("|")
    if ":" not in mod_spec:
        return False
    mod, _, _ = mod_spec.partition(":")
    return mod in ("startswith", "endswith", "ge", "lt")


def _match_modifier(actual: Any, value: str) -> bool:
    """Apply a single Sigma spec modifier.

    The supported modifiers are:
      - `field|startswith: literal` — case-sensitive prefix match
      - `field|endswith: literal` — case-sensitive suffix match
      - `field|ge: number` — actual >= number (float compare)
      - `field|lt: number` — actual < number (float compare)

    A non-numeric actual for `ge`/`lt` returns False (fail-safe:
    no false-positive alert from a malformed rule). A non-string
    actual for `startswith`/`endswith` is stringified first.

    The literal value is stripped of leading/trailing whitespace
    so operators can write `startswith: powershell ` (with a
    trailing space) and have it work as expected.
    """
    _, _, mod_spec = value.partition("|")
    mod, _, lit = mod_spec.partition(":")
    lit = lit.strip()
    if mod == "startswith":
        return str(actual).startswith(lit)
    if mod == "endswith":
        return str(actual).endswith(lit)
    if mod == "ge":
        try:
            return float(actual) >= float(lit)
        except (TypeError, ValueError):
            return False
    if mod == "lt":
        try:
            return float(actual) < float(lit)
        except (TypeError, ValueError):
            return False
    # Unknown modifier — _is_modifier_value should have screened.
    return False


@dataclass(frozen=True)
class CompiledSigmaRule:
    """A Sigma rule compiled into a callable matcher."""

    id: str
    title: str
    level: str
    selection: dict[str, Any]
    detection: dict[str, Any]  # full detection block (for compound conditions)
    condition: str
    count: int
    timeframe_sec: int
    cooldown_sec: int
    dedup_key: str
    action: dict[str, Any] | None
    required_fields: tuple[str, ...] = ()  # v1.4.z: fields that MUST be present

    def matches(self, event: ParsedEvent) -> bool:
        """Single-event matching. The runner is responsible for
        counting events in a window — this function checks one
        event against the rule's selection.

        Supported condition patterns (ADR-010):
        - `selection` — all keys in selection must match
        - `selection and not filter` — filter must NOT match
        - `selection and (filter1 or filter2 or ...)` — at
          least one of the listed filters must match
        - `selection and (filter1 or filter2 or ...) and not filter3` —
          at least one of the OR filters must match AND the
          AND-NOT filter must NOT match
        """
        cond = self.condition
        # v1.4.z: strict missing-field fail-safe. If a rule declares
        # `required_fields`, all must be present in event metadata —
        # otherwise we cannot prove the rule's condition, so the rule
        # does NOT fire (fail-closed). This prevents noise from
        # agents that don't yet emit a particular metadata key.
        if self.required_fields:
            for field in self.required_fields:
                if field not in event.metadata:
                    return False
        # Pattern 1: `selection`
        if cond == "selection":
            return _match_selection(event, self.selection)
        # Pattern 2: `selection and not filter` (v1.4.0 existed
        # but silently dropped the filter; v1.4.y evaluates it)
        m = re.fullmatch(r"selection\s+and\s+not\s+(\w+)", cond.strip())
        if m:
            filter_name = m.group(1)
            if filter_name not in self.detection:
                # Unknown filter → no match (don't fail-open)
                return False
            return _match_selection(
                event, self.selection
            ) and not _match_selection(event, self.detection[filter_name])
        # Pattern 3: `selection and (X or Y or Z)`
        m = re.fullmatch(
            r"selection\s+and\s+\(([^)]+)\)", cond.strip()
        )
        if m:
            inner = m.group(1)
            filter_names = [
                f.strip() for f in inner.split(" or ")
            ]
            for fn in filter_names:
                if fn not in self.detection:
                    # Unknown filter → no match
                    return False
            if not _match_selection(event, self.selection):
                return False
            return any(
                _match_selection(event, self.detection[fn])
                for fn in filter_names
            )
        # Pattern 4: `selection and (X or Y) and not Z`
        m = re.fullmatch(
            r"selection\s+and\s+\(([^)]+)\)\s+and\s+not\s+(\w+)",
            cond.strip(),
        )
        if m:
            inner = m.group(1)
            not_filter = m.group(2)
            filter_names = [
                f.strip() for f in inner.split(" or ")
            ]
            for fn in filter_names + [not_filter]:
                if fn not in self.detection:
                    return False
            if not _match_selection(event, self.selection):
                return False
            if _match_selection(event, self.detection[not_filter]):
                return False
            return any(
                _match_selection(event, self.detection[fn])
                for fn in filter_names
            )
        # Unknown condition → no match. Don't silently fail-open.
        return False

    def render_action(self, event: ParsedEvent) -> dict[str, Any] | None:
        """Render the action block, filling placeholders from
        the event. Returns None if the rule has no action.
        """
        if not self.action:
            return None
        kind = self.action.get("kind")
        target_tpl = self.action.get("target", "")
        target = _interpolate(target_tpl, event.metadata)
        if not kind or not target:
            return None
        ttl = self.action.get("ttl_sec")
        if isinstance(ttl, str):
            ttl = _interpolate(ttl, event.metadata)
            try:
                ttl = int(ttl)
            except (TypeError, ValueError):
                ttl = None
        return {"kind": kind, "target": target, "ttl_sec": ttl}

    def render_dedup_key(self, event: ParsedEvent) -> str:
        if not self.dedup_key:
            return self.id
        return _interpolate(self.dedup_key, event.metadata) or self.id


@dataclass
class SigmaRuleLoadError(Exception):
    path: Path
    reason: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"sigma rule {self.path}: {self.reason}"


def parse_rule_file(path: Path) -> list[CompiledSigmaRule]:
    """Parse one YAML file. A file may contain a single rule or a
    list of rules.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        # F-026: don't leak rule-file source via PyYAML's default error
        # formatter (which includes a snippet of the offending line). Log
        # only the structured position info (line, column) and the problem
        # mark; the full source fragment stays in the exception chain
        # for in-process introspection but is not formatted into the
        # operator-facing message.
        problem = getattr(e, "problem_mark", None)
        if problem is not None:
            loc = f"line {problem.line + 1}, column {problem.column + 1}"
        else:
            loc = "unknown position"
        raise SigmaRuleLoadError(path, f"invalid YAML at {loc}") from e
    except OSError as e:
        # F-026: same hygiene — don't surface the OSError's full str.
        raise SigmaRuleLoadError(path, f"cannot read: {type(e).__name__}") from e
    if data is None:
        return []
    rules_data = data if isinstance(data, list) else [data]
    out: list[CompiledSigmaRule] = []
    for raw in rules_data:
        if not isinstance(raw, dict):
            raise SigmaRuleLoadError(path, "rule must be a mapping")
        out.append(_compile(raw, path))
    return out


def _compile(raw: dict[str, Any], path: Path) -> CompiledSigmaRule:
    title = str(raw.get("title") or raw.get("id") or "unnamed")
    rule_id = str(raw.get("id") or title.lower().replace(" ", "-"))
    level = str(raw.get("level") or "medium")
    if level not in ("low", "medium", "high", "critical"):
        raise SigmaRuleLoadError(path, f"invalid level: {level}")
    detection = raw.get("detection")
    if not isinstance(detection, dict):
        raise SigmaRuleLoadError(path, "missing 'detection' block")
    selection = detection.get("selection")
    if not isinstance(selection, dict):
        raise SigmaRuleLoadError(path, "missing 'detection.selection'")
    condition = str(detection.get("condition") or "selection")
    count = int(detection.get("count") or 1)
    timeframe_raw = detection.get("timeframe", "60s")
    timeframe_sec = _parse_timeframe(timeframe_raw)
    cooldown_sec = int(raw.get("cooldown_sec") or 300)
    dedup_key = str(raw.get("dedup_key") or "")
    action = raw.get("action")
    if action is not None and not isinstance(action, dict):
        raise SigmaRuleLoadError(path, "'action' must be a mapping")
    # v1.4.z: required_fields — list of metadata keys that MUST
    # be present for the rule to fire. Fail-closed semantics.
    required_fields_raw = raw.get("required_fields", [])
    if not isinstance(required_fields_raw, list):
        raise SigmaRuleLoadError(
            path, "'required_fields' must be a list of strings"
        )
    required_fields = tuple(str(f) for f in required_fields_raw)
    return CompiledSigmaRule(
        id=rule_id,
        title=title,
        level=level,
        selection=selection,
        detection=detection,
        condition=condition,
        count=count,
        timeframe_sec=timeframe_sec,
        cooldown_sec=cooldown_sec,
        dedup_key=dedup_key,
        action=action,
        required_fields=required_fields,
    )


def _parse_timeframe(value: Any) -> int:
    """Parse '60s', '5m', '1h' into seconds. Bare numbers default
    to seconds. Invalid values fall back to 60.
    """
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    if not s:
        return 60
    if s.endswith("ms"):
        try:
            return max(1, int(s[:-2]) // 1000)
        except ValueError:
            return 60
    if s.endswith("s"):
        try:
            return int(s[:-1])
        except ValueError:
            return 60
    if s.endswith("m"):
        try:
            return int(s[:-1]) * 60
        except ValueError:
            return 60
    if s.endswith("h"):
        try:
            return int(s[:-1]) * 3600
        except ValueError:
            return 60
    try:
        return int(s)
    except ValueError:
        return 60


def load_rules_from_dir(directory: Path) -> list[CompiledSigmaRule]:
    """Load all `*.yml` and `*.yaml` files in `directory` (recursively).
    Files that fail to parse are logged and skipped — one bad rule
    shouldn't take down the whole engine.
    """
    if not directory.exists() or not directory.is_dir():
        return []
    out: list[CompiledSigmaRule] = []
    for ext in ("*.yml", "*.yaml"):
        for p in directory.rglob(ext):
            try:
                out.extend(parse_rule_file(p))
            except SigmaRuleLoadError as e:
                # Don't crash the runner on a bad rule. The caller
                # can introspect the engine's load_errors if it cares.
                import logging
                logging.getLogger(__name__).warning(str(e))
    return out


__all__ = [
    "CompiledSigmaRule",
    "SigmaRuleLoadError",
    "load_rules_from_dir",
    "parse_rule_file",
]
