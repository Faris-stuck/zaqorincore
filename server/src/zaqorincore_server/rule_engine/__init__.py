"""Rule engine package (Phase 6, ADR-004).

A Sigma-compatible rule loader + runner. Operators write rules in
YAML; the engine compiles them and runs them against the event
stream. Phase 5 detector plugins keep working in parallel.
"""

from __future__ import annotations

from .sigma import (
    CompiledSigmaRule,
    SigmaRuleLoadError,
    load_rules_from_dir,
    parse_rule_file,
)

__all__ = [
    "CompiledSigmaRule",
    "SigmaRuleLoadError",
    "load_rules_from_dir",
    "parse_rule_file",
]
