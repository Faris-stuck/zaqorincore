"""Tests for the compliance rule packs (Phase 8)."""

from __future__ import annotations

from pathlib import Path

import pytest

from zaqorincore_server.rule_engine.sigma import (
    CompiledSigmaRule,
    SigmaRuleLoadError,
    load_rules_from_dir,
)


RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "builtin"


@pytest.mark.parametrize(
    "subdir, expected_min",
    [
        ("", 5),                  # the original 5 generic rules
        ("iso27001_nist80053", 10),
        ("pci_dss", 10),
        ("uu_pdp", 10),
        ("mitre_attack", 8),
    ],
)
def test_compliance_packs_load(subdir: str, expected_min: int) -> None:
    """Each compliance pack must load at least `expected_min`
    rules. The numbers are floor minimums; the actual counts
    are higher once the subagents finish.
    """
    d = RULES_DIR / subdir if subdir else RULES_DIR
    if not d.exists():
        pytest.skip(f"{d} does not exist yet (subagent in progress)")
    rules = load_rules_from_dir(d)
    assert len(rules) >= expected_min, (
        f"expected at least {expected_min} rules in {d}, got {len(rules)}"
    )


def test_builtin_packs_have_unique_ids() -> None:
    """Across all packs, no two rules should share an id.
    Duplicate ids cause silent shadowing.
    """
    seen: dict[str, Path] = {}
    if not RULES_DIR.exists():
        pytest.skip("rules/builtin/ missing")
    for path in RULES_DIR.rglob("*.yml"):
        rules = load_rules_from_dir(path)
        for r in rules:
            rid = r.id
            if rid in seen:
                if seen[rid] != path:
                    pytest.fail(
                        f"duplicate rule id {rid!r} in {path} "
                        f"(also in {seen[rid]})"
                    )
            seen[rid] = path


def test_builtin_packs_have_tags() -> None:
    """Every compliance rule should have at least one tag
    identifying the framework it maps to. Without tags the
    rule is uncategorizable.

    We read the raw YAML so this works even when the compiled
    rule strips the field.
    """
    if not RULES_DIR.exists():
        pytest.skip("rules/builtin/ missing")
    for path in RULES_DIR.rglob("*.yml"):
        import yaml
        with path.open() as f:
            docs = list(yaml.safe_load_all(f))
        for doc in docs:
            if not doc:
                continue
            tags = doc.get("tags") or []
            assert tags, f"{path}: rule {doc.get('title', '?')!r} has no tags"


def test_builtin_packs_have_references() -> None:
    """Every compliance rule should have at least one reference
    linking to the framework/technique it implements. References
    are how auditors verify coverage.
    """
    if not RULES_DIR.exists():
        pytest.skip("rules/builtin/ missing")
    for path in RULES_DIR.rglob("*.yml"):
        import yaml
        with path.open() as f:
            docs = list(yaml.safe_load_all(f))
        for doc in docs:
            if not doc:
                continue
            refs = doc.get("references") or doc.get("ref") or []
            assert refs, (
                f"{path}: rule {doc.get('title', '?')!r} has no references"
            )
