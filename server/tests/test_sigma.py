"""Tests for the Sigma rule loader (sigma.py)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import (
    CompiledSigmaRule,
    SigmaRuleLoadError,
    load_rules_from_dir,
    parse_rule_file,
)


def _event(**metadata) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="sshd",
        raw="Failed password for root from 203.0.113.42 port 54321 ssh2",
        metadata=metadata or {"status": "failed", "source_ip": "203.0.113.42"},
        occurred_at=datetime.now(timezone.utc),
    )


def test_parse_simple_rule(tmp_path: Path) -> None:
    rule_yaml = """
title: Test rule
id: test-001
level: high
detection:
  selection:
    source: "sshd"
  condition: selection
"""
    p = tmp_path / "test.yml"
    p.write_text(rule_yaml)
    rules = parse_rule_file(p)
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "test-001"
    assert r.title == "Test rule"
    assert r.level == "high"
    assert r.count == 1
    assert r.timeframe_sec == 60
    assert r.cooldown_sec == 300


def test_parse_rule_with_action_and_template(tmp_path: Path) -> None:
    rule_yaml = """
title: SSH bf
id: ssh-bf-yaml
level: high
detection:
  selection:
    source: "sshd"
    status: "failed"
  condition: selection
  timeframe: 30s
  count: 3
action:
  kind: block_ip
  target: "{{source_ip}}"
  ttl_sec: 600
cooldown_sec: 120
dedup_key: "{{source_ip}}"
"""
    p = tmp_path / "ssh.yml"
    p.write_text(rule_yaml)
    r = parse_rule_file(p)[0]
    assert r.timeframe_sec == 30
    assert r.count == 3
    assert r.cooldown_sec == 120
    assert r.action is not None
    assert r.action["kind"] == "block_ip"
    assert r.action["target"] == "{{source_ip}}"
    assert r.action["ttl_sec"] == 600
    # Render with a real event.
    e = _event(source_ip="10.0.0.1", status="failed", source="sshd")
    rendered = r.render_action(e)
    assert rendered == {"kind": "block_ip", "target": "10.0.0.1", "ttl_sec": 600}
    assert r.render_dedup_key(e) == "10.0.0.1"


def test_parse_multi_doc_file(tmp_path: Path) -> None:
    p = tmp_path / "multi.yml"
    p.write_text(
        """
- title: R1
  id: r1
  detection:
    selection: {x: a}
    condition: selection
- title: R2
  id: r2
  detection:
    selection: {y: b}
    condition: selection
"""
    )
    rules = parse_rule_file(p)
    assert [r.id for r in rules] == ["r1", "r2"]


def test_parse_invalid_level(tmp_path: Path) -> None:
    p = tmp_path / "bad.yml"
    p.write_text(
        "title: x\nid: x\nlevel: banana\ndetection:\n  selection: {a: b}\n  condition: selection\n"
    )
    with pytest.raises(SigmaRuleLoadError):
        parse_rule_file(p)


def test_parse_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "broken.yml"
    p.write_text("title: : : not yaml")
    with pytest.raises(SigmaRuleLoadError):
        parse_rule_file(p)


def test_load_rules_from_dir_recurses(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "a.yml").write_text(
        "title: A\nid: a\ndetection:\n  selection: {x: y}\n  condition: selection\n"
    )
    (sub / "b.yml").write_text(
        "title: B\nid: b\ndetection:\n  selection: {x: y}\n  condition: selection\n"
    )
    rules = load_rules_from_dir(tmp_path)
    assert {r.id for r in rules} == {"a", "b"}


def test_load_rules_skips_bad_file(tmp_path: Path) -> None:
    (tmp_path / "ok.yml").write_text(
        "title: OK\nid: ok\ndetection:\n  selection: {x: y}\n  condition: selection\n"
    )
    (tmp_path / "bad.yml").write_text("not yaml at all:")
    rules = load_rules_from_dir(tmp_path)
    assert [r.id for r in rules] == ["ok"]


def test_timeframe_parsing() -> None:
    from zaqorincore_server.rule_engine.sigma import _parse_timeframe
    assert _parse_timeframe("60s") == 60
    assert _parse_timeframe("5m") == 300
    assert _parse_timeframe("1h") == 3600
    assert _parse_timeframe("60") == 60
    assert _parse_timeframe("") == 60
    assert _parse_timeframe("garbage") == 60


def test_regex_match_in_selection(tmp_path: Path) -> None:
    rule_yaml = """
title: Web SQLi
id: sqli
level: critical
detection:
  selection:
    url: 're:(?i)(union.+select)'
  condition: selection
"""
    p = tmp_path / "sqli.yml"
    p.write_text(rule_yaml)
    r = parse_rule_file(p)[0]
    e1 = _event(url="/api?id=1 UNION SELECT password FROM users")
    e2 = _event(url="/api?id=42")
    assert r.matches(e1)
    assert not r.matches(e2)


def test_list_match_in_selection(tmp_path: Path) -> None:
    rule_yaml = """
title: Multisource
id: ms
level: medium
detection:
  selection:
    source: ["sshd", "sudo"]
  condition: selection
"""
    p = tmp_path / "ms.yml"
    p.write_text(rule_yaml)
    r = parse_rule_file(p)[0]
    e1 = _event(source="sshd")
    e2 = _event(source="sudo")
    e3 = _event(source="cron")
    assert r.matches(e1)
    assert r.matches(e2)
    assert not r.matches(e3)


def test_contains_match_in_selection(tmp_path: Path) -> None:
    rule_yaml = """
title: Substring
id: sub
level: low
detection:
  selection:
    url: "contains:admin"
  condition: selection
"""
    p = tmp_path / "sub.yml"
    p.write_text(rule_yaml)
    r = parse_rule_file(p)[0]
    assert r.matches(_event(url="/admin/login"))
    assert not r.matches(_event(url="/login"))


def test_placeholder_leaves_unknown_as_literal() -> None:
    rule_yaml = """
title: T
id: t
detection:
  selection: {x: y}
  condition: selection
action:
  kind: webhook_soar
  target: "https://example.com/{{unknown_field}}"
"""
    p = rule_yaml
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(rule_yaml)
        p = f.name
    r = parse_rule_file(Path(p))[0]
    e = _event()
    rendered = r.render_action(e)
    assert rendered is not None
    assert rendered["target"] == "https://example.com/{{unknown_field}}"
