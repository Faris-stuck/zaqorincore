"""Tests for the v1.7.7 CDN-specific Sigma rule expansion (Slice A).

Six new rules in rules/builtin/mitre_attack/ that fire on
cloudflare_logpush (and the same metadata fields when emitted by
nginx_access):
- T1190_cdn_origin_shield_bypass.yml
- T1190_cdn_bot_score_anomaly.yml
- T1110_cdn_login_brute_force.yml
- T1078_cdn_geo_anomaly.yml
- T1190_cdn_waf_bypass_attempt.yml
- T1110_cdn_credential_stuffing.yml
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fake_redis import FakeRedis
from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
from zaqorincore_server.rule_engine.sigma import (
    load_rules_from_dir,
    parse_rule_file,
)


CDN_RULE_FILES = (
    "T1190_cdn_origin_shield_bypass.yml",
    "T1190_cdn_bot_score_anomaly.yml",
    "T1110_cdn_login_brute_force.yml",
    "T1078_cdn_geo_anomaly.yml",
    "T1190_cdn_waf_bypass_attempt.yml",
    "T1110_cdn_credential_stuffing.yml",
)


def _cdn_rules_dir() -> Path:
    return Path("rules/builtin/mitre_attack")


def _cdn_rule_dict():
    """Return {filename: rule} for every cdn file, parsed fresh.

    Used by tests that need to read raw YAML structure (e.g. tags,
    description) rather than the compiled runtime form.
    """
    out = {}
    for fname in CDN_RULE_FILES:
        path = _cdn_rules_dir() / fname
        rules = parse_rule_file(path)
        assert len(rules) == 1, f"{fname} should contain exactly one rule"
        out[fname] = rules[0]
    return out


def _event(source: str, **metadata) -> ParsedEvent:
    md = {"source": source}
    md.update(metadata)
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source=source,
        raw="cdn test event",
        metadata=md,
        occurred_at=datetime.now(timezone.utc),
    )


# --------------------------------------------------------------------
# Structural / schema tests
# --------------------------------------------------------------------


def test_cdn_rules_load_all() -> None:
    """All six CDN rules parse without error and have unique IDs."""
    seen_ids: dict[str, str] = {}
    for fname in CDN_RULE_FILES:
        path = _cdn_rules_dir() / fname
        parsed = parse_rule_file(path)
        assert len(parsed) == 1, f"{fname} should contain exactly one rule"
        rid = parsed[0].id
        assert rid not in seen_ids, (
            f"duplicate rule id {rid} in {fname} and {seen_ids[rid]}"
        )
        seen_ids[rid] = fname
    assert len(seen_ids) == 6
    # Sanity: load_rules_from_dir should also pick them up.
    rules = load_rules_from_dir(_cdn_rules_dir())
    parsed_ids = set(seen_ids.keys())
    assert parsed_ids.issubset({r.id for r in rules})


def test_cdn_rules_detection_shape() -> None:
    """Every CDN rule has a `detection` block with at least one selection."""
    for fname, rule in _cdn_rule_dict().items():
        detection = rule.detection
        assert isinstance(detection, dict), (
            f"{fname}: detection must be a mapping"
        )
        assert "selection" in detection, (
            f"{fname}: detection missing 'selection'"
        )
        assert isinstance(detection["selection"], dict), (
            f"{fname}: detection.selection must be a mapping"
        )
        assert len(detection["selection"]) >= 1, (
            f"{fname}: selection must have at least one key"
        )
        assert "condition" in detection, (
            f"{fname}: detection missing 'condition'"
        )


def test_cdn_rules_mitre_mapping() -> None:
    """Every CDN rule has at least one tag starting with `attack.t`."""
    for fname in CDN_RULE_FILES:
        path = _cdn_rules_dir() / fname
        raw = path.read_text(encoding="utf-8")
        assert re.search(r"^\s*-\s+attack\.t\d", raw, re.MULTILINE), (
            f"{fname}: no MITRE technique tag (attack.tXXXX) found"
        )


def test_cdn_rules_level_valid() -> None:
    """Every CDN rule's `level` is in (low, medium, high, critical)."""
    valid = {"low", "medium", "high", "critical"}
    for fname, rule in _cdn_rule_dict().items():
        assert rule.level in valid, (
            f"{fname}: invalid level {rule.level!r}"
        )


def test_cdn_rules_no_ai_jargon() -> None:
    """No AI/ML/LLM/neural/GPT mentions in any CDN rule file."""
    pattern = re.compile(r"\b(AI|ML|LLM|neural|GPT)\b", re.IGNORECASE)
    for fname in CDN_RULE_FILES:
        path = _cdn_rules_dir() / fname
        text = path.read_text(encoding="utf-8")
        matches = pattern.findall(text)
        assert matches == [], (
            f"{fname}: forbidden AI jargon found: {matches}"
        )


def test_cdn_rules_no_real_ips() -> None:
    """No production-looking IPs in any CDN rule file."""
    forbidden_patterns = (
        "127.0.0.1",
        "10.0.0.",
        "192.168.",
    )
    for fname in CDN_RULE_FILES:
        path = _cdn_rules_dir() / fname
        text = path.read_text(encoding="utf-8")
        for needle in forbidden_patterns:
            assert needle not in text, (
                f"{fname}: forbidden IP literal {needle!r} found"
            )


# --------------------------------------------------------------------
# Behavioural tests — verify each rule actually matches/misses the
# intended events end-to-end through the runner.
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_origin_shield_bypass_fires_on_origin_hit() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_origin_shield_bypass.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.10",
            origin_ip_hit_count="2",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_origin_shield_bypass_fires_on_waf_origin_var() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_origin_shield_bypass.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.11",
            waf_matched_var="origin_server",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_origin_shield_bypass_no_fire_without_signal() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_origin_shield_bypass.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.12",
            origin_ip_hit_count="0",
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_bot_score_anomaly_fires_on_headless_ua() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_bot_score_anomaly.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.20",
            bot_score="15",
            user_agent="HeadlessChrome/120",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_bot_score_anomaly_no_fire_on_normal_ua() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_bot_score_anomaly.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.21",
            bot_score="15",
            user_agent="Mozilla/5.0 (X11; Linux) Firefox/124",
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_login_brute_force_fires_at_eleventh_failure() -> None:
    rule = _cdn_rule_dict()["T1110_cdn_login_brute_force.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = []
    for _ in range(11):
        fires = await runner.evaluate(
            _event(
                "cloudflare_logpush",
                src_ip="198.51.100.30",
                uri="/login",
                status="401",
            )
        )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_login_brute_force_no_fire_on_200() -> None:
    rule = _cdn_rule_dict()["T1110_cdn_login_brute_force.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = []
    for _ in range(11):
        fires = await runner.evaluate(
            _event(
                "cloudflare_logpush",
                src_ip="198.51.100.31",
                uri="/login",
                status="200",
            )
        )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_geo_anomaly_fires_on_blocked_country() -> None:
    rule = _cdn_rule_dict()["T1078_cdn_geo_anomaly.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.40",
            uri="/admin",
            country="CN",
            asn_authoritative="false",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_geo_anomaly_no_fire_on_allowed_country() -> None:
    rule = _cdn_rule_dict()["T1078_cdn_geo_anomaly.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.41",
            uri="/admin",
            country="US",
            asn_authoritative="false",
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_waf_bypass_fires_on_block_plus_2xx() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_waf_bypass_attempt.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.50",
            waf_action="BLOCK",
            status="200",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_waf_bypass_no_fire_on_block_plus_403() -> None:
    rule = _cdn_rule_dict()["T1190_cdn_waf_bypass_attempt.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "cloudflare_logpush",
            src_ip="198.51.100.51",
            waf_action="BLOCK",
            status="403",
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_credential_stuffing_fires_at_fifty_first_request() -> None:
    rule = _cdn_rule_dict()["T1110_cdn_credential_stuffing.yml"]
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = []
    for _ in range(51):
        fires = await runner.evaluate(
            _event(
                "cloudflare_logpush",
                src_ip="198.51.100.60",
                uri="/api/auth/login",
            )
        )
    assert len(fires) == 1