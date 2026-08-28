"""Tests for the 4 new detectors in Phase 5 (port_scan, web_attack,
dns_tunnel, auth_anomaly).

We test only the pure helper functions: shape detection, regex
matching, source-IP extraction, and label-length measurement. The
Redis-backed sliding window is exercised in test_detectors_integration
under the runner fixture (which has a real Redis URL).
"""

from __future__ import annotations

import datetime as _dt
import uuid

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.detectors.dns_tunnel import (
    _extract_qname,
    _is_dns_event,
    _leftmost_label_length,
)
from zaqorincore_server.detectors.port_scan import (
    _extract_dest_port,
    _extract_source_ip,
    _is_port_knock,
)
from zaqorincore_server.detectors.web_attack import _is_http_event, _match_patterns


def _event(**kwargs) -> ParsedEvent:
    """Helper to construct a ParsedEvent with sensible defaults."""
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="test",
        occurred_at=_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc),
        raw=kwargs.pop("raw", ""),
        metadata=kwargs,
    )


# --- port_scan ---

def test_port_knock_recognizes_dport():
    e = _event(dport=22)
    assert _is_port_knock(e)
    assert _extract_dest_port(e) == 22


def test_port_knock_drops_garbage_port():
    e = _event(dport="not-a-port")
    assert _extract_dest_port(e) is None


def test_port_knock_drops_out_of_range():
    assert _extract_dest_port(_event(dest_port=0)) is None
    assert _extract_dest_port(_event(dest_port=65536)) is None
    assert _extract_dest_port(_event(dest_port=99999)) is None


def test_port_knock_network_connect_explicit():
    e = _event(event_type="network.connect")
    assert _is_port_knock(e)


def test_port_knock_no_port_no_event_type():
    e = _event()
    assert not _is_port_knock(e)


def test_port_knock_source_ip():
    e = _event(source_ip="203.0.113.10", dport=80)
    assert _extract_source_ip(e) == "203.0.113.10"


# --- web_attack ---

def test_web_attack_sqli_pattern():
    e = _event(raw="GET /search?q=' OR 1=1 -- HTTP/1.1", source_ip="1.2.3.4")
    matches = _match_patterns(e)
    assert "sqli" in matches


def test_web_attack_xss_pattern():
    e = _event(raw="GET /?q=<script>alert(1)</script> HTTP/1.1", source_ip="1.2.3.4")
    matches = _match_patterns(e)
    assert "xss" in matches


def test_web_attack_path_traversal():
    e = _event(raw="GET /../../etc/passwd HTTP/1.1", source_ip="1.2.3.4")
    matches = _match_patterns(e)
    assert "path_traversal" in matches


def test_web_attack_scanner_fingerprint():
    e = _event(
        raw="GET /nmaplowercheck123456789 HTTP/1.1",
        source_ip="1.2.3.4",
        user_agent="sqlmap/1.5",
    )
    matches = _match_patterns(e)
    assert "scanner" in matches


def test_web_attack_clean_request_no_match():
    e = _event(raw="GET /index.html HTTP/1.1", source_ip="1.2.3.4")
    assert _match_patterns(e) == []


def test_web_attack_is_http_event_nginx():
    e = _event(raw="...", source="nginx")
    assert _is_http_event(e)


def test_web_attack_is_http_event_method_prefix():
    e = _event(raw="POST /api HTTP/1.1")
    assert _is_http_event(e)


def test_web_attack_not_http_event():
    e = _event(raw="kernel: audit ...", source="syslog")
    assert not _is_http_event(e)


# --- dns_tunnel ---

def test_dns_event_recognized():
    assert _is_dns_event(_event(source="dns"))
    assert _is_dns_event(_event(source="bind-named"))
    assert not _is_dns_event(_event(source="auth"))


def test_dns_qname_extracted():
    e = _event(qname="aGVsbG8.example.com.")
    # _extract_qname lowercases the qname (canonical form).
    assert _extract_qname(e) == "agvsbg8.example.com"


def test_dns_qname_missing():
    assert _extract_qname(_event()) is None


def test_dns_leftmost_label_length():
    assert _leftmost_label_length("aaaa.example.com") == 4
    assert _leftmost_label_length("a") == 1
    assert _leftmost_label_length("") == 0


def test_dns_leftmost_label_handles_empty():
    assert _leftmost_label_length("") == 0


# --- auth_anomaly helpers (small, tested via runner integration) ---

def test_auth_anomaly_event_construction():
    """Sanity: events with status=success + user + source_ip are
    well-formed (the detector itself is exercised under the runner)."""
    e = _event(
        source_ip="203.0.113.99",
        user="alice",
        status="success",
    )
    assert e.metadata["user"] == "alice"
    assert e.metadata["source_ip"] == "203.0.113.99"
    assert e.metadata["status"] == "success"
