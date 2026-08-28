"""Port-scan detector (Phase 5).

Fires when a single source IP touches an unusual number of distinct
destination ports on the same host within a short window.

The signature is a heuristic, not a guarantee — legitimate clients
can occasionally sweep ports (nmap itself, a sysadmin's own
diagnostic). The default threshold is high enough to keep the
false-positive rate under control, and the cooldown is long
enough that re-scans don't spam the dashboard.

Tunables (env vars):
- ZAQORIN_PORT_SCAN_THRESHOLD  (default 20 distinct ports)
- ZAQORIN_PORT_SCAN_WINDOW_SEC (default 30)
- ZAQORIN_PORT_SCAN_COOLDOWN_SEC (default 600 = 10 min)
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import Settings
from .base import (
    DetectionAction,
    DetectionResult,
    Detector,
    DetectorContext,
    ParsedEvent,
)

logger = logging.getLogger(__name__)


def _extract_source_ip(event: ParsedEvent) -> str | None:
    return event.metadata.get("source_ip")


def _extract_dest_port(event: ParsedEvent) -> int | None:
    raw = event.metadata.get("dest_port") or event.metadata.get("dport")
    if raw is None:
        return None
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    if 0 < n < 65536:
        return n
    return None


def _is_port_knock(event: ParsedEvent) -> bool:
    """Heuristic: the event represents a TCP/UDP port being hit."""
    if event.metadata.get("event_type") == "network.connect":
        return True
    return _extract_dest_port(event) is not None


def _window_key(host_id: Any, ip: str) -> str:
    return f"zc:rule:port_scan:{host_id}:{ip}"


class PortScanDetector:
    name = "port_scan"

    async def on_event(
        self, event: ParsedEvent, ctx: DetectorContext
    ) -> list[DetectionResult]:
        settings: Settings = ctx.settings
        if not _is_port_knock(event):
            return []
        ip = _extract_source_ip(event)
        port = _extract_dest_port(event)
        if not ip or port is None:
            return []

        threshold = getattr(settings, "port_scan_threshold", 20)
        window_sec = getattr(settings, "port_scan_window_sec", 30)
        cooldown_sec = getattr(settings, "port_scan_cooldown_sec", 600)
        try:
            key = _window_key(event.host_id, ip)
            now_ms = int(event.timestamp.timestamp() * 1000)
            window_start = now_ms - window_sec * 1000
            pipe = ctx.redis.pipeline()
            pipe.zremrangebyscore(key, "-inf", window_start)
            pipe.zadd(key, {f"{port}:{now_ms}": now_ms})
            pipe.zcard(key)
            pipe.expire(key, window_sec * 5)
            results = await pipe.execute()
            distinct_ports_seen = results[2]
        except Exception as e:  # noqa: BLE001
            logger.warning("port_scan: redis error, fail-open: %s", e)
            return []

        if distinct_ports_seen < threshold:
            return []
        return [
            DetectionResult(
                detector=self.name,
                severity="medium",
                summary=f"port scan: {ip} hit {distinct_ports_seen} ports in {window_sec}s",
                detail={
                    "source_ip": ip,
                    "ports_in_window": distinct_ports_seen,
                    "window_sec": window_sec,
                },
                dedup_key=ip,
                cooldown_sec=cooldown_sec,
                action=DetectionAction(
                    kind="tarpit_ip",
                    target=ip,
                    ttl_sec=1800,
                ),
            )
        ]


DETECTOR: Detector = PortScanDetector()
