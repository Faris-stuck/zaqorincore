"""DNS tunneling detector (Phase 5).

Fires when a single source IP issues a large number of long DNS
queries (high-entropy subdomain) within a short window. This is
a strong indicator of DNS exfiltration or C2 over DNS.

The detector does NOT score entropy — it uses a simpler proxy:
the length of the leftmost label. A long subdomain (>40 chars)
on a small query count (>50) is enough to flag.

Tunables (env vars):
- ZAQORIN_DNS_TUNNEL_LABEL_THRESHOLD (default 40)
- ZAQORIN_DNS_TUNNEL_QUERY_THRESHOLD (default 50)
- ZAQORIN_DNS_TUNNEL_WINDOW_SEC (default 60)
- ZAQORIN_DNS_TUNNEL_COOLDOWN_SEC (default 900 = 15 min)
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


def _is_dns_event(event: ParsedEvent) -> bool:
    src = event.metadata.get("source", "").lower()
    return "dns" in src or "named" in src


def _extract_source_ip(event: ParsedEvent) -> str | None:
    return event.metadata.get("source_ip")


def _extract_qname(event: ParsedEvent) -> str | None:
    q = event.metadata.get("qname") or event.metadata.get("query")
    if q and isinstance(q, str):
        return q.strip().rstrip(".").lower()
    return None


def _leftmost_label_length(qname: str) -> int:
    """Return the length of the leftmost label of a DNS name."""
    return len(qname.split(".", 1)[0]) if qname else 0


def _window_key(host_id: Any, ip: str) -> str:
    return f"zc:rule:dns_tunnel:{host_id}:{ip}"


class DnsTunnelDetector:
    name = "dns_tunnel"

    async def on_event(
        self, event: ParsedEvent, ctx: DetectorContext
    ) -> list[DetectionResult]:
        settings: Settings = ctx.settings
        if not _is_dns_event(event):
            return []
        ip = _extract_source_ip(event)
        qname = _extract_qname(event)
        if not ip or not qname:
            return []
        if _leftmost_label_length(qname) < getattr(
            settings, "dns_tunnel_label_threshold", 40
        ):
            return []
        threshold = getattr(settings, "dns_tunnel_query_threshold", 50)
        window_sec = getattr(settings, "dns_tunnel_window_sec", 60)
        cooldown_sec = getattr(settings, "dns_tunnel_cooldown_sec", 900)
        try:
            key = _window_key(event.host_id, ip)
            now_ms = int(event.timestamp.timestamp() * 1000)
            window_start = now_ms - window_sec * 1000
            pipe = ctx.redis.pipeline()
            pipe.zremrangebyscore(key, "-inf", window_start)
            pipe.zadd(key, {f"{qname}:{now_ms}": now_ms})
            pipe.zcard(key)
            pipe.expire(key, window_sec * 5)
            results = await pipe.execute()
            seen = results[2]
        except Exception as e:  # noqa: BLE001
            logger.warning("dns_tunnel: redis error, fail-open: %s", e)
            return []
        if seen < threshold:
            return []
        return [
            DetectionResult(
                detector=self.name,
                severity="high",
                summary=f"possible DNS tunnel from {ip} ({seen} long queries in {window_sec}s)",
                detail={
                    "source_ip": ip,
                    "long_queries_in_window": seen,
                    "window_sec": window_sec,
                    "sample_qname": qname,
                },
                dedup_key=ip,
                cooldown_sec=cooldown_sec,
                action=DetectionAction(
                    kind="block_ip",
                    target=ip,
                    ttl_sec=3600,
                ),
            )
        ]


DETECTOR: Detector = DnsTunnelDetector()
