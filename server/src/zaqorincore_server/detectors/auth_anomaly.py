"""Auth anomaly detector (Phase 5).

Fires when a user authenticates from an unusual source IP (one
they have never used in the last 7 days) OR when the same user
authenticates from multiple IPs in a short window. Both are
signs of credential theft.

The detector keeps a small Redis set of "known IPs per user" and
triggers on the first sighting of a new IP. It does not maintain
a long-term state — a Redis TTL of 7 days is enough for the
"first time" detection.

Tunables (env vars):
- ZAQORIN_AUTH_ANOMALY_KNOWN_IP_TTL_SEC (default 7 * 86400)
- ZAQORIN_AUTH_ANOMALY_DIFFERENT_IPS_THRESHOLD (default 3)
- ZAQORIN_AUTH_ANOMALY_WINDOW_SEC (default 300)
- ZAQORIN_AUTH_ANOMALY_COOLDOWN_SEC (default 600)
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


def _is_auth_success(event: ParsedEvent) -> bool:
    status = str(event.metadata.get("status", "")).lower()
    return status in ("success", "accepted", "ok", "0")


def _extract_user(event: ParsedEvent) -> str | None:
    u = event.metadata.get("user") or event.metadata.get("username")
    if u and isinstance(u, str):
        return u.strip()
    return None


def _extract_source_ip(event: ParsedEvent) -> str | None:
    return event.metadata.get("source_ip")


def _known_ip_key(host_id: Any, user: str) -> str:
    return f"zc:rule:auth_anomaly:known_ips:{host_id}:{user}"


def _diff_ips_key(host_id: Any, user: str) -> str:
    return f"zc:rule:auth_anomaly:diff_ips:{host_id}:{user}"


class AuthAnomalyDetector:
    name = "auth_anomaly"

    async def on_event(
        self, event: ParsedEvent, ctx: DetectorContext
    ) -> list[DetectionResult]:
        settings: Settings = ctx.settings
        if not _is_auth_success(event):
            return []
        user = _extract_user(event)
        ip = _extract_source_ip(event)
        if not user or not ip:
            return []
        known_ttl = getattr(settings, "auth_anomaly_known_ip_ttl_sec", 7 * 86400)
        diff_threshold = getattr(settings, "auth_anomaly_different_ips_threshold", 3)
        window_sec = getattr(settings, "auth_anomaly_window_sec", 300)
        cooldown_sec = getattr(settings, "auth_anomaly_cooldown_sec", 600)
        try:
            known_key = _known_ip_key(event.host_id, user)
            seen_before = await ctx.redis.sismember(known_key, ip)
            await ctx.redis.sadd(known_key, ip)
            await ctx.redis.expire(known_key, known_ttl)

            diff_key = _diff_ips_key(event.host_id, user)
            now_ms = int(event.timestamp.timestamp() * 1000)
            window_start = now_ms - window_sec * 1000
            pipe = ctx.redis.pipeline()
            pipe.zremrangebyscore(diff_key, "-inf", window_start)
            pipe.zadd(diff_key, {f"{ip}:{now_ms}": now_ms})
            pipe.zcard(diff_key)
            pipe.expire(diff_key, window_sec * 5)
            pipe_results = await pipe.execute()
            distinct_ips = pipe_results[2]
        except Exception as e:  # noqa: BLE001
            logger.warning("auth_anomaly: redis error, fail-open: %s", e)
            return []
        results: list[DetectionResult] = []
        # First-time IP for this user
        if not seen_before:
            results.append(
                DetectionResult(
                    detector=self.name,
                    severity="medium",
                    summary=f"new source IP for user {user!r}: {ip}",
                    detail={
                        "user": user,
                        "source_ip": ip,
                        "first_seen": True,
                    },
                    dedup_key=f"{user}:{ip}",
                    cooldown_sec=cooldown_sec,
                    # No auto-block: first-time IP is too noisy. Operator
                    # can ack and add to allowlist.
                )
            )
        # Multiple distinct IPs in short window
        if distinct_ips >= diff_threshold:
            results.append(
                DetectionResult(
                    detector=self.name,
                    severity="high",
                    summary=(
                        f"user {user!r} authenticated from {distinct_ips} "
                        f"distinct IPs in {window_sec}s"
                    ),
                    detail={
                        "user": user,
                        "distinct_ips_in_window": distinct_ips,
                        "window_sec": window_sec,
                    },
                    dedup_key=f"{user}:multi_ip",
                    cooldown_sec=cooldown_sec,
                    action=DetectionAction(
                        kind="revoke_session",
                        target=f"user:{user}",
                        ttl_sec=86400,
                    ),
                )
            )
        return results


DETECTOR: Detector = AuthAnomalyDetector()
