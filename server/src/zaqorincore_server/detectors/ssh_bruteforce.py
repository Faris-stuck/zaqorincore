"""SSH brute-force detector.

Fires when a single source IP generates at least
`ZAQORIN_SSH_BRUTEFORCE_THRESHOLD` failed SSH-login events
(default 5) inside `ZAQORIN_SSH_BRUTEFORCE_WINDOW_SEC`
seconds (default 60).

State: a Redis sorted set per (host, source_ip), scored by
event timestamp, trimmed by ZREMRANGEBYSCORE on every event.
Key TTL is 5× the window so abandoned IPs disappear on their
own.

The detector is "best-effort" — if Redis is unavailable, the
event passes through silently. The runner logs the error and
moves on, so the stream never blocks on a Redis outage.

A regex on `raw` provides a fallback for events whose
`metadata` doesn't carry `status` or `source_ip` — handy
when the agent is pointed at a hand-crafted log file.
"""

from __future__ import annotations

import logging
import re
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


# Match "Failed password for <user> from <ip> port <port> ssh2"
# (also covers "Invalid user" lines from the same family).
# We allow optional leading "sshd[NNNN]:" and the user may be
# "invalid user X" — the regex is forgiving on purpose.
_SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def _extract_source_ip(event: ParsedEvent) -> str | None:
    """Pick the source IP out of metadata, falling back to raw."""
    ip = event.metadata.get("source_ip")
    if ip:
        return ip.strip()
    m = _SSH_FAILED_RE.search(event.raw)
    if m:
        return m.group("ip")
    return None


def _is_failed_login(event: ParsedEvent) -> bool:
    """Heuristic: this event represents a failed SSH login."""
    status = event.metadata.get("status", "").lower()
    if status in ("failed", "failure", "invalid"):
        return True
    # Fall back to the canonical auth.log line.
    return bool(_SSH_FAILED_RE.search(event.raw))


def _window_key(host_id: Any, ip: str) -> str:
    return f"zc:rule:ssh_bruteforce:{host_id}:{ip}"


class SSHBruteForceDetector:
    name = "ssh_bruteforce"

    async def on_event(
        self, event: ParsedEvent, ctx: DetectorContext
    ) -> list[DetectionResult]:
        settings: Settings = ctx.settings
        if not _is_failed_login(event):
            return []

        ip = _extract_source_ip(event)
        if not ip:
            return []

        threshold = settings.ssh_bruteforce_threshold
        window_sec = settings.ssh_bruteforce_window_sec
        cooldown_sec = max(settings.ssh_bruteforce_cooldown_sec, window_sec * 5)

        key = _window_key(event.host_id, ip)
        now_ts = int(event.occurred_at.timestamp())
        cutoff = now_ts - window_sec

        redis = ctx.redis
        try:
            pipe = redis.pipeline(transaction=False)
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zadd(key, {f"{event.event_id}": now_ts})
            pipe.zcard(key)
            pipe.expire(key, cooldown_sec)
            results = await pipe.execute()
            count: int = int(results[2])
        except Exception as exc:  # noqa: BLE001 — fail-open
            logger.warning(
                "ssh_bruteforce redis error, fail-open",
                extra={"host_id": str(event.host_id), "ip": ip, "err": str(exc)},
            )
            return []

        if count < threshold:
            return []

        # Hit threshold. Check the cooldown key before firing so a
        # 1000-event storm doesn't emit 200 alerts.
        cooldown_key = f"{key}:cooldown"
        try:
            fired = await redis.set(
                cooldown_key, "1", ex=cooldown_sec, nx=True
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ssh_bruteforce cooldown check failed, fail-open",
                extra={"err": str(exc)},
            )
            fired = True  # treat as "fire"

        if not fired:
            # We just alerted; throttle until cooldown expires.
            return []

        return [
            DetectionResult(
                detector=self.name,
                severity="medium",
                summary=(
                    f"SSH brute-force from {ip}: {count} failed logins "
                    f"in {window_sec}s"
                ),
                detail={
                    "source_ip": ip,
                    "window_sec": window_sec,
                    "threshold": threshold,
                    "observed_count": count,
                    "host_id": str(event.host_id),
                    "event_id": str(event.event_id),
                },
                cooldown_sec=cooldown_sec,
                dedup_key=ip,
                # Phase 4: enqueue an auto-block action. The
                # dispatcher only fires it for hosts that have
                # `auto_block=true` and an open WS connection.
                action=DetectionAction(
                    kind="block_ip",
                    target=ip,
                    # Default block TTL = 1h. Configurable via the
                    # response section on the agent's TOML.
                    ttl_sec=3600,
                ),
            )
        ]


DETECTOR = SSHBruteForceDetector()

__all__ = ["DETECTOR", "SSHBruteForceDetector"]
