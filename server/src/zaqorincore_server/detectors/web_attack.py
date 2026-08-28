"""Web attack detector (Phase 5).

Catches SQLi, XSS, path-traversal, and scanner patterns in HTTP
request lines. Pure regex; no LLM, no scoring. If the regex
matches, it's a hit. False positives are tolerated at the
threshold level (the operator can tune).

Tunables (env vars):
- ZAQORIN_WEB_ATTACK_COOLDOWN_SEC (default 300 = 5 min)
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


# Each pattern is a clear, deterministic signature. None of them
# would fire on a legitimate request line.
_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("sqli", "SQL injection signature", re.compile(r"(?i)(union\s+select|'\s*or\s+'?\d|or\s+1=1|--\s*$|;drop\s+table)")),
    ("xss", "XSS payload", re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)")),
    ("path_traversal", "path traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e/|%252e%252e/)")),
    ("scanner", "scanner fingerprint", re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|wpscan|acunetix)")),
]


def _is_http_event(event: ParsedEvent) -> bool:
    src = event.metadata.get("source", "").lower()
    if "nginx" in src or "apache" in src or "http" in src or "access" in src:
        return True
    raw_lower = event.raw.lower()
    return any(raw_lower.startswith(p) for p in ("get ", "post ", "put ", "delete ", "head "))


def _extract_source_ip(event: ParsedEvent) -> str | None:
    return event.metadata.get("source_ip")


def _match_patterns(event: ParsedEvent) -> list[str]:
    raw = event.raw
    out: list[str] = []
    for tag, _desc, pat in _PATTERNS:
        if pat.search(raw):
            out.append(tag)
    return out


def _cooldown_key(host_id: Any, ip: str, tag: str) -> str:
    return f"zc:rule:web_attack:{host_id}:{ip}:{tag}"


class WebAttackDetector:
    name = "web_attack"

    async def on_event(
        self, event: ParsedEvent, ctx: DetectorContext
    ) -> list[DetectionResult]:
        settings: Settings = ctx.settings
        if not _is_http_event(event):
            return []
        matches = _match_patterns(event)
        if not matches:
            return []
        ip = _extract_source_ip(event)
        if not ip:
            return []
        cooldown_sec = getattr(settings, "web_attack_cooldown_sec", 300)
        # Cooldown per (host, ip, tag) to suppress repeated alerts.
        for tag in matches:
            try:
                key = _cooldown_key(event.host_id, ip, tag)
                # SET NX EX — returns True if we set it (no cooldown active).
                acquired = await ctx.redis.set(key, "1", nx=True, ex=cooldown_sec)
            except Exception as e:  # noqa: BLE001
                logger.warning("web_attack: redis error, fail-open: %s", e)
                acquired = True
            if not acquired:
                continue
            return [
                DetectionResult(
                    detector=self.name,
                    severity="high" if tag in ("sqli", "scanner") else "medium",
                    summary=f"web attack ({tag}) from {ip}",
                    detail={
                        "source_ip": ip,
                        "match_tags": matches,
                        "raw_excerpt": event.raw[:500],
                    },
                    dedup_key=f"{ip}:{tag}",
                    cooldown_sec=cooldown_sec,
                    action=DetectionAction(
                        kind="block_ip",
                        target=ip,
                        ttl_sec=3600,
                    ),
                )
            ]
        return []


DETECTOR: Detector = WebAttackDetector()
