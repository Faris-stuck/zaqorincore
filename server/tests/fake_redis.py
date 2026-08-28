"""Tiny in-memory Redis stand-in for the rule runner tests.

Supports the small surface SigmaRuleRunner uses:
  - zadd(key, mapping)
  - zremrangebyscore(key, min, max)
  - zcard(key)
  - expire(key, sec)
  - exists(key)
  - set(key, value, ex=sec)

This is NOT a real Redis. It is enough to exercise the rule
runner in unit tests without pulling fakeredis.
"""

from __future__ import annotations

import time
from typing import Any


class _ExpiringKey:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: Any, expires_at: float | None) -> None:
        self.value = value
        self.expires_at = expires_at


class FakeRedis:
    def __init__(self) -> None:
        # string keys: dict[key, _ExpiringKey]
        self._strings: dict[str, _ExpiringKey] = {}
        # sorted sets: dict[key, dict[member, score]]
        self._zsets: dict[str, dict[str, float]] = {}

    def _now(self) -> float:
        return time.time()

    def _purge(self, key: str) -> None:
        """Drop a key from _strings if it expired."""
        entry = self._strings.get(key)
        if entry is not None and entry.expires_at is not None and entry.expires_at <= self._now():
            del self._strings[key]

    # Sorted-set ops -------------------------------------------------

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        zset = self._zsets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if member not in zset:
                added += 1
            zset[member] = score
        return added

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int:
        zset = self._zsets.get(key, {})
        removed = 0
        for member in list(zset.keys()):
            if min_score <= zset[member] <= max_score:
                del zset[member]
                removed += 1
        return removed

    async def zcard(self, key: str) -> int:
        return len(self._zsets.get(key, {}))

    async def expire(self, key: str, sec: int) -> bool:  # noqa: ARG002
        # We don't expire zsets — the runner's tests are short
        # enough that the bounded growth is fine.
        return True

    # String ops ------------------------------------------------------

    async def exists(self, key: str) -> int:
        self._purge(key)
        return 1 if key in self._strings else 0

    async def set(self, key: str, value: Any, ex: int | None = None) -> bool:  # noqa: A002
        expires_at = self._now() + ex if ex else None
        self._strings[key] = _ExpiringKey(value, expires_at)
        return True

    # Inspection helpers (not part of real Redis) --------------------

    def _all_string_keys(self) -> list[str]:
        return list(self._strings.keys())
