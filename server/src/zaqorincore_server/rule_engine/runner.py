"""Sigma rule runner — sliding window, per-rule cooldown, hunt mode.

Phase 6 adds a runner that takes a list of CompiledSigmaRule
objects and applies them to events. It uses Redis for state:

  zaqorin:rule:<rule_id>:events:<dedup>      sorted set of event times
  zaqorin:rule:<rule_id>:cooldown:<dedup>   cooldown key (NX/SET)

Rules fire when:
  (1) the rule's `matches(event)` returns True, AND
  (2) the count of matching events in the last `timeframe_sec`
      is >= rule.count, AND
  (3) the (rule_id, dedup_key) is not in cooldown.

When a rule fires, the runner:
  - inserts a row in alerts (or runs as "hunt" — see below)
  - inserts a row in actions (if the rule defines an action block)
  - sets the cooldown key with TTL = cooldown_sec.

Hunt mode: if the runner is created with `mode="hunt"`, firing
rules write to a `hunt_results` table instead of `alerts`, and
do not create actions. This is the on-demand replay against
historical events.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from ..detectors.base import ParsedEvent
from ..models.alert import Alert
from ..models.action import Action
from .sigma import CompiledSigmaRule

log = logging.getLogger(__name__)


@dataclass
class RuleFire:
    """Result of a rule firing on an event."""
    rule: CompiledSigmaRule
    event: ParsedEvent
    dedup_key: str
    count: int
    rendered_action: dict | None


class SigmaRuleRunner:
    """Per-rule sliding window runner with cooldown and Redis state.

    Constructor takes a Redis client (sync or async — the runner
    uses an `await client.zadd` style API). For the production
    server we use `redis.asyncio.Redis`; for unit tests we use
    `fakeredis.aioredis.FakeRedis`.
    """

    def __init__(
        self,
        redis_client,
        rules: list[CompiledSigmaRule],
        *,
        mode: str = "live",
        clock: Callable[[], float] = time.time,
    ) -> None:
        if mode not in ("live", "hunt"):
            raise ValueError(f"mode must be live or hunt, got {mode!r}")
        self._redis = redis_client
        self._rules = list(rules)
        self._mode = mode
        self._clock = clock

    @property
    def mode(self) -> str:
        return self._mode

    def rules(self) -> list[CompiledSigmaRule]:
        return list(self._rules)

    def add_rule(self, rule: CompiledSigmaRule) -> None:
        self._rules.append(rule)

    def _events_key(self, rule_id: str, dedup: str) -> str:
        return f"zaqorin:rule:{rule_id}:events:{dedup}"

    def _cooldown_key(self, rule_id: str, dedup: str) -> str:
        return f"zaqorin:rule:{rule_id}:cooldown:{dedup}"

    async def _count_in_window(
        self, rule: CompiledSigmaRule, dedup: str, event_time: float,
    ) -> int:
        key = self._events_key(rule.id, dedup)
        window_start = event_time - rule.timeframe_sec
        # Drop events outside the window first.
        await self._redis.zremrangebyscore(key, 0, window_start)
        # Count what remains.
        return int(await self._redis.zcard(key))

    async def _record_event(
        self, rule: CompiledSigmaRule, dedup: str, event_time: float, event_id: str,
    ) -> None:
        key = self._events_key(rule.id, dedup)
        await self._redis.zadd(key, {event_id: event_time})
        # Keep the key bounded to ~ 10x the typical burst.
        await self._redis.expire(key, max(rule.timeframe_sec * 10, 60))

    async def _is_in_cooldown(self, rule: CompiledSigmaRule, dedup: str) -> bool:
        return bool(await self._redis.exists(self._cooldown_key(rule.id, dedup)))

    async def _set_cooldown(self, rule: CompiledSigmaRule, dedup: str) -> None:
        await self._redis.set(
            self._cooldown_key(rule.id, dedup),
            "1",
            ex=rule.cooldown_sec,
        )

    async def evaluate(self, event: ParsedEvent) -> list[RuleFire]:
        """Run all rules against one event. Returns the list of
        rules that fired (empty if none).
        """
        fires: list[RuleFire] = []
        event_time = self._clock()
        for rule in self._rules:
            if not rule.matches(event):
                continue
            dedup = rule.render_dedup_key(event) or rule.id
            if await self._is_in_cooldown(rule, dedup):
                continue
            count = await self._count_in_window(rule, dedup, event_time) + 1
            await self._record_event(rule, dedup, event_time, str(event.event_id))
            if count < rule.count:
                # Not enough events yet — keep counting.
                continue
            await self._set_cooldown(rule, dedup)
            fires.append(
                RuleFire(
                    rule=rule,
                    event=event,
                    dedup_key=dedup,
                    count=count,
                    rendered_action=rule.render_action(event),
                )
            )
        return fires


async def persist_fire(
    session: AsyncSession,
    fire: RuleFire,
    *,
    mode: str = "live",
) -> None:
    """Persist a RuleFire to the DB. In `live` mode we create an
    Alert and (if the rule defines an action) an Action row. In
    `hunt` mode we do nothing here — the hunt_results writer
    is a separate concern.
    """
    if mode == "hunt":
        return
    alert = Alert(
        id=uuid.uuid4(),
        host_id=fire.event.host_id,
        detector=fire.rule.id,
        summary=fire.rule.title,
        severity=fire.rule.level,
        detail={
            "rule_title": fire.rule.title,
            "rule_level": fire.rule.level,
            "count": fire.count,
            "dedup_key": fire.dedup_key,
            "event_id": str(fire.event.event_id),
        },
    )
    session.add(alert)
    if fire.rendered_action:
        action = Action(
            id=uuid.uuid4(),
            host_id=fire.event.host_id,
            alert_id=alert.id,
            kind=fire.rendered_action["kind"],
            target=fire.rendered_action["target"],
            ttl_sec=fire.rendered_action.get("ttl_sec"),
            status="pending",
        )
        session.add(action)
    await session.flush()


__all__ = ["SigmaRuleRunner", "RuleFire", "persist_fire"]
