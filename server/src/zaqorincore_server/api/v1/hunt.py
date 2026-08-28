"""Hunt query API (Phase 6, ADR-004).

Two endpoints:

POST /api/v1/hunt/run
  Body: { "rule": {... sigma yaml as dict ...}, "lookback_hours": 24 }
  Returns: { "fires": [...], "events_scanned": N }
  Replays historical events against a single rule and returns the
  matches without persisting anything.

GET /api/v1/hunt/rules
  Returns: { "rules": [{id, title, level, ...}] }
  Lists every Sigma rule the server loaded from `rules_dir`.

Hunt mode runs the rule engine in `hunt` mode — same matching,
no alerts, no actions. Pure read-only against the event table.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import Settings, get_settings
from ...db import get_session
from ...models.event import Event
from ...rule_engine.runner import SigmaRuleRunner
from ...rule_engine.sigma import (
    CompiledSigmaRule,
    load_rules_from_dir,
    parse_rule_file,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])


class HuntRunRequest(BaseModel):
    rule: dict[str, Any] = Field(..., description="A Sigma rule as a dict")
    lookback_hours: int = Field(24, ge=1, le=24 * 30)


class HuntFire(BaseModel):
    event_id: str
    host_id: str
    occurred_at: datetime
    source: str
    rule_id: str
    rule_title: str
    count: int
    dedup_key: str


class HuntRunResponse(BaseModel):
    fires: list[HuntFire]
    events_scanned: int
    rules_evaluated: int


class SigmaRuleSummary(BaseModel):
    id: str
    title: str
    level: str
    count: int
    timeframe_sec: int
    cooldown_sec: int
    has_action: bool
    source_path: str | None = None


class SigmaRulesResponse(BaseModel):
    rules: list[SigmaRuleSummary]


def _settings() -> Settings:
    return get_settings()


def _load_rules(rules_dir: str) -> list[CompiledSigmaRule]:
    return load_rules_from_dir(Path(rules_dir))


@router.get("/rules", response_model=SigmaRulesResponse)
async def list_rules() -> SigmaRulesResponse:
    """List all Sigma rules the server loaded from the rules dir."""
    settings = _settings()
    rules = _load_rules(settings.rules_dir)
    return SigmaRulesResponse(
        rules=[
            SigmaRuleSummary(
                id=r.id,
                title=r.title,
                level=r.level,
                count=r.count,
                timeframe_sec=r.timeframe_sec,
                cooldown_sec=r.cooldown_sec,
                has_action=r.action is not None,
            )
            for r in rules
        ]
    )


@router.post("/run", response_model=HuntRunResponse)
async def run_hunt(
    payload: HuntRunRequest,
    session: AsyncSession = Depends(get_session),
) -> HuntRunResponse:
    """Replay a single Sigma rule against the last `lookback_hours`
    of stored events. Read-only — no alerts or actions are created.
    """
    import tempfile
    import yaml
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        yaml.safe_dump(payload.rule, f)
        path = Path(f.name)
    try:
        rules = parse_rule_file(path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid rule: {exc}")
    if not rules:
        raise HTTPException(status_code=400, detail="rule did not compile")
    rule = rules[0]
    since = datetime.now(timezone.utc) - timedelta(hours=payload.lookback_hours)
    stmt = select(Event).where(Event.occurred_at >= since)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    fires: list[HuntFire] = []
    # Single-event rule: matches() does the work.
    from ...detectors.base import ParsedEvent
    for row in rows:
        meta = dict(row.metadata or {})
        meta.setdefault("source_ip", "")
        meta.setdefault("user", "")
        meta.setdefault("url", "")
        meta.setdefault("status", "")
        parsed = ParsedEvent(
            event_id=row.id,
            host_id=row.host_id,
            source=row.source,
            raw=row.raw or "",
            metadata=meta,
            occurred_at=row.occurred_at,
        )
        if not rule.matches(parsed):
            continue
        fires.append(
            HuntFire(
                event_id=str(row.id),
                host_id=str(row.host_id),
                occurred_at=row.occurred_at,
                source=row.source,
                rule_id=rule.id,
                rule_title=rule.title,
                count=1,
                dedup_key=rule.render_dedup_key(parsed) or rule.id,
            )
        )
    return HuntRunResponse(
        fires=fires,
        events_scanned=len(rows),
        rules_evaluated=1,
    )
