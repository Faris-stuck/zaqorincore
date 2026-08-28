"""SOAR worker (v1.3.0 / ADR-008).

A long-lived background task that:
  1. Polls the `alerts` table for new rows.
  2. For each enabled backend, applies the per-backend
     filter chain (severity, tags, cooldown).
  3. Calls the backend's `deliver(ctx, alert)`.
  4. Persists every attempt to `soar_deliveries`.
  5. On a transient failure, retries with exponential
     backoff (1s, 5s, 25s, 125s, 625s).
  6. After max_retries, writes a dead-letter file under
     `dead_letter_dir` (the API replay endpoint reads
     these files back).

Design notes:

  - We use a polling worker, not the SQLAlchemy
    `after_insert` event hook. Reason: the hook fires
    inside the *writing* transaction; if the target
    webhook is slow, we'd hold a DB row lock for the
    whole call. Polling with a 2s default keeps the
    critical path tight.

  - Concurrency: an `asyncio.Semaphore(10)` caps
    in-flight deliveries so a slow target can't tie up
    the whole event loop.

  - Backpressure: an `asyncio.Queue` with a bounded
    `maxsize` (default 1000) prevents the worker from
    accepting more alerts than it can drain. When the
    queue is full, the poller just sleeps one tick and
    retries — losing the poll is harmless because the
    next tick re-polls the DB.

  - Lifecycle: the worker is owned by the FastAPI
    lifespan (`zaqorincore_server.main`). It starts in
    `start()` (creates the asyncio.Task) and stops in
    `stop()` (sets the stop event + awaits the task).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..logging import get_logger
from ..models.alert import Alert as AlertRow
from ..models.soar_delivery import SoarDelivery
from . import (
    Alert,
    Backend,
    DeliverOutcome,
    DeliveryResult,
    get_backends,
    load_config,
    register,
    severity_meets,
)
from .backends.generic_webhook import GenericWebhook
from .config import BackendConfig, SoarConfig

log = get_logger("zaqorin.soar")

# Exponential backoff schedule (seconds) for 5xx / network
# retries. The first attempt is the original call; on
# failure, we sleep the n-th entry before retrying.
# max_retries=5 yields up to 6 total attempts (initial +
# 5 retries). Spec: 1s, 5s, 25s, 125s, 625s.
_BACKOFF_SCHEDULE = (1, 5, 25, 125, 625)

# Cooldown tracker key shape: (backend, host_id, detector).
# Stored in-memory only — on restart the worker just
# re-fires once. That's fine: dead-lettering only matters
# for *failures*; the alert is in the DB either way.
_CooldownKey = tuple[str, str, str]


@dataclass
class _PendingDelivery:
    """Internal queue item. One per (alert, backend) pair
    that the poller has decided to send."""

    alert: Alert
    backend_name: str
    backend: Backend
    config: BackendConfig
    attempt: int = 1
    next_eligible_at: float = 0.0  # epoch seconds


class SoarWorker:
    """Long-lived background task. Owns the dispatch loop,
    the dead-letter filesystem, and the in-memory cooldown
    tracker."""

    def __init__(
        self,
        settings: Settings,
        factory: async_sessionmaker[AsyncSession],
        config: SoarConfig | None = None,
    ) -> None:
        self._settings = settings
        self._factory = factory
        self._config = config or load_config()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._semaphore = asyncio.Semaphore(10)
        self._queue: asyncio.Queue[_PendingDelivery] = asyncio.Queue(
            maxsize=self._config.queue_max
        )
        # Cooldown tracker. Holds the epoch-second of the
        # last fire per (backend, host, detector).
        self._cooldowns: dict[_CooldownKey, float] = {}
        # Per-process set of alert_ids that have already
        # been enqueued. Stops the poller from doubling up
        # the queue when the DB poll fires more than once
        # before the queue drains.
        self._enqueued: set[str] = set()
        # Per-process set of (alert_id, backend) pairs that
        # have finished (success or dead-lettered). Keeps
        # us from re-firing on the next poll.
        self._finished: set[tuple[str, str]] = set()

        # Register the real backends. This replaces the
        # Slice 1 NotImplemented stubs.
        self._install_backends()

    @property
    def public_base_url(self) -> str:
        """Templates use this to build console links. The
        backend protocol hands `ctx` to each deliver() and
        the backend reads `ctx.public_base_url`."""
        return self._config.public_base_url

    @property
    def dead_letter_dir(self) -> str:
        return self._config.dead_letter_dir

    def _install_backends(self) -> None:
        """Replace the Slice-1 NotImplemented registry with
        the real v1.3.0 backends, one per config block.

        A backend that is not configured (no block in
        soar.toml) is left as the NotImplemented stub so
        the registry count stays at six and existing
        tests / dashboards still see all six names.
        """
        from .backends.discord import Discord
        from .backends.jira import Jira
        from .backends.pagerduty import PagerDuty
        from .backends.slack import Slack
        from .backends.thehive import TheHive

        # Backend class registry. Adding a 7th backend
        # means adding the import here and a class to
        # `backends/`. Nothing else.
        backend_classes: dict[str, type[Backend]] = {
            "generic_webhook": GenericWebhook,
            "slack": Slack,
            "discord": Discord,
            "pagerduty": PagerDuty,
            "thehive": TheHive,
            "jira": Jira,
        }
        configured_names = set(self._config.backends.keys())
        # If a backend is in the file but its class isn't
        # in our map, that's a packaging bug.
        missing_classes = configured_names - set(backend_classes.keys())
        if missing_classes:
            raise RuntimeError(
                "soar: configured backends without classes: "
                f"{sorted(missing_classes)}"
            )
        for name, cls in backend_classes.items():
            if name in self._config.backends:
                register(cls(self._config.backends[name]))
            # else: leave the NotImplemented stub registered

    # ─── Lifecycle ───────────────────────────────────────────────
    def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="zaqorin-soar")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        log.info(
            "soar: started",
            enabled=self._config.enabled,
            backends=sorted(self._config.backends.keys()),
        )
        try:
            while not self._stop.is_set():
                if self._config.enabled:
                    try:
                        await self._poll_once()
                    except Exception:  # noqa: BLE001
                        log.exception("soar poll failed")
                # Drain a few items off the queue even when
                # disabled, so a slow target doesn't leak
                # attempts indefinitely.
                await self._drain_queue_once()
                try:
                    await asyncio.wait_for(
                        self._stop.wait(),
                        timeout=self._config.poll_sec,
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            log.info("soar: stopped")

    # ─── Polling ─────────────────────────────────────────────────
    async def _poll_once(self) -> None:
        """Look for new alerts we haven't enqueued yet.

        Strategy: read the most recent N alerts from the
        table; for each, check the cooldown tracker and
        enqueue one (alert, backend) pair per enabled
        backend. We use a tight query (last 60s, limit
        200) so the cost per tick is bounded.
        """
        since = datetime.now(timezone.utc) - timedelta(seconds=60)
        async with self._factory() as session:
            stmt = (
                select(AlertRow)
                .where(AlertRow.created_at >= since)
                .order_by(AlertRow.created_at.desc())
                .limit(200)
            )
            rows = list((await session.execute(stmt)).scalars().all())

        for row in rows:
            await self._enqueue_row(row)

    async def _enqueue_row(self, row: AlertRow) -> None:
        """Map one alerts row to N (alert, backend) queue
        items — one per enabled backend whose filter
        chain accepts this alert.

        `row.detail` is a JSONB blob; tags and evidence
        live there. We parse defensively (older alerts
        may not have any).
        """
        alert_id = str(row.id)
        # Skip alerts we've already enqueued.
        if alert_id in self._enqueued:
            return
        detail = row.detail or {}
        if not isinstance(detail, dict):
            detail = {}
        tags = detail.get("tags") if isinstance(detail.get("tags"), list) else []
        tags = [str(t) for t in tags]
        evidence = detail.get("evidence") if isinstance(detail.get("evidence"), str) else None
        metadata = detail.get("metadata") if isinstance(detail.get("metadata"), dict) else {}
        metadata = {str(k): str(v) for k, v in metadata.items()}

        alert = Alert(
            id=alert_id,
            host_id=str(row.host_id) if row.host_id else "",
            detector=row.detector,
            severity=row.severity,
            tags=tags,
            summary=row.summary,
            evidence=evidence,
            metadata=metadata,
            created_at=row.created_at,
        )

        for backend in get_backends():
            name = backend.name
            cfg = self._config.backends.get(name)
            # Not configured in soar.toml — the registry
            # entry is the Slice-1 NotImplemented stub; we
            # skip it.
            if cfg is None or not cfg.enabled:
                continue
            # Severity filter.
            if not severity_meets(alert.severity, cfg.severity_min):
                continue
            # Tag filter: empty list means "no filter"
            # (fire for any tag set); non-empty means the
            # alert must have at least one matching tag.
            if cfg.tags_filter and not (
                set(cfg.tags_filter) & set(alert.tags or [])
            ):
                continue
            # Cooldown: skip if we fired this (backend,
            # host, detector) tuple within the last
            # cooldown_sec.
            cd_key: _CooldownKey = (name, alert.host_id, alert.detector)
            now = time.monotonic()
            last = self._cooldowns.get(cd_key, 0.0)
            if now - last < cfg.cooldown_sec:
                continue
            # Mark the alert as enqueued the first time
            # any backend fires it. The cooldown tracker
            # is updated when the delivery actually
            # *runs*, not when it is enqueued — that
            # way a queued-but-not-yet-fired delivery
            # doesn't block a re-fire.
            self._enqueued.add(alert_id)
            item = _PendingDelivery(
                alert=alert,
                backend_name=name,
                backend=backend,
                config=cfg,
                attempt=1,
                next_eligible_at=now,
            )
            try:
                self._queue.put_nowait(item)
            except asyncio.QueueFull:
                # Drop the oldest in favor of the new one
                # so the most recent alert gets delivered
                # first. This is a deliberate choice: a
                # fresh critical alert is more valuable
                # than a stale retry.
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    pass
                try:
                    self._queue.put_nowait(item)
                except asyncio.QueueFull:
                    pass

    # ─── Delivery loop ───────────────────────────────────────────
    async def _drain_queue_once(self) -> None:
        """Run a batch of pending deliveries. Bounded by
        the queue size and the semaphore so a slow target
        can't block the rest of the server."""
        for _ in range(min(16, self._queue.qsize())):
            if self._stop.is_set():
                return
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            asyncio.create_task(self._run_one(item))

    async def _run_one(self, item: _PendingDelivery) -> None:
        """Run one (alert, backend) with retries. The
        outer loop is the per-attempt delivery; the inner
        loop is the retry counter."""
        async with self._semaphore:
            attempt = item.attempt
            max_retries = item.config.max_retries
            last_outcome: DeliverOutcome | None = None
            while attempt <= max_retries + 1:
                # Honor the per-attempt backoff schedule
                # (skip on the first attempt).
                if attempt > 1 and self._stop.is_set():
                    return
                now = time.monotonic()
                if now < item.next_eligible_at:
                    sleep_for = item.next_eligible_at - now
                    if sleep_for > 0:
                        try:
                            await asyncio.wait_for(
                                self._stop.wait(), timeout=sleep_for
                            )
                            return
                        except asyncio.TimeoutError:
                            pass
                try:
                    outcome = await item.backend.deliver(self, item.alert)
                except Exception as e:  # noqa: BLE001
                    # The backend is supposed to catch its
                    # own errors and return an outcome. If
                    # it didn't, we still record something.
                    outcome = DeliverOutcome(
                        result=DeliveryResult(
                            backend=item.backend_name,
                            alert_id=item.alert.id,
                            status_code=0,
                            attempted_at=datetime.now(timezone.utc),
                            duration_ms=0,
                            error=f"backend exception: {type(e).__name__}: {e}",
                            dead_lettered=True,
                        ),
                        payload_sha256="",
                    )
                last_outcome = outcome
                # Persist this attempt.
                await self._persist_attempt(
                    item=item, outcome=outcome, attempt=attempt
                )
                # Decide whether to retry.
                result = outcome.result
                if result.dead_lettered:
                    # 4xx / config error. No retry.
                    self._maybe_dead_letter(item, outcome, attempt)
                    break
                if 200 <= result.status_code < 400:
                    # Success.
                    self._mark_cooldown(item)
                    break
                if attempt > max_retries:
                    # Out of retries.
                    self._maybe_dead_letter(item, outcome, attempt)
                    break
                # Otherwise: transient. Schedule the next
                # attempt with the exponential schedule.
                backoff = _BACKOFF_SCHEDULE[
                    min(attempt - 1, len(_BACKOFF_SCHEDULE) - 1)
                ]
                attempt += 1
                item.attempt = attempt
                item.next_eligible_at = time.monotonic() + backoff
                log.info(
                    "soar: retrying after backoff",
                    backend=item.backend_name,
                    alert_id=item.alert.id,
                    next_attempt=attempt,
                    sleep_sec=backoff,
                )
            # Mark the (alert, backend) pair as finished
            # so the poller doesn't keep re-enqueueing it.
            self._finished.add((item.alert.id, item.backend_name))
            self._queue.task_done()

    def _mark_cooldown(self, item: _PendingDelivery) -> None:
        """Update the per-(backend, host, detector)
        cooldown so the poller doesn't re-fire the same
        combo within `cooldown_sec`."""
        key: _CooldownKey = (
            item.backend_name,
            item.alert.host_id,
            item.alert.detector,
        )
        self._cooldowns[key] = time.monotonic()

    # ─── Persistence ─────────────────────────────────────────────
    async def _persist_attempt(
        self,
        *,
        item: _PendingDelivery,
        outcome: DeliverOutcome,
        attempt: int,
    ) -> None:
        """Insert one row into soar_deliveries."""
        result = outcome.result
        async with self._factory() as session:
            async with session.begin():
                row = SoarDelivery(
                    id=uuid.uuid4(),
                    alert_id=uuid.UUID(item.alert.id)
                    if _is_uuid(item.alert.id)
                    else None,
                    backend=item.backend_name,
                    status_code=result.status_code,
                    attempted_at=result.attempted_at,
                    duration_ms=result.duration_ms,
                    attempt=attempt,
                    error=result.error,
                    dead_lettered=result.dead_lettered,
                    payload_sha256=outcome.payload_sha256 or None,
                )
                session.add(row)

    def _maybe_dead_letter(
        self,
        item: _PendingDelivery,
        outcome: DeliverOutcome,
        attempt: int,
    ) -> None:
        """Write a dead-letter JSON if this delivery is
        truly given up on (4xx, or retries exhausted on
        5xx / network).

        The file is named `{ts}-{alert_id[:8]}.json` so a
        future replay picks it up deterministically.
        """
        if not _is_dead_letter_candidate(outcome.result, attempt, item.config):
            return
        # Ensure dir exists.
        base = Path(self._config.dead_letter_dir)
        if not base.is_absolute():
            # Resolved relative to the server package
            # root, NOT cwd, so a `cd /tmp` doesn't lose
            # the directory.
            base = (
                Path(__file__).resolve().parent.parent.parent.parent
                / self._config.dead_letter_dir
            )
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log.warning(
                "soar: could not create dead-letter dir",
                path=str(base),
                error=str(e),
            )
            return
        ts = outcome.result.attempted_at.strftime("%Y%m%dT%H%M%SZ")
        short = (
            item.alert.id.replace("-", "")[:8] or "alert"
        )
        path = base / f"{ts}-{short}.json"
        body: dict[str, Any] = {
            "ts": outcome.result.attempted_at.isoformat(),
            "backend": item.backend_name,
            "alert": {
                "id": item.alert.id,
                "host_id": item.alert.host_id,
                "detector": item.alert.detector,
                "severity": item.alert.severity,
                "tags": list(item.alert.tags or []),
                "summary": item.alert.summary,
                "evidence": item.alert.evidence,
                "metadata": dict(item.alert.metadata or {}),
            },
            "status_code": outcome.result.status_code,
            "error": outcome.result.error,
            "attempt": attempt,
            "payload_sha256": outcome.payload_sha256,
        }
        try:
            # Compute the file's own SHA-256 so a replay
            # can verify nothing on disk has been edited
            # since the worker wrote it.
            raw = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
            file_sha = hashlib.sha256(raw).hexdigest()
            body["file_sha256"] = file_sha
            raw = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
            # Write atomically: tmp + rename.
            tmp = path.with_suffix(path.suffix + ".tmp")
            with tmp.open("wb") as fh:
                fh.write(raw)
            os.replace(tmp, path)
        except OSError as e:
            log.warning(
                "soar: could not write dead-letter",
                path=str(path),
                error=str(e),
            )

    # ─── Read paths used by the API ───────────────────────────────
    def list_dead_letters(self) -> list[dict[str, Any]]:
        """Return a list of dead-letter files with their
        parsed bodies. Newest first."""
        base = self._resolve_dead_letter_dir()
        if not base.exists():
            return []
        out: list[dict[str, Any]] = []
        for p in sorted(base.glob("*.json"), reverse=True):
            try:
                with p.open("r", encoding="utf-8") as fh:
                    body = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            body["_file"] = p.name
            body["_path"] = str(p)
            out.append(body)
        return out

    def get_dead_letter(self, file_id: str) -> dict[str, Any] | None:
        """Return a single dead-letter by its file id
        (the part of the filename before the first
        `_`) or full filename."""
        base = self._resolve_dead_letter_dir()
        if not base.exists():
            return None
        # Accept either a full filename or a stem.
        candidates: Iterable[Path] = []
        if "/" in file_id or ".." in file_id:
            return None
        candidate_path = (base / file_id).resolve()
        if not str(candidate_path).startswith(str(base.resolve())):
            return None
        if candidate_path.exists() and candidate_path.is_file():
            candidates = [candidate_path]
        else:
            # Treat as a stem prefix.
            matches = list(base.glob(f"{file_id}*.json"))
            candidates = matches
        for p in candidates:
            try:
                with p.open("r", encoding="utf-8") as fh:
                    body = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            body["_file"] = p.name
            body["_path"] = str(p)
            return body
        return None

    def verify_dead_letter(self, body: dict[str, Any]) -> bool:
        """Recompute the file_sha256 over the body and
        compare. Returns True if the on-disk file
        matches the embedded hash."""
        expected = body.get("file_sha256")
        if not expected:
            return False
        # Re-serialize without file_sha256 and compare.
        clone = {k: v for k, v in body.items() if k != "file_sha256"}
        raw = json.dumps(clone, indent=2, sort_keys=True).encode("utf-8")
        actual = hashlib.sha256(raw).hexdigest()
        return actual == expected

    def _resolve_dead_letter_dir(self) -> Path:
        base = Path(self._config.dead_letter_dir)
        if not base.is_absolute():
            base = (
                Path(__file__).resolve().parent.parent.parent.parent
                / self._config.dead_letter_dir
            )
        return base


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (TypeError, ValueError):
        return False


def _is_dead_letter_candidate(
    result: DeliveryResult,
    attempt: int,
    config: BackendConfig,
) -> bool:
    """True if this delivery attempt is a "final" failure
    that we want to persist for replay."""
    if result.dead_lettered and 400 <= result.status_code < 500:
        return True
    if attempt > config.max_retries and result.status_code >= 500:
        return True
    if attempt > config.max_retries and result.status_code == 0:
        # Network errors with retries exhausted.
        return True
    return False


__all__ = ["SoarWorker"]
