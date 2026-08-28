"""Per-host WebSocket connection registry + dispatcher.

The WS handler calls `register(host_id, ws)` on connect and
`unregister(host_id, ws)` on disconnect. The dispatcher pulls
pending `Action` rows from the DB, looks up the host's open
WebSocket, signs the command, and writes the frame.

If the host is offline (no entry in the registry), the
dispatcher leaves the row in 'pending' state and re-tries on
the next tick. We do NOT use a Redis Streams queue for
pending commands because the DB is already the durable
source of truth.

A small in-memory loop in `Dispatcher.run()` polls every
`ZAQORIN_DISPATCHER_POLL_SEC` seconds (default 5s).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import Settings
from .crypto import sign_command
from .logging import get_logger
from .models.action import Action
from .models.host import Host
from .detectors import action_service
from .action_kinds import is_valid_kind, get_kind, validate_target
from .deployment import get_profile, validate_mode_action


log = get_logger(__name__)


class HostConnectionRegistry:
    """In-memory map of host_id -> active WebSocket.

    Not multi-process safe; if you scale the server beyond
    one uvicorn worker, swap this for a Redis pub/sub
    channel (Phase 5+).
    """

    def __init__(self) -> None:
        self._conns: dict[uuid.UUID, "WebSocket"] = {}  # type: ignore[name-defined]
        self._lock = asyncio.Lock()

    async def register(self, host_id: uuid.UUID, ws) -> None:  # type: ignore[no-untyped-def]
        async with self._lock:
            self._conns[host_id] = ws
        log.info("dispatcher host registered", host_id=str(host_id))

    async def unregister(self, host_id: uuid.UUID) -> None:
        async with self._lock:
            self._conns.pop(host_id, None)
        log.info("dispatcher host unregistered", host_id=str(host_id))

    def get(self, host_id: uuid.UUID):
        return self._conns.get(host_id)


# Module-level singleton, owned by the FastAPI lifespan.
module_registry = HostConnectionRegistry()

# Backward-compat alias: existing imports `from .dispatcher import registry`.
registry = module_registry


async def _build_command_frame(
    settings: Settings,
    action: Action,
    host: Host,
) -> dict | None:
    """Sign and return the COMMAND frame as a dict, or None if
    the host has no secret yet (something's wrong — HELLO must
    have generated one)."""
    if not host.secret:
        log.error(
            "dispatcher: host has no secret, cannot sign",
            host_id=str(host.id),
        )
        return None
    # Phase 5: validate action kind before signing. Unknown kinds
    # are dropped with a clear error (and an audit log row lands in
    # the action_service for the operator to see).
    if not is_valid_kind(action.kind):
        log.error(
            "dispatcher: unknown action kind, refusing to sign",
            kind=action.kind,
            action_id=str(action.id),
        )
        return None
    # Phase 5: validate the target against the kind's expected shape.
    # Malformed targets are dropped here rather than sent to the agent.
    try:
        validate_target(action.kind, action.target)
    except ValueError as e:
        log.error(
            "dispatcher: malformed target for kind, refusing to sign",
            kind=action.kind,
            target=action.target,
            error=str(e),
            action_id=str(action.id),
        )
        return None
    # Phase 5: enforce the deployment mode's allowed kinds. An action
    # row created in startup mode cannot suddenly fire a kind that is
    # only enabled in enterprise mode.
    try:
        validate_mode_action(settings.deployment_mode, action.kind)
    except ValueError:
        log.error(
            "dispatcher: action kind not enabled in current deployment mode",
            kind=action.kind,
            mode=settings.deployment_mode,
            action_id=str(action.id),
        )
        return None
    # Phase 5: enforce the per-kind opt-in flag. block_ip, tarpit_ip,
    # kill_process, isolate_host, etc. all require the host to have
    # explicitly opted in. The action is dropped (not auto-fired) if
    # the host has not opted in.
    kind = get_kind(action.kind)
    if kind.requires_host_opt_in and not host.auto_block:
        log.warning(
            "dispatcher: kind requires host opt-in, but host.auto_block is false",
            kind=action.kind,
            host_id=str(host.id),
        )
        return None
    issued_at = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    hmac_hex = sign_command(
        secret=host.secret,
        command_id=str(action.id),
        kind=action.kind,
        target=action.target,
        ttl_sec=action.ttl_sec or 0,
        issued_at=issued_at,
    )
    return {
        "type": "command",
        "id": str(action.id),
        "kind": action.kind,
        "target": action.target,
        "ttl_sec": action.ttl_sec,
        "issued_at": issued_at,
        "hmac": hmac_hex,
    }


class Dispatcher:
    """Background task: pulls pending actions, signs them, ships
    them over the registered WebSocket."""

    def __init__(
        self,
        settings: Settings,
        factory: async_sessionmaker[AsyncSession],
        registry: HostConnectionRegistry | None = None,
    ) -> None:
        self._settings = settings
        self._factory = factory
        self._registry = registry or module_registry
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="zaqorin-dispatcher")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        log.info("dispatcher: started", poll_sec=self._settings.dispatcher_poll_sec)
        try:
            while not self._stop.is_set():
                try:
                    await self._tick()
                except Exception:  # noqa: BLE001
                    log.exception("dispatcher tick failed")
                try:
                    await asyncio.wait_for(
                        self._stop.wait(), timeout=self._settings.dispatcher_poll_sec
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            log.info("dispatcher: stopped")

    async def _tick(self) -> None:
        async with self._factory() as session:
            stmt = (
                select(Action, Host)
                .join(Host, Host.id == Action.host_id, isouter=True)
                .where(Action.status == "pending")
                .order_by(Action.created_at.asc())
                .limit(16)
            )
            rows = (await session.execute(stmt)).all()

        for action, host in rows:
            if host is None or not host.auto_block:
                # Either the host was deleted or has auto_block off.
                # We leave the row pending until an operator decides.
                # The dashboard (Phase 5) shows it as "skipped".
                continue
            ws = self._registry.get(host.id)
            if ws is None:
                # Host offline; will retry next tick.
                continue
            frame = await _build_command_frame(self._settings, action, host)
            if frame is None:
                # Host has no secret — log once and skip.
                continue
            try:
                await ws.send_text(json.dumps(frame))
            except Exception:  # noqa: BLE001
                # Connection probably died between our registry check
                # and the send. Unregister and let the next tick retry.
                log.warning(
                    "dispatcher: send failed, unregistering",
                    host_id=str(host.id),
                )
                await self._registry.unregister(host.id)
                continue
            await action_service.mark_dispatched(self._factory, action.id)
            log.info(
                "dispatcher: command dispatched",
                action_id=str(action.id),
                host_id=str(host.id),
                kind=action.kind,
                target=action.target,
            )
