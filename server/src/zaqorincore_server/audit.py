"""In-memory audit log (cycle 19, security/obs track).

A bounded ring-buffer of audit events. Each entry records
``who`` (the resolved role / X-API-Key hint), ``when``
(UTC timestamp), ``what`` (HTTP method + path), and any
extra metadata (status code, IP). New entries are added via
``record()`` and read via ``snapshot()``.

This is intentionally a phase-1 placeholder:
* No persistence yet — process restart clears the log.
* No write-side hook into every endpoint (yet). Callers
  that want their events captured call ``record()``
  explicitly.

A future cycle can promote this to a SQL-backed table +
auto-instrumented middleware; both are deferred to keep
the cycle 19 scope tight.

Why bounded: an unbounded in-memory list is a memory leak
waiting to happen on a long-running server. The cap is
configurable via ``AUDIT_MAX`` and defaults to 1024.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

# Default cap. Conservative so a leaked loop can't OOM the
# process overnight. Tests monkeypatch this via ``reset()``.
AUDIT_MAX: int = 1024

_lock = threading.Lock()
_log: "deque[dict[str, Any]]" = deque(maxlen=AUDIT_MAX)


def _utc_now() -> datetime:
    """UTC ``datetime`` with tzinfo. Returns a fresh object per
    call so snapshots stay stable across async boundaries."""
    return datetime.now(timezone.utc)


def record(
    *,
    actor: str,
    action: str,
    target: str,
    status: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one audit entry. Thread-safe.

    Required kwargs:
        actor: who performed the action (role name, key hint,
               or ``"anonymous"``).
        action: short verb (``"GET /api/v1/events"``,
                ``"create canary"``, etc.).
        target: the resource being acted on (path, id, ``"-"``).

    Optional:
        status: HTTP status code if known.
        extra: free-form dict merged into the entry.
    """
    item: dict[str, Any] = {
        "ts": _utc_now(),
        "actor": actor,
        "action": action,
        "target": target,
    }
    if status is not None:
        item["status"] = status
    if extra:
        item.update(extra)
    with _lock:
        _log.append(item)
    return item


def snapshot(limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent ``limit`` entries (newest first).

    The returned dicts are deep-copied so callers cannot mutate
    the live log. Timestamps are returned as ISO-8601 strings
    so the response is JSON-friendly out of the box.
    """
    if limit < 1:
        return []
    with _lock:
        # ``deque`` iteration is oldest-first; we want newest-first.
        items = list(_log)[-limit:][::-1]
    out: list[dict[str, Any]] = []
    for it in items:
        ts = it.get("ts")
        if isinstance(ts, datetime):
            it = {**it, "ts": ts.isoformat()}
        out.append(it)
    return out


def reset() -> None:
    """Clear the audit log. Used by tests and by
    ``server.startup`` lifecycle hooks if you wire one later.
    """
    with _lock:
        _log.clear()


__all__ = ["record", "snapshot", "reset", "AUDIT_MAX"]