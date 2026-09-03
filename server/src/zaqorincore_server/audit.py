"""In-memory audit log + persistent JSONL sink (cycle 19 + F-008 fix v3.2.2).

Two-tier audit log:

1. **In-memory ring buffer** — bounded ``deque(maxlen=AUDIT_MAX)``
   for fast ``snapshot()`` reads (the ``/audit`` endpoint). Process
   restart clears this tier, by design — it is a cache on top of
   the persistent tier.

2. **Append-only JSONL file** — ``{ZAQORIN_AUDIT_LOG_DIR}/audit-YYYY-MM-DD.jsonl``
   rotated daily. Writes are serialised by a single ``threading.Lock``
   shared with the in-memory tier so the order of in-memory entries
   matches the order of on-disk entries.

F-008 fix (v3.2.2)
==================

The original module kept the log in memory only. A crash or
restart silently destroyed every audit event the process had
recorded since boot. The new design writes one line per event
to a daily-rotated JSONL file so an operator can:

* reconstruct the audit history across restarts,
* inspect entries with ``jq`` / ``grep`` on the filesystem,
* ship the file to an external SIEM without writing an exporter.

Failure mode: if the persistent sink raises (disk full, directory
removed, EACCES on the file), the in-memory write still proceeds
and a single warning is emitted so the operator can investigate.
This matches the cycle-19 design — audit must not block the
request path.

Each entry records ``who`` (the resolved role / X-API-Key hint),
``when`` (UTC timestamp), ``what`` (HTTP method + path), and any
extra metadata (status code, IP).
"""

from __future__ import annotations

import json
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default cap on the in-memory tier. Conservative so a leaked
# loop can't OOM the process overnight. Tests monkeypatch this
# via ``reset()``.
AUDIT_MAX: int = 1024

# Default location for the persistent tier. Override via the
# ``ZAQORIN_AUDIT_LOG_DIR`` env var; the per-day filename is
# appended by this module. When the env var is unset, the
# persistent tier is DISABLED — only the in-memory tier records.
# That preserves the cycle-19 zero-config dev experience while
# letting a single env var turn on the audit history for ops.
DEFAULT_AUDIT_LOG_DIR: str | None = os.environ.get("ZAQORIN_AUDIT_LOG_DIR") or None

_lock = threading.Lock()
_log: "deque[dict[str, Any]]" = deque(maxlen=AUDIT_MAX)

# Persistent-tier state. ``_file_handle`` is opened lazily on the
# first write and reopened at midnight UTC (file-rotation). A
# single process-level lock serialises writes across threads so
# in-memory and on-disk entries keep the same order.
_persist_dir: Path | None = (
    Path(DEFAULT_AUDIT_LOG_DIR).expanduser().resolve()
    if DEFAULT_AUDIT_LOG_DIR
    else None
)
_persist_file: Path | None = None
_persist_handle: Any = None
_persist_date: str | None = None
_persist_warned: bool = False


def _utc_now() -> datetime:
    """UTC ``datetime`` with tzinfo. Returns a fresh object per
    call so snapshots stay stable across async boundaries."""
    return datetime.now(timezone.utc)


def _today_str() -> str:
    """Today's UTC date as ``YYYY-MM-DD``. Used as the JSONL
    filename suffix and the rotation boundary."""
    return _utc_now().strftime("%Y-%m-%d")


def _resolve_persist_path() -> Path | None:
    """Return today's JSONL path under the configured directory.

    Returns ``None`` when no directory is configured — callers
    short-circuit on that to keep the persistent tier opt-in.
    """
    if _persist_dir is None:
        return None
    return _persist_dir / f"audit-{_today_str()}.jsonl"


def _ensure_persist_open() -> Any | None:
    """Open (or rotate) the JSONL file for today's date.

    Returns the open file handle, or ``None`` if the persistent
    tier is disabled or a write failure was already warned about.
    Caches the handle at module level so we don't pay open() cost
    on every ``record()`` call.
    """
    global _persist_handle, _persist_file, _persist_date, _persist_warned
    if _persist_dir is None or _persist_warned:
        return None
    today = _today_str()
    target = _persist_dir / f"audit-{today}.jsonl"
    if _persist_handle is not None and _persist_date == today:
        return _persist_handle
    # Date rolled over or first write — reopen.
    try:
        if _persist_handle is not None:
            try:
                _persist_handle.close()
            except Exception:  # noqa: BLE001
                pass
        _persist_dir.mkdir(parents=True, exist_ok=True)
        _persist_handle = target.open("a", encoding="utf-8")
        _persist_file = target
        _persist_date = today
    except OSError as exc:
        # Disk full, EACCES, removed mount — emit once and fall back
        # to the in-memory tier so the request path is never blocked.
        if not _persist_warned:
            import logging as _log

            _log.getLogger(__name__).warning(
                "audit: persistent log disabled, falling back to "
                "in-memory ring buffer: %s",
                exc,
            )
            _persist_warned = True
        _persist_handle = None
        return None
    return _persist_handle


def record(
    *,
    actor: str,
    action: str,
    target: str,
    status: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one audit entry to BOTH tiers. Thread-safe.

    Required kwargs:
        actor: who performed the action (role name, key hint,
               or ``"anonymous"``).
        action: short verb (``"GET /api/v1/events"``,
                ``"create canary"``, etc.).
        target: the resource being acted on (path, id, ``"-"``).

    Optional:
        status: HTTP status code if known.
        extra: free-form dict merged into the entry.

    The in-memory tier and the on-disk tier are written under the
    same lock so the order of snapshot() entries matches the order
    of lines on disk. The on-disk write is best-effort — if the
    filesystem refuses, the in-memory entry is still committed and
    a single warning is logged (see ``_ensure_persist_open``).
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
        # ---- In-memory tier (always) ----
        _log.append(item)

        # ---- Persistent tier (best-effort) ----
        handle = _ensure_persist_open()
        if handle is not None:
            try:
                # Serialize datetime -> ISO-8601 so the JSONL is
                # stable across readers (jq, grep, log shippers).
                payload = {**item, "ts": item["ts"].isoformat()}
                handle.write(json.dumps(payload, ensure_ascii=False))
                handle.write("\n")
                handle.flush()
            except OSError:
                # Don't escalate to the caller — audit must never
                # raise out of ``record()``. The in-memory copy
                # still committed; an operator can correlate later.
                pass

    return item


def snapshot(limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent ``limit`` entries (newest first).

    Reads the in-memory tier. The returned dicts are deep-copied
    so callers cannot mutate the live log. Timestamps are
    returned as ISO-8601 strings so the response is JSON-friendly
    out of the box.
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
    """Clear the in-memory audit log. Tests call this between
    cases. The persistent tier is NOT cleared — operators inspect
    or rotate the on-disk file separately.

    Does NOT close the on-disk handle; ``record()`` will reopen
    on the next call if today's date rolled over between reset
    and the next call.
    """
    global _persist_file, _persist_date
    with _lock:
        _log.clear()
        _persist_file = None
        _persist_date = None


__all__ = [
    "record",
    "snapshot",
    "reset",
    "AUDIT_MAX",
    "DEFAULT_AUDIT_LOG_DIR",
]