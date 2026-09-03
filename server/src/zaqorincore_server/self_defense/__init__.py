"""Self-defense detection pack (ZaqorinCore v3.3.0).

Maps to findings F-001 / F-006 / F-008 / F-009 / F-013 / F-016 from
AUDIT-2026-09-03. After the patches closed the immediate
vulnerabilities, these rules detect ATTEMPT to exploit them so
operators get visibility into who is probing.

Public surface:

* ``SELF_DEFENSE_RULES`` — frozen list of :class:`CompiledSigmaRule`
  loaded from ``server/rules/builtin/self_defense/*.yml``.
* ``RULE_TITLES`` — list of human-readable titles (for status pages).
* ``emit(event)`` — append a :class:`ZaqorinEvent` to the runner's
  in-process stream so the Sigma engine can correlate. The runner
  is responsible for actually firing rules; ``emit`` only buffers.
* ``drain(max_items)`` — snapshot the current stream (bounded slice
  of the most recent events).
* ``with_stream_lock()`` — context manager yielding while holding
  ``_STREAM_LOCK``. Use for atomic read-modify-write of the stream,
  e.g. snapshot + clear in a single critical section.

The pack is intentionally focused (17 rules as of v3.4.17) and is
expected to grow over time as new attack patterns are observed.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from ..rule_engine.sigma import (
    CompiledSigmaRule,
    load_rules_from_dir,
)
from .event_normalizer import ZaqorinEvent

logger = logging.getLogger(__name__)

# Resolve the rule directory relative to this file so the pack works
# whether the server is run from the repo root or from a packaged
# wheel install.
_RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "builtin" / "self_defense"


def load_rules() -> list[CompiledSigmaRule]:
    """Load every self-defense Sigma rule from the builtin dir.

    A bad rule is logged and skipped — one typo must not take down
    the whole engine. Returns a fresh list on every call; callers
    that want the cached singleton should use ``SELF_DEFENSE_RULES``.
    """
    if not _RULES_DIR.exists():
        logger.warning("self_defense rules directory missing: %s", _RULES_DIR)
        return []
    return load_rules_from_dir(_RULES_DIR)


SELF_DEFENSE_RULES: tuple[CompiledSigmaRule, ...] = tuple(load_rules())
RULE_TITLES: tuple[str, ...] = tuple(r.title for r in SELF_DEFENSE_RULES)


# In-process event stream. Bounded so a chatty emitter cannot OOM
# the process; the runner drains it on every rule-fire tick. When
# the buffer fills the oldest events are discarded — losing events
# is preferable to refusing to accept new ones (a fail-open posture
# for *emission* only, not for *detection*).
#
# F-018 fix (v3.4.4): protect the deque with a ``threading.Lock``.
# ``asyncio.Lock`` would require creation inside a running event
# loop (it stores a ``Future``), so it cannot be built at module
# load. ``threading.Lock`` is plain C-level mutex — safe to create
# eagerly, works across asyncio loops (e.g. under
# ``asyncio.to_thread``), and survives a future move to
# free-threaded CPython 3.13+. The lock is held only for
# microseconds (a single ``append`` or list copy) so contention
# on the hot path is negligible.
#
# This is an in-process lock only — it does NOT share state
# across uvicorn workers. Multi-worker deployments still have N
# independent streams. See ``MULTI_WORKER.md`` for the
# Redis-stream future work that closes that gap.
_STREAM: deque[ZaqorinEvent] = deque(maxlen=4096)
_STREAM_LOCK = threading.Lock()


def emit(event: ZaqorinEvent) -> None:
    """Append a normalized event to the in-process stream.

    The runner (registered against ``rule_engine.runner``) drains
    this stream on every detection tick. Returns immediately; this
    is on the hot path of WS/HTTP middleware.

    Thread-safe (F-018): holds ``_STREAM_LOCK`` for the duration
    of the append.
    """
    with _STREAM_LOCK:
        _STREAM.append(event)


@contextmanager
def with_stream_lock() -> Iterator[None]:
    """Yield while holding ``_STREAM_LOCK``.

    Exposed so callers that need an **atomic read-modify-write**
    over the stream can do the whole thing in one critical
    section — preventing a concurrent ``emit()`` from interleaving
    between the read and the write.

    Typical usage — snapshot + clear under one lock::

        with with_stream_lock():
            pending = list(_STREAM)
            _STREAM.clear()
        # process `pending` outside the lock

    The lock is the same ``_STREAM_LOCK`` instance used by
    :func:`emit` and :func:`drain`. Holding this context manager
    blocks new emits and concurrent drains for its duration; keep
    the critical section short (the underlying deque ops are
    microseconds).
    """
    with _STREAM_LOCK:
        yield


def drain(max_items: int = 256) -> Iterable[ZaqorinEvent]:
    """Snapshot the current stream. The runner calls this; we keep
    the snapshot semantics simple (list copy) so the runner can
    safely iterate while new events arrive.

    Thread-safe (F-018): the snapshot copy is taken inside the
    lock so a concurrent ``emit`` cannot shift the deque mid-slice
    and produce a partial or inconsistent view.
    """
    with with_stream_lock():
        # Snapshot copy inside the lock — a concurrent append
        # between ``list()`` and the slice would otherwise shift
        # the deque and could truncate or duplicate entries at
        # the boundary under free-threaded CPython.
        return list(_STREAM)[-max_items:]


__all__ = [
    "SELF_DEFENSE_RULES",
    "RULE_TITLES",
    "ZaqorinEvent",
    "emit",
    "drain",
    "with_stream_lock",
    "load_rules",
]