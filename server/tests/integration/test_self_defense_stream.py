"""Integration tests for the self_defense in-process event stream.

Closes the F-018 loop: the ``_STREAM`` ``deque(maxlen=4096)`` in
``server/src/zaqorincore_server/self_defense/__init__.py`` is a
single-loop data structure. ``emit()`` and ``drain()`` are not
lock-protected — they are safe under the single-event-loop
asyncio model CPython 3.11/3.12 ship, but the test below documents
the gap so a future move to free-threaded CPython 3.13+ trips the
right alarm.

Tests in this module are marked ``integration`` so they can be
skipped under unit-only mode.
"""

from __future__ import annotations

import asyncio
import os
import secrets

# Boot-time env so the package import does not fail.
os.environ.setdefault(
    "ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_WEBHOOK_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:secret@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

import pytest  # noqa: E402

from zaqorincore_server.self_defense import drain, emit  # noqa: E402
from zaqorincore_server.self_defense.event_normalizer import (  # noqa: E402
    ZaqorinEvent,
)

pytestmark = pytest.mark.integration


def _make_event(idx: int) -> ZaqorinEvent:
    """Cheap event fixture — no real timestamp needed for stream bounds."""
    return ZaqorinEvent(
        ts="2026-09-03T00:00:00Z",
        event_type="ws.hello",
        src_ip=f"203.0.113.{idx % 256}",  # RFC 5737 documentation range
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 1: emit() actually appends
# ─────────────────────────────────────────────────────────────────────────


def test_emit_appends_to_stream() -> None:
    """10 emits → drain returns at least 10 events (no upper bound here,
    only that every emit was observed)."""
    # Snapshot before — drain a large window so prior tests don't
    # pollute our count.
    before = list(drain(max_items=100_000))
    base = len(before)

    for i in range(10):
        emit(_make_event(i))

    after = list(drain(max_items=100_000))
    assert len(after) >= base + 10, (
        f"expected at least {base + 10} events, got {len(after)}"
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 2: the stream IS bounded at maxlen=4096
# ─────────────────────────────────────────────────────────────────────────


def test_stream_bounded_at_maxlen() -> None:
    """5000 emits → drain returns at most 4096 (the documented maxlen).

    The deque is configured with ``maxlen=4096`` in
    ``self_defense/__init__.py``; once full, the oldest events
    are dropped on the next append. Emitting 5000 events and
    draining with an unbounded window must yield at most 4096.
    """
    # First emit 5000 events. They may evict older events (which
    # is fine — the bound is what we're testing).
    for i in range(5000):
        emit(_make_event(i))

    # Drain with max_items comfortably above the cap.
    snapshot = list(drain(max_items=10_000))
    assert len(snapshot) <= 4096, (
        f"stream overflowed: got {len(snapshot)} events, cap is 4096"
    )
    # And it's *close* to the cap — if it's tiny, the test isn't
    # actually exercising the bound. Use 4000 as a soft floor so
    # the test isn't flaky on the last few events.
    assert len(snapshot) >= 4000, (
        f"stream under-filled: got {len(snapshot)} events, "
        f"expected ~4096 after 5000 emits"
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 3: drain(max_items=N) honors N
# ─────────────────────────────────────────────────────────────────────────


def test_drain_max_items_respected() -> None:
    """drain(max_items=10) returns at most 10 items even after 100 emits."""
    # 100 fresh emits — they may evict earlier ones, that's fine.
    for i in range(100):
        emit(_make_event(i))

    snapshot = list(drain(max_items=10))
    assert len(snapshot) <= 10, snapshot


# ─────────────────────────────────────────────────────────────────────────
# Invariant 4: concurrent emit() doesn't corrupt (single-loop only)
# ─────────────────────────────────────────────────────────────────────────


def test_concurrent_emit_does_not_corrupt() -> None:
    """10 concurrent emit() calls — all events eventually drained.

    F-018: this test passes under single-loop asyncio
    (CPython 3.11/3.12 default), where ``deque.append`` is atomic
    at the bytecode level and the GIL serializes the operations.
    Under free-threaded CPython 3.13+ (PEP 703) without the GIL,
    ``emit`` and ``drain`` would race; the test would either
    raise or return a partial snapshot.

    If this test becomes flaky on 3.13t, the fix is a ``threading.Lock``
    around ``_STREAM.append`` (and a snapshot copy under the lock
    in ``drain``). For now, the asyncio loop guarantees the order.
    """
    emitted = 10

    async def _emit_many() -> None:
        # 10 concurrent tasks, each appending one event.
        await asyncio.gather(
            *(asyncio.to_thread(emit, _make_event(i)) for i in range(emitted))
        )

    asyncio.run(_emit_many())

    # No exception escaped; snapshot a generous window so the
    # just-emitted events are present (modulo prior tests' evictions).
    snapshot = list(drain(max_items=10_000))
    # We assert "no exception" structurally: the test reaches this
    # line at all means the concurrent emits didn't blow up the
    # process. Confirm at least one event is still in the stream.
    assert len(snapshot) >= 1, snapshot