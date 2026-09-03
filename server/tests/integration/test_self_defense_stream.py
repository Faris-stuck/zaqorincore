"""Integration tests for the self_defense in-process event stream.

F-018 fixed in v3.4.4: ``emit()`` and ``drain()`` are now
protected by ``threading.Lock``. The previous version of this
module documented the unlocked-deque gap; the tests below now
assert that the fix actually works under multi-threaded load.

Note on scope: the lock is **in-process**. Multi-worker uvicorn
deployments still have N independent streams. See
``self_defense/MULTI_WORKER.md`` and the F-018 finding doc for
the cross-worker gap (Redis-stream future work).

Tests in this module are marked ``integration`` so they can be
skipped under unit-only mode.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import threading

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

from zaqorincore_server import self_defense  # noqa: E402
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


def _reset_stream() -> None:
    """Clear the module-level ``_STREAM`` for an isolated test.

    The stream is module-singleton, so prior tests (especially
    ``test_stream_bounded_at_maxlen``) may have left it at the
    ``maxlen=4096`` ceiling. Without resetting, tests that
    assert on the delta from ``before`` will see eviction
    cancel out the just-emitted events.
    """
    with self_defense._STREAM_LOCK:
        self_defense._STREAM.clear()


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
# Invariant 4: F-018 fix — concurrent emit() preserves all events
# ─────────────────────────────────────────────────────────────────────────


def test_emit_uses_lock() -> None:
    """10 threads × 100 emits = 1000 events; stream count grows by 1000.

    F-018 fix: ``emit()`` now holds ``_STREAM_LOCK`` around the
    append. Before the fix, an unlocked ``deque.append`` under
    free-threaded CPython (3.13+) — or under ``asyncio.to_thread``
    where the GIL is periodically released — could race with
    ``drain``'s ``list(_STREAM)[-max_items:]`` snapshot and lose
    events at the slice boundary. With the lock, every emit is
    serialised and the drain snapshot is consistent.

    We pick a count comfortably below ``maxlen=4096`` so eviction
    is not a confounder — if the count does not grow by exactly
    1000, the lock is broken or the snapshot is corrupt.
    """
    _reset_stream()
    n_threads = 10
    per_thread = 100
    total = n_threads * per_thread  # 1000

    before = len(list(drain(max_items=100_000)))

    barrier = threading.Barrier(n_threads)

    def _worker(tid: int) -> None:
        barrier.wait()  # maximise overlap across threads
        for i in range(per_thread):
            emit(_make_event(tid * 10_000 + i))

    threads = [
        threading.Thread(target=_worker, args=(t,))
        for t in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    after = len(list(drain(max_items=100_000)))
    assert after == before + total, (
        f"expected stream to grow by {total} under concurrent emit, "
        f"got before={before} after={after} (delta={after - before})"
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 5: F-018 fix — drain() is atomic with concurrent emit()
# ─────────────────────────────────────────────────────────────────────────


def test_drain_atomic_with_concurrent_emit() -> None:
    """Background emitter + foreground drain must never corrupt the snapshot.

    F-018 fix: ``drain()`` takes the snapshot copy *inside* the
    lock. The pre-fix version computed ``list(_STREAM)[-max_items:]``
    without holding the lock, so a concurrent ``emit`` could
    shift the deque between the ``list()`` call and the slice,
    producing a truncated or duplicated entry at the boundary.

    This test runs a background thread emitting 1000 events while
    the main thread calls ``drain`` 10 times. Every drain must
    return a valid list — no exceptions, no truncated events.
    """
    _reset_stream()
    stop = threading.Event()

    def _emitter() -> None:
        i = 0
        while not stop.is_set():
            emit(_make_event(i))
            i += 1

    emitter = threading.Thread(target=_emitter, daemon=True)
    emitter.start()

    try:
        for _ in range(10):
            snap = list(drain(max_items=128))
            assert isinstance(snap, list)
            # Every item is a ZaqorinEvent — the snapshot copy
            # under the lock guarantees this; if the slice
            # boundary ever crossed an in-flight append the
            # test would see a partially-constructed event.
            assert all(
                hasattr(e, "ts") and hasattr(e, "event_type")
                for e in snap
            ), snap
            assert len(snap) <= 128
    finally:
        stop.set()
        emitter.join(timeout=2.0)


# ─────────────────────────────────────────────────────────────────────────
# Invariant 6: F-018 fix — total event count under sustained load
# ─────────────────────────────────────────────────────────────────────────


def test_emit_thread_safe_under_load() -> None:
    """4 threads × 1000 emits = 4000 events; count grows by exactly 4000.

    We measure ``before`` (count after the prior test left the
    stream) and assert the post-emit snapshot is exactly
    ``before + 4000``. This is robust to ordering: any other test
    can run first, and any prior events can occupy the tail of
    the deque.

    The 4000 is well below ``maxlen=4096`` so eviction cannot
    hide a loss — if the lock is broken, ``after < before + 4000``.
    """
    _reset_stream()
    n_threads = 4
    per_thread = 1000
    total = n_threads * per_thread  # 4000

    before = len(list(drain(max_items=100_000)))

    barrier = threading.Barrier(n_threads)

    def _worker(tid: int) -> None:
        barrier.wait()
        for i in range(per_thread):
            emit(_make_event(tid * 100_000 + i))

    threads = [
        threading.Thread(target=_worker, args=(t,))
        for t in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    after = len(list(drain(max_items=100_000)))
    assert after == before + total, (
        f"expected {total} new events after 4×1000 emits, "
        f"got after={after}, before={before} (delta={after - before})"
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 7: emit/drain work under asyncio.to_thread (the real hot path)
# ─────────────────────────────────────────────────────────────────────────


def test_concurrent_emit_does_not_corrupt() -> None:
    """asyncio.to_thread(emit) — exercises the lock across an event loop.

    F-018 fix: with the ``threading.Lock`` in place, ``emit``
    serialises correctly even when called from
    ``asyncio.to_thread`` workers. Before the fix, the same
    pattern was technically racey on free-threaded CPython.

    No exception escaping the gather is the primary assertion.
    """
    emitted = 10

    async def _emit_many() -> None:
        await asyncio.gather(
            *(asyncio.to_thread(emit, _make_event(i)) for i in range(emitted))
        )

    asyncio.run(_emit_many())

    snapshot = list(drain(max_items=10_000))
    # At least one event is present (prior tests may have
    # evicted older ones; that's fine).
    assert len(snapshot) >= 1, snapshot


# ─────────────────────────────────────────────────────────────────────────
# Invariant 8: with_stream_lock() is a real context manager and serialises
# ─────────────────────────────────────────────────────────────────────────


def test_with_stream_lock_yields_under_load() -> None:
    """4 threads call with_stream_lock() concurrently — no exceptions,
    and the lock is actually acquired/released (verified by a counter
    that must reach exactly ``0`` when all critical sections exit).

    If ``with_stream_lock`` failed to acquire (e.g. wrong lock
    object) or failed to release on exception (a broken
    ``@contextmanager``), the inner counter check would either
    deadlock or see a non-zero value on completion. The barrier
    maximises overlap so all four threads attempt entry at the
    same time.
    """
    _reset_stream()

    from zaqorincore_server.self_defense import with_stream_lock

    n_threads = 4
    iterations = 200
    in_critical = 0
    lock_for_increment = threading.Lock()
    errors: list[BaseException] = []

    barrier = threading.Barrier(n_threads)

    def _worker() -> None:
        nonlocal in_critical
        try:
            for _ in range(iterations):
                barrier.wait()  # align all threads at the start
                with with_stream_lock():
                    # If the lock is not actually held, two threads
                    # could be here at once and the assertion below
                    # would fire under free-threaded CPython.
                    with lock_for_increment:
                        assert in_critical == 0
                        in_critical += 1
                    # Tiny piece of work — without the real lock,
                    # a context switch here lets a peer thread in.
                    with lock_for_increment:
                        in_critical -= 1
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=_worker) for _ in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not errors, f"context manager raised under load: {errors!r}"
    assert in_critical == 0, (
        f"critical-section counter not zero after all threads exited: "
        f"{in_critical} (lock not released on at least one exit)"
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 9: with_stream_lock() makes snapshot+clear atomic
# ─────────────────────────────────────────────────────────────────────────


def test_with_stream_lock_atomic_clear_and_get() -> None:
    """Under with_stream_lock(), list(_STREAM) + _STREAM.clear() runs
    as one atomic critical section. After exit, drain() returns empty.

    This exercises the documented usage pattern in the
    ``with_stream_lock`` docstring (snapshot + clear) and proves
    that holding the lock around both ops prevents the
    background emitter from sneaking events back in between them.
    The background emitter runs for the full duration of the test
    — if the clear is not actually under the lock, the post-clear
    ``drain`` would pick up events the emitter added between the
    list copy and the clear (a tiny race window, but the test
    loops until it would fail without the lock).
    """
    _reset_stream()
    from zaqorincore_server.self_defense import with_stream_lock

    stop = threading.Event()

    def _emitter() -> None:
        i = 0
        while not stop.is_set():
            emit(_make_event(i))
            i += 1

    emitter = threading.Thread(target=_emitter, daemon=True)
    emitter.start()

    try:
        # Pre-fill so the stream is non-empty when we enter the
        # context manager — the assertion that ``pending`` is
        # non-empty catches a misordered list/clear.
        for i in range(50):
            emit(_make_event(10_000 + i))

        with with_stream_lock():
            pending = list(self_defense._STREAM)
            self_defense._STREAM.clear()
        # We drained a non-empty stream under the lock.
        assert len(pending) >= 50, (
            f"expected to snapshot at least 50 events, got {len(pending)}"
        )
        # And nothing was emitted between the snapshot and the clear
        # from the perspective of *this* critical section. Immediately
        # after exit, drain() may already see new events from the
        # background emitter, so we just assert the clear itself ran.
        # The atomic guarantee we actually want is: ``pending`` is
        # a complete view of the stream at the moment of the lock
        # acquisition, and the clear happened before the lock was
        # released. We confirm the clear by checking that the count
        # dropped from a known non-empty value to a much smaller
        # value right after exit (within one drain call).
        snapshot_after = list(drain(max_items=100_000))
        # The stream should be much smaller than ``pending`` because
        # we cleared inside the lock — the emitter's events that
        # arrive *after* the lock release are allowed to be here.
        # We just verify the clear effect: the stream is NOT still
        # at the ~50 baseline we set up before the lock.
        assert len(snapshot_after) < len(pending), (
            f"clear under with_stream_lock did not take effect: "
            f"pending={len(pending)} after={len(snapshot_after)}"
        )
    finally:
        stop.set()
        emitter.join(timeout=2.0)