# F-018 — self_defense.emit() is not concurrency-safe in async context (Low→Medium)

**Component**: `server/src/zaqorincore_server/self_defense/__init__.py` (added in v3.3.0)
**CWE**: CWE-662 (Improper Synchronization)
**Severity**: Low → Medium under high event rate
**Status**: Open
**Discovered**: 2026-09-03 (Round 2 post-v3.4.0 audit)

## Description

The `_STREAM` deque is a plain `collections.deque` shared between
the emit hot path (called from HTTP/WS middleware on every request)
and the runner (called from a periodic task). Both run on the same
event loop, but `deque.append` is **not** safe under interleaved
`_STREAM.append()` + `list(_STREAM)` if the runner iterator is
holding a reference to the deque while emit appends.

In practice with CPython, single-threaded asyncio means the
operations are atomic at the bytecode level. But the moment the
runner yields (e.g. awaiting an I/O), an emit can re-append and
shift the deque. The runner's `list(_STREAM)[-max_items:]` snapshot
is taken non-atomically w.r.t. concurrent appends.

## Impact

Under high event rate, the runner may:
- Skip events (race: emit + drain lose entries mid-snapshot)
- See partial/corrupted events (extremely unlikely with GIL but
  possible under free-threaded CPython 3.13+)

In a single-loop asyncio deployment this is theoretical; in a
multi-worker uvicorn deployment behind a load balancer, **each
worker has its own `_STREAM`** — events from one worker never reach
the runner of another, so multi-worker deployments silently lose
detection coverage on a per-worker basis.

## Recommendation

1. Wrap `_STREAM.append` in an `asyncio.Lock`.
2. For multi-worker: publish events to a shared Redis stream
   (`ZAQORIN_SELF_DEFENSE_REDIS_URL`); runner subscribes.
3. Add a metric `self_defense_stream_size` so operators see
   saturation.

## Mitigation priority

Low under default single-worker uvicorn. Documented as a known
limitation until multi-worker support is added.
