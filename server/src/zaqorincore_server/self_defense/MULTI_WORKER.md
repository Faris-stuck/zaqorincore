# Multi-worker deployments — caveat

> Status: partial fix in v3.4.4 (F-018). Cross-worker gap remains.
> See `docs/security/findings/F-018-self-defense-stream-concurrency.md`.

## The problem

The `self_defense` event stream lives **inside a single Python
process**. `_STREAM` is a module-level `collections.deque`,
created when `self_defense/__init__.py` is imported, and shared
across all coroutines of that one process.

When you run uvicorn with multiple workers, e.g.

```bash
uvicorn zaqorincore_server.app:app --workers 4
```

each worker process imports the package separately and gets its
own `_STREAM`. Events emitted in worker A never reach the runner
of worker B. From the detection side this means:

- **Per-worker detection only.** Each worker sees only its own
  share of the traffic. With 4 workers behind a load balancer and
  round-robin distribution, the runner in worker 0 sees roughly
  1/4 of all incoming events.
- **Correlations break.** If a probe hits worker 0, hits worker 2,
  then hits worker 1 — the runner in any one worker sees only one
  of the three events. Sigma rules that count repeated probes
  will under-fire.
- **No error, no warning.** The process runs normally; the
  detection coverage is just silently incomplete.

## What v3.4.4 fixes

In v3.4.4 we added a `threading.Lock` around `_STREAM.append`
and `drain()`'s snapshot copy. This closes the **in-process**
concurrency concern:

- `emit()` is now safe to call from `asyncio.to_thread()` workers
  and from multiple threads under free-threaded CPython 3.13+.
- `drain()` takes its snapshot copy inside the lock so a
  concurrent `emit` cannot shift the deque mid-slice.

What v3.4.4 does **not** fix is the cross-worker case. Each
worker still has its own `_STREAM`. The lock makes each stream
individually correct; it does not unify them.

## Workarounds for multi-worker deployments

### Option A — single worker (recommended for self-defense)

If you can tolerate it, run the self-defense pack under a
single uvicorn worker. This is the simplest reliable answer:

```bash
uvicorn zaqorincore_server.app:app --workers 1
```

You will lose horizontal scaling on the event ingest path, but
self-defense events are bounded by HTTP/WS request rate, not by
CPU. A single worker can comfortably handle the load on a small
deployment.

### Option B — Redis-backed shared stream (future work, not implemented)

The intended production-grade fix is to publish events to a
shared log and have one runner subscribe. The proposed design:

1. Emit: `emit()` pushes the event onto a Redis Stream
   (`XADD zaqorin:self_defense * ...`) when
   `ZAQORIN_SELF_DEFENSE_REDIS_URL` is set.
2. Runner: a dedicated consumer group (`XREADGROUP`) drains the
   stream and feeds the Sigma engine.
3. Fallback: if the env var is unset, the local in-process
   deque is used (current behaviour). Single-worker deployments
   need no change.

This work is **not** implemented. Tracking: see
`docs/security/findings/F-018-self-defense-stream-concurrency.md`
recommendation §2.

### Option C — sticky routing by session

If you must run multiple workers and want better-than-random
coverage without a shared backend, configure your load balancer
to pin a client to one worker for the duration of its session.
Self-defense probes typically come from a single IP over a short
window, so a `keepalive`-aware load balancer (HAProxy stick-table
by src IP, nginx `ip_hash`) will route the whole probe to one
worker. The runner in that worker sees the full picture.

This does not give 100% cross-worker coverage; a probe that
rotates IPs still fragments. But it removes the random
1/N dilution for the common case.

## Detecting you're affected

If you are running `--workers > 1` and you want to know whether
the self-defense runner is seeing your traffic, the cleanest test
is to fire the documented probe shapes against a single
endpoint from a fixed source IP and watch the runner's hit
count. With sticky routing it should equal your request count.
Without sticky routing it will be roughly 1/N.

A future version of this pack will expose
`self_defense_stream_size` (per-worker) and
`self_defense_emitted_total` (per-worker) Prometheus metrics so
operators can see the per-worker split. See F-018 recommendation
§3.

## Summary

| Deployment shape              | Stream coverage        | Action          |
| ----------------------------- | ---------------------- | --------------- |
| `--workers 1`                 | Full, single process   | None — already  |
|                               |                        | covered by      |
|                               |                        | v3.4.4 lock.    |
| `--workers N`, no sticky      | ~1/N per worker        | Accept the      |
|                               |                        | gap or move to  |
|                               |                        | Option A/B.     |
| `--workers N`, sticky by IP   | Mostly full per source | Acceptable for  |
|                               |                        | most operators. |
| `--workers N`, Redis stream   | Full, shared           | **Future**      |
|                               |                        | (Option B).     |

If you are affected by the gap and want to help implement Option
B, the env-var name is already reserved:
`ZAQORIN_SELF_DEFENSE_REDIS_URL`. The implementation must not
break the in-process fallback path; v3.4.4's lock-based design is
the baseline.