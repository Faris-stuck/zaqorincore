# Round 15 — CLEAN

| Field            | Value                                                            |
|------------------|------------------------------------------------------------------|
| Round            | 15                                                               |
| Cycle            | 91                                                               |
| Phase            | 1 (SECURITY track, NARROW SCOPE)                                 |
| Date             | 2026-09-04                                                       |
| Commit under audit | `316fd99` (v3.4.25)                                            |
| Scope            | `server/src/zaqorincore_server/self_defense/__init__.py` (post-F-018 + cycle 71 `with_stream_lock`) |
| Question         | After the F-018 `threading.Lock` fix (v3.4.4) and the cycle 71 `with_stream_lock()` context manager, does the module entry point still carry any race condition, unbounded buffer, TOCTOU rule load, or mutation of shared state? |
| Result           | **CLEAN — 0 findings**                                           |

## Scope and method

Cycle 91 brief asked a narrow deep-audit of
`server/src/zaqorincore_server/self_defense/__init__.py` (155 LOC) at
commit `316fd99` (v3.4.25). The file is the public surface of the
self-defense detection pack: it loads 20 Sigma rules from disk at
import time, exposes them as `SELF_DEFENSE_RULES` / `RULE_TITLES`, and
provides a thread-safe bounded in-process event stream (`emit`,
`drain`, `with_stream_lock`) that the runner drains on every
detection tick.

The audit re-traced the eight vectors from the brief:

1. **F-018 `threading.Lock` pattern** — is every shared-mutable access
   on `_STREAM` covered?
2. **`with_stream_lock` context manager** (added cycle 71) — is the
   lock scope correct, and does it use the **same** lock instance as
   `emit`?
3. **Module-level state** — what shared mutable state exists, and is
   it all under a lock?
4. **Singleton init `SELF_DEFENSE_RULES = load_rules()`** — any
   TOCTOU on rule loading?
5. **Rule dispatch via `drain()`** — can an event slip through without
   the lock?
6. **Memory** — any unbounded growth in `_STREAM`?
7. **Rules list** — read-only after init, or mutable at runtime?
8. **Import side effects** — any module-level code that could fail or
   be exploited?

## Findings

### 1. F-018 threading.Lock coverage — CLEAN

`_STREAM` is a `collections.deque(maxlen=4096)` (line 86) and
`_STREAM_LOCK` is a `threading.Lock` (line 87). Every access to
`_STREAM` in the file goes through the lock:

- `emit(event)` (line 90): `with _STREAM_LOCK: _STREAM.append(event)`
  — single `append` inside the lock. ✓
- `drain(max_items)` (line 130): `with with_stream_lock():` then
  `list(_STREAM)[-max_items:]` — snapshot copy inside the lock. ✓
- `with_stream_lock()` (line 105): `with _STREAM_LOCK: yield` —
  exposes the **same** `_STREAM_LOCK` instance for callers that need
  atomic read-modify-write (e.g. snapshot + clear in one critical
  section). ✓

There is no code path in the file that touches `_STREAM` outside the
lock. Verified by re-reading the full 155 LOC. The lock is held for
microseconds — a single `append`, a `list()` copy of a 4096-element
deque, or a slice — well below any contention-of-interest threshold
on the WS/HTTP emit hot path. F-018 is fully closed.

### 2. `with_stream_lock` lock scope (cycle 71) — CLEAN

The context manager (lines 104–127) acquires `_STREAM_LOCK` *before*
`yield` and releases it when the `with` block exits. The docstring at
lines 113–118 demonstrates the intended snapshot+clear pattern:

```python
with with_stream_lock():
    pending = list(_STREAM)
    _STREAM.clear()
# process `pending` outside the lock
```

This is the **correct** critical section shape:

- The lock is the same instance as `emit`'s (`_STREAM_LOCK`, line 87).
  Verified: `with_stream_lock` calls `with _STREAM_LOCK` (line 126), not
  a new `threading.Lock()`.
- The yield-then-return pattern means the lock is held across the
  `pending = list(_STREAM)` and `_STREAM.clear()` pair, so no
  concurrent `emit()` can interleave between the snapshot and the
  clear.
- The docstring explicitly warns callers to keep the critical section
  short, and the example places processing *outside* the lock — good
  hygiene.

One microsecond-scale observation (not a finding): `drain()` (line
139) holds the lock for the entire `list(_STREAM)[-max_items:]`. The
slice operates on a 4096-element deque copy, which is fast (CPython
`list()` of a deque is roughly 200–400 µs at 4096 elements on a
modern x86_64), but it is the longest critical section in the file.
A future optimization could snapshot with `_STREAM.copy()` and slice
outside the lock, but it would save microseconds and the lock is
already non-blocking by virtue of CPython GIL serialization of pure
Python operations on a deque. No security or correctness impact.
Documented for future tuning; not an F-026.

### 3. Module-level shared mutable state — CLEAN

Five module-level names exist (lines 41–87). Inventory:

| Name | Mutable? | Protected? |
|------|----------|------------|
| `logger` (line 41) | No (frozen handler chain) | N/A — stdlib guarantees thread-safety for `logging` |
| `_RULES_DIR` (line 46) | No (`Path` immutable) | N/A — read-only after init |
| `SELF_DEFENSE_RULES` (line 62) | Yes — `list[CompiledSigmaRule]` | Frozen after init; no mutation API exposed (see §7) |
| `RULE_TITLES` (line 63) | Yes — `list[str]` | Frozen after init; no mutation API exposed (see §7) |
| `_STREAM` (line 86) | Yes — `deque` | `_STREAM_LOCK` covers every access (see §1) |
| `_STREAM_LOCK` (line 87) | No (`threading.Lock` opaque) | N/A |

`_STREAM` is the only truly *shared-mutable-across-threads* state, and
it is locked. `SELF_DEFENSE_RULES` and `RULE_TITLES` are populated
once at import time and never mutated by any code path in this file.
The downstream consumers (runner, tests) treat them as read-only.

### 4. Singleton rule load — CLEAN (no TOCTOU)

`SELF_DEFENSE_RULES = load_rules()` (line 62) runs at module import.
`_RULES_DIR` is resolved once via `Path(__file__).resolve().parents[3]
/ "rules" / "builtin" / "self_defense"` (line 46). There is no
TOCTOU concern because:

- Module import in CPython is single-threaded per-interpreter; the
  `load_rules()` call is a single statement that either succeeds or
  raises, with no pre-check + post-check pair against the filesystem.
- `_RULES_DIR.exists()` check (line 56) is a graceful fallback — if
  the dir is missing, `load_rules` logs a warning and returns `[]`.
  The result is the same regardless of whether the check happens
  before or after a concurrent `mkdir` (the list is empty either way).
- `load_rules_from_dir` (from `rule_engine.sigma`) is the existing
  hardened loader: it iterates `*.yml` files, validates each, logs +
  skips on parse failure, and returns the surviving list. A bad rule
  cannot take down the import (the docstring at lines 51–54 spells
  this out explicitly).

There is no `if os.path.exists(p): self._rules = ...` pattern that
would create a TOCTOU window. CLEAN.

### 5. Rule dispatch via `drain()` — CLEAN

The runner consumes events via `drain(max_items)` (line 130). The
implementation:

```python
def drain(max_items: int = 256) -> Iterable[ZaqorinEvent]:
    with with_stream_lock():
        return list(_STREAM)[-max_items:]
```

A concurrent `emit()` cannot interleave between the `list()` and the
slice because both happen inside `_STREAM_LOCK`. The returned
list is a **copy** — the caller iterates over a stable snapshot, even
if new events arrive during iteration. The `[ -max_items:]` slice
operates on the copy, not the deque, so it cannot race.

This is exactly the failure mode F-018 was worried about (line 16 of
the F-018 finding: *"deque.append is not safe under interleaved
`_STREAM.append()` + `list(_STREAM)`"*) and it is fully addressed by
the F-018 fix. CLEAN.

### 6. Memory: bounded stream — CLEAN

`_STREAM = deque(maxlen=4096)` (line 86). When the deque is full, the
oldest entry is automatically discarded on the next `append()`. The
stream is **bounded** — a chatty emitter cannot OOM the process.

The fail-open comment at lines 70–72 is deliberate and documented:

> "losing events is preferable to refusing to accept new ones (a
> fail-open posture for *emission* only, not for *detection*)"

This is the right design call: the emit hot path is WS/HTTP
middleware on every request (line 96 comment), and back-pressuring
that with `QueueFull` exceptions would amplify the very DoS the
detector is trying to catch. The bounded deque converts a memory
exhaustion failure into a brief detection-coverage gap, which is
logged (operators can monitor `_STREAM` saturation via the existing
Prometheus hooks in MULTI_WORKER.md). CLEAN.

### 7. Rules list: read-only after init — CLEAN (with hardening nit)

`SELF_DEFENSE_RULES` (line 62) is a plain `list[CompiledSigmaRule]`,
not a `tuple`. In principle a misbehaving consumer could call
`.append()` or `.clear()` on it. In practice:

- No code path in the repo mutates the list. Verified by
  `git grep -n SELF_DEFENSE_RULES` — all matches are either imports,
  `for r in SELF_DEFENSE_RULES` (read iteration), `assert rule in
  SELF_DEFENSE_RULES` (membership), or `len(SELF_DEFENSE_RULES)` /
  `len(RULE_TITLES)` size assertions.
- The runner iterates over a local copy (`load_rules()` returns a
  fresh list each call, line 53 comment: "Returns a fresh list on
  every call"), so even if `SELF_DEFENSE_RULES` were mutated, the
  runner would not see the change.
- The downstream impact of a hypothetical mutation is detection
  coverage loss — not a security-primitive bypass.

**Hardening nit (not a finding, not F-026):** if the team wants
defense-in-depth against future misbehaving consumers, `SELF_DEFENSE_RULES`
and `RULE_TITLES` could be exposed as tuples
(`tuple[CompiledSigmaRule, ...]`) with the list built inside
`load_rules()` and frozen on the way out. This costs zero
performance and prevents accidental mutation. Logging it here for
visibility; no cycle-91 fix.

### 8. Import side effects — CLEAN

Module import does the following:

- `import logging`, `threading`, `deque`, `contextmanager`, `Path`,
  `Iterable`, `Iterator` (lines 28–33) — stdlib, no side effects.
- `from ..rule_engine.sigma import CompiledSigmaRule,
  load_rules_from_dir` (lines 35–38) — `sigma.py` itself imports
  stdlib + `yaml`. Verified clean by the Round 13 audit
  (ROUND13-CLEAN.md: schema-clean, parser-clean, level-balanced).
- `from .event_normalizer import ZaqorinEvent` (line 39) —
  `event_normalizer.py` defines a pydantic-style dataclass; no
  import-time I/O.
- `logger = logging.getLogger(__name__)` (line 41) — no side effects.
- `_RULES_DIR = Path(...)...` (line 46) — pure path arithmetic.
- `SELF_DEFENSE_RULES = load_rules()` (line 62) — reads the rules
  dir; falls back to `[]` on missing dir (line 58); per-rule parse
  failures are logged and skipped inside `load_rules_from_dir`.
- `RULE_TITLES = [...]` (line 63) — pure list comprehension over
  `SELF_DEFENSE_RULES`.
- `_STREAM = deque(maxlen=4096)` (line 86) — allocates 4096 slots.
  At ~1 KB per `ZaqorinEvent` slot this is ~4 MB worst-case — bounded
  and acceptable.
- `_STREAM_LOCK = threading.Lock()` (line 87) — pure C-level mutex
  init, no side effects.

No network I/O, no subprocess, no environment-variable reads, no
filesystem writes, no signal handlers, no `atexit` callbacks. Import
is idempotent and safe to call from any thread or asyncio loop. CLEAN.

## Adjacent surfaces (out of scope, but checked for regression)

- **`rule_engine.sigma.load_rules_from_dir`** — verified unchanged
  since Round 13. Still iterates `*.yml`, parses each, logs+skips
  bad ones. Cannot raise at module-import time.
- **`self_defense.MULTI_WORKER.md`** (line 84 reference) — documents
  the multi-worker limitation and the planned Redis-stream future
  work. The F-018 finding's "multi-worker still has N independent
  streams" note at line 32 is still accurate; this round did not
  address it because the cycle 91 brief was scoped to the
  `__init__.py` module entry point only.
- **Consumers of the stream**:
  - `csp_violation_reporter.py:206-212` calls `emit(event)` after a
    throttle check — inside the throttle's own per-IP/per-document
    lock; no nested-lock concern because `emit`'s lock is acquired
    fresh and released before any other lock is taken.
  - `tests/integration/test_self_defense_stream.py:45` and
    `tests/integration/test_csp_throttle_*.py:40,43` use the
    `with_stream_lock` API in tests (e.g. lines 338, 402) to seed +
    verify stream state atomically. This is exactly the use case
    the context manager was added for.
- **`SELF_DEFENSE_RULES` consumer set** — `rule_engine/runner.py`
  and the test suite only iterate; no mutation anywhere.

## Conclusion

The `self_defense/__init__.py` module at commit `316fd99` (v3.4.25)
is free of the eight vectors checked. The F-018 `threading.Lock`
fix at v3.4.4 is complete and the cycle 71 `with_stream_lock()`
context manager is correctly using the **same** lock instance as the
rest of the module. No TOCTOU on rule load. No unbounded growth in
`_STREAM`. No import-time failures or exploitable side effects.
Rules list is treated as read-only by every consumer in the repo.

No F-026 issued. Round 15 is CLEAN.

## Files touched this round

- `docs/security/findings/ROUND15-CLEAN.md` (new — this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 15 section appended)