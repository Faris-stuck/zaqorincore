# F-023 — CSP reporter throttle has race, no eviction, no body cap; throttled traffic floods event stream (Medium)

**Component**: `server/src/zaqorincore_server/self_defense/csp_violation_reporter.py` (post-F-017, v3.4.3)
**CWE**: CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption), CWE-362 (TOCTOU Race)
**Severity**: Medium
**Status**: Open
**Discovered**: 2026-09-03 (Round 8, cycle 72 — narrow-scope audit of F-017 fix surface)

## Scope

This is a narrow audit of the post-F-017 implementation. F-017 (v3.4.3)
correctly switched the throttle key from `document-uri` to `src_ip`. This
finding covers the residual issues that F-017 left behind or did not
address.

## Description

The throttle in `csp_violation_reporter.py` has four residual issues,
each individually Medium-or-lower severity; aggregated they are Medium
because they share the same abuse vector (unauthenticated spam against
`/api/v1/_csp-report`).

### Issue 1 — Race condition in `_throttle_allowed` (CWE-362)

```python
# Lines 70–83 of csp_violation_reporter.py
_recent: dict[str, deque[float]] = {}

def _throttle_allowed(src_ip: str, now: float) -> bool:
    bucket = _recent.setdefault(src_ip, deque())
    cutoff = now - _THROTTLE_WINDOW_SEC
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= _THROTTLE_BUDGET:
        return False
    bucket.append(now)
    return True
```

`_recent` and its `deque` values are shared mutable state mutated
without any lock. FastAPI runs `async def` route handlers in a
threadpool when they do non-trivial work; concurrent requests can
enter `_throttle_allowed` simultaneously. The dict-setdefault +
popleft + len + append sequence is **not atomic** under the GIL:
two threads can both pass the `len(bucket) >= _THROTTLE_BUDGET` check
at the same time, briefly allowing the bucket to exceed 10 entries.

Concretely, an attacker firing ~20 simultaneous requests at the same
src_ip will see the budget allow ~11–12 through instead of the
intended 10 — a small but real bypass. The bigger risk is **deque
interleaving**: if `popleft()` from one thread races with `append()`
from another, CPython may raise `IndexError` (deque is generally
thread-safe under the GIL for `append`/`popleft`, but the combined
`popleft`-then-`len`-then-`append` sequence is not).

### Issue 2 — Unbounded memory growth in `_recent` (CWE-770 / CWE-400)

There is **no eviction** of stale entries from `_recent` after the
60-second window passes. The deque per src_ip drops old timestamps,
but the **outer dict** keeps every src_ip it has ever seen. An
attacker rotating source IPs (trivial with IPv6 spoofing behind any
NAT that allows it, or with a botnet of residential proxies) can grow
`_recent` until the process is OOM-killed.

The module docstring (lines 65–67) notes "in-process only; the CSP
report volume from any one browser is tiny so a Redis bucket would be
premature optimisation". The justification is correct for honest
clients, but does not account for adversarial cardinality.

### Issue 3 — No per-endpoint body size limit (residual from F-017)

F-017's original finding called for "a global per-endpoint body size
guard (e.g. 64 KiB) since CSP reports are tiny in practice". The
F-017 **fix** only changed the throttle key; it did **not** add a
body cap. A 1 MiB POST × 10/min/IP = 10 MiB/min/IP of unauthenticated
ingress — and the route accepts `payload: dict[str, Any]` which
FastAPI will parse in full (no early body-length rejection at the
route level).

CSP reports in practice are well under 10 KiB; the global 1 MiB
guard is ~100× too generous.

### Issue 4 — Throttled requests emit events, evicting legitimate audit (residual amplification of F-008)

Lines 130–134:

```python
if not _throttle_allowed(src_ip, now):
    event = ZaqorinEvent.from_csp_report(payload, src_ip=src_ip, status=429)
    emit(event)
    return FastAPIRawResponse(status_code=429, content=b"")
```

Every throttled request emits a `ZaqorinEvent`. The in-process
`_STREAM` in `self_defense/__init__.py` is bounded to 4096 entries
(`deque(maxlen=4096)`). An attacker spamming beyond the throttle
budget will push legitimate events out of `_STREAM` at a rate of
10/min/IP × N IPs. Combined with Issue 2 (no IP eviction), this
gives an attacker a lever to suppress real audit events.

## Impact

Combining the four:

* Attacker with a residential botnet (or IPv6 spoofing) can grow
  `_recent` to OOM the server (Issue 2).
* Same attacker can issue 10/min/IP × K IPs of 1 MiB POST bodies,
  sustaining ~K × 10 MiB/min of ingress (Issue 3).
* Same attacker's 429 responses evict legitimate `_STREAM` events
  faster than legitimate traffic can refill them (Issue 4, amplifies
  F-008 — in-memory audit log only).
* The throttle budget is mildly over-spent under concurrency
  (Issue 1) — small by itself, but reduces the per-request cost of
  the attacks above.

The endpoint is unauthenticated by design (CSRF not a concern; no
session cookies). The fix is therefore the **defensive layers** —
the throttle is the only barrier, and four leaks weaken it.

## Reproduction (conceptual, no live payload)

```bash
# Issue 2: rotate IPs to grow _recent.
for i in $(seq 1 100000); do
  curl -fsS -X POST http://target/api/v1/_csp-report \
    -H 'Content-Type: application/csp-report' \
    -H "X-Forwarded-For: 2001:db8::$i" \
    --data '{"csp-report":{"document-uri":"https://x/","violated-directive":"script-src"}}'
done
# _recent now has 100000 entries. No eviction.

# Issue 4: spam from one IP at > 10/min to evict legitimate events.
# (Need ZAQORIN_SRC_IP_HEADER=X-Forwarded-For if behind a proxy.)
while true; do
  curl -fsS -X POST http://target/api/v1/_csp-report \
    -H 'Content-Type: application/csp-report' \
    --data '{"csp-report":{"document-uri":"https://x/","violated-directive":"script-src"}}'
done
```

## Recommendation

In rough order of payoff (lowest cost first):

1. **Per-endpoint body size cap** — FastAPI supports per-route body
   limits via `Request.stream()` and `Content-Length` header checks;
   reject `Content-Length > 64 KiB` with 413 before reading the body.
2. **Eviction in `_throttle_allowed`** — when popping the oldest
   entry, if the deque becomes empty, also `del _recent[src_ip]`
   (under a lock; see 3).
3. **`threading.Lock` around `_throttle_allowed`** — same lock used
   for both eviction and the length-check; protects against the
   race in Issue 1 and the dict-del in Issue 2.
4. **Drop the 429 emit** — emitting an event for every throttled
   request amplifies F-008. Aggregate: emit a single
   "throttle-tripped" event per src_ip per minute, or drop the
   event entirely and rely on the existing T1505.004 Sigma rule.
5. **Cap XFF first-token length** — at the `_resolve_src_ip`
   boundary, truncate the header value to a sane max (e.g. 64 chars)
   before storing as a dict key.

## Mitigation priority

Medium. The endpoint is unauthenticated and each issue is
independently exploitable. None of the four fixes is large — most
are < 10 lines — so they should ship together as a v3.4.14 hotfix.

## Hygiene

- No new IP or credential leaks introduced by this finding.
- No AI-generated code suggested for the fix; the file is already
  short enough to patch in-place.
- The audit is read-only: no code in `server/` was modified.
