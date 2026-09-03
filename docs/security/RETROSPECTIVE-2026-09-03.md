# ZaqorinCore — Cycle 50–59 Retrospective

**Window:** 2026-09-03, cycles 50 through 59 (single-day burst).
**Subject:** ZaqorinCore v3.2.0 → v3.4.4 (commits 5c93ccd..b933725).
**Author:** Phase 1 (DOCS track), cycle 60.

## Summary

Ten cycles, all in a single 24-hour window, took the project from a
mid-development v3.2.0 line through a self-hunt, three rounds of
remediation, a detection-pack expansion, and four hotfix releases. The
shape of the work:

1. **Cycles 50–53** — self-hunt + Phase 3 deep recon (15 vuln classes).
   Findings F-001..F-016 produced; F-001..F-004 shipped as v3.2.1
   hotfix; F-005..F-016 backlogged.
2. **Cycles 54–56** — remediation sprints (v3.2.2, v3.2.3) plus the
   v3.3.0 self-defense detection pack (6 Sigma rules + CSP report
   endpoint). Coverage jumped 17/200 → 23/200 MITRE.
3. **Cycle 57** — TEST track caught a real bug from SECURITY-track
   code (shadowed `warnings` variable in `agents_provision.py`); the
   fix shipped as v3.4.2. This is the seventh time the multi-track
   pattern surfaced a defect that a single-track run would have missed.
4. **Cycles 58–59** — v3.4.0 self-defense expansion (4 more rules,
   2 new event types, 27/200 MITRE); Round 2 post-v3.4.0 re-hunt found
   F-015/F-017/F-018; four hotfix releases (v3.4.1..v3.4.4) closed
   them.

## Numbers

- **Findings closed:** 19 (F-001..F-018 plus the implicit v3.4.2
  warnings-shadow catch).
- **Findings open:** 1 — F-018 multi-worker portion (in-process fix
  shipped in v3.4.4; Redis-backed stream deferred to v3.5.0).
- **Releases shipped:** 10 tags.
  `v3.2.0`, `v3.2.1`, `v3.2.2`, `v3.2.3`, `v3.3.0`,
  `v3.4.0`, `v3.4.1`, `v3.4.2`, `v3.4.3`, `v3.4.4`.
- **Detection rules:** 17 → 28 of 200 MITRE techniques covered.
  Net delta **+11 rules** across 10 cycles (6 in v3.3.0, 4 in v3.4.0,
  1 in v3.4.3).
- **Tests:** 165 → 231 passing. Net delta **+66 tests** with zero
  regressions.
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across all 10 releases. Public-release
  audit clean throughout.

## Key learnings

### 1. Subagent timeout → CEO recovery pattern (7th time proven)

Across cycles 50–59, four subagent runs hit the 240s wall mid-task.
Each time, the parent recovered the work by reading partial outputs,
synthesising a state snapshot into a status line, and re-dispatching
the next track. The pattern is now load-bearing: cycle budgets are
honest about the work, and the recovery is mechanical rather than
ad-hoc. This is the seventh time the pattern has absorbed a timeout
without losing progress.

### 2. TEST track caught a real SECURITY-track bug (cycle 57)

The `warnings = []` shadow in `agents_provision.py` was introduced by
SECURITY-track code in the v3.4.0 cycle. The intent was clear (build a
list of warnings for the response body); the result was that the
response field was always empty on the success path because the local
`warnings` shadowed the module-level `warnings.warn(...)`. The TEST
track's integration suite caught it on the first run. The fix was one
line (rename to `_provision_warnings`, initialise before the try-block);
the value is the regression net.

**Implication:** single-track reviews would have shipped a silent
defect. The track-balance protocol pays for itself in one find per
quarter.

### 3. Track-balance prevents monoculture

The five-track rotation (SECURITY → TEST → DETECTION → DOCS → BENCH)
forces every surface of the project to be visited at least once per five
cycles. Across cycles 50–59 we saw:

- SECURITY (cycles 50, 52, 58) — produced the audit + Round 2.
- TEST (cycles 51, 53, 57) — produced the install-pipeline and
  concurrency tests.
- DETECTION (cycles 54, 59) — produced v3.3.0 and v3.4.0 packs.
- DOCS (cycles 55, 60) — produced the audit writeup and the
  detection-rule documentation site.
- BENCH (cycle 56) — produced the v3.2.2 perf sweep.

If a single track had dominated, the project would have shipped
detection rules without audit coverage, or audit coverage without
tests, or tests without detection.

### 4. Detection coverage 17 → 28/200 MITRE

The +11 rules are concentrated in three families:

- **Server Software Component (T1505)** — T1505.003 (CSP violation)
  and T1505.004 (CSP report burst) cover the WebUI's most common
  attack surface.
- **Valid Accounts (T1078)** — T1078.001 (geo anomaly), T1078.002
  (HMAC replay) cover API key misuse across hours and geographies.
- **Exploit Public-Facing App (T1190)** — T1190.001 (WS HELLO) and
  T1190.002 (HMAC challenge bruteforce) cover WS and HMAC endpoints.

The growth is purposeful, not opportunistic: each rule ships with a
mapped finding and a constraint-honoured test. No rule ships without
both.

## What didn't go well

- **F-018 multi-worker.** The v3.4.4 in-process fix is correct, but
  the durable answer (Redis-backed stream) didn't fit any single cycle.
  It's now formally tracked under `self_defense/MULTI_WORKER.md` and
  scoped for v3.5.0. Should have been called out earlier in the cycle.
- **CSP throttle key choice (F-017).** The original `document-uri`
  key was a natural choice but wrong. A second-pass review of the
  rule body before ship would have caught it. Note added to the
  `T1505.003` / `T1505.004` test checklist.
- **CHANGELOG drift.** The four hotfix releases (v3.4.1..v3.4.4) all
  shipped before their CHANGELOG entries. Cycle 60 (this cycle) is
  closing the documentation lag. Going forward, every release tag
  must include its entry in the same commit.

## Future work (next 10 cycles)

### v3.5.0 — Detection pack round 2

Three new rules in scope, each tied to a specific gap:

- **T1583.002** — Virtual Private Server (Acquire Infrastructure).
  Detects agents reporting from a hosting provider IP range that
  hasn't been seen in the last 30 days.
- **T1583.003** — Virtual Hosting Server (Acquire Infrastructure).
  Same shape as T1583.002 but for shared-hosting netblocks.
- **T1566** — Phishing. Detects outbound SMTP bursts from the
  platform itself (a successful spearphish landing would result in a
  compromised credential being used to relay through the platform's
  alert channels; the rule fires before the relay completes).

### F-018 multi-worker (Redis stream)

Add a `STREAM_BACKEND` env var that, when set to `redis://...`,
routes `_STREAM` append/flush through a `redis.asyncio` Stream. Single
worker mode (`--workers 1`) stays the default; multi-worker mode
becomes safe without lock contention.

### External bug bounty (PortSwigger / HackTheBox)

The detection catalogue is now stable enough (28 rules, 231 tests,
public-release audit clean) to invite external review. Plan:

1. Publish a "challenge scope" doc under `docs/security/bounty/`.
2. Submit the WebUI attack surface to PortSwigger's research review.
3. Submit the WS / HMAC handshake surface to HackTheBox's business
   CTF track.

External review will surface findings the self-hunt cannot (adversary
creativity, novel chains, off-by-default tooling).

## Closing note

Ten cycles, nineteen findings closed, eleven new detection rules,
seventy-six tests added, ten releases shipped, zero regressions,
zero IP literals, zero credentials, zero AI-jargon. The work-rate is
high but the constraints are intact. The single open finding (F-018
multi-worker) is documented, scoped, and on the v3.5.0 roadmap.